# 探讨新的riru加载方式


### 前言
最近在搜索riru相关的项目时偶尔发现了[HuskyDG riru](https://github.com/HuskyDG/Riru)项目中的一个实验性想法

![](https://github.com/tcc0lin/self_pic/blob/main/riru-newload.png?raw=true)

也就是更换加载riru的方式，众所周知，riru.so load是通过赋值ro.dalvik.vm.native.bridge为libriruloader.so来完成的，而HuskyDG则提出了一个新的试验性加载方式---通过修改libandroid_runtime.so替换ro.zygote属性来完成加载

而ro.zygote属性是指的什么呢？它所表达的含义是指定zygote的执行程序时什么，通常情况下它的取值有四种，zygote32、zygote64、zygote32_64、zygote64_32，分别对应着四种.rc文件

- init.zygote32.rc：zygote 进程对应的执行程序是 app_process（纯 32bit 模式）
- init.zygote64.rc：zygote 进程对应的执行程序是 app_process64（纯 64bit 模式）
- init.zygote32_64.rc：启动两个 zygote 进程（名为 zygote 和 zygote_secondary），对应的执行程序分别是 app_process32（主模式）、app_process64
- init.zygote64_32.rc：启动两个 zygote 进程（名为 zygote 和 zygote_secondary），对应的执行程序分别是 app_process64（主模式）、app_process32

而之所以要定义这么多种模式时因为在Android5.0之后开始支持64位程序，为了保证兼容性而推出的

看起来ro.zygote与load并没有什么直接联系，那么HuskyDG的这种新的load方式是怎么实现的呢？

### 一、原理分析
核心代码在[commit: 90ec934](https://github.com/RikkaApps/Riru/commit/90ec93448aab3361c51c3d0df39fda427b24b13f)上，关键代码在两处
```shell
# template/magisk_module/service.sh

mkdir -p "$(magisk --path)/riru"

patch_lib(){
    /data/adb/magisk/magiskboot hexpatch "$1" \
    726f2e64616c76696b2e766d2e6e61746976652e62726964676500 \
    726f2e7a79676f7465000000000000000000000000000000000000
}

if [ -f /system/lib/libandroid_runtime.so ]; then
    cp -af /system/lib/libandroid_runtime.so "$(magisk --path)/riru/libandroid_runtime.so.32"
    magisk --clone-attr /system/lib/libandroid_runtime.so "$(magisk --path)/riru/libandroid_runtime.so.32"
    patch_lib "$(magisk --path)/riru/libandroid_runtime.so.32"
    mount --bind "$(magisk --path)/riru/libandroid_runtime.so.32" /system/lib/libandroid_runtime.so
fi

if [ -f /system/lib64/libandroid_runtime.so ]; then
    cp -af /system/lib64/libandroid_runtime.so "$(magisk --path)/riru/libandroid_runtime.so.64"
    magisk --clone-attr /system/lib64/libandroid_runtime.so "$(magisk --path)/riru/libandroid_runtime.so.64"
    patch_lib "$(magisk --path)/riru/libandroid_runtime.so.64"
    mount --bind "$(magisk --path)/riru/libandroid_runtime.so.64" /system/lib64/libandroid_runtime.so
fi

// restart zygote
stop; start;
```
这里是service.sh新增的代码，从代码中可以看到操作步骤是提取libandroid_runtime.so->patch libandroid_runtime.so->mount bind将修改同步，主要看patch的过程，将726f2e64616c76696b2e766d2e6e61746976652e62726964676500的hex值修改成726f2e7a79676f7465000000000000000000000000000000000000，也就是将ro.dalvik.vm.native.bridge修改成ro.zygote

>为了保证libandroid_runtime.so的总体长度不变，这里额外补充了0来补位

而这么做的意义是什么呢？从libandroid_runtime.so的源码来看
```c
// core/jni/AndroidRuntime.cpp

// Native bridge library. "0" means that native bridge is disabled.
//
// Note: bridging is only enabled for the zygote. Other runs of
//       app_process may not have the permissions to mount etc.
property_get("ro.dalvik.vm.native.bridge", propBuf, "");
if (propBuf[0] == '\0') {
    ALOGW("ro.dalvik.vm.native.bridge is not expected to be empty");
} else if (zygote && strcmp(propBuf, "0") != 0) {
    snprintf(nativeBridgeLibrary, sizeof("-XX:NativeBridge=") + PROPERTY_VALUE_MAX,
                "-XX:NativeBridge=%s", propBuf);
    addOption(nativeBridgeLibrary);
}
```
将原先读取ro.dalvik.vm.native.bridge属性的地方改成了读取ro.zygote属性，避免了对ro.dalvik.vm.native.bridge的赋值，而ro.zygote属性在原生设备上已经赋值，当ro.zygote有值时，就会去加载/system/lib/$(getprop ro.zygote)的so文件
```shell
# template/magisk_module/post-fs-data.sh

cd "$MODDIR" || exit
flock "module.prop"
mount --bind "$TMPPROP" "$MODDIR/module.prop"
# 新增
ln -s ./libriruloader.so "$MODDIR/system/lib/$(getprop ro.zygote)"
ln -s ./libriruloader.so "$MODDIR/system/lib64/$(getprop ro.zygote)"
#
unshare -m sh -c "/system/bin/app_process -Djava.class.path=rirud.apk /system/bin --nice-name=rirud riru.Daemon $(magisk -V) $(magisk --path) $(getprop ro.dalvik.vm.native.bridge)&"
umount "$MODDIR/module.prop"
```
而在post-fs-data阶段，又操作了软链，让/system/lib/$(getprop ro.zygote)实际指向的是libriruloader.so，从而完成libriruloader.so的加载

基本的实现流程就是这样，可以看出HuskyDG的这种方式还是很巧妙的，另外在实现这种方式的同时，HuskyDG也针对性的修改了原有代码和增加了maps隐藏的逻辑
```java
// rirud/src/main/java/riru/DaemonUtils.java

public static void resetNativeBridgeProp(String value) {
    //resetProperty("ro.dalvik.vm.native.bridge", value);
    return;
}
```
去除原有对于ro.dalvik.vm.native.bridge属性的修改，移除template/magisk_module/system.prop
```c
// riru/src/main/cpp/jni_hooks.cpp

static std::vector<lsplt::MapInfo> find_maps(const char *name) {
    auto maps = lsplt::MapInfo::Scan();
    for (auto iter = maps.begin(); iter != maps.end();) {
        if (iter->path != name) {
            iter = maps.erase(iter);
        } else {
            ++iter;
        }
    }
    return maps;
}

void remap_all(const char *name) {
    // 过滤出带有libandroid_runtime.so的segment
    auto maps = find_maps(name);
    for (auto &info : maps) {
        void *addr = reinterpret_cast<void *>(info.start);
        // 获取size
        size_t size = info.end - info.start;
        // 重新mmap申请内存地址
        void *copy = mmap(nullptr, size, PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        // 设置读权限
        if ((info.perms & PROT_READ) == 0) {
            mprotect(addr, size, PROT_READ);
        }
        // 复制到刚申请的内存上
        memcpy(copy, addr, size);
        // 匹配大小
        mremap(copy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, addr);
        // 重新授权
        mprotect(addr, size, info.perms);
    }
}

void fakemap_file(const char *name) {
    auto maps = find_maps(name);
    remap_all(name);
    for (auto &info : maps) {
        //void *addr = reinterpret_cast<void *>(info.start);
        size_t size = info.end - info.start;
        int fd = open(name, O_RDONLY);
        if (fd >= 0) {
            mmap(nullptr, size, info.perms, MAP_PRIVATE, fd, info.offset);
            close(fd);
        } else {
            LOGE("open %s failed\n", name);
        }
    }
}

void jni::RestoreHooks(JNIEnv *env) {
    if (useTableOverride) {
        setTableOverride(nullptr);
@@ -227,6 +272,9 @@ void jni::RestoreHooks(JNIEnv *env) {
    RestoreJNIMethod(zygote, nativeForkSystemServer)

    LOGD("hooks restored");
    // 新增
    fakemap_file("/system/lib/libandroid_runtime.so");
    fakemap_file("/system/lib64/libandroid_runtime.so");

}
```
fakemap_file的作用相当于是去除maps中特征段的文件关联，和riru hide so_list的方式类似

### 二、新方式的思考
相比于老方式来说，新方案没有更改系统属性，而是借助于Magisk修改libandroid_runtime.so。来在HuskyDG的电报群内和一些开发者讨论过，都一致认为这种新方式所暴露出来的风险是大于老方案的，确实如HuskyDG所说，这种新方式只是一种探索吧
