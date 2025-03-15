# Riru原理理解


### 一、前言
什么是riru？正如它Github上面所提到的那样，它提供的能力是允许模块能够将自己的代码注入到各个App进程或者是system_server进程中，而这一切的实现就是基于它对于zygote进程的注入。

那具体是怎么对于zygote进行注入的呢？[文档](https://github.com/RikkaApps/Riru)中也提到，在早期的版本中，riru通过替换libmemtrack.so这个系统库的方式，原因是一方面zygote会加载该系统库，另一方面则是因为这个库足够小，仅仅只有十个函数，也就意味着替换掉它所造成的影响面是很小的，但是后续来看，由于使用到这个so的进程比较多，除了zygote还有SurfaceFlinger（用于显示系统）、mediaserver（用于媒体处理）等等，因此会造成一些意想不到的错误。

因此在v22，riru使用了一个新的注入方式，设置native bridge，也就是指定ro.dalvik.vm.native.bridge的值为riri的so来实现注入，这个思路是来源于canyie的一篇文章[通过系统的native bridge实现注入zygote](https://blog.canyie.top/2020/08/18/nbinjection/)，它的原理大概是
```c&#43;&#43;
void AndroidRuntime::start(const char* className, const Vector&lt;String8&gt;&amp; options, bool zygote)
{
    ALOGD(&#34;&gt;&gt;&gt;&gt;&gt;&gt; START %s uid %d &lt;&lt;&lt;&lt;&lt;&lt;\n&#34;,
            className != NULL ? className : &#34;(unknown)&#34;, getuid());

    /* start the virtual machine */
    JniInvocation jni_invocation;
    jni_invocation.Init(NULL);
    JNIEnv* env;
    // 启动虚拟机
    if (startVm(&amp;mJavaVM, &amp;env, zygote, primary_zygote) != 0) {
        return;
    }
    onVmCreated(env);
}

int AndroidRuntime::startVm(JavaVM** pJavaVM, JNIEnv** pEnv, bool zygote, bool primary_zygote)
{
    JavaVMInitArgs initArgs;
    // ...

    // Native bridge library. &#34;0&#34; means that native bridge is disabled.
    //
    // Note: bridging is only enabled for the zygote. Other runs of
    //       app_process may not have the permissions to mount etc.
    // 读取ro.dalvik.vm.native.bridge属性
    property_get(&#34;ro.dalvik.vm.native.bridge&#34;, propBuf, &#34;&#34;);
    if (propBuf[0] == &#39;\0&#39;) {
        ALOGW(&#34;ro.dalvik.vm.native.bridge is not expected to be empty&#34;);
    } else if (zygote &amp;&amp; strcmp(propBuf, &#34;0&#34;) != 0) {
        snprintf(nativeBridgeLibrary, sizeof(&#34;-XX:NativeBridge=&#34;) &#43; PROPERTY_VALUE_MAX,
                 &#34;-XX:NativeBridge=%s&#34;, propBuf);
        addOption(nativeBridgeLibrary);
    }
    // ...
    initArgs.version = JNI_VERSION_1_4;
    initArgs.options = mOptions.editArray();
    initArgs.nOptions = mOptions.size();
    initArgs.ignoreUnrecognized = JNI_FALSE;

    /*
     * Initialize the VM.
     *
     * The JavaVM* is essentially per-process, and the JNIEnv* is per-thread.
     * If this call succeeds, the VM is ready, and we can start issuing
     * JNI calls.
     */
    if (JNI_CreateJavaVM(pJavaVM, pEnv, &amp;initArgs) &lt; 0) {
        ALOGE(&#34;JNI_CreateJavaVM failed\n&#34;);
        return -1;
    }

    return 0;
}

bool Runtime::Init(RuntimeArgumentMap&amp;&amp; runtime_options_in) {
  // ...
  // Look for a native bridge.
  //
  // The intended flow here is, in the case of a running system:
  //
  // Runtime::Init() (zygote):
  //   LoadNativeBridge -&gt; dlopen from cmd line parameter.
  //  |
  //  V
  // Runtime::Start() (zygote):
  //   No-op wrt native bridge.
  //  |
  //  | start app
  //  V
  // DidForkFromZygote(action)
  //   action = kUnload -&gt; dlclose native bridge.
  //   action = kInitialize -&gt; initialize library
  //
  //
  // The intended flow here is, in the case of a simple dalvikvm call:
  //
  // Runtime::Init():
  //   LoadNativeBridge -&gt; dlopen from cmd line parameter.
  //  |
  //  V
  // Runtime::Start():
  //   DidForkFromZygote(kInitialize) -&gt; try to initialize any native bridge given.
  //   No-op wrt native bridge.
  {
    std::string native_bridge_file_name = runtime_options.ReleaseOrDefault(Opt::NativeBridge);
    // 加载native bridge
    is_native_bridge_loaded_ = LoadNativeBridge(native_bridge_file_name);
  }
  // ...
}

bool LoadNativeBridge(const char* nb_library_filename,
                      const NativeBridgeRuntimeCallbacks* runtime_cbs) {
  // We expect only one place that calls LoadNativeBridge: Runtime::Init. At that point we are not
  // multi-threaded, so we do not need locking here.

  if (nb_library_filename == nullptr || *nb_library_filename == 0) {
    CloseNativeBridge(false);
    return false;
  } else {
    if (!NativeBridgeNameAcceptable(nb_library_filename)) {
      CloseNativeBridge(true);
    } else {
      // Try to open the library.
      // 调用dlopen打开指定so
      void* handle = dlopen(nb_library_filename, RTLD_LAZY);
      if (handle != nullptr) {
        callbacks = reinterpret_cast&lt;NativeBridgeCallbacks*&gt;(dlsym(handle,
                                                                   kNativeBridgeInterfaceSymbol));
        if (callbacks != nullptr) {
          if (isCompatibleWith(NAMESPACE_VERSION)) {
            // Store the handle for later.
            native_bridge_handle = handle;
          } else {
            callbacks = nullptr;
            dlclose(handle);
            ALOGW(&#34;Unsupported native bridge interface.&#34;);
          }
        } else {
          dlclose(handle);
        }
      }

      // Two failure conditions: could not find library (dlopen failed), or could not find native
      // bridge interface (dlsym failed). Both are an error and close the native bridge.
      if (callbacks == nullptr) {
        CloseNativeBridge(true);
      } else {
        runtime_callbacks = runtime_cbs;
        state = NativeBridgeState::kOpened;
      }
    }
    return state == NativeBridgeState::kOpened;
  }
}
```
从上面的源码中就可以了解到整个的实现过程了，简而言之就是
```
startVM-&gt;LoadNativeBridge-&gt;dlopen-&gt;ro.dalvik.vm.native.bridge对应的so
```

以上就是关于riru的大致原理，下面再深入源码中看看有哪些实现细节

### 二、实现细节
#### 1 riru结构
先从riru的项目结构入手，riru是个Magisk模块，自然是以Magisk模块模板为基础，首先来看看Magisk模块模板都具备哪些

参考[开发者文档](https://topjohnwu.github.io/Magisk/guides.html)，Magisk模块都会放在/data/adb/modules目录下，结构如
```
/data/adb/modules
├── .
├── .
|
├── $MODID 模块名称                 &lt;--- The folder is named with the ID of the module
│   │
│   │      *** Module Identity ***
│   │
│   ├── module.prop   模块的基础信息      &lt;--- This file stores the metadata of the module
│   │
│   │      *** Main Contents ***
│   │
│   ├── system   挂载到system目录           &lt;--- This folder will be mounted if skip_mount does not exist
│   │   ├── ...
│   │   ├── ...
│   │   └── ...
│   │
│   ├── zygisk              &lt;--- This folder contains the module&#39;s Zygisk native libraries
│   │   ├── arm64-v8a.so
│   │   ├── armeabi-v7a.so
│   │   ├── x86.so
│   │   ├── x86_64.so
│   │   └── unloaded        &lt;--- If exists, the native libraries are incompatible
│   │
│   │      *** Status Flags ***
│   │
│   ├── skip_mount          &lt;--- If exists, Magisk will NOT mount your system folder
│   ├── disable             &lt;--- If exists, the module will be disabled
│   ├── remove              &lt;--- If exists, the module will be removed next reboot
│   │
│   │      *** Optional Files ***
│   │
│   ├── post-fs-data.sh  定制脚本   &lt;--- This script will be executed in post-fs-data
│   ├── service.sh          &lt;--- This script will be executed in late_start service
|   ├── uninstall.sh        &lt;--- This script will be executed when Magisk removes your module
│   ├── system.prop  系统属性修改        &lt;--- Properties in this file will be loaded as system properties by resetprop
│   ├── sepolicy.rule   sepolicy规则修改    &lt;--- Additional custom sepolicy rules
│   │
│   │      *** Auto Generated, DO NOT MANUALLY CREATE OR MODIFY ***
│   │
│   ├── vendor              &lt;--- A symlink to $MODID/system/vendor
│   ├── product             &lt;--- A symlink to $MODID/system/product
│   ├── system_ext          &lt;--- A symlink to $MODID/system/system_ext
│   │
│   │      *** Any additional files / folders are allowed ***
│   │
│   ├── ...
│   └── ...
|
├── another_module
│   ├── .
│   └── .
├── .
├── .
```
再看看模块的安装过程
```
module.zip
│
├── META-INF
│   └── com
│       └── google
│           └── android
│               ├── update-binary      &lt;--- The module_installer.sh you downloaded
│               └── updater-script     &lt;--- Should only contain the string &#34;#MAGISK&#34;
│
├── customize.sh                       &lt;--- (Optional, more details later)
│                                           This script will be sourced by update-binary
├── ...
├── ...  /* The rest of module&#39;s files */
```
customize.sh和update-binary是互相配合来完成安装过程中定制的部分

具体看看riru修改了
- module.prop
    ```
    id=${id}
    name=${name}
    version=${version}
    versionCode=${versionCode}
    author=${author}
    description=${description}
    riruApi=${riruApi}
    riruMinApi=${riruMinApi}
    ```
    设置全局变量
- post-fs-data
    ```
    #!/system/bin/sh
    MODDIR=${0%/*}
    TMPPROP=&#34;$(magisk --path)/riru.prop&#34;
    MIRRORPROP=&#34;$(magisk --path)/.magisk/modules/riru-core/module.prop&#34;
    sh -Cc &#34;cat &#39;$MODDIR/module.prop&#39; &gt; &#39;$TMPPROP&#39;&#34;
    if [ $? -ne 0 ]; then
    exit
    fi
    mount --bind &#34;$TMPPROP&#34; &#34;$MIRRORPROP&#34;
    if [ &#34;$ZYGISK_ENABLE&#34; = &#34;1&#34; ]; then
        sed -Ei &#39;s/^description=(\[.*][[:space:]]*)?/description=[ ⛔ Riru is not loaded because of Zygisk. ] /g&#39; &#34;$MIRRORPROP&#34;
        exit
    fi
    sed -Ei &#39;s/^description=(\[.*][[:space:]]*)?/description=[ ⛔ app_process fails to run. ] /g&#39; &#34;$MIRRORPROP&#34;
    cd &#34;$MODDIR&#34; || exit
    flock &#34;module.prop&#34;
    mount --bind &#34;$TMPPROP&#34; &#34;$MODDIR/module.prop&#34;
    unshare -m sh -c &#34;/system/bin/app_process -Djava.class.path=rirud.apk /system/bin --nice-name=rirud riru.Daemon $(magisk -V) $(magisk --path) $(getprop ro.dalvik.vm.native.bridge)&amp;&#34;
    umount &#34;$MODDIR/module.prop&#34;
    ```
    主要在于使用unshare资源隔离的方式启动rirud的守护进程，和magiskd类似，都是在post-fs-data阶段启动的
- system.prop
    ```
    ro.dalvik.vm.native.bridge=libriruloader.so
    ```
    最关键的修改，修改了ro.dalvik.vm.native.bridge属性指向libriruloader.so
- customize
    ```
    // template/magisk_module/customize.sh

    // 文件解压
    if [ &#34;$ARCH&#34; = &#34;x86&#34; ] || [ &#34;$ARCH&#34; = &#34;x64&#34; ]; then
        ui_print &#34;- Extracting x86 libraries&#34;
        extract &#34;$ZIPFILE&#34; &#39;lib/x86/libriru.so&#39; &#34;$MODPATH/lib&#34; true
        extract &#34;$ZIPFILE&#34; &#39;lib/x86/libriruhide.so&#39; &#34;$MODPATH/lib&#34; true
        extract &#34;$ZIPFILE&#34; &#39;lib/x86/libriruloader.so&#39; &#34;$MODPATH/system/lib&#34; true

        if [ &#34;$IS64BIT&#34; = true ]; then
            ui_print &#34;- Extracting x64 libraries&#34;
            extract &#34;$ZIPFILE&#34; &#39;lib/x86_64/libriru.so&#39; &#34;$MODPATH/lib64&#34; true
            extract &#34;$ZIPFILE&#34; &#39;lib/x86_64/libriruhide.so&#39; &#34;$MODPATH/lib64&#34; true
            extract &#34;$ZIPFILE&#34; &#39;lib/x86_64/libriruloader.so&#39; &#34;$MODPATH/system/lib64&#34; true
        fi
    else
        ui_print &#34;- Extracting arm libraries&#34;
        extract &#34;$ZIPFILE&#34; &#39;lib/armeabi-v7a/libriru.so&#39; &#34;$MODPATH/lib&#34; true
        extract &#34;$ZIPFILE&#34; &#39;lib/armeabi-v7a/libriruhide.so&#39; &#34;$MODPATH/lib&#34; true
        extract &#34;$ZIPFILE&#34; &#39;lib/armeabi-v7a/libriruloader.so&#39; &#34;$MODPATH/system/lib&#34; true

        if [ &#34;$IS64BIT&#34; = true ]; then
            ui_print &#34;- Extracting arm64 libraries&#34;
            extract &#34;$ZIPFILE&#34; &#39;lib/arm64-v8a/libriru.so&#39; &#34;$MODPATH/lib64&#34; true
            extract &#34;$ZIPFILE&#34; &#39;lib/arm64-v8a/libriruhide.so&#39; &#34;$MODPATH/lib64&#34; true
            extract &#34;$ZIPFILE&#34; &#39;lib/arm64-v8a/libriruloader.so&#39; &#34;$MODPATH/system/lib64&#34; true
        fi
    fi

    // 权限设置
    ui_print &#34;- Setting permissions&#34;
    set_perm_recursive &#34;$MODPATH&#34; 0 0 0755 0644

    ui_print &#34;- Extracting rirud&#34;
    extract &#34;$ZIPFILE&#34; &#34;rirud.apk&#34; &#34;$MODPATH&#34;
    set_perm &#34;$MODPATH/rirud.apk&#34; 0 0 0600

    // 执行installer来检测selinux的规则是否符合预期
    ui_print &#34;- Checking if your ROM has incorrect SELinux rules&#34;
    /system/bin/app_process -Djava.class.path=&#34;$MODPATH/rirud.apk&#34; /system/bin --nice-name=riru_installer riru.Installer --check-selinux
    ```

到这里关于riru的安装部分就结束了，下面回到riru项目来看看它的启动过程

#### 2 riru启动过程
上面讲到system.prop时已经可以看到riru指定了
```c
ro.dalvik.vm.native.bridge=libriruloader.so
```
而从CMake文件（riru\src\main\cpp\CMakeLists.txt）中可以发现libriruloader.so来源于loader.cpp
```c
add_library(riruloader SHARED loader/loader.cpp ${CMAKE_CURRENT_BINARY_DIR}/config.cpp)
target_link_libraries(riruloader log utils cxx::cxx)
```
跟进loader.cpp
```c
// riru/src/main/cpp/loader/loader.cpp

#ifdef HAS_NATIVE_BRIDGE

#include &#34;native_bridge_callbacks.h&#34;

//NOLINTNEXTLINE
extern &#34;C&#34; [[gnu::visibility(&#34;default&#34;)]] uint8_t NativeBridgeItf[
        sizeof(NativeBridgeCallbacks&lt;__ANDROID_API_R__&gt;) * 2]{0};

static void *original_bridge = nullptr;

__used __attribute__((destructor)) void Destructor() {
    if (original_bridge) dlclose(original_bridge);
}

#endif

__used __attribute__((constructor)) void Constructor() {
    if (getuid() != 0) {
        return;
    }
    // 获取当前进程名
    std::string_view cmdline = getprogname();
    // 由于只注入zygoye，因此过滤其他进程
    if (cmdline != &#34;zygote&#34; &amp;&amp;
        cmdline != &#34;zygote32&#34; &amp;&amp;
        cmdline != &#34;zygote64&#34; &amp;&amp;
        cmdline != &#34;usap32&#34; &amp;&amp;
        cmdline != &#34;usap64&#34;) {
        LOGW(&#34;not zygote (cmdline=%s)&#34;, cmdline.data());
        return;
    }

    LOGI(&#34;Riru %s (%d) in %s&#34;, riru::versionName, riru::versionCode, cmdline.data());
    LOGI(&#34;Android %s (api %d, preview_api %d)&#34;, android_prop::GetRelease(),
         android_prop::GetApiLevel(),
         android_prop::GetPreviewApiLevel());
    // 初始化rirud
    constexpr auto retries = 5U;
    RirudSocket rirud{retries};

    if (!rirud.valid()) {
        LOGE(&#34;rirud connect fails&#34;);
        return;
    }
    // 获取riru模块的地址，riru模块名称是riru-core
    std::string magisk_path = rirud.ReadMagiskTmpfsPath();
    if (magisk_path.empty()) {
        LOGE(&#34;failed to obtain magisk path&#34;);
        return;
    }

    // 获取到riru.so的路径
    BuffString&lt;PATH_MAX&gt; riru_path;
    riru_path &#43;= magisk_path;
    riru_path &#43;= &#34;/.magisk/modules/riru-core/lib&#34;;
#ifdef __LP64__
    riru_path &#43;= &#34;64&#34;;
#endif
    riru_path &#43;= &#34;/libriru.so&#34;;

    // 读取so并调用init方法
    auto *handle = DlopenExt(riru_path, 0);
    if (handle) {
        auto init = reinterpret_cast&lt;void (*)(void *, const char *, const RirudSocket &amp;)&gt;(dlsym(
                handle, &#34;init&#34;));
        if (init) {
            init(handle, magisk_path.data(), rirud);
        } else {
            LOGE(&#34;dlsym init %s&#34;, dlerror());
        }
    } else {
        LOGE(&#34;dlopen riru.so %s&#34;, dlerror());
    }

#ifdef HAS_NATIVE_BRIDGE
    // 针对x86设备
    auto native_bridge = rirud.ReadNativeBridge();
    if (native_bridge.empty()) {
        LOGW(&#34;Failed to read original native bridge from socket&#34;);
        return;
    }

    LOGI(&#34;original native bridge: %s&#34;, native_bridge.data());

    if (native_bridge == &#34;0&#34;) {
        return;
    }
    
    original_bridge = dlopen(native_bridge.data(), RTLD_NOW);
    if (original_bridge == nullptr) {
        LOGE(&#34;dlopen failed: %s&#34;, dlerror());
        return;
    }

    auto *original_native_bridge_itf = dlsym(original_bridge, &#34;NativeBridgeItf&#34;);
    if (original_native_bridge_itf == nullptr) {
        LOGE(&#34;dlsym failed: %s&#34;, dlerror());
        return;
    }

    int sdk = 0;
    std::array&lt;char, PROP_VALUE_MAX &#43; 1&gt; value;
    if (__system_property_get(&#34;ro.build.version.sdk&#34;, value.data()) &gt; 0) {
        sdk = atoi(value.data());
    }

    auto callbacks_size = 0;
    if (sdk &gt;= __ANDROID_API_R__) {
        callbacks_size = sizeof(NativeBridgeCallbacks&lt;__ANDROID_API_R__&gt;);
    } else if (sdk == __ANDROID_API_Q__) {
        callbacks_size = sizeof(NativeBridgeCallbacks&lt;__ANDROID_API_Q__&gt;);
    } else if (sdk == __ANDROID_API_P__) {
        callbacks_size = sizeof(NativeBridgeCallbacks&lt;__ANDROID_API_P__&gt;);
    } else if (sdk == __ANDROID_API_O_MR1__) {
        callbacks_size = sizeof(NativeBridgeCallbacks&lt;__ANDROID_API_O_MR1__&gt;);
    } else if (sdk == __ANDROID_API_O__) {
        callbacks_size = sizeof(NativeBridgeCallbacks&lt;__ANDROID_API_O__&gt;);
    } else if (sdk == __ANDROID_API_N_MR1__) {
        callbacks_size = sizeof(NativeBridgeCallbacks&lt;__ANDROID_API_N_MR1__&gt;);
    } else if (sdk == __ANDROID_API_N__) {
        callbacks_size = sizeof(NativeBridgeCallbacks&lt;__ANDROID_API_N__&gt;);
    } else if (sdk == __ANDROID_API_M__) {
        callbacks_size = sizeof(NativeBridgeCallbacks&lt;__ANDROID_API_M__&gt;);
    }
    // 覆盖原始的NativeBridgeItf
    memcpy(NativeBridgeItf, original_native_bridge_itf, callbacks_size);
#endif
}
```
从代码中可以看出，正常对于arm设备来说libriruloader.so相当于loader，负责读取解压在module目录中的libriru.so，而对于x86设备来说，也就是代码中的ifdef HAS_NATIVE_BRIDGE，它的定义可以在这里看到
```c
// riru/src/main/cpp/CMakeLists.txt

if (&#34;${ANDROID_ABI}&#34; STREQUAL &#34;x86&#34; OR &#34;${ANDROID_ABI}&#34; STREQUAL &#34;x86_64&#34;)
    add_definitions(-DHAS_NATIVE_BRIDGE)
endif ()
```
需要和rirud通信，用原始的NativeBridgeItf替换修改后的NativeBridgeItf

riruloader引导启动了riru.so，riru.so来自entry.cpp
```txt
// riru/src/main/cpp/CMakeLists.txt

add_library(riru SHARED
        entry.cpp
        jni_hooks.cpp
        hide_utils.cpp
        module.cpp
        magisk.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/config.cpp)
target_include_directories(riru PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(riru log utils xhook::xhook cxx::cxx proc-maps-parser::proc-maps-parser)
```
根据loader中的流程，在dlopen riru.so会调用的是init方法，也就是
```c
// riru/src/main/cpp/entry.cpp

extern &#34;C&#34; [[gnu::visibility(&#34;default&#34;)]] [[maybe_unused]] void
// NOLINTNEXTLINE
init(void *handle, const char* magisk_path, const RirudSocket&amp; rirud) {
    self_handle = handle;

    magisk::SetPath(magisk_path);
    hide::PrepareMapsHideLibrary();
    jni::InstallHooks();
    modules::Load(rirud);
}
```
init的过程分为了三个部分

##### 2.1 hide::PrepareMapsHideLibrary
```c
// riru/src/main/cpp/hide_utils.cpp

void PrepareMapsHideLibrary() {
    // 获取so的绝对路径，也就是/data/adb/modules/riru-core
    auto hide_lib_path = magisk::GetPathForSelfLib(&#34;libriruhide.so&#34;);

    // load riruhide.so and run the hide
    LOGD(&#34;dlopen libriruhide&#34;);
    // dlopen
    riru_hide_handle = DlopenExt(hide_lib_path.c_str(), 0);
    if (!riru_hide_handle) {
        LOGE(&#34;dlopen %s failed: %s&#34;, hide_lib_path.c_str(), dlerror());
        return;
    }
    // dlsym riru_hide
    riru_hide_func = reinterpret_cast&lt;riru_hide_t *&gt;(dlsym(riru_hide_handle, &#34;riru_hide&#34;));
    if (!riru_hide_func) {
        LOGE(&#34;dlsym failed: %s&#34;, dlerror());
        dlclose(riru_hide_handle);
        return;
    }
}
```
调用libriruhide.so的riru_hide方法，libriruhide.so对应的是
```
add_library(riruhide SHARED hide/hide.cpp)
```
这一步只是准备好riru_hide的函数，并未真正执行，执行需要在各个注入进程内部来执行

提前来看看具体代码
```c
// riru/src/main/cpp/hide/hide.cpp

int riru_hide(const std::set&lt;std::string_view&gt; &amp;names) {
    // 对应的是https://github.com/h33p/vmread/blob/master/pmparser.c，格式化当前进程的maps变成对应的结构体
    procmaps_iterator *maps = pmparser_parse(-1);
    if (maps == nullptr) {
        LOGE(&#34;cannot parse the memory map&#34;);
        return false;
    }

    char buf[PATH_MAX];
    hide_struct *data = nullptr;
    size_t data_count = 0;
    procmaps_struct *maps_tmp;
    // 遍历maps结构体
    while ((maps_tmp = pmparser_next(maps)) != nullptr) {
        bool matched = false;
#ifdef DEBUG_APP
        matched = strstr(maps_tmp-&gt;pathname, &#34;libriru.so&#34;);
#endif
        // 检测maps是否包含name
        matched = names.count(maps_tmp-&gt;pathname);

        if (!matched) continue;
        // 如果匹配到了
        auto start = (uintptr_t) maps_tmp-&gt;addr_start;
        auto end = (uintptr_t) maps_tmp-&gt;addr_end;
        // 如果可读
        if (maps_tmp-&gt;is_r) {
            // 创建data来存储maps_tmp
            if (data) {
                data = (hide_struct *) realloc(data, sizeof(hide_struct) * (data_count &#43; 1));
            } else {
                data = (hide_struct *) malloc(sizeof(hide_struct));
            }
            // 保存到hide_struct结构体中
            data[data_count].original = maps_tmp;
            data_count &#43;= 1;
        }
        LOGD(&#34;%&#34; PRIxPTR&#34;-%&#34; PRIxPTR&#34; %s %ld %s&#34;, start, end, maps_tmp-&gt;perm, maps_tmp-&gt;offset,
             maps_tmp-&gt;pathname);
    }

    for (int i = 0; i &lt; data_count; &#43;&#43;i) {
        // 进行hide
        do_hide(&amp;data[i]);
    }

    if (data) free(data);
    pmparser_free(maps);
    return 0;
}

static int do_hide(hide_struct *data) {
    auto procstruct = data-&gt;original;
    auto start = (uintptr_t) procstruct-&gt;addr_start;
    auto end = (uintptr_t) procstruct-&gt;addr_end;
    auto length = end - start;
    int prot = get_prot(procstruct);

    // backup
    // 通过mmap建立内存映射，由于fd为-1，表示建立的是匿名映射，backup_address为新地址
    data-&gt;backup_address = (uintptr_t) FAILURE_RETURN(
            mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0),
            MAP_FAILED);
    LOGD(&#34;%&#34; PRIxPTR&#34;-%&#34; PRIxPTR&#34; %s %ld %s is backup to %&#34; PRIxPTR, start, end, procstruct-&gt;perm,
         procstruct-&gt;offset,
         procstruct-&gt;pathname, data-&gt;backup_address);

    if (!procstruct-&gt;is_r) {
        // 老地址如果不可读，通过mprotect授予可读权限
        LOGD(&#34;mprotect &#43;r&#34;);
        FAILURE_RETURN(mprotect((void *) start, length, prot | PROT_READ), -1);
    }
    // 老地址数据复制到新地址上
    LOGD(&#34;memcpy -&gt; backup&#34;);
    memcpy((void *) data-&gt;backup_address, (void *) start, length);

    // munmap original
    LOGD(&#34;munmap original&#34;);
    // 删除老地址的映射
    FAILURE_RETURN(munmap((void *) start, length), -1);

    // restore
    LOGD(&#34;mmap original&#34;);
    // 老地址重建映射
    FAILURE_RETURN(mmap((void *) start, length, prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0),
                   MAP_FAILED);
    LOGD(&#34;mprotect &#43;w&#34;);
    // 授予老地址写权限
    FAILURE_RETURN(mprotect((void *) start, length, prot | PROT_WRITE), -1);
    LOGD(&#34;memcpy -&gt; original&#34;);
    // 新地址数据返还给老地址
    memcpy((void *) start, (void *) data-&gt;backup_address, length);
    if (!procstruct-&gt;is_w) {
        LOGD(&#34;mprotect -w&#34;);
        // 使用老权限，也就是没有可写权限的权限
        FAILURE_RETURN(mprotect((void *) start, length, prot), -1);
    }
    return 0;
}
```
do_hide的逻辑简单来看就是替换原有的map记录，中间会涉及到数据的转存，因此会有memcpy的操作，去除文件的关键点就在于munmap去除了fd引用从而保证该map没有关联的文件，调用点在
```c
// riru/src/main/cpp/hide_utils.cpp

void HideFromMaps() {
    // 获取libriru.so的绝对路径
    auto self_path = magisk::GetPathForSelfLib(&#34;libriru.so&#34;);
    std::set&lt;std::string_view&gt; names{self_path};
    // 得到真实路径
    for (const auto &amp;module : modules::Get()) {
        if (module.supportHide) {
            if (!module.isLoaded()) {
                LOGD(&#34;%s is unloaded&#34;, module.id.data());
            } else {
                names.emplace(module.path);
            }
        } else {
            LOGD(&#34;module %s does not support hide&#34;, module.id.data());
        }
    }
    if (!names.empty()) hide::HidePathsFromMaps(names);
}
```
##### 2.2 jni::InstallHooks
```c
// riru/src/main/cpp/jni_hooks.cpp

void jni::InstallHooks() {
    // 引入xhook
    XHOOK_REGISTER(&#34;.*\\libandroid_runtime.so$&#34;, jniRegisterNativeMethods)
    // 确认hook状态
    if (xhook_refresh(0) == 0) {
        xhook_clear();
        LOGI(&#34;hook installed&#34;);
    } else {
        LOGE(&#34;failed to refresh hook&#34;);
    }

    useTableOverride = old_jniRegisterNativeMethods == nullptr;
}

#define XHOOK_REGISTER(PATH_REGEX, NAME) \
    if (xhook_register(PATH_REGEX, #NAME, (void*) new_##NAME, (void **) &amp;old_##NAME) != 0) \
        LOGE(&#34;failed to register hook &#34; #NAME &#34;.&#34;); \

#define NEW_FUNC_DEF(ret, func, ...) \
    using func##_t = ret(__VA_ARGS__); \
    static func##_t *old_##func; \
    static ret new_##func(__VA_ARGS__)

NEW_FUNC_DEF(int, jniRegisterNativeMethods, JNIEnv *env, const char *className,
             const JNINativeMethod *methods, int numMethods) {
    LOGD(&#34;jniRegisterNativeMethods %s&#34;, className);

    auto newMethods = handleRegisterNative(className, methods, numMethods);
    int res = old_jniRegisterNativeMethods(env, className, newMethods ? newMethods.get() : methods,
                                           numMethods);
    /*if (!newMethods) {
        NativeMethod::jniRegisterNativeMethodsPost(env, className, methods, numMethods);
    }*/
    return res;
}
```
替换了RegisterNative方法，新的RegisterNative采用handleRegisterNative处理
```c
// riru/src/main/cpp/jni_hooks.cpp

static std::unique_ptr&lt;JNINativeMethod[]&gt;
handleRegisterNative(const char *className, const JNINativeMethod *methods, int numMethods) {
    if (strcmp(&#34;com/android/internal/os/Zygote&#34;, className) == 0) {
        // 注入zygote
        return onRegisterZygote(className, methods, numMethods);
    } else {
        return nullptr;
    }
}

static std::unique_ptr&lt;JNINativeMethod[]&gt;
onRegisterZygote(const char *className, const JNINativeMethod *methods, int numMethods) {

    // 替换原始方法所在的内存
    auto newMethods = std::make_unique&lt;JNINativeMethod[]&gt;(numMethods);
    memcpy(newMethods.get(), methods, sizeof(JNINativeMethod) * numMethods);

    // 主要hooks三个函数
    // - nativeForkAndSpecialize
    // - nativeSpecializeAppProcess
    // - nativeForkSystemServer
    // 可以覆盖到所有app和system_server
    JNINativeMethod method;
    for (int i = 0; i &lt; numMethods; &#43;&#43;i) {
        method = methods[i];

        if (strcmp(method.name, &#34;nativeForkAndSpecialize&#34;) == 0) {
            jni::zygote::nativeForkAndSpecialize = new JNINativeMethod{method.name,
                                                                       method.signature,
                                                                       method.fnPtr};

            if (strcmp(nativeForkAndSpecialize_r_sig, method.signature) == 0)
                newMethods[i].fnPtr = (void *) nativeForkAndSpecialize_r;

            ......
            
            // 适配不同版本，替换实现指针
            auto replaced = newMethods[i].fnPtr != methods[i].fnPtr;
            if (replaced) {
                LOGI(&#34;replaced com.android.internal.os.Zygote#nativeForkAndSpecialize&#34;);
            }
        } else if (strcmp(method.name, &#34;nativeSpecializeAppProcess&#34;) == 0) {
            jni::zygote::nativeSpecializeAppProcess = new JNINativeMethod{method.name,
                                                                          method.signature,
                                                                          method.fnPtr};

            if (strcmp(nativeSpecializeAppProcess_r_sig, method.signature) == 0)
                newMethods[i].fnPtr = (void *) nativeSpecializeAppProcess_r;
            
            ......

            auto replaced = newMethods[i].fnPtr != methods[i].fnPtr;
            if (replaced) {
                LOGI(&#34;replaced com.android.internal.os.Zygote#nativeSpecializeAppProcess&#34;);
            }
        } else if (strcmp(method.name, &#34;nativeForkSystemServer&#34;) == 0) {
            jni::zygote::nativeForkSystemServer = new JNINativeMethod{method.name, method.signature,
                                                                      method.fnPtr};

            if (strcmp(nativeForkSystemServer_sig, method.signature) == 0)
                newMethods[i].fnPtr = (void *) nativeForkSystemServer;
            else if (strcmp(nativeForkSystemServer_samsung_q_sig, method.signature) == 0)
                newMethods[i].fnPtr = (void *) nativeForkSystemServer_samsung_q;
            else
                LOGW(&#34;found nativeForkSystemServer but signature %s mismatch&#34;, method.signature);

            auto replaced = newMethods[i].fnPtr != methods[i].fnPtr;
            if (replaced) {
                LOGI(&#34;replaced com.android.internal.os.Zygote#nativeForkSystemServer&#34;);
            }
        }
    }
    return newMethods;
}
```
具体逻辑的实现
```c
// riru/src/main/cpp/jni_hooks.cpp

jint nativeForkSystemServer(
        JNIEnv *env, jclass clazz, uid_t uid, gid_t gid, jintArray gids, jint runtimeFlags,
        jobjectArray rlimits, jlong permittedCapabilities, jlong effectiveCapabilities) {

    // pre
    nativeForkSystemServer_pre(
            env, clazz, uid, gid, gids, runtimeFlags, rlimits, permittedCapabilities,
            effectiveCapabilities);

    // origin
    jint res = ((nativeForkSystemServer_t *) jni::zygote::nativeForkSystemServer-&gt;fnPtr)(
            env, clazz, uid, gid, gids, runtimeFlags, rlimits, permittedCapabilities,
            effectiveCapabilities);

    // post
    nativeForkSystemServer_post(env, clazz, res);
    return res;
}

static void nativeForkSystemServer_pre(
        JNIEnv *env, jclass clazz, uid_t &amp;uid, gid_t &amp;gid, jintArray &amp;gids, jint &amp;debug_flags,
        jobjectArray &amp;rlimits, jlong &amp;permittedCapabilities, jlong &amp;effectiveCapabilities) {

    // 执行各个模块的方法
    for (const auto &amp;module : modules::Get()) {
        if (!module.hasForkSystemServerPre())
            continue;

        module.resetAllowUnload();

        module.forkSystemServerPre(
                env, clazz, &amp;uid, &amp;gid, &amp;gids, &amp;debug_flags, &amp;rlimits, &amp;permittedCapabilities,
                &amp;effectiveCapabilities);
    }
}

static void nativeForkSystemServer_post(JNIEnv *env, jclass clazz, jint res) {
    
    if (res == 0) jni::RestoreHooks(env);

    if (res == 0 &amp;&amp; android_prop::CheckZTE()) {
        auto *process = env-&gt;FindClass(&#34;android/os/Process&#34;);
        auto *set_argv0 = env-&gt;GetStaticMethodID(process, &#34;setArgV0&#34;, &#34;(Ljava/lang/String;)V&#34;);
        env-&gt;CallStaticVoidMethod(process, set_argv0, env-&gt;NewStringUTF(&#34;system_server&#34;));
    }

    // 同理
    for (const auto &amp;module : modules::Get()) {
        if (!module.hasForkSystemServerPost()) continue;

        if (res == 0) LOGD(&#34;%s: forkSystemServerPost&#34;, module.id.data());
        module.forkSystemServerPost(env, clazz, res);
    }
}

static void
nativeSpecializeAppProcess_post(JNIEnv *env, jclass clazz, jint uid, jboolean is_child_zygote) {

    jni::RestoreHooks(env);

    for (const auto &amp;module : modules::Get()) {
        if (!module.hasSpecializeAppProcessPost())
            continue;

        if (module.apiVersion &lt; 25) {
            if (module.hasShouldSkipUid() &amp;&amp; module.shouldSkipUid(uid))
                continue;

            if (!module.hasShouldSkipUid() &amp;&amp; shouldSkipUid(uid))
                continue;
        }

        LOGD(&#34;%s: specializeAppProcessPost&#34;, module.id.data());
        module.specializeAppProcessPost(env, clazz);
    }
    // 每个app初始化时需要额外对solist进行隐藏
    Entry::Unload(is_child_zygote);
}

void Entry::Unload(jboolean is_child_zygote) {
    self_unload_allowed = true;

    for (auto &amp;module : modules::Get()) {
        if (module.allowUnload()) {
            LOGD(&#34;%s: unload&#34;, module.id.data());
            module.unload();
        } else {
            if (module.apiVersion &gt;= 25)
                LOGD(&#34;%s: unload is not allow for this process&#34;, module.id.data());
            else {
                LOGD(&#34;%s: unload is not supported by module (API &lt; 25), self unload is also disabled&#34;,
                     module.id.data());
                self_unload_allowed = false;
            }
        }
    }

    hide::HideFromSoList();

    // Child zygote (webview zyote or app zygote) has no &#34;execmem&#34; permission
    if (android_prop::GetApiLevel() &lt; 29 &amp;&amp; !is_child_zygote) {
        hide::HideFromMaps();
    }

    if (self_unload_allowed) {
        SelfUnload();
    }
}
```
除了对maps隐藏以外，还有HideFromSoList对系统so列表的隐藏
```c&#43;&#43;
// riru/src/main/cpp/hide_utils.cpp

void HideFromSoList() {
    // 获取libriru.so的路径，这里的路径是magisk目录下的路径
    auto self_path = magisk::GetPathForSelfLib(&#34;libriru.so&#34;);
    std::set&lt;std::string_view&gt; names_to_remove{};
    if (Entry::IsSelfUnloadAllowed()) {
        LOGD(&#34;don&#39;t hide self since it will be unloaded&#34;);
    } else {
        names_to_remove.emplace(self_path);
    }
    for (const auto &amp;module : modules::Get()) {
        if (module.supportHide) {
            if (!module.isLoaded()) {
                LOGD(&#34;%s is unloaded&#34;, module.id.data());
                continue;
            }
            if (module.apiVersion &lt; 24) {
                LOGW(&#34;%s is too old to hide so&#34;, module.id.data());
            } else {
                names_to_remove.emplace(module.path);
            }
        } else {
            LOGD(&#34;module %s does not support hide&#34;, module.id.data());
        }
    }

    if (android_prop::GetApiLevel() &gt;= 23 &amp;&amp; !names_to_remove.empty()) {
        // 具体移除方法
        RemoveFromSoList(names_to_remove);
    }
}

void RemovePathsFromSolist(const std::set&lt;std::string_view&gt; &amp;names) {
    if (!initialized) {
        LOGW(&#34;not initialized&#34;);
        return;
    }
    ProtectedDataGuard g;
    for (const auto &amp;soinfo : linker_get_solist()) {
        const auto &amp;real_path = soinfo-&gt;get_realpath();
        if (real_path &amp;&amp; names.count(real_path)) {
            solist_remove_soinfo(soinfo);
        }
    }
}
```
先看看so列表是怎么获取到的
```c&#43;&#43;
std::list&lt;soinfo *&gt; linker_get_solist() {
    std::list&lt;soinfo *&gt; linker_solist{};
    for (auto *iter = solist; iter; iter = iter-&gt;next()) {
        linker_solist.push_back(iter);
    }
    return linker_solist;
}

// 通过获取linker地址进而获取solist的地址
const auto initialized = []() {
    SandHook::ElfImg linker(&#34;/linker&#34;);
    return ProtectedDataGuard::setup(linker) &amp;&amp;
            (solist = getStaticVariable&lt;soinfo&gt;(linker, &#34;__dl__ZL6solist&#34;)) != nullptr &amp;&amp;
            (sonext = linker.getSymbAddress&lt;soinfo**&gt;(&#34;__dl__ZL6sonext&#34;)) != nullptr &amp;&amp;
            (somain = getStaticVariable&lt;soinfo&gt;(linker, &#34;__dl__ZL6somain&#34;)) != nullptr &amp;&amp;
            soinfo::setup(linker);
}();
```
隐藏逻辑
```c
bool solist_remove_soinfo(soinfo *si) {
    soinfo *prev = nullptr, *trav;
    for (trav = solist; trav != nullptr; trav = trav-&gt;next()) {
        if (trav == si) {
            break;
        }
        prev = trav;
    }

    if (trav == nullptr) {
        // si was not in solist
        LOGE(&#34;name \&#34;%s\&#34;@%p is not in solist!&#34;, si-&gt;get_realpath(), si);
        return false;
    }
    // 相当于重构链表
    // prev will never be null, because the first entry in solist is
    // always the static libdl_info.
    prev-&gt;next(si-&gt;next());
    if (si == *sonext) {
        *sonext = prev;
    }

    LOGD(&#34;removed soinfo: %s&#34;, si-&gt;get_realpath());

    return true;
}
```

##### 2.3 modules::Load
```c
// riru/src/main/cpp/module.cpp

void modules::Load(const RirudSocket &amp;rirud) {
    uint32_t num_modules;
    // 模块获取
    auto &amp;modules = modules::Get();
    if (!rirud.Write(RirudSocket::Action::READ_MODULES) ||
        !rirud.Write(is64bit) || !rirud.Read(num_modules)) {
        LOGE(&#34;Faild to load modules&#34;);
        return;
    }
    std::string magisk_module_path;
    std::string path;
    std::string id;
    uint32_t num_libs;
    // 遍历模块进行load
    while (num_modules-- &gt; 0) {
        if (!rirud.Read(magisk_module_path) || !rirud.Read(num_libs)) {
            LOGE(&#34;Faild to read module&#39;s magisk path&#34;);
            return;
        }
        while (num_libs-- &gt; 0) {
            if (!rirud.Read(id) || !rirud.Read(path)) {
                LOGE(&#34;Faild to read module&#39;s lib path&#34;);
                return;
            }
            LoadModule(id, path, magisk_module_path);
        }
    }

    // android10以上额外增加maps hide
    // On Android 10&#43;, zygote has &#34;execmem&#34; permission, we can use &#34;riru hide&#34; here
    if (android_prop::GetApiLevel() &gt;= __ANDROID_API_Q__) {
        hide::HideFromMaps();
    }

    // 另一种load方式
    for (const auto &amp;module : modules::Get()) {
        if (module.hasOnModuleLoaded()) {
            LOGV(&#34;%s: onModuleLoaded&#34;, module.id.data());
            module.onModuleLoaded();
        }
    }

    WriteModules(rirud);
}
```
关于模块的load关键点在三个地方，首先是LoadModule
```c
static void LoadModule(std::string_view id, std::string_view path, std::string_view magisk_module_path) {
    // 判断路径是否可读
    if (access(path.data(), F_OK) != 0) {
        PLOGE(&#34;access %s&#34;, path.data());
        return;
    }
    // dlopen
    auto *handle = DlopenExt(path.data(), 0);
    if (!handle) {
        LOGE(&#34;dlopen %s failed: %s&#34;, path.data(), dlerror());
        return;
    }
    // 调用init函数
    auto init = reinterpret_cast&lt;RiruInit_t *&gt;(dlsym(handle, &#34;init&#34;));
    if (!init) {
        LOGW(&#34;%s does not export init&#34;, path.data());
        Cleanup(handle);
        return;
    }

    auto allow_unload = std::make_unique&lt;int&gt;();
    auto riru = std::make_unique&lt;Riru&gt;(Riru{
            .riruApiVersion = riru::apiVersion,
            .unused = nullptr,
            .magiskModulePath = magisk_module_path.data(),
            .allowUnload = allow_unload.get()
    });

    auto *module_info = init(riru.get());
    if (module_info == nullptr) {
        LOGE(&#34;%s requires higher Riru version (or its broken)&#34;, path.data());
        Cleanup(handle);
        return;
    }

    auto api_version = module_info-&gt;moduleApiVersion;
    if (api_version &lt; riru::minApiVersion || api_version &gt; riru::apiVersion) {
        LOGW(&#34;unsupported API %s: %d&#34;, id.data(), api_version);
        Cleanup(handle);
        return;
    }

    LOGI(&#34;module loaded: %s (api %d)&#34;, id.data(), api_version);

    modules::Get().emplace_back(id, path, magisk_module_path, api_version, module_info-&gt;moduleInfo,
                                handle,
                                std::move(allow_unload));
}
```
HideFromMaps是之前PrepareMapsHideLibrary的调用点

最后是onModuleLoaded，这个功能是为了防止模块开发者在使用线程时造成hide功能产生SIGSEGV

至此riru的实现细节大概分析完了，都说”riru提供注入功能，lsposed提供hook功能“，lsposed确实底层也依赖riru或者zygisk，下次再深入看看lsposed

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/riru%E5%8E%9F%E7%90%86%E7%90%86%E8%A7%A3/  

