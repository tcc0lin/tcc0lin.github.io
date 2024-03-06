# Zygisk-v27.0源码阅读


隔了很久再读Magisk源码中关于Zygisk的部分，上次翻源码还是v25.0，这次已经更新到了v27.0。粗略扫了眼，变化的地方还是挺多的，想搜索一下关键字也基本上搜索不到，懒得重新过一遍源码，既然是关于zygisk，那就以`(zygisk_enabled)`作为关键搜索词切入


load_modules
if (zygisk_enabled){
    设置native_bridge变成libzygisk.so+native_bridge_orig 
    如果native_bridge_orig为空则变成libzygisk.so
}

inject_zygisk_libs 如果有/system/bin/linker64，把libzygisk.so加入/system/lib64



handle_modules
if (zygisk_enabled) 
每个模块的info.z32 对应jit-cache fd
