# Riru Unshare源码分析

### 一、前言
在之前的Magisk检测方式的文章中，提到过isolated process的概念，MagiskHide无法处理这种进程，因为它和zygote共同使用同一个namespace，如果对这类进程进行unmount的话，会导致所有app都无法正正常访问到su，对于这种情况，可以使用riru-unshare模块来处理使指定的独立进程不与zygote共享namespace
### 二、源码分析
riru-unshare是一个riru模块，看源码就从从main.cpp入手
```c
#ifndef RIRU_MODULE_LEGACY_INIT
RiruVersionedModuleInfo *init(Riru *riru) {
    auto core_max_api_version = riru-&gt;riruApiVersion;
    riru_api_version = core_max_api_version &lt;= RIRU_MODULE_API_VERSION ? core_max_api_version : RIRU_MODULE_API_VERSION;
    module.moduleApiVersion = riru_api_version;

    riru_magisk_module_path = strdup(riru-&gt;magiskModulePath);
    if (riru_api_version &gt;= 25) {
        riru_allow_unload = riru-&gt;allowUnload;
    }
    return &amp;module;
}
#else
RiruVersionedModuleInfo *init(Riru *riru) {
    static int step = 0;
    step &#43;= 1;

    switch (step) {
        case 1: {
            auto core_max_api_version = riru-&gt;riruApiVersion;
            riru_api_version = core_max_api_version &lt;= RIRU_MODULE_API_VERSION ? core_max_api_version : RIRU_MODULE_API_VERSION;
            if (riru_api_version &lt; 25) {
                module.moduleInfo.unused = (void *) shouldSkipUid;
            } else {
                riru_allow_unload = riru-&gt;allowUnload;
            }
            if (riru_api_version &gt;= 24) {
                module.moduleApiVersion = riru_api_version;
                riru_magisk_module_path = strdup(riru-&gt;magiskModulePath);
                return &amp;module;
            } else {
                return (RiruVersionedModuleInfo *) &amp;riru_api_version;
            }
        }
        case 2: {
            return (RiruVersionedModuleInfo *) &amp;module.moduleInfo;
        }
        case 3:
        default: {
            return nullptr;
        }
    }
}
#endif
}
```
配置需要替换的函数
```c
static auto module = RiruVersionedModuleInfo{
        .moduleApiVersion = RIRU_MODULE_API_VERSION,
        .moduleInfo= RiruModuleInfo{
                .supportHide = true,
                .version = RIRU_MODULE_VERSION,
                .versionName = RIRU_MODULE_VERSION_NAME,
                .onModuleLoaded = nullptr,
                .forkAndSpecializePre = forkAndSpecializePre,
                .forkAndSpecializePost = forkAndSpecializePost,
                .forkSystemServerPre = nullptr,
                .forkSystemServerPost = nullptr,
                .specializeAppProcessPre = specializeAppProcessPre,
                .specializeAppProcessPost = specializeAppProcessPost
        }
};
```
主要是四个函数forkAndSpecializePre、forkAndSpecializePost、specializeAppProcessPre和specializeAppProcessPost

在zygote fork产生新进程前后做处理
#### 1 forkAndSpecializePre
在forck出一个新的子进程前被调用，处理工作如设置UID、GID、环境变量等等，选择在forkAndSpecializePre阶段做doUnshare处理也是防止进程正常启动后无法再改变namespace
```c
static void forkAndSpecializePre(
        JNIEnv *env, jclass clazz, jint *uid, jint *gid, jintArray *gids, jint *runtimeFlags,
        jobjectArray *rlimits, jint *mountExternal, jstring *seInfo, jstring *niceName,
        jintArray *fdsToClose, jintArray *fdsToIgnore, jboolean *is_child_zygote,
        jstring *instructionSet, jstring *appDataDir, jboolean *isTopApp, jobjectArray *pkgDataInfoList,
        jobjectArray *whitelistedDataInfoList, jboolean *bindMountAppDataDirs, jboolean *bindMountAppStorageDirs) {
    //应用启动前调用
    doUnshare(env, uid, mountExternal, niceName, *is_child_zygote);
}

static void doUnshare(JNIEnv *env, jint *uid, jint *mountExternal, jstring *niceName, bool is_child_zygote) {
    //uid判断
    if (shouldSkipUid(*uid)) return;
    // 改变mount状态
    if (*mountExternal == 0) {
        *mountExternal = 1;
        ScopedUtfChars name(env, *niceName);
        is_app_zygote = is_child_zygote &amp;&amp; is_app(*uid);
        nice_name_ = niceName;
        LOGI(&#34;unshare uid=%d name=%s app_zygote=%s&#34;, *uid, name.c_str(), is_app_zygote?&#34;true&#34;:&#34;false&#34;);
    }
}

static int shouldSkipUid(int uid) {
    int appid = uid % AID_USER_OFFSET;
    if (appid &gt;= AID_APP_START &amp;&amp; appid &lt;= AID_APP_END) return false;
    if (appid &gt;= AID_ISOLATED_START &amp;&amp; appid &lt;= AID_ISOLATED_END) return false;
    return true;
}

static bool is_app(int uid) {
    return uid%100000 &gt;= 10000 &amp;&amp; uid%100000 &lt;= 19999;
}
```
关键在于mountExternal这个参数的修改，那这个参数的作用是什么呢？从zygote源码中看看
```java
private Process.ProcessStartResult startViaZygote(@NonNull final String processClass,
                                                      @Nullable final String niceName,
                                                      final int uid, final int gid,
                                                      @Nullable final int[] gids,
                                                      int runtimeFlags, int mountExternal,
                                                      int targetSdkVersion,
                                                      @Nullable String seInfo,
                                                      @NonNull String abi,
                                                      @Nullable String instructionSet,
                                                      @Nullable String appDataDir,
                                                      @Nullable String invokeWith,
                                                      boolean startChildZygote,
                                                      @Nullable String packageName,
                                                      int zygotePolicyFlags,
                                                      boolean isTopApp,
                                                      @Nullable long[] disabledCompatChanges,
                                                      @Nullable Map&lt;String, Pair&lt;String, Long&gt;&gt;
                                                              pkgDataInfoMap,
                                                      @Nullable Map&lt;String, Pair&lt;String, Long&gt;&gt;
                                                              allowlistedDataInfoList,
                                                      boolean bindMountAppsData,
                                                      boolean bindMountAppStorageDirs,
                                                      @Nullable String[] extraArgs)
                                                      throws ZygoteStartFailedEx {
    ArrayList&lt;String&gt; argsForZygote = new ArrayList&lt;&gt;();

    // --runtime-args, --setuid=, --setgid=,
    // and --setgroups= must go first
    argsForZygote.add(&#34;--runtime-args&#34;);
    argsForZygote.add(&#34;--setuid=&#34; &#43; uid);
    argsForZygote.add(&#34;--setgid=&#34; &#43; gid);
    argsForZygote.add(&#34;--runtime-flags=&#34; &#43; runtimeFlags);
    if (mountExternal == Zygote.MOUNT_EXTERNAL_DEFAULT) {
        argsForZygote.add(&#34;--mount-external-default&#34;);
    } else if (mountExternal == Zygote.MOUNT_EXTERNAL_INSTALLER) {
        argsForZygote.add(&#34;--mount-external-installer&#34;);
    } else if (mountExternal == Zygote.MOUNT_EXTERNAL_PASS_THROUGH) {
        argsForZygote.add(&#34;--mount-external-pass-through&#34;);
    } else if (mountExternal == Zygote.MOUNT_EXTERNAL_ANDROID_WRITABLE) {
        argsForZygote.add(&#34;--mount-external-android-writable&#34;);
    }
}
```
在传给zygote时处理了mountExternal参数，当mountExternal值为1的时候对应Zygote.MOUNT_EXTERNAL_DEFAULT
```c
static void com_android_internal_os_Zygote_nativeSpecializeAppProcess(
        JNIEnv* env, jclass, jint uid, jint gid, jintArray gids, jint runtime_flags,
        jobjectArray rlimits, jint mount_external, jstring se_info, jstring nice_name,
        jboolean is_child_zygote, jstring instruction_set, jstring app_data_dir,
        jboolean is_top_app, jobjectArray pkg_data_info_list,
        jobjectArray allowlisted_data_info_list, jboolean mount_data_dirs,
        jboolean mount_storage_dirs) {
    jlong capabilities = CalculateCapabilities(env, uid, gid, gids, is_child_zygote);
    //公共fork进程的方法
    SpecializeCommon(env, uid, gid, gids, runtime_flags, rlimits, capabilities, capabilities,
                     mount_external, se_info, nice_name, false, is_child_zygote == JNI_TRUE,
                     instruction_set, app_data_dir, is_top_app == JNI_TRUE, pkg_data_info_list,
                     allowlisted_data_info_list, mount_data_dirs == JNI_TRUE,
                     mount_storage_dirs == JNI_TRUE);
}

static void SpecializeCommon(JNIEnv* env, uid_t uid, gid_t gid, jintArray gids, jint runtime_flags,
                             jobjectArray rlimits, jlong permitted_capabilities,
                             jlong effective_capabilities, jint mount_external,
                             jstring managed_se_info, jstring managed_nice_name,
                             bool is_system_server, bool is_child_zygote,
                             jstring managed_instruction_set, jstring managed_app_data_dir,
                             bool is_top_app, jobjectArray pkg_data_info_list,
                             jobjectArray allowlisted_data_info_list, bool mount_data_dirs,
                             bool mount_storage_dirs) {
    const char* process_name = is_system_server ? &#34;system_server&#34; : &#34;zygote&#34;;
    auto fail_fn = std::bind(ZygoteFailure, env, process_name, managed_nice_name, _1);
    auto extract_fn = std::bind(ExtractJString, env, process_name, managed_nice_name, _1);

    auto se_info = extract_fn(managed_se_info);
    auto nice_name = extract_fn(managed_nice_name);
    auto instruction_set = extract_fn(managed_instruction_set);
    auto app_data_dir = extract_fn(managed_app_data_dir);

    // Keep capabilities across UID change, unless we&#39;re staying root.
    if (uid != 0) {
        EnableKeepCapabilities(fail_fn);
    }

    SetInheritable(permitted_capabilities, fail_fn);

    DropCapabilitiesBoundingSet(fail_fn);

    bool need_pre_initialize_native_bridge = !is_system_server &amp;&amp; instruction_set.has_value() &amp;&amp;
            android::NativeBridgeAvailable() &amp;&amp;
            // Native bridge may be already initialized if this
            // is an app forked from app-zygote.
            !android::NativeBridgeInitialized() &amp;&amp;
            android::NeedsNativeBridge(instruction_set.value().c_str());
    //根据mount_external处理namespace
    MountEmulatedStorage(uid, mount_external, need_pre_initialize_native_bridge, fail_fn);

    ......                             
}

// Create a private mount namespace and bind mount appropriate emulated
// storage for the given user.
static void MountEmulatedStorage(uid_t uid, jint mount_mode,
        bool force_mount_namespace,
        fail_fn_t fail_fn) {
  // See storage config details at http://source.android.com/tech/storage/
  ATRACE_CALL();

  if (mount_mode &lt; 0 || mount_mode &gt;= MOUNT_EXTERNAL_COUNT) {
    fail_fn(CREATE_ERROR(&#34;Unknown mount_mode: %d&#34;, mount_mode));
  }

  //当传参为0时，不创建额外的namespace
  if (mount_mode == MOUNT_EXTERNAL_NONE &amp;&amp; !force_mount_namespace) {
    // Valid default of no storage visible
    return;
  }

  // Create a second private mount namespace for our process
  ensureInAppMountNamespace(fail_fn);

  // Handle force_mount_namespace with MOUNT_EXTERNAL_NONE.
  if (mount_mode == MOUNT_EXTERNAL_NONE) {
    return;
  }

  const userid_t user_id = multiuser_get_user_id(uid);
  const std::string user_source = StringPrintf(&#34;/mnt/user/%d&#34;, user_id);
  // Shell is neither AID_ROOT nor AID_EVERYBODY. Since it equally needs &#39;execute&#39; access to
  // /mnt/user/0 to &#39;adb shell ls /sdcard&#39; for instance, we set the uid bit of /mnt/user/0 to
  // AID_SHELL. This gives shell access along with apps running as group everybody (user 0 apps)
  // These bits should be consistent with what is set in vold in
  // Utils#MountUserFuse on FUSE volume mount
  PrepareDir(user_source, 0710, user_id ? AID_ROOT : AID_SHELL,
             multiuser_get_uid(user_id, AID_EVERYBODY), fail_fn);

  bool isAppDataIsolationEnabled = GetBoolProperty(kVoldAppDataIsolation, false);

  if (mount_mode == MOUNT_EXTERNAL_PASS_THROUGH) {
      const std::string pass_through_source = StringPrintf(&#34;/mnt/pass_through/%d&#34;, user_id);
      PrepareDir(pass_through_source, 0710, AID_ROOT, AID_MEDIA_RW, fail_fn);
      BindMount(pass_through_source, &#34;/storage&#34;, fail_fn);
  } else if (mount_mode == MOUNT_EXTERNAL_INSTALLER) {
      const std::string installer_source = StringPrintf(&#34;/mnt/installer/%d&#34;, user_id);
      BindMount(installer_source, &#34;/storage&#34;, fail_fn);
  } else if (isAppDataIsolationEnabled &amp;&amp; mount_mode == MOUNT_EXTERNAL_ANDROID_WRITABLE) {
      const std::string writable_source = StringPrintf(&#34;/mnt/androidwritable/%d&#34;, user_id);
      BindMount(writable_source, &#34;/storage&#34;, fail_fn);
  } else {
      BindMount(user_source, &#34;/storage&#34;, fail_fn);
  }
}
```
理解好mountExternal的使用之后，再结合unshare的机制来看，就是当有进程想和zygote共享namespace时，强行为该进程创建新的namespace，这样就能够对这个进程进行unmount了
#### 2 forkAndSpecializePost
```c
static void forkAndSpecializePost(JNIEnv *env, jclass clazz, jint res) {
    if (res == 0) {
        if (is_app_zygote &amp;&amp; nice_name_)
            SetProcessName(env, *nice_name_);
        clear_state();
        riru_set_unload_allowed(true);
    }
}

void SetProcessName(JNIEnv* env, jstring name) {
    jclass Process = env-&gt;FindClass(&#34;android/os/Process&#34;);
    jmethodID setArgV0 = env-&gt;GetStaticMethodID(Process, &#34;setArgV0&#34;, &#34;(Ljava/lang/String;)V&#34;);
    if (env-&gt;ExceptionCheck()) {
        env-&gt;ExceptionClear();
        LOGW(&#34;Process.setArgV0(String) not found&#34;);
    } else {
        env-&gt;CallStaticVoidMethod(Process, setArgV0, name);
        if (env-&gt;ExceptionCheck()) {
            env-&gt;ExceptionClear();
            LOGW(&#34;Process.setArgV0(String) threw exception&#34;);
        }
    }
    env-&gt;DeleteLocalRef(Process);
}

static void clear_state(){
    nice_name_ = nullptr;
    is_app_zygote = false;
}
```
#### 3 specializeAppProcessPre
```c
static void specializeAppProcessPre(
        JNIEnv *env, jclass clazz, jint *uid, jint *gid, jintArray *gids, jint *runtimeFlags,
        jobjectArray *rlimits, jint *mountExternal, jstring *seInfo, jstring *niceName,
        jboolean *startChildZygote, jstring *instructionSet, jstring *appDataDir,
        jboolean *isTopApp, jobjectArray *pkgDataInfoList, jobjectArray *whitelistedDataInfoList,
        jboolean *bindMountAppDataDirs, jboolean *bindMountAppStorageDirs) {
    doUnshare(env, uid, mountExternal, niceName, false);
}
```
#### 4 specializeAppProcessPost
```c
static void specializeAppProcessPost(JNIEnv *env, jclass clazz) {
    clear_state();
    riru_set_unload_allowed(true);
}
```

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/riru-unshare%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90/  

