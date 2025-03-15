# Riru MomoHider源码分析




### 一、前言
同样的，作为一个riru模块，从该项目的简介中，就可以发现它的主要作用了
&gt;Riru - MomoHider (aka IsolatedMagiskHider)

主要针对isolated进程所做的隐藏，MomoHider提供了几个配置选项来从多个角度隐藏MagiskHide，如下

|配置项|说明|
|---|---|
|isolated|对每一个isolated processes卸载magisk相关的文件，但是无法控制卸载时机，可能会导致部分模块无法正常使用|
|setns|在isolated processes中能够更快隐藏Magisk|
|app_zygote_magic|让momo无法检测到MagiskHide是运行状态|
|initrc|隐藏修改init.rc的堆栈|

这些配置应该是作者最初的想法，现在某些配置已经无法正常使用了，所以还是从源码中看看现在这个模块具体做了哪些事

### 二、源码分析
从riru模块的入口main.cpp入手
```cpp
// 配置了五个自定义方法
static auto module = RiruVersionedModuleInfo {
        .moduleApiVersion = RIRU_NEW_MODULE_API_VERSION,
        .moduleInfo = RiruModuleInfo {
                .supportHide = true,
                .version = RIRU_MODULE_VERSION_CODE,
                .versionName = RIRU_MODULE_VERSION_NAME,
                .onModuleLoaded = onModuleLoaded,
                .shouldSkipUid = nullptr,
                .forkAndSpecializePre = forkAndSpecializePre,
                .forkAndSpecializePost = forkAndSpecializePost,
                .forkSystemServerPre = nullptr,
                .forkSystemServerPost = nullptr,
                .specializeAppProcessPre = specializeAppProcessPre,
                .specializeAppProcessPost = specializeAppProcessPost
        }
};

// 变量定义
// module目录
const char* module_dir_ = nullptr;
// 配置值，可以看到关于initrc的参数是没有设置了
constexpr const char* kSetNs = &#34;setns&#34;;
constexpr const char* kMagicHandleAppZygote = &#34;app_zygote_magic&#34;;
constexpr const char* kMagiskTmp = &#34;magisk_tmp&#34;;
constexpr const char* kIsolated = &#34;isolated&#34;;

const char* magisk_tmp_ = nullptr;
bool magic_handle_app_zygote_ = false;
bool hide_isolated_ = false;
bool in_child_ = false;
bool isolated_ = false;
bool app_zygote_ = false;
bool no_new_ns_ = false;

jstring* nice_name_ = nullptr;

bool use_nsholder_ = false;
char* nsholder_mnt_ns_ = nullptr;
pid_t nsholder_pid_ = -1;

pid_t (*orig_fork)() = nullptr;
int (*orig_unshare)(int) = nullptr;

int* riru_allow_unload = nullptr;
```
#### 1 onModuleLoaded
```c&#43;&#43;
void onModuleLoaded() {
    // magisk加载模块时会分配给模块特定目录
    LOGI(&#34;Magisk module dir is %s&#34;, module_dir_);
    // 分配给magisk tmp的目录，路径是module_dir_/config/magisk_tmp
    magisk_tmp_ = ReadMagiskTmp();
    LOGI(&#34;Magisk temp path is %s&#34;, magisk_tmp_);
    // 读取配置文件，也就是看config目录下是否存在这些配置文件，存在则表明开启这些配置
    hide_isolated_ = Exists(kIsolated);
    magic_handle_app_zygote_ = Exists(kMagicHandleAppZygote);
    use_nsholder_ = Exists(kSetNs);
    RegisterHooks();
}

void RegisterHooks() {
    if (!hide_isolated_ &amp;&amp; !magic_handle_app_zygote_) return;
    // 使用xhook
    xhook_enable_debug(1);
    xhook_enable_sigsegv_protection(0);
    bool failed = false;
    // 定义hook函数
#define HOOK(NAME, REPLACE) \
failed = failed || RegisterHook(#NAME, reinterpret_cast&lt;void*&gt;(REPLACE), reinterpret_cast&lt;void**&gt;(&amp;orig_##NAME))
    // hook fork函数
    HOOK(fork, ForkReplace);
    if (hide_isolated_) {
        // hook unshare函数
        HOOK(unshare, UnshareReplace);
    }

#undef HOOK

    if (failed || xhook_refresh(0)) {
        LOGE(&#34;Failed to register hooks!&#34;);
        return;
    }
    xhook_clear();
}

bool RegisterHook(const char* name, void* replace, void** backup) {
    int ret = xhook_register(&#34;.*\\libandroid_runtime.so$&#34;, name, replace, backup);
    if (ret != 0) {
        LOGE(&#34;Failed to hook %s&#34;, name);
        return true;
    }
    return false;
}
```
在加载该模块时，主要做的事情是读取用户自定义的配置文件，并通过xhook hook了fork函数和unshare函数，具体hook操作如下
##### 1.1 ForkReplace
```cpp
pid_t ForkReplace() {
    int read_fd = -1, write_fd = -1;

#if !USE_NEW_APP_ZYGOTE_MAGIC
    // 创建管道，用于后续进程通信
    if (app_zygote_ &amp;&amp; magic_handle_app_zygote_) {
        int pipe_fd[2];
        if (pipe(pipe_fd) == -1) {
            LOGE(&#34;Failed to create pipe for new app zygote: %s&#34;, strerror(errno));
        } else {
            read_fd = pipe_fd[0];
            write_fd = pipe_fd[1];
        }
    }
#endif
    // 调用原始fork方法
    pid_t pid = orig_fork();
    // pid&lt;0，fork失败，清理管道
    if (pid &lt; 0) {
#if !USE_NEW_APP_ZYGOTE_MAGIC
        // fork() failed, clean up
        if (read_fd != -1)
            close(read_fd);
        if (write_fd != -1)
            close(write_fd);
#endif
    } else if (pid == 0) {
        // 正常情况的两种情况，第一种事pid=0，也就是子进程中
        // child process
        // Do not hide here because the namespace not separated
        in_child_ = true;
#if !USE_NEW_APP_ZYGOTE_MAGIC
        if (read_fd != -1 &amp;&amp; write_fd != -1) {
            close(read_fd);
            // 获取新pid
            pid_t new_pid = MagicHandleAppZygote();
            // 向管道中写入新pid值
            WriteIntAndClose(write_fd, new_pid);
        }
#endif
    } else {
#if !USE_NEW_APP_ZYGOTE_MAGIC
        // parent process
        if (read_fd != -1 &amp;&amp; write_fd != -1) {
            close(write_fd);
            // 读取子进程写入的pid值
            pid = ReadIntAndClose(read_fd);
            LOGI(&#34;Zygote received new substitute pid %d&#34;, pid);
        }
#endif
    }
    return pid;
}

#if !USE_NEW_APP_ZYGOTE_MAGIC
pid_t MagicHandleAppZygote() {
    // 在子进程中进一步调用fork，返回子进程的子进程的pid
    LOGI(&#34;Magic handling app zygote&#34;);
    // App zygote, fork a new process to run it (after forking magiskhide detachs)
    // This makes some detection not working (but also can be easily detected)
    pid_t pid = orig_fork();
    if (pid &gt; 0) {
        // parent
        LOGI(&#34;Child zygote forked substitute %d&#34;, pid);
        exit(0);
    } else if (pid == 0) {
        pid = getpid();
    } else { // pid &lt; 0
        LOGE(&#34;Failed to fork new process for app zygote&#34;);
    }
    return pid;
}
#endif
```
##### 1.2 UnshareReplace
unshare是Linux中的一个系统调用，用于将当前进程从某个namespace中分离出来，创建一个新的namespace
```cpp
int UnshareReplace(int flags) {
    // 子进程中操作的话为true，其余为false
    bool isolated_ns = (flags &amp; CLONE_NEWNS) != 0 &amp;&amp; in_child_ &amp;&amp; (isolated_ || app_zygote_);
    bool cleaned = false;
    if (isolated_ns) {
        cleaned = MaybeSwitchMntNs();
        if (cleaned &amp;&amp; no_new_ns_) {
            // We&#39;re in the &#34;cleaned&#34; ns, don&#39;t unshare new ns
            // isolated process and app zygote uses the same ns with zygote on pre-11
            // this can be detected by app
            // https://android-review.googlesource.com/c/platform/frameworks/base/&#43;/1554432
            // https://cs.android.com/android/_/android/platform/frameworks/base/&#43;/e986bc4cad9b68e1cf4aedfb3b99381cc64d0497
            if (flags == CLONE_NEWNS) return 0;
            flags &amp;= ~CLONE_NEWNS;
        }
    }
    int res = orig_unshare(flags);
    if (res == -1) return res;
    if (isolated_ns &amp;&amp; !cleaned) { // If not in a cleaned ns, try hide directly again
        HideMagisk();
    }
    return res;
}

bool MaybeSwitchMntNs() {
    // 如果ns没初始化好，直接返回
    if (!nsholder_mnt_ns_) return false;
    int fd = open(nsholder_mnt_ns_, O_RDONLY);
    if (fd &lt; 0) { // Maybe the nsholder died...
        LOGE(&#34;Can&#39;t open %s: %s&#34;, nsholder_mnt_ns_, strerror(errno));
        return false;
    }
    // 存在初始化好的ns，就切换到初始化好的ns
    int ret = setns(fd, 0);
    int err = errno;
    close(fd);
    if (ret != 0) {
        LOGE(&#34;Failed to switch ns: %s&#34;, strerror(err));
        return false;
    }
    return true;
}

void HideMagisk() {
    使用magisk自带的方式umount
    hide_unmount(magisk_tmp_);
}
```
#### 2 forkAndSpecializePre
```c
static void forkAndSpecializePre(
        JNIEnv* env, jclass, jint* _uid, jint* gid, jintArray* gids, jint* runtimeFlags,
        jobjectArray* rlimits, jint* mountExternal, jstring* seInfo, jstring* niceName,
        jintArray* fdsToClose, jintArray* fdsToIgnore, jboolean* is_child_zygote,
        jstring* instructionSet, jstring* appDataDir, jboolean* isTopApp,
        jobjectArray* pkgDataInfoList,
        jobjectArray* whitelistedDataInfoList, jboolean* bindMountAppDataDirs,
        jboolean* bindMountAppStorageDirs) {
    InitProcessState(*_uid, *is_child_zygote);
    nice_name_ = niceName;
    if (hide_isolated_) {
        no_new_ns_ = EnsureSeparatedNamespace(mountExternal, *bindMountAppDataDirs, *bindMountAppStorageDirs);
        MaybeInitNsHolder(env);
    }
}

// Maybe change the mount external mode to make sure the new process will call unshare().
// Returns true if we don&#39;t need a new ns for this process
bool EnsureSeparatedNamespace(jint* mountMode, jboolean bindMountAppDataDirs, jboolean bindMountAppStorageDirs) {
    if (*mountMode == 0) {
        // 这里和riru-unsharem模块一样，更改mountMode，强行产生新的namespace
        bool no_need_newns = bindMountAppDataDirs == JNI_FALSE &amp;&amp; bindMountAppStorageDirs == JNI_FALSE;
        LOGI(&#34;Changed mount mode from NONE to DEFAULT and %s&#34;, no_need_newns ? &#34;skip unshare&#34; : &#34;keep unshare&#34;);
        *mountMode = 1;
        return no_need_newns;
    }
    return false;
}

void MaybeInitNsHolder(JNIEnv* env) {
    if (!use_nsholder_) return;

    if (nsholder_mnt_ns_) {
        if (access(nsholder_mnt_ns_, F_OK) != 0) {
            // Maybe the nsholder died
            LOGW(&#34;access %s failed with error %s&#34;, nsholder_mnt_ns_, strerror(errno));
            if (nsholder_pid_ &gt; 0) {
                kill(nsholder_pid_, SIGKILL);
            }
            free(nsholder_mnt_ns_);
        } else { // Still alive
            return;
        }
    }

    LOGI(&#34;Starting nsholder&#34;);
    int read_fd, write_fd;
    {
        int pipe_fd[2];
        if (pipe(pipe_fd) == -1) {
            LOGE(&#34;Failed to create pipe for nsholder: %s&#34;, strerror(errno));
            return;
        } else {
            read_fd = pipe_fd[0];
            write_fd = pipe_fd[1];
        }
    }

    nsholder_pid_ = orig_fork();
    if (nsholder_pid_ &lt; 0) { // failed, cleanup
        LOGE(&#34;fork nsholder failed: %s&#34;, strerror(errno));
        close(read_fd);
        close(write_fd);
        nsholder_mnt_ns_ = nullptr;
    } else if (nsholder_pid_ == 0) { // child
        close(read_fd);
        if (orig_unshare(CLONE_NEWNS) == -1) {
            LOGE(&#34;nsholder: failed to clone new ns: %s&#34;, strerror(errno));
            WriteIntAndClose(write_fd, 1);
            exit(1);
        }
        LOGI(&#34;Hiding Magisk in nsholder %d...&#34;, getpid());
        HideMagisk();
        LOGI(&#34;Unmounted magisk file system.&#34;);

        // Change process name
        {
            jstring name = env-&gt;NewStringUTF(sizeof(void*) == 8 ? &#34;nsholder64&#34; : &#34;nsholder32&#34;);
            SetProcessName(env, name);
            env-&gt;DeleteLocalRef(name);
        }

        // We&#39;re in the &#34;cleaned&#34; ns, notify the zygote we&#39;re ready and stop us
        WriteIntAndClose(write_fd, 0);

        // All done, but we should keep alive, because we need to keep the namespace
        // If a fd references the namespace, the ns won&#39;t be destroyed
        // but we need to open a fd in zygote, and Google don&#39;t want we opened new fd across fork,
        // zygote will abort with error like &#34;Not whitelisted (41): mnt:[4026533391]&#34;
        // We can manually call the Zygote.nativeAllowAcrossFork(), but this can be detected by app;
        // or, we can use the &#34;fdsToIgnore&#34; argument, but for usap, forkApp() haven&#39;t the argument.
        // To keep it simple, just let fd not opened in zygote
        for (;;) {
            // Note: SIGSTOP can&#39;t stop us here when magisk hide is enabled
            // I think the magisk hiding catches our SIGSTOP and not handle it properly (didn&#39;t resend the signal)
            // raise(SIGSTOP);
            pause();
            LOGW(&#34;nsholder wakes up unexpectedly, sleep again&#34;);
        }
    } else { // parent, wait the nsholder enter a &#34;clean&#34; ns
        close(write_fd);
        int status = ReadIntAndClose(read_fd);
        if (status == 0) {
            kill(nsholder_pid_, SIGSTOP); // make nsholder is stopped again
            char mnt[32];
            snprintf(mnt, sizeof(mnt), &#34;/proc/%d/ns/mnt&#34;, nsholder_pid_);
            LOGI(&#34;The nsholder is cleaned and stopped, mnt_ns is %s&#34;, mnt);
            nsholder_mnt_ns_ = strdup(mnt);
            return;
        } else {
            LOGE(&#34;Unexpected status %d received from the nsholder&#34;, status);

            kill(nsholder_pid_, SIGKILL);
            nsholder_pid_ = -1;
            nsholder_mnt_ns_ = nullptr;
            use_nsholder_ = false;
        }
    }
}

```
#### 3 forkAndSpecializePost
```c
static void forkAndSpecializePost(JNIEnv* env, jclass, jint res) {
#if USE_NEW_APP_ZYGOTE_MAGIC
    if (res == 0 &amp;&amp; app_zygote_ &amp;&amp; magic_handle_app_zygote_ &amp;&amp; nice_name_ &amp;&amp; *nice_name_) {
        // forkAndSpecialize() changed the name of the current thread, not the process
        // For normal processes, the process name will be changed in ZygoteConnection.handleChildProc()
        // And use binder to communicate with system_server, which will create a binder thread pool.
        // This triggers MagiskHide to detach and unmount Magisk filesystems.
        // But for App Zygotes, after handleChildProc() there is no thread to start (VM daemon threads had started before)
        // So MagiskHide won&#39;t detach and won&#39;t unmount Magisk.
        // In this case, we manually set process name, and the start of VM daemon threads will trigger MagiskHide.
        // We only check this because app zygote won&#39;t be started with USAP.
        SetProcessName(env, *nice_name_);
#if 0
        // Just in case some ROMs have broken art implementation that won&#39;t start daemon threads...
        pthread_t th;
        int r = pthread_create(&amp;th, nullptr, DoNothing, nullptr);
        if (r == 0)
            r = pthread_join(th, nullptr);
        if (r)
            LOGE(&#34;Failed to create/join thread for app zygote&#34;);
#endif
    }
#endif
    ClearProcessState();
    if (res == 0) {
        ClearHooks();
        AllowUnload();
    }
}
```
#### 4 specializeAppProcessPre
```c
static void specializeAppProcessPre(
        JNIEnv *env, jclass clazz, jint *uid, jint *gid, jintArray *gids, jint *runtimeFlags,
        jobjectArray *rlimits, jint *mountExternal, jstring *seInfo, jstring *niceName,
        jboolean *startChildZygote, jstring *instructionSet, jstring *appDataDir,
        jboolean *isTopApp, jobjectArray *pkgDataInfoList, jobjectArray *whitelistedDataInfoList,
        jboolean *bindMountAppDataDirs, jboolean *bindMountAppStorageDirs) {
    InitProcessState(*uid, *startChildZygote);
    if (hide_isolated_)
        no_new_ns_ = EnsureSeparatedNamespace(mountExternal, *bindMountAppDataDirs, *bindMountAppStorageDirs);
}
```
#### 5 specializeAppProcessPost
```c
static void specializeAppProcessPost(JNIEnv *env, jclass clazz) {
    ClearProcessState();
    ClearHooks();
    AllowUnload();
}
```

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/riru-momohider%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90/  

