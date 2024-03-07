# Zygisk源码阅读

基于Magisk v25.0

### 一、Zygisk注入

#### 1. magic_mount挂载app_process
magic_mount的原理是挂载tmpfs作为目录，并bind_mount原有的和修改后的文件，而zygisk的处理逻辑也在这个函数当中，整个过程是在magiskd这个系统守护进程中处理的
```c++
// native/jni/core/module.cpp

void magic_mount() {
    // bind_mount的过程
    ......

    // Mount on top of modules to enable zygisk
    if (zygisk_enabled) {
        string zygisk_bin = MAGISKTMP + "/" ZYGISKBIN;
        // zygisk_bin对应的是/dev/xxxx/zygisk
        mkdir(zygisk_bin.data(), 0);
        mount_zygisk(32)
        mount_zygisk(64)
    }
}

// native/jni/core/module.cpp

int app_process_32 = -1;
int app_process_64 = -1;

#define mount_zygisk(bit)                                                               \
if (access("/system/bin/app_process" #bit, F_OK) == 0) {                                \
    app_process_##bit = xopen("/system/bin/app_process" #bit, O_RDONLY | O_CLOEXEC);    \
    string zbin = zygisk_bin + "/app_process" #bit;                                     \
    string dbin = zygisk_bin + "/magisk" #bit;                                          \
    string mbin = MAGISKTMP + "/magisk" #bit;                                           \
    int src = xopen(mbin.data(), O_RDONLY | O_CLOEXEC);                                 \
    int out = xopen(zbin.data(), O_CREAT | O_WRONLY | O_CLOEXEC, 0);                    \
    xsendfile(out, src, nullptr, INT_MAX);                                              \
    close(out);                                                                         \
    out = xopen(dbin.data(), O_CREAT | O_WRONLY | O_CLOEXEC, 0);                        \
    lseek(src, 0, SEEK_SET);                                                            \
    xsendfile(out, src, nullptr, INT_MAX);                                              \
    close(out);                                                                         \
    close(src);                                                                         \
    clone_attr("/system/bin/app_process" #bit, zbin.data());                            \
    clone_attr("/system/bin/app_process" #bit, dbin.data());                            \
    bind_mount(zbin.data(), "/system/bin/app_process" #bit);                            \
}
```
从mount_zygisk的过程中可以看出做了三件事
1. 打开原先的app_process(32|64)文件，fd保存到app_process_(32|64)中
2. 把magisk自己的可执行文件magisk(32|64)(mbin)复制到zygisk目录下的app_process(32|64)(zbin)，此处用了sendfile直接在内核中复制文件
   >sendfile函数在两个文件描写叙述符之间直接传递数据(完全在内核中操作，传送)，从而避免了内核缓冲区数据和用户缓冲区数据之间的拷贝，操作效率非常高，被称之为零拷贝
3. 把zygisk目录下app_process(实际上是magisk文件)通过bind_mount的方式挂载到到原先的/system/bin/app_process(32|64)上

那么这样一来，/system/bin下的app_process就变成了magisk文件，而原先的app_process的fd被magiskd持有。执行app_process的时候就是执行了magisk

#### 2. app_process_main
首先magisk可执行文件的入口main在native/jni/core/applets.cpp里面，app_process实际上可以看作是它的一个applet（类似su、resetprop这些，不过被隐藏了，因为这是个内部功能）

main启动会判断自己的文件名(argv0)，如果是app_process就会调用app_process_main，如下
```c++
// native\jni\core\applets.cpp

int main(int argc, char *argv[]) {
    enable_selinux();
    cmdline_logging();
    init_argv0(argc, argv);

    string_view base = basename(argv[0]);

    // app_process is actually not an applet
    if (str_starts(base, "app_process")) {
        return app_process_main(argc, argv);
    }

    umask(0);
    if (base == "magisk" || base == "magisk32" || base == "magisk64") {
        if (argc > 1 && argv[1][0] != '-') {
            // Calling applet via magisk [applet] args
            --argc;
            ++argv;
        } else {
            return magisk_main(argc, argv);
        }
    }

    return call_applet(argc, argv);
}

// native/jni/zygisk/main.cpp
// Entrypoint for app_process overlay
int app_process_main(int argc, char *argv[]) {
    android_logging();
    char buf[256];

    bool zygote = false;
    if (auto fp = open_file("/proc/self/attr/current", "r")) {
        fscanf(fp.get(), "%s", buf);
        zygote = (buf == "u:r:zygote:s0"sv);
    }

    if (!zygote) {
        // ...
    }

    if (int socket = connect_daemon(); socket >= 0) {
        do {
            write_int(socket, ZYGISK_REQUEST);
            write_int(socket, ZYGISK_SETUP);

            if (read_int(socket) != 0)
                break;

            int app_proc_fd = recv_fd(socket);
            if (app_proc_fd < 0)
                break;

            string tmp = read_string(socket);
#if defined(__LP64__)
            string lib = tmp + "/" ZYGISKBIN "/zygisk.app_process64.1.so";
#else
            string lib = tmp + "/" ZYGISKBIN "/zygisk.app_process32.1.so";
#endif
            if (char *ld = getenv("LD_PRELOAD")) {
                char env[256];
                sprintf(env, "%s:%s", ld, lib.data());
                setenv("LD_PRELOAD", env, 1);
            } else {
                setenv("LD_PRELOAD", lib.data(), 1);
            }
            setenv(INJECT_ENV_1, "1", 1);
            setenv("MAGISKTMP", tmp.data(), 1);

            close(socket);

            snprintf(buf, sizeof(buf), "/proc/self/fd/%d", app_proc_fd);
            fcntl(app_proc_fd, F_SETFD, FD_CLOEXEC);
            execve(buf, argv, environ);
        } while (false);

        close(socket);
    }

    // If encountering any errors, unmount and execute the original app_process
    xreadlink("/proc/self/exe", buf, sizeof(buf));
    xumount2("/proc/self/exe", MNT_DETACH);
    execve(buf, argv, environ);
    return 1;
}
```
逻辑中会区分是否是zygote的情况，这里我们只关注zygote

首先连接到magiskd，然后发送ZYGISK_SETUP，会得到一个fd和一个字符串，观察对应的处理
```c++
// native/jni/zygisk/entry.cpp
void zygisk_handler(int client, const sock_cred *cred) {
    int code = read_int(client);
    char buf[256];
    switch (code) {
    case ZYGISK_SETUP:
        setup_files(client, cred);
        break;
        // ...
    }
  // ...
}

static void setup_files(int client, const sock_cred *cred) {
    LOGD("zygisk: setup files for pid=[%d]\n", cred->pid);

    char buf[256]; 
    // 请求者的可执行程序路径 (/proc/pid/exec) ，一般是/system/bin/app_process[32|64]
    if (!get_exe(cred->pid, buf, sizeof(buf))) {
        write_int(client, 1);
        return;
    }

    bool is_64_bit = str_ends(buf, "64");
    write_int(client, 0);
    // 发送持有的真正的 app_process文件fd
    send_fd(client, is_64_bit ? app_process_64 : app_process_32); 

    string path = MAGISKTMP + "/" ZYGISKBIN "/zygisk." + basename(buf);
    // 复制buf路径的文件到MAGISKTMP/zygisk/zygisk.app_process[32|64].1.so
    cp_afc(buf, (path + ".1.so").data()); 
    cp_afc(buf, (path + ".2.so").data());
    // 发送MAGISKTMP路径
    write_string(client, MAGISKTMP); 
}
```
从代码中可以看到
- fd对应的是原始app_process文件的fd，可以用来exec
- string对应的是magisktmp路径

其中还有一个操作是将/system/bin/app_process文件复制到MAGISKTMP/zygisk/zygisk.app_process[32|64].1.so上

回到app_process_main，后面做了几件事
1. 把MAGISKTMP/zygisk/zygisk.app_process(32|64).1.so、MAGISKTMP/zygisk/zygisk.app_process(32|64).2.so写入环境变量LD_PRELOAD里
   >LD_PRELOAD是Linux系统中的一个环境变量，它可以影响程序的运行时的链接（Runtimelinker），它允许你定义在程序运行前优先加载的动态链接库，这样，在程序运行时会优先使用动态库中的符号而不是系统默认的符号
2. 设置INJECT_ENV_1、MAGISKTMP_ENV到系统变量中
3. fcntl(app_proc_fd, F_SETFD, FD_CLOEXEC)表示当执行exec时关闭fd，这里的app_proc_fd是原始的fd
4. fexecve开始执行原生的app_process，此时LD_PRELOAD已经被替换

目前为止，可以看到zygisk的注入思路，通过类似hook的方式hook app_process，用LD_PRELOAD的方式完成自身注入，而不是像riru那样通过修改native_bridge或者xposed直接修改app_process

再细看下LD_PRELOAD的执行逻辑
```c++
// linker_main.cpp

static ElfW(Addr) linker_main(KernelArgumentBlock& args, const char* exe_to_load) {
  ProtectedDataGuard guard;

  // These should have been sanitized by __libc_init_AT_SECURE, but the test
  // doesn't cost us anything.
  const char* ldpath_env = nullptr;
  const char* ldpreload_env = nullptr;
  if (!getauxval(AT_SECURE)) {
    ldpath_env = getenv("LD_LIBRARY_PATH");
    if (ldpath_env != nullptr) {
      INFO("[ LD_LIBRARY_PATH set to \"%s\" ]", ldpath_env);
    }
    ldpreload_env = getenv("LD_PRELOAD");
    if (ldpreload_env != nullptr) {
      INFO("[ LD_PRELOAD set to \"%s\" ]", ldpreload_env);
    }
  }
  ......

  // Use LD_LIBRARY_PATH and LD_PRELOAD (but only if we aren't setuid/setgid).
  parse_LD_LIBRARY_PATH(ldpath_env);
  parse_LD_PRELOAD(ldpreload_env);

  std::vector<android_namespace_t*> namespaces = init_default_namespaces(exe_info.path.c_str());

  if (!si->prelink_image()) __linker_cannot_link(g_argv[0]);

  // add somain to global group
  si->set_dt_flags_1(si->get_dt_flags_1() | DF_1_GLOBAL);
  // ... and add it to all other linked namespaces
  for (auto linked_ns : namespaces) {
    if (linked_ns != &g_default_namespace) {
      linked_ns->add_soinfo(somain);
      somain->add_secondary_namespace(linked_ns);
    }
  }

  linker_setup_exe_static_tls(g_argv[0]);

  // Load ld_preloads and dependencies.
  std::vector<const char*> needed_library_name_list;
  size_t ld_preloads_count = 0;

  for (const auto& ld_preload_name : g_ld_preload_names) {
    needed_library_name_list.push_back(ld_preload_name.c_str());
    ++ld_preloads_count;
  }
  ......

  if (needed_libraries_count > 0 &&
      !find_libraries(&g_default_namespace,
                      si,
                      needed_library_names,
                      needed_libraries_count,
                      nullptr,
                      &g_ld_preloads,
                      ld_preloads_count,
                      RTLD_GLOBAL,
                      nullptr,
                      true /* add_as_children */,
                      true /* search_linked_namespaces */,
                      &namespaces)) {
    __linker_cannot_link(g_argv[0]);
  } else if (needed_libraries_count == 0) {
    if (!si->link_image(SymbolLookupList(si), si, nullptr, nullptr)) {
      __linker_cannot_link(g_argv[0]);
    }
    si->increment_ref_count();
  }

  linker_finalize_static_tls();
  __libc_init_main_thread_final();

  if (!get_cfi_shadow()->InitialLinkDone(solist)) __linker_cannot_link(g_argv[0]);

  si->call_pre_init_constructors();
  si->call_constructors();
  ......
  return entry;
}

static void parse_LD_PRELOAD(const char* path) {
  g_ld_preload_names.clear();
  if (path != nullptr) {
    // We have historically supported ':' as well as ' ' in LD_PRELOAD.
    g_ld_preload_names = android::base::Split(path, " :");
    g_ld_preload_names.erase(std::remove_if(g_ld_preload_names.begin(), g_ld_preload_names.end(),
                                            [](const std::string& s) { return s.empty(); }),
                             g_ld_preload_names.end());
  }
}
```
linker_main这里关于LD_PRELOAD做了三件事
1. 获取了环境变量中的值ldpreload_env = getenv("LD_PRELOAD");
2. parse_LD_PRELOAD(ldpreload_env);解析LD_PRELOAD的值写入全局变量g_ld_preload_names
3. 遍历g_ld_preload_names添加至needed_library_name_list
4. so加载流程：find_library、call_pre_init_constructors、call_constructors调用DT_INIT、DT_INIT_ARRAY段的函数

### 二、Zygisk加载
```c++
// native/jni/zygisk/entry.cpp

__attribute__((constructor))
static void zygisk_init() {
    if (getenv(INJECT_ENV_2)) {
        // Return function pointer to first stage
        char buf[128];
        snprintf(buf, sizeof(buf), "%p", &second_stage_entry);
        setenv(SECOND_STAGE_PTR, buf, 1);
    } else if (getenv(INJECT_ENV_1)) {
        first_stage_entry();
    }
}
```
这里根据系统变量决定不同阶段处理方式
#### 2.1 一阶段
正常加载时会加载第一阶段，这是在写入LD_PRELOAD时完成环境变量设置
```c++
static void first_stage_entry() {
    android_logging();
    ZLOGD("inject 1st stage\n");

    char *ld = getenv("LD_PRELOAD");
    char tmp[128];
    strlcpy(tmp, getenv("MAGISKTMP"), sizeof(tmp));
    char *path;
    if (char *c = strrchr(ld, ':')) {
        *c = '\0';
        setenv("LD_PRELOAD", ld, 1);  // Restore original LD_PRELOAD
        path = strdup(c + 1);
    } else {
        unsetenv("LD_PRELOAD");
        path = strdup(ld);
    }
    unsetenv(INJECT_ENV_1);
    unsetenv("MAGISKTMP");
    sanitize_environ();

    char *num = strrchr(path, '.') - 1;

    // Update path to 2nd stage lib
    *num = '2';

    // Load second stage
    setenv(INJECT_ENV_2, "1", 1);
    void *handle = dlopen(path, RTLD_LAZY);
    remap_all(path);

    // Revert path to 1st stage lib
    *num = '1';

    // Run second stage entry
    char *env = getenv(SECOND_STAGE_PTR);
    decltype(&second_stage_entry) second_stage;
    sscanf(env, "%p", &second_stage);
    second_stage(handle, tmp, path);
}
```
一阶段的作用，环境清理（重置env）、获取LD_PRELOAD路径并dlopen、开启二阶段，这种方式和riru很类似，native_bridge加载的libriruloader.so只是一个loader的作用，负责load libriru.so后被处理

dlopen的path对应的是zygisk.app_process.[32|64].2.so，加载完成后调用remap_all
```c++
void remap_all(const char *name) {
    vector<map_info> maps = find_maps(name);
    for (map_info &info : maps) { 
        // 遍历 maps 中指定文件名的映射信息
        void *addr = reinterpret_cast<void *>(info.start);
        size_t size = info.end - info.start;
        // 映射和目标同样大小的可写内存
        void *copy = xmmap(nullptr, size, PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0); 
        if ((info.perms & PROT_READ) == 0) {
            // 如果目标不可读，让其可读
            mprotect(addr, size, PROT_READ); 
        }
        // 复制目标的内存到新的映射
        memcpy(copy, addr, size); 
        // 用新的匿名映射覆盖到原先目标的位置
        mremap(copy, size, size, MREMAP_MAYMOVE | MREMAP_FIXED, addr); 
        // 恢复权限使其和目标一致
        mprotect(addr, size, info.perms); 
    }
}
```
maps文件处理，把path对应的映射全部重新处理成匿名，目的应该是为了隐藏
#### 2.2 二阶段
```c++
static void second_stage_entry(void *handle, const char *tmp, char *path) {
    self_handle = handle;
    MAGISKTMP = tmp;
    unsetenv(INJECT_ENV_2);
    unsetenv(SECOND_STAGE_PTR);

    zygisk_logging();
    ZLOGD("inject 2nd stage\n");
    hook_functions();

    // First stage will be unloaded before the first fork
    first_stage_path = path;
}
```
核心函数hook_functions
```c++
// native\jni\zygisk\hook.cpp

#define XHOOK_REGISTER_SYM(PATH_REGEX, SYM, NAME) \
    hook_register(PATH_REGEX, SYM, (void*) new_##NAME, (void **) &old_##NAME)

#define XHOOK_REGISTER(PATH_REGEX, NAME) \
    XHOOK_REGISTER_SYM(PATH_REGEX, #NAME, NAME)

#define ANDROID_RUNTIME ".*/libandroid_runtime.so$"
#define APP_PROCESS     "^/system/bin/app_process.*"

void hook_functions() {
#if MAGISK_DEBUG
    // xhook_enable_debug(1);
    xhook_enable_sigsegv_protection(0);
#endif
    default_new(xhook_list);
    default_new(jni_hook_list);
    default_new(jni_method_map);

    XHOOK_REGISTER(ANDROID_RUNTIME, fork);
    XHOOK_REGISTER(ANDROID_RUNTIME, unshare);
    XHOOK_REGISTER(ANDROID_RUNTIME, jniRegisterNativeMethods);
    XHOOK_REGISTER(ANDROID_RUNTIME, selinux_android_setcontext);
    XHOOK_REGISTER_SYM(ANDROID_RUNTIME, "__android_log_close", android_log_close);
    hook_refresh();

    // Remove unhooked methods
    xhook_list->erase(
            std::remove_if(xhook_list->begin(), xhook_list->end(),
            [](auto &t) { return *std::get<2>(t) == nullptr;}),
            xhook_list->end());

    if (old_jniRegisterNativeMethods == nullptr) {
        ZLOGD("jniRegisterNativeMethods not hooked, using fallback\n");

        // android::AndroidRuntime::setArgv0(const char*, bool)
        XHOOK_REGISTER_SYM(APP_PROCESS, "_ZN7android14AndroidRuntime8setArgv0EPKcb", setArgv0);
        hook_refresh();

        // We still need old_jniRegisterNativeMethods as other code uses it
        // android::AndroidRuntime::registerNativeMethods(_JNIEnv*, const char*, const JNINativeMethod*, int)
        constexpr char sig[] = "_ZN7android14AndroidRuntime21registerNativeMethodsEP7_JNIEnvPKcPK15JNINativeMethodi";
        *(void **) &old_jniRegisterNativeMethods = dlsym(RTLD_DEFAULT, sig);
    }
}
```
我们知道，Zygisk和Riru最大的不同在于它有一个「排除列表」，被排除的进程一定不会注入，而如果像Riru那样直接在zygote进程中加载所有模块显然是做不到的，一旦Zygote加载了模块，它想干什么就不是Zygisk能管的了。但是又要让模块有修改forkAndSpecialize参数的能力，而这个方法调用fork前是在zygote进程中执行的，因此好像必须在zygote中执行模块的代码。这么看来Zygisk一定用了一些巧妙的手段处理

注意到Zygisk hook了很多关键的函数，我们先看看fork
```c++
// Skip actual fork and return cached result if applicable
// Also unload first stage zygisk if necessary
DCL_HOOK_FUNC(int, fork) {
    unload_first_stage();
    return (g_ctx && g_ctx->pid >= 0) ? g_ctx->pid : old_fork();
}

#define DCL_HOOK_FUNC(ret, func, ...) \
ret (*old_##func)(__VA_ARGS__);       \
ret new_##func(__VA_ARGS__)
```
如果g_ctx存在且pid大于0返回pid，否则则调用原始fork，那这是什么含义呢？
```c++
// Current context
HookContext *g_ctx;
```
这是一个HookContext类型的全局变量
```c++
// native\jni\zygisk\hook.cpp

struct HookContext {
    JNIEnv *env;
    union {
        AppSpecializeArgsImpl *args;
        ServerSpecializeArgsImpl *server_args;
        void *raw_args;
    };
    const char *process;
    int pid;
    bitset<FLAG_MAX> flags;
    AppInfo info;
    vector<ZygiskModule> modules;

    HookContext() : pid(-1), info{} {}

    static void close_fds();
    void unload_zygisk();

    DCL_PRE_POST(fork)
    void run_modules_pre(const vector<int> &fds);
    void run_modules_post();
    DCL_PRE_POST(nativeForkAndSpecialize)
    DCL_PRE_POST(nativeSpecializeAppProcess)
    DCL_PRE_POST(nativeForkSystemServer)
};

#define DCL_PRE_POST(name) \
void name##_pre();         \
void name##_post();
```
DCL_PRE_POST声明了fork的两个函数
- fork_pre
- fork_post
```c++
// Do our own fork before loading any 3rd party code
// First block SIGCHLD, unblock after original fork is done
void HookContext::fork_pre() {
    g_ctx = this;
    sigmask(SIG_BLOCK, SIGCHLD);
    // this->pid, 即 g_ctx->pid
    pid = old_fork(); 
}
```
可见，fork_pre中修改了全局变量g_ctx为this，屏蔽SIGCHLD信号，并主动调用了原先的fork函数。注释中说，这是要在加载第三方代码（模块）前先进行fork，看看fork_pre的调用场景
```c++
void HookContext::nativeForkSystemServer_pre() {
    fork_pre();
    flags[SERVER_SPECIALIZE] = true;
    if (pid == 0) {
        ZLOGV("pre  forkSystemServer\n");
        run_modules_pre(remote_get_info(1000, "system_server", &info));
        close_fds();
        android_logging();
    }
}

void HookContext::nativeForkAndSpecialize_pre() {
    fork_pre();
    flags[FORK_AND_SPECIALIZE] = true;
    if (pid == 0) {
        nativeSpecializeAppProcess_pre();
    }
}
```
梳理下流程，根据Android应用启动流程，zygote在接收到启动新进程的socket通信请求后会调用nativeForkAndSpecialize从而调用fork启动新进程，而被hook之后先调用了nativeForkAndSpecialize_pre，在这个函数中做了fork，再调用nativeForkAndSpecialize，也就是说fork被提前了

这里存在一个问题，nativeForkAndSpecialize本身调用的fork会发生什么呢？看看上面的fork函数
```c++
(g_ctx && g_ctx->pid >= 0) ? g_ctx->pid : old_fork();
```
hook后的fork会先判断g_ctx->pid的值是否为0，若为0表示它没做过fork，进而调用原本的fork函数，若不为0就直接返回pid，这个是子进程的pid值，说明nativeForkAndSpecialize的第二次fork不会调用真正的fork函数

提前fork的作用是什么呢？看下nativeForkAndSpecialize_pre
```c++
void HookContext::nativeSpecializeAppProcess_pre() {
    g_ctx = this;
    state[APP_SPECIALIZE] = true;
    process = env->GetStringUTFChars(args->nice_name, nullptr);
    if (state[FORK_AND_SPECIALIZE]) {
        ZLOGV("pre  forkAndSpecialize [%s]\n", process);
    } else {
        ZLOGV("pre  specialize [%s]\n", process);
    }

    vector<int> module_fds;
    int fd = remote_get_info(args->uid, process, &flags, module_fds);
    if ((flags & UNMOUNT_MASK) == UNMOUNT_MASK) {
        ZLOGI("[%s] is on the denylist\n", process);
        state[DO_UNMOUNT] = true;
    } else if (fd >= 0) {
        // 加载模块
        run_modules_pre(module_fds);
    }
    close(fd);

    close_fds();
    android_logging();
}
```
它调用的nativeSpecializeAppProcess_pre会做zygisk模块的加载，也就是说zygisk为了让fork后的进程加载模块，就得提前fork，这样还在它自己的代码空间，它可以根据denylist决定是否加载模块

zygisk这种在fork后加载模块的方式使得它可以在不重启的情况下更新lsposed代码

fork_post没有特殊的处理逻辑，zygisk环境清理
```c++
void HookContext::fork_post() {
    sigmask(SIG_UNBLOCK, SIGCHLD);
    g_ctx = nullptr;
    unload_zygisk();
}

void HookContext::unload_zygisk() {
    if (state[CAN_DLCLOSE]) {
        // Do NOT call the destructor
        operator delete(jni_method_map);
        // Directly unmap the whole memory block
        jni_hook::memory_block::release();

        // Strip out all API function pointers
        for (auto &m : modules) {
            memset(&m.api, 0, sizeof(m.api));
        }

        new_daemon_thread(reinterpret_cast<thread_entry>(&dlclose), self_handle);
    }
}
```
