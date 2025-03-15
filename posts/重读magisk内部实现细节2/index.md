# 重读Magisk内部实现细节2


### 前言
承接上文，经过Magisk修补后的boot.img在启动引导过程中为了实现Root的功能很关键的一步在于patch了init.rc和sepolicy文件，在Magisk正式把init的执行权交由二阶段的原生init之后，便引导了Magisk deamon的启动
### 一、Magisk是如何工作的？
#### 1 init.rc
首先了解下init.rc，它是一个配置文件，内部由Android初始化语言（Android Init Language）编写的脚本，主要包含五种类型语句：Action、Command、Service、Option 和 Import，关键的两种类型是Action和Service
- Action
    以 “on” 关键字开头的action list
    ```shell
    //触发阶段
    on early-init                           
        # Disable sysrq from keyboard      
        write /proc/1/oom_score_adj -1000

        # Set the security context of /adb_keys if present.
        restorecon /adb_keys
        ... ...

        # cgroup for system_server and surfaceflinger
        mkdir /dev/memcg/system 0550 system system

        start ueventd
        
        exec_start apexd-bootstrap
    ```
    Action简单理解是定义当触发XX阶段时应该执行的动作
- Service
    ```shell
    service ueventd /system/bin/ueventd   
        class core
        critical
        seclabel u:r:ueventd:s0
        shutdown critical
    ```
    Service定义了进程，包括名称、权限、执行用户等等，一般都是由init进程通过fork产生子进程来启动

从源码上来看看init.rc是如何被解析并执行其中的类型语句的（以Android11的源码为例）
```c&#43;&#43;
// system/core/init/init.cpp
static void LoadBootScripts(ActionManager&amp; action_manager, ServiceList&amp; service_list) {
    // 建立parser对象，传入的是ActionManager和ServiceList，对应init.rc的action和service
    Parser parser = CreateParser(action_manager, service_list);
    // 优先从属性中获取rc文件的path，正常情况下都是为空
    std::string bootscript = GetProperty(&#34;ro.boot.init_rc&#34;, &#34;&#34;);
    // 也就是在android11中init.rc都是存在/system/etc/init/hw/init.rc这个路径下
    if (bootscript.empty()) {
        parser.ParseConfig(&#34;/system/etc/init/hw/init.rc&#34;);
        if (!parser.ParseConfig(&#34;/system/etc/init&#34;)) {
            late_import_paths.emplace_back(&#34;/system/etc/init&#34;);
        }
        // late_import is available only in Q and earlier release. As we don&#39;t
        // have system_ext in those versions, skip late_import for system_ext.
        parser.ParseConfig(&#34;/system_ext/etc/init&#34;);
        if (!parser.ParseConfig(&#34;/vendor/etc/init&#34;)) {
            late_import_paths.emplace_back(&#34;/vendor/etc/init&#34;);
        }
        if (!parser.ParseConfig(&#34;/odm/etc/init&#34;)) {
            late_import_paths.emplace_back(&#34;/odm/etc/init&#34;);
        }
        if (!parser.ParseConfig(&#34;/product/etc/init&#34;)) {
            late_import_paths.emplace_back(&#34;/product/etc/init&#34;);
        }
    } else {
        parser.ParseConfig(bootscript);
    }
}

// system/core/init/parser.cpp
bool Parser::ParseConfig(const std::string&amp; path) {
    if (is_dir(path.c_str())) {
        return ParseConfigDir(path);
    }
    // 只从文件角度来看看
    auto result = ParseConfigFile(path);
    if (!result.ok()) {
        LOG(INFO) &lt;&lt; result.error();
    }
    return result.ok();
}

Result&lt;void&gt; Parser::ParseConfigFile(const std::string&amp; path) {
    LOG(INFO) &lt;&lt; &#34;Parsing file &#34; &lt;&lt; path &lt;&lt; &#34;...&#34;;
    android::base::Timer t;
    // 读取文件内容
    auto config_contents = ReadFile(path);
    if (!config_contents.ok()) {
        return Error() &lt;&lt; &#34;Unable to read config file &#39;&#34; &lt;&lt; path
                       &lt;&lt; &#34;&#39;: &#34; &lt;&lt; config_contents.error();
    }

    // 将文件内容解析写入Parser类
    ParseData(path, &amp;config_contents.value());

    LOG(VERBOSE) &lt;&lt; &#34;(Parsing &#34; &lt;&lt; path &lt;&lt; &#34; took &#34; &lt;&lt; t &lt;&lt; &#34;.)&#34;;
    return {};
}
```
以上这些步骤主要是init进程搜索init.rc并逐行解析init.rc文件，将文件中的action和service和传入的ActionManager和ServiceList关联起来等待后续触发
```c&#43;&#43;
// system/core/init/init.cpp
ActionManager&amp; am = ActionManager::GetInstance();
ServiceList&amp; sm = ServiceList::GetInstance();
// 完成init.rc解析与绑定
LoadBootScripts(am, sm);

// Turning this on and letting the INFO logging be discarded adds 0.2s to
// Nexus 9 boot time, so it&#39;s disabled by default.
if (false) DumpState();

// Make the GSI status available before scripts start running.
auto is_running = android::gsi::IsGsiRunning() ? &#34;1&#34; : &#34;0&#34;;
SetProperty(gsi::kGsiBootedProp, is_running);
auto is_installed = android::gsi::IsGsiInstalled() ? &#34;1&#34; : &#34;0&#34;;
SetProperty(gsi::kGsiInstalledProp, is_installed);
if (android::gsi::IsGsiRunning()) {
    std::string dsu_slot;
    if (android::gsi::GetActiveDsu(&amp;dsu_slot)) {
        SetProperty(gsi::kDsuSlotProp, dsu_slot);
    }
}
// 挂载触发时机
am.QueueBuiltinAction(SetupCgroupsAction, &#34;SetupCgroups&#34;);
am.QueueBuiltinAction(SetKptrRestrictAction, &#34;SetKptrRestrict&#34;);
am.QueueBuiltinAction(TestPerfEventSelinuxAction, &#34;TestPerfEventSelinux&#34;);
am.QueueBuiltinAction(ConnectEarlyStageSnapuserdAction, &#34;ConnectEarlyStageSnapuserd&#34;);
am.QueueEventTrigger(&#34;early-init&#34;);
......
// Trigger all the boot actions to get us started.
am.QueueEventTrigger(&#34;init&#34;);

while (true) {
    ......
    // 轮询监听，触发指令
    if (!(prop_waiter_state.MightBeWaiting() || Service::is_exec_service_running())) {
        am.ExecuteOneCommand();
        // If there&#39;s more work to do, wake up again immediately.
        if (am.HasMoreCommands()) {
            next_action_time = boot_clock::now();
        }
    }
    ......
}
```
这一步将设置触发点并轮询监听来触发对应action，触发点包括early-init，init，late-init这三大主触发点，还包括其他细分的自触发点，可以从init.rc文件中看出
```shell
on late-init
    trigger early-fs

    # Mount fstab in init.{$device}.rc by mount_all command. Optional parameter
    # &#39;--early&#39; can be specified to skip entries with &#39;latemount&#39;.
    # /system and /vendor must be mounted by the end of the fs stage,
    # while /data is optional.
    trigger fs
    trigger post-fs

    # Mount fstab in init.{$device}.rc by mount_all with &#39;--late&#39; parameter
    # to only mount entries with &#39;latemount&#39;. This is needed if &#39;--early&#39; is
    # specified in the previous mount_all command on the fs stage.
    # With /system mounted and properties form /system &#43; /factory available,
    # some services can be started.
    trigger late-fs

    # Now we can mount /data. File encryption requires keymaster to decrypt
    # /data, which in turn can only be loaded when system properties are present.
    trigger post-fs-data

    # Should be before netd, but after apex, properties and logging is available.
    trigger load_bpf_programs

    # Now we can start zygote for devices with file based encryption
    trigger zygote-start

    # Remove a file to wake up anything waiting for firmware.
    trigger firmware_mounts_complete

    trigger early-boot
    trigger boot

on post-fs-data

    mark_post_data

    # Start checkpoint before we touch data
    exec - system system -- /system/bin/vdc checkpoint prepareCheckpoint

    # We chown/chmod /data again so because mount is run as root &#43; defaults
    chown system system /data
    chmod 0771 /data
    # We restorecon /data in case the userdata partition has been reset.
    restorecon /data

    # Make sure we have the device encryption key.
    installkey /data

    # Start bootcharting as soon as possible after the data partition is
    # mounted to collect more data.
    mkdir /data/bootchart 0755 shell shell encryption=Require
    bootchart start
```
可以看到，在init进程初始化完成之后，会进行各种子阶段的初始化行为

#### 2 magisk core
了解完init.rc的解析、触发时机之后，再回头看Magisk对init.rc的patch
```c&#43;&#43;
constexpr char MAGISK_RC[] =
&#34;\n&#34;

// 在post-fs-data阶段执行magisk进行，并传参post-fs-data
&#34;on post-fs-data\n&#34;
&#34;    start logd\n&#34;
&#34;    rm &#34; UNBLOCKFILE &#34;\n&#34;
&#34;    start %2$s\n&#34;
&#34;    wait &#34; UNBLOCKFILE &#34; &#34; str(POST_FS_DATA_WAIT_TIME) &#34;\n&#34;
&#34;    rm &#34; UNBLOCKFILE &#34;\n&#34;
&#34;\n&#34;

&#34;service %2$s %1$s/magisk --post-fs-data\n&#34;
&#34;    user root\n&#34;
&#34;    seclabel u:r:&#34; SEPOL_PROC_DOMAIN &#34;:s0\n&#34;
&#34;    oneshot\n&#34;
&#34;\n&#34;


&#34;service %3$s %1$s/magisk --service\n&#34;
&#34;    class late_start\n&#34;
&#34;    user root\n&#34;
&#34;    seclabel u:r:&#34; SEPOL_PROC_DOMAIN &#34;:s0\n&#34;
&#34;    oneshot\n&#34;
&#34;\n&#34;

// 在boot完成阶段执行magisk进行，并传参boot-complete
&#34;on property:sys.boot_completed=1\n&#34;
&#34;    start %4$s\n&#34;
&#34;\n&#34;

&#34;service %4$s %1$s/magisk --boot-complete\n&#34;
&#34;    user root\n&#34;
&#34;    seclabel u:r:&#34; SEPOL_PROC_DOMAIN &#34;:s0\n&#34;
&#34;    oneshot\n&#34;
&#34;\n&#34;
;
```
可以看到，Magisk主要patch在三个阶段，post-fs-data、nonencrypted、boot_completed，都是基于/sbin/magisk来执行，而magisk对应的源码从native/jni/Android.mk可以看出
```shell
LOCAL_MODULE := magisk
LOCAL_STATIC_LIBRARIES := libnanopb libsystemproperties libutils
LOCAL_C_INCLUDES := jni/include

LOCAL_SRC_FILES := \
    core/applets.cpp \
    core/magisk.cpp \
    core/daemon.cpp \
    core/bootstages.cpp \
    core/socket.cpp \
    core/db.cpp \
    core/scripting.cpp \
    core/restorecon.cpp \
    core/module.cpp \
    magiskhide/magiskhide.cpp \
    magiskhide/hide_utils.cpp \
    magiskhide/hide_policy.cpp \
    resetprop/persist_properties.cpp \
    resetprop/resetprop.cpp \
    su/su.cpp \
    su/connect.cpp \
    su/pts.cpp \
    su/su_daemon.cpp
```
入口函数可以从core/magisk.cpp入手

magisk.cpp
```c&#43;&#43;
int magisk_main(int argc, char *argv[]) {
    if (argc &lt; 2)
        usage();
    if (argv[1] == &#34;-c&#34;sv) {
        printf(MAGISK_VERSION &#34;:MAGISK (&#34; str(MAGISK_VER_CODE) &#34;)\n&#34;);
        return 0;
    } else if (argv[1] == &#34;-v&#34;sv) {
        int fd = connect_daemon();
        write_int(fd, CHECK_VERSION);
        string v = read_string(fd);
        printf(&#34;%s\n&#34;, v.data());
        return 0;
    } else if (argv[1] == &#34;-V&#34;sv) {
        int fd = connect_daemon();
        write_int(fd, CHECK_VERSION_CODE);
        printf(&#34;%d\n&#34;, read_int(fd));
        return 0;
    ......
    } else if (argv[1] == &#34;--daemon&#34;sv) {
        int fd = connect_daemon(true);
        write_int(fd, START_DAEMON);
        return 0;
    } else if (argv[1] == &#34;--post-fs-data&#34;sv) {
        int fd = connect_daemon(true);
        write_int(fd, POST_FS_DATA);
        return read_int(fd);
    } else if (argv[1] == &#34;--service&#34;sv) {
        int fd = connect_daemon(true);
        write_int(fd, LATE_START);
        return read_int(fd);
    } else if (argv[1] == &#34;--boot-complete&#34;sv) {
        int fd = connect_daemon(true);
        write_int(fd, BOOT_COMPLETE);
        return read_int(fd);
    ......
#if 0
    /* Entry point for testing stuffs */
    else if (argv[1] == &#34;--test&#34;sv) {
        return 0;
    }
#endif
    usage();
}
```
可以看到，magisk对于不同入参的处理，连接daemon进程并传输对应动作的枚举来完成动作的执行，不管是任何动作都会首先执行connect_daemon，优先从这个函数入手
```c&#43;&#43;
// native/jni/core/daemon.cpp
int connect_daemon(bool create) {
    sockaddr_un sun;
    // 设置socket，地址为MAIN_SOCKET-d30138f2310a9fb9c54a3e0c21f58591
    socklen_t len = setup_sockaddr(&amp;sun, MAIN_SOCKET);
    // 创建socket获取fd
    int fd = xsocket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    // 判断是否正常连接，没有正常连接则进行创建
    if (connect(fd, (struct sockaddr *) &amp;sun, len)) {
        // 如果create为false并非root属组的话则认为daemon进程未正常启动
        if (!create || getuid() != UID_ROOT || getgid() != UID_ROOT) {
            LOGE(&#34;No daemon is currently running!\n&#34;);
            exit(1);
        }
        if (fork_dont_care() == 0) {
            // 类似linux fork机制，父进程返回子进程pid，子进程返回0，也就是在子进程中
            // 会引导daemon_entry
            close(fd);
            daemon_entry();
        }
        // 父进程会循环等待
        while (connect(fd, (struct sockaddr *) &amp;sun, len))
            usleep(10000);
    }
    return fd;
}

[[noreturn]] static void daemon_entry() {
    // 配置日志
    magisk_logging();

    // Block all signals
    sigset_t block_set;
    // 将所有信号都设置为1，表示需要收集处理所有信号
    sigfillset(&amp;block_set);
    // 设置信号屏蔽字为block_set
    pthread_sigmask(SIG_SETMASK, &amp;block_set, nullptr);

    // 设置进程名为magiskd
    // Change process name
    set_nice_name(&#34;magiskd&#34;);
    // out和err写入/dev/null
    int fd = xopen(&#34;/dev/null&#34;, O_WRONLY);
    xdup2(fd, STDOUT_FILENO);
    xdup2(fd, STDERR_FILENO);
    if (fd &gt; STDERR_FILENO)
        close(fd);
    fd = xopen(&#34;/dev/zero&#34;, O_RDONLY);
    xdup2(fd, STDIN_FILENO);
    if (fd &gt; STDERR_FILENO)
        close(fd);

    setsid();
    // SEPOL_PROC_DOMAIN = magisk
    // 设置进程的type为magisk，让进程相当于拥有root的权限
    setcon(&#34;u:r:&#34; SEPOL_PROC_DOMAIN &#34;:s0&#34;);
    // 设置log daemon
    start_log_daemon();

    LOGI(NAME_WITH_VER(Magisk) &#34; daemon started\n&#34;);

    // Escape from cgroup
    int pid = getpid();
    if (switch_cgroup(&#34;/acct&#34;, pid) &amp;&amp; switch_cgroup(&#34;/sys/fs/cgroup&#34;, pid))
        LOGW(&#34;Can&#39;t switch cgroup\n&#34;);

    // Get self stat
    char buf[64];
    // 读取当前进程的绝对路径
    xreadlink(&#34;/proc/self/exe&#34;, buf, sizeof(buf));
    MAGISKTMP = dirname(buf);
    // 获取当前进程的属性
    xstat(&#34;/proc/self/exe&#34;, &amp;self_st);
    // 在android11中MAGISKTMP通常指/dev/xxxxx

    // Get API level
    parse_prop_file(&#34;/system/build.prop&#34;, [](auto key, auto val) -&gt; bool {
        if (key == &#34;ro.build.version.sdk&#34;) {
            SDK_INT = parse_int(val);
            return false;
        }
        return true;
    });
    if (SDK_INT &lt; 0) {
        // In case some devices do not store this info in build.prop, fallback to getprop
        auto sdk = getprop(&#34;ro.build.version.sdk&#34;);
        if (!sdk.empty()) {
            SDK_INT = parse_int(sdk);
        }
    }
    LOGI(&#34;* Device API level: %d\n&#34;, SDK_INT);
    // 对MAGISKTMP目录下的文件设置SELinux context
    restore_tmpcon();

    // SAR cleanups
    auto mount_list = MAGISKTMP &#43; &#34;/&#34; ROOTMNT;
    if (access(mount_list.data(), F_OK) == 0) {
        file_readline(true, mount_list.data(), [](string_view line) -&gt; bool {
            umount2(line.data(), MNT_DETACH);
            return true;
        });
    }
    unlink(&#34;/dev/.se&#34;);

    // Load config status
    auto config = MAGISKTMP &#43; &#34;/&#34; INTLROOT &#34;/config&#34;;
    parse_prop_file(config.data(), [](auto key, auto val) -&gt; bool {
        if (key == &#34;RECOVERYMODE&#34; &amp;&amp; val == &#34;true&#34;)
            RECOVERY_MODE = true;
        return true;
    });

    // 设置socket并监听
    struct sockaddr_un sun;
    socklen_t len = setup_sockaddr(&amp;sun, MAIN_SOCKET);
    fd = xsocket(AF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (xbind(fd, (struct sockaddr*) &amp;sun, len))
        exit(1);
    xlisten(fd, 10);

    // 轮询处理socket消息，使用handle_request函数去处理
    // Loop forever to listen for requests
    for (;;) {
        int client = xaccept4(fd, nullptr, nullptr, SOCK_CLOEXEC);
        handle_request(client);
    }
}

static void handle_request(int client) {
    int req_code;

    // Verify client credentials
    ucred cred;
    get_client_cred(client, &amp;cred);

    bool is_root = cred.uid == 0;
    bool is_zygote = check_zygote(cred.pid);
    bool is_client = verify_client(cred.pid);

    if (!is_root &amp;&amp; !is_zygote &amp;&amp; !is_client)
        goto shortcut;

    req_code = read_int(client);
    if (req_code &lt; 0 || req_code &gt;= DAEMON_CODE_END)
        goto shortcut;
    // 权限检验
    // Check client permissions
    switch (req_code) {
    case POST_FS_DATA:
    case LATE_START:
    case BOOT_COMPLETE:
    case SQLITE_CMD:
    case GET_PATH:
        if (!is_root) {
            write_int(client, ROOT_REQUIRED);
            goto shortcut;
        }
        break;
    case REMOVE_MODULES:
        if (cred.uid != UID_SHELL &amp;&amp; cred.uid != UID_ROOT) {
            write_int(client, 1);
            goto shortcut;
        }
        break;
    case MAGISKHIDE:  // accept hide request from zygote
        if (!is_root &amp;&amp; !is_zygote) {
            write_int(client, ROOT_REQUIRED);
            goto shortcut;
        }
        break;
    }

    // Simple requests
    switch (req_code) {
    case CHECK_VERSION:
        write_string(client, MAGISK_VERSION &#34;:MAGISK&#34;);
        goto shortcut;
    case CHECK_VERSION_CODE:
        write_int(client, MAGISK_VER_CODE);
        goto shortcut;
    case GET_PATH:
        write_string(client, MAGISKTMP.data());
        goto shortcut;
    case START_DAEMON:
        setup_logfile(true);
        goto shortcut;
    }

    // 新起个线程来处理请求
    // Create new thread to handle complex requests
    new_daemon_thread([=] { return request_handler(client, req_code, cred); });
    return;

shortcut:
    close(client);
}

static void request_handler(int client, int req_code, ucred cred) {
    switch (req_code) {
    case MAGISKHIDE:
        magiskhide_handler(client, &amp;cred);
        break;
    case SUPERUSER:
        su_daemon_handler(client, &amp;cred);
        break;
    case POST_FS_DATA:
        post_fs_data(client);
        break;
    case LATE_START:
        late_start(client);
        break;
    case BOOT_COMPLETE:
        boot_complete(client);
        break;
    case SQLITE_CMD:
        exec_sql(client);
        break;
    case REMOVE_MODULES:
        remove_modules();
        write_int(client, 0);
        close(client);
        reboot();
        break;
    default:
        close(client);
        break;
    }
}
```
上面可以看出connect_daemon所做的是判断daemon是否启动，如果启动则获取daemon的fd，没有的话则创建daemon。而daemon启动后会轮询监听socket请求，一旦接收到请求则新起线程去执行指令

##### 2.1 post-fs-data
对应枚举是POST_FS_DATA
```c&#43;&#43;
void post_fs_data(int client) {
    // ack
    write_int(client, 0);
    close(client);

    mutex_guard lock(stage_lock);

    if (getenv(&#34;REMOUNT_ROOT&#34;))
        xmount(nullptr, &#34;/&#34;, nullptr, MS_REMOUNT | MS_RDONLY, nullptr);

    if (!check_data())
        goto unblock_init;

    DAEMON_STATE = STATE_POST_FS_DATA;
    setup_logfile(true);

    LOGI(&#34;** post-fs-data mode running\n&#34;);
    // 设置成/dev/block下的块文件为读写模式，关键命令ioctl(fd, BLKROSET, &amp;OFF)
    unlock_blocks();
    mount_mirrors();
    // 判断/data/adb目录是否存在，正常情况下Android会自动创建
    if (access(SECURE_DIR, F_OK) != 0) {
        if (SDK_INT &lt; 24) {
            // There is no FBE pre 7.0, we can directly create the folder without issues
            xmkdir(SECURE_DIR, 0700);
        } else {
            // If the folder is not automatically created by Android,
            // do NOT proceed further. Manual creation of the folder
            // will have no encryption flag, which will cause bootloops on FBE devices.
            LOGE(SECURE_DIR &#34; is not present, abort\n&#34;);
            goto early_abort;
        }
    }
    // magisk_env初始化环境
    if (!magisk_env()) {
        LOGE(&#34;* Magisk environment incomplete, abort\n&#34;);
        goto early_abort;
    }

    if (getprop(&#34;persist.sys.safemode&#34;, true) == &#34;1&#34; || check_key_combo()) {
        safe_mode = true;
        // Disable all modules and magiskhide so next boot will be clean
        disable_modules();
        stop_magiskhide();
    } else {
        // 执行自定义的post-fs-data阶段的脚本
        // 目录在/data/adb/post-fs-data.d
        exec_common_scripts(&#34;post-fs-data&#34;);
        auto_start_magiskhide(false);
        handle_modules();
    }

early_abort:
    // We still do magic mount because root itself might need it
    magic_mount();
    DAEMON_STATE = STATE_POST_FS_DATA_DONE;

unblock_init:
    close(xopen(UNBLOCKFILE, O_RDONLY | O_CREAT, 0));
}

static bool magisk_env() {
    char buf[4096];
    // 初始化环境
    LOGI(&#34;* Initializing Magisk environment\n&#34;);

    string pkg;
    check_manager(&amp;pkg);

    sprintf(buf, &#34;%s/0/%s/install&#34;, APP_DATA_DIR, pkg.data());

    // Alternative binaries paths
    const char *alt_bin[] = { &#34;/cache/data_adb/magisk&#34;, &#34;/data/magisk&#34;, buf };
    for (auto alt : alt_bin) {
        struct stat st;
        if (lstat(alt, &amp;st) == 0) {
            if (S_ISLNK(st.st_mode)) {
                unlink(alt);
                continue;
            }
            rm_rf(DATABIN);
            cp_afc(alt, DATABIN);
            rm_rf(alt);
            break;
        }
    }

    // Remove stuffs
    rm_rf(&#34;/cache/data_adb&#34;);
    rm_rf(&#34;/data/adb/modules/.core&#34;);
    unlink(&#34;/data/adb/magisk.img&#34;);
    unlink(&#34;/data/adb/magisk_merge.img&#34;);
    unlink(&#34;/data/magisk.img&#34;);
    unlink(&#34;/data/magisk_merge.img&#34;);
    unlink(&#34;/data/magisk_debug.log&#34;);

    // Directories in /data/adb
    xmkdir(DATABIN, 0755);
    xmkdir(MODULEROOT, 0755);
    xmkdir(SECURE_DIR &#34;/post-fs-data.d&#34;, 0755);
    xmkdir(SECURE_DIR &#34;/service.d&#34;, 0755);

    if (access(DATABIN &#34;/busybox&#34;, X_OK))
        return false;

    sprintf(buf, &#34;%s/&#34; BBPATH &#34;/busybox&#34;, MAGISKTMP.data());
    mkdir(dirname(buf), 0755);
    cp_afc(DATABIN &#34;/busybox&#34;, buf);
    exec_command_async(buf, &#34;--install&#34;, &#34;-s&#34;, dirname(buf));

    return true;
}

// native/jni/core/module.cpp
void magic_mount() {
    node_entry::mirror_dir = MAGISKTMP &#43; &#34;/&#34; MIRRDIR;
    node_entry::module_mnt = MAGISKTMP &#43; &#34;/&#34; MODULEMNT &#34;/&#34;;

    auto root = make_unique&lt;root_node&gt;(&#34;&#34;);
    auto system = new root_node(&#34;system&#34;);
    root-&gt;insert(system);

    char buf[4096];
    LOGI(&#34;* Loading modules\n&#34;);
    for (const auto &amp;m : module_list) {
        auto module = m.data();
        char *b = buf &#43; sprintf(buf, &#34;%s/&#34; MODULEMNT &#34;/%s/&#34;, MAGISKTMP.data(), module);

        // Read props
        strcpy(b, &#34;system.prop&#34;);
        if (access(buf, F_OK) == 0) {
            LOGI(&#34;%s: loading [system.prop]\n&#34;, module);
            load_prop_file(buf, false);
        }

        // Check whether skip mounting
        strcpy(b, &#34;skip_mount&#34;);
        if (access(buf, F_OK) == 0)
            continue;

        // Double check whether the system folder exists
        strcpy(b, &#34;system&#34;);
        if (access(buf, F_OK) != 0)
            continue;

        LOGI(&#34;%s: loading mount files\n&#34;, module);
        b[-1] = &#39;\0&#39;;
        int fd = xopen(buf, O_RDONLY | O_CLOEXEC);
        system-&gt;collect_files(module, fd);
        close(fd);
    }

    // 关键处理
    if (MAGISKTMP != &#34;/sbin&#34;) {
        // Need to inject our binaries into /system/bin
        inject_magisk_bins(system);
    }

    if (system-&gt;is_empty())
        return;

    // Handle special read-only partitions
    for (const char *part : { &#34;/vendor&#34;, &#34;/product&#34;, &#34;/system_ext&#34; }) {
        struct stat st;
        if (lstat(part, &amp;st) == 0 &amp;&amp; S_ISDIR(st.st_mode)) {
            if (auto old = system-&gt;extract(part &#43; 1); old) {
                auto new_node = new root_node(old);
                root-&gt;insert(new_node);
            }
        }
    }

    root-&gt;prepare();
    root-&gt;mount();
}

static void inject_magisk_bins(root_node *system) {
    // 对/system/bin目录的处理
    auto bin = system-&gt;child&lt;inter_node&gt;(&#34;bin&#34;);
    if (!bin) {
        bin = new inter_node(&#34;bin&#34;, &#34;&#34;);
        system-&gt;insert(bin);
    }
    // 往system目录插入bin目录

    // Insert binaries
    // bin目录设置两个magisk_node类型的新文件，magisk和magiskinit
    bin-&gt;insert(new magisk_node(&#34;magisk&#34;));
    bin-&gt;insert(new magisk_node(&#34;magiskinit&#34;));
    // 删除可能存在applet_names列表中的文件，因为后续mount时会重新配置
    // applet_names[] = { &#34;su&#34;, &#34;resetprop&#34;, &#34;magiskhide&#34;, nullptr };
    // Also delete all applets to make sure no modules can override it
    for (int i = 0; applet_names[i]; &#43;&#43;i)
        delete bin-&gt;extract(applet_names[i]);
    for (int i = 0; init_applet[i]; &#43;&#43;i)
        delete bin-&gt;extract(init_applet[i]);
}

void mount() override {
    对每个节点执行mount方法
    for (auto &amp;pair : children)
        pair.second-&gt;mount();
}

class magisk_node : public node_entry {
public:
    explicit magisk_node(const char *name) : node_entry(name, DT_REG, this) {}

    void mount() override {
        const string &amp;dir_name = parent()-&gt;node_path();
        if (name() == &#34;magisk&#34;) {
            // 对applet_names中的文件都做软链，也就是su -&gt; ./magisk
            for (int i = 0; applet_names[i]; &#43;&#43;i) {
                string dest = dir_name &#43; &#34;/&#34; &#43; applet_names[i];
                VLOGD(&#34;create&#34;, &#34;./magisk&#34;, dest.data());
                xsymlink(&#34;./magisk&#34;, dest.data());
            }
        } else {
            for (int i = 0; init_applet[i]; &#43;&#43;i) {
                string dest = dir_name &#43; &#34;/&#34; &#43; init_applet[i];
                VLOGD(&#34;create&#34;, &#34;./magiskinit&#34;, dest.data());
                xsymlink(&#34;./magiskinit&#34;, dest.data());
            }
        }
        create_and_mount(MAGISKTMP &#43; &#34;/&#34; &#43; name());
    }
};
```
##### 2.2 service
对应枚举是LATE_START
```c&#43;&#43;
void late_start(int client) {
    // ack
    write_int(client, 0);
    close(client);

    mutex_guard lock(stage_lock);
    run_finally fin([]{ DAEMON_STATE = STATE_LATE_START_DONE; });
    setup_logfile(false);

    LOGI(&#34;** late_start service mode running\n&#34;);

    if (DAEMON_STATE &lt; STATE_POST_FS_DATA_DONE || safe_mode)
        return;
    // 执行自定义的post-fs-data阶段的脚本
    // 目录在/data/adb/service.d
    exec_common_scripts(&#34;service&#34;);
    exec_module_scripts(&#34;service&#34;);
}
```
##### 2.3 boot-complete
对应枚举是boot_complete
```c&#43;&#43;
void boot_complete(int client) {
    // ack
    write_int(client, 0);
    close(client);

    mutex_guard lock(stage_lock);
    DAEMON_STATE = STATE_BOOT_COMPLETE;
    setup_logfile(false);

    LOGI(&#34;** boot_complete triggered\n&#34;);

    if (safe_mode)
        return;

    // At this point it&#39;s safe to create the folder
    if (access(SECURE_DIR, F_OK) != 0)
        xmkdir(SECURE_DIR, 0700);

    auto_start_magiskhide(true);
    // 判断是否有magisk manager
    if (!check_manager()) {
        if (access(MANAGERAPK, F_OK) == 0) {
            // Only try to install APK when no manager is installed
            // Magisk Manager should be upgraded by itself, not through recovery installs
            rename(MANAGERAPK, &#34;/data/magisk.apk&#34;);
            install_apk(&#34;/data/magisk.apk&#34;);
        } else {
            // Install stub
            auto init = MAGISKTMP &#43; &#34;/magiskinit&#34;;
            exec_command_sync(init.data(), &#34;-x&#34;, &#34;manager&#34;, &#34;/data/magisk.apk&#34;);
            install_apk(&#34;/data/magisk.apk&#34;);
        }
    }
    unlink(MANAGERAPK);
}
```


---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/%E9%87%8D%E8%AF%BBmagisk%E5%86%85%E9%83%A8%E5%AE%9E%E7%8E%B0%E7%BB%86%E8%8A%822/  

