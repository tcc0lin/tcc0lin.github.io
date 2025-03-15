# 重读Magisk内部实现细节3


### 前言
Magisk内部实现细节的第三篇，主要通过源码来了解下Magisk Hide的原理，这部分代码在native/jni/magiskhide当中

### 一、Magisk Hide入口
不管是在Magisk Manager中管理Magisk Hide
```kotlin
object MagiskHide : BaseSettingsItem.Toggle() {
    override val title = R.string.magiskhide.asText()
    override val description = R.string.settings_magiskhide_summary.asText()
    override var value = Config.magiskHide
        set(value) = setV(value, field, { field = it }) {
            val cmd = if (it) &#34;enable&#34; else &#34;disable&#34;
            Shell.su(&#34;magiskhide $cmd&#34;).submit { cb -&gt;
                if (cb.isSuccess) Config.magiskHide = it
                else field = !it
            }
        }
}
```
还是通过adb shell来管理Magisk Hide
```shell
(base)  大慈大悲观世音菩萨  ~  adb shell
selene:/ $ su
selene:/ # magiskhide status
MagiskHide is not enabled
1|selene:/ # magiskhide enable
selene:/ # magiskhide status
MagiskHide is enabled
selene:/ #
```
其底层都是通过magiskhide这个二进制文件来触发的，而magiskhide的入口是
```c
// native/jni/magiskhide/magiskhide.cpp
// 入口函数
int magiskhide_main(int argc, char *argv[]) {
    if (argc &lt; 2)
        usage(argv[0]);

    // CLI backwards compatibility
    const char *opt = argv[1];
    if (opt[0] == &#39;-&#39; &amp;&amp; opt[1] == &#39;-&#39;)
        opt &#43;= 2;

    int req;
    // 选择触发的指令
    if (opt == &#34;enable&#34;sv)
        req = LAUNCH_MAGISKHIDE;
    else if (opt == &#34;disable&#34;sv)
        req = STOP_MAGISKHIDE;
    else if (opt == &#34;add&#34;sv)
        req = ADD_HIDELIST;
    else if (opt == &#34;rm&#34;sv)
        req = RM_HIDELIST;
    else if (opt == &#34;ls&#34;sv)
        req = LS_HIDELIST;
    else if (opt == &#34;status&#34;sv)
        req = HIDE_STATUS;
    else if (opt == &#34;exec&#34;sv &amp;&amp; argc &gt; 2) {
        xunshare(CLONE_NEWNS);
        xmount(nullptr, &#34;/&#34;, nullptr, MS_PRIVATE | MS_REC, nullptr);
        hide_unmount();
        execvp(argv[2], argv &#43; 2);
        exit(1);
    }
#if 0 &amp;&amp; !ENABLE_INJECT
    else if (opt == &#34;test&#34;sv)
        test_proc_monitor();
#endif
    else
        usage(argv[0]);
    // 同样需要和daemon进行交互
    // Send request
    int fd = connect_daemon();
    write_int(fd, MAGISKHIDE);
    write_int(fd, req);
    if (req == ADD_HIDELIST || req == RM_HIDELIST) {
        write_string(fd, argv[2]);
        write_string(fd, argv[3] ? argv[3] : &#34;&#34;);
    }

    // Get response
    int code = read_int(fd);
    switch (code) {
    case DAEMON_SUCCESS:
        break;
    case HIDE_NOT_ENABLED:
        fprintf(stderr, &#34;MagiskHide is not enabled\n&#34;);
        goto return_code;
    case HIDE_IS_ENABLED:
        fprintf(stderr, &#34;MagiskHide is enabled\n&#34;);
        goto return_code;
    case HIDE_ITEM_EXIST:
        fprintf(stderr, &#34;Target already exists in hide list\n&#34;);
        goto return_code;
    case HIDE_ITEM_NOT_EXIST:
        fprintf(stderr, &#34;Target does not exist in hide list\n&#34;);
        goto return_code;
    case HIDE_NO_NS:
        fprintf(stderr, &#34;Your kernel doesn&#39;t support mount namespace\n&#34;);
        goto return_code;
    case HIDE_INVALID_PKG:
        fprintf(stderr, &#34;Invalid package / process name\n&#34;);
        goto return_code;
    case ROOT_REQUIRED:
        fprintf(stderr, &#34;Root is required for this operation\n&#34;);
        goto return_code;
    case DAEMON_ERROR:
    default:
        fprintf(stderr, &#34;Daemon error\n&#34;);
        return DAEMON_ERROR;
    }

    if (req == LS_HIDELIST) {
        string res;
        for (;;) {
            read_string(fd, res);
            if (res.empty())
                break;
            printf(&#34;%s\n&#34;, res.data());
        }
    }

return_code:
    return req == HIDE_STATUS ? (code == HIDE_IS_ENABLED ? 0 : 1) : code != DAEMON_SUCCESS;
```
而对于daemon进程来说，处理magiskhide传来的指令，具体的处理逻辑还是在magiskhide.cpp中
```c
// native/jni/core/daemon.cpp
static void request_handler(int client, int req_code, ucred cred) {
    switch (req_code) {
        case MAGISKHIDE:
            magiskhide_handler(client, &amp;cred);
            break;
        ......

// native/jni/magiskhide/magiskhide.cpp
void magiskhide_handler(int client, ucred *cred) {
    int req = read_int(client);
    int res = DAEMON_ERROR;

    ......

    switch (req) {
    // magiskhide启动
    case LAUNCH_MAGISKHIDE:
        res = launch_magiskhide(true);
        break;
    // magiskhide关闭
    case STOP_MAGISKHIDE:
        res = stop_magiskhide();
        break;
    // 新增需要隐藏的app
    case ADD_HIDELIST:
        res = add_list(client);
        break;
    // 移除
    case RM_HIDELIST:
        res = rm_list(client);
        break;
    case LS_HIDELIST:
        ls_list(client);
        return;
    case HIDE_STATUS:
        res = hide_enabled() ? HIDE_IS_ENABLED : HIDE_NOT_ENABLED;
        break;
#if ENABLE_INJECT
    case REMOTE_CHECK_HIDE:
        res = check_uid_map(client);
        break;
    case REMOTE_DO_HIDE:
        kill(cred-&gt;pid, SIGSTOP);
        write_int(client, 0);
        hide_daemon(cred-&gt;pid);
        close(client);
        return;
#endif
    }

    write_int(client, res);
    close(client);
}
```

### 二、Magisk Hide指令分析
#### 1 LAUNCH_MAGISKHIDE
```c
// native/jni/magiskhide/hide_utils.cpp
// 开启magiskhide
int launch_magiskhide(bool late_props) {
    // 锁申请
    mutex_guard lock(hide_state_lock);

    // 判断全局变量hide_state的值，如果已经启动直接返回
    if (hide_state)
        return HIDE_IS_ENABLED;

    // 检测是否有访问namespace的权限
    if (access(&#34;/proc/self/ns/mnt&#34;, F_OK) != 0)
        return HIDE_NO_NS;

    // 复制procfp
    if (procfp == nullptr &amp;&amp; (procfp = opendir(&#34;/proc&#34;)) == nullptr)
        return DAEMON_ERROR;

    LOGI(&#34;* Enable MagiskHide\n&#34;);
    // 初始化hide_set并杀死相关进程
    // Initialize the hide list
    if (!init_list())
        return DAEMON_ERROR;
    // 替换prop属性
    hide_sensitive_props();
    if (late_props)
        // 针对vendor.boot.verifiedbootstate进行替换
        hide_late_sensitive_props();

#if !ENABLE_INJECT
    // Start monitoring
    // 创建监控线程monitor_thread
    if (new_daemon_thread(&amp;proc_monitor))
        return DAEMON_ERROR;
#endif
    // 更新当前magiskhide状态
    hide_state = true;
    // 更新settings里的magiskhide配置
    update_hide_config();
    // 释放锁
    // Unlock here or else we&#39;ll be stuck in deadlock
    lock.unlock();
    // 更新uid_proc_map，需要隐藏的app的uid对应进程名
    update_uid_map();
    return DAEMON_SUCCESS;
}
```
#### 2 STOP_MAGISKHIDE
```c
// native/jni/magiskhide/hide_utils.cpp
int stop_magiskhide() {
    mutex_guard g(hide_state_lock);

    if (hide_state) {
        LOGI(&#34;* Disable MagiskHide\n&#34;);
        // 清理工作
        uid_proc_map.clear();
        hide_set.clear();
#if !ENABLE_INJECT
        // 向monitor_thread发送自定义信号SIGTERMTHRD
        pthread_kill(monitor_thread, SIGTERMTHRD);
#endif
    }
    // 更新当前magiskhide状态
    hide_state = false;
    // 更新settings里的magiskhide配置
    update_hide_config();
    return DAEMON_SUCCESS;
}
```
#### 3 ADD_HIDELIST
```c
// native/jni/magiskhide/hide_utils.cpp
int add_list(int client) {
    string pkg = read_string(client);
    string proc = read_string(client);
    int ret = add_list(pkg.data(), proc.data());
    if (ret == DAEMON_SUCCESS)
        // 更新uid_proc_map
        update_uid_map();
    return ret;
}

static int add_list(const char *pkg, const char *proc) {
    if (proc[0] == &#39;\0&#39;)
        proc = pkg;

    if (!validate(pkg, proc))
        return HIDE_INVALID_PKG;

    for (auto &amp;hide : hide_set)
        if (hide.first == pkg &amp;&amp; hide.second == proc)
            return HIDE_ITEM_EXIST;

    // Add to database
    char sql[4096];
    // 写入hidelist数据表
    snprintf(sql, sizeof(sql),
            &#34;INSERT INTO hidelist (package_name, process) VALUES(&#39;%s&#39;, &#39;%s&#39;)&#34;, pkg, proc);
    char *err = db_exec(sql);
    db_err_cmd(err, return DAEMON_ERROR);

    {
        // Critical region
        mutex_guard lock(hide_state_lock);
        // 更新hide_set
        add_hide_set(pkg, proc);
    }

    return DAEMON_SUCCESS;
}
```
可以看出，首先在Magisk Hide中有三个存储结构用来做Magisk Hide的管理工作
- hide_set: 存储需要隐藏功能的包名-进程名
- uid_proc_map: 根据hide_set集合来存储对应App的uid以及进程名映射
- hidelist: 数据表，供展示时使用

其次，可以看到在Magisk Hide启动时会额外启动monitor_thread这个线程，而这个就是Magisk Hide隐藏功能的核心

### 三、Magisk Hide原理
跟进monitor_thread
#### 1 信号处理
```c
// native/jni/magiskhide/proc_monitor.cpp

// 设置该线程为monitor_thread，并于后续清理
monitor_thread = pthread_self();

// Backup original mask
// 获取当前线程的信号掩码保存在orin_mask
sigset_t orig_mask;
pthread_sigmask(SIG_SETMASK, nullptr, &amp;orig_mask);

// 清空信号集并初始化
sigset_t unblock_set;
sigemptyset(&amp;unblock_set);
sigaddset(&amp;unblock_set, SIGTERMTHRD);
sigaddset(&amp;unblock_set, SIGIO);
sigaddset(&amp;unblock_set, SIGALRM);

// 设置信号处理函数集合
struct sigaction act{};
sigfillset(&amp;act.sa_mask);
act.sa_handler = SIG_IGN;
sigaction(SIGTERMTHRD, &amp;act, nullptr);
sigaction(SIGIO, &amp;act, nullptr);
sigaction(SIGALRM, &amp;act, nullptr);

// 防止信号积压处理
// Temporary unblock to clear pending signals
pthread_sigmask(SIG_UNBLOCK, &amp;unblock_set, nullptr);
pthread_sigmask(SIG_SETMASK, &amp;orig_mask, nullptr);

// 使用term_thread来处理SIGTERMTHRD信号
act.sa_handler = term_thread;
sigaction(SIGTERMTHRD, &amp;act, nullptr);
// 使用inotify_event处理SIGIO信号
act.sa_handler = inotify_event;
sigaction(SIGIO, &amp;act, nullptr);
// 使用check_zygote处理SIGALRM信号
act.sa_handler = [](int){ check_zygote(); };
sigaction(SIGALRM, &amp;act, nullptr);

setup_inotify();

static void setup_inotify() {
    // 创建inotify实例时指定了IN_CLOEXEC标志位，表示将inotify实例设置为 close-on-exec 模式。
    // 在close-on-exec模式下，当进程调用exec函数时，inotify实例会自动关闭
    inotify_fd = xinotify_init1(IN_CLOEXEC);
    if (inotify_fd &lt; 0)
        return;

    // Setup inotify asynchronous I/O
    // 设置inotify文件描述符的异步通知和所有权
    fcntl(inotify_fd, F_SETFL, O_ASYNC);
    struct f_owner_ex ex = {
        .type = F_OWNER_TID,
        .pid = gettid()
    };
    fcntl(inotify_fd, F_SETOWN_EX, &amp;ex);

    // 监控/data/system的写入并关闭事件
    // Monitor packages.xml
    inotify_add_watch(inotify_fd, &#34;/data/system&#34;, IN_CLOSE_WRITE);

    // 监控app_process的被访问的事件，也就是监控App
    // Monitor app_process
    if (access(APP_PROC &#34;32&#34;, F_OK) == 0) {
        inotify_add_watch(inotify_fd, APP_PROC &#34;32&#34;, IN_ACCESS);
        if (access(APP_PROC &#34;64&#34;, F_OK) == 0)
            inotify_add_watch(inotify_fd, APP_PROC &#34;64&#34;, IN_ACCESS);
    } else {
        inotify_add_watch(inotify_fd, APP_PROC, IN_ACCESS);
    }
}
```
这个部分主要做的事是
- 设置信号处理函数，信号分别是SIGTERMTHRD、SIGIO、SIGALRM
- 启动inotify，fd写入inotify_fd，监控/system/bin/app_process的access事件，重点在于packages.xml文件的写入
#### 2 ptrace Zygote
```c
check_zygote();
if (!is_zygote_done()) {
    // 如果获取到zygote，则每250ms发送SIGALRM信号触发check_zygote
    // Periodic scan every 250ms
    timeval val { .tv_sec = 0, .tv_usec = 250000 };
    itimerval interval { .it_interval = val, .it_value = val };
    setitimer(ITIMER_REAL, &amp;interval, nullptr);
}

static void check_zygote() {
    crawl_procfs([](int pid) -&gt; bool {
        char buf[512];
        snprintf(buf, sizeof(buf), &#34;/proc/%d/cmdline&#34;, pid);
        if (FILE *f = fopen(buf, &#34;re&#34;)) {
            fgets(buf, sizeof(buf), f);
            if (strncmp(buf, &#34;zygote&#34;, 6) == 0 &amp;&amp; parse_ppid(pid) == 1)
                new_zygote(pid);
            fclose(f);
        }
        return true;
    });
    if (is_zygote_done()) {
        // Stop periodic scanning
        timeval val { .tv_sec = 0, .tv_usec = 0 };
        itimerval interval { .it_interval = val, .it_value = val };
        setitimer(ITIMER_REAL, &amp;interval, nullptr);
    }
}

static DIR *procfp;
// procfp在之前已经被赋值成/proc目录
void crawl_procfs(const function&lt;bool(int)&gt; &amp;fn) {
    // 指针重置到目录起始位置
    rewinddir(procfp);
    crawl_procfs(procfp, fn);
}

// 遍历proc目录，获取zygote的pid
void crawl_procfs(DIR *dir, const function&lt;bool(int)&gt; &amp;fn) {
    struct dirent *dp;
    int pid;
    while ((dp = readdir(dir))) {
        pid = parse_int(dp-&gt;d_name);
        if (pid &gt; 0 &amp;&amp; !fn(pid))
            break;
    }
}

static void new_zygote(int pid) {
    struct stat st;
    // 读取zygote挂载的namespace信息
    if (read_ns(pid, &amp;st))
        return;

    // 更新或者存储st到zygote_map
    auto it = zygote_map.find(pid);
    if (it != zygote_map.end()) {
        // Update namespace info
        it-&gt;second = st;
        return;
    }

    LOGD(&#34;proc_monitor: ptrace zygote PID=[%d]\n&#34;, pid);
    zygote_map[pid] = st;
    // ptrace attach到zygote进程
    xptrace(PTRACE_ATTACH, pid);
    // 等待zygote进程状态变化 
    waitpid(pid, nullptr, __WALL | __WNOTHREAD);
    监控zygote fork/vfork/exit事件
    xptrace(PTRACE_SETOPTIONS, pid, nullptr,
            PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXIT);
    // 恢复zygote进程执行
    xptrace(PTRACE_CONT, pid);
}
```
这一部分的作用是轮询判断zygote进程是否启动以及ptrace attach到zygote以便于监控到zygote的fork操作（引导启动App进程）
#### 3 子进程信号处理
```c
for (int status;;) {
    // 解除信号阻塞，获取信号
    pthread_sigmask(SIG_UNBLOCK, &amp;unblock_set, nullptr);
    // 获取待处理的pid
    const int pid = waitpid(-1, &amp;status, __WALL | __WNOTHREAD);
    if (pid &lt; 0) {
        if (errno == ECHILD) {
            // Nothing to wait yet, sleep and wait till signal interruption
            LOGD(&#34;proc_monitor: nothing to monitor, wait for signal\n&#34;);
            struct timespec ts = {
                .tv_sec = INT_MAX,
                .tv_nsec = 0
            };
            nanosleep(&amp;ts, nullptr);
        }
        continue;
    }

    pthread_sigmask(SIG_SETMASK, &amp;orig_mask, nullptr);

    if (!WIFSTOPPED(status) /* Ignore if not ptrace-stop */)
        DETACH_AND_CONT;
    // 获取pid的信号和事件类型
    int event = WEVENT(status);
    int signal = WSTOPSIG(status);

    if (signal == SIGTRAP &amp;&amp; event) {
        unsigned long msg;
        xptrace(PTRACE_GETEVENTMSG, pid, nullptr, &amp;msg);
        // 处理zygote消息
        if (zygote_map.count(pid)) {
            // Zygote event
            switch (event) {
                case PTRACE_EVENT_FORK:
                case PTRACE_EVENT_VFORK:
                    PTRACE_LOG(&#34;zygote forked: [%lu]\n&#34;, msg);
                    // 表示收到的是zygote消息，监控到zygote fork子进程
                    // 此时设置attaches map中app pid的值为true
                    attaches[msg] = true;
                    break;
                case PTRACE_EVENT_EXIT:
                    PTRACE_LOG(&#34;zygote exited with status: [%lu]\n&#34;, msg);
                    [[fallthrough]];
                default:
                    zygote_map.erase(pid);
                    DETACH_AND_CONT;
            }
        } else {
            // 处理用户App消息
            switch (event) {
                // 表示收到的是子进程的信号，有新的App启动，开始执行隐藏操作
                case PTRACE_EVENT_CLONE:
                    PTRACE_LOG(&#34;create new threads: [%lu]\n&#34;, msg);
                    if (attaches[pid] &amp;&amp; check_pid(pid))
                        continue;
                    break;
                case PTRACE_EVENT_EXEC:
                case PTRACE_EVENT_EXIT:
                    PTRACE_LOG(&#34;exit or execve\n&#34;);
                    [[fallthrough]];
                default:
                    DETACH_AND_CONT;
            }
        }
        xptrace(PTRACE_CONT, pid);
    } else if (signal == SIGSTOP) {
        // 收到暂停信号，继续监控
        if (!attaches[pid]) {
            // Double check if this is actually a process
            attaches[pid] = is_process(pid);
        }
        if (attaches[pid]) {
            // This is a process, continue monitoring
            PTRACE_LOG(&#34;SIGSTOP from child\n&#34;);
            xptrace(PTRACE_SETOPTIONS, pid, nullptr,
                    PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT);
            xptrace(PTRACE_CONT, pid);
        } else {
            // This is a thread, do NOT monitor
            PTRACE_LOG(&#34;SIGSTOP from thread\n&#34;);
            DETACH_AND_CONT;
        }
    } else {
        // 恢复执行
        // Not caused by us, resend signal
        xptrace(PTRACE_CONT, pid, nullptr, signal);
        PTRACE_LOG(&#34;signal [%d]\n&#34;, signal);
    }
}

static bool check_pid(int pid) {
    char path[128];
    char cmdline[1024];
    struct stat st;

    sprintf(path, &#34;/proc/%d&#34;, pid);
    if (stat(path, &amp;st)) {
        // Process died unexpectedly, ignore
        detach_pid(pid);
        return true;
    }
    // 获取进程pid
    int uid = st.st_uid;

    // UID hasn&#39;t changed
    if (uid == 0)
        return false;

    // 读取/proc/pid/cmdline的内容到cmdline
    sprintf(path, &#34;/proc/%d/cmdline&#34;, pid);
    if (auto f = open_file(path, &#34;re&#34;)) {
        fgets(cmdline, sizeof(cmdline), f.get());
    } else {
        // Process died unexpectedly, ignore
        detach_pid(pid);
        return true;
    }
    
    // 必须是用户进程
    if (cmdline == &#34;zygote&#34;sv || cmdline == &#34;zygote32&#34;sv || cmdline == &#34;zygote64&#34;sv ||
        cmdline == &#34;usap32&#34;sv || cmdline == &#34;usap64&#34;sv)
        return false;

    // 如果非需要隐藏的进程，忽略
    if (!is_hide_target(uid, cmdline, 95))
        goto not_target;

    // 同上
    // Ensure ns is separated
    read_ns(pid, &amp;st);
    for (auto &amp;zit : zygote_map) {
        if (zit.second.st_ino == st.st_ino &amp;&amp;
            zit.second.st_dev == st.st_dev) {
            // ns not separated, abort
            LOGW(&#34;proc_monitor: skip [%s] PID=[%d] UID=[%d]\n&#34;, cmdline, pid, uid);
            goto not_target;
        }
    }

    // Detach but the process should still remain stopped
    // The hide daemon will resume the process after hiding it
    LOGI(&#34;proc_monitor: [%s] PID=[%d] UID=[%d]\n&#34;, cmdline, pid, uid);
    detach_pid(pid, SIGSTOP);
    hide_daemon(pid);
    return true;

not_target:
    PTRACE_LOG(&#34;[%s] is not our target\n&#34;, cmdline);
    detach_pid(pid);
    return true;
}

void hide_daemon(int pid) {
    if (fork_dont_care() == 0) {
        // 关键隐藏动作
        hide_unmount(pid);
        // Send resume signal
        kill(pid, SIGCONT);
        _exit(0);
    }
}

void hide_unmount(int pid) {
    // 切换目标pid的namespace
    if (pid &gt; 0 &amp;&amp; switch_mnt_ns(pid))
        return;

    LOGD(&#34;hide: handling PID=[%d]\n&#34;, pid);

    char val;
    // 读取selinux的模式
    int fd = xopen(SELINUX_ENFORCE, O_RDONLY);
    xxread(fd, &amp;val, sizeof(val));
    close(fd);
    // Permissive
    // 如果是宽容模式，则限制访问
    if (val == &#39;0&#39;) {
        chmod(SELINUX_ENFORCE, 0640);
        chmod(SELINUX_POLICY, 0440);
    }

    vector&lt;string&gt; targets;

    // Unmount dummy skeletons and /sbin links
    // android11中为/dev/xxxx
    targets.push_back(MAGISKTMP);
    parse_mnt(&#34;/proc/self/mounts&#34;, [&amp;](mntent *mentry) {
        if (TMPFS_MNT(system) || TMPFS_MNT(vendor) || TMPFS_MNT(product) || TMPFS_MNT(system_ext))
            targets.emplace_back(mentry-&gt;mnt_dir);
        return true;
    });

    for (auto &amp;s : reversed(targets))
        lazy_unmount(s.data());
    targets.clear();

    // Unmount all Magisk created mounts
    parse_mnt(&#34;/proc/self/mounts&#34;, [&amp;](mntent *mentry) {
        if (strstr(mentry-&gt;mnt_fsname, BLOCKDIR))
            targets.emplace_back(mentry-&gt;mnt_dir);
        return true;
    });

    for (auto &amp;s : reversed(targets))
        lazy_unmount(s.data());
}

```
核心步骤，上一步已经ptrace attach到zygote，当监听到App启动了，切换到目标进程的namespace并执行umount操作

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/%E9%87%8D%E8%AF%BBmagisk%E5%86%85%E9%83%A8%E5%AE%9E%E7%8E%B0%E7%BB%86%E8%8A%823/  

