# Magisk检测方式




### 一、市面现存的检测方式
#### 1 Magisk Detector
来源于[Magisk Detector](https://github.com/vvb2060/MagiskDetector)（现已停止维护），我们可以从官方的[细节文档](https://github.com/vvb2060/MagiskDetector/blob/master/README_ZH.md)看出它之前的设计思路
，目前从最新的代码上看，仅仅存在三种检测方式
```c
JNINativeMethod methods[] = {
        {&#34;haveSu&#34;,         &#34;()I&#34;, haveSu},
        {&#34;haveMagiskHide&#34;, &#34;()I&#34;, haveMagiskHide},
        {&#34;haveMagicMount&#34;, &#34;()I&#34;, haveMagicMount},
};
```
##### 1.1 su文件检测
- 检测方式

    ```c&#43;&#43;
    static int scan_path() {
        char *path = getenv(&#34;PATH&#34;);
        char *p = strtok(path, &#34;:&#34;);
        char supath[PATH_MAX];
        do {
            sprintf(supath, &#34;%s/su&#34;, p);
            if (access(supath, F_OK) == 0) {
                LOGW(&#34;Found su at %s&#34;, supath);
                return 1;
            }
        } while ((p = strtok(NULL, &#34;:&#34;)) != NULL);
        return 0;
    }
    ```
    代码比较少，很容易理解，通过获取系统环境变量path的值来确定当前有哪些可执行文件的目录，再依次遍历这些目录检测是否存在su文件，系统环境变量path内的路径通常是
    ```shell
    selene:/ $ echo $PATH
    /product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:/system_ext/bin:/system/bin:/system/xbin:/odm/bin:/vendor/bin:/vendor/xbin
    selene:/ $
    ```
- 思路

    之所以要检测这些可执行文件的目录是否存在su文件是因为正常情况下，root过的手机都会依照传统方式通过执行su命令来提权切换到root用户下，那这就依靠在这些可执行文件的目录下放置su文件。对于Magisk来说，同样也是在每次启动后去动态修改bin目录，先是将magisk、magiskinit放入自身文件下的bin目录，再将例如su、magiskhide等做magisk的软链，最后通过bind mount同步到真实的bin目录下达到修改bin的效果
    ```c&#43;&#43;
    // native/jni/core/module.cpp
    static void inject_magisk_bins(root_node *system) {
        auto bin = system-&gt;child&lt;inter_node&gt;(&#34;bin&#34;);
        if (!bin) {
            bin = new inter_node(&#34;bin&#34;, &#34;&#34;);
            system-&gt;insert(bin);
        }

        // Insert binaries
        bin-&gt;insert(new magisk_node(&#34;magisk&#34;));
        bin-&gt;insert(new magisk_node(&#34;magiskinit&#34;));

        // Also delete all applets to make sure no modules can override it
        for (int i = 0; applet_names[i]; &#43;&#43;i)
            delete bin-&gt;extract(applet_names[i]);
        for (int i = 0; init_applet[i]; &#43;&#43;i)
            delete bin-&gt;extract(init_applet[i]);
    }

    class magisk_node : public node_entry {
    public:
        explicit magisk_node(const char *name) : node_entry(name, DT_REG, this) {}

        void mount() override {
            const string &amp;dir_name = parent()-&gt;node_path();
            if (name() == &#34;magisk&#34;) {
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
    所以，可以在/system/bin目录下看到magisk所做的变动，通过这个方面来检测magisk
    ```shell
    selene:/ $ ls -al /system/bin |grep magisk
    -rwxr-xr-x  1 root root   170224 2023-06-16 17:00 magisk
    lrwxrwxrwx  1 root root        8 2023-06-16 17:00 magiskhide -&gt; ./magisk
    -rwxr-xr-x  1 root root  3987848 2023-06-16 17:00 magiskinit
    lrwxrwxrwx  1 root root       12 2023-06-16 17:00 magiskpolicy -&gt; ./magiskinit
    lrwxrwxrwx  1 root root        8 2023-06-16 17:00 resetprop -&gt; ./magisk
    lrwxrwxrwx  1 root root        8 2023-06-16 17:00 su -&gt; ./magisk
    lrwxrwxrwx  1 root root       12 2023-06-16 17:00 supolicy -&gt; ./magiskinit
    ```
##### 1.2 Magisk模块篡改系统文件检测
- 检测方式

    ```c&#43;&#43;
    static jint haveMagicMount(JNIEnv *env __unused, jclass clazz __unused) {
        dev_t data_dev = scan_mountinfo();
        if (data_dev == 0) return -1;
        return scan_maps(data_dev);
    }

    static dev_t scan_mountinfo() {
        int major = 0;
        int minor = 0;
        char line[PATH_MAX];
        char mountinfo[] = &#34;/proc/self/mountinfo&#34;;
        int fd = sys_open(mountinfo, O_RDONLY, 0);
        if (fd &lt; 0) {
            LOGE(&#34;cannot open %s&#34;, mountinfo);
            return 0;
        }
        FILE *fp = fdopen(fd, &#34;r&#34;);
        if (fp == NULL) {
            LOGE(&#34;cannot open %s&#34;, mountinfo);
            close(fd);
            return 0;
        }
        // 遍历mountinfo文件，判断存在/ /data的行时拿它的设备号
        while (fgets(line, PATH_MAX - 1, fp) != NULL) {
            if (strstr(line, &#34;/ /data &#34;) != NULL) {
                sscanf(line, &#34;%*d %*d %d:%d&#34;, &amp;major, &amp;minor);
            }
        }
        fclose(fp);
        // 根据major和minor创建设备号
        return makedev(major, minor);
    }

    static int scan_maps(dev_t data_dev) {
        int module = 0;
        char line[PATH_MAX];
        char maps[] = &#34;/proc/self/maps&#34;;
        int fd = sys_open(maps, O_RDONLY, 0);
        if (fd &lt; 0) {
            LOGE(&#34;cannot open %s&#34;, maps);
            return -1;
        }
        FILE *fp = fdopen(fd, &#34;r&#34;);
        if (fp == NULL) {
            LOGE(&#34;cannot open %s&#34;, maps);
            close(fd);
            return -1;
        }
        while (fgets(line, PATH_MAX - 1, fp) != NULL) {
            // 在maps的内容里判断都否存在/data目录下的设备号
            if (strchr(line, &#39;/&#39;) == NULL) continue;
            if (strstr(line, &#34; /system/&#34;) != NULL ||
                strstr(line, &#34; /vendor/&#34;) != NULL ||
                strstr(line, &#34; /product/&#34;) != NULL ||
                strstr(line, &#34; /system_ext/&#34;) != NULL) {
                int f;
                int s;
                char p[PATH_MAX];
                sscanf(line, &#34;%*s %*s %*s %x:%x %*s %s&#34;, &amp;f, &amp;s, p);
                if (makedev(f, s) == data_dev) {
                    LOGW(&#34;Magisk module file %x:%x %s&#34;, f, s, p);
                    module&#43;&#43;;
                }
            }
        }
        fclose(fp);
        return module;
    }
    ```
- 思路

    我理解是在Android系统中，类似system、vendor、product这些都属于系统相关的镜像，它们挂载到设备上时分区通常是只读的，而相对而言，data分区是可读写的，因此某些magisk模块会通过挂载的方式将例如system挂载到/data/system下面，从而完成对system分区的修改。
    &gt;
    这样做的检测原理是例如当访问/system/build.prop时，实际上却是访问/data/system/build.prop，在上面的检测逻辑中是先获取挂载信息中/data目录相关的挂载设备号，例如
    ```shell
    selene:/ # cat /proc/7428/mountinfo |grep &#34;/ /data&#34;
    94628 94522 253:6 / /data rw,nosuid,nodev,noatime master:42 - f2fs /dev/block/dm-6 rw,lazytime,seclabel,background_gc=on,gc_merge,discard,no_heap,user_xattr,inline_xattr,acl,inline_data,inline_dentry,extent_cache,mode=adaptive,active_logs=6,reserve_root=54072,resuid=0,resgid=1065,inlinecrypt,alloc_mode=default,checkpoint_merge,fsync_mode=nobarrier
    136334 94522 0:36 / /data_mirror rw,nosuid,nodev,noexec,relatime master:43 - tmpfs tmpfs rw,seclabel,size=1906244k,nr_inodes=476561,mode=700,gid=1000
    141106 94628 0:155 / /data/data rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,mode=751
    141107 94628 0:156 / /data/user rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,mode=751
    141108 94628 0:157 / /data/user_de rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,mode=751
    141111 94628 0:158 / /data/misc/profiles/cur rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,seclabel,mode=751 
    ```
    像253:6、0:36这样的主设备号:次设备号的结构，接着去maps中寻找是否system、vendor、product中是否包含相同设备号的，例如
    ```shell
    7cd43b5000-7cd43b6000 r--s 00000000 fd:06 924                            /data/resource-cache/vendor@overlay@MiuiFrameworkResOverlay.apk@idmap
    7cd4424000-7cd4425000 r--s 00000000 fd:02 2543                           /vendor/overlay/DevicesAndroidOverlay.apk
    7cd4425000-7cd4426000 r--s 00002000 fd:02 2543                           /vendor/overlay/DevicesAndroidOverlay.apk
    7cd4426000-7cd4427000 r--s 00000000 fd:06 920                            /data/resource-cache/vendor@overlay@DevicesAndroidOverlay.apk@idmap
    7cd445a000-7cd445c000 r--s 00000000 fd:02 2539                           /vendor/overlay/AospFrameworkResOverlay.apk
    7cd445c000-7cd445d000 r--s 00000000 fd:06 919                            /data/resource-cache/vendor@overlay@AospFrameworkResOverlay.apk@idmap
    7cd4497000-7cd4499000 r--s 00000000 fd:02 2541                           /vendor/overlay/DeviceAndroidConfig.apk
    7cd4499000-7cd449a000 r--s 00000000 fd:06 918                            /data/resource-cache/vendor@overlay@DeviceAndroidConfig.apk@idmap
    7cd44fa000-7cd44fb000 r--s 00000000 fd:02 2546                           /vendor/overlay/FrameworkResOverlay/FrameworkResOverlay.apk
    7cd44fb000-7cd44fc000 r--s 00002000 fd:02 2546                           /vendor/overlay/FrameworkResOverlay/FrameworkResOverlay.apk
    7cd44fc000-7cd44fd000 r--s 00000000 fd:06 917                            /data/resource-cache/vendor@overlay@FrameworkResOverlay@FrameworkResOverlay.apk@idmap
    7cd47d5000-7cd47e0000 r--p 00000000 fd:01 3517                           /system/lib64/vendor.mediatek.hardware.mms@1.2.so
    7cd47e0000-7cd47e8000 r-xp 0000b000 fd:01 3517                           /system/lib64/vendor.mediatek.hardware.mms@1.2.so
    7cd47e8000-7cd47ea000 r--p 00013000 fd:01 3517                           /system/lib64/vendor.mediatek.hardware.mms@1.2.so
    7cd47ea000-7cd47eb000 rw-p 00014000 fd:01 3517                           /system/lib64/vendor.mediatek.hardware.mms@1.2.so
    ```
    取出像01:3517、02:2541设备号来检测一致性
    
    上述检测异常结果并没有在Android11上复现，待后续分析原因
##### 1.3 Magisk Hide开启检测
- 检测方式

    ```c&#43;&#43;
    static int scan_status() {
        if (getppid() == 1) return -1;
        int pid = -1;
        char line[PATH_MAX];
        char maps[] = &#34;/proc/self/status&#34;;
        int fd = sys_open(maps, O_RDONLY, 0);
        if (fd &lt; 0) {
            LOGE(&#34;cannot open %s&#34;, maps);
            return -1;
        }
        FILE *fp = fdopen(fd, &#34;r&#34;);
        if (fp == NULL) {
            LOGE(&#34;cannot open %s&#34;, maps);
            close(fd);
            return -1;
        }
        // 遍历status文件查看TracerPid的值为否为0
        while (fgets(line, PATH_MAX - 1, fp) != NULL) {
            if (strncmp(line, &#34;TracerPid&#34;, 9) == 0) {
                pid = atoi(&amp;line[10]);
                break;
            }
        }
        fclose(fp);
        return pid;
    }
    ```

- 思路

    检测逻辑比较简单，比较maps中的TracerPid是否为0，更有意思的是它的检测时机，首先看看AndroidManifest.xml
    ```shell
    # app/src/main/AndroidManifest.xml
    &lt;application
        android:allowBackup=&#34;false&#34;
        android:label=&#34;@string/app_name&#34;
        android:supportsRtl=&#34;true&#34;
        android:theme=&#34;@android:style/Theme.DeviceDefault&#34;
        android:zygotePreloadName=&#34;io.github.vvb2060.magiskdetector.AppZygote&#34;
        tools:ignore=&#34;AllowBackup,MissingApplicationIcon&#34;
        tools:targetApi=&#34;q&#34;&gt;
        
        ......

        &lt;service
            android:name=&#34;.RemoteService&#34;
            android:isolatedProcess=&#34;true&#34;
            android:useAppZygote=&#34;true&#34; /&gt;

    &lt;/application&gt;
    ```
    首先是引用了zygotePreloadName这个属性，它是在Android 4.1后引入的，App可以通过该属性指定在Zygote启动时需要加载自定义的so并缓存到Zygote进程中。然后是isolatedProcess以及useAppZygote这两个属性，isolatedProcess是表示让service独立运行在进程中，而useAppZygote则从名字上能直接看出来，表明是否需要使用AppZygote模式
    
    有了上面这些属性的开启，就能确保检测进程以AppZygote模式启动，并且也在Zygote启动时加载检测so文件，之所以要以AppZygote的模式启动，也是因为为了要规避Magisk Hide的影响，可以从文档中以下两个方面的解释来看
    - &gt;Magisk Hide的实现核心是ptrace：magiskd跟踪zygote进程，监控fork和clone操作，即关注子进程创建及其线程创建。 被触发后读取/proc/pid/cmdline和uid判断是否为目标进程。 一般应用进程的cmdline在Java设置，此时已有主线程及JVM虚拟机工作线程。 在加载用户代码前，会至少有一次binder调用，使binder线程启动，此操作触发magiskhide卸载挂载
    - &gt; 唯一的例外是app zygote，它和zygote一样通过socket通信，没有binder线程。在设置cmdline和加载用户代码之间没有线程启动， 因此，可以检测是否被ptrace来判断magiskhide的存在，即使不在隐藏列表中，只要开启功能，就会被发现

    可以从进程列表上看
    ```shell
    selene:/ # ps -ef|grep vvb
    u0_a244        6375    607 0 11:16:12 ?     00:00:01 io.github.vvb2060.magiskdetector
    u0_a244        7285    607 0 11:38:22 ?     00:00:00 io.github.vvb2060.magiskdetector_zygote
    u0_i0          7295   7285 1 11:38:22 ?     00:00:00 io.github.vvb2060.magiskdetector:io.github.vvb2060.magiskdetector.RemoteService
    root           7322   6346 3 11:38:35 pts/27 00:00:00 grep vvb
    ```
    启动了名为io.github.vvb2060.magiskdetector_zygote的AppZygote进程，而就是通过这个检测来判断TracerPid
    
    从源码角度来看看AppZygote进程和App进程启动方式的区别，直接从AMS看起
    ```java
    // frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java
    @GuardedBy(&#34;this&#34;)
    final ProcessRecord startProcessLocked(String processName,
            ApplicationInfo info, boolean knownToBeDead, int intentFlags,
            HostingRecord hostingRecord, int zygotePolicyFlags, boolean allowWhileBooting,
            boolean isolated) {
        return mProcessList.startProcessLocked(processName, info, knownToBeDead, intentFlags,
                hostingRecord, zygotePolicyFlags, allowWhileBooting, isolated, 0 /* isolatedUid */,
                false /* isSdkSandbox */, 0 /* sdkSandboxClientAppUid */,
                null /* sdkSandboxClientAppPackage */,
                null /* ABI override */, null /* entryPoint */,
                null /* entryPointArgs */, null /* crashHandler */);
    }

    // frameworks/base/services/core/java/com/android/server/am/ProcessList.java
    @GuardedBy(&#34;mService&#34;)
    boolean startProcessLocked(HostingRecord hostingRecord, String entryPoint, ProcessRecord app,
            int uid, int[] gids, int runtimeFlags, int zygotePolicyFlags, int mountExternal,
            String seInfo, String requiredAbi, String instructionSet, String invokeWith,
            long startUptime, long startElapsedTime) {
        app.setPendingStart(true);
        app.setRemoved(false);
        
        ......

        if (mService.mConstants.FLAG_PROCESS_START_ASYNC) {
            if (DEBUG_PROCESSES) Slog.i(TAG_PROCESSES,
                    &#34;Posting procStart msg for &#34; &#43; app.toShortString());
            mService.mProcStartHandler.post(() -&gt; handleProcessStart(
                    app, entryPoint, gids, runtimeFlags, zygotePolicyFlags, mountExternal,
                    requiredAbi, instructionSet, invokeWith, startSeq));
            return true;
        } else {
            try {
                // 调用startProcess
                final Process.ProcessStartResult startResult = startProcess(hostingRecord,
                        entryPoint, app,
                        uid, gids, runtimeFlags, zygotePolicyFlags, mountExternal, seInfo,
                        requiredAbi, instructionSet, invokeWith, startUptime);
                handleProcessStartedLocked(app, startResult.pid, startResult.usingWrapper,
                        startSeq, false);
            } catch (RuntimeException e) {
                Slog.e(ActivityManagerService.TAG, &#34;Failure starting process &#34;
                        &#43; app.processName, e);
                app.setPendingStart(false);
                mService.forceStopPackageLocked(app.info.packageName, UserHandle.getAppId(app.uid),
                        false, false, true, false, false, app.userId, &#34;start failure&#34;);
            }
            return app.getPid() &gt; 0;
        }
    }

    private Process.ProcessStartResult startProcess(HostingRecord hostingRecord, String entryPoint,
            ProcessRecord app, int uid, int[] gids, int runtimeFlags, int zygotePolicyFlags,
            int mountExternal, String seInfo, String requiredAbi, String instructionSet,
            String invokeWith, long startTime) {
        try {
            
            ......

            final Process.ProcessStartResult startResult;
            boolean regularZygote = false;
            if (hostingRecord.usesWebviewZygote()) {
                startResult = startWebView(entryPoint,
                        app.processName, uid, uid, gids, runtimeFlags, mountExternal,
                        app.info.targetSdkVersion, seInfo, requiredAbi, instructionSet,
                        app.info.dataDir, null, app.info.packageName,
                        app.getDisabledCompatChanges(),
                        new String[]{PROC_START_SEQ_IDENT &#43; app.getStartSeq()});
            } else if (hostingRecord.usesAppZygote()) {
                final AppZygote appZygote = createAppZygoteForProcessIfNeeded(app);

                // We can&#39;t isolate app data and storage data as parent zygote already did that.
                startResult = appZygote.getProcess().start(entryPoint,
                        app.processName, uid, uid, gids, runtimeFlags, mountExternal,
                        app.info.targetSdkVersion, seInfo, requiredAbi, instructionSet,
                        app.info.dataDir, null, app.info.packageName,
                        /*zygotePolicyFlags=*/ ZYGOTE_POLICY_FLAG_EMPTY, isTopApp,
                        app.getDisabledCompatChanges(), pkgDataInfoMap, allowlistedAppDataInfoMap,
                        false, false,
                        new String[]{PROC_START_SEQ_IDENT &#43; app.getStartSeq()});
            } else {
                regularZygote = true;
                startResult = Process.start(entryPoint,
                        app.processName, uid, uid, gids, runtimeFlags, mountExternal,
                        app.info.targetSdkVersion, seInfo, requiredAbi, instructionSet,
                        app.info.dataDir, invokeWith, app.info.packageName, zygotePolicyFlags,
                        isTopApp, app.getDisabledCompatChanges(), pkgDataInfoMap,
                        allowlistedAppDataInfoMap, bindMountAppsData, bindMountAppStorageDirs,
                        new String[]{PROC_START_SEQ_IDENT &#43; app.getStartSeq()});
            }
            return startResult;
        } finally {
            Trace.traceEnd(Trace.TRACE_TAG_ACTIVITY_MANAGER);
        }
    }
    ```
    只看关键点，根据传入的hostingRecord判断启动什么样的进程，如果是AppZygote进程，则
    ```java
    // frameworks/base/services/core/java/com/android/server/am/ProcessList.java
    private AppZygote createAppZygoteForProcessIfNeeded(final ProcessRecord app) {
        synchronized (mService) {
            // The UID for the app zygote should be the UID of the application hosting
            // the service.
            final int uid = app.hostingRecord.getDefiningUid();
            AppZygote appZygote = mAppZygotes.get(app.info.processName, uid);
            final ArrayList&lt;ProcessRecord&gt; zygoteProcessList;
            if (appZygote == null) {
                if (DEBUG_PROCESSES) {
                    Slog.d(TAG_PROCESSES, &#34;Creating new app zygote.&#34;);
                }
                final IsolatedUidRange uidRange =
                        mAppIsolatedUidRangeAllocator.getIsolatedUidRangeLocked(
                                app.info.processName, app.hostingRecord.getDefiningUid());
                final int userId = UserHandle.getUserId(uid);
                // Create the app-zygote and provide it with the UID-range it&#39;s allowed
                // to setresuid/setresgid to.
                final int firstUid = UserHandle.getUid(userId, uidRange.mFirstUid);
                final int lastUid = UserHandle.getUid(userId, uidRange.mLastUid);
                ApplicationInfo appInfo = new ApplicationInfo(app.info);
                // If this was an external service, the package name and uid in the passed in
                // ApplicationInfo have been changed to match those of the calling package;
                // that is not what we want for the AppZygote though, which needs to have the
                // packageName and uid of the defining application. This is because the
                // preloading only makes sense in the context of the defining application,
                // not the calling one.
                appInfo.packageName = app.hostingRecord.getDefiningPackageName();
                appInfo.uid = uid;
                appZygote = new AppZygote(appInfo, uid, firstUid, lastUid);
                mAppZygotes.put(app.info.processName, uid, appZygote);
                zygoteProcessList = new ArrayList&lt;ProcessRecord&gt;();
                mAppZygoteProcesses.put(appZygote, zygoteProcessList);
            } else {
                if (DEBUG_PROCESSES) {
                    Slog.d(TAG_PROCESSES, &#34;Reusing existing app zygote.&#34;);
                }
                mService.mHandler.removeMessages(KILL_APP_ZYGOTE_MSG, appZygote);
                zygoteProcessList = mAppZygoteProcesses.get(appZygote);
            }
            // Note that we already add the app to mAppZygoteProcesses here;
            // this is so that another thread can&#39;t come in and kill the zygote
            // before we&#39;ve even tried to start the process. If the process launch
            // goes wrong, we&#39;ll clean this up in removeProcessNameLocked()
            zygoteProcessList.add(app);

            return appZygote;
        }
    }
    ```
    主要是创建了AppZygote的对象，接着会调用getProcess方法，而getProcess中就创建了AppZygote的进程
    ```java
    // frameworks/base/core/java/android/os/AppZygote.java
    public ChildZygoteProcess getProcess() {
        synchronized (mLock) {
            if (mZygote != null) return mZygote;

            connectToZygoteIfNeededLocked();
            return mZygote;
        }
    }

    @GuardedBy(&#34;mLock&#34;)
    private void connectToZygoteIfNeededLocked() {
        String abi = mAppInfo.primaryCpuAbi != null ? mAppInfo.primaryCpuAbi :
                Build.SUPPORTED_ABIS[0];
        try {
            int runtimeFlags = Zygote.getMemorySafetyRuntimeFlagsForSecondaryZygote(
                    mAppInfo, mProcessInfo);
            // 创建了ChildZygote进程，可以认为这个就是AppZygote进程
            mZygote = Process.ZYGOTE_PROCESS.startChildZygote(
                    &#34;com.android.internal.os.AppZygoteInit&#34;,
                    mAppInfo.processName &#43; &#34;_zygote&#34;,
                    mZygoteUid,
                    mZygoteUid,
                    null,  // gids
                    runtimeFlags,
                    &#34;app_zygote&#34;,  // seInfo
                    abi,  // abi
                    abi, // acceptedAbiList
                    VMRuntime.getInstructionSet(abi), // instructionSet
                    mZygoteUidGidMin,
                    mZygoteUidGidMax);

            ZygoteProcess.waitForConnectionToZygote(mZygote.getPrimarySocketAddress());
            // preload application code in the zygote
            Log.i(LOG_TAG, &#34;Starting application preload.&#34;);
            mZygote.preloadApp(mAppInfo, abi);
            Log.i(LOG_TAG, &#34;Application preload done.&#34;);
        } catch (Exception e) {
            Log.e(LOG_TAG, &#34;Error connecting to app zygote&#34;, e);
            stopZygoteLocked();
        }
    }
    ```
    可以看到是通过ZYGOTE_PROCESS的startChildZygote来启动的进程，而正常的App则是这么启动的
    ```java
    // core/java/android/os/Process.java
    public static ProcessStartResult start(@NonNull final String processClass,
                                           @Nullable final String niceName,
                                           int uid, int gid, @Nullable int[] gids,
                                           int runtimeFlags,
                                           int mountExternal,
                                           int targetSdkVersion,
                                           @Nullable String seInfo,
                                           @NonNull String abi,
                                           @Nullable String instructionSet,
                                           @Nullable String appDataDir,
                                           @Nullable String invokeWith,
                                           @Nullable String packageName,
                                           int zygotePolicyFlags,
                                           boolean isTopApp,
                                           @Nullable long[] disabledCompatChanges,
                                           @Nullable Map&lt;String, Pair&lt;String, Long&gt;&gt;
                                                   pkgDataInfoMap,
                                           @Nullable Map&lt;String, Pair&lt;String, Long&gt;&gt;
                                                   whitelistedDataInfoMap,
                                           boolean bindMountAppsData,
                                           boolean bindMountAppStorageDirs,
                                           @Nullable String[] zygoteArgs) {
        return ZYGOTE_PROCESS.start(processClass, niceName, uid, gid, gids,
                    runtimeFlags, mountExternal, targetSdkVersion, seInfo,
                    abi, instructionSet, appDataDir, invokeWith, packageName,
                    zygotePolicyFlags, isTopApp, disabledCompatChanges,
                    pkgDataInfoMap, whitelistedDataInfoMap, bindMountAppsData,
                    bindMountAppStorageDirs, zygoteArgs);
    }

    //core/java/android/os/ZygoteProcess.java
    public final Process.ProcessStartResult start(@NonNull final String processClass,
                                                  final String niceName,
                                                  int uid, int gid, @Nullable int[] gids,
                                                  int runtimeFlags, int mountExternal,
                                                  int targetSdkVersion,
                                                  @Nullable String seInfo,
                                                  @NonNull String abi,
                                                  @Nullable String instructionSet,
                                                  @Nullable String appDataDir,
                                                  @Nullable String invokeWith,
                                                  @Nullable String packageName,
                                                  int zygotePolicyFlags,
                                                  boolean isTopApp,
                                                  @Nullable long[] disabledCompatChanges,
                                                  @Nullable Map&lt;String, Pair&lt;String, Long&gt;&gt;
                                                          pkgDataInfoMap,
                                                  @Nullable Map&lt;String, Pair&lt;String, Long&gt;&gt;
                                                          whitelistedDataInfoMap,
                                                  boolean bindMountAppsData,
                                                  boolean bindMountAppStorageDirs,
                                                  @Nullable String[] zygoteArgs) {
        // TODO (chriswailes): Is there a better place to check this value?
        if (fetchUsapPoolEnabledPropWithMinInterval()) {
            informZygotesOfUsapPoolStatus();
        }

        try {
            return startViaZygote(processClass, niceName, uid, gid, gids,
                    runtimeFlags, mountExternal, targetSdkVersion, seInfo,
                    abi, instructionSet, appDataDir, invokeWith, /*startChildZygote=*/ false,
                    packageName, zygotePolicyFlags, isTopApp, disabledCompatChanges,
                    pkgDataInfoMap, whitelistedDataInfoMap, bindMountAppsData,
                    bindMountAppStorageDirs, zygoteArgs);
        } catch (ZygoteStartFailedEx ex) {
            Log.e(LOG_TAG,
                    &#34;Starting VM process through Zygote failed&#34;);
            throw new RuntimeException(
                    &#34;Starting VM process through Zygote failed&#34;, ex);
        }
    }
    ```
    差异在于startViaZygote与startChildZygote的不同，而startChildZygote的关键在于
    ```java
    // core/java/android/os/ZygoteProcess.java
    if (startChildZygote) {
        argsForZygote.add(&#34;--start-child-zygote&#34;);
    }
    ```
    启动参数的不同，在Zygote处理命令时的不同
    ```java
    // core/java/com/android/internal/os/ZygoteInit.java
    /**
     * The main function called when started through the zygote process. This could be unified with
     * main(), if the native code in nativeFinishInit() were rationalized with Zygote startup.&lt;p&gt;
     *
     * Current recognized args:
     * &lt;ul&gt;
     * &lt;li&gt; &lt;code&gt; [--] &amp;lt;start class name&amp;gt;  &amp;lt;args&amp;gt;
     * &lt;/ul&gt;
     *
     * @param targetSdkVersion target SDK version
     * @param disabledCompatChanges set of disabled compat changes for the process (all others
     *                              are enabled)
     * @param argv             arg strings
     */
    public static final Runnable zygoteInit(int targetSdkVersion, long[] disabledCompatChanges,
            String[] argv, ClassLoader classLoader) {
        if (RuntimeInit.DEBUG) {
            Slog.d(RuntimeInit.TAG, &#34;RuntimeInit: Starting application from zygote&#34;);
        }

        Trace.traceBegin(Trace.TRACE_TAG_ACTIVITY_MANAGER, &#34;ZygoteInit&#34;);
        RuntimeInit.redirectLogStreams();

        RuntimeInit.commonInit();
        // 启动binder线程池
        ZygoteInit.nativeZygoteInit();
        return RuntimeInit.applicationInit(targetSdkVersion, disabledCompatChanges, argv,
                classLoader);
    }

    /**
     * The main function called when starting a child zygote process. This is used as an alternative
     * to zygoteInit(), which skips calling into initialization routines that start the Binder
     * threadpool.
     */
    static final Runnable childZygoteInit(
            int targetSdkVersion, String[] argv, ClassLoader classLoader) {
        RuntimeInit.Arguments args = new RuntimeInit.Arguments(argv);
        return RuntimeInit.findStaticMain(args.startClass, args.startArgs, classLoader);
    }
    ```
    相比于zygoteInit，childZygoteInit跳过了zygoteInit的步骤（也就是初始化binder线程池的步骤）
    ```c
    // core/jni/AndroidRuntime.cpp
    static void com_android_internal_os_ZygoteInit_nativeZygoteInit(JNIEnv* env, jobject clazz)
    {
        gCurRuntime-&gt;onZygoteInit();
    }

    // cmds/app_process/app_main.cpp
    virtual void onZygoteInit()
    {
        sp&lt;ProcessState&gt; proc = ProcessState::self();
        ALOGV(&#34;App process: starting thread pool.\n&#34;);
        // binder线程池启动
        proc-&gt;startThreadPool();
    }
    ```


#### 2 DetectMagiskHide
来源于开源项目[DetectMagiskHide](https://github.com/darvincisec/DetectMagiskHide)（现已停止维护），作者也通过一篇[文章](https://darvincitech.wordpress.com/2019/11/04/detecting-magisk-hide/)来阐述他的想法，想法和上一个项目类似，也是寻找到MagiskHide的漏洞，当service存在于一个独立的isolated process中时，MagiskHide无法改变其namespace，因此service就可以用常规的su/magisk检测手段来做检测了，具体看看代码
```xml
&lt;?xml version=&#34;1.0&#34; encoding=&#34;utf-8&#34;?&gt;
&lt;manifest xmlns:android=&#34;http://schemas.android.com/apk/res/android&#34;
    xmlns:tools=&#34;http://schemas.android.com/tools&#34;
    package=&#34;com.darvin.security&#34;&gt;

    &lt;application
        android:allowBackup=&#34;false&#34;
        android:icon=&#34;@mipmap/ic_launcher&#34;
        android:label=&#34;@string/app_name&#34;
        android:roundIcon=&#34;@mipmap/ic_launcher_round&#34;
        android:supportsRtl=&#34;true&#34;
        android:zygotePreloadName=&#34;.AppZygotePreload&#34;
        android:theme=&#34;@style/AppTheme&#34;
        tools:targetApi=&#34;q&#34;&gt;
        &lt;activity android:name=&#34;.DetectMagisk&#34;
            android:exported=&#34;true&#34;&gt;
            &lt;intent-filter&gt;
                &lt;action android:name=&#34;android.intent.action.MAIN&#34; /&gt;

                &lt;category android:name=&#34;android.intent.category.LAUNCHER&#34; /&gt;
            &lt;/intent-filter&gt;
        &lt;/activity&gt;
        &lt;service
            android:name=&#34;.IsolatedService&#34;
            android:exported=&#34;false&#34;
            android:isolatedProcess=&#34;true&#34;
            android:useAppZygote=&#34;true&#34; /&gt;
    &lt;/application&gt;

&lt;/manifest&gt;
```
从AndroidManifest.xml上也能看出，zygotePreloadName指定了预加载so的类，isolatedProcess和useAppZygote也指定了IsolatedService作为独立进程，检测的方式也是常用的检测手段

##### 2.1 su文件检测
```c
static const char *suPaths[] = {
        &#34;/data/local/su&#34;,
        &#34;/data/local/bin/su&#34;,
        &#34;/data/local/xbin/su&#34;,
        &#34;/sbin/su&#34;,
        &#34;/su/bin/su&#34;,
        &#34;/system/bin/su&#34;,
        &#34;/system/bin/.ext/su&#34;,
        &#34;/system/bin/failsafe/su&#34;,
        &#34;/system/sd/xbin/su&#34;,
        &#34;/system/usr/we-need-root/su&#34;,
        &#34;/system/xbin/su&#34;,
        &#34;/cache/su&#34;,
        &#34;/data/su&#34;,
        &#34;/dev/su&#34;
};
static inline bool is_supath_detected() {
    int len = sizeof(suPaths) / sizeof(suPaths[0]);

    bool bRet = false;
    for (int i = 0; i &lt; len; i&#43;&#43;) {
        __android_log_print(ANDROID_LOG_INFO, TAG, &#34;Checking SU Path  :%s&#34;, suPaths[i]);
        if (open(suPaths[i], O_RDONLY) &gt;= 0) {
            __android_log_print(ANDROID_LOG_INFO, TAG, &#34;Found SU Path :%s&#34;, suPaths[i]);
            bRet = true;
            break;
        }
        if (0 == access(suPaths[i], R_OK)) {
            __android_log_print(ANDROID_LOG_INFO, TAG, &#34;Found SU Path :%s&#34;, suPaths[i]);
            bRet = true;
            break;
        }
    }

    return bRet;
}
```
##### 2.2 mount文件检测
```c
static char *blacklistedMountPaths[] = {
        &#34;magisk&#34;,
        &#34;core/mirror&#34;,
        &#34;core/img&#34;
};

static inline bool is_mountpaths_detected() {
    int len = sizeof(blacklistedMountPaths) / sizeof(blacklistedMountPaths[0]);

    bool bRet = false;

    FILE *fp = fopen(&#34;/proc/self/mounts&#34;, &#34;r&#34;);
    if (fp == NULL)
        goto exit;

    fseek(fp, 0L, SEEK_END);
    long size = ftell(fp);
    __android_log_print(ANDROID_LOG_INFO, TAG, &#34;Opening Mount file size: %ld&#34;, size);
    /* For some reason size comes as zero */
    if (size == 0)
        size = 20000;  /*This will differ for different devices */
    char *buffer = calloc(size, sizeof(char));
    if (buffer == NULL)
        goto exit;

    size_t read = fread(buffer, 1, size, fp);
    int count = 0;
    for (int i = 0; i &lt; len; i&#43;&#43;) {
        __android_log_print(ANDROID_LOG_INFO, TAG, &#34;Checking Mount Path  :%s&#34;, blacklistedMountPaths[i]);
        char *rem = strstr(buffer, blacklistedMountPaths[i]);
        if (rem != NULL) {
            count&#43;&#43;;
            __android_log_print(ANDROID_LOG_INFO, TAG, &#34;Found Mount Path :%s&#34;, blacklistedMountPaths[i]);
            break;
        }
    }
    if (count &gt; 0)
        bRet = true;

    exit:

    if (buffer != NULL)
        free(buffer);
    if (fp != NULL)
        fclose(fp);

    return bRet;
}
```

#### 3 MagiskKiller
来源于开源项目[MagiskKiller](https://github.com/canyie/MagiskKiller)（现已停止维护），作者在项目中也说明了适用于Magisk v23.0版本及以下，因此对于高版本的Magisk来说已经无法适用了

检测方式都来源于MagiskKiller类的detect方法
```java
public static int detect(String apk) {
    var detectTracerTask = detectTracer(apk);
    // int类型的result用来存储结果数据
    int result;
    // 检测Properties
    result = detectProperties();
    // 检测/dev/pts
    result |= detectMagiskPts();

    int tracer;
    try {
        // 检测trace
        tracer = detectTracerTask.call();
    } catch (Exception e) {
        throw new RuntimeException(&#34;wait trace checker&#34;, e);
    }
    if (tracer != 0) {
        Log.e(TAG, &#34;Found magiskd &#34; &#43; tracer);
        result |= FOUND_TRACER;
    }
    return result;
}
```
##### 3.1 detectProperties
- 检测方式
    ```java
    // app/src/main/java/top/canyie/magiskkiller/MagiskKiller.java
    public static int detectProperties() {
        int result = 0;
        try {
            result = detectBootloaderProperties();
            result |= detectDalvikConfigProperties();
        } catch (Exception e) {
            Log.e(TAG, &#34;Failed to check props&#34;, e);
        }
        return result;
    }

    private static int detectDalvikConfigProperties() {
        int result = 0;
        PropArea dalvikConfig = PropArea.any(&#34;dalvik_config_prop&#34;, &#34;exported_dalvik_prop&#34;, &#34;dalvik_prop&#34;);
        if (dalvikConfig == null) return 0;
        var values = dalvikConfig.findPossibleValues(&#34;ro.dalvik.vm.native.bridge&#34;);
        if (values.size() &gt; 1) {
            result |= FOUND_RESETPROP;
        }

        for (String value : values) {
            if (&#34;libriruloader.so&#34;.equals(value)) {
                result |= FOUND_RIRU;
                break;
            }
        }
        return result;
    }

    private static int detectBootloaderProperties() {
        int result = 0;
        // The better way to get the filename would be `getprop -Z`
        // But &#34;-Z&#34; option requires Android 7.0&#43;, and I&#39;m lazy to implement it
        PropArea bootloader = PropArea.any(&#34;bootloader_prop&#34;, &#34;exported2_default_prop&#34;, &#34;default_prop&#34;);
        if (bootloader == null) return 0;
        var values = bootloader.findPossibleValues(&#34;ro.boot.verifiedbootstate&#34;);
        // ro properties are read-only, multiple values found = the property has been modified by resetprop
        if (values.size() &gt; 1) {
            result |= FOUND_RESETPROP;
        }
        for (String value : values) {
            if (&#34;orange&#34;.equals(value)) {
                result |= FOUND_BOOTLOADER_UNLOCKED;
                result &amp;= ~FOUND_BOOTLOADER_SELF_SIGNED;
            } else if (&#34;yellow&#34;.equals(value) &amp;&amp; (result &amp; FOUND_BOOTLOADER_UNLOCKED) == 0) {
                result |= FOUND_BOOTLOADER_SELF_SIGNED;
            }
        }

        values = bootloader.findPossibleValues(&#34;ro.boot.vbmeta.device_state&#34;);
        if (values.size() &gt; 1) {
            result |= FOUND_RESETPROP;
        }
        for (String value : values) {
            if (&#34;unlocked&#34;.equals(value)) {
                result |= FOUND_BOOTLOADER_UNLOCKED;
                result &amp;= ~FOUND_BOOTLOADER_SELF_SIGNED;
                break;
            }
        }
        return result;
    }
    ```
- 思路
    关于prop的检测思路很简单，直接操作运行时的属性文件，读取其中的属性值
    - ro.boot.verifiedbootstate: 用来表示bl锁是否已经解锁，解锁后属性值为yellow
    - ro.boot.vbmeta.device_state: 同样用来表示设备完成性，当解锁bl或是刷入非官方boot时，属性值都会变成unlocked
    - ro.dalvik.vm.native.bridge: 正常情况下会是0，但是riru修改了该属性，替换成了libriruloader，这样就能通过判断这个属性来检测是否加载了riru
    
##### 3.2 detectMagiskPts
- 检测方式
    ```java
    // Scan /dev/pts and check if there is an alive magisk pts
    // Use `magisk su` to open a root session to test it
    @SuppressLint({&#34;PrivateApi&#34;, &#34;DiscouragedPrivateApi&#34;})
    private static int detectMagiskPts() {
        Method getFileContext;

        // Os.getxattr is available since Oreo, fallback to getFileContext on pre O
        if (Build.VERSION.SDK_INT &lt; Build.VERSION_CODES.O) {
            try {
                getFileContext = Class.forName(&#34;android.os.SELinux&#34;)
                        .getDeclaredMethod(&#34;getFileContext&#34;, String.class);
                getFileContext.setAccessible(true);
            } catch (Throwable e) {
                Log.e(TAG, &#34;Failed to reflect getFileContext&#34;, e);
                return 0;
            }
        } else {
            getFileContext = null;
        }

        // Listing files under /dev/pts is not possible because of SELinux
        // So we manually recreate the folder structure
        // 轮询查找是否有可用的rts
        var basePts = new File(&#34;/dev/pts&#34;);
        for (int i = 0;i &lt; 1024;i&#43;&#43;) {
            var pts = new File(basePts, Integer.toString(i));

            // No more pts, break.
            if (!pts.exists()) break;

            // We found an active pts, check if it has magisk context.
            try {
                String ptsContext;
                if (getFileContext != null) {
                    ptsContext = (String) getFileContext.invoke(null, pts.getAbsolutePath());
                } else {
                    @SuppressLint({&#34;NewApi&#34;, &#34;LocalSuppress&#34;})
                    byte[] raw = Os.getxattr(pts.getAbsolutePath(), &#34;security.selinux&#34;);
                    // Os.getxattr returns the raw data which includes the C-style terminator (&#39;\0&#39;)
                    // We need to manually exclude it
                    int terminatorIndex = 0;
                    for (;terminatorIndex &lt; raw.length &amp;&amp; raw[terminatorIndex] != 0;terminatorIndex&#43;&#43;);
                    ptsContext = new String(raw, 0, terminatorIndex, StandardCharsets.UTF_8);
                }
                if (&#34;u:object_r:magisk_file:s0&#34;.equals(ptsContext))
                    return FOUND_MAGISK_PTS;
            } catch (Throwable e) {
                Log.e(TAG, &#34;Failed to check file context of &#34; &#43; pts, e);
            }
        }
        return 0;
    }
    ```
- 思路
    首先了解下/dev/pts，/dev/pts是一个特殊的文件系统，用于提供伪终端（pseudo terminal）设备。伪终端是一种虚拟的终端设备，它可以模拟物理终端设备的功能，让用户和程序可以像使用物理终端一样使用它来进行输入和输出。也就是说当我们使用adb去调试设备时，每当我们开启一个adb连接，/dev/pts目录下就会新增一个对应的文件，而也正可以通过这个方法来检测是否开启了magisk的pts，如下
    ```
    1|sailfish:/ # ls -alZ /dev/pts
    total 0
    drwxr-xr-x  2 root  root  u:object_r:devpts:s0             0 1970-01-01 08:00 .
    drwxr-xr-x 18 root  root  u:object_r:device:s0          3980 2022-02-11 00:16 ..
    crw-------  1 shell shell u:object_r:devpts:s0      136,   0 2022-02-12 02:11 0
    crw-------  1 shell shell u:object_r:magisk_file:s0 136,   1 2022-02-12 02:11 1
    crw-------  1 shell shell u:object_r:magisk_file:s0 136,   2 2022-02-12 02:12 2
    crw-------  1 shell shell u:object_r:devpts:s0      136,   3 2022-02-12 02:12 3
    crw-------  1 root  root  u:object_r:magisk_file:s0 136,   4 2022-02-12 02:11 4
    crw-------  1 shell shell u:object_r:devpts:s0      136,   5 2022-02-12 02:06 5
    ```
    查看/dev/pts目录下的文件属性可以看出，magisk_file特征的文件就是magisk pts
##### 3.3 detectTracerTask
最关键的一个检测手段，也是为了应对MagiskHide
- 检测方式
    ```java
    //app/src/main/java/top/canyie/magiskkiller/MagiskKiller.java
    public static Callable&lt;Integer&gt; detectTracer(String apk) {
        // Magisk Hide will attach processes with name=zygote/zygote64 and ppid=1
        // Orphan processes will have PPID=1
        // The return value is the pipe to communicate with the child process
        int rawReadFd = forkOrphan(apk);

        if (rawReadFd &lt; 0) throw new RuntimeException(&#34;fork failed&#34;);
        var readFd = ParcelFileDescriptor.adoptFd(rawReadFd);
        return () -&gt; {
            try (DataInputStream fis = new DataInputStream(new ParcelFileDescriptor.AutoCloseInputStream(readFd))) {
                return Integer.parseInt(fis.readUTF());
            }
        };
    }
    ```
    创建fd的过程
    ```c
    //app/src/main/cpp/main.cpp
    jint SafetyChecker_forkOrphan(JNIEnv* env, jclass, jstring apk) {
        // After forking we are no longer able to call many functions including JNI
        auto orig_apk_path = env-&gt;GetStringUTFChars(apk, nullptr);
        auto apk_path = strdup(orig_apk_path);
        env-&gt;ReleaseStringUTFChars(apk, orig_apk_path);
        // 获取apk_path

        // Create pipe to communicate with the child process
        // Do not use O_CLOEXEC as we want to write to pipe after exec
        int fd[2];
        if (pipe(fd) == -1) return -1;
        // 创建匿名管道
        int read_fd = fd[0];
        int write_fd = fd[1];

        char tmp[32];
        snprintf(tmp, sizeof(tmp), &#34;%d&#34;, write_fd);
        auto fd_arg = strdup(tmp);
        // fd_arg是write_fd

        pid_t pid = fork();
        if (pid &lt; 0) return pid; // fork failed
        // 调用fork产生子进程
        if (pid == 0) { // child process
            close(read_fd);
            // 在子进程中再次调用fork
            pid = fork();
            if (pid &gt; 0) {
                exit(0);
            } else if (pid &lt; 0) {
                // fork failed, exit to trigger EOFException when reader reads from pipe
                LOGE(&#34;fork() failed with %d: %s&#34;, errno, strerror(errno));
                close(write_fd);
                abort();
            }
            // 杀死父进程，保证子进程是孤儿进程以便于让zygote接管，ppid=1
            // pid == 0, make sure we&#39;re orphan process (parent died)
            kill(getppid(), SIGKILL);

            // After fork we cannot call many functions including JNI (otherwise we may deadlock)
            // Call execl() to recreate runtime and run our checking code
            // 创建新进程，名称为zygote，执行的类为SubprocessMain，传入pipe的fd
            setenv(&#34;CLASSPATH&#34;, apk_path, 1);
            execl(&#34;/system/bin/app_process&#34;,
                &#34;/system/bin/app_process&#34;,
                &#34;/system/bin&#34;,
                // We already have PPID=1, set process name to zygote
                // MagiskHide will think we&#39;re zygote and attach us
                &#34;--nice-name=zygote&#34;,
                &#34;top.canyie.magiskkiller.SubprocessMain&#34;,
                &#34;--write-fd&#34;,
                fd_arg,
                (char*) nullptr);

            // execl() only returns if failed
            LOGE(&#34;execl() failed with %d: %s&#34;, errno, strerror(errno));
            abort();
        }
        // parent process
        free(fd_arg);
        free(apk_path);
        close(write_fd);
        return read_fd;
    }
    ```
    到这步已经创建好了基于SubprocessMain类的新进程，这个进程ppid=1并且名为zygote，可以被MagiskHide attach
    ```java
    //app/src/main/java/top/canyie/magiskkiller/SubprocessMain.java
    public class SubprocessMain {
        public static void main(String[] args) {
            // 解析出writeFd
            // Parse fd
            if (args.length != 2 || !&#34;--write-fd&#34;.equals(args[0])) {
                String error = &#34;Bad args passed: &#34; &#43; Arrays.toString(args);
                System.err.println(error);
                Log.e(MagiskKiller.TAG, error);
                System.exit(1);
            }
            ParcelFileDescriptor writeFd = null;
            try {
                writeFd = ParcelFileDescriptor.adoptFd(Integer.parseInt(args[1]));
            } catch (Exception e) {
                System.err.println(&#34;Unable to parse &#34; &#43; args[1]);
                e.printStackTrace();
                Log.e(MagiskKiller.TAG, &#34;Unable to parse &#34; &#43; args[1], e);
                System.exit(1);
            }
            try {
                // 获取tracer，将tracer的pid写回pipe
                // Do our work and send the tracer&#39;s pid back to app
                int tracer = MagiskKiller.requestTrace();
                try (DataOutputStream fos = new DataOutputStream(new ParcelFileDescriptor.AutoCloseOutputStream(writeFd))) {
                    fos.writeUTF(Integer.toString(tracer));
                }
            } catch (Throwable e) {
                e.printStackTrace();
                Log.e(MagiskKiller.TAG, &#34;&#34;, e);
                System.exit(1);
            }
        }
    }

    //app/src/main/java/top/canyie/magiskkiller/MagiskKiller.java
    public static int getTracer() {
        try (BufferedReader br = new BufferedReader(new FileReader(&#34;/proc/self/status&#34;))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.startsWith(&#34;TracerPid:&#34;)) {
                    return Integer.parseInt(line.substring(&#34;TracerPid:&#34;.length()).trim());
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(&#34;read tracer&#34;, e);
        }
        return 0;
    }
    ```
    具体例子如下
    ```shell
    sailfish:/ $ ps -ef|grep magiskkiller
    u0_a148      30043   763 72 17:09:19 ?    00:00:01 top.canyie.magiskkiller
    u0_a148      30110     1 17 17:09:20 ?    00:00:00 app_process /system/bin --nice-name=zygote top.canyie.magiskkiller.SubprocessMain --write-fd 40
    ```
- 思路
    很巧妙的思路，因为MagiskHide会attach到zygote进程，监控zygote的动作，因此就可以主动构成一个伪zygote进程，主动让MagiskHide attach，这样就可以根据TracerPid来判断是否开启了MagiskHide

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/magisk%E6%A3%80%E6%B5%8B%E6%96%B9%E5%BC%8F/  

