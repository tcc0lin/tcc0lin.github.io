# Frida源码编译说明


### 一、编译环境搭建
这次编译的目标版本是14.2.18
#### 1 物料准备
- 设备：红米note11（MIUI12 Android11）
- frida源码：https://github.com/frida/frida
#### 2 工具准备
参照[官方编译指南](https://frida.re/docs/building/#gnulinux)

- 编译支撑系统：ubuntu23
    ```shell
    Linux ubuntu23 6.2.0-27-generic #28-Ubuntu SMP PREEMPT_DYNAMIC Wed Jul 12 22:39:51 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
    ```
    之所以选择ubuntu23而不是其他版本是因为在安装三方库的时候不用再额外考虑版本问题了，亲测这点太坑了
- frida源码下载
    ```shell
    git clone -b 14.2.18 --recurse-submodules https://github.com/frida/frida
    ```
    选择tag为14.2.18，不必全量clone再切换，后续的版本和当前版本差别较大，会造成无法正常编译，原因是因为直接使用checkout的话只是针对frida这个仓库，但是对于submodule来说版本依旧未变，需要执行如下命令
    ```shell
    git submodule update --recursive
    ```
- toolchain/sdk
    可以选择自己编译，但是为了减少不必要的麻烦，直接选择官方已经打好的编译产物，frida官方是存在toolchain/sdk的编译后的产物，可以直接下，下载链接的格式参考
    ```shell
    https://build.frida.re/deps/{frida_toolchain_version}/toolchain-linux-x86_64.tar.bz2
    ```
    frida_toolchain_version可以从releng/deps.mk中获取
    ```shell
    frida_toolchain_version = 20210419
    ```
    最终可得的下载地址是
    ```shell
    https://build.frida.re/deps/20210419/toolchain-linux-x86_64.tar.bz2  # toolchains 工具
    https://build.frida.re/deps/20210419/sdk-linux-x86_64.tar.bz2  # sdk 工具
    # 下面是需要编译的对应架构的文件
    https://build.frida.re/deps/20210419/sdk-android-x86.tar.bz2
    https://build.frida.re/deps/20210419/sdk-android-x86_64.tar.bz2
    https://build.frida.re/deps/20210419/sdk-android-arm.tar.bz2
    https://build.frida.re/deps/20210419/sdk-android-arm64.tar.bz2  
    ```
    将上面的四个文件分别下载好后放在frida/build目录下（没有可新建），执行命令
    ```shell
    bash releng/setup-env.sh
    ```
    输出结果如下
    ```shell
    Assuming host is linux-x86_64 Set FRIDA_HOST to override.
    Deploying local toolchain toolchain-linux-x86_64.tar.bz2...
    Deploying local SDK sdk-linux-x86_64.tar.bz2...
    ```
- 三方库安装
    ```shell
    sudo apt-get install build-essential curl git lib32stdc++-9-dev libc6-dev-i386 nodejs npm python3-dev python3-pip
    ```
- ndk安装
    ```
    wget https://dl.google.com/android/repository/android-ndk-r22b-linux-x86_64.zip
    unzip android-ndk-r22-linux-x86_64.zip
    ```
    再添加到环境变量中
    ```
    export ANDROID_NDK_ROOT=xxxxxx
    export PATH=$ANDROID_NDK_ROOT:$PATH
    ```
    执行`ndk-build --v`如果有版本信息输出，说明环境变量配置生效了
### 二、编译流程
切换到frida项目根目录下执行命令`make core-android-arm64`
#### 1 缺少build/frida-version.h
```
make[1]: *** No rule to make target '.git/refs/heads/master', needed by 'build/frida-version.h'.  Stop.
```
需要在build目录下手动添加build/frida-version.h文件，内容如
```h
#ifndef __FRIDA_VERSION_H__
#define __FRIDA_VERSION_H__

#define FRIDA_VERSION "14.2.2"

#define FRIDA_MAJOR_VERSION 14
#define FRIDA_MINOR_VERSION 2
#define FRIDA_MICRO_VERSION 2
#define FRIDA_NANO_VERSION 0

#endif
```
#### 2 分支修改
下载的14.2.18版本，需要将`frida-deps.vcxproj`（4处）和`frida.mk`（1处）中的master修改为main
#### 3 执行编译
执行`make core-android-arm64`命令之后正常输出如下
```shell
Installing lib/gadget/frida-gadget.so to /home/linhanqiu/proj/frida/build/frida-android-arm64/lib/frida/64
This file does not have an rpath.
This file does not have a runpath.
Installing src/api/frida-core.h to /home/linhanqiu/proj/frida/build/frida-android-arm64/include/frida-1.0
Installing src/api/frida-core-1.0.vapi to /home/linhanqiu/proj/frida/build/frida-android-arm64/share/vala/vapi
Installing src/api/frida-core-1.0.deps to /home/linhanqiu/proj/frida/build/frida-android-arm64/share/vala/vapi
Installing src/api/libfrida-core-1.0.a to /home/linhanqiu/proj/frida/build/frida-android-arm64/lib
Installing server/frida-server to /home/linhanqiu/proj/frida/build/frida-android-arm64/bin
This file does not have an rpath.
This file does not have a runpath.
Installing inject/frida-inject to /home/linhanqiu/proj/frida/build/frida-android-arm64/bin
This file does not have an rpath.
This file does not have a runpath.
Installing /home/linhanqiu/proj/frida/frida-core/lib/selinux/frida-selinux.h to /home/linhanqiu/proj/frida/build/frida-android-arm64/include/frida-1.0
Installing /home/linhanqiu/proj/frida/build/tmp-android-arm64/frida-core/meson-private/frida-core-1.0.pc to /home/linhanqiu/proj/frida/build/frida-android-arm64/lib/pkgconfig
make[1]: Leaving directory '/home/linhanqiu/proj/frida'
```
由于选择的架构是arm64，对应的输出目录是build/tmp-android-arm64
### 三、产物测试
在官方版本列表上看frida-server14.2.18对应的python工具库版本
```shell
pip install frida==14.2.18
pip install frida-tools==9.2.4
```
测试具体案例
