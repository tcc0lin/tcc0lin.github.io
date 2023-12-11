# Android11AOSP编译流程

### 前言
### 一、编译环境搭建
#### 1 物料准备
- 设备：pixel2（walleye）
- 源码：[aosp源码](https://source.android.google.cn/docs/setup/about/build-numbers?hl=zh-cn)
    - build id：RP1A.200720.009
    - tag：android-11.0.0_r1
    - sdk version：Android11
- 驱动源码准备：[驱动源码](https://developers.google.cn/android/drivers)
#### 2 工具准备
- 编译支撑系统：centos7，使用公司的云容器（16核32G、600G磁盘）
- 三方库准备
    ```shell
    yum install -y gcc make libstdc++.i686 libstdc++-devel.i686 zlib-devel openssl-devel perl cpio expat-devel gettext-devel autoconf glibc.i686 glibc-devel.i686 zlib-devel.i686 libstdc++.i686 libX11-devel.i686 ncurses-devel.i686 ncurses-libs.i686 gperf flex gcc-c++ bison patch
    ```
- Java/Python环境准备
### 二、编译流程
- 源码下载
    ```shell
    // repo工具下载
    curl https://mirrors.tuna.tsinghua.edu.cn/git/git-repo > repo
    chmod a+x repo
    // 指定版本AOSP源码拉取
    ./repo init -u https://mirrors.tuna.tsinghua.edu.cn/git/AOSP/platform/manifest -b android-11.0.0_r48
    。/repo sync
    // 驱动解压放在源码根目录下，执行驱动脚本，会自动填充到vendor目录
    ./extract-google_devices-blueline.sh
    ./extract-qcom-blueline.sh
    ```

- 编译环境配置
    ```shell
    source build/envsetup.sh
    // 选择对应设备
    lunch
    ```

- 执行编译
    ```shell
    // 根据系统性能选择线程数
    make -j 4
    ```
