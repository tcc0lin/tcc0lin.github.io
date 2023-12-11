# 红米Note11内核编译流程


### 前言
涉及到需要隐藏设备特征，所以需要编译内核来抹除暴露出的特征。小米内核有现成的[源码](https://github.com/MiCode/Xiaomi_Kernel_OpenSource)，可以根据自身设备的型号来选择，下面简单描述下编译流程

### 一、编译环境搭建
#### 1 物料准备
- 设备：红米note11（MIUI12 Android11）
- 源码：[selene版本内核源码](https://github.com/MiCode/Xiaomi_Kernel_OpenSource/tree/selene-r-oss)
    >需要注意的是note11(selenes)是国内的叫法，而国际版对应的是红米10(selene)
- 原生boot.img镜像文件，参考[下载网站](https://xiaomifirmwareupdater.com/miui/selenes/)
#### 2 工具准备
- 编译支撑系统：ubuntu18
    >参照官方文档的版本来的，不过经过测试，使用ubuntu14的话会导致某些三方库安装失败
- 三方库预装
    ```shell
    sudo apt-get install git ccache automake flex lzop bison \
    gperf build-essential zip curl zlib1g-dev zlib1g-dev:i386 \
    g++-multilib python-networkx libxml2-utils bzip2 libbz2-dev \
    libbz2-1.0 libghc-bzlib-dev squashfs-tools pngcrush \
    schedtool dpkg-dev liblz4-tool make optipng maven libssl-dev \
    pwgen libswitch-perl policycoreutils minicom libxml-sax-base-perl \
    libxml-simple-perl bc libc6-dev-i386 lib32ncurses5-dev \
    x11proto-core-dev libx11-dev lib32z-dev libgl1-mesa-dev xsltproc unzip
    ```
- 编译工具链准备
    - clang：c/c++编译工具
    - lineage：交叉编译工具
- 一键编译脚本
    ```
    CLANG_BIN="clang-r383902/bin"    //需要需要路径

    GCC_BIN="android_prebuilts_gcc_linux-x86_aarch64_aarch64-linux-android-4.9-lineage-19.1/bin"    //需要需要路径

    export PATH="$CLANG_BIN:$GCC_BIN:$PATH"

    export PLATFORM_VERSION=11.0

    ARCH=arm64 make CC=clang HOSTCC=gcc AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip O=out CLANG_TRIPLE=aarch64-linux-gnu- CROSS_COMPILE=aarch64-linux-androidkernel- LD=ld.lld selene_defconfig

    ARCH=arm64 make CC=clang HOSTCC=gcc AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip O=out CLANG_TRIPLE=aarch64-linux-gnu- CROSS_COMPILE=aarch64-linux-androidkernel- LD=ld.lld -j 6
    ```
- boot.img解包打开工具
    [Android_boot_image_editor](https://github.com/cfig/Android_boot_image_editor)
### 二、编译错误修复
#### 1 文件缺失
错误提示如下
```
../drivers/input/touchscreen/mediatek/FT8719P/focaltech_flash.c:60:10: fatal error: 'include/firmware/fw_sample.i' file not found
```
在drivers/input/touchscreen/mediatek/focaltech_touch/include/firmware目录下添加fw_sample.i文件

fw_sample.i文件内容从[fw_sample.i](https://github.com/AOSPA/android_kernel_xiaomi_laurel_sprout/blob/373fd3abc3203d8201b696a3e8dceab30897ba84/drivers/input/touchscreen/focaltech_touch/include/firmware/fw_sample.i)中复制
#### 2 方法重复定义
错误提示如下
```
ld.lld: error: duplicate symbol: mtk_vcu_mem_init
>>> defined at mtk_vcodec_mem.c:29 (/home/linhanqiu/proj/Xiaomi_Kernel_OpenSource/out/../drivers/media/platform/mtk-vcu/mtk_vcodec_mem.c:29)
>>>            drivers/media/platform/mtk-vcu/mtk_vcodec_mem.o:(mtk_vcu_mem_init) in archive built-in.o
>>> defined at mtk_vcodec_mem.c:29 (/home/linhanqiu/proj/Xiaomi_Kernel_OpenSource/out/../drivers/media/platform/mtk-vcu/mtk_vcodec_mem.c:29)
>>>            drivers/media/platform/mtk-vcu/mtk_vcodec_mem.o:(.text+0x0) in archive built-in.o

ld.lld: error: duplicate symbol: mtk_vcu_mem_release
>>> defined at mtk_vcodec_mem.c:53 (/home/linhanqiu/proj/Xiaomi_Kernel_OpenSource/out/../drivers/media/platform/mtk-vcu/mtk_vcodec_mem.c:53)
>>>            drivers/media/platform/mtk-vcu/mtk_vcodec_mem.o:(mtk_vcu_mem_release) in archive built-in.o
>>> defined at mtk_vcodec_mem.c:53 (/home/linhanqiu/proj/Xiaomi_Kernel_OpenSource/out/../drivers/media/platform/mtk-vcu/mtk_vcodec_mem.c:53)
>>>            drivers/media/platform/mtk-vcu/mtk_vcodec_mem.o:(.text+0xBC) in archive built-in.o

ld.lld: error: duplicate symbol: mtk_vcu_set_buffer
>>> defined at mtk_vcodec_mem.c:100 (/home/linhanqiu/proj/Xiaomi_Kernel_OpenSource/out/../drivers/media/platform/mtk-vcu/mtk_vcodec_mem.c:100)
>>>            drivers/media/platform/mtk-vcu/mtk_vcodec_mem.o:(mtk_vcu_set_buffer) in archive built-in.o
>>> defined at mtk_vcodec_mem.c:100 (/home/linhanqiu/proj/Xiaomi_Kernel_OpenSource/out/../drivers/media/platform/mtk-vcu/mtk_vcodec_mem.c:100)
>>>            drivers/media/platform/mtk-vcu/mtk_vcodec_mem.o:(.text+0x24C) in archive built-in.o

ld.lld: error: duplicate symbol: mtk_vcu_get_buffer
>>> defined at mtk_vcodec_mem.c:184 (/home/linhanqiu/proj/Xiaomi_Kernel_OpenSource/out/../drivers/media/platform/mtk-vcu/mtk_vcodec_mem.c:184)
>>>            drivers/media/platform/mtk-vcu/mtk_vcodec_mem.o:(mtk_vcu_get_buffer) in archive built-in.o
>>> defined at mtk_vcodec_mem.c:184 (/home/linhanqiu/proj/Xiaomi_Kernel_OpenSource/out/../drivers/media/platform/mtk-vcu/mtk_vcodec_mem.c:184)
>>>            drivers/media/platform/mtk-vcu/mtk_vcodec_mem.o:(.text+0x5D0) in archive built-in.o

ld.lld: error: duplicate symbol: mtk_vcu_get_page
>>> defined at slab.h:522 (/home/linhanqiu/proj/Xiaomi_Kernel_OpenSource/out/../include/linux/slab.h:522)
>>>            drivers/media/platform/mtk-vcu/mtk_vcodec_mem.o:(mtk_vcu_get_page) in archive built-in.o
>>> defined at slab.h:522 (/home/linhanqiu/proj/Xiaomi_Kernel_OpenSource/out/../include/linux/slab.h:522)
>>>            drivers/media/platform/mtk-vcu/mtk_vcodec_mem.o:(.text+0x748) in archive built-in.o

ld.lld: error: duplicate symbol: mtk_vcu_free_buffer
>>> defined at mtk_vcodec_mem.c:251 (/home/linhanqiu/proj/Xiaomi_Kernel_OpenSource/out/../drivers/media/platform/mtk-vcu/mtk_vcodec_mem.c:251)
>>>            drivers/media/platform/mtk-vcu/mtk_vcodec_mem.o:(mtk_vcu_free_buffer) in archive built-in.o
>>> defined at mtk_vcodec_mem.c:251 (/home/linhanqiu/proj/Xiaomi_Kernel_OpenSource/out/../drivers/media/platform/mtk-vcu/mtk_vcodec_mem.c:251)
>>>            drivers/media/platform/mtk-vcu/mtk_vcodec_mem.o:(.text+0x850) in archive built-in.o
```

修改参考：[重复定义异常](https://github.com/PixelExperience-Devices/kernel_redmi_rosemary/commit/646c084eb3a9a8a155fb39543358a8b399407fa6)
#### 3 驱动文件缺失
原因是未加载wlan相关的驱动，官方代码只是内核相关的，需要将wlan驱动内嵌到内核源码中

修改参考：[驱动异常](https://github.com/Luquidtester/android_kernel_xiaomi_selene/commits/twelve?before=2757679fc5c2c98db45ef41c3f4d952c8f6ee155+35&branch=twelve&path%5B%5D=drivers&path%5B%5D=misc&path%5B%5D=mediatek&qualified_name=refs%2Fheads%2Ftwelve)

复制到Xiaomi_Kernel_OpenSource/drivers/misc/mediatek/connectivity这个目录下面，并且修改connectivity里面的Kconfig文件，增加启用模块编译
```c
config WLAN_DRV_BUILD_IN
	bool "Build Wlan module in kernel"
  default y //默认启用
	help
	  This will build the wlan driver and the corresponding componenets
	  into the kernel.
	  If unsure say n
```
### 三、正式编译与boot重打包
将上面的环境、工具以及修复后的源码准备好就可以正式开始编译了，编译的产物是内核，而最终刷入系统的boot.img，因此整个流程大致可以看成如下：

boot.img解包->内核编译->内核替换->boot.img重打包
#### 1 boot.img解包
使用Android_boot_image_editor来处理解包打包，先把boot.img放在在Android_boot_image_editor目录下后执行./gradlew unpack命令，下面是输出结果
```shell
Starting a Gradle Daemon (subsequent builds will be faster)

> Task :unpack
20:00:53.716 [main] WARN  cfig.packable.PackableLauncher - [boot.img] will be handled by [BootImgParser]
20:00:53.817 [main] WARN  cfig.packable.PackableLauncher - 'unpack' sequence initialized
20:00:53.820 [main] INFO  cfig.packable.IPackable - deleting build/unzip_boot/ ...
20:00:54.190 [main] INFO  Helper - deleting uiderrors
20:00:54.198 [main] INFO  cfig.packable.BootImgParser - header version 2
20:00:54.397 [main] WARN  cfig.bootimg.v2.BootHeaderV2 - BootImgHeader constructor
20:00:54.417 [main] INFO  cfig.Avb - python aosp/avb/avbtool.v1.2.py verify_image --image boot.img
Verifying image boot.img using embedded public key
vbmeta: Successfully verified footer and SHA256_RSA2048 vbmeta struct in boot.img
boot: Successfully verified sha256 hash of boot.img for image of 30773248 bytes
20:00:55.460 [main] INFO  KernelExtractor - [aosp/make/tools/extract_kernel.py, --input, build/unzip_boot/kernel, --output-configs, build/unzip_boot/kernel_configs.txt, --output-version, build/unzip_boot/kernel_version.txt]
20:00:55.464 [main] INFO  KernelExtractor - kernel version: [4.14.186]
20:00:55.464 [main] INFO  KernelExtractor - kernel config dumped to : build/unzip_boot/kernel_configs.txt
20:00:56.329 [main] INFO  ZipHelper - decompress(gz) done: build/unzip_boot/ramdisk.img.gz -> build/unzip_boot/ramdisk.img
20:00:56.332 [main] INFO  cfig.bootimg.cpio.AndroidCpio - Cleaning /Users/linhanqiu/Projects/Android_boot_image_editor/build/unzip_boot/root ...
20:00:56.358 [main] WARN  cfig.bootimg.cpio.AndroidCpio -   root/config has improper file mode 555, fix it
20:00:57.293 [main] WARN  cfig.bootimg.cpio.AndroidCpio -   root/system/bin/logd has improper file mode 550, fix it
20:00:57.629 [main] INFO  cfig.bootimg.cpio.AndroidCpio - cpio trailer found, mode=000001ed
20:00:57.631 [main] INFO  cfig.bootimg.Common -  ramdisk extracted : build/unzip_boot/ramdisk.img -> build/unzip_boot/root
20:00:57.647 [main] INFO  cfig.utils.DTC - parsing DTB: build/unzip_boot/dtb
FATAL ERROR: Blob has incorrect magic number
20:00:57.683 [main] ERROR cfig.utils.DTC - can not parse DTB: build/unzip_boot/dtb
20:00:57.687 [main] INFO  avb.AVBInfo - parseFrom(FILE:boot.img) ...
20:00:57.723 [main] INFO  avb.AVBInfo - FILE:boot.img: Glance(footer=Footer(versionMajor=1, versionMinor=0, originalImageSize=30773248, vbMetaOffset=30773248, vbMetaSize=1600), vbMetaOffset=30773248).footer
20:00:57.837 [main] INFO  avb.AVBInfo - VBMeta: boot.img -> build/unzip_boot/boot.avb.json
20:00:58.013 [main] INFO  cfig.Avb - signed with release key: 'Xiaomi Phone' by Mi
20:00:58.028 [main] WARN  cfig.Avb - Found key: PublicKey(device='Xiaomi Phone' by 'Mi', algorithm='SHA256_RSA2048', sha1='b2a02f1e56e366d727a1a8e089762fe0b91bbc84')
20:00:58.079 [main] INFO  cfig.bootimg.v2.BootV2 -
                        Unpack Summary of boot.img
┌───────────────────────────────────────┬──────────────────────────────────────┐
│What                                   │Where                                 │
└───────────────────────────────────────┴──────────────────────────────────────┘
┌───────────────────────────────────────┬──────────────────────────────────────┐
│image info                             │build/unzip_boot/boot.json            │
├───────────────────────────────────────┼──────────────────────────────────────┤
│AVB info [verified]                    │build/unzip_boot/boot.avb.json        │
│\-- signing key                        │Xiaomi Phone by Mi                    │
├───────────────────────────────────────┼──────────────────────────────────────┤
│kernel                                 │build/unzip_boot/kernel               │
│\-- version [4.14.186]                 │build/unzip_boot/kernel_version.txt   │
│\-- config                             │build/unzip_boot/kernel_configs.txt   │
├───────────────────────────────────────┼──────────────────────────────────────┤
│ramdisk                                │build/unzip_boot/ramdisk.img.gz       │
│\-- extracted ramdisk rootfs           │build/unzip_boot/root                 │
├───────────────────────────────────────┼──────────────────────────────────────┤
│dtb                                    │build/unzip_boot/dtb                  │
└───────────────────────────────────────┴──────────────────────────────────────┘
20:00:58.159 [main] WARN  cfig.packable.PackableLauncher - 'unpack' sequence completed

BUILD SUCCESSFUL in 27s
10 actionable tasks: 1 executed, 9 up-to-date
```
可以从日志中看到解包后的文件都放在build/unzip_boot下
```shell
boot.avb.json            dtb                      kernel_configs.txt       ramdisk.img              ramdisk.img_filelist.txt
boot.json                kernel                   kernel_version.txt       ramdisk.img.gz           root
```
#### 2 内核编译
编译结果如下
```shell
  AR      drivers/misc/mediatek/connectivity/wlan_drv_gen4m/built-in.o
  AR      drivers/misc/mediatek/connectivity/built-in.o
  AR      drivers/misc/mediatek/built-in.o
  AR      drivers/misc/built-in.o
  AR      drivers/built-in.o
  GEN     .version
  CHK     include/generated/compile.h
  UPD     include/generated/compile.h
  CC      init/version.o
  AR      init/built-in.o
  AR      built-in.o
  LD      vmlinux.o
  MODPOST vmlinux.o
  KSYM    .tmp_kallsyms1.o
  KSYM    .tmp_kallsyms2.o
  LD      vmlinux
  SORTEX  vmlinux
  SYSMAP  System.map
  OBJCOPY arch/arm64/boot/Image
  Building modules, stage 2.
  MODPOST 4 modules
  GZIP    arch/arm64/boot/Image.gz
  DTC     arch/arm64/boot/dts/mediatek/mt6768.dtb
  CAT     arch/arm64/boot/Image.gz-dtb
make[1]: Leaving directory '/xiaomi_kernel_opensource-selene-r-oss/out'
```
在out目录下可以看到内核编译产物，具体路径在out/arch/arm64/boot下
```
dts  Image  Image.gz  Image.gz-dtb
```
内核文件是Image.gz-dtb，这个是将kenrl和dtb打包在一起
另外还需要的文件是dts目录下的mt6768.dtb，因为kernel启动时需要配套的dtb文件
#### 3 内核替换
替换kernel和dtb文件
#### 4 boot.img重打包
```shell
./gradlew pack
```

