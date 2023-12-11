# Super分区定制


### 一、编译环境搭建
#### 1 物料准备
- 设备：红米note11（MIUI12 Android11）
- 原生super.img镜像文件，参考[下载网站](https://xiaomifirmwareupdater.com/miui/selenes/)
#### 2 工具准备
- 编译支撑系统：ubuntu14（经测试不受版本影响，正常来说ubuntu都可以安装所有的工具）
- [simg2img](https://github.com/anestisb/android-simg2img)
- [lpunpack/lmake](https://github.com/LonelyFool/lpunpack_and_lpmake)
- imjtool
### 二、案例说明（内置应用）
#### 1 镜像格式转化
正常image镜像都是Android sparse image格式的
```shell
(base)  大慈大悲观世音菩萨  ~/Projects/小米rom/原生12511/images  file super.img
super.img: Android sparse image, version: 1.0, Total of 2197864 4096-byte output blocks in 4352 input chunks.
```
但是要挂载使用的话需要转换成data格式，利用到`simg2img super.img super.raw.img`命令，得到的文件如下
```shell 
(base)  大慈大悲观世音菩萨  ~/tt  file super.img.raw
super.img.raw: data
```
#### 2 镜像拆解
Android10以上的设备通常都是动态分区，也就是system、vendor、product等逻辑分区合并成一个物理分区，可以使用imjtool来看当前镜像的具体信息
```
(base)  大慈大悲观世音菩萨  ~/tt  imjtool super.img.raw
MMapped: 0x1103a2000, imgMeta 0x1103a3000
liblp dynamic partition (super.img) - Blocksize 0x1000, 3 slots
LP MD Header @0x3000, version 10.2, with 6 logical partitions @0x0 on block device of 8704 GB, at partition super, first sector: 0x800
Partitions @0x3100 in 3 groups:
	Group 0: default
	Group 1: main_a
		Name: product_a (read-only, Linux Ext2/3/4/? Filesystem Image, @0x100000 spanning 1 extents of 237 MB)
		Name: vendor_a (read-only, Linux Ext2/3/4/? Filesystem Image, @0xef00000 spanning 1 extents of 869 MB)
		Name: system_a (read-only, Linux Ext2/3/4/? Filesystem Image, @0x45500000 spanning 1 extents of 4 GB)
	Group 2: main_b
		Name: product_b (read-only,  empty)
		Name: vendor_b (read-only,  empty)
		Name: system_b (read-only, Linux Ext2/3/4/? Filesystem Image, @0x161200000 spanning 1 extents of 345 MB)
```
默认镜像中存在三个槽，但实际上可用的只是两个槽，负责用来做AB分区转换的，但是小米使用的应该是VAB分区，B分区其实只是个假分区，通常都是空的

因此想要动其中的分区需要额外进行一步镜像拆解，需要利用到lpunpack工具，执行命令
```shell
lpunpack super.img.raw super/
```
得到的拆解后的文件如下
```shell
(base)  大慈大悲观世音菩萨  ~/tt/super  ll
total 15558584
-rw-r--r--  1 linhanqiu  staff   237M  4 24 16:35 product_a.img
-rw-r--r--  1 linhanqiu  staff     0B  4 24 16:36 product_b.img
drwxr-xr-x  2 linhanqiu  staff    64B  4 24 16:39 sys1
-rw-r--r--  1 linhanqiu  staff   6.0G  5  8 18:13 system_a.img
-rw-r--r--  1 linhanqiu  staff   346M  4 24 16:29 system_b.img
-rw-r--r--  1 linhanqiu  staff   870M  4 24 16:36 vendor_a.img
-rw-r--r--  1 linhanqiu  staff     0B  4 24 16:35 vendor_b.img
```
#### 3 定制修改
修改的是system_a.img镜像，需要mount到指定目录上，但现在system_a.img的空间是满的，需要额外扩充空间保证我们的修改和新增生效，有的Linux系统可以直接使用fallocate命令，但是ubuntu不可以，替换成
```shell
dd if=system_a.img of=system_a.img bs=1G seek=7 count=0
resize2fs system_a.img 7G
```
原本的system_a.img是5G，现在额外扩展到7G
```
mount -t ext4 -o loop system_a.img system
```
挂载到system目录上，可得到以下文件列表，根据自身需求修改即可
#### 4 镜像重打包
针对system目录修改完成后，取消挂载
```shell
umount system
```          
利用lpmake工具打包，具体的值需要计算 
```
lpmake 
--metadata-size 65536 
--device super:9002450944 
--metadata-slots 3 
--group main_a:7603306496 
--partition product_a:none:248659968:main_a 
--partition system_a:none:6442450944:main_a 
--partition vendor_a:none:912195584:main_a 
--image product_a=./product_a.img 
--image system_a=./system_a.img 
--image vendor_a=./vendor_a.img 
--group main_b:362688512 
--partition system_b:none:362688512:main_b 
--image system_b=./system_b.img 
--sparse 
--output ./super.new.img
```
