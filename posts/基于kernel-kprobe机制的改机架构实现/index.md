# 基于Kernel Kprobe机制的改机架构实现


### 一、背景
如上文[Linux Kprobe原理探究
](https://tcc0lin.github.io/linux-kprobe%E5%8E%9F%E7%90%86%E6%8E%A2%E7%A9%B6/)所提及的，Kprobe有多种玩法，在设备改机场景中可以通过对内核系统函数的篡改以完成改机的目的，本文就是基于Kernel Kprobe机制来搭建一套完整的改机架构

### 二、思路
从整体流程上看，Kprobe的实现是基于LKM的，那么编译方式、生效时机、更新方式都需要参考LKM的做法
![](https://github.com/tcc0lin/self_pic/blob/main/kprobe.png?raw=true)

### 三、具体执行
#### 3.1 LKM编译
#### 3.2 patch init.rc
#### 3.3 insmod ko

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/%E5%9F%BA%E4%BA%8Ekernel-kprobe%E6%9C%BA%E5%88%B6%E7%9A%84%E6%94%B9%E6%9C%BA%E6%9E%B6%E6%9E%84%E5%AE%9E%E7%8E%B0/  

