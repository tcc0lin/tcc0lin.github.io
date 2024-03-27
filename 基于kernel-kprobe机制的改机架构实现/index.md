# 基于Kernel Kprobe机制的改机架构实现



改机的目的是为了让App获取到我们所想要其获取的数据，通常App在Native层获取数据时一般都会调用封装好的libc库或者通过内联汇编的方式最终调用内核函数，所以我们的应对通常是针对内核函数，下面就是针对内核函数调用结果修改的几种方案


|层级|原理|方案|
|----------- | ----------- | ----------- |
|用户层|inline hook    | 定位svc指令，通过inline hook修改返回结果       |
|| seccomp异常拦截      | ptrace注入进程，配合seccomp拦截函数调用      |
||       | frida的方案和ptrace同理       |
|| 依赖tracepoint监控      | epbf通过bpf_probe_write_user函数修改用户态数据      |
|内核层| 定制源码   | 直接修改原生函数，例如重写open函数所对应的do_sys_open        |
|| Kprobe Hook机制   | 利用Kernel hook方案的Kprobe机制来hook具体函数        |

对比内核层的两种实现方案，都是需要完整的内核源码才能实现，这点是最大的掣肘
1. 定制源码
   - 整体流程
        修改对应的内核函数/syscall_table替换函数->内核编译->重打包boot.img->dd命令替换boot分区文件->重启完成内核更新
   - 风险点
        各种异常情况下dd命令执行过程中异常导致系统无法启动
1. Kprobe内核模块
   - 整体流程
        增加对应的函数hook->内核模块编译->init.rc增加模块自动加载功能->重装内核模块

