# Unidbg特征检测汇总



Unidbg对抗点
- 不支持信号机制
- 内存布局检测
- Unidbg通过Java实现JNI的逻辑，导致JNI函数地址控制在0xfffe0000L - 0xffff0000L范围内，检测JNI函数地址是否处于该范围或者相邻两个函数的地址差值
- 类检测：Unidbg通常会对不存在的类也会正常返回
- 函数检测：对比methodid是否是hashcode
- 文件描述符：Unidbg的文件描述符通常是3-6
- uname判断
- hook框架检测（xhook、dobby）
- 依赖库对抗：Unidbg只实现了十余个常用so库
- 字节对齐？
- getenv
- 增加目标函数前置执行条件
