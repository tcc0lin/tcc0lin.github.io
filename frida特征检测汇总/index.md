# Frida特征检测汇总


- `端口检测`：frida默认暴露端口为27047
- `通信方式检测`：frida使用App低频使用的D-Bus通信协议来进行通信，可以遍历端口对它们发送D-Bus AUTH消息来判断是否存在REJECT的情况
- `内存检测`
    - so列表检测
        - maps文件内容遍历检测
        - 通过linker获取so list遍历检测
    - 可执行段字符检测：遍历maps文件中带有可执行属性的segment，检测是否包含libfrida/frida:rpc等字符特征
- `线程检测`：遍历proc/self/task的文件内容，查找字符特征
- `命名通道检测`：遍历proc/self/fd，反查fd判断是否包含linjector字符特征
- `section crc检验`：对比内存中的so 各个section与本地的section的crc值对比
- `segment属性检测`：针对inline hook，由于frida是基于inline hook的，因此会改动libart，进而暴露在maps中会有rwxp属性的地址段
- `inline hook跳转检测`：frida inline hook和其他inline hook的原理相同，在函数的头几个字节通常是ldr、br这类的指令
- `目录检测`：针对/data/local/tmp下面的re.frida.server
- `代码漏洞`
    - elf头字节魔改：frida gum_try_parse_linker_proc_maps_line函数中在获取linker时会判断elf头字节是否匹配，可以选择修改elf头字节
    - libc属性修改：使用目标libc的mmap将自身的相关so注册到目标maps表中;再执行目标libc的dlopen和dlsym函数将自身so中的函数进行执行，做法是主动mmap只读的libc从而让frida启动崩溃
- `检测线程保护`
- `匿名内存检测`

额外需要注意的是
- 自定义syscall：从上面的特征检测来看，文件是重要的检测介质，为了要获取到真实的文件，还需要使用自定义syscall，例如open/read/close等
- 自定义pthread_create
