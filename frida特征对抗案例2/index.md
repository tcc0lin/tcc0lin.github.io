# Frida特征对抗案例2


### 一、资源准备
- com.jingdong.app.mall 12.1.0
- pixel2 android10.0
- frida 14.2.2
### 二、分析思路
使用frida以spawn模式启动，可以发现进程直接崩溃，说明存在反调试
```shell
Spawned `com.jingdong.app.mall`. Resuming main thread!                  
[Pixel 2::com.jingdong.app.mall]-> Process terminated
[Pixel 2::com.jingdong.app.mall]->
```
通常检测逻辑是放在native层的，因此进一步判断是哪个so导致的
```js
function hook_dlopen() {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    console.log("load " + path);
                }
            }
        }
    );
}
```
由so的加载流程可知，so都是是顺序加载，从命令行中当加载libJDMobileSec之后，进程就崩溃了，可以猜测反调试点在libJDMobileSec中
```
Spawned `com.jingdong.app.mall`. Resuming main thread!                  
[Pixel 2::com.jingdong.app.mall]-> load /system/framework/oat/arm/org.apache.http.legacy.odex
load /data/app/com.jingdong.app.mall-OXNoca8Sb7xq1IC0YJW2PA==/oat/arm/base.odex
load /data/app/com.jingdong.app.mall-OXNoca8Sb7xq1IC0YJW2PA==/lib/arm/libJDMobileSec.so
Process terminated
```
同样需要判断具体检测的函数在哪个部分，优先确定JNI_OnLoad的偏移是0x56BC
```js
function hook_dlopen(soName = '') {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    if (path.indexOf(soName) >= 0) {
                        this.is_can_hook = true;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.is_can_hook) {
                    hook_JNI_OnLoad()
                }
            }
        }
    );
}
 
function hook_JNI_OnLoad(){
    let module = Process.findModuleByName("libJDMobileSec.so")
    Interceptor.attach(module.base.add(0x56BC + 1), {
        onEnter(args){
            console.log("call JNI_OnLoad")
        }
    })
}

setImmediate(hook_dlopen,"libJDMobileSec.so")
```
看到是在JNI_OnLoad之后进程崩溃的，说明检测逻辑应该是JNI_OnLoad里面
```shell
Spawned `com.jingdong.app.mall`. Resuming main thread!                  
[Pixel 2::com.jingdong.app.mall]-> call JNI_OnLoad
Process terminated
```
测试下是否有新起线程检测
```js
function hook_pthread_create(){
    var base = Process.findModuleByName("libJDMobileSec.so").base
    console.log("libJDMobileSec.so --- " + base)
    Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"),{
        onEnter(args){
            let func_addr = args[2]
            console.log("The thread function address is " + func_addr + " offset:" + (func_addr-base).toString(16))
        }
    })
}
```
可以看到有个新起的线程
```shell
Spawned `com.jingdong.app.mall`. Resuming main thread!                  
[Pixel 2::com.jingdong.app.mall]-> call JNI_OnLoad
libJDMobileSec.so --- 0xce055000
The thread function address is 0xce06151d offset:c51d
Process terminated
```
优先nop掉看是否该点是检测点，追溯到JNI_OnLoad方法里面偏移0x688A上
```js
function bypass(){
    let module = Process.findModuleByName("libJDMobileSec.so")
    nop(module.base.add(0x688A))
}
```
nop掉之后还是崩溃，看来检测点可能不是这里或者不止一个，继续尝试其他hook点
```js
function replace_str() {
    var pt_strstr = Module.findExportByName("libc.so", 'strstr');
 
    Interceptor.attach(pt_strstr, {
        onEnter: function (args) {
            var str1 = args[0].readCString();
            var str2 = args[1].readCString();
            console.log("strstr-->", str1, str2);
            // console.log('strstr called from:\\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n') + '\\n');
            // console.log('strstr called from:\\n' + Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\\n') + '\\n');
        }
    }); 
}
```
看看字符比较会不会有发现
```shell
strstr--> bb123000-bb222000 r--p 00000000 103:1d 2720259                           /data/app/com.jingdong.app.mall-OXNoca8Sb7xq1IC0YJW2PA==/oat/arm/base.odex
 com.saurik.substrate
strstr called from:\n0xcdf5dbfb libJDMobileSec.so!0xabfb\n0xcdf6e5a1 libJDMobileSec.so!0x1b5a1\n
strstr--> bb222000-bb272000 r--p 00000000 103:06 1437                              /system/framework/oat/arm/org.apache.http.legacy.odex
 re.frida.server/frida-agent-32.so
strstr called from:\n0xcdf5da3f libJDMobileSec.so!0xaa3f\n0xcdf6e5a1 libJDMobileSec.so!0x1b5a1\n
strstr--> bb222000-bb272000 r--p 00000000 103:06 1437                              /system/framework/oat/arm/org.apache.http.legacy.odex
 re.frida.server/frida-agent-64.so
strstr called from:\n0xcdf5da85 libJDMobileSec.so!0xaa85\n0xcdf6e5a1 libJDMobileSec.so!0x1b5a1\n
strstr--> bb222000-bb272000 r--p 00000000 103:06 1437                              /system/framework/oat/arm/org.apache.http.legacy.odex
 com.saurik.substrate
strstr called from:\n0xcdf5dbfb libJDMobileSec.so!0xabfb\n0xcdf6e5a1 libJDMobileSec.so!0x1b5a1\n
strstr--> bb272000-bc06a000 r--p 00000000 103:1d 1032201                           /data/local/tmp/re.frida.server/frida-agent-32.so
 re.frida.server/frida-agent-32.so
strstr called from:\
```
从日志中看出来应该是比较了maps中是否包含frida-agent、substrate等特征，根据堆栈确定调用点大致是在0xaa85、0xabfb这几个偏移上，从ida上看都集中在sub_A934这个函数里面，看看交叉引用的地方
，在JNI_OnLoad中有两处，nop掉看看效果
```js
function bypass(){
    let module = Process.findModuleByName("libJDMobileSec.so")
    nop(module.base.add(0x688A))
    nop(module.base.add(0x623A))
    nop(module.base.add(0x634A))
}
```
nop掉两处后就可以正常调试了，说明sub_A934这个函数就是反调试检测的函数，看看具体sub_A934的函数逻辑是什么
```c
int sub_A934()
{
  ......
  v0 = -1072311660;
  v1 = 1723222422;
  v47 = dword_24ED8;
  v2 = -1703318409;
  do
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            while ( 1 )
            {
              while ( 1 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      while ( 1 )
                      {
                        while ( 1 )
                        {
                          while ( 1 )
                          {
                            while ( 1 )
                            {
                              while ( 1 )
                              {
                                while ( 1 )
                                {
                                  while ( 1 )
                                  {
                                    while ( v2 <= -1401839159 )
                                    {
                                      if ( v2 == -1703318409 )
                                      {
                                        v2 = 775535239;
                                        if ( !v47 )
                                          v2 = -419580537;
                                      }
                                    }
                                    if ( v2 <= 1993647575 )
                                      break;
                                    if ( v2 == 1993647576 )
                                    {
                                      if ( !s )
                                        goto LABEL_73;
                                      v3 = sub_97C4((float *)&unk_21C24, 33);
                                      v4 = v1;
                                      v5 = v0;
                                      v6 = strstr(s, v3);
                                      free(v3);
                                      v2 = 509119054;
                                      v7 = v6 == 0;
                                      v0 = v5;
                                      v1 = v4;
                                      if ( v7 )
                                      {
                                        v8 = v0;
                                        v9 = sub_97C4((float *)&unk_21CA8, 33);
                                        v10 = strstr(s, v9);
                                        v11 = (char *)v9;
                                        v0 = v8;
                                        v1 = v4;
                                        free(v11);
                                        v2 = 509119054;
                                        if ( !v10 )
LABEL_73:
                                          v2 = 1287785172;
                                      }
                                    }
                                  }
                                  if ( v2 <= 1723222421 )
                                    break;
                                  if ( v2 == v1 )
LABEL_108:
                                    v2 = -370315561;
                                }
                                if ( v2 > -1282738887 )
                                  break;
                                if ( v2 == -1401839158 )
                                {
                                  v2 = 3915268;
                                  if ( v49 )
                                    v2 = -1282738886;
                                }
                              }
                              if ( v2 > v0 )
                                break;
                              if ( v2 == -1282738886 )
                              {
                                s = &v51;
                                v7 = fgets(&v51, 256, stream) == 0;
                                v2 = -104947837;
                                if ( !v7 )
                                  v2 = 1993647576;
                              }
                            }
                            if ( v2 <= 1389383840 )
                              break;
                            if ( v2 == 1389383841 )
                            {
                              fclose(stream);
                              sub_113FC();
                              v12 = 0;
                              v13 = x * ~-x & (x * ~-x ^ 0xFFFFFFFE);
                              v14 = 0;
                              if ( !v13 )
                                v14 = 1;
                              if ( y < 10 )
                                v12 = 1;
                              v15 = v13 != 0;
                              v16 = 0;
                              v17 = v14 ^ v12;
                              if ( y > 9 )
                                v16 = 1;
                              v7 = ((v15 | v16) ^ 1 | v17) == 0;
                              v2 = -1072311659;
                              if ( !v7 )
                                v2 = 327108677;
                            }
                          }
                          if ( v2 <= 1287785171 )
                            break;
                          if ( v2 == 1287785172 )
                          {
                            if ( !s )
                              goto LABEL_87;
                            v18 = v1;
                            v19 = v0;
                            v20 = sub_97C4((float *)&unk_21BD4, 20);
                            v21 = strstr(s, v20);
                            v22 = (char *)v20;
                            v0 = v19;
                            v1 = v18;
                            free(v22);
                            v2 = -1046283837;
                            if ( !v21 )
LABEL_87:
                              v2 = -1282738886;
                          }
                        }
                        if ( v2 <= 775535238 )
                          break;
                        if ( v2 == 775535239 )
                        {
                          v23 = 0;
                          v24 = ~(x * (x - 1)) | 0xFFFFFFFE;
                          v25 = 0;
                          if ( v24 == -1 )
                            v25 = 1;
                          if ( y < 10 )
                            v23 = 1;
                          v7 = v24 == -1;
                          v26 = 0;
                          if ( !v7 )
                            v26 = 1;
                          v27 = 0;
                          v28 = v25 ^ v23;
                          if ( y > 9 )
                            v27 = 1;
                          v7 = ((v26 | v27) ^ 1 | v28) == 0;
                          v2 = -909066482;
                          if ( !v7 )
                            v2 = 129779082;
                        }
                      }
                      if ( v2 <= 509119053 )
                        break;
                      if ( v2 == 509119054 )
                      {
                        v29 = 0;
                        v30 = x * ~-x & (x * ~-x ^ 0xFFFFFFFE);
                        v31 = 0;
                        if ( !v30 )
                          v31 = 1;
                        if ( y < 10 )
                          v29 = 1;
                        v32 = v30 != 0;
                        v33 = 0;
                        v34 = v31 ^ v29;
                        if ( y > 9 )
                          v33 = 1;
                        v7 = ((v32 | v33) ^ 1 | v34) == 0;
                        v2 = -1072311659;
                        if ( !v7 )
                          v2 = 1389383841;
                      }
                    }
                    if ( v2 <= 327108676 )
                      break;
                    if ( v2 == 327108677 )
                      goto LABEL_73;
                  }
                  if ( v2 <= 129779081 )
                    break;
                  if ( v2 == 129779082 )
                  {
                    v35 = sub_97C4((float *)&unk_21BA0, 13);
                    v36 = getpid();
                    sprintf(&v52, v35, v36);
                    free(v35);
                    v0 = -1072311660;
                    v37 = fopen(&v52, (const char *)&unk_1B5A1);
                    stream = v37;
                    if ( v37 )
                      LOBYTE(v37) = 1;
                    v49 = (char)v37;
                    v38 = 0;
                    if ( (~(x * (x - 1)) | 0xFFFFFFFE) != -1 )
                      v38 = 1;
                    v39 = 0;
                    if ( y > 9 )
                      v39 = 1;
                    v7 = ((v38 | v39) ^ 1 | v39 ^ v38) == 0;
                    v2 = -909066482;
                    if ( !v7 )
                      v2 = -1401839158;
                  }
                }
                if ( v2 > -1046283838 )
                  break;
                if ( v2 == -1072311659 )
                {
                  fclose(stream);
                  sub_113FC();
                  v2 = 1389383841;
                }
              }
              if ( v2 > -909066483 )
                break;
              if ( v2 == -1046283837 )
              {
                fclose(stream);
                sub_113FC();
                goto LABEL_87;
              }
            }
            if ( v2 > -813385351 )
              break;
            if ( v2 == -909066482 )
            {
              v40 = sub_97C4((float *)&unk_21BA0, 13);
              v41 = getpid();
              sprintf(&v52, v40, v41);
              free(v40);
              v0 = -1072311660;
              fopen(&v52, (const char *)&unk_1B5A1);
              v2 = 129779082;
            }
          }
          if ( v2 > -419580538 )
            break;
          if ( v2 == -813385350 )
            v2 = 4185867;
        }
        if ( v2 > -370315562 )
          break;
        if ( v2 == -419580537 )
        {
          v42 = 0;
          if ( !((x * ~-x ^ 0xFFFFFFFE) & x * ~-x) )
            v42 = 1;
          v43 = 0;
          if ( y < 10 )
            v43 = 1;
          v7 = (v42 & v43 | v43 ^ v42) == 0;
          v2 = -813385350;
          if ( !v7 )
            v2 = 4185867;
        }
      }
      if ( v2 <= -104947838 )
        break;
      switch ( v2 )
      {
        case -104947837:
          fclose(stream);
          v2 = 3915268;
          break;
        case 3915268:
          goto LABEL_108;
        case 4185867:
          v44 = 0;
          if ( !((x * ~-x ^ 0xFFFFFFFE) & x * ~-x) )
            v44 = 1;
          v45 = 0;
          if ( y < 10 )
            v45 = 1;
          v7 = (v44 & v45 | v45 ^ v44) == 0;
          v2 = -813385350;
          if ( !v7 )
            v2 = 1723222422;
          break;
      }
    }
  }
  while ( v2 != -370315561 );
  return _stack_chk_guard - v53;
}
```
代码量不长，检测点应该都收敛在maps中，两个需要注意的函数
- sub_97C4
    负责字符动态解密的，有多处调用
    ```c
    _BYTE *__fastcall sub_97C4(float *a1, signed int a2)
    {
    signed int v2; // r4
    float *v3; // r5
    _BYTE *result; // r0
    _BYTE *v5; // r1
    signed int v6; // r2
    float v7; // s0

    v2 = a2;
    v3 = a1;
    result = malloc(a2 + 1);
    if ( v2 >= 1 )
    {
        v5 = result;
        v6 = v2;
        do
        {
        v7 = *v3;
        ++v3;
        --v6;
        *v5++ = ((signed int)(float)(v7 + v7) ^ 0xDE) + 34;
        }
        while ( v6 );
    }
    result[v2] = 0;
    return result;
    }
    ```
- sub_113FC
    syscall执行系统编号37的功能，就是kill，等待1秒后杀死当前进程
    ```
    int sub_113FC()
    {
    __pid_t v0; // r0

    sleep(1u);
    v0 = getpid();
    return syscall(37, v0, 9);
    }
    ```
### 三 总结
完整代码看这里[libJDMobileSec.js](https://github.com/tcc0lin/SecCase/blob/main/libJDMobileSec.js)
