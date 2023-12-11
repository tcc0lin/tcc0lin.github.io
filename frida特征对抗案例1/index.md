# Frida特征对抗案例1


### 一、资源准备
- tv.danmaku.bili 7.43.0
- pixel2 android10.0
- frida 14.2.2
### 二、分析思路
使用frida以spawn模式启动，可以发现进程直接崩溃，说明存在反调试
```shell
Spawned `tv.danmaku.bili`. Resuming main thread!
[Pixel 2::tv.danmaku.bili]-> Process terminated
[Pixel 2::tv.danmaku.bili]->
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
由so的加载流程可知，so都是是顺序加载，从命令行中当加载libmsaoaidsec.so之后，进程就崩溃了，可以猜测反调试点在libmsaoaidsec.so中
```shell
[Pixel 2::tv.danmaku.bili]-> load /system/framework/oat/arm/com.android.future.usb.accessory.odex
load /system/framework/oat/arm/org.apache.http.legacy.odex
load /data/app/tv.danmaku.bili-j_iiq65L9CsVGLfbrhaTgA==/oat/arm/base.odex
load /data/app/tv.danmaku.bili-j_iiq65L9CsVGLfbrhaTgA==/lib/arm/libblkv.so
load /data/app/tv.danmaku.bili-j_iiq65L9CsVGLfbrhaTgA==/lib/arm/libbili_core.so
load /data/app/tv.danmaku.bili-j_iiq65L9CsVGLfbrhaTgA==/lib/arm/libbilicr.88.0.4324.188.so
load /data/app/tv.danmaku.bili-j_iiq65L9CsVGLfbrhaTgA==/lib/arm/libijkffmpeg.so
load /data/app/tv.danmaku.bili-j_iiq65L9CsVGLfbrhaTgA==/lib/arm/libavif-jni.so
load /data/dalvik-cache/arm/system@product@app@TrichromeLibrary@TrichromeLibrary.apk@classes.dex
load /data/dalvik-cache/arm/system@product@app@WebViewGoogle@WebViewGoogle.apk@classes.dex
load /data/app/tv.danmaku.bili-j_iiq65L9CsVGLfbrhaTgA==/lib/arm/libmsaoaidsec.so
Process terminated
```
而libmsaoaidsec.so从字面上可知是[MSA（移动安全联盟）](https://github.com/2tu/msa)出品的，确定了so之后，需要进一步确定具体的函数，so的函数执行顺序是.init函数->JNI_OnLoad，先判断下是在JNI_OnLoad前后进行检测的

从libmsaoaidsec.so的export函数表中可以知道JNI_OnLoad的偏移量是0xC6DC，先hook JNI_OnLoad尝试下
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
    let module = Process.findModuleByName("libmsaoaidsec.so")
    Interceptor.attach(module.base.add(0xC6DC + 1), {
        onEnter(args){
            console.log("call JNI_OnLoad")
        }
    })
}
 
setImmediate(hook_dlopen, "libmsaoaidsec.so")
```
结果依旧是进程崩溃
```
Spawned `tv.danmaku.bili`. Resuming main thread!                        
[Pixel 2::tv.danmaku.bili]-> Process terminated
[Pixel 2::tv.danmaku.bili]->
```
那么可以断定检测位置在JNI_OnLoad之前，因此需要hook .init函数，选取.init_proc中的外部函数引用来做入口
```c
int sub_B1B4()
{
  _DWORD *v0; // r5
  int result; // r0
  int v2; // r1
  int v3; // [sp+0h] [bp-20h]
  int v4; // [sp+4h] [bp-1Ch]
  int v5; // [sp+Ch] [bp-14h]

  v0 = off_1FC04;
  v5 = *(_DWORD *)off_1FC04;
  v4 = 0;
  v3 = 0;
  // 选取
  _system_property_get("ro.build.version.sdk", &v3);
  result = atoi((const char *)&v3);
  v2 = *v0 - v5;
  return result;
}
```
以pthread_create函数为例，尝试下是否有启动线程来做检测
```js
function hook_dlopen(soName = '') {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    if (path.indexOf(soName) >= 0) {
                        locate_init()
                    }
                }
            }
        }
    );
}
 
function locate_init() {
    let secmodule = null
    Interceptor.attach(Module.findExportByName(null, "__system_property_get"),
        {
            // _system_property_get("ro.build.version.sdk", v1);
            onEnter: function (args) {
                secmodule = Process.findModuleByName("libmsaoaidsec.so")
                var name = args[0];
                if (name !== undefined && name != null) {
                    name = ptr(name).readCString();
                    if (name.indexOf("ro.build.version.sdk") >= 0) {
                        hook_pthread_create()
                    }
                }
            }
        }
    );
}

function hook_pthread_create(){
    var base = Process.findModuleByName("libmsaoaidsec.so").base
    console.log("libmsaoaidsec.so --- " + base)
    Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"),{
        onEnter(args){
            let func_addr = args[2]
            console.log("The thread function address is " + func_addr + " offset:" + (func_addr-base).toString(16))
        }
    })
}
 
setImmediate(hook_dlopen, "libmsaoaidsec.so")
```
可以看到，创建了两个线程，分别是在0x11129和0x10975
```shell
Spawned `tv.danmaku.bili`. Resuming main thread!                        
[Pixel 2::tv.danmaku.bili]-> libmsaoaidsec.so --- 0xb3689000
The thread function address is 0xeab3fc15 offset:374b6c15
The thread function address is 0xeab3fc15 offset:374b6c15
The thread function address is 0xb369a129 offset:11129
The thread function address is 0xb3699975 offset:10975
```
继续通过ida来确定反调试检测
#### 1 反调试检测
##### 1.1 0x11129
```c
while ( 1 )
  {
    v49 = sub_10BE8();
    v50 = sub_10D1C(v49);
    v51 = sub_10DEC(v50);
    sub_16B48(v51);
    // 每4秒触发
    sleep(4u);
  }
```
0x11129前面大部分都是关于字符串的解密，在while中才到了具体的检测逻辑
###### 1.1.1 sub_10BE8
```c
int sub_10BE8()
{
  char *v0; // r4
  _DWORD *v1; // r5
  DIR *v2; // r0
  DIR *v3; // r6
  struct dirent *v4; // r0
  DIR *v5; // r5
  struct dirent *v6; // r7
  const char *v7; // r7
  int v8; // r0
  int v9; // r7
  unsigned int v10; // r4
  int result; // r0
  _DWORD *v12; // [sp+0h] [bp-438h]
  char *v13; // [sp+4h] [bp-434h]
  char v14; // [sp+18h] [bp-420h]
  char buf; // [sp+1Ch] [bp-41Ch]
  char haystack[512]; // [sp+20h] [bp-418h]
  char s; // [sp+220h] [bp-218h]

  v0 = &v14;
  v1 = off_1FC04;
  *(_DWORD *)&v14 = *(_DWORD *)off_1FC04;
  v2 = opendir(&byte_21018);                    // /proc/self/task
  if ( v2 )
  {
    v3 = v2;
    v12 = v1;
    v13 = &v14;
    v4 = readdir(v2);                           // 遍历读取
    v5 = v3;
    if ( v4 )
    {
      v6 = v4;
      do
      {
        _aeabi_memclr4(&s, 512);
        v7 = &v6->d_name[8];
        if ( strcmp(v7, ".") )
        {
          if ( strcmp(v7, "..") )
          {
            snprintf(&s, 0x200u, &byte_21028, v7, v12, v13);
            v5 = v3;
            v8 = openat(-100, &s, 0x80000, 0);
            if ( v8 )
            {
              v9 = v8;
              _aeabi_memclr4(haystack, 512);
              v10 = 0;
              do
              {
                if ( read(v9, &buf, 1u) != 1 )
                  break;
                if ( buf == 10 )
                  break;
                haystack[v10++] = buf;
              }
              while ( v10 < 0x1FF );
              if ( strstr(haystack, &byte_21042) || strstr(haystack, &byte_2104E) )// 搜索gum-js-loop和gmain
                goto LABEL_17;                  // 如果存在的话就exit退出进程
              close(v9);
            }
          }
        }
        v6 = readdir(v5);
      }
      while ( v6 );
    }
    closedir(v5);
    v0 = v13;
    v1 = v12;
  }
  result = *v1 - *(_DWORD *)v0;
  if ( *v1 != *(_DWORD *)v0 )
LABEL_17:
    exit(0);
  return result;
}
```
###### 1.1.2 sub_10D1C
```c
int sub_10D1C()
{
  _DWORD *v0; // r6
  DIR *v1; // r0
  DIR *v2; // r4
  struct dirent *v3; // r0
  struct dirent *v4; // r7
  int result; // r0
  int v6; // [sp+14h] [bp-48Ch]
  char v7; // [sp+18h] [bp-488h]
  int v8; // [sp+28h] [bp-478h]
  char path; // [sp+84h] [bp-41Ch]
  char buf; // [sp+284h] [bp-21Ch]

  v0 = off_1FC04;
  v6 = *(_DWORD *)off_1FC04;
  v1 = opendir(&byte_21054);                    // /proc/self/fd
  if ( v1 )
  {
    v2 = v1;
    v3 = readdir(v1);
    if ( v3 )
    {
      v4 = v3;
      while ( 1 )
      {
        _aeabi_memclr4(&buf, 512);
        _aeabi_memclr4(&path, 512);
        snprintf(&path, 0x200u, "/proc/self/fd/%s", &v4->d_name[8]);
        lstat(&path, (struct stat *)&v7);
        if ( (v8 & 0xF000) == 40960 )
        {
          readlink(&path, &buf, 0x200u);        // 读取文件指向
          if ( strstr(&buf, &byte_21062) )      // linjector
            break;
        }
        v4 = readdir(v2);
        if ( !v4 )
          goto LABEL_7;
      }
LABEL_9:
      exit(0);
    }
LABEL_7:
    closedir(v2);
  }
  result = *v0 - v6;
  if ( *v0 != v6 )
    goto LABEL_9;
  return result;
}
```
###### 1.1.3 sub_10DEC
```c
char *sub_10DEC()
{
  ......

  v31 = off_1FC04;
  v0 = *(_DWORD *)off_1FC04;
  v32 = &v38;
  *(_DWORD *)&v38 = v0;
  v50 = 0;
  v47 = 0;
  v46 = 0;
  v48 = &v46;
  v37 = &v46;
  v49 = &v46;
  v1 = fopen(&byte_2106C, "r");                 // 读取maps
  if ( v1 )
  {
    v2 = v1;
    v56 = 0;
    v57 = 0;
    v58 = 0;
    v55 = 0;
    v54 = 0;
    v53 = 0;
    _aeabi_memclr4(&haystack, 4096);
    if ( !feof(v2) )
    {
      v36 = (_DWORD **)-12;
      v3 = &byte_2107C;
      v34 = (char *)off_1FC20;
      v35 = &byte_2107C;
      do
      {
        if ( !fgets((char *)&v25 + (_DWORD)&stru_1084 + 4, 4096, v2) )
          break;
        v29 = &haystack;
        v28 = &v42;
        v27 = (int *)((char *)&v25 + (_DWORD)&stru_1064 + 12);
        v26 = &v41;
        v25 = &v56;
        if ( sscanf(
               (const char *)&v25 + (_DWORD)&stru_1084 + 4,
               "%lx-%lx %s %lx %s %ld %s",
               &v44,
               &v43,
               &v56,
               &v41,
               (char *)&v25 + (_DWORD)&stru_1064 + 12,
               &v42,
               &haystack) == 7                  // 遍历读取每行内容
          && strstr(&haystack, v3)              // 是否存在/data/local/tmp的文件映射
          && strchr((const char *)&v25 + (_DWORD)&stru_1074 + 8, 120)
          && strchr((const char *)&v25 + (_DWORD)&stru_1074 + 8, 114) )
        {
          sub_187A8(&v40, &haystack, (int)&v39);

          std::_Rb_tree<std::string,std::string,std::_Identity<std::string>,std::less<std::string>,std::allocator<std::string>>::_M_insert_unique<std::string>(
            &v51,
            &v45,
            &v40);                              // 如果存在文件特征，插入数组
          v4 = (char *)v36 + v40;
          if ( (char *)v36 + v40 != v34 && sub_4D00((int)(v4 + 8), (int)v36 + 11, 4) <= 0 )
            sub_18680(v4);
          v3 = v35;
        }
      }
      while ( !feof(v2) );
    }
    fclose(v2);
  }
  v5 = (int)v48;
  if ( v48 == v37 )
  {
LABEL_35:
    std::_Rb_tree<std::string,std::string,std::_Identity<std::string>,std::less<std::string>,std::allocator<std::string>>::_M_erase(
      &v45,
      v47);
    v15 = 0;
    v47 = 0;
    v48 = v37;
    v49 = v37;
    v50 = 0;
  }
  else
  {
    v33 = -12;
    v35 = &byte_2108C;
    v34 = &byte_21097;
    while ( 1 )
    {
      v6 = operator new(0xB4u);
      _aeabi_memclr4(v6 + 56, 41);
      *(_DWORD *)v6 = 0;
      *(_DWORD *)(v6 + 4) = 0;
      *(_DWORD *)(v6 + 8) = 0;
      *(_DWORD *)(v6 + 12) = 0;
      *(_DWORD *)(v6 + 16) = 0;
      *(_DWORD *)(v6 + 20) = 0;
      *(_DWORD *)(v6 + 24) = 0;
      *(_DWORD *)(v6 + 28) = 0;
      _aeabi_memclr4(v6 + 100, 80);
      v7 = *(const char **)(v5 + 16);
      *(_DWORD *)(v6 + 176) = 0;
      if ( !sub_EBC0((void **)v6, v7) || !sub_E7F0((_DWORD *)(v6 + 12), *(_DWORD *)v6) )
        break;
      if ( sub_E6C0((_DWORD *)(v6 + 12), v35, v34) )// _AGENT_1.0 frida-agent
        goto LABEL_52;
      v8 = *(FILE **)(v6 + 8);
      if ( v8 )
        fclose(v8);
      ......
LABEL_52:

    exit(0);
  return "_class_type_infoEPKvRNS1_15__upcast_resultE";
}
```
###### 1.1.4 sub_16B48
```c
int sub_16B48()
{
  _DWORD *v0; // r5
  int *v1; // r6
  unsigned int v2; // r5
  char *v3; // r4
  int v4; // r0
  _DWORD *v6; // [sp+8h] [bp-40h]
  int v7; // [sp+Ch] [bp-3Ch]
  int v8; // [sp+10h] [bp-38h]
  int v9; // [sp+14h] [bp-34h]
  int v10; // [sp+18h] [bp-30h]
  int v11; // [sp+1Ch] [bp-2Ch]
  int v12; // [sp+20h] [bp-28h]
  int v13; // [sp+24h] [bp-24h]
  int v14; // [sp+28h] [bp-20h]
  int v15; // [sp+2Ch] [bp-1Ch]
  int v16; // [sp+30h] [bp-18h]

  v0 = off_1FC04;
  v16 = *(_DWORD *)off_1FC04;
  if ( sub_167E0() )                            // 检测libart.so
  {
    v6 = v0;
    v7 = 2013882270;
    v8 = 1107745203;
    v9 = 1185388969;
    v10 = 2013910933;
    v11 = 1186354873;
    v12 = 1208457641;
    v13 = 2013898649;
    v14 = 1178184103;
    v15 = -1448633943;
    LOBYTE(v7) = 7;
    v1 = dword_1D914;
    v2 = 1;
    do
    {
      *((_BYTE *)&v7 + v2) ^= LOBYTE(v1[-3 * (v2 / 3)]);
      ++v1;
      ++v2;
    }
    while ( v2 != 36 );
    v15 = 248;
    v3 = (char *)mmap(0, 0x24u, 7, 34, -1, 0);
    if ( v3 == (char *)-1 )
    {
      v0 = v6;
    }
    else
    {
      _aeabi_memcpy(v3, &v7, 36);               // v7复制到v3
      j___clear_cache(v3, v3 + 36);
      v0 = v6;
      if ( v3 )
      {
        ((void (__fastcall *)(_DWORD))v3)(0);   // 执行v3通过svc exit_group
        v4 = sysconf(40);
        munmap(v3, v4);
      }
    }
  }
  return *v0 - v16;
}
```
libart.so的检测逻辑
```c
signed int sub_167E0()
{
  .....

  v0 = off_1FC04;
  v38 = *(_DWORD *)off_1FC04;
  v1 = dword_22640;
  if ( dword_22640 )
    goto LABEL_25;
  v2 = *off_1FC08;
  if ( (unsigned int)(*off_1FC08 - 21) <= 1 )
  {
    v3 = dlopen("libart.so", 0);                // dlopen libart
    if ( !v3 )
      goto LABEL_24;
    handle = v3;
    v25 = v0;
    s = -1427636794;
    v27 = -1762796602;
    v28 = -858404453;
    v29 = -724511763;
    v30 = -923673150;
    v31 = -403186483;
    v32 = -190842678;
    v33 = -924066866;
    v34 = -605642533;
    v35 = -305337619;
    v36 = -486684977;
    v37 = 203;
    v4 = strlen((const char *)&s);
    if ( v4 >= 1 )
    {
      LOBYTE(s) = 95;
      if ( v4 != 1 )
      {
        v5 = dword_1D914;
        v6 = (char *)&s + 1;
        v7 = v4 - 1;
        v8 = 1;
        do
        {
          *v6 ^= LOBYTE(v5[-3 * (v8 / 3)]);
          ++v6;
          --v7;
          ++v5;
          ++v8;
        }
        while ( v7 );
      }
    }
    dword_22640 = (int)dlsym(handle, (const char *)&s);// 获取_ZN3art9ArtMethod12PrettyMethodEb的地址
    dlclose(handle);
    goto LABEL_23;
  }
  if ( (unsigned int)(v2 - 23) <= 2 )
  {
    v9 = sub_EFEC((int)"libart.so");
    if ( !v9 )
      goto LABEL_24;
    handlea = (void *)v9;
    v25 = v0;
    s = -1427636794;
    v27 = -1762796602;
    v28 = -858404453;
    v29 = -724511763;
    v30 = -923673150;
    v31 = -403186483;
    v32 = -661587766;
    v33 = -1026236971;
    v34 = -842468899;
    BYTE2(v35) = 0;
    LOWORD(v35) = -14884;
    v10 = strlen((const char *)&s);             // _ZN3art12PrettyMethodEPNS%
    if ( v10 >= 1 )
    {
      LOBYTE(s) = 95;
      if ( v10 != 1 )
      {
        v11 = dword_1D914;
        v12 = (char *)&s + 1;
        v13 = v10 - 1;
        v14 = 1;
        do
        {
          *v12 ^= LOBYTE(v11[-3 * (v14 / 3)]);
          ++v12;
          --v13;
          ++v11;
          ++v14;
        }
        while ( v13 );
      }
    }
    goto LABEL_22;
  }
  if ( v2 >= 26 )
  {
    v15 = sub_EFEC((int)"libart.so");
    if ( v15 )
    {
      handlea = (void *)v15;
      v25 = v0;
      s = -1427636794;
      v27 = -1628578874;
      v28 = -455873560;
      v29 = -155069444;
      v30 = -139749181;
      v31 = -573309733;
      v32 = -305337632;
      v33 = -486684977;
      LOWORD(v34) = 203;
      v16 = strlen((const char *)&s);
      if ( v16 >= 1 )
      {
        LOBYTE(s) = 95;
        if ( v16 != 1 )
        {
          v17 = dword_1D914;
          v18 = (char *)&s + 1;
          v19 = v16 - 1;
          v20 = 1;
          do
          {
            *v18 ^= LOBYTE(v17[-3 * (v20 / 3)]);
            ++v18;
            --v19;
            ++v17;
            ++v20;
          }
          while ( v19 );
        }
      }
LABEL_22:
      dword_22640 = sub_F118((int)handlea, (int)&s);
      sub_F15C(handlea);
LABEL_23:
      v0 = v25;
      goto LABEL_24;
    }
  }
LABEL_24:
  v1 = dword_22640;
  if ( !dword_22640 )
  {
LABEL_26:
    result = 0;
    goto LABEL_27;
  }
LABEL_25:
  result = 1;
  if ( *(_DWORD *)(v1 & 0xFFFFFFFE) != -268371745 )// 判断函数的首个指令是否为0xF000F8DF对应的是LDR PC, [PC, #0]
    goto LABEL_26;
LABEL_27:
  v22 = *v0 - v38;
  return result;
}
```
##### 1.2 0x10975 
```c
void __noreturn sub_10974()
{
  int v0; // r0

  while ( 1 )
  {
    v0 = sub_1041C();
    if ( v0 == -1 || v0 && !sub_1025C(v0) || sub_10850() == 777 )
      // 异常触发
      sub_AF84();
    // 每十秒检测一次
    sleep(0xAu);
  }
}
```
可以看到存在三个检测方法：sub_1041C、sub_1025C、sub_10850，检测逻辑是每十秒触发一次
###### 1.2.1 sub_1041C
```c
int sub_1041C()
{
  signed int v0; // r0
  int *v1; // r7
  char *v2; // r4
  int v3; // r5
  unsigned int v4; // r6
  signed int v5; // r4
  FILE *v6; // r0
  signed int v7; // r0
  int *v8; // r4
  char *v9; // r6
  int v10; // r5
  unsigned int v11; // r7
  char *v12; // r0
  int v13; // r0
  int result; // r0
  FILE *stream; // [sp+4h] [bp-84Ch]
  _DWORD *v16; // [sp+8h] [bp-848h]
  int v17; // [sp+18h] [bp-838h]
  char s[4]; // [sp+1Ch] [bp-834h]
  int v19; // [sp+20h] [bp-830h]
  __int16 v20; // [sp+24h] [bp-82Ch]
  char v21; // [sp+26h] [bp-82Ah]
  char haystack; // [sp+28h] [bp-828h]
  int v23; // [sp+428h] [bp-428h]
  int v24; // [sp+42Ch] [bp-424h]
  int v25; // [sp+430h] [bp-420h]
  int v26; // [sp+434h] [bp-41Ch]
  int v27; // [sp+438h] [bp-418h]

  v16 = off_1FC04;
  v17 = *(_DWORD *)off_1FC04;
  _aeabi_memclr4(&v27, 1024);
  v26 = 14340845;
  v25 = -925635962;
  v24 = -1011054908;
  v23 = -153364554;
  v0 = strlen((const char *)&v23);
  if ( v0 >= 1 )
  {
    LOBYTE(v23) = 47;
    if ( v0 != 1 )
    {
      v1 = dword_1D87C;
      v2 = (char *)&v23 + 1;
      v3 = v0 - 1;
      v4 = 1;
      do
      {
        *v2 ^= LOBYTE(v1[-3 * (v4 / 3)]);
        ++v2;
        --v3;
        ++v1;
        ++v4;
      }
      while ( v3 );
    }
  }
  v5 = -1;
  sprintf((char *)&v27, (const char *)&v23, dword_2100C);
  v6 = fopen((const char *)&v27, "r");          // 读取/proc/30087/status获取指针
  if ( v6 )
  {
    stream = v6;
    _aeabi_memclr4(&haystack, 1024);
    v21 = 0;
    v20 = (unsigned int)&off_A3CC + 1;
    v19 = -825631806;
    *(_DWORD *)s = -87501363;
    v7 = strlen(s);
    if ( v7 >= 1 )
    {
      s[0] = 84;
      if ( v7 != 1 )
      {
        v8 = dword_1D87C;
        v9 = &s[1];
        v10 = v7 - 1;
        v11 = 1;
        do
        {
          *v9 ^= LOBYTE(v8[-3 * (v11 / 3)]);
          ++v9;
          --v10;
          ++v8;
          ++v11;
        }
        while ( v10 );
      }
    }
    while ( fgets(&haystack, 1024, stream) )
    {
      v12 = strstr(&haystack, s);               // 在status内容中搜索TracerPid:
      if ( v12 )
      {
        v13 = atoi(v12 + 10);                   // 获取TracerPid值
        if ( v13 )
        {
          v5 = v13;
          fclose(stream);
          goto LABEL_15;
        }
        break;
      }
    }
    fclose(stream);
    v5 = 0;
  }
LABEL_15:
  result = *v16 - v17;                          // 返回TracerPid
  if ( *v16 == v17 )
    result = v5;
  return result;
}
```
sub_1041C函数主要是为了获取TracerPid
###### 1.2.2 sub_1025C
```c
int __fastcall sub_1025C(int a1)
{
  int v1; // r5
  signed int v2; // r2
  signed int v3; // r0
  int *v4; // r6
  char *v5; // r5
  int v6; // r4
  unsigned int v7; // r7
  FILE *v8; // r0
  signed int v9; // r0
  int *v10; // r7
  char *v11; // r4
  int v12; // r5
  unsigned int v13; // r6
  char *v14; // r0
  int result; // r0
  int v16; // [sp+4h] [bp-84Ch]
  FILE *stream; // [sp+8h] [bp-848h]
  _DWORD *v18; // [sp+10h] [bp-840h]
  int v19; // [sp+1Ch] [bp-834h]
  char s[4]; // [sp+20h] [bp-830h]
  __int16 v21; // [sp+24h] [bp-82Ch]
  char haystack; // [sp+28h] [bp-828h]
  int v23; // [sp+428h] [bp-428h]
  int v24; // [sp+42Ch] [bp-424h]
  int v25; // [sp+430h] [bp-420h]
  int v26; // [sp+434h] [bp-41Ch]
  int v27; // [sp+438h] [bp-418h]

  v1 = a1;
  v18 = off_1FC04;
  v19 = *(_DWORD *)off_1FC04;
  _aeabi_memclr4(&v27, 1024);
  v26 = 14340845;
  v25 = -925635962;
  v24 = -1011054908;
  v23 = -153364554;
  v2 = 0;
  if ( v1 != -1 )
  {
    v16 = v1;
    v3 = strlen((const char *)&v23);
    if ( v3 >= 1 )
    {
      LOBYTE(v23) = 47;
      if ( v3 != 1 )
      {
        v4 = dword_1D87C;
        v5 = (char *)&v23 + 1;
        v6 = v3 - 1;
        v7 = 1;
        do
        {
          *v5 ^= LOBYTE(v4[-3 * (v7 / 3)]);
          ++v5;
          --v6;
          ++v4;
          ++v7;
        }
        while ( v6 );
      }
    }
    sprintf((char *)&v27, (const char *)&v23, v16);
    v8 = fopen((const char *)&v27, "r");        // 同理获取/proc/TracerPid/status
    v2 = 0;
    if ( v8 )
    {
      stream = v8;
      _aeabi_memclr4(&haystack, 1024);
      v21 = 157;
      *(_DWORD *)s = -37685303;                 // ppid
      v9 = strlen(s);
      if ( v9 >= 1 )
      {
        s[0] = 80;
        if ( v9 != 1 )
        {
          v10 = dword_1D87C;
          v11 = &s[1];
          v12 = v9 - 1;
          v13 = 1;
          do
          {
            *v11 ^= LOBYTE(v10[-3 * (v13 / 3)]);
            ++v11;
            --v12;
            ++v10;
            ++v13;
          }
          while ( v12 );
        }
      }
      do
      {
        if ( !fgets(&haystack, 1024, stream) )
          goto LABEL_14;
        v14 = strstr(&haystack, s);
      }                                         // 获取ppid值
      while ( !v14 );
      if ( atoi(v14 + 5) == dword_2100C )       // 比较ppid和当前进程
      {
LABEL_14:
        fclose(stream);
        v2 = 1;
        goto LABEL_16;
      }
      fclose(stream);
      v2 = 0;
    }
  }
LABEL_16:
  result = *v18 - v19;
  if ( *v18 == v19 )
    result = v2;
  return result;
}
```
sub_1025C的作用是检测TracerPid的ppid是否是当前进程
###### 1.2.3 sub_10850
```c
int sub_10850()
{
  char *v0; // r6
  _DWORD *v1; // r7
  __pid_t v2; // r0
  DIR *v3; // r5
  signed int v4; // r4
  struct dirent *v5; // r0
  int v6; // r1
  int v7; // r6
  char *v8; // r0
  __pid_t v9; // r0
  int v10; // r6
  char *v11; // r0
  int v12; // r7
  int result; // r0
  int v15; // [sp+0h] [bp-A28h]
  _DWORD *v16; // [sp+4h] [bp-A24h]
  char *v17; // [sp+8h] [bp-A20h]
  char v18; // [sp+Ch] [bp-A1Ch]
  char buf; // [sp+10h] [bp-A18h]
  int v20; // [sp+410h] [bp-618h]

  v0 = &v18;
  v1 = off_1FC04;
  *(_DWORD *)&v18 = *(_DWORD *)off_1FC04;
  _aeabi_memclr4((char *)&v15 + (_DWORD)&stru_804 + 12, 512);
  _aeabi_memclr4(&v20, 1024);
  _aeabi_memclr4(&buf, 1024);
  v2 = getpid();
  sprintf((char *)&v20, "/proc/%d/task", v2);   // 获取当前进程的task目录
  v3 = opendir((const char *)&v20);             // 获取目录指针
  v4 = -1;
  if ( v3 )
  {
    v16 = v1;
    v17 = &v18;
LABEL_3:
    while ( 1 )
    {
      v5 = readdir(v3);                         // 遍历读取文件

      if ( !v5 )
        break;
      LOBYTE(v6) = v5->d_name[8];
      v7 = (int)&v5->d_name[8];
      if ( v5->d_name[8] )
      {
        v8 = &v5->d_name[9];
        while ( (unsigned int)(unsigned __int8)v6 - 48 > 9 )
        {
          v6 = (unsigned __int8)*v8++;
          if ( !v6 )
            goto LABEL_3;
        }
        v9 = getpid();
        sprintf((char *)&v15 + (_DWORD)&stru_804 + 12, "/proc/%d/task/%s/stat", v9, v7);// 获取主进程信息
        v10 = open((const char *)&v15 + (_DWORD)&stru_804 + 12, 0);
        if ( v10 == -1 || read(v10, &buf, 0x400u) == -1 )
          goto LABEL_18;
        v11 = &buf;
        do
          v12 = (int)(v11 + 1);
        while ( *v11++ != 41 );                 // 读取长度41的内容
        close(v10);
        if ( (*(unsigned __int8 *)(v12 + 1) | 0x20) == 116 && *(_BYTE *)(v12 + 2) == 32 )// 判断status状态
        {
          v4 = 777;
          goto LABEL_18;
        }
      }
    }
    closedir(v3);
    v4 = 0;
LABEL_18:
    v0 = v17;
    v1 = v16;
  }
  result = *v1 - *(_DWORD *)v0;
  if ( *v1 == *(_DWORD *)v0 )
    result = v4;
  return result;
}
```
sub_10850函数功能是判断当前进程的state状态，为T的时候则表示进程处于被调试状态
###### 1.2.4 sub_AF84
```c
int sub_AF84()
{
  _DWORD *v0; // r4
  int v1; // ST04_4

  v0 = off_1FC04;
  v1 = *(_DWORD *)off_1FC04;
  sub_F758();
  sub_E498();
  //调用svc exit_group退出
  sub_15C48(0); 
  return *v0 - v1;
}
```
#### 2 字符解密
```c
#include <algorithm>
#include <cstring>
#include<iomanip>
#include <iostream>
#include <ostream>
using namespace std;

int main()
{
   size_t v0;
   // 设置字节数 1或者4 当数据元素为4个字节时设1，为1个字节时设4
   // int type = 4;
   // unsigned int v21[18] = {
   //    0xFF,          
   //    0xD5,
   //    0xC0,
   //    0xFD,
   //    0xC6,
   //    0x84,
   //    0xF8,
   //    0xC0,
   //    0xCC,
   //    0xF7,
   //    0xD3,
   //       0,
   //       0
   // };
   int type = 1;
   unsigned int v21[18] = {
      0x78096707,          
      0x4206D9B3,
      0x46A799A9,
      0x7809D795,
      0x46B656B9,
      0x480799A9,
      0x7809A799,
      0x4639A9A7,
      0xA9A799A9
   };
   unsigned char* decode = reinterpret_cast<unsigned char*>(v21);
   v0 = strlen((const char *)decode);
   cout<<v0<<endl;
   unsigned short temp[] = {0x99,0xA7,0xA9};
   for(int i=0;i<80;i+=type){
      unsigned short j = (unsigned short)*(decode +i);
      unsigned short k = temp[i%3];
      cout<<(unsigned char)(j^k);
   }
}
```
#### 3 对抗方式
##### 3.1 调用点指令nop
```js
function hook_dlopen(soName = '') {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    if (path.indexOf(soName) >= 0) {
                        locate_init()
                    }
                }
            }
        }
    );
}
 
function locate_init() {
    let secmodule = null
    Interceptor.attach(Module.findExportByName(null, "__system_property_get"),
        {
            // _system_property_get("ro.build.version.sdk", v1);
            onEnter: function (args) {
                secmodule = Process.findModuleByName("libmsaoaidsec.so")
                var name = args[0];
                if (name !== undefined && name != null) {
                    name = ptr(name).readCString();
                    if (name.indexOf("ro.build.version.sdk") >= 0) {
                        // 这是.init_proc刚开始执行的地方，是一个比较早的时机点
                        // do something
                        // hook_pthread_create()
                        bypass()
                    }
                }
            }
        }
    );
}
 
function hook_pthread_create(){
    var base = Process.findModuleByName("libmsaoaidsec.so").base
    console.log("libmsaoaidsec.so --- " + base)
    Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"),{
        onEnter(args){
            let func_addr = args[2]
            console.log("The thread function address is " + func_addr + " offset:" + (func_addr-base).toString(16))
        }
    })
}
 
function nop(addr) {
    Memory.patchCode(ptr(addr), 4, code => {
        const cw = new ThumbWriter(code, { pc: ptr(addr) });
        cw.putNop();
        cw.putNop();
        cw.flush();
    });
}
 
function bypass(){
    let module = Process.findModuleByName("libmsaoaidsec.so")
    nop(module.base.add(0x10ADE))
    nop(module.base.add(0x113F2))
}
 
setImmediate(hook_dlopen, "libmsaoaidsec.so")
```
### 三、总结
从上面的检测方式可以大概总结如下：
- frida特征
- inlinehoook特征
- trace特征

通常都是通过strstr来做判断，但是某些情况，例如验证inlinehook指令时无法直接定位，杀死进程通常都是使用exit或是通过svc exit_group来操作

完整代码看这里[libmsaoaidsec.js](https://github.com/tcc0lin/SecCase/blob/main/libmsaoaidsec.js)
