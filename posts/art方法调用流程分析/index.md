# Art方法调用流程分析


### 一、关于JavaVM
Java是一门跨平台的语言，系统实际运行的是Java字节码，由Java虚拟机去解释执行。解释执行的过程可以看做是一个循环，对每条指令进行解析，并针对指令的名称通过巨大的switch-case分发到不同的分支中处理。Java虚拟机的原理就类似这样，但JVM对于性能做了很多优化，比如JIT运行时将字节码优化成对应平台的二进制代码，提高后续运行速度等

Android代码既然是用Java代码编写的，那么运行时应该也会有一个解析字节码的虚拟机。和标准的JVM不同，Android中实际会将Java代码编译为Dalvik字节码，运行时解析的也是用自研的虚拟机实现。之所以使用自研实现，也许一方面有商业版权的考虑，另一方面也确实是适应了移动端的的运行场景。Dalvik指令基于寄存器，占1-2字节，Java虚拟机指令基于栈，每条指令只占1字节；因此Dalvik虚拟机用空间换时间从而获得比OracleJVM更快的执行速度
#### 1.1 VM启动
其实Java代码执行并不慢，但其启动时间却是一大瓶颈。如果每个APP运行都要启动并初始化Java虚拟机，那延时将是无法接受的。了解应用启动的流程的话，都知道APP应用进程实际上是通过zygote进程fork出来的，这样的好处是子进程继承了父进程的进程空间，对于只读部分可以直接使用，而数据段也可以通过COW(CopyOnWrite)进行延时映射。查看zygote与其子进程的/proc/self/maps可以发现大部分系统库的映射都是相同的，这就是fork所带来的好处

从zygote的启动流程上看
```c&#43;&#43;
// cmds/app_process/app_main.cpp
if (zygote) {
    runtime.start(&#34;com.android.internal.os.ZygoteInit&#34;, args, zygote);
} else if (className) {
    runtime.start(&#34;com.android.internal.os.RuntimeInit&#34;, args, zygote);
} else {
    fprintf(stderr, &#34;Error: no class name or --zygote supplied.\n&#34;);
    app_usage();
    LOG_ALWAYS_FATAL(&#34;app_process: no class name or --zygote supplied.&#34;);
}
```
上述代码在frameworks/base/cmds/app_process/app_main.cpp中，runtime.start的作用就是启动Java虚拟机并将执行流转交给对应的Java函数
```c&#43;&#43;
void AndroidRuntime::start(const char* className, const Vector&lt;String8&gt;&amp; options, bool zygote)
{
    ......
    /* start the virtual machine */
    JniInvocation jni_invocation;
    jni_invocation.Init(NULL);
    JNIEnv* env;
    if (startVm(&amp;mJavaVM, &amp;env, zygote, primary_zygote) != 0) {
        return;
    }
    onVmCreated(env);

    /*
     * Register android functions.
     */
    if (startReg(env) &lt; 0) {
        ALOGE(&#34;Unable to register all android natives\n&#34;);
        return;
    }

    ......
    /*
     * Start VM.  This thread becomes the main thread of the VM, and will
     * not return until the VM exits.
     */
    jclass startClass = env-&gt;FindClass(slashClassName);
    if (startClass == NULL) {
        ALOGE(&#34;JavaVM unable to locate class &#39;%s&#39;\n&#34;, slashClassName);
        /* keep going */
    } else {
        jmethodID startMeth = env-&gt;GetStaticMethodID(startClass, &#34;main&#34;,
            &#34;([Ljava/lang/String;)V&#34;);
        if (startMeth == NULL) {
            ALOGE(&#34;JavaVM unable to find main() in &#39;%s&#39;\n&#34;, className);
            /* keep going */
        } else {
            env-&gt;CallStaticVoidMethod(startClass, startMeth, strArray);

#if 0
            if (env-&gt;ExceptionCheck())
                threadExitUncaughtException(env);
#endif
        }
    }
    free(slashClassName);

    ALOGD(&#34;Shutting down VM\n&#34;);
    if (mJavaVM-&gt;DetachCurrentThread() != JNI_OK)
        ALOGW(&#34;Warning: unable to detach main thread\n&#34;);
    if (mJavaVM-&gt;DestroyJavaVM() != 0)
        ALOGW(&#34;Warning: VM did not shut down cleanly\n&#34;);
}
```
中间省略了一些错误处理代码，更加突出主要逻辑。其中:
- startVm负责创建Java虚拟机，可根据参数和属性值调整虚拟机的特性；
- startReg负责动态绑定一系列JNInative函数(使用JNIEnv-&gt;RegisterNatives来注册)；
- 调用对应Java类的主函数static void main(String[]args)。

根据代码逻辑，可以了解到主线程会启动VM，VM一旦启动后就不会返回直到VM销毁为止，因此可以知道Java虚拟机是在Zygote进程创建的，并由子进程继承，因此APP从zygote进程中fork启动后就无需再次启动Java虚拟机，而是复用原有的虚拟机执行轻量的初始化即可
#### 1.2 VM对外接口
AndroidJava虚拟机包括早期的Dalvik虚拟机和当前的ART虚拟机，我们将其统称为Java虚拟机，因为对于应用程序而言应该是透明的，也就是说二者应该提供了统一的对外接口。

这个接口可以分为两部分，一部分是提供给Java应用的接口，即我们常见的JavaVM、JNIEnv结构体提供的诸如FindClass、GetMethodID、CallVoidMethod等接口；另一部分则是提供给系统开发者的接口，系统通过这些接口去初始化并创建虚拟机，从而使自身具备执行Java代码的功能。

JniInvocation.Init方法中即进行了第二部分接口的初始化操作，其中主要逻辑是根据系统属性persist.sys.dalvik.vm.lib.2来判断待加载的虚拟机动态库，Dalvik虚拟机对应的是libdvm，ART虚拟机对应的是libart，然后通过dlopen进行加载，并通过dlsym获取其中三个函数符号，作为抽象Java虚拟机的接口:
- JNI_GetDefaultJavaVMInitArgs:获取默认的JVM初始化参数；
- JNI_CreateJavaVM:创建Java虚拟机；
- JNI_GetCreatedJavaVMs:获取已经创建的Java虚拟机实例；

例如，在上述zygote的AndroidRuntime::startVm方法实现中，就是通过指定参数最终调用JNI_CreateJavaVM来完成Java虚拟机的创建工作。

通过这三个接口实现了对于不同Java虚拟机细节的隐藏，既可以用ART无缝替换Dalvik虚拟机，也可以在未来用某个新的虚拟机无缝替换掉ART虚拟机。

总的来说，Java虚拟机只在Zygote进程中创建一次，子进程通过fork获得虚拟机的一个副本，因此zygote才被称为所有Java进程的父进程；同时，也因为每个子进程拥有独立的虚拟机副本，所以某个进程的虚拟机崩溃后不影响其他进程，从而实现安全的运行时隔离

### 二、ART
ART全称为AndroidRuntime，是继Dalvik之后推出的高性能AndroidJava虚拟机。在本文中我们重点关注ART虚拟机执行Java代码的流程，在介绍ART的代码执行流程之前，我们需要先了解在ART中针对DEX的一系列提前优化方案，以及由此产生的各类中间文件
#### 2.1 提前优化
在我们使用Android Studio编译应用时，实际上是通过Java编译器先将.java代码编译为对应的Java字节码，即.class类文件；然后用dx(在新版本中是d8)将Java字节码转换为Dalvik字节码，并将所有生成的类打包到统一的DEX文件中，最终和资源文件一起zip压缩为.apk文件

在安装用户的APK时，Android系统主要通过PacketManager对应用进行解包和安装。其中在处理DEX文件时候，会通过installd进程调用对应的二进制程序对字节码进行优化，这对于Dalvik虚拟机而言使用的是dexopt程序，而ART中使用的是dex2oat程序。

dexopt将dex文件优化为odex文件，即optimized-dex的缩写，其中包含的是优化后的Dalvik字节码，称为quickenddex；dex2oat基于LLVM，优化后生成的是对应平台的二进制代码，以oat格式保存，oat的全称为Ahead-Of-Time。oat文件实际上是以ELF格式进行存储的，并在其中oatdata段(section)包含了原始的DEX内容。

在Android8之后，将OAT文件一分为二，原oat仍然是ELF格式，但原始DEX文件内容被保存到了VDEX中，VDEX有其独立的文件格式。整体流程如下图所示:
![](https://evilpan.com/img/2021-12-26-art-internal/1.png)
如前文所言，Android实现了自己的Java虚拟机，这个虚拟机本身是用C/C&#43;&#43;实现的，其中的一些Java原语有对应的C&#43;&#43;类，比如
- java.lang.Class 对应 art::mirror::Class
- java.lang.String 对应 art::mirror::String
- java.lang.reflect.Method 对应 art::mirror::Method

当创建一个Java对象时，内存中会创建对应的C&#43;&#43;对象并调用其构造函数，JVM管理者这些C&#43;&#43;对象的引用。为了加速启动过程，避免对这些常见类的初始化，Android使用了.art格式来保存这些C&#43;&#43;对象的实例，简单来说，art文件可以看做是一系列常用C&#43;&#43;对象的内存dump

不论是oat、vdex还是art，都是Android定义的内部文件格式，官方并不保证其兼容性，事实上在Android各个版本中这些文件格式都有不同程度的变化，这些变化是不反映在文档中的，只能通过代码去一窥究竟。因此对于这些文件格式我们现在只需要知道其大致作用，无需关心其实现细节

#### 2.2 文件加载
APP最终在ActivityThread中完成Application的创建和初始化，最终调用Activity.onCreate进入视图组件的生命周期。但这里其实忽略了一个问题: APP的代码(DEX/OAT文件)是如何加载到进程中的？

在Java中负责加载指定类的对象是ClassLoader，Android中也是类似，BaseDexClassLoader继承自ClassLoader类，实现了许多DEX相关的加载操作，其子类包括:
- DexClassLoader: 负责从 .jar 或者 .apk 中加载类；
- PathClassLoader: 负责从本地文件中初始化类加载器；
- InMemoryDexClassLoader: 从内存中初始化类加载器；
##### 2.2.1 ClassLoader
以常见的PathClassLoader为例，其构造函数会调用父类的构造函数，整体调用链路简化如下表:
1. new PathClassLoader
2. new BaseDexClassLoader	
3. new DexPathList	
4. DexPathList.makeDexElements	
5. DexPathList.loadDexFile	
6. new DexFile	
7. DexFile.openDexFile	
8. DexFile.openDexFileNative
9. DexFile_openDexFileNative
10. OatFileManager::OpenDexFilesFromOat	

在OpenDexFilesFromOat中执行了真正的代码加载工作，伪代码如下:
```c&#43;&#43;
std::vector&lt;std::unique_ptr&lt;const DexFile&gt;&gt; OatFileManager::OpenDexFilesFromOat() {
    std::vector&lt;std::unique_ptr&lt;const DexFile&gt;&gt; dex_files = OpenDexFilesFromOat_Impl(...);
    for (std::unique_ptr&lt;const DexFile&gt;&amp; dex_file : dex_files) {
      if (!dex_file-&gt;DisableWrite()) {
        error_msgs-&gt;push_back(&#34;Failed to make dex file &#34; &#43; dex_file-&gt;GetLocation() &#43; &#34; read-only&#34;);
      }
    }
    return dex_files;
}
```
通过OpenDexFilesFromOat_Impl加载获取DexFile结构体数组，值得注意的是加载完DEX之后会将内存中的dex_file设置为不可写，当然目前还没有强制，但可见这是未来的趋势

继续看实现部分是如何加载Dex文件的
```c&#43;&#43;
std::vector&lt;std::unique_ptr&lt;const DexFile&gt;&gt; OatFileManager::OpenDexFilesFromOat_Impl() {
    // Extract dex file headers from `dex_mem_maps`.
    const std::vector&lt;const DexFile::Header*&gt; dex_headers = GetDexFileHeaders(dex_mem_maps);

    // Determine dex/vdex locations and the combined location checksum.
    std::string dex_location;
    std::string vdex_path;
    bool has_vdex = OatFileAssistant::AnonymousDexVdexLocation(dex_headers,
                                                             kRuntimeISA,
                                                             &amp;dex_location,
                                                             &amp;vdex_path);

    if (has_vdex &amp;&amp; OS::FileExists(vdex_path.c_str())) {
        vdex_file = VdexFile::Open(vdex_path,
                                /* writable= */ false,
                                /* low_4gb= */ false,
                                /* unquicken= */ false,
                                &amp;error_msg);
    }

    // Load dex files. Skip structural dex file verification if vdex was found
    // and dex checksums matched.
    std::vector&lt;std::unique_ptr&lt;const DexFile&gt;&gt; dex_files;
    for (size_t i = 0; i &lt; dex_mem_maps.size(); &#43;&#43;i) {
        static constexpr bool kVerifyChecksum = true;
        const ArtDexFileLoader dex_file_loader;
        std::unique_ptr&lt;const DexFile&gt; dex_file(dex_file_loader.Open(
            DexFileLoader::GetMultiDexLocation(i, dex_location.c_str()),
            dex_headers[i]-&gt;checksum_,
            std::move(dex_mem_maps[i]),
            /* verify= */ (vdex_file == nullptr) &amp;&amp; Runtime::Current()-&gt;IsVerificationEnabled(),
            kVerifyChecksum,
            &amp;error_msg));
        if (dex_file != nullptr) {
            dex::tracking::RegisterDexFile(dex_file.get());  // Register for tracking.
            dex_files.push_back(std::move(dex_file));
        }
    }

    // Initialize an OatFile instance backed by the loaded vdex.
    std::unique_ptr&lt;OatFile&gt; oat_file(OatFile::OpenFromVdex(
        MakeNonOwningPointerVector(dex_files),
        std::move(vdex_file),
        dex_location));
    if (oat_file != nullptr) {
        VLOG(class_linker) &lt;&lt; &#34;Registering &#34; &lt;&lt; oat_file-&gt;GetLocation();
        *out_oat_file = RegisterOatFile(std::move(oat_file));
    }
    return dex_files;
}
```
加载过程首先将vdex映射到内存中，然后将已经映射到内存中的dex或者在磁盘中的dex转换为DexFile结构体，最后再将vdex和oat文件关联起来
#### 2.3 方法调用
本来按照时间线来看的话，这里应该先介绍ART运行时类和方法的加载过程，但我从实践出发，先看Java方法的调用过程，并针对其中涉及到的概念在下一节继续介绍。

在Web安全中，Java服务端通常带有一个称为RASP(RuntimeApplicationSelf-Protection)的动态防护方案，比如监控某些执行命令的敏感函数调用并进行告警，其实际hook点是在JVM中，不论是方法直接调用还是反射调用都可以检测到。因此我们有理由猜测在Android中也有类似的调用链路，为了方便观察，这里先看反射调用的场景，一般反射调用的示例如下
```java
import java.lang.reflect.*;
public class Test {
    public static void main(String args[]) throws Exception {
        Class c = Class.forName(&#34;com.xxx.Test&#34;);
        Method m = c.getMethod(&#34;run&#34;, null);
        m.invoke();
    }
}
```
因此一个方法的调用会进入到Method.invoke方法，这是一个native方法，实际实现在
```c&#43;&#43;
// art/runtime/native/java_lang_reflect_Method.cc
static jobject Method_invoke(JNIEnv* env, jobject javaMethod, jobject javaReceiver,
                             jobjectArray javaArgs) {
  ScopedFastNativeObjectAccess soa(env);
  return InvokeMethod&lt;kRuntimePointerSize&gt;(soa, javaMethod, javaReceiver, javaArgs);
}

// art/runtime/reflection.cc
template &lt;PointerSize kPointerSize&gt;
jobject InvokeMethod(const ScopedObjectAccessAlreadyRunnable&amp; soa, jobject javaMethod,
                     jobject javaReceiver, jobject javaArgs, size_t num_frames) {
    ObjPtr&lt;mirror::Executable&gt; executable = soa.Decode&lt;mirror::Executable&gt;(javaMethod);
    const bool accessible = executable-&gt;IsAccessible();
    ArtMethod* m = executable-&gt;GetArtMethod();

    if (UNLIKELY(!declaring_class-&gt;IsVisiblyInitialized())) {
        Thread* self = soa.Self();
        Runtime::Current()-&gt;GetClassLinker()-&gt;EnsureInitialized(
            self, h_class,
            /*can_init_fields=*/ true,
            /*can_init_parents=*/ true)
    }

    if (!m-&gt;IsStatic()) {
        if (declaring_class-&gt;IsStringClass() &amp;&amp; m-&gt;IsConstructor()) {
            m = WellKnownClasses::StringInitToStringFactory(m);
        } else {
            m = receiver-&gt;GetClass()-&gt;FindVirtualMethodForVirtualOrInterface(m, kPointerSize);
        }
    }

    if (!accessible &amp;&amp; !VerifyAccess(/*...*/)) {
        ThrowIllegalAccessException(
        StringPrintf(&#34;Class %s cannot access %s method %s of class %s&#34;, ...));
    }

    InvokeMethodImpl(soa, m, np_method, receiver, objects, &amp;shorty, &amp;result);
}
```
上面省略了许多细节，主要是做了一些调用前的检查和预处理工作，流程可以概况为:
- 判断方法所属的类是否已经初始化过，如果没有则进行初始化；
- 将 String.&lt;init&gt; 构造函数调用替换为对应的工厂 StringFactory 方法调用；
- 如果是虚函数调用，替换为运行时实际的函数；
- 判断方法是否可以访问，如果不能访问则抛出异常；
- 调用函数；

值得注意的是，jobject类型的javaMethod可以转换为ArtMethod指针，该结构体是ART虚拟机中对于具体方法的描述。之后经过一系列调用:
- InvokeMethodImpl
- InvokeWithArgArray
- method-&gt;Invoke()

最终进入 ArtMethod::Invoke 函数，还是只看核心代码
```c&#43;&#43;
void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result,
                       const char* shorty) {
    Runtime* runtime = Runtime::Current();
    if (UNLIKELY(!runtime-&gt;IsStarted() ||
               (self-&gt;IsForceInterpreter() &amp;&amp; !IsNative() &amp;&amp; !IsProxyMethod() &amp;&amp; IsInvokable()))) {
        art::interpreter::EnterInterpreterFromInvoke(...);
    } else {
        bool have_quick_code = GetEntryPointFromQuickCompiledCode() != nullptr;
        if (LIKELY(have_quick_code)) {
            if (!IsStatic()) {
                (*art_quick_invoke_stub)(this, args, args_size, self, result, shorty);
            } else {
                (*art_quick_invoke_static_stub)(this, args, args_size, self, result, shorty);
            }
        } else {
            LOG(INFO) &lt;&lt; &#34;Not invoking &#39;&#34; &lt;&lt; PrettyMethod() &lt;&lt; &#34;&#39; code=null&#34;;
        }
    }
    self-&gt;PopManagedStackFragment(fragment);
}
```
ART对于Java方法实现了两种执行模式
- 一种是像Dalvik虚拟机一样解释执行字节码，姑且称为解释模式
- 另一种是快速模式，即直接调用通过OAT编译后的本地代码

阅读上述代码可以得知，当ART运行时尚未启动或者指定强制使用解释执行时，虚拟机执行函数使用的是解释模式，ART可以在启动时指定-Xint参数强制使用解释执行，但即便指定了使用解释执行模式，还是有一些情况无法使用解释执行，比如
- 当所执行的方法是Native方法时，这时只有二进制代码，不存在字节码，自然无法解释执行；
- 当所执行的方法无法调用，比如access_flag判定无法访问或者当前方法是抽象方法时；
- 当所执行的方式是代理方法时，ART对于代理方法有单独的本地调用方式；
##### 2.3.1 解释执行
解释执行的入口是art::interpreter::EnterInterpreterFromInvoke
```c&#43;&#43;
// art/runtime/interpreter/interpreter.cc
void EnterInterpreterFromInvoke(Thread* self,
                                ArtMethod* method,
                                ObjPtr&lt;mirror::Object&gt; receiver,
                                uint32_t* args,
                                JValue* result,
                                bool stay_in_interpreter) {
    CodeItemDataAccessor accessor(method-&gt;DexInstructionData());
    if (accessor.HasCodeItem()) {
        num_regs =  accessor.RegistersSize();
        num_ins = accessor.InsSize();
    }
    // 初始化栈帧 ......
    if (LIKELY(!method-&gt;IsNative())) {
        JValue r = Execute(self, accessor, *shadow_frame, JValue(), stay_in_interpreter);
        if (result != nullptr) {
        *result = r;
        }
  }
}
```
其中的CodeItem就是DEX文件中对应方法的字节码，还是老样子，直接看简化的调用链路
1. Execute
2. ExecuteSwitch
3. ExecuteSwitchImpl
4. ExecuteSwitchImplAsm
5. ExecuteSwitchImplCpp

ExecuteSwitchImplAsm为了速度直接使用汇编实现，在ARM64平台中的定义如下:
```c
//  Wrap ExecuteSwitchImpl in assembly method which specifies DEX PC for unwinding.
//  Argument 0: x0: The context pointer for ExecuteSwitchImpl.
//  Argument 1: x1: Pointer to the templated ExecuteSwitchImpl to call.
//  Argument 2: x2: The value of DEX PC (memory address of the methods bytecode).
ENTRY ExecuteSwitchImplAsm
    SAVE_TWO_REGS_INCREASE_FRAME x19, xLR, 16
    mov x19, x2                                   // x19 = DEX PC
    CFI_DEFINE_DEX_PC_WITH_OFFSET(0 /* x0 */, 19 /* x19 */, 0)
    blr x1                                        // Call the wrapped method.
    RESTORE_TWO_REGS_DECREASE_FRAME x19, xLR, 16
    ret
END ExecuteSwitchImplAsm
```
本质上是调用保存在x1寄存器的第二个参数，调用处的代码片段如下:
```c
template&lt;bool do_access_check, bool transaction_active&gt;
ALWAYS_INLINE JValue ExecuteSwitchImpl() {
    //...
    void* impl = reinterpret_cast&lt;void*&gt;(&amp;ExecuteSwitchImplCpp&lt;do_access_check, transaction_active&gt;);
    const uint16_t* dex_pc = ctx.accessor.Insns();
    ExecuteSwitchImplAsm(&amp;ctx, impl, dex_pc);
}
```
即调用了ExecuteSwitchImplCpp，在该函数中，可以看见典型的解释执行代码
```c&#43;&#43;
template&lt;bool do_access_check, bool transaction_active&gt;
void ExecuteSwitchImplCpp(SwitchImplContext* ctx) {
    Thread* self = ctx-&gt;self;
    const CodeItemDataAccessor&amp; accessor = ctx-&gt;accessor;
    ShadowFrame&amp; shadow_frame = ctx-&gt;shadow_frame;
    self-&gt;VerifyStack();

    uint32_t dex_pc = shadow_frame.GetDexPC();
    const auto* const instrumentation = Runtime::Current()-&gt;GetInstrumentation();
    const uint16_t* const insns = accessor.Insns();
    const Instruction* next = Instruction::At(insns &#43; dex_pc);

    while (true) {
        const Instruction* const inst = next;
        dex_pc = inst-&gt;GetDexPc(insns);
        shadow_frame.SetDexPC(dex_pc);
        TraceExecution(shadow_frame, inst, dex_pc);
        uint16_t inst_data = inst-&gt;Fetch16(0); // 一条指令 4 字节

        if (InstructionHandler(...).Preamble()) {
            switch (inst-&gt;Opcode(inst_data)) {
                case xxx: ...;
                case yyy: ...;
                ...
            }
        }
    }
}
```
在当前版本中(Android12)，实际上是通过宏展开去定义了所有op_code的处理分支，不同版本实现都略有不同，但解释执行的核心思路从Android2.x版本到现在都是一致的，因为字节码的定义并没有太多改变
##### 2.3.2 快速执行
再回到ArtMethod真正调用之前，如果不使用解释模式执行，则通过art_quick_invoke_stub去调用。stub是一小段中间代码，用于跳转到实际的native执行，该符号使用汇编实现，在ARM64中的定义在art/runtime/arch/arm64/quick_entrypoints_arm64.S，核心代码如下
```c&#43;&#43;
.macro INVOKE_STUB_CALL_AND_RETURN
    REFRESH_MARKING_REGISTER
    REFRESH_SUSPEND_CHECK_REGISTER

    // load method-&gt; METHOD_QUICK_CODE_OFFSET
    ldr x9, [x0, #ART_METHOD_QUICK_CODE_OFFSET_64]
    // Branch to method.
    blr x9
.endm

/*
 *  extern&#34;C&#34; void art_quick_invoke_stub(ArtMethod *method,   x0
 *                                       uint32_t  *args,     x1
 *                                       uint32_t argsize,    w2
 *                                       Thread *self,        x3
 *                                       JValue *result,      x4
 *                                       char   *shorty);     x5
 */
ENTRY art_quick_invoke_stub
    // ...
    INVOKE_STUB_CALL_AND_RETURN
END art_quick_invoke_static_stub
```
中间省略了一些保存上下文以及调用后恢复寄存器的代码，其核心是调用了ArtMethod结构体偏移ART_METHOD_QUICK_CODE_OFFSET_64处的指针，该值对应的代码为
```c&#43;&#43;
ASM_DEFINE(ART_METHOD_QUICK_CODE_OFFSET_64,
           art::ArtMethod::EntryPointFromQuickCompiledCodeOffset(art::PointerSize::k64).Int32Value())
```
即entry_point_from_quick_compiled_code_属性所指向的地址
```c&#43;&#43;
// art/runtime/art_method.h
static constexpr MemberOffset EntryPointFromQuickCompiledCodeOffset(PointerSize pointer_size) {
return MemberOffset(PtrSizedFieldsOffset(pointer_size) &#43; OFFSETOF_MEMBER(
    PtrSizedFields, entry_point_from_quick_compiled_code_) / sizeof(void*)
        * static_cast&lt;size_t&gt;(pointer_size));
}
```
可以认为这就是所有快速模式执行代码的入口，至于该指针指向什么地方，又是什么时候初始化的，可以参考下一节代码加载部分。实际在方法调用时，快速模式执行的方法可能在其中执行到了需要以解释模式执行的方法，同样以解释模式执行的方法也可能在其中调用到JNI方法或者其他以快速模式执行的方法，所以在单个函数执行的过程中运行状态并不是一成不变的，但由于每次切换调用前后都保存和恢复了当前上下文，使得不同调用之间可以保持透明，这也是模块化设计的一大优势所在
#### 2.4 代码加载
在上节我们知道在ART虚拟机中，Java方法的调用主要通过ArtMethod::Invoke去实现，那么ArtMethod结构是什么时候创建的呢？为什么jmethod/jobject可以转换为ArtMethod指针呢？

在Java这门语言中，方法是需要依赖类而存在的，因此要分析方法的初始化需要先分析类的初始化。虽然我们前面知道如何从OAT/VDEX/DEX文件中构造对应的ClassLoader来进行类查找，但那个时候类并没有初始化
##### 2.4.1 FindClass
FindClass实现了根据类名查找类的过程，定义在art/runtime/class_linker.cc中，关键流程如下:
```c&#43;&#43;
ObjPtr&lt;mirror::Class&gt; ClassLinker::FindClass(Thread* self,
                                             const char* descriptor,
                                             Handle&lt;mirror::ClassLoader&gt; class_loader) 
    if (descriptor[1] == &#39;\0&#39;) 
        return FindPrimitiveClass(descriptor[0]);

    const size_t hash = ComputeModifiedUtf8Hash(descriptor);
    // 在已经加载的类中查找
    ObjPtr&lt;mirror::Class&gt; klass = LookupClass(self, descriptor, hash, class_loader.Get());
    if (klass != nullptr) {
        return EnsureResolved(self, descriptor, klass);
    }
    // 尚未加载
    if (descriptor[0] != &#39;[&#39; &amp;&amp; class_loader == nullptr) {
        // 类加载器为空，且不是数组类型，在启动类中进行查找
        ClassPathEntry pair = FindInClassPath(descriptor, hash, boot_class_path_);
        return DefineClass(self, descriptor, hash,
                           ScopedNullHandle&lt;mirror::ClassLoader&gt;(),
                           *pair.first, *pair.second);
    }

    ObjPtr&lt;mirror::Class&gt; result_ptr;
    bool descriptor_equals;
    ScopedObjectAccessUnchecked soa(self);
    // 先通过 classLoader 的父类查找
    bool known_hierarchy =
        FindClassInBaseDexClassLoader(soa, self, descriptor, hash, class_loader, &amp;result_ptr);
    if (result_ptr != nullptr) {
        descriptor_equals = true;
    } else if (!self-&gt;IsExceptionPending()) {
        // 如果没找到，再通过 classLoader 查找
        std::string class_name_string(descriptor &#43; 1, descriptor_length - 2);
        std::replace(class_name_string.begin(), class_name_string.end(), &#39;/&#39;, &#39;.&#39;);
        ScopedLocalRef&lt;jobject&gt; class_loader_object(
            soa.Env(), soa.AddLocalReference&lt;jobject&gt;(class_loader.Get()));
        ScopedLocalRef&lt;jobject&gt; result(soa.Env(), nullptr);
        result.reset(soa.Env()-&gt;CallObjectMethod(class_loader_object.get(),
                                                 WellKnownClasses::java_lang_ClassLoader_loadClass,
                                                 class_name_object.get()));
    }

    // 将找到的类插入到缓存表中
    ClassTable* const class_table = InsertClassTableForClassLoader(class_loader.Get());
    class_table-&gt;InsertWithHash(result_ptr, hash);

    return result_ptr;
}
```
首先会通过LookupClass在已经加载的类中查找，已经加载的类会保存在ClassTable中，以hash表的方式存储，该表的键就是类对应的hash，通过descriptor计算得出。如果之前已经加载过，那么这时候就可以直接返回，如果没有就需要执行真正的加载了。从这里我们也可以看出，类的加载过程属于懒加载(lazyloading)，如果一个类不曾被使用，那么是不会有任何加载开销的

然后会判断指定的类加载器是否为空，为空表示要查找的类实际上是一个系统类。系统类不存在于app的dex文件中，而是Android系统的一部分。由于每个Android(Java)应用都会用到系统类，为了提高启动速度，实际通过zygote去加载，并由所有子进程一起共享。上述boot_class_path_数组在Runtime::Init中通过ART启动的参数进行初始化，感兴趣的可以自行研究细节

我们关心的应用类查找过程可以分为两步，首先在父类的ClassLoader进行查找，如果没找到才会通过指定的classLoader进行查找，这也是很多类似Java文章中提到的“双亲委派”机制。保证关键类的查找过程优先通过系统类加载器，可以防止关键类实现被应用篡改

FindClassInBaseDexClassLoader的实现使用伪代码描述如下所示:
```c&#43;&#43;
Class ClassLinker::FindClassInBaseDexClassLoader(ClassLoader class_loader, size_t hash) {
    if (class_loader == java_lang_BootClassLoader) {
        return FindClassInBootClassLoaderClassPath(class_loader, hash);
    }
    if (class_loader == dalvik_system_PathClassLoader ||
        class_loader == dalvik_system_DexClassLoader ||
        class_loader == dalvik_system_InMemoryDexClassLoader) {
        // For regular path or dex class loader the search order is:
        //    - parent
        //    - shared libraries
        //    - class loader dex files
        FindClassInBaseDexClassLoader(class_loader-&gt;GetParent, hash) &amp;&amp; return result;
        FindClassInSharedLibraries(...) &amp;&amp; return result;
        FindClassInBaseDexClassLoaderClassPath(...) &amp;&amp; return result;
        FindClassInSharedLibrariesAfter(...) &amp;&amp; return result;
    }
    if (class_loader == dalvik_system_DelegateLastClassLoader) {
        // For delegate last, the search order is:
        //    - boot class path
        //    - shared libraries
        //    - class loader dex files
        //    - parent
        FindClassInBootClassLoaderClassPath(...) &amp;&amp; return result;
        FindClassInBaseDexClassLoaderClassPath(...) &amp;&amp; return result;
        FindClassInSharedLibrariesAfter(...) &amp;&amp; return result;
        FindClassInBaseDexClassLoader(class_loader-&gt;GetParent, hash) &amp;&amp; return result;
    }
    return null;
}
```
根据不同的class_loader类型使用不同的搜索顺序，如果涉及到父ClassLoader的搜索，则使用递归查找，递归的停止条件是当前class_loader为java.lang.BootClassLoader

FindClassInBootClassLoaderClassPath的关键代码如下:
```c&#43;&#43;
using ClassPathEntry = std::pair&lt;const DexFile*, const dex::ClassDef*&gt;;
bool ClassLinker::FindClassInBootClassLoaderClassPath(Thread* self,
                                                      const char* descriptor,
                                                      size_t hash,
                                                      /*out*/ ObjPtr&lt;mirror::Class&gt;* result) {
    ClassPathEntry pair = FindInClassPath(descriptor, hash, boot_class_path_);
    if (pair.second != nullptr) {
        ObjPtr&lt;mirror::Class&gt; klass = LookupClass(self, descriptor, hash, nullptr);
        if (klass != nullptr) {
            *result = EnsureResolved(self, descriptor, klass);
        } else {
            *result = DefineClass(self, ...);
        }
    }
    return true;
```
如果在BaseClassLoader中没有找到对应的类，那么最终会通过传入的classLoader查找，即调用指定类加载器的loadClass方法
![](https://evilpan.com/img/2021-12-26-art-internal/0.png)
最终调用了DexFile的native方法defineClassNative，实现在art/runtime/native/dalvik_system_DexFile.cc，关键代码如下:
```c&#43;&#43;
static jclass DexFile_defineClassNative(JNIEnv* env,
                                        jclass,
                                        jstring javaName,
                                        jobject javaLoader,
                                        jobject cookie,
                                        jobject dexFile) {
    std::vector&lt;const DexFile*&gt; dex_files;
    ConvertJavaArrayToDexFiles(env, cookie, /*out*/ dex_files, /*out*/ oat_file);

    ScopedUtfChars class_name(env, javaName);
    const std::string descriptor(DotToDescriptor(class_name.c_str()));
    const size_t hash(ComputeModifiedUtf8Hash(descriptor.c_str()));
    for (auto&amp; dex_file : dex_files) {
        const dex::ClassDef* dex_class_def = OatDexFile::FindClassDef(*dex_file, descriptor.c_str(), hash);
        // dex_class_def != nullptr
        ClassLinker* class_linker = Runtime::Current()-&gt;GetClassLinker();
        Handle&lt;mirror::ClassLoader&gt; class_loader(
          hs.NewHandle(soa.Decode&lt;mirror::ClassLoader&gt;(javaLoader)));
        ObjPtr&lt;mirror::DexCache&gt; dex_cache =
          class_linker-&gt;RegisterDexFile(*dex_file, class_loader.Get());
        // dex_cache != nullptr
        ObjPtr&lt;mirror::Class&gt; result = class_linker-&gt;DefineClass(soa.Self(),
                                                               descriptor.c_str(),
                                                               hash,
                                                               class_loader,
                                                               *dex_file,
                                                               *dex_class_def);
        class_linker-&gt;InsertDexFileInToClassLoader(soa.Decode&lt;mirror::Object&gt;(dexFile),
                                                 class_loader.Get());
    }
}
```
也就是说，不论是通过FindClassInBaseDexClassLoader查找还是通过指定classLoader的loadClass加载，最终执行的流程都是类似的，即在对应的DexFile(OatDexFile)中根据类名搜索对应类的ClassDef字段，了解Dex文件结构的对这个字段应该不会陌生

在找到类在对应Dex文件中的ClassDef内容后，会通过ClassLinker完成该类的后续注册流程，包括:
- 对于当前DexFile，如果是第一次遇到，会创建一个DexCache缓存，保存到ClassLinker的dex_caches_哈希表中；
- 通过ClassLinker::DefineClass完成目标类的定义，详见后文；
- 将对应DexFile添加到类加载器对应的ClassTable中；

其中DefineClass是我们比较关心的，因此下面单独进行介绍
##### 2.4.2 DefineClass
```c&#43;&#43;
ObjPtr&lt;mirror::Class&gt; ClassLinker::DefineClass(Thread* self,
                                               const char* descriptor,
                                               size_t hash,
                                               Handle&lt;mirror::ClassLoader&gt; class_loader,
                                               const DexFile&amp; dex_file,
                                               const dex::ClassDef&amp; dex_class_def) {
    ScopedDefiningClass sdc(self);
    StackHandleScope&lt;3&gt; hs(self);
    auto klass = hs.NewHandle&lt;mirror::Class&gt;(nullptr);

    // Load the class from the dex file.
    if (UNLIKELY(!init_done_)) {
        // [1] finish up init of hand crafted class_roots_
    }

    ObjPtr&lt;mirror::DexCache&gt; dex_cache = RegisterDexFile(*new_dex_file, class_loader.Get());
    klass-&gt;SetDexCache(dex_cache);
    ObjPtr&lt;mirror::Class&gt; existing = InsertClass(descriptor, klass.Get(), hash);
    if (existing != nullptr) {
        // 其他线程正在链接该类，阻塞等待其完成
        return sdc.Finish(EnsureResolved(self, descriptor, existing));
    }
    LoadClass(self, *new_dex_file, *new_class_def, klass);
    // klass-&gt;IsLoaded
    LoadSuperAndInterfaces(klass, *new_dex_file))
    Runtime::Current()-&gt;GetRuntimeCallbacks()-&gt;ClassLoad(klass);
    // klass-&gt;IsResolved
    LinkClass(self, descriptor, klass, interfaces, &amp;h_new_class)
    Runtime::Current()-&gt;GetRuntimeCallbacks()-&gt;ClassPrepare(klass, h_new_class);

    jit::Jit::NewTypeLoadedIfUsingJit(h_new_class.Get());
    return sdc.Finish(h_new_class);
}
```
这里只列出一些关键代码，init_done_用于表示当前ClassLinker的初始化状态，初始化过程用于从Image空间或者手动创建内部类，手动创建的内部类包括:
- Ljava/lang/Object;
- Ljava/lang/Class;
- Ljava/lang/String;
- Ljava/lang/ref/Reference;
- Ljava/lang/DexCache;
- Ldalvik/system/ClassExt;

它们都直接定义在了art::runtime::mirror命名空间中，比如Object定义为mirror::Object，所属文件为art/runtime/mirror/object.h；
##### 2.4.3 LoadClass
ClassLinker::LoadClass用于从指定DEX文件中加载目标类的属性和方法等内容，注意这里其实是在对应类添加到ClassTable之后才加载的，这是出于ART的内部优化考虑，另外一个原因是类的属性根只能通过ClassTable访问，因此需要在访问前先在ClassTable中占好位置。其实现如下:
```c&#43;&#43;
void ClassLinker::LoadClass(Thread* self,
                            const DexFile&amp; dex_file,
                            const dex::ClassDef&amp; dex_class_def,
                            Handle&lt;mirror::Class&gt; klass) {
    ClassAccessor accessor(dex_file,
                         dex_class_def,
                         /* parse_hiddenapi_class_data= */ klass-&gt;IsBootStrapClassLoaded());
    Runtime* const runtime = Runtime::Current();
    accessor.VisitFieldsAndMethods(
        [&amp;](const ClassAccessor::Field&amp; field) {
            LoadField(field, klass, &amp;sfields-&gt;At(num_sfields));
            &#43;&#43;num_sfields;
        },
        [&amp;](const ClassAccessor::Field&amp; field) {
            LoadField(field, klass, &amp;ifields-&gt;At(num_ifields));
            &#43;&#43;num_ifields;
        },
        [&amp;](const ClassAccessor::Method&amp; method) {
            ArtMethod* art_method = klass-&gt;GetDirectMethodUnchecked(
                class_def_method_index,
                image_pointer_size_);
            LoadMethod(dex_file, method, klass, art_method);
            LinkCode(this, art_method, oat_class_ptr, class_def_method_index);
            &#43;&#43;class_def_method_index;
        },
        [&amp;](const ClassAccessor::Method&amp; method) {
            ArtMethod* art_method = klass-&gt;GetVirtualMethodUnchecked(
                class_def_method_index - accessor.NumDirectMethods(),
                image_pointer_size_);
            LoadMethod(dex_file, method, klass, art_method);
            LinkCode(this, art_method, oat_class_ptr, class_def_method_index);
            &#43;&#43;class_def_method_index;
        }
    );
    klass-&gt;SetSFieldsPtr(sfields);
    klass-&gt;SetIFieldsPtr(ifields);
}
```
上面用到了C&#43;&#43;11的lambda函数来通过迭代器访问类中的关联元素，分别是:
- sfields:staticfields，静态属性
- ifields:instancefields，对象属性
- directmethod:对象方法
- virtualmethod:抽象方法

对于属性的加载通过LoadField实现，主要作用是初始化ArtField并与目标类关联起来；LoadMethod的实现亦是类似，主要是使用dex文件中对应方法的CodeItem对ArtMethod进行初始化，并与klass关联。但是对于方法而言，还好进行额外的一步，即LinkCode
##### 2.4.4 LinkCode
LinkCode顾名思义是对代码进行链接，关键代码如下
```c&#43;&#43;
static void LinkCode(ClassLinker* class_linker,
                     ArtMethod* method,
                     const OatFile::OatClass* oat_class,
                     uint32_t class_def_method_index) {
    Runtime* const runtime = Runtime::Current();
    const void* quick_code = nullptr;
    if (oat_class != nullptr) {
         // Every kind of method should at least get an invoke stub from the oat_method.
         // non-abstract methods also get their code pointers.
         const OatFile::OatMethod oat_method = oat_class-&gt;GetOatMethod(class_def_method_index);
         quick_code = oat_method.GetQuickCode();
    }
    runtime-&gt;GetInstrumentation()-&gt;InitializeMethodsCode(method, quick_code);

    if (method-&gt;IsNative()) {
    // Set up the dlsym lookup stub. Do not go through `UnregisterNative()`
    // as the extra processing for @CriticalNative is not needed yet.
        method-&gt;SetEntryPointFromJni(
            method-&gt;IsCriticalNative() ? GetJniDlsymLookupCriticalStub() : GetJniDlsymLookupStub());
  }
}
```
其中quick_code指针指向的是OatMethod中的code_offset_偏移处的值，该值指向的是OAT优化后的本地代码位置
InitializeMethodsCode是Instrumentation类的方法，实现在art/runtime/instrumentation.cc，，即作为某些关键调用的收口，并在其中实现可插拔的追踪行为。其内部实现如下:
```c&#43;&#43;
void Instrumentation::InitializeMethodsCode(ArtMethod* method, const void* aot_code) {
    // Use instrumentation entrypoints if instrumentation is installed.
    if (UNLIKELY(EntryExitStubsInstalled())) {
        if (!method-&gt;IsNative() &amp;&amp; InterpretOnly()) {
            UpdateEntryPoints(method, GetQuickToInterpreterBridge());
        } else {
            UpdateEntryPoints(method, GetQuickInstrumentationEntryPoint());
        }
        return;
    }
    if (UNLIKELY(IsForcedInterpretOnly())) {
        UpdateEntryPoints(
            method, method-&gt;IsNative() ? GetQuickGenericJniStub() : GetQuickToInterpreterBridge());
        return;
    }
    // Use the provided AOT code if possible.
    if (CanUseAotCode(method, aot_code)) {
        UpdateEntryPoints(method, aot_code);
        return;
    }
    // Use default entrypoints.
    UpdateEntryPoints(
      method, method-&gt;IsNative() ? GetQuickGenericJniStub() : GetQuickToInterpreterBridge());
}
```
第一部分正是用于追踪的判断，如果当前已经安装了追踪监控，那么会根据当前方法的类别分别设置对应的入口点；否则就以常规方式设置方法的调用入口:
- 对于强制解释执行的运行时环境:
    - 如果是Native方法则将入口点设置为art_quick_generic_jni_trampoline，用于跳转执行JNI本地代码；
    - 对于Java方法则将入口点设置为art_quick_to_interpreter_bridge，使方法调用过程会跳转到解释器继续；
- 如果AOT编译的本地代码可用，则直接将方法入口点设置为AOT代码；
- 如果AOT代码不可用，那么就回到解释执行场景进行处理；

设置ArtMethod入口地址的方法是UpdateEntryPoints，其内部实现非常简单:
```c&#43;&#43;
static void UpdateEntryPoints(ArtMethod* method, const void* quick_code)
    REQUIRES_SHARED(Locks::mutator_lock_) {
    if (kIsDebugBuild) {
        ...
    }
    // If the method is from a boot image, don&#39;t dirty it if the entrypoint
    // doesn&#39;t change.
    if (method-&gt;GetEntryPointFromQuickCompiledCode() != quick_code) {
        method-&gt;SetEntryPointFromQuickCompiledCode(quick_code);
    }
}
```
内部实质上是调用了ArtMethod::SetEntryPointFromQuickCompiledCode
```c&#43;&#43;
void SetEntryPointFromQuickCompiledCode(const void* entry_point_from_quick_compiled_code)
      REQUIRES_SHARED(Locks::mutator_lock_) {
    SetEntryPointFromQuickCompiledCodePtrSize(entry_point_from_quick_compiled_code,
                                              kRuntimePointerSize);
  }
```
回顾我们前面分析方法调用的章节，对于快速执行的场景，ArtMethod::Invoke最终是跳转到entry_point_from_quick_compiled_code进行执行，而这个字段就是在这里进行设置的

至此，我们完成了ART方法调用流程分析的最后一块拼图

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/art%E6%96%B9%E6%B3%95%E8%B0%83%E7%94%A8%E6%B5%81%E7%A8%8B%E5%88%86%E6%9E%90/  

