# LSPlant源码学习


LSPlant是LSPosed官方推出的新的ART hook框架，用来替代LSPosed之前使用的YAHFA框架

从官方README上看，对于LSPlant的使用分为几种

1. Init LSPlant within JNI_OnLoad（在JNI_OnLoad时初始化LSPlant）
   ```c&#43;&#43;
   bool Init(JNIEnv *env,
          const InitInfo &amp;info);
   ```
2. Hook
   ```c&#43;&#43;
   jobject Hook(JNIEnv *env,
             jobject target_method,
             jobject hooker_object,
             jobject callback_method);
   ```
   这里存在三个入参，分别是目标方法、上下文、回调方法

3. Check
   ```c&#43;&#43;
   bool IsHooked(JNIEnv *env,
              jobject method);
   ```

4. Unhook
   ```c&#43;&#43;
   bool UnHook(JNIEnv *env,
            jobject target_method);
   ```

5. Deoptimize
   ```c&#43;&#43;
   bool Deoptimize(JNIEnv *env,
                jobject method);
   ```
   防止某些短函数被内联导致hook失效

### 一、LSPlant框架初始化
lsplant的函数都实现在lsplant.cc中，看下init函数
```c&#43;&#43;
// lsplant\src\main\jni\lsplant.cc

[[maybe_unused]] bool Init(JNIEnv *env, const InitInfo &amp;info) {
    bool static kInit = InitConfig(info) &amp;&amp; InitJNI(env) &amp;&amp; InitNative(env, info);
    return kInit;
}
```
以三个子流程的初始化状态来判断框架的状态
#### 1.1 InitConfig
```c&#43;&#43;
bool InitConfig(const InitInfo &amp;info) {
    if (info.generated_class_name.empty()) {
        LOGE(&#34;generated class name cannot be empty&#34;);
        return false;
    }
    generated_class_name = info.generated_class_name;
    if (info.generated_field_name.empty()) {
        LOGE(&#34;generated field name cannot be empty&#34;);
        return false;
    }
    generated_field_name = info.generated_field_name;
    if (info.generated_method_name.empty()) {
        LOGE(&#34;generated method name cannot be empty&#34;);
        return false;
    }
    generated_method_name = info.generated_method_name;
    generated_source_name = info.generated_source_name;
    return true;
}
```
这里说明入参必须要参照结构体InitInfo，需要配置的generated_class_name、generated_field_name、generated_method_name等字段
```c&#43;&#43;
struct InitInfo {
    /// \brief Type of inline hook function.
    /// In \ref std::function form so that user can use lambda expression with capture list.&lt;br&gt;
    /// \p target is the target function to be hooked.&lt;br&gt;
    /// \p hooker is the hooker function to replace the \p target function.&lt;br&gt;
    /// \p return is the backup function that points to the previous target function.
    /// it should return null if hook fails and nonnull if successes.
    using InlineHookFunType = std::function&lt;void *(void *target, void *hooker)&gt;;
    /// \brief Type of inline unhook function.
    /// In \ref std::function form so that user can use lambda expression with capture list.&lt;br&gt;
    /// \p func is the target function that is previously hooked.&lt;br&gt;
    /// \p return should indicate the status of unhooking.&lt;br&gt;
    using InlineUnhookFunType = std::function&lt;bool(void *func)&gt;;
    /// \brief Type of symbol resolver to \p libart.so.
    /// In \ref std::function form so that user can use lambda expression with capture list.&lt;br&gt;
    /// \p symbol_name is the symbol name that needs to retrieve.&lt;br&gt;
    /// \p return is the absolute address in the memory that points to the target symbol. It should
    /// be null if the symbol cannot be found. &lt;br&gt;
    /// \note It should be able to resolve symbols from both .dynsym and .symtab.
    using ArtSymbolResolver = std::function&lt;void *(std::string_view symbol_name)&gt;;

    using ArtSymbolPrefixResolver = std::function&lt;void *(std::string_view symbol_prefix)&gt;;

    /// \brief The inline hooker function. Must not be null.
    InlineHookFunType inline_hooker;
    /// \brief The inline unhooker function. Must not be null.
    InlineUnhookFunType inline_unhooker;
    /// \brief The symbol resolver to \p libart.so. Must not be null.
    ArtSymbolResolver art_symbol_resolver;

    /// \brief The symbol prefix resolver to \p libart.so. May be null.
    ArtSymbolPrefixResolver art_symbol_prefix_resolver;

    /// \brief The generated class name. Must not be empty. It contains a field and a method
    /// and they could be set by \p generated_field_name and \p generated_method_name respectively.
    std::string_view generated_class_name = &#34;LSPHooker_&#34;;
    /// \brief The generated source name. Could be empty.
    std::string_view generated_source_name = &#34;LSP&#34;;
    /// \brief The generated field name. Must not be empty.
    std::string_view generated_field_name = &#34;hooker&#34;;
    /// \brief The generated class name. Must not be emtpy. If {target} is set,
    /// it will follows the name of the target.
    std::string_view generated_method_name = &#34;{target}&#34;;
};
```
可以看到name相关的字段都是默认的，因此可以不关注，最主要需要配置的是art_symbol_resolver、art_symbol_prefix_resolver这两个对于libart.so的hook，参考LSPosed的使用
```c&#43;&#43;
void
    MagiskLoader::OnNativeForkAndSpecializePost(JNIEnv *env, jstring nice_name, jstring app_dir) {
        const JUTFString process_name(env, nice_name);
        auto *instance = Service::instance();
        auto binder = skip_ ? ScopedLocalRef&lt;jobject&gt;{env, nullptr}
                            : instance-&gt;RequestBinder(env, nice_name);
        if (binder) {
            lsplant::InitInfo initInfo{
                    .inline_hooker = [](auto t, auto r) {
                        void* bk = nullptr;
                        return HookFunction(t, r, &amp;bk) == RS_SUCCESS ? bk : nullptr;
                    },
                    .inline_unhooker = [](auto t) {
                        return UnhookFunction(t) == RT_SUCCESS;
                    },
                    .art_symbol_resolver = [](auto symbol){
                        return GetArt()-&gt;getSymbAddress(symbol);
                    },
                    .art_symbol_prefix_resolver = [](auto symbol) {
                        return GetArt()-&gt;getSymbPrefixFirstAddress(symbol);
                    },
            };
            ......
        } else {
            auto context = Context::ReleaseInstance();
            auto service = Service::ReleaseInstance();
            GetArt(true);
            LOGD(&#34;skipped {}&#34;, process_name.get());
            setAllowUnload(true);
        }
    }
```
#### 1.2 InitJNI
```c&#43;&#43;
bool InitJNI(JNIEnv *env) {
    int sdk_int = GetAndroidApiLevel();
    if (sdk_int &gt;= __ANDROID_API_O__) {
        executable = JNI_NewGlobalRef(env, JNI_FindClass(env, &#34;java/lang/reflect/Executable&#34;));
    } else {
        executable = JNI_NewGlobalRef(env, JNI_FindClass(env, &#34;java/lang/reflect/AbstractMethod&#34;));
    }
    if (!executable) {
        LOGE(&#34;Failed to found Executable/AbstractMethod&#34;);
        return false;
    }

    if (method_get_name = JNI_GetMethodID(env, executable, &#34;getName&#34;, &#34;()Ljava/lang/String;&#34;);
        !method_get_name) {
        LOGE(&#34;Failed to find getName method&#34;);
        return false;
    }
    if (method_get_declaring_class =
            JNI_GetMethodID(env, executable, &#34;getDeclaringClass&#34;, &#34;()Ljava/lang/Class;&#34;);
        !method_get_declaring_class) {
        LOGE(&#34;Failed to find getDeclaringClass method&#34;);
        return false;
    }
    if (method_get_parameter_types =
            JNI_GetMethodID(env, executable, &#34;getParameterTypes&#34;, &#34;()[Ljava/lang/Class;&#34;);
        !method_get_parameter_types) {
        LOGE(&#34;Failed to find getParameterTypes method&#34;);
        return false;
    }
    if (method_get_return_type =
            JNI_GetMethodID(env, JNI_FindClass(env, &#34;java/lang/reflect/Method&#34;), &#34;getReturnType&#34;,
                            &#34;()Ljava/lang/Class;&#34;);
        !method_get_return_type) {
        LOGE(&#34;Failed to find getReturnType method&#34;);
        return false;
    }
    auto clazz = JNI_FindClass(env, &#34;java/lang/Class&#34;);
    if (!clazz) {
        LOGE(&#34;Failed to find Class&#34;);
        return false;
    }

    if (class_get_class_loader =
            JNI_GetMethodID(env, clazz, &#34;getClassLoader&#34;, &#34;()Ljava/lang/ClassLoader;&#34;);
        !class_get_class_loader) {
        LOGE(&#34;Failed to find getClassLoader&#34;);
        return false;
    }

    if (class_get_declared_constructors = JNI_GetMethodID(env, clazz, &#34;getDeclaredConstructors&#34;,
                                                          &#34;()[Ljava/lang/reflect/Constructor;&#34;);
        !class_get_declared_constructors) {
        LOGE(&#34;Failed to find getDeclaredConstructors&#34;);
        return false;
    }

    if (class_get_name = JNI_GetMethodID(env, clazz, &#34;getName&#34;, &#34;()Ljava/lang/String;&#34;);
        !class_get_name) {
        LOGE(&#34;Failed to find getName&#34;);
        return false;
    }

    if (class_access_flags = JNI_GetFieldID(env, clazz, &#34;accessFlags&#34;, &#34;I&#34;); !class_access_flags) {
        LOGE(&#34;Failed to find Class.accessFlags&#34;);
        return false;
    }
    auto path_class_loader = JNI_FindClass(env, &#34;dalvik/system/PathClassLoader&#34;);
    if (!path_class_loader) {
        LOGE(&#34;Failed to find PathClassLoader&#34;);
        return false;
    }
    if (path_class_loader_init = JNI_GetMethodID(env, path_class_loader, &#34;&lt;init&gt;&#34;,
                                                 &#34;(Ljava/lang/String;Ljava/lang/ClassLoader;)V&#34;);
        !path_class_loader_init) {
        LOGE(&#34;Failed to find PathClassLoader.&lt;init&gt;&#34;);
        return false;
    }
    auto dex_file_class = JNI_FindClass(env, &#34;dalvik/system/DexFile&#34;);
    if (!dex_file_class) {
        LOGE(&#34;Failed to find DexFile&#34;);
        return false;
    }
    if (sdk_int &gt;= __ANDROID_API_Q__) {
        dex_file_init_with_cl = JNI_GetMethodID(
            env, dex_file_class, &#34;&lt;init&gt;&#34;,
            &#34;([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;[Ldalvik/system/DexPathList$Element;)V&#34;);
    } else if (sdk_int &gt;= __ANDROID_API_O__) {
        dex_file_init = JNI_GetMethodID(env, dex_file_class, &#34;&lt;init&gt;&#34;, &#34;(Ljava/nio/ByteBuffer;)V&#34;);
    }
    if (sdk_int &gt;= __ANDROID_API_O__ &amp;&amp; !dex_file_init_with_cl &amp;&amp; !dex_file_init) {
        LOGE(&#34;Failed to find DexFile.&lt;init&gt;&#34;);
        return false;
    }
    if (load_class =
            JNI_GetMethodID(env, dex_file_class, &#34;loadClass&#34;,
                            &#34;(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/Class;&#34;);
        !load_class) {
        LOGE(&#34;Failed to find a suitable way to load class&#34;);
        return false;
    }
    auto accessible_object = JNI_FindClass(env, &#34;java/lang/reflect/AccessibleObject&#34;);
    if (!accessible_object) {
        LOGE(&#34;Failed to find AccessibleObject&#34;);
        return false;
    }
    if (set_accessible = JNI_GetMethodID(env, accessible_object, &#34;setAccessible&#34;, &#34;(Z)V&#34;);
        !set_accessible) {
        LOGE(&#34;Failed to find AccessibleObject.setAccessible&#34;);
        return false;
    }
    return true;
}
```
InitJNI的部分没什么可说的，入参是JNIEnv，根据不同版本获取JNI方法并设置成全局变量
#### 1.3 InitNative
```c&#43;&#43;
bool InitNative(JNIEnv *env, const HookHandler &amp;handler) {
    if (!handler.inline_hooker || !handler.inline_unhooker || !handler.art_symbol_resolver) {
        return false;
    }
    if (!ArtMethod::Init(env, handler)) {
        LOGE(&#34;Failed to init art method&#34;);
        return false;
    }
    UpdateTrampoline(ArtMethod::GetEntryPointOffset());
    if (!Thread::Init(handler)) {
        LOGE(&#34;Failed to init thread&#34;);
        return false;
    }
    if (!ClassLinker::Init(handler)) {
        LOGE(&#34;Failed to init class linker&#34;);
        return false;
    }
    ......
    // This should always be the last one
    if (IsJavaDebuggable(env)) {
        // Make the runtime non-debuggable as a workaround
        // when ShouldUseInterpreterEntrypoint inlined
        Runtime::Current()-&gt;SetJavaDebuggable(Runtime::RuntimeDebugState::kNonJavaDebuggable);
    }
    return true;
}
```
InitNative主要是对libart.so当中的方法做了hook，先看看ArtMethod::Init, 函数里面关于版本适配的代码很多，我们就以Android11以上的视角来看
```c&#43;&#43;
static bool Init(JNIEnv *env, const HookHandler handler) {
        // 根据不同版本获取Executable
        executable = JNI_FindClass(env, &#34;java/lang/reflect/Executable&#34;);
        if (!executable) {
            LOGE(&#34;Failed to found Executable/AbstractMethod/ArtMethod&#34;);
            return false;
        }

        // 获取artMethod的FieldID
        art_method_field = JNI_GetFieldID(env, executable, &#34;artMethod&#34;, &#34;J&#34;)

        // 获取art_method_size，采用的方法是通过两个相邻方法的指针地址相减
        auto throwable = JNI_FindClass(env, &#34;java/lang/Throwable&#34;);
        if (!throwable) {
            LOGE(&#34;Failed to found Executable&#34;);
            return false;
        }
        auto clazz = JNI_FindClass(env, &#34;java/lang/Class&#34;);
        static_assert(std::is_same_v&lt;decltype(clazz)::BaseType, jclass&gt;);
        jmethodID get_declared_constructors = JNI_GetMethodID(env, clazz, &#34;getDeclaredConstructors&#34;,
                                                              &#34;()[Ljava/lang/reflect/Constructor;&#34;);
        const auto constructors =
            JNI_Cast&lt;jobjectArray&gt;(JNI_CallObjectMethod(env, throwable, get_declared_constructors));
        if (constructors.size() &lt; 2) {
            LOGE(&#34;Throwable has less than 2 constructors&#34;);
            return false;
        }
        auto first_ctor = constructors[0];
        auto second_ctor = constructors[1];
        auto *first = FromReflectedMethod(env, first_ctor.get());
        auto *second = FromReflectedMethod(env, second_ctor.get());
        art_method_size = reinterpret_cast&lt;uintptr_t&gt;(second) - reinterpret_cast&lt;uintptr_t&gt;(first);
        LOGD(&#34;ArtMethod size: %zu&#34;, art_method_size);


        // kPointerSize对应一个void *指针的大小 sizeof(void *)
        entry_point_offset = art_method_size - kPointerSize;
        data_offset = entry_point_offset - kPointerSize;

        LOGD(&#34;ArtMethod::declaring_class offset: %zu&#34;, declaring_class_offset);
        LOGD(&#34;ArtMethod::entrypoint offset: %zu&#34;, entry_point_offset);
        LOGD(&#34;ArtMethod::data offset: %zu&#34;, data_offset);
        LOGD(&#34;ArtMethod::access_flags offset: %zu&#34;, access_flags_offset);

        ......
        return true;
    }
```
这里关键在于获取art_method_field、entry_point_offset、data_offset

entry_point_offset怎么理解呢？从art_method.h的ArtMethod类中看
```c&#43;&#43;
protected:
  // Field order required by test &#34;ValidateFieldOrderOfJavaCppUnionClasses&#34;.
  // The class we are a part of.
  GcRoot&lt;mirror::Class&gt; declaring_class_;
  // Access flags; low 16 bits are defined by spec.
  // Getting and setting this flag needs to be atomic when concurrency is
  // possible, e.g. after this method&#39;s class is linked. Such as when setting
  // verifier flags and single-implementation flag.
  std::atomic&lt;std::uint32_t&gt; access_flags_;
  /* Dex file fields. The defining dex file is available via declaring_class_-&gt;dex_cache_ */
  // Offset to the CodeItem.
  uint32_t dex_code_item_offset_;
  // Index into method_ids of the dex file associated with this method.
  uint32_t dex_method_index_;
  /* End of dex file fields. */
  // Entry within a dispatch table for this method. For static/direct methods the index is into
  // the declaringClass.directMethods, for virtual methods the vtable and for interface methods the
  // ifTable.
  uint16_t method_index_;
  union {
    // Non-abstract methods: The hotness we measure for this method. Not atomic,
    // as we allow missing increments: if the method is hot, we will see it eventually.
    uint16_t hotness_count_;
    // Abstract methods: IMT index (bitwise negated) or zero if it was not cached.
    // The negation is needed to distinguish zero index and missing cached entry.
    uint16_t imt_index_;
  };
  // Fake padding field gets inserted here.
  // Must be the last fields in the method.
  struct PtrSizedFields {
    // Depending on the method type, the data is
    //   - native method: pointer to the JNI function registered to this method
    //                    or a function to resolve the JNI function,
    //   - conflict method: ImtConflictTable,
    //   - abstract/interface method: the single-implementation if any,
    //   - proxy method: the original interface method or constructor,
    //   - other methods: the profiling data.
    void* data_;
    // Method dispatch from quick compiled code invokes this pointer which may cause bridging into
    // the interpreter.
    void* entry_point_from_quick_compiled_code_;
  } ptr_sized_fields_;
```
art_method_size对应的是ArtMethod类实例的大小，也等于所有protected字段的大小总和
1. entry_point_offset = art_method_size - kPointerSize;
    对应的是使用总和-void*，从类中来看，减去的部分是entry_point_from_quick_compiled_code_所对应的指针大小，那么也就得到了entry_point_from_quick_compiled_code_指针的偏移量
2. data_offset = entry_point_offset - kPointerSize;
    同理，data_也对应了void*，也就相当于得到了data_指针的偏移量

接着是UpdateTrampoline
```c&#43;&#43;
// offset来自之前获取的entry_point_offset
inline void UpdateTrampoline(uint8_t offset) {
    trampoline[entry_point_offset / CHAR_BIT] |= offset &lt;&lt; (entry_point_offset % CHAR_BIT);
    trampoline[entry_point_offset / CHAR_BIT &#43; 1] |=
        offset &gt;&gt; (CHAR_BIT - entry_point_offset % CHAR_BIT);
}
```
trampoline的由来
```c&#43;&#43;
auto [trampoline, entry_point_offset, art_method_offset] = GetTrampoline();

consteval inline auto GetTrampoline() {
    if constexpr (kArch == Arch::kArm) {
        return std::make_tuple(&#34;\x00\x00\x9f\xe5\x00\xf0\x90\xe5\x78\x56\x34\x12&#34;_uarr,
                               // NOLINTNEXTLINE
                               uint8_t{32u}, uintptr_t{8u});
    }
    if constexpr (kArch == Arch::kArm64) {
        return std::make_tuple(
            &#34;\x60\x00\x00\x58\x10\x00\x40\xf8\x00\x02\x1f\xd6\x78\x56\x34\x12\x78\x56\x34\x12&#34;_uarr,
            // NOLINTNEXTLINE
            uint8_t{44u}, uintptr_t{12u});
    }
    if constexpr (kArch == Arch::kX86) {
        return std::make_tuple(&#34;\xb8\x78\x56\x34\x12\xff\x70\x00\xc3&#34;_uarr,
                               // NOLINTNEXTLINE
                               uint8_t{56u}, uintptr_t{1u});
    }
    if constexpr (kArch == Arch::kX86_64) {
        return std::make_tuple(&#34;\x48\xbf\x78\x56\x34\x12\x78\x56\x34\x12\xff\x77\x00\xc3&#34;_uarr,
                               // NOLINTNEXTLINE
                               uint8_t{96u}, uintptr_t{2u});
    }
    if constexpr (kArch == Arch::kRiscv64) {
        return std::make_tuple(
            &#34;\x17\x05\x00\x00\x03\x35\xc5\x00\x67\x00\x05\x00\x78\x56\x34\x12\x78\x56\x34\x12&#34;_uarr,
            // NOLINTNEXTLINE
            uint8_t{84u}, uintptr_t{12u});
    }
}
```
entry_point_offset表示ArtMethod的entry_point_from_quick_compiled_code_偏移在指令中的位置（按位）
- x86-64
    ```c&#43;&#43;
    0x0000000000000000:  48 BF 78 56 34 12 78 56 34 12    movabs rdi, 0x1234567812345678 # ArtMethod 地址置于 rdi 中
    0x000000000000000a:  FF 77 xx                         push   qword ptr [rdi &#43; xx] # 取 hook ArtMethod 的 entry_point_from_quick_compiled_code_ 放到栈上
    0x000000000000000d:  C3                               ret    # 跳转到 hook 的 entry_point_from_quick_compiled_code_
    ```
- arm64
    ```c&#43;&#43;
    0x0000000000000000:  60 00 00 58    ldr  x0, #0xc # 读相对第一条指令 0xc 偏移的位置的内存，即 hook 的 ArtMethod 地址到第一个参数 (x0)
    0x0000000000000004:  10 00 40 F8    ldur x16, [x0] # 取 entry_point_from_quick_compiled_code_
    0x0000000000000008:  00 02 1F D6    br   x16 # 跳转到 hook
    0x000000000000000c:  78 56 34 12    and  w24, w19, #0xfffff003 # ArtMethod 地址
    0x0000000000000010:  78 56 34 12    and  w24, w19, #0xfffff003
    ```
- arm
    ```c&#43;&#43;
    0: e59f0000      ldr     r0, [pc] # 加载 pc&#43;8 到第一个参数，即 hook ArtMethod 地址
    4: e590f0xx      ldr     pc, [r0, #xx] # hook entry_point_from_quick_compiled_code_ 送 pc 直接跳转
    8: 12345678      # hook ArtMethod 地址
    ```
- x86
    ```c&#43;&#43;
    0: b8 78 56 34 12                movl    $0x12345678, %eax       # imm = 0x12345678
    5: ff 70 xx                      pushl   (%eax &#43; xx)
    8: c3 
    ```
这里以arm64来看下UpdateTrampoline的作用是什么
```
0x0000000000000000:  60 00 00 58 ldr  x0, #0xc
0x0000000000000004:  10 00 40 F8 ldur x16, [x0]
0x0000000000000008:  00 02 1F D6 br x16
0x000000000000000c:  78 56 34 12
0x000000000000000c:  78 56 34 12
```
前三行可以看出是跳转使用的，后两行应该会站位使用，编译测试可以得到
- art_method_size 40
- entry_point_offset 44
- offset 32
- CHAR_BIT 8
- kPointerSize 8
代入UpdateTrampoline，也就得到
```c&#43;&#43;
trampoline[5] |= offset &lt;&lt; 4;
trampoline[6] |= offset &gt;&gt; 4;
```
替换掉x0 4x变成00 42， arm64指令为ldur x16, [x0, #0x20]，目前x是未知的，从指令上看是获取x0&#43;12位置的地址，也就是第四行的地址，继续往下看第四行什么时候被赋值的


### 二、LSPlant ART hook原理
```c&#43;&#43;
[[maybe_unused]] jobject Hook(JNIEnv *env, jobject target_method, jobject hooker_object,
                              jobject callback_method) {
    ......

    jmethodID hook_method = nullptr;
    jmethodID backup_method = nullptr;
    jfieldID hooker_field = nullptr;

    auto target_class =
        JNI_Cast&lt;jclass&gt;(JNI_CallObjectMethod(env, target_method, method_get_declaring_class));
    constexpr static uint32_t kAccClassIsProxy = 0x00040000;
    bool is_proxy = JNI_GetIntField(env, target_class, class_access_flags) &amp; kAccClassIsProxy;
    auto *target = ArtMethod::FromReflectedMethod(env, target_method);
    bool is_static = target-&gt;IsStatic();

    // 避免重复hook
    if (IsHooked(target, true)) {
        LOGW(&#34;Skip duplicate hook&#34;);
        return nullptr;
    }

    ScopedLocalRef&lt;jclass&gt; built_class{env};
    {
        auto callback_name =
            JNI_Cast&lt;jstring&gt;(JNI_CallObjectMethod(env, callback_method, method_get_name));
        JUTFString callback_method_name(callback_name);
        auto target_name =
            JNI_Cast&lt;jstring&gt;(JNI_CallObjectMethod(env, target_method, method_get_name));
        JUTFString target_method_name(target_name);
        auto callback_class = JNI_Cast&lt;jclass&gt;(
            JNI_CallObjectMethod(env, callback_method, method_get_declaring_class));
        auto callback_class_loader =
            JNI_CallObjectMethod(env, callback_class, class_get_class_loader);
        auto callback_class_name =
            JNI_Cast&lt;jstring&gt;(JNI_CallObjectMethod(env, callback_class, class_get_name));
        JUTFString class_name(callback_class_name);
        if (!JNI_IsInstanceOf(env, hooker_object, callback_class)) {
            LOGE(&#34;callback_method is not a method of hooker_object&#34;);
            return nullptr;
        }
        std::tie(built_class, hooker_field, hook_method, backup_method) = WrapScope(
            env,
            BuildDex(env, callback_class_loader,
                     __builtin_expect(is_proxy, 0) ? GetProxyMethodShorty(env, target_method)
                                                   : ArtMethod::GetMethodShorty(env, target_method),
                     is_static, target-&gt;IsConstructor() ? &#34;constructor&#34; : target_method_name.get(),
                     class_name.get(), callback_method_name.get()));
        if (!built_class || !hooker_field || !hook_method || !backup_method) {
            LOGE(&#34;Failed to generate hooker&#34;);
            return nullptr;
        }
    }

    auto reflected_hook = JNI_ToReflectedMethod(env, built_class, hook_method, is_static);
    auto reflected_backup = JNI_ToReflectedMethod(env, built_class, backup_method, is_static);

    JNI_CallVoidMethod(env, reflected_backup, set_accessible, JNI_TRUE);

    auto *hook = ArtMethod::FromReflectedMethod(env, reflected_hook);
    auto *backup = ArtMethod::FromReflectedMethod(env, reflected_backup);

    JNI_SetStaticObjectField(env, built_class, hooker_field, hooker_object);

    if (DoHook(target, hook, backup)) {
        std::apply(
            [backup_method, target_method_id = env-&gt;FromReflectedMethod(target_method)](auto... v) {
                ((*v == target_method_id &amp;&amp;
                  (LOGD(&#34;Propagate internal used method because of hook&#34;), *v = backup_method)) ||
                 ...);
            },
            kInternalMethods);
        jobject global_backup = JNI_NewGlobalRef(env, reflected_backup);
        RecordHooked(target, target-&gt;GetDeclaringClass()-&gt;GetClassDef(), global_backup, backup);
        if (!is_proxy) [[likely]] {
            RecordJitMovement(target, backup);
        }
        // Always record backup as deoptimized since we dont want its entrypoint to be updated
        // by FixupStaticTrampolines on hooker class
        // Used hook&#39;s declaring class here since backup&#39;s is no longer the same with hook&#39;s
        RecordDeoptimized(hook-&gt;GetDeclaringClass()-&gt;GetClassDef(), backup);
        return global_backup;
    }

    return nullptr;
}
```
核心函数DoHook
```c&#43;&#43;
bool DoHook(ArtMethod *target, ArtMethod *hook, ArtMethod *backup) {
    ScopedGCCriticalSection section(art::Thread::Current(), art::gc::kGcCauseDebugger,
                                    art::gc::kCollectorTypeDebugger);
    ScopedSuspendAll suspend(&#34;LSPlant Hook&#34;, false);
    LOGV(&#34;Hooking: target = %s(%p), hook = %s(%p), backup = %s(%p)&#34;, target-&gt;PrettyMethod().c_str(),
         target, hook-&gt;PrettyMethod().c_str(), hook, backup-&gt;PrettyMethod().c_str(), backup);

    // 为hook函数生成trampoline
    if (auto *entrypoint = GenerateTrampolineFor(hook); !entrypoint) {
        LOGE(&#34;Failed to generate trampoline&#34;);
        return false;
        // NOLINTNEXTLINE
    } else {
        LOGV(&#34;Generated trampoline %p&#34;, entrypoint);

        target-&gt;SetNonCompilable();
        hook-&gt;SetNonCompilable();

        // copy after setNonCompilable
        backup-&gt;CopyFrom(target);

        target-&gt;ClearFastInterpretFlag();

        target-&gt;SetEntryPoint(entrypoint);

        if (!backup-&gt;IsStatic()) backup-&gt;SetPrivate();

        LOGV(&#34;Done hook: target(%p:0x%x) -&gt; %p; backup(%p:0x%x) -&gt; %p; hook(%p:0x%x) -&gt; %p&#34;, target,
             target-&gt;GetAccessFlags(), target-&gt;GetEntryPoint(), backup, backup-&gt;GetAccessFlags(),
             backup-&gt;GetEntryPoint(), hook, hook-&gt;GetAccessFlags(), hook-&gt;GetEntryPoint());

        return true;
    }
}
```
#### 2.1 GenerateTrampolineFor
```c&#43;&#43;
void *GenerateTrampolineFor(art::ArtMethod *hook) {
    unsigned count;
    uintptr_t address;
    while (true) {
        auto tl = Trampoline{.address = trampoline_pool.fetch_add(1, std::memory_order_release)};
        count = tl.count;
        address = tl.address &amp; ~kAddressMask;
        if (address == 0 || count &gt;= kTrampolineNumPerPage) {
            if (trampoline_lock.test_and_set(std::memory_order_acq_rel)) {
                trampoline_lock.wait(true, std::memory_order_acquire);
                continue;
            }
            address = reinterpret_cast&lt;uintptr_t&gt;(mmap(nullptr, kPageSize,
                                                       PROT_READ | PROT_WRITE | PROT_EXEC,
                                                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
            if (address == reinterpret_cast&lt;uintptr_t&gt;(MAP_FAILED)) {
                PLOGE(&#34;mmap trampoline&#34;);
                trampoline_lock.clear(std::memory_order_release);
                trampoline_lock.notify_all();
                return nullptr;
            }
            count = 0;
            tl.address = address;
            tl.count = count &#43; 1;
            trampoline_pool.store(tl.address, std::memory_order_release);
            trampoline_lock.clear(std::memory_order_release);
            trampoline_lock.notify_all();
        }
        LOGV(&#34;trampoline: count = %u, address = %zx, target = %zx&#34;, count, address,
             address &#43; count * kTrampolineSize);
        address = address &#43; count * kTrampolineSize;
        break;
    }
    auto *address_ptr = reinterpret_cast&lt;char *&gt;(address);
    std::memcpy(address_ptr, trampoline.data(), trampoline.size());

    *reinterpret_cast&lt;art::ArtMethod **&gt;(address_ptr &#43; art_method_offset) = hook;

    __builtin___clear_cache(address_ptr, reinterpret_cast&lt;char *&gt;(address &#43; trampoline.size()));

    return address_ptr;
}
```
DoHook首先会当前hook函数生成trampoine，通过调用GenerateTrampolineFor函数，它的流程是
1. 首先通过mmap创建rwx内存来保存trampoline，这里出现了trampoline_pool的概念，先忽略
2. address转化成指针address_ptr
3. 把之前调整好的trampoline对应的值memcpy到address_ptr指针指向地址
4. address_ptr指针&#43;art_method_offset地址写入hook指针地址，在arm64中art_method_offset对应12，那么回顾之前那5行trampoline模版代码，也就是把第四、五行替换成了hook的指针地址
5. 返回address_ptr指针

实际上GenerateTrampolineFor的作用就是在trampoline中补充好hook函数地址

#### 2.2 SetNonCompilable
```c&#43;&#43;
void SetNonCompilable() {
    auto access_flags = GetAccessFlags();
    access_flags |= kAccCompileDontBother;
    access_flags &amp;= ~kAccPreCompiled;
    SetAccessFlags(access_flags);
}
```
为函数加上kAccCompileDontBother标志位，防止ART对函数进行JIT编译替换函数

#### 2.3 SetEntryPoint
```c&#43;&#43;
backup-&gt;CopyFrom(target);
void CopyFrom(const ArtMethod *other) { memcpy(this, other, art_method_size); }

target-&gt;SetEntryPoint(entrypoint);
void SetEntryPoint(void *entry_point) {
    *reinterpret_cast&lt;void **&gt;(reinterpret_cast&lt;uintptr_t&gt;(this) &#43; entry_point_offset) = entry_point;
}
```
接下来的过程就是把target保存在backup指针里面做备份，设置target的entry_point_offset偏移，对应的就是entry_point_from_quick_compiled_code_指针被替换成trampoline

关于回调原方法的问题可以看到target的art_method完整的复制给了backup，也就是直接调用backup就相当于调用target了

### 参考
1. [ART hook 框架 - YAHFA 源码分析](https://www.jianshu.com/p/994db0f1c8c9)
2. [ART上的动态Java方法hook框架](https://blog.canyie.top/2020/04/27/dynamic-hooking-framework-on-art/)

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/lsplant%E6%BA%90%E7%A0%81%E5%AD%A6%E4%B9%A0/  

