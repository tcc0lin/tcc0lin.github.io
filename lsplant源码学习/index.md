# LSPlant源码学习


LSPlant是LSPosed官方推出的新的ART hook框架，用来替代LSPosed之前使用的YAHFA框架

从官方README上看，对于LSPlant的使用分为几种

1. Init LSPlant within JNI_OnLoad（在JNI_OnLoad时初始化LSPlant）
   ```c++
   bool Init(JNIEnv *env,
          const InitInfo &info);
   ```
2. Hook
   ```c++
   jobject Hook(JNIEnv *env,
             jobject target_method,
             jobject hooker_object,
             jobject callback_method);
   ```
   这里存在三个入参，分别是目标方法、上下文、回调方法

3. Check
   ```c++
   bool IsHooked(JNIEnv *env,
              jobject method);
   ```

4. Unhook
   ```c++
   bool UnHook(JNIEnv *env,
            jobject target_method);
   ```

5. Deoptimize
   ```c++
   bool Deoptimize(JNIEnv *env,
                jobject method);
   ```
   防止某些短函数被内联导致hook失效

### 一、LSPlant框架初始化
lsplant的函数都实现在lsplant.cc中，看下init函数
```c++
// lsplant\src\main\jni\lsplant.cc

[[maybe_unused]] bool Init(JNIEnv *env, const InitInfo &info) {
    bool static kInit = InitConfig(info) && InitJNI(env) && InitNative(env, info);
    return kInit;
}
```
以三个子流程的初始化状态来判断框架的状态
#### 1.1 InitConfig
```c++
bool InitConfig(const InitInfo &info) {
    if (info.generated_class_name.empty()) {
        LOGE("generated class name cannot be empty");
        return false;
    }
    generated_class_name = info.generated_class_name;
    if (info.generated_field_name.empty()) {
        LOGE("generated field name cannot be empty");
        return false;
    }
    generated_field_name = info.generated_field_name;
    if (info.generated_method_name.empty()) {
        LOGE("generated method name cannot be empty");
        return false;
    }
    generated_method_name = info.generated_method_name;
    generated_source_name = info.generated_source_name;
    return true;
}
```
这里说明入参必须要参照结构体InitInfo，需要配置的generated_class_name、generated_field_name、generated_method_name等字段
```c++
struct InitInfo {
    /// \brief Type of inline hook function.
    /// In \ref std::function form so that user can use lambda expression with capture list.<br>
    /// \p target is the target function to be hooked.<br>
    /// \p hooker is the hooker function to replace the \p target function.<br>
    /// \p return is the backup function that points to the previous target function.
    /// it should return null if hook fails and nonnull if successes.
    using InlineHookFunType = std::function<void *(void *target, void *hooker)>;
    /// \brief Type of inline unhook function.
    /// In \ref std::function form so that user can use lambda expression with capture list.<br>
    /// \p func is the target function that is previously hooked.<br>
    /// \p return should indicate the status of unhooking.<br>
    using InlineUnhookFunType = std::function<bool(void *func)>;
    /// \brief Type of symbol resolver to \p libart.so.
    /// In \ref std::function form so that user can use lambda expression with capture list.<br>
    /// \p symbol_name is the symbol name that needs to retrieve.<br>
    /// \p return is the absolute address in the memory that points to the target symbol. It should
    /// be null if the symbol cannot be found. <br>
    /// \note It should be able to resolve symbols from both .dynsym and .symtab.
    using ArtSymbolResolver = std::function<void *(std::string_view symbol_name)>;

    using ArtSymbolPrefixResolver = std::function<void *(std::string_view symbol_prefix)>;

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
    std::string_view generated_class_name = "LSPHooker_";
    /// \brief The generated source name. Could be empty.
    std::string_view generated_source_name = "LSP";
    /// \brief The generated field name. Must not be empty.
    std::string_view generated_field_name = "hooker";
    /// \brief The generated class name. Must not be emtpy. If {target} is set,
    /// it will follows the name of the target.
    std::string_view generated_method_name = "{target}";
};
```
可以看到name相关的字段都是默认的，因此可以不关注，最主要需要配置的是art_symbol_resolver、art_symbol_prefix_resolver这两个对于libart.so的hook，参考LSPosed的使用
```c++
void
    MagiskLoader::OnNativeForkAndSpecializePost(JNIEnv *env, jstring nice_name, jstring app_dir) {
        const JUTFString process_name(env, nice_name);
        auto *instance = Service::instance();
        auto binder = skip_ ? ScopedLocalRef<jobject>{env, nullptr}
                            : instance->RequestBinder(env, nice_name);
        if (binder) {
            lsplant::InitInfo initInfo{
                    .inline_hooker = [](auto t, auto r) {
                        void* bk = nullptr;
                        return HookFunction(t, r, &bk) == RS_SUCCESS ? bk : nullptr;
                    },
                    .inline_unhooker = [](auto t) {
                        return UnhookFunction(t) == RT_SUCCESS;
                    },
                    .art_symbol_resolver = [](auto symbol){
                        return GetArt()->getSymbAddress(symbol);
                    },
                    .art_symbol_prefix_resolver = [](auto symbol) {
                        return GetArt()->getSymbPrefixFirstAddress(symbol);
                    },
            };
            ......
        } else {
            auto context = Context::ReleaseInstance();
            auto service = Service::ReleaseInstance();
            GetArt(true);
            LOGD("skipped {}", process_name.get());
            setAllowUnload(true);
        }
    }
```
#### 1.2 InitJNI
```c++
bool InitJNI(JNIEnv *env) {
    int sdk_int = GetAndroidApiLevel();
    if (sdk_int >= __ANDROID_API_O__) {
        executable = JNI_NewGlobalRef(env, JNI_FindClass(env, "java/lang/reflect/Executable"));
    } else {
        executable = JNI_NewGlobalRef(env, JNI_FindClass(env, "java/lang/reflect/AbstractMethod"));
    }
    if (!executable) {
        LOGE("Failed to found Executable/AbstractMethod");
        return false;
    }

    if (method_get_name = JNI_GetMethodID(env, executable, "getName", "()Ljava/lang/String;");
        !method_get_name) {
        LOGE("Failed to find getName method");
        return false;
    }
    if (method_get_declaring_class =
            JNI_GetMethodID(env, executable, "getDeclaringClass", "()Ljava/lang/Class;");
        !method_get_declaring_class) {
        LOGE("Failed to find getDeclaringClass method");
        return false;
    }
    if (method_get_parameter_types =
            JNI_GetMethodID(env, executable, "getParameterTypes", "()[Ljava/lang/Class;");
        !method_get_parameter_types) {
        LOGE("Failed to find getParameterTypes method");
        return false;
    }
    if (method_get_return_type =
            JNI_GetMethodID(env, JNI_FindClass(env, "java/lang/reflect/Method"), "getReturnType",
                            "()Ljava/lang/Class;");
        !method_get_return_type) {
        LOGE("Failed to find getReturnType method");
        return false;
    }
    auto clazz = JNI_FindClass(env, "java/lang/Class");
    if (!clazz) {
        LOGE("Failed to find Class");
        return false;
    }

    if (class_get_class_loader =
            JNI_GetMethodID(env, clazz, "getClassLoader", "()Ljava/lang/ClassLoader;");
        !class_get_class_loader) {
        LOGE("Failed to find getClassLoader");
        return false;
    }

    if (class_get_declared_constructors = JNI_GetMethodID(env, clazz, "getDeclaredConstructors",
                                                          "()[Ljava/lang/reflect/Constructor;");
        !class_get_declared_constructors) {
        LOGE("Failed to find getDeclaredConstructors");
        return false;
    }

    if (class_get_name = JNI_GetMethodID(env, clazz, "getName", "()Ljava/lang/String;");
        !class_get_name) {
        LOGE("Failed to find getName");
        return false;
    }

    if (class_access_flags = JNI_GetFieldID(env, clazz, "accessFlags", "I"); !class_access_flags) {
        LOGE("Failed to find Class.accessFlags");
        return false;
    }
    auto path_class_loader = JNI_FindClass(env, "dalvik/system/PathClassLoader");
    if (!path_class_loader) {
        LOGE("Failed to find PathClassLoader");
        return false;
    }
    if (path_class_loader_init = JNI_GetMethodID(env, path_class_loader, "<init>",
                                                 "(Ljava/lang/String;Ljava/lang/ClassLoader;)V");
        !path_class_loader_init) {
        LOGE("Failed to find PathClassLoader.<init>");
        return false;
    }
    auto dex_file_class = JNI_FindClass(env, "dalvik/system/DexFile");
    if (!dex_file_class) {
        LOGE("Failed to find DexFile");
        return false;
    }
    if (sdk_int >= __ANDROID_API_Q__) {
        dex_file_init_with_cl = JNI_GetMethodID(
            env, dex_file_class, "<init>",
            "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;[Ldalvik/system/DexPathList$Element;)V");
    } else if (sdk_int >= __ANDROID_API_O__) {
        dex_file_init = JNI_GetMethodID(env, dex_file_class, "<init>", "(Ljava/nio/ByteBuffer;)V");
    }
    if (sdk_int >= __ANDROID_API_O__ && !dex_file_init_with_cl && !dex_file_init) {
        LOGE("Failed to find DexFile.<init>");
        return false;
    }
    if (load_class =
            JNI_GetMethodID(env, dex_file_class, "loadClass",
                            "(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/Class;");
        !load_class) {
        LOGE("Failed to find a suitable way to load class");
        return false;
    }
    auto accessible_object = JNI_FindClass(env, "java/lang/reflect/AccessibleObject");
    if (!accessible_object) {
        LOGE("Failed to find AccessibleObject");
        return false;
    }
    if (set_accessible = JNI_GetMethodID(env, accessible_object, "setAccessible", "(Z)V");
        !set_accessible) {
        LOGE("Failed to find AccessibleObject.setAccessible");
        return false;
    }
    return true;
}
```
InitJNI的部分没什么可说的，入参是JNIEnv，根据不同版本获取JNI方法并设置成全局变量
#### 1.3 InitNative
```c++
bool InitNative(JNIEnv *env, const HookHandler &handler) {
    if (!handler.inline_hooker || !handler.inline_unhooker || !handler.art_symbol_resolver) {
        return false;
    }
    if (!ArtMethod::Init(env, handler)) {
        LOGE("Failed to init art method");
        return false;
    }
    UpdateTrampoline(ArtMethod::GetEntryPointOffset());
    if (!Thread::Init(handler)) {
        LOGE("Failed to init thread");
        return false;
    }
    if (!ClassLinker::Init(handler)) {
        LOGE("Failed to init class linker");
        return false;
    }
    ......
    // This should always be the last one
    if (IsJavaDebuggable(env)) {
        // Make the runtime non-debuggable as a workaround
        // when ShouldUseInterpreterEntrypoint inlined
        Runtime::Current()->SetJavaDebuggable(Runtime::RuntimeDebugState::kNonJavaDebuggable);
    }
    return true;
}
```
InitNative主要是对libart.so当中的方法做了hook，先看看ArtMethod::Init
```c++
static bool Init(JNIEnv *env, const HookHandler handler) {
        // 根据不同版本获取Executable
        executable = JNI_FindClass(env, "java/lang/reflect/Executable");
        if (!executable) {
            LOGE("Failed to found Executable/AbstractMethod/ArtMethod");
            return false;
        }

        // 获取artMethod的FieldID
        art_method_field = JNI_GetFieldID(env, executable, "artMethod", "J")

        // 获取art_method_size，采用的方法是通过两个相邻方法的指针地址相减
        auto throwable = JNI_FindClass(env, "java/lang/Throwable");
        if (!throwable) {
            LOGE("Failed to found Executable");
            return false;
        }
        auto clazz = JNI_FindClass(env, "java/lang/Class");
        static_assert(std::is_same_v<decltype(clazz)::BaseType, jclass>);
        jmethodID get_declared_constructors = JNI_GetMethodID(env, clazz, "getDeclaredConstructors",
                                                              "()[Ljava/lang/reflect/Constructor;");
        const auto constructors =
            JNI_Cast<jobjectArray>(JNI_CallObjectMethod(env, throwable, get_declared_constructors));
        if (constructors.size() < 2) {
            LOGE("Throwable has less than 2 constructors");
            return false;
        }
        auto first_ctor = constructors[0];
        auto second_ctor = constructors[1];
        auto *first = FromReflectedMethod(env, first_ctor.get());
        auto *second = FromReflectedMethod(env, second_ctor.get());
        art_method_size = reinterpret_cast<uintptr_t>(second) - reinterpret_cast<uintptr_t>(first);
        LOGD("ArtMethod size: %zu", art_method_size);


        // kPointerSize对应一个指针的大小 sizeof(void *)
        entry_point_offset = art_method_size - kPointerSize;
        data_offset = entry_point_offset - kPointerSize;

        if (sdk_int >= __ANDROID_API_M__) [[likely]] {
            if (auto access_flags_field = JNI_GetFieldID(env, executable, "accessFlags", "I");
                access_flags_field) {
                uint32_t real_flags = JNI_GetIntField(env, first_ctor, access_flags_field);
                for (size_t i = 0; i < art_method_size; i += sizeof(uint32_t)) {
                    if (*reinterpret_cast<uint32_t *>(reinterpret_cast<uintptr_t>(first) + i) ==
                        real_flags) {
                        access_flags_offset = i;
                        break;
                    }
                }
            }
            if (access_flags_offset == 0) {
                LOGW("Failed to find accessFlags field. Fallback to 4.");
                access_flags_offset = 4U;
            }
        } else {
            auto art_field = JNI_FindClass(env, "java/lang/reflect/ArtField");
            auto field = JNI_FindClass(env, "java/lang/reflect/Field");
            auto art_field_field =
                JNI_GetFieldID(env, field, "artField", "Ljava/lang/reflect/ArtField;");
            auto field_offset = JNI_GetFieldID(env, art_field, "offset", "I");
            auto get_offset_from_art_method = [&](const char *name, const char *sig) {
                return JNI_GetIntField(
                    env,
                    JNI_GetObjectField(
                        env,
                        env->ToReflectedField(executable,
                                              JNI_GetFieldID(env, executable, name, sig), false),
                        art_field_field),
                    field_offset);
            };
            access_flags_offset = get_offset_from_art_method("accessFlags", "I");
            declaring_class_offset =
                get_offset_from_art_method("declaringClass", "Ljava/lang/Class;");
            if (sdk_int == __ANDROID_API_L__) {
                entry_point_offset =
                    get_offset_from_art_method("entryPointFromQuickCompiledCode", "J");
                interpreter_entry_point_offset =
                    get_offset_from_art_method("entryPointFromInterpreter", "J");
                data_offset = get_offset_from_art_method("entryPointFromJni", "J");
            }
        }
        LOGD("ArtMethod::declaring_class offset: %zu", declaring_class_offset);
        LOGD("ArtMethod::entrypoint offset: %zu", entry_point_offset);
        LOGD("ArtMethod::data offset: %zu", data_offset);
        LOGD("ArtMethod::access_flags offset: %zu", access_flags_offset);

        ......
        return true;
    }
```
这里关键在于获取art_method_field、entry_point_offset、data_offset

接着是UpdateTrampoline
```c++
// offset来自之前获取的entry_point_offset
inline void UpdateTrampoline(uint8_t offset) {
    trampoline[entry_point_offset / CHAR_BIT] |= offset << (entry_point_offset % CHAR_BIT);
    trampoline[entry_point_offset / CHAR_BIT + 1] |=
        offset >> (CHAR_BIT - entry_point_offset % CHAR_BIT);
}
```

### 二、LSPlant ART hook原理
```c++
[[maybe_unused]] jobject Hook(JNIEnv *env, jobject target_method, jobject hooker_object,
                              jobject callback_method) {
    ......

    jmethodID hook_method = nullptr;
    jmethodID backup_method = nullptr;
    jfieldID hooker_field = nullptr;

    auto target_class =
        JNI_Cast<jclass>(JNI_CallObjectMethod(env, target_method, method_get_declaring_class));
    constexpr static uint32_t kAccClassIsProxy = 0x00040000;
    bool is_proxy = JNI_GetIntField(env, target_class, class_access_flags) & kAccClassIsProxy;
    auto *target = ArtMethod::FromReflectedMethod(env, target_method);
    bool is_static = target->IsStatic();

    // 避免重复hook
    if (IsHooked(target, true)) {
        LOGW("Skip duplicate hook");
        return nullptr;
    }

    ScopedLocalRef<jclass> built_class{env};
    {
        auto callback_name =
            JNI_Cast<jstring>(JNI_CallObjectMethod(env, callback_method, method_get_name));
        JUTFString callback_method_name(callback_name);
        auto target_name =
            JNI_Cast<jstring>(JNI_CallObjectMethod(env, target_method, method_get_name));
        JUTFString target_method_name(target_name);
        auto callback_class = JNI_Cast<jclass>(
            JNI_CallObjectMethod(env, callback_method, method_get_declaring_class));
        auto callback_class_loader =
            JNI_CallObjectMethod(env, callback_class, class_get_class_loader);
        auto callback_class_name =
            JNI_Cast<jstring>(JNI_CallObjectMethod(env, callback_class, class_get_name));
        JUTFString class_name(callback_class_name);
        if (!JNI_IsInstanceOf(env, hooker_object, callback_class)) {
            LOGE("callback_method is not a method of hooker_object");
            return nullptr;
        }
        std::tie(built_class, hooker_field, hook_method, backup_method) = WrapScope(
            env,
            BuildDex(env, callback_class_loader,
                     __builtin_expect(is_proxy, 0) ? GetProxyMethodShorty(env, target_method)
                                                   : ArtMethod::GetMethodShorty(env, target_method),
                     is_static, target->IsConstructor() ? "constructor" : target_method_name.get(),
                     class_name.get(), callback_method_name.get()));
        if (!built_class || !hooker_field || !hook_method || !backup_method) {
            LOGE("Failed to generate hooker");
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
            [backup_method, target_method_id = env->FromReflectedMethod(target_method)](auto... v) {
                ((*v == target_method_id &&
                  (LOGD("Propagate internal used method because of hook"), *v = backup_method)) ||
                 ...);
            },
            kInternalMethods);
        jobject global_backup = JNI_NewGlobalRef(env, reflected_backup);
        RecordHooked(target, target->GetDeclaringClass()->GetClassDef(), global_backup, backup);
        if (!is_proxy) [[likely]] {
            RecordJitMovement(target, backup);
        }
        // Always record backup as deoptimized since we dont want its entrypoint to be updated
        // by FixupStaticTrampolines on hooker class
        // Used hook's declaring class here since backup's is no longer the same with hook's
        RecordDeoptimized(hook->GetDeclaringClass()->GetClassDef(), backup);
        return global_backup;
    }

    return nullptr;
}
```
核心函数DoHook
```c++
bool DoHook(ArtMethod *target, ArtMethod *hook, ArtMethod *backup) {
    ScopedGCCriticalSection section(art::Thread::Current(), art::gc::kGcCauseDebugger,
                                    art::gc::kCollectorTypeDebugger);
    ScopedSuspendAll suspend("LSPlant Hook", false);
    LOGV("Hooking: target = %s(%p), hook = %s(%p), backup = %s(%p)", target->PrettyMethod().c_str(),
         target, hook->PrettyMethod().c_str(), hook, backup->PrettyMethod().c_str(), backup);

    // 生成trampoline
    if (auto *entrypoint = GenerateTrampolineFor(hook); !entrypoint) {
        LOGE("Failed to generate trampoline");
        return false;
        // NOLINTNEXTLINE
    } else {
        LOGV("Generated trampoline %p", entrypoint);

        target->SetNonCompilable();
        hook->SetNonCompilable();

        // copy after setNonCompilable
        backup->CopyFrom(target);

        target->ClearFastInterpretFlag();

        target->SetEntryPoint(entrypoint);

        if (!backup->IsStatic()) backup->SetPrivate();

        LOGV("Done hook: target(%p:0x%x) -> %p; backup(%p:0x%x) -> %p; hook(%p:0x%x) -> %p", target,
             target->GetAccessFlags(), target->GetEntryPoint(), backup, backup->GetAccessFlags(),
             backup->GetEntryPoint(), hook, hook->GetAccessFlags(), hook->GetEntryPoint());

        return true;
    }
}

void *GenerateTrampolineFor(art::ArtMethod *hook) {
    unsigned count;
    uintptr_t address;
    while (true) {
        auto tl = Trampoline{.address = trampoline_pool.fetch_add(1, std::memory_order_release)};
        count = tl.count;
        address = tl.address & ~kAddressMask;
        if (address == 0 || count >= kTrampolineNumPerPage) {
            if (trampoline_lock.test_and_set(std::memory_order_acq_rel)) {
                trampoline_lock.wait(true, std::memory_order_acquire);
                continue;
            }
            address = reinterpret_cast<uintptr_t>(mmap(nullptr, kPageSize,
                                                       PROT_READ | PROT_WRITE | PROT_EXEC,
                                                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
            if (address == reinterpret_cast<uintptr_t>(MAP_FAILED)) {
                PLOGE("mmap trampoline");
                trampoline_lock.clear(std::memory_order_release);
                trampoline_lock.notify_all();
                return nullptr;
            }
            count = 0;
            tl.address = address;
            tl.count = count + 1;
            trampoline_pool.store(tl.address, std::memory_order_release);
            trampoline_lock.clear(std::memory_order_release);
            trampoline_lock.notify_all();
        }
        LOGV("trampoline: count = %u, address = %zx, target = %zx", count, address,
             address + count * kTrampolineSize);
        address = address + count * kTrampolineSize;
        break;
    }
    auto *address_ptr = reinterpret_cast<char *>(address);
    std::memcpy(address_ptr, trampoline.data(), trampoline.size());

    *reinterpret_cast<art::ArtMethod **>(address_ptr + art_method_offset) = hook;

    __builtin___clear_cache(address_ptr, reinterpret_cast<char *>(address + trampoline.size()));

    return address_ptr;
}
```
