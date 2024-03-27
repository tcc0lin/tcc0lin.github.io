# Frida源码阅读


以14.2.18版本为例
### 一、frida-server做了什么
#### 1.1 进程注入
```js
// frida-core/src/linux/linux-host-session.vala

protected override async Future<IOStream> perform_attach_to (uint pid, Cancellable? cancellable, out Object? transport)
        throws Error, IOError {
    PipeTransport.set_temp_directory (tempdir.path);

    var t = new PipeTransport ();

    var stream_request = Pipe.open (t.local_address, cancellable);

    uint id;
    string entrypoint = "frida_agent_main";
    var linjector = injector as Linjector;
#if HAVE_EMBEDDED_ASSETS
    id = yield linjector.inject_library_resource (pid, agent, entrypoint, t.remote_address, cancellable);
#else
    id = yield linjector.inject_library_file (pid, Config.FRIDA_AGENT_PATH, entrypoint, t.remote_address, cancellable);
#endif
    injectee_by_pid[pid] = id;

    transport = t;

    return stream_request;
}
```
perform_attach_to这里引入linjector来处理注入，注意这里的entrypoint
```js
// frida-core/src/linux/linjector.vala

public async uint inject_library_resource (uint pid, AgentDescriptor agent, string entrypoint, string data,
        Cancellable? cancellable) throws Error, IOError {
    ensure_tempdir_prepared ();
    return yield inject_library_file_with_template (pid, agent.get_path_template (), entrypoint, data, cancellable);
}

public async uint inject_library_file (uint pid, string path, string entrypoint, string data, Cancellable? cancellable)
        throws Error, IOError {
    return yield inject_library_file_with_template (pid, PathTemplate (path), entrypoint, data, cancellable);
}

private async uint inject_library_file_with_template (uint pid, PathTemplate path_template, string entrypoint, string data,
        Cancellable? cancellable) throws Error, IOError {
    ensure_tempdir_prepared ();
    uint id = next_injectee_id++;
    yield helper.inject_library_file (pid, path_template, entrypoint, data, tempdir.path, id, cancellable);
    pid_by_id[id] = pid;
    return id;
}

public async void inject_library_file (uint pid, PathTemplate path_template, string entrypoint, string data,
        string temp_path, uint id, Cancellable? cancellable) throws Error, IOError {
    string path = path_template.expand (arch_name_from_pid (pid));

    _do_inject (pid, path, entrypoint, data, temp_path, id);

    yield establish_session (id, pid);
}
```
最终调用了_do_inject
```c
// frida-core/src/linux/frida-helper-backend-glue.c
_frida_linux_helper_backend_do_inject (FridaLinuxHelperBackend * self, guint pid, const gchar * path, const gchar * entrypoint, const gchar * data, const gchar * temp_path, guint id, GError ** error)
{
  FridaInjectInstance * instance;
  FridaInjectParams params;
  guint offset, page_size;
  FridaRegs saved_regs;
  gboolean exited;

  params.pid = pid;
  params.so_path = path;
  params.entrypoint_name = entrypoint;
  params.entrypoint_data = data;

  params.fifo_path = NULL;

  offset = 0;
  page_size = gum_query_page_size ();

  params.code.offset = offset;
  params.code.size = page_size;
  offset += params.code.size;

  params.data.offset = offset;
  params.data.size = page_size;
  offset += params.data.size;

  params.guard.offset = offset;
  params.guard.size = page_size;
  offset += params.guard.size;

  params.stack.offset = offset;
  params.stack.size = page_size * 2;
  offset += params.stack.size;

  params.remote_address = 0;
  params.remote_size = offset;

  params.open_impl = frida_resolve_libc_function (pid, "open");
  params.close_impl = frida_resolve_libc_function (pid, "close");
  params.write_impl = frida_resolve_libc_function (pid, "write");
  params.syscall_impl = frida_resolve_libc_function (pid, "syscall");
  if (params.open_impl == 0 || params.close_impl == 0 || params.write_impl == 0 || params.syscall_impl == 0)
    goto no_libc;

#if defined (HAVE_GLIBC)
  params.dlopen_impl = frida_resolve_libc_function (pid, "__libc_dlopen_mode");
  params.dlclose_impl = frida_resolve_libc_function (pid, "__libc_dlclose");
  params.dlsym_impl = frida_resolve_libc_function (pid, "__libc_dlsym");
#elif defined (HAVE_UCLIBC)
  params.dlopen_impl = frida_resolve_linker_address (params.pid, dlopen);
  params.dlclose_impl = frida_resolve_linker_address (params.pid, dlclose);
  params.dlsym_impl = frida_resolve_linker_address (params.pid, dlsym);
#elif defined (HAVE_ANDROID)
  params.dlopen_impl = frida_resolve_android_dlopen (pid);
  params.dlclose_impl = frida_resolve_linker_address (pid, dlclose);
  params.dlsym_impl = frida_resolve_linker_address (pid, dlsym);
#endif
  if (params.dlopen_impl == 0 || params.dlclose_impl == 0 || params.dlsym_impl == 0)
    goto no_libc;

  instance = frida_inject_instance_new (self, id, pid, temp_path);
  if (instance->executable_path == NULL)
    goto premature_termination;

  if (!frida_inject_instance_attach (instance, &saved_regs, error))
    goto premature_termination;

  params.fifo_path = instance->fifo_path;
  params.remote_address = frida_remote_alloc (pid, params.remote_size, PROT_READ | PROT_WRITE, error);
  if (params.remote_address == 0)
    goto premature_termination;
  instance->remote_payload = params.remote_address;
  instance->remote_size = params.remote_size;

  if (!frida_inject_instance_emit_and_transfer_payload (frida_inject_instance_emit_payload_code, &params, &instance->entrypoint, error))
    goto premature_termination;
  instance->stack_top = params.remote_address + params.stack.offset + params.stack.size;
  instance->trampoline_data = params.remote_address + params.data.offset;

  if (!frida_inject_instance_start_remote_thread (instance, &exited, error) && !exited)
    goto premature_termination;

  if (!exited)
    frida_inject_instance_detach (instance, &saved_regs, NULL);
  else
    g_clear_error (error);

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->inject_instances), GUINT_TO_POINTER (id), instance);

  return;

no_libc:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unable to inject library into process without libc");
    return;
  }
premature_termination:
  {
    frida_inject_instance_free (instance, FRIDA_UNLOAD_POLICY_IMMEDIATE);
    return;
  }
}
```
frida_inject_instance_attach函数中定义了真正的attach实现
```c
static gboolean
frida_inject_instance_attach (FridaInjectInstance * self, FridaRegs * saved_regs, GError ** error)
{
  const pid_t pid = self->pid;
  gboolean can_seize;
  long ret;
  int attach_errno;
  const gchar * failed_operation;
  gboolean maybe_already_attached, success;

  can_seize = frida_is_seize_supported ();

  if (can_seize)
    ret = ptrace (PTRACE_SEIZE, pid, NULL, PTRACE_O_TRACEEXEC);
  else
    ret = ptrace (PTRACE_ATTACH, pid, NULL, NULL);
  attach_errno = errno;

  maybe_already_attached = (ret != 0 && attach_errno == EPERM);
  if (maybe_already_attached)
  {
    ret = frida_get_regs (pid, saved_regs);
    CHECK_OS_RESULT (ret, ==, 0, "frida_get_regs");

    self->already_attached = TRUE;
  }
  else
  {
    CHECK_OS_RESULT (ret, ==, 0, can_seize ? "PTRACE_SEIZE" : "PTRACE_ATTACH");

    self->already_attached = FALSE;

    if (can_seize)
    {
      ret = ptrace (PTRACE_INTERRUPT, pid, NULL, NULL);
      CHECK_OS_RESULT (ret, ==, 0, "PTRACE_INTERRUPT");
    }

    success = frida_wait_for_attach_signal (pid);
    if (!success)
      goto wait_failed;

    ret = frida_get_regs (pid, saved_regs);
    if (ret != 0)
      goto wait_failed;
  }

  return TRUE;

os_failure:
  {
    if (attach_errno == EPERM)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_PERMISSION_DENIED,
          "Unable to access process with pid %u due to system restrictions;"
          " try `sudo sysctl kernel.yama.ptrace_scope=0`, or run Frida as root",
          pid);
    }
    else
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_NOT_SUPPORTED,
          "Unexpected error while attaching to process with pid %u (%s returned '%s')",
          pid, failed_operation, g_strerror (errno));
    }

    return FALSE;
  }
wait_failed:
  {
    ptrace (PTRACE_DETACH, pid, NULL, NULL);

    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while attaching to process with pid %u",
        pid);

    return FALSE;
  }
}
```
可以看到，frida注入的选型是使用到了ptrace来实现，在注入使用可以看到调用了frida_remote_alloc来申请内存空间将agent copy到目标进程中执行代码，执行完成之后调用detach
#### 1.2 frida-agent启动
在perform_attach_to函数中完成动态注入后执行的函数符号是frida_agent_main，对应的文件是
```js
// frida-core/lib/agent/agent.vala
namespace Frida.Agent {
	public void main (string agent_parameters, ref Frida.UnloadPolicy unload_policy, void * injector_state) {
		if (Runner.shared_instance == null)
			Runner.create_and_run (agent_parameters, ref unload_policy, injector_state);
		else
			Runner.resume_after_fork (ref unload_policy, injector_state);
	}

	private enum StopReason {
		UNLOAD,
		FORK
	}
    ......
}
```
调用链路如下
```
Runner.create_and_run->shared_instance.run->Runner.run->Runner.start
```
其中Runner.run函数在调用完start后会进入main_loop循环，直至进程退出或者收到server的解除命令
Runner.start的作用是准备Interceptor以及GumJS的ScriptBackend，并连接到启动时指定的transport_uri建立通信隧道
### 二、frida-gadget做了什么
gadget本身是一个动态库，在加载到目标进程中后会马上触发ctor执行指定代码，默认情况下是挂起当前进程并监听在27042端口等待Host的连接并恢复运行。其文件路径为lib/gadget/gadget.vala，启动入口为
```js
// frida-core/lib/gadget/gadget.vala

public void load (Gum.MemoryRange? mapped_range, string? config_data, int * result) {
    if (loaded)
        return;
    loaded = true;

    Environment.init ();

    Gee.Promise<int>? request = null;
    if (result != null)
        request = new Gee.Promise<int> ();

    location = detect_location (mapped_range);

    try {
        config = (config_data != null)
            ? parse_config (config_data)
            : load_config (location);
    } catch (Error e) {
        log_warning (e.message);
        return;
    }

    Gum.Process.set_code_signing_policy (config.code_signing);

    Gum.Cloak.add_range (location.range);

    exceptor = Gum.Exceptor.obtain ();

    wait_for_resume_needed = true;

    var listen_interaction = config.interaction as ListenInteraction;
    if (listen_interaction != null && listen_interaction.on_load == ListenInteraction.LoadBehavior.RESUME) {
        wait_for_resume_needed = false;
    }

    if (!wait_for_resume_needed)
        resume ();

    if (wait_for_resume_needed && Environment.can_block_at_load_time ()) {
        var scheduler = Gum.ScriptBackend.get_scheduler ();

        scheduler.disable_background_thread ();

        wait_for_resume_context = scheduler.get_js_context ();

        var ignore_scope = new ThreadIgnoreScope ();

        start (request);

        var loop = new MainLoop (wait_for_resume_context, true);
        wait_for_resume_loop = loop;

        wait_for_resume_context.push_thread_default ();
        loop.run ();
        wait_for_resume_context.pop_thread_default ();

        scheduler.enable_background_thread ();

        ignore_scope = null;
    } else {
        start (request);
    }

    if (result != null) {
        try {
            *result = request.future.wait ();
        } catch (Gee.FutureError e) {
            *result = -1;
        }
    }
}
```
Gadget启动时会根据指定路径去搜索配置文件，默认配置文件如下
```js
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_port_conflict": "fail",
    "on_load": "wait"
  }
}
```
即使用listen模式，监听在27042端口并等待连接。除了listen以外，还支持以下几种模式:
- connect: Gadget启动后主动连接到指定地址
- script: 启动后直接加载指定的JavaScript文件
- script-directory: 启动后加载指定目录下的所有JavaScript文件
### 三、ART Hook
frida对于ART Hook的实现在项目frida-java-bridge中，在ART虚拟机中，对于方法的调用，大部分会调用到ArtMethod::Invoke
```c
void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result, const char* shorty) {
    if (UNLIKELY(!runtime->IsStarted() || (self->IsForceInterpreter() && !IsNative() && !IsProxyMethod() && IsInvokable()))) {
        if (IsStatic()) {
            art::interpreter::EnterInterpreterFromInvoke(
                self, this, nullptr, args, result, /*stay_in_interpreter=*/ true);
        } else {
            mirror::Object* receiver = reinterpret_cast<StackReference<mirror::Object>*>(&args[0])->AsMirrorPtr();
            art::interpreter::EnterInterpreterFromInvoke(self, this, receiver, args + 1, result, /*stay_in_interpreter=*/ true);
        }
  } else {
    if (!IsStatic()) {
        (*art_quick_invoke_stub)(this, args, args_size, self, result, shorty);
    } else {
        (*art_quick_invoke_static_stub)(this, args, args_size, self, result, shorty);
    }
  }
}
```
主要分为两种情况
- 一种是ART未初始化完成或者系统配置强制以解释模式运行，此时则进入解释器
- 另一种情况是有native代码时，比如JNI代码、OAT提前编译过的代码或者JIT运行时编译过的代码以及代理方法等，此时则直接跳转到invoke_stub去执行
对于解释执行的情况，也细分为两种情况，一种是真正的解释执行，不断循环解析CodeItem中的每条指令并进行解析；另外一种是在当前解释执行遇到native方法时，这种情况一般是遇到了JNI函数，这时则通过method->GetEntryPointFromJni()获取对应地址进行跳转
```c
class ArtMethod final {
// ...
struct PtrSizedFields {
    // Depending on the method type, the data is
    //   - native method: pointer to the JNI function registered to this method
    //                    or a function to resolve the JNI function,
    //   - resolution method: pointer to a function to resolve the method and
    //                        the JNI function for @CriticalNative.
    //   - conflict method: ImtConflictTable,
    //   - abstract/interface method: the single-implementation if any,
    //   - proxy method: the original interface method or constructor,
    //   - other methods: during AOT the code item offset, at runtime a pointer
    //                    to the code item.
    void* data_;

    // Method dispatch from quick compiled code invokes this pointer which may cause bridging into
    // the interpreter.
    void* entry_point_from_quick_compiled_code_;
} ptr_sized_fields_;
// ...
};
```
对于快速执行的模式是跳转到stub代码，以非静态方法为例，该stub定义在art/runtime/arch/arm64/quick_entrypoints_arm64.S文件中，大致作用是将参数保存在对应寄存器中，然后跳转到实际的地址执行
```s
.macro INVOKE_STUB_CALL_AND_RETURN

    REFRESH_MARKING_REGISTER
    REFRESH_SUSPEND_CHECK_REGISTER

    // load method-> METHOD_QUICK_CODE_OFFSET
    ldr x9, [x0, #ART_METHOD_QUICK_CODE_OFFSET_64]
    // Branch to method.
    blr x9

    // Pop the ArtMethod* (null), arguments and alignment padding from the stack.
    mov sp, xFP
    // ...
.endm
```
而ART_METHOD_QUICK_CODE_OFFSET_64对应的就是entry_point_from_quick_compiled_code_

因此，不管是解释模式还是其他模式，只要目标方法有native代码，那么该方法的代码地址都是会保存在entry_point_from_quick_compiled_code_字段，只不过这个字段的含义在不同的场景中略有不同

所以我们若想要实现ARTHook，理论上只要找到对应方法在内存中的ArtMethod地址，然后替换其entrypoint的值即可。但是前面说过，并不是所有方法都会走到ArtMethod::Invoke。比如对于系统函数的调用，OAT优化时会直接将对应系统函数方法的调用替换为汇编跳转，跳转的目的就是就是对应方法的entrypoint，因为boot.oat由zygote加载，对于所有应用而言内存地址都是固定的，因此ART可以在优化过程中省略方法的查找过程从而直接跳转

再回到frida，对于ART Hook的实现在ArtMethodMangler当中
```js
// lib/android.js

patchArtMethod(replacementMethodId, {
    jniCode: impl,
    accessFlags: ((originalFlags & ~(kAccCriticalNative | kAccFastNative | kAccNterpEntryPointFastPathFlag)) | kAccNative | kAccCompileDontBother) >>> 0,
    quickCode: api.artClassLinker.quickGenericJniTrampoline,
    interpreterCode: api.artInterpreterToCompiledCodeBridge
}, vm);
```
jniCode替换为用户封装而成的NativeFunction，并将accessFlags设置成kAccNative，即这是一个JNI方法。quickCode和interpreterCode分别是Quick模式和解释器模式的入口，替换为了上文中查找保存的trampoline，令Quick模式跳转到JNI入口，解释器模式跳转到Quick代码，这样就实现了该方法的拦截，每次执行都会当做JNI函数执行到jniCode即我们替换的代码中

虽然此时我们已经将目标ArtMethod改成了Native方法，且JNI的入口指向我们的hook函数，但如果该方法已经被OAT或者JIT优化成了二进制代码，此时在字节码层调用invoke-xxx时会通过方法的entry_point_from_quick_compiled_code_直接跳转到native代码执行，而不是quick_xxx_trampoline。

因此对于这种情况，我们可以将entrypoint的地址重新指向trampoline，但如前文所说，对于系统函数而言，其地址已知，因此调用方被优化后很可能直接就调转到了对应的native地址，而不会通过entrypoint去查找。因此frida采用的方法是直接修改目标方法的quickCode内容，将其替换为一段跳板代码，然后再间接跳转到我们的劫持实现中
```js
Memory.patchCode(trampoline, 256, code => {
    const writer = new Arm64Writer(code, { pc: trampoline });

    const relocator = new Arm64Relocator(address, writer);
    for (let i = 0; i !== 2; i++) {
      relocator.readOne();
    }
    relocator.writeAll();

    relocator.readOne();
    relocator.skipOne();
    writer.putBCondLabel('eq', 'runtime_or_replacement_method');

    const savedRegs = [
      'd0', 'd1',
      'd2', 'd3',
      'd4', 'd5',
      'd6', 'd7',
      'x0', 'x1',
      'x2', 'x3',
      'x4', 'x5',
      'x6', 'x7',
      'x8', 'x9',
      'x10', 'x11',
      'x12', 'x13',
      'x14', 'x15',
      'x16', 'x17'
    ];
    const numSavedRegs = savedRegs.length;

    for (let i = 0; i !== numSavedRegs; i += 2) {
      writer.putPushRegReg(savedRegs[i], savedRegs[i + 1]);
    }

    writer.putCallAddressWithArguments(artController.replacedMethods.isReplacement, [methodReg]);
    writer.putCmpRegReg('x0', 'xzr');

    for (let i = numSavedRegs - 2; i >= 0; i -= 2) {
      writer.putPopRegReg(savedRegs[i], savedRegs[i + 1]);
    }

    writer.putBCondLabel('ne', 'runtime_or_replacement_method');
    writer.putBLabel('regular_method');

    relocator.readOne();
    const tailInstruction = relocator.input;

    const tailIsRegular = tailInstruction.address.equals(target.whenRegularMethod);

    writer.putLabel(tailIsRegular ? 'regular_method' : 'runtime_or_replacement_method');
    relocator.writeOne();
    writer.putBranchAddress(tailInstruction.next);

    writer.putLabel(tailIsRegular ? 'runtime_or_replacement_method' : 'regular_method');
    writer.putBranchAddress(target.whenTrue);

    writer.flush();
});
```
