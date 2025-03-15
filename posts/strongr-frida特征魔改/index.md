# StrongR Frida特征魔改

### 一、背景
参考项目[strongR-frida](https://github.com/hluwa/Patchs/tree/master/strongR-frida/frida-core)对frida14.2.18进行魔改
### 二、魔改点
[patch文件](https://github.com/hluwa/Patchs/tree/master/strongR-frida/frida-core)总共有八个，分别是对八个主要特征进行魔改，下面逐个分析下
#### 1 0001-strongR-frida-string_frida_rpc.patch
针对frida-core/lib/interfaces/session.vala文件，修改了frida:rpc字符串，使用了base64 decode来隐去字符串的特征

具体修改如下
```js
// .add_string_value (&#34;frida:rpc&#34;)
.add_string_value ((string) GLib.Base64.decode(&#34;ZnJpZGE6cnBj=&#34;))
// if (raw_message.index_of (&#34;\&#34;frida:rpc\&#34;&#34;) == -1)
if (raw_message.index_of ((string) GLib.Base64.decode(&#34;ImZyaWRhOnJwYyI=&#34;)) == -1)
// if (type == null || type != &#34;frida:rpc&#34;)
if (type == null || type != (string) GLib.Base64.decode(&#34;ZnJpZGE6cnBj=&#34;))
```

##### 原理
应对内存特征的扫描，App会对关键代码的可读代码段进行扫描，而`frida:rpc`是很明显的字符串特征，因此对字符串做了一层base来隐藏
#### 2 0002-strongR-frida-io_re_frida_server.patch
```js
// private const string DEFAULT_DIRECTORY = &#34;re.frida.server&#34;;
private static string DEFAULT_DIRECTORY = null;

private static int main (string[] args) {
    DEFAULT_DIRECTORY = GLib.Uuid.string_random();
    Environment.init ();
```
##### 原理
re.frida.server是frida在启动时会创建的目录，里面有包括frida-agent等关键so，这些会在App的maps里面被检测到
#### 3 0003-strongR-frida-pipe_linjector.patch
```c
// self-&gt;fifo_path = g_strdup_printf (&#34;%s/linjector-%u&#34;, self-&gt;temp_path, self-&gt;id);
self-&gt;fifo_path = g_strdup_printf (&#34;%s/%p%u&#34;, self-&gt;temp_path, self ,self-&gt;id);
```
##### 原理
linjector是linux上提供注入能力的工具，当frida注入进程时，可以在App的/proc/self/fd看到某个fd的软链是指向frida目录的linjector的
#### 4 0004-strongR-frida-io_frida_agent_so.patch
```js
// agent = new AgentDescriptor (PathTemplate (&#34;frida-agent-&lt;arch&gt;.so&#34;),
var random_prefix = GLib.Uuid.string_random();
agent = new AgentDescriptor (PathTemplate (random_prefix &#43; &#34;-&lt;arch&gt;.so&#34;),

// new AgentResource (&#34;frida-agent-arm.so&#34;, new Bytes.static (emulated_arm.data), tempdir),
// new AgentResource (&#34;frida-agent-arm64.so&#34;, new Bytes.static (emulated_arm64.data), tempdir),
new AgentResource (random_prefix &#43; &#34;-arm.so&#34;, new Bytes.static (emulated_arm.data), tempdir),
new AgentResource (random_prefix &#43; &#34;-arm64.so&#34;, new Bytes.static (emulated_arm64.data), tempdir),
```
##### 原理
和第二个是相同的，都是在maps中存在的特征
#### 5 0005-strongR-frida-symbol_frida_agent_main.patch
针对frida-agent特征进行隐藏
```js
// frida-core/src/agent-container.vala
// var main_func_found = container.module.symbol (&#34;frida_agent_main&#34;, out main_func_symbol);
var main_func_found = container.module.symbol (&#34;main&#34;, out main_func_symbol);

// frida-core/src/darwin/darwin-host-session.vala
// unowned string entrypoint = &#34;frida_agent_main&#34;;
unowned string entrypoint = &#34;main&#34;;

// frida-core/tests/test-injector.vala
// yield injector.inject_library_file (process.id, path, &#34;frida_agent_main&#34;, data);
yield injector.inject_library_file (process.id, path, &#34;main&#34;, data);

// frida-core/tests/test-agent.vala
// var main_func_found = module.symbol (&#34;frida_agent_main&#34;, out main_func_symbol);
var main_func_found = module.symbol (&#34;main&#34;, out main_func_symbol);

// frida-core/src/linux/linux-host-session.vala
// string entrypoint = &#34;frida_agent_main&#34;;
string entrypoint = &#34;main&#34;;

// frida-core/src/windows/windows-host-session.vala
// var id = yield winjector.inject_library_resource (pid, agent, &#34;frida_agent_main&#34;, t.remote_address, cancellable);
var id = yield winjector.inject_library_resource (pid, agent, &#34;main&#34;, t.remote_address, cancellable);

// frida-core/src/qnx/qnx-host-session.vala
// var id = yield qinjector.inject_library_resource (pid, agent_desc, &#34;frida_agent_main&#34;, t.remote_address,
// 				cancellable);
var id = yield qinjector.inject_library_resource (pid, agent_desc, &#34;main&#34;, t.remote_address,
    cancellable);
```
##### 原理
定位所有frida_agent_main进行隐藏
#### 6 0006-strongR-frida-thread_gum_js_loop.patch
无
##### 原理
#### 7 0007-strongR-frida-thread_gmain.patch
无
##### 原理
#### 8 0008-strongR-frida-protocol_unexpected_command.patch
```js
case &#34;OPEN&#34;:
case &#34;CLSE&#34;:
case &#34;WRTE&#34;:
    // throw new Error.PROTOCOL (&#34;Unexpected command&#34;);
    break; //throw new Error.PROTOCOL (&#34;Unexpected command&#34;);
```
##### 原理


---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/strongr-frida%E7%89%B9%E5%BE%81%E9%AD%94%E6%94%B9/  

