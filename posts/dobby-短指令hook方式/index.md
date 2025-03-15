# Dobby 短指令hook方式


从上一篇Dobby的文章可以了解到Dobby对于inline hook的实现是通过替换origin method的前三行指令（前12个字节）来跳转到对应的trampoline上，那对于指令数少于三行的函数它是怎么做到inline hook的呢？从它的案例中可以发现
```c&#43;&#43;
// examples/socket_example.cc
__attribute__((constructor)) static void ctor() {
  logger_set_options(0, 0, 0, LOG_LEVEL_DEBUG, false, false);

  void *func = NULL;
  func_map = new std::map&lt;void *, const char *&gt;();
  for (int i = 0; i &lt; sizeof(func_array) / sizeof(char *); &#43;&#43;i) {
    func = DobbySymbolResolver(NULL, func_array[i]);
    if (func == NULL) {
      INFO_LOG(&#34;func %s not resolve&#34;, func_array[i]);
      continue;
    }
    func_map-&gt;insert(std::pair&lt;void *, const char *&gt;(func, func_array[i]));
  }

  for (auto iter = func_map-&gt;begin(), e = func_map-&gt;end(); iter != e; iter&#43;&#43;) {
    bool is_short = false;
    for (int i = 0; i &lt; sizeof(func_short_array) / sizeof(char *); &#43;&#43;i) {
      if (strcmp(func_short_array[i], iter-&gt;second) == 0) {
        is_short = true;
        break;
      }
    }
    if (is_short) {
      dobby_enable_near_branch_trampoline();
      DobbyInstrument(iter-&gt;first, common_handler);
      dobby_disable_near_branch_trampoline();
    } else {
      DobbyInstrument(iter-&gt;first, common_handler);
    }
  }
  ......
}
```
在调用DobbyInstrument完成指令的hook时，判定accept函数为短函数，看下accept函数源码
```c&#43;&#43;
.text:000000000001E024                         accept                                  ; DATA XREF: LOAD:0000000000003C68↑o
.text:000000000001E024                         ; __unwind {
.text:000000000001E024 03 00 80 52                             MOV             W3, #0
.text:000000000001E028 D6 EA FF 17                             B               .accept4
.text:000000000001E028                         ; } // starts at 1E024
```
函数只有两行代码，无法满足正常inline hook的要求，开启了near branch的模式

### Dobby插件NearBranchTrampoline
```c&#43;&#43;
// source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/NearBranchTrampoline.cc

PUBLIC void dobby_enable_near_branch_trampoline() {
  RoutingPluginInterface *plugin = new NearBranchTrampolinePlugin;
  RoutingPluginManager::registerPlugin(&#34;near_branch_trampoline&#34;, plugin);
  RoutingPluginManager::near_branch_trampoline = plugin;
}
```
开启了near branch插件，于是在调用GenerateTrampolineBuffer时优先调用
```c&#43;&#43;
// source/InterceptRouting/InterceptRouting.cpp

bool InterceptRouting::GenerateTrampolineBuffer(addr_t src, addr_t dst) {
  // if near branch trampoline plugin enabled
  if (RoutingPluginManager::near_branch_trampoline) {
    auto plugin = static_cast&lt;RoutingPluginInterface *&gt;(RoutingPluginManager::near_branch_trampoline);
    if (plugin-&gt;GenerateTrampolineBuffer(this, src, dst) == false) {
      DEBUG_LOG(&#34;Failed enable near branch trampoline plugin&#34;);
    }
  }

  if (GetTrampolineBuffer() == nullptr) {
    auto tramp_buffer = GenerateNormalTrampolineBuffer(src, dst);
    SetTrampolineBuffer(tramp_buffer);
  }
  return true;
}
```
arm64架构下的GenerateNearTrampolineBuffer的实现
```c&#43;&#43;
// source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/near_trampoline_arm64.cc

CodeBufferBase *GenerateNearTrampolineBuffer(InterceptRouting *routing, addr_t src, addr_t dst) {
  CodeBufferBase *result = nullptr;

  TurboAssembler turbo_assembler_((void *)src);
#define _ turbo_assembler_.

  // branch to trampoline_target directly
  if (llabs((long long)dst - (long long)src) &lt; ARM64_B_XXX_RANGE) {
    _ b(dst - src);
  } else {
    auto fast_forward_trampoline = GenerateFastForwardTrampoline(src, dst);
    if (!fast_forward_trampoline)
      return nullptr;
    _ b(fast_forward_trampoline-&gt;addr - src);
  }

  // free the original trampoline
  result = turbo_assembler_.GetCodeBuffer()-&gt;Copy();
  return result;
}
```
根据代码逻辑，最终的跳转都是通过b指令来跳的，也就是只会替换一行指令完成短指令的inline hook，具体看看b指令跳转是怎么实现的
#### 1. b指令直接跳转
判断是否dst、src间距在b指令跳转范围内，arm64 b指令跳转范围在128M

#### 2. fast_forward模式
第一步是寻找dst周边的可执行内存块
```c&#43;&#43; 
// source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/near_trampoline_arm64.cc

// [adrp &#43; add &#43; br branch]
auto tramp_size = 3 * 4;
auto tramp_mem = NearMemoryAllocator::SharedAllocator()-&gt;allocateNearExecMemory(tramp_size, src, ARM64_B_XXX_RANGE);
if (tramp_mem == nullptr) {
  ERROR_LOG(&#34;search near code block failed&#34;);
  return nullptr;
}
```
两种搜索方式
```c&#43;&#43;
// source/MemoryAllocator/NearMemoryAllocator.cc

MemBlock *NearMemoryAllocator::allocateNearBlock(uint32_t size, addr_t pos, size_t search_range, bool executable) {
  MemBlock *result = nullptr;
  result = allocateNearBlockFromDefaultAllocator(size, pos, search_range, executable);
  if (!result) {
    result = allocateNearBlockFromUnusedRegion(size, pos, search_range, executable);
  }

  if (!result) {
    ERROR_LOG(&#34;[near memory allocator] allocate near block failed (%p, %p, %p)&#34;, size, pos, search_range);
  }
  return result;
}
```

##### 2.1 allocateNearBlockFromDefaultAllocator
依赖于allocateNearBlockFromUnusedRegion函数中注册的default_allocator
##### 2.2 allocateNearBlockFromUnusedRegion
遍历当前进程内存地址段（maps文件中），寻找unuse的内存地址，创建内存块

当创建好内存块后，判断新内存块与dst的距离是否满足adrp指令的范围，满足则跳转
```c&#43;&#43;
// /Users/linhanqiu/Projects/study/Dobby/source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/near_trampoline_arm64.cc

uint64_t distance = llabs((int64_t)(tramp_mem - dst));
  uint64_t adrp_range = ((uint64_t)1 &lt;&lt; (2 &#43; 19 &#43; 12 - 1));
  if (distance &lt; adrp_range) {
    // use adrp &#43; add &#43; br branch == (3 * 4) trampoline size
    _ AdrpAdd(TMP_REG_0, (uint64_t)tramp_mem, dst);
    _ br(TMP_REG_0);
    DEBUG_LOG(&#34;forward trampoline use [adrp, add, br]&#34;);
  } 
```
这里可以这么理解，b指令是为了跳转到这个新创建的内存块上，借由这个内存块再跳转到dst上，相当于做了二次跳转

当距离还是不够大时，只能使用mov&#43;br的方式跳转到dst上
```c&#43;&#43;
// /Users/linhanqiu/Projects/study/Dobby/source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/near_trampoline_arm64.cc

// use mov &#43; br == (4 * 5) trampoline size
_ Mov(TMP_REG_0, dst);
_ br(TMP_REG_0);
DEBUG_LOG(&#34;forward trampoline use  [mov, br]&#34;);
```

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/dobby-%E7%9F%AD%E6%8C%87%E4%BB%A4hook%E6%96%B9%E5%BC%8F/  

