# Dobby 短指令hook方式


从上一篇Dobby的文章可以了解到Dobby对于inline hook的实现是通过替换origin method的前三行指令（前12个字节）来跳转到对应的trampoline上，那对于指令数少于三行的函数它是怎么做到inline hook的呢？从它的案例中可以发现
```c++
// examples/socket_example.cc
__attribute__((constructor)) static void ctor() {
  logger_set_options(0, 0, 0, LOG_LEVEL_DEBUG, false, false);

  void *func = NULL;
  func_map = new std::map<void *, const char *>();
  for (int i = 0; i < sizeof(func_array) / sizeof(char *); ++i) {
    func = DobbySymbolResolver(NULL, func_array[i]);
    if (func == NULL) {
      INFO_LOG("func %s not resolve", func_array[i]);
      continue;
    }
    func_map->insert(std::pair<void *, const char *>(func, func_array[i]));
  }

  for (auto iter = func_map->begin(), e = func_map->end(); iter != e; iter++) {
    bool is_short = false;
    for (int i = 0; i < sizeof(func_short_array) / sizeof(char *); ++i) {
      if (strcmp(func_short_array[i], iter->second) == 0) {
        is_short = true;
        break;
      }
    }
    if (is_short) {
      dobby_enable_near_branch_trampoline();
      DobbyInstrument(iter->first, common_handler);
      dobby_disable_near_branch_trampoline();
    } else {
      DobbyInstrument(iter->first, common_handler);
    }
  }
  ......
}
```
在调用DobbyInstrument完成指令的hook时，判定accept函数为短函数，看下accept函数源码
```c++
.text:000000000001E024                         accept                                  ; DATA XREF: LOAD:0000000000003C68↑o
.text:000000000001E024                         ; __unwind {
.text:000000000001E024 03 00 80 52                             MOV             W3, #0
.text:000000000001E028 D6 EA FF 17                             B               .accept4
.text:000000000001E028                         ; } // starts at 1E024
```
函数只有两行代码，无法满足正常inline hook的要求，开启了near branch的模式

### Dobby插件NearBranchTrampoline
```c++
// source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/NearBranchTrampoline.cc

PUBLIC void dobby_enable_near_branch_trampoline() {
  RoutingPluginInterface *plugin = new NearBranchTrampolinePlugin;
  RoutingPluginManager::registerPlugin("near_branch_trampoline", plugin);
  RoutingPluginManager::near_branch_trampoline = plugin;
}
```
开启了near branch插件，于是在调用GenerateTrampolineBuffer时优先调用
```c++
// source/InterceptRouting/InterceptRouting.cpp

bool InterceptRouting::GenerateTrampolineBuffer(addr_t src, addr_t dst) {
  // if near branch trampoline plugin enabled
  if (RoutingPluginManager::near_branch_trampoline) {
    auto plugin = static_cast<RoutingPluginInterface *>(RoutingPluginManager::near_branch_trampoline);
    if (plugin->GenerateTrampolineBuffer(this, src, dst) == false) {
      DEBUG_LOG("Failed enable near branch trampoline plugin");
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
```c++
// source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/near_trampoline_arm64.cc

CodeBufferBase *GenerateNearTrampolineBuffer(InterceptRouting *routing, addr_t src, addr_t dst) {
  CodeBufferBase *result = nullptr;

  TurboAssembler turbo_assembler_((void *)src);
#define _ turbo_assembler_.

  // branch to trampoline_target directly
  if (llabs((long long)dst - (long long)src) < ARM64_B_XXX_RANGE) {
    _ b(dst - src);
  } else {
    auto fast_forward_trampoline = GenerateFastForwardTrampoline(src, dst);
    if (!fast_forward_trampoline)
      return nullptr;
    _ b(fast_forward_trampoline->addr - src);
  }

  // free the original trampoline
  result = turbo_assembler_.GetCodeBuffer()->Copy();
  return result;
}
```
根据代码逻辑，最终的跳转都是通过b指令来跳的，也就是只会替换一行指令完成短指令的inline hook，具体看看b指令跳转是怎么实现的
#### 1. b指令直接跳转
判断是否dst、src间距在b指令跳转范围内，arm64 b指令跳转范围在128M

#### 2. fast_forward模式
第一步是寻找dst周边的可执行内存块
```c++ 
// source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/near_trampoline_arm64.cc

// [adrp + add + br branch]
auto tramp_size = 3 * 4;
auto tramp_mem = NearMemoryAllocator::SharedAllocator()->allocateNearExecMemory(tramp_size, src, ARM64_B_XXX_RANGE);
if (tramp_mem == nullptr) {
  ERROR_LOG("search near code block failed");
  return nullptr;
}
```
两种搜索方式
```c++
// source/MemoryAllocator/NearMemoryAllocator.cc

MemBlock *NearMemoryAllocator::allocateNearBlock(uint32_t size, addr_t pos, size_t search_range, bool executable) {
  MemBlock *result = nullptr;
  result = allocateNearBlockFromDefaultAllocator(size, pos, search_range, executable);
  if (!result) {
    result = allocateNearBlockFromUnusedRegion(size, pos, search_range, executable);
  }

  if (!result) {
    ERROR_LOG("[near memory allocator] allocate near block failed (%p, %p, %p)", size, pos, search_range);
  }
  return result;
}
```

##### 2.1 allocateNearBlockFromDefaultAllocator
依赖于allocateNearBlockFromUnusedRegion函数中注册的default_allocator
##### 2.2 allocateNearBlockFromUnusedRegion
遍历当前进程内存地址段（maps文件中），寻找unuse的内存地址，创建内存块

当创建好内存块后，判断新内存块与dst的距离是否满足adrp指令的范围，满足则跳转
```c++
// /Users/linhanqiu/Projects/study/Dobby/source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/near_trampoline_arm64.cc

uint64_t distance = llabs((int64_t)(tramp_mem - dst));
  uint64_t adrp_range = ((uint64_t)1 << (2 + 19 + 12 - 1));
  if (distance < adrp_range) {
    // use adrp + add + br branch == (3 * 4) trampoline size
    _ AdrpAdd(TMP_REG_0, (uint64_t)tramp_mem, dst);
    _ br(TMP_REG_0);
    DEBUG_LOG("forward trampoline use [adrp, add, br]");
  } 
```
这里可以这么理解，b指令是为了跳转到这个新创建的内存块上，借由这个内存块再跳转到dst上，相当于做了二次跳转

当距离还是不够大时，只能使用mov+br的方式跳转到dst上
```c++
// /Users/linhanqiu/Projects/study/Dobby/source/InterceptRouting/RoutingPlugin/NearBranchTrampoline/near_trampoline_arm64.cc

// use mov + br == (4 * 5) trampoline size
_ Mov(TMP_REG_0, dst);
_ br(TMP_REG_0);
DEBUG_LOG("forward trampoline use  [mov, br]");
```
