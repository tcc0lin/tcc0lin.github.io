# Ollvm混淆与反混淆: Goron框架间接跳转的实现原理


Obfusaction Pass的管理统一在类ObfuscationPassManager中
```c&#43;&#43;
static cl::opt&lt;bool&gt;
    EnableIndirectBr(&#34;irobf-indbr&#34;, cl::init(false), cl::NotHidden,
                     cl::desc(&#34;Enable IR Indirect Branch Obfuscation.&#34;));
```
根据clang的flag来判断是否开启某类混淆，以间接跳转为例
```c&#43;&#43;
add(llvm::createIndirectBranchPass(EnableIndirectBr || Options-&gt;EnableIndirectBr, IPO, Options.get()));
```
对应的实现类是IndirectBranch，集成自类FunctionPass，重写函数getPassName、runOnFunction，具体实现是在runOnFunction函数中
### 一、间接跳转实现逻辑
#### 1.1 初始化BBNumbering、BBTargets集合
```c&#43;&#43;
// llvm/lib/Transforms/Obfuscation/IndirectBranch.cpp

std::map&lt;BasicBlock *, unsigned&gt; BBNumbering;
std::vector&lt;BasicBlock *&gt; BBTargets;        //all conditional branch targets
// Init member fields
BBNumbering.clear();
BBTargets.clear();
```
#### 1.2 BBNumbering、BBTargets块信息收集
```c&#43;&#43;
SplitAllCriticalEdges(Fn, CriticalEdgeSplittingOptions(nullptr, nullptr));

// llvm/lib/Transforms/Utils/BasicBlockUtils.cpp
unsigned
llvm::SplitAllCriticalEdges(Function &amp;F,
                            const CriticalEdgeSplittingOptions &amp;Options) {
  unsigned NumBroken = 0;
//   遍历所有基础块
  for (BasicBlock &amp;BB : F) {
    // 获取块的终止指令
    Instruction *TI = BB.getTerminator();
    // 如果指令有后继指令
    if (TI-&gt;getNumSuccessors() &gt; 1 &amp;&amp; !isa&lt;IndirectBrInst&gt;(TI))
      for (unsigned i = 0, e = TI-&gt;getNumSuccessors(); i != e; &#43;&#43;i)
        // 分割块和后继块之间的连接
        if (SplitCriticalEdge(TI, i, Options))
          &#43;&#43;NumBroken;
  }
  return NumBroken;
}

// llvm/lib/Transforms/Obfuscation/IndirectBranch.cpp
void NumberBasicBlock(Function &amp;F) {
    // 块遍历
    for (auto &amp;BB : F) {
      if (auto *BI = dyn_cast&lt;BranchInst&gt;(BB.getTerminator())) {
        // 如果末尾指令是条件指令，则在BBTargets、BBNumbering中初始化对应块数量
        if (BI-&gt;isConditional()) {
          unsigned N = BI-&gt;getNumSuccessors();
          for (unsigned I = 0; I &lt; N; I&#43;&#43;) {
            BasicBlock *Succ = BI-&gt;getSuccessor(I);
            if (BBNumbering.count(Succ) == 0) {
              BBTargets.push_back(Succ);
              BBNumbering[Succ] = 0;
            }
          }
        }
      }
    }

    // 打乱BBTargets顺序
    long seed = RandomEngine.get_uint32_t();
    std::default_random_engine e(seed);
    std::shuffle(BBTargets.begin(), BBTargets.end(), e);

    // 遍历BBTargets，填充BBNumbering，值为BBTargets的序号
    unsigned N = 0;
    for (auto BB:BBTargets) {
      BBNumbering[BB] = N&#43;&#43;;
    }
  }
```

#### 1.3 重构BBTargets块的全局跳转变量
```c&#43;&#43;
// llvm/lib/Transforms/Obfuscation/IndirectBranch.cpp

// enckey创建
uint32_t V = RandomEngine.get_uint32_t() &amp; ~3;
ConstantInt *EncKey = ConstantInt::get(Type::getInt32Ty(Ctx), V, false);

GlobalVariable *DestBBs = getIndirectTargets(Fn, EncKey);

GlobalVariable *getIndirectTargets(Function &amp;F, ConstantInt *EncKey) {
    std::string GVName(F.getName().str() &#43; &#34;_IndirectBrTargets&#34;);
    GlobalVariable *GV = F.getParent()-&gt;getNamedGlobal(GVName);
    if (GV)
      return GV;

    // encrypt branch targets
    std::vector&lt;Constant *&gt; Elements;
    // 遍历BBTargets块
    for (const auto BB:BBTargets) {
        // 获取块地址
      Constant *CE = ConstantExpr::getBitCast(BlockAddress::get(BB), Type::getInt8PtrTy(F.getContext()));
    //   地址&#43;=enckey
      CE = ConstantExpr::getGetElementPtr(Type::getInt8Ty(F.getContext()), CE, EncKey);
    //   加入到Elements
      Elements.push_back(CE);
    }

    // 加入到全局变量中
    ArrayType *ATy = ArrayType::get(Type::getInt8PtrTy(F.getContext()), Elements.size());
    Constant *CA = ConstantArray::get(ATy, ArrayRef&lt;Constant *&gt;(Elements));
    GV = new GlobalVariable(*F.getParent(), ATy, false, GlobalValue::LinkageTypes::PrivateLinkage,
                                               CA, GVName);
    // 添加到section llvm.metadata中
    appendToCompilerUsed(*F.getParent(), {GV});
    return GV;
  }
```
目的是收集BBTargets块的地址&#43;enckey加入到全局变量中，这里全局变量已经得到

#### 1.4 指令替换
```c&#43;&#43;
for (auto &amp;BB : Fn) {
      auto *BI = dyn_cast&lt;BranchInst&gt;(BB.getTerminator());
      if (BI &amp;&amp; BI-&gt;isConditional()) {
        IRBuilder&lt;&gt; IRB(BI);
        // 获取块末尾指令
        Value *Cond = BI-&gt;getCondition();
        Value *Idx;
        Value *TIdx, *FIdx;
        // 获取
        TIdx = ConstantInt::get(Type::getInt32Ty(Ctx), BBNumbering[BI-&gt;getSuccessor(0)]);
        FIdx = ConstantInt::get(Type::getInt32Ty(Ctx), BBNumbering[BI-&gt;getSuccessor(1)]);
        Idx = IRB.CreateSelect(Cond, TIdx, FIdx);

        // 加载全局变量&#43;idx地址的值
        Value *GEP = IRB.CreateGEP(DestBBs, {Zero, Idx});
        LoadInst *EncDestAddr = IRB.CreateLoad(GEP, &#34;EncDestAddr&#34;);
        // Use IPO context to compute the encryption key
        // X = FuncSecret - EncKey
        // 全局变量-enckey等于块地址
        Constant *X;
        if (SecretInfo) {
          X = ConstantExpr::getSub(SecretInfo-&gt;SecretCI, EncKey);
        } else {
          X = ConstantExpr::getSub(Zero, EncKey);
        }
        // -EncKey = X - FuncSecret
        Value *DecKey = IRB.CreateSub(X, MySecret);
        Value *DestAddr = IRB.CreateGEP(EncDestAddr, DecKey);   
        // 跳转目标地址
        IndirectBrInst *IBI = IndirectBrInst::Create(DestAddr, 2);
        IBI-&gt;addDestination(BI-&gt;getSuccessor(0));
        IBI-&gt;addDestination(BI-&gt;getSuccessor(1));
        // 指令替换
        ReplaceInstWithInst(BI, IBI);
      }
    }
```
#### 1.5 效果分析
![](https://github.com/tcc0lin/self_pic/blob/main/indbr1.png?raw=true)
- w12为后继块的index
- x8为全局变量&#43;index-enckey后的地址
- br x8完成对后继块的跳转
### 二、总结
根据对代码的分析，可以简述间接跳转的原理
1. 收集末尾块的指令对应的后继块，形成map，map包含块以及对应的index
2. 生成enckey，遍历后继块，对后继块的地址进行二次加密，整理到全局变量中
3. 遍历末尾块的指令，对跳转后继块的指令进行重构
    - 根据map获取index，在全局变量中获取后继块的加密地址
    - 解析得到原始地址
    - 指令替换

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/ollvm%E6%B7%B7%E6%B7%86%E4%B8%8E%E5%8F%8D%E6%B7%B7%E6%B7%86-goron%E6%A1%86%E6%9E%B6%E9%97%B4%E6%8E%A5%E8%B7%B3%E8%BD%AC%E7%9A%84%E5%AE%9E%E7%8E%B0%E5%8E%9F%E7%90%86/  

