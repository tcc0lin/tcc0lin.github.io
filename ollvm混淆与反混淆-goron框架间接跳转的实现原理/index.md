# Ollvm混淆与反混淆: goron框架间接跳转的实现原理


Obfusaction Pass的管理统一在类ObfuscationPassManager中
```c++
static cl::opt<bool>
    EnableIndirectBr("irobf-indbr", cl::init(false), cl::NotHidden,
                     cl::desc("Enable IR Indirect Branch Obfuscation."));
```
根据clang的flag来判断是否开启某类混淆，以间接跳转为例
```c++
add(llvm::createIndirectBranchPass(EnableIndirectBr || Options->EnableIndirectBr, IPO, Options.get()));
```
对应的实现类是IndirectBranch，集成自类FunctionPass，重写函数getPassName、runOnFunction，具体实现是在runOnFunction函数中
### 一、间接跳转实现逻辑
#### 1.1 初始化BBNumbering、BBTargets集合
```c++
// llvm/lib/Transforms/Obfuscation/IndirectBranch.cpp

std::map<BasicBlock *, unsigned> BBNumbering;
std::vector<BasicBlock *> BBTargets;        //all conditional branch targets
// Init member fields
BBNumbering.clear();
BBTargets.clear();
```
#### 1.2 BBNumbering、BBTargets块信息收集
```c++
SplitAllCriticalEdges(Fn, CriticalEdgeSplittingOptions(nullptr, nullptr));

// llvm/lib/Transforms/Utils/BasicBlockUtils.cpp
unsigned
llvm::SplitAllCriticalEdges(Function &F,
                            const CriticalEdgeSplittingOptions &Options) {
  unsigned NumBroken = 0;
//   遍历所有基础块
  for (BasicBlock &BB : F) {
    // 获取块的终止指令
    Instruction *TI = BB.getTerminator();
    // 如果指令有后继指令
    if (TI->getNumSuccessors() > 1 && !isa<IndirectBrInst>(TI))
      for (unsigned i = 0, e = TI->getNumSuccessors(); i != e; ++i)
        // 分割块和后继块之间的连接
        if (SplitCriticalEdge(TI, i, Options))
          ++NumBroken;
  }
  return NumBroken;
}

// llvm/lib/Transforms/Obfuscation/IndirectBranch.cpp
void NumberBasicBlock(Function &F) {
    // 块遍历
    for (auto &BB : F) {
      if (auto *BI = dyn_cast<BranchInst>(BB.getTerminator())) {
        // 如果末尾指令是条件指令，则在BBTargets、BBNumbering中初始化对应块数量
        if (BI->isConditional()) {
          unsigned N = BI->getNumSuccessors();
          for (unsigned I = 0; I < N; I++) {
            BasicBlock *Succ = BI->getSuccessor(I);
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
      BBNumbering[BB] = N++;
    }
  }
```

#### 1.3 重构BBTargets块的全局跳转变量
```c++
// llvm/lib/Transforms/Obfuscation/IndirectBranch.cpp

// enckey创建
uint32_t V = RandomEngine.get_uint32_t() & ~3;
ConstantInt *EncKey = ConstantInt::get(Type::getInt32Ty(Ctx), V, false);

GlobalVariable *DestBBs = getIndirectTargets(Fn, EncKey);

GlobalVariable *getIndirectTargets(Function &F, ConstantInt *EncKey) {
    std::string GVName(F.getName().str() + "_IndirectBrTargets");
    GlobalVariable *GV = F.getParent()->getNamedGlobal(GVName);
    if (GV)
      return GV;

    // encrypt branch targets
    std::vector<Constant *> Elements;
    // 遍历BBTargets块
    for (const auto BB:BBTargets) {
        // 获取块地址
      Constant *CE = ConstantExpr::getBitCast(BlockAddress::get(BB), Type::getInt8PtrTy(F.getContext()));
    //   地址+=enckey
      CE = ConstantExpr::getGetElementPtr(Type::getInt8Ty(F.getContext()), CE, EncKey);
    //   加入到Elements
      Elements.push_back(CE);
    }

    // 加入到全局变量中
    ArrayType *ATy = ArrayType::get(Type::getInt8PtrTy(F.getContext()), Elements.size());
    Constant *CA = ConstantArray::get(ATy, ArrayRef<Constant *>(Elements));
    GV = new GlobalVariable(*F.getParent(), ATy, false, GlobalValue::LinkageTypes::PrivateLinkage,
                                               CA, GVName);
    // 添加到section llvm.metadata中
    appendToCompilerUsed(*F.getParent(), {GV});
    return GV;
  }
```
目的是收集BBTargets块的地址+enckey加入到全局变量中，这里全局变量已经得到

#### 1.4 指令替换
```c++
for (auto &BB : Fn) {
      auto *BI = dyn_cast<BranchInst>(BB.getTerminator());
      if (BI && BI->isConditional()) {
        IRBuilder<> IRB(BI);
        // 获取块末尾指令
        Value *Cond = BI->getCondition();
        Value *Idx;
        Value *TIdx, *FIdx;
        // 获取
        TIdx = ConstantInt::get(Type::getInt32Ty(Ctx), BBNumbering[BI->getSuccessor(0)]);
        FIdx = ConstantInt::get(Type::getInt32Ty(Ctx), BBNumbering[BI->getSuccessor(1)]);
        Idx = IRB.CreateSelect(Cond, TIdx, FIdx);

        // 加载全局变量+idx地址的值
        Value *GEP = IRB.CreateGEP(DestBBs, {Zero, Idx});
        LoadInst *EncDestAddr = IRB.CreateLoad(GEP, "EncDestAddr");
        // Use IPO context to compute the encryption key
        // X = FuncSecret - EncKey
        // 全局变量-enckey等于块地址
        Constant *X;
        if (SecretInfo) {
          X = ConstantExpr::getSub(SecretInfo->SecretCI, EncKey);
        } else {
          X = ConstantExpr::getSub(Zero, EncKey);
        }
        // -EncKey = X - FuncSecret
        Value *DecKey = IRB.CreateSub(X, MySecret);
        Value *DestAddr = IRB.CreateGEP(EncDestAddr, DecKey);   
        // 跳转目标地址
        IndirectBrInst *IBI = IndirectBrInst::Create(DestAddr, 2);
        IBI->addDestination(BI->getSuccessor(0));
        IBI->addDestination(BI->getSuccessor(1));
        // 指令替换
        ReplaceInstWithInst(BI, IBI);
      }
    }
```
#### 1.5 效果分析
![](https://github.com/tcc0lin/self_pic/blob/main/indbr1.png?raw=true)
- w12为后继块的index
- x8为全局变量+index-enckey后的地址
- br x8完成对后继块的跳转
### 二、总结
根据对代码的分析，可以简述间接跳转的原理
1. 收集末尾块的指令对应的后继块，形成map，map包含块以及对应的index
2. 生成enckey，遍历后继块，对后继块的地址进行二次加密，整理到全局变量中
3. 遍历末尾块的指令，对跳转后继块的指令进行重构
    - 根据map获取index，在全局变量中获取后继块的加密地址
    - 解析得到原始地址
    - 指令替换
