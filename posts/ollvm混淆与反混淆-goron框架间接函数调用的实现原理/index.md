# Ollvm混淆与反混淆: Goron框架间接函数调用的实现原理


函数实现逻辑在llvm/lib/Transforms/Obfuscation/IndirectCall.cpp文件中，IndirectBranch，集成自类FunctionPass

### 一、间接函数调用实现逻辑

#### 1.1 变量初始化
```c&#43;&#43;
std::map&lt;Function *, unsigned&gt; CalleeNumbering;
std::vector&lt;CallInst *&gt; CallSites;
std::vector&lt;Function *&gt; Callees;

CalleeNumbering.clear();
Callees.clear();
CallSites.clear();
```

#### 1.2 CallSites、CalleeNumbering、Callees信息收集
```c&#43;&#43;
void NumberCallees(Function &amp;F) {
    for (auto &amp;BB:F) {
      for (auto &amp;I:BB) {
        // 如果指令是调用指令
        if (dyn_cast&lt;CallInst&gt;(&amp;I)) {
          CallSite CS(&amp;I);
        //   获取被调用的函数
          Function *Callee = CS.getCalledFunction();
          if (Callee == nullptr) {
            continue;
          }
          if (Callee-&gt;isIntrinsic()) {
            continue;
          }
        //   CallSites添加这条指令
          CallSites.push_back((CallInst *) &amp;I);
          if (CalleeNumbering.count(Callee) == 0) {
            CalleeNumbering[Callee] = Callees.size();
            // Callees添加被调用的函数
            Callees.push_back(Callee);
          }
        }
      }
    }
  }
```

#### 1.3 重构Callees块的全局跳转变量
```c&#43;&#43;
// 生成enckey
uint32_t V = RandomEngine.get_uint32_t() &amp; ~3;
ConstantInt *EncKey = ConstantInt::get(Type::getInt32Ty(Ctx), V, false);

GlobalVariable *Targets = getIndirectCallees(Fn, EncKey);

GlobalVariable *getIndirectCallees(Function &amp;F, ConstantInt *EncKey) {
    std::string GVName(F.getName().str() &#43; &#34;_IndirectCallees&#34;);
    GlobalVariable *GV = F.getParent()-&gt;getNamedGlobal(GVName);
    if (GV)
      return GV;

    // callee&#39;s address
    std::vector&lt;Constant *&gt; Elements;
    for (auto Callee:Callees) {
      Constant *CE = ConstantExpr::getBitCast(Callee, Type::getInt8PtrTy(F.getContext()));
      CE = ConstantExpr::getGetElementPtr(Type::getInt8Ty(F.getContext()), CE, EncKey);
      Elements.push_back(CE);
    }

    ArrayType *ATy = ArrayType::get(Type::getInt8PtrTy(F.getContext()), Elements.size());
    Constant *CA = ConstantArray::get(ATy, ArrayRef&lt;Constant *&gt;(Elements));
    GV = new GlobalVariable(*F.getParent(), ATy, false, GlobalValue::LinkageTypes::PrivateLinkage,
                                               CA, GVName);
    appendToCompilerUsed(*F.getParent(), {GV});
    return GV;
  }
```
和间接跳转同理，间接模式都需要使用到全局变量&#43;enckey，这里将所有的Callees函数都&#43;enckey保存在全局变量中

#### 1.4 指令替换
```c&#43;&#43;
for (auto CI : CallSites) {
    //   获取idx
      Value *Idx = ConstantInt::get(Type::getInt32Ty(Ctx), CalleeNumbering[CS.getCalledFunction()]);
      Value *GEP = IRB.CreateGEP(Targets, {Zero, Idx});
      LoadInst *EncDestAddr = IRB.CreateLoad(GEP, CI-&gt;getName());
      Constant *X;
      if (SecretInfo) {
        X = ConstantExpr::getSub(SecretInfo-&gt;SecretCI, EncKey);
      } else {
        X = ConstantExpr::getSub(Zero, EncKey);
      }
        // 获取原始的地址
      const AttributeList &amp;CallPAL = CS.getAttributes();
      CallSite::arg_iterator I = CS.arg_begin();
      unsigned i = 0;

      for (unsigned e = FTy-&gt;getNumParams(); i != e; &#43;&#43;I, &#43;&#43;i) {
        Args.push_back(*I);
        AttributeSet Attrs = CallPAL.getParamAttributes(i);
        ArgAttrVec.push_back(Attrs);
      }

      for (CallSite::arg_iterator E = CS.arg_end(); I != E; &#43;&#43;I, &#43;&#43;i) {
        Args.push_back(*I);
        ArgAttrVec.push_back(CallPAL.getParamAttributes(i));
      }

      AttributeList NewCallPAL = AttributeList::get(
          IRB.getContext(), CallPAL.getFnAttributes(), CallPAL.getRetAttributes(), ArgAttrVec);

      Value *Secret = IRB.CreateSub(X, MySecret);
      Value *DestAddr = IRB.CreateGEP(EncDestAddr, Secret);

      Value *FnPtr = IRB.CreateBitCast(DestAddr, FTy-&gt;getPointerTo());
      FnPtr-&gt;setName(&#34;Call_&#34; &#43; Callee-&gt;getName());
    //   新建调用替换原始调用
      CallInst *NewCall = IRB.CreateCall(FTy, FnPtr, Args, Call-&gt;getName());
      NewCall-&gt;setAttributes(NewCallPAL);
      Call-&gt;replaceAllUsesWith(NewCall);
      Call-&gt;eraseFromParent();
    }
```

#### 1.5 效果分析
![](https://github.com/tcc0lin/self_pic/blob/main/icall1.png?raw=true)
- w8赋值
- x10为全局变量&#43;index&#43;enckey后的地址
- blr x10
### 二、总结
1. 收集调用块中的被调用函数，形成map，map包含被调用函数和对应的index
2. 生成enckey，遍历被调用函数，对其地址进行二次加密，整理到全局变量中
3. 遍历调用块，对调用方式进行重构
    - 根据map获取index，在全局变量中获取被调用函数的加密地址
    - 解析得到原始地址
    - 指令替换

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/ollvm%E6%B7%B7%E6%B7%86%E4%B8%8E%E5%8F%8D%E6%B7%B7%E6%B7%86-goron%E6%A1%86%E6%9E%B6%E9%97%B4%E6%8E%A5%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8%E7%9A%84%E5%AE%9E%E7%8E%B0%E5%8E%9F%E7%90%86/  

