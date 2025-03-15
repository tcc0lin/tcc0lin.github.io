# Ollvm混淆与反混淆: Goron框架间接全局变量引用的实现原理


与间接函数调用同理，可参考
```c&#43;&#43;
// llvm/lib/Transforms/Obfuscation/IndirectGlobalVariable.cpp

bool runOnFunction(Function &amp;Fn) override {
    if (!toObfuscate(flag, &amp;Fn, &#34;indgv&#34;)) {
      return false;
    }

    if (Options &amp;&amp; Options-&gt;skipFunction(Fn.getName())) {
      return false;
    }

    LLVMContext &amp;Ctx = Fn.getContext();

    GVNumbering.clear();
    GlobalVariables.clear();

    LowerConstantExpr(Fn);
    NumberGlobalVariable(Fn);

    if (GlobalVariables.empty()) {
      return false;
    }

    uint32_t V = RandomEngine.get_uint32_t() &amp; ~3;
    ConstantInt *EncKey = ConstantInt::get(Type::getInt32Ty(Ctx), V, false);

    const IPObfuscationContext::IPOInfo *SecretInfo = nullptr;
    if (IPO) {
      SecretInfo = IPO-&gt;getIPOInfo(&amp;Fn);
    }

    Value *MySecret;
    if (SecretInfo) {
      MySecret = SecretInfo-&gt;SecretLI;
    } else {
      MySecret = ConstantInt::get(Type::getInt32Ty(Ctx), 0, true);
    }

    ConstantInt *Zero = ConstantInt::get(Type::getInt32Ty(Ctx), 0);
    GlobalVariable *GVars = getIndirectGlobalVariables(Fn, EncKey);

    for (inst_iterator I = inst_begin(Fn), E = inst_end(Fn); I != E; &#43;&#43;I) {
      Instruction *Inst = &amp;*I;
      if (PHINode *PHI = dyn_cast&lt;PHINode&gt;(Inst)) {
        for (unsigned int i = 0; i &lt; PHI-&gt;getNumIncomingValues(); &#43;&#43;i) {
          Value *val = PHI-&gt;getIncomingValue(i);
          if (GlobalVariable *GV = dyn_cast&lt;GlobalVariable&gt;(val)) {
            if (GVNumbering.count(GV) == 0) {
              continue;
            }

            Instruction *IP = PHI-&gt;getIncomingBlock(i)-&gt;getTerminator();
            IRBuilder&lt;&gt; IRB(IP);

            Value *Idx = ConstantInt::get(Type::getInt32Ty(Ctx), GVNumbering[GV]);
            Value *GEP = IRB.CreateGEP(GVars, {Zero, Idx});
            LoadInst *EncGVAddr = IRB.CreateLoad(GEP, GV-&gt;getName());
            Constant *X;
            if (SecretInfo) {
              X = ConstantExpr::getSub(SecretInfo-&gt;SecretCI, EncKey);
            } else {
              X = ConstantExpr::getSub(Zero, EncKey);
            }

            Value *Secret = IRB.CreateSub(X, MySecret);
            Value *GVAddr = IRB.CreateGEP(EncGVAddr, Secret);
            GVAddr = IRB.CreateBitCast(GVAddr, GV-&gt;getType());
            GVAddr-&gt;setName(&#34;IndGV&#34;);
            Inst-&gt;replaceUsesOfWith(GV, GVAddr);
          }
        }
      } else {
        for (User::op_iterator op = Inst-&gt;op_begin(); op != Inst-&gt;op_end(); &#43;&#43;op) {
          if (GlobalVariable *GV = dyn_cast&lt;GlobalVariable&gt;(*op)) {
            if (GVNumbering.count(GV) == 0) {
              continue;
            }

            IRBuilder&lt;&gt; IRB(Inst);
            Value *Idx = ConstantInt::get(Type::getInt32Ty(Ctx), GVNumbering[GV]);
            Value *GEP = IRB.CreateGEP(GVars, {Zero, Idx});
            LoadInst *EncGVAddr = IRB.CreateLoad(GEP, GV-&gt;getName());
            Constant *X;
            if (SecretInfo) {
              X = ConstantExpr::getSub(SecretInfo-&gt;SecretCI, EncKey);
            } else {
              X = ConstantExpr::getSub(Zero, EncKey);
            }

            Value *Secret = IRB.CreateSub(X, MySecret);
            Value *GVAddr = IRB.CreateGEP(EncGVAddr, Secret);
            GVAddr = IRB.CreateBitCast(GVAddr, GV-&gt;getType());
            GVAddr-&gt;setName(&#34;IndGV&#34;);
            Inst-&gt;replaceUsesOfWith(GV, GVAddr);
          }
        }
      }
    }

      return true;
    }

  };
```

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/ollvm%E6%B7%B7%E6%B7%86%E4%B8%8E%E5%8F%8D%E6%B7%B7%E6%B7%86-goron%E6%A1%86%E6%9E%B6%E9%97%B4%E6%8E%A5%E5%85%A8%E5%B1%80%E5%8F%98%E9%87%8F%E5%BC%95%E7%94%A8%E7%9A%84%E5%AE%9E%E7%8E%B0%E5%8E%9F%E7%90%86/  

