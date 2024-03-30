# Ollvm混淆与反混淆: goron框架间接全局变量引用的实现原理


与间接函数调用同理，可参考
```c++
// llvm/lib/Transforms/Obfuscation/IndirectGlobalVariable.cpp

bool runOnFunction(Function &Fn) override {
    if (!toObfuscate(flag, &Fn, "indgv")) {
      return false;
    }

    if (Options && Options->skipFunction(Fn.getName())) {
      return false;
    }

    LLVMContext &Ctx = Fn.getContext();

    GVNumbering.clear();
    GlobalVariables.clear();

    LowerConstantExpr(Fn);
    NumberGlobalVariable(Fn);

    if (GlobalVariables.empty()) {
      return false;
    }

    uint32_t V = RandomEngine.get_uint32_t() & ~3;
    ConstantInt *EncKey = ConstantInt::get(Type::getInt32Ty(Ctx), V, false);

    const IPObfuscationContext::IPOInfo *SecretInfo = nullptr;
    if (IPO) {
      SecretInfo = IPO->getIPOInfo(&Fn);
    }

    Value *MySecret;
    if (SecretInfo) {
      MySecret = SecretInfo->SecretLI;
    } else {
      MySecret = ConstantInt::get(Type::getInt32Ty(Ctx), 0, true);
    }

    ConstantInt *Zero = ConstantInt::get(Type::getInt32Ty(Ctx), 0);
    GlobalVariable *GVars = getIndirectGlobalVariables(Fn, EncKey);

    for (inst_iterator I = inst_begin(Fn), E = inst_end(Fn); I != E; ++I) {
      Instruction *Inst = &*I;
      if (PHINode *PHI = dyn_cast<PHINode>(Inst)) {
        for (unsigned int i = 0; i < PHI->getNumIncomingValues(); ++i) {
          Value *val = PHI->getIncomingValue(i);
          if (GlobalVariable *GV = dyn_cast<GlobalVariable>(val)) {
            if (GVNumbering.count(GV) == 0) {
              continue;
            }

            Instruction *IP = PHI->getIncomingBlock(i)->getTerminator();
            IRBuilder<> IRB(IP);

            Value *Idx = ConstantInt::get(Type::getInt32Ty(Ctx), GVNumbering[GV]);
            Value *GEP = IRB.CreateGEP(GVars, {Zero, Idx});
            LoadInst *EncGVAddr = IRB.CreateLoad(GEP, GV->getName());
            Constant *X;
            if (SecretInfo) {
              X = ConstantExpr::getSub(SecretInfo->SecretCI, EncKey);
            } else {
              X = ConstantExpr::getSub(Zero, EncKey);
            }

            Value *Secret = IRB.CreateSub(X, MySecret);
            Value *GVAddr = IRB.CreateGEP(EncGVAddr, Secret);
            GVAddr = IRB.CreateBitCast(GVAddr, GV->getType());
            GVAddr->setName("IndGV");
            Inst->replaceUsesOfWith(GV, GVAddr);
          }
        }
      } else {
        for (User::op_iterator op = Inst->op_begin(); op != Inst->op_end(); ++op) {
          if (GlobalVariable *GV = dyn_cast<GlobalVariable>(*op)) {
            if (GVNumbering.count(GV) == 0) {
              continue;
            }

            IRBuilder<> IRB(Inst);
            Value *Idx = ConstantInt::get(Type::getInt32Ty(Ctx), GVNumbering[GV]);
            Value *GEP = IRB.CreateGEP(GVars, {Zero, Idx});
            LoadInst *EncGVAddr = IRB.CreateLoad(GEP, GV->getName());
            Constant *X;
            if (SecretInfo) {
              X = ConstantExpr::getSub(SecretInfo->SecretCI, EncKey);
            } else {
              X = ConstantExpr::getSub(Zero, EncKey);
            }

            Value *Secret = IRB.CreateSub(X, MySecret);
            Value *GVAddr = IRB.CreateGEP(EncGVAddr, Secret);
            GVAddr = IRB.CreateBitCast(GVAddr, GV->getType());
            GVAddr->setName("IndGV");
            Inst->replaceUsesOfWith(GV, GVAddr);
          }
        }
      }
    }

      return true;
    }

  };
```
