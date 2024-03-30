# Ollvm混淆与反混淆: goron框架字符串加密的实现原理


函数实现逻辑在llvm/lib/Transforms/Obfuscation/StringEncryption.cpp文件中，IndirectBranch，集成自类ModulePass，实现了runOnModule函数

Module（模块）：
- Module是LLVM的最高级别的组织单元，它代表一个编译单元或一个独立的代码模块
- Module包含了全局变量、函数定义、类型定义等
- 一个Module可以包含多个Function

Function（函数）：
- Function代表一个具体的函数，包含函数的定义和实现
- Function定义了函数的参数类型、返回类型、函数名等信息
- Function还包含了函数的基本块（Basic Block）和指令（Instruction）

在LLVM的编译过程中，首先创建一个Module，然后在Module中创建和添加Function，最后为每个Function添加基本块和指令

### 一、字符串加密的实现逻辑

#### 1.1 字符串收集
```c++
// llvm/lib/Transforms/Obfuscation/StringEncryption.cpp

std::set<GlobalVariable *> ConstantStringUsers;

  // collect all c strings

  LLVMContext &Ctx = M.getContext();
  ConstantInt *Zero = ConstantInt::get(Type::getInt32Ty(Ctx), 0);
  for (GlobalVariable &GV : M.globals()) {
    if (!GV.isConstant() || !GV.hasInitializer()) {
      continue;
    }
    // 获取module下面的全局变量
    Constant *Init = GV.getInitializer();
    if (Init == nullptr)
      continue;
    if (ConstantDataSequential *CDS = dyn_cast<ConstantDataSequential>(Init)) {
      if (CDS->isCString()) {
        CSPEntry *Entry = new CSPEntry();
        StringRef Data = CDS->getRawDataValues();
        Entry->Data.reserve(Data.size());
        // 保存字符数据到Data字段
        for (unsigned i = 0; i < Data.size(); ++i) {
          Entry->Data.push_back(static_cast<uint8_t>(Data[i]));
        }
        Entry->ID = static_cast<unsigned>(ConstantStringPool.size());
        ConstantAggregateZero *ZeroInit = ConstantAggregateZero::get(CDS->getType());
        GlobalVariable *DecGV = new GlobalVariable(M, CDS->getType(), false, GlobalValue::PrivateLinkage,
                                                   ZeroInit, "dec" + Twine::utohexstr(Entry->ID) + GV.getName());
        GlobalVariable *DecStatus = new GlobalVariable(M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage,
                                                   Zero, "dec_status_" + Twine::utohexstr(Entry->ID) + GV.getName());
        DecGV->setAlignment(GV.getAlignment());
        Entry->DecGV = DecGV;
        Entry->DecStatus = DecStatus;
        ConstantStringPool.push_back(Entry);
        CSPEntryMap[&GV] = Entry;
        collectConstantStringUser(&GV, ConstantStringUsers);
      }
    }
  }
```
ConstantStringPool收集CSPEntry实例，包含字符串
CSPEntryMap包含对应的GV

#### 1.2 字符加密并构建解密函数
```c++
// llvm/lib/Transforms/Obfuscation/StringEncryption.cpp

for (CSPEntry *Entry: ConstantStringPool) {
    // 生成enckey，针对每个module不同
    getRandomBytes(Entry->EncKey, 16, 32);
    // 每个字符串进行加密
    for (unsigned i = 0; i < Entry->Data.size(); ++i) {
      Entry->Data[i] ^= Entry->EncKey[i % Entry->EncKey.size()];
    }
    // 为每个module的解密函数生成
    Entry->DecFunc = buildDecryptFunction(&M, Entry);
  }

void StringEncryption::getRandomBytes(std::vector<uint8_t> &Bytes, uint32_t MinSize, uint32_t MaxSize) {
  uint32_t N = RandomEngine.get_uint32_t();
  uint32_t Len;

  assert(MaxSize >= MinSize);

  if (MinSize == MaxSize) {
    Len = MinSize;
  } else {
    Len = MinSize + (N % (MaxSize - MinSize));
  }

  char *Buffer = new char[Len];
  RandomEngine.get_bytes(Buffer, Len);
  for (uint32_t i = 0; i < Len; ++i) {
    Bytes.push_back(static_cast<uint8_t>(Buffer[i]));
  }

  delete[] Buffer;
}

Function *StringEncryption::buildDecryptFunction(Module *M, const StringEncryption::CSPEntry *Entry) {
  LLVMContext &Ctx = M->getContext();
  IRBuilder<> IRB(Ctx);
//   根据开头所说，module包含func、func包含块，因此创建逻辑也根据此
  FunctionType *FuncTy = FunctionType::get(Type::getVoidTy(Ctx), {IRB.getInt8PtrTy(), IRB.getInt8PtrTy()}, false);
//   函数创建
  Function *DecFunc =
      Function::Create(FuncTy, GlobalValue::PrivateLinkage, "goron_decrypt_string_" + Twine::utohexstr(Entry->ID), M);
    // 参数
  auto ArgIt = DecFunc->arg_begin();
  Argument *PlainString = ArgIt; // output
  ++ArgIt;
  Argument *Data = ArgIt;       // input

  PlainString->setName("plain_string");
  PlainString->addAttr(Attribute::NoCapture);
  Data->setName("data");
  Data->addAttr(Attribute::NoCapture);
  Data->addAttr(Attribute::ReadOnly);

    // 创建块
  BasicBlock *Enter = BasicBlock::Create(Ctx, "Enter", DecFunc);
  BasicBlock *LoopBody = BasicBlock::Create(Ctx, "LoopBody", DecFunc);
  BasicBlock *UpdateDecStatus = BasicBlock::Create(Ctx, "UpdateDecStatus", DecFunc);
  BasicBlock *Exit = BasicBlock::Create(Ctx, "Exit", DecFunc);

  IRB.SetInsertPoint(Enter);
  ConstantInt *KeySize = ConstantInt::get(Type::getInt32Ty(Ctx), Entry->EncKey.size());
  Value *EncPtr = IRB.CreateInBoundsGEP(Data, KeySize);
  Value *DecStatus = IRB.CreateLoad(Entry->DecStatus);
  Value *IsDecrypted = IRB.CreateICmpEQ(DecStatus, IRB.getInt32(1));
  IRB.CreateCondBr(IsDecrypted, Exit, LoopBody);

  IRB.SetInsertPoint(LoopBody);
  PHINode *LoopCounter = IRB.CreatePHI(IRB.getInt32Ty(), 2);
  LoopCounter->addIncoming(IRB.getInt32(0), Enter);

  Value *EncCharPtr = IRB.CreateInBoundsGEP(EncPtr, LoopCounter);
  Value *EncChar = IRB.CreateLoad(EncCharPtr);
  Value *KeyIdx = IRB.CreateURem(LoopCounter, KeySize);

  Value *KeyCharPtr = IRB.CreateInBoundsGEP(Data, KeyIdx);
  Value *KeyChar = IRB.CreateLoad(KeyCharPtr);

  Value *DecChar = IRB.CreateXor(EncChar, KeyChar);
  Value *DecCharPtr = IRB.CreateInBoundsGEP(PlainString, LoopCounter);
  IRB.CreateStore(DecChar, DecCharPtr);

  Value *NewCounter = IRB.CreateAdd(LoopCounter, IRB.getInt32(1), "", true, true);
  LoopCounter->addIncoming(NewCounter, LoopBody);

  Value *Cond = IRB.CreateICmpEQ(NewCounter, IRB.getInt32(static_cast<uint32_t>(Entry->Data.size())));
  IRB.CreateCondBr(Cond, UpdateDecStatus, LoopBody);

  IRB.SetInsertPoint(UpdateDecStatus);
  IRB.CreateStore(IRB.getInt32(1), Entry->DecStatus);
  IRB.CreateBr(Exit);

  IRB.SetInsertPoint(Exit);
  IRB.CreateRetVoid();

  return DecFunc;
}
```
对ConstantStringPool中的字符串进行加密并生成解密函数

#### 1.3 init函数构建
```c++
// build initialization function for supported constant string users
  for (GlobalVariable *GV: ConstantStringUsers) {
    if (isValidToEncrypt(GV)) {
      Type *EltType = GV->getType()->getElementType();
      ConstantAggregateZero *ZeroInit = ConstantAggregateZero::get(EltType);
      GlobalVariable *DecGV = new GlobalVariable(M, EltType, false, GlobalValue::PrivateLinkage,
                                                 ZeroInit, "dec_" + GV->getName());
      DecGV->setAlignment(GV->getAlignment());
      GlobalVariable *DecStatus = new GlobalVariable(M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage,
          Zero, "dec_status_" + GV->getName());
      CSUser *User = new CSUser(GV, DecGV);
      User->DecStatus = DecStatus;
      User->InitFunc = buildInitFunction(&M, User);
      CSUserMap[GV] = User;
    }
  }
```
每个GV都生成CSUser并保存在CSUserMap中

#### 1.4 离散字符串常量池
```c++
// emit the constant string pool
  // | junk bytes | key 1 | encrypted string 1 | junk bytes | key 2 | encrypted string 2 | ...
  std::vector<uint8_t> Data;
  std::vector<uint8_t> JunkBytes;

  JunkBytes.reserve(32);
  for (CSPEntry *Entry: ConstantStringPool) {
    JunkBytes.clear();
    // 生成垃圾代码
    getRandomBytes(JunkBytes, 16, 32);
    // 插入垃圾代码在enckey之前
    Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
    Entry->Offset = static_cast<unsigned>(Data.size());
    Data.insert(Data.end(), Entry->EncKey.begin(), Entry->EncKey.end());
    Data.insert(Data.end(), Entry->Data.begin(), Entry->Data.end());
  }
  Constant *CDA = ConstantDataArray::get(M.getContext(), ArrayRef<uint8_t>(Data));
  EncryptedStringTable = new GlobalVariable(M, CDA->getType(), true, GlobalValue::PrivateLinkage,
                                            CDA, "EncryptedStringTable");

```
保存全量的加密字符串

#### 1.5 动态解密
```c++
bool Changed = false;
  for (Function &F:M) {
    if (F.isDeclaration())
      continue;
    Changed |= processConstantStringUse(&F);
  }

  for (auto &I : CSUserMap) {
    CSUser *User = I.second;
    Changed |= processConstantStringUse(User->InitFunc);
  }

  // delete unused global variables
  deleteUnusedGlobalVariable();
  for (CSPEntry *Entry: ConstantStringPool) {
    if (Entry->DecFunc->use_empty()) {
      Entry->DecFunc->eraseFromParent();
    }
  }
```
包括加密字符串的处理和未使用的全局变量的删除
```c++
bool StringEncryption::processConstantStringUse(Function *F) {
  ......
  LowerConstantExpr(*F);
  SmallPtrSet<GlobalVariable *, 16> DecryptedGV; // if GV has multiple use in a block, decrypt only at the first use
  bool Changed = false;
  for (BasicBlock &BB : *F) {
    DecryptedGV.clear();
    for (Instruction &Inst: BB) {
        // 处理每行指令
      if (PHINode *PHI = dyn_cast<PHINode>(&Inst)) {
        for (unsigned int i = 0; i < PHI->getNumIncomingValues(); ++i) {
          if (GlobalVariable *GV = dyn_cast<GlobalVariable>(PHI->getIncomingValue(i))) {
            auto Iter1 = CSPEntryMap.find(GV);
            auto Iter2 = CSUserMap.find(GV);
            if (Iter2 != CSUserMap.end()) { // GV is a constant string user
              CSUser *User = Iter2->second;
              if (DecryptedGV.count(GV) > 0) {
                Inst.replaceUsesOfWith(GV, User->DecGV);
              } else {
                Instruction *InsertPoint = PHI->getIncomingBlock(i)->getTerminator();
                IRBuilder<> IRB(InsertPoint);
                IRB.CreateCall(User->InitFunc, {User->DecGV});
                Inst.replaceUsesOfWith(GV, User->DecGV);
                MaybeDeadGlobalVars.insert(GV);
                DecryptedGV.insert(GV);
                Changed = true;
              }
            } else if (Iter1 != CSPEntryMap.end()) { // GV is a constant string
              CSPEntry *Entry = Iter1->second;
              if (DecryptedGV.count(GV) > 0) {
                // 字符串替换成加密字符串
                Inst.replaceUsesOfWith(GV, Entry->DecGV);
              } else {
                Instruction *InsertPoint = PHI->getIncomingBlock(i)->getTerminator();
                IRBuilder<> IRB(InsertPoint);

                Value *OutBuf = IRB.CreateBitCast(Entry->DecGV, IRB.getInt8PtrTy());
                Value *Data = IRB.CreateInBoundsGEP(EncryptedStringTable, {IRB.getInt32(0), IRB.getInt32(Entry->Offset)});
                IRB.CreateCall(Entry->DecFunc, {OutBuf, Data});

                Inst.replaceUsesOfWith(GV, Entry->DecGV);
                MaybeDeadGlobalVars.insert(GV);
                DecryptedGV.insert(GV);
                Changed = true;
              }
            }
          }
        }
      } else {
        for (User::op_iterator op = Inst.op_begin(); op != Inst.op_end(); ++op) {
          if (GlobalVariable *GV = dyn_cast<GlobalVariable>(*op)) {
            auto Iter1 = CSPEntryMap.find(GV);
            auto Iter2 = CSUserMap.find(GV);
            if (Iter2 != CSUserMap.end()) {
              CSUser *User = Iter2->second;
              if (DecryptedGV.count(GV) > 0) {
                Inst.replaceUsesOfWith(GV, User->DecGV);
              } else {
                IRBuilder<> IRB(&Inst);
                IRB.CreateCall(User->InitFunc, {User->DecGV});
                Inst.replaceUsesOfWith(GV, User->DecGV);
                MaybeDeadGlobalVars.insert(GV);
                DecryptedGV.insert(GV);
                Changed = true;
              }
            } else if (Iter1 != CSPEntryMap.end()) {
              CSPEntry *Entry = Iter1->second;
              if (DecryptedGV.count(GV) > 0) {
                Inst.replaceUsesOfWith(GV, Entry->DecGV);
              } else {
                IRBuilder<> IRB(&Inst);

                Value *OutBuf = IRB.CreateBitCast(Entry->DecGV, IRB.getInt8PtrTy());
                Value *Data = IRB.CreateInBoundsGEP(EncryptedStringTable, {IRB.getInt32(0), IRB.getInt32(Entry->Offset)});
                IRB.CreateCall(Entry->DecFunc, {OutBuf, Data});
                Inst.replaceUsesOfWith(GV, Entry->DecGV);
                MaybeDeadGlobalVars.insert(GV);
                DecryptedGV.insert(GV);
                Changed = true;
              }
            }
          }
        }
      }
    }
  }
  return Changed;
}
```
清空未使用的变量
```c++
void StringEncryption::deleteUnusedGlobalVariable() {
  bool Changed = true;
  while (Changed) {
    Changed = false;
    for (auto Iter = MaybeDeadGlobalVars.begin(); Iter != MaybeDeadGlobalVars.end();) {
      GlobalVariable *GV = *Iter;
      if (!GV->hasLocalLinkage()) {
        ++Iter;
        continue;
      }

      GV->removeDeadConstantUsers();
      if (GV->use_empty()) {
        if (GV->hasInitializer()) {
          Constant *Init = GV->getInitializer();
          GV->setInitializer(nullptr);
          if (isSafeToDestroyConstant(Init))
            Init->destroyConstant();
        }
        Iter = MaybeDeadGlobalVars.erase(Iter);
        GV->eraseFromParent();
        Changed = true;
      } else {
        ++Iter;
      }
    }
  }
}
```
