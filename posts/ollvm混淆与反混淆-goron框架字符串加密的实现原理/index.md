# Ollvm混淆与反混淆: Goron框架字符串加密的实现原理


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
```c&#43;&#43;
// llvm/lib/Transforms/Obfuscation/StringEncryption.cpp

std::set&lt;GlobalVariable *&gt; ConstantStringUsers;

  // collect all c strings

  LLVMContext &amp;Ctx = M.getContext();
  ConstantInt *Zero = ConstantInt::get(Type::getInt32Ty(Ctx), 0);
  for (GlobalVariable &amp;GV : M.globals()) {
    if (!GV.isConstant() || !GV.hasInitializer()) {
      continue;
    }
    // 获取module下面的全局变量
    Constant *Init = GV.getInitializer();
    if (Init == nullptr)
      continue;
    if (ConstantDataSequential *CDS = dyn_cast&lt;ConstantDataSequential&gt;(Init)) {
      if (CDS-&gt;isCString()) {
        CSPEntry *Entry = new CSPEntry();
        StringRef Data = CDS-&gt;getRawDataValues();
        Entry-&gt;Data.reserve(Data.size());
        // 保存字符数据到Data字段
        for (unsigned i = 0; i &lt; Data.size(); &#43;&#43;i) {
          Entry-&gt;Data.push_back(static_cast&lt;uint8_t&gt;(Data[i]));
        }
        Entry-&gt;ID = static_cast&lt;unsigned&gt;(ConstantStringPool.size());
        ConstantAggregateZero *ZeroInit = ConstantAggregateZero::get(CDS-&gt;getType());
        GlobalVariable *DecGV = new GlobalVariable(M, CDS-&gt;getType(), false, GlobalValue::PrivateLinkage,
                                                   ZeroInit, &#34;dec&#34; &#43; Twine::utohexstr(Entry-&gt;ID) &#43; GV.getName());
        GlobalVariable *DecStatus = new GlobalVariable(M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage,
                                                   Zero, &#34;dec_status_&#34; &#43; Twine::utohexstr(Entry-&gt;ID) &#43; GV.getName());
        DecGV-&gt;setAlignment(GV.getAlignment());
        Entry-&gt;DecGV = DecGV;
        Entry-&gt;DecStatus = DecStatus;
        ConstantStringPool.push_back(Entry);
        CSPEntryMap[&amp;GV] = Entry;
        collectConstantStringUser(&amp;GV, ConstantStringUsers);
      }
    }
  }
```
ConstantStringPool收集CSPEntry实例，包含字符串
CSPEntryMap包含对应的GV

#### 1.2 字符加密并构建解密函数
```c&#43;&#43;
// llvm/lib/Transforms/Obfuscation/StringEncryption.cpp

for (CSPEntry *Entry: ConstantStringPool) {
    // 生成enckey，针对每个module不同
    getRandomBytes(Entry-&gt;EncKey, 16, 32);
    // 每个字符串进行加密
    for (unsigned i = 0; i &lt; Entry-&gt;Data.size(); &#43;&#43;i) {
      Entry-&gt;Data[i] ^= Entry-&gt;EncKey[i % Entry-&gt;EncKey.size()];
    }
    // 为每个module的解密函数生成
    Entry-&gt;DecFunc = buildDecryptFunction(&amp;M, Entry);
  }

void StringEncryption::getRandomBytes(std::vector&lt;uint8_t&gt; &amp;Bytes, uint32_t MinSize, uint32_t MaxSize) {
  uint32_t N = RandomEngine.get_uint32_t();
  uint32_t Len;

  assert(MaxSize &gt;= MinSize);

  if (MinSize == MaxSize) {
    Len = MinSize;
  } else {
    Len = MinSize &#43; (N % (MaxSize - MinSize));
  }

  char *Buffer = new char[Len];
  RandomEngine.get_bytes(Buffer, Len);
  for (uint32_t i = 0; i &lt; Len; &#43;&#43;i) {
    Bytes.push_back(static_cast&lt;uint8_t&gt;(Buffer[i]));
  }

  delete[] Buffer;
}

Function *StringEncryption::buildDecryptFunction(Module *M, const StringEncryption::CSPEntry *Entry) {
  LLVMContext &amp;Ctx = M-&gt;getContext();
  IRBuilder&lt;&gt; IRB(Ctx);
//   根据开头所说，module包含func、func包含块，因此创建逻辑也根据此
  FunctionType *FuncTy = FunctionType::get(Type::getVoidTy(Ctx), {IRB.getInt8PtrTy(), IRB.getInt8PtrTy()}, false);
//   函数创建
  Function *DecFunc =
      Function::Create(FuncTy, GlobalValue::PrivateLinkage, &#34;goron_decrypt_string_&#34; &#43; Twine::utohexstr(Entry-&gt;ID), M);
    // 参数
  auto ArgIt = DecFunc-&gt;arg_begin();
  Argument *PlainString = ArgIt; // output
  &#43;&#43;ArgIt;
  Argument *Data = ArgIt;       // input

  PlainString-&gt;setName(&#34;plain_string&#34;);
  PlainString-&gt;addAttr(Attribute::NoCapture);
  Data-&gt;setName(&#34;data&#34;);
  Data-&gt;addAttr(Attribute::NoCapture);
  Data-&gt;addAttr(Attribute::ReadOnly);

    // 创建块
  BasicBlock *Enter = BasicBlock::Create(Ctx, &#34;Enter&#34;, DecFunc);
  BasicBlock *LoopBody = BasicBlock::Create(Ctx, &#34;LoopBody&#34;, DecFunc);
  BasicBlock *UpdateDecStatus = BasicBlock::Create(Ctx, &#34;UpdateDecStatus&#34;, DecFunc);
  BasicBlock *Exit = BasicBlock::Create(Ctx, &#34;Exit&#34;, DecFunc);

  IRB.SetInsertPoint(Enter);
  ConstantInt *KeySize = ConstantInt::get(Type::getInt32Ty(Ctx), Entry-&gt;EncKey.size());
  Value *EncPtr = IRB.CreateInBoundsGEP(Data, KeySize);
  Value *DecStatus = IRB.CreateLoad(Entry-&gt;DecStatus);
  Value *IsDecrypted = IRB.CreateICmpEQ(DecStatus, IRB.getInt32(1));
  IRB.CreateCondBr(IsDecrypted, Exit, LoopBody);

  IRB.SetInsertPoint(LoopBody);
  PHINode *LoopCounter = IRB.CreatePHI(IRB.getInt32Ty(), 2);
  LoopCounter-&gt;addIncoming(IRB.getInt32(0), Enter);

  Value *EncCharPtr = IRB.CreateInBoundsGEP(EncPtr, LoopCounter);
  Value *EncChar = IRB.CreateLoad(EncCharPtr);
  Value *KeyIdx = IRB.CreateURem(LoopCounter, KeySize);

  Value *KeyCharPtr = IRB.CreateInBoundsGEP(Data, KeyIdx);
  Value *KeyChar = IRB.CreateLoad(KeyCharPtr);

  Value *DecChar = IRB.CreateXor(EncChar, KeyChar);
  Value *DecCharPtr = IRB.CreateInBoundsGEP(PlainString, LoopCounter);
  IRB.CreateStore(DecChar, DecCharPtr);

  Value *NewCounter = IRB.CreateAdd(LoopCounter, IRB.getInt32(1), &#34;&#34;, true, true);
  LoopCounter-&gt;addIncoming(NewCounter, LoopBody);

  Value *Cond = IRB.CreateICmpEQ(NewCounter, IRB.getInt32(static_cast&lt;uint32_t&gt;(Entry-&gt;Data.size())));
  IRB.CreateCondBr(Cond, UpdateDecStatus, LoopBody);

  IRB.SetInsertPoint(UpdateDecStatus);
  IRB.CreateStore(IRB.getInt32(1), Entry-&gt;DecStatus);
  IRB.CreateBr(Exit);

  IRB.SetInsertPoint(Exit);
  IRB.CreateRetVoid();

  return DecFunc;
}
```
对ConstantStringPool中的字符串进行加密并生成解密函数

#### 1.3 init函数构建
```c&#43;&#43;
// build initialization function for supported constant string users
  for (GlobalVariable *GV: ConstantStringUsers) {
    if (isValidToEncrypt(GV)) {
      Type *EltType = GV-&gt;getType()-&gt;getElementType();
      ConstantAggregateZero *ZeroInit = ConstantAggregateZero::get(EltType);
      GlobalVariable *DecGV = new GlobalVariable(M, EltType, false, GlobalValue::PrivateLinkage,
                                                 ZeroInit, &#34;dec_&#34; &#43; GV-&gt;getName());
      DecGV-&gt;setAlignment(GV-&gt;getAlignment());
      GlobalVariable *DecStatus = new GlobalVariable(M, Type::getInt32Ty(Ctx), false, GlobalValue::PrivateLinkage,
          Zero, &#34;dec_status_&#34; &#43; GV-&gt;getName());
      CSUser *User = new CSUser(GV, DecGV);
      User-&gt;DecStatus = DecStatus;
      User-&gt;InitFunc = buildInitFunction(&amp;M, User);
      CSUserMap[GV] = User;
    }
  }
```
每个GV都生成CSUser并保存在CSUserMap中

#### 1.4 离散字符串常量池
```c&#43;&#43;
// emit the constant string pool
  // | junk bytes | key 1 | encrypted string 1 | junk bytes | key 2 | encrypted string 2 | ...
  std::vector&lt;uint8_t&gt; Data;
  std::vector&lt;uint8_t&gt; JunkBytes;

  JunkBytes.reserve(32);
  for (CSPEntry *Entry: ConstantStringPool) {
    JunkBytes.clear();
    // 生成垃圾代码
    getRandomBytes(JunkBytes, 16, 32);
    // 插入垃圾代码在enckey之前
    Data.insert(Data.end(), JunkBytes.begin(), JunkBytes.end());
    Entry-&gt;Offset = static_cast&lt;unsigned&gt;(Data.size());
    Data.insert(Data.end(), Entry-&gt;EncKey.begin(), Entry-&gt;EncKey.end());
    Data.insert(Data.end(), Entry-&gt;Data.begin(), Entry-&gt;Data.end());
  }
  Constant *CDA = ConstantDataArray::get(M.getContext(), ArrayRef&lt;uint8_t&gt;(Data));
  EncryptedStringTable = new GlobalVariable(M, CDA-&gt;getType(), true, GlobalValue::PrivateLinkage,
                                            CDA, &#34;EncryptedStringTable&#34;);

```
保存全量的加密字符串

#### 1.5 动态解密
```c&#43;&#43;
bool Changed = false;
  for (Function &amp;F:M) {
    if (F.isDeclaration())
      continue;
    Changed |= processConstantStringUse(&amp;F);
  }

  for (auto &amp;I : CSUserMap) {
    CSUser *User = I.second;
    Changed |= processConstantStringUse(User-&gt;InitFunc);
  }

  // delete unused global variables
  deleteUnusedGlobalVariable();
  for (CSPEntry *Entry: ConstantStringPool) {
    if (Entry-&gt;DecFunc-&gt;use_empty()) {
      Entry-&gt;DecFunc-&gt;eraseFromParent();
    }
  }
```
包括加密字符串的处理和未使用的全局变量的删除
```c&#43;&#43;
bool StringEncryption::processConstantStringUse(Function *F) {
  ......
  LowerConstantExpr(*F);
  SmallPtrSet&lt;GlobalVariable *, 16&gt; DecryptedGV; // if GV has multiple use in a block, decrypt only at the first use
  bool Changed = false;
  for (BasicBlock &amp;BB : *F) {
    DecryptedGV.clear();
    for (Instruction &amp;Inst: BB) {
        // 处理每行指令
      if (PHINode *PHI = dyn_cast&lt;PHINode&gt;(&amp;Inst)) {
        for (unsigned int i = 0; i &lt; PHI-&gt;getNumIncomingValues(); &#43;&#43;i) {
          if (GlobalVariable *GV = dyn_cast&lt;GlobalVariable&gt;(PHI-&gt;getIncomingValue(i))) {
            auto Iter1 = CSPEntryMap.find(GV);
            auto Iter2 = CSUserMap.find(GV);
            if (Iter2 != CSUserMap.end()) { // GV is a constant string user
              CSUser *User = Iter2-&gt;second;
              if (DecryptedGV.count(GV) &gt; 0) {
                Inst.replaceUsesOfWith(GV, User-&gt;DecGV);
              } else {
                Instruction *InsertPoint = PHI-&gt;getIncomingBlock(i)-&gt;getTerminator();
                IRBuilder&lt;&gt; IRB(InsertPoint);
                IRB.CreateCall(User-&gt;InitFunc, {User-&gt;DecGV});
                Inst.replaceUsesOfWith(GV, User-&gt;DecGV);
                MaybeDeadGlobalVars.insert(GV);
                DecryptedGV.insert(GV);
                Changed = true;
              }
            } else if (Iter1 != CSPEntryMap.end()) { // GV is a constant string
              CSPEntry *Entry = Iter1-&gt;second;
              if (DecryptedGV.count(GV) &gt; 0) {
                // 字符串替换成加密字符串
                Inst.replaceUsesOfWith(GV, Entry-&gt;DecGV);
              } else {
                Instruction *InsertPoint = PHI-&gt;getIncomingBlock(i)-&gt;getTerminator();
                IRBuilder&lt;&gt; IRB(InsertPoint);

                Value *OutBuf = IRB.CreateBitCast(Entry-&gt;DecGV, IRB.getInt8PtrTy());
                Value *Data = IRB.CreateInBoundsGEP(EncryptedStringTable, {IRB.getInt32(0), IRB.getInt32(Entry-&gt;Offset)});
                IRB.CreateCall(Entry-&gt;DecFunc, {OutBuf, Data});

                Inst.replaceUsesOfWith(GV, Entry-&gt;DecGV);
                MaybeDeadGlobalVars.insert(GV);
                DecryptedGV.insert(GV);
                Changed = true;
              }
            }
          }
        }
      } else {
        for (User::op_iterator op = Inst.op_begin(); op != Inst.op_end(); &#43;&#43;op) {
          if (GlobalVariable *GV = dyn_cast&lt;GlobalVariable&gt;(*op)) {
            auto Iter1 = CSPEntryMap.find(GV);
            auto Iter2 = CSUserMap.find(GV);
            if (Iter2 != CSUserMap.end()) {
              CSUser *User = Iter2-&gt;second;
              if (DecryptedGV.count(GV) &gt; 0) {
                Inst.replaceUsesOfWith(GV, User-&gt;DecGV);
              } else {
                IRBuilder&lt;&gt; IRB(&amp;Inst);
                IRB.CreateCall(User-&gt;InitFunc, {User-&gt;DecGV});
                Inst.replaceUsesOfWith(GV, User-&gt;DecGV);
                MaybeDeadGlobalVars.insert(GV);
                DecryptedGV.insert(GV);
                Changed = true;
              }
            } else if (Iter1 != CSPEntryMap.end()) {
              CSPEntry *Entry = Iter1-&gt;second;
              if (DecryptedGV.count(GV) &gt; 0) {
                Inst.replaceUsesOfWith(GV, Entry-&gt;DecGV);
              } else {
                IRBuilder&lt;&gt; IRB(&amp;Inst);

                Value *OutBuf = IRB.CreateBitCast(Entry-&gt;DecGV, IRB.getInt8PtrTy());
                Value *Data = IRB.CreateInBoundsGEP(EncryptedStringTable, {IRB.getInt32(0), IRB.getInt32(Entry-&gt;Offset)});
                IRB.CreateCall(Entry-&gt;DecFunc, {OutBuf, Data});
                Inst.replaceUsesOfWith(GV, Entry-&gt;DecGV);
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
```c&#43;&#43;
void StringEncryption::deleteUnusedGlobalVariable() {
  bool Changed = true;
  while (Changed) {
    Changed = false;
    for (auto Iter = MaybeDeadGlobalVars.begin(); Iter != MaybeDeadGlobalVars.end();) {
      GlobalVariable *GV = *Iter;
      if (!GV-&gt;hasLocalLinkage()) {
        &#43;&#43;Iter;
        continue;
      }

      GV-&gt;removeDeadConstantUsers();
      if (GV-&gt;use_empty()) {
        if (GV-&gt;hasInitializer()) {
          Constant *Init = GV-&gt;getInitializer();
          GV-&gt;setInitializer(nullptr);
          if (isSafeToDestroyConstant(Init))
            Init-&gt;destroyConstant();
        }
        Iter = MaybeDeadGlobalVars.erase(Iter);
        GV-&gt;eraseFromParent();
        Changed = true;
      } else {
        &#43;&#43;Iter;
      }
    }
  }
}
```

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/ollvm%E6%B7%B7%E6%B7%86%E4%B8%8E%E5%8F%8D%E6%B7%B7%E6%B7%86-goron%E6%A1%86%E6%9E%B6%E5%AD%97%E7%AC%A6%E4%B8%B2%E5%8A%A0%E5%AF%86%E7%9A%84%E5%AE%9E%E7%8E%B0%E5%8E%9F%E7%90%86/  

