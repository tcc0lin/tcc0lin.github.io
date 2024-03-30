# Ollvm混淆与反混淆: goron框架控制流平坦化的实现原理


goron使用的控制流平坦化是ollvm原生的

### 一、控制流平坦化实现逻辑

#### 1.1 生成SCRAMBLER
```c++
// SCRAMBLER
char scrambling_key[16];
llvm::cryptoutils->get_bytes(scrambling_key, 16);
// END OF SCRAMBLER
```

#### 1.2 调用Lower switch
```c++
// Lower switch
#if LLVM_VERSION_MAJOR * 10 + LLVM_VERSION_MINOR >= 90
  FunctionPass *lower = createLegacyLowerSwitchPass();
#else
  FunctionPass *lower = createLowerSwitchPass();
#endif
  lower->runOnFunction(*f);

bool LowerSwitch::runOnFunction(Function &F) {
  bool Changed = false;
  SmallPtrSet<BasicBlock*, 8> DeleteList;

    // 遍历function获取基本块
  for (Function::iterator I = F.begin(), E = F.end(); I != E; ) {
    BasicBlock *Cur = &*I++; // Advance over block so we don't traverse new blocks

    // If the block is a dead Default block that will be deleted later, don't
    // waste time processing it.
    if (DeleteList.count(Cur))
      continue;

    // 如果块的末尾指令是switch指令，则需要处理
    if (SwitchInst *SI = dyn_cast<SwitchInst>(Cur->getTerminator())) {
      Changed = true;
      processSwitchInst(SI, DeleteList);
    }
  }

  for (BasicBlock* BB: DeleteList) {
    DeleteDeadBlock(BB);
  }

  return Changed;
}
```
Lower switch的目的是去除原生函数的switch结构降级成if结构

#### 1.3 保存所有块
```c++
// Save all original BB
  for (Function::iterator i = f->begin(); i != f->end(); ++i) {
    BasicBlock *tmp = &*i;
    origBB.push_back(tmp);

    BasicBlock *bb = &*i;
    if (isa<InvokeInst>(bb->getTerminator())) {
      return false;
    }
  }
```

#### 1.4 第一个基本块处理 
```c++
// Remove first BB 
// 删除第一个块并做一些处理
  origBB.erase(origBB.begin());

  // Get a pointer on the first BB
//   获取第一个块指针
  Function::iterator tmp = f->begin();  //++tmp;
  BasicBlock *insert = &*tmp;

  // If main begin with an if
  BranchInst *br = NULL;
  if (isa<BranchInst>(insert->getTerminator())) {
    br = cast<BranchInst>(insert->getTerminator());
  }

    // 如果块末尾是条件指令或者后继块有多个，都需要单独切割出来
  if ((br != NULL && br->isConditional()) ||
      insert->getTerminator()->getNumSuccessors() > 1) {
    BasicBlock::iterator i = insert->end();
	--i;

    if (insert->size() > 1) {
      --i;
    }

    // 将条件跳转的语句切割出来，成为一个新的基本块，并插入到vector开头
    BasicBlock *tmpBB = insert->splitBasicBlock(i, "first");
    origBB.insert(origBB.begin(), tmpBB);
  }

  // Remove jump
//   删除第一个基本块最后的末尾跳转
  insert->getTerminator()->eraseFromParent();
```
因为平坦化要求第一个基本块只能有一个后继基本块，如果第一个基本块末尾就是条件跳转（有两个或多个后继块）就无法进行后面的平坦化操作

#### 1.5 创建switch变量并设置初始值
```c++
// Create switch variable and set as it
switchVar =
    new AllocaInst(Type::getInt32Ty(f->getContext()), 0, "switchVar", insert);
// 首先设置初始值
new StoreInst(
    ConstantInt::get(Type::getInt32Ty(f->getContext()),
                    llvm::cryptoutils->scramble32(0, scrambling_key)),
    switchVar, insert);
```

#### 1.6 基本骨架设置
```c++
// Create main loop
// 创建loopEntry、loopEntry两个基本块
loopEntry = BasicBlock::Create(f->getContext(), "loopEntry", f, insert);
loopEnd = BasicBlock::Create(f->getContext(), "loopEnd", f, insert);

// load switchVar 变量
load = new LoadInst(switchVar, "switchVar", loopEntry);

// Move first BB on top
insert->moveBefore(loopEntry);
// 构建顺序insert->loopEntry

BranchInst::Create(loopEntry, insert);

// loopEnd jump to loopEntry
// 构建顺序loopEnd->loopEntry
BranchInst::Create(loopEntry, loopEnd);

BasicBlock *swDefault =
    BasicBlock::Create(f->getContext(), "switchDefault", f, loopEnd);
// 构建swDefault->loopEnd
BranchInst::Create(loopEnd, swDefault);

// Create switch instruction itself and set condition
switchI = SwitchInst::Create(&*f->begin(), swDefault, 0, loopEntry);
switchI->setCondition(load);

// Remove branch jump from 1st BB and make a jump to the while
f->begin()->getTerminator()->eraseFromParent();

// 构建顺序第一个块到loopEntry
BranchInst::Create(loopEntry, &*f->begin());
```
整体顺序就是第一个块->loopEntry，swDefault->loopEnd，loopEnd->loopEntry

#### 1.7 装入基本块
```c++
// Put all BB in the switch
    // 遍历每个块
  for (vector<BasicBlock *>::iterator b = origBB.begin(); b != origBB.end();
       ++b) {
    BasicBlock *i = *b;
    ConstantInt *numCase = NULL;

    // 块放在loopEnd前面
    // Move the BB inside the switch (only visual, no code logic)
    i->moveBefore(loopEnd);
    // 设置随机值并加入到switch结构中
    // Add case to switch
    numCase = cast<ConstantInt>(ConstantInt::get(
        switchI->getCondition()->getType(),
        llvm::cryptoutils->scramble32(switchI->getNumCases(), scrambling_key)));
    switchI->addCase(numCase, i);
  } 
```
这里只是单纯的将块和随机变量绑定，并没有指定块的跳转顺序，下面要开始调整基本块之间的关系了

#### 1.8 计算switchVar
遍历每个块，分别对不同类型的块做处理，这里有三种情况

##### 1.8.1 无后继基本块
```c++
// Ret BB
if (i->getTerminator()->getNumSuccessors() == 0) {
  continue;
}
```
如果这个块的末尾指令没有后继，则表明这个块是结束块，无需再回到分发器
##### 1.8.2 无条件跳转结尾基本块
```c++
// If it's a non-conditional jump
// 如果这个块末尾指令不是条件指令
if (i->getTerminator()->getNumSuccessors() == 1) {
    // Get successor and delete terminator
    // 获取后继基本块
    BasicBlock *succ = i->getTerminator()->getSuccessor(0);
    // 删除该块到后继块的跳转
    i->getTerminator()->eraseFromParent();

    // Get next case
    // 获取后继基本块的case值
    numCase = switchI->findCaseDest(succ);

    // 如果case为空，表示是default分支
    // If next case == default case (switchDefault)
    if (numCase == NULL) {
    numCase = cast<ConstantInt>(
        ConstantInt::get(switchI->getCondition()->getType(),
                            llvm::cryptoutils->scramble32(
                                switchI->getNumCases() - 1, scrambling_key)));
    }

    // numCase = MySecret - (MySecret - numCase)
    // X = MySecret - numCase
    Constant *X;
    if (SecretInfo) {
    X = ConstantExpr::getSub(SecretInfo->SecretCI, numCase);
    } else {
    X = ConstantExpr::getSub(Zero, numCase);
    }
    // 获取真实case值
    Value *newNumCase = BinaryOperator::Create(Instruction::Sub, MySecret, X, "", i);

    // Update switchVar and jump to the end of loop
    // 末尾更新switchVar值
    new StoreInst(newNumCase, load->getPointerOperand(), i);
    // 跳转到loopEnd
    BranchInst::Create(loopEnd, i);
    continue;
}
```
##### 1.8.3 条件跳转结尾基本块
```c++
// If it's a conditional jump
// 如果末尾指令是分支指令
if (i->getTerminator()->getNumSuccessors() == 2) {
    // Get next cases
    // 获取两个后继的case值
    ConstantInt *numCaseTrue =
        switchI->findCaseDest(i->getTerminator()->getSuccessor(0));
    ConstantInt *numCaseFalse =
        switchI->findCaseDest(i->getTerminator()->getSuccessor(1));

    // 判断defalut的情况
    // Check if next case == default case (switchDefault)
    if (numCaseTrue == NULL) {
    numCaseTrue = cast<ConstantInt>(
        ConstantInt::get(switchI->getCondition()->getType(),
                            llvm::cryptoutils->scramble32(
                                switchI->getNumCases() - 1, scrambling_key)));
    }

    if (numCaseFalse == NULL) {
    numCaseFalse = cast<ConstantInt>(
        ConstantInt::get(switchI->getCondition()->getType(),
                            llvm::cryptoutils->scramble32(
                                switchI->getNumCases() - 1, scrambling_key)));
    }

    // 获取真实值
    Constant *X, *Y;
    if (SecretInfo) {
    X = ConstantExpr::getSub(SecretInfo->SecretCI, numCaseTrue);
    Y = ConstantExpr::getSub(SecretInfo->SecretCI, numCaseFalse);
    } else {
    X = ConstantExpr::getSub(Zero, numCaseTrue);
    Y = ConstantExpr::getSub(Zero, numCaseFalse);
    }
    Value *newNumCaseTrue = BinaryOperator::Create(Instruction::Sub, MySecret, X, "", i->getTerminator());
    Value *newNumCaseFalse = BinaryOperator::Create(Instruction::Sub, MySecret, Y, "", i->getTerminator());

    // Create a SelectInst
    // 构造条件指令
    BranchInst *br = cast<BranchInst>(i->getTerminator());
    SelectInst *sel =
        SelectInst::Create(br->getCondition(), newNumCaseTrue, newNumCaseFalse, "",
                            i->getTerminator());

    // Erase terminator
    // 删除结尾跳转指令
    i->getTerminator()->eraseFromParent();

    // Update switchVar and jump to the end of loop
    // 末尾添加条件指令
    new StoreInst(sel, load->getPointerOperand(), i);
    // 跳转到loopEnd
    BranchInst::Create(loopEnd, i);
    continue;
}
}
```

#### 1.9 栈修复
```c++
void fixStack(Function *f) {
  // Try to remove phi node and demote reg to stack
  std::vector<PHINode *> tmpPhi;
  std::vector<Instruction *> tmpReg;
  BasicBlock *bbEntry = &*f->begin();

  do {
    tmpPhi.clear();
    tmpReg.clear();

    for (Function::iterator i = f->begin(); i != f->end(); ++i) {

      for (BasicBlock::iterator j = i->begin(); j != i->end(); ++j) {

        if (isa<PHINode>(j)) {
          PHINode *phi = cast<PHINode>(j);
          tmpPhi.push_back(phi);
          continue;
        }
        if (!(isa<AllocaInst>(j) && j->getParent() == bbEntry) &&
            (valueEscapes(&*j) || j->isUsedOutsideOfBlock(&*i))) {
          tmpReg.push_back(&*j);
          continue;
        }
      }
    }
    for (unsigned int i = 0; i != tmpReg.size(); ++i) {
      DemoteRegToStack(*tmpReg.at(i), f->begin()->getTerminator());
    }

    for (unsigned int i = 0; i != tmpPhi.size(); ++i) {
      DemotePHIToStack(tmpPhi.at(i), f->begin()->getTerminator());
    }

  } while (tmpReg.size() != 0 || tmpPhi.size() != 0);
}
```

### 二、总结
1. 调用lower switch去除当前函数的switch结构
2. 保存所有块并单独刨除第一个块
3. 创建switch变量并设置初始值
4. 设置基本骨架frist->loopEntry->switch->loopEnd->loopEntry
5. 装入基本块
6. 重新计算switchVar
7. 栈修复
