# Ollvm混淆与反混淆: Goron框架控制流平坦化的实现原理


goron使用的控制流平坦化是ollvm原生的

### 一、控制流平坦化实现逻辑

#### 1.1 生成SCRAMBLER
```c&#43;&#43;
// SCRAMBLER
char scrambling_key[16];
llvm::cryptoutils-&gt;get_bytes(scrambling_key, 16);
// END OF SCRAMBLER
```

#### 1.2 调用Lower switch
```c&#43;&#43;
// Lower switch
#if LLVM_VERSION_MAJOR * 10 &#43; LLVM_VERSION_MINOR &gt;= 90
  FunctionPass *lower = createLegacyLowerSwitchPass();
#else
  FunctionPass *lower = createLowerSwitchPass();
#endif
  lower-&gt;runOnFunction(*f);

bool LowerSwitch::runOnFunction(Function &amp;F) {
  bool Changed = false;
  SmallPtrSet&lt;BasicBlock*, 8&gt; DeleteList;

    // 遍历function获取基本块
  for (Function::iterator I = F.begin(), E = F.end(); I != E; ) {
    BasicBlock *Cur = &amp;*I&#43;&#43;; // Advance over block so we don&#39;t traverse new blocks

    // If the block is a dead Default block that will be deleted later, don&#39;t
    // waste time processing it.
    if (DeleteList.count(Cur))
      continue;

    // 如果块的末尾指令是switch指令，则需要处理
    if (SwitchInst *SI = dyn_cast&lt;SwitchInst&gt;(Cur-&gt;getTerminator())) {
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
```c&#43;&#43;
// Save all original BB
  for (Function::iterator i = f-&gt;begin(); i != f-&gt;end(); &#43;&#43;i) {
    BasicBlock *tmp = &amp;*i;
    origBB.push_back(tmp);

    BasicBlock *bb = &amp;*i;
    if (isa&lt;InvokeInst&gt;(bb-&gt;getTerminator())) {
      return false;
    }
  }
```

#### 1.4 第一个基本块处理 
```c&#43;&#43;
// Remove first BB 
// 删除第一个块并做一些处理
  origBB.erase(origBB.begin());

  // Get a pointer on the first BB
//   获取第一个块指针
  Function::iterator tmp = f-&gt;begin();  //&#43;&#43;tmp;
  BasicBlock *insert = &amp;*tmp;

  // If main begin with an if
  BranchInst *br = NULL;
  if (isa&lt;BranchInst&gt;(insert-&gt;getTerminator())) {
    br = cast&lt;BranchInst&gt;(insert-&gt;getTerminator());
  }

    // 如果块末尾是条件指令或者后继块有多个，都需要单独切割出来
  if ((br != NULL &amp;&amp; br-&gt;isConditional()) ||
      insert-&gt;getTerminator()-&gt;getNumSuccessors() &gt; 1) {
    BasicBlock::iterator i = insert-&gt;end();
	--i;

    if (insert-&gt;size() &gt; 1) {
      --i;
    }

    // 将条件跳转的语句切割出来，成为一个新的基本块，并插入到vector开头
    BasicBlock *tmpBB = insert-&gt;splitBasicBlock(i, &#34;first&#34;);
    origBB.insert(origBB.begin(), tmpBB);
  }

  // Remove jump
//   删除第一个基本块最后的末尾跳转
  insert-&gt;getTerminator()-&gt;eraseFromParent();
```
因为平坦化要求第一个基本块只能有一个后继基本块，如果第一个基本块末尾就是条件跳转（有两个或多个后继块）就无法进行后面的平坦化操作

#### 1.5 创建switch变量并设置初始值
```c&#43;&#43;
// Create switch variable and set as it
switchVar =
    new AllocaInst(Type::getInt32Ty(f-&gt;getContext()), 0, &#34;switchVar&#34;, insert);
// 首先设置初始值
new StoreInst(
    ConstantInt::get(Type::getInt32Ty(f-&gt;getContext()),
                    llvm::cryptoutils-&gt;scramble32(0, scrambling_key)),
    switchVar, insert);
```

#### 1.6 基本骨架设置
```c&#43;&#43;
// Create main loop
// 创建loopEntry、loopEntry两个基本块
loopEntry = BasicBlock::Create(f-&gt;getContext(), &#34;loopEntry&#34;, f, insert);
loopEnd = BasicBlock::Create(f-&gt;getContext(), &#34;loopEnd&#34;, f, insert);

// load switchVar 变量
load = new LoadInst(switchVar, &#34;switchVar&#34;, loopEntry);

// Move first BB on top
insert-&gt;moveBefore(loopEntry);
// 构建顺序insert-&gt;loopEntry

BranchInst::Create(loopEntry, insert);

// loopEnd jump to loopEntry
// 构建顺序loopEnd-&gt;loopEntry
BranchInst::Create(loopEntry, loopEnd);

BasicBlock *swDefault =
    BasicBlock::Create(f-&gt;getContext(), &#34;switchDefault&#34;, f, loopEnd);
// 构建swDefault-&gt;loopEnd
BranchInst::Create(loopEnd, swDefault);

// Create switch instruction itself and set condition
switchI = SwitchInst::Create(&amp;*f-&gt;begin(), swDefault, 0, loopEntry);
switchI-&gt;setCondition(load);

// Remove branch jump from 1st BB and make a jump to the while
f-&gt;begin()-&gt;getTerminator()-&gt;eraseFromParent();

// 构建顺序第一个块到loopEntry
BranchInst::Create(loopEntry, &amp;*f-&gt;begin());
```
整体顺序就是第一个块-&gt;loopEntry，swDefault-&gt;loopEnd，loopEnd-&gt;loopEntry

#### 1.7 装入基本块
```c&#43;&#43;
// Put all BB in the switch
    // 遍历每个块
  for (vector&lt;BasicBlock *&gt;::iterator b = origBB.begin(); b != origBB.end();
       &#43;&#43;b) {
    BasicBlock *i = *b;
    ConstantInt *numCase = NULL;

    // 块放在loopEnd前面
    // Move the BB inside the switch (only visual, no code logic)
    i-&gt;moveBefore(loopEnd);
    // 设置随机值并加入到switch结构中
    // Add case to switch
    numCase = cast&lt;ConstantInt&gt;(ConstantInt::get(
        switchI-&gt;getCondition()-&gt;getType(),
        llvm::cryptoutils-&gt;scramble32(switchI-&gt;getNumCases(), scrambling_key)));
    switchI-&gt;addCase(numCase, i);
  } 
```
这里只是单纯的将块和随机变量绑定，并没有指定块的跳转顺序，下面要开始调整基本块之间的关系了

#### 1.8 计算switchVar
遍历每个块，分别对不同类型的块做处理，这里有三种情况

##### 1.8.1 无后继基本块
```c&#43;&#43;
// Ret BB
if (i-&gt;getTerminator()-&gt;getNumSuccessors() == 0) {
  continue;
}
```
如果这个块的末尾指令没有后继，则表明这个块是结束块，无需再回到分发器
##### 1.8.2 无条件跳转结尾基本块
```c&#43;&#43;
// If it&#39;s a non-conditional jump
// 如果这个块末尾指令不是条件指令
if (i-&gt;getTerminator()-&gt;getNumSuccessors() == 1) {
    // Get successor and delete terminator
    // 获取后继基本块
    BasicBlock *succ = i-&gt;getTerminator()-&gt;getSuccessor(0);
    // 删除该块到后继块的跳转
    i-&gt;getTerminator()-&gt;eraseFromParent();

    // Get next case
    // 获取后继基本块的case值
    numCase = switchI-&gt;findCaseDest(succ);

    // 如果case为空，表示是default分支
    // If next case == default case (switchDefault)
    if (numCase == NULL) {
    numCase = cast&lt;ConstantInt&gt;(
        ConstantInt::get(switchI-&gt;getCondition()-&gt;getType(),
                            llvm::cryptoutils-&gt;scramble32(
                                switchI-&gt;getNumCases() - 1, scrambling_key)));
    }

    // numCase = MySecret - (MySecret - numCase)
    // X = MySecret - numCase
    Constant *X;
    if (SecretInfo) {
    X = ConstantExpr::getSub(SecretInfo-&gt;SecretCI, numCase);
    } else {
    X = ConstantExpr::getSub(Zero, numCase);
    }
    // 获取真实case值
    Value *newNumCase = BinaryOperator::Create(Instruction::Sub, MySecret, X, &#34;&#34;, i);

    // Update switchVar and jump to the end of loop
    // 末尾更新switchVar值
    new StoreInst(newNumCase, load-&gt;getPointerOperand(), i);
    // 跳转到loopEnd
    BranchInst::Create(loopEnd, i);
    continue;
}
```
##### 1.8.3 条件跳转结尾基本块
```c&#43;&#43;
// If it&#39;s a conditional jump
// 如果末尾指令是分支指令
if (i-&gt;getTerminator()-&gt;getNumSuccessors() == 2) {
    // Get next cases
    // 获取两个后继的case值
    ConstantInt *numCaseTrue =
        switchI-&gt;findCaseDest(i-&gt;getTerminator()-&gt;getSuccessor(0));
    ConstantInt *numCaseFalse =
        switchI-&gt;findCaseDest(i-&gt;getTerminator()-&gt;getSuccessor(1));

    // 判断defalut的情况
    // Check if next case == default case (switchDefault)
    if (numCaseTrue == NULL) {
    numCaseTrue = cast&lt;ConstantInt&gt;(
        ConstantInt::get(switchI-&gt;getCondition()-&gt;getType(),
                            llvm::cryptoutils-&gt;scramble32(
                                switchI-&gt;getNumCases() - 1, scrambling_key)));
    }

    if (numCaseFalse == NULL) {
    numCaseFalse = cast&lt;ConstantInt&gt;(
        ConstantInt::get(switchI-&gt;getCondition()-&gt;getType(),
                            llvm::cryptoutils-&gt;scramble32(
                                switchI-&gt;getNumCases() - 1, scrambling_key)));
    }

    // 获取真实值
    Constant *X, *Y;
    if (SecretInfo) {
    X = ConstantExpr::getSub(SecretInfo-&gt;SecretCI, numCaseTrue);
    Y = ConstantExpr::getSub(SecretInfo-&gt;SecretCI, numCaseFalse);
    } else {
    X = ConstantExpr::getSub(Zero, numCaseTrue);
    Y = ConstantExpr::getSub(Zero, numCaseFalse);
    }
    Value *newNumCaseTrue = BinaryOperator::Create(Instruction::Sub, MySecret, X, &#34;&#34;, i-&gt;getTerminator());
    Value *newNumCaseFalse = BinaryOperator::Create(Instruction::Sub, MySecret, Y, &#34;&#34;, i-&gt;getTerminator());

    // Create a SelectInst
    // 构造条件指令
    BranchInst *br = cast&lt;BranchInst&gt;(i-&gt;getTerminator());
    SelectInst *sel =
        SelectInst::Create(br-&gt;getCondition(), newNumCaseTrue, newNumCaseFalse, &#34;&#34;,
                            i-&gt;getTerminator());

    // Erase terminator
    // 删除结尾跳转指令
    i-&gt;getTerminator()-&gt;eraseFromParent();

    // Update switchVar and jump to the end of loop
    // 末尾添加条件指令
    new StoreInst(sel, load-&gt;getPointerOperand(), i);
    // 跳转到loopEnd
    BranchInst::Create(loopEnd, i);
    continue;
}
}
```

#### 1.9 栈修复
```c&#43;&#43;
void fixStack(Function *f) {
  // Try to remove phi node and demote reg to stack
  std::vector&lt;PHINode *&gt; tmpPhi;
  std::vector&lt;Instruction *&gt; tmpReg;
  BasicBlock *bbEntry = &amp;*f-&gt;begin();

  do {
    tmpPhi.clear();
    tmpReg.clear();

    for (Function::iterator i = f-&gt;begin(); i != f-&gt;end(); &#43;&#43;i) {

      for (BasicBlock::iterator j = i-&gt;begin(); j != i-&gt;end(); &#43;&#43;j) {

        if (isa&lt;PHINode&gt;(j)) {
          PHINode *phi = cast&lt;PHINode&gt;(j);
          tmpPhi.push_back(phi);
          continue;
        }
        if (!(isa&lt;AllocaInst&gt;(j) &amp;&amp; j-&gt;getParent() == bbEntry) &amp;&amp;
            (valueEscapes(&amp;*j) || j-&gt;isUsedOutsideOfBlock(&amp;*i))) {
          tmpReg.push_back(&amp;*j);
          continue;
        }
      }
    }
    for (unsigned int i = 0; i != tmpReg.size(); &#43;&#43;i) {
      DemoteRegToStack(*tmpReg.at(i), f-&gt;begin()-&gt;getTerminator());
    }

    for (unsigned int i = 0; i != tmpPhi.size(); &#43;&#43;i) {
      DemotePHIToStack(tmpPhi.at(i), f-&gt;begin()-&gt;getTerminator());
    }

  } while (tmpReg.size() != 0 || tmpPhi.size() != 0);
}
```

### 二、总结
1. 调用lower switch去除当前函数的switch结构
2. 保存所有块并单独刨除第一个块
3. 创建switch变量并设置初始值
4. 设置基本骨架frist-&gt;loopEntry-&gt;switch-&gt;loopEnd-&gt;loopEntry
5. 装入基本块
6. 重新计算switchVar
7. 栈修复

---

> 作者: tcc0lin  
> URL: http://localhost:1313/posts/ollvm%E6%B7%B7%E6%B7%86%E4%B8%8E%E5%8F%8D%E6%B7%B7%E6%B7%86-goron%E6%A1%86%E6%9E%B6%E6%8E%A7%E5%88%B6%E6%B5%81%E5%B9%B3%E5%9D%A6%E5%8C%96%E7%9A%84%E5%AE%9E%E7%8E%B0%E5%8E%9F%E7%90%86/  

