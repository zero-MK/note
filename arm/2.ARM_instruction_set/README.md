# ARM & Thumb

ARM 处理器有两种主要的运行模式（除开 Jazelle 这个另类）：ARM 和 Thumb，这两个模式主要的区别在于指令长度，ARM 模式下，所有的指令都是 32 位的，Thumb 模式下主要是 16 位的（当然也可以是 32 位的）。ARM 下面的 shellcode 开发我们主要是使用 Thumb 的指令，这样可以减少遇到 NULL 字节的几率（NULL 字节会截断 payload）。

## ARM 和 Thumb 的区别

- 条件执行：ARM 下所有的指令都支持条件执行，不是所有版本的 ARM 处理器都支持 Thumb 条件执行（有的版本的处理器是通过 IT 指令实现条件执行）条件执行需要更高的代码密度，因为它
- 32 位的 ARM 和 32 位的 Thumb：32 位的 Thumb 的指令有 .w 后缀
- 桶式位移器是 ARM 模式下的另一个特点：它可以将多条指令压缩成一条，例如，进行乘法运算，原本的乘法的步骤是：对寄存器里面的值 乘 2，然后再使用 mov 指令把值存到其他寄存器。可以转换的等价的操作是进行位运算，左移 1：`mov  R1, R0, LSL #1`，相当于 `R1 = R0 * 2`



## 切换执行模式

切换执行模式需要满足下面的两个条件之一：

- 设置 CPSR 的 T 标志位切换到 Thumb 模式
- 使用 BX (branch and exchange) 指令或者 BLX (branch, link, and exchange) 指令，通过将目的寄存器的值的最低的一个比特设置成 1 ，就能切换到 Thumb 模式，例如：

```asm
.text
.global _start

_start:
     .code 32         @ ARM mode
     add r2, pc, #1   @ put PC+1 into R2
     bx r2            @ branch + exchange to R2

    .code 16          @ Thumb mode
     mov r0, #1
```

可以看到在切换到 Thumb 模式前会把 pc 的值加 1 存入 r2 ，然后执行 bx r2，这里 r2 就是目的寄存器，因为指令是按照 2 或者 4 个字节对齐的，所以最低一个比特是不会影响到执行结果的（或者可以说成最低一个比特处理器会直接忽略掉），这个位可以被当成切换 Thumb 模式的标志位。当然从 Thumb 模式回 ARM 是进行相反的模式，会把 目的寄存器 的值的最低一个比特改成 0,



# ARM 汇编指令

汇编是由指令组成的，这些指令是主要构建块，ARM 指令后面通常有一个或者两个操作数

模板：

```asm
MNEMONIC{S}{condition} {Rd}, Operand1, Operand2
```

每个字段的说明：

```
MNEMONIC               - 指令
{S}                    - 可选后缀，如果加了 S 后缀，指令的执行结果会影响 CPSR 的条件执行标志位
{condition}            - 执行指令需要满足的条件
{Rd}                   - 用于存储指令的执行结果，目的寄存器
Operand1               - 第一个操作数，一般是寄存器或者是一个立即数
Operand2               - 第二个操作数，可以是立即数和寄存器，也可以是寄存器加上位运算指令
```

Operand2 可选值：

```asm
#123                    - 立即数
Rx                      - 寄存器 x (像是 R1, R2, R3 ...)
Rx, ASR n               - 对 Rx 寄存器的值进行算数右移 n 位 (n 大于等于 1 小于等于 32)
Rx, LSL n               - 对 Rx 寄存器的值进行逻辑左移 n 位 (n 大于等于 0 小于等于 31)
Rx, LSR n               - 对 Rx 寄存器的值进行逻辑右移 n 位 (n 大于等于 1 小于等于 32)
Rx, ROR n               - 对 Rx 寄存器的值进行循环右移 n 位 (n 大于等于 1 小于等于 31)
Rx, RRX                 - 对 Rx 寄存器的值进行带扩展循环右移 1 位
```



例子：

```
ADD   R0, R1, R2         - 把 R1 的值和 R2 的值相加，把结果存入 R0 寄存器
ADD   R0, R1, #2         - 把 R1 的值和立即数 2 相加，把结果存入 R0 寄存器
MOVLE R0, #5             - 这里的 LE (Less Than or Equal) 后缀就是 {S} 字段，条件执行，当 R0 的值小于等于 5 时才会把 5 存入 R0 寄存器
MOV   R0, R1, LSL #1     - 将 R1 的值进行逻辑左移 1 ，把结果存入 R0
```



指令及其功能描述：

| 指令 |          描述          |  指令   |             描述              |
| :--: | :--------------------: | :-----: | :---------------------------: |
| MOV  |       Move data        |   EOR   |          Bitwise XOR          |
| MVN  |    Move and negate     |   LDR   |             Load              |
| ADD  |        Addition        |   STR   |             Store             |
| SUB  |      Subtraction       |   LDM   |         Load Multiple         |
| MUL  |     Multiplication     |   STM   |        Store Multiple         |
| LSL  |   Logical Shift Left   |  PUSH   |         Push on Stack         |
| LSR  |  Logical Shift Right   |   POP   |         Pop off Stack         |
| ASR  | Arithmetic Shift Right |    B    |            Branch             |
| ROR  |      Rotate Right      |   BL    |       Branch with Link        |
| CMP  |        Compare         |   BX    |      Branch and eXchange      |
| AND  |      Bitwise AND       |   BLX   | Branch with Link and eXchange |
| ORR  |       Bitwise OR       | SWI/SVC |          System Call          |

为了方便记忆，这个表我就不翻译了（学到汇编的人了，这几个英语单词应该都会的）

# 参考

via：https://azeria-labs.com/arm-instruction-set-part-3/