## 数据类型

跟高级语言很相似，ARM 支持对不同数据类型进行操作。

可以 `load` 和 `store` 的数据的类型分成：字（word），半字（halfwords）或字节（Byte）

![image-20200802184742065](https://gitee.com/scriptkiddies/images/raw/master/image-20200802184742065.png)

无符号后缀：`-h` （无符号半字），`-b` （无符字节）

有符号后缀：`-sh`（有符号半子）,` -sb`（有符号字节）

`word`（字）的有符号和无符号类型都是没有后缀的

注：这里的后缀指的是 指令 的后缀，详细看下面的 `load/store` 例子

![data-types-1.png.pagespeed.ce.fDcGOe6Jz-](https://gitee.com/scriptkiddies/images/raw/master/data-types-1.png.pagespeed.ce.fDcGOe6Jz--20200802184449462.png)

有符号和无符号的区别：

- 有符号数据类型可以包含正值和负值，因此在范围内较小。
- 无符号数据类型可以保存较大的正数 (包括 ' 0 ' )，但不能保存负数，因此范围更广。

这些例子是如何 load/store 数据

```
ldr = Load Word
ldrh = Load unsigned Half Word
ldrsh = Load signed Half Word
ldrb = Load unsigned Byte
ldrsb = Load signed Bytes

str = Store Word
strh = Store unsigned Half Word
strsh = Store signed Half Word
strb = Store unsigned Byte
strsb = Store signed Byte
```

## 字节序

字节序分成两种：

现在有一个字符：`ABCD` 他们对应的 `ascii` 值是：`0x41 0x42 0x43 0x44`

### 小端序：Little-Endian (LE)

在小端序机器的内存中存储着四个字母是：`0x44434241`

最低有效字节` LSB (least-significant-byte)`为会放在低地址

### 大端序：Big-Endian (BE)

在小端序机器的内存中存储着四个字母是：`0x41424344`

最高有效字节 `MSB (most-significant-byte)`放在低地址

![big-little-endian-1.png.pagespeed.ce.MrerzS_XjS](https://gitee.com/scriptkiddies/images/raw/master/big-little-endian-1.png.pagespeed.ce.MrerzS_XjS.png)

可以看的出来这两个的字节序不同之处在于对象的每个字节存储在内存中的字节顺序（`byte-order`），`ARM` 架构在 `version 3` 以前使用的是小端序（`litter-endian`），从 `version 3` 开始都是使用的大端序（`big-endian`），`ARM` 架构支持切换字节序，比如说在 `ARMv6` 上指令 [固定是小端序](http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0301h/Cdfbbchb.html) ，但是数据访问可以是小端序，也可以是大端序，由程序状态寄存器(`CPSR`) 的第 `9` 位 -- `E` 标志位控制。

## ARM 寄存器

寄存器的数量取决于 `ARM` 的版本，[ARM 参考手册上写的：除了 ARMv6-M 和 ARMv7-M 以外 ARM 架构有 30 个通用 32 位寄存器](http://infocenter.arm.com/help/topic/com.arm.doc.dui0473c/Babdfiih.html)，前 `16` 个（`r0-r15`）可以在用户模式（`user-level mode`）下使用，其他寄存器供特权模式下使用（ `ARMv6-M` 和 `ARMv7-M` 除外）。在这里我们只会解接触到 `r0-r15`

| #     | 别称  | 用途            |
|:-----:|:--- |:------------- |
| R0    | –   | 通用寄存器         |
| R1    | –   | 通用寄存器         |
| R2    | –   | 通用寄存器         |
| R3    | –   | 通用寄存器         |
| R4    | –   | 通用寄存器         |
| R5    | –   | 通用寄存器         |
| R6    | –   | 通用寄存器         |
| R7    | –   | 存放系统调用号       |
| R8    | –   | 通用寄存器         |
| R9    | –   | 通用寄存器         |
| R10   | –   | 通用寄存器         |
| R11   | FP  | 帧指针寄存器        |
| 特殊寄存器 |     |               |
| R12   | IP  | 指令指针寄存器       |
| R13   | SP  | 堆栈指针寄存器       |
| R14   | LR  | 连接寄存器（存放返回地址） |
| R15   | PC  | 程序计数器         |
| CPSR  | –   | 当前程序状态寄存器     |

与 `x86` 架构的寄存器相关联性的概览

| ARM      | Description          | x86                     |
|:--------:|:--------------------:|:-----------------------:|
| R0       | 通用寄存器                | EAX                     |
| R1-R5    | 通用寄存器                | EBX, ECX, EDX, ESI, EDI |
| R6-R10   | 通用寄存器                | –                       |
| R11 (FP) | 帧指针寄存器               | EBP                     |
| R12      | 内部程序调用寄存器            | –                       |
| R13 (SP) | 堆栈指针寄存器              | ESP                     |
| R14 (LR) | 连接寄存器（存放返回地址）        | –                       |
| R15 (PC) | <- 程序计数器 /指令指针寄存器 -> | EIP                     |
| CPSR     | 当前程序状态寄存器            | EFLAGS                  |

`r0-r12`：可以在用来存放临时数据或者地址

`r0`：可以充当算数运算的累加器，或者用于存放函数的返回值（像不像 `x86` 的 `eax`）

`r7`：在进行系统调用的时候用来存放系统调用号

`r11`：相当于 x86 的基址指针寄存器 `ebp` ，存放的是一个指向栈底的指针（因为栈是从高到低增长的，所以存的是栈的上边界地址）

`r13 (SP)`：始终指向栈顶，相当于 `x86` 中的堆栈指针寄存器 `esp`

`r14 (LR)`：当调用函数时，连接寄存器会更新为调用函数初始化的指令的下一条指令的内存地址。这样做允许程序在子函数调用结束后返回到父函数继续执行

`r15 (PC)`：程序计数器的每次的增量等于执行的指令的大小。这个大小在 `ARM` 下始终为 `4` 字节 ，在 `Thumb` 模式下始终为 `2` 字节，执行跳转指令时，`PC` 保存目的地址。在执行分支代码的过程中 `PC` 在 `ARM` 状态下存储当前指令的地址加 `8`（两个 `ARM` 指令）的地址，在 `Thumb(V1)` 状态下存储当前指令加 `4` (两个 `Thumb` 指令)的地址。这与 `x86` 不同，在 `x86` 中，`PC` 总是指向要执行的下一条指令。

`ARM` 的函数调用约定：函数的前 `4` 个参数会放到 `r0-r3`

## 当前程序状态寄存器（CPSR）

当前程序状态寄存器 (`CPSR`) 是一个 `32` 为位寄存器用来保存处理器的状态和控制信息

这个寄存器的作用相当于 `x86` 的 `EFLAGS` 寄存器

单个比特位的含义（省略了部分，详细的可以看 [这篇文章](https://www.cnblogs.com/hjbf/p/13292589.html)）：

| Bits | 标志             | 描述                                                                                       |
|:----:| -------------- |:---------------------------------------------------------------------------------------- |
| 31   | N (Negative)   | 指令运行结果为负数，则置 1                                                                           |
| 30   | Z (Zero)       | 指令运行结果为 0 ，则置 1                                                                          |
| 29   | C (Carry)      | 当运算结果导致进位，则置 1                                                                           |
| 28   | V (Overflow)   | 如果指令的结果产生的值不能用 32 位的补码表示，则置 1                                                            |
| 24   | J (Jazelle)    | 除了 ARM  和 Thumb 以外的第三种执行状态，允许某些 ARM 处理器在硬件中执行 Java 字节码                                   |
| 9    | E (Endian-bit) | 字节序控制位：置 0 时表示启用小端序，置 1 时表示启用大端序                                                         |
| 5    | T (Thumb-bit)  | ARM 模式下置 0，Thumb 模式下置 1                                                                  |
| 0-4  | M (Mode-bits)  | 表示当前的 [特权模式](https://www.keil.com/pack/doc/CMSIS/Core_A/html/group__CMSIS__CPSR__M.html) |

`CPSR` 最高 `4` 位 `N、Z、C、V`，称为条件码标志。`ARM` 的大多数指令可以条件执行的，即通过检测这些条件码标志来决定程序指令如何执行。

假设现在用 `cmp` 指令来比较 `1` 和 `2` ，`cmp` 会进行减法运算 `1 - 2 = -1` 结果为负数，这时这个运算结果就会影响到 `CPSR` 的 `N` 标志位，因为 `cmp` 的运算结果是负数所以会把 `N` 置为 `1`，如果是比较 `2` 和 `2` 运算结果是 `0` 这会置位 `Z` 标志位，但是要注意一点是 `cmp`  的执行结果不会影响它使用的寄存器只会 **隐式** 地影响 `CPSR` 寄存器的值

## 参考

via：https://azeria-labs.com/arm-data-types-and-registers-part-2/