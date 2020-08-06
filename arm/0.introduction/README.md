# ARM 汇编简介

via：https://azeria-labs.com/writing-arm-assembly-part-1/

推荐看维基百科：https://zh.wikipedia.org/zh-cn/ARM%E6%9E%B6%E6%A7%8B

## 介绍

​        欢迎来到 ARM 汇编基础系列教程。这是为后续的 ARM 利用开发系列教程做的准备。在开始创建 ARM shellcode 和构建 ROP 链之前，我们需要先介绍一些 ARM 汇编语言的基础知识。

​        为了后续的练习，您需要一个基于 ARM 的实验室环境。如果您没有 ARM 设备(如 Raspberry Pi )，您可以按照 [这个教程](https://azeria-labs.com/emulate-raspberry-pi-with-qemu/) 使用 QEMU 和 Raspberry Pi 发行版镜像在虚拟机中设置自己的实验室环境。如果您不熟悉 GDB 的基本调试，那么您可以从 [这个教程](https://azeria-labs.com/debugging-with-gdb-introduction/) 中获得基础知识。在本教程中，重点将放在 32 位 ARM 上，示例都是在 ARMv6 上编译的。

​        本教程一般是为那些想要学习 ARM 汇编基础知识的人准备的。特别是对于那些对在 ARM 平台上编写漏洞利用代码感兴趣的人。您可能已经注意到，您周围到处都是 ARM 处理器。当我环顾四周时，我可以数出我家里使用 ARM 处理器的设备比使用英特尔处理器的设备多得多。这包括电话、路由器，更不要忘了最近销量激增的物联网设备。也就是说，ARM 处理器已经成为世界上使用最广泛的 CPU 之一。这让我们认识到，与 pc 一样，物联网设备也容易受到不当输入的影响，比如缓冲区溢出。基于 ARM 的设备的广泛使用和潜在的误用，使得对这些设备的攻击变得更加普遍。

​        然而，在 x86 安全研究方面的专家比在 ARM 方面的专家多得多，尽管 ARM 汇编语言可能是广泛使用的最简单的汇编语言。那么，为什么没有更多的人关注 ARM 呢？也许是因为与 ARM 相比，存在更多 Intel 漏洞利用的学习资源。想想由 [Fuzzy Security](https://www.fuzzysecurity.com/tutorials/expDev/1.html) 或 [Corelan](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/) 团队编写的关于 Intel x86 的优秀教程——像这样的指南可以帮助对特定领域感兴趣的人获得实践知识和获得这些教程所涵盖的内容以外的知识的灵感。如果您对编写 x86 利用程序感兴趣，Corelan 和 Fuzzysec 教程是您完美的起点。在本系列教程中，我们将重点介绍 ARM 汇编基础知识和编写 ARM 利用程序。



## 对比 ARM 处理器和 intel 处理器

​        Intel 和 ARM 有很多不同，但主要的不同是指令集。Intel 是一个 CISC ( Complex Instruction Set Computing) 处理器，它有更大更丰富的指令集，拥有许多复杂的访存指令。因此，它有更多的操作，寻址模式，但寄存器比 ARM 少。CISC 处理器主要用于普通的 P C机、工作站和服务器。

​        ARM 是一个 RISC （Reduced instruction set Computing） 处理器，有一个简化指令集 （100 条或更少）和比 CISC 更通用的寄存器。与 intel 不同的是，ARM 使用的指令只能在寄存器上操作，并使用  Load/Store 内存模型 来访问内存，这意味着只有 加载/存储指令 才能访问内存。意味着递增一个 32位 的值在一个特定的内存地址的 ARM 需要三种类型的指令 (装载、增加和存储(load, increment and store) ) 首先通过变量的地址把变量的值加载到寄存器中，对寄存器中的值进行加运算，然后将寄存器中的值放回内存。

​        简化后的指令集有其优点也有其缺点。其中一个优点是可以更快地执行指令，潜在地允许更大的速度( RISC 系统通过减少每条指令的时钟周期来缩短执行时间)。缺点是较少的指令意味着更强调用有限的可用指令高效地编写软件。同样重要的是，ARM 有两种模式，ARM 模式和 Thumb 模式。Thumb 指令可以是 2 个字节也可以是 4 个字节(详见第3部分:ARM 指令集)。

 ARM和x86之间更多的区别是:

- 在ARM中，大多数指令都可以用于条件执行。
- Intel x86 和 x86-64 系列处理器使用小端序（little-endian） 格式
- 在 version 3 之前，ARM 的架构是小端序 （little-endian） 。在 version 3 后，ARM 处理器变成了大端序 （BI-endian），并提供了切换字节序的设置。

[不同 ARM 版本](https://en.wikipedia.org/wiki/List_of_ARM_microarchitectures)的命名也可能令人感到困惑:

| ARM family | ARM architecture |
| :--------: | :--------------: |
|    ARM7    |      ARM v4      |
|    ARM9    |      ARM v5      |
|   ARM11    |      ARM v6      |
|  Cortex-A  |     ARM v7-A     |
|  Cortex-R  |     ARM v7-R     |
|  Cortex-M  |     ARM v7-M     |



## 编写汇编

​         在开始深入开发 ARM exploit 之前，在您开始欣赏它之前，我们首先需要了解汇编语言编程的基础知识，这需要一点背景知识。但为什么我们需要学 ARM 汇编，难道用 “正常” 编程/脚本语言来编写我们的漏洞还不够吗？如果我们想要能够做逆向工程，理解 ARM 二进制文件的程序执行流程，构建我们自己的 ARM shellcode ，构建 ARM ROP 链，调试 ARM 应用程序，那么不会 ARM 汇编将寸步难行。

​        进行逆向工程和漏铜利用开发不需要您了解汇编语言的每一个小细节，但是其中一些是理解大局所必需的。本系列教程将介绍基础知识。如果你想了解更多，你可以访问本章末尾列出的链接。

​		那么，汇编语言到底是什么呢？汇编语言只是机器代码之上的一层薄薄的语法，机器代码是由指令组成的，这些指令用二进制表示（机器码）编码，这是我们的计算机所能理解的。我们为什么不直接写机器代码呢？嗯，那会是一个令人头疼的问题。因为这个原因，我们写汇编语言而不是机器码。ARM 汇编，对人类来说更容易理解（相对而言）。我们的计算机本身不能运行汇编代码，因为它需要机器码。我们将使用的将汇编代码组装成机器代码的工具是 [GNU Binutils](https://www.gnu.org/software/binutils/) 项目中的 GNU Assembler，用于处理扩展名为 *.s 的源文件。

一旦您编写了扩展名为 *.s 的源文件，您需要使用 [as](https://sourceware.org/binutils/docs/as/index.html#Top) 将其汇编，并用 [ld](https://sourceware.org/binutils/docs/ld/) 进行链接：

```
$ as program.s -o program.o
$ ld program.o -o program
```

![gif-assembly-to-machine-code.gif](https://gitee.com/scriptkiddies/images/raw/master/gif-assembly-to-machine-code.gif.pagespeed.ce.9OfwSzjzT0.gif)

## 汇编之下

​        让我们从最底层开始，再到汇编语言。在最底层，我们的电路中有电子信号。信号是通过切换电压到两个电平中的一个形成的，比如 0 伏特('关')或 5 伏特('开')。因为通过我们不能轻易告诉电路使用什么电压，我们选择写的开/关电压模式使用视觉表示，数字 0 和 1 ，不仅代表缺席的想法或信号，还因为 0 和 1 是二进制的数字系统。然后我们将 0 和 1 的序列组合成一个机器代码指令，它是计算机处理器的最小工作单元。下面是一个机器语言指令的例子:

1110 0001 1010 0000 0010 0000 0000 0001

​        到目前为止，一切都很好，但我们不记得这些 (0和1) 的组合是什么意思。出于这个原因，我们使用所谓的助记符、缩写来帮助我们记住这些二进制，其中每个机器代码指令都有一个名称。这些助记法通常包括三个字母，但这不是必须的。我们可以用这些助记符作为指令来编写程序。这个程序被称为汇编语言程序，用来表示计算机机器代码的助记符集被称为该计算机的汇编语言。因此，汇编语言是人类用来编写计算机程序的最低层次的语言。指令的操作数在助记符之后。下面是一个例子:

MOV R2, R1

​        既然我们知道汇编程序是由称为助记符的文本信息组成的，我们就需要把它转换成机器码。如上所述，在 ARM 环境下，[GNU Binutils](https://www.gnu.org/software/binutils/) 项目为我们提供了一个称为 as 的工具。使用像 as 这样的汇编程序将 (ARM) 汇编语言转换为 (ARM) 机器码的过程称为汇编。

​        总之，我们了解到计算机可以理解 (响应) 电压 (信号) 的存在或不存在，并且我们可以用一个包含 0 和 1 的序列来表示多个信号。我们可以使用机器码 (信号序列) 使计算机以某种明确定义的方式作出响应。因为我们不记得所有这些序列的意思，所以我们给它们写了缩写——助记符，然后用它们来表示指令。这些助记符就是是计算机的汇编语言，我们使用一个叫做汇编器的程序来将代码从助记符表示转换为计算机可读的机器码，就像编译器对高级语言所做的那样。



## 延伸阅读

Whirlwind Tour of ARM Assembly: https://www.coranac.com/tonc/text/asm.htm

ARM assembler in Raspberry Pi: http://thinkingeek.com/arm-assembler-raspberry-pi/

Practical Reverse Engineering: x86, x64, ARM, Windows Kernel, Reversing Tools, and Obfuscation by Bruce Dang, Alexandre Gazet, Elias Bachaalany and Sebastien Josse.

ARM Reference Manual: http://infocenter.arm.com/help/topic/com.arm.doc.dui0068b/index.html

Assembler User Guide: http://www.keil.com/support/man/docs/armasm/default.htm