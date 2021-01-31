其实只要接触过 Linux 内核源码的人都应该见过 `current` 这个宏，使用它获取当前进程的 `task_struct` 结构（当然这个不是绝对的）

现在就来看看 `current` 真正的样子

```c
/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CURRENT_H
#define _ASM_X86_CURRENT_H
#include <linux/compiler.h>
#include <asm/percpu.h>
#ifndef __ASSEMBLY__
struct task_struct;
DECLARE_PER_CPU(struct task_struct *, current_task);
static __always_inline struct task_struct *get_current(void)
{
	return this_cpu_read_stable(current_task);
}
#define current get_current()

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_CURRENT_H */
```

 `DECLARE_PER_CPU(struct task_struct *, current_task);`  表示在 `.data..percpu` 数据段声明一个 名为：`current_task` 的 `struct task_struct *`

可以看到 `current` 是个宏，真正调用的是 get_current 函数 可以看到返回值是一个 task_struct *，总是 内联 ，也就是说正常编译出来不会有函数体

```c
static __always_inline struct task_struct *get_current(void)
{
	return this_cpu_read_stable(current_task);
}
```

然后 get_current 函数调用 this_cpu_read_stable

```c
#define this_cpu_read_stable(var)	percpu_stable_op("mov", var)
#define percpu_stable_op(op, var)			\
({							\
	typeof(var) pfo_ret__;				\
	switch (sizeof(var)) {				\
	case 1:						\
		asm(op "b "__percpu_arg(P1)",%0"	\
		    : "=q" (pfo_ret__)			\
		    : "p" (&(var)));			\
		break;					\
	case 2:						\
		asm(op "w "__percpu_arg(P1)",%0"	\
		    : "=r" (pfo_ret__)			\
		    : "p" (&(var)));			\
		break;					\
	case 4:						\
		asm(op "l "__percpu_arg(P1)",%0"	\
		    : "=r" (pfo_ret__)			\
		    : "p" (&(var)));			\
		break;					\
	case 8:						\
		asm(op "q "__percpu_arg(P1)",%0"	\
		    : "=r" (pfo_ret__)			\
		    : "p" (&(var)));			\
		break;					\
	default: __bad_percpu_size();			\
	}						\
	pfo_ret__;					\
})
```

在 x86-64 体系下，所以 `sizeof(current_task)` 的值为 ` 8`

对应的是：

```c
		asm(op "q "__percpu_arg(P1)",%0"	\
		    : "=r" (pfo_ret__)			\
		    : "p" (&(var)));			\
```



```c
#define __percpu_arg(x)		__percpu_prefix "%" #x
#define __percpu_prefix		"%%"__stringify(__percpu_seg)":"
#define __stringify_1(x)	#x
#define __stringify(x)		__stringify_1(x)
```

linux 最喜欢的 "万层" define 嵌套

```c
#ifdef CONFIG_X86_64
#define __percpu_seg		gs
#define __percpu_mov_op		movq
#else
#define __percpu_seg		fs
#define __percpu_mov_op		movl
#endif
```

这里就是终点了

在 X86_64 体系下面是 `gs`  ; mov 操作指令是 `movq`

否则的话 就是  `fs`  ; mov 操作指令是 `movl`

现在看来就是一直在拼接字符，宏展开就是一句汇编，完整的代码是：

```c
asm(movq "%%gs:%P1","%0" : "=r" (var) :"p" (&(var)) 
```

编译完后得到的会是像这样的

```asm
mov    rdi, QWORD PTR gs:0xXXXXXXXX
```

写个 demo 去动态调试，我选的是 `getpid`

code:

```c
#include <stdio.h>
#include <unistd.h>

int main() {
	printf("I am init\n");
	printf("my pid: %d", getpid());
	return 0;
}
```

在内核里 getpid 会在调用 __task_pid_nr_ns 前，获取 current task 的 task_struct 的地址作为参数（第一个，放入 rdi）

源码：

```c
SYSCALL_DEFINE0(getpid)
{
	return task_tgid_vnr(current);
}
static inline pid_t task_tgid_vnr(struct task_struct *tsk)
{
	return __task_pid_nr_ns(tsk, PIDTYPE_TGID, NULL);
}
pid_t __task_pid_nr_ns(struct task_struct *task, enum pid_type type,
			struct pid_namespace *ns)
{
	pid_t nr = 0;

	rcu_read_lock();
	if (!ns)
		ns = task_active_pid_ns(current);
	nr = pid_nr_ns(rcu_dereference(*task_pid_ptr(task, type)), ns);
	rcu_read_unlock();

	return nr;
}
```



静态编译，打包成 initrd

```
➜  cat init.c
#include <stdio.h>
#include <unistd.h>

int main() {
	printf("I am init\n");
	printf("my pid: %d\n", getpid());
	return 0;
}
➜  gcc -static init.c -o init
➜  ls init | cpio -o --format=newc > init.img
1652 blocks
```

调试

```
qemu-system-x86_64 -kernel arch/x86_64/boot/bzImage -append "nokaslr" -initrd init.img  -S -s
```



直接在 do_syscall_64 下硬件断点，这是 x86-64 系统调用进入内核的必经之路

getpid 的系统调用号是，39

```bash
➜  ~ cat /usr/include/asm/unistd_64.h| grep getpid
#define __NR_getpid 39
```

就一直 c 到 do_syscall_64 的参数 nr 为 39（0x27）停下

![image-20201203181407718](https://gitee.com/scriptkiddies/images/raw/master/image-20201203181407718.png)

看到：`do_syscall_64 (nr=0x27, regs=0xffffc90000013f58)`

在 `task_tgid_vnr` 下断点（其实不用在系统调用那里下断点，直接在 task_tgid_vnr 下断点也是一样可以断下来的）然后 c

![image-20201203182132339](https://gitee.com/scriptkiddies/images/raw/master/image-20201203182132339.png)

可以看到上面那两句汇编

```asm
   0xffffffff81079f97 <__x64_sys_getpid+7> mov    rdi, QWORD PTR gs:0x17d00
   0xffffffff81079fa0 <__x64_sys_getpid+16> call   0xffffffff810865f0 <__task_pid_nr_ns>
```

从 `gs:0x17d00` 处取一个 QWORD 大小的数据，放入 rdi，再调用 `__task_pid_nr_ns`，根据 x86-64 的函数调用约定，rdi 存的就是调用函数的第一个参数

__task_pid_nr_ns 的源码上面已经贴出来过了，函数原型

```c
pid_t __task_pid_nr_ns(struct task_struct *task, enum pid_type type,
			struct pid_namespace *ns)
```

传入的就是 current 的 task_struct 的地址（仔细看上面给出的代码）

```
gef➤  p $gs
$1 = 0x0
```

gs 寄存器的值是 0，看看 vmlinux， VMA 为 0 是哪个 section 的地址起始地址，其实就是 `.data..percpu`

```
➜  linux-5.6 objdump -h vmlinux                     

vmlinux:     file format elf64-x86-64

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .text         00e011c1  ffffffff81000000  0000000001000000  00200000  2**12
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, CODE
  1 .rodata       002dd0f0  ffffffff82000000  0000000002000000  01200000  2**12
                  CONTENTS, ALLOC, LOAD, RELOC, DATA
  2 .pci_fixup    00003000  ffffffff822dd0f0  00000000022dd0f0  014dd0f0  2**4
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, DATA
  3 .tracedata    00000078  ffffffff822e00f0  00000000022e00f0  014e00f0  2**0
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, DATA
  4 __ksymtab     000115b0  ffffffff822e0168  00000000022e0168  014e0168  2**2
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, DATA
  5 __ksymtab_gpl 0000e3dc  ffffffff822f1718  00000000022f1718  014f1718  2**2
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, DATA
  6 __ksymtab_strings 00032d09  ffffffff822ffaf4  00000000022ffaf4  014ffaf4  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  7 __param       00004b00  ffffffff82332800  0000000002332800  01532800  2**3
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, DATA
  8 __modver      00000080  ffffffff82337300  0000000002337300  01537300  2**3
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, DATA
  9 __ex_table    00003588  ffffffff82337380  0000000002337380  01537380  2**2
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, DATA
 10 .notes        0000003c  ffffffff8233a908  000000000233a908  0153a908  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 11 .data         0017c480  ffffffff82400000  0000000002400000  01600000  2**13
                  CONTENTS, ALLOC, LOAD, RELOC, DATA
 12 __bug_table   000184d4  ffffffff8257c480  000000000257c480  0177c480  2**0
                  CONTENTS, ALLOC, LOAD, RELOC, DATA
 13 .orc_unwind_ip 00190124  ffffffff82594954  0000000002594954  01794954  2**0
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, DATA
 14 .orc_unwind   002581b6  ffffffff82724a78  0000000002724a78  01924a78  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 15 .orc_lookup   0003804c  ffffffff8297cc30  000000000297cc30  01b7cc2e  2**0
                  ALLOC
 16 .vvar         00001000  ffffffff829b5000  00000000029b5000  01bb5000  2**4
                  CONTENTS, ALLOC, LOAD, DATA
 17 .data..percpu 0002b158  0000000000000000  00000000029b6000  01c00000  2**12
                  CONTENTS, ALLOC, LOAD, RELOC, DATA
 18 .init.text    00050049  ffffffff829e2000  00000000029e2000  01de2000  2**4
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, CODE
 19 .altinstr_aux 0000234b  ffffffff82a32049  0000000002a32049  01e32049  2**0
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, CODE
 20 .init.data    0009a410  ffffffff82a36000  0000000002a36000  01e36000  2**13
                  CONTENTS, ALLOC, LOAD, RELOC, DATA
 21 .x86_cpu_dev.init 00000028  ffffffff82ad0410  0000000002ad0410  01ed0410  2**3
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, DATA
 22 .altinstructions 000076ba  ffffffff82ad0438  0000000002ad0438  01ed0438  2**0
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, DATA
 23 .altinstr_replacement 00001dba  ffffffff82ad7af2  0000000002ad7af2  01ed7af2  2**0
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, CODE
 24 .iommu_table  000000a0  ffffffff82ad98b0  0000000002ad98b0  01ed98b0  2**3
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, DATA
 25 .apicdrivers  00000010  ffffffff82ad9950  0000000002ad9950  01ed9950  2**3
                  CONTENTS, ALLOC, LOAD, RELOC, DATA
 26 .exit.text    00001ba3  ffffffff82ad9960  0000000002ad9960  01ed9960  2**0
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, CODE
 27 .smp_locks    0000a000  ffffffff82adc000  0000000002adc000  01edc000  2**2
                  CONTENTS, ALLOC, LOAD, RELOC, READONLY, DATA
 28 .data_nosave  00001000  ffffffff82ae6000  0000000002ae6000  01ee6000  2**2
                  CONTENTS, ALLOC, LOAD, DATA
 29 .bss          00119000  ffffffff82ae7000  0000000002ae7000  01ee7000  2**12
                  ALLOC
 30 .brk          0002c000  ffffffff82c00000  0000000002c00000  01ee7000  2**0
                  ALLOC
 31 .comment      00000020  0000000000000000  0000000000000000  01ee7000  2**0
                  CONTENTS, READONLY
 32 .debug_aranges 00029ee0  0000000000000000  0000000000000000  01ee7020  2**4
                  CONTENTS, RELOC, READONLY, DEBUGGING
 33 .debug_info   0ea570ad  0000000000000000  0000000000000000  01f10f00  2**0
                  CONTENTS, RELOC, READONLY, DEBUGGING
 34 .debug_abbrev 0065b7fb  0000000000000000  0000000000000000  10967fad  2**0
                  CONTENTS, READONLY, DEBUGGING
 35 .debug_line   017c0bb1  0000000000000000  0000000000000000  10fc37a8  2**0
                  CONTENTS, RELOC, READONLY, DEBUGGING
 36 .debug_frame  002bc680  0000000000000000  0000000000000000  12784360  2**3
                  CONTENTS, RELOC, READONLY, DEBUGGING
 37 .debug_str    003f1b41  0000000000000000  0000000000000000  12a409e0  2**0
                  CONTENTS, READONLY, DEBUGGING
 38 .debug_loc    00f17248  0000000000000000  0000000000000000  12e32521  2**0
                  CONTENTS, RELOC, READONLY, DEBUGGING
 39 .debug_ranges 00fd4bd0  0000000000000000  0000000000000000  13d49770  2**4
                  CONTENTS, RELOC, READONLY, DEBUGGING
                  
 ➜  linux-5.6 objdump -h vmlinux | grep .data..percpu
 17 .data..percpu 0002b158  0000000000000000  00000000029b6000  01c00000  2**12
```

可以`.data..percpu` 的 `VMA` 为 `0` 大小为 `0x2b158`

其实当前进程的 `task_struct` 的地址会存在 `.data..percpu`，名为 `current_task`

```c
DECLARE_PER_CPU(struct task_struct *, current_task);
```

详细看：http://linux.laoqinren.net/kernel/percpu-var/

其实就能知道了 `gs` 就是指向的 `.data..percpu` 的起始地址（虚拟地址 VMA），而`.data..percpu` 的起始地址（虚拟地址 VMA）为 0，`current_task` 在 `.data..percpu` 的偏移量为 `0x17d00`



看内核导出的符号

```
➜  linux-5.6 nm vmlinux | grep current_task
0000000000017d00 D current_task
```

`D` 表示 该符号是个全局变量，放在某个数据段中

man: https://www.man7.org/linux/man-pages/man1/nm.1p.html



```
gef➤  p &current_task
$2 = (struct task_struct **) 0x17d00 <current_task>
```

看到 current_task 的地址就是 `0x17d00`，解引用就能得到当前进程的 `task_struct` 的地址（当然 gdb 不能访问这个地址的内容）

完！





