Linux内核源码分析 -- 中断描述符表初始化

今天看了 CSAPP （深入理解计算机系统）的异常控制流篇，直接来简单分析一下 Linux 内核的 中断描述符表 的初始化

源码版本：Linux kernel 5.6

内核启动时会在 start_kernel 里面调用 trap_init 去初始化中断向量表

以此为入口，开始分析

## start_kernel

/init/main.c

```c
	trap_init();
```

## trap_init

/arch/x86/kernel/traps.c

```c
void __init trap_init(void)
{
    .......
    
	idt_setup_traps(); // 使用默认 trap（陷阱） 初始化 中断描述符表

	/*
	 * Set the IDT descriptor to a fixed read-only location, so that the
	 * "sidt" instruction will not leak the location of the kernel, and
	 * to defend the IDT against arbitrary memory write vulnerabilities.
	 * It will be reloaded in cpu_init() */
	cea_set_pte(CPU_ENTRY_AREA_RO_IDT_VADDR, __pa_symbol(idt_table),
		    PAGE_KERNEL_RO);
	idt_descr.address = CPU_ENTRY_AREA_RO_IDT;

	/*
	 * Should be a barrier for any external CPU state:
	 */
	cpu_init();

	idt_setup_ist_traps();
    ...........
}
```

## idt_setup_traps

核心就在这里了

```c
struct idt_data { // 中断描述符表 idt 的每一个表项都由一个 idt_data 结构去描述
	unsigned int	vector;  // 中断向量
	unsigned int	segment; // 中断代码处于的代码段
	struct idt_bits	bits; // 应该是标志位
	const void	*addr; // 指向中断处理函数
};

#define G(_vector, _addr, _ist, _type, _dpl, _segment)	\
	{						\
		.vector		= _vector,		\
		.bits.ist	= _ist,			\
		.bits.type	= _type,		\
		.bits.dpl	= _dpl,			\
		.bits.p		= 1,			\
		.addr		= _addr,		\
		.segment	= _segment,		\
	}

// __KERNEL_CS 表示内核代码段

/* Interrupt gate */
// 中断陷阱
#define INTG(_vector, _addr)				\
	G(_vector, _addr, DEFAULT_STACK, GATE_INTERRUPT, DPL0, __KERNEL_CS)

/* System interrupt gate */
// 系统中断陷阱
#define SYSG(_vector, _addr)				\
	G(_vector, _addr, DEFAULT_STACK, GATE_INTERRUPT, DPL3, __KERNEL_CS)

/*
 * Interrupt gate with interrupt stack. The _ist index is the index in
 * the tss.ist[] array, but for the descriptor it needs to start at 1.
 */
// 使用中断栈（可以去看看 struct cpu_entry_area）
#define ISTG(_vector, _addr, _ist)			\
	G(_vector, _addr, _ist + 1, GATE_INTERRUPT, DPL0, __KERNEL_CS)

/* Task gate */
// 任务陷阱
#define TSKG(_vector, _gdt)				\
	G(_vector, NULL, DEFAULT_STACK, GATE_TASK, DPL0, _gdt << 3)

/* Interrupts/Exceptions */
// 中断向量，其实是一个 枚举，0~32 号由 intel 规定
enum {
    // 除 0 异常
	X86_TRAP_DE = 0,	/*  0, Divide-by-zero */ 
    // 发生调试异常
	X86_TRAP_DB,		/*  1, Debug */
	X86_TRAP_NMI,		/*  2, Non-maskable Interrupt */
    // 断点（int3）
	X86_TRAP_BP,		/*  3, Breakpoint */
    // 算术溢出
	X86_TRAP_OF,		/*  4, Overflow */
    // 越界访问
	X86_TRAP_BR,		/*  5, Bound Range Exceeded */
    // cpu 执行到无效操作码
	X86_TRAP_UD,		/*  6, Invalid Opcode */
    // 在 没有 浮点运算单元 时（或者设置了 cr0 的标志位标识  FPU/MMX/SSE 不可用）进行浮点运算
	X86_TRAP_NM,		/*  7, Device Not Available */
    // 双重异常（比如在发生异常后调用异常处理函数时又触发了异常）
	X86_TRAP_DF,		/*  8, Double Fault */
	X86_TRAP_OLD_MF,	/*  9, Coprocessor Segment Overrun */
    // TSS 无效
	X86_TRAP_TS,		/* 10, Invalid TSS */
	X86_TRAP_NP,		/* 11, Segment Not Present */
	X86_TRAP_SS,		/* 12, Stack Segment Fault */
	X86_TRAP_GP,		/* 13, General Protection Fault */
    // 缺页
	X86_TRAP_PF,		/* 14, Page Fault */
	X86_TRAP_SPURIOUS,	/* 15, Spurious Interrupt */
	X86_TRAP_MF,		/* 16, x87 Floating-Point Exception */
	X86_TRAP_AC,		/* 17, Alignment Check */
	X86_TRAP_MC,		/* 18, Machine Check */
	X86_TRAP_XF,		/* 19, SIMD Floating-Point Exception */
	X86_TRAP_IRET = 32,	/* 32, IRET Exception */
};

/*
 * The default IDT entries which are set up in trap_init() before
 * cpu_init() is invoked. Interrupt stacks cannot be used at that point and
 * the traps which use them are reinitialized with IST after cpu_init() has
 * set up TSS.
 */
static const __initconst struct idt_data def_idts[] = {
    // 每一个 INTG 就是设置一个 idt_data 表项（第一个参数是中断向量）
	INTG(X86_TRAP_DE,		divide_error),
	INTG(X86_TRAP_NMI,		nmi),
	INTG(X86_TRAP_BR,		bounds),
	INTG(X86_TRAP_UD,		invalid_op),
	INTG(X86_TRAP_NM,		device_not_available),
	INTG(X86_TRAP_OLD_MF,		coprocessor_segment_overrun),
	INTG(X86_TRAP_TS,		invalid_TSS),
	INTG(X86_TRAP_NP,		segment_not_present),
	INTG(X86_TRAP_SS,		stack_segment),
	INTG(X86_TRAP_GP,		general_protection),
	INTG(X86_TRAP_SPURIOUS,		spurious_interrupt_bug),
	INTG(X86_TRAP_MF,		coprocessor_error),
	INTG(X86_TRAP_AC,		alignment_check),
	INTG(X86_TRAP_XF,		simd_coprocessor_error),

#ifdef CONFIG_X86_32
	TSKG(X86_TRAP_DF,		GDT_ENTRY_DOUBLEFAULT_TSS),
#else
	INTG(X86_TRAP_DF,		double_fault),
#endif
	INTG(X86_TRAP_DB,		debug),

#ifdef CONFIG_X86_MCE
	INTG(X86_TRAP_MC,		&machine_check),
#endif

	SYSG(X86_TRAP_OF,		overflow),
#if defined(CONFIG_IA32_EMULATION)
	SYSG(IA32_SYSCALL_VECTOR,	entry_INT80_compat),
#elif defined(CONFIG_X86_32)
	SYSG(IA32_SYSCALL_VECTOR,	entry_INT80_32), // x86_32 的系统调用 int 0x80
#endif
};

/**
 * idt_setup_traps - Initialize the idt table with default traps
 */
void __init idt_setup_traps(void)
{
    // 使用预设的 def_idts 来设置 中断描述符表 idt_table
	idt_setup_from_table(idt_table, def_idts, ARRAY_SIZE(def_idts), true);
}
```



| Name                                                         | Vector nr.        | Type       | Mnemonic | Error code? |
| ------------------------------------------------------------ | ----------------- | ---------- | -------- | ----------- |
| [Divide-by-zero Error](https://wiki.osdev.org/Exceptions#Divide-by-zero_Error) | 0 (0x0)           | Fault      | #DE      | No          |
| [Debug](https://wiki.osdev.org/Exceptions#Debug)             | 1 (0x1)           | Fault/Trap | #DB      | No          |
| [Non-maskable Interrupt](https://wiki.osdev.org/Non_Maskable_Interrupt) | 2 (0x2)           | Interrupt  | -        | No          |
| [Breakpoint](https://wiki.osdev.org/Exceptions#Breakpoint)   | 3 (0x3)           | Trap       | #BP      | No          |
| [Overflow](https://wiki.osdev.org/Exceptions#Overflow)       | 4 (0x4)           | Trap       | #OF      | No          |
| [Bound Range Exceeded](https://wiki.osdev.org/Exceptions#Bound_Range_Exceeded) | 5 (0x5)           | Fault      | #BR      | No          |
| [Invalid Opcode](https://wiki.osdev.org/Exceptions#Invalid_Opcode) | 6 (0x6)           | Fault      | #UD      | No          |
| [Device Not Available](https://wiki.osdev.org/Exceptions#Device_Not_Available) | 7 (0x7)           | Fault      | #NM      | No          |
| [Double Fault](https://wiki.osdev.org/Exceptions#Double_Fault) | 8 (0x8)           | Abort      | #DF      | Yes (Zero)  |
| ~~[Coprocessor Segment Overrun](https://wiki.osdev.org/Exceptions#Coprocessor_Segment_Overrun)~~ | 9 (0x9)           | Fault      | -        | No          |
| [Invalid TSS](https://wiki.osdev.org/Exceptions#Invalid_TSS) | 10 (0xA)          | Fault      | #TS      | Yes         |
| [Segment Not Present](https://wiki.osdev.org/Exceptions#Segment_Not_Present) | 11 (0xB)          | Fault      | #NP      | Yes         |
| [Stack-Segment Fault](https://wiki.osdev.org/Exceptions#Stack-Segment_Fault) | 12 (0xC)          | Fault      | #SS      | Yes         |
| [General Protection Fault](https://wiki.osdev.org/Exceptions#General_Protection_Fault) | 13 (0xD)          | Fault      | #GP      | Yes         |
| [Page Fault](https://wiki.osdev.org/Exceptions#Page_Fault)   | 14 (0xE)          | Fault      | #PF      | Yes         |
| Reserved                                                     | 15 (0xF)          | -          | -        | No          |
| [x87 Floating-Point Exception](https://wiki.osdev.org/Exceptions#x87_Floating-Point_Exception) | 16 (0x10)         | Fault      | #MF      | No          |
| [Alignment Check](https://wiki.osdev.org/Exceptions#Alignment_Check) | 17 (0x11)         | Fault      | #AC      | Yes         |
| [Machine Check](https://wiki.osdev.org/Exceptions#Machine_Check) | 18 (0x12)         | Abort      | #MC      | No          |
| [SIMD Floating-Point Exception](https://wiki.osdev.org/Exceptions#SIMD_Floating-Point_Exception) | 19 (0x13)         | Fault      | #XM/#XF  | No          |
| [Virtualization Exception](https://wiki.osdev.org/Exceptions#Virtualization_Exception) | 20 (0x14)         | Fault      | #VE      | No          |
| Reserved                                                     | 21-29 (0x15-0x1D) | -          | -        | No          |
| [Security Exception](https://wiki.osdev.org/Exceptions#Security_Exception) | 30 (0x1E)         | -          | #SX      | Yes         |
| Reserved                                                     | 31 (0x1F)         | -          | -        | No          |
| [Triple Fault](https://wiki.osdev.org/Exceptions#Triple_Fault) | -                 | -          | -        | No          |
| ~~[FPU Error Interrupt](https://wiki.osdev.org/Exceptions#FPU_Error_Interrupt)~~ | IRQ 13            | Interrupt  | #FERR    | No          |



```c
static inline void idt_init_desc(gate_desc *gate, const struct idt_data *d)
{
	unsigned long addr = (unsigned long) d->addr;

	gate->offset_low	= (u16) addr;
	gate->segment		= (u16) d->segment;
	gate->bits		= d->bits;
	gate->offset_middle	= (u16) (addr >> 16);
#ifdef CONFIG_X86_64
	gate->offset_high	= (u32) (addr >> 32);
	gate->reserved		= 0;
#endif
}

#define write_idt_entry(dt, entry, g)		native_write_idt_entry(dt, entry, g)

static inline void native_write_idt_entry(gate_desc *idt, int entry, const gate_desc *gate)
{
	memcpy(&idt[entry], gate, sizeof(*gate));
}

static void
idt_setup_from_table(gate_desc *idt, const struct idt_data *t, int size, bool sys)
{
	gate_desc desc;
    
    // 循环拷贝每个表项
	for (; size > 0; t++, size--) {
		idt_init_desc(&desc, t);  // 把每个表项的数据拷贝到 desc
		write_idt_entry(idt, t->vector, &desc); // 直接使用 memcpy 拷贝，t->vector 就是 对应 desc 的中断向量，拷贝到对应的 idt 的中断向量是 t->vector 的表项
		if (sys)
			set_bit(t->vector, system_vectors);
	}
}
```



## 总结

其实开机时初始化中断描述符表（idt_table）就是从默认的描述符表（def_idts）拷贝需要的表项

## 参考

[osdev Exceptions](https://wiki.osdev.org/Exceptions)

