其实只要接触过 Linux 内核源码的人都应该见过 `current` 的东西，它很多时候表示指向当前进程的 `task_struct` 结构（当然这个不是绝对的）

被关小黑屋了几天了，闲的无聊

废话少说（好吧，反正也没有人看，我自言自语）

现在就来看看 `current` 真正的样子

via：https://code.woboq.org/linux/linux/arch/x86/include/asm/current.h.html#_M/current

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

对于这个 `DECLARE_PER_CPU(struct task_struct *, current_task);` 的解释，我只能那么描述：为 CPU 创建 一个 名为 current_task 的 `struct task_struct *`  类型的  `per_cpu` 变量（ CPU私有变量）

可以看到 current 是个宏，真正调用的是 get_current 函数（可以看到返回值是一个 task_struct *）

然后 get_current 函数调用 this_cpu_read_stable

via：https://code.woboq.org/linux/linux/arch/x86/include/asm/percpu.h.html#392

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

在 x86 体系下，所以 `sizeof(current_task)` 的值为 ` 4`

对应的是：

```c
		asm(op "l "__percpu_arg(P1)",%0"	\
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

这里就是终点了 意思是 

在 X86_64 体系下面是 `gs`  ; mov 操作指令是 `movq`

否则的话 就是  `fs`  ; mov 操作指令是 `movl`

现在看来就是一直在拼接字符，完整的代码是：

```c
asm(movl "%%fs:%P1","%0" : "=r" (var) :"p" (&(var)) 
```



其实刚刚看的时候我没有看明白为什么是从 fs 存的地址拿指向当前 task_struct 的指针

这个东西今天大概看了一下，其实在进程切换的时候就有把当前进程的 task_struct 的地址放到 fs 寄存器里面

这个操作是在 switch_to() 和 __switch_to() 里面

调用链是 ：

schedule()

via：https://elixir.bootlin.com/linux/v5.6.6/source/kernel/sched/core.c#L4146



__schedule()

via：https://elixir.bootlin.com/linux/v5.6.6/source/kernel/sched/core.c#L3999



context_switch()

Via：https://elixir.bootlin.com/linux/v5.6.6/source/kernel/sched/core.c#L3329



重点就在这里，动态调试的话可以断在 context_switch 然后单步 ，因为 switch_to 是一个宏

switch_to(prev, next, prev);

via：https://elixir.bootlin.com/linux/v5.6.6/source/arch/x86/include/asm/switch_to.h#L68

```c
#define switch_to(prev, next, last)					\
do {									\
	prepare_switch_to(next);					\
									\
	((last) = __switch_to_asm((prev), (next)));			\
} while (0)
```

 prepare_switch_to(struct task_struct *next) 读取要切换到的进程的 sp 寄存器内容

```c
static inline void prepare_switch_to(struct task_struct *next)
{
#ifdef CONFIG_VMAP_STACK
	/*
	 * If we switch to a stack that has a top-level paging entry
	 * that is not present in the current mm, the resulting #PF will
	 * will be promoted to a double-fault and we'll panic.  Probe
	 * the new stack now so that vmalloc_fault can fix up the page
	 * tables if needed.  This can only happen if we use a stack
	 * in vmap space.
	 *
	 * We assume that the stack is aligned so that it never spans
	 * more than one top-level paging entry.
	 *
	 * To minimize cache pollution, just follow the stack pointer.
	 */
	READ_ONCE(*(unsigned char *)next->thread.sp);
#endif
}
```



真正的 上下文寄存器 操作

__switch_to_asm

via：https://elixir.bootlin.com/linux/v5.6.6/source/arch/x86/entry/entry_32.S#L733

```asm
/*
 * %eax: prev task
 * %edx: next task
 */
 /* 可以看到，这里的注释 
  * eax 存的的是 现在运行的进程的 task_struct 的地址
  * edx 存的的是 要切换到的进程的 task_struct 的地址
  */
SYM_CODE_START(__switch_to_asm)
	/*
	 * Save callee-saved registers
	 * This must match the order in struct inactive_task_frame
	 */
	 /* 将 prev task 的 ebp、ebx、edi、esi、eflags 寄存器值压入 prev task 的内核栈。*/
	pushl	%ebp
	pushl	%ebx
	pushl	%edi
	pushl	%esi
	/*
	 * Flags are saved to prevent AC leakage. This could go
	 * away if objtool would have 32bit support to verify
	 * the STAC/CLAC correctness.
	 */
	pushfl

	/* switch stack */
	/* TASK_threadsp 是从 task_struct -> thread_struct -> sp 获取 esp 指针 */
	movl	%esp, TASK_threadsp(%eax)
	movl	TASK_threadsp(%edx), %esp

#ifdef CONFIG_STACKPROTECTOR
	movl	TASK_stack_canary(%edx), %ebx
	movl	%ebx, PER_CPU_VAR(stack_canary)+stack_canary_offset
#endif

#ifdef CONFIG_RETPOLINE
	/*
	 * When switching from a shallower to a deeper call stack
	 * the RSB may either underflow or use entries populated
	 * with userspace addresses. On CPUs where those concerns
	 * exist, overwrite the RSB with entries which capture
	 * speculative execution to prevent attack.
	 */
	FILL_RETURN_BUFFER %ebx, RSB_CLEAR_LOOPS, X86_FEATURE_RSB_CTXSW
#endif

	/* Restore flags or the incoming task to restore AC state. */
	popfl
	/* restore callee-saved registers */
	popl	%esi
	popl	%edi
	popl	%ebx
	popl	%ebp

	jmp	__switch_to
SYM_CODE_END(__switch_to_asm)
```

这是反编译出来的（x64）：

```asm
Dump of assembler code for function __switch_to_asm:
=> 0xffffffff81c00170 <+0>:	push   rbp
   0xffffffff81c00171 <+1>:	push   rbx
   0xffffffff81c00172 <+2>:	push   r12
   0xffffffff81c00174 <+4>:	push   r13
   0xffffffff81c00176 <+6>:	push   r14
   0xffffffff81c00178 <+8>:	push   r15
   0xffffffff81c0017a <+10>:	mov    QWORD PTR [rdi+0x1318],rsp
   0xffffffff81c00181 <+17>:	mov    rsp,QWORD PTR [rsi+0x1318]
   0xffffffff81c00188 <+24>:	mov    rbx,QWORD PTR [rsi+0x8b8]
   0xffffffff81c0018f <+31>:	mov    QWORD PTR gs:0x28,rbx
   0xffffffff81c00198 <+40>:	mov    r12,0x10
   0xffffffff81c0019f <+47>:	call   0xffffffff81c001ab <__switch_to_asm+59>
   0xffffffff81c001a4 <+52>:	pause  
   0xffffffff81c001a6 <+54>:	lfence 
   0xffffffff81c001a9 <+57>:	jmp    0xffffffff81c001a4 <__switch_to_asm+52>
   0xffffffff81c001ab <+59>:	call   0xffffffff81c001b7 <__switch_to_asm+71>
   0xffffffff81c001b0 <+64>:	pause  
   0xffffffff81c001b2 <+66>:	lfence 
   0xffffffff81c001b5 <+69>:	jmp    0xffffffff81c001b0 <__switch_to_asm+64>
   0xffffffff81c001b7 <+71>:	dec    r12
   0xffffffff81c001ba <+74>:	jne    0xffffffff81c0019f <__switch_to_asm+47>
   0xffffffff81c001bc <+76>:	add    rsp,0x100
   0xffffffff81c001c3 <+83>:	pop    r15
   0xffffffff81c001c5 <+85>:	pop    r14
   0xffffffff81c001c7 <+87>:	pop    r13
   0xffffffff81c001c9 <+89>:	pop    r12
   0xffffffff81c001cb <+91>:	pop    rbx
   0xffffffff81c001cc <+92>:	pop    rbp
   0xffffffff81c001cd <+93>:	jmp    0xffffffff810307d0 <__switch_to>
End of assembler dump.
```



最后一条指令 jmp __switch_to 跳到  \_\_switch_to，这里就有我们要的答案了

Via：https://elixir.bootlin.com/linux/v5.6.6/source/arch/x86/kernel/process_32.c#L159

```c
__visible __notrace_funcgraph struct task_struct *
__switch_to(struct task_struct *prev_p, struct task_struct *next_p)
{
	struct thread_struct *prev = &prev_p->thread,
			     *next = &next_p->thread;
	struct fpu *prev_fpu = &prev->fpu;
	struct fpu *next_fpu = &next->fpu;
	int cpu = smp_processor_id();

	/* never put a printk in __switch_to... printk() calls wake_up*() indirectly */

	if (!test_thread_flag(TIF_NEED_FPU_LOAD))
		switch_fpu_prepare(prev_fpu, cpu);

	/*
	 * Save away %gs. No need to save %fs, as it was saved on the
	 * stack on entry.  No need to save %es and %ds, as those are
	 * always kernel segments while inside the kernel.  Doing this
	 * before setting the new TLS descriptors avoids the situation
	 * where we temporarily have non-reloadable segments in %fs
	 * and %gs.  This could be an issue if the NMI handler ever
	 * used %fs or %gs (it does not today), or if the kernel is
	 * running inside of a hypervisor layer.
	 */
	lazy_save_gs(prev->gs);

	/*
	 * Load the per-thread Thread-Local Storage descriptor.
	 */
	load_TLS(next, cpu);

	switch_to_extra(prev_p, next_p);

	/*
	 * Leave lazy mode, flushing any hypercalls made here.
	 * This must be done before restoring TLS segments so
	 * the GDT and LDT are properly updated.
	 */
	arch_end_context_switch(next_p);

	/*
	 * Reload esp0 and cpu_current_top_of_stack.  This changes
	 * current_thread_info().  Refresh the SYSENTER configuration in
	 * case prev or next is vm86.
	 */
	update_task_stack(next_p);
	refresh_sysenter_cs(next);
	this_cpu_write(cpu_current_top_of_stack,
		       (unsigned long)task_stack_page(next_p) +
		       THREAD_SIZE);

	/*
	 * Restore %gs if needed (which is common)
	 */
	if (prev->gs | next->gs)
		lazy_load_gs(next->gs);

	this_cpu_write(current_task, next_p);

	switch_fpu_finish(next_fpu);

	/* Load the Intel cache allocation PQR MSR. */
	resctrl_sched_in();

	return prev_p;
}
```

懒得扒 `define` ,直接动态调试然后 disassmble（直接看编译出来的汇编，emmmm，好像有点狂）

不对，突然想起来我没有 32 位的内核，算了，道理都一样，贴上来

gdb 断下来

![image-20200426224007390](__switch_to.png)

上汇编：

```asm
Dump of assembler code for function __switch_to:
   0xffffffff810307d0 <+0>:	push   rbp
=> 0xffffffff810307d1 <+1>:	mov    rax,QWORD PTR gs:0x18bc0
   0xffffffff810307da <+10>:	mov    rbp,rsp
   0xffffffff810307dd <+13>:	push   r15
   0xffffffff810307df <+15>:	push   r14
   0xffffffff810307e1 <+17>:	push   r13
   0xffffffff810307e3 <+19>:	push   r12
   0xffffffff810307e5 <+21>:	lea    r14,[rdi+0x1300]
   0xffffffff810307ec <+28>:	push   rbx
   0xffffffff810307ed <+29>:	mov    r12,rdi
   0xffffffff810307f0 <+32>:	mov    rbx,rsi
   0xffffffff810307f3 <+35>:	lea    r13,[rsi+0x1300]
   0xffffffff810307fa <+42>:	sub    rsp,0x10
   0xffffffff810307fe <+46>:	mov    rdx,QWORD PTR [rax]
   0xffffffff81030801 <+49>:	mov    r15d,DWORD PTR gs:[rip+0x7efe1b57]        # 0x12360 <cpu_number>
   0xffffffff81030809 <+57>:	and    dh,0x40
   0xffffffff8103080c <+60>:	je     0xffffffff81030ad1 <__switch_to+769>
   0xffffffff81030812 <+66>:	mov    ax,fs
   0xffffffff81030815 <+69>:	mov    WORD PTR [r12+0x1324],ax
   0xffffffff8103081e <+78>:	mov    ax,gs
   0xffffffff81030821 <+81>:	cmp    WORD PTR [r12+0x1324],0x0
   0xffffffff8103082b <+91>:	mov    WORD PTR [r12+0x1326],ax
   0xffffffff81030834 <+100>:	jne    0xffffffff81030bae <__switch_to+990>
   0xffffffff8103083a <+106>:	cmp    WORD PTR [r12+0x1326],0x0
   0xffffffff81030844 <+116>:	jne    0xffffffff81030b8f <__switch_to+959>
   0xffffffff8103084a <+122>:	mov    esi,r15d
   0xffffffff8103084d <+125>:	mov    rdi,r13
   0xffffffff81030850 <+128>:	call   0xffffffff810783e0 <native_load_tls>
   0xffffffff81030855 <+133>:	xchg   ax,ax
   0xffffffff81030857 <+135>:	mov    rdi,rbx
   0xffffffff8103085a <+138>:	data16 data16 xchg ax,ax
   0xffffffff8103085e <+142>:	data16 xchg ax,ax
   0xffffffff81030861 <+145>:	mov    ax,es
   0xffffffff81030864 <+148>:	mov    WORD PTR [r14+0x20],ax
   0xffffffff81030869 <+153>:	movzx  eax,WORD PTR [rbx+0x1320]
   0xffffffff81030870 <+160>:	mov    ecx,eax
   0xffffffff81030872 <+162>:	or     cx,WORD PTR [r12+0x1320]
   0xffffffff8103087b <+171>:	jne    0xffffffff81030ba0 <__switch_to+976>
   0xffffffff81030881 <+177>:	mov    ax,ds
   0xffffffff81030884 <+180>:	mov    WORD PTR [r14+0x22],ax
   0xffffffff81030889 <+185>:	movzx  eax,WORD PTR [rbx+0x1322]
   0xffffffff81030890 <+192>:	mov    esi,eax
   0xffffffff81030892 <+194>:	or     si,WORD PTR [r12+0x1322]
   0xffffffff8103089b <+203>:	jne    0xffffffff81030ba7 <__switch_to+983>
   0xffffffff810308a1 <+209>:	movzx  eax,WORD PTR [rbx+0x1324]
   0xffffffff810308a8 <+216>:	mov    rdx,QWORD PTR [rbx+0x1328]
   0xffffffff810308af <+223>:	movzx  ecx,WORD PTR [r12+0x1324]
   0xffffffff810308b8 <+232>:	cmp    ax,0x3
   0xffffffff810308bc <+236>:	ja     0xffffffff81030b88 <__switch_to+952>
   0xffffffff810308c2 <+242>:	test   rdx,rdx
   0xffffffff810308c5 <+245>:	je     0xffffffff81030a71 <__switch_to+673>
   0xffffffff810308cb <+251>:	cmp    ax,cx
   0xffffffff810308ce <+254>:	je     0xffffffff810308d2 <__switch_to+258>
   0xffffffff810308d0 <+256>:	mov    fs,eax
   0xffffffff810308d2 <+258>:	mov    esi,edx
   0xffffffff810308d4 <+260>:	mov    edi,0xc0000100
   0xffffffff810308d9 <+265>:	shr    rdx,0x20
   0xffffffff810308dd <+269>:	call   0xffffffff81078890 <native_write_msr>
   0xffffffff810308e2 <+274>:	xchg   ax,ax
   0xffffffff810308e4 <+276>:	movzx  r13d,WORD PTR [rbx+0x1326]
   0xffffffff810308ec <+284>:	mov    r14,QWORD PTR [rbx+0x1330]
   0xffffffff810308f3 <+291>:	movzx  eax,WORD PTR [r12+0x1326]
   0xffffffff810308fc <+300>:	cmp    r13w,0x3
   0xffffffff81030901 <+305>:	ja     0xffffffff81030b65 <__switch_to+917>
   0xffffffff81030907 <+311>:	test   r14,r14
   0xffffffff8103090a <+314>:	jne    0xffffffff81030aa5 <__switch_to+725>
   0xffffffff81030910 <+320>:	jmp    0xffffffff81030b51 <__switch_to+897>
   0xffffffff81030915 <+325>:	mov    edi,0x2b
   0xffffffff8103091a <+330>:	call   0xffffffff81c00f00 <native_load_gs_index>
   0xffffffff8103091f <+335>:	xchg   ax,ax
   0xffffffff81030921 <+337>:	movzx  edi,r13w
   0xffffffff81030925 <+341>:	call   0xffffffff81c00f00 <native_load_gs_index>
   0xffffffff8103092a <+346>:	xchg   ax,ax
   0xffffffff8103092c <+348>:	mov    QWORD PTR gs:[rip+0x7efe828c],rbx        # 0x18bc0 <current_task>
   0xffffffff81030934 <+356>:	mov    rax,QWORD PTR [rbx+0x18]
   0xffffffff81030938 <+360>:	add    rax,0x4000
   0xffffffff8103093e <+366>:	mov    QWORD PTR gs:[rip+0x7efd56c6],rax        # 0x600c <cpu_tss_rw+12>
   0xffffffff81030946 <+374>:	mov    r13d,DWORD PTR [rip+0x161f333]        # 0xffffffff8264fc80 <init_pkru_value>
   0xffffffff8103094d <+381>:	mov    rax,QWORD PTR gs:0x18bc0
   0xffffffff81030956 <+390>:	or     BYTE PTR ds:[rax+0x1],0x40
   0xffffffff8103095b <+395>:	jmp    0xffffffff8103099e <__switch_to+462>
   0xffffffff8103095d <+397>:	data16 xchg ax,ax
   0xffffffff81030960 <+400>:	mov    rax,QWORD PTR gs:0x18bc0
   0xffffffff81030969 <+409>:	cmp    QWORD PTR [rax+0x800],0x0
   0xffffffff81030971 <+417>:	je     0xffffffff8103098c <__switch_to+444>
   0xffffffff81030973 <+419>:	lea    rdi,[rbx+0x1400]
   0xffffffff8103097a <+426>:	mov    esi,0x9
   0xffffffff8103097f <+431>:	call   0xffffffff81040de0 <get_xsave_addr>
   0xffffffff81030984 <+436>:	test   rax,rax
   0xffffffff81030987 <+439>:	je     0xffffffff8103098c <__switch_to+444>
   0xffffffff81030989 <+441>:	mov    r13d,DWORD PTR [rax]
   0xffffffff8103098c <+444>:	xor    ecx,ecx
   0xffffffff8103098e <+446>:	rdpkru 
   0xffffffff81030991 <+449>:	cmp    eax,r13d
   0xffffffff81030994 <+452>:	je     0xffffffff8103099e <__switch_to+462>
   0xffffffff81030996 <+454>:	mov    eax,r13d
   0xffffffff81030999 <+457>:	mov    edx,ecx
   0xffffffff8103099b <+459>:	wrpkru 
   0xffffffff8103099e <+462>:	jmp    0xffffffff810309b5 <__switch_to+485>
   0xffffffff810309a0 <+464>:	data16 xchg ax,ax
   0xffffffff810309a3 <+467>:	mov    rax,QWORD PTR [rbx+0x18]
   0xffffffff810309a7 <+471>:	lea    rdi,[rax+0x4000]
   0xffffffff810309ae <+478>:	call   0xffffffff81078320 <native_load_sp0>
   0xffffffff810309b3 <+483>:	xchg   ax,ax
   0xffffffff810309b5 <+485>:	mov    rax,QWORD PTR [rbx]
   0xffffffff810309b8 <+488>:	mov    rdx,QWORD PTR [r12]
   0xffffffff810309bc <+492>:	jmp    0xffffffff81030a84 <__switch_to+692>
   0xffffffff810309c1 <+497>:	test   eax,0x2018620
   0xffffffff810309c6 <+502>:	jne    0xffffffff81030a95 <__switch_to+709>
   0xffffffff810309cc <+508>:	test   edx,0x2418e20
   0xffffffff810309d2 <+514>:	jne    0xffffffff81030a95 <__switch_to+709>
   0xffffffff810309d8 <+520>:	data16 xchg ax,ax
   0xffffffff810309db <+523>:	xchg   ax,ax
   0xffffffff810309dd <+525>:	mov    ax,ss
   0xffffffff810309e0 <+528>:	cmp    ax,0x18
   0xffffffff810309e4 <+532>:	je     0xffffffff810309ed <__switch_to+541>
   0xffffffff810309e6 <+534>:	mov    eax,0x18
   0xffffffff810309eb <+539>:	mov    ss,eax
   0xffffffff810309ed <+541>:	jmp    0xffffffff81030a5f <__switch_to+655>
   0xffffffff810309f2 <+546>:	mov    rax,0x19260
   0xffffffff810309f9 <+553>:	add    rax,QWORD PTR gs:[rip+0x7efe1967]        # 0x12368 <this_cpu_off>
   0xffffffff81030a01 <+561>:	mov    edx,DWORD PTR [rax+0xc]
   0xffffffff81030a04 <+564>:	mov    esi,DWORD PTR [rax+0x8]
   0xffffffff81030a07 <+567>:	jmp    0xffffffff81030a27 <__switch_to+599>
   0xffffffff81030a0c <+572>:	mov    rcx,QWORD PTR gs:0x18bc0
   0xffffffff81030a15 <+581>:	mov    r8d,DWORD PTR [rcx+0xcc8]
   0xffffffff81030a1c <+588>:	test   r8d,r8d
   0xffffffff81030a1f <+591>:	je     0xffffffff81030a27 <__switch_to+599>
   0xffffffff81030a21 <+593>:	mov    edx,DWORD PTR [rcx+0xcc8]
   0xffffffff81030a27 <+599>:	jmp    0xffffffff81030a45 <__switch_to+629>
   0xffffffff81030a2c <+604>:	mov    rcx,QWORD PTR gs:0x18bc0
   0xffffffff81030a35 <+613>:	mov    edi,DWORD PTR [rcx+0xccc]
   0xffffffff81030a3b <+619>:	test   edi,edi
   0xffffffff81030a3d <+621>:	je     0xffffffff81030a45 <__switch_to+629>
   0xffffffff81030a3f <+623>:	mov    esi,DWORD PTR [rcx+0xccc]
   0xffffffff81030a45 <+629>:	cmp    DWORD PTR [rax+0x4],edx
   0xffffffff81030a48 <+632>:	je     0xffffffff81030b44 <__switch_to+884>
   0xffffffff81030a4e <+638>:	mov    DWORD PTR [rax+0x4],edx
   0xffffffff81030a51 <+641>:	mov    DWORD PTR [rax],esi
   0xffffffff81030a53 <+643>:	mov    edi,0xc8f
   0xffffffff81030a58 <+648>:	call   0xffffffff81078890 <native_write_msr>
   0xffffffff81030a5d <+653>:	xchg   ax,ax
   0xffffffff81030a5f <+655>:	add    rsp,0x10
   0xffffffff81030a63 <+659>:	mov    rax,r12
   0xffffffff81030a66 <+662>:	pop    rbx
   0xffffffff81030a67 <+663>:	pop    r12
   0xffffffff81030a69 <+665>:	pop    r13
   0xffffffff81030a6b <+667>:	pop    r14
   0xffffffff81030a6d <+669>:	pop    r15
   0xffffffff81030a6f <+671>:	pop    rbp
   0xffffffff81030a70 <+672>:	ret    
   0xffffffff81030a71 <+673>:	jmp    0xffffffff81030b75 <__switch_to+933>
   0xffffffff81030a76 <+678>:	mov    edx,0x2b
   0xffffffff81030a7b <+683>:	mov    fs,edx
   0xffffffff81030a7d <+685>:	mov    fs,eax
   0xffffffff81030a7f <+687>:	jmp    0xffffffff810308e4 <__switch_to+276>
   0xffffffff81030a84 <+692>:	and    ah,0xfd
   0xffffffff81030a87 <+695>:	and    dh,0xfd
   0xffffffff81030a8a <+698>:	test   eax,0x2018620
   0xffffffff81030a8f <+703>:	je     0xffffffff810309cc <__switch_to+508>
   0xffffffff81030a95 <+709>:	mov    rsi,rbx
   0xffffffff81030a98 <+712>:	mov    rdi,r12
   0xffffffff81030a9b <+715>:	call   0xffffffff8103e430 <__switch_to_xtra>
   0xffffffff81030aa0 <+720>:	jmp    0xffffffff810309d8 <__switch_to+520>
   0xffffffff81030aa5 <+725>:	cmp    r13w,ax
   0xffffffff81030aa9 <+729>:	je     0xffffffff81030ab6 <__switch_to+742>
   0xffffffff81030aab <+731>:	movzx  edi,r13w
   0xffffffff81030aaf <+735>:	call   0xffffffff81c00f00 <native_load_gs_index>
   0xffffffff81030ab4 <+740>:	xchg   ax,ax
   0xffffffff81030ab6 <+742>:	mov    rdx,r14
   0xffffffff81030ab9 <+745>:	mov    esi,r14d
   0xffffffff81030abc <+748>:	mov    edi,0xc0000102
   0xffffffff81030ac1 <+753>:	shr    rdx,0x20
   0xffffffff81030ac5 <+757>:	call   0xffffffff81078890 <native_write_msr>
   0xffffffff81030aca <+762>:	xchg   ax,ax
   0xffffffff81030acc <+764>:	jmp    0xffffffff8103092c <__switch_to+348>
   0xffffffff81030ad1 <+769>:	test   BYTE PTR [rax+0x26],0x20
   0xffffffff81030ad5 <+773>:	jne    0xffffffff81030812 <__switch_to+66>
   0xffffffff81030adb <+779>:	lea    rax,[rdi+0x13c0]
   0xffffffff81030ae2 <+786>:	mov    QWORD PTR [rbp-0x38],rax
   0xffffffff81030ae6 <+790>:	jmp    0xffffffff81030c0b <__switch_to+1083>
   0xffffffff81030aeb <+795>:	mov    r9d,DWORD PTR [rip+0x182cf66]        # 0xffffffff8285da58 <alternatives_patched>
   0xffffffff81030af2 <+802>:	lea    rdi,[r12+0x1400]
   0xffffffff81030afa <+810>:	test   r9d,r9d
   0xffffffff81030afd <+813>:	je     0xffffffff81030c1f <__switch_to+1103>
   0xffffffff81030b03 <+819>:	mov    eax,0xffffffff
   0xffffffff81030b08 <+824>:	mov    edx,eax
   0xffffffff81030b0a <+826>:	xsave64 [rdi]
   0xffffffff81030b0e <+830>:	xor    eax,eax
   0xffffffff81030b10 <+832>:	test   eax,eax
   0xffffffff81030b12 <+834>:	jne    0xffffffff81030c18 <__switch_to+1096>
   0xffffffff81030b18 <+840>:	test   BYTE PTR [r12+0x1600],0xe0
   0xffffffff81030b21 <+849>:	je     0xffffffff81030b32 <__switch_to+866>
   0xffffffff81030b23 <+851>:	mov    rax,QWORD PTR [rip+0x15d44d6]        # 0xffffffff82605000 <jiffies_64>
   0xffffffff81030b2a <+858>:	mov    QWORD PTR [r12+0x13c8],rax
   0xffffffff81030b32 <+866>:	mov    DWORD PTR [r12+0x13c0],r15d
   0xffffffff81030b3a <+874>:	data16 data16 data16 xchg ax,ax
   0xffffffff81030b3f <+879>:	jmp    0xffffffff81030812 <__switch_to+66>
   0xffffffff81030b44 <+884>:	cmp    DWORD PTR [rax],esi
   0xffffffff81030b46 <+886>:	jne    0xffffffff81030a4e <__switch_to+638>
   0xffffffff81030b4c <+892>:	jmp    0xffffffff81030a5f <__switch_to+655>
   0xffffffff81030b51 <+897>:	or     eax,r13d
   0xffffffff81030b54 <+900>:	movzx  eax,ax
   0xffffffff81030b57 <+903>:	or     rax,QWORD PTR [r12+0x1330]
   0xffffffff81030b5f <+911>:	je     0xffffffff8103092c <__switch_to+348>
   0xffffffff81030b65 <+917>:	movzx  edi,r13w
   0xffffffff81030b69 <+921>:	call   0xffffffff81c00f00 <native_load_gs_index>
   0xffffffff81030b6e <+926>:	xchg   ax,ax
   0xffffffff81030b70 <+928>:	jmp    0xffffffff8103092c <__switch_to+348>
   0xffffffff81030b75 <+933>:	or     ecx,eax
   0xffffffff81030b77 <+935>:	movzx  ecx,cx
   0xffffffff81030b7a <+938>:	or     rcx,QWORD PTR [r12+0x1328]
   0xffffffff81030b82 <+946>:	je     0xffffffff810308e4 <__switch_to+276>
   0xffffffff81030b88 <+952>:	mov    fs,eax
   0xffffffff81030b8a <+954>:	jmp    0xffffffff810308e4 <__switch_to+276>
   0xffffffff81030b8f <+959>:	mov    QWORD PTR [r12+0x1330],0x0
   0xffffffff81030b9b <+971>:	jmp    0xffffffff8103084a <__switch_to+122>
   0xffffffff81030ba0 <+976>:	mov    es,eax
   0xffffffff81030ba2 <+978>:	jmp    0xffffffff81030881 <__switch_to+177>
   0xffffffff81030ba7 <+983>:	mov    ds,eax
   0xffffffff81030ba9 <+985>:	jmp    0xffffffff810308a1 <__switch_to+209>
   0xffffffff81030bae <+990>:	mov    QWORD PTR [r12+0x1328],0x0
   0xffffffff81030bba <+1002>:	jmp    0xffffffff8103083a <__switch_to+106>
   0xffffffff81030bbf <+1007>:	mov    eax,DWORD PTR gs:[rip+0x7efe179a]        # 0x12360 <cpu_number>
   0xffffffff81030bc6 <+1014>:	mov    eax,eax
   0xffffffff81030bc8 <+1016>:	bt     QWORD PTR [rip+0x1830c10],rax        # 0xffffffff828617e0 <__cpu_online_mask>
   0xffffffff81030bd0 <+1024>:	jae    0xffffffff81030812 <__switch_to+66>
   0xffffffff81030bd6 <+1030>:	mov    rax,QWORD PTR [rip+0x17f502b]        # 0xffffffff82825c08 <__tracepoint_x86_fpu_regs_deactivated+40>
   0xffffffff81030bdd <+1037>:	test   rax,rax
   0xffffffff81030be0 <+1040>:	je     0xffffffff81030c06 <__switch_to+1078>
   0xffffffff81030be2 <+1042>:	mov    rdx,QWORD PTR [rax]
   0xffffffff81030be5 <+1045>:	mov    rdi,QWORD PTR [rax+0x8]
   0xffffffff81030be9 <+1049>:	mov    QWORD PTR [rbp-0x30],rax
   0xffffffff81030bed <+1053>:	mov    rsi,QWORD PTR [rbp-0x38]
   0xffffffff81030bf1 <+1057>:	call   0xffffffff81e00e10 <__x86_indirect_thunk_rdx>
   0xffffffff81030bf6 <+1062>:	mov    rax,QWORD PTR [rbp-0x30]
   0xffffffff81030bfa <+1066>:	add    rax,0x18
   0xffffffff81030bfe <+1070>:	mov    rdx,QWORD PTR [rax]
   0xffffffff81030c01 <+1073>:	test   rdx,rdx
   0xffffffff81030c04 <+1076>:	jne    0xffffffff81030be5 <__switch_to+1045>
   0xffffffff81030c06 <+1078>:	jmp    0xffffffff81030812 <__switch_to+66>
   0xffffffff81030c0b <+1083>:	fxsave64 [rdi+0x1400]
   0xffffffff81030c13 <+1091>:	jmp    0xffffffff81030b32 <__switch_to+866>
   0xffffffff81030c18 <+1096>:	ud2    
   0xffffffff81030c1a <+1098>:	jmp    0xffffffff81030b18 <__switch_to+840>
   0xffffffff81030c1f <+1103>:	ud2    
   0xffffffff81030c21 <+1105>:	jmp    0xffffffff81030b03 <__switch_to+819>
```

