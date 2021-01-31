浅析一下 copy_from_user

源码：Linux kernel 5.6

平台：x86_64



via: include/linux/uaccess.h

这个函数 __always_inline 

```c
static __always_inline unsigned long __must_check
copy_from_user(void *to, const void __user *from, unsigned long n)
{
	if (likely(check_copy_size(to, n, false)))
		n = _copy_from_user(to, from, n);
	return n;
}
```

via: lib/usercopy.c

_copy_from_user

```c
unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n)
{
	unsigned long res = n;
	might_fault();
	if (likely(access_ok(from, n))) {
		kasan_check_write(to, n);
		res = raw_copy_from_user(to, from, n);
	}
	if (unlikely(res))
		memset(to + (n - res), 0, res);
	return res;
}
```



```c
/*
 * Is a address valid? This does a straightforward calculation rather
 * than tests.
 *
 * Address valid if:
 *  - "addr" doesn't have any high-bits set
 *  - AND "size" doesn't have any high-bits set
 *  - AND "addr+size-(size != 0)" doesn't have any high-bits set
 *  - OR we are in kernel mode.
 */
#define __access_ok(addr, size) ({				\
	unsigned long __ao_a = (addr), __ao_b = (size);		\
	unsigned long __ao_end = __ao_a + __ao_b - !!__ao_b;	\
	(get_fs().seg & (__ao_a | __ao_b | __ao_end)) == 0; })

#define access_ok(addr, size)				\
({							\
	__chk_user_ptr(addr);				\
	__access_ok(((unsigned long)(addr)), (size));	\
})
```



asm

```asm
Dump of assembler code for function _copy_from_user:
   0xffffffff813d8560 <+0>:     push   r12
   0xffffffff813d8562 <+2>:     mov    rax,QWORD PTR gs:0x17d00 #获取 current task_struct
   0xffffffff813d856b <+11>:    push   rbp
   0xffffffff813d856c <+12>:    mov    rbp,rdi
   0xffffffff813d856f <+15>:    push   rbx
   0xffffffff813d8570 <+16>:    mov    rbx,rdx
   0xffffffff813d8573 <+19>:    mov    rdx,QWORD PTR [rax+0xa10]
   0xffffffff813d857a <+26>:    mov    rax,rsi
   0xffffffff813d857d <+29>:    add    rax,rbx
   0xffffffff813d8580 <+32>:    jb     0xffffffff813d8587 <_copy_from_user+39>
   0xffffffff813d8582 <+34>:    cmp    rdx,rax
   0xffffffff813d8585 <+37>:    jae    0xffffffff813d8597 <_copy_from_user+55>
   0xffffffff813d8587 <+39>:    mov    r12,rbx
   0xffffffff813d858a <+42>:    test   r12,r12
   0xffffffff813d858d <+45>:    jne    0xffffffff813d85a6 <_copy_from_user+70>
   0xffffffff813d858f <+47>:    mov    rax,r12
   0xffffffff813d8592 <+50>:    pop    rbx
   0xffffffff813d8593 <+51>:    pop    rbp
   0xffffffff813d8594 <+52>:    pop    r12
   0xffffffff813d8596 <+54>:    ret    
   0xffffffff813d8597 <+55>:    mov    edx,ebx
   0xffffffff813d8599 <+57>:    call   0xffffffff81b20af0 <copy_user_generic_unrolled>
   0xffffffff813d859e <+62>:    mov    r12d,eax
   0xffffffff813d85a1 <+65>:    test   r12,r12
   0xffffffff813d85a4 <+68>:    je     0xffffffff813d858f <_copy_from_user+47>
   0xffffffff813d85a6 <+70>:    sub    rbx,r12
   0xffffffff813d85a9 <+73>:    mov    rdx,r12
   0xffffffff813d85ac <+76>:    xor    esi,esi
   0xffffffff813d85ae <+78>:    lea    rdi,[rbp+rbx*1+0x0]
   0xffffffff813d85b3 <+83>:    call   0xffffffff81b23300 <memset>
   0xffffffff813d85b8 <+88>:    mov    rax,r12
   0xffffffff813d85bb <+91>:    pop    rbx
   0xffffffff813d85bc <+92>:    pop    rbp
   0xffffffff813d85bd <+93>:    pop    r12
   0xffffffff813d85bf <+95>:    ret    
End of assembler dump.
```

