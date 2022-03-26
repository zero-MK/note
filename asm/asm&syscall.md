```c
// 不带参数的系统调用宏函数。type name(void)。
// %0 - eax(__res)，%1 - eax(__NR_##name)。其中name 是系统调用的名称，与 __NR_ 组合形成上面
// 的系统调用符号常数，从而用来对系统调用表中函数指针寻址。
// 返回：如果返回值大于等于0，则返回该值，否则置出错号errno，并返回-1。
#define _syscall0(type,name) \
type name(void) \
{ \
long __res; \
__asm__ volatile ( "int $0x80" \    // 调用系统中断0x80。
:"=a" (__res) \        // 返回值??eax(__res)。
:"" (__NR_
##name)); \            // 输入为系统中断调用号__NR_name。
      if (__res >= 0) \        // 如果返回值>=0，则直接返回该值。
      return (type) __res; errno = -__res; \    // 否则置出错号，并返回-1。
      return -1;}





// 有1 个参数的系统调用宏函数。type name(atype a)
// %0 - eax(__res)，%1 - eax(__NR_name)，%2 - ebx(a)。
#define _syscall1(type,name,atype,a) \
type name(atype a) \
{ \
long __res; \
__asm__ volatile ( "int $0x80" \
: "=a" (__res) \
: "" (__NR_##name), "b" ((long)(a))); \
if (__res >= 0) \
return (type) __res; \
errno = -__res; \
return -1; \
}





// 有2 个参数的系统调用宏函数。type name(atype a, btype b)
// %0 - eax(__res)，%1 - eax(__NR_name)，%2 - ebx(a)，%3 - ecx(b)。
#define _syscall2(type,name,atype,a,btype,b) \
type name(atype a,btype b) \
{ \
long __res; \
__asm__ volatile ( "int $0x80" \
: "=a" (__res) \
: "" (__NR_##name), "b" ((long)(a)), "c" ((long)(b))); \
if (__res >= 0) \
return (type) __res; \
errno = -__res; \
return -1; \
}






// 有3 个参数的系统调用宏函数。type name(atype a, btype b, ctype c)
// %0 - eax(__res)，%1 - eax(__NR_name)，%2 - ebx(a)，%3 - ecx(b)，%4 - edx(c)。
#define _syscall3(type,name,atype,a,btype,b,ctype,c) \
type name(atype a,btype b,ctype c) \
{ \
long __res; \
__asm__ volatile ( "int $0x80" \
: "=a" (__res) \
: "" (__NR_##name), "b" ((long)(a)), "c" ((long)(b)), "d" ((long)(c))); \
if (__res>=0) \
return (type) __res; \
errno=-__res; \
return -1; \
}
```

这三个系统调用