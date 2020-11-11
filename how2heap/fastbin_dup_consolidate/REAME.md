```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
  void* p1 = malloc(0x40);
  void* p2 = malloc(0x40);
  fprintf(stderr, "Allocated two fastbins: p1=%p p2=%p\n", p1, p2);
  fprintf(stderr, "Now free p1!\n");
  free(p1);

  void* p3 = malloc(0x400);
  fprintf(stderr, "Allocated large bin to trigger malloc_consolidate(): p3=%p\n", p3);
  fprintf(stderr, "In malloc_consolidate(), p1 is moved to the unsorted bin.\n");
  free(p1);
  fprintf(stderr, "Trigger the double free vulnerability!\n");
  fprintf(stderr, "We can pass the check in malloc() since p1 is not fast top.\n");
  fprintf(stderr, "Now p1 is in unsorted bin and fast bin. So we'will get it twice: %p %p\n", malloc(0x40), malloc(0x40));
}
```

Linux -- x64 -- glibc 2.23

```
$ ldd fastbin_dup_consolidate 
        linux-vdso.so.1 (0x00007fffd50fd000)
        libdl.so.2 => /glibc/x64/2.23/lib/libdl.so.2 (0x00007fd7401c3000)
        libc.so.6 => /glibc/x64/2.23/lib/libc.so.6 (0x00007fd73fe22000)
        /glibc/x64/2.23/lib/ld-2.23.so => /usr/lib64/ld-linux-x86-64.so.2 (0x00007fd7403ce000)
```

两次申请内存得到的 chunk 大小 为 0x50

![](https://gitee.com/scriptkiddies/images/raw/master/20201111144553.png)

free 掉 p1

![](https://gitee.com/scriptkiddies/images/raw/master/20201111144737.png)

现在 p1 chunk 位于 fastbinY[3] 中

我们现在申请 0x400 的内存，0x400 == 1024，chunk 的大小是 1024 + 16 = 0x410，大于 1024 的 chunk 会从 largebins 里面申请

![](https://gitee.com/scriptkiddies/images/raw/master/20201111145608.png)

可以看到，在获取了分配的 chunk 的 size 对应的 largrbin 的 index 后使用 have_fastchunks 判断分配区 av 中是否有 fastbin，如果有执行 malloc_consolidate 把 fastbins 合并后放入 unsorted bin 

源码

```c
#define have_fastchunks(M)     (((M)->flags & FASTCHUNKS_BIT) == 0)

idx = largebin_index (nb);
if (have_fastchunks (av))
	malloc_consolidate (av);
```

关于 malloc_consolidate 的操作可以看我注释的源码（当然这是 glibc 2.31 的 ptmalloc 源码）：https://github.com/zero-MK/note/blob/master/malloc/ptmalloc_source/malloc.c

