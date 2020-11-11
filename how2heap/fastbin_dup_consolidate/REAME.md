how2heap -- glibc 2.23 -- fastbin_dup_consolidate.c

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

```c
#define have_fastchunks(M)     (((M)->flags & FASTCHUNKS_BIT) == 0)

idx = largebin_index (nb);
if (have_fastchunks (av))
	malloc_consolidate (av);
```

关于 malloc_consolidate 的操作可以看我注释的源码（当然这是 glibc 2.31 的 ptmalloc 源码，我不给 # 行数了，因为现在还没注释完，所以，自行搜索 malloc_consolidate）：https://github.com/zero-MK/note/blob/master/malloc/ptmalloc_source/malloc.c

malloc_consolidate 中有一个点是比较重要的

```c
	  nextchunk = chunk_at_offset(p, size);
	  nextsize = chunksize(nextchunk);
	  ......
	  // 如果 nextchunk 不是 inuse 状态
	  if (!nextinuse) {
      // 合并 p 和 nextchunk
	    size += nextsize;
	    unlink_chunk (av, nextchunk);
	  } else
	    clear_inuse_bit_at_offset(nextchunk, 0); // 不然就清除 nextchunk 的 inuse 的标志位，表示 p 不是 inuse 状态

	  first_unsorted = unsorted_bin->fd;
    // 把 p 放入 unsorted bin
	  unsorted_bin->fd = p;
	  first_unsorted->bk = p;

    // 一旦合并后得到的 p 不属于 smallbin（那 p 一定是 largebin），则设置 fd_nextsize bk_nextsize
	  if (!in_smallbin_range (size)) {
	    p->fd_nextsize = NULL;
	    p->bk_nextsize = NULL;
	  }

	  set_head(p, size | PREV_INUSE);
	  p->bk = unsorted_bin;
	  p->fd = first_unsorted;
	  set_foot(p, size);
	}

	else {
    // 物理位置上相邻的下一个 chunk 是 top chunk
    // 直接把 p 合并到 top chunk
	  size += nextsize;
	  set_head(p, size | PREV_INUSE);
	  av->top = p;
	}
```

为了避免歧义，我直接把 **p1 所属的 chunk 就称为 p1 chunk，p2 所属的 chunk 称为 p2 chunk**

为了避免歧义，我直接把 **p1 所属的 chunk 就称为 p1 chunk，p2 所属的 chunk 称为 p2 chunk**

为了避免歧义，我直接把 **p1 所属的 chunk 就称为 p1 chunk，p2 所属的 chunk 称为 p2 chunk**



就是这一段，上面的检查解释了为什么 开始我们要 malloc 两个 chunk： p1 chunk 和 p2 chunk 而不是只 malloc 出 p1 chunk。这样能保证 malloc_consolidate 的时候不会把 p1 chunk 合并到 top chunk，而是放入 unsorted bin

在 malloc 完 p1 和 p2 的时候，堆是这样的

```
              +---------------------+
              |      prev_size      |
              +---------------------+
              |        size         |
 p1 +-------> +---------------------+
              |                     |
              |                     |
              |                     |
              |                     |
              |                     |
              +---------------------+
              |      prev_size      |
              +---------------------+
              |        size         |
 p2 +-------> +---------------------+
              |                     |
              |                     |
              |                     |
              |                     |
              |                     |
top +-------> +---------------------+
              |      prev_size      |
              +---------------------+
              |        size         |
              +---------------------+
              |                     |
              |                     |
              |                     |
              |                     |
              |                     |
```

回到上面的 malloc_consolidate ，p1 chunk 物理位置相邻的下一个 chunk 其实就是 p2 chunk，一旦刚刚开始我们不 malloc p2 chunk，p1 chunk 物理位置相邻的下一个 chunk 就是 top chunk，执行 malloc_consolidate 时 p1 就不是放进 unsorted bin 而是和 top chunk 合并

执行完 malloc_consolidate 后，malloc 会尝试从 unsorted bin 里面分配 chunk，源码有点长，自己去上面那个链接看，我注释好了的

现在我们来一步一步分析上面的代码

malloc(0x400);  前的 heap

![](https://gitee.com/scriptkiddies/images/raw/master/20201111171804.png)



malloc(0x400); 触发 malloc_consolidate 后的 heap，p1 会处于 unsorted bin 中

![](https://gitee.com/scriptkiddies/images/raw/master/20201111171916.png)



然后再次 free(p1)，p1 又会被 “放进” fastbin 中（double free，而不是从 unsorted bin 中移除然后放入 fastbin）

![](https://gitee.com/scriptkiddies/images/raw/master/20201111172038.png)



这时 p1 就会有两种状态：处于 fastbinY[3] 中，同时又处于 unsorted bin 中（看鼠标划线的地方，和 fastbinY[3]）

![](https://gitee.com/scriptkiddies/images/raw/master/20201111172212.png)



我们现在可以 malloc 到 p1 两次

第一次会把 fastbin 中的 p1 chunk 给 malloc 出来，然后 fastbin 为空

![](https://gitee.com/scriptkiddies/images/raw/master/20201111172651.png)



第二次会把 unsorted 中的 p1 chunk 给 malloc 出来，所以会能 malloc 到两次一样的 chunk

```
Now p1 is in unsorted bin and fast bin. So we'will get it twice: 0x555555559010 0x555555559010
```

然后现在 bin 中就没有 chunk 了

![](https://gitee.com/scriptkiddies/images/raw/master/20201111172801.png)





最后

致谢：华庭 《glibc内存管理ptmalloc源码分析》

还有 shellphish 的 how2heap 提供的 demo：https://github.com/shellphish/how2heap