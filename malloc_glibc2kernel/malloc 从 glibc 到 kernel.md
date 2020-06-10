我大概看完了从 glibc 的 malloc 到内核对页的操作原理，现在我从代码的角度去分析它们的工作

malloc 的分析我就不做了，我现在直接从 malloc 对应的系统调用去看，malloc 怎么去操作堆



调用 malloc 是分成两种情况，当 malloc(size)

1. size < 128 Bytes， 会 brk -> sys_brk
2. size >= 128 Byte，会 mmap ->  sys_mmap

当然，查看调用时，glibc 里面的函数调用顺序大概是：

```
__libc_malloc() -> _int_malloc() -> sysmalloc()
```

glibc 中大概的源代码(我已经省去部分无关分析的代码):

/malloc/malloc.c

__libc_malloc:

```c
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;
.........
.........
.........
  arena_get (ar_ptr, bytes);
.........
.........
.........
  victim = _int_malloc (ar_ptr, bytes);
.........
.........
.........
}
```



_int_malloc:

```c
static void *
_int_malloc (mstate av, size_t bytes)
{
    .........
	.........
	.........
  /*
     Convert request size to internal form by adding SIZE_SZ bytes
     overhead plus possibly more to obtain necessary alignment and/or
     to obtain a size of at least MINSIZE, the smallest allocatable
     size. Also, checked_request2size traps (returning 0) request sizes
     that are so large that they wrap around zero when padded and
     aligned.
   */
  checked_request2size (bytes, nb);

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */

  if (__glibc_unlikely (av == NULL))
    {
        /*就是这里，这个函数就是分清是使用 mmap 还是 brk*/
      void *p = sysmalloc (nb, av);
      if (p != NULL)
	alloc_perturb (p, bytes);
      return p;
    }
    .........
	.........
	.........
}
```



sysmalloc:



```c
#define DEFAULT_MMAP_THRESHOLD DEFAULT_MMAP_THRESHOLD_MIN
#define DEFAULT_MMAP_THRESHOLD_MIN (128 * 1024)

static struct malloc_par mp_ =
{
  .top_pad = DEFAULT_TOP_PAD,
  .n_mmaps_max = DEFAULT_MMAP_MAX,
  .mmap_threshold = DEFAULT_MMAP_THRESHOLD,
  .trim_threshold = DEFAULT_TRIM_THRESHOLD,
#define NARENAS_FROM_NCORES(n) ((n) * (sizeof (long) == 4 ? 2 : 8))
  .arena_test = NARENAS_FROM_NCORES (1)
};
```



```c
static void *
sysmalloc (INTERNAL_SIZE_T nb, mstate av)
{
  mchunkptr old_top;              /* incoming value of av->top */
  INTERNAL_SIZE_T old_size;       /* its size */
  char *old_end;                  /* its end address */

  long size;                      /* arg to first MORECORE or mmap call */
  char *brk;                      /* return value from MORECORE */

  long correction;                /* arg to 2nd MORECORE call */
  char *snd_brk;                  /* 2nd return val */

  INTERNAL_SIZE_T front_misalign; /* unusable bytes at front of new space */
  INTERNAL_SIZE_T end_misalign;   /* partial page left at end of new space */
  char *aligned_brk;              /* aligned offset into brk */

  mchunkptr p;                    /* the allocated/returned chunk */
  mchunkptr remainder;            /* remainder from allocation */
  unsigned long remainder_size;   /* its size */


  size_t pagesize = GLRO (dl_pagesize);
  bool tried_mmap = false;
 /*
*这里就是判断是不是使用 mmap，可以看到这里有一个名为mp_ 的 malloc_par 结构体
*具体是怎么样的看上面，我已经把主要的宏整理出来
*nb 就是我们要分配的 chunk 的大小
*（是 chunk 的大小不是我们 malloc 的参数 chunk 有metadata，所以 chunk 的大小会大于 malloc 的参数）
*结合上面的我们可以看到 当 chunk 的大小大于 128 * 1024 Bytes 时 就使用 mmap
*/
if (av == NULL
      || ((unsigned long) (nb) >= (unsigned long) (mp_.mmap_threshold)
	  && (mp_.n_mmaps < mp_.n_mmaps_max)))
    {
      char *mm;           /* return value from mmap call*/

    try_mmap:
      /*
         Round up size to nearest page.  For mmapped chunks, the overhead
         is one SIZE_SZ unit larger than for normal chunks, because there
         is no following chunk whose prev_size field could be used.

         See the front_misalign handling below, for glibc there is no
         need for further alignments unless we have have high alignment.
       */
      if (MALLOC_ALIGNMENT == 2 * SIZE_SZ)
        size = ALIGN_UP (nb + SIZE_SZ, pagesize);
      else
        size = ALIGN_UP (nb + SIZE_SZ + MALLOC_ALIGN_MASK, pagesize);
      tried_mmap = true;

      /* Don't try if size wraps around 0 */
      if ((unsigned long) (size) > (unsigned long) (nb))
        {
          mm = (char *) (MMAP (0, size, PROT_READ | PROT_WRITE, 0));
          ................
          ................
      }
```



如果 nb 小于 128 KB，就使用 brk

sysmalloc 有点庞大，基本上就是一些 检查 和 设置标志位，我就不一一详细写，重心放在内核里面



在内核里面对应的是 sys_brk, sys_mmap_pgoff，其实不是很好找

这里就讲一讲怎么在内核里面找被“隐藏”的函数

比如 sys_brk

我用 vscode 选择跳转到工作区中的符号

搜索

sys_brk



```c
SYSCALL_DEFINE1(brk, unsigned long, brk)
{
	unsigned long retval;
	unsigned long newbrk, oldbrk, origbrk;
    
    /* 获得描述当前进程的内存的 mm_struct
	* current 指向的是当前进程的 task_struct 
	*/
    struct mm_struct *mm = current->mm;
	/* 每一个内存区段（像是 mmap ，heap，详细描述看下面的图）都是用 vm_area_struct 来描述
     *在 内存块少的时候使用的是链表把每个 块链接起来
     * 在 内存块多的时候使用红黑树
     * 这里的 next 是用来指向下一个内存块
     */
    
    struct vm_area_struct *next;
	unsigned long min_brk;
	bool populate;
	bool downgraded = false;
	LIST_HEAD(uf);

	brk = untagged_addr(brk);

	if (down_write_killable(&mm->mmap_sem))
		return -EINTR;

    // 获取现在 heap 的最高地址
	origbrk = mm->brk;

#ifdef CONFIG_COMPAT_BRK
	/*
	 * CONFIG_COMPAT_BRK can still be overridden by setting
	 * randomize_va_space to 2, which will still cause mm->start_brk
	 * to be arbitrarily shifted
	 */
    	/*
	      *一般用户进程地址空间划分，堆在数据段的上方
	       *如果开始 brk_randomized 属性最小堆地址就没办法通过数据段直接获取。
	       * 也就是说 heap 和 data 在没开启 brk_randomized 贴在一起的 data 的结束地址就是 heap 的起始地址
	       * 要是开启了 brk_randomized ，则 start_brk 指向 heap 的起始地址
		*/
	
	if (current->brk_randomized)
        // heap 的最低地址就是 start_brk
		min_brk = mm->start_brk;
	else
        // heap 的最低地址是 data 段（数据段）的结束地址
		min_brk = mm->end_data;
#else
	min_brk = mm->start_brk;
#endif
	if (brk < min_brk)
		goto out;

	/*
	 * Check against rlimit here. If this check is done later after the test
	 * of oldbrk with newbrk then it can escape the test and let the data
	 * segment grow beyond its set limit the in case where the limit is
	 * not page aligned -Ram Gupta
	 */
    /*
  --------------------------------------------------------------------------------
    #define RLIMIT_DATA		2 
    rlimit(RLIMIT_DATA) 展开就是
    READ_ONCE(current->signal->rlim[2].rlim_cur)
    // 2020.04.21 深入学了资源限制才明白， RLIMIT_DATA 是一个 task->signal->rlim 数组的索引  
    // rlim[2].rlim_cur 里面存的就是堆大小的最大值
    // 其实这里就是检查我们 扩展堆后是不是超过了大小上限
  --------------------------------------------------------------------------------
    	static inline int check_data_rlimit(unsigned long rlim,
				    unsigned long new,
				    unsigned long start,
				    unsigned long end_data,
				    unsigned long start_data)
{
	if (rlim < RLIM_INFINITY) {
		if (((new - start) + (end_data - start_data)) > rlim)
		这个展开就是
		( brk - mm->start_brk ) + (mm->end_data - mm->start_data) > current->signal->rlim[2].rlim_cur
			return -ENOSPC;
	}

	return 0;
}
    */

	if (check_data_rlimit(rlimit(RLIMIT_DATA), brk, mm->start_brk,
			      mm->end_data, mm->start_data))
		goto out;

    // 按照页对齐 brk
	newbrk = PAGE_ALIGN(brk);
	oldbrk = PAGE_ALIGN(mm->brk);
    
	if (oldbrk == newbrk) {
        // 更新 heap 的最高地址，这里就是真正的扩增 heap
		mm->brk = brk;
		goto success;
	}

	/*
	 * Always allow shrinking brk.
	 * __do_munmap() may downgrade mmap_sem to read.
	 */
	if (brk <= mm->brk) {
		int ret;

		/*
		 * mm->brk must to be protected by write mmap_sem so update it
		 * before downgrading mmap_sem. When __do_munmap() fails,
		 * mm->brk will be restored from origbrk.
		 */
		mm->brk = brk;
		ret = __do_munmap(mm, newbrk, oldbrk-newbrk, &uf, true);
		if (ret < 0) {
			mm->brk = origbrk;
			goto out;
		} else if (ret == 1) {
			downgraded = true;
		}
		goto success;
	}

	/* Check against existing mmap mappings. */
	next = find_vma(mm, oldbrk);
	if (next && newbrk + PAGE_SIZE > vm_start_gap(next))
		goto out;

	/* Ok, looks good - let it rip. */
	if (do_brk_flags(oldbrk, newbrk-oldbrk, 0, &uf) < 0)
		goto out;
	mm->brk = brk;

success:
	populate = newbrk > oldbrk && (mm->def_flags & VM_LOCKED) != 0;
	if (downgraded)
		up_read(&mm->mmap_sem);
	else
		up_write(&mm->mmap_sem);
	userfaultfd_unmap_complete(mm, &uf);
	if (populate)
		mm_populate(oldbrk, newbrk - oldbrk);
    // 返回新的 heap 结束地址
	return brk;

out:
	retval = origbrk;
	up_write(&mm->mmap_sem);
	return retval;
}
```

这里要讲的就是 mm_struct ，这个结构体是描述进程的内存空间

具体是这样的：

![](https://gitee.com/scriptkiddies/images/raw/master/task_mm.png)

start_brk 指向的是 Heap 起始地址

brk 指向 Heap 的结束地址

其实 brk 操作就是 操作 brk 来调整 Heap 的大小

