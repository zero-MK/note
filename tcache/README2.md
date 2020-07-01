## malloc_par

via：https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L1783

每个分配区是 `struct malloc_state` 的一个实例,  `ptmalloc` 使用 `malloc_state` 来管理分配区, 而参数管理使用 `struct malloc_par`, 全局拥有一个唯一的 `malloc_par` 实例。

这里描述了 `tcache`

@tcache_count -- 每个 `tcache` 能容纳多少个 `chunk`， 这里是 `7` 

@tcache_bins -- `tcache` 的数量， 这里是 `64` 个（其实就是包括了 `fastbin` 和 `smallbin`）

@tcache_max_bytes -- 最大的 `tcache`， 计算  `tidx2usize` 宏，`32` 位下是 `512`，`64` 位下是 `1024`

@tcache_unsorted_limit -- 

相关宏via：https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L302

```c
/* We want 64 entries.  This is an arbitrary limit, which tunables can reduce.  */
# define TCACHE_MAX_BINS		64

/* With rounding and alignment, the bins are...
   idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   idx 1   bytes 25..40 or 13..20
   idx 2   bytes 41..56 or 21..28
   etc.  */

/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7

/* Only used to pre-fill the tunables.  */
# define tidx2usize(idx)	(((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)

/* MALLOC_ALIGNMENT is the minimum alignment for malloc'ed chunks.  It
   must be a power of two at least 2 * SIZE_SZ, even on machines for
   which smaller alignments would suffice. It may be defined as larger
   than this though. Note however that code and data structures are
   optimized for the case of 8-byte alignment.  */
#define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
			  ? __alignof__ (long double) : 2 * SIZE_SZ)

/* There is only one instance of the malloc parameters.  */
static struct malloc_par mp_ =
{
    ......
    ......
#if USE_TCACHE
  ,
  .tcache_count = TCACHE_FILL_COUNT,
  .tcache_bins = TCACHE_MAX_BINS,
  .tcache_max_bytes = tidx2usize (TCACHE_MAX_BINS-1),
  .tcache_unsorted_limit = 0 /* No limit.  */
#endif
};
```

看完这个，可以知道

`tcache` 一共有 `64` 条单链表（`tcache_bins`），每条单链表最多有 `7` 个节点（`tcache_count`），每条 `tcache` 的 `chunk` 的大小在 `32` 位系统上是以 `8 Bytes` 递增，最大 `chunk` 为 `512`。在 `64` 位系统上是以 `16 Bytes` 递增，最大 `chunk` 为 `1024`（`tcache_max_bytes`）



## _int_malloc

via：https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L3585

### fastbin

`malloc` 的 `chunk` 是在 `fastbin` 范围的时候

```c
  /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */
#define REMOVE_FB(fb, victim, pp)			\
  do							\
    {							\
      victim = pp;					\
      if (victim == NULL)				\
	break;						\
    }							\
  while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim)) \
	 != victim);					\

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp = *fb;
      REMOVE_FB (fb, victim, pp);
      if (victim != 0)
        {
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb);

#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
      // nb 就是 chunk 的 size，csize2tidx 把 chunk 的 size 转换成 tcache 的 index
	  size_t tc_idx = csize2tidx (nb);
      // 如果 tcache 已经初始化成功，并且 tc_idx 是一个合法的 tcache index
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
          // 当 bin 不为空，并且 tcache 没有填满的时候
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (pp = *fb) != NULL)
		{
          // 把 chunk 从 bin 里面拿下来
		  REMOVE_FB (fb, tc_victim, pp);
		  if (tc_victim != 0)
		    {
              // 把 tc_victim 放入 tc_idx 对应的 tcache 里面
		      tcache_put (tc_victim, tc_idx);
	        }
		  }
	    }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```



### smallbin

via：https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L3611

`malloc` 的 `chunk` 是在 `smallbin` 范围的时候

```c
/*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
   */

  if (in_smallbin_range (nb))
    {
      // 获取 nb 大小的 chunk 对应的 smallbin 的 index 
      idx = smallbin_index (nb);
      // 获取对应 smallbin 的双链表头
      bin = bin_at (av, idx);

      // 将最后一个 chunk 赋值给 victim （#define last(b)      ((b)->bk)）
      // smallbin 是个循环双链表
      if ((victim = last (bin)) != bin)
        {
          if (victim == 0) /* initialization check */
            malloc_consolidate (av);
          else
            {
              // 获取 victim 的上一个 chunk（bin 里的位置，不是物理位置）
              bck = victim->bk;
	if (__glibc_unlikely (bck->fd != victim))
                {
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
              // 设置 inuse 标志位
              set_inuse_bit_at_offset (victim, nb);
              // 链表头的 bk 设置成 victim 的上一个 chunk
              bin->bk = bck;
              // 把 victim 的上一个 chunk 的 fd 设置成 bin
              bck->fd = bin;
              // 其实上面的操作就是把 victim 从双链表里面删除，数据结构应该学过吧？
              /*
+-------------------------------------------------------------------------------------------------------------+
|                                                                                                             |
|                                                                                                             |
|                                                                                                             |
|                                                                                                             |
|                   bin                                              bck                  victim              |
|                                                                                                             |
|    +-------> +-------------+<-+   +->+-------------+<--+   +->+-------------+<-+  +>+-------------+ <-------+
|    |         |   prev_size |  |   |  |   prev_size |   |   |  |   prev_size |  |  | |   prev_size |
|    |         +-------------+  |   |  +-------------+   |   |  +-------------+  |  | +-------------+
|    |         |    size     |  |   |  |    size     |   |   |  |    size     |  |  | |    size     |
|    |         +-------------+  |   |  +-------------+   |   |  +-------------+  |  | +-------------+
|    |         |     fd      +------+  |     fd      +-------+  |     fd      +-----+ |     fd      +---------+
|    |         +-------------+  |      +-------------+   |      +-------------+  |    +-------------+         |
+--------------+     bk      |  +------+     bk      |   +------+     bk      |  +----+     bk      |         |
     |         +-------------+         +-------------+          +-------------+       +-------------+         |
     |         |             |         |             |          |             |       |             |         |
     |         | user data   |         | user data   |          | user data   |       | user data   |         |
     |         |             |         |             |          |             |       |             |         |
     |         |             |         |             |          |             |       |             |         |
     |         +-------------+         +-------------+          +-------------+       +-------------+         |
     |                                                                                                        |
     |                                                                                                        |
     |                                                                                                        |
     +--------------------------------------------------------------------------------------------------------+

              */

              if (av != &main_arena)
		set_non_main_arena (victim);
              check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
      // nb 就是 chunk 的 size，csize2tidx 把 chunk 的 size 转换成 tcache 的 index
	  size_t tc_idx = csize2tidx (nb);
      // 如果 tcache 已经初始化成功，并且 tc_idx 是一个合法的 tcache index
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
          // 当 bin 不为空，并且tcache 没有填满的时候
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
              // 获取 chunk 的上一个 chunk（bin 里的位置，不是物理位置）
		      bck = tc_victim->bk;
              // 设置下一个 chunk 的 inuse 位（这里为什么那么做呢，因为 tchace 的 chunk 都不取消 inuse 标志位）
		      set_inuse_bit_at_offset (tc_victim, nb);
              // 如果当前不是位于主分配区，设置标志位
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
              
              // 一样的，看上面，取出 tc_victim 必须工作
		      bin->bk = bck;
		      bck->fd = bin;

              // 把 chunk 放入对应 tc_idx 的 tcache 中去
		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
#endif
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
    }
```



小结：

- `malloc` 时优先从 `tcache` 取 `chunk` ，直到该 `tcache` 为空才会从原本的 `bin` 找
- `tcache` 为空时，如果 `fastbin/smallbin/unsorted bin` 有刚好 `size` 的 `chunk` 时，会先将该 `fastbin/smallbin/unsroted bin` 中的 `chunk` 填充到 `tcache` 中，直到填满为止（`while (tcache->counts[tc_idx] < mp_.tcache_count && (tc_victim = last (bin)) != bin)`），然后再从 `tcache` 相对应的 `tcache` 中取出

