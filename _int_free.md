```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size （要 free 的 chunk 的大小）*/
  mfastbinptr *fb;             /* associated fastbin （关联的 fastbin）*/
  mchunkptr nextchunk;         /* next contiguous chunk （下一个 chunk）*/
  INTERNAL_SIZE_T nextsize;    /* its size （下一个 chunk 的大小）*/
  int nextinuse;               /* true if nextchunk is used (当下一个 chunk 正在使用是就为 1)*/
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk （上一个 chunk 的大小）*/
  mchunkptr bck;               /* misc temp for linking （指向链表（bin）中的上一个块）*/
  mchunkptr fwd;               /* misc temp for linking （指向链表（bin）中的下一个块）*/

  const char *errstr = NULL;
  int locked = 0;

  size = chunksize (p);
   /* #define chunksize(p)    ((p)->size & ~(SIZE_BITS)) 
    * 得到 chunk 的 size
    */

  /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
   
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    {
      errstr = "free(): invalid pointer";
    errout:
      if (!have_lock && locked)
        (void) mutex_unlock (&av->mutex);
      malloc_printerr (check_action, errstr, chunk2mem (p), av);
      return;
    }
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
    
  /*检查要释放的 chunk 大小是不是小于最小 size ，这里用的 || ，其实只要 chunk 的大小
   *大于最小 size 就不会进行对齐检查
   */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    {
      errstr = "free(): invalid size";
      goto errout;
    }

  check_inuse_chunk(av, p);

  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
  */

    /* 检查 chunk 的大小符不符合 fastbin 并且下一个 chunk 不是 top chunk */
  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) {

    if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
      {
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might have let to a false positive.  Redo the test
	   after getting the lock.  */
	if (have_lock
	    || ({ assert (locked == 0);
		  mutex_lock(&av->mutex);
		  locked = 1;
		  chunk_at_offset (p, size)->size <= 2 * SIZE_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem;
	      }))
	  {
	    errstr = "free(): invalid next size (fast)";
	    goto errout;
	  }
	if (! have_lock)
	  {
	    (void)mutex_unlock(&av->mutex);
	    locked = 0;
	  }
      }

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    set_fastchunks(av);
    /* 拿到 chunk 的 idx*/
    unsigned int idx = fastbin_index(size);
    /* #define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx]) 
     * 拿到对应 idx 的 fastbin 的地址 
     */
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    /* old 代表 fastbin 第一个 chunk 的地址 */
    mchunkptr old = *fb, old2;
    unsigned int old_idx = ~0u;
    do
      {
	/* Check that the top of the bin is not the record we are going to add
	   (i.e., double free).  */
        
    /* 这里就是大名鼎鼎的 double free 的检查机制
     * old 是对应 idx 的 fastbin 的第一个 chunk 的地址
     * 如果它的地址等于 p（我们要 free 的 chunk）的地址，说明 p 和 old 是
     * 同一个 chunk ，这样的话，说明 free 的 chunk 已经位于 fastbin 中
     * 再次 free 就判定为 double free
     */
	if (__builtin_expect (old == p, 0))
	  {
	    errstr = "double free or corruption (fasttop)";
	    goto errout;
	  }
	/* Check that size of fastbin chunk at the top is the same as
	   size of the chunk that we are adding.  We can dereference OLD
	   only if we have the lock, otherwise it might have already been
	   deallocated.  See use of OLD_IDX below for the actual check.  */
     /*检查是不是有锁，并且要 free 的 chunk ptr 不是指向 NULL*/
	if (have_lock && old != NULL)
      /**/
	  old_idx = fastbin_index(chunksize(old));
     /* 这一句的是把 chunk 串到 fastbin 中
      * 就是把 free chunk 的 fd 指向原先在 fastbin 头的那个 chunk 的地址
      */   
	p->fd = old2 = old;
      }
    while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);

    if (have_lock && old != NULL && __builtin_expect (old_idx != idx, 0))
      {
	errstr = "invalid fastbin entry (free)";
	goto errout;
      }
  }

  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  /* 检查 chunk 是不是 mmap() 分配的*/
  else if (!chunk_is_mmapped(p)) {
    if (! have_lock) {
      (void)mutex_lock(&av->mutex);
      locked = 1;
    }

    /* chunk_at_offset 这个宏：((mchunkptr)) ((char *) (p)) + (s)))*/
    /* 传进来的 p + size 的地址当成一个 malloc_chunk 指针
     * 通过 malloc_chunk 的结构可以知道 p 是指向 fd 的位置的
     * 加上 size 就是得到下一个 chunk
     */
    nextchunk = chunk_at_offset(p, size);

    /* Lightweight tests: check whether the block is already the
       top block.  */
    /* 检查 p 的下一个块是不是 top chunk 。这里的 av 是一个 mstate 
     * mstate 是一个 malloc_state 结构体的指针
     * 这个结构体描述了当前堆的信息
     */
    if (__glibc_unlikely (p == av->top))
      {
	errstr = "double free or corruption (top)";
	goto errout;
      }
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
      {
	errstr = "double free or corruption (out)";
	goto errout;
      }
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      {
	errstr = "double free or corruption (!prev)";
	goto errout;
      }

    nextsize = chunksize(nextchunk);
    if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      {
	errstr = "free(): invalid next size (normal)";
	goto errout;
      }

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    /* consolidate backward */
    /* 检查上一个 chunk 是不是正在使用
     * 这个宏展开是： (p->size) & 0x1
     */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      /* 把 size 的大小加上 上个 chunk 的 size*/
      size += prevsize;
      /* 向上移动 p 指针，加上个 chunk 的 size ，指向新的 chunk*/
      p = chunk_at_offset(p, -((long) prevsize));
      /* 对相邻的三个 chunk 进行 unlink*/
      unlink(av, p, bck, fwd);
    }

    /* 检查下一个 chunk 是不是 top 
     * 是的话就合并 chunk 到 top chunk
     */
    if (nextchunk != av->top) {
        /*如果下一个块不是 top chunk*/
       /* #define inuse_bit_at_offset(p, s)					      \
  					(((mchunkptr) (((char *) (p)) + (s)))->size & PREV_INUSE)
  	    */
        /* get and clear inuse bit */
        /*获取，清除 inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
       /* 如果下一个块的 inuse bit 是 0 (表明当前块是 free 状态)*/
      if (!nextinuse) {
       /*直接进行 unlink*/
	unlink(av, nextchunk, bck, fwd);
       /*把当前的 size 加上 next chunk 的 size，形成了一个新的 chunk，这个 chunk 的大小就是 这个新的 size*/
	size += nextsize;
      } else
       /* 如果 下一个 chunk 的inuse bit 不是 0，直接置零
       	* 因为我们在 free 当前 chunk 
        * 当前块的 free 状态标志位于下一个 chunk 的 size 的 bit0
       */
	clear_inuse_bit_at_offset(nextchunk, 0);

      /*
	Place the chunk in unsorted chunk list. Chunks are
	not placed into regular bins until after they have
	been given one chance to be used in malloc.
      */

      bck = unsorted_chunks(av);
      fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
	{
	  errstr = "free(): corrupted unsorted chunks";
	  goto errout;
	}
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }

    /*
      If the chunk borders the current high end of memory,
      consolidate into top
    */

    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }

    /*
      If freeing a large space, consolidate possibly-surrounding
      chunks. Then, if the total unused topmost memory exceeds trim
      threshold, ask malloc_trim to reduce top.

      Unless max_fast is 0, we don't know if there are fastbins
      bordering top, so we cannot tell for sure whether threshold
      has been reached unless fastbins are consolidated.  But we
      don't want to consolidate on each free.  As a compromise,
      consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
      is reached.
    */

    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
      if (have_fastchunks(av))
	malloc_consolidate(av);

      if (av == &main_arena) {
#ifndef MORECORE_CANNOT_TRIM
	if ((unsigned long)(chunksize(av->top)) >=
	    (unsigned long)(mp_.trim_threshold))
	  systrim(mp_.top_pad, av);
#endif
      } else {
	/* Always try heap_trim(), even if the top chunk is not
	   large, because the corresponding heap might go away.  */
	heap_info *heap = heap_for_ptr(top(av));

	assert(heap->ar_ptr == av);
	heap_trim(heap, mp_.top_pad);
      }
    }

    if (! have_lock) {
      assert (locked);
      (void)mutex_unlock(&av->mutex);
    }
  }
  /*
    If the chunk was allocated via mmap, release via munmap().
  */

  else {
    munmap_chunk (p);
  }
}
```



上面是完整的 glibc2.23 -- _int_free 的源码


