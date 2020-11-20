
#if USE_TCACHE
/* We want 64 entries.  This is an arbitrary limit, which tunables can reduce.  */
# define TCACHE_MAX_BINS    64
# define MAX_TCACHE_SIZE  tidx2usize (TCACHE_MAX_BINS-1)

/* Only used to pre-fill the tunables.  */
# define tidx2usize(idx)  (((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)

/* When "x" is from chunksize().  */
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
/* When "x" is a user-provided size.  */
# define usize2tidx(x) csize2tidx (request2size (x))

/* With rounding and alignment, the bins are...
   idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   idx 1   bytes 25..40 or 13..20
   idx 2   bytes 41..56 or 21..28
   etc.  */

/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7
#endif


static struct malloc_par mp_ =
{


#if USE_TCACHE
  ,
  .tcache_count = TCACHE_FILL_COUNT,
  .tcache_bins = TCACHE_MAX_BINS,
  .tcache_max_bytes = tidx2usize (TCACHE_MAX_BINS-1),
  .tcache_unsorted_limit = 0 /* No limit.  */
#endif
};


#if USE_TCACHE

/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
// tcache 的数据结构
// 单链表，next 指向 下一条 tcache
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;

/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
// 每个线程都有一个 tcache_perthread_struct 结构来描述当前线程的 tcache
// 默认情况下 TCACHE_MAX_BINS == 64，包含了 smallbin
// entries 是个数组，就是每一种大小的 chunk 所存的 tcache 的链表头组成的数组
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

static __thread bool tcache_shutting_down = false;
static __thread tcache_perthread_struct *tcache = NULL;

/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
// 把 chunk 放入下标为 tc_idx 的 tcache 中
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  // tcache 的 tcache_entry 总是指向 chunk 的 mem，而不是像 bin 是指向 chunk
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  // 断言，这个 chunk 所对应的 tcache entries 数组的下标是合法的
  assert (tc_idx < TCACHE_MAX_BINS);
  // 直接把 chunk 插入 entries[tc_idx] 对应的 tcache 中，插入位置的是链表头
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  // 增加 计数器 的值
  ++(tcache->counts[tc_idx]);
}

/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
// 从下标为 tc_idx 的 tcache 中取出 chunk
static __always_inline void *
tcache_get (size_t tc_idx)
{
  // 获取下标数为 tc_idx 的 tcache 的链表头
  tcache_entry *e = tcache->entries[tc_idx];
  // 断言 tc_idx 是一个合法值，小于 TCACHE_MAX_BINS
  assert (tc_idx < TCACHE_MAX_BINS);
  // 断言下标为 tc_idx 的 tcache 中有 chunk 
  assert (tcache->entries[tc_idx] > 0);
  // 从链表头取出一个 chunk（可以看到 tcache 是先进后出）
  tcache->entries[tc_idx] = e->next;
  // 减少 计数器 的值
  --(tcache->counts[tc_idx]);
  // 直接 返回 e，因为 e 指向的是 chunk 的 mem
  return (void *) e;
}

// 停止使用 tcache
static void
tcache_thread_shutdown (void)·
{
  int i;
  tcache_perthread_struct *tcache_tmp = tcache;

  if (!tcache)
    return;

  /* Disable the tcache and prevent it from being reinitialized.  */
  // 关闭 tcache，并且阻止其重新初始化（初始化是会检查 tcache_shutting_down，tcache_shutting_down 为 true 就终止初始化）
  tcache = NULL;
  tcache_shutting_down = true;

  /* Free all of the entries and the tcache itself back to the arena
     heap for coalescing.  */
  // 把 tcache 中的每个 chunk 都放入 bins 中
  for (i = 0; i < TCACHE_MAX_BINS; ++i)
    {
      while (tcache_tmp->entries[i])
	{
	  tcache_entry *e = tcache_tmp->entries[i];
	  tcache_tmp->entries[i] = e->next;
	  __libc_free (e);
	}
    }

  __libc_free (tcache_tmp);
}

// 初始化 tcache
static void
tcache_init(void)
{
  mstate ar_ptr;
  void *victim = 0;
  const size_t bytes = sizeof (tcache_perthread_struct);

  if (tcache_shutting_down)
    return;

  // arena_get 获取线程对应的 arena，并对其上锁，如果没有对应的 arena 就会请求分配一个 arena
  arena_get (ar_ptr, bytes);
  // 从 线程 arena 中分配一个大小为 bytes 的 chunk（其实就是为 tcache_perthread_struct 分配内存）
  victim = _int_malloc (ar_ptr, bytes);
  // 如果分配失败
  if (!victim && ar_ptr != NULL)
    {
      // 直接从 main_arena 中分配
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  // 分配成功后解锁分配区
  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  /* In a low memory situation, we may not be able to allocate memory
     - in which case, we just keep trying later.  However, we
     typically do this very early, so either there is sufficient
     memory, or there isn't enough memory to do non-trivial
     allocations anyway.  */
  if (victim)
    {
      // 把分配到的内存当成当前线程的 tcache_perthread_struct
      tcache = (tcache_perthread_struct *) victim;
      // 用 0 填充
      memset (tcache, 0, sizeof (tcache_perthread_struct));
    }

}

// 这个宏是用来判断 tcache 是否已经初始化，如果没有则调用 tcache_init 初始化 tcache
# define MAYBE_INIT_TCACHE() \
  if (__glibc_unlikely (tcache == NULL)) \
    tcache_init();

#else  /* !USE_TCACHE */
# define MAYBE_INIT_TCACHE()

static void
tcache_thread_shutdown (void)
{
  /* Nothing to do if there is no thread cache.  */
}

#endif /* !USE_TCACHE  */
