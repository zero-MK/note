从 `glibc2.26` 开始引入了一个 `freed chunk` 管理机制：`Tcache`

还是那句话：`Read The F**king Source Code`

glibc 版本：2.26，via：https://elixir.bootlin.com/glibc/glibc-2.26/source

## tcache_entry

via：https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L2927

在 chunk  freed 时，会把 chunk 串到一个 单链表 上，next 指针指向的是 chunk data 部分（跟 mem 一样）

```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of previous chunk, if unallocated (P clear)  |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             User data starts here...                          .
	    .                                                               .
	    .             (malloc_usable_size() bytes)                      .
	    .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             (size of chunk, but used for application data)    |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of next chunk, in bytes                |A|0|1|
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```c
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;
```



## tcache_perthread_struct

via：https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L2937

每个线程有单独的 `tcache_perthread_struct` 

在每个线程第一次调用 `malloc` 时初始化

会根据大小分成多个不同的 `tcache`， `counts` 对应每个 `tcache` 中 `chunk` 的数量

```c
# define TCACHE_MAX_BINS		64
/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```



## MAYBE_INIT_TCACHE

via：https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L3056

第一次调用 `malloc` 时，会判断 `tcache` 有没有初始化，没有就会调用 `tcache_init` 初始化

其实就是给线程的 `tcache_perthread_struct` 分配内存

```c
#define MAYBE_INIT_TCACHE() \
  if (__glibc_unlikely (tcache == NULL)) \
    tcache_init();
    
static void
tcache_init(void)
{
  mstate ar_ptr;
  void *victim = 0;
  const size_t bytes = sizeof (tcache_perthread_struct);

  if (tcache_shutting_down)
    return;

  // 获得分配区
  arena_get (ar_ptr, bytes);
  // 给 tcache_perthread_struct 分配一个 chunk 
  victim = _int_malloc (ar_ptr, bytes);
  if (!victim && ar_ptr != NULL)
    {
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }


  if (ar_ptr != NULL)
    __libc_lock_unlock (ar_ptr->mutex);

  /* In a low memory situation, we may not be able to allocate memory
     - in which case, we just keep trying later.  However, we
     typically do this very early, so either there is sufficient
     memory, or there isn't enough memory to do non-trivial
     allocations anyway.  */
  if (victim)
    {
      // tcache 就是线程的 tcache_perthread_struct
      tcache = (tcache_perthread_struct *) victim;
      memset (tcache, 0, sizeof (tcache_perthread_struct));
    }

}
```

## tcache_put

@chunk：要放入 tcache 的 chunk

@tc_idx：对应的 tcache 的 index

via：https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L2949

往 tc_idx 对应的 tcache 加入 chunk

```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  // 通过 chunk2mem 宏获得一个指向 user data 部分的指针 e
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  // 断言 index 合法
  assert (tc_idx < TCACHE_MAX_BINS);
  // 把 chunk 串到 index 对应得 tcache 上
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  // counts += 1
  ++(tcache->counts[tc_idx]);
}
```



## tcache_get

@tc_idx： tcache 的 index

via：https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L2961

要从 index 为 tc_idx 对应的 tcache 里面取出一个 chunk

```c
/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static void *
tcache_get (size_t tc_idx)
{
  // 从链表头取出一个 chunk（这里的 e 指向的是 chunk 的 user data 部分）
  tcache_entry *e = tcache->entries[tc_idx];
  // 断言 tc_idx 合法
  assert (tc_idx < TCACHE_MAX_BINS);
  // 断言 index 为 tc_idx 的 tcache 不为空
  assert (tcache->entries[tc_idx] > 0);
  // 把第二个 chunk 当成 tcache 的 head
  tcache->entries[tc_idx] = e->next;
  // count -= 1
  --(tcache->counts[tc_idx]);
  // 返回的是一个指向 chunk 的 user data 部分的指针（不是指向 chunk ，看上面的 tcache_put）
  return (void *) e;
}
```



`tcache`小结：

- 单链表
- 把 `chunk` 放入 `tcache` 的时候 `next` 其实指向的是 `user data` 而不是像 `bin` 一样是指向 `chunk` 的（`tcache_entry *e = (tcache_entry *) chunk2mem (chunk);`）
- 先进后出，从 `tcache` 取 `chunk` 的时候总是先取头节点 （`tcache_entry *e = tcache->entries[tc_idx];`）
- 没有检查！！！！！！！！（说实话我也没看懂 `ptmalloc` 维护者的操作）


