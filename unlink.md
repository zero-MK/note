关于 unlink 的参数

```c
mchunkptr top_chunk = top (ar_ptr), p, bck, fwd;
```



top 宏：

```c
#define top(ar_ptr) ((ar_ptr)->top)
```



触发 unlink 的条件是：当前块的 inuse 位不为 1（也就是当前块的物理位置上面的前一个块是 free 的，当然位于 fastbin 里面的块除外）

```c


if (!prev_inuse (p)) /* consolidate backward */ 
{
	p = prev_chunk (p);
	unlink (ar_ptr, p, bck, fwd);
}
```



prev_inuse 宏：

```c
#define PREV_INUSE 0x1
/* extract inuse bit of previous chunk */
#define prev_inuse(p)       ((p)->size & PREV_INUSE)
```





ar_ptr 是一个指向 malloc_state 结构体的指针：

```c
struct malloc_state
{
  /* Serialize access.  */
  mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
```





传入的 P 是要 unlink 的块，BK 和 FD 是指向 malloc_chunk 的指针

```c
#define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd; \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0)) 		      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
    else {								      \
        FD->bk = BK;							      \
        BK->fd = FD;							      \
        if (!in_smallbin_range (P->size)				      \
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
	    if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      \
		|| __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
	      malloc_printerr (check_action,				      \
			       "corrupted double-linked list (not small)",    \
			       P, AV);					      \
            if (FD->fd_nextsize == NULL) {				      \
                if (P->fd_nextsize == P)				      \
                  FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                else {							      \
                    FD->fd_nextsize = P->fd_nextsize;			      \
                    FD->bk_nextsize = P->bk_nextsize;			      \
                    P->fd_nextsize->bk_nextsize = FD;			      \
                    P->bk_nextsize->fd_nextsize = FD;			      \
                  }							      \
              } else {							      \
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
              }								      \
          }								      \
      }									      \
}
```



把 P 的下一个块和上一个块分别保存到 FD 和 BK



    FD = P->fd; 
    BK = P->bk;


检查块是不是已经损坏：

```
__builtin_expect (FD->bk != P || BK->fd != P, 0)
```

__builtin_expect 是 gcc 的内置函数用来优化分支，这里不多说。

glibc 2.23 主要是 

FD->bk != P 

BK->fd != P

就是 

下一个块的 上一个块 不是它自己的话就说明 chunk 被破坏

上一个块的 下一个块 不是它自己的话就说明 chunk 被破坏

，可以避免有些 heap exploit



检查通过了就是 

    FD->bk = BK;							      
    BK->fd = FD;
白话就是：

下一个块的上一个块变成 当前块的 上一个块

上一个块的下一个块变成 当前块的 下一个块

这样就能把 bin 中的前后两块链接，把当前块从 bin 中取下来







in_smallbin_range 宏是检查 chunk 是不是位于 smallbin 里面的:

```c
#define MALLOC_ALIGNMENT       (2 *SIZE_SZ)
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)
#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
#define in_smallbin_range(sz)  \
  ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)
```

 参数是 chunk 的 size 

