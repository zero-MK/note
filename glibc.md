## 前言

linux 或者 glibc 源码中有很多 把一个指针转成字符型指针的操作（ (char    *) ），这样做的好处在于在做运算的的时候避免了数据类型对公式的影响，就比如：

```c
int i = 1;
printf("%p\n",  &i);  //0x7fff9561ac5c
printf("%p\n", (&i + 1)); //0x7fff9561ac60
```

我虽然是  +1 ,但是实际上 指针移动了 size(int) 的大小

转成 char * 的话：

```c
int i = 1;
printf("%p\n",  &i);  //0x7fff9561ac5c
printf("%p\n", ((char *)&i + 1)); //0x7fff9561ac6d
```

-----------------------------------------------------------------------------------------------------------



##  chunk 和 mem 指针的转换

```c
#define chunk2mem(p)   ((void*)((char*)(p) + 2*SIZE_SZ))
```

先把 p 指针转成 char 类型的指针，然后加上 2 × SIZE_SZ ，然后再转成 void 类型的指针



```c
#define mem2chunk(mem) ((mchunkptr)((char*)(mem) - 2*SIZE_SZ))
```

先把 mem 指针转成 char *，然后减掉 2 × SIZE_SZ，再转成 mchunkptr（typedef struct malloc_chunk* mchunkptr;）

示意图：`

```
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	| 			Size of previous chunk	                |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
`head:' | 			Size of chunk, in bytes               |P|
  mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | 	 Forward pointer to next chunk in list 			|
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Back pointer to previous chunk in list              |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```



最小 chunk 要包含 prev_size, size, fd, bk

offsetof 宏：

```c
#define offsetof(Type, Member) ((size_t) &((Type *) NULL)->Member)
```

Type：结构体指针

Member：成员（这个成员并不是当前成员，而是取它的下一个）



使用 offsetof 宏得到最小 chunk 大小 MIN_CHUNK_SIZE

```c
/* The smallest possible chunk */
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))
```

展开就是：

```
(size_t) & ((struct malloc_chunk*)NULL) -> fd_nextsize)
```

**NULL是一个指向 0 地址的指针，这句代码的意思是：当地址为 0 的地方有一个 malloc_chunk 然后取 fd_nextsize 的地址，这样得到的地址就是这个成员在结构体里面的偏移量**

malloc_chunk 的结构

```
prev_size
size
fd
bk
fd_nextsize
bk_nextsize
```

前四个必有，后两个 仅用于large bin（Only used for large blocks: pointer to next larger size. ）

就是得到了前面四个 member 的大小，32 位平台上位 16 字节,64 位平台为 24字节或是 32 字节。MINSIZE 定义了最小的分配的内存大小,是对 MIN_CHUNK_SIZE 进行了2*SIZE_SZ 对齐,地址对齐后与 MIN_CHUNK_SIZE 的大小仍然是一样的。



## 获取 chunk 的大小：

```c
#define PREV_INUSE 0x1
#define IS_MMAPPED 0x2
#define NON_MAIN_ARENA 0x4
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
#define chunksize(p)         ((p)->size & ~(SIZE_BITS))
```

这个宏用来获取当前 chunk 的 size，size 的低 3 个 bit 分别代表：是不是位于主分配区（NON_MAIN_ARENA），是不是 mmap（IS_MMAPPED），前一个 chunk 是不是正在使用（PREV_INUSE）。当然这些为被置为 1 的时候就为真，这些不属于 size ，只是标志位，我们取 size 的时候要把他们去掉。

SIZE_BITS 就是 0x1 | 0x2 | 0x4 = 0x8 = 0b111

~SIZE_BITS 就是 SIZE_BITS 取反 得到 0b000 ，& size 就能把 size 的低 3 个 bit 清除56



## 检查 chunk 的 metadata：

```c
/*
   --------------- Physical chunk operations ---------------
 */


/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1

/* extract inuse bit of previous chunk */
#define prev_inuse(p)       ((p)->size & PREV_INUSE)


/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2

/* check for mmap()'ed chunk */
/*检查 chunk 是不是 mmap 分配的*/
#define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED)


/* size field is or'ed with NON_MAIN_ARENA if the chunk was obtained
   from a non-main arena.  This is only set immediately before handing
   the chunk to the user, if necessary.  */
#define NON_MAIN_ARENA 0x4

/* check for chunk from non-main arena */
/* 检查 chunk 是不是不属于主分配区（main arena）*/
#define chunk_non_main_arena(p) ((p)->size & NON_MAIN_ARENA)


/*
   Bits to mask off when extracting size

   Note: IS_MMAPPED is intentionally not masked off from size field in
   macros for which mmapped chunks should never be seen. This should
   cause helpful core dumps to occur if it is tried by accident by
   people extending or adapting this malloc.
 */
/*取 chunk 的 size 的掩码 1 & 2 & 4 = 0b111 用来去除 size 的低三位（标志位）*/
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

/* Get size, ignoring use bits */
/*取 size 忽略 use bits （~ 是按位取反, ~(SIZE_BITS) = 0b000）*/
#define chunksize(p)         ((p)->size & ~(SIZE_BITS))


/* Ptr to next physical malloc_chunk. */
/* 指向物理位置上面的下一个 malloc_chunk */
#define next_chunk(p) ((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))

/* Ptr to previous physical malloc_chunk */
/* 指向物理位置上面的上一个 malloc_chunk */
#define prev_chunk(p) ((mchunkptr) (((char *) (p)) - ((p)->prev_size)))

/* Treat space at ptr + offset as a chunk */
/* 将 p + s 的空间视为一个 chunk */
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))

/* extract p's inuse bit */
/* 取出 p 的 inuse 标志位 */
#define inuse(p)							      \
  ((((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))->size) & PREV_INUSE)

/* set/clear chunk as being inuse without otherwise disturbing */
/* 设置 chunk 的 inuse bit */
#define set_inuse(p)							      \
  ((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))->size |= PREV_INUSE

/* 清除 chunk 的 inuse bit */
#define clear_inuse(p)							      \
  ((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))->size &= ~(PREV_INUSE)


/* check/set/clear inuse bits in known places */
/* 检查/设置/清除已知空间的 inuse bit */
#define inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->size & PREV_INUSE)

/* 设置已知空间的 inuse bit */
#define set_inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->size |= PREV_INUSE)

/* 已知空间的 inuse bit */
#define clear_inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->size &= ~(PREV_INUSE))


/* Set size at head, without disturbing its use bit */
/* 设置头部的 size，不影响它的标志位。*/
#define set_head_size(p, s)  ((p)->size = (((p)->size & SIZE_BITS) | (s)))

/* Set size/use field */
/* 设置 size/use 字段 */
#define set_head(p, s)       ((p)->size = (s))

/* Set size at footer (only when chunk is not in use) */
#define set_foot(p, s)       (((mchunkptr) ((char *) (p) + (s)))->prev_size = (s))
```



### 获取上一个和下一个（物理位置） chunk ：

```c
/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))

/* Ptr to previous physical malloc_chunk */
#define prev_chunk(p) ((mchunkptr) (((char *) (p)) - ((p)->prev_size)))
```

next_chunk(p)：
获得下一个 chunk 

先是把 p 转成 char * 再加上去掉标志位的 size 再转成 mchunkptr（就是 malloc_chunk 指针）

next_chunl(p)：

获得上一个 chunk

先是把 p 转成 char * 再减去 prev_size ，因为是没有标志位的，所以不用多余操作



把指定空间当成 malloc_chunk:

```c
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))
```

p 是一个字符型指针指向这个 chunk 的起始地址，s 代表这个 chunk 多大





### 对 inuse bit 的操作：

```c
#define inuse(p)							      \
  ((((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))->size) & PREV_INUSE)

#define set_inuse(p)							      \
  ((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))->size |= PREV_INUSE

#define clear_inuse(p)							      \
  ((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))->size &= ~(PREV_INUSE)
```

当前块的 inuse 的标志位 是位于下一个 chunk 的 size 的最低一位。

 malloc_chunk 结构体的结构：

```
    p-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  ---
	| 	Size of previous chunk					|      |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      |
        | 	Size of chunk, in bytes 		              |P|      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      | - chunk1
        | 			                        		|      |
        +                                                               +      |
        |                                                               |      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   ---
	| 		Size of previous chunk				|      |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      |
        | 		Size of chunk, in bytes 	              |P|      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      | - chunk2
        | 			             				|      |
        +                                                               +      |
        |                                                               |      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  ---
```

检查：(把 p 转成字符型指针 +`(p)->size & ~SIZE_BITS` 把当前块的标志位去掉得到的结果) 再把这个得到的指针转成 malloc_chunk指针也就是 mchunkptr （这个指针就是指向下一个 chunk 的）再取这个指针指向的 malloc_chunk 的 size 字段 和 PREV_INUSE（0x1）进行 & 运算，这样就完成了检查当前 chunk 是不是 inuse。



设置：(把 p 转成字符型指针 +`(p)->size & ~SIZE_BITS` 把当前块的标志位去掉得到的结果) 再把这个得到的指针转成 malloc_chunk指针也就是 mchunkptr （这个指针就是指向下一个 chunk 的）再取这个指针指向的 malloc_chunk 的 size 字段 和 PREV_INUSE（0x1）进行 | 运算，这样就完成了设置当前 chunk 的 inuse bit 为 1，因为 1 | 上任何数都是 1。



清除：(把 p 转成字符型指针 +`(p)->size & ~SIZE_BITS` 把当前块的标志位去掉得到的结果) 再把这个得到的指针转成 malloc_chunk指针也就是 mchunkptr （这个指针就是指向下一个 chunk 的）再取这个指针指向的 malloc_chunk 的 size 字段 和 `～PREV_INUSE`（0x0）进行 & 运算，这样就清除了当前 chunk 的 inuse bit 因为 0 & 上任何数都是 0。



### 对指定空间的操作：

```c
/* check/set/clear inuse bits in known places */
/* 检查/设置/清除已知空间的 inuse bit */

/* 检查已知空间的 inuse bit */
#define inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->size & PREV_INUSE)

/* 设置已知空间的 inuse bit */
#define set_inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->size |= PREV_INUSE)

/* 已知空间的 inuse bit */
#define clear_inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->size &= ~(PREV_INUSE))
```

((char *) (p)) + (s) 的意思是把 p + s 这一块空间当成一个 malloc_chunk



### 操作 size 字段

```c
/* Set size at head, without disturbing its use bit */
/* 设置 size 字段，不影响它的标志位。*/
#define set_head_size(p, s)  ((p)->size = (((p)->size & SIZE_BITS) | (s)))

/* Set size/use field */
/* 设置 size/use 字段 */

/* 设置 size ，忽略标志位 */
#define set_head(p, s)       ((p)->size = (s))

/* Set size at footer (only when chunk is not in use) */
/* 设置下一个 chunk 的 prev_size 为 s */
#define set_foot(p, s)       (((mchunkptr) ((char *) (p) + (s)))->prev_size = (s))
```

宏 set_head_size(p, s) 用于设置当前 chunk p 的 size 域并保留 size 域的控制信息。



宏 set_head(p, s) 用于设置当前 chunk p 的 size 域并忽略已有的 size 域控制信息。



宏 set_foot(p,s)用于设置当前 chunk p 的下一个 chunk 的 prev_size 为 s, s 为当前 chunk 的 size,只有当 chunk p 为空闲时才能使用这个宏,当前 chunk 的 foot 的内存空间存在于下一个 chunk,即下一个chunk 的 prev_size。

