每次分配的 堆内存 是用一个叫做  malloc_chunk  的 结构体描述的

```c
struct malloc_chunk {
  size_t      prev_size;  /* Size of previous chunk (if free).  */
  size_t      size;       /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

 `prev_size`：如果物理位置相邻的上一个 `chunk` 是 `free` 状态的时候，这个字段存的就是 上一个`chunk` 的 `size` 

`size`: 当前 `chunk` 的 `size`

