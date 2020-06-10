函数调用顺序：

__libc_malloc() -> malloc_hook_ini() ->



mstate 其实是一个 malloc_state 指针

```c
typedef struct malloc_state *mstate;
```

