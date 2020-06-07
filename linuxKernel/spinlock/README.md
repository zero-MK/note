自旋锁 `spinlock_t`

```c
typedef struct spinlock {
        union {
              struct raw_spinlock rlock;
#ifdef CONFIG_DEBUG_LOCK_ALLOC
# define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))
                struct {
                        u8 __padding[LOCK_PADSIZE];
                        struct lockdep_map dep_map;
                };
#endif
        };
} spinlock_t;
```

如果一个处理程序尝试执行受`自旋锁`保护的代码，那么代码将会被锁住，直到占有锁的处理程序释放掉。

自旋锁 一共有两种状态

- acquired
- released

自旋锁获取（`spinlock acquire`）

自旋锁释放（`spinlock released`）



`raw_spinlock` 结构

```c
typedef struct raw_spinlock {
        arch_spinlock_t raw_lock;
#ifdef CONFIG_GENERIC_LOCKBREAK
        unsigned int break_lock;
#endif
} raw_spinlock_t;
```



`x86` 的 `arch_spinlock` 结构

```
typedef struct arch_spinlock {
        union {
                __ticketpair_t head_tail;
                struct __raw_tickets {
                        __ticket_t head, tail;
                } tickets;
        };
} arch_spinlock_t;
```



Linux内核在`自旋锁`上提供了一下主要的操作：

- `spin_lock_init` ——给定的`自旋锁`进行初始化；
- `spin_lock` ——获取给定的`自旋锁`；
- `spin_lock_bh` ——禁止软件[中断](https://en.wikipedia.org/wiki/Interrupt)并且获取给定的`自旋锁`。
- `spin_lock_irqsave` 和 `spin_lock_irq`——禁止本地处理器上的中断，并且保存／不保存之前的中断状态的`标识 (flag)`；
- `spin_unlock` ——释放给定的`自旋锁`;
- `spin_unlock_bh` ——释放给定的`自旋锁`并且启动软件中断；
- `spin_is_locked` - 返回给定的`自旋锁`的状态；
- 等等



## spin_lock_init —— 对给定的自旋锁进行初始化

```c
#define spin_lock_init(_lock)        \
do {                                            \
    spinlock_check(_lock);                        \
    raw_spin_lock_init(&(_lock)->rlock);        \
} while (0)
```

`spinlock_check` 检查 `_lock`

返回已知的`自旋锁`的 `raw_spinlock_t`，来确保我们精确获得`正常 (normal)` 原生自旋锁

```c
static __always_inline raw_spinlock_t *spinlock_check(spinlock_t *lock)
{
  return &lock->rlock;
}
```

`raw_spin_lock_init` 宏

这个宏为给定的`自旋锁`执行初始化操作，并且将锁设置为`释放 (released)` 状态

```c
# define raw_spin_lock_init(lock)        \
do {                                                  \
    *(lock) = __RAW_SPIN_LOCK_UNLOCKED(lock);         \
} while (0)                                           \
```

`__RAW_SPIN_LOCK_UNLOCKED` 宏

```c
#define __RAW_SPIN_LOCK_UNLOCKED(lockname)      \
         (raw_spinlock_t) __RAW_SPIN_LOCK_INITIALIZER(lockname)
#define __RAW_SPIN_LOCK_INITIALIZER(lockname)   \
         {                                                      \
             .raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,             \
             SPIN_DEBUG_INIT(lockname)                          \
             SPIN_DEP_MAP_INIT(lockname)                        \
         }
#define __ARCH_SPIN_LOCK_UNLOCKED       { { 0 } }
```

展开 `__RAW_SPIN_LOCK_UNLOCKED` 宏就是

```c
*(lock) = __ARCH_SPIN_LOCK_UNLOCKED;
```

展开 `raw_spin_lock_init` 就是

```c
*(&(_lock)->rlock) = __ARCH_SPIN_LOCK_UNLOCKED;
```

在 `spin_lock_init` 宏的扩展之后，给定的`自旋锁`将会初始化并且状态变为——`解锁 (unlocked)`。

初始化操作其实就是把 给定的自旋锁 的 `rlock` 设置成 `0` ，表示锁是 `released` 状态

## spin_lock —— 获取给定的自旋锁

```c
static __always_inline void spin_lock(spinlock_t *lock)
{
    raw_spin_lock(&lock->rlock);
}
```

`raw_spin_lock` 宏

```c
#define _raw_spin_lock(lock) __raw_spin_lock(lock)
```

`__raw_spin_lock` 函数

```c
static inline void __raw_spin_lock(raw_spinlock_t *lock)
{
        preempt_disable(); // 禁用抢占（当程序正在自旋锁时，这个已经获取锁的程序必须阻止其他程序方法的抢占）
        spin_acquire(&lock->dep_map, 0, 0, _RET_IP_);
        LOCK_CONTENDED(lock, do_raw_spin_trylock, do_raw_spin_lock);
}
```

跳过 `spin_acquire`

分析 `LOCK_CONTENDED`

```c
LOCK_CONTENDED(lock, do_raw_spin_trylock, do_raw_spin_lock);
```

`LOCK_CONTENDED`

```c
#define LOCK_CONTENDED(_lock, try, lock) \
         lock(_lock)
```

其实 `lock` 就是 `do_raw_spin_lock`

```c
static inline void do_raw_spin_lock(raw_spinlock_t *lock) __acquires(lock)
{
        __acquire(lock); // [稀疏(sparse)]相关宏
         arch_spin_lock(&lock->raw_lock);
}
#define arch_spin_lock(l)               queued_spin_lock(l)
```



`arch_spinlock`

```
typedef struct arch_spinlock {
        union {
                __ticketpair_t head_tail;
                struct __raw_tickets {
                        __ticket_t head, tail;
                } tickets;
        };
} arch_spinlock_t;
```

这个`自旋锁`的变体被称为——`标签自旋锁 (ticket spinlock)`

当锁被获取，如果有程序想要获取自旋锁，它就会将 `tail` 的值加 `1`，如果 `tail != head` ，那么程序就会被锁住，直到这些变量的值不再相等

`arch_spin_lock`

```c
#define __TICKET_LOCK_INC       1
#define cpu_relax()     asm volatile("rep; nop")
static __always_inline void arch_spin_lock(arch_spinlock_t *lock)
{
        register struct __raw_tickets inc = { .tail = TICKET_LOCK_INC }; // tail 加 1
        inc = xadd(&lock->tickets, inc);
        if (likely(inc.head == inc.tail))
                goto out;
        for (;;) {
                 unsigned count = SPIN_THRESHOLD;
                 do {
                       inc.head = READ_ONCE(lock->tickets.head);
                       if (__tickets_equal(inc.head, inc.tail))
                                goto clear_slowpath;
                        cpu_relax();
                 } while (--count);
                 __ticket_lock_spinning(lock, inc.tail);
         }
clear_slowpath:
        __ticket_check_and_clear_slowpath(lock, inc.head);
out:
        barrier();
}
```

