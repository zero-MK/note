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

当锁被获取，如果有程序想要获取自旋锁，它就会将 `tail` 的值加 `1`，如果 `tail != head` ，那么程序就会被锁住，直到 `tail == head`

`arch_spin_lock`

```c
#define __TICKET_LOCK_INC       1
#define cpu_relax()     asm volatile("rep; nop")
static __always_inline void arch_spin_lock(arch_spinlock_t *lock)
{
        register struct __raw_tickets inc = { .tail = TICKET_LOCK_INC }; // tail = 1
        inc = xadd(&lock->tickets, inc); // 这个操作过后 &lock->tickets = inc (这是个原子操作,详细请自行搜索 xadd)
        // 锁的关键就在这里了,只要 inc.head == inc.tail 成立,就说明这个锁没有被其他进程获取
        if (likely(inc.head == inc.tail))
                goto out; // 这个锁没有被获取,直接跳到 out 去执行
        // inc.head != inc.tail 说明有线程获取了这个锁,进入这个循环,等待这个锁被释放
        for (;;) {
                 unsigned count = SPIN_THRESHOLD; // 这是类似于信号量的 timeout 的东西,这个变量定义了进程 "等多久" (while执行多少次)
                 do {
                       // 把 head 读出来
                       inc.head = READ_ONCE(lock->tickets.head);
                       // 对比 head 和 tail,相等就说明这个锁被释放了
                       if (__tickets_equal(inc.head, inc.tail))
                                goto clear_slowpath;
                        cpu_relax(); // #define cpu_relax()     asm volatile("rep; nop"),就是一个 nop 指令,啥都不做
                 } while (--count);
                 __ticket_lock_spinning(lock, inc.tail);
         }
clear_slowpath:
        __ticket_check_and_clear_slowpath(lock, inc.head);
out:
        barrier(); // 屏障指令(防止 CPU 乱序)
}
```



## spin_unlock -- 释放给定的自旋锁

其实这个锁的释放就是让 `head` 加 `1`

核心操作

```c
__add(&lock->tickets.head, TICKET_LOCK_INC, UNLOCK_LOCK_PREFIX);
```

这样的话所有的等待进程就形成一个队列

`head` 是当前获得锁的进程的编号

`tail` 就是正在等待的进程的编号

在锁没有被释放的时候, 一直有进程请求这个锁,请求一次 `tail` 就加 `1`

释放锁的时候是 `head` 加 `1`, 这样对应的 `tail` (`head == tail`)的进程就能获得锁

就像是这样的

```
          +-------+
head      |   3   |
          +-------+

                  +-------+-------+-------+-------+
tail              |   4   |   5   |   6   |   7   |
                  +-------+-------+-------+-------+
```

现在 `tail` 等于 `3` , `head` 等于 `3`

释放锁后,` head` 等于 `4`

```
          +-------+
head      |   4   |
          +-------+

          +-------+-------+-------+-------+
tail      |   4   |   5   |   6   |   7   |
          +-------+-------+-------+-------+
```

这样 `tail == 4` 的进程就能获得锁