Linux内核源码分析 -- 同步原语 -- 信号量 `semaphore` 

源码位于 `include/linux/semaphore`

```c
struct semaphore {
    raw_spinlock_t        lock; // 保护信号量的自旋锁
    unsigned int        count; // 现有的资源的数量
    struct list_head    wait_list; // 等待获取这个锁的进程队列
};
```



## 初始化

`DEFINE_SEMAPHORE` 是初始化一个 `二值信号量`

```c
#define DEFINE_SEMAPHORE(name)  \
         struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)
#define __SEMAPHORE_INITIALIZER(name, n)              \
{                                                                       \
        .lock           = __RAW_SPIN_LOCK_UNLOCKED((name).lock),        \
        .count          = n,                                            \
        .wait_list      = LIST_HEAD_INIT((name).wait_list),             \
}
```

`__RAW_SPIN_LOCK_UNLOCKED((name).lock)` 返回的是一个 `released` 的自旋锁

`n` 表示现有的资源的数量

`LIST_HEAD_INIT((name).wait_list)`  返回 `NULL`， 把 等待获取这个锁的进程队列 初始化为链表头，指向 `NULL`



可以用 `sema_init` 函数来初始化一个 `普通信号量`

```c
static inline void sema_init(struct semaphore *sem, int val)
{
       static struct lock_class_key __key;
       *sem = (struct semaphore) __SEMAPHORE_INITIALIZER(*sem, val);
       lockdep_init_map(&sem->lock.dep_map, "semaphore->lock", &__key, 0); // 锁验证 这里不用管
}
```

其实还是调用了 `__SEMAPHORE_INITIALIZER`  把 `cout` 赋值成 `val`	





## 信号量的 API

```c
void down(struct semaphore *sem); // 获取信号量
void up(struct semaphore *sem);  // 释放信号量
int  down_interruptible(struct semaphore *sem); 
int  down_killable(struct semaphore *sem);
int  down_trylock(struct semaphore *sem);
int  down_timeout(struct semaphore *sem, long jiffies);
```

- `down_interruptible` 函数：试图去获取一个 `信号量`。如果被成功获取，`信号量` 的计数就会被减少并且锁也会被获取。同时当前任务也会被调度到受阻状态，也就是说 `TASK_INTERRUPTIBLE` 标志将会被至位。`TASK_INTERRUPTIBLE` 表示这个进程也许可以通过信号退回到销毁状态。

- `down_killable` 函数：和 `down_interruptible` 函数提供类似的功能，但是它还将当前进程的 `TASK_KILLABLE` 标志置位。这表示等待的进程可以被杀死信号中断。

- `down_trylock` 函数：和 `spin_trylock` 函数相似。这个函数试图去获取一个锁并且退出如果这个操作是失败的。在这个例子中，想获取锁的进程不会等待

- `down_timeout`函数试图去获取一个锁。当前进程将会被中断进入到等待状态当超过传入的可等待时间。这个等待的时间是以 [jiffies](https://xinqiu.gitbooks.io/linux-insides-cn/content/Timers/linux-timers-1.html)计数。

### down

获取信号量

```c
void down(struct semaphore *sem)
{
        unsigned long flags;
        raw_spin_lock_irqsave(&sem->lock, flags);
        // 如果现有的资源的数量大于 0
        if (likely(sem->count > 0))
                // 将可用资源减 1，表示我们已经获取了这个锁
                sem->count--;
        else // 现有的资源的数量小于（不可能小于 0 的吧）等于 0，这表示所以的现有资源都已经被占用
                __down(sem);
        raw_spin_unlock_irqrestore(&sem->lock, flags);
}
EXPORT_SYMBOL(down);
```

#### __down

把当前进程的状态设置成：TASK_UNINTERRUPTIBLE（将进程放入等待队伍中，等待资源有效时唤醒）

等待时间是：MAX_SCHEDULE_TIMEOUT（）

```c
static noinline void __sched __down(struct semaphore *sem)
{
        __down_common(sem, TASK_UNINTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
}


```

## __down_common

`__down_interruptible`， `__down_killable`， `__down_timeout` 的核心其实都是` __down_common`

`__down_interruptible`：

```c
__down_common(sem, TASK_INTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
```

`__down_killable` ：

```c
__down_common(sem, TASK_KILLABLE, MAX_SCHEDULE_TIMEOUT);
```

`__down_timeout`:

```c
__down_common(sem, TASK_UNINTERRUPTIBLE, timeout);
```

```c
 /*
 * Because this function is inlined, the 'state' parameter will be
 * constant, and thus optimised away by the compiler.  Likewise the
 * 'timeout' parameter for the cases without timeouts.
 */
static inline int __sched __down_common(struct semaphore *sem, long state,
								long timeout)
{
	struct semaphore_waiter waiter;

   	list_add_tail(&waiter.list, &sem->wait_list);
	waiter.task = current;  // 把当前进程加入等待队列的尾（这是队列不是栈），先等待的进程获取信号量的优先级高，因为有等待超时的问题
	waiter.up = false;

    // 进入一个死循环
	for (;;) {
        // 检查 state 和 检查当前的进程是否处于 pending 状态
		if (signal_pending_state(state, current))
			goto interrupted;
		if (unlikely(timeout <= 0))
			goto timed_out;
        
        // 如果一个任务没有挂起信号而且给予的超时也没有过期，当前的任务将会被设置为传入的 state
		__set_current_state(state);
        
		raw_spin_unlock_irq(&sem->lock);
        // 将当前的任务置为休眠到设置的超时为止
		timeout = schedule_timeout(timeout);
		raw_spin_lock_irq(&sem->lock);
		if (waiter.up)
			return 0;
	}

 timed_out:
    // 清空等待 list
	list_del(&waiter.list);
    // 返回 超时 的错误码
	return -ETIME;

 interrupted:
     // 清空等待 list
	list_del(&waiter.list);
    // 返回 任务没有挂起 的错误码
	return -EINTR;
}
```

#### signal_pending_state

先检测  `state`  [位掩码](https://en.wikipedia.org/wiki/Mask_(computing)) 是否包含  `TASK_INTERRUPTIBLE`  或者  `TASK_WAKEKILL`  位，如果不包含这两个位，函数退出。下一步我们检测当前任务是否有一个挂起信号，如果没有挂起信号函数退出。最后我们就检测  `state`  位掩码的  `TASK_INTERRUPTIBLE`  位。

```c
static inline int signal_pending_state(long state, struct task_struct *p)
{
         // 检查 state 有没有 TASK_INTERRUPTIBLE 和 TASK_WAKEKILL 标志
         if (!(state & (TASK_INTERRUPTIBLE | TASK_WAKEKILL)))
                 return 0;
         // 检查进程是不是处于 pending 状态
         if (!signal_pending(p))
                 return 0;
         return (state & TASK_INTERRUPTIBLE) || __fatal_signal_pending(p);
}
```



如果一个函数想要获取一个已经被其它任务获取的锁，它将会转入到无限循环。并且它不能被信号中断，当前设置的超时不会过期或者当前持有锁的任务不释放它。



### up

释放信号量

```c
oid up(struct semaphore *sem)
{
        unsigned long flags;
        raw_spin_lock_irqsave(&sem->lock, flags);
        // 检查等待队列是不是为空
        if (likely(list_empty(&sem->wait_list)))
                // 为空的话，让可用资源数加一
                sem->count++;
        else // 有进程想要获得锁
                __up(sem);
        raw_spin_unlock_irqrestore(&sem->lock, flags);
}
EXPORT_SYMBOL(up);
```

#### __up

```c
static noinline void __sched __up(struct semaphore *sem)
{
        // 获取等待队列中的第一个任务
        struct semaphore_waiter *waiter = list_first_entry(&sem->wait_list,
                                                struct semaphore_waiter, list);
        // 将进程从等待队列中移除
        list_del(&waiter->list);
        // 设置 waiter->up 为 true，让进程结束等待（跳出 __down_common 中的 死循环）
        waiter->up = true;
        // 唤醒进程
        wake_up_process(waiter->task);
}
```

其实就是，判断当前等待队列里面有没有进程，有的话调用 `__up`，获得等待队列中的第一个进程，然后把它从等待队列里面删除，结束进程的等待，唤醒进程。



本文参考（抄于）

《Linux Inside》：https://github.com/0xAX/linux-insides

《内核揭秘（中文版）》：https://github.com/MintCN/linux-insides-zh

我在书栈网看的，在此推荐一波：https://www.bookstack.cn/ （我在上面的 id：scriptkid）