Linux内核源码分析 -- 同步原语 -- 互斥锁 `mutex` 

```c

/*
 * Simple, straightforward mutexes with strict semantics:
 *
 * - only one task can hold the mutex at a time (同一时间仅能被一个进程持有)
 * - only the owner can unlock the mutex (只有锁的持有者才能进行解锁操作)
 * - multiple unlocks are not permitted (不能进行多次解锁)
 * - recursive locking is not permitted (不能进行递归加锁)
 * - a mutex object must be initialized via the API (mutex 结构只能通过API 区初始化)
 * - a mutex object must not be initialized via memset or copying (mutex 不能通过 memset 或者拷贝进行初始化)
 * - task may not exit with mutex held (获取互斥锁后进程可能不能退出)
 * - memory areas where held locks reside must not be freed
 * - held mutexes must not be reinitialized (被持有的互斥锁不能进行再次初始化)
 * - mutexes may not be used in hardware or software interrupt (互斥锁不能用在硬件或者软件上下文)
 *   contexts such as tasklets and timers
 *
 * These semantics are fully enforced when DEBUG_MUTEXES is
 * enabled. Furthermore, besides enforcing the above rules, the mutex
 * debugging code also implements a number of additional features
 * that make lock debugging easier and faster:
 *
 * - uses symbolic names of mutexes, whenever they are printed in debug output
 * - point-of-acquire tracking, symbolic lookup of function names
 * - list of all locks held in the system, printout of them
 * - owner tracking
 * - detects self-recursing locks and prints out all relevant info
 * - detects multi-task circular deadlocks and prints out all affected
 *   locks and tasks (and only those tasks)
 */
struct mutex {
	atomic_long_t		owner;
	spinlock_t		wait_lock;
#ifdef CONFIG_MUTEX_SPIN_ON_OWNER
	struct optimistic_spin_queue osq; /* Spinner MCS lock */
#endif
	struct list_head	wait_list;
#ifdef CONFIG_DEBUG_MUTEXES
	void			*magic;
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	dep_map;
#endif
};
```

`owner` -- 原子计数，用于指向锁持有者的 `task_struct` 结构，当 `owner`  等于 `0` 时表明锁没有被持有，当 `owner`  不等于 `0` 时表明锁被其他进程持有

`wait_list` -- 等待队列

`wait_lock`  -- 一个自旋锁,用来保护  `wait_list `(等待队列)

## 初始化互斥锁 -- mutex_init

方法 1：

DEFINE_MUTEX(mutexname)

```c
#define DEFINE_MUTEX(mutexname) \
	struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)
```

__MUTEX_INITIALIZER(lockname)

```c
#define __MUTEX_INITIALIZER(lockname) \
		{ .owner = ATOMIC_LONG_INIT(0) \
		, .wait_lock = __SPIN_LOCK_UNLOCKED(lockname.wait_lock) \
		, .wait_list = LIST_HEAD_INIT(lockname.wait_list) \
		__DEBUG_MUTEX_INITIALIZER(lockname) \
		__DEP_MAP_MUTEX_INITIALIZER(lockname) }
```

 `owner` 初始化为 `0`，表明这个锁刚开始是 `unlock`

`wait_lock` 初始化保护等待队列的锁，是个自旋锁

`wait_list` 初始化 等待队列，是一个链表



方法2：

mutex_init

```c
#define mutex_init(mutex)						\
do {									\
	static struct lock_class_key __key;				\
									\
	__mutex_init((mutex), #mutex, &__key);				\
} while (0)
```

__mutex_init

```c
void
__mutex_init(struct mutex *lock, const char *name, struct lock_class_key *key)
{
	atomic_long_set(&lock->owner, 0); // 一样调用 atomic_long_set 把 &lock->owner 置为 0
	spin_lock_init(&lock->wait_lock); // 初始化保护等待队列的自旋锁
	INIT_LIST_HEAD(&lock->wait_list); // 初始化等待队列
#ifdef CONFIG_MUTEX_SPIN_ON_OWNER
	osq_lock_init(&lock->osq);
#endif

	debug_mutex_init(lock, name, key);
}
EXPORT_SYMBOL(__mutex_init);
```



## 请求持有互斥锁 -- mutex_lock

### mutex_lock

请求一个 互斥锁

```c
/**
 * mutex_lock - acquire the mutex
 * @lock: the mutex to be acquired
 *
 * Lock the mutex exclusively for this task. If the mutex is not
 * available right now, it will sleep until it can get it.
 *
 * The mutex must later on be released by the same task that
 * acquired it. Recursive locking is not allowed. The task
 * may not exit without first unlocking the mutex. Also, kernel
 * memory where the mutex resides must not be freed with
 * the mutex still locked. The mutex must first be initialized
 * (or statically defined) before it can be locked. memset()-ing
 * the mutex to 0 is not allowed.
 *
 * (The CONFIG_DEBUG_MUTEXES .config option turns on debugging
 * checks that will enforce the restrictions and will also do
 * deadlock debugging)
 *
 * This function is similar to (but not equivalent to) down().
 */
void __sched mutex_lock(struct mutex *lock)
{
	might_sleep();

	if (!__mutex_trylock_fast(lock)) // 尝试先从 fastpath 去获取锁
		__mutex_lock_slowpath(lock); // 失败的话从 midpath 去获取锁
}
EXPORT_SYMBOL(mutex_lock);
```





当进程试图获取互斥锁时，有两种可能的路径，选择哪一种主要取决于锁的当前状态



1.`fastpath` -- 这是最简单的情况，就是锁没有被任何进程持有

获取锁的时候就是让 `owner` 等于获取锁的进程的 `task_struct` 的地址 (原子性操作)

### __mutex_trylock_fast

```c
/*
 * Optimistic trylock that only works in the uncontended case. Make sure to
 * follow with a __mutex_trylock() before failing.
 */
static __always_inline bool __mutex_trylock_fast(struct mutex *lock)
{
    // current 宏其实就是获取当前进程的 task_struct 的地址
	unsigned long curr = (unsigned long)current;
	unsigned long zero = 0UL;

    // 把 &lock->owner 设置成 curr (原子操作)
	if (atomic_long_try_cmpxchg_acquire(&lock->owner, &zero, curr))
		return true;

	return false;
}
```



2.`slowpath`   -- 当请求的锁处于被持有状态的时候则会走这条路

### __mutex_lock_slowpath

@lock -- 要请求的锁

```c
static noinline void __sched
__mutex_lock_slowpath(struct mutex *lock)
{
	__mutex_lock(lock, TASK_UNINTERRUPTIBLE, 0, NULL, _RET_IP_);
}
```

这里说一下 _RET_IP\_ 其实这个是个宏

```c
(unsigned long)__builtin_return_address(0)
```

`__builtin_return_address` 是  `gcc` 的内建函数，其实就是用来获取函数的返回地址，这里是 `0` 



#### __mutex_lock

```c
static int __sched
__mutex_lock(struct mutex *lock, long state, unsigned int subclass,
	     struct lockdep_map *nest_lock, unsigned long ip)
{
	return __mutex_lock_common(lock, state, subclass, nest_lock, ip, NULL, false);
}
```

#### __mutex_lock_common

阻塞进程真正获取锁的地方

```c
struct ww_mutex {
	struct mutex base;
	struct ww_acquire_ctx *ctx;
#ifdef CONFIG_DEBUG_MUTEXES
	struct ww_class *ww_class;
#endif
};
```

```c
/*
 * Lock a mutex (possibly interruptible), slowpath:
 */
static __always_inline int __sched
__mutex_lock_common(struct mutex *lock, long state, unsigned int subclass,
		    struct lockdep_map *nest_lock, unsigned long ip,
		    struct ww_acquire_ctx *ww_ctx, const bool use_ww_ctx)
{
	struct mutex_waiter waiter;
	bool first = false;
	struct ww_mutex *ww;
	int ret;

	might_sleep();

#ifdef CONFIG_DEBUG_MUTEXES
	DEBUG_LOCKS_WARN_ON(lock->magic != lock);
#endif

  // 获取 lock 对应的 ww_mutex 结构的地址（因为 mutex 结构在 ww_mutex 对应的是 base 字段。在 Linux 内核里面这是个很出名的用的范围也广的宏，还有 offsetof）
	ww = container_of(lock, struct ww_mutex, base);
	if (use_ww_ctx && ww_ctx) {
		if (unlikely(ww_ctx == READ_ONCE(ww->ctx)))
			return -EALREADY;

		/*
		 * Reset the wounded flag after a kill. No other process can
		 * race and wound us here since they can't have a valid owner
		 * pointer if we don't have any locks held.
		 */
		if (ww_ctx->acquired == 0)
			ww_ctx->wounded = 0;
	}

	preempt_disable(); // 禁止内核抢占
	mutex_acquire_nest(&lock->dep_map, subclass, 0, nest_lock, ip);

  // 尝试获取 锁
	if (__mutex_trylock(lock) ||
	    mutex_optimistic_spin(lock, ww_ctx, use_ww_ctx, NULL)) {
		/* got the lock, yay! */
		lock_acquired(&lock->dep_map, ip);
		if (use_ww_ctx && ww_ctx)
			ww_mutex_set_context_fastpath(ww, ww_ctx);
		preempt_enable(); // 恢复内核抢占
		return 0;
	}

	spin_lock(&lock->wait_lock);
	/*
	 * After waiting to acquire the wait_lock, try again.
	 */
	if (__mutex_trylock(lock)) {
		if (use_ww_ctx && ww_ctx)
			__ww_mutex_check_waiters(lock, ww_ctx);

		goto skip_wait;
	}

	debug_mutex_lock_common(lock, &waiter);

	lock_contended(&lock->dep_map, ip);

	if (!use_ww_ctx) {
		/* add waiting tasks to the end of the waitqueue (FIFO): */
		__mutex_add_waiter(lock, &waiter, &lock->wait_list);


#ifdef CONFIG_DEBUG_MUTEXES
		waiter.ww_ctx = MUTEX_POISON_WW_CTX;
#endif
	} else {
		/*
		 * Add in stamp order, waking up waiters that must kill
		 * themselves.
		 */
		ret = __ww_mutex_add_waiter(&waiter, lock, ww_ctx);
		if (ret)
			goto err_early_kill;

		waiter.ww_ctx = ww_ctx;
	}

	waiter.task = current;

	set_current_state(state);
	for (;;) {
		/*
		 * Once we hold wait_lock, we're serialized against
		 * mutex_unlock() handing the lock off to us, do a trylock
		 * before testing the error conditions to make sure we pick up
		 * the handoff.
		 */
		if (__mutex_trylock(lock))
			goto acquired;

		/*
		 * Check for signals and kill conditions while holding
		 * wait_lock. This ensures the lock cancellation is ordered
		 * against mutex_unlock() and wake-ups do not go missing.
		 */
		if (signal_pending_state(state, current)) {
			ret = -EINTR;
			goto err;
		}

		if (use_ww_ctx && ww_ctx) {
			ret = __ww_mutex_check_kill(lock, &waiter, ww_ctx);
			if (ret)
				goto err;
		}

		spin_unlock(&lock->wait_lock);
		schedule_preempt_disabled();

		/*
		 * ww_mutex needs to always recheck its position since its waiter
		 * list is not FIFO ordered.
		 */
		if ((use_ww_ctx && ww_ctx) || !first) {
			first = __mutex_waiter_is_first(lock, &waiter);
			if (first)
				__mutex_set_flag(lock, MUTEX_FLAG_HANDOFF);
		}

		set_current_state(state);
		/*
		 * Here we order against unlock; we must either see it change
		 * state back to RUNNING and fall through the next schedule(),
		 * or we must see its unlock and acquire.
		 */
		if (__mutex_trylock(lock) ||
		    (first && mutex_optimistic_spin(lock, ww_ctx, use_ww_ctx, &waiter)))
			break;

		spin_lock(&lock->wait_lock);
	}
	spin_lock(&lock->wait_lock);
acquired:
	__set_current_state(TASK_RUNNING);

	if (use_ww_ctx && ww_ctx) {
		/*
		 * Wound-Wait; we stole the lock (!first_waiter), check the
		 * waiters as anyone might want to wound us.
		 */
		if (!ww_ctx->is_wait_die &&
		    !__mutex_waiter_is_first(lock, &waiter))
			__ww_mutex_check_waiters(lock, ww_ctx);
	}

	mutex_remove_waiter(lock, &waiter, current);
	if (likely(list_empty(&lock->wait_list)))
		__mutex_clear_flag(lock, MUTEX_FLAGS);

	debug_mutex_free_waiter(&waiter);

skip_wait:
	/* got the lock - cleanup and rejoice! */
	lock_acquired(&lock->dep_map, ip);

	if (use_ww_ctx && ww_ctx)
		ww_mutex_lock_acquired(ww, ww_ctx);

	spin_unlock(&lock->wait_lock);
	preempt_enable();
	return 0;

err:
	__set_current_state(TASK_RUNNING);
	mutex_remove_waiter(lock, &waiter, current);
err_early_kill:
	spin_unlock(&lock->wait_lock);
	debug_mutex_free_waiter(&waiter);
	mutex_release(&lock->dep_map, ip);
	preempt_enable();
	return ret;
}
```

__mutex_trylock

先说一下 mutex 标志位（task_struxt 的 低 3 bits）

```c
/*
 * @owner: contains: 'struct task_struct *' to the current lock owner,
 * NULL means not owned. Since task_struct pointers are aligned at
 * at least L1_CACHE_BYTES, we have low bits to store extra state.
 *
 * Bit0 indicates a non-empty waiter list; unlock must issue a wakeup.
 * Bit1 indicates unlock needs to hand the lock to the top-waiter
 * Bit2 indicates handoff has been done and we're waiting for pickup.
 */
#define MUTEX_FLAG_WAITERS	0x01
#define MUTEX_FLAG_HANDOFF	0x02
#define MUTEX_FLAG_PICKUP	0x04

#define MUTEX_FLAGS		0x07
```



```c
/*
 * Trylock variant that retuns the owning task on failure.
 */
static inline struct task_struct *__mutex_trylock_or_owner(struct mutex *lock)
{
  // 获取当前进程的 task_struct
	unsigned long owner, curr = (unsigned long)current;

  // 获取 lock 的持有者
	owner = atomic_long_read(&lock->owner);
	for (;;) { /* must loop, can race against a flag */
		unsigned long old, flags = __owner_flags(owner);  // owner & 0x7
		unsigned long task = owner & ~MUTEX_FLAGS; // MUTEX_FLAGS = 0x7

		if (task) {
      // 如果锁的持有者不是当前进程直接跳出循环
			if (likely(task != curr))
				break;

      // 
			if (likely(!(flags & MUTEX_FLAG_PICKUP)))
				break;

			flags &= ~MUTEX_FLAG_PICKUP;
		} else {
#ifdef CONFIG_DEBUG_MUTEXES
			DEBUG_LOCKS_WARN_ON(flags & MUTEX_FLAG_PICKUP);
#endif
		}

		/*
		 * We set the HANDOFF bit, we must make sure it doesn't live
		 * past the point where we acquire it. This would be possible
		 * if we (accidentally) set the bit on an unlocked mutex.
		 */
		flags &= ~MUTEX_FLAG_HANDOFF;

		old = atomic_long_cmpxchg_acquire(&lock->owner, owner, curr | flags);
		if (old == owner)
			return NULL;

		owner = old;
	}

	return __owner_task(owner);
}
```



## mutex_unlock



