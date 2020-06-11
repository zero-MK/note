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

  // 尝试获取锁
	if (__mutex_trylock(lock) ||
	    mutex_optimistic_spin(lock, ww_ctx, use_ww_ctx, NULL)) {
		/* got the lock, yay! */
        // 执行到这里说明获取锁成功
		lock_acquired(&lock->dep_map, ip);
		if (use_ww_ctx && ww_ctx)
			ww_mutex_set_context_fastpath(ww, ww_ctx);
		preempt_enable(); // 恢复内核抢占
		return 0;
	}

	spin_lock(&lock->wait_lock); // 上锁等待队列
	/*
	 * After waiting to acquire the wait_lock, try again.
	 */
    // 再次尝试
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

    // 设置的状态取决于在调用 __mutex_lock 函数
    // 设置当前进程的状态（当是 __mutex_lock_slowpath 调用过来的话就是把当前进程状态设置成不可中断）
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

 Since task_struct pointers are aligned at least L1_CACHE_BYTES, we have low bits to store extra state.

由于 `task_struct`  指针向 `L1_CACHE_BYTES` 对齐（至于数值是多少的看架构，位于 `arch/xxxx/include/asm/cache.h` 里面），这样用低 `3` bits 做标识，并不会有影响

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

Bit0：表明 等待队列非空，解锁时要执行唤醒（wakeup）操作（唤醒等待的进程）

Bit1：释放锁时要把锁交给等待队列的第一个等待进程（top-waiter）

Bit2：锁的状态切换已经完成，等待被获取



__mutex_trylock_or_owner

 尝试上锁，成功的话返回持有者的 `task_struct` 指针

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
    // 有点像自旋锁的操作
	for (;;) { /* must loop, can race against a flag */
        // 取出标志位
		unsigned long old, flags = __owner_flags(owner);  // owner & 0x7
        // 获得真正的 task_struxt 的地址（屏蔽掉 mutex 的 flags）
		unsigned long task = owner & ~MUTEX_FLAGS; // MUTEX_FLAGS = 0x7

		if (task) {
     		 // 如果锁的持有者不是当前进程直接跳出循环
			if (likely(task != curr))
				break;

      		// 如果锁现在处于不可获取的状态跳出循环
			if (likely(!(flags & MUTEX_FLAG_PICKUP)))
				break;

            // 把 flags 的 MUTEX_FLAG_PICKUP 置反
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
        // 设置 状态切换位 （HANDOFF bit）
		flags &= ~MUTEX_FLAG_HANDOFF;

        // &lock->owner = (curr | flags); return (curr | flags);  (原子操作)
		old = atomic_long_cmpxchg_acquire(&lock->owner, owner, curr | flags);
        //  检查更改 锁 的所有者是否成功
		if (old == owner)
			return NULL;

        // owner =  (curr | flags)，仔细看吧
		owner = old;
	}

    // 返回指向锁的持有者的，屏蔽 flags 后的 task_struct 指针
	return __owner_task(owner);
}
```

```c
static inline struct task_struct *__owner_task(unsigned long owner)
{
	return (struct task_struct *)(owner & ~MUTEX_FLAGS);
}
```

mutex_optimistic_spin

```c
/*
 * Optimistic spinning.
 *
 * We try to spin for acquisition when we find that the lock owner
 * is currently running on a (different) CPU and while we don't
 * need to reschedule. The rationale is that if the lock owner is
 * running, it is likely to release the lock soon.
 *
 * The mutex spinners are queued up using MCS lock so that only one
 * spinner can compete for the mutex. However, if mutex spinning isn't
 * going to happen, there is no point in going through the lock/unlock
 * overhead.
 *
 * Returns true when the lock was taken, otherwise false, indicating
 * that we need to jump to the slowpath and sleep.
 *
 * The waiter flag is set to true if the spinner is a waiter in the wait
 * queue. The waiter-spinner will spin on the lock directly and concurrently
 * with the spinner at the head of the OSQ, if present, until the owner is
 * changed to itself.
 */
static __always_inline bool
mutex_optimistic_spin(struct mutex *lock, struct ww_acquire_ctx *ww_ctx,
		      const bool use_ww_ctx, struct mutex_waiter *waiter)
{
	if (!waiter) {
		/*
		 * The purpose of the mutex_can_spin_on_owner() function is
		 * to eliminate the overhead of osq_lock() and osq_unlock()
		 * in case spinning isn't possible. As a waiter-spinner
		 * is not going to take OSQ lock anyway, there is no need
		 * to call mutex_can_spin_on_owner().
		 */
        // 
		if (!mutex_can_spin_on_owner(lock))
			goto fail;

		/*
		 * In order to avoid a stampede of mutex spinners trying to
		 * acquire the mutex all at once, the spinners need to take a
		 * MCS (queued) lock first before spinning on the owner field.
		 */
		if (!osq_lock(&lock->osq))
			goto fail;
	}

	for (;;) {
		struct task_struct *owner;

		/* Try to acquire the mutex... */
        // 获取锁的持有者
		owner = __mutex_trylock_or_owner(lock);
		if (!owner)
			break;

		/*
		 * There's an owner, wait for it to either
		 * release the lock or go to sleep.
		 */
		if (!mutex_spin_on_owner(lock, owner, ww_ctx, waiter))
			goto fail_unlock;

		/*
		 * The cpu_relax() call is a compiler barrier which forces
		 * everything in this loop to be re-loaded. We don't need
		 * memory barriers as we'll eventually observe the right
		 * values at the cost of a few extra spins.
		 */
		cpu_relax();
	}

	if (!waiter)
		osq_unlock(&lock->osq);

	return true;


fail_unlock:
	if (!waiter)
		osq_unlock(&lock->osq);

fail:
	/*
	 * If we fell out of the spin path because of need_resched(),
	 * reschedule now, before we try-lock the mutex. This avoids getting
	 * scheduled out right after we obtained the mutex.
	 */
	if (need_resched()) {
		/*
		 * We _should_ have TASK_RUNNING here, but just in case
		 * we do not, make it so, otherwise we might get stuck.
		 */
		__set_current_state(TASK_RUNNING);
		schedule_preempt_disabled();
	}

	return false;
}
```

mutex_can_spin_on_owner

```c
/*
 * Initial check for entering the mutex spinning loop
 */
static inline int mutex_can_spin_on_owner(struct mutex *lock)
{
	struct task_struct *owner;
	int retval = 1;

	if (need_resched())
		return 0;

	rcu_read_lock();
    // 获取锁的持有者
	owner = __mutex_owner(lock);

	/*
	 * As lock holder preemption issue, we both skip spinning if task is not
	 * on cpu or its cpu is preempted
	 */
    // 如果任务不在 cpu 上或其 cpu 被抢占，都会跳过旋转
	if (owner)
		retval = owner->on_cpu && !vcpu_is_preempted(task_cpu(owner));
	rcu_read_unlock();

	/*
	 * If lock->owner is not set, the mutex has been released. Return true
	 * such that we'll trylock in the spin path, which is a faster option
	 * than the blocking slow path.
	 */
    // 如果 lock->owner 没有设置，就说明锁是 释放（released） 状态
    // 这样的话我们尝试走 spin path 去获取锁，这是一个比阻塞 slow path 更快的选项。
	return retval;
}
```



mutex_spin_on_owner

```c

/*
 * Look out! "owner" is an entirely speculative pointer access and not
 * reliable.
 *
 * "noinline" so that this function shows up on perf profiles.
 */
static noinline
bool mutex_spin_on_owner(struct mutex *lock, struct task_struct *owner,
			 struct ww_acquire_ctx *ww_ctx, struct mutex_waiter *waiter)
{
	bool ret = true;

	rcu_read_lock();
	while (__mutex_owner(lock) == owner) {
		/*
		 * Ensure we emit the owner->on_cpu, dereference _after_
		 * checking lock->owner still matches owner. If that fails,
		 * owner might point to freed memory. If it still matches,
		 * the rcu_read_lock() ensures the memory stays valid.
		 */
        // 内存屏障
		barrier();

		/*
		 * Use vcpu_is_preempted to detect lock holder preemption issue.
		 */
		if (!owner->on_cpu || need_resched() ||
				vcpu_is_preempted(task_cpu(owner))) {
			ret = false;
			break;
		}

		if (ww_ctx && !ww_mutex_spin_on_owner(lock, ww_ctx, waiter)) {
			ret = false;
			break;
		}

		cpu_relax();
	}
	rcu_read_unlock();

	return ret;
}
```





## mutex_unlock

这个也分两个路径

释放一个互斥锁

```c
/**
 * mutex_unlock - release the mutex
 * @lock: the mutex to be released
 *
 * Unlock a mutex that has been locked by this task previously.
 *
 * This function must not be used in interrupt context. Unlocking
 * of a not locked mutex is not allowed.
 *
 * This function is similar to (but not equivalent to) up().
 */
void __sched mutex_unlock(struct mutex *lock)
{
#ifndef CONFIG_DEBUG_LOCK_ALLOC
	if (__mutex_unlock_fast(lock))
		return;
#endif
	__mutex_unlock_slowpath(lock, _RET_IP_);
}
EXPORT_SYMBOL(mutex_unlock);
```



### __mutex_unlock_fast

通过 `fastpath` 去释放锁

```c
static __always_inline bool __mutex_unlock_fast(struct mutex *lock)
{
    // 获取当前进程的task_struct 的地址
	unsigned long curr = (unsigned long)current;

    // &lock->owner = 0; (原子操作)
	if (atomic_long_cmpxchg_release(&lock->owner, curr, 0UL) == curr)
		return true;

	return false;
}
```



### __mutex_unlock_slowpath

通过 `slowpath` 去释放锁

```c
/*
 * Release the lock, slowpath:
 */
static noinline void __sched __mutex_unlock_slowpath(struct mutex *lock, unsigned long ip)
{
	struct task_struct *next = NULL;
	DEFINE_WAKE_Q(wake_q);
	unsigned long owner;

	mutex_release(&lock->dep_map, ip);

	/*
	 * Release the lock before (potentially) taking the spinlock such that
	 * other contenders can get on with things ASAP.
	 *
	 * Except when HANDOFF, in that case we must not clear the owner field,
	 * but instead set it to the top waiter.
	 */
	owner = atomic_long_read(&lock->owner);
	for (;;) {
		unsigned long old;

#ifdef CONFIG_DEBUG_MUTEXES
		DEBUG_LOCKS_WARN_ON(__owner_task(owner) != current);
		DEBUG_LOCKS_WARN_ON(owner & MUTEX_FLAG_PICKUP);
#endif

		if (owner & MUTEX_FLAG_HANDOFF)
			break;

		old = atomic_long_cmpxchg_release(&lock->owner, owner,
						  __owner_flags(owner));
		if (old == owner) {
			if (owner & MUTEX_FLAG_WAITERS)
				break;

			return;
		}

		owner = old;
	}

	spin_lock(&lock->wait_lock);
	debug_mutex_unlock(lock);
	if (!list_empty(&lock->wait_list)) {
		/* get the first entry from the wait-list: */
		struct mutex_waiter *waiter =
			list_first_entry(&lock->wait_list,
					 struct mutex_waiter, list);

		next = waiter->task;

		debug_mutex_wake_waiter(lock, waiter);
		wake_q_add(&wake_q, next);
	}

	if (owner & MUTEX_FLAG_HANDOFF)
		__mutex_handoff(lock, next);

	spin_unlock(&lock->wait_lock);

	wake_up_q(&wake_q);
}
```

