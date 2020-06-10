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



当进程试图获取互斥锁时，有三种可能的路径，选择哪一种主要取决于锁的当前状态

`fastpath` -- 这是最简单的情况，就是锁没有被任何进程持有

- 获取锁的时候就是让 `owner` 等于获取锁的进程的 `task_struct` 的地址 (原子性操作)

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

  

- 释放锁的时候就是让 `owner` 等于`0` (原子性操作)

  ```
  
  ```

  

`midpath` -- 

`slowpath` -- 







## 初始化互斥锁

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





## mutex_lock

```c
static int processes;
static int mutex_lock(unsigned long *m)
{
	int c;
	int flags = FUTEX_WAIT;
	if (!processes)
		flags |= FUTEX_PRIVATE_FLAG;

	c = cmpxchg(m, 0, 1);
	if (!c)
		return 0;

	if (c == 1)
		c = xchg(m, 2);

	while (c) {
		sys_futex(m, flags, 2, NULL, NULL, 0);
		c = xchg(m, 2);
	}

	return 0;
}
```

cmpxchg 宏 展开

```c
({ 
__typeof__(*( (m) ) )__ret; 
__typeof__(*( (m) ) )__old = ( (0) ); 
__typeof__(*( (m) ) )__new = ( (1) ); 
switch ( (sizeof(*(m) ) ) )
   {
   case 1: { 
   volatile u8 *__ptr = (volatile u8 *) ( (m) ); 
   asm volatile (
					"\n\tlock; " "cmpxchgb %2,%1" 
						: "=a" (__ret), "+m" (*__ptr) 
						: "q" (__new), "0" (__old) 
						: "memory");
   break; 
   } 
   case 2: { 
   volatile u16 *__ptr = (volatile u16 *) ( (m) );
   asm volatile (
					"\n\tlock; " "cmpxchgw %2,%1" 
						: "=a" (__ret), "+m" (*__ptr) 
						: "r" (__new), "0" (__old) 
						: "memory");
   break;
   } 
   case 4: { 
   volatile u32 *__ptr = (volatile u32 *) ( (m) );
   asm volatile (
					"\n\tlock; " "cmpxchgl %2,%1" 
					: "=a" (__ret), "+m" (*__ptr) 
					: "r" (__new), "0" (__old) 
					: "memory");
   break;
   } 
   case -1: 
   { 
   volatile u64 *__ptr = (volatile u64 *) ( (m) ); 
   asm volatile (
					"\n\tlock; " "cmpxchgq %2,%1" 
					: "=a" (__ret), "+m" (*__ptr) 
					: "r" (__new), "0" (__old) 
					: "memory");
   break; 
   } 
   default: 
   __cmpxchg_wrong_size();
   }
   __ret; })
```





## mutex_unlock

```c
static int processes;
static int mutex_unlock(unsigned long *m)
{
	int flags = FUTEX_WAKE;
	if (!processes)
		flags |= FUTEX_PRIVATE_FLAG;

	if (*m == 2)
		*m = 0;
	else if (xchg(m, 0) == 1)
		return 0;

	sys_futex(m, flags, 1, NULL, NULL, 0);

	return 0;
}
```

