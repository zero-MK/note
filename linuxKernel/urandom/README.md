探索一下 Linux 内核提供的随机数生成器

字符设备：/dev/random 和 /dev/urandom

```
$ ls -l /dev/*random
crw-rw-rw- 1 root root 1, 8 Dec  6 16:31 /dev/random
crw-rw-rw- 1 root root 1, 9 Dec  6 16:31 /dev/urandom
```

源码位于：drivers/char/random.c

版本：Linux kernel-5.6

字符设备，肯定填写了 `file_operations` 结构

```c
const struct file_operations random_fops = {
	.read  = random_read,
	.write = random_write,
	.poll  = random_poll,
	.unlocked_ioctl = random_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.fasync = random_fasync,
	.llseek = noop_llseek,
};

const struct file_operations urandom_fops = {
	.read  = urandom_read,
	.write = random_write,
	.unlocked_ioctl = random_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.fasync = random_fasync,
	.llseek = noop_llseek,
};
```

可以看到  urandom 注册了 6 个操作函数，我们关注的是 urandom_read 和 random_write

也就是我们 使用 open 去打开 /dev/random 或者 /dev/urandom 后，对设备进行读写时触发的函数

random 和 urandom 的 write 函数是一样的，都是往熵池里面写入数据

但是 read 函数是各自实现的，这是为啥？其实稍微了解过这两个 ”文件“ 的人应该都能猜到

直接开始探索源码

## urandom_read

先来看看 urandom_read

```c
static ssize_t
urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
	unsigned long flags;
	static int maxwarn = 10;
    
    // 检查 crng_init 变量，是否初始化
	if (!crng_ready() && maxwarn > 0) {
		maxwarn--;
        // 解锁 warn_urandom_randomness 结构
		if (__ratelimit(&urandom_warning))
			pr_notice("%s: uninitialized urandom read (%zd bytes read)\n",
				  current->comm, nbytes);
        // 给 主加密随机数生成器 加锁，并屏蔽中断
		spin_lock_irqsave(&primary_crng.lock, flags);
        // 进入临界区
        // crng_init_cnt 设置为 0
		crng_init_cnt = 0;
        // 设置完 crng_init_cnt 解锁，恢复中断
		spin_unlock_irqrestore(&primary_crng.lock, flags);
	}

	return urandom_read_nowarn(file, buf, nbytes, ppos);
}
```

### urandom_read_nowarn

```c
static ssize_t
urandom_read_nowarn(struct file *file, char __user *buf, size_t nbytes,
		    loff_t *ppos)
{
	int ret;
    
    // min_t 就是取 nbytes 和 INT_MAX >> (ENTROPY_SHIFT + 3) 中的最小值
    // INT_MAX >> (ENTROPY_SHIFT + 3) 展开就是 0x7fffffff >> 6
    // 翻译成人话就是一次调用 urandom_read_nowarn 所能产生的随机数据最大为 0x7fffffff >> 6
	nbytes = min_t(size_t, nbytes, INT_MAX >> (ENTROPY_SHIFT + 3));
    // 继续下一步
	ret = extract_crng_user(buf, nbytes);
	trace_urandom_read(8 * nbytes, 0, ENTROPY_BITS(&input_pool));
	return ret;
}
```

### extract_crng_user

```c
static ssize_t extract_crng_user(void __user *buf, size_t nbytes)
{
	ssize_t ret = 0, i = CHACHA_BLOCK_SIZE;
    // tmp 是一个拥有 64 个 __u8 成员的数组， __aligned(4) 向 4 对齐
	__u8 tmp[CHACHA_BLOCK_SIZE] __aligned(4);
    // 请求是否超过 256 字节
	int large_request = (nbytes > 256);

	while (nbytes) {
        // 请求的数据大于 256 字节 并且进程需要重新调度
		if (large_request && need_resched()) {
            // 检查当前进程是否有信号要处理
			if (signal_pending(current)) {
				if (ret == 0)
					ret = -ERESTARTSYS;
				break;
			}
            // 调度
			schedule();
		}
        
        // 生成随机数据存入 tmp
		extract_crng(tmp);
        // 每轮 while 循环拷贝给用户的数据的大小
		i = min_t(int, nbytes, CHACHA_BLOCK_SIZE);
        // 分两种情况，就是 nbytes 小于 CHACHA_BLOCK_SIZE 时就拷贝 nbytes 的数据
        // nbytes 大于 CHACHA_BLOCK_SIZE 时就拷贝 CHACHA_BLOCK_SIZE 的数据
		if (copy_to_user(buf, tmp, i)) {
			ret = -EFAULT;
			break;
		}
        
        // nbytes 就是还需要多少随机数据
		nbytes -= i;
		buf += i;
		ret += i;
	}
	crng_backtrack_protect(tmp, i);

	/* Wipe data just written to memory */
	memzero_explicit(tmp, sizeof(tmp));

	return ret;
}
```

### extract_crng

```c
static void extract_crng(__u8 out[CHACHA_BLOCK_SIZE])
{
	struct crng_state *crng = NULL;
// 开启多 CPU 支持时
#ifdef CONFIG_NUMA
    // 获取当前 CPU 上对应的 crng_state
	if (crng_node_pool)
		crng = crng_node_pool[numa_node_id()];
    // 如果当前 CPU 上对应的 crng_state 为空
	if (crng == NULL)
#endif
        // 使用 primary_crng 里面保存 state 和 time
        // (因为在单 CPU 的系统中不会并行访问，只要一个 primary_crng 就足够了
        // 或者说当前 CPU 上没有对应的 crng_state，那就使用 primary_crng）
		crng = &primary_crng;
	_extract_crng(crng, out);
}
```

### _extract_crng

```c
static void _extract_crng(struct crng_state *crng,
			  __u8 out[CHACHA_BLOCK_SIZE])
{
	unsigned long v, flags;
    
    // crng_ready 检查 crng 有没有初始化
    // 然后检查时间，CRNG_RESEED_INTERVAL 是一个时间间隔，每过 CRNG_RESEED_INTERVAL 就重新播种（这里的时间指的是系统时间节拍，jiffies 表示的是当前的系统时钟节拍总数，它统计的是从开机到现在的系统时间节拍）
	if (crng_ready() &&
	    (time_after(crng_global_init_time, crng->init_time) ||
	     time_after(jiffies, crng->init_time + CRNG_RESEED_INTERVAL)))
        // 重新播种
		crng_reseed(crng, crng == &primary_crng ? &input_pool : NULL);
    
    // 上锁 crng ，并屏蔽中断
	spin_lock_irqsave(&crng->lock, flags);
    
    // 主要就是这里了，每个架构都有自己的实现方式
	if (arch_get_random_long(&v))
        // 更新 state ，把生成的随机数据和 state[14] 异或然后放入 state[14]
		crng->state[14] ^= v;
    // 经过一次 chacha20 再输出
	chacha20_block(&crng->state[0], out);
	if (crng->state[12] == 0)
		crng->state[13]++;
    // 解锁，恢复中断
	spin_unlock_irqrestore(&crng->lock, flags);
}
```

### arch_get_random_long

现在探究的是 x86 ，所以 arch_get_random_long 对应的函数位于 arch/x86/include/asm/archrandom.h

```c
static inline bool __must_check arch_get_random_long(unsigned long *v)
{
    // 检查 cpu 是否支持 rdrand 指令，支持的话调用 rdrand_long
	return static_cpu_has(X86_FEATURE_RDRAND) ? rdrand_long(v) : false;
}
static inline bool __must_check rdrand_long(unsigned long *v)
{
	bool ok;
    // RDRAND_RETRY_LOOPS == 10
	unsigned int retry = RDRAND_RETRY_LOOPS;
    // 进行 10 轮 rdrand，intel 推荐至少 10 轮，可以看看维基百科 rdrand 条目，或者看 intel 手册
	do {
		asm volatile(RDRAND_LONG
			     CC_SET(c)
			     : CC_OUT(c) (ok), "=a" (*v));
		if (ok)
			return true;
	} while (--retry);
	return false;
}
```



## random_read



```c
static ssize_t random_read(struct file *file, char __user *buf, size_t nbytes,
			   loff_t *ppos)
{
	int ret;

    // 等待 urandom 池被播种（返回 0 的话说明 urandom 池已经被播种）
	ret = wait_for_random_bytes();
	if (ret != 0)
		return ret;
    // 走 urandom 的路线生成
	return urandom_read_nowarn(file, buf, nbytes, ppos);
}
```



### wait_for_random_bytes

```c
int wait_for_random_bytes(void)
{
    // 检查 crng 有没有初始化，没有直接 return 0
	if (likely(crng_ready()))
		return 0;
    
    // 一直等待（有点像自旋锁）
	do {
		int ret;
        // 休眠，这里设置的超时时间 HZ 是 1000 个系统节拍（超时的时间单位是：系统时钟节拍）
        // 1000 系统时钟节拍后检查 crng 初始化，crng 初始化 ret = 1，没有初始化 ret = 0
		ret = wait_event_interruptible_timeout(crng_init_wait,
						       crng_ready(), HZ);
        
        // 当检查 crng 为已经初始化，直接返回
		if (ret)
			return ret > 0 ? 0 : ret;
        // 尝试产生足够的 熵
		try_to_generate_entropy();
	} while (!crng_ready());

	return 0;
}
EXPORT_SYMBOL(wait_for_random_bytes);
```



### wait_event_interruptible_timeout

```c
/**
 * wait_event_interruptible_timeout - sleep until a condition gets true or a timeout elapses
 * @wq_head: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received.
 * The @condition is checked each time the waitqueue @wq_head is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * Returns:
 * 0 if the @condition evaluated to %false after the @timeout elapsed,
 * 1 if the @condition evaluated to %true after the @timeout elapsed,
 * the remaining jiffies (at least 1) if the @condition evaluated
 * to %true before the @timeout elapsed, or -%ERESTARTSYS if it was
 * interrupted by a signal.
 */
#define wait_event_interruptible_timeout(wq_head, condition, timeout)		\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_interruptible_timeout(wq_head,		\
						condition, timeout);		\
	__ret;									\
})
```



### try_to_generate_entropy

```c
/*
 * If we have an actual cycle counter, see if we can
 * generate enough entropy with timing noise
 */
// 使用计时器噪声填充熵
static void try_to_generate_entropy(void)
{
	struct {
		unsigned long now;
		struct timer_list timer;
	} stack;

	stack.now = random_get_entropy();

	/* Slow counter - or none. Don't even bother */
	if (stack.now == random_get_entropy())
		return;

    // 设置计时器 timer，entropy_timer 是一个回调函数，第三个参数 0 是 entropy_timer 的参数（为空）
	timer_setup_on_stack(&stack.timer, entropy_timer, 0);
    // 一直尝试初始化 crng
	while (!crng_ready()) {
        // 如果计时器没有被挂起
		if (!timer_pending(&stack.timer))
            // 重新设置超时时间为 jiffies + 1 ，并启动定时器  
			mod_timer(&stack.timer, jiffies + 1);
		mix_pool_bytes(&input_pool, &stack.now, sizeof(stack.now));
		schedule();
		stack.now = random_get_entropy();
	}

	del_timer_sync(&stack.timer);
	destroy_timer_on_stack(&stack.timer);
	mix_pool_bytes(&input_pool, &stack.now, sizeof(stack.now));
}

```

### entropy_timer

```c
/*
 * Each time the timer fires, we expect that we got an unpredictable
 * jump in the cycle counter. Even if the timer is running on another
 * CPU, the timer activity will be touching the stack of the CPU that is
 * generating entropy..
 *
 * Note that we don't re-arm the timer in the timer itself - we are
 * happy to be scheduled away, since that just makes the load more
 * complex, but we do not want the timer to keep ticking unless the
 * entropy loop is running.
 *
 * So the re-arming always happens in the entropy loop itself.
 */
static void entropy_timer(struct timer_list *t)
{
    // 重新评估 input_pool 熵池
	credit_entropy_bits(&input_pool, 1);
}
```

### credit_entropy_bits

```c
/*
 * Credit (or debit) the entropy store with n bits of entropy.
 * Use credit_entropy_bits_safe() if the value comes from userspace
 * or otherwise should be checked for extreme values.
 */
static void credit_entropy_bits(struct entropy_store *r, int nbits)
{
	int entropy_count, orig, has_initialized = 0;
	const int pool_size = r->poolinfo->poolfracbits;
	int nfrac = nbits << ENTROPY_SHIFT;

	if (!nbits)
		return;

retry:
    // 读取熵池的信息量
	entropy_count = orig = READ_ONCE(r->entropy_count);
	if (nfrac < 0) {
		/* Debit */
		entropy_count += nfrac;
	} else {
		/*
		 * Credit: we have to account for the possibility of
		 * overwriting already present entropy.	 Even in the
		 * ideal case of pure Shannon entropy, new contributions
		 * approach the full value asymptotically:
		 *
		 * entropy <- entropy + (pool_size - entropy) *
		 *	(1 - exp(-add_entropy/pool_size))
		 *
		 * For add_entropy <= pool_size/2 then
		 * (1 - exp(-add_entropy/pool_size)) >=
		 *    (add_entropy/pool_size)*0.7869...
		 * so we can approximate the exponential with
		 * 3/4*add_entropy/pool_size and still be on the
		 * safe side by adding at most pool_size/2 at a time.
		 *
		 * The use of pool_size-2 in the while statement is to
		 * prevent rounding artifacts from making the loop
		 * arbitrarily long; this limits the loop to log2(pool_size)*2
		 * turns no matter how large nbits is.
		 */
		int pnfrac = nfrac;
		const int s = r->poolinfo->poolbitshift + ENTROPY_SHIFT + 2;
		/* The +2 corresponds to the /4 in the denominator */

		do {
			unsigned int anfrac = min(pnfrac, pool_size / 2);
			unsigned int add =
				((pool_size - entropy_count) * anfrac * 3) >> s;

			entropy_count += add;
			pnfrac -= anfrac;
		} while (unlikely(entropy_count < pool_size - 2 && pnfrac));
	}

	if (WARN_ON(entropy_count < 0)) {
		pr_warn("negative entropy/overflow: pool %s count %d\n",
			r->name, entropy_count);
		entropy_count = 0;
	} else if (entropy_count > pool_size)
		entropy_count = pool_size;
	if (cmpxchg(&r->entropy_count, orig, entropy_count) != orig)
		goto retry;

	if (has_initialized) {
		r->initialized = 1;
		kill_fasync(&fasync, SIGIO, POLL_IN);
	}

	trace_credit_entropy_bits(r->name, nbits,
				  entropy_count >> ENTROPY_SHIFT, _RET_IP_);
    
    //  如果是对 input_pool 熵池进行操作的话
	if (r == &input_pool) {
		int entropy_bits = entropy_count >> ENTROPY_SHIFT;

		if (crng_init < 2) {
			if (entropy_bits < 128)
				return;
            // primary_crng 重新播种
			crng_reseed(&primary_crng, r);
			entropy_bits = ENTROPY_BITS(r);
		}
	}
}
```

### crng_reseed

```c
static void crng_reseed(struct crng_state *crng, struct entropy_store *r)
{
	unsigned long flags;
	int i, num;
	union {
		__u8 block[CHACHA_BLOCK_SIZE];
		__u32 key[8];
	} buf;

	if (r) {
        // 从熵池中获取 32 字节数据
		num = extract_entropy(r, &buf, 32, 16, 0);
		if (num == 0)
			return;
	} else {
		_extract_crng(&primary_crng, buf.block);
		_crng_backtrack_protect(&primary_crng, buf.block,
					CHACHA_KEY_SIZE);
	}
	spin_lock_irqsave(&crng->lock, flags);
	for (i = 0; i < 8; i++) {
		unsigned long rv;
		if (!arch_get_random_seed_long(&rv) &&
		    !arch_get_random_long(&rv))
			rv = random_get_entropy();
		crng->state[i + 4] ^= buf.key[i] ^ rv;
	}
	memzero_explicit(&buf, sizeof(buf));
	crng->init_time = jiffies;
	spin_unlock_irqrestore(&crng->lock, flags);
	if (crng == &primary_crng && crng_init < 2) {
		invalidate_batched_entropy();
		numa_crng_init();
		crng_init = 2;
		process_random_ready_list();
		wake_up_interruptible(&crng_init_wait);
		kill_fasync(&fasync, SIGIO, POLL_IN);
		pr_notice("crng init done\n");
		if (unseeded_warning.missed) {
			pr_notice(
				"%d get_random_xx warning(s) missed due to ratelimiting\n",
				unseeded_warning.missed);
			unseeded_warning.missed = 0;
		}
		if (urandom_warning.missed) {
			pr_notice(
				"%d urandom warning(s) missed due to ratelimiting\n",
				urandom_warning.missed);
			urandom_warning.missed = 0;
		}
	}
}
```

### extract_entropy

```c
/*
 * This function extracts randomness from the "entropy pool", and
 * returns it in a buffer.
 *
 * The min parameter specifies the minimum amount we can pull before
 * failing to avoid races that defeat catastrophic reseeding while the
 * reserved parameter indicates how much entropy we must leave in the
 * pool after each pull to avoid starving other readers.
 */
static ssize_t extract_entropy(struct entropy_store *r, void *buf,
			       size_t nbytes, int min, int reserved)
{
	__u8 tmp[EXTRACT_SIZE];
	unsigned long flags;

	/* if last_data isn't primed, we need EXTRACT_SIZE extra bytes */
	if (fips_enabled) {
		spin_lock_irqsave(&r->lock, flags);
		if (!r->last_data_init) {
			r->last_data_init = 1;
			spin_unlock_irqrestore(&r->lock, flags);
			trace_extract_entropy(r->name, EXTRACT_SIZE,
					      ENTROPY_BITS(r), _RET_IP_);
			extract_buf(r, tmp);
			spin_lock_irqsave(&r->lock, flags);
			memcpy(r->last_data, tmp, EXTRACT_SIZE);
		}
		spin_unlock_irqrestore(&r->lock, flags);
	}

	trace_extract_entropy(r->name, nbytes, ENTROPY_BITS(r), _RET_IP_);
	nbytes = account(r, nbytes, min, reserved);

	return _extract_entropy(r, buf, nbytes, fips_enabled);
}
```



```c

static ssize_t _extract_entropy(struct entropy_store *r, void *buf,
				size_t nbytes, int fips)
{
	ssize_t ret = 0, i;
	__u8 tmp[EXTRACT_SIZE];
	unsigned long flags;

	while (nbytes) {
		extract_buf(r, tmp);

		if (fips) {
			spin_lock_irqsave(&r->lock, flags);
			if (!memcmp(tmp, r->last_data, EXTRACT_SIZE))
				panic("Hardware RNG duplicated output!\n");
			memcpy(r->last_data, tmp, EXTRACT_SIZE);
			spin_unlock_irqrestore(&r->lock, flags);
		}
		i = min_t(int, nbytes, EXTRACT_SIZE);
		memcpy(buf, tmp, i);
		nbytes -= i;
		buf += i;
		ret += i;
	}

	/* Wipe data just returned from memory */
    // 清除残留在内存中的数据
	memzero_explicit(tmp, sizeof(tmp));
    
    // 返回拷贝数据量
	return ret;
}
```



## 参考文献：

[Analysis of the Linux Random Number Generator](https://eprint.iacr.org/2006/086.pdf)

[ 软件随机数发生器安全性的研究综述](http://www.jcr.cacrnet.org.cn/CN/Y2020/V7/I6/735)

[Linux内核定时器struct timer_list](https://www.cnblogs.com/Cqlismy/p/11838913.html)