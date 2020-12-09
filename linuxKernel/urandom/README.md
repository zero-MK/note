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
		spin_lock_irqsave(&primary_crng.lock, flags);
		crng_init_cnt = 0;
		spin_unlock_irqrestore(&primary_crng.lock, flags);
	}

	return urandom_read_nowarn(file, buf, nbytes, ppos);
}
```

urandom_read_nowarn

```c
static ssize_t
urandom_read_nowarn(struct file *file, char __user *buf, size_t nbytes,
		    loff_t *ppos)
{
	int ret;
    
    // min_t 取 nbytes 和 INT_MAX >> (ENTROPY_SHIFT + 3) 中的最小值
    // INT_MAX >> (ENTROPY_SHIFT + 3) 展开就是 0x7fffffff >> 6
    // 翻译成人话就是一次调用 urandom_read_nowarn 所能产生的随机数据最大为 0x7fffffff >> 6
	nbytes = min_t(size_t, nbytes, INT_MAX >> (ENTROPY_SHIFT + 3));
	ret = extract_crng_user(buf, nbytes);
	trace_urandom_read(8 * nbytes, 0, ENTROPY_BITS(&input_pool));
	return ret;
}
```

extract_crng_user

```c
static ssize_t extract_crng_user(void __user *buf, size_t nbytes)
{
	ssize_t ret = 0, i = CHACHA_BLOCK_SIZE;
    // tmp 是一个拥有 64 个 __u8 成员的数组， __aligned(4) 向 4 对齐
	__u8 tmp[CHACHA_BLOCK_SIZE] __aligned(4);
	int large_request = (nbytes > 256);

	while (nbytes) {
        // 请求的数据大于 256 字节 并且进程需要重新调度
		if (large_request && need_resched()) {
            // 检查当前进程是否有信号处理
			if (signal_pending(current)) {
				if (ret == 0)
					ret = -ERESTARTSYS;
				break;
			}
			schedule();
		}
        
        // 生成随机数据存入 tmp
		extract_crng(tmp);
		i = min_t(int, nbytes, CHACHA_BLOCK_SIZE);
		if (copy_to_user(buf, tmp, i)) {
			ret = -EFAULT;
			break;
		}

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

extract_crng

```c
static void extract_crng(__u8 out[CHACHA_BLOCK_SIZE])
{
	struct crng_state *crng = NULL;

#ifdef CONFIG_NUMA
	if (crng_node_pool)
		crng = crng_node_pool[numa_node_id()];
	if (crng == NULL)
#endif
        // primary_crng 里面保存 state 和 time
		crng = &primary_crng;
	_extract_crng(crng, out);
}
```

_extract_crng

```c
static void _extract_crng(struct crng_state *crng,
			  __u8 out[CHACHA_BLOCK_SIZE])
{
	unsigned long v, flags;
    
    // 检查初始化，检查时间
	if (crng_ready() &&
	    (time_after(crng_global_init_time, crng->init_time) ||
	     time_after(jiffies, crng->init_time + CRNG_RESEED_INTERVAL)))
		crng_reseed(crng, crng == &primary_crng ? &input_pool : NULL);
	spin_lock_irqsave(&crng->lock, flags);
    
    // 主要就是这里了
	if (arch_get_random_long(&v))
        // 把生成的随机数据和 state[14] 异或然后放入 state[14]
		crng->state[14] ^= v;
    // chacha20 
	chacha20_block(&crng->state[0], out);
	if (crng->state[12] == 0)
		crng->state[13]++;
	spin_unlock_irqrestore(&crng->lock, flags);
}
```

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



```c
static ssize_t
urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
	unsigned long flags;
	static int maxwarn = 10;

	if (!crng_ready() && maxwarn > 0) {
		maxwarn--;
		if (__ratelimit(&urandom_warning))
			pr_notice("%s: uninitialized urandom read (%zd bytes read)\n",
				  current->comm, nbytes);
		spin_lock_irqsave(&primary_crng.lock, flags);
		crng_init_cnt = 0;
		spin_unlock_irqrestore(&primary_crng.lock, flags);
	}

	return urandom_read_nowarn(file, buf, nbytes, ppos);
}
```
