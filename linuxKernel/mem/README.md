/dev/mem 内核实现

源码：Linux kernel-5.6

```c
static const struct file_operations __maybe_unused mem_fops = {
	.llseek		= memory_lseek,
	.read		= read_mem,
	.write		= write_mem,
	.mmap		= mmap_mem,
	.open		= open_mem,
#ifndef CONFIG_MMU
	.get_unmapped_area = get_unmapped_area_mem,
	.mmap_capabilities = memory_mmap_capabilities,
#endif
};
```

read_mem

```c
/*
 * This funcion reads the *physical* memory. The f_pos points directly to the
 * memory location.
 */
static ssize_t read_mem(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	phys_addr_t p = *ppos;
	ssize_t read, sz;
	void *ptr;
	char *bounce;
	int err;

	if (p != *ppos)
		return 0;
    
    // 验证有没有越界读取
    // 实现方式
    // return addr + count <= __pa(high_memory);
    // 就是读取的内存区域不能小于或者等于 high_memory 的物理地址，不可读取 high_memory 的内存，__pa 宏把一个虚拟地址转换成虚拟地址
    // 关于啥是 high memory：https://www.kernel.org/doc/html/latest/vm/highmem.html
	if (!valid_phys_addr_range(p, count))
		return -EFAULT;
	read = 0;
#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
	/* we don't have page 0 mapped on sparc and m68k.. */
    // 有的架构不映射第 0 页，不能读取里面的内容
	if (p < PAGE_SIZE) {
		sz = size_inside_page(p, count);
		if (sz > 0) {
            // 清除 buf
			if (clear_user(buf, sz))
				return -EFAULT;
            // 跳过
			buf += sz;
			p += sz;
			count -= sz;
			read += sz;
		}
	}
#endif
    
    // 分配一个页的大小的内存
	bounce = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!bounce)
		return -ENOMEM;
    
    // count 就是想要读取多少字节内存
	while (count > 0) {
		unsigned long remaining;
		int allowed, probe;
        
        // 当想要读取的内存大于一个页的大小时，每一轮就复制一个页面
		sz = size_inside_page(p, count);

		err = -EPERM;
        // 检查 mem 是否有权限访问 p 所对应的物理内存
		allowed = page_is_allowed(p >> PAGE_SHIFT);
		if (!allowed)
			goto failed;

		err = -EFAULT;
		if (allowed == 2) {
			/* Show zeros for restricted memory. */
			remaining = clear_user(buf, sz);
		} else {
			/*
			 * On ia64 if a page has been mapped somewhere as
			 * uncached, then it must also be accessed uncached
			 * by the kernel or data corruption may occur.
			 */
            // 在 ia64 上，如果某个页面已映射为 uncached 的某个位置，则还必须由内核以 uncached 的方式访问该页面，否则可能会损坏数据。
			ptr = xlate_dev_mem_ptr(p);
			if (!ptr)
				goto failed;
            
            // 安全的在非原子环境下从用户空间 copy 数据到 kernel 空间
			probe = probe_kernel_read(bounce, ptr, sz);
			unxlate_dev_mem_ptr(p, ptr);
			if (probe)
				goto failed;
            
            // 把 bounce 复制到 buf
            // 最终就是这里把内存里的内容复制到我们用户态的 buf 中
			remaining = copy_to_user(buf, bounce, sz);
		}

		if (remaining)
			goto failed;
        
        // 每一轮读取的步长为 sz
		buf += sz;
		p += sz;
		count -= sz;
		read += sz;
        // 如果进程需要重新调度，就重新调度
		if (should_stop_iteration())
			break;
	}
    // 复制完释放 bounce 
	kfree(bounce);

	*ppos += read;
	return read;

failed:
    // 复制出错释放内存，防止内存泄漏
	kfree(bounce);
	return err;
}
```

size_inside_page

```c
// size 大于一个 页面大小 的时候取的是 一个页面的大小
static inline unsigned long size_inside_page(unsigned long start,
					     unsigned long size)
{
	unsigned long sz;
    
	sz = PAGE_SIZE - (start & (PAGE_SIZE - 1));

	return min(sz, size);
}
```

通过 /dev/mem 读取内存的时候分两种情况

- 读取的内存的 size 小于等于一个页面大小 的时候，就一次性读取完
- 读取的内存的 size 大于一个页面大小的时候，就会多次执行 whlie 里面的操作 ，每次读取一个页面的内存复制到用户态的 buf



write_mem

```c
static ssize_t write_mem(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	phys_addr_t p = *ppos;
	ssize_t written, sz;
	unsigned long copied;
	void *ptr;

	if (p != *ppos)
		return -EFBIG;
    
    // 验证 p 指向的地址的有效性
	if (!valid_phys_addr_range(p, count))
		return -EFAULT;

	written = 0;

#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
	/* we don't have page 0 mapped on sparc and m68k.. */
    // 有的架构不映射 0 号页，所以不能直接读取 0 号页
	if (p < PAGE_SIZE) {
		sz = size_inside_page(p, count);
		/* Hmm. Do something? */
        // 跳过
		buf += sz;
		p += sz;
		count -= sz;
		written += sz;
	}
#endif

	while (count > 0) {
		int allowed;
        
        // 获取要写入的数据的大小
		sz = size_inside_page(p, count);

        // 检查页面权限
		allowed = page_is_allowed(p >> PAGE_SHIFT);
		if (!allowed)
			return -EPERM;

		/* Skip actual writing when a page is marked as restricted. */
		if (allowed == 1) {
			/*
			 * On ia64 if a page has been mapped somewhere as
			 * uncached, then it must also be accessed uncached
			 * by the kernel or data corruption may occur.
			 */
            // 
			ptr = xlate_dev_mem_ptr(p);
			if (!ptr) {
				if (written)
					break;
				return -EFAULT;
			}
            
            // 把数据从用户态的 buf 拷贝到内核态的 ptr 所指向的内存
			copied = copy_from_user(ptr, buf, sz);
			unxlate_dev_mem_ptr(p, ptr);
            // 复制成功
			if (copied) {
                // 检查有没有复制完成，复制完成直接 break
				written += sz - copied;
				if (written)
					break;
				return -EFAULT;
			}
		}

		buf += sz;
		p += sz;
		count -= sz;
		written += sz;
		if (should_stop_iteration())
			break;
	}

	*ppos += written;
	return written;
}
```

xlate_dev_mem_ptr

设备相关代码，x86  ，位于：arch/x86/mm/ioremap.c

```c
/*
 * Convert a physical pointer to a virtual kernel pointer for /dev/mem
 * access
 */
// 把指向物理内存地址的指针转换成指向内核内存地址的指针
void *xlate_dev_mem_ptr(phys_addr_t phys)
{
    // 获取页面起始地址
	unsigned long start  = phys &  PAGE_MASK;
    // 获取页面偏移量
	unsigned long offset = phys & ~PAGE_MASK;
	void *vaddr;

	/* memremap() maps if RAM, otherwise falls back to ioremap() */
    // 以 MEMREMAP_WB 的方式映射从 start 开始的大小为 PAGE_SIZE 的内存
	vaddr = memremap(start, PAGE_SIZE, MEMREMAP_WB);

	/* Only add the offset on success and return NULL if memremap() failed */
    // 获得的地址加上页内偏移就能的到内核内存地址
	if (vaddr)
		vaddr += offset;

	return vaddr;
}
```

