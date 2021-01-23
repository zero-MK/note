源码版本：Linux kernel 1.0

分析字符设备 /dev/mem 的驱动程序

既然是字符设备，万物皆文件，先找 `file_operations` 结构

## struct file_operations mem_fops

```c
static struct file_operations mem_fops = {
	memory_lseek,
	read_mem,
	write_mem,
	NULL,		/* mem_readdir */
	NULL,		/* mem_select */
	NULL,		/* mem_ioctl */
	mmap_mem,
	NULL,		/* no special open code */
	NULL,		/* no special release code */
	NULL		/* fsync */
};
```

支持 `read` `write` `lseek` `mmap`

一个一个分析

## read_mem

参数就是直接对 inode 进行操作

```c
static int read_mem(struct inode * inode, struct file * file,char * buf, int count)
{
	unsigned long p = file->f_pos; // 获取 mem 文件的 pos 指针（其实就是我们指定的读取的地址）
	int read; // 计数器，用来记录拷贝了多少数据

	
	if (count < 0) // 检查读取 size 的合法性，不能读取一个负数大小
		return -EINVAL;

	if (p >= high_memory) // 不能读取 high memory
		return 0;
	if (count > high_memory - p) // 如果读取的大小比可读内存区域还大的话
		count = high_memory - p; // 只允许读除了 high memory 以外的内存
	read = 0;

	// 不能读取 0 号页，所以逐字节把 buf 前 4096 字节置 0（因为现在是在内核态，buf 位于用户态，需要用 put_fs_byte 来操作）
	while (p < PAGE_SIZE && count > 0) {
		put_fs_byte(0,buf); 
		buf++;
		p++;
		count--;
		read++;
	}
	// 把 p 为起始地址，大小为 count 的内存数据拷贝到用户态的 buf
	memcpy_tofs(buf,(void *) p,count);
	read += count; // 增加计数器的值
	file->f_pos += read; // 移动文件 pos 指针
	return read;
}
```



## write_mem



```c
static int write_mem(struct inode * inode, struct file * file,char * buf, int count)
{
	unsigned long p = file->f_pos; // 获取 mem 文件的 pos 指针（我们要写入数据的地址）
	int written; // 计数器

	if (count < 0) // 检查写入数据的大小的合法性
		return -EINVAL;
	if (p >= high_memory) // 不能写 high memory
		return 0;
	if (count > high_memory - p)
		count = high_memory - p;
	written = 0;
	// 不能写 0 号页，直接跳过
	while (p < PAGE_SIZE && count > 0) {
		/* Hmm. Do something? */
		buf++;
		p++;
		count--;
		written++;
	}
	memcpy_fromfs((void *) p,buf,count); // 把数据从用户态 buf 拷贝到现在 p 指向的地址（数据块大小为 count）
	written += count; // 增加计数器的值
	file->f_pos += written; // 移动指针
	return count;
}
```



## memory_lseek

```c
/*
 * The memory devices use the full 32 bits of the offset, and so we cannot
 * check against negative addresses: they are ok. The return value is weird,
 * though, in that case (0).
 *
 * also note that seeking relative to the "end of file" isn't supported:
 * it has no meaning, so it returns -EINVAL.
 */
static int memory_lseek(struct inode * inode, struct file * file, off_t offset, int orig)
{
	switch (orig) {
		case 0:
			file->f_pos = offset;
			return file->f_pos;
		case 1:
			file->f_pos += offset;
			return file->f_pos;
		default:
			return -EINVAL;
	}
	if (file->f_pos < 0)
		return 0;
	return file->f_pos;
}
```



## 结语

在对 /dev/mem 进行读写时，`file->f_pos` 其实就是我们读写的地址，`buf` 因为是位于用户态，在内核态不能直接读写用户态的数据，所以需要特定的函数去执行，就像高版本的 kernel 的 `copy_from_user` `copy_to_user` .......这类函数