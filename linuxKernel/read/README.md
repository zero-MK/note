这几天一直在忙别的事，完事了，看了点文件系统相关的部分，就看看 `read` 在内核里面的实现

这是大概的函数调用链，但是我不会一个一个全部去分析，我只看主要的

![](ksys_read.svg)

man 手册描述

via：https://man7.org/linux/man-pages/man2/read.2.html

```
NAME
       read - read from a file descriptor

SYNOPSIS
       #include <unistd.h>

       ssize_t read(int fd, void *buf, size_t count);
       
DESCRIPTION
       read() attempts to read up to count bytes from file descriptor fd into the buffer starting at buf.

       On  files that support seeking, the read operation commences at the file offset, and the file offset is incremented by the number of bytes read.  If the file offset is at or past the end of file,      
       no bytes are read, and read() returns zero.

       If count is zero, read() may detect the errors described below.  In the absence of any errors, or if read() does not check for errors, a read() with a count of 0 returns zero and has no other ef‐      
       fects.

       According to POSIX.1, if count is greater than SSIZE_MAX, the result is implementation-defined; see NOTES for the upper limit on Linux.
```

从 文件描述符 读取文件内容

三个参数，对应 `SYSCALL_DEFINE3`

```c
SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	return ksys_read(fd, buf, count);
}
```

## ksys_read

@fd -- 文件描述符

@buf -- 把指定长度的文件内容存入这个 `buf` 里面

@count -- 读取的长度

```c
ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
{
    /* 传进来的是一个 int，现在要获取对应的 fd 结构
     * 像是 stdin 是一个 fd，对应的是 0
     */
	struct fd f = fdget_pos(fd);
    // EBADF : fd is not a valid file descriptor or is not open for reading.
    // fd 不是有效的文件描述符，或者没有打开进行读取。
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos, *ppos = file_ppos(f.file);
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_read(f.file, buf, count, ppos);
		if (ret >= 0 && ppos)
			f.file->f_pos = pos;
		fdput_pos(f);
	}
	return ret;
}
```



## fdget_pos

```c
static inline struct fd fdget_pos(int fd)
{
	return __to_fd(__fdget_pos(fd));
}
```

### __fdget_pos

```c
unsigned long __fdget_pos(unsigned int fd)
{
	unsigned long v = __fdget(fd);
	struct file *file = (struct file *)(v & ~3);

	if (file && (file->f_mode & FMODE_ATOMIC_POS)) {
		if (file_count(file) > 1) {
			v |= FDPUT_POS_UNLOCK;
			mutex_lock(&file->f_pos_lock);
		}
	}
	return v;
}
```

### __fdget

```c
unsigned long __fdget(unsigned int fd)
{
	return __fget_light(fd, FMODE_PATH);
}
```

### __fget_light

```c
/*
 * Lightweight file lookup - no refcnt increment if fd table isn't shared.
 *
 * You can use this instead of fget if you satisfy all of the following
 * conditions:
 * 1) You must call fput_light before exiting the syscall and returning control
 *    to userspace (i.e. you cannot remember the returned struct file * after
 *    returning to userspace).
 * 2) You must not call filp_close on the returned struct file * in between
 *    calls to fget_light and fput_light.
 * 3) You must not clone the current task in between the calls to fget_light
 *    and fput_light.
 *
 * The fput_needed flag returned by fget_light should be passed to the
 * corresponding fput_light.
 */
static unsigned long __fget_light(unsigned int fd, fmode_t mask)
{
    // 获取当前进程的 files 结构（这个结构存储了打开的文件与进程交互的有关信息）
	struct files_struct *files = current->files;
	struct file *file;

    // count -- 使用该表的进程数
	if (atomic_read(&files->count) == 1) {
		file = __fcheck_files(files, fd);
		if (!file || unlikely(file->f_mode & mask))
			return 0;
		return (unsigned long)file;
	} else {
		file = __fget(fd, mask, 1);
		if (!file)
			return 0;
		return FDPUT_FPUT | (unsigned long)file;
	}
}
```



### __fcheck_files

调用者必须确保 `fd` 表不共享，或者持有 `rcu` 或者 `文件锁`

```c
/*
 * The caller must ensure that fd table isn't shared or hold rcu or file lock
 */
static inline struct file *__fcheck_files(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt = rcu_dereference_raw(files->fdt);

	if (fd < fdt->max_fds) {
		fd = array_index_nospec(fd, fdt->max_fds);
		return rcu_dereference_raw(fdt->fd[fd]);
	}
	return NULL;
}
```

### __fget

```c
static inline struct file *__fget(unsigned int fd, fmode_t mask,
				  unsigned int refs)
{
	return __fget_files(current->files, fd, mask, refs);
}
```

### __fget_files

```c
static struct file *__fget_files(struct files_struct *files, unsigned int fd,
				 fmode_t mask, unsigned int refs)
{
	struct file *file;

	rcu_read_lock();
loop:
	file = fcheck_files(files, fd);
	if (file) {
		/* File object ref couldn't be taken.
		 * dup2() atomicity guarantee is the reason
		 * we loop to catch the new file (or NULL pointer)
		 */
		if (file->f_mode & mask)
			file = NULL;
		else if (!get_file_rcu_many(file, refs))
			goto loop;
	}
	rcu_read_unlock();

	return file;
}
```

