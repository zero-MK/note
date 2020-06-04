`chroot` 在 内核中的实现

在 Linux 5.6 版本中 `chroot` 函数的系统调用对应的函数位于：`./fs/open.c:539:SYSCALL_DEFINE1(chroot, const char __user *, filename)`

via: https://elixir.bootlin.com/linux/v5.6/source/fs/open.c#L539

```c
SYSCALL_DEFINE1(chroot, const char __user *, filename)
{
	return ksys_chroot(filename);
}
```

## ksys_chroot

via: https://elixir.bootlin.com/linux/v5.6/source/fs/open.c#L506

```c
int ksys_chroot(const char __user *filename)
{
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
retry:
    // 根据文件名找到 path 结构
	error = user_path_at(AT_FDCWD, filename, lookup_flags, &path);
	if (error)
		goto out;

    // 解析 path 的 mm_root dentry 结构，再解析相应的 inode 结构，即 d_inode，就可找到挂载点相应的 inode 结构
	error = inode_permission(path.dentry->d_inode, MAY_EXEC | MAY_CHDIR);
	if (error)
		goto dput_and_out;

	error = -EPERM;
    // 判断当前进程所有者是不是有执行 chroot 操作的权限
    // 这里是 namespace, cred 的内容了，不展开
	if (!ns_capable(current_user_ns(), CAP_SYS_CHROOT))
		goto dput_and_out;
	error = security_path_chroot(&path);
	if (error)
		goto dput_and_out;

    // 主要操作就是这个函数
	set_fs_root(current->fs, &path);
	error = 0;
dput_and_out:
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	return error;
}
```

### flag 含义

```c
#define LOOKUP_FOLLOW		0x0001	/* follow links at the end */
#define LOOKUP_DIRECTORY	0x0002	/* require a directory */
```



## set_fs_root

主要函数，就是在这个函数里修改了程序的 “根目录”

via: https://elixir.bootlin.com/linux/v5.6/source/fs/fs_struct.c#L15

先来看一下 fs_struct

```c
struct fs_struct {
	int users;
	spinlock_t lock;
	seqcount_t seq;
	int umask;
	int in_exec;
	struct path root, pwd; 
    // root：根目录的目录项
	 // pwd：当前工作目录的目录项
} __randomize_layout;
```

```c
/*
 * Replace the fs->{rootmnt,root} with {mnt,dentry}. Put the old values.
 * It can block.
 */
void set_fs_root(struct fs_struct *fs, const struct path *path)
{
	struct path old_root;

	path_get(path);
	spin_lock(&fs->lock); // 自旋锁
	write_seqcount_begin(&fs->seq);
	old_root = fs->root; // 保存程序的 根目录 的目录项
	fs->root = *path; // 设置 根目录 为 path 的目录项
	write_seqcount_end(&fs->seq);
	spin_unlock(&fs->lock);
	if (old_root.dentry)
		path_put(&old_root);
}
```



## struct path

via: https://elixir.bootlin.com/linux/v5.6/source/include/linux/path.h#L8

```c
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __randomize_layout;
```

## struct vfsmount

描述独立文件系统的挂载信息，每个不同的挂载点对应一个独立的 `vfsmount` 结构，属于同一文件系统的所有目录和文件隶属同一 `vfsmount` 该 `vfsmount` 结构对应于该文件系统顶层目录，即挂载目录

via: https://elixir.bootlin.com/linux/v5.6/source/include/linux/mount.h#L68

```c
struct vfsmount {
	struct dentry *mnt_root;	/* 上一层挂载点对应的 dentry */
	struct super_block *mnt_sb;	/* 指向超级块 */
	int mnt_flags;
} __randomize_layout;
```

## struct dentry

目录项，是Linux文件系统中某个 索引节点(inode) 的链接

via：https://elixir.bootlin.com/linux/v5.6/source/include/linux/dcache.h#L89

```c
struct dentry {
	/* RCU lookup touched fields */
	unsigned int d_flags;		/* protected by d_lock */
	seqcount_t d_seq;		/* per dentry seqlock */
	struct hlist_bl_node d_hash;	/* lookup hash list */
	struct dentry *d_parent;	/* 父目录项指针 */
	struct qstr d_name; // 文件或者目录的名称
    // 目录的 inode
	struct inode *d_inode;		/* Where the name belongs to - NULL is
					 * negative */
	unsigned char d_iname[DNAME_INLINE_LEN];	/* small names */

	/* Ref lookup also touches following */
	struct lockref d_lockref;	/* per-dentry lock and refcount */
	const struct dentry_operations *d_op;
	struct super_block *d_sb;	/* The root of the dentry tree */
	unsigned long d_time;		/* used by d_revalidate */
	void *d_fsdata;			/* fs-specific data */

	union {
		struct list_head d_lru;		/* LRU list */
		wait_queue_head_t *d_wait;	/* in-lookup ones only */
	};
	struct list_head d_child;	/* child of parent list */
	struct list_head d_subdirs;	/* our children */
	/*
	 * d_alias and d_rcu can share memory
	 */
	union {
		struct hlist_node d_alias;	/* inode alias list */
		struct hlist_bl_node d_in_lookup_hash;	/* only for in-lookup ones */
	 	struct rcu_head d_rcu;
	} d_u;
} __randomize_layout;
```

上面这两个都是 文件系统 的东西，不在这里详细分析



## 总结

其实 chroot 修改了进程的 root 目录的核心操作就是修改了 进程 的 `task_struct -> fs -> root`

因为是 `struct path root`，所以 

```c
user_path_at(AT_FDCWD, filename, lookup_flags, &path);
```

就是通过文件名去解析 文件夹 对应的 `path` 结构，存在 `path` 变量里面

然后就是权限检查

在然后把 `path` 传进 `set_fs_root` 函数

```c
fs->root = *path;
```

修改了 root 

这样进程就认为 `filename` 是根目录，因为 `fs->root` 存的是  `filename` 目录的 `path` 结构