cred 结构体

进程的安全相关信息上下文（context）

一个进程有两个 `cred`

在 `task_struct` 里面有 `cred` `real_cred`

- 当其他进程试图影响此进程的时候就是访问 `cred` ，`cred` 是可以临时改变的，通常情况下是和 `real_cred` 是一样的
- 当进程试图对一个其他对象（文件，进程，或者任何东西）进行操作的时候就是访问 `real_cred`

```c
/*
 * The security context of a task
 *
 * The parts of the context break down into two categories:
 *
 *  (1) The objective context of a task.  These parts are used when some other
 *	task is attempting to affect this one.
 *
 *  (2) The subjective context.  These details are used when the task is acting
 *	upon another object, be that a file, a task, a key or whatever.
 *
 * Note that some members of this structure belong to both categories - the
 * LSM security pointer for instance.
 *
 * A task has two security pointers.  task->real_cred points to the objective
 * context that defines that task's actual details.  The objective part of this
 * context is used whenever that task is acted upon.
 *
 * task->cred points to the subjective context that defines the details of how
 * that task is going to act upon another object.  This may be overridden
 * temporarily to point to another security context, but normally points to the
 * same context as task->real_cred.
 */
struct cred {
	atomic_t	usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
	atomic_t	subscribers;	/* number of processes subscribed 使用这个 cred 的进程数*/
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
	kuid_t		uid;		/* real UID of the task 创建进程的用户的 id ，不是创建可执行程序的用户 id*/
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task 保存的 euid 切换之前的 id，用于 euid 切换回来*/
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task  euid 是进程运行过程中实时的 id*/
	kgid_t		egid;		/* effective GID of the task */
	kuid_t		fsuid;		/* UID for VFS ops */
	kgid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
#ifdef CONFIG_KEYS
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
	struct key	*session_keyring; /* keyring inherited over fork */
	struct key	*process_keyring; /* keyring private to this process */
	struct key	*thread_keyring; /* keyring private to this thread */
	struct key	*request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
	void		*security;	/* subjective LSM security */
#endif
	struct user_struct *user;	/* real user ID subscription 创建进程的用户的 id 描述符*/
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	/* RCU deletion */
	union {
		int non_rcu;			/* Can we skip RCU deletion? */
		struct rcu_head	rcu;		/* RCU deletion hook */
	};
} __randomize_layout;
```

real user ID (uid): 实际用户 ID ,指的是进程执行者是谁
effective user ID (euid): 有效用户 ID ,指进程执行时对文件的访问权限
saved set-user-ID (saved uid): 保存设置用户 ID 。是进程刚开始执行时， euid 的副本。在执行 exec 调用之后能重新恢复原来的 effectiv user ID



user_struct

```c
struct user_struct {
	refcount_t __count;	/* reference count 引用计数*/
	atomic_t processes;	/* How many processes does this user have? 这个用户一共有多少个进程 */
	atomic_t sigpending;	/* How many pending signals does this user have? 这个用户一共有多少个挂起信号*/
#ifdef CONFIG_FANOTIFY
	atomic_t fanotify_listeners;
#endif
#ifdef CONFIG_EPOLL
	atomic_long_t epoll_watches; /* The number of file descriptors currently watched 当前监视的文件描述符的数量 */
#endif
#ifdef CONFIG_POSIX_MQUEUE
	/* protected by mq_lock	*/
	unsigned long mq_bytes;	/* How many bytes can be allocated to mqueue? */
#endif
	unsigned long locked_shm; /* How many pages of mlocked shm ? */
	unsigned long unix_inflight;	/* How many files in flight in unix sockets 有多少套接字 */
	atomic_long_t pipe_bufs;  /* how many pages are allocated in pipe buffers 管道缓冲区中分配了多少个 页 的内存*/

	/* Hash table maintenance information */
	struct hlist_node uidhash_node;
	kuid_t uid; /*用户的 uid*/

#if defined(CONFIG_PERF_EVENTS) || defined(CONFIG_BPF_SYSCALL) || \
    defined(CONFIG_NET) || defined(CONFIG_IO_URING)
	atomic_long_t locked_vm;
#endif

	/* Miscellaneous per-user rate limit */
	struct ratelimit_state ratelimit;
};
```



user_namespace

```c
struct user_namespace {
	struct uid_gid_map	uid_map;
	struct uid_gid_map	gid_map;
	struct uid_gid_map	projid_map;
	atomic_t		count;
	struct user_namespace	*parent;
	int			level;
	kuid_t			owner;
	kgid_t			group;
	struct ns_common	ns;
	unsigned long		flags;

#ifdef CONFIG_KEYS
	/* List of joinable keyrings in this namespace.  Modification access of
	 * these pointers is controlled by keyring_sem.  Once
	 * user_keyring_register is set, it won't be changed, so it can be
	 * accessed directly with READ_ONCE().
	 */
	struct list_head	keyring_name_list;
	struct key		*user_keyring_register;
	struct rw_semaphore	keyring_sem;
#endif

	/* Register of per-UID persistent keyrings for this namespace */
#ifdef CONFIG_PERSISTENT_KEYRINGS
	struct key		*persistent_keyring_register;
#endif
	struct work_struct	work;
#ifdef CONFIG_SYSCTL
	struct ctl_table_set	set;
	struct ctl_table_header *sysctls;
#endif
	struct ucounts		*ucounts;
	int ucount_max[UCOUNT_COUNTS];
} __randomize_layout;
```



user_group

```c
struct group_info {
	atomic_t	usage;
	int		ngroups;
	kgid_t		gid[0];
} __randomize_layout;
```

