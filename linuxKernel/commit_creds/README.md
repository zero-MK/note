浅析一下用来修改当前进程 `cred` 的函数 `commit_creds`

源码版本：Linux kernel 5.9.9

首先来看 cred 结构

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

## commit_creds

```c
/**
 * commit_creds - Install new credentials upon the current task
 * @new: The credentials to be assigned
 *
 * Install a new set of credentials to the current task, using RCU to replace
 * the old set.  Both the objective and the subjective credentials pointers are
 * updated.  This function may not be called if the subjective credentials are
 * in an overridden state.
 *
 * This function eats the caller's reference to the new credentials.
 *
 * Always returns 0 thus allowing this function to be tail-called at the end
 * of, say, sys_setgid().
 */
int commit_creds(struct cred *new)
{
  // 获取当前进程的 task_struct
	struct task_struct *task = current;
  // 保存当前进程的 real_cred 
	const struct cred *old = task->real_cred;

	kdebug("commit_creds(%p{%d,%d})", new,
	       atomic_read(&new->usage),
	       read_cred_subscribers(new));
  
  // cred != real_cred 通常这个两个是一样的 当进程试图对一个其他对象（文件，进程，或者任何东西）进行操作的时候就是访问 real_cred
	BUG_ON(task->cred != old);
#ifdef CONFIG_DEBUG_CREDENTIALS
  // 使用 task->real_cred 的进程数小于 2，也就是说只能有一个进程使用这个 cred（real_cred 也是 cred 结构）
	BUG_ON(read_cred_subscribers(old) < 2);
  // 检查 cred 有没有被破坏，其实就是检查 cred 的魔数头 magic 字段是不是 CRED_MAGIC（默认 magic 是 CRED_MAGIC 值： 0x43736564），如果不是则认为 cred 可能被内存溢出覆盖
	validate_creds(old);
	validate_creds(new);
#endif
  // 对 new 的引用数不小于 1
	BUG_ON(atomic_read(&new->usage) < 1);
  
  // get_cred 这个函数会先用 validate_creds 检查 cred 是否有效，
  // 然后把 non_rcu 置 0
  // 然后让 usage 加 1 表示引用这个 cred 的进程数 加 1
	get_cred(new); /* we will require a ref for the subj creds too */

	/* dumpability changes */
  // 检查当前进程的 real_cred 和 new cred（要修改成的那个 cred）的各个字段是否一样，_eq 结尾的函数其实就是 比较两个值是否相等
	if (!uid_eq(old->euid, new->euid) || // 检查 uid 是否相等
	    !gid_eq(old->egid, new->egid) || // 检查 egid 是否相等
	    !uid_eq(old->fsuid, new->fsuid) || // 检查 fsuid 是否相等
	    !gid_eq(old->fsgid, new->fsgid) || // 检查 fsgid 是否相等
	    !cred_cap_issubset(old, new)) { // 检查 new cres 的 namespace 是不是 old cred 的 namespace 的子集
    // 如果当前进程的 mm_struct 不是 NULL
		if (task->mm)
			set_dumpable(task->mm, suid_dumpable); // 设置 mm_struct 的 flag，加上 suid_dumpable 标志，表示 接受到 coredump 信号时生成 coredump
		task->pdeath_signal = 0;
		/*
		 * If a task drops privileges and becomes nondumpable,
		 * the dumpability change must become visible before
		 * the credential change; otherwise, a __ptrace_may_access()
		 * racing with this change may be able to attach to a task it
		 * shouldn't be able to attach to (as if the task had dropped
		 * privileges without becoming nondumpable).
		 * Pairs with a read barrier in __ptrace_may_access().
		 */
    // sfence 内存屏障
		smp_wmb();
	}

	/* alter the thread keyring */
  // 如果 new cred 的文件系统的 uid 和 gid 和目前进程的文件系统的 uid 和 gid 不一样则
	if (!uid_eq(new->fsuid, old->fsuid))
		key_fsuid_changed(new); // 更新 new 的 thread_keyring->uid 为 new->fsuid
	if (!gid_eq(new->fsgid, old->fsgid))
		key_fsgid_changed(new); // // 更新 new 的 thread_keyring->gid 为 new->fsgid

	/* do it
	 * RLIMIT_NPROC limits on user->processes have already been checked
	 * in set_user().
	 */
  // new 的订阅进程 ubscribers 加 2
	alter_cred_subscribers(new, 2);
  // 如果 new cres 和 old cred 所属的 用户 不一样（对，就是你理解的系统里面的那个用户，每个 uid 就是一个 用户），user 是一个 user_struct，每个用户都有一个，里面记录的  processes 表示这个用户有多少个进程
	if (new->user != old->user)
		atomic_inc(&new->user->processes); // 既然 old cred 和 new cred 不是属于同一个用户，那么当前进程 使用 new cred 的时候 cred 对应的用户所有的进程数肯定要加 1（如果有点绕，仔细想想就能想通了）
  // cred 和 real_cred 是 rcu 变量，是个指针，所以需要用 rcu_assign_pointer 去更新
	rcu_assign_pointer(task->real_cred, new); // task->real_cred = new
	rcu_assign_pointer(task->cred, new); // task->cred = new
  // 这里检查有没有设置成功，因为 old 是指向当前进程的 real_cred 的，上面我们更新了 real_cred 为 new，所以这两个是一样的现在，都是指向 new cred
  // 如果没有更新成功
	if (new->user != old->user)
		atomic_dec(&old->user->processes); // 用户进程数 减 1 ，因为上面我们加 1
  // 操作结束 new 的订阅进程 ubscribers 减 2（或者说是加上 -2），对应上面那个加 2
	alter_cred_subscribers(old, -2);

	/* send notifications */
  // 现在检查各个 uid 字段，还不一样就见鬼了
	if (!uid_eq(new->uid,   old->uid)  ||
	    !uid_eq(new->euid,  old->euid) ||
	    !uid_eq(new->suid,  old->suid) ||
	    !uid_eq(new->fsuid, old->fsuid))
		proc_id_connector(task, PROC_EVENT_UID);

	if (!gid_eq(new->gid,   old->gid)  ||
	    !gid_eq(new->egid,  old->egid) ||
	    !gid_eq(new->sgid,  old->sgid) ||
	    !gid_eq(new->fsgid, old->fsgid))
		proc_id_connector(task, PROC_EVENT_GID);

	/* release the old obj and subj refs both */
  // 释放  old cred
	put_cred(old); // 对 old cred 的引用 减 1
	put_cred(old); // 对 old cred 的引用 减 1
	return 0;
}
EXPORT_SYMBOL(commit_creds);
```





### get_cred

```c
/**
 * get_cred - Get a reference on a set of credentials
 * @cred: The credentials to reference
 *
 * Get a reference on the specified set of credentials.  The caller must
 * release the reference.  If %NULL is passed, it is returned with no action.
 *
 * This is used to deal with a committed set of credentials.  Although the
 * pointer is const, this will temporarily discard the const and increment the
 * usage count.  The purpose of this is to attempt to catch at compile time the
 * accidental alteration of a set of credentials that should be considered
 * immutable.
 */
static inline const struct cred *get_cred(const struct cred *cred)
{
	struct cred *nonconst_cred = (struct cred *) cred;
  // 检查是不是 cred 一个有效的地址
	if (!cred)
		return cred;
  // 验证 cred 的 magic
	validate_creds(cred);
	nonconst_cred->non_rcu = 0;
  // usage 字段加 1
	return get_new_cred(nonconst_cred);
}
```



#### get_new_cred

```c
/**
 * get_new_cred - Get a reference on a new set of credentials
 * @cred: The new credentials to reference
 *
 * Get a reference on the specified set of new credentials.  The caller must
 * release the reference.
 */
static inline struct cred *get_new_cred(struct cred *cred)
{
  // usage 字段加 1
	atomic_inc(&cred->usage);
	return cred;
}
```



### cred_cap_issubset

```c
static bool cred_cap_issubset(const struct cred *set, const struct cred *subset)
{
  // 获取 cred 的 namespace
	const struct user_namespace *set_ns = set->user_ns;
	const struct user_namespace *subset_ns = subset->user_ns;

	/* If the two credentials are in the same user namespace see if
	 * the capabilities of subset are a subset of set.
	 */
  // 如果这两个 cred 位于相同的 namespace
	if (set_ns == subset_ns)
		return cap_issubset(subset->cap_permitted, set->cap_permitted);

	/* The credentials are in a different user namespaces
	 * therefore one is a subset of the other only if a set is an
	 * ancestor of subset and set->euid is owner of subset or one
	 * of subsets ancestors.
	 */
  // 遍历 namespace 
	for (;subset_ns != &init_user_ns; subset_ns = subset_ns->parent) {
    // 如果 old cred 的 namespace 是 new cred 的 namespace 的先祖，并且 new 的 namespace 的实际所有者是 ord
		if ((set_ns == subset_ns->parent)  &&
		    uid_eq(subset_ns->owner, set->euid))
			return true; // 也可以判定 new cred 的 namespace 是 ord cred 的 namespace 的子集
	}

	return false; // 如果遍历完所有的 namespace 没有符合的，说明 new cred 的 namespace 不是 old cred 的 namespace 的子集
}
```



### put_cred

```c
/**
 * put_cred - Release a reference to a set of credentials
 * @cred: The credentials to release
 *
 * Release a reference to a set of credentials, deleting them when the last ref
 * is released.  If %NULL is passed, nothing is done.
 *
 * This takes a const pointer to a set of credentials because the credentials
 * on task_struct are attached by const pointers to prevent accidental
 * alteration of otherwise immutable credential sets.
 */
static inline void put_cred(const struct cred *_cred)
{
	struct cred *cred = (struct cred *) _cred;
  
	if (cred) {
    // 验证 cred 没有被破坏
		validate_creds(cred);
    // usage 减 1，如果 usage 为 0 则条件为真陷入 if
		if (atomic_dec_and_test(&(cred)->usage))
			__put_cred(cred); // 因为 usage 为 0，表示没有进程在使用这个 cred，直接销毁 cred
	}
}
```



#### __put_cred

```c
/**
 * __put_cred - Destroy a set of credentials
 * @cred: The record to release
 *
 * Destroy a set of credentials on which no references remain.
 */
void __put_cred(struct cred *cred)
{
	kdebug("__put_cred(%p{%d,%d})", cred,
	       atomic_read(&cred->usage),
	       read_cred_subscribers(cred));
  
  // 再次检查要销毁的 cred 的 usage 
	BUG_ON(atomic_read(&cred->usage) != 0);
#ifdef CONFIG_DEBUG_CREDENTIALS
  // 检查查要销毁的 cred 的 subscribers 
	BUG_ON(read_cred_subscribers(cred) != 0);
  // 把 cred 的 magic 更改成 CRED_MAGIC_DEAD 表示 cred 不可用
	cred->magic = CRED_MAGIC_DEAD;
	cred->put_addr = __builtin_return_address(0);
#endif
  // 要销毁的 cred 当然不能是当前进程使用的 cred
	BUG_ON(cred == current->cred);
	BUG_ON(cred == current->real_cred);
  
  // 如果是使用 RCU deletion hook 的话 ，则可以直接调用 put_cred_rcu 函数
	if (cred->non_rcu)
		put_cred_rcu(&cred->rcu);
	else
		call_rcu(&cred->rcu, put_cred_rcu); // 不然需要使用 call_rcu 去找 put_cred_rcu 函数（ rcu 函数是串在一条 RCU deletion hook 链表上每个节点都是一个 rcu_head ）（大概是这样的，我也没深究，其实还是调用 put_cred_rcu 函数，反正就是在申请 cred 的时候有没有设置 hook 了，设置了可以直接调用，不然要使用 call_rcu 去找，毕竟 cred 是 rcu 变量，需要特定的方式去销毁）
}
EXPORT_SYMBOL(__put_cred);
```

其实后面的也没什么好分析的了

```c
void security_cred_free(struct cred *cred)
{
	/*
	 * There is a failure case in prepare_creds() that
	 * may result in a call here with ->security being NULL.
	 */
	if (unlikely(cred->security == NULL))
		return;

	call_void_hook(cred_free, cred);

	kfree(cred->security);
	cred->security = NULL;
}

/*
 * The RCU callback to actually dispose of a set of credentials
 */
static void put_cred_rcu(struct rcu_head *rcu)
{
  // 通过 rcu 字段的地址去找包含这个 rcu 的 cred 结构，这个 container_of 实际很巧妙我以前分析过就不展开了
	struct cred *cred = container_of(rcu, struct cred, rcu);

	kdebug("put_cred_rcu(%p)", cred);

#ifdef CONFIG_DEBUG_CREDENTIALS
	if (cred->magic != CRED_MAGIC_DEAD ||
	    atomic_read(&cred->usage) != 0 ||
	    read_cred_subscribers(cred) != 0)
		panic("CRED: put_cred_rcu() sees %p with"
		      " mag %x, put %p, usage %d, subscr %d\n",
		      cred, cred->magic, cred->put_addr,
		      atomic_read(&cred->usage),
		      read_cred_subscribers(cred));
#else
  // 检查 usage，还有进程使用这个 cred 直接就 panic
	if (atomic_read(&cred->usage) != 0)
		panic("CRED: put_cred_rcu() sees %p with usage %d\n",
		      cred, atomic_read(&cred->usage));
#endif
  
  // 使用 kfree 释放 cred->security，并置 cred->security 为 NULL，防止 UAF
	security_cred_free(cred);
  // 先检查 keyring 的有效性，然后让 keyring 的 usage 减 1，跟 cred 一样，如果 usage 为 0 ，则销毁 keyring，因为 keyring 可以被多个 cred 使用（一个 keyring 对应多个 cred），所以才会有一个 usage 字段，现在销毁 这个 cred 如果是 最后一个使用这个 keyring 的，则销毁 cred 后销毁 keyring
	key_put(cred->session_keyring);
	key_put(cred->process_keyring);
	key_put(cred->thread_keyring);
	key_put(cred->request_key_auth);
  // 一样，对 group_info 的 usage 减 1，跟 cred 一样，如果 usage 为 0 ，则销毁 group_info，因为 group_info 可以被多个 cred 使用（一个 group_info 对应多个 cred），所以才会有一个 usage 字段。。。。。。跟上面的 keyring 一样
	if (cred->group_info)
		put_group_info(cred->group_info);
  // 释放 user_struct 
	free_uid(cred->user);
  // 跟上面的 keyring group_info 一样
	put_user_ns(cred->user_ns);
  // 完成这些工作后，把 cred 放入 cred_jar，因为 cred 是个高频使用的数据结构，所以不是释放内存，而是把 cred 放入 一个缓存 cred_jar
	kmem_cache_free(cred_jar, cred);
}
```

现在快凌晨 4 点了，困死了

```zsh
# r00t @ FakeLinux in ~/code/asm [3:53:16]
$ date
Tue 23 Feb 2021 03:53:19 AM CST
```

后面的 检查释放 keyring，group_info，user_ns 不想一句一句分析代码了，道理都一样，先引用计数器减 1，为 0 说明这个结构没有在使用，就释放掉

over！



