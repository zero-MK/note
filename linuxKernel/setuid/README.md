Linux 内核源码分析 -- setuid, seteuid



## setuid()

设置用户标识号

setuid 是类 unix 系统提供的一个标志位，设置进程的 euid 为这个可执行文件或程序的拥有者(比如 root )的 uid ， 也就是说当 setuid 位被设置之后， 当程序被执行时, 操作系统会赋予文件所有者的权限, 因为其 euid 是文件所有者的 uid

相当于 `chmod +s`

via: https://man7.org/linux/man-pages/man2/setuid.2.html       

`setuid()` sets the effective user ID of the calling process.  If the calling process is privileged (more precisely: if the process has the `CAP_SETUID` capability in its user namespace), the real UID and saved set-user-ID are also set.

```c
SYSCALL_DEFINE1(setuid, uid_t, uid)
{
	return __sys_setuid(uid);
}
```

### __sys_setuid()

```c
/*
 * setuid() is implemented like SysV with SAVED_IDS
 *
 * Note that SAVED_ID's is deficient in that a setuid root program
 * like sendmail, for example, cannot set its uid to be a normal
 * user and then switch back, because if you're root, setuid() sets
 * the saved uid too.  If you don't like this, blame the bright people
 * in the POSIX committee and/or USG.  Note that the BSD-style setreuid()
 * will allow a root program to temporarily drop privileges and be able to
 * regain them by swapping the real and effective uid.
 */
long __sys_setuid(uid_t uid)
{
    // 获取当前进程的 namespace
	struct user_namespace *ns = current_user_ns();
    // 用来保存当前进程的 cred , const 不可修改
	const struct cred *old;
	struct cred *new;
	int retval;
	kuid_t kuid;

    // uid 对应的 kuid_t 结构
	kuid = make_kuid(ns, uid);
	if (!uid_valid(kuid))
		return -EINVAL;

    // 给 new 分配内存(prepare_creds 在分析 fork 的时候我看过了,不重复)
	new = prepare_creds();
	if (!new)
		return -ENOMEM;
    // old 存入当前的 cred
	old = current_cred();

	retval = -EPERM;
    // 检查启动进程的用户是否有 CAP_SETUID 权限
	if (ns_capable_setid(old->user_ns, CAP_SETUID)) {
        // 把 new 的 suid 和 uid 当前的用户标识符
		new->suid = new->uid = kuid;
        // 对比 kuid->val 和 old->uid->val
		if (!uid_eq(kuid, old->uid)) {
            // change the user struct in a credentials set to match the new UID(原注释)
			retval = set_user(new);
			if (retval < 0)
				goto error;
		}
	} else if (!uid_eq(kuid, old->uid) && !uid_eq(kuid, new->suid)) {
		goto error;
	}

	new->fsuid = new->euid = kuid;

	retval = security_task_fix_setuid(new, old, LSM_SETID_ID);
	if (retval < 0)
		goto error;

	return commit_creds(new);

error:
	abort_creds(new);
	return retval;
}
```



### make_kuid()

```c
/**
 *	make_kuid - Map a user-namespace uid pair into a kuid.
 *	@ns:  User namespace that the uid is in
 *	@uid: User identifier
 *
 *	Maps a user-namespace uid pair into a kernel internal kuid,
 *	and returns that kuid.
 *
 *	When there is no mapping defined for the user-namespace uid
 *	pair INVALID_UID is returned.  Callers are expected to test
 *	for and handle INVALID_UID being returned.  INVALID_UID
 *	may be tested for using uid_valid().
 */
kuid_t make_kuid(struct user_namespace *ns, uid_t uid)
{
	/* Map the uid to a global kernel uid */
	return KUIDT_INIT(map_id_down(&ns->uid_map, uid));
}
```



```c
static u32 map_id_range_down(struct uid_gid_map *map, u32 id, u32 count)
{
	struct uid_gid_extent *extent;
	unsigned extents = map->nr_extents;
	smp_rmb();

	if (extents <= UID_GID_MAP_MAX_BASE_EXTENTS)
		extent = map_id_range_down_base(extents, map, id, count);
	else
		extent = map_id_range_down_max(extents, map, id, count);

	/* Map the id or note failure */
	if (extent)
		id = (id - extent->first) + extent->lower_first;
	else
		id = (u32) -1;

	return id;
}

static u32 map_id_down(struct uid_gid_map *map, u32 id)
{
	return map_id_range_down(map, id, 1);
}
```





### set_user()

change the user struct in a credentials set to match the new UID

```c
/*
 * change the user struct in a credentials set to match the new UID
 */
static int set_user(struct cred *new)
{
	struct user_struct *new_user;

    // 获取
	new_user = alloc_uid(new->uid);
	if (!new_user)
		return -EAGAIN;

	/*
	 * We don't fail in case of NPROC limit excess here because too many
	 * poorly written programs don't check set*uid() return code, assuming
	 * it never fails if called by root.  We may still enforce NPROC limit
	 * for programs doing set*uid()+execve() by harmlessly deferring the
	 * failure to the execve() stage.
	 */
    // &new_user->processes) >= rlimit(RLIMIT_NPROC) 检查进程数是否合法
    // new_user != INIT_USER 是不是 init 进程
	if (atomic_read(&new_user->processes) >= rlimit(RLIMIT_NPROC) &&
			new_user != INIT_USER)
		current->flags |= PF_NPROC_EXCEEDED; 
	else
		current->flags &= ~PF_NPROC_EXCEEDED; // 标记程序已被执行

	free_uid(new->user);
    // 
	new->user = new_user;
	return 0;
}
```



### alloc_uid()

```c
struct user_struct *alloc_uid(kuid_t uid)
{
    // uidhashentry(uid) 展开 就是 (uidhash_table + ((((__kuid_val(uid)) >> (CONFIG_BASE_SMALL ? 3 : 7)) + (__kuid_val(uid))) & ((1 << (CONFIG_BASE_SMALL ? 3 : 7)) - 1)))
	struct hlist_head *hashent = uidhashentry(uid);
	struct user_struct *up, *new;

    // 自旋锁,防止竞争条件
	spin_lock_irq(&uidhash_lock);
	up = uid_hash_find(uid, hashent);
	spin_unlock_irq(&uidhash_lock);

	if (!up) {
        // 分配内存
		new = kmem_cache_zalloc(uid_cachep, GFP_KERNEL);
		if (!new)
			return NULL;

        // 设置 new 的 uid 为我们指定的值
		new->uid = uid;
        // 设置引用标志位
		refcount_set(&new->__count, 1);
        // 资源限制检查
		ratelimit_state_init(&new->ratelimit, HZ, 100);
		ratelimit_set_flags(&new->ratelimit, RATELIMIT_MSG_ON_RELEASE);

		/*
		 * Before adding this, check whether we raced
		 * on adding the same user already..
		 */
		spin_lock_irq(&uidhash_lock);
		up = uid_hash_find(uid, hashent);
		if (up) {
			kmem_cache_free(uid_cachep, new);
		} else {
			uid_hash_insert(new, hashent);
			up = new;
		}
		spin_unlock_irq(&uidhash_lock);
	}

	return up;
}
```



### uid_eq()

```c
static inline uid_t __kuid_val(kuid_t uid)
{
	return uid.val;
}
static inline bool uid_eq(kuid_t left, kuid_t right)
{
	return __kuid_val(left) == __kuid_val(right);
}
```

意义很明显



### ns_capable_setid()

检查进程是否有对应的权限

`ns`:  The usernamespace we want the capability in

`cap`: The capability to be tested for

`ns`: 要检查的 user_namespace

`cap`: 要检查的权限

```c
/**
 * ns_capable_setid - Determine if the current task has a superior capability
 * in effect, while signalling that this check is being done from within a
 * setid syscall.
 * @ns:  The usernamespace we want the capability in
 * @cap: The capability to be tested for
 *
 * Return true if the current task has the given superior capability currently
 * available for use, false if not.
 *
 * This sets PF_SUPERPRIV on the task if the capability is available on the
 * assumption that it's about to be used.
 */
bool ns_capable_setid(struct user_namespace *ns, int cap)
{
	return ns_capable_common(ns, cap, CAP_OPT_INSETID);
}
```



#### ns_capable_common()

现在的 opt 是: CAP_OPT_INSETID 

```c
/* If capable is being called by a setid function */
#define CAP_OPT_INSETID BIT(2)
```

其实这个标志位就是说明要调用 `setid` 函数

```c
static bool ns_capable_common(struct user_namespace *ns,
			      int cap,
			      unsigned int opts)
{
	int capable;

    // 检查 cap 是否合法(0 => cap <= 37)
	if (unlikely(!cap_valid(cap))) {
		pr_crit("capable() called with invalid cap=%u\n", cap);
		BUG();
	}

	capable = security_capable(current_cred(), ns, cap, opts);
	if (capable == 0) {
		current->flags |= PF_SUPERPRIV;
		return true;
	}
	return false;
}
```

cap_valid()

```c
#define CAP_AUDIT_READ		37
#define CAP_LAST_CAP         CAP_AUDIT_READ
#define cap_valid(x) ((x) >= 0 && (x) <= CAP_LAST_CAP)
```

security_capable()

第一个参数传入了当前进程的 `cred` 

第二个参数是 `user_namespace`

第三个参数是 权限

第四个参数是 操作的函数

```c
static inline int security_capable(const struct cred *cred,
				   struct user_namespace *ns,
				   int cap,
				   unsigned int opts)
{
	return cap_capable(cred, ns, cap, opts);
}
```

cap_capable()

Determine whether a task has a particular effective capability

@cred: The credentials to use

@ns:  The user namespace in which we need the capability

@cap: The capability to check for

@opts: Bitmask of options defined in include/linux/security.h

```c

/**
 * cap_capable - Determine whether a task has a particular effective capability
 * @cred: The credentials to use
 * @ns:  The user namespace in which we need the capability
 * @cap: The capability to check for
 * @opts: Bitmask of options defined in include/linux/security.h
 *
 * Determine whether the nominated task has the specified capability amongst
 * its effective set, returning 0 if it does, -ve if it does not.
 *
 * NOTE WELL: cap_has_capability() cannot be used like the kernel's capable()
 * and has_capability() functions.  That is, it has the reverse semantics:
 * cap_has_capability() returns 0 when a task has a capability, but the
 * kernel's capable() and has_capability() returns 1 for this case.
 */
int cap_capable(const struct cred *cred, struct user_namespace *targ_ns,
		int cap, unsigned int opts)
{
	struct user_namespace *ns = targ_ns;

	/* See if cred has the capability in the target user namespace
	 * by examining the target user namespace and all of the target
	 * user namespace's parents.
	 */
	for (;;) {
		/* Do we have the necessary capabilities? */
        // 检查 user_namespace 是否一样
        // 其实退回 __sys_setuid() 会发现 ns == cred->user_ns 成立
		if (ns == cred->user_ns)
            // 检查权限的主做函数
			return cap_raised(cred->cap_effective, cap) ? 0 : -EPERM;

		/*
		 * If we're already at a lower level than we're looking for,
		 * we're done searching.
		 */
		if (ns->level <= cred->user_ns->level)
			return -EPERM;

		/* 
		 * The owner of the user namespace in the parent of the
		 * user namespace has all caps.
		 */
		if ((ns->parent == cred->user_ns) && uid_eq(ns->owner, cred->euid))
			return 0;

		/*
		 * If you have a capability in a parent user ns, then you have
		 * it over all children user namespaces as well.
		 */
		ns = ns->parent;
	}

	/* We never get here */
}
```

cap_raised()

其实一路追过来, 这里就是尽头了

```c
#define CAP_TO_INDEX(x)     ((x) >> 5)        /* 1 << 5 == bits in __u32 */
#define CAP_TO_MASK(x)      (1 << ((x) & 31)) /* mask for indexed __u32 */
#define cap_raised(c, flag) ((c).cap[CAP_TO_INDEX(flag)] & CAP_TO_MASK(flag))
```

**其实检查权限就是检查 `cred` 结构的 `(cap_effective).cap`** 

这里的 `CAP_TO_MASK(flag)`  计算出 `cap` 的掩码然后和 `cread->cap_effective` 对应的 `cap` 做 `&` 

`cap_effective`  字段: caps we can actually use (实际权限)

`cap_effective` 是 ` kernel_cap_t` 一个结构体

`kernel_cap_struct.cap` 就是一个数组

```c
typedef struct kernel_cap_struct {
	__u32 cap[_KERNEL_CAPABILITY_U32S];
} kernel_cap_t;
```

