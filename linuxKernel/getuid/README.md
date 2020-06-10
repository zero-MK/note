Linux 内核源码分析 -- getuid，geteuid



# getuid 

获取用户标识号

via：https://man7.org/linux/man-pages/man2/geteuid.2.html

returns the real user ID of the calling process.

```C
SYSCALL_DEFINE0(getuid)
{
	/* Only we change this so SMP safe */
	return from_kuid_munged(current_user_ns(), current_uid());
}
```



## current_user_ns()

一个宏，用来获取当前进程的 `cred`

```c
#define current_user_ns()	(current_cred_xxx(user_ns))
#define current_cred_xxx(xxx)			\
({						\
	current_cred()->xxx;			\
})
```

```c
/**
 * current_cred - Access the current task's subjective credentials
 *
 * Access the subjective credentials of the current task.  RCU-safe,
 * since nobody else can modify it.
 */
#define current_cred() \
	rcu_dereference_protected(current->cred, 1)
```



## current_uid()

获取进程的 `cred->uid`

```c
#define current_uid()		(current_cred_xxx(uid))
#define current_cred_xxx(xxx)			\
({						\
	current_cred()->xxx;			\
})
```

```c
/**
 * current_cred - Access the current task's subjective credentials
 *
 * Access the subjective credentials of the current task.  RCU-safe,
 * since nobody else can modify it.
 */
#define current_cred() \
	rcu_dereference_protected(current->cred, 1)
```

其实跟上面的 `current_user_ns()` 差不多，就是用 `current_cred_xxx()` 拼接

`current_cred() ` 获取当前进程的 `cred` 

展开宏就是 ：`current->cred->uid`



## from_kuid_munged()

```c
uid_t from_kuid_munged(struct user_namespace *targ, kuid_t kuid)
{
	uid_t uid;
	uid = from_kuid(targ, kuid);

    // 如果 uid 是 -1 的话,把 uid 设置成 65534 (overflow)
	if (uid == (uid_t) -1)
		uid = overflowuid;
	return uid;
}
```

## from_kuid()

```c
static inline uid_t from_kuid(struct user_namespace *to, kuid_t kuid)
{
	return __kuid_val(kuid);
}
```

### __kuid_val()

```c
static inline uid_t __kuid_val(kuid_t uid)
{
    // 获取 kuid_t 结构的 val,这个就是 uid 的值了
	return uid.val;
}
```



# geteuid 

获取用户有效标识号

via：https://man7.org/linux/man-pages/man2/geteuid.2.html

returns the effective user ID of the calling process.

```c
SYSCALL_DEFINE0(geteuid)
{
	/* Only we change this so SMP safe */
	return from_kuid_munged(current_user_ns(), current_euid());
}
```

其实和上面的 getuid 是一样的



## 总结

获取用户标识号 和 获取用户有效标识号 其实就是获取 `current->cred->uid->val`,   `current->cred->euid->val`

