Linux 内核源码分析 -- getuid，geteuid



# getuid 

返回调用进程的真实用户 ID

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

	if (uid == (uid_t) -1)
		uid = overflowuid;
	return uid;
}
```





# geteuid 

返回调用进程的有效用户 ID

via：https://man7.org/linux/man-pages/man2/geteuid.2.html

returns the effective user ID of the calling process.

```c
SYSCALL_DEFINE0(geteuid)
{
	/* Only we change this so SMP safe */
	return from_kuid_munged(current_user_ns(), current_euid());
}
```

