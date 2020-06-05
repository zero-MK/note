Linux 内核源码分析 -- setuid, seteuid



## setuid()

设置用户标识号

setuid 是类 unix 系统提供的一个标志位，设置进程的 euid 为这个可执行文件或程序的拥有者(比如 root )的 uid ， 也就是说当 setuid 位被设置之后， 当文件或程序(统称为 executable )被执行时, 操作系统会赋予文件所有者的权限, 因为其 euid 是文件所有者的 uid

相当于 `chmod u+s`

via: https://man7.org/linux/man-pages/man2/setuid.2.html       

`setuid()` sets the effective user ID of the calling process.  If the calling process is privileged (more precisely: if the process has the `CAP_SETUID` capability in its user namespace), the real UID and saved set-user-ID are also set.

```c
SYSCALL_DEFINE1(setuid, uid_t, uid)
{
	return __sys_setuid(uid);
}
```



### __sys_setuid

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

    // 获取 uid 
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
        // 如果
		if (!uid_eq(kuid, old->uid)) {
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

