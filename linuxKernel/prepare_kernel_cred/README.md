prepare_kernel_cred - Prepare a set of credentials for a kernel service

使用指定进程的 real_cred 去构造一个新的 cred，不是引用，不是引用，不是引用，而是创建一个新的 cred



源码版本：Linux Kernel 5.9.9

## prepare_kernel_cred

```c
/**
 * prepare_kernel_cred - Prepare a set of credentials for a kernel service
 * @daemon: A userspace daemon to be used as a reference
 *
 * Prepare a set of credentials for a kernel service.  This can then be used to
 * override a task's own credentials so that work can be done on behalf of that
 * task that requires a different subjective context.
 *
 * @daemon is used to provide a base for the security record, but can be NULL.
 * If @daemon is supplied, then the security data will be derived from that;
 * otherwise they'll be set to 0 and no groups, full capabilities and no keys.
 *
 * The caller may change these controls afterwards if desired.
 *
 * Returns the new credentials or NULL if out of memory.
 */
struct cred *prepare_kernel_cred(struct task_struct *daemon)
{
	const struct cred *old;
	struct cred *new;
  
  // 从 cred_jar 中分配一个 cred 
  //（cred_jar 是一个 kmem_cache ,每次 释放一个无用的 cred 的时候不会直接释放占用的内存 而是放入 cred_jar，高频使用的数据结构都有这样一个缓存机制 详细可以自己查查）
	new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
  // 分配失败的话直接 return
	if (!new)
		return NULL;

	kdebug("prepare_kernel_cred() alloc %p", new);
  
  // 如果有指定进程，也就是参数 deamon
	if (daemon)
		old = get_task_cred(daemon); // 获取参数 daemon 进程（我说的是参数，不是真的 daemon 进程）的 real_cred
	else
		old = get_cred(&init_cred); // 没有指定进程的话，也就是传入参数 0，直接使用 init 进程的 cred 
  
  // 验证 old cred 的 magic，看 cred 是否可用 （ord->magic == CRED_MAGIC）
	validate_creds(old);

	*new = *old; // 拷贝内容，把 old 的各个字段的值赋值给 new cred（对指针不了解的人可能迷惑，这里对指针解引用了）
  // 不设置 rcu 变量销毁时调用的 hook 函数
	new->non_rcu = 0;
  // 设置使用 new cred 的进程数为 1
	atomic_set(&new->usage, 1);
  // 订阅进程数为 0
	set_cred_subscribers(new, 0);
  // 初始化 group_info，usage 加 1 。(atomic_inc(&gi->usage);) 
	get_group_info(new->group_info);
  // 初始化 user_struct，__count 加 1。（refcount_inc(&u->__count);）
	get_uid(new->user);
  // 这里好像啥也不做，get_user_ns 返回 init 进程的 user_namespace
	get_user_ns(new->user_ns);

// 启用 keyring 的话，初始化
#ifdef CONFIG_KEYS
	new->session_keyring = NULL;
	new->process_keyring = NULL;
	new->thread_keyring = NULL;
	new->request_key_auth = NULL;
	new->jit_keyring = KEY_REQKEY_DEFL_THREAD_KEYRING;
#endif

// LSM 相关，不想详细讲，无非就是使用了 LSM 它自己的 hook 函数
#ifdef CONFIG_SECURITY
	new->security = NULL;
#endif
  // 这里的 security_prepare_creds 最终会调用 LSM 自己的 hook 函数
	if (security_prepare_creds(new, old, GFP_KERNEL_ACCOUNT) < 0)
		goto error;

	put_cred(old); // old->usage - 1，如果减 1 后为 0 则销毁 cred
	validate_creds(new); // 验证 new cred 的 magic，看 cred 是否可用 （ord->magic == CRED_MAGIC）
	return new; // 返回 new cred，结束

error:
	put_cred(new);
	put_cred(old);
	return NULL;
}
EXPORT_SYMBOL(prepare_kernel_cred);
```



### get_task_cred

```c
/**
 * get_task_cred - Get another task's objective credentials
 * @task: The task to query
 *
 * Get the objective credentials of a task, pinning them so that they can't go
 * away.  Accessing a task's credentials directly is not permitted.
 *
 * The caller must also make sure task doesn't get deleted, either by holding a
 * ref on task or by holding tasklist_lock to prevent it from being unlinked.
 */
const struct cred *get_task_cred(struct task_struct *task)
{
	const struct cred *cred;
  
  // 上 rcu 读取锁
	rcu_read_lock();

	do {
    // 读取 task 的 real_cred
    // 因为 real_cred 是 rcu 变量需要持有锁
    // 然后使用 rcu_dereference 去读取
		cred = __task_cred((task));
		BUG_ON(!cred);
	} while (!get_cred_rcu(cred));

	rcu_read_unlock();
	return cred;
}
EXPORT_SYMBOL(get_task_cred);
```



#### __task_cred

```c
/**
 * __task_cred - Access a task's objective credentials
 * @task: The task to query
 *
 * Access the objective credentials of a task.  The caller must hold the RCU
 * readlock.
 *
 * The result of this function should not be passed directly to get_cred();
 * rather get_task_cred() should be used instead.
 */
// 因为 real_cred 是 rcu 变量需要持有锁
// 然后使用 rcu_dereference 去读取
#define __task_cred(task)	\
	rcu_dereference((task)->real_cred)
```



### security_prepare_creds

```c
int security_prepare_creds(struct cred *new, const struct cred *old, gfp_t gfp)
{
	int rc = lsm_cred_alloc(new, gfp);

	if (rc)
		return rc;
  
  // 调用 Linux Security Module hook function 里面对应的 cred_prepare 的 cred_prepare 函数
  // 其实这里 LSM 有几个分支，比如 apparmor, tomoyo, bpf....等等
  // https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html
	rc = call_int_hook(cred_prepare, 0, new, old, gfp);
	if (unlikely(rc))
		security_cred_free(new);
	return rc;
}
```

关于 LSM 有以下几种

- [AppArmor](https://www.kernel.org/doc/html/latest/admin-guide/LSM/apparmor.html)
- [LoadPin](https://www.kernel.org/doc/html/latest/admin-guide/LSM/LoadPin.html)
- [SELinux](https://www.kernel.org/doc/html/latest/admin-guide/LSM/SELinux.html)
- [Smack](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Smack.html)
- [TOMOYO](https://www.kernel.org/doc/html/latest/admin-guide/LSM/tomoyo.html)
- [Yama](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [SafeSetID](https://www.kernel.org/doc/html/latest/admin-guide/LSM/SafeSetID.html)

这里讲 prepare_kernel_cred， LSM 又是别的内容了，不展开讲了，可以去下面这些文件里面看看具体的 hook 函数

![image-20210223184547478](https://gitee.com/scriptkiddies/images/raw/master/image-20210223184547478.png)

apparmor 的 cred_prepare 的 hook 函数

```c
	LSM_HOOK_INIT(cred_prepare, apparmor_cred_prepare)
    
 /*
 * prepare new cred label for modification by prepare_cred block
 */
static int apparmor_cred_prepare(struct cred *new, const struct cred *old,
				 gfp_t gfp)
{
	set_cred_label(new, aa_get_newest_label(cred_label(old)));
	return 0;
}
```

tomoyo 的 cred_prepare 的 hook 函数 

```c
/**
 * tomoyo_cred_prepare - Target for security_prepare_creds().
 *
 * @new: Pointer to "struct cred".
 * @old: Pointer to "struct cred".
 * @gfp: Memory allocation flags.
 *
 * Returns 0.
 */
static int tomoyo_cred_prepare(struct cred *new, const struct cred *old,
			       gfp_t gfp)
{
	/* Restore old_domain_info saved by previous execve() request. */
	struct tomoyo_task *s = tomoyo_task(current);

	if (s->old_domain_info && !current->in_execve) {
		atomic_dec(&s->domain_info->users);
		s->domain_info = s->old_domain_info;
		s->old_domain_info = NULL;
	}
	return 0;
}

```

。。。。。。



### 总结

正常调用 `prepare_kernel_cred` 会两种情况

- 一种是 调用 `prepare_kernel_cred` 的时候给一个有效的 `task_struct` 地址，这样的话会使用这个 `task_struct` 的 `real_cred` 作为模板去复制一个新的 cred
- 还有一种情况就是 `prepare_kernel_cred(0)`，这个情况下 `prepare_kernel_cred` 会使用 `init` 进程的 `cred` 作为模板复制出一个新的 `cred`



结束！

```zsh
# scriptkid @ MacBook-Pro in ~ [19:01:34]
$ date
2021年 2月23日 星期二 19时01分35秒 CST
```

