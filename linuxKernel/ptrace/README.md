```c
SYSCALL_DEFINE4(ptrace, long, request, long, pid, unsigned long, addr,
		unsigned long, data)
{
	struct task_struct *child;
	long ret;
  
  // 一般是子进程调用，使自己进入被追踪模式
	if (request == PTRACE_TRACEME) {
		ret = ptrace_traceme();
		if (!ret)
			arch_ptrace_attach(current);
		goto out;
	}
  
  // find_get_task_by_vpid 获取 pid 对应进程的 task_struct
	child = find_get_task_by_vpid(pid);
	if (!child) {
		ret = -ESRCH;
		goto out;
	}
  
  // 父进程附加到子进程
	if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
		ret = ptrace_attach(child, request, addr, data);
		/*
		 * Some architectures need to do book-keeping after
		 * a ptrace attach.
		 */
		if (!ret)
			arch_ptrace_attach(child);
		goto out_put_task_struct;
	}

	ret = ptrace_check_attach(child, request == PTRACE_KILL ||
				  request == PTRACE_INTERRUPT);
	if (ret < 0)
		goto out_put_task_struct;

	ret = arch_ptrace(child, request, addr, data);
	if (ret || request != PTRACE_DETACH)
		ptrace_unfreeze_traced(child);

 out_put_task_struct:
	put_task_struct(child);
 out:
	return ret;
}
```



## ptrace_traceme

```c
static int ptrace_traceme(void)
{
	int ret = -EPERM;
  
  // 上锁进程链表
	write_lock_irq(&tasklist_lock);
	/* Are we already being traced? */
  // task_struct -> ptrace 表示进程是否可以 trace，成员 ptrace 被设置为 0 时表示不需要被跟踪
	if (!current->ptrace) {
		ret = security_ptrace_traceme(current->parent);
		/*
		 * Check PF_EXITING to ensure ->real_parent has not passed
		 * exit_ptrace(). Otherwise we don't report the error but
		 * pretend ->real_parent untraces us right after return.
		 */
    // PF_EXITING 进程开始关闭
		if (!ret && !(current->real_parent->flags & PF_EXITING)) {
			current->ptrace = PT_PTRACED;
			ptrace_link(current, current->real_parent);
		}
	}
	write_unlock_irq(&tasklist_lock);

	return ret;
}
```

security_ptrace_traceme -> 

