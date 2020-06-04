太闲了看了一下 fork 在内核里面的工作

via：[https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L2522](https://elixir.bootlin.com/linux/latest/source/kernel/fork.c#L2522)

```c
SYSCALL_DEFINE0(fork)
{
#ifdef CONFIG_MMU
    struct kernel_clone_args args = {
        .exit_signal = SIGCHLD,
    };

    return _do_fork(&args);
#else
    /* can not support in nommu mode */
    return -EINVAL;
#endif
}
```

其实在内核里面 `fork` `vfork` `clone` 最终都是会调用 `_do_fork`
直接跟进去

## _do_frok

via：[https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L2403](https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L2403)

```c
long _do_fork(struct kernel_clone_args *args)
{
    // 取出 flag 参数
    u64 clone_flags = args->flags;
    struct completion vfork;
    struct pid *pid;
    // 创建一个 进程描述符
    struct task_struct *p;
    int trace = 0;
    long nr;
​
    /*
     * Determine whether and which event to report to ptracer.  When
     * called from kernel_thread or CLONE_UNTRACED is explicitly
     * requested, no event is reported; otherwise, report if the event
     * for the type of forking is enabled.
     */
    // 对 flag 标志进行检查，详细说明参见下面的 标志含义
    if (!(clone_flags & CLONE_UNTRACED)) {
        if (clone_flags & CLONE_VFORK)
            trace = PTRACE_EVENT_VFORK;
        else if (args->exit_signal != SIGCHLD)
            trace = PTRACE_EVENT_CLONE;
        else
            trace = PTRACE_EVENT_FORK;
        
       // 程序是否支持调试 trace 
       /*
       这是 ptrace_event_enabled 的源码
 * ptrace_event_enabled - test whether a ptrace event is enabled
 * @task: ptracee of interest
 * @event: %PTRACE_EVENT_* to test
 *
 * Test whether @event is enabled for ptracee @task.
 *
 * Returns %true if @event is enabled, %false otherwise.
​
static inline bool ptrace_event_enabled(struct task_struct *task, int event)
{
    return task->ptrace & PT_EVENT_FLAG(event);
}
       */
        if (likely(!ptrace_event_enabled(current, trace)))
            trace = 0;
    }
​
   // fork 的主要工作 copy_process 生成新的进程 p
    p = copy_process(NULL, trace, NUMA_NO_NODE, args);
    add_latent_entropy();
​
    if (IS_ERR(p))
        return PTR_ERR(p);
​
    /*
     * Do this prior waking up the new thread - the thread pointer
     * might get invalid after that point, if the thread exits quickly.
     */
    trace_sched_process_fork(current, p);
​
    pid = get_task_pid(p, PIDTYPE_PID);
    nr = pid_vnr(pid);
​
    if (clone_flags & CLONE_PARENT_SETTID)
        put_user(nr, args->parent_tid);
​
    if (clone_flags & CLONE_VFORK) {
        p->vfork_done = &vfork;
        init_completion(&vfork);
        get_task_struct(p);
    }
​
    wake_up_new_task(p);
​
    /* forking complete and child started to run, tell ptracer */
    if (unlikely(trace))
        ptrace_event_pid(trace, pid);
​
    if (clone_flags & CLONE_VFORK) {
        if (!wait_for_vfork_done(p, &vfork))
            ptrace_event_pid(PTRACE_EVENT_VFORK_DONE, pid);
    }
​
    put_pid(pid);
    return nr;
}
```

### 标志含义

```
  CLONE_PARENT   创建的子进程的父进程是调用者的父进程，新进程与创建它的进程成了“兄弟”而不是“父子”
  CLONE_FS       子进程与父进程共享相同的文件系统，包括 root 、当前目录、 umask
  CLONE_FILES    子进程与父进程共享相同的文件描述符（file descriptor）表
  CLONE_NEWNS    在新的 namespace 启动子进程， namespace 描述了进程的文件 hierarchy
  CLONE_SIGHAND  子进程与父进程共享相同的信号处理（signal handler）表
  CLONE_PTRACE   若父进程被 trace ，子进程也被 trace
  CLONE_VFORK    父进程被挂起，直至子进程释放虚拟内存资源
  CLONE_VM       子进程与父进程运行于相同的内存空间
  CLONE_PID      子进程在创建时 PID 与父进程一致
  CLONE_THREAD   Linux 2.4 中增加以支持 POSIX 线程标准，子进程与父进程共享相同的线程群
```

## copy_process 

生成新的进程

```c
p = copy_process(NULL, trace, NUMA_NO_NODE, args);
```

via：[https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L1824](https://elixir.bootlin.com/linux/latest/source/kernel/fork.c#L1824)
这个函数有点长得可怕 在 Linux 5.6.14 下面一共 538 行，不能每一行都分析了，选重点吧

```c
/*
 * This creates a new process as a copy of the old one,
 * but does not actually start it yet.
 *
 * It copies the registers, and all the appropriate
 * parts of the process environment (as per the clone
 * flags). The actual kick-off is left to the caller.
 */
static __latent_entropy struct task_struct *copy_process(
                    struct pid *pid,
                    int trace,
                    int node,
                    struct kernel_clone_args *args)
{
    int pidfd = -1, retval;
    struct task_struct *p;
    struct multiprocess_signals delayed;
    struct file *pidfile = NULL;
    u64 clone_flags = args->flags;
    struct nsproxy *nsp = current->nsproxy;
​
    /*
     * Don't allow sharing the root directory with processes in a different
     * namespace
     */
    // 不同的命名空间（namespace）不允许共享 根目录（/） 其实共享根目录了那还玩啥，全透明了都
    // CLONE_NEWNS    在新的 namespace 启动子进程， namespace 描述了进程的文件 hierarchy
    // CLONE_FS       子进程与父进程共享相同的文件系统，包括 root 、当前目录、 umask
    if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))
        return ERR_PTR(-EINVAL);
​
    // namespace 用户隔离，这个东西曾经出了一个提权漏洞
    if ((clone_flags & (CLONE_NEWUSER|CLONE_FS)) == (CLONE_NEWUSER|CLONE_FS))
        return ERR_PTR(-EINVAL);
​
    /*
     * Thread groups must share signals as well, and detached threads
     * can only be started up within the thread group.
     */
    //CLONE_THREAD 子进程与父进程共享相同的线程群
    //共享相同的线程组不共享 signals 冲突
    if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
        return ERR_PTR(-EINVAL);
​
    /*
     * Shared signal handlers imply shared VM. By way of the above,
     * thread groups also imply shared VM. Blocking this case allows
     * for various simplifications in other code.
     */
    //CLONE_SIGHAND  子进程与父进程共享相同的信号处理（signal handler）表
    //CLONE_VM       子进程与父进程运行于相同的内存空间
    if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
        return ERR_PTR(-EINVAL);
​
    /*
     * Siblings of global init remain as zombies on exit since they are
     * not reaped by their parent (swapper). To solve this and to avoid
     * multi-rooted process trees, prevent global and container-inits
     * from creating siblings.
     */
    if ((clone_flags & CLONE_PARENT) &&
                current->signal->flags & SIGNAL_UNKILLABLE)
        return ERR_PTR(-EINVAL);
​
    /*
     * If the new process will be in a different pid or user namespace
     * do not allow it to share a thread group with the forking task.
     */
    //新进程有独立的 pid
    //运行于另一个命名空间（namespace）的进程
    //都不允许共享线程组
    if (clone_flags & CLONE_THREAD) {
        if ((clone_flags & (CLONE_NEWUSER | CLONE_NEWPID)) ||
            (task_active_pid_ns(current) != nsp->pid_ns_for_children))
            return ERR_PTR(-EINVAL);
    }
​
    /*
     * If the new process will be in a different time namespace
     * do not allow it to share VM or a thread group with the forking task.
     */
    if (clone_flags & (CLONE_THREAD | CLONE_VM)) {
        if (nsp->time_ns != nsp->time_ns_for_children)
            return ERR_PTR(-EINVAL);
    }
​
    if (clone_flags & CLONE_PIDFD) {
        /*
         * - CLONE_DETACHED is blocked so that we can potentially
         *   reuse it later for CLONE_PIDFD.
         * - CLONE_THREAD is blocked until someone really needs it.
         */
        if (clone_flags & (CLONE_DETACHED | CLONE_THREAD))
            return ERR_PTR(-EINVAL);
    }
​
    /*
     * Force any signals received before this point to be delivered
     * before the fork happens.  Collect up signals sent to multiple
     * processes that happen during the fork and delay them so that
     * they appear to happen after the fork.
     */
    sigemptyset(&delayed.signal);
    INIT_HLIST_NODE(&delayed.node);
​
    spin_lock_irq(&current->sighand->siglock);
    if (!(clone_flags & CLONE_THREAD))
        hlist_add_head(&delayed.node, &current->signal->multiprocess);
    recalc_sigpending();
    spin_unlock_irq(&current->sighand->siglock);
    retval = -ERESTARTNOINTR;
    if (signal_pending(current))
        goto fork_out;
​
    retval = -ENOMEM;
    // 重点操作，就是在里面复制 父进程 的进程描述符，详细分析见下面
    p = dup_task_struct(current, node);
    if (!p)
        goto fork_out;
​
    /*
     * This _must_ happen before we call free_task(), i.e. before we jump
     * to any of the bad_fork_* labels. This is to avoid freeing
     * p->set_child_tid which is (ab)used as a kthread's data pointer for
     * kernel threads (PF_KTHREAD).
     */
    p->set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ? args->child_tid : NULL;
    /*
     * Clear TID on mm_release()?
     */
    p->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? args->child_tid : NULL;
​
    ftrace_graph_init_task(p);
​
    rt_mutex_init_task(p);
​
#ifdef CONFIG_PROVE_LOCKING
    DEBUG_LOCKS_WARN_ON(!p->hardirqs_enabled);
    DEBUG_LOCKS_WARN_ON(!p->softirqs_enabled);
#endif
    retval = -EAGAIN;
    // RLIMIT_NPROC 每个 real id（ruid） 可拥有的最大子进程数
    if (atomic_read(&p->real_cred->user->processes) >=
            task_rlimit(p, RLIMIT_NPROC)) {
        if (p->real_cred->user != INIT_USER &&
            !capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN))
            goto bad_fork_free;
    }
    current->flags &= ~PF_NPROC_EXCEEDED;
​
    // 顾名思义，复制 cred，详细源码下面分析
    // 官方描述：Copy credentials for the new process created by fork()
    // cred 结构体其实就是将原先 task_struct 中的一些涉及安全和信任的字段包装成了一个结构体
    retval = copy_creds(p, clone_flags);
    if (retval < 0)
        goto bad_fork_free;
​
    /*
     * If multiple threads are within copy_process(), then this check
     * triggers too late. This doesn't hurt, the check is only there
     * to stop root fork bombs.
     */
    retval = -EAGAIN;
    if (nr_threads >= max_threads)
        goto bad_fork_cleanup_count;
​
    delayacct_tsk_init(p);  /* Must remain after dup_task_struct() */
    // task_struct 的 flag 字段
    // via：https://elixir.bootlin.com/linux/v5.6.14/source/include/linux/sched.h#L1461
    // PF_SUPERPRIV 使用超级用户权限
    // PF_IDLE 标志进程空闲
    // PF_WQ_WORKER 标志是工作者线程
    // PF_FORKNOEXEC fork 但是不执行
    p->flags &= ~(PF_SUPERPRIV | PF_WQ_WORKER | PF_IDLE);
    p->flags |= PF_FORKNOEXEC;
    
    // 初始化进程亲属关系链表
    INIT_LIST_HEAD(&p->children);
    INIT_LIST_HEAD(&p->sibling);
    rcu_copy_process(p);
    // vfork 会用到的字段
    p->vfork_done = NULL;
    spin_lock_init(&p->alloc_lock);
​
    /*
static inline void sigemptyset(sigset_t *set)
{
    switch (_NSIG_WORDS) {
    default:
        memset(set, 0, sizeof(sigset_t));
        break;
    case 2: set->sig[1] = 0;
        // fall through 
    case 1: set->sig[0] = 0;
        break;
    }
}
分支说明：
x86：case 1
x64：case 2
其他：default
​
pending 字段：进程上还需要处理的信号
    */
    init_sigpending(&p->pending);
​
    // 初始化 时间数据成员
    p->utime = p->stime = p->gtime = 0;
#ifdef CONFIG_ARCH_HAS_SCALED_CPUTIME
    p->utimescaled = p->stimescaled = 0;
#endif
    prev_cputime_init(&p->prev_cputime);
​
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
    seqcount_init(&p->vtime.seqcount);
    //starttime 进程的开始执行时间
    p->vtime.starttime = 0;
    p->vtime.state = VTIME_INACTIVE;
#endif
​
#if defined(SPLIT_RSS_COUNTING)
    memset(&p->rss_stat, 0, sizeof(p->rss_stat));
#endif
​
    // 复制父进程的 时间延迟值
    p->default_timer_slack_ns = current->timer_slack_ns;
​
#ifdef CONFIG_PSI
    p->psi_flags = 0;
#endif
​
    // 等价 memset(ioac, 0, sizeof(p->ioac));
    task_io_accounting_init(&p->ioac);
    acct_clear_integrals(p);
​
    posix_cputimers_init(&p->posix_cputimers);
​
    p->io_context = NULL;
    audit_set_context(p, NULL);
    // cgroup 和 init_css_set
    // via：https://elixir.bootlin.com/linux/v5.6.14/source/kernel/cgroup/cgroup.c#L5870
    cgroup_fork(p);
#ifdef CONFIG_NUMA
    p->mempolicy = mpol_dup(p->mempolicy);
    if (IS_ERR(p->mempolicy)) {
        retval = PTR_ERR(p->mempolicy);
        p->mempolicy = NULL;
        goto bad_fork_cleanup_threadgroup_lock;
    }
#endif
#ifdef CONFIG_CPUSETS
    p->cpuset_mem_spread_rotor = NUMA_NO_NODE;
    p->cpuset_slab_spread_rotor = NUMA_NO_NODE;
    seqcount_init(&p->mems_allowed_seq);
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
    // 初始化中断请求
    p->irq_events = 0;
    p->hardirqs_enabled = 0;
    p->hardirq_enable_ip = 0;
    p->hardirq_enable_event = 0;
    p->hardirq_disable_ip = _THIS_IP_;
    p->hardirq_disable_event = 0;
    p->softirqs_enabled = 1;
    p->softirq_enable_ip = _THIS_IP_;
    p->softirq_enable_event = 0;
    p->softirq_disable_ip = 0;
    p->softirq_disable_event = 0;
    p->hardirq_context = 0;
    p->softirq_context = 0;
#endif
​
    p->pagefault_disabled = 0;
​
#ifdef CONFIG_LOCKDEP
    lockdep_init_task(p);
#endif
​
#ifdef CONFIG_DEBUG_MUTEXES
    p->blocked_on = NULL; /* not blocked yet */
#endif
#ifdef CONFIG_BCACHE
    p->sequential_io    = 0;
    p->sequential_io_avg    = 0;
#endif
​
    /* Perform scheduler related setup. Assign this task to a CPU. */
    // 把进程加入调度队列
    retval = sched_fork(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_policy;
​
    retval = perf_event_init_task(p);
    if (retval)
        goto bad_fork_cleanup_policy;
    retval = audit_alloc(p);
    if (retval)
        goto bad_fork_cleanup_perf;
    /* copy all the process information */
    // 复制所有进程信息
    shm_init_task(p); // #define shm_init_task(task) INIT_LIST_HEAD(&(task)->sysvshm.shm_clist)
    
    // 用 kzalloc 给 security 分配内存
    retval = security_task_alloc(p, clone_flags);
    if (retval)
        goto bad_fork_cleanup_audit;
    // 这个函数直接返回 0 
    // via：https://elixir.bootlin.com/linux/v5.6.14/source/include/linux/sem.h#L25
    retval = copy_semundo(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_security;
    
    // 复制父进程打开的文件信息，详细见下面分析
    retval = copy_files(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_semundo;
    
    // 复制父进程 fs_struct 信息，详细见下面分析
    retval = copy_fs(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_files;
    
    retval = copy_sighand(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_fs;
    
    // 复制父进程所接收的信号
    retval = copy_signal(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_sighand;
    
    // 复制父进程的内存管理相关信息，详细见下面分析
    retval = copy_mm(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_signal;
    
    // 复制父进程的 namespaces
    retval = copy_namespaces(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_mm;
    
    // 复制父进程的 io_context 上下文信息，详细见下面分析
    retval = copy_io(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_namespaces;
    
    // 复制线程的 
    retval = copy_thread_tls(clone_flags, args->stack, args->stack_size, p,
                 args->tls);
    if (retval)
        goto bad_fork_cleanup_io;
​
    stackleak_task_init(p);
​
    if (pid != &init_struct_pid) {
        pid = alloc_pid(p->nsproxy->pid_ns_for_children, args->set_tid,
                args->set_tid_size);
        if (IS_ERR(pid)) {
            retval = PTR_ERR(pid);
            goto bad_fork_cleanup_thread;
        }
    }
​
    /*
     * This has to happen after we've potentially unshared the file
     * descriptor table (so that the pidfd doesn't leak into the child
     * if the fd table isn't shared).
     */
    if (clone_flags & CLONE_PIDFD) {
        retval = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
        if (retval < 0)
            goto bad_fork_free_pid;
​
        pidfd = retval;
​
        pidfile = anon_inode_getfile("[pidfd]", &pidfd_fops, pid,
                          O_RDWR | O_CLOEXEC);
        if (IS_ERR(pidfile)) {
            put_unused_fd(pidfd);
            retval = PTR_ERR(pidfile);
            goto bad_fork_free_pid;
        }
        get_pid(pid);   /* held by pidfile now */
​
        retval = put_user(pidfd, args->pidfd);
        if (retval)
            goto bad_fork_put_pidfd;
    }
​
#ifdef CONFIG_BLOCK
    p->plug = NULL;
#endif
    futex_init_task(p);
​
    /*
     * sigaltstack should be cleared when sharing the same VM
     */
    if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM)
        sas_ss_reset(p);
​
    /*
     * Syscall tracing and stepping should be turned off in the
     * child regardless of CLONE_PTRACE.
     */
    user_disable_single_step(p);
    clear_tsk_thread_flag(p, TIF_SYSCALL_TRACE);
#ifdef TIF_SYSCALL_EMU
    clear_tsk_thread_flag(p, TIF_SYSCALL_EMU);
#endif
    clear_tsk_latency_tracing(p);
​
    /* ok, now we should be set up.. */
    p->pid = pid_nr(pid);
    if (clone_flags & CLONE_THREAD) {
        p->exit_signal = -1;
        p->group_leader = current->group_leader;
        p->tgid = current->tgid;
    } else {
        if (clone_flags & CLONE_PARENT)
            p->exit_signal = current->group_leader->exit_signal;
        else
            p->exit_signal = args->exit_signal;
        p->group_leader = p;
        p->tgid = p->pid;
    }
​
    p->nr_dirtied = 0;
    p->nr_dirtied_pause = 128 >> (PAGE_SHIFT - 10);
    p->dirty_paused_when = 0;
​
    p->pdeath_signal = 0;
    INIT_LIST_HEAD(&p->thread_group);
    p->task_works = NULL;
​
    cgroup_threadgroup_change_begin(current);
    /*
     * Ensure that the cgroup subsystem policies allow the new process to be
     * forked. It should be noted the the new process's css_set can be changed
     * between here and cgroup_post_fork() if an organisation operation is in
     * progress.
     */
    retval = cgroup_can_fork(p);
    if (retval)
        goto bad_fork_cgroup_threadgroup_change_end;
​
    /*
     * From this point on we must avoid any synchronous user-space
     * communication until we take the tasklist-lock. In particular, we do
     * not want user-space to be able to predict the process start-time by
     * stalling fork(2) after we recorded the start_time but before it is
     * visible to the system.
     */
​
    p->start_time = ktime_get_ns();
    p->start_boottime = ktime_get_boottime_ns();
​
    /*
     * Make it visible to the rest of the system, but dont wake it up yet.
     * Need tasklist lock for parent etc handling!
     */
    write_lock_irq(&tasklist_lock);
​
    /* CLONE_PARENT re-uses the old parent */
    if (clone_flags & (CLONE_PARENT|CLONE_THREAD)) {
        p->real_parent = current->real_parent;
        p->parent_exec_id = current->parent_exec_id;
    } else {
        p->real_parent = current;
        p->parent_exec_id = current->self_exec_id;
    }
​
    klp_copy_process(p);
​
    spin_lock(&current->sighand->siglock);
​
    /*
     * Copy seccomp details explicitly here, in case they were changed
     * before holding sighand lock.
     */
    copy_seccomp(p);
​
    rseq_fork(p, clone_flags);
​
    /* Don't start children in a dying pid namespace */
    if (unlikely(!(ns_of_pid(pid)->pid_allocated & PIDNS_ADDING))) {
        retval = -ENOMEM;
        goto bad_fork_cancel_cgroup;
    }
​
    /* Let kill terminate clone/fork in the middle */
    if (fatal_signal_pending(current)) {
        retval = -EINTR;
        goto bad_fork_cancel_cgroup;
    }
​
    /* past the last point of failure */
    if (pidfile)
        fd_install(pidfd, pidfile);
​
    init_task_pid_links(p);
    if (likely(p->pid)) {
        ptrace_init_task(p, (clone_flags & CLONE_PTRACE) || trace);
​
        init_task_pid(p, PIDTYPE_PID, pid);
        if (thread_group_leader(p)) {
            init_task_pid(p, PIDTYPE_TGID, pid);
            init_task_pid(p, PIDTYPE_PGID, task_pgrp(current));
            init_task_pid(p, PIDTYPE_SID, task_session(current));
​
            if (is_child_reaper(pid)) {
                ns_of_pid(pid)->child_reaper = p;
                p->signal->flags |= SIGNAL_UNKILLABLE;
            }
            p->signal->shared_pending.signal = delayed.signal;
            p->signal->tty = tty_kref_get(current->signal->tty);
            /*
             * Inherit has_child_subreaper flag under the same
             * tasklist_lock with adding child to the process tree
             * for propagate_has_child_subreaper optimization.
             */
            p->signal->has_child_subreaper = p->real_parent->signal->has_child_subreaper ||
                             p->real_parent->signal->is_child_subreaper;
            list_add_tail(&p->sibling, &p->real_parent->children);
            list_add_tail_rcu(&p->tasks, &init_task.tasks);
            attach_pid(p, PIDTYPE_TGID);
            attach_pid(p, PIDTYPE_PGID);
            attach_pid(p, PIDTYPE_SID);
            __this_cpu_inc(process_counts);
        } else {
            current->signal->nr_threads++;
            atomic_inc(&current->signal->live);
            refcount_inc(&current->signal->sigcnt);
            task_join_group_stop(p);
            list_add_tail_rcu(&p->thread_group,
                      &p->group_leader->thread_group);
            list_add_tail_rcu(&p->thread_node,
                      &p->signal->thread_head);
        }
        attach_pid(p, PIDTYPE_PID);
        nr_threads++;
    }
    total_forks++;
    hlist_del_init(&delayed.node);
    spin_unlock(&current->sighand->siglock);
    syscall_tracepoint_update(p);
    write_unlock_irq(&tasklist_lock);
​
    proc_fork_connector(p);
    cgroup_post_fork(p);
    cgroup_threadgroup_change_end(current);
    perf_event_fork(p);
​
    trace_task_newtask(p, clone_flags);
    uprobe_copy_process(p, clone_flags);
​
    return p;
​
bad_fork_cancel_cgroup:
    spin_unlock(&current->sighand->siglock);
    write_unlock_irq(&tasklist_lock);
    cgroup_cancel_fork(p);
bad_fork_cgroup_threadgroup_change_end:
    cgroup_threadgroup_change_end(current);
bad_fork_put_pidfd:
    if (clone_flags & CLONE_PIDFD) {
        fput(pidfile);
        put_unused_fd(pidfd);
    }
bad_fork_free_pid:
    if (pid != &init_struct_pid)
        free_pid(pid);
bad_fork_cleanup_thread:
    exit_thread(p);
bad_fork_cleanup_io:
    if (p->io_context)
        exit_io_context(p);
bad_fork_cleanup_namespaces:
    exit_task_namespaces(p);
bad_fork_cleanup_mm:
    if (p->mm) {
        mm_clear_owner(p->mm, p);
        mmput(p->mm);
    }
bad_fork_cleanup_signal:
    if (!(clone_flags & CLONE_THREAD))
        free_signal_struct(p->signal);
bad_fork_cleanup_sighand:
    __cleanup_sighand(p->sighand);
bad_fork_cleanup_fs:
    exit_fs(p); /* blocking */
bad_fork_cleanup_files:
    exit_files(p); /* blocking */
bad_fork_cleanup_semundo:
    exit_sem(p);
bad_fork_cleanup_security:
    security_task_free(p);
bad_fork_cleanup_audit:
    audit_free(p);
bad_fork_cleanup_perf:
    perf_event_free_task(p);
bad_fork_cleanup_policy:
    lockdep_free_task(p);
#ifdef CONFIG_NUMA
    mpol_put(p->mempolicy);
bad_fork_cleanup_threadgroup_lock:
#endif
    delayacct_tsk_free(p);
bad_fork_cleanup_count:
    atomic_dec(&p->cred->user->processes);
    exit_creds(p);
bad_fork_free:
    p->state = TASK_DEAD;
    put_task_stack(p);
    delayed_free_task(p);
fork_out:
    spin_lock_irq(&current->sighand->siglock);
    hlist_del_init(&delayed.node);
    spin_unlock_irq(&current->sighand->siglock);
    return ERR_PTR(retval);
}
```

## dup_task_struct

```c
p = dup_task_struct(current, node);
```

node == NUMA_NO_NODE
via：[https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L859](https://elixir.bootlin.com/linux/latest/source/kernel/fork.c#L859)

```c
static struct task_struct *dup_task_struct(struct task_struct *orig, int node)
{
    struct task_struct *tsk;
    unsigned long *stack;
    struct vm_struct *stack_vm_area __maybe_unused;
    int err;
​
    if (node == NUMA_NO_NODE)
        node = tsk_fork_get_node(orig);
/*
via：https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L167
​
static struct kmem_cache *task_struct_cachep;
static inline struct task_struct *alloc_task_struct_node(int node)
{
    return kmem_cache_alloc_node(task_struct_cachep, GFP_KERNEL, node);
}
就是分配内存
kmem_cache_alloc_node   如果指定的 NUMA 节点与本处理器所在节点不一致，则先从指定节点上获取 slab，替换处理器活动 slab，然后分配对象。
*/
    tsk = alloc_task_struct_node(node);
    if (!tsk)
        return NULL;
/*
via：https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L305
​
static unsigned long *alloc_thread_stack_node(struct task_struct *tsk,
                          int node)
{
    unsigned long *stack;
    stack = kmem_cache_alloc_node(thread_stack_cache, THREADINFO_GFP, node);
    tsk->stack = stack;
    return stack;
}
给新进程分配栈内存
*/
    stack = alloc_thread_stack_node(tsk, node);
    if (!stack)
        goto free_tsk;
​
    // 源码有点长，放下面了
    if (memcg_charge_kernel_stack(tsk))
        goto free_stack;
​
    // return t->stack_vm_area; 获取 tsk 的 stack 的 vm_area
    stack_vm_area = task_stack_vm_area(tsk);
​
    // 重点，这里就是真正的复制父进程的 task_struct，其实源码很简单
/*
via：https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L844
​
int __weak arch_dup_task_struct(struct task_struct *dst,
                           struct task_struct *src)
{
    *dst = *src;
    return 0;
}
orig 就是指向父进程的 task_struct 指针
tsk  就是指向子进程的 task_struct 指针
解引用，复制值
*/
    err = arch_dup_task_struct(tsk, orig);
​
    /*
     * arch_dup_task_struct() clobbers the stack-related fields.  Make
     * sure they're properly initialized before using any stack-related
     * functions again.
     */
    // 子进程肯定用的是自己的栈，没有这个一句子进程就会父进程共用一个栈
    // 这个就是为什么上面要分配内存，并取出这个两个字段
    tsk->stack = stack;
#ifdef CONFIG_VMAP_STACK
    tsk->stack_vm_area = stack_vm_area;
#endif
#ifdef CONFIG_THREAD_INFO_IN_TASK
    refcount_set(&tsk->stack_refcount, 1);
#endif
​
    if (err)
        goto free_stack;
​
#ifdef CONFIG_SECCOMP
    /*
     * We must handle setting up seccomp filters once we're under
     * the sighand lock in case orig has changed between now and
     * then. Until then, filter must be NULL to avoid messing up
     * the usage counts on the error path calling free_task.
     */
    tsk->seccomp.filter = NULL;
#endif
​
/* 设置线程栈
   via：https://elixir.bootlin.com/linux/v5.6.14/source/include/linux/sched/task_stack.h#L24
   展开的源码是
static inline void setup_thread_stack(struct task_struct *p, struct task_struct *org)
{
    *((struct thread_info *)(p)->stack) = *(((struct thread_info *)(org)->stack));
    (&p->thread_info)->task = p;
}
其实就是复制了父进程的 栈 ，然后设置子进程的 thread_info 的 task 字段
这里补充一点：一个进程的 task_strcut 的 thread_info 字段存的是进程的 thread_info，然后 thread_info 里的 task 字段存的是进程的 task_struct
*/ 
    setup_thread_stack(tsk, orig);
    // 把进程加入调度队列（就是把 thread_info 的 标志位（flag） 设置成 TIF_NEED_RESCHED 1 （rescheduling necessary））
    clear_user_return_notifier(tsk);
    clear_tsk_need_resched(tsk);
/*
via：https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L851
​
#define STACK_END_MAGIC     0x57AC6E9D
void set_task_stack_end_magic(struct task_struct *tsk)
{
    unsigned long *stackend;
​
    stackend = end_of_stack(tsk);
    *stackend = STACK_END_MAGIC;    // for overflow detection
}
在栈底设置一个 魔数 以检测是否发生栈溢出（有点像 canary ，但是这个是固定的数，只是用来检测意外溢出，不是用来防止 overflow exploit）
*/
    set_task_stack_end_magic(tsk);
​
#ifdef CONFIG_STACKPROTECTOR
    // 顾名思义，canary，随机数，详细算法
    // via：https://elixir.bootlin.com/linux/v5.6.14/source/drivers/char/random.c#L2162
    tsk->stack_canary = get_random_canary();
#endif
    if (orig->cpus_ptr == &orig->cpus_mask)
        tsk->cpus_ptr = &tsk->cpus_mask;
​
    /*
     * One for the user space visible state that goes away when reaped.
     * One for the scheduler.
     */
    refcount_set(&tsk->rcu_users, 2);
    /* One for the rcu users */
    refcount_set(&tsk->usage, 1);
#ifdef CONFIG_BLK_DEV_IO_TRACE
    tsk->btrace_seq = 0;
#endif
    tsk->splice_pipe = NULL;
    tsk->task_frag.page = NULL;
    tsk->wake_q.next = NULL;
​
    account_kernel_stack(tsk, 1);
​
    kcov_task_init(tsk);
​
#ifdef CONFIG_FAULT_INJECTION
    tsk->fail_nth = 0;
#endif
​
#ifdef CONFIG_BLK_CGROUP
    tsk->throttle_queue = NULL;
    tsk->use_memdelay = 0;
#endif
​
#ifdef CONFIG_MEMCG
    tsk->active_memcg = NULL;
#endif
    return tsk;
​
free_stack:
    free_thread_stack(tsk);
free_tsk:
    free_task_struct(tsk);
    return NULL;
}
```

## memcg_charge_kernel_stack

via：[https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L405](https://elixir.bootlin.com/linux/latest/source/kernel/fork.c#L405)

```c
static int memcg_charge_kernel_stack(struct task_struct *tsk)
{
#ifdef CONFIG_VMAP_STACK
    struct vm_struct *vm = task_stack_vm_area(tsk);
    int ret;
​
    if (vm) {
        int i;
​
        for (i = 0; i < THREAD_SIZE / PAGE_SIZE; i++) {
            /*
             * If memcg_kmem_charge() fails, page->mem_cgroup
             * pointer is NULL, and both memcg_kmem_uncharge()
             * and mod_memcg_page_state() in free_thread_stack()
             * will ignore this page. So it's safe.
             */
            ret = memcg_kmem_charge(vm->pages[i], GFP_KERNEL, 0);
            if (ret)
                return ret;
​
            mod_memcg_page_state(vm->pages[i],
                         MEMCG_KERNEL_STACK_KB,
                         PAGE_SIZE / 1024);
        }
    }
#endif
    return 0;
}
```

## copy_creds

via：[https://elixir.bootlin.com/linux/v5.6.14/source/kernel/cred.c#L330](https://elixir.bootlin.com/linux/v5.6.14/source/kernel/cred.c#L330)

```c
/*
 * Copy credentials for the new process created by fork()
 *
 * We share if we can, but under some circumstances we have to generate a new
 * set.
 *
 * The new process gets the current process's subjective credentials as its
 * objective and subjective credentials
 */
int copy_creds(struct task_struct *p, unsigned long clone_flags)
{
    struct cred *new;
    int ret;
​
#ifdef CONFIG_KEYS_REQUEST_CACHE
    p->cached_requested_key = NULL;
#endif
​
    if (
#ifdef CONFIG_KEYS
        !p->cred->thread_keyring &&
#endif
        clone_flags & CLONE_THREAD
        ) {
        //设置 p 的 real cred 为 cred
        p->real_cred = get_cred(p->cred);
        get_cred(p->cred);
        alter_cred_subscribers(p->cred, 2);
        kdebug("share_creds(%p{%d,%d})",
               p->cred, atomic_read(&p->cred->usage),
               read_cred_subscribers(p->cred));
        // 原子性增加 p进程对应的 用户（其实是 ruid） 的进程数
        atomic_inc(&p->cred->user->processes);
        return 0;
    }
​
    // 官方注释：prepare_creds - Prepare a new set of credentials for modification
    // 详细分析见下面
    new = prepare_creds();
    if (!new)
        return -ENOMEM;
​
    // namespace 相关。要是指定用新用户的身份去启动子进程，就要修改 cred
    if (clone_flags & CLONE_NEWUSER) {
        // 
        ret = create_user_ns(new);
        if (ret < 0)
            goto error_put;
    }
​
#ifdef CONFIG_KEYS
    /* new threads get their own thread keyrings if their parent already
     * had one */
    if (new->thread_keyring) {
        key_put(new->thread_keyring);
        new->thread_keyring = NULL;
        if (clone_flags & CLONE_THREAD)
            install_thread_keyring_to_cred(new);
    }
​
    /* The process keyring is only shared between the threads in a process;
     * anything outside of those threads doesn't inherit.
     */
    if (!(clone_flags & CLONE_THREAD)) {
        key_put(new->process_keyring);
        new->process_keyring = NULL;
    }
#endif
​
    atomic_inc(&new->user->processes);
    p->cred = p->real_cred = get_cred(new);
    alter_cred_subscribers(new, 2);
    validate_creds(new);
    return 0;
​
error_put:
    put_cred(new);
    return ret;
}
```

## prepare_creds

via：[https://elixir.bootlin.com/linux/v5.6.14/source/kernel/cred.c#L250](https://elixir.bootlin.com/linux/latest/source/kernel/cred.c#L250)

```c
/**
 * prepare_creds - Prepare a new set of credentials for modification
 *
 * Prepare a new set of task credentials for modification.  A task's creds
 * shouldn't generally be modified directly, therefore this function is used to
 * prepare a new copy, which the caller then modifies and then commits by
 * calling commit_creds().
 *
 * Preparation involves making a copy of the objective creds for modification.
 *
 * Returns a pointer to the new creds-to-be if successful, NULL otherwise.
 *
 * Call commit_creds() or abort_creds() to clean up.
 */
struct cred *prepare_creds(void)
{
    //获取父进程的进程描述符指针（task_struct）
    struct task_struct *task = current;
    const struct cred *old;
    struct cred *new;
​
    validate_process_creds();
​
    // 分配内存
    new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
    if (!new)
        return NULL;
​
    kdebug("prepare_creds() alloc %p", new);
​
    // 保存父进程的 cred
    old = task->cred;
    // 直接把父进程的 cred 拷贝给子进程
    memcpy(new, old, sizeof(struct cred));
​
    new->non_rcu = 0;
    atomic_set(&new->usage, 1);
    set_cred_subscribers(new, 0);
    
   // get_group_info(new->group_info); 相当于 atomic_inc(&gi->usage);
    get_group_info(new->group_info);
    // refcount_inc(&u->__count);
    get_uid(new->user);
/*
static inline struct user_namespace *get_user_ns(struct user_namespace *ns)
{
    if (ns)
        atomic_inc(&ns->count);
    return ns;
}
namespace 相关
*/
    get_user_ns(new->user_ns);
​
#ifdef CONFIG_KEYS
    key_get(new->session_keyring);
    key_get(new->process_keyring);
    key_get(new->thread_keyring);
    key_get(new->request_key_auth);
#endif
​
#ifdef CONFIG_SECURITY
    new->security = NULL;
#endif
​
    if (security_prepare_creds(new, old, GFP_KERNEL_ACCOUNT) < 0)
        goto error;
    validate_creds(new);
    return new;
​
error:
    abort_creds(new);
    return NULL;
}
EXPORT_SYMBOL(prepare_creds);
```

## create_user_ns

via：[https://elixir.bootlin.com/linux/v5.6.14/source/kernel/user_namespace.c#L69](https://elixir.bootlin.com/linux/latest/source/kernel/user_namespace.c#L69)

```c
int create_user_ns(struct cred *new)
{
    // 取出父进程的 user_namespace
    struct user_namespace *ns, *parent_ns = new->user_ns;
    // euid 用于系统决定用户对系统资源的权限。也就是说当用户做任何一个操作时，最终看它有没有权限
    kuid_t owner = new->euid;
    kgid_t group = new->egid;
    struct ucounts *ucounts;
    int ret, i;
​
    ret = -ENOSPC;
    // user ns 是可以层级关系的，但是最高不允许超过 32 层
    if (parent_ns->level > 32)
        goto fail;
​
    ucounts = inc_user_namespaces(parent_ns, owner);
    if (!ucounts)
        goto fail;
​
    /*
     * Verify that we can not violate the policy of which files
     * may be accessed that is specified by the root directory,
     * by verifing that the root directory is at the root of the
     * mount namespace which allows all files to be accessed.
     */
    ret = -EPERM;
    // 判断是不是 chroot 环境
    if (current_chrooted())
        goto fail_dec;
​
    /* The creator needs a mapping in the parent user namespace
     * or else we won't be able to reasonably tell userspace who
     * created a user_namespace.
     */
    ret = -EPERM;
    // 检查映射
    /*
    via：https://elixir.bootlin.com/linux/v5.6.14/source/include/linux/uidgid.h#L179
    via：https://elixir.bootlin.com/linux/v5.6.14/source/include/linux/uidgid.h#L111
    
    return __kuid_val(uid) != (uid_t) -1;
    这里的 -1 就是表示不映射
    */
    if (!kuid_has_mapping(parent_ns, owner) ||
        !kgid_has_mapping(parent_ns, group))
        goto fail_dec;
​
    ret = -ENOMEM;
    ns = kmem_cache_zalloc(user_ns_cachep, GFP_KERNEL);
    if (!ns)
        goto fail_dec;
​
    ret = ns_alloc_inum(&ns->ns);
    if (ret)
        goto fail_free;
    ns->ns.ops = &userns_operations;
​
    atomic_set(&ns->count, 1);
    /* Leave the new->user_ns reference with the new user namespace. */
    // 把子进程的 namespce 的 parent 字段设置为父进程的 namespace
    ns->parent = parent_ns;
    ns->level = parent_ns->level + 1;
    ns->owner = owner;
    ns->group = group;
    INIT_WORK(&ns->work, free_user_ns);
    for (i = 0; i < UCOUNT_COUNTS; i++) {
        ns->ucount_max[i] = INT_MAX;
    }
    ns->ucounts = ucounts;
​
    /* Inherit USERNS_SETGROUPS_ALLOWED from our parent */
    mutex_lock(&userns_state_mutex);
    ns->flags = parent_ns->flags;
    mutex_unlock(&userns_state_mutex);
​
#ifdef CONFIG_KEYS
    INIT_LIST_HEAD(&ns->keyring_name_list);
    init_rwsem(&ns->keyring_sem);
#endif
    ret = -ENOMEM;
    if (!setup_userns_sysctls(ns))
        goto fail_keyring;
​
    // 设置 crediential ，就是所谓的 cap
/*
static void set_cred_user_ns(struct cred *cred, struct user_namespace *user_ns)
{
    // Start with the same capabilities as init but useless for doing
    // anything as the capabilities are bound to the new user namespace.
    // 设置和 init 一样的权限，但是由于这些功能已绑定到新的用户 namespace ，因此这些权限只在用户命名空间有效。
    cred->securebits = SECUREBITS_DEFAULT;
    cred->cap_inheritable = CAP_EMPTY_SET;
    cred->cap_permitted = CAP_FULL_SET;
    cred->cap_effective = CAP_FULL_SET;
    cred->cap_ambient = CAP_EMPTY_SET;
    cred->cap_bset = CAP_FULL_SET;
#ifdef CONFIG_KEYS
    key_put(cred->request_key_auth);
    cred->request_key_auth = NULL;
#endif
    // tgcred will be cleared in our caller bc CLONE_THREAD won't be set 
    cred->user_ns = user_ns;
}
*/
    set_cred_user_ns(new, ns);
    return 0;
fail_keyring:
#ifdef CONFIG_PERSISTENT_KEYRINGS
    key_put(ns->persistent_keyring_register);
#endif
    ns_free_inum(&ns->ns);
fail_free:
    kmem_cache_free(user_ns_cachep, ns);
fail_dec:
    dec_user_namespaces(ucounts);
fail:
    return ret;
}
```

## copy_files

复制父进程的 文件描述符

via：[https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L1449](https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L1449)

```c
static int copy_files(unsigned long clone_flags, struct task_struct *tsk)
{
	struct files_struct *oldf, *newf;
	int error = 0;
	/*
	 * A background process may not have any files ...
	 */
    // 获取父进程的 files 结构体指针
	oldf = current->files;
	if (!oldf)
		goto out;
	if (clone_flags & CLONE_FILES) {
		atomic_inc(&oldf->count);
		goto out;
	}
    // 直接用 dup_fd 复制
    // via：https://elixir.bootlin.com/linux/latest/source/fs/file.c#L272
	newf = dup_fd(oldf, &error);
	if (!newf)
		goto out;
    // 更新子进程的 files 为父进程的  files_struct 的副本
	tsk->files = newf;
	error = 0;
out:
	return error;
}
```

## copy_fs

via：[https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L1429](https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L1429)

```c
static int copy_fs(unsigned long clone_flags, struct task_struct *tsk)
{
	struct fs_struct *fs = current->fs;
	if (clone_flags & CLONE_FS) {
		/* tsk->fs is already what we want */
		spin_lock(&fs->lock);
		if (fs->in_exec) {
			spin_unlock(&fs->lock);
			return -EAGAIN;
		}
		fs->users++;
		spin_unlock(&fs->lock);
		return 0;
	}
	tsk->fs = copy_fs_struct(fs);
	if (!tsk->fs)
		return -ENOMEM;
	return 0;
}
```

### copy_fs_struct

copy_fs 的实际操作

```c
struct fs_struct *copy_fs_struct(struct fs_struct *old)
{
    // 分配内存
	struct fs_struct *fs = kmem_cache_alloc(fs_cachep, GFP_KERNEL);
	/* We don't need to lock fs - think why ;-) */
	if (fs) {
		fs->users = 1;
		fs->in_exec = 0;
		spin_lock_init(&fs->lock);
		seqcount_init(&fs->seq);
        // 复制父进程的 umask 
		fs->umask = old->umask;

		spin_lock(&old->lock);
        // 根目录
		fs->root = old->root;
		path_get(&fs->root);
        // 当前目录
		fs->pwd = old->pwd;
		path_get(&fs->pwd);
		spin_unlock(&old->lock);
	}
	return fs;
}
```



## copy_mm

via：[https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L1382](https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L1382)

```c
static int copy_mm(unsigned long clone_flags, struct task_struct *tsk)
{
	struct mm_struct *mm, *oldmm;
	int retval;
	tsk->min_flt = tsk->maj_flt = 0;
	tsk->nvcsw = tsk->nivcsw = 0;
#ifdef CONFIG_DETECT_HUNG_TASK
	tsk->last_switch_count = tsk->nvcsw + tsk->nivcsw;
	tsk->last_switch_time = 0;
#endif
	tsk->mm = NULL;
	tsk->active_mm = NULL;
	/*
	 * Are we cloning a kernel thread?
	 *
	 * We need to steal a active VM for that..
	 */
    // 获取父进程的 mm_struct（mm_struct 是用来描述进程的内存空间的）
	oldmm = current->mm;
	if (!oldmm)
		return 0;
	/* initialize the new vmacache entries */
	vmacache_flush(tsk);
    // 如果子进程与父进程运行于相同的内存空间
	if (clone_flags & CLONE_VM) {
		mmget(oldmm); // &oldmm->mm_users 增加 1
		mm = oldmm; // 直接让子进程的 mm_struct 指向父进程的 mm_struct
		goto good_mm;
	}
	retval = -ENOMEM;
    // 复制父进程 mm_struct 的内容
	mm = dup_mm(tsk, current->mm);
	if (!mm)
		goto fail_nomem;
good_mm:
	tsk->mm = mm;
	tsk->active_mm = mm;
	return 0;
fail_nomem:
	return retval;
}
```

### dup _mm

via：https://elixir.bootlin.com/linux/latest/source/kernel/fork.c#L1345

```c
static struct mm_struct *dup_mm(struct task_struct *tsk,
				struct mm_struct *oldmm)
{
	struct mm_struct *mm;
	int err;

	mm = allocate_mm();
	if (!mm)
		goto fail_nomem;

    // 拷贝父进程的 mm 的内容到 子进程（不同于 CLONE_VM）
	memcpy(mm, oldmm, sizeof(*mm));

    // 初始化 mm 的其他字段（我有点累暂时不看）
	if (!mm_init(mm, tsk, mm->user_ns))
		goto fail_nomem;

    // 拷贝父进程地址空间
	err = dup_mmap(mm, oldmm);
	if (err)
		goto free_pt;

	mm->hiwater_rss = get_mm_rss(mm);
	mm->hiwater_vm = mm->total_vm;

	if (mm->binfmt && !try_module_get(mm->binfmt->module))
		goto free_pt;

	return mm;

free_pt:
	/* don't put binfmt in mmput, we haven't got module yet */
	mm->binfmt = NULL;
	mm_init_owner(mm, NULL);
	mmput(mm);

fail_nomem:
	return NULL;
}
```

#### dup_mmap

拷贝父进程地址空间

via：https://elixir.bootlin.com/linux/latest/source/kernel/fork.c#L481

```c
static __latent_entropy int dup_mmap(struct mm_struct *mm,
					struct mm_struct *oldmm)
{
	struct vm_area_struct *mpnt, *tmp, *prev, **pprev;
	struct rb_node **rb_link, *rb_parent;
	int retval;
	unsigned long charge;
	LIST_HEAD(uf);

	uprobe_start_dup_mmap();
    // 获取 线性区 的信号量
	if (down_write_killable(&oldmm->mmap_sem)) {
		retval = -EINTR;
		goto fail_uprobe_end;
	}
	flush_cache_dup_mm(oldmm);
	uprobe_dup_mmap(oldmm, mm);
	/*
	 * Not linked in yet - no deadlock potential:
	 */
	down_write_nested(&mm->mmap_sem, SINGLE_DEPTH_NESTING);

	/* No ordering required: file already has been exposed. */
	RCU_INIT_POINTER(mm->exe_file, get_mm_exe_file(oldmm));

	mm->total_vm = oldmm->total_vm; // 复制父进程的进程地址空间的的页数
	mm->data_vm = oldmm->data_vm;
	mm->exec_vm = oldmm->exec_vm; // 复制父进程的可执行内存映射中的页数
	mm->stack_vm = oldmm->stack_vm;// 复制父进程的用户态栈堆中的页数

    // 红黑树。。。。
    // rblink 存的是 VMA 的根节点
	rb_link = &mm->mm_rb.rb_node;
	rb_parent = NULL;
	pprev = &mm->mmap;
	retval = ksm_fork(mm, oldmm);
	if (retval)
		goto out;
	retval = khugepaged_fork(mm, oldmm);
	if (retval)
		goto out;

	prev = NULL;
    // 遍历父进程的 VMA
	for (mpnt = oldmm->mmap; mpnt; mpnt = mpnt->vm_next) {
		struct file *file;

        // VM_DONTCOPY 在 fork 系统调用执行时不复制
		if (mpnt->vm_flags & VM_DONTCOPY) {
            // 见下面
			vm_stat_account(mm, mpnt->vm_flags, -vma_pages(mpnt));
			continue;
		}
		charge = 0;
		/*
		 * Don't duplicate many vmas if we've been oom-killed (for
		 * example)
		 */
		if (fatal_signal_pending(current)) {
			retval = -EINTR;
			goto out;
		}
        // VM_ACCOUNT
		if (mpnt->vm_flags & VM_ACCOUNT) {
			unsigned long len = vma_pages(mpnt);

			if (security_vm_enough_memory_mm(oldmm, len)) /* sic */
				goto fail_nomem;
			charge = len;
		}
		tmp = vm_area_dup(mpnt);
		if (!tmp)
			goto fail_nomem;
		retval = vma_dup_policy(mpnt, tmp);
		if (retval)
			goto fail_nomem_policy;
		tmp->vm_mm = mm;
		retval = dup_userfaultfd(tmp, &uf);
		if (retval)
			goto fail_nomem_anon_vma_fork;
		if (tmp->vm_flags & VM_WIPEONFORK) {
			/* VM_WIPEONFORK gets a clean slate in the child. */
			tmp->anon_vma = NULL;
			if (anon_vma_prepare(tmp))
				goto fail_nomem_anon_vma_fork;
		} else if (anon_vma_fork(tmp, mpnt))
			goto fail_nomem_anon_vma_fork;
		tmp->vm_flags &= ~(VM_LOCKED | VM_LOCKONFAULT);
		tmp->vm_next = tmp->vm_prev = NULL;
		file = tmp->vm_file;
		if (file) {
			struct inode *inode = file_inode(file);
			struct address_space *mapping = file->f_mapping;

			get_file(file);
			if (tmp->vm_flags & VM_DENYWRITE)
				atomic_dec(&inode->i_writecount);
			i_mmap_lock_write(mapping);
			if (tmp->vm_flags & VM_SHARED)
				atomic_inc(&mapping->i_mmap_writable);
			flush_dcache_mmap_lock(mapping);
			/* insert tmp into the share list, just after mpnt */
			vma_interval_tree_insert_after(tmp, mpnt,
					&mapping->i_mmap);
			flush_dcache_mmap_unlock(mapping);
			i_mmap_unlock_write(mapping);
		}

		/*
		 * Clear hugetlb-related page reserves for children. This only
		 * affects MAP_PRIVATE mappings. Faults generated by the child
		 * are not guaranteed to succeed, even if read-only
		 */
		if (is_vm_hugetlb_page(tmp))
			reset_vma_resv_huge_pages(tmp);

		/*
		 * Link in the new vma and copy the page table entries.
		 */
		*pprev = tmp;
		pprev = &tmp->vm_next;
		tmp->vm_prev = prev;
		prev = tmp;

		__vma_link_rb(mm, tmp, rb_link, rb_parent);
		rb_link = &tmp->vm_rb.rb_right;
		rb_parent = &tmp->vm_rb;

        // 在 copy_page_range 里面就是 fork 写时复制（COW）
		mm->map_count++;
		if (!(tmp->vm_flags & VM_WIPEONFORK))
			retval = copy_page_range(mm, oldmm, mpnt);

		if (tmp->vm_ops && tmp->vm_ops->open)
			tmp->vm_ops->open(tmp);

		if (retval)
			goto out;
	}
	/* a new mm has just been created */
	retval = arch_dup_mmap(oldmm, mm);
out:
	up_write(&mm->mmap_sem);
	flush_tlb_mm(oldmm);
	up_write(&oldmm->mmap_sem);
	dup_userfaultfd_complete(&uf);
fail_uprobe_end:
	uprobe_end_dup_mmap();
	return retval;
fail_nomem_anon_vma_fork:
	mpol_put(vma_policy(tmp));
fail_nomem_policy:
	vm_area_free(tmp);
fail_nomem:
	retval = -ENOMEM;
	vm_unacct_memory(charge);
	goto out;
}
```

##### vm_stat_account

via：https://elixir.bootlin.com/linux/latest/source/mm/mmap.c#L3287

```c
void vm_stat_account(struct mm_struct *mm, vm_flags_t flags, long npages)
{
	mm->total_vm += npages;

    // return (flags & (VM_EXEC | VM_WRITE | VM_STACK)) == VM_EXEC;
	if (is_exec_mapping(flags))
		mm->exec_vm += npages;
    // return (flags & VM_STACK) == VM_STACK;
	else if (is_stack_mapping(flags))
		mm->stack_vm += npages;
    // return (flags & (VM_WRITE | VM_SHARED | VM_STACK)) == VM_WRITE;
	else if (is_data_mapping(flags))
		mm->data_vm += npages;
}
```

##### copy_page_range

fork 的写时复制的核心

```c
int copy_page_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		struct vm_area_struct *vma)
{
	pgd_t *src_pgd, *dst_pgd;
	unsigned long next;
    // 获得 vma 的起始地址和 结束地址
	unsigned long addr = vma->vm_start;
	unsigned long end = vma->vm_end;
	struct mmu_notifier_range range;
	bool is_cow;
	int ret;

	/*
	 * Don't copy ptes where a page fault will fill them correctly.
	 * Fork becomes much lighter when there are big shared or private
	 * readonly mappings. The tradeoff is that copy_page_range is more
	 * efficient than faulting.
	 */
    /*
    VM_HUGETLB 巨型页
    VM_PFNMAP  Page-ranges 管理没有 struct page，只有 PFN pages
    VM_MIXEDMAP 可以包含 struct page 和 PFN pages
    */
	if (!(vma->vm_flags & (VM_HUGETLB | VM_PFNMAP | VM_MIXEDMAP)) &&
			!vma->anon_vma)
		return 0;

    // return !!(vma->vm_flags & VM_HUGETLB);
	if (is_vm_hugetlb_page(vma))
		return copy_hugetlb_page_range(dst_mm, src_mm, vma);

	if (unlikely(vma->vm_flags & VM_PFNMAP)) {
		/*
		 * We do not free on error cases below as remove_vma
		 * gets called on error from higher level routine
		 */
		ret = track_pfn_copy(vma);
		if (ret)
			return ret;
	}

	/*
	 * We need to invalidate the secondary MMU mappings only when
	 * there could be a permission downgrade on the ptes of the
	 * parent mm. And a permission downgrade will only happen if
	 * is_cow_mapping() returns true.
	 */
  
  /* return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
     VM_MAYWRITE 允许设置VM_WRITE标志
     VM_WRITE 可以写入页面
  */
	is_cow = is_cow_mapping(vma->vm_flags);

	if (is_cow) {
		mmu_notifier_range_init(&range, MMU_NOTIFY_PROTECTION_PAGE,
					0, vma, src_mm, addr, end);
		mmu_notifier_invalidate_range_start(&range);
	}

	ret = 0;
	dst_pgd = pgd_offset(dst_mm, addr);
	src_pgd = pgd_offset(src_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(src_pgd))
			continue;
		if (unlikely(copy_p4d_range(dst_mm, src_mm, dst_pgd, src_pgd,
					    vma, addr, next))) {
			ret = -ENOMEM;
			break;
		}
	} while (dst_pgd++, src_pgd++, addr = next, addr != end);

	if (is_cow)
		mmu_notifier_invalidate_range_end(&range);
	return ret;
}
```



## copy_namespaces

via：[https://elixir.bootlin.com/linux/v5.6.14/source/kernel/nsproxy.c#L149](https://elixir.bootlin.com/linux/v5.6.14/source/kernel/nsproxy.c#L149)

```c
/*
 * called from clone.  This now handles copy for nsproxy and all
 * namespaces therein.
 */
int copy_namespaces(unsigned long flags, struct task_struct *tsk)
{
	struct nsproxy *old_ns = tsk->nsproxy;
	struct user_namespace *user_ns = task_cred_xxx(tsk, user_ns);
	struct nsproxy *new_ns;
	int ret;
	if (likely(!(flags & (CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
			      CLONE_NEWPID | CLONE_NEWNET |
			      CLONE_NEWCGROUP | CLONE_NEWTIME)))) {
		if (likely(old_ns->time_ns_for_children == old_ns->time_ns)) {
			get_nsproxy(old_ns);
			return 0;
		}
	} else if (!ns_capable(user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	/*
	 * CLONE_NEWIPC must detach from the undolist: after switching
	 * to a new ipc namespace, the semaphore arrays from the old
	 * namespace are unreachable.  In clone parlance, CLONE_SYSVSEM
	 * means share undolist with parent, so we must forbid using
	 * it along with CLONE_NEWIPC.
	 */
	if ((flags & (CLONE_NEWIPC | CLONE_SYSVSEM)) ==
		(CLONE_NEWIPC | CLONE_SYSVSEM)) 
		return -EINVAL;
	new_ns = create_new_namespaces(flags, tsk, user_ns, tsk->fs);
	if (IS_ERR(new_ns))
		return  PTR_ERR(new_ns);
	ret = timens_on_fork(new_ns, tsk);
	if (ret) {
		free_nsproxy(new_ns);
		return ret;
	}
	tsk->nsproxy = new_ns;
	return 0;
}
```

## 

## copy_io

via：[https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L1476](https://elixir.bootlin.com/linux/v5.6.14/source/kernel/fork.c#L1476)

```c
static int copy_io(unsigned long clone_flags, struct task_struct *tsk)
{
#ifdef CONFIG_BLOCK
	struct io_context *ioc = current->io_context;
	struct io_context *new_ioc;
	if (!ioc)
		return 0;
	/*
	 * Share io context with parent, if CLONE_IO is set
	 */
	if (clone_flags & CLONE_IO) {
		ioc_task_link(ioc);
		tsk->io_context = ioc;
	} else if (ioprio_valid(ioc->ioprio)) {
		new_ioc = get_task_io_context(tsk, GFP_KERNEL, NUMA_NO_NODE);
		if (unlikely(!new_ioc))
			return -ENOMEM;
		new_ioc->ioprio = ioc->ioprio;
		put_io_context(new_ioc);
	}
#endif
	return 0;
}
```

## copy_thread_tls

via：[https://elixir.bootlin.com/linux/v5.6.14/source/arch/x86/kernel/process.c#L125](https://elixir.bootlin.com/linux/v5.6.14/source/arch/x86/kernel/process.c#L125)

```c
nt copy_thread_tls(unsigned long clone_flags, unsigned long sp,
		    unsigned long arg, struct task_struct *p, unsigned long tls)
{
	struct inactive_task_frame *frame;
	struct fork_frame *fork_frame;
	struct pt_regs *childregs;
	int ret = 0;
	childregs = task_pt_regs(p);
	fork_frame = container_of(childregs, struct fork_frame, regs);
	frame = &fork_frame->frame;
	frame->bp = 0;
	frame->ret_addr = (unsigned long) ret_from_fork;
	p->thread.sp = (unsigned long) fork_frame;
	p->thread.io_bitmap = NULL;
	memset(p->thread.ptrace_bps, 0, sizeof(p->thread.ptrace_bps));
#ifdef CONFIG_X86_64
	savesegment(gs, p->thread.gsindex);
	p->thread.gsbase = p->thread.gsindex ? 0 : current->thread.gsbase;
	savesegment(fs, p->thread.fsindex);
	p->thread.fsbase = p->thread.fsindex ? 0 : current->thread.fsbase;
	savesegment(es, p->thread.es);
	savesegment(ds, p->thread.ds);
#else
	p->thread.sp0 = (unsigned long) (childregs + 1);
	/*
	 * Clear all status flags including IF and set fixed bit. 64bit
	 * does not have this initialization as the frame does not contain
	 * flags. The flags consistency (especially vs. AC) is there
	 * ensured via objtool, which lacks 32bit support.
	 */
	frame->flags = X86_EFLAGS_FIXED;
#endif
	/* Kernel thread ? */
	if (unlikely(p->flags & PF_KTHREAD)) {
		memset(childregs, 0, sizeof(struct pt_regs));
		kthread_frame_init(frame, sp, arg);
		return 0;
	}
	frame->bx = 0;
	*childregs = *current_pt_regs();
	childregs->ax = 0;
	if (sp)
		childregs->sp = sp;
#ifdef CONFIG_X86_32
	task_user_gs(p) = get_user_gs(current_pt_regs());
#endif
	/* Set a new TLS for the child thread? */
	if (clone_flags & CLONE_SETTLS)
		ret = set_new_tls(p, tls);
	if (!ret && unlikely(test_tsk_thread_flag(current, TIF_IO_BITMAP)))
		io_bitmap_share(p);
	return ret;
}
```

## 参考资料

via：[https://www.cnblogs.com/qiuheng/p/5749366.html](https://www.cnblogs.com/qiuheng/p/5749366.html)

via：[https://www.jianshu.com/p/3035f2be3ef0](https://www.jianshu.com/p/3035f2be3ef0)

via：[https://www.cnblogs.com/nufangrensheng/p/3509262.html](https://www.cnblogs.com/nufangrensheng/p/3509262.html)

via：[https://www.ibm.com/developerworks/cn/linux/l-cn-cncrrc-mngd-wkq/](https://www.ibm.com/developerworks/cn/linux/l-cn-cncrrc-mngd-wkq/)

via：[https://www.jianshu.com/p/691d02380312](https://www.jianshu.com/p/691d02380312)

via：https://www.cnblogs.com/wanghetao/archive/2011/11/06/2237931.html

via：https://www.cnblogs.com/holyxp/p/10016582.html