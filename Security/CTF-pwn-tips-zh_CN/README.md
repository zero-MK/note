CTF-pwn-tips-zh_CN
===========================

原项目：https://github.com/Naetw/CTF-pwn-tips


# 目录
* [缓冲区溢出](#缓冲区溢出)
* [在 gdb 中查找字符串](#在gdb中查找字符串)
* [让程序运行在指定端口上](#让程序运行在指定端口上)
* [在 libc 中查找特定的函数偏移量](#在libc中查找特定的函数偏移量)
* [在共享库里面查找/bin/sh或者sh字符串](#在共享库里面查找/bin/sh或者sh字符串)
* [泄露栈地址](#泄露栈地址)
* [gdb 中 fork 跟踪调试的问题](#gdb中fork跟踪调试的问题)
* [.tls 段的秘密](#.tls段的秘密)
* [可预测的随机数发生器 -- RNG(Random Number Generator)](#可预测的随机数发生器))
* [使栈可执行](#使栈可执行)
* [使用 one-gadget-RCE 代替 system](#使用one-gadget-RCE代替system)
* [劫持钩子函数](#劫持钩子函数)
* [使用 printf 触发 malloc 和 free](#使用printf触发malloc和free)
* [使用 execveat 打开一个 shell](#使用execveat打开一个shell)


## 缓冲区溢出

现在有

一个 `buffer` ： `char buf[40]` 

一个无符号整形变量 `num` ： `signed int num`

### scanf

* `scanf("%s", buf)`
    * `%s` 没有进行边界检查
    * **pwnable**

* `scanf("%39s", buf)`
    * `%39s` 只从标准输入获取 `39` 个字节的数据，并将 `NULL` 放在输入数据的结尾
    * **useless**

* `scanf("%40s", buf)`
    * 乍一看好像没有什么问题
    * 从标准输入获取 `40` 个字节的数据，并将 `NULL` 放在输入数据的结尾
    * 因为 `buf` 只有 `40 Bytes` 的空间，输入数据加上 `NULL`溢出了一个字节（**one-byte-overflow**）
    * **pwnable**

* `scanf("%d", &num)`
    * 输入的 `num` 用做 `alloca` 的参数 `alloca(num)`
        * `alloca` 是从调用者的栈上分配内存，相当于 `sub esp, eax` 
        * 如果我们输入的是一个负数，就会发生栈帧重叠
        * E.g. [Seccon CTF quals 2016 cheer_msg](https://github.com/ctfs/write-ups-2016/tree/master/seccon-ctf-quals-2016/exploit/cheer-msg-100)
    * 利用 `num` 访问一些数据结构
        * 很多时候程序员写检查的时候只进行了高边界的检查，而没有检查低边界，然后 `num` 又是无符号类型
        * 将 `num` 设置成负数会发生整数溢出，`num` 会变得非常大，这样我们就能覆盖到一些重要的数据

### gets

* `gets(buf)`
    * 没有进行边界检查
    * **pwnable**

* `fgets(buf, 40, stdin)`
    * 从标准输入获取 `39` 个字节的数据，并将 `NULL` 放在输入数据的结尾
    * **useless**

### read

* `read(stdin, buf, 40)`
    * 从标准输入获取 `40` 个字节的数据，但是不会把 `NULL` 放在输入数据的结尾
    * 看起来安全，但是可能会发生信息泄露（**information leak**）
    * **leakable**

E.g.

**内存布局**

```
0x7fffffffdd00: 0x4141414141414141      0x4141414141414141
0x7fffffffdd10: 0x4141414141414141      0x4141414141414141
0x7fffffffdd20: 0x4141414141414141      0x00007fffffffe1cd
```

* 如果使用 `printf` 或者 `puts` 输出 `buf` ，这两个函数会一直读取内存上的东西直到遇到 
    `NULL`
* 在这里我们能输出 `'A'*40 + '\xcd\xe1\xff\xff\xff\x7f'`

* `fread(buf, 1, 40, stdin)`
    * 和  `read` 几乎一样
    * **leakable**

### strcpy

假设有一个 buffer: `char buf2[60]`

* `strcpy(buf, buf2)`
    * 没有进行边界检查
    * 它会将 `buf2`的内容复制到 `buf` (直到遇到 NULL byte)  这时 `length(buf2) > length(buf)`
    * 因为 `length(buf2) > length(buf)` 所以 `buf` 发生溢出
    * **pwnable**

* `strncpy(buf, buf2, 40)` && `memcpy(buf, buf2, 40)`
    * 从 `buf2` 复制 `40 Bytes` 的数据到 `buf`，但是结尾没有添加 `NULL`
    * 由于没有 `NULL` 标志字符串结束，所以跟上面的一样会发生信息泄露
    * **leakable**

### strcat

假设有另一个 `buffer`：`char buf2[60]`

* `strcat(buf, buf2)`
    * 在  `buf` 没有足够大的空间的时候会有 **缓冲区溢出** 漏洞
    * 它会将 `NULL` 添加到末尾，可能会导致 **单字节溢出**
    * 在某些情况下，我们可以使用这个 `NULL` 来更改栈地址或堆地址
    * **pwnable**

* `strncat(buf, buf2, n)`
    * 功能跟 `strcat` 一样，但是会有长度限制（参数 `n`）
    * **pwnable**
    * E.g. [Seccon CTF quals 2016 jmper](https://github.com/ctfs/write-ups-2016/tree/master/seccon-ctf-quals-2016/exploit/jmper-300)


## 在gdb中查找字符串

在有[SSP](http://j00ru.vexillium.org/blog/24_03_15/dragons_ctf.pdf) （Stack-smashing Protection） 的情况下 , 我们需要找出 `argv[0]` 和输入缓冲区的偏移量

### gdb

* `argv[0]`位于 `environ的地址 - 0x10` 的地方，在 `gdb` 里面可以使用 `p/x ((char **)environ)` 查看环境变量 `environ` 的地址

E.g.

```
(gdb) p/x (char **)environ
$9 = 0x7fffffffde38
(gdb) x/gx 0x7fffffffde38-0x10
0x7fffffffde28: 0x00007fffffffe1cd
(gdb) x/s 0x00007fffffffe1cd
0x7fffffffe1cd: "/home/naetw/CTF/seccon2016/check/checker"
```

### [gdb peda](https://github.com/longld/peda)

* 使用 `searchmem "/home/naetw/CTF/seccon2016/check/checker"` 搜索内存中 `/home/naetw/CTF/seccon2016/check/checker` 字符串的地址
* 然后 `searchmem $result_address`

```
gdb-peda$ searchmem "/home/naetw/CTF/seccon2016/check/checker"
Searching for '/home/naetw/CTF/seccon2016/check/checker' in: None ranges
Found 3 results, display max 3 items:
[stack] : 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffed7c ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffefcf ("/home/naetw/CTF/seccon2016/check/checker")
gdb-peda$ searchmem 0x7fffffffe1cd
Searching for '0x7fffffffe1cd' in: None ranges
Found 2 results, display max 2 items:
   libc : 0x7ffff7dd33b8 --> 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
[stack] : 0x7fffffffde28 --> 0x7fffffffe1cd ("/home/naetw/CTF/seccon2016/check/checker")
```

## 让程序运行在指定端口上

一般情况下：

* `ncat -vc ./binary -kl 127.0.0.1 $port`

下面这两个方式是指定了 `binary` 运行时使用的库：

* `ncat -vc 'LD_PRELOAD=/path/to/libc.so ./binary' -kl 127.0.0.1 $port`
* `ncat -vc 'LD_LIBRARY_PATH=/path/of/libc.so ./binary' -kl 127.0.0.1 $port`

  然后你就可以使用 `nc` 连接到 `binary` 所运行的端口和它进行交互： `nc localhost $port`.

## 在libc中查找特定的函数偏移量

如果我们成功泄漏出了某些函数的 `libc` 地址，我们就可以通过减去该函数在 `libc` 里面的偏移量来获取 `libc` 基址

### 手动

* `readelf -s $libc | grep ${function}@`

E.g.

```
$ readelf -s libc-2.19.so | grep system@
    620: 00040310    56 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
   1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
```

### 自动

* 使用 [pwntools](https://github.com/Gallopsled/pwntools)

```python
from pwn import *

libc = ELF('libc.so')
system_off = libc.symbols['system']
```

## 在共享库里面查找/bin/sh或者sh字符串

需要先获得 `libc` 的基地址

### 手动

* `objdump -s libc.so | less`  然后搜索 'sh'
* `strings -tx libc.so | grep /bin/sh`

### 自动

* 使用 [pwntools](https://github.com/Gallopsled/pwntools)

E.g.

```python
from pwn import *

libc = ELF('libc.so')
...
sh = base + next(libc.search('sh\x00'))
binsh = base + next(libc.search('/bin/sh\x00'))
```

## 泄露栈地址

**制约因素**：

* 已经泄露出 `libc` 的基地址
* 可以泄漏任意地址的内容

There is a symbol `environ` in libc, whose value is the same as the third argument of `main` function, `char **envp`.
The value of `char **envp` is on the stack, thus we can leak stack address with this symbol.

`libc` 中有一个叫 `environ` 的 `symbol` ，他的值与 `main` 函数的第三个参数 `char ** envp` 相同。

`char ** envp` 的值在 栈 上，因此我们可以通过泄露这个 `symbol` 的地址来泄漏堆栈地址

```
(gdb) list 1
1       #include <stdlib.h>
2       #include <stdio.h>
3
4       extern char **environ;
5
6       int main(int argc, char **argv, char **envp)
7       {
8           return 0;
9       }
(gdb) x/gx 0x7ffff7a0e000 + 0x3c5f38
0x7ffff7dd3f38 <environ>:       0x00007fffffffe230
(gdb) p/x (char **)envp
$12 = 0x7fffffffe230
```

* `0x7ffff7a0e000` 是当前 `libc` 的基地址
* `0x3c5f38` 是 `environ` 在 `libc` 里面的偏移量

这个 [手册](https://www.gnu.org/software/libc/manual/html_node/Program-Arguments.html) 详细的描述了 `environ`

## gdb中fork跟踪调试的问题

当你使用 **gdb** 调试带有 `fork()` 函数的可执行文件时，您可以使用下面列出的命令来确定要跟踪哪个进程（`gdb` 的默认设置是跟踪父进程，`gdb-peda` 的默认设置是跟踪子进程）：

* `set follow-fork-mode parent`
* `set follow-fork-mode child`

另外，我们可以通过 `set detach-on-fork off` 命令同时调试父进程和子进程，通过 `inferior X` 切换跟踪调试进程， `X` 可以是 `info inferiors` 得到的任意数字（每个数字代表着一个进程）。 如果 `fork` 得出的两个进程都需要跟踪获取信息，上面的只跟踪任意一个进程是达不到目的的，同时跟踪两个进程还是很有用的（像是演示子进程的 `canary` 是和父进程一样的时候）

## .tls段的秘密

**约制因素**:

* 需要有 `malloc` 函数并且要能分配任意大小的内存
* 可以泄露任意地址的内容

我们使用 `malloc` 的 `mmap`（默认情况下，当 `malloc` 或者 `new` 操作一次性分配大于等于 `128KB` 的内存时，会使用 `mmap` 来进行，而在小于 `128KB` 时，使用的是 `brk` 的方式）方式来分配内存（ `0x21000` 大小就足够了）。一般来说，这些页面将放在 `.tls` 段之前的地址。

 通常会有一些有用的东西会放在 **`.tls`** 段， 像是主分配区（`main_arena`） 的地址， `canary` （栈保护值） ，还有一个奇怪的栈地址（`stack address`），它指向栈上的某个地方，每次运行可能不一样，但它具有固定的偏移量。

**在 mmap 之前:**

```
7fecbfe4d000-7fecbfe51000 r--p 001bd000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe51000-7fecbfe53000 rw-p 001c1000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe53000-7fecbfe57000 rw-p 00000000 00:00 0
7fecbfe57000-7fecbfe7c000 r-xp 00000000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc0068000-7fecc006a000 rw-p 00000000 00:00 0              <- .tls section
7fecc0078000-7fecc007b000 rw-p 00000000 00:00 0
7fecc007b000-7fecc007c000 r--p 00024000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc007c000-7fecc007d000 rw-p 00025000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
```

**在 mmap 之后:**

```
7fecbfe4d000-7fecbfe51000 r--p 001bd000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe51000-7fecbfe53000 rw-p 001c1000 fd:00 131210         /lib/x86_64-linux-gnu/libc-2.24.so
7fecbfe53000-7fecbfe57000 rw-p 00000000 00:00 0
7fecbfe57000-7fecbfe7c000 r-xp 00000000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc0045000-7fecc006a000 rw-p 00000000 00:00 0              <- memory of mmap + .tls section
7fecc0078000-7fecc007b000 rw-p 00000000 00:00 0
7fecc007b000-7fecc007c000 r--p 00024000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
7fecc007c000-7fecc007d000 rw-p 00025000 fd:00 131206         /lib/x86_64-linux-gnu/ld-2.24.so
```

## 可预测的随机数发生器

当二进制文件使用随机数生成器（RNG） 的生成的伪随机数作为重要信息的地址时，如果它是可预测的，我们可以猜测出相同的值。

假设它是可预测的，我们可以使用 [ctypes](https://docs.python.org/2/library/ctypes.html) 模块（`Python` 内置模块）

**ctypes** 可以让我们用 `python` 调用 DLL(Dynamic-Link Library 动态链接库) 或者 共享库（`Shared Library`）里的函数

如果有一个 `init_proc` 函数 :

```c
srand(time(NULL));
while(addr <= 0x10000){
    addr = rand() & 0xfffff000;
}
secret = mmap(addr,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS ,-1,0);
if(secret == -1){
    puts("mmap error");
    exit(0);
}
```

我们可以使用 **ctypes** 来获得相同的 `addr`

```python
import ctypes
LIBC = ctypes.cdll.LoadLibrary('/path/to/dll')
LIBC.srand(LIBC.time(0))
addr = LIBC.rand() & 0xfffff000
```

## 使栈可执行

* [link1](http://radare.today/posts/defeating-baby_rop-with-radare2/)
* [link2](https://sploitfun.wordpress.com/author/sploitfun/)
* Haven't read yet orz

## 使用one-gadget-RCE代替system

**约制条件**:

* 有 `libc` 的基地址
* 任意地址写

几乎所有的 `pwnable` 挑战都要执行 `system('/bin/sh')` ，如果我们想执行  `system('/bin/sh')`， 需要能控制函数参数并且能劫持程序执行流程调用 `system` 函数。如果我们不能控制参数该怎么办

使用 [one-gadget-RCE](http://j00ru.vexillium.org/blog/24_03_15/dragons_ctf.pdf) 技术!

有了 **one-gadget-RCE**，我们就能劫持 `.got.plt`或者我们可以用来控制 `eip` 让程序跳到 **one-gadget** 上执行，但是在使用它之前需要满足一些约束条件。

`libc` 里面有很多 **one-gadgets** 。每种方法都有不同的约束条件，但这些约束条件是相似的。每个约束都与寄存器的状态有关。

E.g.

* ebx 存的是 `libc` 的 `rw-p` 区的地址
* [esp+0x34] == NULL

我们怎样才能满足这些限制？这里有一个有用的工具： [one_gadget](https://github.com/david942j/one_gadget) !!!!

如果我们能满足这些限制，我们就可以更容易地得到一个 `shell`

## 劫持钩子函数

**约制条件**:

* 有 `libc` 基地址
* 任意地址写
* 程序有用到 `malloc`，`free` 或 `realloc`函数

By manual:

> GNU C Library （glibc）允许您通过指定适当的钩子函数来修改 `malloc`、`realloc` 和 `free` 的行为。 例如，可以使用这些钩子函数来协助调试 使用动态内存分配的程序。

在 `malloc.h` 中声明了钩子变量，它们的默认值为 `0x0`

* `__malloc_hook`
* `__free_hook`
* ...

因为它们是用来帮助我们调试程序的，所以它们在执行过程中是可写的。

```
0xf77228e0 <__free_hook>:       0x00000000
0xf7722000 0xf7727000 rw-p      mapped
```

我们可以看看 [malloc.c 的源码](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#2917)。 我会用 `__libc_free` 来做演示

```c
void (*hook) (void *, const void *) = atomic_forced_read (__free_hook);
if (__builtin_expect (hook != NULL, 0))
{
    (*hook)(mem, RETURN_ADDRESS (0));
    return;
}
```

这段代码会检查 `__free_hook`。如果它不为 `NULL`，它将优先调用钩子函数。在这里我们可以使用 **one-gadget-RCE**。由于钩子函数是在 `libc` 中调用的， 所以通常满足 **one-gadget** 的约束条件。

## 使用printf触发malloc和free

来看看 `printf` 的源码，有几个地方可能会触发 `malloc` 。 以 [vfprintf.c 的第 1470 行](https://code.woboq.org/userspace/glibc/stdio-common/vfprintf.c.html#1470) 为例：

```c
#define EXTSIZ 32
enum { WORK_BUFFER_SIZE = 1000 };

if (width >= WORK_BUFFER_SIZE - EXTSIZ)
{
    /* We have to use a special buffer.  */
    size_t needed = ((size_t) width + EXTSIZ) * sizeof (CHAR_T);
    if (__libc_use_alloca (needed))
        workend = (CHAR_T *) alloca (needed) + width + EXTSIZ;
    else
    {
        workstart = (CHAR_T *) malloc (needed);
        if (workstart == NULL)
        {
            done = -1;
            goto all_done;
        }
        workend = workstart + width + EXTSIZ;
    }
}
```

我们可以发现，如果 `width` 变量够大的时候将会触发 `malloc`（当然，如果触发了 `malloc`，`printf` 末尾也会触发 `free`）。然而，因为 `WORK_BUFFER_SIZE` 不够大，所以程序会跳到  **else**  代码块去执行。 让我们看看 `__libc_use_alloca` 来决定我们应该给出的最小的 `width`。

```c

/* Minimum size for a thread.  We are free to choose a reasonable value.  */
#define PTHREAD_STACK_MIN        16384

#define __MAX_ALLOCA_CUTOFF        65536

int __libc_use_alloca (size_t size)
{
    return (__builtin_expect (size <= PTHREAD_STACK_MIN / 4, 1)
        || __builtin_expect (__libc_alloca_cutoff (size), 1));
}

int __libc_alloca_cutoff (size_t size)
{
	return size <= (MIN (__MAX_ALLOCA_CUTOFF,
					THREAD_GETMEM (THREAD_SELF, stackblock_size) / 4
					/* The main thread, before the thread library is
						initialized, has zero in the stackblock_size
						element.  Since it is the main thread we can
						assume the maximum available stack space.  */
					?: __MAX_ALLOCA_CUTOFF * 4));
}
```

我们必须确保：

1. `size > PTHREAD_STACK_MIN / 4`
2. `size > MIN(__MAX_ALLOCA_CUTOFF, THREAD_GETMEM(THREAD_SELF, stackblock_size) / 4 ?: __MAX_ALLOCA_CUTOFF * 4)`
    * 我不完全理解 `THREAD_GETMEM` 到底是做什么的，但它似乎大多时候返回 0。
    * 因此，第二个条件通常是 `size > 65536`

More details:

* [__builtin_expect](https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html)
* [THREAD_GETMEM](https://code.woboq.org/userspace/glibc/sysdeps/x86_64/nptl/tls.h.html#_M/THREAD_GETMEM)


### 总结

* 大多数时候，触发 `malloc` 和 `free` 的最小 `width` 是 `65537`。
* 如果存在格式字符串漏洞，并且程序在调用 `printf(buf)` 后立即结束，我们可以使用 `one-gadget` 劫持 `__malloc_hook` 或 `__free_hook` 并使用上述技巧触发 `malloc` 和 `free`，那么即使在 `printf(buf)` 后面没有任何函数调用或其他东西，我们仍然可以获得 `shell`（这里的意思是，即使调用 `printf` 结束后程序直接退出，我们还是能做到程序执行流程劫持，因为我们劫持了 `__malloc_hook` 或 `__free_hook` ，在触发  `malloc` 和 `free` 的时候我们已经执行了我们想要的操作）



## 使用execveat打开一个shell

提到使用系统调用去开一个 `shell` 时我们的脑子中想到的会是 `execve` ，然而，由于缺少 `gadget` 或其他限制，执行起来总是很艰难

实际上，有一个系统调用 `execveat`，其原型如下：

```c
int execveat(int dirfd, const char *pathname,
             char *const argv[], char *const envp[],
             int flags);
```

根据它在 [man 手册](http://man7.org/linux/man-pages/man2/execveat.2.html) 中的描述，可以发现其操作方式与 `execve` 相同。 至于附加的参数，它提到：

> pathname 是绝对路径，则 dirfd 可以省略

因此，我们可以让 `pathname` 指向 `"/bin/sh"`， 并将 `argv`, `envp` 和 `flags` 设置为 `0`， 那么无论 `dirfd` 的值是多少，我们仍然可以得到一个 `shell`。
