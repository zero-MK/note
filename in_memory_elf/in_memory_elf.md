关于 linux 环境下无文件执行elf ：就是执行 ELF 文件，但是 它不会被存在硬盘中

前段时间大概去了解了一下这个东西



其实就是

> 创建一个匿名文件得到一个指向这个文件的文件描述符。这个文件就像是一个普通文件一样，所以能够被修改，截断，内存映射等等．不同于一般文件，此文件是保存在RAM中



所谓的文件描符就是比如：

pid为 ：xxxx 的进程，其文件描述符一般是在 其 fd 文件夹下面（unix 下万物皆文件，上文提到的，这个匿名文件就像是一个普通文件一样躺在这个文件夹下面，当然，这个并不是真实存在在硬盘上面的）

```bash&#39;
/proc/xxxx/fd
```

随便打开个进程的 fd（我这里是 zsh 的）

![MPFsTx.png](https://s2.ax1x.com/2019/11/06/MPFsTx.png)

关于 /proc 我就不多说什么，详细的可以看看这个博主写的

https://blog.spoock.com/2019/10/08/proc/



首先要注意一点的是，如果是进程自己读取 fd 的话可以不用 pid ，只要读取这个目录：/proc/self/fd

思路：

1.  读取要执行的 elf 文件的信息（open(), lseek(),read()）
2. 创建匿名文件，获得文件描述符（syscall(), memfd_create(), ftruncate()）
3. 把已经读取进 elfbuf 的 elf 写入 /proc/self/fd/xxxx 中（write()）
4. 执行文件（execve()）



代码：

```c
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<fcntl.h>
#include<linux/memfd.h>
#include<sys/syscall.h>
#include <errno.h>


int anonyexec(const char *path, char *argv[]);

int main()
{
  char *argv[] = {"/bin/uname", "-a", NULL};
  int result = anonyexec("/bin/uname", argv);
  return result;
}

int anonyexec(const char *path, char *argv[])
{
  int fd; 
  int fdm;
  int filesize;
  void *elfbuf;
  char cmdline[256];

  fd = open(path, O_RDONLY);
  filesize = lseek(fd, SEEK_SET, SEEK_END); //从 0 字节跳到文件末尾，从而得到文件大小
  lseek(fd, SEEK_SET, SEEK_SET); //跳回文件开始位置
  elfbuf = malloc(filesize);

  read(fd, elfbuf, filesize); //把 ELF 文件读取到 elfbuf
  close(fd);

  fdm = memfd_create("elf", MFD_CLOEXEC); //创建匿名文件的fd, MFD_CLOEXEC等同于close-on-exec, 在运行完毕之后关闭这个文件句柄
  /*
   * syscall(__NR_memfd_create, "elf", MFD_CLOEXEC);
   * syscall(319, "elf", 1);
   */
  ftruncate(fdm, filesize); //ftruncate(fd, lenght)会将参数 fd 指定的文件大小改为参数 length 指定的大小
  write(fdm, elfbuf, filesize); //把 elf 写入匿名文件
  free(elfbuf);

  sprintf(cmdline, "/proc/self/fd/%d", fdm); //fdm 就是当前进程 fd 下面的一个匿名文件，这句话就是在拼接路径
  printf("%s\n", cmdline);
  argv[0] = cmdline; // argv[0] 一般是存当前可执行文件的文件名
  getchar();
  execve(argv[0], argv, NULL); //这个函数的原型：execve(path, argv, envp); 路径，参数，环境变量，也就是我们要执行 path 路径上的二进制文件， 参数是 argv。。。
  free(elfbuf);
  return -1;
}
```



python：

```python
import ctypes
import os
import subprocess

libc = ctypes.CDLL(None)
argv = ctypes.pointer((ctypes.c_char_p * 0)(*[]))
syscall = libc.syscall
fexecve = libc.fexecve

file = raw_input("ELF path: ")

content = open(file).read()


fd = syscall(319, "", 1) #319 号系统调用，也就是 memfd_create
os.write(fd, content)

print "pid: " + str(os.getpid())
print "fd: " + str(fd)

raw_input()

#fexecve(fd, argv, argv)
print subprocess.check_output("/proc/self/fd/"+ str(fd))
```



监测：

```bash
auditctl -W /proc -p rwxa #监测 /proc 目录
ausearch -f /proc | grep self/fd | grep EXEC #列举 执行 self/fd/xxx 的记录
```

![M97yrj.png](https://s2.ax1x.com/2019/11/06/M97yrj.png)



或者使用 `lsof -f pid`

![M97yrj.png](https://s2.ax1x.com/2019/11/06/M97yrj.png)