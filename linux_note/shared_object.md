记录一下 Linux 共享库的编译及调用



测试：

libc.c

```c
int xor(const char a, const char b)
{
        int result;
        result = (int)a ^ (int)b;
        return result;
}
```

编译 .so：

```bash
gcc -shared -fPIC source.c -o libc.so
```





main.c

```c
#include<stdio.h>
#include <dlfcn.h>

int main()
{
        void *libc_handle = NULL;
        int (*xor)(const char a, const char b);
        libc_handle = dlopen("./libc.so", RTLD_LAZY);
        xor = dlsym(libc_handle, "xor");
        int tmp = (*xor)('a', '1');
        printf("%c", (char)tmp);
        dlclose(libc_handle);
        return 0;
}
```

编译源文件：

```bash
gcc -rdynamic main.c -o main -ldl
```





这里用到的函数主要有：

查 man 手册：man 3 dlopen

```
DLSYM(3)                                            Linux Programmer's Manual                                           DLSYM(3)

NAME
       dlsym, dlvsym - obtain address of a symbol in a shared object or executable

SYNOPSIS
       #include <dlfcn.h>

       void *dlsym(void *handle, const char *symbol);

       #define _GNU_SOURCE
       #include <dlfcn.h>

       void *dlvsym(void *handle, char *symbol, char *version);

       Link with -ldl.

SYNOPSIS
       #include <dlfcn.h>

       void *dlopen(const char *filename, int flags);

       int dlclose(void *handle);

       #define _GNU_SOURCE
       #include <dlfcn.h>

       void *dlmopen (Lmid_t lmid, const char *filename, int flags);

       Link with -ldl.
```

dlopen 就是 load 一个 共享库，返回一个  handle （void 指针），他有两个参数，第一个就是 共享库 的路径，第二个是 load 的模式

dlclose 相反



man 3 dlsym

```
DLSYM(3)                                            Linux Programmer's Manual                                           DLSYM(3)

NAME
       dlsym, dlvsym - obtain address of a symbol in a shared object or executable

SYNOPSIS
       #include <dlfcn.h>

       void *dlsym(void *handle, const char *symbol);

       #define _GNU_SOURCE
       #include <dlfcn.h>

       void *dlvsym(void *handle, char *symbol, char *version);

       Link with -ldl.

```



dlsym 就是通过 dlopen 返回的 handle 和函数名 解析出 函数，其返回值是一个 函数指针