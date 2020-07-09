Linux 内核中 offset_of 和 container_of 宏的实现

## offset_of

via: https://elixir.bootlin.com/linux/latest/source/tools/include/linux/kernel.h#L23

获取成员在结构体中的偏移量

```c++
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
```

在以前我很奇怪，为什么用 `0` 指针
后来在某个群里面和群主讨论了一下，发现这个设计很巧妙

其实就是把地址 `0`当成是结构体的起始地址，这样，获取它的成员的地址，就相当于获取成员相在结构体里的偏移

举个例子，有这样一个结构体

```c++
struct demo {
  int i_var;
  int i2_var;
  int i3_var;
};
```

`((struct demo *) 0)`  它是这样的

```plain
        +--------------+
0x0     |              |
0x1     |    i_var     |
0x2     |              |
0x3     |              |
        +--------------+
0x4     |              |
0x5     |    i2_var    |
0x6     |              |
0x7     |              |
        +--------------+
0x8     |              |
0x9     |    i3_var    |
0xa     |              |
0xb     |              |
        +--------------+
```

我想获取 `i3_var` 的偏移量，只要 `&(((struct demo *) 0) -> i3_var)`
得到的是 `0x8`

可以看到这里是取 `i3_var` 地址，为什么是取地址？

因为这个结构体的起始地址是 `0` ，`i3_var` 的地址肯定是：结构体的起始地址加上偏移量，因为起始地址是 `0` 所以取 `i3_var` 的地址就相当于是获得它在结构体里面的偏移量

## container_of

via: https://elixir.bootlin.com/linux/latest/source/tools/include/linux/kernel.h#L26

通过成员获取结构体地址

参数

@ptr：指向成员的指针

@type：成员位于的结构体

@member：成员在结构体里面的名称

```c++
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })
```

开始分析之前需要补一下 `{()}` 表达式

这个表达式就是返回最后一条语句的 **运算结果** 记住必须是 **运算表达式** 或者 是一个 **值** ，不能是赋值语句（不知道该怎么表达，自己多写几个 `demo` 试试就知道了）

上 `demo` 吧

```c
#include <stdio.h>

int main() {
    int v = ({
            int v2 = 1;
            int v3 = 2;
            v2 + v3;
    });
    printf("%d\n", v);
    return 0;
}
```

上面的程序运行结果会是 `3`

```c
#include <stdio.h>

int main() {
    int v = ({
            int v2 = 1;
            int v3 = 2;
            0;
    });
    printf("%d\n", v);
    return 0;
}
```

上面的程序运行结果会是 `0`

错误演示

```c
#include <stdio.h>

int main() {
    int v = ({
            int v2 = 1;
            int v3 = 2;
            int v4 = v2 + v3;
    });
    printf("%d\n", v);
    return 0;
}
```

用 `gcc` 编译的话会直接报错

```c
main.c: 在函数‘main’中:
main.c:4:13: 错误：void 值未如预期地被忽略
    4 |     int v = ({
      |             ^
```



回归正题一句一句分析

```c
const typeof(((type *)0)->member) * __mptr = (ptr);
```

获取 `member` 的类型，然后声明一个 对应 `member` 类型的常量指针（在常量指针中，指针指向的内容是不可改变的，指针看起来好像指向了一个常量） `__mptr`， `__mptr = ptr`，这样保证我们的操作不会误操作修改了 `ptr`导致程序出错，反正就是 `__mptr` 是指向已知成员的地址的，并且是不可修改的

`typeof` 是  `c` 的 `GNU` 扩展函数，它会返回参数对应的类型

`int int_var = 0;`

`typeof(int_var)` 会得到 `int` 类型



```c
(type *)((char *)__mptr - offsetof(type, member));
```

先把 `__mptr` 转成 `char *` 然后在减去 `member` 在结构体里的偏移量就能得到结构体的真实地址

为什么要先把 `__mptr` 转成 `char *`？

因为对指针进行加减运算的时候并不是说 `addr + 1` 得到的地址就是 `addr` 加上 `1`，实际上加的是 `1 * (sizeof(typeof(*addr)))` （自己细品），转成 `char *` 后就相当于 `sizeof(typeof(char))`，其实就是 `1`，加 `n` 变成：`(n * 1)`



现在一个结构体 `demo`

```c
struct demo {
    int i_var;
    int i2_var;
    int i3_var;
};
```



```
offset                         address

           +--------------+
   0x0     |              |	0x7ffd7a0a8c0c
   0x1     |    i_var     |
   0x2     |              |
   0x3     |              |
           +--------------+
   0x4     |              |	0x7ffd7a0a810
   0x5     |    i2_var    |
   0x6     |              |
   0x7     |              |
           +--------------+
   0x8     |              |	0x7ffd7a0a814
   0x9     |    i3_var    |
   0xa     |              |
   0xb     |              |
           +--------------+
```

我要通过 `i3_var` 的地址去找对应的 `demo` 结构体实例的地址

假设 `i3_var` 的地址是 `0x7ffd7a0a8d4` 偏移量是 `0x8`，只要用地址减去偏移量就能获得其对应的 `demo` 结构体实例的地址



其实这两个宏相关的文章有很多人写过，我看过很多，写的都比我的好，我只是想以自己的理解去写一篇

可以看看这一篇：https://radek.io/2012/11/10/magical-container_of-macro/