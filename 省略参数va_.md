主要是：

```c
#include <stdarg.h>

void va_start(va_list ap, last);
type va_arg(va_list ap, type);
void va_end(va_list ap);
```



```
va_list 
```

额外的参数检索状态信息 va_list 类型的对象



```c
va_start(va_list ap, last);
```

ap -- 这是va_list的对象，将持有va_arg的额外的参数来检索所需的信息。last_arg -- 这是最后一个已知的固定参数传递给函数。



```c
va_arg(va_list ap, type);
```

ap -- 这是额外的参数检索状态信息 va_list 类型的对象。这个对象应已初始化由初始调用，va_start 前第一次调用va_arg。type -- 这是一个不同的名称。此类型的名称作为该宏展开的表达类型。该宏返回下一个额外的参数作为一个表达式的类型类型。



```c
va_end(va_list ap);
```

ap -- 这是va_list的对象，以前在同一个函数用va_start初始化。



source：

```c
#include<stdio.h>
#include<stdarg.h>

void func(int, ...);

int main()
{
  func(4, 'a', 'b', 'c', 'b');
  return 0;
}

void func(int num_args, ...)
{
  int val = 0;
  va_list ap;
  int i;
  va_start(ap, num_args);
  for(i = 0; i < num_args; i++)
  {
    printf("%c\n", va_arg(ap, int));
  }
  va_end(ap);
}
```



结果：

```bash
# root @ FK in ~/code/c/va_start [22:31:35] 
$ ./va
a
b
c
b
```

