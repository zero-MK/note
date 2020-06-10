关闭端口上面运行的程序

```bash
cat /etc/services | grep port
```

查看是哪个服务占用端口



```bash
systemctl list-unit-files --all | grep name
```

查看 服务



```bash
systemctl disable
systemctl stop 
```

 关闭服务进程和开机启动

