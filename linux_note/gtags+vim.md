安装 gtags：

```
sudo apt-get install global
```

安装 neovim：

https://neovim.io/

配置文件：

[spacevim](spacevim.org/cn)



方法：

直接在源代码根目录运行：`gtags`

会生成 GPATH， GRTAGS， GTAGS 文件。



只要在 ~/.SpaceVim.d/init.toml 中加入

```
[[layers]]
  name = "gtags"
  gtagslabel = "pygments"
```

重启 vim ，即可完成插件的加载

进入源码根目录 vim ./

按 F3 打开 vimfiler 随便打开一个源文件

要是发现搜索用不了

依次按下：

```
space + m + g +u
```

