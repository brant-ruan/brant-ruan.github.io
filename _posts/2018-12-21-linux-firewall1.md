---
title: Linux Firewall Part 1 防火墙的基本概念
category: linux-firewall
---

# {{ page.title }}

## 前言

> 还未如愿见到不朽 就把自己先搞丢

事实上，本系列文章是[《更安全的Linux网络》](https://book.douban.com/subject/3596701/)一书的阅读学习笔记。

最近在研究Docker和Snort时，发现两者都要求iptables的背景知识。基于BFS、DFS以及拓扑排序的原则，我决定先研究一下iptables。

在网络上搜索iptables的教程时，有幸找到陈勇勋先生这本大作。该书出版时间较早，如今已经绝版。

![01B92BCB021D5CE814A97CBC9331EB]({{ site.url }}/images/linux-firewall/media/15452192527122/01B92BCB021D5CE814A97CBC9331EBC1.png)

实验环境说明：

```
uname -r
3.10.0-862.14.4.el7.x86_64

cat /etc/redhat-release 
CentOS Linux release 7.5.1804 (Core) 

iptables --version
iptables v1.4.21

ifconfig | grep 172
        inet 172.16.56.138  netmask 255.255.255.0  broadcast 172.16.56.255
```

用来与CentOS通信的机器地址为`172.16.56.1`。

CentOS 7 提供了iptables和firewalld两种操作内核Netfilter的接口，默认使用的是firewalld。事实上，firewalld的底层依然调用了iptables命令行，但是firewalld本身不兼容iptables语法（我们不能使用iptables规则去操作firewalld）。这里我们研究iptables，所以需要关闭firewalld，开启iptables：

```bash
# stop firewalld
systemctl stop firewalld
systemctl disable firewalld
# install iptables services
yum install -y iptables-services iptables-devel.x86_64 iptables.x86_64
# start iptables
systemctl enable iptables
systemctl start iptables
# check status
systemctl status iptables
```

为了避免SELinux对实验结果的影响，请先暂时关闭它：

```bash
setenforce 0
```

用以下命令开启数据包转发：

```bash
echo "1" > /proc/sys/net/ipv4/ip_forward
```

## 1.1 基础知识

要学习防火墙，网络知识必不可少。具体到这里，就是以太网和TCP/IP协议蔟相关的背景知识。

在学习本章时，我发现过去自己对TCP连接的理解有一个问题：过去写C/S模式的程序时，把socket和port的概念弄混了。S端在accept时会返回一个新的socket文件描述符，但是并没有占用新的端口。**新启用的socket和原来的监听socket使用同一个端口。**其实socket只是TCP/IP协议的一种实现，而端口的目的仅仅为了帮助系统理解进程与数据包之间的对应关系。至于一个进程内部怎么去利用这个端口，怎么去处理这个端口的数据包，操作系统是不管的。

OK，言归正传。

```bash
cat /etc/services
```

上述文件给出了协议规定的部分端口与服务之间的对应关系。

简单来说，防火墙的主要任务是“根据匹配条件，放行合法数据包，过滤非法数据包”。“条件”是防火墙的重中之重，各种条件构成一系列的规则，这些规则才是真正的守夜人。

我们可以把条件划分为三大类：

- 各层封包包头信息：如以太网连接层的src/dst-MAC，网络层的IP地址等
- 封包内的payload信息：如应用层HTTP协议中指定的访问目标“`www.example.com`”字符串等
- 连接状态：这是宏观概念，例如允许内网数据包流出，不允许外网数据包流入等

关于“连接状态”，这里要补充一点：如果我们希望内网主机能够访问外网服务，但是限制外网数据包进入内网，在这样的场景下，比如内网host去访问`www.baidu.com:80`，由于通信是双向的，势必会有外网数据包进入内网的需求，但是它们似乎会被防火墙挡住。其实不是的。防火墙提供了“连接状态判别”机制，会对这种情况下的流入数据包放行。详细内容在后面的章节中。

## 1.2 防火墙分类

前面讲过条件分类，那么防火墙有那些分类呢？

按照过滤技术区分：

- 包过滤防火墙：能够检查的最小单位为“一个封包”，成本不高
- 应用层防火墙：可以检查应用层payload的每个字节，成本较高

按照网络拓扑结构区分：

- 单机式防火墙

早期一些企业的网络架构可能如下图所示：

![38705CEBFCEFCA5943FF8C38080FACF0]({{ site.url }}/images/linux-firewall/media/15452192527122/38705CEBFCEFCA5943FF8C38080FACF0.png)

虽然安装了单机防火墙，但任何来自互联网的攻击行为都由Mail和Web服务器自行承担，风险较大。

- 网关式防火墙

根据拓扑细节不同，主要有三种形式：

![566EE7B047C89F3E3FB44280B2EEF6E]({{ site.url }}/images/linux-firewall/media/15452192527122/566EE7B047C89F3E3FB44280B2EEF6EC.png)

形式1中，Mail与Web服务器被放在内网，这很危险，它们一旦被攻击成功将直接导致内网沦陷。

形式2在形式1的基础上做了改进，加入了我们熟知的DMZ，安全性有很大提高。在这种结构下，我们还可以做一点改进，就是将服务器放入企业内网，然后在DMZ放置一个反向代理：

![FB4161FBA22DB2B94C03CE83AE6A490F]({{ site.url }}/images/linux-firewall/media/15452192527122/FB4161FBA22DB2B94C03CE83AE6A490F.png)

当然，这样做将使开销增大。

形式3与形式2基本相同，区别是构建了多层次内网。在这种形势下需要注意的是，使用不同厂商的防火墙产品，以实现最佳防御效果。

- 通透式防火墙

网关防火墙本身就是一个路由器，它的加入使得原拓扑环境下的IP配置需要重新调整。通透式防火墙则工作在OSI第二层，相当于“Bridge+Filter”，它既不需要IP地址，也不会引入路由问题：

![64092D9B7618DCC8E452DBB95C6F3D6E]({{ site.url }}/images/linux-firewall/media/15452192527122/64092D9B7618DCC8E452DBB95C6F3D6E.png)