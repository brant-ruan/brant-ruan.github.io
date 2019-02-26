---
title: Linux Firewall Part 4 Netfilter/Iptables的高级技巧
category: linux-firewall
---

# {{ page.title }}

## 前言

> 闷声大发财。

本章介绍一些深入且实际的技巧。

本章导图：

![LFW-4]({{ site.url }}/images/linux-firewall/media/15457936963819/LFW-4.png)

## 4.1 防火墙性能优化

性能优化的基本原则是“减少不必要的规则匹配”。

### 4.1.1 规则顺序调整

```bash
iptables -A INPUT -p tcp --syn -m state --state NEW --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --syn -m state --state NEW --dport 23 -j ACCEPT
iptables -A INPUT -p tcp --syn -m state --state NEW --dport 25 -j ACCEPT
iptables -A INPUT -p tcp --syn -m state --state NEW --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --syn -m state --state NEW --dport 110 -j ACCEPT
iptables -A INPUT -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
```

上述规则可以作出两点调整：

1. 将最后一条规则放到第一去
2. 将前五条针对单服务的规则按照热门程度（匹配命中次数）依次排列

另外，可以使用以下命令去统计规则匹配频度，从而对规则顺序作出优化：

```bash
iptables -L -v -n
```

### 4.1.2 善用“指定多目标”模块

匹配多IP和多端口的模块可以帮助减少规则数。上一小节的规则范例可以优化为：

```bash
iptables -A INPUT -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --syn -m state --state NEW -m multiport --dports 22,23,25,80,110 -j ACCEPT
```

### 4.1.3 善用用户自定义规则

考虑一种情况：我们部署了一个网关防火墙，其后有三台主机。我们为每台主机在网关防火墙上各制定了100条FORWARD规则。这些规则在同一条链中排列，必定有先有后。对于符合第300条规则的封包来说，它将经过299道无用过滤。

为了解决这个问题，可以设置三条用户自定义规则链：

```bash
iptables -A FORWARD -p all -d $HOST1 -j $CHAIN_HOST1
iptables -A FORWARD -p all -d $HOST2 -j $CHAIN_HOST2
iptables -A FORWARD -p all -d $HOST3 -j $CHAIN_HOST3
```

这样一来，无用匹配将大大减少。

除了按照不同主机分割规则链，也可以按照不同协议，不同网络栈层次来划分。

## 4.2 Netfilter连接处理能力与内存损耗

用于连接追踪统计的文件是`/proc/net/nf_conntrack`，它的一个项如下：

```
ipv4     2 tcp      6 431819 ESTABLISHED src=172.16.56.138 dst=172.16.56.1 sport=41028 dport=10000 src=172.16.56.1 dst=172.16.56.138 sport=10000 dport=41028 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
```

注意，`/proc`存在于内存中。每多追踪一条连接，就会多消耗一点内存。但是我们可以调整连接追踪数量上限。

## 4.3 RAW Table

本节介绍RAW表。

只要conntrack模块被加载，那么穿越防火墙的所有连接就会被记录。在一些场景下，我们希望某些连接不被记录下来，就可以使用RAW：

```bash
iptables -t raw -A PREROUTING -i eth2 -p tcp --dport 25 -j NOTRACK
iptables -t raw -A PREROUTING -i eth1 -p tcp --sport 25 -j NOTRACK
```

在第二章最后的流程图中可以看到，RAW的PREROUTING链处理优先级是最高的。

RAW表的好处就是提高防火墙性能，增加可追踪的连接数量。需要注意的是，RAW表定义下的连接会跳过NAT表。

RAW的PREROUTING链用来处理“防火墙两侧网络之间建立的”以及“到防火墙本身的”连接；OUTPUT链用于处理防火墙自身对外建立的连接（与NAT表的OUTPUT链类似）。

## 4.4 简单及复杂通信协议处理

Netfilter将通信协议划分为两类：简单的和复杂的。（你是在逗我吗？）

### 4.4.1 简单通信协议

简单通信协议指的是那些Client访问Server只产生一条连接的协议，如HTTP、SSH、SMTP等。

简单通信协议的处理很简单，就是我们之前学过的那些内容（Filter、NAT都没什么问题）。

### 4.4.2 复杂通信协议

复杂通信协议如FTP、PPTP等，需要在Client与Server之间建立一条以上的连接。下面以FTP协议为例来介绍Netfilter处理复杂通信协议的方式。

FTP协议分为Passive和Active模式，工作流程分别如下图所示：

![Bildschirmfoto 2019-01-08 um 1.16.48 P]({{ site.url }}/images/linux-firewall/media/15457936963819/Bildschirmfoto%202019-01-08%20um%201.16.48%20PM.png)

Filter在处理FTP通信协议时会遇到问题：在被动模式下，假如Server端被放在一个防火墙后面，那么`1955 <- 21`后，常规的连接追踪机制并不能生效，所以`1956 -> 29318`这条连接不被认为是`RELATED`，所以将被防火墙挡在外面；类似地，在主动模式下，假如Client端被放在一个防火墙后面，也会出现这个问题。

问题的根本在于默认的conntrack模块不能处理FTP协议在控制信道指定的数据端口信息。

解决方案：Netfilter为复杂通信协议提供了特定的判别模块，我们拿来用就好，这里需要的就是`ip_conntrack_ftp.ko`。

先加载模块，后面正常写就好：

```bash
modprobe ip_conntrack_ftp
...
iptables -A FORWARD -i eth0 -o eth1 -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
```

如果需要指定端口，则可以在加载模块时给出：

```bash
modprobe ip_conntrack_ftp ports=21,2121,3131
```

NAT在处理FTP协议时也会遇到问题：默认的NAT机制不能处理FTP协议在控制信道指定的IP地址信息，应用层传递的依然是私有IP。

解决方案类似，加载`ip_nat_ftp`模块即可。

### 4.4.3 ICMP封包处理原则

处理原则很简单：

- 放行所有来自因特网的ESTABLISHED及RELATED状态的ICMP封包
- 丢弃所有来自因特网的其他状态的ICMP封包

### 4.4.4 常见网络攻击及防护

#### PortScan

端口扫描的目的在于探测目标主机开放了那些端口，特征是短时间内向目标主机发出针对不同端口的连接请求。结合此特征，我们可以给出以下论断：

- 访问服务器上开放的端口属于正常行为（这里仅仅讨论端口扫描层面上的行为）
- 访问服务器上其他端口属于不正常行为

我们从而可以给出如下防火墙规则：

```bash
iptables -A INPUT -p all -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p all -m state --state NEW -m recent --name port_scan --update --seconds 1800 --hitcount 10 -j DROP
iptables -A INPUT -p tcp --syn -m state --state NEW -m multiport --dports 22,25,80,110 -j ACCEPT
iptables -A INPUT -p all -m recent --name port_scan --set
```

#### 密码暴力破解

此类攻击的特征是，服务端会在短时间内发出很多认证失败的信息。例如，针对POP3暴力破解可以使用如下规则判断防御：

```bash
iptables -A OUTPUT -p tcp --sport 110 -m string --algo bm --string "-ERR Authentication failed." -m recent --name pop3 --update --seconds 600 --hitcount 6 -j REJECT
iptables -A OUTPUT -p tcp --sport 110 -m string --algo bm --string "-ERR Authentication failed." -m recent --name pop3 --set
```

这是针对未加密的通信协议；加密的通信协议处理起来要困难一些，使用服务本身提供的防破解机制会更有效。

## 总结

陈先生的这本书到此算是读完。后面关于代理服务器和VPN的部分暂时没有需求去阅读。就我读过的部分来说，这本书真值得推荐。我从王爽老师的《汇编语言》、陈勇勋老师的《更安全的Linux网络》及赵鹏老师的《毫无PS痕迹》三本书中学到了一些教育与写作的艺术：他们的书就像厨艺大师烧好的可口的菜，而不是常见书籍那样的简单铺陈。所谓由点及面、提纲挈领、循循善诱，如是而已。

## 参考

参考链接为本系列文章引用到的所有参考链接。

- 《更安全的Linux网络》 陈勇勋 著
- [防火墙（firewalld与iptables）](https://blog.csdn.net/weixin_40658000/article/details/78708375)
- [关闭CentOS7的firewalld并启用iptables操作](https://blog.csdn.net/lqy461929569/article/details/74370396)
- [Netfilter Packet Traversal](http://developer.gauner.org/doc/iptables/images/nfk-traversal.png)