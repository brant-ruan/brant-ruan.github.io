---
title: Linux Firewall Part 3 Netfilter模块的匹配方式与处理方法
category: linux-firewall
---

# {{ page.title }}

## 前言

> 城郊牧笛声 落在那座野村 缘份落地生根是我们

本章我们来学习如何使用不同模块提供的匹配方式(Matches)和处理方法(Targets)，达到进一步的封包筛选目的。

本章导图：

![LFW-Netfilter模块的匹配方式与处理方法]({{ site.url }}/images/linux-firewall/media//15453839464087/LFW-2-Mindmap.png)

## 3.1 匹配方式(Matches)

“匹配方式”是Netfiter筛选封包的基本单元。

### 3.1.1 内建匹配方式

Netfilter的四大机制分别由以下四大模块提供：

- iptable_filter.ko
- iptable_mangle.ko
- iptable_nat.ko
- iptable_raw.ko

这些模块中内建了一些匹配方式：

- Interface (-i -o)
- IP Address (-s -d)
- Protocol (-p 参考/etc/protocols)

**例1：ICMP协议高级匹配**

我们希望配置规则，使得自身能够去ping外部机器，但外部机器ping自己的请求被丢弃。很明显，下面的命令不能实现这个目的：

```bash
iptables -A INPUT -p icmp -j DROP
```

结合ICMP协议，我们给出以下命令：

```bash
iptables -A INPUT -p icmp --icmp-type=8 -j DROP
```

**例2：TCP协议高级匹配**

我们已经介绍过`--sport`/`--dport`，现在介绍依据TCP Flags（8 bits，用于TCP连接控制）的匹配。一些重要的标志如下：

|位|范围|描述|
|:-:|:-:|:-:|
|bit 1|Finish|连接终止信号|
|bit 2|Synchronize|连接请求信号|
|bit 3|Reset|立即中断连接|
|bit 5|Acknowledge|确认回复信号|

我们借助Wireshark回顾一下TCP连接的建立和终止过程：

建立：`C-SYN->S; S-SYN,ACK->C; C-ACK->S`

![Bildschirmfoto 2018-12-26 um 11.40.23 A]({{ site.url }}/images/linux-firewall/media//15453839464087/Bildschirmfoto%202018-12-26%20um%2011.40.23%20AM.png)

终止：理论上需要4次握手，但抓包往往出现其他情况（例如我下面的）

客户端先终止连接：

![Bildschirmfoto 2018-12-26 um 11.43.54 A]({{ site.url }}/images/linux-firewall/media//15453839464087/Bildschirmfoto%202018-12-26%20um%2011.43.54%20AM.png)

服务端先终止连接：

![Bildschirmfoto 2018-12-26 um 11.51.17 A]({{ site.url }}/images/linux-firewall/media//15453839464087/Bildschirmfoto%202018-12-26%20um%2011.51.17%20AM.png)

我们暂时不去深究协议内容，专注于Netfilter本身。可以明确的是，正常封包不会同时具备`SYN`/`FIN`标志。为了避免主机接收到这样的封包后出现异常，我们可以对这一类异常封包进行过滤。

有如下规则：

```bash
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

我们可以对其修改，只允许第一个封包带有SYN标志：

```bash
iptables -A INPUT -p tcp --syn --dport 22 -m state --state NEW -j ACCEPT
```

结果如下：

```bash
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh flags:FIN,SYN,RST,ACK/SYN state NEW
```

或者，使用如下命令，检查所有TCP Flags，过滤掉同时包含SYN与FIN的封包：

```bash
iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN -j DROP
```

结果如下：

```
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
DROP       tcp  --  anywhere             anywhere             tcp flags:FIN,SYN,RST,PSH,ACK,URG/FIN,SYN
```

一个变种是，不检查其他标志，只检查SYN与FIN同时为1，效果相同：

```bash
iptables -A INPUT -p tcp --tcp-flags SYN,FIN -j DROP
```

结果如下：

```bash
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
DROP       tcp  --  anywhere             anywhere             tcp flags:FIN,SYN/FIN,SYN
```

### 3.1.2 延伸匹配方式

现在我们介绍其他模块提供的匹配功能，可以到前文给出的Netfilter模块路径下查看有哪些模块可以使用。

**例1：MAC地址匹配**

该功能由xt_mac.ko模块提供，简单举例：

限制只有某台机器可以访问MySQL服务器：

```bash
iptables -A INPUT -p tcp --dport 3306 -m mac --mac-source 00:11:22:33:44:55 -j ACCEPT
```

**例2：Multiport匹配**

该模块在上一章中已经讲过，不再赘述。需要注意的是除了`--dport`/`--sport`还可以用`--port`来匹配来源或目的端口。

**例3：IP范围匹配**

```bash
iptables -A INPUT -m iprange --src-range 172.16.56.3-172.16.56.100 -j DROP
```

**例4：MARK匹配**

这种匹配方式的思想很有趣，它大大提升了匹配自由度。还记得上一章章末，我们给出了一张封包流经Netfilter完整流程的图吗？我们可以在Mangle表中借助MARK来将符合特定条件的封包打上标记，然后在逻辑链下游的表中对标记过的封包进行处理。例如：

```bash
iptables -t mangle -A PREROUTING -p tcp --dport 80 -j MARK --set-mark 80
iptables -t filter -A FORWARD -p all -m mark --mark 80 -j DROP
```

执行后的Mangle表：

```bash
Chain PREROUTING (policy ACCEPT)
target     prot opt source               destination         
MARK       tcp  --  anywhere             anywhere             tcp dpt:http MARK set 0x50
```

执行后的Filter表：

```bash
Chain FORWARD (policy DROP)
target     prot opt source               destination         
DROP       all  --  anywhere             anywhere             mark match 0x50
```

关于MARK还可以参考[基于IPTABLES MARK机制实现策略路由](http://www.just4coding.com/blog/2016/12/23/iptables-mark-and-polices-based-route/)和[关于IPTABLES 各种MARK 功能的用法](https://blog.csdn.net/wsclinux/article/details/53084904)。MARK作用于内核，不会修改封包内容。

**例5：所有者匹配**

该功能由xt_owner.ko模块提供，只适用于OUTPUT链。它提供的匹配方式如下：

- `--uid-owner userid`
- `--gid-owner groupid`

结合Linux基础知识就很好理解。这里举一个例子：

```bash
iptables -A OUTPUT -p all -m owner --uid-owner centos -j DROP
```

**例6：TTL值匹配**

```bash
iptables -A INPUT -m ttl --ttl-eq 64 -j REJECT
```

另外还有`--ttl-lt`/`--ttl-gt`。

**例7：封包状态匹配**

上一章中我们已经基本了解过state模块提供的匹配方式。这里我们深入探讨一下，在不同的通信协议中state规定的四种连接状态的具体含义。

`TCP协议`

Client发送`SYN`请求的封包经过防火墙将被标识为NEW，Server以`SYN&ACK`响应后该连接上的所有封包均被认定为`ESTABLISHED`。

在CentOS 7中，`/proc/net/nf_conntrack`是连接追踪数据库，`/proc/sys/net/nf_conntrack_max`给出该数据库中记录连接数的上限。

该数据库中的一条记录如下：

```
ipv4     2 tcp      6 431819 ESTABLISHED src=172.16.56.138 dst=172.16.56.1 sport=41028 dport=10000 src=172.16.56.1 dst=172.16.56.138 sport=10000 dport=41028 [ASSURED] mark=0 secctx=system_u:object_r:unlabeled_t:s0 zone=0 use=2
```

`UDP协议`

与TCP类似。

`ICMP协议`

与TCP类似。

**例8：AH及ESP协议的SPI值匹配**

```bash
iptables -A FORWARD -p ah -m ah --ahspi 300 -j ACCEPT
iptables -A FORWARD -p esp -m esp --espspi 200 -j ACCEPT
```

**例9：pkttype匹配**

这里的类型指是`unicast`、`broadcast`还是`multicast`。

例如，我们可以过滤掉ping的广播包：

```bash
iptables -A FORWARD -i eth0 -p icmp -m pkttype --pkt-type broadcast -j DROP
```

这针对的是下面这种操作：

```bash
ping -b 172.16.56.255
```

**例10：封包长度匹配**

以ICMP封包为例，我们往往用MTU和MSS去描述封包长度：

- Maximum Transmission Unit = IP包头 + ICMP包头 + DATA
- Maximum Segment Size = ICMP包头 + DATA

计算一下，可以得到正常Windows系统ping的MTU，并用以下命令放行：

```bash
iptables -A INPUT -p icmp --icmp-type 8 -m length --length 92 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 8 -j DROP
```

另外，`100:`、`:100`和`50:100`分别匹配长度大于等于100、小于等于100及50到100。

**例11：limit特定封包重复率匹配**

有时我们不想完全禁止外部ping主机，因为自己可能也有这个需求。这时，我们可以限制频率，例如设定：每分钟只能进入10个封包，但如果进入多于10个，则限制每分钟只能进入6个。

```bash
iptables -A INPUT -p icmp --icmp-type 8 -m limit --limit 6/m --limit-burst 10 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type 8 -j DROP
```

另外，`/s`、`/h`、`/d`分别代表秒、小时、天。

设定规则后去ping一下主机。结果符合预期，先进入10个，然后降为每分钟6个，也就是10秒一个：

```
ping 172.16.56.138
PING 172.16.56.138 (172.16.56.138): 56 data bytes
64 bytes from 172.16.56.138: icmp_seq=0 ttl=64 time=0.312 ms
64 bytes from 172.16.56.138: icmp_seq=1 ttl=64 time=0.618 ms
64 bytes from 172.16.56.138: icmp_seq=2 ttl=64 time=0.559 ms
64 bytes from 172.16.56.138: icmp_seq=3 ttl=64 time=0.576 ms
64 bytes from 172.16.56.138: icmp_seq=4 ttl=64 time=0.626 ms
64 bytes from 172.16.56.138: icmp_seq=5 ttl=64 time=0.595 ms
64 bytes from 172.16.56.138: icmp_seq=6 ttl=64 time=0.535 ms
64 bytes from 172.16.56.138: icmp_seq=7 ttl=64 time=0.492 ms
64 bytes from 172.16.56.138: icmp_seq=8 ttl=64 time=0.498 ms
64 bytes from 172.16.56.138: icmp_seq=9 ttl=64 time=0.610 ms
Request timeout for icmp_seq 10
64 bytes from 172.16.56.138: icmp_seq=11 ttl=64 time=0.645 ms
Request timeout for icmp_seq 12
Request timeout for icmp_seq 13
Request timeout for icmp_seq 14
Request timeout for icmp_seq 15
Request timeout for icmp_seq 16
Request timeout for icmp_seq 17
Request timeout for icmp_seq 18
Request timeout for icmp_seq 19
Request timeout for icmp_seq 20
64 bytes from 172.16.56.138: icmp_seq=21 ttl=64 time=0.765 ms
```

**例12：recent特定封包重复率匹配**

这是一个比`limit`更为强大的模块，具体的使用方法如下：

|名称|解释|
|:-:|:-:|
|--name|指定追踪数据库的文件名|
|--set|将符合条件的来源信息加入数据库，若来源信息已存在，则仅更新数据库|
|--rcheck|只进行信息匹配，不更改数据库信息|
|--update|若来源信息已存在，则更新，否则不处理|
|--remove|若来源信息已存在，则删除，否则不处理|
|--seconds second|事件发生时，只匹配数据库中前几秒记录，必须与--rcheck或--update配合使用|
|--hitcount hits|匹配重复发生次数，必须与--rcheck或--update配合使用|

同样以ICMP流量控制为例，我们希望每分钟只能进来6个封包：

```bash
# rule 1
iptables -A INPUT -p icmp --icmp-type 8 -m recent --name icmp_db --rcheck --second 60 --hitcount 6 -j DROP
# rule 2
iptables -A INPUT -p icmp --icmp-type 8 -m recent --set --name icmp_db
```

结果如下：

```bash
ping 172.16.56.138
PING 172.16.56.138 (172.16.56.138): 56 data bytes
64 bytes from 172.16.56.138: icmp_seq=0 ttl=64 time=0.419 ms
64 bytes from 172.16.56.138: icmp_seq=1 ttl=64 time=0.583 ms
64 bytes from 172.16.56.138: icmp_seq=2 ttl=64 time=0.461 ms
64 bytes from 172.16.56.138: icmp_seq=3 ttl=64 time=0.620 ms
64 bytes from 172.16.56.138: icmp_seq=4 ttl=64 time=0.579 ms
64 bytes from 172.16.56.138: icmp_seq=5 ttl=64 time=0.598 ms
Request timeout for icmp_seq 6
Request timeout for icmp_seq 7
...
Request timeout for icmp_seq 58
Request timeout for icmp_seq 59
64 bytes from 172.16.56.138: icmp_seq=60 ttl=64 time=0.600 ms
64 bytes from 172.16.56.138: icmp_seq=61 ttl=64 time=0.399 ms
64 bytes from 172.16.56.138: icmp_seq=62 ttl=64 time=0.256 ms
64 bytes from 172.16.56.138: icmp_seq=63 ttl=64 time=0.317 ms
64 bytes from 172.16.56.138: icmp_seq=64 ttl=64 time=0.562 ms
64 bytes from 172.16.56.138: icmp_seq=65 ttl=64 time=0.240 ms
```

需要注意的是，与`limit`无差别计算封包总量的方式不同，`recent`是针对不同来源做分别匹配的，也就是说，上述规则允许不同来源的ping在每分钟发生6次。可以看一下`/proc/net/xt_recent/icmp_db`文件，它也是分条存放的：

```
src=172.16.56.1 ttl: 64 last_seen: 4364842324 oldest_pkt: 18 4364252889, 4364253887, 4364254888, 4364255884, 4364256883, 4364257884, 4364312924, 4364313926, 4364314928, 4364315929, 4364316928, 4364317925, 4364837357, 4364838351, 4364839345, 4364840340, 4364841333, 4364842324
src=172.16.56.164 ttl: 64 last_seen: 4364907742 oldest_pkt: 9 4364845564, 4364846557, 4364847548, 4364848558, 4364849552, 4364850545, 4364905710, 4364906726, 4364907742
```

我们来解释一下上述两条规则的原理：遇到符合条件的封包时，第一条规则去`icmp_db`向前找60秒的记录，如果向前60秒已经有过6次记录，则丢弃该封包；第二条规则将符合条件的封包信息记录到`icmp_db`文件中。

跟踪一下ping的过程：我们的ping是1秒一次。

- 防火墙遇到第一个封包时，第一条规则去数据库中找不到记录，所以该封包会交给第二条规则，从而在数据库中留下一个记录。但是第二条规则并没有对封包进行任何处理，所以该封包被交给下一条规则（在我的环境中，也就是`INPUT`的默认规则`ACCEPT`）；
- 防火墙遇到第二个封包时，第一条规则在数据库中向前60秒找到1条记录，因此该封包又被交给第二条规则，同样地，记录后又被交给下一条规则；
- 按这样的方式一直接受6个封包；
- 直到第七个封包到达时，第一条规则向前搜索60秒发现已经有6条记录，因此以“丢弃”方式“处理”该封包，因此该封包不会被交给后面的规则；
- 按这样的方式，从第7秒到第60秒都不会接受该来源的封包；
- 到第61秒时，第一条规则向前搜索60秒只能找到5条记录，所以又开始接受封包，并交给下一条规则；
- 按这样的方式一直接受6个封包；
- 到67秒时，发现前60秒（即6到66秒）又有6条记录，因此以“丢弃”方式“处理”封包；
- ...

我们甚至可以更进一步，实时更新数据库记录，这样以来，如果同一个来源一直ping，那么它的封包将一直无法进入主机：

```bash
iptables -A INPUT -p icmp --icmp-type 8 -m recent --name icmp_db --update --second 60 --hitcount 6 -j DROP
iptables -A INPUT -p icmp --icmp-type 8 -m recent --set --name icmp_db
```

最后，我们可以设置数据库记录来源IP数和每个来源封包信息数的上限：

```bash
modprobe xt_recent ip_list_tot=1024 ip_pkt_list_tot=50
```

`recent`为我们提供了发挥想象力的空间。例如，我们可以借助它来禁止端口扫描，实质是限制同一来源IP在规定时间内（如10分钟），不得发来超过10个`SYN`包：

```bash
iptables -P INPUT DROP
iptables -F
iptables -A INPUT -p tcp --syn -m recent --name PortScan --update --second 600 --hitcount 10 -j DROP
iptables -A INPUT -p tcp --syn -m state --state NEW -m multiport --dports 22,25,110 -j ACCEPT
iptables -A INPUT -p tcp --syn -m recent --set --name PortScan
```

**例13：载荷匹配**

这是一个很酷的功能，类似于应用层防火墙，但是是在网络层直接匹配载荷内容，不必交给应用层，效率更高，且不占用多余空间。局限在于，匹配范围为单个封包。它的本质是字符串匹配，例如：

```bash
iptables -A INPUT -p tcp -m string --algo bm --string 'system32' -j DROP
```

结果如下：

![Bildschirmfoto 2018-12-28 um 11.33.53 A]({{ site.url }}/images/linux-firewall/media//15453839464087/Bildschirmfoto%202018-12-28%20um%2011.33.53%20AM.png)

该模块提供的参数如下：

|名称|解释|
|:-:|:-:|
|--algo|匹配算法选择，有两个：`bm`(Boyer-Moore)和`kmp`(Knuth-Morris-Pratt)|
|--from/--to|指定匹配起止范围，单位为字节，不指定则默认范围是整个封包|
|--string|要匹配的字符串|

## 3.2 处理方法(Targets)

处理方法指的是当一个封包符合匹配条件时，可以怎么处理该封包。

### 3.2.1 内建处理方法

**ACCEPT**和**DROP**不必过多介绍。

**QUEUE**处理方法指将符合条件的封包送给用户层程序处理，应用场景比较少。

在介绍**RETURN**前，我们要了解User Define Chain的概念：用户可以自定义规则链。以下为自定义规则链的命令：

```bash
# create a new chain
iptables -N ICMP
# rename a chain
iptables -E ICMP MYICMP
# delete a chain (it must be empty)
iptables -X MYICMP
```

假设我们已经创建了一个名为`ICMP`的链。事实上，现在封包经过Netfilter时并不会进入用户自定义链，即使我们做了如下操作：

```bash
iptables -A ICMP -p icmp -j DROP
```

我们需要将它与其他链关联起来，例如，与`INPUT`链关联起来：

```bash
iptables -A INPUT -p icmp -j ICMP
```

这样规定以后，封包进入`INPUT`链匹配到该规则后，将转到`ICMP`链匹配。如果`ICMP`内的所有规则都没有匹配到，那么最后封包又被转送回`INPUT`进行下一条规则匹配（这是不是很像汇编指令`call`的特点？）。

`RETURN`目的在于，让符合规则的封包提前返回调用用户自定义链的原始链，这里即`INPUT`。例如，我们执行：

```bash
iptables -I ICMP 1 -p all -j RETURN
```

这样一来，又可以ping通了。

### 3.2.2 延伸处理方法

我们不再介绍**REJECT**。

**LOG**用于生成日志，因为Netfilter默认不生成任何日志。由于`LOG`本身并不处理封包，所以一般我们会将它与其他规则配合使用，例如：

```bash
iptables -A INPUT -p tcp --dport 22 -j LOG
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

Netfilter日志与其他各种日志存放在`/var/log/messages`中。事实上，我们可以将它存放在单独的文件中：

先在iptables中设定日志等级：

```bash
iptables -A INPUT -p tcp --dport 22 -j LOG --log-level alert --log-prefix "[SSH-REQUEST] "
```

然后修改日志服务配置文件：

```bash
# add "kern.=alert /var/log/netfilter"
vim /etc/rsyslog.conf
service rsyslog restart
```

日志内容如下：

```
Dec 28 15:49:00 localhost kernel: [SSH-REQUEST] IN=ens33 OUT= MAC=00:0c:29:85:db:15:00:50:56:c0:00:08:08:00 SRC=172.16.56.1 DST=172.16.56.138 LEN=52 TOS=0x08 PREC=0x40 TTL=64 ID=0 DF PROTO=TCP SPT=54286 DPT=22 WINDOW=2048 RES=0x00 ACK URGP=0 
```

**ULOG**与`LOG`类似，只不过ULOG将日志交给用户层机制处理。

**DSCP**用于QOS任务，这里不再展开。

**MARK**在前面已经介绍过，不再赘述。

**REDIRECT**是一种特殊的DNAT机制。

**MASQUERADE**是一种特殊的SNAT机制，在上一章已经介绍过。

**NETMAP**用于建立全网段一对一NAT映射（如果每对IP都分别建立一对一NAT，将花费大量时间），例如：

```bash
iptables -t nat -A PREROUTING -i eth0 -d 10.0.0.0/24 -j NETMAP --to 192.168.1.0/24
iptables -t nat -A POSTROUTING -o eth0 -s 192.168.1.0/24 -j NETMAP --to 10.0.0.0/24
```

## 总结

本章内容看似琐碎，其实很系统。我们要善于总结，不要死记硬背。经过逐渐的学习，相信大家对于Netfilter能够做什么、怎么做已经有很多自己的理解。

下一章，我们将介绍一些高级技巧。

