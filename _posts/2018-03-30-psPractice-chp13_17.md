---
title: PowerShell实战指南 Chapter 13-17
category: powershell
---

# {{ page.title }}

## Chapter 13 远程处理：一对一及一对多

PowerShell的远程处理类似于Telnet，即命令在远程主机上运行，结果返回到本地。但是它采用的通信协议不同：WS-MAN (Web Services for Management)，基于HTTP或`HTTPS`，其基于的后台服务为Windows远程管理组件`WinRM`（在有的系统中该服务处于禁用状态）。PowerShell将输出对象序列化到XML中，通过网络传输，到达本地计算机后再反序列化为PowerShell中的对象。

![Screen Shot 2018-06-11 at 12.53.59 PM.png]({{ site.url }}/images/powershell/EE53BD9231D64F9D3A1BC65371B4A28A.png)

远程处理在域环境中实现起来较容易。如果需要跨域，参看

```powershell
help About_Remote_TroubleShooting
```

本章使用的环境为第七章提到的环境。第七章提到的主机为域控制器，域中有一台Win7。本章的实验为WIn7通过远程管理对域控制器进行操作。

Win7在域中的相关信息如下：

![Screen Shot 2018-05-27 at 3.18.40 PM.png]({{ site.url }}/images/powershell/6438E22C8BA27E4C82DB7010560F5726.png)

域控制器的相关信息如下：

![Screen Shot 2018-05-27 at 3.19.28 PM.png]({{ site.url }}/images/powershell/BA6E5E2A6FB7536B77D1DC5CFC076435.png)

首先要在域控制器上一个以管理员权限运行的PowerShell中执行`Enable-PSRemoting`，来创建一个WinRM监听器：

![Screen Shot 2018-05-27 at 2.41.48 PM.png]({{ site.url }}/images/powershell/F6193C0D79D2F2CD34363AFC95D85822.png)

**一对一场景**

你在远程计算机执行的任何命令都依赖于你的凭据（这一点通过`Kerberos`实现）。另外，远程计算机的执行策略会限制某些脚本的运行。如果你使用的账号在远程计算机上没有管理员权限，那么你需要使用`Enter-PSSession`或者`Invoke-Command`命令的`-Credential`参数去指定一个拥有管理员权限的账号。

```powershell
Enter-PSSession -ComputerName WIN-F8E9GPVN2N1 -Credential "rambo\administrator"
```

![Screen Shot 2018-05-27 at 3.20.38 PM.png]({{ site.url }}/images/powershell/6529405F4AD401560C82CD3CF3AF03E5.png)

成功获得一个Shell。我们执行一些操作：

![Screen Shot 2018-05-27 at 3.21.59 PM.png]({{ site.url }}/images/powershell/3A154BB7BEFE4A25DB9BCDAF71BF141A.png)

**一对多场景**

例如：

```powershell
Invoke-Command -ComputerName xx1,xx2,xx3 -Command {Get-EventLog Security -Newest 200 | where {$_.EventID -eq 1212}}
```

默认情况下，一次最多能与32台远程计算机通信。超过32台则会形成一个队列，依次执行。

![Screen Shot 2018-05-27 at 3.26.35 PM.png]({{ site.url }}/images/powershell/C55D427DE6C2E96B903DD0F86C7D65CD.png)

（上面我们重复了对同一台计算机的命令来模拟一对多）

当然，我们也可以把计算机名放在文本文件中，通过`Get-Content`提取；亦或直接从`Get-ADComputer`中提取，这会用到我们前面学到的`Select-Object -Expand`。

注意：

```powershell
Invoke-Command -ComputerName xxx -Command {Get-EventLog -Newest 100}
```

上面这条命令和

```powershell
Get-EventLog Seucurity -Newest 100 -ComputerName xxx
```

得到的结果差不多相同，但命令执行方式存在很大不同。下面的命令不通过`WinRM`实现，且`-ComputerName`提到的计算机会被顺序串行访问，而不是并发访问。一般来说，`Invoke-Command`更有效率。

比较下面两条命令：

```powershell
Invoke-Command -ComputerName xxx -Command {Get-Process -Name Notepad} | Stop-Process
```

```powershell
Invoke-Command -ComputerName xxx -Command {Get-Process -Name Notepad | Stop-Process}
```

注意大括号的位置。很明显，第二条才是我们希望的。

另外，通过远程处理获得的反序列化对象也与本地的不同，缺少了很多方法：

![Screen Shot 2018-05-27 at 3.06.18 PM.png]({{ site.url }}/images/powershell/231EED330CB081718BF3AFED53E05282.png)

**练习**

- 创建针对一对一连接并打开`notepad.exe`，会发生什么？

如果直接`notepad.exe`打开，则命令行会挂在那里，直到我按了`CTRL-C`，也可以用`Start-Process notepad.exe`，这样命令行不会挂起。这两种方法的确能打开记事本，在远程计算机的任务管理器中也能看到进程，但记事本本身却并不出现在远程计算机的桌面上！

## Chapter 14 Windows管理规范

本章使用第七章环境。

WMI即`Windows Management Instrumentation`，Windows管理规范。它可能是微软提供给管理员使用的最优秀的工具之一。典型的Windows计算机包含数万个管理信息，WMI会把这些收集并整理成尽量通俗易懂的信息。

![Screen Shot 2018-05-27 at 6.37.44 PM.png]({{ site.url }}/images/powershell/FF0F1A2A5C4FB97F9666CF3AF21D99BF.png)

在最顶层，WMI被组织为命名空间。在`WMI控件`右键点击“属性”，查看“安全”选项卡可以看到其命名空间。

由于WMI命名空间在服务器与在客户机上内容不尽相同，所以下面再展示一下Win7上的WMI命名空间：

![Screen Shot 2018-05-27 at 6.46.37 PM.png]({{ site.url }}/images/powershell/8338ABC0743A480AB64FB2F1530D1F14.png)

举例来说，`root/CIMv2`包含了所有Windows操作系统和计算机硬件信息；而`root/MicrosoftDNS`包含了所有关于DNS服务器的信息。在客户机上，`root/SecurityCenter`包含了关于防火墙、杀毒软件和反流氓软件工具的信息（如上图所示，新版本的Windows使用`root/SecurityCenter2`代替）。

在命名空间中，WMI被分成一系列的类，每个类是可用于WMI查询的管理单元。比如在`root/CIMv2`中的`Win32_LogicalDisk`用于保存逻辑磁盘的信息（但是即使计算机上存在某个类，也不代表计算机实际上安装了对应组件）。

我们可以试着查询一下：

![Screen Shot 2018-05-27 at 6.52.51 PM.png]({{ site.url }}/images/powershell/136A927C70B34352280067341E15F3FF.png)

![Screen Shot 2018-05-27 at 6.53.51 PM.png]({{ site.url }}/images/powershell/6A1264AD09E27B10EDD8559115688792.png)

![Screen Shot 2018-05-27 at 6.54.55 PM.png]({{ site.url }}/images/powershell/91CA96EBF0549BE55BAD9A740840848E.png)

可以看到，类的一个实例代表一个现实世界的事物。比如，机器上的确有两个硬盘、一个BIOS、许多后台服务。

注意，在`root/CIMv2`中的类名往往是`Win32_`或`CIM_`开头（`CIM`即`Common Information Model`的缩写，它是WMI建立的标准）。但是在其他命名空间中，这些类名前缀很少出现。

由于不同命名空间中的类可能重名，所以在引用类时，注意带上命名空间。

所有这些实例、类等被称为WMI Repository。

我觉得从上面的操作看，WMI和PowerShell很像。

在`root/CIMv2`中，有些类提供了修改设置的方法（因为属性是只读的，所以你必须使用这些方法来改），但是如果对应方法不存在，你就无法通过WMI来更改。（IIS团队放弃了WMI作为管理接口，转向了PowerShell的一个PSProvider，有趣）

WMI不支持类搜索，同时许多类并没有相关文档......

在PowerShell v3及后续版本中，有大量`CIM`命令。它们往往都是对WMI的某部分做了封装，从而隐藏底层WMI的复杂性。

**探索WMI**

使用来自Sapien的WMi Explorer工具（还得注册，然后免费试用45天）：

![Screen Shot 2018-05-27 at 7.27.17 PM.png]({{ site.url }}/images/powershell/A7B59B178D820D58B61241F647034581.png)

让我们来试一下！假设我们现在需要查询计算机桌面图标间距的设置。它肯定和桌面有关，而且是操作系统核心部分。最终，我们在`root/CIMv2`找到这个`Win32_Desktop`类，并找到其`IconSpacing`属性：

![Screen Shot 2018-05-27 at 7.35.53 PM.png]({{ site.url }}/images/powershell/66BFF2139EC79A9D3B8C9B4316C656A6.png)

![Screen Shot 2018-05-27 at 7.36.13 PM.png]({{ site.url }}/images/powershell/BE4D38D6CC51EFA951EFA4E7AD4770AA.png)

这个工具的强大之处在于，它还提供了具体的操作命令：

![Screen Shot 2018-05-27 at 7.36.54 PM.png]({{ site.url }}/images/powershell/4DD33089045ED5838EE7354B5F726FD2.png)

当然，我们也可以通过PowerShell来查找：

![Screen Shot 2018-05-27 at 7.41.08 PM.png]({{ site.url }}/images/powershell/617B42990411E8CCB874524A6DA1A859.png)

注：以`CIM_`开头的通常为基本类，不能直接使用。`Win_32`开头的则是Windows特有的，且仅用于特定命名空间。

在PowerShell v3及后续版本中，有两种与WMI交互的方式：

- WMI Cmdlets

如`Get-WmiObject`和`Invoke-WmiMethod`。它们是遗留命令（且它们与RPC交互，这需要防火墙的支持）。

- CMI Cmdlets

如`Get-CimInstance`和`Invoke-CimMethod`。它们是新版命令，通过`WS-MAN`交互：

![Screen Shot 2018-05-27 at 7.45.52 PM.png]({{ site.url }}/images/powershell/232520A0F464712BA1608CAB78E3AE1C.png)

**使用Get-WmiObject**

常见的用法如下：

```powershell
Get-WmiObject -Namespace root\cimv2 -list
Get-WmiObject -Namespace root\cimv2 -Classname Win32_Desktop
```

![Screen Shot 2018-05-27 at 7.55.38 PM.png]({{ site.url }}/images/powershell/4C55575051767B9394F6269A7DE3A5F0.png)

我们还可以在上一章用过的Win7上远程查询域控制器的WMI：

![Screen Shot 2018-05-27 at 7.54.18 PM.png]({{ site.url }}/images/powershell/4E0A17FC822626DF93B173A13EB7351E.png)

可以看到，在域控制器本地执行命令给出的结果中展示的属性只有5个，而远程获取到的却是全部，这是为什么呢？这就涉及到[Chapter 10 格式化及如何正确使用](quiver:///notes/504B51DD-E016-4655-B4CB-C2FD9728FC43)学过的内容了。

![Screen Shot 2018-05-27 at 7.58.03 PM.png]({{ site.url }}/images/powershell/35443E59D4A0879A4DEFAA83422360E1.png)

可以在这个命令中使用`-Filter`，但规则很麻烦。暂不学习它。

**使用Get-CimInstance**

它的用法与`Get-WmiObject`类似，但不存在`-List`参数，而是又一个独立命令`Get-Cimclass -Namespace`来获取类列表。它也没有`-Credential`参数，所以也许你需要用到[Chapter 13 远程处理：一对一及一对多](quiver:///notes/CEC8AF22-D17C-484B-A9BA-4E2C1FF0A922)中的`Invoke-Command`。

在本章开头已经展示过一些这个命令的用法，这里不再展示。

最后请注意，WMI的筛选语法和PowerShell是有差异的。

**练习**

- What class could be used to view the current IP address of a network adapter? Does the class have any methods that could be used to release a DHCP lease? (Hint: network is a good keyword here.)

![Screen Shot 2018-05-27 at 8.23.05 PM.png]({{ site.url }}/images/powershell/DA538F5E81996883C3DD3695A427E8F1.png)

![Screen Shot 2018-05-27 at 8.37.49 PM.png]({{ site.url }}/images/powershell/D5ACBA10258C0861DF89D75B9760E6C0.png)

也可以直接用Cmdlet去获取IP，更方便。不过操作过程中有个有意思的地方：

![Screen Shot 2018-05-27 at 8.53.55 PM.png]({{ site.url }}/images/powershell/275319A617C4C9465FAC0F30E8104A6B.png)

![Screen Shot 2018-05-27 at 8.53.45 PM.png]({{ site.url }}/images/powershell/0AC63B1D073B9A276D9D0A1C6E60003D.png)

我需要进行两遍`expand`过滤才能拿到值。

- Create a table that shows a computer name, operating system build number, operating system description (caption), and BIOS serial number. (Hint: you’ve seen this technique, but you’ll need to reverse it a bit and query the OS class first, then query the BIOS second).

```powershell
Get-Ciminstance win32_operatingsystem | 
Select BuildNumber,Caption,@{l='Computername';e={$_.CSName}},@{l='BIOSSerialNumber';e={(get-ciminstance win32_bios).serialnumber  }} | 
ft -auto
```

![Screen Shot 2018-05-27 at 8.33.42 PM.png]({{ site.url }}/images/powershell/8C0DB98AE6F150AF714E3CC26D1EFE26.png)

- Display a list of services, including their current status, their start mode, and the account they use to log on.

```powershell
get-ciminstance win32_service | Select Name,State,StartMode,StartName
```

![Screen Shot 2018-05-27 at 8.35.17 PM.png]({{ site.url }}/images/powershell/F6A8D2B5CFF78A440D02033311A20FC0.png)

- Can you find a class that will display a list of installed software products? Do you consider the resulting list to be complete?

```powershell
get-wmiobject -list *product
```

![Screen Shot 2018-05-27 at 8.35.52 PM.png]({{ site.url }}/images/powershell/74E6479BCD6F2D8B7C97EF5A7ABA786C.png)

no.

## Chapter 15 多任务后台作业

同步（前台）与异步（后台）的差异：

- 同步下可以响应输入请求，异步如果遇到输入请求则会停止执行
- 同步下遇到错误可以立即查看信息，异步需要通过其他手段获取
- 异步下必须等待命令结束才能获取缓存的执行结果

后台任务又被称为job。

**本地作业**

```powershell
Start-Job -ScriptBlock {dir}
```

![Screen Shot 2018-05-30 at 9.04.39 AM.png]({{ site.url }}/images/powershell/DC2D710BCA5380BEFAA3094FF9E057E7.png)

注意ID的变化，每次递增2，这是因为每个作业至少都包含一个子作业。267的子作业ID为268。

本地作业也依赖远程处理系统，如果远程处理系统未启用，则无法创建本地作业。

**WMI作业**

[实战指南 Chapter 14 Windows管理规范](quiver:///notes/3B2F9033-1530-47C2-80D1-87662B7E636B)提到，`Get-WmiObject`可以与一台或多台远程计算机连接。它以串行方式实现。如果计算机名称过多，则时间会长，所以我们需要把它移至后台。

```powershell
Get-WmiObject Win32_OperatingSystem -ComputerName (hostname) -AsJob
```

![Screen Shot 2018-05-30 at 9.11.03 AM.png]({{ site.url }}/images/powershell/6C0E7E6EF0E5966A663A81E5A0ACCD81.png)

该命令会针对每个指定的计算机创建一个子作业。

通过`Get-Command -ParameterName AsJob`可以发现相当多的命令都支持`-AsJob`参数。

![Screen Shot 2018-05-30 at 9.13.13 AM.png]({{ site.url }}/images/powershell/9C29A4F212900FAACA8BEE83E07B817E.png)

**远程处理作业**

通过`Invoke-Command`进行。其优点在于并行，这一点我们在之前已经讨论过。

```powershell
Invoke-Command -Command {Get-Process} -ComputerName (hostname) -AsJob -JobName MyRemoteJob
```

![Screen Shot 2018-05-30 at 9.16.44 AM.png]({{ site.url }}/images/powershell/DE1F7CB634356F337092251F6E2EC03E.png)

**获取作业执行结果**

```powershell
Get-Job
Get-Job -Id 263 | Format-List *
```

![Screen Shot 2018-05-30 at 9.18.30 AM.png]({{ site.url }}/images/powershell/48D2913BB90E1B5FA1D7C95D43A8578C.png)

从上图可以看到`ChildJobs`的即`Job264`。

关于获取执行结果：

- 必须指定ID，名称或通过`Get-Job`来配合管道指定对象
- 父作业的结果，它包含所有子作业的结果
- 正常情况下，获取一个作业的结果后，其作业缓存会被清除，无法再次获取。除非使用参数`-Keep`
- 作业返回的结果可能是反序列化的对象（即不包含可用于修改的方法）
- 如果作业失败，其失败原因会被记录在结果中

![Screen Shot 2018-05-30 at 9.22.59 AM.png]({{ site.url }}/images/powershell/58C33124AD296582E674620E8F5D0819.png)

![Screen Shot 2018-05-30 at 9.23.50 AM.png]({{ site.url }}/images/powershell/C90B6F0E86B1BC1D895205710A3D107B.png)

注意作业263的`HasMoreData`变成了`False`，而作业265却没有。

另外，注意作业263，我们的`pwd`一直是`C:\`，而它却是在`C:\Users\Administrator\Documents`执行的。所以当初如果你希望获取`pwd`下的列表，就应该手动指定：

```powershell
Start-Job -ScriptBlock {dir (pwd)}
```

作业对象通过管道传输的例子：

```powershell
Receive-Job -Name MyRemoteJob | Sort-Object PsComputerName | Format-Table -GroupBy ComputerName
```

![Screen Shot 2018-05-30 at 9.27.49 AM.png]({{ site.url }}/images/powershell/7D89BAEFDE6C8159A802B5F42576797F.png)

**子作业**

![Screen Shot 2018-05-30 at 9.30.30 AM.png]({{ site.url }}/images/powershell/5544FBC0117DA898F7A6FA899153A4D1.png)

可以发现，子作业的`ChildJobs`项是空的。

你可以用

```powershell
Get-Job -Id 271 | Select-Object -ExpandProperty ChildJobs
```

来查看所有子作业。当然，也可以用`Receive-Job`来获取某个子作业的结果。

**其他管理命令**

- Remove-Job
- Stop-Job
- Wait-Job

当使用脚本开启作业时，如果你希望在作业结束后脚本继续运行，可以用`Wait-Job`。

**调度作业**

这一类型的作业我们在以前提到过类似的：[实战指南 Chapter 12 学以致用](quiver:///notes/FCD0628A-041F-4984-A92E-9245A8C9B2FC)，只不过这里变成了`Register-ScheduledJob`。关于其用法，可以参考后面的第二个练习。

**注意**

不要混用前三种作业方式！

**练习**

- 后台作业，寻找`C:\`上所有的PowerShell脚本

```powershell
Start-Job -Name FindPS1 {Get-ChildItem -Recurse -Name "*.ps1"  -Path "C:\"}
```

![Screen Shot 2018-05-30 at 9.43.46 AM.png]({{ site.url }}/images/powershell/028BB93945342B9677AFC06BB5D9317E.png)

- 如何在远程计算机上运行上一个任务中的命令？

```powershell
Invoke-Command -ComputerName (hostname) -Command {Get-ChildItem -Path "C:\" -Name "*.ps1" -Recurse} -AsJob
```

- 创建一个后台作业，在每周一到周五早六点运行，获取计算机系统事件日志中最近的25条错误记录

```powershell
Register-ScheduledJob -Name DailyError -ScriptBlock {Get-EventLog -Newest 25 -EntryType Error -LogName * | Export-Clixml (Get-Date | Out-String) + ".xml"} -Trigger (New-JobTrigger -Daily -At 6am)
```

我们可以按如下方式清除前面的作业命令：

```powershell
Unregister-ScheduledJob -id 3
```

## Chapter 16 同时处理多个对象

以往，对于大量管理的自动化方式都是`for each`枚举。事实上，PowerShell提供了三种不同的方式。

**首选：“批处理”Cmdlet**

我们已经见到过，比如

```powershell
Get-Service | Stop-Service
```

它默认会对管道内的所有对象做同样的事情。再比如，我们希望改变三个服务的启动模式，VBScript的方式如下：

```VBScript
For Each varService in colServices
    varService.ChangeStartMode("Automatic")
Next
```

而在PowerShell中：

```powershell
Get-Service -Name BITS,Spooler,W32Time | Set-Service -Startuptype Automatic
```

你甚至可以对多台计算机同时进行操作。

你可以使用`-PassThru`参数来输出结果，否则可能你看不到更改会不安心（下图的第一次尝试是没有结果输出的）：

![Screen Shot 2018-05-31 at 5.40.10 PM.png]({{ site.url }}/images/powershell/7F2D5DBFD5CFF628A5AD9CA3D8C328EE.png)

**调用WMI**

有些操作无法通过Cmdlet完成，其中的部分可以通过WMI完成。比如，我们希望对计算机上所有的Intel网卡启用DHCP（不包含虚拟网卡或其他网卡）。

我们首先查询网卡，发现有一个

```powershell
Get-WmiObject win32_networkadapterconfiguration -filter "description like '%intel%'"
```

![Screen Shot 2018-05-31 at 5.45.07 PM.png]({{ site.url }}/images/powershell/9A6340330AFDA15CB6D54522B75D8F7C.png)

我们看一下对象本身是否包含了可以启用DHCP的方法：

```powershell
Get-WmiObject win32_networkadapterconfiguration -filter "description like '%intel%'" | gm
```

![Screen Shot 2018-05-31 at 5.45.50 PM.png]({{ site.url }}/images/powershell/B1D8852C870446AD352E01BDD65966C6.png)

OK，存在。那么我们就需要调用该方法：

```powershell
Get-WmiObject win32_networkadapterconfiguration -filter "description like '%intel%'" | Invoke-WmiMethod -Name enabledhcp
```

![Screen Shot 2018-05-31 at 5.47.36 PM.png]({{ site.url }}/images/powershell/9B2B333A5AFF07C0F70DE93B814E3686.png)

测试的计算机上只有一个Intel网卡，但事实上这种WMI处理方式是可以处理多个对象的。

“如果你可以使用`Get-WmiObject`获取对象，就也能够用`Invoke-WmiObject`调用它的方法。”

当然，你也可以使用“新命令”：

```powershell
Get-CimInstance -classname win32_networkadapterconfiguration -filter "description like '%intel%'" | Invoke-CimMethod -Name enabledhcp
```

WMI需要难以穿透防火墙的RPC通信，但WMI能够适用于老计算机。

另外，在新机器上，`Get-Command *Set-Net*`系列命令已经足够简单强大。

**后备计划：枚举对象**

当你不得不这么做的时候，你应该知道怎么做。

其用法如下：

```powershell
Get-Service -Name *vm* | ForEach-Object -Process {Set-Service -StartupType Automatic -InputObject $_ -PassThru}
```

![Screen Shot 2018-05-31 at 5.59.49 PM.png]({{ site.url }}/images/powershell/99CFA40EDC1F241272CF6FF863251EFD.png)

当然，上面的例子并不恰当，因为并不是必须用枚举。这里只是为了展示其用法。

注意，`%`是`ForEach-Object`的别名。

**总结**

下面几种方法其功能是完全相同的：

```powershell
Get-Service -Name *B* | Stop-Service
Get-Service -Name *B* | ForEach-Object {$_.Stop()}
Get-WmiObject Win32_Service -filter "name LIKE '%B%'" | Invoke-WmiMethod -name StopService
Get-WmiObject Win32_Service -filter "name LIKE '%B%'" | ForEach-Object {$_.StopService()}
Stop-Service -name *B*
```

如果你获取到的对象只有方法，而没有对应的Cmdlet来完成工作，那么你可能需要`ForEach-Object`，对象无法被通过管道传递给一个方法。

记住，可以用`Get-Member`查看对象的方法。

**练习**

- 写至少4个命令，结束所有notepad进程

```powershell
Get-Process -Name "notepad" | Stop-Process
Get-Process -Name "notepad" | ForEach-Object -Process {$_.Kill()}
Get-WmiObject -Class Win32_process -Filter "name like '%notepad%'" | Invoke-WmiMethod -Name terminate
Get-WmiObject -Class Win32_process -Filter "name like '%notepad%'" | ForEach-Object -Process {$_.terminate()}
Stop-Process -Name *notepad*
```

## Chapter 17 安全警报

- PowerShell不会给处理的对象额外权限（它给的最大权限也就是你使用的当前权限）
- PowerShell无法绕过既有的权限限制
- 通过脚本封装技术，如SAPIEM PrimalScript可以将用户凭据一起打包进exe文件，这可以使得用户在该凭据的权限下运行某些命令
- PoweShell中的安全措施主要是“执行策略”和“代码签名”

**执行策略**

默认是`Restricted`，阻止脚本运行。

修改的方法：

- Set-ExecutionPolicy

![Screen Shot 2018-05-31 at 8.15.11 PM.png]({{ site.url }}/images/powershell/2629FB6D6DF1B5B58A0CDCC80722A680.png)

- `gpedit.msc`

![Screen Shot 2018-05-31 at 8.19.05 PM.png]({{ site.url }}/images/powershell/EBE0387B47F6D6EFCAECE5F7DFBBE94C.png)

组策略会覆盖掉`Set-ExecutionPolicy`的设置：

![Screen Shot 2018-05-31 at 8.19.49 PM.png]({{ site.url }}/images/powershell/695E63E56959DF277977FDECD961180C.png)

- 手动运行PowerShell时给出`-ExecutionPolicy`的命令行参数

![Screen Shot 2018-05-31 at 8.25.27 PM.png]({{ site.url }}/images/powershell/9A5492D0E239DCDE11284FB6AEAD62B3.png)

![Screen Shot 2018-05-31 at 8.26.37 PM.png]({{ site.url }}/images/powershell/01C4DA899CD62B44C693468848EDAAA7.png)

可以发现，这种方式的修改会暂时覆盖组策略的设定。

`Restricted`

默认选项。除部分微软提供的配置PowerShell的默认脚本（其带有微软的数字签名）外，不允许执行其他脚本。

`AllSigned`

经过受信任的CA设计的数字证书签名后的任意脚本可执行。

`RemoteSigned`

可以运行本地人和脚本，以及受信任CA签名的远程脚本（远端计算机上的脚本，往往通过UNC方式访问）。在某些版本的Windows中，会区分网络路径与UNC路径，此时，本地网络中的UNC不被认为是“远程”。

`Unrestricted`

所有脚本都可执行。

`Bypass`

针对开发人员。它会忽略已经配置好的执行策略。

微软建议在执行脚本时使用`RemoteSigned`。

**数字签名**

```
<!-- SIG # Begin signature block -->
<!-- MIIXXAYJKoZIhvcNAQcCoIIXTTCCF0kCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB -->
<!-- gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR -->
<!-- AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUquHIxmxcLxkCFtxrNl0NLF4B -->
<!-- LhmgghIxMIIEYDCCA0ygAwIBAgIKLqsR3FD/XJ3LwDAJBgUrDgMCHQUAMHAxKzAp -->
<!-- BgNVBAsTIkNvcHlyaWdodCAoYykgMTk5NyBNaWNyb3NvZnQgQ29ycC4xHjAcBgNV -->
...
```

签名包含两部分：

- 签名的公司或组织
- 脚本的加密副本

签名需要由CA颁发的证书。应当在IE浏览器的选项中配置对CA的信任。信任一个CA意味着信任其颁发的所有证书。

使用`Set-AuthenticodeSignature`对脚本签名。可以通过`help about_signing`查看更多信息（可以查询如何获取以及使用`MakeCert.exe`制作自己的本地安全证书）。

处理流程如下：

![Screen Shot 2018-05-31 at 8.45.07 PM.png]({{ site.url }}/images/powershell/5A187FCA85C67D1EBCC3C01A7A63AC95.png)

**其他措施**

- 双击不会运行`.ps1`
- 在命令行中要执行需要输入`.\test`而非`test`