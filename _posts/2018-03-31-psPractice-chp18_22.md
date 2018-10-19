---
title: PowerShell实战指南 Chapter 18-22
category: powershell
---

# {{ page.title }}

## Chapter 18 变量：一个存放资料的地方

变量名可以包含空格，但是名字必须被花括号包住。

注意单双引号的区别：

![Screen Shot 2018-06-05 at 12.38.13 PM.png]({{ site.url }}/images/powershell/1FADB0665E9B6FE399E41E80C0FAD851.png)

双引号中的变量名会被解析，但是只是发生在形成字符串时。之后即使`$comp`改变，也不影响`$phrase`。

另外，反引号会把`$`取消转义，即不会解析变量。反引号相当于C语言中的`\`，所以

![Screen Shot 2018-06-05 at 12.41.59 PM.png]({{ site.url }}/images/powershell/715EC409353168801FFDE473A79F748B.png)

如上相当于`\n`。

通过`help about_escape`了解更多。

单一变量可以存储多个对象，用逗号隔开：

```powershell
$computers = 'Servcer-R2','Server-R1','localhost'
```

![Screen Shot 2018-06-05 at 12.49.10 PM.png]({{ site.url }}/images/powershell/BC3C39648F27151F31E7ED7572906051.png)

如上图，对元素的访问倒是类似于Python。

修改元素内容：

```powershell
$computers[1] = $computers[1].replace('SERVER', 'CLIENT')
```

如何对多个对象都调用某方法？

```powershell
$computers = $computers | ForEach-Object {$_.ToLower()}
```

![Screen Shot 2018-06-05 at 12.53.10 PM.png]({{ site.url }}/images/powershell/895AAB35AA7EDF272E87C26301ABBA61.png)

在v3及后续版本中，可以直接对包含多个对象的单一变量进行属性或方法的访问：

![Screen Shot 2018-06-05 at 12.55.15 PM.png]({{ site.url }}/images/powershell/6C85804E73354021B4089D29DA09441D.png)

如果在字符串中要解析某个元素，则需要使用双引号和`$()`（即子表达式）：

![Screen Shot 2018-06-05 at 12.58.09 PM.png]({{ site.url }}/images/powershell/3947CA8A04A145A48858F69E15E8D410.png)

有时我们需要指定变量类型，否则如下图：

![Screen Shot 2018-06-05 at 1.00.18 PM.png]({{ site.url }}/images/powershell/62AB49CEF82A9FD05663D62EE01C268B.png)

应该如下：

![Screen Shot 2018-06-05 at 1.01.21 PM.png]({{ site.url }}/images/powershell/4F3D807236F7574BFFF64DAA2060B99C.png)

**练习**

完成以下操作：

- 创建后台作业，从两台计算机中查询`Win32_BIOS`信息
- 作业运行完毕后，将结果存入变量
- 展示变量内容
- 把内容导出到CliXML

![Screen Shot 2018-06-05 at 1.01.21 PM.png]({{ site.url }}/images/powershell/4F3D807236F7574BFFF64DAA2060B99C.png)

![Screen Shot 2018-06-05 at 1.07.31 PM.png]({{ site.url }}/images/powershell/EFED0FC75D8D10428081D7B4D80F1F1F.png)

## Chapter 19 输入和输出

PowerShell的运作方式为

![Screen Shot 2018-06-06 at 3.01.47 PM.png]({{ site.url }}/images/powershell/CE7ADE38458DDBE6500688DC8049B9BF.png)

### Read-Host 

![Screen Shot 2018-06-06 at 2.53.14 PM.png]({{ site.url }}/images/powershell/60CF211FD55D784F284FC61472E32043.png)

注意提示信息的最后被自动加了冒号，另外，输入的信息被放入了管道（与后面的`Write-Host`区别）。

如果希望能够提供一个GUI让用户来输入，则需要直接调用`.Net`框架：

先载入组件：

```powershell
[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
```

再使用：

```powershell
$computername = [Microsoft.VisualBasic.Interaction]::InputBox('Enter a computer name', 'Computer name', 'localhost')
```

效果如下：

![Screen Shot 2018-06-06 at 2.58.20 PM.png]({{ site.url }}/images/powershell/67F272C52F13A74082AB47087C01FD5D.png)

### Write-Host

`Write-Host`的工作原理如下：

![Screen Shot 2018-06-06 at 3.02.11 PM.png]({{ site.url }}/images/powershell/15AFCDA93A8E1ADF9A5F32E58E2C9878.png)

它会绕过管道，直接显示。所以，它还可以控制显示的颜色：

![Screen Shot 2018-06-06 at 3.03.34 PM.png]({{ site.url }}/images/powershell/61EF89D07F12D4664AC5030AD232D5E0.png)

另外还有`Write-Verbose`/`Write-Debug`/`Write-Warning`/`Write-Error`，但是前两者默认不输出，需要修改变量如下：

```powershell
$VerbosePreference = "Continue"
$DebugPreference = "Continue"
```

测试如下：

![Screen Shot 2018-06-06 at 3.15.19 PM.png]({{ site.url }}/images/powershell/55E349EBDBBE027B9F787CD772A43A46.png)

注意，`Write-Error`会把信息写入错误流。

### Write-Output

与`Write-Host`相反，它把对象直接发送给管道。

![Screen Shot 2018-06-06 at 3.12.09 PM.png]({{ site.url }}/images/powershell/7BB80526C416F7855F238B3FF8B3753D.png)

也就是说，你可以在其后加入其他命令，如：

```powershell
Write-Output "Hello" | Where-Object {$_.Length -GT 10}
```

另外，还有一个`Write-Process`用于显示进度条。

## Chapter 20 轻松实现远程控制

**可重用会话**

```powershell
$ad_computer = New-PSSession -ComputerName WIN-F8E9GPVN2N1 -Credential "rambo\administrator"
```

![Screen Shot 2018-06-07 at 4.07.08 PM.png]({{ site.url }}/images/powershell/050563DA9A0C5A2619E353B03C7D5942.png)

查看并使用会话：

![Screen Shot 2018-06-07 at 4.09.31 PM.png]({{ site.url }}/images/powershell/6AC85C8B8B799EBE35D7913C60B47288.png)

不过比较优雅的方式是这样：

```powershell
Get-PSSession -ComputerName WIN-F8E9GPVN2N1 | Enter-PSSession
```

注意，会话会消耗计算机资源。如果不用可以关闭会话：

```powershell
Get-PSSession | Remove-PSSession
# or
$ad_computer | Remove-PSSession
```

会话变量的优势体现在一次性处理多个会话的场景：

```powershell
Invoke-Command -Command {Get-WmiObject -Class Win32_Process} -Session $sessions
```

**隐式远程控制**

它的适用场景是：你需要一些管理模块对远程计算机进行管理。远程计算机上有这些模块，你的本地系统没有且不支持这些模块的安装（如XP或Vista），那么可以通过从远程会话导入命令的手段来达到“在本地添加管理命令”的目的（事实上并未添加，用的还是远程的）。

```powershell
Invoke-Command -Command {Import-Module ActiveDirectory} -Session $ad_computer

Import-PSSession -Session $ad_computer -Module ActiveDirectory -prefix rem
```

![Screen Shot 2018-06-07 at 4.28.30 PM.png]({{ site.url }}/images/powershell/C61113118C09CB77FFB9576694F6DAE0.png)

此时我们查看**当前**（关闭Shell或远程连接后就不存在了）拥有的命令：

![Screen Shot 2018-06-07 at 4.33.28 PM.png]({{ site.url }}/images/powershell/684E17EF297D84224A2484CBD2A1AB48.png)

这些命令在远程计算机上运行，然后把结果（反序列化对象）返回给本地计算机，就好像你直接在远程计算机上操作一样。

**断开会话**

在v3及以后，你需要显式断开会话。且，断开的会话需要你自己去清理。

```powershell
Disconnect-PSSession -Id 4
# re-connect
Get-PSSession -ComputerName Computer2 | Connect-PSSession
```

在`WSMan:\localhost\Shell`下有管理已断开会话的设置项：

![Screen Shot 2018-06-07 at 4.58.30 PM.png]({{ site.url }}/images/powershell/CA1121D48FF14CD81622B672E847AB02.png)

**练习**

- 在Shell中关闭所有已打开连接

```powershell
Get-PSSession | Remove-PSSession
```

- 建立一个到远程计算机的会话存入变量，并利用`Invoke-Command`与`Get-PSSession`命令从远程计算机上获取最近20条安全事件日志条目
- 将`ServerManager`模块的命令由远程计算机导入本地计算机，并使用`rem`作为名词部分前缀

![Screen Shot 2018-06-07 at 5.06.30 PM.png]({{ site.url }}/images/powershell/B3D5A7B857B34C72C327135951673E2C.png)

- 运行刚刚导入的`Get-WindowsFeature`命令

![Screen Shot 2018-06-07 at 5.06.57 PM.png]({{ site.url }}/images/powershell/FCA87A435BD122690A13762A9409966F.png)

- 关闭会话

```powershell
Remove-PSSession -Session $ad_computer
```

## Chapter 21 你把这叫做脚本

```powershell
Get-WmiObject -Class Win32_LogicalDisk -ComputerName localhost -Filter "drivetype=3" |
Sort-Object -Property DeviceID |
Format-Table -Property DeviceID,
@{label='FreeSpace(MB)';expression={$_.FreeSpace / 1MB -as [int]}},
@{label='Size(GB';expression={$_.Size / 1GB -as [int]}},
@{label='%Free';expression={$_.FreeSpace / $_.Size * 100 -as [int]}}
```

![Screen Shot 2018-06-09 at 3.46.02 PM.png]({{ site.url }}/images/powershell/974AEE152A79B379BDE0C8762FF1AA93.png)

如上，在ISE中每一行都可以以逗号或管道操作符结尾。在脚本中最好指定参数名称，方便以后查看。

如下，一个好用的debug技巧是进行部分运行，选中要运行的命令并按`F8`或单击上方的“部分运行”按钮（所以在写脚本的时候把不同命令分行写，方便debug）：

![Screen Shot 2018-06-09 at 3.49.04 PM.png]({{ site.url }}/images/powershell/C546EB6D14040EE2D15DB60AF0311185.png)

推荐按照“动词-名词”这样的格式保存脚本，如上为`Get-DiskInventory.ps1`。

硬编码往往是需要避免的。另外，可以用\`符号把参数每行一个分开：

```powershell
$computername = 'localhost'

Get-WmiObject -Class Win32_LogicalDisk `
    -ComputerName $computername `
    -Filter "drivetype=3" |
Sort-Object -Property DeviceID |
Format-Table -Property DeviceID,
@{label='FreeSpace(MB)';expression={$_.FreeSpace / 1MB -as [int]}},
@{label='Size(GB';expression={$_.Size / 1GB -as [int]}},
@{label='%Free';expression={$_.FreeSpace / $_.Size * 100 -as [int]}}
```

**带参数运行**

```powershell
param(
    $computername = 'localhost',
    $drivetype = 3
)

Get-WmiObject -Class Win32_LogicalDisk `
    -ComputerName $computername `
    -Filter "drivetype=$drivetype" |
Sort-Object -Property DeviceID |
Format-Table -Property DeviceID,
@{label='FreeSpace(MB)';expression={$_.FreeSpace / 1MB -as [int]}},
@{label='Size(GB';expression={$_.Size / 1GB -as [int]}},
@{label='%Free';expression={$_.FreeSpace / $_.Size * 100 -as [int]}}
```

如上。`param()`中的是包含默认值的命命、位置参数：

![Screen Shot 2018-06-09 at 4.08.13 PM.png]({{ site.url }}/images/powershell/FE3E9D4773B370498913DBF46D31DF70.png)

![Screen Shot 2018-06-09 at 4.08.00 PM.png]({{ site.url }}/images/powershell/03ED55B8189027C509E59368F9370245.png)

**添加文档**

```powershell
<#
.SYNOPSIS
Get-DiskInventory retrieves logical disk information from one or
more computers.
.DESCRIPTION
Get-DiskInventory uses WMI to retrieve the Win32_LogicalDisk
instances from one or more computers. It displays each disk's
drive letter, free space, total size, and percentage of free
space.
.PARAMETER computername
The computer name, or names, to query. Default: Localhost.
.PARAMETER drivetype
The drive type to query. See Win32_LogicalDisk documentation
for values. 3 is a fixed disk, and is the default.
.EXAMPLE
Get-DiskInventory -computername SERVER-R2 -drivetype 3
#>

param(
    $computername = 'localhost',
    $drivetype = 3
)

Get-WmiObject -Class Win32_LogicalDisk `
    -ComputerName $computername `
    -Filter "drivetype=$drivetype" |
Sort-Object -Property DeviceID |
Format-Table -Property DeviceID,
@{label='FreeSpace(MB)';expression={$_.FreeSpace / 1MB -as [int]}},
@{label='Size(GB';expression={$_.Size / 1GB -as [int]}},
@{label='%Free';expression={$_.FreeSpace / $_.Size * 100 -as [int]}}
```

如上添加文档，这样别人可以用`help`查看：

![Screen Shot 2018-06-09 at 4.13.44 PM.png]({{ site.url }}/images/powershell/2867A31FD7C341335633112DBA2E4D13.png)

可以通过`help about_comment_based_help`查看更多。

**脚本与管道**

首先来看一个小实验：

我们在Shell中依次执行`Get-Process`和`Get-Service`，得到的为格式化过的结果：

![Screen Shot 2018-06-09 at 8.14.02 PM.png]({{ site.url }}/images/powershell/225FF35F7135196EC82A5A513004A6B6.png)

![Screen Shot 2018-06-09 at 8.14.13 PM.png]({{ site.url }}/images/powershell/61914B80B4C293AF793BB2C1CCA4BE20.png)

上面的详细处理过程其实如下：

![Screen Shot 2018-06-09 at 8.18.10 PM.png]({{ site.url }}/images/powershell/A5FEDF19219F41A99236C735B92D0901.png)

但如果在脚本中像这样连续执行，结果不同：

![Screen Shot 2018-06-09 at 8.15.44 PM.png]({{ site.url }}/images/powershell/5B72AF7BD288801DC38018DDE80348EB.png)

![Screen Shot 2018-06-09 at 8.15.55 PM.png]({{ site.url }}/images/powershell/4B67585380A46B10FEE6F951444B61E4.png)

可以发现，进程的展示结果与之前相同，而服务的则不同。这是因为一个脚本中的所有命令共用一个管道：脚本自身运行的管道。其处理过程如下：

![Screen Shot 2018-06-09 at 8.18.17 PM.png]({{ site.url }}/images/powershell/F22A2426D29FE6253B27F469794AE11A.png)

由于`Process`对象先被放入管道，所以其输出结果很正常。因此，一般来说最好在一个脚本中尽量保持输出对象属于同一类。

**作用域**

作用域是特定类型PowerShell元素的容器，如别名、变量和函数。Shell本身具有最高级的作用域，成为`global scope`，运行脚本时，会在脚本范围创建一个新的`script scope`，其为全局作用域的子集（父子关系）。函数有自己的`private scope`。

![Screen Shot 2018-06-09 at 8.22.51 PM.png]({{ site.url }}/images/powershell/0597B8EF11B93AD9E8D2D8EC34BA51A0.png)

作用域的生命周期持续到作用域的最后一行代码。当你访问域元素时，PowerShell的查找顺序如下：

```
当前域 -(if not found)-> 父作用域 -(if not found)-> ... -(if not found)-> 全局域
```

## Chapter 22 优化可传参脚本

以上一章的示例脚本为起点进行优化：

```powershell
<#
.SYNOPSIS
Get-DiskInventory retrieves logical disk information from one or
more computers.
.DESCRIPTION
Get-DiskInventory uses WMI to retrieve the Win32_LogicalDisk
instances from one or more computers. It displays each disk's
drive letter, free space, total size, and percentage of free
space.
.PARAMETER computername
The computer name, or names, to query. Default: Localhost.
.PARAMETER drivetype
The drive type to query. See Win32_LogicalDisk documentation
for values. 3 is a fixed disk, and is the default.
.EXAMPLE
Get-DiskInventory -computername SERVER-R2 -drivetype 3
#>

param(
    $computername = 'localhost',
    $drivetype = 3
)

Get-WmiObject -Class Win32_LogicalDisk `
    -ComputerName $computername `
    -Filter "drivetype=$drivetype" |
Sort-Object -Property DeviceID |
Select-Object -Property DeviceID,
@{label='FreeSpace(MB)';expression={$_.FreeSpace / 1MB -as [int]}},
@{label='Size(GB';expression={$_.Size / 1GB -as [int]}},
@{label='%Free';expression={$_.FreeSpace / $_.Size * 100 -as [int]}}
```

注意，`Select-Object`替换了`Format-Table`，这样一来用户可以自己决定他需要什么输出，比如CSV：

```powershell
.\Get-DiskInventory.ps1 | Export-Csv disks.csv
```

**添加高级功能**

在注释后、参数前添加

```powershell
<#
...
#>
[CmdletBinding()]
param(
...
)
```

这样一来，我们就启用了几个功能，如下：

- 将参数定义为强制参数

```powershell
param(
    [Parameter(Mandatory=$True, HelpMessage="Enter a computer name to query")]
    [string]$computername = 'localhost',
    
    [int]$drivetype = 3
)
```

如上，如果用户没有给出参数，则PowerShell会提示他输入：

![Screen Shot 2018-06-10 at 3.10.35 PM.png]({{ site.url }}/images/powershell/9F8A9E58F63ABFE89F32052B647EE865.png)

注意，`[Parameter(Mandatory=$True)]`只是`computername`参数的修饰符，不影响`drivetype`。如果你需要提示用户输入`drivetype`，则需要在前面再加一行。

- 添加参数别名

```powershell
param(
    [Parameter(Mandatory=$True, HelpMessage="Enter a computer name to query")]
    [Alias('hostname')]
    [string]$computername = 'localhost',
    
    [int]$drivetype = 3
)
```

- 验证输入的参数

```powershell
param(
    [Parameter(Mandatory=$True, HelpMessage="Enter a computer name to query")]
    [Alias('hostname')]
    [string]$computername = 'localhost',
    
    [ValidateSet(2,3)]
    [int]$drivetype = 3
)
```

![Screen Shot 2018-06-10 at 3.16.23 PM.png]({{ site.url }}/images/powershell/20A70E8327F45E091C6B3C23731C6E09.png)

参看`help about_functions_advanced_parameters`获取更多信息。

- 添加详细输出

```powershell
# ...
param(
    [Parameter(Mandatory=$True, HelpMessage="Enter a computer name to query")]
    [Alias('hostname')]
    [string]$computername = 'localhost',
    
    [ValidateSet(2,3)]
    [int]$drivetype = 3
)
Write-Verbose "Connecting to $computername"
Write-Verbose "Looking for drive type $drivetype"
Get-WmiObject -Class Win32_LogicalDisk `
    -ComputerName $computername `
    -Filter "drivetype=$drivetype" |
Sort-Object -Property DeviceID |
Select-Object -Property DeviceID,
@{label='FreeSpace(MB)';expression={$_.FreeSpace / 1MB -as [int]}},
@{label='Size(GB';expression={$_.Size / 1GB -as [int]}},
@{label='%Free';expression={$_.FreeSpace / $_.Size * 100 -as [int]}}
Write-Verbose "Finished running command"
```

![Screen Shot 2018-06-10 at 3.20.56 PM.png]({{ site.url }}/images/powershell/F791F202788FD6A53632008B2304DAD3.png)

注意，`[CmdletBinding()]`会激活脚本中所有命令的详细输出（同时，你不必修改`$VerbosePreference`变量，参见[实战指南 Chapter 19 输入和输出](quiver:///notes/C470D5B5-3EB4-47A8-9755-2F9CFEB378BC)）。

**练习**

将

```powershell
Get-WmiObject Win32_networkadapter -ComputerName localhost |
where {$_.PhysicalAdapter} |
Select-Object MACAddress,AdapterType,DeviceID,Name,Speed
```

改成高级脚本。结果如下：

```powershell
<#
.SYNOPSIS
Get-PhysicalAdapters.ps1 returns physical adapters on the specified computer
.PARAMETER computername
The computer name, or names, to query. Default: Localhost.
.EXAMPLE
Get-PhysicalAdapters.ps1 -computername localhost
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$True, HelpMessage="Enter a computer name to query")]
    [Alias('hostname')]
    [string]$computername
)

Write-Verbose "[*] wait a moment..."
Get-WmiObject Win32_networkadapter -ComputerName $computername |
where {$_.PhysicalAdapter} |
Select-Object MACAddress,AdapterType,DeviceID,Name,Speed
Write-Verbose "$computername done."
```

![Screen Shot 2018-06-10 at 3.30.58 PM.png]({{ site.url }}/images/powershell/746916551ED7694DA88DB588237AE246.png)

**总结**

学习PowerShell至此大概有一个月，我从这本书中学到的除了技术，还有别的东西：不急不躁的学习态度，步步为营、稳扎稳打、不贪心的学习进程。每天学一点点，就好像是吃点心一般快乐。我以前有过很多次贪心的经历：学习，只是为了证明自己学过这本书，有时根本不去理解作者在书中的思路，也没有耐心去解决那一个个巧妙设置的问题，只是为了赶快学完，让自己的水平有所提高。然而这样其实只是求得心理安慰：我研究过多少本书，我有多厉害，而事实上收获甚少。那样每天都给自己灌很多知识，而不是技术、方法或者思想，最终只能是消化不良。那样每天灌输的过程必然也是充满煎熬的，完全不似吃点心。当然，当年学习Linux和汇编的时候每天的进度也很快，但是却不觉得煎熬和难受。那是因为当时的自己是真的急切地渴望学习，因为当时自己真的为它们着迷。一旦进入那种状态，很自然地就会废寝忘食地学习。我认为，那种学习过程和这种每天一点点的过程都是可取的，主要还是看自己对于眼前学习的东西是否有那种痴迷的感觉。

总之，不要急。博学而笃志，切问而近思。但行好事，莫问前程。

静水流深吧。