---
title:  PowerShell实战指南 Chapter 3-7
category: powershell
---

# {{ page.title }}

> 你说彼岸灯火，心之所向；后来渔舟晚唱，烟雨彷徨。

## Chapter 3 使用帮助系统

由于其他平台上的PowerShell功能没有Windows上完整，所以在未加特别说明的情况下，后面的截图等均基于Windows平台。

系统版本：

![Screen Shot 2018-05-16 at 3.23.13 PM.png]({{ site.url }}/images/powershell/E6CE02CF92AA682EE11B8026C14D1B76.png)

PowerShell版本：

![Screen Shot 2018-05-16 at 3.21.20 PM.png]({{ site.url }}/images/powershell/1B13783F07CD663BC08630643629F9E5.png)

- 输入参数名时只需输入能区分它的前缀即可
- 可选参数：参数名和参数值均在中括号内
- 必选参数
- 定位参数：参数名在中括号内，而参数值在小括号内（参数值必选），不必输入参数名，参数值的位置正确即可

建议刚开始一直输入参数名。

先执行括号里的命令：

```powershell
Get-EventLog Application -computer (Get-Content names.txt)
```

```powershell
# about 主题也有很多信息
help about*
# 如查看关于数组的内容
help Arrays
help about_core_commands

# 可以帮助查找有哪些可能有用的命令，比如找关于进程的
Get-Command *Process*
```

像下面这样的语法描述，即这个命令适应三种不同的语法规则（参数组合）。你输入的命令应该符合其中一种：

![Screen Shot 2018-05-21 at 3.56.08 PM.png]({{ site.url }}/images/powershell/CE5EBD41AC1BB06B30DB3F64A3EF4135.png)

## Chapter 4 运行命令

- Cmdlet 是原生PowerShell命令行工具
- 函数与其类似，但不是以.Net编写，而是以PowerShell自己的脚本语言编写
- 工作流是嵌入PowerShell的工作流执行系统的一类特殊函数
- 应用程序是任意类型的外部可执行程序（原cmd命令基本都可用）

`Get-Verb`查看可用动词：

```
PS /Users/rambo> Get-Verb
Enable      e           Lifecycle      Configures a resource to an available...
Verb        AliasPrefix Group          Description
----        ----------- -----          -----------
Add         a           Common         Adds a resource to a container, or attaches an item to another item
Clear       cl          Common         Removes all the resources from a container but does not delete the container
Close       cs          Common         Changes the state of a resource to make it inaccessible, unavailable, or unusable
Copy        cp          Common         Copies a resource to another name or to another container
Enter       et          Common         Specifies an action that allows the user to move into a resource
Exit        ex          Common         Sets the current environment or context to the most recently used context
Find        fd          Common         Looks for an object in a container that is unknown, implied, optional, or specified
Format      f           Common         Arranges objects in a specified form or layout
Get         g           Common         Specifies an action that retrieves a resource
...
```

PowerShell允许开发人员自己命名名词。

使用`New-Alias`创建自定义别名，其生命周期为当前Shell。所以如果以后要使用，则需要`Export-Alias`。

`Show-Command Get-Process`以GUI方式显示命令的用法：

![Screen Shot 2018-05-14 at 10.21.30 PM.png]({{ site.url }}/images/powershell/C7B44A94071D1E49D66714FFA094EDB6.png)

- 显示最新的100个应用程序日志

```powershell
Get-Eventlog -LogName Application -Newest 100
```

## Chapter 5 使用提供程序

这一章的内容较为抽象。简略来说，**文件系统、环境变量、PowerShell本身的变量、PowerShell的函数等等**这些东西被抽象成`Drives`，而`PSProvider`作为访问这些数据介质的适配器。它向`PSDrive`提供服务。用户则使用`Cmdlet`去操作`PSDrive`呈现的数据。

我画了张图来表达自己对上面这些概念的理解（不一定对）：

![Screen Shot 2018-05-16 at 3.38.03 PM.png]({{ site.url }}/images/powershell/16C161CB13ACCAFE42B8E9A6FAD02773.png)

对于数据介质的一个更高级的抽象是“项”（Item）。无论文件系统中的文件、文件夹，还是注册表中的项，在PowerShell都被视为“项”。（注意，注册表和文件系统具有相同的分层结构）这样一来，为数据的访问和操作提供了统一的术语。而相关的`Cmdlet`也往往是包含`Item`字符的：

`Get-Command -Noun *Item*`

![Screen Shot 2018-05-16 at 3.17.36 PM.png]({{ site.url }}/images/powershell/C1E3FDCB2247C21867CD91DE8EE45B3C.png)

所以，在PowerShell的`cd`或者`Set-Location`具有了更广泛的含义，它不仅仅是像传统命令行或Bash那样切换工作目录，甚至可以从文件系统切换到注册表中。

一般每个项都有其属性。如文件夹：

![Screen Shot 2018-05-16 at 3.49.37 PM.png]({{ site.url }}/images/powershell/5F3683DB3E19413452F15829A95BDC02.png)

再如注册表键：

![Screen Shot 2018-05-16 at 3.50.24 PM.png]({{ site.url }}/images/powershell/87316E25D017B0F08F0ABC6563157037.png)

但有的`PSProvider`并不具有项属性，如`Environment`：

![Screen Shot 2018-05-16 at 3.54.09 PM.png]({{ site.url }}/images/powershell/6CF78871393E2DBD2F16B055383FB5A8.png)

`Get-PSProvider`

![Screen Shot 2018-05-16 at 3.15.51 PM.png]({{ site.url }}/images/powershell/E2B471BAD8B27E84825DFAE7ED75A124.png)

`Get-PSDrive`

![Screen Shot 2018-05-16 at 3.16.09 PM.png]({{ site.url }}/images/powershell/0D6E3074D18A0E938C14996F1D3A5291.png)

访问注册表并修改值：

![Screen Shot 2018-05-16 at 3.03.08 PM.png]({{ site.url }}/images/powershell/8F60186036CE5B6100FEA1DAABC8B08F.png)

最后别忘了改回默认值。

大部分`Cmdlet`都包含`-Path`，且默认情况下支持通配符。如果不希望自己输入的`?*`被当作通配符，可以使用`-LiteralPath`代替。

## Chapter 6 管道：连接命令

### 格式化输出结果

输出结果到CSV (Comma-Separated Values)：

```powershell
Get-Process | Export-Csv procs.csv
```

![Screen Shot 2018-05-16 at 4.49.47 PM.png]({{ site.url }}/images/powershell/315C938196F3DEABA6FBCA61F17996D8.png)

![Screen Shot 2018-05-16 at 4.48.34 PM.png]({{ site.url }}/images/powershell/E006483C3ABA6C6B6F1E9790FD4C2D39.png)

相比直接在命令行中显示的内容，很明显输出到文件的内容更丰富。

之后可以在别处把`procs.csv`导入到PowerShell进行查看：

```powershell
Import-Csv procs.csv | more
```

![Screen Shot 2018-05-16 at 4.53.19 PM.png]({{ site.url }}/images/powershell/7C954AC21BFE1179847CE683285343EC.png)

注意，与`Get-Content`相比，`Import-Csv`会去解析它的格式，以更有序的形式展示出来。

另外也可以导出为`XML`：

```powershell
Get-Process | Export-Clixml procs.xml
```

![Screen Shot 2018-05-16 at 4.56.18 PM.png]({{ site.url }}/images/powershell/0BBCA3FEC8D1184C93356FC60E5571D5.png)

还有其他的各种导出导入：

![Screen Shot 2018-05-16 at 4.58.19 PM.png]({{ site.url }}/images/powershell/CE537444A9C18F06DEF67CF3AEC0DC2C.png)

还有一个对比功能蛮有趣：

`Compare-Object`或者`diff`

```powershell
Compare-Object -ReferenceObject (Import-CliXML procs.xml) -DifferenceObject (Get-Process) -Property Name
```

![Screen Shot 2018-05-16 at 7.21.02 PM.png]({{ site.url }}/images/powershell/C019D0E2A7DDF39157E3F6511B1B82B9.png)

`=>`表示不存在于`ReferenceObject`的进程，`<=`表示不存在于`DifferenceObject`的进程。另外注意小括号`()`的妙用。

### 输出到文件或打印机

`dir > x.txt`这种写法是为了向后兼容。实际上它是以管道实现：`dir | Out-File x.txt`（`Out-file`默认一行80列）。

### 输出到HTML

```powershell
Get-Process | ConvertTo-Html | Out-File procs.html
```

注意，`ConvertTo-`意味着只转换，不存储。`Export`则还会自动帮你存储。但是如果接下来还要用管道处理数据，那么`ConvertTo`更方便。

### 修改系统

```powershell
Get-Process -Name notepad | Stop-Process
```

这个例子想要说明的是，带有相同名词（如上面的`Process`）的`Cmdlet`可以在彼此之间传递信息。

像`Stop-`这种会修改系统的命令，都有`impact level`，这些`level`是不可修改的。同时，PowerShell有一个全局的`$ConfirmPreference`：

![Screen Shot 2018-05-16 at 7.40.48 PM.png]({{ site.url }}/images/powershell/E30D7AEF0608C0F4F1A8D2E5FDE81C83.png)

如果命令的`level`大于等于全局的，则PowerShell会问你是否确定要这么做。当然，你也可以强制它每次问你一下，即使命令的`level`小于全局的：

![Screen Shot 2018-05-16 at 7.47.22 PM.png]({{ site.url }}/images/powershell/34D9CDD2A9984D37FC0B85E34193E28E.png)

`-Confirm`会询问，`-WhatIf`会告诉你将发生什么。

我们之前有提到`PSProvider`。再次看一下这张图片：

![Screen Shot 2018-05-16 at 3.15.51 PM.png]({{ site.url }}/images/powershell/E2B471BAD8B27E84825DFAE7ED75A124.png)

其中，带有`ShouldProcess`的`PSProvider`支持`-WhatIf`和`-confirm`参数。

另外，`Filter`指的是其支持`-Filter`参数；`Credentials`指的是“允许使用可变更的凭据连接数据存储。”，即`-Credentials`参数；`Transactions`说明其支持事务（即原子操作）。

## Chapter 7 扩展命令

由于本章需要的某些模块在之前使用的Windows Server 2008中不存在，故本章采用如下版本的`Windows Server 2012 R2`和`PowerShell`：

![Screen Shot 2018-05-19 at 2.40.41 PM.png]({{ site.url }}/images/powershell/296C4C18D6A0FC8A355B6DC891E4280B.png)

![Screen Shot 2018-05-19 at 2.41.06 PM.png]({{ site.url }}/images/powershell/F60D864CEAB450183222CCB26F0ECAAE.png)

本章学习PowerShell的两种扩展：

- 管理单元
- 模块

首先是管理单元。它类似于插件。这种方式正逐渐被微软遗弃。它使用的主要命令是：

```powershell
Get-PSSnapin
Add-PSSnapin
```

深入学习模块：

模块不需要注册。`PSModulePath`定义了PowerShell期望存放模块的路径，路径下的模块会自动被查找：

![Screen Shot 2018-05-19 at 2.42.43 PM.png]({{ site.url }}/images/powershell/7A7B4BBBD328E1B0FA2F4F2D522E088F.png)

（图中两个路径分别存放系统和个人的模块）

另外，`PSModulePath`不能在PowerShell中修改，需要到系统环境变量中修改。

**测试：**

首先移除所有模块：

![Screen Shot 2018-05-19 at 2.52.26 PM.png]({{ site.url }}/images/powershell/D3FD0553D815CF919F8AECEC2CB35E9C.png)

之后查找一下`network`相关命令，可以发现还是可以找到，即使你没有加载那个模块。PowerShell会为你自动发现和加载：

![Screen Shot 2018-05-19 at 2.53.47 PM.png]({{ site.url }}/images/powershell/F163DD79029B956A81044761FF7F3457.png)

如果模块不在前面的路径下，那么需要手动导入：`Import-Module`。

插件和模块都可以添加`PSDrive`，所以在加载之后你可以使用`Get-PSProvider`查看新添加了哪些。

注：如果加载多个模块，其中包含相同命令，那么在使用命令时需要加上模块或插件前缀。例如：

```
MyCoolPowerShellSnapin\Get-User
```

**小实验：清除DNS缓存**

首先查看一下有哪些命令可以用：

![Screen Shot 2018-05-19 at 3.05.08 PM.png]({{ site.url }}/images/powershell/14CB2E11CF7D6F532E5F714313F37AD7.png)

发现很多都来自`DnsClient`模块。我们手动加载一下这个模块试一下（其实没有必要）：

![Screen Shot 2018-05-19 at 3.02.54 PM.png]({{ site.url }}/images/powershell/1B5E25CBC41E90FAD740674DB5626027.png)

试一下`Clear-DnsClientCache`：

![Screen Shot 2018-05-19 at 3.03.50 PM.png]({{ site.url }}/images/powershell/4BDBE75E121C36DB1CDD0AC32BF93860.png)

Es klappt!

**使用配置脚本**

这个类似于Shell的`profile`，这里的主要目的是帮你自动加载插件和模块。

- 在用户的`Documents`目录下新建目录`WindowsPowerShell`
- 在其中新建文件`profile.ps1`
- 在刚刚的文件中输入`Add-PSSnapin`和`Import-Module`，一行一个命令的格式来加载插件和模块
- 在PowerShell中修改执行策略（需要管理员身份）

```
Set-ExecutionPolicy RemoteSigned
```

- 关闭当前PowerShell并重启

**动手实验：运行网络故障诊断包**

用`Get-Command`搜索`network`没有找到有用的。看了英文版的题目才知道“网络故障诊断包”是`Networking troubleshooting pack`，那就找一下`trouble`吧：

![Screen Shot 2018-05-19 at 3.25.01 PM.png]({{ site.url }}/images/powershell/310B33E20F817F07EC4D1AA5D2601CC5.png)

Got it!

但是一开始不太会用这个东西，看一下帮助：

![Screen Shot 2018-05-19 at 3.31.20 PM.png]({{ site.url }}/images/powershell/E76FF8E779ACE2892F265F61B715C984.png)

这个好像是声音相关的。那我看一下那个目录下都有什么：

![Screen Shot 2018-05-19 at 3.32.22 PM.png]({{ site.url }}/images/powershell/95CA7CC426BB90601BB921898FB349F9.png)

太棒了。

![Screen Shot 2018-05-19 at 3.33.08 PM.png]({{ site.url }}/images/powershell/D6F854C330518A7D8FB97C119D41C37F.png)

然后把它传给`Invoke-`：

![Screen Shot 2018-05-19 at 3.30.36 PM.png]({{ site.url }}/images/powershell/F62D24B63BE72940E3FE10ED56D16642.png)

不过，这个功能略鸡肋啊。

## 补充知识

注：[在线教程](https://www.pstips.net/powershell-online-tutorials)。

### 交互式

基本C语言中的算术运算符在这里都能用。另外`0xdeadbeef`这种十六进制也可以用。同时，它还能识别`tb/gb/mb/kb`，如`1gb`：

![Screen Shot 2018-05-28 at 6.45.10 PM.png]({{ site.url }}/images/powershell/C420E34FE64AC96AA3193453899ABAE0.png)

通过字符串执行外部程序：

![Screen Shot 2018-05-28 at 6.47.09 PM.png]({{ site.url }}/images/powershell/49E9775DEC882D2AE320B095048FA0F8.png)

通过`Get-Command | gm`查看命令集的类型（目前我的环境上有三种）：

- System.Management.Automation.AliasInfo
- System.Management.Automation.FunctionInfo
- System.Management.Automation.CmdletInfo

通过函数来将带有常用参数的命令扩展为别名：

```powershell
function test-conn { Test-Connection  -Count 2 -ComputerName $args}
```

注意，`$args`为占位符。

执行VBS脚本：

```powershell
cscript.exe .\test.vbs
```

Powershell调用入口的优先级

- 别名：控制台首先会寻找输入是否为一个别名，如果是，执行别名所指的命令。因此我们可以通过别名覆盖任意powershell命令，因为别名的优先级最高。
- 函数：如果没有找到别名，会继续寻找函数，函数类似别名，只不过它包含了更多的powershell命令。因此可以自定义函数扩充cmdlet 把常用的参数给固化进去。
- 命令：如果没有找到函数，控制台会继续寻找命令，即cmdlet，powershell的内部命令。
- 脚本：没有找到命令，继续寻找扩展名为“.ps1”的Powershell脚本。
- 文件：没有找到脚本，会继续寻找文件，如果没有可用的文件，控制台会抛出异常。

默认的安全设置禁止执行脚本：

![Screen Shot 2018-05-28 at 6.57.12 PM.png]({{ site.url }}/images/powershell/F41923DAFB78AEE9CD72F1F6F7BDD781.png)

### 变量

#### 定义变量

- 不需要显式声明
- 可以自动创建变量
- 字母不区分大小写
- 变量的前缀为$
- 几乎可以把任何数据赋值给变量，一切都是对象
- 交换两变量的值非常简单

以上特性可以参照下图：

![Screen Shot 2018-05-28 at 7.05.34 PM.png]({{ site.url }}/images/powershell/7BAC77E8382A6C147F4791B766762506.png)

变量被存放在`Variable`的`Drive`中：

![Screen Shot 2018-05-28 at 7.07.17 PM.png]({{ site.url }}/images/powershell/35F713238CC8EC05F126A0E65A30EF3F.png)

验证变量是否存在：

![Screen Shot 2018-05-28 at 7.09.49 PM.png]({{ site.url }}/images/powershell/03107810E336F0DBA7F2E851509F8014.png)

（这与验证文件是否存在一样，关于原理可以参考[Chapter 5 使用提供程序](quiver-note-url/E74F3CE4-45A1-453D-BF49-C5F809AF5B2D)）

PowerShell提供5个管理变量的命令：

- Clear-Variable
- Remove-Variable
- Set-Variable
- Get-Variable
- New-Variable

后两个比较有用。比如：

- 创建只读变量

![Screen Shot 2018-05-28 at 7.11.58 PM.png]({{ site.url }}/images/powershell/2C4C249A1D2207C716D9620880B9B95A.png)

- 创建常量

![Screen Shot 2018-05-28 at 7.13.56 PM.png]({{ site.url }}/images/powershell/C35F9135F07FE30CFEB771937AE1793D.png)

通过`help about_scope`可以详细了解。

#### 自动化变量

**自动化变量**是那些一旦打开Powershell就会自动加载的变量：

![Screen Shot 2018-05-28 at 7.15.40 PM.png]({{ site.url }}/images/powershell/EBCC7E9863FF465FC11D483D2D42407B.png)

可以通过

```powershell
help about_Automatic_Variables
```

深入了解。

#### 环境变量

关于环境变量：

![Screen Shot 2018-05-28 at 7.22.05 PM.png]({{ site.url }}/images/powershell/3BE0AC4D8309C40BF170C913663A456A.png)

借助`.Net`方法，可以使用户设置的环境变量在系统级别生效：

```powershell
[environment]::SetEnvironmentvariable("myPath", ";c:\powershellscript", "User")
```

![Screen Shot 2018-05-28 at 7.24.08 PM.png]({{ site.url }}/images/powershell/E538C8E4AED2FFB17514C909EAECFC24.png)

#### 驱动器变量

可以通过`${PATH}`直接访问文件内容（其实这也是一切皆为“项”的体现）：

![Screen Shot 2018-05-28 at 7.27.05 PM.png]({{ site.url }}/images/powershell/596DEE3536559CAC28D3A0D4C7DFC730.png)

甚至函数也可以：

![Screen Shot 2018-05-28 at 7.28.47 PM.png]({{ site.url }}/images/powershell/6B27F4D1640864AB1747AB94C5DDDD88.png)

`$()`子表达式：

![Screen Shot 2018-05-28 at 7.30.29 PM.png]({{ site.url }}/images/powershell/6036E8C55CFBE71FDF798A4D0AD50A68.png)