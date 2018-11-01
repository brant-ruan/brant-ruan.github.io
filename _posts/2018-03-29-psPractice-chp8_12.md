---
title: PowerShell实战指南 Chapter 8-12
category: powershell
---

# {{ page.title }}

> 很多年 冰山形成以前 鱼曾浮出水面 很多年

## Chapter 8 对象：数据的另一个名称

`Get-Process`产生的进程表其实是进程对象的集合：

- 对象——表行
- 属性——表列
- 方法
- 集合——表

![Screen Shot 2018-05-20 at 4.38.04 PM.png]({{ site.url }}/images/powershell/7F8F8A86FB1214FEE0A39EC4193E5922.png)

PowerShell给出的结果是对象的格式化展示，这一点区别于Linux Shell，Linux Shell纯粹是文本。所以在Linux上需要依赖各种文本解析工具来筛选到想要的结果，如`awk`/`sed`/`grep`。相比之下，基于对象的处理方法更为优越，因为你只需指明属性（也就是类的成员），而无需担心输出文本位置改变等不可控因素。

其实，在PowerShell管道中传输的正是对象，而非Linux Shell管道中的文本。`GetProcess`在控制台中默认不会把进程对象的属性展示完全，这只是在将要输出时受到了配置文件的限制（最终展示的是表还是列表，也受到配置文件的限制）。但进程对象本身是完整的。如果你导出到文件中，就会发现进程对象的所有属性都被导出了：

```powershell
Get-Process | ConvertTo-Html | Out-File procs.html
```

查看类的成员：`Get-Member`(gm)：

![Screen Shot 2018-05-20 at 4.42.31 PM.png]({{ site.url }}/images/powershell/B58F24C98F1D4F8CB7C01C745DDE6B98.png)

事实上，所有会产生输出的Cmdlet都能够被`Get-Member`，比如它本身：

![Screen Shot 2018-05-20 at 4.43.52 PM.png]({{ site.url }}/images/powershell/394FAF99986BFF85C870525C88DF4297.png)

如上，`MemberType`有如下的值：

- Method
- Property (.Net中的)
- NoteProperty (PowerShell ETS自动添加的)
- ScriptProperty (PowerShell ETS自动添加的)
- AliasProperty (PowerShell ETS自动添加的)
- PropertySet
- Event

PowerShell中对象属性往往是只读的。

此时再回看Cmdlet的组合：

```powershell
Get-Process | Sort-Object -Property VM -Descending
```

全部都是对对象的操作。

**另外，`Select-Object`用于选择所需属性，而`Where-Object`基于筛选条件从管道中移除或过滤对象。**

在一个命令行中管道可以包含不同类型的对象。注意下面两幅图：

![Screen Shot 2018-05-20 at 4.56.10 PM.png]({{ site.url }}/images/powershell/5C59BE44C38FD8F17D7861B546C7C92C.png)

![Screen Shot 2018-05-20 at 4.57.15 PM.png]({{ site.url }}/images/powershell/EC3F13B950802BFC0E5FB62E9224FB37.png)

`Sort-Object`从管道中取出进程对象，放入的还是进程对象。而`Select-Object`在取出后放入的则是一个自定义对象。

当`PowerShell`发现光标到达命令行末尾时，它必须知道如何对文本输出结果进行排版。在`Select-Object`后，由于管道中已经是自定义对象，所以它只能尽最大努力排版，所以最后结果不如`Get-Process`的输出那么好看。

**动手实验**

- 找出生成随机数字的Cmdlet

Das ist einfach.

![Screen Shot 2018-05-20 at 5.03.18 PM.png]({{ site.url }}/images/powershell/2AF9B83BF6E1F6FCCA11596B7452468B.png)

- 找出显示时间和日期的Cmdlet

![Screen Shot 2018-05-20 at 5.04.56 PM.png]({{ site.url }}/images/powershell/EAAF705696EE3ECCF4302B5C817E3585.png)

- 用2中的Cmdlet只显示星期几

![Screen Shot 2018-05-20 at 5.07.01 PM.png]({{ site.url }}/images/powershell/1ECB2A6D0D30468013979D02C467723C.png)

- 找出显示已安装hotfix的Cmdlet，按照安装日期排序，并仅显示安装日期、补丁ID和安装用户

首先看一下都有哪些属性：

![Screen Shot 2018-05-20 at 5.11.52 PM.png]({{ site.url }}/images/powershell/A487DCE1DE77ACAEB75E5323336CB83D.png)

OK，行动：

![Screen Shot 2018-05-20 at 5.14.10 PM.png]({{ site.url }}/images/powershell/CB9F29DF9E785A0864F1EA156A6F9315.png)

- 从安全事件日志中显示最新的50条列表。按时间升序排序，同时也按索引排序。显示索引、时间和来源，把这些内容存入文本文件

![Screen Shot 2018-05-20 at 5.18.33 PM.png]({{ site.url }}/images/powershell/C5A6FB5D47B7D3AD7D7EB7F226AC865C.png)

## Chapter 9 深入理解管道

### ByValue & ByPropertyName

首先做一个测试：

在一个文本文件`computers.txt`中输入

```powershell
SERVER2
WIN8
CLIENT17
DONJONE1D96
```

然后执行

```powershell
Get-Content .\computers.txt | Get-Service
```

![Screen Shot 2018-05-21 at 1.51.41 PM.png]({{ site.url }}/images/powershell/6E8D430F93AEA07178783F4EF3633FA9.png)

产生错误。本章我们研究`Pipeline parameter binding`，即上一个命令通过管道把内容传递给下一个命令后，PowerShell如何决定由下一条命令的哪个参数去接收这些内容。

抽象出研究模型：

```
CommandA | CommandB
```

它会依次尝试下面两种方法：

- ByValue
- ByPropertyName

`ByValue`即先确定`CommandA`产生的数据对象类型，然后看`CommandB`中哪个参数可以接受这个类型。比如：

![Screen Shot 2018-05-21 at 3.36.59 PM.png]({{ site.url }}/images/powershell/9EBD5BC982858116804A7B26C92CE757.png)

可以看到传递过来的是`System.String`，而`CommandB`中也的确存在可以以`ByValue`方式接收`String`类型的参数`-Name`：

![Screen Shot 2018-05-21 at 3.39.14 PM.png]({{ site.url }}/images/powershell/3A1C0FC0F46330194F56EE2590DFCF3A.png)

但是由于的确没有如`computers.txt`内容那样的服务名，所以报错为“找不到服务”。同时，由于PowerShell只允许一个参数去接收`ByValue`管道传递的对象类型，而`-Name`接收了，所以其他参数无法接收这个数据。

我们之前提到，具有相同名词的命令在大部分情况下都可以直接通过管道传递对象。比如：

```powershell
Get-Process -Name note* | Stop-Process
```

这是因为`Stop-Process`具有如下参数：

![Screen Shot 2018-05-21 at 3.48.18 PM.png]({{ site.url }}/images/powershell/9E34BDB959371A2EC89881DDDA0D3FD8.png)

那么什么时候用`ByPropertyName`呢？看下面这个例子：

```powershell
Get-Service -Name s* | Stop-Process
```

![Screen Shot 2018-05-21 at 3.51.43 PM.png]({{ site.url }}/images/powershell/63368134872552119718608AD8E5CF06.png)

经过比对后发现，`Stop-Process`没有一个参数可以接收传过来的对象类型，于是`ByValue`失败，尝试`ByPropertyName`，它会尝试匹配传递对象的属性名称与后一个命令的参数名称。

![Screen Shot 2018-05-21 at 3.55.11 PM.png]({{ site.url }}/images/powershell/B20AFCE5D71BA301FD4E2E7FF583A853.png)

![Screen Shot 2018-05-21 at 3.56.08 PM.png]({{ site.url }}/images/powershell/CE5EBD41AC1BB06B30DB3F64A3EF4135.png)

![Screen Shot 2018-05-21 at 3.58.00 PM.png]({{ site.url }}/images/powershell/A5B68C35218168EE6C4719498CA04E1F.png)

我们可以看到，`Name`是传递对象和后面命令共有的一个名称，且对于后面的命令来说，其`-Name`参数支持`ByPropertyName`。PowerShell会尝试把所有能够对应起来的属性名与参数名进行关联。这里只有`Name`匹配。

![Screen Shot 2018-05-21 at 4.00.28 PM.png]({{ site.url }}/images/powershell/A79B4A6B34CEC76558D6B9817C3ABAE8.png)

所以我们看到其报错为，“找不到进程”，因为的确没有以服务名称命名的进程。

下面进行另一个测试。将下面的文本保存为`Alias.CSV`：

```
Name,Value
d,Get-ChildItem
sel,Select-Object
go,Invoke-Command
```

接着我们尝试导入并查看导入的是什么类型的对象：

![Screen Shot 2018-05-21 at 4.04.29 PM.png]({{ site.url }}/images/powershell/62CC5AA186829A70C1B06F80C93DBA65.png)

然后我们看一下`New-Alias`命令的参数：

![Screen Shot 2018-05-21 at 4.05.52 PM.png]({{ site.url }}/images/powershell/9585B48D5E842B900F162309EEB2CEDF.png)

可以看到，其恰好接收`-Name`和`Value`。我们再看这两个参数是否支持`ByPropertyName`：

![Screen Shot 2018-05-21 at 4.07.19 PM.png]({{ site.url }}/images/powershell/69517D916AEEDEDCFB34FFA8F702A741.png)

![Screen Shot 2018-05-21 at 4.07.29 PM.png]({{ site.url }}/images/powershell/02AD931BBBA9838C5D569BD02265E328.png)

支持！那么下面这条语句应该可以正常工作：

```powershell
Import-CSV Alias.csv | New-Alias
```

果然成功：

![Screen Shot 2018-05-21 at 4.09.06 PM.png]({{ site.url }}/images/powershell/571E57C031B13DFE8CF301CBECDB146B.png)

这说明，我们只需要为命令提供符合其用法的值，然后就可以用管道把这些连接起来。这有点像拼图或者拼装玩具。

### 自定义属性

下面通过一个例子，学习数据不对齐时的处理方法：自定义属性。

**由于默认环境无相关命令，从这里到本章结束为“Chapter 7 扩展命令”使用的环境。**

这个实验的情景是，我们要处理其他对象或者是别人提供给自己的数据（比如，以上文提到的CSV格式）。

我们使用的命令是`New-ADUser`（需要预先配置域控制器）：

![Screen Shot 2018-05-21 at 7.51.17 PM.png]({{ site.url }}/images/powershell/3A16B7516EF99B93E30590E5B69B6415.png)

我们需要用到以下参数：

![Screen Shot 2018-05-21 at 7.53.22 PM.png]({{ site.url }}/images/powershell/24A02EDA740D85A89124BF321D54021B.png)

![Screen Shot 2018-05-21 at 7.53.37 PM.png]({{ site.url }}/images/powershell/2A5FF119A7BEF1AAF7B6F7BD1BCDE656.png)

![Screen Shot 2018-05-21 at 7.53.55 PM.png]({{ site.url }}/images/powershell/F55C3E42D5D61363BDE9426A5A765494.png)

![Screen Shot 2018-05-21 at 7.54.07 PM.png]({{ site.url }}/images/powershell/638D8A1E4E7B3D7284255E264DC30CE0.png)

![Screen Shot 2018-05-21 at 7.54.32 PM.png]({{ site.url }}/images/powershell/A41F62B555E47C8E5E18B67D2A590AE3.png)

可以发现，这些参数都支持`ByPropertyName`，且`-Name`是必需的。假设我们是某公司的管理员，公司的HR部门提供了一个如下的CSV文件（他们固执的使用自己的格式）：

```
login, dept, city, title
DonJ, IT, Las Vegas, CTO
Gregs, Custodial, Denver, Janitor
JeffH, IT, Syracuse, Network Engineer
```

![Screen Shot 2018-05-21 at 7.59.45 PM.png]({{ site.url }}/images/powershell/115C4C541151B29B4F0C66240A9E16AE.png)

如上，成功导入文件并产生三个对象。但是这些对象的属性与我们前面提到的参数并不完全对应：

- `dept`并不是`-Department`的前缀
- `login`属性完全不存在于前面的参数中（事实上，它应该是`-Name`）

那么如何解决这个问题？一个方法是，手动去修改CSV文件。另一个方法是，使用我们提到的自定义属性：

![Screen Shot 2018-05-21 at 8.05.54 PM.png]({{ site.url }}/images/powershell/0277D7EA033EAD5CDCCD66332FA75CDF.png)

解释：

- 我们使用`Select-Object`及`-Property`参数，首先是`*`，即选择所有属性列，然后输入逗号，意思是后面还有别的
- 之后创建哈希表，其形式为`@{}`，其中包含一个或多个Key-Value
- 哈希表中第一个键是`Name`/`N`/`Label`/`L`其中任意一个均可（即它们是等同的），其对应的值为我们想要创建的属性名称

![Screen Shot 2018-05-21 at 8.12.06 PM.png]({{ site.url }}/images/powershell/D09225ECA6A5994041EE9DDE6D67B6D3.png)

- 第二个键是`expression`/`e`任意均可，其对应的值是一个包含在大括号内的脚本块。`$_`指的是已经存在的管道对象（即CSV文件中每行的数据），我们借此来读取管道对象的属性

![Screen Shot 2018-05-21 at 8.14.57 PM.png]({{ site.url }}/images/powershell/ABE38487B4EF0FE2BD7B25DE6E63CAB1.png)

OK。我们测试一下：

![Screen Shot 2018-05-21 at 8.39.57 PM.png]({{ site.url }}/images/powershell/53DE1641F3EB11107D3813D69B6219A3.png)

成功，我们查看一下：

`Get-ADUser -Filter *`

![Screen Shot 2018-05-21 at 8.40.42 PM.png]({{ site.url }}/images/powershell/3C62848ADD63207C0A2DA88CA538501E.png)

我们可以通过`help Select-Object -Examples`看一下官方对这种用法的解释：

![Screen Shot 2018-05-21 at 8.44.18 PM.png]({{ site.url }}/images/powershell/D62CB0F12156E78E4F6AF7D01CE9A664.png)

### 括号的使用

当参数不支持管道输入时怎么办？使用括号！例如：

![Screen Shot 2018-05-21 at 8.49.49 PM.png]({{ site.url }}/images/powershell/A60424EE97CC00516C4186AE5D356B1F.png)

我们看一下帮助：

![Screen Shot 2018-05-21 at 8.50.30 PM.png]({{ site.url }}/images/powershell/456F13B5B3B069D569E2F5AC5898E0CA.png)

果然不行。那么就用括号吧：

![Screen Shot 2018-05-21 at 8.51.38 PM.png]({{ site.url }}/images/powershell/F8EB833F9D29C35ED29926BF80A7A352.png)

成功了。报错只是因为没有相关的配置而已。

那么，如果`ComputerName`并不是从文件中直接获取，而是需要从其他对象的属性中获取呢？比如下面这个例子：

![Screen Shot 2018-05-21 at 8.57.11 PM.png]({{ site.url }}/images/powershell/9D2D6DDC1E85194ED87A771374596DD0.png)

我们希望提取其中的`Name`传给其他命令，比如

```powershell
Get-Service -ComputerName (Get-ADComputer -Filter * -SearchBase "ou=domain controllers, dc=rambo, dc=com")
```

这样会报错（当然，其实对于`Get-Service`来说，可以使用管道，但这里我们是为了学习括号的用法）：

![Screen Shot 2018-05-21 at 9.10.11 PM.png]({{ site.url }}/images/powershell/5A0546C26CFD1833401E7332433066F0.png)

原因很简单，我们之前已经说了，类型不匹配：

![Screen Shot 2018-05-21 at 9.02.20 PM.png]({{ site.url }}/images/powershell/3A19C6824FA26E12A5318C489C9C0CD3.png)

我们需要提取其中的`Name`属性。这里可以用到`Select-Object`的`-ExpandProperty`参数。首先注意它与`-Property`的区别。它们的作用分别是“提取属性的值并返回”和“返回只包含特定属性的对象”。下图清楚地展示了这些区别：

![Screen Shot 2018-05-21 at 9.06.21 PM.png]({{ site.url }}/images/powershell/A56C7FDE6E6DB35875C5F1E8F274D1EC.png)

很明显。这里我们需要的是`String`！

![Screen Shot 2018-05-21 at 9.10.47 PM.png]({{ site.url }}/images/powershell/38A9A2B0F7432BF600964F4A87A62EB5.png)

Bingo!

（作者不停地说这个技术非常强大，一定要掌握！）

进一步地，我们来设计另一个实验：

创建一个`computers.csv`：

```
hostname, operatingsystem
localhost, windows
```

由于我的虚拟机环境目前只能访问本机，所以只写了`localhost`，但这不影响我们的实验。

![Screen Shot 2018-05-21 at 9.17.56 PM.png]({{ site.url }}/images/powershell/BE5C8F624CC1875E2696EFFB1DD2B2ED.png)

如上。我们借用括号技术从CSV文件中获取了属性，并成功读取了相关计算机的进程列表。

我们也可以使用管道（只要参数支持管道，就能用）：

![Screen Shot 2018-05-21 at 9.21.07 PM.png]({{ site.url }}/images/powershell/49D6760058810A2CB8118EBF13ED8FB9.png)

当然了，直接搞是不行的：

![Screen Shot 2018-05-21 at 9.21.54 PM.png]({{ site.url }}/images/powershell/D56BAEAC626C0BFBA4179E671ED55094.png)

### 总结

本章学习了非常有用的概念和方法：

- ByValue
- ByPropertyName
- 自定义属性
- 括号
- ExpandProperty提取属性值

有了这些技术，我们可以获得比Linux Shell强大得多的功能，而不必编写复杂的脚本，只需利用“面向对象的特性”和上面这些技能就可以达到目的。

一个意外的惊喜是 **The Computername parameter in Get-WMIObject doesn’t take any pipeline binding.**

## Chapter 10 格式化及如何正确使用

### 默认格式化方法

默认的输出格式受配置文件的约束，配置文件如下：

```
C:\Windows\System32\WindowsPowerShell\v1.0
```

![Screen Shot 2018-05-22 at 3.11.50 PM.png]({{ site.url }}/images/powershell/1D28B41EB86F39E1FD306618ED17E417.png)

![Screen Shot 2018-05-22 at 3.33.19 PM.png]({{ site.url }}/images/powershell/253FC586DDD7097B2972EEF88BBE9C99.png)

![Screen Shot 2018-05-22 at 3.33.27 PM.png]({{ site.url }}/images/powershell/C56CC45BA804FEA6684756C043C59A15.png)

另外，不要改动文件，因为其末尾有数字签名：

![Screen Shot 2018-05-22 at 3.17.59 PM.png]({{ site.url }}/images/powershell/A13AC9814816CB002FBAC4549648A54F.png)

其中`DotNetTypes.format.ps1xml`中包含了进程对象的格式化方式，如下：

```xml
        <View>
            <Name>process</Name>
            <ViewSelectedBy>
                <TypeName>System.Diagnostics.Process</TypeName>
            </ViewSelectedBy>
            <TableControl>
                <TableHeaders>
                    <TableColumnHeader>
                        <Label>Handles</Label>
                        <Width>7</Width>
                        <Alignment>right</Alignment>
                    </TableColumnHeader>
                    <TableColumnHeader>
                        <Label>NPM(K)</Label>
                        <Width>7</Width>
                        <Alignment>right</Alignment>
                    </TableColumnHeader>
                    <TableColumnHeader>
                        <Label>PM(K)</Label>
                        <Width>8</Width>
                        <Alignment>right</Alignment>
                    </TableColumnHeader>
                    <TableColumnHeader>
                        <Label>WS(K)</Label>
                        <Width>10</Width>
                        <Alignment>right</Alignment>
                    </TableColumnHeader>
                    <TableColumnHeader>
                        <Label>VM(M)</Label>
                        <Width>5</Width>
                        <Alignment>right</Alignment>
                    </TableColumnHeader>
                    <TableColumnHeader>
                        <Label>CPU(s)</Label>
                        <Width>8</Width>
                        <Alignment>right</Alignment>
                    </TableColumnHeader>
                    <TableColumnHeader>
                        <Width>6</Width>
                        <Alignment>right</Alignment>
                    </TableColumnHeader>
                    <TableColumnHeader />
                </TableHeaders>
                <TableRowEntries>
                    <TableRowEntry>
                        <TableColumnItems>
                            <TableColumnItem>
                                <PropertyName>HandleCount</PropertyName>
                            </TableColumnItem>
                            <TableColumnItem>
                                <ScriptBlock>[int]($_.NPM / 1024)</ScriptBlock>
                            </TableColumnItem>
                            <TableColumnItem>
                                <ScriptBlock>[int]($_.PM / 1024)</ScriptBlock>
                            </TableColumnItem>
                            <TableColumnItem>
                                <ScriptBlock>[int]($_.WS / 1024)</ScriptBlock>
                            </TableColumnItem>
                            <TableColumnItem>
                                <ScriptBlock>[int]($_.VM / 1048576)</ScriptBlock>
                            </TableColumnItem>
                            <TableColumnItem>
                                <ScriptBlock>
if ($_.CPU -ne $()) 
{ 
    $_.CPU.ToString("N") 
}
				</ScriptBlock>
                            </TableColumnItem>
                            <TableColumnItem>
                                <PropertyName>Id</PropertyName>
                            </TableColumnItem>
                            <TableColumnItem>
                                <PropertyName>ProcessName</PropertyName>
                            </TableColumnItem>
                        </TableColumnItems>
                    </TableRowEntry>
                </TableRowEntries>
            </TableControl>
        </View>
```

![Screen Shot 2018-05-22 at 3.21.07 PM.png]({{ site.url }}/images/powershell/516F1717EB1815DECFB401D2D9EAA8FA.png)

可以看到，XML对格式的定义就是我们看到的那样。

当运行`Get-Process`时，发生下面的事情：

- Cmdlet把`System.Diagnostics.Process`类型的对象放入管道
- 管道末端有一个名为`Out-Default`的隐藏`Cmdlet`，它把需要运行的命令全部放入管道中
- `Out-Default`把对象传输到`Out-Host`（默认即为本地机器的显示屏）
- 大部分`Out-Cmdlets`不适合用在普通对象中，而主要用于特定格式化指令。所以`Out-Host`看到普通对象会把它们传递给格式化系统
- 格式化系统依赖内部规则检查对象类型，并产生格式化指令，最终传输回`Out-Host`
- `Out-Host`发现格式化指令，于是根据这个指令产生显示到屏幕上的结果

同理，当你`Get-Process | Out-File procs.txt`时也会经历上面的几个步骤。只不过`Out-Host`被换成了`Out-File`。

格式化系统所谓的内部规则做了什么呢？

- 检查对象类型是否能够被预定义视图处理（即`DotNetType.format.ps1xml`中的进程部分）
- 如果没有找到对应的预定义视图，则寻找是否有针对这个对象类型的“default display property set”，这部分被定义在`types.ps1xml`中

一个例子是`Win32_OperatingSystem`，我们可以在`types.ps1xml`对其的定义：

```xml
    <Type>
        <Name>System.Management.ManagementObject#root\cimv2\Win32_OperatingSystem</Name>
        <Members>
            <PropertySet>
                <Name>PSStatus</Name>
                <ReferencedProperties>
                    <Name>Status</Name>
                    <Name>Name</Name>
                </ReferencedProperties>
            </PropertySet>
            <PropertySet>
                <Name>FREE</Name>
                <ReferencedProperties>
                    <Name>FreePhysicalMemory</Name>
                    <Name>FreeSpaceInPagingFiles</Name>
                    <Name>FreeVirtualMemory</Name>
                    <Name>Name</Name>
                </ReferencedProperties>
            </PropertySet>
            <MemberSet>
                <Name>PSStandardMembers</Name>
                <Members>
                    <PropertySet>
                        <Name>DefaultDisplayPropertySet</Name>
                        <ReferencedProperties>
                            <Name>SystemDirectory</Name>
                            <Name>Organization</Name>
                            <Name>BuildNumber</Name>
                            <Name>RegisteredUser</Name>
                            <Name>SerialNumber</Name>
                            <Name>Version</Name>
                        </ReferencedProperties>
                    </PropertySet>
                </Members>
            </MemberSet>
        </Members>
    </Type>
```

![Screen Shot 2018-05-22 at 3.38.06 PM.png]({{ site.url }}/images/powershell/06C0335CB01DED3419AD7466EFBDCF31.png)

也是一致的。

- 继续。如果上一步中也没有找到相应的结果，那么下一步的决策就会考虑所有对象的属性值
- 决策。如果显示4个及以下的属性，将采用表格。否则，将采用列表（那么为什么`Get-Process`用的是表格呢？因为预定义中文件用的是表格`<TableControl>`）

### 自定义格式化

PowerShell中有4种用于格式化的Cmdlets，分别为`Format-Table`/`Foramt-List`/`Format-Wide`/`Format-Custom`。`Format-Custom`在这里暂不介绍。

- `Format-Table`(ft)

其常用参数如下：

`-AutoSize`

强制结果集仅保存足够的列空间，使表格更为紧凑。

![Screen Shot 2018-05-22 at 3.54.49 PM.png]({{ site.url }}/images/powershell/B5E808EE026CB91D9F6539F07E82F62D.png)

`-Property`

使用你提供的属性列。我们看几个效果：

![Screen Shot 2018-05-22 at 3.57.48 PM.png]({{ site.url }}/images/powershell/C92C7B4C73246385CBB7CF2B2C17853E.png)

（好丑）

![Screen Shot 2018-05-22 at 3.59.31 PM.png]({{ site.url }}/images/powershell/0D93B131D7268956B1166FE859C995D2.png)

![Screen Shot 2018-05-22 at 4.00.27 PM.png]({{ site.url }}/images/powershell/3C6B2FC0E2DFF2BEBC73AA34EAFCEABB.png)

（这个比第一幅图好看得多）

`-GroupBy`

每当指定属性值变更时，创建一个具有新列头的结果集。效果如下：

![Screen Shot 2018-05-22 at 4.02.56 PM.png]({{ site.url }}/images/powershell/C7FF801FCC0D30EC67840A30765449B1.png)

![Screen Shot 2018-05-22 at 4.03.05 PM.png]({{ site.url }}/images/powershell/5646341E5BC1E127774554D9B452474A.png)

上面的例子中，它实际上把输出给分成了两部分。

`-Wrap`

默认情况下如果Shell需要把列的信息截断，会在列尾带上（...），如下图：

![Screen Shot 2018-05-22 at 4.08.44 PM.png]({{ site.url }}/images/powershell/358767D2477C79BDC4FFA62D49C1983E.png)

而加上`-Wrap`后，它会让信息拐到下一行。像这样：

![Screen Shot 2018-05-22 at 4.10.03 PM.png]({{ site.url }}/images/powershell/C9730DF9564BF040FF88B96B432A586A.png)

- `Format-List`(fl)

`Format-Table`相关参数`Format-List`也有。不过，`fl`也是除`gm`外的另一个展示对象属性的方法：

![Screen Shot 2018-05-22 at 4.12.32 PM.png]({{ site.url }}/images/powershell/8B1E59B3EC1FA9B9DBA60A79F2763C5B.png)

- `Format-Wide`(fw)

用于展示一个宽列表。

它仅展示一个属性的值，所以它的`-Property`只接受一个属性。

![Screen Shot 2018-05-22 at 4.14.04 PM.png]({{ site.url }}/images/powershell/8EFA2C3F6B1815EA5E4CDFBEBCAD8088.png)

### 与“自定义属性”结合

上一章我们提到“自定义属性”，这一技术在`Format-Table`和`Format-List`中也可以使用：

![Screen Shot 2018-05-22 at 4.18.24 PM.png]({{ site.url }}/images/powershell/C330D883E3342A3D882233F89416B8F3.png)

### 输出到网格

`Out-GridView`完全绕过了格式化子系统，它也不接受`Format-Cmdlet`的输出：

![Screen Shot 2018-05-22 at 4.22.48 PM.png]({{ site.url }}/images/powershell/07F2279EEF28EC0C08DA3ACEFBCF2931.png)

### 常见问题

`Format-`命令应该是`Out-File`或者`Out-Printer`前的最后一个命令，因为只有`Out-`相关命令能够处理`Format-`产生的结果。如果你直接让`Format-`作为命令行的结尾，那么最终会通过`Out-Default -> Out-Host`，这样的格式化是非预期的。

![Screen Shot 2018-05-22 at 4.28.11 PM.png]({{ site.url }}/images/powershell/FE65163F86DAA09468C9CF829EFDF4B2.png)

上面这条命令结果如下：

![Screen Shot 2018-05-22 at 4.28.02 PM.png]({{ site.url }}/images/powershell/B8C53218DA792A30A59F0D22E6DD30E7.png)

另外，一次只输出一种对象。

```powershell
Get-Process; Get-Service
```

这种不要做。

### 练习

使用`Get-EventLog`显示所有可用事件日志的列表，并把信息格式化为一个表，日志需要显示名字和保留期限，分别以“LogName”和“RetDays”显示。

![Screen Shot 2018-05-22 at 4.37.11 PM.png]({{ site.url }}/images/powershell/55320160990E1788B7F99C947E50BD16.png)

## Chapter 11 过滤和对比

本章使用“Chapter 7 扩展命令”的环境。

PowerShell提供两种方式缩小结果集：

- 尝试让Cmdlet命令只检索指定内容
- 使用另一个命令进行迭代过滤（类似于grep）

一般来说，能用第一种尽量用第一种。例如：

![Screen Shot 2018-05-23 at 11.18.48 AM.png]({{ site.url }}/images/powershell/DCD6863EDF44947964555A4902990DF2.png)

但是如果你希望基于更为复杂的条件进行过滤，比如只返回正在运行的服务，而不考虑服务名称，只用`Get-Service`就无法做到——它没有提供相关参数。

然而，对于微软的活动目录模块相关的命令来说，`Get-`基本上都有`-Filter`参数。但不建议用`-Filter *`，这样会增大域控制器的压力。如下的命令是推荐的：

![Screen Shot 2018-05-23 at 11.23.08 AM.png]({{ site.url }}/images/powershell/E1B7C1B10478FF5CE71FC0E8F4CBECE4.png)

上述技巧被称为“左过滤”，其优势在于只检索匹配的对象。

### 左过滤

左过滤的缺点是可能不同的Cmdlet过滤方法不同。比如`Get-Service`只能通过`Name`过滤，而`Get-ADComputer`可以根据任何属性过滤。

**对比操作符**

注：当对比文本字符串时会忽略大小写。

`-eq`/`-ne`/`-ge`/`-le`/`-gt`/`-lt`

如果希望区分字符串的大小写，可以在所有操作符前加`c`，如`-ceq`：

![Screen Shot 2018-05-23 at 12.30.13 PM.png]({{ site.url }}/images/powershell/C923707C5CF5C7165D7D6F92B5274AB2.png)

日期也可以比较：

![Screen Shot 2018-05-23 at 12.28.55 PM.png]({{ site.url }}/images/powershell/34CA0D91A53D3596252EE9171463FC69.png)

另外还有`-and`/`-or`/`-not`。

`$False`/`$True`表示false和true。

对于字符串，还有`-like`和`-notlike`，即比较可以使用通配符；`-match`/`-notmatch`则允许使用正则表达式。

![Screen Shot 2018-05-23 at 12.34.30 PM.png]({{ site.url }}/images/powershell/7CDE91CC8456DE0A8FBECADAB87C6097.png)

可通过查看帮助文件进一步学习：

![Screen Shot 2018-05-23 at 12.36.25 PM.png]({{ site.url }}/images/powershell/F7648DACDFDED82E15F811B80770505E.png)

那么我们可以在哪些地方使用对比操作表达式？一个地方是前面演示过的`-Filter`，另一个地方是`Where-Object`。

**Where-Object**

![Screen Shot 2018-05-23 at 12.44.02 PM.png]({{ site.url }}/images/powershell/1777DC213E621DBB9FA4AC744E314778.png)

上面的截图也表现了它的优点——`Where-Object`是通用的，即使`Get-Service`本身并没有上面的过滤功能。往往它也简写为`Where`。

### 迭代过滤

一个例子：我们想要计算正在使用虚拟内存的十大进程占用的虚拟内存总量（排除powershell进程）：

```powershell
Get-Process |
Where-Object -FilterScript {$_.Name -notlike "powershell*"} |
Sort-Object -Property VM | 
Select-Object -Last 10 |
Measure-Object -Property VM -Sum |
Select-Object -Property @{l="Sum";e={$_.Sum / 1024 / 1024 -as [int]}}
```

![Screen Shot 2018-05-23 at 1.08.58 PM.png]({{ site.url }}/images/powershell/7661BCAFD1DB1545D04ABDCBA740E5E7.png)

### 总结

`Where-Object`不是首选。首选是“左过滤”原则。对于一个Cmdlet来说，应该尽可能地使用其参数提供的功能。

## Chapter 12 学以致用

本章我们做一个自学实验：添加计划任务。

首先通过`Get-Command *task*`找到可能要用的命令，然后发现它们基本上都属于`ScheduledTasks`，于是查看该模块下的命令：

![Screen Shot 2018-05-24 at 7.13.18 PM.png]({{ site.url }}/images/powershell/C7048BBEA9B702B261725807C889CCE1.png)

发现`New-ScheduledTask`可能会有帮助，看一下文档：

![Screen Shot 2018-05-24 at 7.11.22 PM.png]({{ site.url }}/images/powershell/E1DE788E8FB41453371C524F7429475E.png)

![Screen Shot 2018-05-24 at 7.11.36 PM.png]({{ site.url }}/images/powershell/C51908421FE2D95A4415613AA9AD11B6.png)

发现它并不能自动注册。根据样例，最终还是要用到另一个命令：`Register-ScheduledTask`。另外需要注意的是，`Action`和`Trigger`。

![Screen Shot 2018-05-24 at 7.14.06 PM.png]({{ site.url }}/images/powershell/8DB5800DF15726FF86D42DF24163F85D.png)

最终，结合我们之前学习的括号知识，可以成功完成任务，效果如下：

![Screen Shot 2018-05-24 at 7.10.08 PM.png]({{ site.url }}/images/powershell/1289BEEE9D5DEE83A56F41F5AF6EC20E.png)

### 总结

> 当每次创建触发器时触发器的ID都为0，而不是每次创建触发器都有一个连续递增的触发器ID时，我们可以安全地确认PowerShell不会将该触发器存到某个列表。这还意味着我们需要将触发器传递给某个父命令，而不是先创建它供后续使用。