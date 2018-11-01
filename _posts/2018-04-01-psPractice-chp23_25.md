---
title: PowerShell实战指南 Chapter 23-25
category: powershell
---

# {{ page.title }}

> 惟此独立之精神，自由之思想，历千万祀，与天壤而同久，共三光而永光。

## Chapter 23 高级远程配置

接续[实战指南 Chapter 13 远程处理：一对一及一对多](quiver:///notes/CEC8AF22-D17C-484B-A9BA-4E2C1FF0A922)。

![Screen Shot 2018-06-11 at 1.57.49 PM.png]({{ site.url }}/images/powershell/97885618580FBE157C19CA0A6E24A513.png)

一台计算机可以包含多个端点。在PowerShell中，端点也被称为`session configurations`。如上图，在64位系统上也会开启32位端点，只不过64位是默认的。

使用其他端点：

![Screen Shot 2018-06-11 at 2.00.09 PM.png]({{ site.url }}/images/powershell/59779914BD679929011F1F96082F606A.png)

**创建自定义端点**

分两步：

- 通过`New-PSSessionConfigurationFile`创建新的会话配置文件（`.pssc`）
- 通过`Register-PSSessionConfiguration`载入该文件

举例如下（未实验）：创建一个只有域中HelpDesk组的成员可以访问的端点。在端点内，只允许他们看到与网络适配器相关的命令，但不可运行。另外，我们配置该端点使用我们提供的备用凭据：

```powershell
New-PSSessionConfigurationFile -Path C:\HelpDeskEndpoint.pssc `
    -ModulesToImport NetAdapter `
    -SessionType RestrictedRemoteServer `
    -CompanyName "Our Company" `
    -Author "Don Jones" `
    -Description "New adapter commands for use by help desk" `
    -PowerShellVersion "3.0"
    
Register-PSSessionConfiguration -Name "HelpDesk" `
    -Path .\HelpDeskEndpoint.pssc `
    -RunAsCredential COMPANY\HelpDeskProxyAdmin `
    -ShowSecurityDescriptorUI
```

## Chapter 24 使用正则表达式解析文本文件

需要注意的是，在PowerShell内部我们往往不需要使用正则表达式，因为那些对象都有相应的属性供我们筛选。正则表达式往往在处理外部大量文本时使用。

|0|1|0|1|
|:-:|:-:|:-:|:-:|
|\w|字母、数字、下划线|\W|空格、标点符号（非字母）|
|\d|数字|\D|非数字|
|\s|空格类（空格、tab、回车）|\S|非空格类|
|.|任意单字符|[abcde]|集合中任意单字符|
|[a-z]|范围内任意单个字符|[^a-z]|范围外任意单个字符|
|?|前面的元素出现0次或1次|*|前面的元素出现任意次|
|+|前面的元素出现大于0次|\\|转义|
|{2,5}|前面的元素出现的次数在2与5之间|()|形成一个元素|
|^|匹配开始位置|$|匹配结尾位置|

通过`help about_regular_expressions`查询更多。

使用`-Match`和`-Cmatch`（区分大小写）来做匹配：

![Screen Shot 2018-06-11 at 2.41.01 PM.png]({{ site.url }}/images/powershell/2088D99C1E85D1218283B39888C9DE8A.png)

**通过Select-String使用正则表达式**

下面我们将在IIS日志文件中做测试：

- 查找`40x`错误作为开头的日志并生成报表

```powershell
Get-ChildItem -Filter *.log -Recurse | 
Select-String -Pattern "\s40[0-9]\s" |
Format-Table Filename,LineNumber,Line -Wrap
```

![Screen Shot 2018-06-11 at 2.51.12 PM.png]({{ site.url }}/images/powershell/71C83E27F92C07722BFCFF69DB1F4C11.png)

- 查找所有被基于`Gecko`的浏览器访问过的文件，且使用的操作系统为`Windows NT 6.2`

也就是要查找如下的字符串：

```
(Windows+NT+6.2;+WOW64;+rv:11.0)+Gecko
```

其中，`WOW64`不必要。

```powershell
Get-ChildItem -Filter *.log -Recurse | 
Select-String -Pattern "6\.2;[\w\W]+\+Gecko"
```

其他的例子如：

```powershell
Get-EventLog -LogName Security | 
where {$_.eventid -eq 4264 -and $_.message -match "WIN[\W\w]+TM[234][0-9]\$"} 
```

可以看到，正则表达式在PowerShell中是无处不在的。

**练习**

- 获取计算机中所有非微软进程，显示ID、名称和公司名称

![Screen Shot 2018-06-11 at 3.06.23 PM.png]({{ site.url }}/images/powershell/294882E0134278EEBB5CEC4407A7B28E.png)

P.S. https://www.regextester.com 测试你的正则表达式。

## Chapter 25-28 旅程的最后

**Profile**

我们在四个不同的地方添加`profile`配置文件，并在其中添加一个打印语句，然后重新启动PowerShell，观察不同载入顺序：

```powershell
# 1
Write-Host '$PSHOME/Profile.ps1'
# 2
Write-Host '$PSHOME/Micrsoft.PowerShell_Profile.ps1'
# 3
Write-Host '$HOME/Documents/WindowsPowerShell/Profile.ps1'
# 4
Write-Host '$HOME/Documents/WindowsPowerShell/Microsoft.PowerShell_Profile.ps1'
```

![Screen Shot 2018-06-12 at 3.20.49 PM.png]({{ site.url }}/images/powershell/4140606E032332D94FECC5C93FFF188E.png)

关于`profile`的配置，可以参考`help about_profiles`。

**运算符**

- 类型转换

![Screen Shot 2018-06-12 at 3.24.48 PM.png]({{ site.url }}/images/powershell/B6731C7905F7DC37B2941DA98341A7A5.png)

![Screen Shot 2018-06-12 at 3.25.06 PM.png]({{ site.url }}/images/powershell/96CC8041B4D9E7F3A82C4D11D7C73A2C.png)

- 类型判断

![Screen Shot 2018-06-12 at 3.26.20 PM.png]({{ site.url }}/images/powershell/CD1A38F539A315A69BEE5028ACFBD4A9.png)

- 替换字符（串）

![Screen Shot 2018-06-12 at 3.27.17 PM.png]({{ site.url }}/images/powershell/40A2C111110FC23842CA41EA448ED006.png)

- 字符串与数组互相转化

![Screen Shot 2018-06-12 at 3.29.19 PM.png]({{ site.url }}/images/powershell/810C6C5AD19C55D08263C2FF4EEF194A.png)

![Screen Shot 2018-06-12 at 3.33.11 PM.png]({{ site.url }}/images/powershell/23588AA893CFFBFD11351E757FCA511D.png)

- 包含与存在

![Screen Shot 2018-06-12 at 3.50.14 PM.png]({{ site.url }}/images/powershell/0B43EE7991410C39B4A19A32423E2E54.png)

**脚本块**

```powershell
$Block = {Get-Process | Sort -Property VM -Descending}
# invoke
&$Block
```

参考`help about_script_block`。

**脚本**

![Screen Shot 2018-06-12 at 3.59.39 PM.png]({{ site.url }}/images/powershell/3F2F6636C601BFA136BEB14D6095E169.png)

**练习**

理解以下脚本：

```powershell
function get-LastOn {
<#
.DESCRIPTION
Tell me the most recent event log entries for logon or logoff.
.BUGS
Blank 'computer' column
.EXAMPLE
get-LastOn -computername server1 | Sort-Object time -Descending |
Sort-Object id -unique | format-table -AutoSize -Wrap
ID
--
LOCAL SERVICE
NETWORK SERVICE NT AUTHORITY
SYSTEM          NT AUTHORITY
Computer Time
-------- ----
         4/3/2012 11:16:39 AM
         4/3/2012 11:16:39 AM
         4/3/2012 11:16:02 AM
Domain
------
NT AUTHORITY
Sorting -unique will ensure only one line per user ID, the most recent.
Needs more testing
.EXAMPLE
PS C:\Users\administrator> get-LastOn -computername server1 -newest 10000
 -maxIDs 10000 | Sort-Object time -Descending |
 Sort-Object id -unique | format-table -AutoSize -Wrap
ID              Domain
--              ------
Administrator   USS
ANONYMOUS LOGON NT AUTHORITY
LOCAL SERVICE   NT AUTHORITY
NETWORK SERVICE NT AUTHORITY
student         WIN7
SYSTEM          NT AUTHORITY
USSDC$          USS
WIN7$           USS
PS C:\Users\administrator>
Computer Time
-------- ----
         4/11/2012 10:44:57 PM
         4/3/2012 8:19:07 AM
         10/19/2011 10:17:22 AM
         4/4/2012 8:24:09 AM
         4/11/2012 4:16:55 PM
         10/18/2011 7:53:56 PM
         4/11/2012 9:38:05 AM
         10/19/2011 3:25:30 AM
.EXAMPLE
get-LastOn -newest 1000 -maxIDs 20
Only examines the last 1000 lines of the event log
.EXAMPLE
get-LastOn -computername server1| Sort-Object time -Descending |
Sort-Object id -unique | format-table -AutoSize -Wrap
#>

    param (
        [string]$ComputerName = 'localhost',
        [int]$Newest = 5000,
        [int]$maxIDs = 5,
        [int]$logonEventNum = 4624, # log on successfully
        [int]$logoffEventNum = 4647
    )

    $eventsAndIDs = Get-EventLog -LogName security -Newest $Newest |
        Where-Object {$_.instanceid -eq $logonEventNum -or $_.instanceid -eq $logoffEventNum} |
        Select-Object -Last $maxIDs -Property TimeGenerated,Message,ComputerName

    foreach ($event in $eventsAndIDs) {
        $id = ($event |
            parseEventLogMessage |
            where-Object {$_.fieldName -eq "Account Name"}  |
            Select-Object -last 1).fieldValue
    
        $domain = ($event |
            parseEventLogMessage |
            where-Object {$_.fieldName -eq "Account Domain"}  |
            Select-Object -last 1).fieldValue
    
        # hashtable
        $props = @{'Time'=$event.TimeGenerated;
            'Computer'=$ComputerName;
            'ID'=$id
            'Domain'=$domain}
    
        $output_obj = New-Object -TypeName PSObject -Property $props
    
        Write-Output $output_obj
    }
}

function parseEventLogMessage()
{
    [CmdletBinding()]
    param (
        [parameter(ValueFromPipeline=$True,Mandatory=$True)]
        [string]$Message
    )

    $eachLineArray = $Message -split "`n"

    foreach ($oneLine in $eachLineArray) {
        write-verbose "line:_$oneLine_"
        $fieldName,$fieldValue = $oneLine -split ":", 2
    } 
}

Get-LastOn
```

该脚本用于从安全日志中获取用户的登录登出信息。

在**我的测试**中，发现它有几点瑕疵：

- 没有处理异常（暂不修改）
- 无法接受外部传入的参数（在后面修改）
- 无法使用help（在后面修改）

最终，我给修改成如下形式：

```powershell
<#
.DESCRIPTION
Tell me the most recent event log entries for logon or logoff.
.BUGS
Blank 'computer' column
.EXAMPLE
get-LastOn -computername server1 | Sort-Object time -Descending |
Sort-Object id -unique | format-table -AutoSize -Wrap
ID
--
LOCAL SERVICE
NETWORK SERVICE NT AUTHORITY
SYSTEM          NT AUTHORITY
Computer Time
-------- ----
         4/3/2012 11:16:39 AM
         4/3/2012 11:16:39 AM
         4/3/2012 11:16:02 AM
Domain
------
NT AUTHORITY
Sorting -unique will ensure only one line per user ID, the most recent.
Needs more testing
.EXAMPLE
PS C:\Users\administrator> get-LastOn -computername server1 -newest 10000
 -maxIDs 10000 | Sort-Object time -Descending |
 Sort-Object id -unique | format-table -AutoSize -Wrap
ID              Domain
--              ------
Administrator   USS
ANONYMOUS LOGON NT AUTHORITY
LOCAL SERVICE   NT AUTHORITY
NETWORK SERVICE NT AUTHORITY
student         WIN7
SYSTEM          NT AUTHORITY
USSDC$          USS
WIN7$           USS
PS C:\Users\administrator>
Computer Time
-------- ----
         4/11/2012 10:44:57 PM
         4/3/2012 8:19:07 AM
         10/19/2011 10:17:22 AM
         4/4/2012 8:24:09 AM
         4/11/2012 4:16:55 PM
         10/18/2011 7:53:56 PM
         4/11/2012 9:38:05 AM
         10/19/2011 3:25:30 AM
.EXAMPLE
get-LastOn -newest 1000 -maxIDs 20
Only examines the last 1000 lines of the event log
.EXAMPLE
get-LastOn -computername server1| Sort-Object time -Descending |
Sort-Object id -unique | format-table -AutoSize -Wrap
#>

param (
    [string]$ComputerName = 'localhost',
    [int]$Newest = 5000,
    [int]$maxIDs = 5,
    [int]$logonEventNum = 4624, # log on successfully
    [int]$logoffEventNum = 4647
)

function get-LastOn([string]$ComputerName, [int]$Newest, [int]$maxIDs, [int]$logonEventNum, [int]$logoffEventNum) {

    $eventsAndIDs = Get-EventLog -LogName security -Newest $Newest |
        Where-Object {$_.instanceid -eq $logonEventNum -or $_.instanceid -eq $logoffEventNum} |
        Select-Object -Last $maxIDs -Property TimeGenerated,Message,ComputerName

    foreach ($event in $eventsAndIDs) {
        $id = ($event |
            parseEventLogMessage |
            where-Object {$_.fieldName -eq "Account Name"}  |
            Select-Object -last 1).fieldValue
    
        $domain = ($event |
            parseEventLogMessage |
            where-Object {$_.fieldName -eq "Account Domain"}  |
            Select-Object -last 1).fieldValue
    
        # hashtable
        $props = @{'Time'=$event.TimeGenerated;
            'Computer'=$ComputerName;
            'ID'=$id
            'Domain'=$domain}
    
        $output_obj = New-Object -TypeName PSObject -Property $props
    
        Write-Output $output_obj
    }
}

function parseEventLogMessage()
{
    [CmdletBinding()]
    param (
        [parameter(ValueFromPipeline=$True,Mandatory=$True)]
        [string]$Message
    )

    $eachLineArray = $Message -split "`n"

    foreach ($oneLine in $eachLineArray) {
        write-verbose "line:_$oneLine_"
        $fieldName,$fieldValue = $oneLine -split ":", 2
    } 
}

get-LastOn -ComputerName $ComputerName -Newest $Newest -maxIDs $maxIDs -logonEventNum $logonEventNum -logoffEventNum $logoffEventNum 
```

不过，如果上述脚本只是作为模块使用的话，倒不必这样做。

运行截图如下：

![Screen Shot 2018-06-12 at 4.49.27 PM.png]({{ site.url }}/images/powershell/2877F63723F51572B9F059A0626E09DB.png)

![Screen Shot 2018-06-12 at 4.52.15 PM.png]({{ site.url }}/images/powershell/1AEC19AEDAEADB1E0439F172F91A3996.png)