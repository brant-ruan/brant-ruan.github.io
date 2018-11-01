---
title: PowerShell实战指南 实验回顾
category: powershell
---

# {{ page.title }}

> 纵豆蔻词工，青楼梦好，难赋深情。

## 实验回顾 1-6 章

- 按日期将最新的100个安全日志条目输出为HTML

```powershell
Get-EventLog -LogName Security -Newest 100 | Sort-Object -Descending -Property TimeGenerated | ConvertTo-Html | Out-File sec.html
```

- 显示前五个最消耗虚拟内存进程

```powershell
Get-Process | Sort-Object -Descending -Property VM | Select-Object -First 5
```

![Screen Shot 2018-05-16 at 8.08.55 PM.png]({{ site.url }}/images/powershell/1E2D1D1368AA6971AFDB3CD607FDEC6B.png)

- 创建一个包含所有服务的CSV文件，只需列出服务名称和状态。所有出于运行状态的服务处于停止状态的服务之前

```powershell
Get-Service | Select-Object -Property Name,Status | Sort-Object -Descending -Property Status | Export-Csv services.csv
```

- 将BITS服务的启动项类型变更为手动

```powershell
Set-Service -Name "BITS" -StartupType Manual
```

- 显示计算机中所有文件名称为`Win*.*`的文件，以`C:\`开始

```powershell
Get-ChildItem -LiteralPath "C:\" -Include "Win*.*" -Recurse
```

![Screen Shot 2018-05-17 at 10.31.28 PM.png]({{ site.url }}/images/powershell/EA6BC21BEE759ADB1DC3FD035C0E62FA.png)

- 获取`C:\Program Files`的目录列表。包含所有子文件夹，把这些目录列表放到位于`C:\Dir.txt`的文本文件内

```powershell
Get-ChildItem -Path "C:\Program Files" -Recurse > C:\Dir.txt
```

- 获取最近20条安全事件日志的列表，将这些信息转化成XML格式。不要在硬盘上创建文件，而是把XML在控制台窗口直接显示出来

```powershell
Get-EventLog -LogName Security -Newest 20 | Format-Custom
Get-EventLog -LogName Security -Newest 20 | ConvertTo-Xml
```

- 获取一个服务列表，仅保留服务名称、显示名称和状态，然后将这些信息发送到一个HTML文件。在HTML文件中的服务信息表格之前显示“Installed Services”

```powershell
Get-Service | Select-Object -Property Name,DisplayName,Status | ConvertTo-Html -PreContent "Installed Services"
```

- 为Get-ChildItem创建一个新的别名D。仅将别名导出到一个文件里。关闭这个Shell，然后打开一个新的控制台窗口。把别名导入到新的Shell中。确认能够通过运行D获得一个目录列表

```powershell
New-Alias -Name "D" -Value "Get-ChildItem"
Export-Alias -Path "c:\d.txt" -Name "D"
Import-Alias -Path "c:\d.txt"
```

导出的别名文件内容如下：

```
# 别名文件
# 导出者 : Administrator
# 日期/时间 : 2018年5月18日 20:15:28
# 计算机: iZubw3nsaoh3v6Z
"D","Get-ChildItem","","None"
```

在新的窗口中测试：

![Screen Shot 2018-05-18 at 8.16.09 PM.png]({{ site.url }}/images/powershell/7638CE999F726BCAD90C995413D3462B.png)

- 显示系统中存在的事件日志列表

这里补充一下，`Get-EventLog`仅适用于传统事件日志。若要从使用`Vista`及更高版本中的事件日志技术的日志中获取事件，用`Get-WinEvent`命令。

```powershell
Get-EventLog -List
```

![Screen Shot 2018-05-18 at 8.21.58 PM.png]({{ site.url }}/images/powershell/17675CBCEA2A652BAADAB7581F34EF97.png)

- 展示Shell所在当前目录

```powershell
Get-Location
```

- 运行一个命令，展示最近你在Shell中运行过的命令。从中查找你在“显示系统中存在的事件日志列表”所运行的命令，并通过管道重新运行这个命令

```powershell
Get-History -Id 9 | Invoke-History
```

- 运行一个命令，从而在需要时通过覆盖旧日志来修改安全事件日志

```powershell
Limit-EventLog -LogName "Security" -OverflowAction "OverwriteAsNeeded"
```

- 通过`New-Item`新建一个目录

```powershell
New-Item -ItemType "Directory" -Path "C:\Review"
```

- 显示`HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`的内容

```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
```

- 找出重启电脑、关闭电脑、从一个工作组或域内移除电脑、恢复电脑系统并重建检查点的命令

```powershell
Stop-Computer
Restart-Computer
Remove-Computer
Restore-Computer
Checkpoint-Computer
```

注：这些命令都可通过`Get-Command *Computer*`查到。

- 什么命令可以修改一个注册表值

```powershell
Set-ItemProperty
```

## 实验回顾 1-14 章

- 1

Display a list of running processes in a table that includes only the process names and ID numbers. Don’t let the table have a large blank area between the two columns.

```powershell
Get-Process | 
Format-Table -Property processname,id -AutoSize
```

- 2

Run this: 

```powershell
Get-WmiObject -class Win32_UserAccount
```

Now run that same command again, but format the output into a table that has Domain and UserName columns. The UserName column should show the users' Name property, like this:

```
Domain   UserName
=======  ========
COMPANY  DonJ
```

Make sure the second column header says UserName, and not Name.

```powershell
Get-WmiObject -class Win32_UserAccount |
Format-Table -Property Domain,@{l='Username';e={$_.Name}} -AutoSize
```

![Screen Shot 2018-06-13 at 2.55.33 PM.png]({{ site.url }}/images/powershell/7336FB0BE0826797766F49BB9EAA897A.png)

- 3

Have two computers (it's OK to use localhost twice) run this command:

```powershell
Get-PSProvider
```

Use Remoting to do this. Ensure that the output includes the computer names.

```powershell
Invoke-Command -ComputerName localhost,localhost -command {Get-PSProvider}
```

- 4

Use Notepad to create a file named C:\Computers.txt. In that file, put the following:

```
Localhost
localhost
```

You should have those two names on their own lines in the file—two lines total. Save the file and close Notepad. Then write a command that will list the running services on the computer names in C:\Computers.txt.

```powershell
Invoke-Command -ComputerName (Get-Content .\computers.txt) -command {Get-Service | Where-Object -FilterScript {$_.Status -like "runn*"}}
```

- 5

Query all instances of `Win32_LogicalDisk`. Display only those instances that have a DriveType property containing 3 and that have 50 percent or more free disk space. 

Hint: to calculate free space percentage, it’s freespace/size * 100.

Note that the –Filter parameter of Get-WmiObject cannot contain mathematical expressions.

```powershell
Get-WmiObject Win32_LogicalDisk | 
Where-Object -FilterScript {$_.drivetype -eq 3 -and ($_.freespace / $_.size) -gt 0.5}
```

![Screen Shot 2018-06-13 at 3.44.19 PM.png]({{ site.url }}/images/powershell/0DDBAC919A4797EBDCB603F1A0CF7E46.png)

- 6

Display a list of all WMI classes in the root\CIMv2 namespace.

```powershell
Get-CimClass -Namespace root\CIMv2
```

- 7

Display a list of all Win32_Service instances where the StartMode is Auto and the State is not Running.

```powershell
Get-WmiObject win32_service | 
Where-Object -FilterScript {$_.startmode -eq "auto" -and $_.state -ne "running"} |
Format-List
```

- 8

Find a command that can send email messages. What are the mandatory parameters of this command?

```powershell
Send-MailMessage
```

- 9

Run a command that will display the folder permissions on C:\.

```powershell
Get-Acl -Path c:\
```

- 10

Run a command that will display the permissions on every subfolder of C:\Users. Just the direct subfolders; you don’t need to recurse all files and folders. You’ll need to pipe one command to another command to achieve this.

```powershell
Get-ChildItem C:\Users | Get-Acl
```

![Screen Shot 2018-06-13 at 3.43.22 PM.png]({{ site.url }}/images/powershell/BA8A77431C8DF8D4997258AABE93DB4D.png)

- 11

Find a command that will start Notepad under a credential other than the one you’ve used to log into the shell.

```powershell
Start-Process -FilePath notepad -Credential xxx
```

- 12

Run a command that makes the shell pause, or idle, for 10 seconds.

```powershell
Start-Sleep 10
```

- 13

Can you find a help file (or files) that explains the shell’s various operators?

```powershell
help *operators*
```

![Screen Shot 2018-06-13 at 3.42.55 PM.png]({{ site.url }}/images/powershell/9E7EFBD4B81EBA6252E0A4AA4205B53D.png)

- 14

Write an informational message to the Application event log. Use a category of 1 and raw data of 100,100.

```powershell
Write-EventLog -LogName Application -EntryType Information -RawData 100,100 -Category 1 -EventId 1 -Message "hello" -Source msiinstaller
```

- 15

Run this command:

```powershell
Get-WmiObject –Class Win32_Processor
```

Study the default output of this command. Now, modify the command so that it dis- plays in a table. The table should include each processor’s number of cores, manufacturer, and name. Also include a column called “MaxSpeed” that contains the processor’s maximum clock speed.

```powershell
Get-WmiObject -Class Win32_Processor |
Format-Table -Property NumberofCores,Manufacturer,Name,@{l='MaxSpeed';e={$_.MaxClockSpeed}} -AutoSize
```

![Screen Shot 2018-06-13 at 3.42.19 PM.png]({{ site.url }}/images/powershell/30E81BFB3FCA1912C4A0090B00ED250D.png)

- 16

Run this command:

```powershell
Get-WmiObject –Class Win32_Process
```

Study the default output of this command, and pipe it to Get-Member if you want. Now, modify the command so that only processes with a peak working set size greater than 5,000 are displayed.

```powershell
Get-WmiObject -Class Win32_Process | 
Where-Object -FilterScript {$_.PeakWorkingSetSize -gt 5000}
```

## 实验回顾 1-19 章

- 1

Create a list of running processes. The list should include only process name, ID, VM, and PM columns. Put the list into an HTML-formatted file named C:\Procs.html. Make sure that the HTML file has an embedded title of “Current Processes”. Display the file in a web browser and make sure that title appears in the browser window’s titlebar.

```powershell
Get-Process | 
Select-Object -Property Name,Id,VM,PM |
ConvertTo-Html -Title "Current Processes" |
Out-File C:\Procs.html
```

![Screen Shot 2018-06-13 at 5.34.59 PM.png]({{ site.url }}/images/powershell/F327935F30475453AEA16FC9747B275C.png)

- 2

Create a tab-delimited file named C:\Services.tdf that contains all services on your computer. "`t" (backtick t inside double quotes) is PowerShell’s escape sequence for a horizontal tab. Include only the services’ names, display names, and statuses.

我想到的方法不太优雅，还用到了追加重定向：

```powershell
Get-Service |
Select-Object -Property Name,DisplayName,Status |
ForEach-Object -Process {$line = $_.Name + "`t" + $_.DisplayName + "`t" + $_.Status; $line >> Services.tdf}
```

不过最终能够达到目的：

![Screen Shot 2018-06-13 at 5.46.18 PM.png]({{ site.url }}/images/powershell/F495301D9B84CBF0EEEC4AD0F4EA22D9.png)

参考答案很优雅：

```powershell
Get-Service |
Select-Object -Property Name,DisplayName,Status | Export-CSV c:\services.tdf –Delimiter "`t"
```

竟然是替换掉csv格式默认的逗号.....

结果也比我的专业：

![Screen Shot 2018-06-13 at 5.49.27 PM.png]({{ site.url }}/images/powershell/20B9FF1BFFD16AE60DB94524199655E5.png)

不过最终哪个更好用，也不好说。我觉得我生成的文档更简洁，方便程序调用。

- 3

Repeat task 1, modifying your command so that the VM and PM columns of the HTML file display values in megabytes (MB), instead of bytes. The formula to calculate mega- bytes, displaying the value as a whole number, goes something like $_.VM / 1MB –as [int] for the VM property.

```powershell
Get-Process | 
Select-Object -Property Name,Id,@{l="VM(MB)";e={$_.VM / 1MB -as [int]}},@{l="PM(MB)";e={$_.PM / 1MB -as [int]}} |
ConvertTo-Html -Title "Current Processes" |
Out-File C:\Procs.html
```

![Screen Shot 2018-06-13 at 5.53.21 PM.png]({{ site.url }}/images/powershell/0A4A7A7684926F5538A7A28D235080FE.png)

**总结**

这本书的学习到这里就结束了。感谢作者Don Jones和Jeffery Hicks。感谢同济大学图书馆。译者也辛苦了，虽然这翻译并不好。