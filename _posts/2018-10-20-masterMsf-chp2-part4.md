---
title: MasterMsf 2.5 番外篇：Metasploit之水面以下
category: metasploit
---

# {{ page.title }}

## 水面以下：Metasploit的启动过程

注意，我使用的是Mac OSX上的Metasploit。

```bash
type msfconsole
msfconsole is /opt/metasploit-framework/bin/msfconsole

file /opt/metasploit-framework/bin/msfconsole
/opt/metasploit-framework/bin/msfconsole: POSIX shell script text executable, ASCII text
```

既然是脚本，我们就打开看一下：

关键部分如下：

```bash
cmd=`basename $0`
EMBEDDED=$SCRIPTDIR/../embedded
BIN=$EMBEDDED/bin
FRAMEWORK=$EMBEDDED/framework

if [ -e "$FRAMEWORK/$cmd" ]; then

  if [ $cmd = "msfconsole" ]; then
    if [ -n "`find $FRAMEWORK/$cmd -mmin +20160`" ]; then
      (>&2 echo "This copy of metasploit-framework is more than two weeks old.")
      (>&2 echo " Consider running 'msfupdate' to update to the latest version.")
    fi
#   Uncomment to enable libedit support
#   cmd="$cmd -L"
    cmd="$cmd $db_args"
  fi

  $BIN/ruby $FRAMEWORK/$cmd "$@"
else
  if [ "$FROM_CONSOLE_PATH" = true ]; then
    (cd $FRAMEWORK && $BIN/ruby $BIN/$cmd "$@")
  else
    $BIN/ruby $BIN/$cmd "$@"
  fi
fi
```

原来提醒我更新的代码就是这里。OK，关键的一句：

```bash
$BIN/ruby $FRAMEWORK/$cmd "$@"
```

那很明显即将运行的是`/opt/metasploit-framework/embedded/framework/msfconsole`，且它是一个Ruby脚本。打开看看：

```ruby
begin
  require Pathname.new(__FILE__).realpath.expand_path.parent.join('config', 'boot')
  require 'metasploit/framework/command/console'
  require 'msf/core/payload_generator'
  Metasploit::Framework::Command::Console.start
rescue Interrupt
  puts "\nAborting..."
  exit(1)
end
```

关键的一句：

```ruby
Metasploit::Framework::Command::Console.start
```

基于我们已有的对Metasploit的了解，很容易找到`/opt/metasploit-framework/embedded/framework/lib/metasploit/framework/command/console.rb`。打开，找到其中的`start`方法：

```ruby
  def start
    case parsed_options.options.subcommand
    when :version
      $stderr.puts "Framework Version: #{Metasploit::Framework::VERSION}"
    else
      spinner unless parsed_options.options.console.quiet
      driver.run
    end
  end
```

关键的一句是

```ruby
driver.run
```

但是在它前面有一个更有趣的东西：`spinner`。记得每次Metasploit启动时，都会有一句话：

```
[*] Starting the Metasploit Framework console...
```

并且这句话会一直变化：从第一个字母到最后一个字母循环改变其大小写，直到msfconsole启动起来。它的代码很简单也很有趣：

```ruby
# Based on pattern used for lib/rails/commands in the railties gem.
class Metasploit::Framework::Command::Console < Metasploit::Framework::Command::Base

  # Provides an animated spinner in a seperate thread.
  #
  # See GitHub issue #4147, as this may be blocking some
  # Windows instances, which is why Windows platforms
  # should simply return immediately.

  def spinner
    return if Rex::Compat.is_windows
    return if Rex::Compat.is_cygwin
    return if $msf_spinner_thread
    $msf_spinner_thread = Thread.new do
      base_line = "[*] Starting the Metasploit Framework console..."
      cycle = 0
      loop do
        %q{/-\|}.each_char do |c|
          status = "#{base_line}#{c}\r"
          cycle += 1
          off    = cycle % base_line.length
          case status[off, 1]
          when /[a-z]/
            status[off, 1] = status[off, 1].upcase
          when /[A-Z]/
            status[off, 1] = status[off, 1].downcase
          end
          $stderr.print status
          ::IO.select(nil, nil, nil, 0.10)
```

OK，回归正题。`driver`也在同一个文件中：

```ruby
  # The console UI driver.
  #
  # @return [Msf::Ui::Console::Driver]
  def driver
    unless @driver
      # require here so minimum loading is done before {start} is called.
      require 'msf/ui'

      @driver = Msf::Ui::Console::Driver.new(
          Msf::Ui::Console::Driver::DefaultPrompt,
          Msf::Ui::Console::Driver::DefaultPromptChar,
          driver_options
      )
    end

    @driver
  end
```

我们看到`@driver`，这里可以参考[Ruby 变量](http://www.runoob.com/ruby/ruby-variable.html)来了解Ruby中的变量。以单`@`开头的是属于对象的变量，未初始化时为nil。

我们找到`/opt/metasploit-framework/embedded/framework/lib/msf/ui/console/driver.rb`，这是一个大文件，里边有各种driver方法，用来处理不同的情况，比如用户设置了变量(`on_variable_set`)、用户输入了未知命令(`unknown_command`)等等。

**明确一下，我们当前的目的是找到`driver.run`。**但是由于前面代码中有`@driver = Msf::Ui::Console::Driver.new`，也就是说在`run`被调用前，`Msf::Ui::Console::Driver`的构造函数已经被调用。为了不遗漏有意思的东西，我们浏览一下这个构造函数，果然发现了有意思的地方：

```ruby
class Driver < Msf::Ui::Driver
  # ...
  
  # Initializes a console driver instance with the supplied prompt string and
  # prompt character.  The optional hash can take extra values that will
  # serve to initialize the console driver.
  def initialize(prompt = DefaultPrompt, prompt_char = DefaultPromptChar, opts = {})
    # ...
    
    # Process things before we actually display the prompt and get rocking
    on_startup(opts)
    # ...
  end
```

我们跟进看一下这个`on_startup`函数：

```ruby
  # Called before things actually get rolling such that banners can be
  # displayed, scripts can be processed, and other fun can be had.
  #
  def on_startup(opts = {})
    # Check for modules that failed to load
    if framework.modules.module_load_error_by_path.length > 0
      print_error("WARNING! The following modules could not be loaded!")

      framework.modules.module_load_error_by_path.each do |path, error|
        print_error("\t#{path}: #{error}")
      end
    end

    if framework.modules.module_load_warnings.length > 0
      print_warning("The following modules were loaded with warnings:")
      framework.modules.module_load_warnings.each do |path, error|
        print_warning("\t#{path}: #{error}")
      end
    end

    framework.events.on_ui_start(Msf::Framework::Revision)

    if $msf_spinner_thread
      $msf_spinner_thread.kill
      $stderr.print "\r" + (" " * 50) + "\n"
    end

    run_single("banner") unless opts['DisableBanner']

    opts["Plugins"].each do |plug|
      run_single("load '#{plug}'")
    end if opts["Plugins"]

    self.on_command_proc = Proc.new { |command| framework.events.on_ui_command(command) }
  end
```

也就是说，这里会检查一下有没有模块加载失败，并且会检查之前那个`spinner`的独立线程有没有结束，没有就kill掉，看起来逻辑还是挺严密的。另外插件也是在这里加载的。但是，我们更为关心的是其中这句

```ruby
run_single("banner") unless opts['DisableBanner']
```

这个`banner`就是每次打开Metasploit跳出的命令行图案，比如：

![Screen Shot 2018-10-24 at 9.57.35 AM.png]({{ site.url }}/images/metasploit/01ADD4B82059C2909B41A20F90C0449C.png)

`run_single`在`/opt/metasploit-framework/embedded/framework/lib/rex/ui/text/dispatcher_shell.rb`中，它会解析收到的参数，然后执行

```ruby
###
#
# The dispatcher shell class is designed to provide a generic means
# of processing various shell commands that may be located in
# different modules or chunks of codes.  These chunks are referred
# to as command dispatchers.  The only requirement for command dispatchers is
# that they prefix every method that they wish to be mirrored as a command
# with the cmd_ prefix.
#
###
module DispatcherShell
  # ...
  run_command(dispatcher, method, arguments)
```

这个函数在同一个文件中，它最终会执行

```ruby
dispatcher.send('cmd_' + method, *arguments)
```

也就是说，最终有一个`cmd_banner`的方法被`send`。这个`send`我一直没有找到。到这里思路是否就卡住了？我们回到`Msf::Ui::Console::Driver`的构造函数中，在`on_startup(opts)`前有一个操作：

```ruby
    # Console Command Dispatchers to be loaded after the Core dispatcher.
    CommandDispatchers = [
      CommandDispatcher::Modules,
      CommandDispatcher::Jobs,
      CommandDispatcher::Resource,
      CommandDispatcher::Developer
    ]
    # ...

    # Add the core command dispatcher as the root of the dispatcher
    # stack
    enstack_dispatcher(CommandDispatcher::Core)
    # ...
    
    # Load the other "core" command dispatchers
    CommandDispatchers.each do |dispatcher|
      enstack_dispatcher(dispatcher)
    end
```

我们跟入到`CommandDispatcher::Core`所在的`/opt/metasploit-framework/embedded/framework/lib/msf/ui/console/command_dispatcher/core.rb`中：

```ruby
  # Display one of the fabulous banners.
  #
  def cmd_banner(*args)
    banner  = "%cya" + Banner.to_s + "%clr\n\n"
    # ...
    banner << ("       =[ %-#{banner_trailers[:padding]+8}s]\n" % banner_trailers[:version])
    banner << ("+ -- --=[ %-#{banner_trailers[:padding]}s]\n" % banner_trailers[:exp_aux_pos])
    banner << ("+ -- --=[ %-#{banner_trailers[:padding]}s]\n" % banner_trailers[:pay_enc_nop])

    # TODO: People who are already on a Pro install shouldn't see this.
    # It's hard for Framework to tell the difference though since
    # license details are only in Pro -- we can't see them from here.
    banner << ("+ -- --=[ %-#{banner_trailers[:padding]}s]\n" % banner_trailers[:free_trial])
    # Display the banner
    print_line(banner)
```

终于找到你！而`Banner.to_s`即`/opt/metasploit-framework/embedded/framework/lib/msf/ui/banner.rb`中的

```ruby
  def self.to_s
    return self.readfile ENV['MSFLOGO'] if ENV['MSFLOGO']

    logos = []

    # Easter egg (always a cow themed logo): export/set GOCOW=1
    if ENV['GOCOW']
      logos.concat(Dir.glob(::Msf::Config.logos_directory + File::SEPARATOR + 'cow*.txt'))
    # Easter egg (always a halloween themed logo): export/set THISISHALLOWEEN=1
    elsif ( ENV['THISISHALLOWEEN'] || Time.now.strftime("%m%d") == "1031" )
      logos.concat(Dir.glob(::Msf::Config.logos_directory + File::SEPARATOR + '*.hwtxt'))
    elsif ( ENV['APRILFOOLSPONIES'] || Time.now.strftime("%m%d") == "0401" )
      logos.concat(Dir.glob(::Msf::Config.logos_directory + File::SEPARATOR + '*.aftxt'))
    else
      logos.concat(Dir.glob(::Msf::Config.logos_directory + File::SEPARATOR + '*.txt'))
      logos.concat(Dir.glob(::Msf::Config.user_logos_directory + File::SEPARATOR + '*.txt'))
    end

    logos = logos.map { |f| File.absolute_path(f) }
    self.readfile logos[rand(logos.length)]
  end
```

**Bingo，找到了代码中的一个彩蛋！**我们来尝试一下，先设置环境变量再启动msfconsole：

![Screen Shot 2018-10-24 at 10.56.12 AM.png]({{ site.url }}/images/metasploit/8BC84FC8F2FD4D3BE9C6FF6F9E6C04EF.png)

![Screen Shot 2018-10-24 at 10.57.47 AM.png]({{ site.url }}/images/metasploit/8E1BFCB250CD90521800D46D27AC629E.png)

这里有个问题：`to_s`函数第一句就直接返回了，那么为什么我们后面的彩蛋还会生效？这其实涉及到Ruby本身：参考[stackoverflow](https://stackoverflow.com/questions/5436034/is-there-a-ruby-one-line-return-if-x)，这种`return if`的写法就是如果后面的条件为真才返回。我们没有设置`MSFLOGO`环境变量，所以这里不会返回（这个变量的意图就是指定你要显示的banner的文件路径）。那么这个方法就没有返回值了吗？不是的，Ruby默认会把最后一条语句的值作为方法的返回值。这里就是`self.readfile logos[rand(logos.length)]`，也就是`readfile`方法的返回值。

看起来似乎所有logo都在`::Msf::Config.logos_directory`目录下。它位于`/opt/metasploit-framework/embedded/framework/lib/msf/base/config.rb`：

```ruby
  # Default configuration locations.
  Defaults    =
    {
      'ConfigDirectory'     => get_config_root,
      'ConfigFile'          => "config",
      'ModuleDirectory'     => "modules",
      'ScriptDirectory'     => "scripts",
      'LogDirectory'        => "logs",
      'LogosDirectory'      => "logos",
      'SessionLogDirectory' => "logs/sessions",
      'PluginDirectory'     => "plugins",
      'DataDirectory'       => "data",
      'LootDirectory'       => "loot",
      'LocalDirectory'      => "local"
    }
```

于是，我们找到了logo所在目录：`/opt/metasploit-framework/embedded/framework/data/logos`：

```
ls
3kom-superhack.txt            i-heart-shells.txt            missile-command.txt           pony-03.aftxt                 r7-metasploit.txt
cow-branded-longhorn.txt      json01.hwtxt                  mummy.hwtxt                   pony-04.aftxt                 tricks01.hwtxt
cow-head.txt                  metasploit-heart-red-bold.txt ninja.txt                     pony-05.aftxt                 wake-up-neo.txt
cowsay.txt                    metasploit-heart-red.txt      null-pointer-deref.txt        pumpkin01.hwtxt               workflow.txt
figlet.txt                    metasploit-park.txt           pentagram01.hwtxt             pumpkin02.hwtxt               zsploit-1.txt
gargoyle.hwtxt                metasploit-shield.txt         pony-01.aftxt                 pumpkin03.hwtxt               zsploit-2.txt
ghost01.hwtxt                 metasploit-trail.txt          pony-02.aftxt                 pumpkin04.hwtxt               zsploit-3.txt
```

看来有不少。我们随便挑一个看看，看`wake-up-neo`吧：

![Screen Shot 2018-10-24 at 11.19.31 AM.png]({{ site.url }}/images/metasploit/35FB87FA9FF8B2F597C36D3EA98B3771.png)

OK，banner的小插曲到这里结束。我们继续看Metasploit启动流程：

可以看到，`Msf::Ui::Console::Driver`继承了`Msf::Ui::Driver`。然而参考注释，`/opt/metasploit-framework/embedded/framework/lib/msf/ui/driver.rb`中的这个`Msf::Ui::Driver`是一个`abstract base class`。它的`run`如下：

```ruby
def run
  raise NotImplementedError
end
```

很明显需要子类去重写。但是`Msf::Ui::Console::Driver`中找不到`run`。那只剩下一种可能：`run`来自`Msf::Ui::Console::Driver`引入的mixins。通览代码，它做了如下引入：

```ruby
# The console driver processes various framework notified events.
include FrameworkEventManager
# The console driver is a command shell.
include Rex::Ui::Text::DispatcherShell

include Rex::Ui::Text::Resource
```

根据经验，`Rex::Ui::Text::DispatcherShell`看起来最可能是我们要找的东西。于是找到`/opt/metasploit-framework/embedded/framework/lib/rex/ui/text/dispatcher_shell.rb`。通览代码，它也没有`run`。我们继续看它的引入：

```ruby
include Resource

# DispatcherShell derives from shell.
include Shell
```

于是我们继续打开`/opt/metasploit-framework/embedded/framework/lib/rex/ui/text/shell.rb`。至此，我们算是找到了这个`run`方法：

```ruby
  # Run the command processing loop.
  #
  def run(&block)

    begin

      while true
        # If the stop flag was set or we've hit EOF, break out
        break if self.stop_flag || self.stop_count > 1

        init_tab_complete
        update_prompt

        line = get_input_line

        # If you have sessions active, this will give you a shot to exit
        # gracefully. If you really are ambitious, 2 eofs will kick this out
        if input.eof? || line == nil
          self.stop_count += 1
          next if self.stop_count > 1
          run_single("quit")

        # If a block was passed in, pass the line to it.  If it returns true,
        # break out of the shell loop.
        elsif block
          break if block.call(line)

        # Otherwise, call what should be an overriden instance method to
        # process the line.
        else
          ret = run_single(line)
          # don't bother saving lines that couldn't be found as a
          # command, create the file if it doesn't exist, don't save dupes
          if ret && self.histfile && line != @last_line
            File.open(self.histfile, "a+") { |f| f.puts(line) }
            @last_line = line
          end
          self.stop_count = 0
        end

      end
    # Prevent accidental console quits
    rescue ::Interrupt
      output.print("Interrupt: use the 'exit' command to quit\n")
      retry
    end
  end
```

这就是我们熟悉的msfconsole交互程序了。至此，我们对Metasploit的运作流程有了一定了解。

显然，所有的命令最终都会递交给`run_single`执行。而我们知道，最终是`cmd_`形式的命令被调用。也就是说，`/opt/metasploit-framework/embedded/framework/lib/msf/ui/console/command_dispatcher/core.rb`是这个交互器的核心。

通过`cat core.rb | grep "def cmd_"`我们可以发现，许多msfconsle中的命令都可以在其中找到。如`sessions`/`history`/`help`之类。其中help的help还蛮无奈的：

```ruby
    def cmd_help_help
      print_line "There's only so much I can do"
    end
```

但有的是找不到的，比如我们最常用的`use`。其实这些找不到的命令都被分解在了`command_dispatcher`目录下不同的文件中。

```
ls
auxiliary.rb core.rb      db.rb        encoder.rb   jobs.rb      nop.rb       post.rb
common.rb    creds.rb     developer.rb exploit.rb   modules.rb   payload.rb   resource.rb
```

比如：

```ruby
# command_dispatcher/modules.rb
          def commands
            {
              "back"       => "Move back from the current context",
              "advanced"   => "Displays advanced options for one or more modules",
              "info"       => "Displays information about one or more modules",
              "options"    => "Displays global options or for one or more modules",
              "loadpath"   => "Searches for and loads modules from a path",
              "popm"       => "Pops the latest module off the stack and makes it active",
              "pushm"      => "Pushes the active or list of modules onto the module stack",
              "previous"   => "Sets the previously loaded module as the current module",
              "reload_all" => "Reloads all modules from all defined module paths",
              "search"     => "Searches module names and descriptions",
              "show"       => "Displays modules of a given type, or all modules",
              "use"        => "Selects a module by name",
            }
          end
```

可以回过头看一下，我们在前面提到过`Msf::Ui::Console::Driver`中会加载以下命令解释模块：

```ruby
    CommandDispatchers = [
      CommandDispatcher::Modules,
      CommandDispatcher::Jobs,
      CommandDispatcher::Resource,
      CommandDispatcher::Developer
    ]
```

## 水面以下：use exploit/windows/http/rejetto_hfs_exec

下面，我们就可以来从不一样的“水下视角”来看看我们日常的操作：

打开msfconsole后，我们处于`run`方法的循环中。我输入

```
use exploit/windows/http/rejetto_hfs_exec
```

它转去`run_single(line)`，从`dispatcher_stack`选择有`use`命令的dispatcher：

```ruby
  # Run a single command line.
  def run_single(line, propagate_errors: false)
    arguments = parse_line(line)
    method    = arguments.shift
    found     = false
    error     = false
    # ...
    if (method)
      entries = dispatcher_stack.length

      dispatcher_stack.each { |dispatcher|
        next if not dispatcher.respond_to?('commands')
        begin
          # here!
          if (dispatcher.commands.has_key?(method) or dispatcher.deprecated_commands.include?(method))
            self.on_command_proc.call(line.strip) if self.on_command_proc
            run_command(dispatcher, method, arguments)
            found = true
          end
```

然后转去`run_command`，它会`dispatcher.send('cmd_' + method, *arguments)`，在我们的示例中就是去调用`command_dispatcher/modules.rb`中的`cmd_use`方法：

先去尝试加载模块：

```ruby
  # Uses a module.
  def cmd_use(*args)
    if args.length == 0 || args.first == '-h'
      cmd_use_help
      return false
    end

    # Divert logic for dangerzone mode
    args = dangerzone_codename_to_module(args)

    # Try to create an instance of the supplied module name
    mod_name = args[0]

    # ...
    begin
      mod = framework.modules.create(mod_name)
      unless mod
        # Try one more time; see #4549
        sleep CMD_USE_TIMEOUT
        mod = framework.modules.create(mod_name)
        unless mod
          print_error("Failed to load module: #{mod_name}")
          return false
        end
      end
    # ...
    end

    return false if (mod == nil)
```

其中`mod = framework.modules.create(mod_name)`将调用`/opt/metasploit-framework/embedded/framework/lib/msf/core/module_manager.rb`的`create`方法：

```ruby
    # Creates a module instance using the supplied reference name.
    #
    # @param name [String] A module reference name.  It may optionally
    #   be prefixed with a "<type>/", in which case the module will be
    #   created from the {Msf::ModuleSet} for the given <type>.
    #   Otherwise, we step through all sets until we find one that
    #   matches.
    # @return (see Msf::ModuleSet#create)
    def create(name)
      # Check to see if it has a module type prefix.  If it does,
      # try to load it from the specific module set for that type.
      names = name.split("/")
      potential_type_or_directory = names.first

      # if first name is a type
      if Msf::Modules::Loader::Base::DIRECTORY_BY_TYPE.has_key? potential_type_or_directory
        type = potential_type_or_directory
      # if first name is a type directory
      else
        type = TYPE_BY_DIRECTORY[potential_type_or_directory]
      end

      module_instance = nil
      if type
        module_set = module_set_by_type[type]

        # First element in names is the type, so skip it
        module_reference_name = names[1 .. -1].join("/")
        module_instance = module_set.create(module_reference_name)
      else
        # ...
      end

      module_instance
    end
```

加载成功后根据模块类型判断使用哪个dispatcher，并修改`active_module`：

```ruby
    # Enstack the command dispatcher for this module type
    dispatcher = nil
    case mod.type
      when Msf::MODULE_ENCODER
        dispatcher = Msf::Ui::Console::CommandDispatcher::Encoder
      when Msf::MODULE_EXPLOIT
        dispatcher = Msf::Ui::Console::CommandDispatcher::Exploit
      when Msf::MODULE_NOP
        dispatcher = Msf::Ui::Console::CommandDispatcher::Nop
      when Msf::MODULE_PAYLOAD
        dispatcher = Msf::Ui::Console::CommandDispatcher::Payload
      when Msf::MODULE_AUX
        dispatcher = Msf::Ui::Console::CommandDispatcher::Auxiliary
      when Msf::MODULE_POST
        dispatcher = Msf::Ui::Console::CommandDispatcher::Post
      else
        print_error("Unsupported module type: #{mod.type}")
        return false
    end

    # If there's currently an active module, enqueque it and go back
    if (active_module)
      @previous_module = active_module
      cmd_back()
    end

    if (dispatcher != nil)
      driver.enstack_dispatcher(dispatcher)
    end

    # Update the active module
    self.active_module = mod
    # ...
  end
```

那么很明显，我们这里会转入EXPLOIT的dispatcher：

在攻击者设置完选项后，输入exploit，转入`cmd_exploit`执行：


```ruby
  # Launches an exploitation attempt.
  def cmd_exploit(*args)
    opt_str = nil
    payload = mod.datastore['PAYLOAD']
    encoder = mod.datastore['ENCODER']
    target  = mod.datastore['TARGET']
    nop     = mod.datastore['NOP']
    bg      = false
    jobify  = false
    force   = false

    # ...

    if not payload
      payload = Exploit.choose_payload(mod, target)
    end

    begin
      session = mod.exploit_simple(
        'Encoder'        => encoder,
        'Payload'        => payload,
        'Target'         => target,
        'Nop'            => nop,
        'OptionStr'      => opt_str,
        'LocalInput'     => driver.input,
        'LocalOutput'    => driver.output,
        'RunAsJob'       => jobify)
      # ...
    end
```

之后看是否成功获得session：

```ruby
    # If we were given a session, let's see what we can do with it
    if (session)

      # If we aren't told to run in the background and the session can be
      # interacted with, start interacting with it by issuing the session
      # interaction command.
      if (bg == false and session.interactive?)
        print_line

        driver.run_single("sessions -q -i #{session.sid}")
      # Otherwise, log that we created a session
      else
        print_status("Session #{session.sid} created in the background.")
      end
    # ..
    # Worst case, the exploit ran but we got no session, bummer.
    else
      # If we didn't run a payload handler for this exploit it doesn't
      # make sense to complain to the user that we didn't get a session
      unless mod.datastore["DisablePayloadHandler"]
        fail_msg = 'Exploit completed, but no session was created.'
        print_status(fail_msg)
        begin
          framework.events.on_session_fail(fail_msg)
        # ...
```

## 总结

通过这一番梳理，我对Metasploit的内部结构又多了一些认识。但依然还有很多不懂的地方。后来在网上找到一本非常好的书：[Metasploit - The Exploit Learning Tree](https://www.exploit-db.com/docs/english/27935-metasploit---the-exploit-learning-tree.pdf)。

真的是路漫漫其修远兮，吾将上下而求索。