---
layout: post
title: サイバーコロッセオxSECCON 2016 に参加しました
categories: [ctf, seccon]
date: 2017-03-07 00:15:00 +0900
---

チーム Harekaze として [@hiww](https://twitter.com/hiww) さん、[@jtwp470](https://twitter.com/jtwp470) さん、[@megumish](https://twitter.com/megumish) さんと[サイバーコロッセオ×SECCON 2016](http://2016.seccon.jp/news/#137)に参加しました。最終的にチームで 788 点を獲得し、順位は参加 24 チーム中 13 位でした。

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">サイバーコロッセオxSECCON 終了しました。優勝dodododo、準優勝urandom、3位NaruseJunという結果でした。参加した皆様お疲れ様でした！ <a href="https://twitter.com/hashtag/seccon?src=hash">#seccon</a> <a href="https://t.co/ekMDne43lh">pic.twitter.com/ekMDne43lh</a></p>&mdash; SECCON CTF (@secconctf) <a href="https://twitter.com/secconctf/status/838305966730850304">2017年3月5日</a></blockquote>
<script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

競技形式は King of the Hill 形式とチームメンバー全員が (たぶん) 経験したことのないものでしたが、善戦できたかなと思います。

今回の形式は一言でいうと Jeopardy 形式と Attack & Defense 形式のハイブリッドでした。チームの順位は攻撃ポイント [^ap] と防御ポイント [^dp] の合算で決まります。

他のメンバーの write-up はこちら。

- [@jtwp470](https://twitter.com/jtwp470) さん : [サイバーコロッセオに参加してきました - jtwp470’s blog](http://jtwp470.hatenablog.jp/entry/cyber-colosseo-2016)

以下、私が見ていた問題の write-up です。

## 弐

問題文にある `nc 10.100.2.1 11111` で問題サーバに接続できました。入力したコマンドがそのまま実行されるようですが、試しに `ls` しようとすると `/bin/ash: can't fork` と怒られてしまいました。

どんなファイルがあるか `echo *` で調べてみましょう。

```
echo *
keyword1.txt keyword2.txt keyword3.txt nano nano.c pico pico.c
```

どうやってファイルの中身を見ればいいんだろう…と詰まりました。

伍を解いたあとなんとなく 22222 番ポートに接続してみると、fork の制限がゆるくなった状態で動いていました。`cat keyword1.txt` で 1 個目のフラグが得られました。(フラグの内容は失念)

`ls -la` してみると、keyword2.txt は nano というユーザの権限で読めるようでした。同じディレクトリにある nano という実行ファイルと nano.c は nano というユーザのものでした。nano.c の内容は次のようなものでした。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
        char shellcode[140];
        fread(shellcode, 1, 140, stdin);
        setreuid(geteuid(), -1);
        (*(void (*)())shellcode)();
        return 0;
}
```

入力したシェルコードがそのまま実行されています。[x86 alphanumeric shellcodeを書いてみる - ももいろテクノロジー](http://inaz2.hatenablog.com/entry/2014/07/11/004655)のシェルコードを投げるとシェルが取れ、2 個目のフラグが得られました。

```
SECCON{nano_easy_shellcode}
```

keyword3.txt は pico というユーザの権限で読めるようでした。今度は pico と pico.c が pico というユーザのもので、pico.c の内容は次のようなものでした。

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int auth(char *user, char *pass)
{
  printf("user: %s\n", user);
  printf("pass: %s\n", pass);
}

int evil()
{
   printf("H@ck3d!!!\n");
   exit(1);
}

int input()
{
  int a = 0x33333333;
  int b = 0x44444444;
  char user[8] = "";
  char pass[8] = "";

  setreuid(geteuid(), -1);

  printf("addr: 0x%08x\n", (unsigned int)pass);
  scanf("%s", user);
  scanf("%s", pass);

  auth(user, pass);
}

int main() {
  input();
}
```

自明な脆弱性があり、バッファのアドレスも教えてくれ、しかもバイナリは SSP も NX も無効でしたが当日は解けず。

## 参

http://10.100.3.1:8080/ で Web カメラが見られるのでハックしようという感じの問題でした。

動いているのはよくあるライブカメラのようなサービスで、ボタンを押すとカメラを左右に移動させることができます。カメラを右に移動させ続けると `SECC` とフラグっぽい文字列が見えます。が、それ以上右に移動させることはできない様子でした。

1 個目のフラグはチームメンバーが取っていました。これはボタンに disabled 属性がつけられているだけで、これを消して押すとまだ右に移動させることができ、フラグが見られるようでした。

しばらく後に [@jtwp470](https://twitter.com/jtwp470) さんがポートスキャンをかけて、57017 番で何かサービスが動いているのを見つけていました。

57017 番ポートでは動いている Web カメラのデバッグができるようでした。何ができるのかよくわかりませんでしたが、`help` ができると教えてもらいました (つらい)。

```
Welcome to webcam.
> help
Usage: <command> [<argument>...]
    admin: set mode admin
    exit: exit the system
    help: show help
    show: show information
    ?: show help
```

`admin` を入力すると admin になれるようです。admin になって `help` を実行しましょう。

```
> admin
admin> help
Usage: <command> [<argument>...]
    config: set mode configuration
    exit: set mode user
    help: show help
    show: show information
    ?: show help
```

`config` というコマンドが増えました。今度は `config` で設定モードになれるようです。設定モードで `help` を実行しましょう。

```
admin> config
config> help
Usage: <command> [<argument>...]
    exit: set mode admin
    help: show help
    save: save configuration
    set: set configuration
    show: show configuration
    ?: show help
```

いろいろ試していると `show help` で `show` コマンドのヘルプが見られるようでした。

```
config> show help
Usage: show <argument> [<argument>...]
    config: show configuration
    date: show date
    help: show help
    version: show system version
    ?: show help
```

`show config` で 2 個目のフラグが取れました。

```
config> show config
    keyword SECCON{this_is_the_default_keyword}
```

続いて `save` コマンドと `set` コマンドについて調べてみましょう。

```
config> save help
Usage: save [<argument>...]
    [<filename>]: save the configuration into a file <filename>,
                  default file name is "config"
    help: show help
    ?: show help
config> set help
Usage: set <argument> [<argument>...]
    help: show help
    keyword: set keyword
    ?: show help
```

`save ...` で保存ができ、`set keyword ...` でキーワードが設定できるようです。`set keyword (チームのキーワード)` してから `save flag.txt` で指定されたファイルに書き込むと防御ポイントが得られました。

## 四

問題文にある `ssh user07@10.100.4.1` で問題サーバに接続できました。接続して /stage1.txt を見てみると、

```
[user07@caitsith ~]$ /usr/bin/cat /stage1.txt
Question 1:

What is your user ID and group ID?
Execute /usr/bin/stage1 with your answer passed to command line.

  $ /usr/bin/stage1 $your_user_id_here $your_group_id_here

If your answer is correct, you will be able to read /stage2.txt file.
```

`id` でユーザ ID とグループ ID を調べましょう。

```
[user07@caitsith ~]$ id
uid=1006(user07) gid=1006(user07) groups=1006(user07)
[user07@caitsith ~]$ /usr/bin/stage1 1006 1006
Good! Proceed to next stage.
```

/stage1.txt にあったように /stage2.txt を `/usr/bin/cat` で読もうとしたものの…読めませんでした。`echo $(</stage2.txt)` をしてみると読めました。

```
[user07@caitsith ~]$ echo $(</stage2.txt)
Question 2: Execute /usr/bin/stage2 . You likely find that something is preventing /usr/bin/stage2 from proceeding to next stage. If you found the reason and solve it, you will be able to read /stage3.txt file. Note that you cannot read /usr/bin/stage2 to know what /usr/bin/stage2 is doing. Find an alternative approach.
```

.bash_history を見ると `strace -i ...` という文字列を見つけたので実行してみると、

```
[user07@caitsith ~]$ strace -i /usr/bin/stage2
[00007f22965c69f7] execve("/usr/bin/stage2", ["/usr/bin/stage2"], [/* 22 vars */]) = 0
[00007f5c9d4c6b3c] brk(0)               = 0x9a6000
[00007f5c9d4c782a] mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f5c9d6cd000
[00007f5c9d4c7747] access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
[00007f5c9d4c76c7] open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[00007f5c9d4c7654] fstat(3, {st_mode=S_IFREG|0644, st_size=20090, ...}) = 0
[00007f5c9d4c782a] mmap(NULL, 20090, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f5c9d6c8000
[00007f5c9d4c76e7] close(3)             = 0
[00007f5c9d4c76c7] open("/lib64/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
[00007f5c9d4c7707] read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0@\34\2\0\0\0\0\0"..., 832) = 832
[00007f5c9d4c7654] fstat(3, {st_mode=S_IFREG|0755, st_size=2118128, ...}) = 0
[00007f5c9d4c782a] mmap(NULL, 3932672, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f5c9d0ee000
[00007f5c9d4c78c7] mprotect(0x7f5c9d2a4000, 2097152, PROT_NONE) = 0
[00007f5c9d4c782a] mmap(0x7f5c9d4a4000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1b6000) = 0x7f5c9d4a4000
[00007f5c9d4c782a] mmap(0x7f5c9d4aa000, 16896, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f5c9d4aa000
[00007f5c9d4c76e7] close(3)             = 0
[00007f5c9d4c782a] mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f5c9d6c7000
[00007f5c9d4c782a] mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f5c9d6c5000
[00007f5c9d4aff87] arch_prctl(ARCH_SET_FS, 0x7f5c9d6c5740) = 0
[00007f5c9d4c78c7] mprotect(0x7f5c9d4a4000, 16384, PROT_READ) = 0
[00007f5c9d4c78c7] mprotect(0x600000, 4096, PROT_READ) = 0
[00007f5c9d4c78c7] mprotect(0x7f5c9d6ce000, 4096, PROT_READ) = 0
[00007f5c9d4c78a7] munmap(0x7f5c9d6c8000, 20090) = 0
[00007f5c9d1e68b7] socket(PF_LOCAL, SOCK_DGRAM, 0) = 3
[00007f5c9d1d6a10] open("/var/tmp/seccon/flag.txt", O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0644) = -1 EEXIST (File exists)
[00007f5c9d1e6803] sendto(3, "0 172.16.7.111 65509 10.100.4.1 "..., 34, 0, {sa_family=AF_LOCAL, sun_path=@"/seccon/attackmon"}, 20) = 34
[00007f5c9d1d6ba0] close(3)             = 0
[00007f5c9d1d6c60] write(2, "Oops! Your answer is wrong.\n", 28Oops! Your answer is wrong.
) = 28
[00007f5c9d1ac9c9] exit_group(0)        = ?
[????????????????] +++ exited with 0 +++
```

ここで何をすればいいのかわからず、次には進めませんでした。

## 伍

問題文にある `nc 10.100.5.1 11111` で問題サーバに接続できました。これも弐と同様に入力したコマンドがそのまま実行されるようです。まずどんなファイルがあるか調べましょう。

```
ls -la
total 20
drwxr-xr-x    2 busybox  busybox       4096 Feb 25 21:35 .
drwxr-xr-x    5 root     root          4096 Feb 19 00:56 ..
-r--r--r--    1 root     root            33 Feb 25 21:35 keyword1.txt
-r--------    1 nano     root            35 Feb 25 21:35 keyword2.txt
-r--------    1 pico     root            24 Feb 25 21:35 keyword3.txt
```

`cat keyword1.txt` で 1 個目のフラグが得られました。

```
cat keyword1.txt
SECCON{exec cat /etc/inetd.conf}
```

/etc/inetd.conf を見ると、

```
cat /etc/inetd.conf
11111 stream tcp nowait root /root/daemon daemon /home/busybox 19 1 4194304 2 ip 1001 10 10240 0 /bin/ash
22222 stream tcp nowait root /root/daemon daemon /home/busybox 19 1 4194304 3 ip 1001 30 10240 1 /bin/ash
```

22222 番ポートでサービスが動いているようでした。

続いて keyword2.txt は nano というユーザの権限で読めるようです。`nano keyword2.txt` で 2 個目のフラグが得られました。

```
nano keyword2.txt
GNU nano 2.7.2                  File: keyword2.txt                            

SECCON{nano_is_simple_text_editor}
```

keyword3.txt は pico というユーザの権限で読めるようです。何のファイルが pico のものか調べましょう。

```
find / -user pico 2>/dev/null
/home/busybox/keyword3.txt
/usr/share/nginx/html/flag.txt
/usr/bin/vipp
/tmp/zzz
/tmp/po
/tmp/111
```

`/usr/bin/vipp keyword3.txt` しようとしたものの、なかなか見ることができません。何度か試すと 3 個目のフラグが得られました。(フラグの内容は失念)

/usr/share/nginx/html/flag.txt にチームのキーワードを書き込めば防御ポイントが得られるはずでしたが、どう書き込めばいいのか思いつかず得られませんでした。つらい。

## 感想


特に攻撃ポイントについては 1 つの正答で少なくとも 100 点ものポイントを得られたため、もしあと 1 個取れていたら 10 位以内に入れたなあと思い悔しいです。今後もし King of the Hill 形式の CTF に参加できる機会があればリベンジしたいです。

私は King of the Hill 形式での CTF も、このチームでオンサイトの CTF に参加するのも初めてでしたが、楽しむことができ満足です。

ただ、Twitter でも言ってましたが、Web 問が欲しかったですね…。

[^ap]: 問題サーバを攻撃し、あらかじめ仕込まれているフラグをスコアサーバに送信することで得られるポイント
[^dp]: 問題サーバの指定されたファイルに、チームごとに設定されるユニークなキーワードを書き込み保持することで得られるポイント
