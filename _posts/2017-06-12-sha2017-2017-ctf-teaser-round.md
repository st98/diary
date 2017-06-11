---
layout: post
title: SHA2017 CTF Teaser round の write-up
categories: [ctf]
date: 2017-06-12 04:53:00 +0900
---

チーム Harekaze で [SHA2017 CTF Teaser round](https://ctf.sha2017.org/) に参加しました。最終的にチームで 650 点を獲得し、順位は得点 94 チーム中 8 位でした。うち、私は 2 問を解いて 300 点を入れました。

以下、解いた問題の write-up です。

## [Web 100] Follow Me

与えられた URL に、同じセッション ID で指定された国の IP アドレスからアクセスするのを 12 回繰り返すという問題でした。

実際にその国の IP アドレスからアクセスする必要はなく、X-Forwarded-For でごまかせるようです。

例えば南アフリカ共和国と指定された場合、以下のようにすると南アフリカ共和国からアクセスしたとみなされます。

```
$ curl https://followme.stillhackinganyway.nl/ -b "PHPSESSID=..." -H "X-Forwarded-For: 41.0.0.0"
...
     <div class="rightbar">
        <a href="?restart=1" class="restart">RESTART</a>
        <p>Visited countries [2/12]:</p>

        <div class="row"><div class="box" style="background:#c057d6"></div><span>South Africa</span></div>
        <div class="row"><div class="box" style="background:#086a9a"></div><span>New Caledonia</span></div>     </div>
        <p class="message">You just missed the hacker, he moved to: nc</p>
</body>
</html>
```

これを 12 回繰り返すとフラグが得られました。

```
$ curl https://followme.stillhackinganyway.nl/ -b "PHPSESSID=..." -H "X-Forwarded-For: 2.16.74.0"
...
        <p class="message">The hacker fled to the Netherlands. Guess he is visiting <a href='http://sha2017.org'>SHA2017</a> also. Hope to see you there in August. The flag is flag{df2e914109f97c70d915cd9e3ab88b83}.</p>
</body>
</html>
```

```
flag{df2e914109f97c70d915cd9e3ab88b83}
```

## [Crypto 200] Crypto Engine

入力されたテキストを暗号化して画像として返すサービスと、それによって暗号化されたフラグが与えられるので復号するという問題でした。

![flag.png](../images/2017-06-12_4.png)

私が問題を見た時点で、[@ki6o4](https://twitter.com/ki6o4) さんによって、以下のような挙動をすることが分かっていました。

- 3 文字が 1 タイルになる
- 端数が出た場合はテキストで表示される (例えば 8 文字の場合は 2 文字がテキストで表示される)
- 文字を増やしてもそれより前のタイルには影響しない

`AAA` `zzz` `0Az` を入力すると以下のような画像が返ってきました。

![AAA](../images/2017-06-12_1.png)
![zzz](../images/2017-06-12_2.png)
![0Az](../images/2017-06-12_3.png)

タイルの色はそれぞれ `rgb(115, 113, 112)` `rgb(72, 74, 75)` `rgb(2, 113, 75)` です。入力した文字列と xor するといずれも `[50, 48, 49]` になりました。これで暗号化にはおそらく xor が使われていると分かりました。

平文と何が xor されているかを 1 タイルずつ調べ、暗号化されたフラグと xor するスクリプトを書きましょう。

```python
import io
import requests
from PIL import Image

def get_image(s):
  r = requests.get('https://cryptoengine.stillhackinganyway.nl/encrypt?text=' + s)
  return Image.open(io.BytesIO(r.content))

def get_color(im, i):
  return im.getpixel((1 + 40 * i, 1))

flag = Image.open('flag')
res = ''
for i in range(12):
  im = get_image(res + 'aaa')
  c1 = [x ^ ord('a') for x in get_color(im, i)]
  c2 = get_color(flag, i)

  res += ''.join(chr(x ^ y) for x, y in zip(c1, c2))
  print(res)
```

```
$ python solve.py
fla
flag{d
flag{deaf
flag{deaf983
flag{deaf983eb3
flag{deaf983eb34e4
flag{deaf983eb34e485c
flag{deaf983eb34e485ce9d
flag{deaf983eb34e485ce9d2af
flag{deaf983eb34e485ce9d2aff0a
flag{deaf983eb34e485ce9d2aff0ae44
flag{deaf983eb34e485ce9d2aff0ae44f85
```

これで最後の 2 文字以外が分かりました。あとは残りを手で戻すとフラグが得られました。

```
flag{deaf983eb34e485ce9d2aff0ae44f852}
```