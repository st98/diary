---
layout: post
title: SECCON 京都大会 (サイバー甲子園) に参加しました
categories: [ctf]
date: 2016-11-12 22:44:00 +0900
---

crane さん ([@crane_memory](https://twitter.com/crane_memory)) と一緒にチーム omakase として SECCON 京都大会 (サイバー甲子園) に参加しました。  
最終的にチームで 2410 点を獲得し、チーム順位は 2 位 (10 チーム中) でした。

## 競技時間中に私が解いた問題
### [Sample 10] TRY FIRST
フラグ提出のテスト。問題文に書かれているフラグを投げるだけでした。

```
SECCON{Cyber_Koshien}
```

### [Binary 100] Assembler Tanka
問題文紛失。アセンブラ短歌を実行しろという問題でした。`0x53454343` (SECC) のような数値が見えたので集めてデコードするとフラグが出てきました。

```
SECCON{57577}
```

### [Binary 200] guess the flag
`strings -e L ./guessflag`

```
SECCON{Piece of cake!?}
```

### [Crypto 100] gokai?
問題名の通りに 5 回、base64 としてデコード。

```python
print 'Vm14U1ExWXhTa2RTV0dSUVZsUnNjMVJWVm5kUk1WcFZVV3hhVG1GNlZrcFVWVkYzVUZFOVBRPT0='.decode('base64').decode('base64').decode('base64').decode('base64').decode('base64')
```

フラグが出てきました。

```
SECCON{BASE64}
```

### [Crypto 100] very easy
hex デコード。

```
SECCON{hex_dump}
```

### [Crypto 200] decode the flag
OpenSSL で `53CC0NZOl6` をパスワードに暗号化したのはいいものの、どの形式で暗号化したか忘れてしまったので復号してほしいという問題。使える形式で総当たりするだけ。

```python
import re
import subprocess
s = '''
aes-128-cbc       aes-128-ecb       aes-192-cbc       aes-192-ecb
aes-256-cbc       aes-256-ecb       base64            bf
bf-cbc            bf-cfb            bf-ecb            bf-ofb
camellia-128-cbc  camellia-128-ecb  camellia-192-cbc  camellia-192-ecb
camellia-256-cbc  camellia-256-ecb  cast              cast-cbc
cast5-cbc         cast5-cfb         cast5-ecb         cast5-ofb
des               des-cbc           des-cfb           des-ecb
des-ede           des-ede-cbc       des-ede-cfb       des-ede-ofb
des-ede3          des-ede3-cbc      des-ede3-cfb      des-ede3-ofb
des-ofb           des3              desx              rc2
rc2-40-cbc        rc2-64-cbc        rc2-cbc           rc2-cfb
rc2-ecb           rc2-ofb           rc4               rc4-40
seed              seed-cbc          seed-cfb          seed-ecb
seed-ofb
'''
s = re.findall(r'[a-z0-9-]+', s)
r = ''
for c in s:
  try:
    r = subprocess.check_output('openssl {} -d -in flag.encrypted -pass pass:53CC0NZOl6'.format(c).split(' '))
    print(r)
  except:
    pass
```

雑なスクリプトですがフラグは出ます。

```
SECCON{R U 4 0P3N55L M457ER?}
```

### [Crypto 100] onlineyosen
PNG が渡されます。ペイントで開いて背景を適当な色で塗りつぶしてみると、塗りつぶされない箇所がちょこっとあるのを見つけました。

stegsolve.jar で BGR の順に LSB を取ると 2 進数っぽい文字列が現れました。あとは適当にデコードするだけ。

```python
x = 0b101001101000101010000110100001101001111010011100111101101001000011010010110010001100101011100110110010101100011011100100110010101110100010010010110110100110100011001110011001101111101
print hex(x)[2:-1].decode('hex')
```

```
SECCON{HidesecretIm4g3}
```

### [Network 100] gettheflag
与えられた pcap を見ると、`/flag.php` に `n=0` を POST して JSON が返ってくる、というのを何度も繰り返している様子が確認できます。

どうやら `n=0` でフラグの 1 文字目が返ってくるようですが、`{"result":"success","data":{"char":".","last":false}}` のような JSON も返ってきているのが確認できます。

`"last":true` になっている文字が本来のフラグの一部のようなので、これだけ `strings gettheflag.pcap | grep true` で集めるとフラグが出てきました。

```
SECCON{42LbAwGV}
```

### [Network 200] get the flag
与えられた pcap を見ると、FTP で通信している様子が確認できます。ユーザ名 (`seccon2016`) とパスワード (`kyoto=beautiful`) も丸見えなので、得られた情報を使ってこの pcap に記録されている FTP サーバにアクセス。

`flag.zip` をダウンロードして展開すると、フラグが出てきました。

```
SECCON{Plain text communication is dangerous}
```

### [Programming 100] megrep
適当なエディタで与えられたテキストファイルを開いてみると `BzBzBzBzBzBzBz...` と Bz だらけ。

バイナリエディタの Bz でこのファイルを開いてビットマップ表示をしてみるとフラグが出ました。

```
SECCON{bsdbanner}
```

### [Programming 100] x2.txt
2 倍。

```python
s = open('x2.txt', 'r').read()
print ''.join(chr(ord(x) / 2) for x in s)
```

```
SECCON{lshift_or_rshift}
```

### [Programming 200] decode the trapezoid QR code
歪んでいる QR コードが渡されます。適当に画像を加工して読み取るとフラグが出ました。

```python
from PIL import Image
im = Image.open('qrcode.png')
w, h = im.size
im2 = Image.new('RGB', (1225, h))

for y in range(h):
  im2.paste(im.crop((0, y, w, y+1)), (490 - y*2, y))

im2.show()
```

```
SECCON{The QR code system was invented by Denso Wave in Japan}
```

### [Programming 100] sum primes
12345 番目から 31337 番目の素数の合計を出せという問題。ひどいスクリプトですがいけます。

```python
import sympy
s = []
i = 2
j = 0
while j < 31337:
  if sympy.ntheory.primetest.isprime(i):
    s.append(i)
    j += 1
  i += 1
print 'SECCON{%d}' % (sum(s[12345-1:31337]))
```

```
SECCON{4716549971}
```

### [Web 100] sessionhijack
Web アプリで Admin としてログインしろという問題。今回のサイバー甲子園では唯一の Web 問でした。

まずログイン後の画面に Stored XSS が存在したので、XSS を仕込むと Admin が踏んで Cookie を残していってくれるのかと思ったのですが、よく見ると Cookie が httponly だったので断念。

Cookie をもうちょっとよく見てみると、`JSESSIONID=6364d3f0f495b6ab9dcf8d3b5c6e0b01` のような形式になっていました。試しにググってみるとこれは `md5(32)` の様子。

`JSESSIONID` に `c4ca4238a0b923820dcc509a6f75849b` (`md5(1)`) をセットしてみるとフラグが表示されました。

```
SECCON{SequentialMD5}
```

### [Trivia 100] blacked out PDF
黒塗りの PDF が渡されます。全選択してコピペすると黒塗りの下のテキストが読めました。

```
SECCON{kuronuri_ha_dame_zettai}
```

### [Trivia 200] blacked out PDF again
黒塗りの PDF が渡されます。先ほどとは違い全選択してコピペしてもテキストは読めません。

ならばと [yob/pdf-reader](https://github.com/yob/pdf-reader) の `pdf_text` に投げてみると読めました。

```
SECCON{1234567890}
```

### [Trivia 300] how much a fine?
選択肢として 7 つの法律があり、与えられた 5 つの行為がどの法律に抵触するかを答える問題でした。

```
SECCON{42576}
```
