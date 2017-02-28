---
layout: post
title: SECCON 京都大会 (サイバー甲子園) に参加しました
categories: [ctf, seccon]
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
問題文紛失。アセンブラ短歌を実行しろという問題でした。`0x43434553` (SECC) のような数値が見えたので集めてデコードするとフラグが出てきました。

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

どうやら `n=0` で `{"result":"success","data":{"char":"S","last":true}}` のような形でフラグの 1 文字目が返ってくるようですが、`{"result":"success","data":{"char":".","last":false}}` のような JSON も返ってきているのが確認できます。

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
与えられた文字列は文字コードが 2 倍にされているようです。戻しましょう。

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
print 'SECCON{' + str(sum(s[12345-1:31337])) + '}'
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

## 終わってから解けた問題

### [Binary 100] sl is not ls
ELF ファイルですが、私の環境だとそのまま実行すると `Error opening terminal: xterm-256color.` というようなエラーが出て怒られるだけでした。

`strace ./sl` を実行してみると、どうやら `/home/user/.terminfo/x/xterm-256color` や `/usr/share/terminfo/x/xterm-256color` が存在しないためにコケているとわかります。

ならばと `TERM='xterm-color' ./sl` で実行してみると動きました。

この方法で `./sl -h` を実行すると、以下のような結果になりました。

```
Try `./sl [-h] [OPTIONS]' for more information.
                OPTIONS: -[alFS]
```

`./sl -S` を実行するとフラグが表示されました。

```
SECCON{SL_l0v3}
```

---

本番では実行できずに終わりでした。なぜ実行できないか探ってみるべきでした。

### [Binary 300] fakeransom
exe ファイル (`binary300.exe`) と、この exe ファイルを使って暗号化されたファイル (`flag.txt.rsec`) が渡されます。

`strings` にバイナリを投げてみると `CryptAcquireContextW` や `CryptEncrypt` のような文字列があり、CryptoAPI を使って暗号化を行っているのではと推測できます。

特に重要な処理をしていそうなところを中心に `IDA` (Free 版) でバイナリを調べていきましょう。暗号化の準備をしていると思われる部分 (`0x40EFF0` ~)、暗号化をしていると思われる部分 (`0x40D6B0` ~) から読んでいきます。

暗号化の準備をしていると思われる部分を読みます。まずいくつかの変数の初期化が行われているようですが、以下のような気になる部分がありました。覚えておきましょう。

```
mov    BYTE PTR [ebp-0x78],0x4c
mov    BYTE PTR [ebp-0x77],0x57
mov    BYTE PTR [ebp-0x76],0x4a
mov    BYTE PTR [ebp-0x75],0x50
mov    BYTE PTR [ebp-0x74],0x5e
...
mov    BYTE PTR [ebp-0x3e],0xe
mov    BYTE PTR [ebp-0x3d],0xc
mov    BYTE PTR [ebp-0x3c],0x15
mov    BYTE PTR [ebp-0x3b],0xb
mov    BYTE PTR [ebp-0x3a],0xc
```

その後、いくつか関数を呼んでいます。定数をググったり、C っぽくして読みやすくしてみます。

```c
CryptAcquireContextW(&hProv, 0, 0, PROV_RSA_FULL, 0);
CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
CryptHashData(hHash, &kininaru, 0x3f, 0);
CryptDeriveKey(hProv, CALG_RC4, hHash, 0, &hKey);
```

先ほど気になると言っていた変数は `kininaru` としていますが、使われている関数について調べてみるとどうやらこれは暗号化に使うパスワードだったようです。`pass.bin` として保存しておきましょう。

暗号化をしていると思われる部分を読みます。長くて面倒なので `CryptEncrypt` を呼んでいる部分だけ読みやすくしてみます。

```c
CryptEncrypt(hKey, 0, 1, 0, pbData, &pdwDataLen, dwBufLen);
```

`pbData` は暗号化するデータのようです。特に変わったことはしていません。

では、得られた情報から復号するプログラムを書きましょう。

```c
#include <windows.h>
#include <wincrypt.h>

#define PASSWORD_LENGTH 0x3f

int main() {
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	HCRYPTHASH hHash;
	CHAR sPassword[PASSWORD_LENGTH] = "";
	CHAR sBuffer[256] = "";
	HANDLE hFile;
	DWORD dwBufferLen;
	DWORD dwReadByte;

	hFile = CreateFile("flag.txt.rsec", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	dwBufferLen = GetFileSize(hFile, NULL);
	ReadFile(hFile, sBuffer, dwBufferLen, &dwReadByte, NULL);
	CloseHandle(hFile);

	hFile = CreateFile("pass.bin", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	ReadFile(hFile, sPassword, PASSWORD_LENGTH, &dwReadByte, NULL);
	CloseHandle(hFile);

	CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0);
	CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
	CryptHashData(hHash, sPassword, PASSWORD_LENGTH, 0);
	CryptDeriveKey(hProv, CALG_RC4, hHash, 0, &hKey);

	CryptDecrypt(hKey, 0, TRUE, 0, sBuffer, &dwBufferLen);
	MessageBox(NULL, sBuffer, "FLAG", MB_OK);

	CryptDestroyKey(hKey);
	CryptReleaseContext(hProv, 0);

	return 0;
}
```

`gcc decrypt.c -o decrypt.exe -mwindows` のような感じでコンパイルして実行すると、フラグが表示されました。

```
SECCON{DATA_DECRYPTED_FROM_FAKE_RANSOMWARE}
```

---

本番では暗号化されたファイルを復号するプログラムを書き始めるところまで進められたのですが、WinAPI が全く分からず、いろいろ調べているうちに時間切れでした。

時間内に解けず惜しい思いをしましたが、面白い問題でした。

---

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr"><a href="https://twitter.com/_N4NU_">@_N4NU_</a> あーなるほどです…って思ったんですが、そもそも暗号化のアルゴリズムがRC4なのでCryptDecryptに変える必要すらなくてただ動かすだけでいいですね…</p>&mdash; st98 (@st98_) <a href="https://twitter.com/st98_/status/797963802826244097">2016年11月14日</a></blockquote>
<script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

こういうことを考えたんですが、

- 適当なフォルダを作って移動
- `binary300.exe` と `flag.txt.rsec` を作ったフォルダにコピー
- `flag.txt.rsec` を `flag.txt` にリネーム
- `binary300.exe` を実行

という手順で簡単にフラグが出てきます。

### [Network 200] sample
pcap ファイルが渡されます。Wireshark で開いてみると ping のエコー要求とエコー応答を何度も行っている様子をキャプチャしていることが分かります。

TTL を見てみるとエコー応答の方は 64 のみなのに対し、エコー要求の方は 61, 80, 66 のように不自然な値になっています。

試しにエコー要求の TTL を集めてみます。

```python
from scapy.all import *
pcap = rdpcap('sample.pcap')

r = ''
for k, p in enumerate(pcap):
  if k % 2 == 1: continue
  r += chr(p.ttl)

print r
```

`===PB@@LKxMfkdFpKlDllaz` という結果でした。`PB@@LK` と `SECCON` とを比べてみると、TTL に仕込まれていた文字列は、文字コードが本来の文字列から 3 引かれているのではと分かります。やってみます。

```python
s = '===PB@@LKxMfkdFpKlDllaz'
print ''.join(chr(ord(c) + 3) for c in s)
```

フラグが出ました。

```
SECCON{PingIsNoGood}
```

---

本番では、私は TTL を集めるところまでしか解けませんでした。

正直に言うと、これは面白くない問題でした。知識や経験があれば TTL がおかしいと気づけるとは思いますが、その次の段階は解くには手がかりが少なすぎるのではないかと思います。
