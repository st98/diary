---
layout: post
title: SHA2017 CTF - Growing Up (Misc 200) の write-up
categories: [ctf]
date: 2017-08-09 15:19:00 +0900
---

[SHA2017 CTF](2017-08-09-sha2017-ctf.html) で Growing Up という問題が出題されました。これは [Junior CTF](https://junior.stillhackinganyway.nl/home) の問題をすべて解くとフラグが貰えるという問題でした。

以下、解いた問題の write-up です。

## Binary

### Find The Flag (1)

x86_64 の ELF ファイルが与えられました。

与えられたバイナリを `strings` するとフラグが得られました。

```
flag{b760866fa6f035548be127b7525dbb66}
```

### Jump Around (4)

x86_64 の ELF ファイルが与えられました。

main を逆アセンブルすると以下のようになりました。0x400639 の jne を je に変えて実行するとフラグが得られました。

```
   0x0000000000400626 <+0>:     push   rbp
   0x0000000000400627 <+1>:     mov    rbp,rsp
   0x000000000040062a <+4>:     sub    rsp,0x10
   0x000000000040062e <+8>:     mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000400635 <+15>:    cmp    DWORD PTR [rbp-0x4],0x0
   0x0000000000400639 <+19>:    jne    0x400647 <main+33>
   0x000000000040063b <+21>:    mov    edi,0x400738
   0x0000000000400640 <+26>:    call   0x400410 <puts@plt>
   0x0000000000400645 <+31>:    jmp    0x400651 <main+43>
   0x0000000000400647 <+33>:    mov    eax,0x0
   0x000000000040064c <+38>:    call   0x400546 <print_flag>
   0x0000000000400651 <+43>:    leave  
   0x0000000000400652 <+44>:    ret 
```

```
flag{f525a6abd58ce9488f3c90904149145d}
```

### Flip A Coin (4)

x86 の PE ファイルが与えられました。

100 回 `rand()` の結果が 0 になるとフラグが表示されるようです。`call rand` を `xor eax, eax` にして実行するとフラグが得られました。

```
flag{d754c599d47d9b3e4a376e1d770ca8c1}
```

### Hidden Message (3)

apk ファイルが与えられました。

展開して `resources.arsc` で `flag` を検索するとフラグが得られました。

```
flag{d3314ac1a08d65ea32ffd30907de2409}
```

## Crypto

### All about the Base (1)

問題文を Base64 デコードするとフラグが得られました。

```
flag{b3e9c3eee609bac46fad4439cf321fe5}
```

### Exclusive or ... (2)

暗号文と `\x03` を xor するとフラグが得られました。

```
flag{a157d2b4eb73c60ff0cdbe2a2dea06c3}
```

### Substitute Teacher (2)

暗号文を [quipqiup](http://quipqiup.com/) に投げるとフラグが得られました。

```
flag{a230a7e624afac36291c5f31fa818d6f}
```

### Rotation (1)

暗号文をシーザー暗号として右に 20 シフトするとフラグが得られました。

```
flag{30d3a1aa0cda9f08cdfa52668bc6854a}
```

### Transposition (3)

暗号文を以下のスクリプトに投げるとフラグが得られました。

```python
s = 'Citgoe6b0 oohern636 nni.tg1e2 gssThe58e rschii366 aohess3ae tlafcf3dc uvllhl24f lilaaa730 aneglg506 tgnfl{33}'
res = ''
for x in range(9):
  for t in s.split():
    res += t[x]
print(res)
```

```
flag{66153332753b3e86ad4303062e6ecf06}
```

## Forensics

### Deleted File (3)

与えられたファイルの 0x9f0400 辺りにある JPEG を抽出するとフラグが得られました。

```
FLAG{129F0A52F0F41E077E0FD03063FF4FAD}
```

## Misc

### Zipfile One (1)

鍵付きの zip ファイルが与えられました。zip2john を使って John the Ripper に投げるとパスワードが `42831` と分かり、フラグが得られました。

```
flag{d6f56ae046bb241cc61f9d26f8e525d9}
```

### Zipfile Two (2)

鍵付きの zip ファイルが与えられました。zip2john を使って John the Ripper に投げるとパスワードが `future` と分かり、フラグが得られました。

```
flag{7128d78caf1e3297386a09afae0f8ea4}
```

### Reverse (3)

[与えられたファイルをニブル単位でひっくり返す](https://st98.github.io/diary/posts/2014-12-07-seccon.html#reverse-it-binary-100) とフラグが得られました。

```
flag{758d7fa2762ab838c4835f1995e151d2}
```

## Network

### Wanna Buy A Flag? (2)

pcap ファイルが与えられました。TCP で 1 バイトずつ文字が送信されているようだったので、スクリプトで集めるとフラグが得られました。

```python
from scapy.all import *
pcap = rdpcap('wannabuyaflag.pcap')
res = ''
for p in pcap[9:85:2]:
  res += str(p.payload)[-4:-3]
print res
```

```
flag{f08574923ec9c9ffb47188e6edc1a20f}
```

### Download (1)

pcap ファイルが与えられました。NetworkMiner でファイルを抽出するとフラグが得られました。

```
flag{259F1B841EAAA4FCB843D77DCDADE55A}
```

### Weird Website (3)

pcap ファイルが与えられました。NetworkMiner でファイルを抽出してブラウザで開くとフラグが得られました。

```
flag{8233daf526dcee25fd9ffda3bb99d677}
```

### Captured Mail (4)

pcap ファイルが与えられました。メールの添付ファイルを Base64 デコードして zip として展開するとフラグが得られました。

```
flag{1b5978777658baca99ce653af6fa596e}
```

## Pwnable

### small (4)

以下のようなファイルが与えられました。

```python
print "HACK "*input("Number: ")
```

サーバに接続して `__import__('os').system('cat /home/small/flag')` を入力するとフラグが得られました。

```
flag{69b5a247b9cd52ac97de7cc94994083e}
```

## Web

### Location (3)

与えられた URL にアクセスしてリンクをクリックすると、`/fla` -> `/g{` -> `/f51c` -> … という感じで遷移しました。パスを集めるとフラグが得られました。

```
flag{f51cf5e7e1d003986acd2864139553a1}
```

### Ping (4)

与えられた URL にアクセスすると IP アドレスの入力フォームが表示されました。任意の IP アドレスに ping ができるようです。

`$(ls | tac)` を入力すると `ping: unknown host s3cr3tfl4g.txt` と表示されました。`/s3cr3tfl4g.txt` にアクセスするとフラグが得られました。

```
flag{a8bb1ea55704762941ef519f98fff075}
```

### In Your Head (1)

与えられた URL に `curl -v` でアクセスすると HTTP レスポンスヘッダに `X-Flag: flag{a1a4d64086f713e92a809859d930d120}` というヘッダがありました。

```
flag{a1a4d64086f713e92a809859d930d120}
```

### Old School (2)

与えられた URL にアクセスすると `This website only works on Internet Explorer 6` と表示されました。IE6 の UA でアクセスするとフラグが得られました。

```
flag{f374df6554c7c6a6fced10396c84baf6}
```

### Broken Image (2)

与えられた URL にアクセスしてソースを見ると、以下のような画像が読み込まれていました。

```html
<img alt="broken image" src="data:image/png;base64,Q29uZ3JhdHVsYXRpb25zLCB0aGUgZmxhZyBpcyBmbGFne2MwNzExNjE0MzU4YTI3MTEwY2ExNTkzMDJiMTA2NzU5fQo=" />
```

これを Base64 デコードするとフラグが得られました。

```
flag{c0711614358a27110ca159302b106759}
```