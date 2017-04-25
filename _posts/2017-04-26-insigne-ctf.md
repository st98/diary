---
layout: post
title: Insigne CTF の write-up
categories: [ctf]
date: 2017-04-26 08:52:00 +0900
---

チーム Harekaze で [Insigne CTF](http://insignectf.in/) に参加しました。最終的にチームで 110 点を獲得し、順位は 31 位 (得点 303 チーム中) でした。うち、私は 2 問を解いて 110 点を入れました。

以下、解いた問題の write-up です。

## [Web 10] PwnPeAuto

`/flag.txt` にフラグがありました。

```
flag{bl1ndl1k3d4r3d3v1l}
```

## [RE 100] wasm1

wasm ファイルが与えられます。

バイナリエディタで眺めると、0x31cd から `01 00 00 00 09 00 00 00 08 00 00 00 05 00 0 00 01 00 00 00 ...` という数値の配列、0x329d から `guil|i<c<g=>k;<:64@i5=:4>83:n869?9;fl~` という文字列が見えます。

`guil|` と `flag{` の文字コードの差は `[1, 9, 8, 5, 1]` でした。0x329d の文字列から 0x31cd の数値の配列を引けばいいようです。

```python
import struct

s = open('wasm1.wasm', 'rb').read()
encrypted = s[0x329d:]
key = struct.unpack('<' + 'i' * 38, s[0x31cd:0x3265])

print ''.join(chr(ord(c) - key[k]) for k, c in enumerate(encrypted))
```

```
flag{e9a4a69c737417a15705816f845708bd}
```
