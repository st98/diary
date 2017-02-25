---
layout: post
title: VolgaCTF 2017 Teaser の write-up
categories: [ctf]
date: 2017-02-26 05:51:00 +0900
---

チーム Harekaze で [VolgaCTF 2017 Teaser](https://teaser.2017.volgactf.ru/) に参加しました。

最終的にチームで 110 点を獲得し、順位は 34 位 (得点 80 チーム中) でした。うち、私は 1 問を解いて 100 点を入れました。

以下、解いた問題の write-up です。

## [Stegano 100] Universal Text

UTF-16LE のテキストファイル…のはずなのですが、`00 46 00 4C 41 00 47 00` と途中からビッグエンディアンになってしまっているようです。

```python
s = open('message.txt', 'rb').read()
open('result.txt', 'wb').write(b'\xff\xfe' + s[0x37:])
```

で読めました。

```
UNICODE_SOMETIMES_HURTS
```

## 感想

この CTF が終わるまで起きているつもりでしたが、睡魔には勝てませんでした (´・ω・｀)
