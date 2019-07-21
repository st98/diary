---
layout: post
title: CyBRICS CTF Quals 2019 の write-up
categories: [ctf]
date: 2019-07-22 07:00:00 +0900
---

7 月 20 日から 7 月 21 日にかけて開催された [CyBRICS CTF Quals 2019](https://cybrics.net) に、チーム zer0pts として参加しました。最終的にチームで 386 点を獲得し、順位は得点 775 チーム中 69 位でした。うち、私は 3 問を解いて 70 点を入れました。

他のメンバーの write-up はこちら。

- [CyBRICS CTF 2019 Writeup - CTFするぞ](https://ptr-yudai.hatenablog.com/entry/2019/07/21/212133)

以下、私が解いた問題の writeup です。

## Web
## Warmup (10)
> E_TOO_EASY
> 
> Just get the flag (問題サーバへのリンク)

与えられた URL にアクセスすると、ページのロードが終わった途端に `/final.html` に遷移しました。`/final.html` は普通のテキストのようで、特に気になることはありません。

遷移前のファイルは以下のような内容でした。

```html
<html>
        <script language="JavaScript">
                function func() {
                  document.location.href = 'final.html'
                }
              </script>
<body onload=func()>
︙
```

JavaScript で遷移を行っていることがわかります。

よく見ると、後ろの方に以下のような怪しげなテキストがありました。

```html
︙
Here is your base64-encoded flag: Y3licmljc3s0YjY0NmM3OTg1ZmVjNjE4OWRhZGY4ODIyOTU1YjAzNH0=
</p></body></html>
```

これを Base64 デコードするとフラグが得られました。

```
cybrics{4b646c7985fec6189dadf8822955b034}
```

### Caesaref (50)
> This web resource is highly optimized:
> 
> (URL)

与えられた URL にアクセスすると、以下のようなログインフォームが表示されました。

```html
<head>
    <link rel="stylesheet" href="styles.css">
</head>



    <form name="user" action="/" method="POST">
        <input type="hidden" name="csrf-token" value="5b2dc2536394518d40770a1b9d39548c8c70034fcd604c5a98f6ea329a5006fc">
        username <input type="text" name="user" value=""><br /><br />
        password <input type="password" name="password" value=""><br /><br />
        <input type="submit" name="submit" value="Login">
    </form>
```

適当なユーザ名とパスワードを入力するとログインすることができ、以下のようなフォームが表示されました。

```html
<head>
    <link rel="stylesheet" href="styles.css">
</head>


    <div>
        Hello, aikatsu<br>
        Ask support:
        <form name="support" action="/" method="POST">
            <input type="hidden" name="csrf-token" value="15c1cc4e7e1bcbed356e01f0687077f9b1816bb1008be8630894ef62b3b26b28">
            <input type="text" name="question" value="">
            <input type="submit" name="submit" value="Ask">
        </form>

    </div>
```

適当な文字列を入力すると `Please, attach link to the screenshot or detailed explanation of your issue` と返ってきました。自分が管理しているサーバの 8000 番ポートを開けて待ち受け、この URL を投げてみると以下のような HTTP リクエストがやってきました。

```
GET / HTTP/1.1
Host: (省略)
User-Agent: python-requests/2.18.4
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Cookie: PHPSESSID=blvm4ip4v7ausj15b49bks6qkt
```

なぜ初めての訪問のはずなのに `PHPSESSID` を持っているのでしょうか🤔

**問題サーバで**この `PHPSESSID` をセットし、ページをリロードすると以下のようなフォームが出現しました。

```html
Retrieve the secret flag:
<form name="flag" action="/">
    <input type="hidden" name="csrf-token" value="540fe22fc6b52ea2e471b99c9e7d215e1027e3b054ab2cfc0448cb84c56ba1fe">
    <input type="hidden" name="flag" value="1">
    <input type="submit" value="Show flag">
</form>
```

`Show flag` を押すとフラグが得られました。

```
cybrics{k4Ch3_C4N_83_vuln3R48l3}
```

## CTB
### ProCTF (10)
> We Provide you a Login for your scientific researches. Don't try to find the flag.
> 
> ssh (接続情報)

与えられた SSH の接続情報を使って問題サーバにアクセスすると、以下のような内容が返ってきました。

```
$ ssh (省略)
Welcome to Ubuntu 19.04 (GNU/Linux 5.0.0-15-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul 21 21:35:16 UTC 2019

︙


84 updates can be installed immediately.
48 of these updates are security updates.


WARNING: Your kernel does not support swap limit capabilities or the cgroup is not mounted. Memory limited without swap.

?- 
```

私が問題を確認した時点で、[ptr-yudai](https://twitter.com/ptrYudai) さんによってこれは Prolog の処理系の REPL であることがわかっていました。

Ctrl-C を押してみると、以下のようなメッセージが表示されました。

```
WARNING: By typing Control-C twice, you have forced an asynchronous
WARNING: interrupt.  Your only SAFE operations are: c(ontinue), p(id),
WARNING: s(stack) and e(xit).  Notably a(abort) often works, but
WARNING: leaves the system in an UNSTABLE state
```

ググると処理系が [SWI-Prolog](https://www.swi-prolog.org/) であることが推測できます。

OS コマンドを実行できないか `SWI-Prolog shell` でググってみると、[shell/2 という述語](https://www.swi-prolog.org/pldoc/man?predicate=shell/2)が存在していることがわかりました。これでシェルを立ち上げてみましょう。

```
?- shell('/bin/bash').
user@1114f6956902:/$ 
```

立ち上がりました。フラグを探しましょう。

```
user@1114f6956902:/$ pwd
/
user@1114f6956902:/$ ls
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
user@1114f6956902:/$ ls home
user
user@1114f6956902:/$ ls home/user
flag.txt
user@1114f6956902:/$ cat home/user/flag.txt 
cybrics{feeling_like_a_PRO?_that_sounds_LOGical_to_me!____g3t_it?_G37_1T?!?!_ok_N3v3Rm1nd...}
user@1114f6956902:/$ exit
exit
true.
```

フラグが得られました。

```
cybrics{feeling_like_a_PRO?_that_sounds_LOGical_to_me!____g3t_it?_G37_1T?!?!_ok_N3v3Rm1nd...}
```