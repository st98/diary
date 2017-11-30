---
layout: post
title: CSAW CTF Qualification Round 2017 の write-up
categories: [ctf]
date: 2017-09-19 01:49:00 +0900
---

チーム Harekaze で [CSAW CTF Qualification Round 2017](https://ctf.csaw.io/) に参加しました。最終的にチームで 1026 点を獲得し、順位は得点 1444 チーム中 204 位でした。うち、私は 1 問を解いて 150 点を入れました。

以下、解いた問題の write-up です。

## [Web 150] Shia Labeouf-off!

与えられた URL にアクセスすると `| Django + Docker Example` というタイトルのページが表示されました。メニューには `/polls/` `/ad-lib/` へのリンクが設置されています。

`/polls/` にアクセスすると `/polls/1` `/polls/2` の 2 つの投票ページへのリンクが表示されました。この 2 つ以外に何かページがないか `/polls/3/` にアクセスすると、以下のようなエラーが表示されました。

```
Exception at /polls/3/

Our infrastructure can't support that many Shias!

Request Method:	GET
Request URL:	http://web.chal.csaw.io:5490/polls/3/
Django Version:	1.11.5
Exception Type:	Exception
Exception Value:	
Our infrastructure can't support that many Shias!
Exception Location:	./polls/templatetags/pools_extras.py in check, line 20
Python Executable:	/usr/local/bin/uwsgi
Python Version:	2.7.6
Python Path:	
['.',
 '',
 '/opt/ve/djdocker/lib/python2.7',
 '/opt/ve/djdocker/lib/python2.7/plat-x86_64-linux-gnu',
 '/opt/ve/djdocker/lib/python2.7/lib-tk',
 '/opt/ve/djdocker/lib/python2.7/lib-old',
 '/opt/ve/djdocker/lib/python2.7/lib-dynload',
 '/usr/lib/python2.7',
 '/usr/lib/python2.7/plat-x86_64-linux-gnu',
 '/usr/lib/python2.7/lib-tk',
 '/opt/ve/djdocker/local/lib/python2.7/site-packages',
 '/opt/ve/djdocker/lib/python2.7/site-packages']
Server time:	Mon, 18 Sep 2017 11:25:56 -0500
...
./polls/templatetags/pools_extras.py in checknum
5. 
6. @register.filter(name='getme')
7. def getme(value, arg):
8.   return getattr(value, arg)
9. 
10. @register.filter(name='checknum')
11. def checknum(value):
12.   check(value)
13. 
14. @register.filter(name='listme')
15. def listme(value):
16.   return dir(value)
17. 
18. def check(value):

./polls/templatetags/pools_extras.py in check
13. 
14. @register.filter(name='listme')
15. def listme(value):
16.   return dir(value)
17. 
18. def check(value):
19.   if value > 2:
20.     raise Exception("Our infrastructure can't support that many Shias!") 
...
You're seeing this error because you have DEBUG = True in your Django settings file. Change that to False, and Django will display a standard page generated by the handler for this status code.
```

Django のデバッグモードがオンになっているようです。`./polls/templatetags/pools_extras.py` の一部が得られ、テンプレートのフィルタに `getme` `checknum` `listme` が追加されていることが分かりました。

`/ad-lib/` にアクセスすると以下のようなメッセージと、テキストを入力するフォームが表示されました。

```
Give me an ad lib and I will Shia Labeouf it up for you!

Where you want a noun, just put: "{% raw %}{{ noun }}{% endraw %}", for a verb: "{% raw %}{{ verb }}{% endraw %}", and for an adjective: "{% raw %}{{ adjective }}{% endraw %}"!
```

`{% raw %}{% lorem %}{% endraw %}` (Lorem ipsum を表示するテンプレートのタグ) を入力すると Lorem ipsum が表示されました。Server-Side Template Injection (SSTI) ができそうです。

`{% raw %}{{ 3 | checknum }}{% endraw %}` でわざと `./polls/templatetags/pools_extras.py` でエラーを発生させて `./ad-lib/views.py` で `template.render(context)` が呼ばれたときのローカル変数を確認すると、以下のようになっていました。

```
context: [{'False': False, 'None': None, 'True': True}, {'adjective': '<img src="https://media1.giphy.com/media/TxXhUgEUWWL6/200.webp#129-grid1" />', 'verb': '<img src="https://media3.giphy.com/media/R0vQH2T9T4zza/200.webp#165-grid1" />', 'noun': '<img src="https://media0.giphy.com/media/arNexgslLkqVq/200.webp#70-grid1" />', 'mrpoopy': <ad-lib.someclass.Woohoo instance at 0x7f135f113758>}, {}, {}]
data: u'{% raw %}{{ 3 | checknum }}{% endraw %}'
...
```

`noun` `verb` `adjective` の他にも `mrpoopy` という変数があるようです。

`{% raw %}{{ mrpoopy | listme }{% endraw %}}` を入力すると `mrpoopy` には `['Woohoo', '__doc__', '__flag__', '__module__']` というメンバーがあると分かりました。

`{% raw %}{{ mrpoopy | getme:'__flag__' }}{% endraw %}` を入力すると `flag{wow_much_t3mplate}` と表示されました。

```
flag{wow_much_t3mplate}
```