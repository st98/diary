---
layout: post
title: RedpwnCTF 2019 の write-up
categories: [ctf]
date: 2019-08-20 14:09:00 +0900
---

8 月 12 日から 8 月 16 日にかけて開催された [RedpwnCTF 2019](https://redpwn.net) に、チーム zer0pts として参加しました。最終的にチームで 4433 点を獲得し、順位は得点 926 チーム中 29 位でした。うち、私は 5 問を解いて 530 点を入れました。

他のメンバーの write-up はこちら。

- [RedpwnCTF 2019 Writeup - CTFするぞ](https://ptr-yudai.hatenablog.com/entry/2019/08/17/061600)

以下、私が解いた問題の writeup です。

## Web
### crypt (50)
> Store your most valuable secrets with this new encryption algorithm (URL).

与えられた URL にアクセスすると、以下のような HTML が返ってきました。

```html
<!doctype html>
your safely encrypted flag is vdDby72W15O2qrnJtqep0cSnsd3HqZzbx7io27C7tZi7lanYx6jPyb2nsczHuMec
<script>
  setInterval(_=>console.clear(), 50)
  setInterval(_=>{debugger}, 50)
  // saving the code here for ultra secure encryption
  self.example_flag = eval(/* めっちゃ長いコード */)('example_flag{xyz}')
</script>
```

`/* めっちゃ長いコード */` の部分は `(![]+[]) …` というような感じで `!` `[` `]` `(` `)` `+` の 6 種類の文字しか使われていません。おそらく [JSF*ck](http://www.jsfuck.com/) で難読化しているのでしょう。この部分を実行して得られるコードを確認しましょう。

`setInterval` が使われている行と `('example_flag{xyz}')` をコメントアウトし、`eval` を `console.log` に置換すると以下のようなコードが出力されました。

```javascript
f=>btoa([...btoa(f)].map(s=>String.fromCharCode(s.charCodeAt(0)+(location.host.charCodeAt(0)%location.host.charCodeAt(3)))).join(''))
```

フラグを引数としてこの関数を呼んだ返り値が `vdDby72W15O2qrnJtqep0cSnsd3HqZzbx7io27C7tZi7lanYx6jPyb2nsczHuMec` になるようなので、これを元に戻すコードを書きましょう。

```javascript
let host = 'chall.2019.redpwn.net:8005';
console.log(atob(atob('vdDby72W15O2qrnJtqep0cSnsd3HqZzbx7io27C7tZi7lanYx6jPyb2nsczHuMec').split('').map(c => String.fromCharCode(c.charCodeAt(0) - (host.charCodeAt(0) % host.charCodeAt(3)))).join('')));
```

これを実行するとフラグが得られました。

```
flag{tHe_H1gh3st_quA11ty_antI_d3buG}
```

### easycipher (50)
> This is an easy cipher (URL)? I heard it's broken.

与えられた URL にアクセスすると、`What is the password` というプロンプトが表示され、適当な文字列を入力すると `:(` と表示されました。内容は以下のような HTML でした。

```html
<script>var _0x29a9=["\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65\x66","","\x63\x68\x61\x72\x41\x74","\x6C\x65\x6E\x67\x74\x68","\x63\x68\x61\x72\x43\x6F\x64\x65\x41\x74","\x57\x68\x61\x74\x20\x69\x73\x20\x74\x68\x65\x20\x70\x61\x73\x73\x77\x6F\x72\x64","\x61\x61\x34\x32\x62\x32\x33\x34\x63\x62\x30\x35\x39\x31\x35\x37\x31\x36\x63\x31\x34\x33\x34\x30\x35\x38\x66\x65\x31\x61\x65\x65\x31\x36\x63\x31\x34\x33\x34\x30\x63\x62\x30\x35\x39\x31\x35\x37\x61\x61\x34\x32\x62\x32\x33\x34","\x73\x75\x62\x6D\x69\x74\x20\x61\x73\x20\x72\x65\x64\x70\x77\x6E\x63\x74\x66\x7B\x50\x41\x53\x53\x57\x4F\x52\x44\x7D","\x3A\x28"];var hex_chr=_0x29a9[0];function rhex(_0x8e5dx3){str= _0x29a9[1];for(j= 0;j<= 3;j++){str+= hex_chr[_0x29a9[2]]((_0x8e5dx3>> (j* 8+ 4))& 0x0F)+ hex_chr[_0x29a9[2]]((_0x8e5dx3>> (j* 8))& 0x0F)};return str}function str2blks_MD5(_0x8e5dx5){nblk= ((_0x8e5dx5[_0x29a9[3]]+ 8)>> 6)+ 1;blks=  new Array(nblk* 16);for(i= 0;i< nblk* 16;i++){blks[i]= 0};for(i= 0;i< _0x8e5dx5[_0x29a9[3]];i++){blks[i>> 2]|= _0x8e5dx5[_0x29a9[4]](i)<< ((i% 4)* 8)};blks[i>> 2]|= 0x80<< ((i% 4)* 8);blks[nblk* 16- 2]= _0x8e5dx5[_0x29a9[3]]* 8;return blks}function add(_0x8e5dx7,_0x8e5dx8){var _0x8e5dx9=(_0x8e5dx7& 0xFFFF)+ (_0x8e5dx8& 0xFFFF);var _0x8e5dxa=(_0x8e5dx7>> 16)+ (_0x8e5dx8>> 16)+ (_0x8e5dx9>> 16);return (_0x8e5dxa<< 16)| (_0x8e5dx9& 0xFFFF)}function rol(_0x8e5dx3,_0x8e5dxc){return (_0x8e5dx3<< _0x8e5dxc)| (_0x8e5dx3>>> (32- _0x8e5dxc))}function cmn(_0x8e5dxe,_0x8e5dxf,_0x8e5dx10,_0x8e5dx7,_0x8e5dx11,_0x8e5dx12){return add(rol(add(add(_0x8e5dxf,_0x8e5dxe),add(_0x8e5dx7,_0x8e5dx12)),_0x8e5dx11),_0x8e5dx10)}function ff(_0x8e5dxf,_0x8e5dx10,_0x8e5dx14,_0x8e5dx15,_0x8e5dx7,_0x8e5dx11,_0x8e5dx12){return cmn((_0x8e5dx10& _0x8e5dx14)| ((~_0x8e5dx10) & _0x8e5dx15),_0x8e5dxf,_0x8e5dx10,_0x8e5dx7,_0x8e5dx11,_0x8e5dx12)}function gg(_0x8e5dxf,_0x8e5dx10,_0x8e5dx14,_0x8e5dx15,_0x8e5dx7,_0x8e5dx11,_0x8e5dx12){return cmn((_0x8e5dx10& _0x8e5dx15)| (_0x8e5dx14& (~_0x8e5dx15)),_0x8e5dxf,_0x8e5dx10,_0x8e5dx7,_0x8e5dx11,_0x8e5dx12)}function hh(_0x8e5dxf,_0x8e5dx10,_0x8e5dx14,_0x8e5dx15,_0x8e5dx7,_0x8e5dx11,_0x8e5dx12){return cmn(_0x8e5dx10^ _0x8e5dx14^ _0x8e5dx15,_0x8e5dxf,_0x8e5dx10,_0x8e5dx7,_0x8e5dx11,_0x8e5dx12)}function ii(_0x8e5dxf,_0x8e5dx10,_0x8e5dx14,_0x8e5dx15,_0x8e5dx7,_0x8e5dx11,_0x8e5dx12){return cmn(_0x8e5dx14^ (_0x8e5dx10| (~_0x8e5dx15)),_0x8e5dxf,_0x8e5dx10,_0x8e5dx7,_0x8e5dx11,_0x8e5dx12)}function calcMD5(_0x8e5dx5){x= str2blks_MD5(_0x8e5dx5);a= 1732584193;b=  -271733879;c=  -1732584194;d= 271733878;for(i= 0;i< x[_0x29a9[3]];i+= 16){olda= a;oldb= b;oldc= c;oldd= d;a= ff(a,b,c,d,x[i+ 0],7,-680876936);d= ff(d,a,b,c,x[i+ 1],12,-389564586);c= ff(c,d,a,b,x[i+ 2],17,606105819);b= ff(b,c,d,a,x[i+ 3],22,-1044525330);a= ff(a,b,c,d,x[i+ 4],7,-176418897);d= ff(d,a,b,c,x[i+ 5],12,1200080426);c= ff(c,d,a,b,x[i+ 6],17,-1473231341);b= ff(b,c,d,a,x[i+ 7],22,-45705983);a= ff(a,b,c,d,x[i+ 8],7,1770035416);d= ff(d,a,b,c,x[i+ 9],12,-1958414417);c= ff(c,d,a,b,x[i+ 10],17,-42063);b= ff(b,c,d,a,x[i+ 11],22,-1990404162);a= ff(a,b,c,d,x[i+ 12],7,1804603682);d= ff(d,a,b,c,x[i+ 13],12,-40341101);c= ff(c,d,a,b,x[i+ 14],17,-1502002290);b= ff(b,c,d,a,x[i+ 15],22,1236535329);a= gg(a,b,c,d,x[i+ 1],5,-165796510);d= gg(d,a,b,c,x[i+ 6],9,-1069501632);c= gg(c,d,a,b,x[i+ 11],14,643717713);b= gg(b,c,d,a,x[i+ 0],20,-373897302);a= gg(a,b,c,d,x[i+ 5],5,-701558691);d= gg(d,a,b,c,x[i+ 10],9,38016083);c= gg(c,d,a,b,x[i+ 15],14,-660478335);b= gg(b,c,d,a,x[i+ 4],20,-405537848);a= gg(a,b,c,d,x[i+ 9],5,568446438);d= gg(d,a,b,c,x[i+ 14],9,-1019803690);c= gg(c,d,a,b,x[i+ 3],14,-187363961);b= gg(b,c,d,a,x[i+ 8],20,1163531501);a= gg(a,b,c,d,x[i+ 13],5,-1444681467);d= gg(d,a,b,c,x[i+ 2],9,-51403784);c= gg(c,d,a,b,x[i+ 7],14,1735328473);b= gg(b,c,d,a,x[i+ 12],20,-1926607734);a= hh(a,b,c,d,x[i+ 5],4,-378558);d= hh(d,a,b,c,x[i+ 8],11,-2022574463);c= hh(c,d,a,b,x[i+ 11],16,1839030562);b= hh(b,c,d,a,x[i+ 14],23,-35309556);a= hh(a,b,c,d,x[i+ 1],4,-1530992060);d= hh(d,a,b,c,x[i+ 4],11,1272893353);c= hh(c,d,a,b,x[i+ 7],16,-155497632);b= hh(b,c,d,a,x[i+ 10],23,-1094730640);a= hh(a,b,c,d,x[i+ 13],4,681279174);d= hh(d,a,b,c,x[i+ 0],11,-358537222);c= hh(c,d,a,b,x[i+ 3],16,-722521979);b= hh(b,c,d,a,x[i+ 6],23,76029189);a= hh(a,b,c,d,x[i+ 9],4,-640364487);d= hh(d,a,b,c,x[i+ 12],11,-421815835);c= hh(c,d,a,b,x[i+ 15],16,530742520);b= hh(b,c,d,a,x[i+ 2],23,-995338651);a= ii(a,b,c,d,x[i+ 0],6,-198630844);d= ii(d,a,b,c,x[i+ 7],10,1126891415);c= ii(c,d,a,b,x[i+ 14],15,-1416354905);b= ii(b,c,d,a,x[i+ 5],21,-57434055);a= ii(a,b,c,d,x[i+ 12],6,1700485571);d= ii(d,a,b,c,x[i+ 3],10,-1894986606);c= ii(c,d,a,b,x[i+ 10],15,-1051523);b= ii(b,c,d,a,x[i+ 1],21,-2054922799);a= ii(a,b,c,d,x[i+ 8],6,1873313359);d= ii(d,a,b,c,x[i+ 15],10,-30611744);c= ii(c,d,a,b,x[i+ 6],15,-1560198380);b= ii(b,c,d,a,x[i+ 13],21,1309151649);a= ii(a,b,c,d,x[i+ 4],6,-145523070);d= ii(d,a,b,c,x[i+ 11],10,-1120210379);c= ii(c,d,a,b,x[i+ 2],15,718787259);b= ii(b,c,d,a,x[i+ 9],21,-343485551);a= add(a,olda);b= add(b,oldb);c= add(c,oldc);d= add(d,oldd)};return rhex(a)+ rhex(b)+ rhex(c)+ rhex(d)+ rhex(c)+ rhex(b)+ rhex(a)}if(calcMD5(prompt(_0x29a9[5]))=== _0x29a9[6]){alert(_0x29a9[7])}else {alert(_0x29a9[8])}</script>
```

おそらく [javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator) で難読化されており、読むのが面倒くさそうです。とりあえず DevTools で整形して眺めていると、スクリプトの終わりの方に気になる部分がありました。

```javascript
    if (calcMD5(prompt(_0x29a9[5])) === _0x29a9[6]) {
        alert(_0x29a9[7])
    } else {
        alert(_0x29a9[8])
    }
```

おそらくユーザ入力の MD5 ハッシュと計算済みの正しいパスワードの MD5 ハッシュを比較しているのでしょう。まずは正しいパスワードの MD5 ハッシュを取得しましょう。

Sources タブで `if (calcMD5(prompt(_0x29a9[5])) === _0x29a9[6]) {` の前の行にブレークポイントを置き、プロンプトが表示されたら適当な文字列を入力します。Console タブで `_0x29a9[6]` を入力すると、`aa42b234cb05915716c1434058fe1aee16c14340cb059157aa42b234` という文字列が返ってきました。[CrackStaion](https://crackstation.net/) に投げてみると、これは `shazam` の MD5 ハッシュであることが分かりました。

リロードして、プロンプトに `shazam` を入力すると `submit as redpwnctf{PASSWORD}` と表示されました。

```
redpwnctf{shazam}
```

### ghast (50)
> Ghast (URL). It's like a gist, but spookier.
> 
> 添付ファイル: ghast.tar.gz

`ghast.tar.gz` を展開すると `ghast.js` と `package.json` の 2 つのファイルが出てきました。`ghast.js` は以下のような内容でした。

```javascript
const { promisify } = require('util')
const http = require('http')
const rawBody = promisify(require('raw-body'))
const cookie = require('cookie')
const secrets = require('./secrets')

let idIdx = 0

const makeId = () => Buffer.from(`ghast:${idIdx++}`).toString('base64').replace(/=/g, '')

const things = new Map()

things.set(makeId(), {
  name: secrets.adminName,
  // to prevent abuse, the admin account is locked
  locked: true,
})

const registerPage = `
<!doctype html>
<form id=form>
  your name: <br><input type=text id=uname><br><br>
  <button type=submit>submit</button>
</form>
<script>
  form.addEventListener('submit', async (evt) => {
    evt.preventDefault()
    const res = await fetch('/api/register', {
      method: 'POST',
      body: JSON.stringify({
        name: uname.value,
      }),
    })
    const text = await res.text()
    if (res.status === 200) {
      document.cookie = 'user=' + encodeURIComponent(text)
      location = '/ghasts/make'
    } else {
      alert(text)
    }
  })
</script>
`

const ghastMakePage = `
<!doctype html>
<form id=form>
  ghast name: <br><input type=text id=gname><br><br>
  ghast content: <br><textarea id=content></textarea><br><br>
  <button type=submit>submit</button>
</form>
<script>
  form.addEventListener('submit', async (evt) => {
    evt.preventDefault()
    const res = await fetch('/api/ghasts', {
      method: 'POST',
      body: JSON.stringify({
        name: gname.value,
        content: content.value,
      }),
    })
    const text = await res.text()
    if (res.status === 200) {
      location = '/ghasts/' + text
    } else {
      alert(text)
    }
  })
</script>
`

const ghastViewPage = `
<!doctype html>
<h1 id=gname></h1>
<div id=content></div>
<script>
  (async () => {
    const res = await fetch('/api/things/' + encodeURIComponent(location.pathname.replace('/ghasts/', '')))
    if (res.status === 200) {
      const body = await res.json()
      gname.textContent = body.name
      content.textContent = body.content
    } else {
      alert(await res.text())
    }
  })()
</script>
`

http.createServer(async (req, res) => {
  let user
  if (req.headers.cookie !== undefined) {
    const userId = cookie.parse(req.headers.cookie).user
    if (things.get(userId) === undefined && req.url !== '/register' && req.url !== '/api/register') {
      res.writeHead(302, {
        location: '/register',
      })
      res.end('')
      return
    } else {
      user = things.get(userId)
    }
  } else if (req.url !== '/register' && req.url !== '/api/register') {
    res.writeHead(302, {
      location: '/register',
    })
    res.end('')
    return
  }
  if (user !== undefined && (req.url === '/register' || req.url === '/')) {
    res.writeHead(302, {
      location: '/ghasts/make',
    })
    res.end('')
  }
  if (req.url === '/api/ghasts' && req.method === 'POST') {
    let body
    try {
      body = JSON.parse(await rawBody(req, {
        limit: '512kb',
      }))
      if (typeof body.name !== 'string' && typeof body.content !== 'string') {
        throw 1
      }
    } catch (e) {
      res.writeHead(400)
      res.end('bad body')
      return
    }
    const id = makeId()
    things.set(id, {
      name: body.name,
      content: body.content,
    })
    res.writeHead(200)
    res.end(id)
  } else if (req.url.startsWith('/api/things/') && req.method === 'GET') {
    const id = req.url.replace('/api/things/', '')
    if (things.get(id) === undefined) {
      res.writeHead(404)
      res.end('ghast not found')
    } else {
      res.writeHead(200)
      res.end(JSON.stringify(things.get(id)))
    }
  } else if (req.url === '/api/register' && req.method === 'POST') {
    let body
    try {
      body = JSON.parse(await rawBody(req, {
        limit: '512kb',
      }))
      if (typeof body.name !== 'string') {
        throw 1
      }
    } catch (e) {
      res.writeHead(400)
      res.end('bad body')
      return
    }
    if (body.name === secrets.adminName) {
      res.writeHead(403)
      res.end('no')
      return
    }
    const id = makeId()
    things.set(id, {
      name: body.name,
    })
    res.writeHead(200)
    res.end(id)
  } else if (req.url === '/api/flag' && req.method === 'GET') {
    if (user.locked) {
      res.writeHead(403)
      res.end('this account is locked')
      return
    }
    if (user.name === secrets.adminName) {
      res.writeHead(200)
      res.end(secrets.flag)
    } else {
      res.writeHead(403)
      res.end('only the admin can wield the flag')
    }
  } else if (req.url === '/register' && req.method === 'GET') {
    res.writeHead(200, {
      'content-type': 'text/html',
    })
    res.end(registerPage)
  } else if (req.url === '/ghasts/make' && req.method === 'GET') {
    res.writeHead(200, {
      'content-type': 'text/html',
    })
    res.end(ghastMakePage)
  } else if (req.url.startsWith('/ghasts/') && req.method === 'GET') {
    res.writeHead(200, {
      'content-type': 'text/html',
    })
    res.end(ghastViewPage)
  } else {
    res.writeHead(404)
    res.end('not found')
  }
}).listen(80, () => {
  console.log('listening on port 80')
})
```

ユーザ登録後、記事を投稿・表示することができるサービスのようです。ユーザ名が `secrets.adminName` で、`locked` が偽である場合に `/api/flag` にアクセスすればフラグが表示されるようです。

記事やユーザの情報は全て `things` という名前の `Map` に、`makeId` 関数 (`ghast:(連番の整数)` を Base64 エンコードした文字列を返す) を使って生成されるキーでオブジェクトを保存するという不思議な実装をしています。そのため、例えばこの `ghast.js` を立ち上げてすぐの状態で `neko` というユーザを作成すると、`things.get(btoa('ghast:1'))` は `{name: 'neko'}` を返します。さらに `aaa` という名前で `bbb` という内容の記事を投稿すると `things.get(btoa('ghast:2'))` は `{name: 'aaa', content: 'bbb'}` を返します。

まずは `secrets.adminName` を得る方法を考えましょう。`ghast.js` を立ち上げてすぐに以下のコードが実行されている (= `idIdx` が `0` なのでキーは必ず `btoa('ghast:0')` になる) ので、`things.get(btoa('ghast:0'))` の内容をどこかで出力させられれば `secrets.adminName` が得られるはずです。

```javascript
const makeId = () => Buffer.from(`ghast:${idIdx++}`).toString('base64').replace(/=/g, '')

const things = new Map()

things.set(makeId(), {
  name: secrets.adminName,
  // to prevent abuse, the admin account is locked
  locked: true,
})
```

前述の通り、記事やユーザの情報はいずれも `things` に保存されており、またキーの生成方法も同じで、`name` というプロパティを持っています。`/ghasts/(ID)` にアクセスするとその記事を閲覧できることを利用しましょう。

`/ghasts/Z2hhc3Q6MA` にアクセスすると、`secrets.adminName` が `sherlockholmes99` であることがわかりました。このユーザ名でユーザ登録…できればよさそうですが、以下のように制限されています。

```javascript
    if (body.name === secrets.adminName) {
      res.writeHead(403)
      res.end('no')
      return
    }
```

ではどうすればよいかというと、ユーザ登録をせずに `name` プロパティが `sherlockholmes99` であるオブジェクトを作ればよいはずです。`sherlockholmes99` という名前の記事を投稿し、この ID を Cookie にセットした上で `/api/flag` にアクセスするとフラグが得られました。

```
flag{th3_AdM1n_ne3dS_A_n3W_nAme}
```

### blueprint (168)
> All the haxors are using blueprint (URL). You created a blueprint with the flag in it, but the military-grade security of blueprint won't let you get it!
> 
> 添付ファイル: blueprint.tar.gz

`blueprint.tar.gz` を展開すると `blueprint.js` と `package.json` の 2 つのファイルが出てきました。`blueprint.js` は以下のような内容でした。

```javascript
const crypto = require('crypto')
const http = require('http')
const mustache = require('mustache')
const getRawBody = require('raw-body')
const _ = require('lodash')
const flag = require('./flag')

const indexTemplate = `
<!doctype html>
<style>
  body {
    background: #172159;
  }
  * {
    color: #fff;
  }
</style>
<h1>your public blueprints!</h1>
<i>(in compliance with military-grade security, we only show the public ones. you must have the unique URL to access private blueprints.)</i>
<br>
︙
<br><a href="/make">make your own blueprint!</a>
`

// ︙

// very janky, but it works
const parseUserId = (cookies) => {
  if (cookies === undefined) {
    return null
  }
  const userIdCookie = cookies.split('; ').find(cookie => cookie.startsWith('user_id='))
  if (userIdCookie === undefined) {
    return null
  }
  return decodeURIComponent(userIdCookie.replace('user_id=', ''))
}

const makeId = () => crypto.randomBytes(16).toString('hex')

// list of users and blueprints
const users = new Map()

http.createServer((req, res) => {
  let userId = parseUserId(req.headers.cookie)
  let user = users.get(userId)
  if (userId === null || user === undefined) {
    // create user if one doesnt exist
    userId = makeId()
    user = {
      blueprints: {
        [makeId()]: {
          content: flag,
        },
      },
    }
    users.set(userId, user)
  }

  // send back the user id
  res.writeHead(200, {
    'set-cookie': 'user_id=' + encodeURIComponent(userId) + '; Path=/',
  })

  if (req.url === '/' && req.method === 'GET') {
    // list all public blueprints
    res.end(mustache.render(indexTemplate, {
      blueprints: Object.entries(user.blueprints).map(([k, v]) => ({
        id: k,
        content: v.content,
        public: v.public,
      })),
    }))
  } else if (req.url.startsWith('/blueprints/') && req.method === 'GET') {
    // show an individual blueprint, including private ones
    const blueprintId = req.url.replace('/blueprints/', '')
    if (user.blueprints[blueprintId] === undefined) {
      res.end(notFoundPage)
      return
    }
    res.end(mustache.render(blueprintTemplate, {
      content: user.blueprints[blueprintId].content,
    }))
  } else if (req.url === '/make' && req.method === 'GET') {
    // show the static blueprint creation page
    res.end(makePage)
  } else if (req.url === '/make' && req.method === 'POST') {
    // API used by the creation page
    getRawBody(req, {
      limit: '1mb',
    }, (err, body) => {
      if (err) {
        throw err
      }
      let parsedBody
      try {
        // default values are easier to do than proper input validation
        parsedBody = _.defaultsDeep({
          publiс: false, // default private
          cоntent: '', // default no content
        }, JSON.parse(body))
      } catch (e) {
        res.end('bad json')
        return
      }

      // make the blueprint
      const blueprintId = makeId()
      user.blueprints[blueprintId] = {
        content: parsedBody.content,
        public: parsedBody.public,
      }

      res.end(blueprintId)
    })
  } else {
    res.end(notFoundPage)
  }
}).listen(80, () => {
  console.log('listening on port 80')
})
```

やっていることはほとんど ghast と同じですが、実装は結構異なっています。特に気になる部分を見てみます。まず、`makeId` の返り値は推測ができなくなっています。

```javascript
const makeId = () => crypto.randomBytes(16).toString('hex')
```

フラグは、以下のように `publiс` が設定されていない記事の内容として存在しています。

```javascript
  if (userId === null || user === undefined) {
    // create user if one doesnt exist
    userId = makeId()
    user = {
      blueprints: {
        [makeId()]: {
          content: flag,
        },
      },
    }
    users.set(userId, user)
  }
```

記事の追加は API に JSON を投げる形で行われ、これをパースした結果が [Lodash](https://lodash.com/) の [`_.defaultsDeep`](https://lodash.com/docs/#defaultsDeep) に通された後、ほとんどそのまま保存されています。

```javascript
      let parsedBody
      try {
        // default values are easier to do than proper input validation
        parsedBody = _.defaultsDeep({
          publiс: false, // default private
          cоntent: '', // default no content
        }, JSON.parse(body))
      } catch (e) {
        res.end('bad json')
        return
      }

      // make the blueprint
      const blueprintId = makeId()
      user.blueprints[blueprintId] = {
        content: parsedBody.content,
        public: parsedBody.public,
      }
```

さて、この Web アプリケーションの脆弱性を探してみましょう。まずは使われているライブラリに脆弱性がないか確認します。`npm i --package-lock-only` で `package-lock.json` を生成した後、`npm audit` を実行すると以下のように出力されました。

```javascript
$ npm audit

                       === npm audit security report ===

# Run  npm install lodash@4.17.15  to resolve 1 vulnerability

  High            Prototype Pollution

  Package         lodash

  Dependency of   lodash

  Path            lodash

  More info       https://npmjs.com/advisories/1065



found 1 high severity vulnerability in 13 scanned packages
  run `npm audit fix` to fix 1 of them.
```

このバージョンの Lodash にプロトタイプ汚染攻撃が可能になる脆弱性があるようです。`package.json` を見ると `"lodash": "4.17.11"` とこのバージョンで固定されており、これはおそらく意図的に設定されたものでしょう。

[この脆弱性のアドバイザリ](https://www.npmjs.com/advisories/1065)を確認すると、`_.defaultsDeep` に `{constructor: {prototype: {...}}}` のようなオブジェクトを投げることで `Object` の `prototype` を汚染できてしまうようです。この Web アプリケーションでは前述のように `_.defaultsDeep` が使われており、この脆弱性が利用できそうです。

もし `Object.prototype.public` を `true` にできれば、`public` プロパティが存在していないフラグの記事については、`public` プロパティにアクセスする際にこれが参照されて `true` と判定され、全てのユーザから閲覧できるようになるはずです。

ということで、先述の脆弱性を利用して `Object.prototype.public` を書き換えましょう。以下の JavaScript コードを DevTools で実行します。

```javascript
fetch('/make', {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
  },
  body: '{"content":"value","public":true,"constructor":{"prototype":{"public": true}}}'
}).then(res => res.text()).then(res => { console.log(res); });
```

記事一覧のページを参照するとフラグが得られました。

```
flag{8lu3pr1nTs_aRe_tHe_hiGh3s1_quA11tY_pr0t()s}
```

## Forensics
### Molecule Shirts (212)
> Apparently, this picture has a name? The flag is in the format flag{name}.
> 
> 添付ファイル: picture.png

よく分からない物質の構造式の画像が与えられました。とりあえず問題名でググってみると [Molecular Shirts](http://www.molecularshirts.com/) というサイトがヒットしました。

このサイトの [Your name in molecules!](http://www.molecularshirts.com/your-name-in-molecules/) というページで適当な名前を選択すると `picture.png` とよく似た構造式が表示されました。色々試していると、名前が長ければ長いほど画像の幅は大きくなり、また、よく似た文字列であれば出力される構造式もよく似たものが出力されることが分かりました。片っ端から試していくと、`Dr. ARMSTRONG` の時に `picture.png` と同じ画像が出力されました。Forensics とは一体…

```
flag{Dr. ARMSTRONG}
```