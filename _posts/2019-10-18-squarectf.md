---
layout: post
title: Square CTF 2019 の write-up
categories: [ctf]
date: 2019-10-18 06:00:00 +0900
---

10 月 11 日から 10 月 17 日にかけて開催された [Square CTF 2019](https://2019.squarectf.com/) に、チーム zer0pts として参加しました。最終的にチームで 6450 点を獲得し、順位は得点 223 チーム中 7 位でした。うち、私は 1 問を解いて 200 点を入れました。

以下、私が解いた問題の write-up です。

## [Web 200] Inwasmable
> After watching you type around on your computer a bunch, you inspire Sam to give the ‘ol computers a try. They decide a website sounds nice. They use websites. Plenty of tutorials on how to make the thing.
> 
> “Let me know if you need any help, Sam” you say as you lay down on the couch to take a nice little nap.
> 
> Midway through a dream where you can fly but only some of the time for some reason, you feel a nudge on your shoulder.
> 
> “Hey, I, uh, need you to have a look at something.” Sam whispers.
> 
> They hand over their laptop, and you are greeted with their browser and more browser tabs of Stack Overflow than you’ve ever seen.
> 
> “I tried to do what I could,” Sam starts, “but I borrowed some snippets from the internet, and now my site doesn’t work.”
> 
> Sam's site. (URL)

与えられた URL にアクセスすると、以下のような HTML が返ってきました。

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
html, body { height: 100%; } html { display: table; margin: auto; } body { display: table-cell; vertical-align: middle; } input[type=text] { width: 22rem; } * { font-size: x-large; margin: 2px; padding: 5px; height: 1em}
</style>
</head>
<body>
  <pre>Inwasmble</pre>
  <input id="x" type="text" onKeyUp="go()" autocomplete="off">
  <div id="r">&nbsp;</div>
	<script>eval(unescape(escape('').replace(/u.{8}/g,'')))</script>
<!-- Alok -->
</body>
</html>
```

何もしていないように見えますが、バイナリエディタで開いてみると `escape('')` でエスケープされている文字列は `U+E0176` や `U+E0161` などの不可視な文字であることがわかりました。

上記の HTML を保存して `eval` を `console.log` に書き換え、どのようなコードが実行されているか確認しましょう。

```javascript
var code = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60,
  0x00, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01,
  0x07, 0x15, 0x02, 0x06, 0x6d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x02, 0x00,
  0x08, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x00, 0x00, 0x0a,
  0x87, 0x01, 0x01, 0x84, 0x01, 0x01, 0x04, 0x7f, 0x41, 0x00, 0x21, 0x00,
  0x02, 0x40, 0x02, 0x40, 0x03, 0x40, 0x20, 0x00, 0x41, 0x20, 0x46, 0x0d,
  0x01, 0x41, 0x02, 0x21, 0x02, 0x41, 0x00, 0x21, 0x01, 0x02, 0x40, 0x03,
  0x40, 0x20, 0x00, 0x20, 0x01, 0x46, 0x0d, 0x01, 0x20, 0x01, 0x41, 0x04,
  0x6c, 0x41, 0x80, 0x02, 0x6a, 0x28, 0x02, 0x00, 0x20, 0x02, 0x6c, 0x21,
  0x02, 0x20, 0x01, 0x41, 0x01, 0x6a, 0x21, 0x01, 0x0c, 0x00, 0x0b, 0x0b,
  0x20, 0x00, 0x41, 0x04, 0x6c, 0x41, 0x80, 0x02, 0x6a, 0x20, 0x02, 0x41,
  0x01, 0x6a, 0x36, 0x02, 0x00, 0x20, 0x00, 0x2d, 0x00, 0x00, 0x20, 0x00,
  0x41, 0x80, 0x01, 0x6a, 0x2d, 0x00, 0x00, 0x73, 0x20, 0x00, 0x41, 0x04,
  0x6c, 0x41, 0x80, 0x02, 0x6a, 0x2d, 0x00, 0x00, 0x47, 0x0d, 0x02, 0x20,
  0x00, 0x41, 0x01, 0x6a, 0x21, 0x00, 0x0c, 0x00, 0x0b, 0x0b, 0x41, 0x01,
  0x0f, 0x0b, 0x41, 0x00, 0x0b, 0x0b, 0x27, 0x01, 0x00, 0x41, 0x80, 0x01,
  0x0b, 0x20, 0x4a, 0x6a, 0x5b, 0x60, 0xa0, 0x64, 0x92, 0x7d, 0xcf, 0x42,
  0xeb, 0x46, 0x00, 0x17, 0xfd, 0x50, 0x31, 0x67, 0x1f, 0x27, 0x76, 0x77,
  0x4e, 0x31, 0x94, 0x0e, 0x67, 0x03, 0xda, 0x19, 0xbc, 0x51
]);

var wa = new WebAssembly.Instance(new WebAssembly.Module(code));
var buf = new Uint8Array(wa.exports.memory.buffer);

async function go() {
  sizes = [...[...Array(4)].keys()].map(x=>x*128);
  buf.set(x.value.substr(sizes[0], sizes[1]).padEnd(sizes[1]).split('').map(x=>x.charCodeAt('')));
  if (wa.exports.validate()) {
    hash = await window.crypto.subtle.digest("SHA-1", buf.slice(sizes[2], sizes[3]));
    r.innerText = "\uD83D\uDEA9 flag-" + [... new Uint8Array(hash)].map(x => x.toString(16)).join('');
  } else {
    r.innerHTML = x.value == "" ? "&nbsp;" : "\u26D4";
  }
}
```

WebAssembly のバイナリをロードし、入力した文字列をメモリにロードしたあと、バイナリ中で定義されている `validate` 関数が `true` と評価される値を返せばフラグを表示するようです。

実行されている WebAssembly コードは次のようなものでした。

```
func (result i32)
(local i32 i32 i32 i32)
  i32.const 0
  local.set 0
  block
    block
      loop
        local.get 0
        i32.const 32
        i32.eq
        br_if 1
        i32.const 2
        local.set 2
        i32.const 0
        local.set 1
        block
          loop
            local.get 0
            local.get 1
            i32.eq
            br_if 1
            local.get 1
            i32.const 4
            i32.mul
            i32.const 256
            i32.add
            i32.load offset=0 align=4
            local.get 2
            i32.mul
            local.set 2
            local.get 1
            i32.const 1
            i32.add
            local.set 1
            br 0
          end
        end
        local.get 0
        i32.const 4
        i32.mul
        i32.const 256
        i32.add
        local.get 2
        i32.const 1
        i32.add
        i32.store offset=0 align=4
        local.get 0
        i32.load8_u offset=0 align=1
        local.get 0
        i32.const 128
        i32.add
        i32.load8_u offset=0 align=1
        i32.xor
        local.get 0
        i32.const 4
        i32.mul
        i32.const 256
        i32.add
        i32.load8_u offset=0 align=1
        i32.ne
        br_if 2
        local.get 0
        i32.const 1
        i32.add
        local.set 0
        br 0
      end
    end
    i32.const 1
    return
  end
  i32.const 0
end
```

JavaScript 等でいう `if (a != b) break` にあたる、次のような命令列に注目します。

```
i32.ne
br_if 2
```

`i32.ne` (スタックから 2 つの 32 ビット整数値を pop し、等しければ 0 を、そうでなければ 1 を push する) にブレークポイントを置き、`a` を入力すると、`43` と `3` が比較されていることが確認できました。入力する文字列を `b` に変えると、今度は `40` と `3` が比較されていることが確認できました。

`43` と `3` と `97` (`a` の ASCII コード) を XOR して文字に変換した `I` を入力すると、`i32.ne` は 0 を push するようになり、これで `br_if 2` でループを抜けて `validate` が 0 を返すことがなくなりました。これを繰り返すと `Impossible is for the unwilling.` が正解の文字列であることがわかり、これを入力するとフラグが得られました。

```
flag-bee523b8ed974cb8929c3a5f2d89e4fb99694a2
```