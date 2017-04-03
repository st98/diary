---
layout: post
title: Teaser CONFidence CTF 2017 の write-up
categories: [ctf]
date: 2017-04-03 14:30:02 +0900
---

チーム Harekaze で [Teaser CONFidence CTF 2017](https://ctf.dragonsector.pl/) に参加しました。最終的にチームで 201 点を獲得し、順位は 35 位 (得点 258 チーム中) でした。うち、私は 1 問を解いて 200 点を入れました。

以下、解いた問題の write-up です。

## [Reverse Engineering 200] Starblind

与えられた URL を開いてしばらく待つと、`Who rules this star system?` という文章とともに入力画面が表示されました。

index.html をダウンロードしてみると、どうやらこれは約 1 MB の巨大なファイルのようでした。

`<script src="data:text/javascript;base64,..."></script>` という形でスクリプトを読み込んでいるようだったので

```python
import re
s = open('starblind.html').read()
open('a.js', 'w').write(a.decode('base64'))
```

で実行されているスクリプトを取り出しました。取り出したスクリプトの主要な部分を抜き出すと以下のようになりました。

```javascript
// ...
var CalcSHA4 = function(block) {
  let r = new Uint8Array(64);

  for (let i = 0; i < block.length; i++) {
    r[i] = block.charCodeAt(i);
  }

  for (let i = 32; i < 64; i++) {
    r[i] = i * 48271;  
  }

  let xor = function (imm) {
    for (let i = 0; i < 64; i++) {
      r[i] ^= imm[i];
    }
  };

  let perm = function (imm) {
    let n = new Uint8Array(64);  
    for (let i = 0; i < 512; i++) {
      const dst_bit = i%8;
      const dst_byte = i/8|0;
      const sign = Math.sgn(imm[i]);
      const idx = sign ? -imm[i] : imm[i];
      const src_bit = idx%8;
      const src_byte = idx/8|0;
      let b = (r[src_byte] >> src_bit) & 1;
      if (sign) { b ^= 1; }      
      n[dst_byte] |= b << dst_bit;
    }
    r = n;
  };

  xor([...]);
  perm([...])
  // ...
  hexdigest = "";
  for (let i = 0; i < 64; i++) {
    let n = r[i].toString(16);        
    if (n.length < 2) {
      n = "0" + n;
    }
    hexdigest += n;
  }

  return hexdigest;
}
// ...
var gPassword = "";
var gLastChecked = "";
var gGoodPassword = false;
// ...
var HandleDown = function(e) {
  const code = e.key.charCodeAt(0);
  if (e.key.length === 1 && code >= 0x20 && code <= 0x7e) {
    if (gPassword.length < 27) {
      gPassword += e.key;
    }

  } else if (e.key === "Backspace") {
    gPassword = gPassword.substring(0, gPassword.length - 1);
    e.preventDefault();    
  } else {
    //console.log(e);
  }  

  if (gLastChecked != gPassword) {
    gLastChecked = gPassword;
    CheckPassword();
  }
};
// ...
var CheckPassword = function() {
  if (gPassword.length != 27) {
    gGoodPassword = false;
    return;
  }

  const hash = CalcSHA4(gPassword);
  const correct = "983bb35ed0a800fcc85d12806df9225364713be578ba67f65bc508b77f0c54878eda18a5eed50bac705bdc7db205623221e8ffe330483955a22216960754a122";
  gGoodPassword = hash === correct;
};
// ...
  Math.sgn = function(a) { return 1/a<0; };
// ...
```

`CalcSHA4` がどのような値を返すか少し試してみましょう。

```javascript
console.log(CalcSHA4('A'.repeat(26) + 'A'));
console.log(CalcSHA4('A'.repeat(26) + 'B'));
console.log(CalcSHA4('A'.repeat(26) + 'C'));
```

この出力は以下のようになりました。

```
103b815690a801fec95b1a816d392316687b3de54a3a67725e940ab57f84548eeeda5a85ecc54fac685f5d59b605629231e9f7e330413d75a232169e5556d226
103b815690a803fec95b1a816d392316685b3de54a3a67725e940ab57f84548eeeda5a85ecc54fac685f5d59b605629231e9f7e330413d75a232169e5556d226
103b815690a801fec95b1a816d392316685b3de54a3a67725e940ab57f84548eeeda5a85ecc54fac685f5d59b605629231e9f7e330413d75a232169e5556d226
```

変化している部分がほとんどありません。フラグは `DrgnS{(20文字)}` というような形であると分かっているので、ゴリ押ししましょう。

```javascript
var correct = '983bb35ed0a800fcc85d12806df9225364713be578ba67f65bc508b77f0c54878eda18a5eed50bac705bdc7db205623221e8ffe330483955a22216960754a122';
var zfill = function (s, n) {
  return '0'.repeat(n - s.length) + s;
};
var count = function (a, b) {
  var res = 0;
  for (var i = 0; i < a.length; i++) {
    var c, d;
    c = zfill(parseInt(a[i], 16), 4);
    d = zfill(parseInt(b[i], 16), 4);
    for (var j = 0; j < 4; j++) {
      res += c[j] == d[j];
    }
  }
  return res;
};
var check = function (t) {
  var a = [];
  for (var i = 0x20; i < 0x7f; i++) {
    var s = t;
    s += String.fromCharCode(i);
    s += (26 - s.length) > 0 ? 'a'.repeat(26 - s.length) : '';
    s += '}';
    s = s.slice(-27);
    a.push([s, count(correct, CalcSHA4(s))]);
  }
  return a.sort((a, b) => a[1] - b[1]);
}
console.clear();
console.log(check('DrgnS{').join('\n'));
```

このスクリプトを使うと

```
console.log(check('DrgnS{').join('\n'));
...
-> DrgnS{Haaaaaaaaaaaaaaaaaaa},467
-> DrgnS{Laaaaaaaaaaaaaaaaaaa},467
```

```
console.log(check('DrgnS{H').join('\n'));
...
-> DrgnS{HQaaaaaaaaaaaaaaaaaa},468
-> DrgnS{Huaaaaaaaaaaaaaaaaaa},468
-> DrgnS{HUaaaaaaaaaaaaaaaaaa},468
-> DrgnS{Hqaaaaaaaaaaaaaaaaaa},468
```

```
console.log(check('DrgnS{Hu').join('\n'));
-> DrgnS{Humaaaaaaaaaaaaaaaaa},470
```

という感じで少しずつフラグを得ることができました。

```
DrgnS{Humank1ndEmpire0fAbh}
```
