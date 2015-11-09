---
layout: post
title: SECCON 福島大会 (サイバー甲子園) に参加しました
categories: [ctf]
date: 2015-11-08 23:20:00 +0900
---

竹さん ([@takemioIO](https://twitter.com/takemioIO)) と一緒にチーム omakase として SECCON 福島大会 (サイバー甲子園) に参加しました。  
最終的に獲得できたポイントは 1510 点で、チーム順位は 3 位 (10 チーム中) でした。

どうやら 2016 年の 1 月に開催される決勝大会 (intercollege) に参加できるようです。嬉しい。

## 競技時間中に解いた問題
私は競技時間中、

- Find from binary (binary 100)
- Guess the flag (binary 200)
- Easy decrypto (crypto 100)
- Simple crypto (crypto 100)
- Access to restricted url (network 100)
- National flag (programming 100)
- RPN (programming 200)
- Invisible flag (web 100)
- Login (web 100)
- Your browser is not supported (web 200)
- Invisible (unknown 100)
- PDF (unknown 100)

の 12 問を解きました。

web や crypto の問題は問題文を全然メモってなかったのでアレですが、以下にそれぞれの問題の write-up を書いてみます。

### Find from binary (binary 100)
questions という ELF ファイルが渡されました。

0x08048429 で eax > 0x2 となるようにしてやるとフラッグが表示されました。

```sh
$ gdb -q -n ./questions
(gdb) b *0x08048429
Breakpoint 1 at 0x8048429
(gdb) commands
>  set $eax = 3
>  c
>end
(gdb) r
Breakpoint 1, 0x08048429 in main ()
SECCON{Can Uread me?
```

```
flag: SECCON{Can U read me?}
```

### Guess the flag (binary 200)
guess という ELF ファイルが渡されました。

0x0804857b で al にビット反転されたフラッグの n 文字目が入っているので、ZF を立てて、al をビット反転させた文字を出力するとフラッグが出てきました。

```sh
$ gdb -n -q guess
(gdb) b *0x0804857b
Breakpoint 1 at 0x804857b
(gdb) commands
>  silent
>  set $eflags |= (1 << 6)
>  printf "%c", $al ^ 0xff
>  c
>end
(gdb) r
Guess the flag: a
SECCON{XOR_encryption_message}
Congraturations!
```

```
flag: SECCON{XOR_encryption_message}
```

### Easy decrypto (crypto 100) / Simple crypto (crypto 100)
それぞれ ROT13 か base64 でエンコードされていたので、デコードするとフラッグ (もしくはヒント) が出てきました。

```
flag: (忘れました)
```

### Access to restricted url (network 100)
pcap ファイルが渡されました。

Basic 認証でアクセスが制限されているファイルにアクセスしている様子が記録されています。認証情報も記録されているので Base64 でデコードするとフラッグが出てきました。

```
flag: SECCON{Basic_auth_is_not_secure_in_most_cases.}
```

### National flag (programming 100)
Python プログラムのファイルが渡されました。

```python
def draw_flag():
  def fill_rect(size, fill_color):
    …
```

という感じで `draw_flag()` が定義されているのはいいのですが、どこからも呼ばれていません。

ファイルの最終行に `draw_flag()` を書き足して Python で実行してやると国旗が描かれます。

問題文に書かれているフォーマットに、あらわれた国旗の国名を当てはめたものがフラッグでした。

```
flag: SECCON{MYANMAR}
```

### RPN (programming 200)
RPN.txt という、すごい長い逆ポーランド記法の式が渡されました。

数値がちょっと変わっていて、`1lp(34)` なら 1lp を 34 進数として解釈した数値をスタックに積む…という仕様でした。

```python
from decimal import *
getcontext().prec = 100
s = open('RPN.txt').read().replace('\n', '').split(' ')
stack = []
for x in s:
  if x == '+':
    a, b = stack.pop(), stack.pop()
    stack.append(a + b)
  elif x == '-':
    a, b = stack.pop(), stack.pop()
    stack.append(b - a)
  elif x == '*':
    a, b = stack.pop(), stack.pop()
    stack.append(a * b)
  elif x == '/':
    a, b = stack.pop(), stack.pop()
    stack.append(b / a)
  else:
    if '(' in x:
      x = Decimal(int(x[:x.find('(')],int(x[x.find('(')+1:-1])))
    else:
      x = int(x)
    stack.append(x)
print ('%x' % stack[0]).decode('hex')
```

```
flag: SECCON{RPN can be read as Japanese}
```

### Invisible flag (web 100)
(忘れました)

### Login (web 100)
与えられた URL (`http://…/index.php`) にアクセスすると、302 で`login.php` に飛ばされログイン画面が表示されました。

ユーザ名とパスワードを適当に入力して送信したところ、SQLite3 が見つからないという感じのエラーが表示されました。

Wireshark でキャプチャしながらもう一度 `index.php` にアクセスしたところ、レスポンスボディにフラッグが書かれていました。

```
flag: (忘れました)
```

### Your browser is not supported (web 200)
与えられた URL に Chrome でアクセスしたところ、そのブラウザには対応していないと表示されました。

favicon が Netscape なので curl などで User-Agent を Netscape のものに変えた状態でアクセスするとフラッグが表示されました。

```
flag: (忘れました)
```

### Invisible (unknown 100)
真っ黒な PNG ファイルが渡されました。

そのままだと何も書かれていないように見えますが、ペイントで開いて適当な色で塗りつぶしてやるとフラッグが出てきました。

```
flag: SECCON{INVISIBLE_FOR_HUMAN}
```

### PDF (unknown 100)
一部が黒塗りにされた PDF ファイルが渡されました。

黒塗りの下はテキストのようなので、選択して適当なところに貼り付けると黒塗りにされていたフラッグが出てきました。

```
flag: SECCON{kuronuri_chuui}
```

## 終わってから解けた (?) 問題
### Where is the flag (binary 300)
WpfApplication2.exe という exe ファイルが渡されました。

とりあえず `file` に投げてみると、`PE32 executable for MS Windows (GUI) Intel 80386 32-bit Mono/.Net assembly`。  
ILSpy に投げると逆コンパイルできました。

リソース部分を眺めていると `mainwindow.baml` というファイルが。  
BAML 形式ですが、ILSpy が XAML に逆コンパイルしてくれているのでそちらを保存。

Path 要素の Data を眺めていると `M0.53906256…` から始まる同じパスデータが複数あったので、

```html
<svg>
  <path d="…">
</svg>
```

の … の部分に挿入して `a.html` みたいな感じで保存して閲覧。`フラグはどこ？` と表示されました。

他のパスデータを探すと、`M3.6386719…` から始まるパスデータを発見。  
同様にして閲覧すると、フラッグ (らしきもの) が表示されました。

```
flag (たぶん): SECCON{QqqVhPSnPekPmJA3twJM}
```
