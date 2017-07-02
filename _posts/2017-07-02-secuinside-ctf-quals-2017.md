---
layout: post
title: SECUINSIDE CTF Quals 2017 の write-up
categories: [ctf]
date: 2017-07-02 18:52:00 +0900
---

チーム Harekaze で [SECUINSIDE CTF Quals 2017](https://ctf.leave.cat/) に参加しました。最終的にチームで 523 点を獲得し、順位は得点 543 チーム中 43 位でした。うち、私は 2 問を解いて 463 点を入れました。

以下、解いた問題の write-up です。

## [REVERSING 196] TripleRotate

内容が 0 と 1 だけの暗号化された `encrypt` というファイルと、`prob` というバイナリが与えられました。

`prob` について調べてみます。

```
$ file prob 
prob: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=26a87d66cee9849e606408ca0d67f2023af31da4, stripped
$ ./prob 
Input : hoge
check your input
$ ./prob 
Input : aaaaaaaaa
Length : 200
check your length
$ ./prob 
Input : aaaaaaaaa
Length : 201
$ cat encrypt
1 0 0 0 1 1 1 1 ... 0 0 0 0 1 1 1 0 
```

`aaaaaaaaa` と `201` を入力すると、暗号化された 201 ビットのデータが `encrypt` というファイルに書き出されるようです。

バイナリをデコンパイルすると以下のようになりました。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void func_400876(char *arg0, int arg1, char *arg2);
void func_400998(char **arg0, char *arg1);
void func_400acf(char *arg0, int arg1);
void func_400b22(char *arg0, int arg1);
void func_400b9b(char *arg0, int arg1);

// 0x400704
int main(void) {
  char *buf; // rbp-0x40
  FILE *fp; // rbp-0x38
  int length; // rbp-0x2c
  int i; // rbp-28;
  char c; // rbp-0x21
  char input[24]; // rbp-0x20
  int result = 0; // rbp-0x8

  printf("Input : ");
  scanf("%s", input);

  if (strlen(input) != 9) {
    puts("check your input");
    return result;
  }

  printf("Length : ");
  scanf("%d", &length);

  if (length <= 200) {
    puts("check your length");
    return result;
  }

  buf = malloc(length);
  func_400876(input, length, buf);

  fp = fopen("encrypt", "wb");
  for (i = 0; i < length; i++) {
    if (buf[i]) {
      c = '1';
    } else {
      c = '0';
    }
    fputc(c, fp);
    fputc(' ', fp);
  }

  return result;
}

void func_400876(char *arg0, int arg1, char *arg2) {
  void (*var_60[3])(char *, int) = { // rbp-0x60
    func_400acf,
    func_400b22,
    func_400b9b
  };
  char *var_40[3]; // rbp-0x40
  int i; // rbp-0x1c
  int j; // rbp-0x18
  int k; // rbp-0x14

  for (i = 0; i <= 2; i++) {
    var_40[i] = malloc(arg1);
  }

  func_400998(var_40, arg0);

  for (j = 0; j <= 2; j++) {
    var_60[j](var_40[j], arg1);
  }

  for (k = 0; k < arg1; k++) {
    arg2[k] = (var_40[0][k] & var_40[1][k]) ^ (var_40[2][k] & var_40[1][k]) ^ var_40[2][k];
  }
}

void func_400998(char **arg0, char *arg1) {
  int var_80[4] = { // rbp-0x80
    0, 0x17, 0x18, 0x19
  };
  int i; // rbp-0x60
  int var_5c; // rbp-0x5c
  int j; // rbp-0x58
  int k; // rbp-0x54
  char var_50[72]; // rbp-0x50
  char *var_68 = var_50; // rbp-68

  for (i = 0; i <= 0x47; i++) {
    var_50[i] = (arg1[i >> 3] >> (7 - i & 7)) & 1;
  }

  for (j = var_5c = 0; j <= 2; j++) {
    var_5c += var_80[j];
    k = var_80[j + 1] - 1;

    while (k >= 0) {
      arg0[j][k] = *var_68;
      var_68++;
      k--;
    }
  }
}

void func_400acf(char *arg0, int arg1) {
  int i; // rbp-0x4

  for (i = 0; arg1 - 0x17 > i; i++) {
    arg0[i + 0x17] = arg0[i + 5] ^ arg0[i];
  }
}

void func_400b22(char *arg0, int arg1) {
  int i; // rbp-0x4

  for (i = 0; arg1 - 0x18 > i; i++) {
    arg0[i + 0x18] = arg0[i + 4] ^ arg0[i + 3] ^ arg0[i + 1] ^ arg0[i];
  }
}

void func_400b9b(char *arg0, int arg1) {
  int i; // rbp-0x4

  for (i = 0; arg1 - 0x19 > i; i++) {
    arg0[i + 0x19] = arg0[i + 3] ^ arg0[i];
  }
}
```

Z3 で解きましょう。

```python
def func_400acf(s, n):
  i = 0
  while n - 0x17 > i:
    s[i + 0x17] = s[i + 5] ^ s[i]
    i += 1

def func_400b22(s, n):
  i = 0
  while n - 0x18 > i:
    s[i + 0x18] = s[i + 4] ^ s[i + 3] ^ s[i + 1] ^ s[i]
    i += 1

def func_400b9b(s, n):
  i = 0
  while n - 0x19 > i:
    s[i + 0x19] = s[i + 3] ^ s[i]
    i += 1

def func_400998(s, t):
  var_80 = [0, 0x17, 0x18, 0x19]
  var_50 = [0] * 72

  i = 0
  for i in range(0x48):
    var_50[i] = (t[i >> 3] >> (7 - i & 7)) & 1

  var_5c = 0
  k = 0
  for i in range(3):
    var_5c += var_80[i]
    j = var_80[i + 1] - 1

    while j >= 0:
      s[i][j] = var_50[k]
      k += 1
      j -= 1

def func_400876(s, n):
  var_60 = [func_400acf, func_400b22, func_400b9b]
  var_40 = []
  res = [0] * n

  for i in range(3):
    var_40.append([0] * n)

  func_400998(var_40, s)

  for i in range(3):
    var_60[i](var_40[i], n)

  for i in range(n):
    res[i] = (var_40[0][i] & var_40[1][i]) ^ (var_40[2][i] & var_40[1][i]) ^ var_40[2][i]

  return res

if __name__ == '__main__':
  import sys
  from z3 import *

  with open('encrypt', 'r') as f:
    encrypted = f.read()

  xs = [BitVec('x_%d' % x, 8) for x in range(9)]
  res = func_400876(xs, 201)
  solver = Solver()

  for a, b in zip(res, encrypted.strip().split(' ')):
    b = int(b)
    solver.add(a == b)

  r = solver.check()
  if r != sat:
    sys.exit(1)

  m = solver.model()

  flag = ''
  for x in xs:
    flag += chr(m[x].as_long())

  print('SECU[%s]' % flag)
```

```
$ python2 solve.py
SECU[I_L0v3_zE]
```

```
SECU[I_L0v3_zE]
```

## [REVERSING 267] snake

`snake` というバイナリが与えられました。

`snake` について調べてみます。

```
$ file snake
snake: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=ca05421c9b431767bbcb30b644f9b625866606a3, stripped
$ ./snake

        ███████╗███╗   ██╗ █████╗ ██╗  ██╗███████╗     ██████╗  █████╗ ███╗   ███╗███████╗
        ██╔════╝████╗  ██║██╔══██╗██║ ██╔╝██╔════╝    ██╔════╝ ██╔══██╗████╗ ████║██╔════╝
        ███████╗██╔██╗ ██║███████║█████╔╝ █████╗      ██║  ███╗███████║██╔████╔██║█████╗  
        ╚════██║██║╚██╗██║██╔══██║██╔═██╗ ██╔══╝      ██║   ██║██╔══██║██║╚██╔╝██║██╔══╝  
        ███████║██║ ╚████║██║  ██║██║  ██╗███████╗    ╚██████╔╝██║  ██║██║ ╚═╝ ██║███████╗
        ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝     ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝
                        Welcome To The Snake Game!
                Do you Want Play Game and Get FLAG?? Let's Play Game.


        1. Game Start    
        2. How To Play   
        3. How To Get FLAG 
        4. Exit

(3 を入力)

        [!] How To Get FLAG?
         If you clear the Game, you Get FLAG

        1. Game Start    
        2. How To Play   
        3. How To Get FLAG 
        4. Exit

(1 を入力)

################################################################################
#                                                                              #
#                                                      0                       #
#                                                                              #
#                                                                              #
#                                                                              #
#                                                                              #
#                                                                              #
#                                                                              #
#                                    X###                                      #
#                                                                              #
#                                                                              #
#                                                                              #
#                                                                              #
#                                                                              #
#                                                                              #
#                                                                              #
#                                                                              #
#                                                                              #
#                                                                              #
################################################################################

    Score: 0                                       Stage : 1
```

どうやらスネークゲームのようです。普通にクリアできてしまうのではと考えてやってみたものの、ステージが上がるごとにヘビが速くなり、ステージ 10 まで行くと人間には反応できないスピードになってしまいました。

なんとかならないか、`snake` を解析していきましょう。

main は 0x401cbe です。0x401ba0 で `SNAKE GAME` のバナーなどを表示し、0x401c15 でメニューを表示して返り値に選択されたメニューの番号を得、それが 1 (Game Start) であれば 0x401a46 を呼んでいます。

0x401a46 はどうやら様々な初期化を行っているようで、最後にヘビの向きや画面の幅、高さなどを引数として 0x4014db を呼んでいます。

0x4014db はメインループのようです。

まずエサの当たり判定処理を探すと、以下の処理が見つかりました。

```
  4015ee:	48 8b 95 60 ff ff ff 	mov    rdx,QWORD PTR [rbp-0xa0]
  4015f5:	48 8b 85 68 ff ff ff 	mov    rax,QWORD PTR [rbp-0x98]
  4015fc:	48 89 d6             	mov    rsi,rdx
  4015ff:	48 89 c7             	mov    rdi,rax
  401602:	e8 53 fa ff ff       	call   40105a <rand@plt+0x75a>
  401607:	85 c0                	test   eax,eax
  401609:	0f 84 bb 00 00 00    	je     4016ca <rand@plt+0xdca>
  40160f:	8b bd 54 ff ff ff    	mov    edi,DWORD PTR [rbp-0xac] ; length of snake
  401615:	48 8b 8d 68 ff ff ff 	mov    rcx,QWORD PTR [rbp-0x98]
  40161c:	8b 95 58 ff ff ff    	mov    edx,DWORD PTR [rbp-0xa8]
  401622:	8b b5 5c ff ff ff    	mov    esi,DWORD PTR [rbp-0xa4]
  401628:	48 8b 85 60 ff ff ff 	mov    rax,QWORD PTR [rbp-0xa0]
  40162f:	41 89 f8             	mov    r8d,edi
  401632:	48 89 c7             	mov    rdi,rax
  401635:	e8 9c f7 ff ff       	call   400dd6 <rand@plt+0x4d6>
  40163a:	83 85 54 ff ff ff 01 	add    DWORD PTR [rbp-0xac],0x1 ; length of snake
  401641:	8b 45 18             	mov    eax,DWORD PTR [rbp+0x18] ; stage
  401644:	01 45 10             	add    DWORD PTR [rbp+0x10],eax ; score
```

0x40105a を呼んで、その返り値が 0 以外ならスコアを増やしてヘビを伸ばしています。`je 4016ca` を nop で潰すと、エサを食べなくてもヘビがどんどん伸びるようになりました。

次にヘビの移動処理を探すと、0x400f84 というヘビの描画などを行っている関数の中で以下の処理が見つかりました。

```
  40100a:	8b 55 e0             	mov    edx,DWORD PTR [rbp-0x20] ; direction
  40100d:	8b 4d e4             	mov    ecx,DWORD PTR [rbp-0x1c]
  401010:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
  401014:	89 ce                	mov    esi,ecx
  401016:	48 89 c7             	mov    rdi,rax
  401019:	e8 93 fe ff ff       	call   400eb1 <rand@plt+0x5b1>
```

```
  400eb1:	55                   	push   rbp
  400eb2:	48 89 e5             	mov    rbp,rsp
  400eb5:	48 89 7d e8          	mov    QWORD PTR [rbp-0x18],rdi
  400eb9:	89 75 e4             	mov    DWORD PTR [rbp-0x1c],esi
  400ebc:	89 55 e0             	mov    DWORD PTR [rbp-0x20],edx ; direction
...
  400f1a:	8b 45 e0             	mov    eax,DWORD PTR [rbp-0x20]
  400f1d:	83 f8 42             	cmp    eax,0x42
  400f20:	74 18                	je     400f3a <rand@plt+0x63a>
  400f22:	83 f8 42             	cmp    eax,0x42
  400f25:	7f 07                	jg     400f2e <rand@plt+0x62e>
  400f27:	83 f8 41             	cmp    eax,0x41
  400f2a:	74 32                	je     400f5e <rand@plt+0x65e>
  400f2c:	eb 54                	jmp    400f82 <rand@plt+0x682>
  400f2e:	83 f8 43             	cmp    eax,0x43
  400f31:	74 1a                	je     400f4d <rand@plt+0x64d>
  400f33:	83 f8 44             	cmp    eax,0x44
  400f36:	74 39                	je     400f71 <rand@plt+0x671>
  400f38:	eb 48                	jmp    400f82 <rand@plt+0x682>
  400f3a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
  400f3e:	48 05 d8 04 00 00    	add    rax,0x4d8
  400f44:	8b 10                	mov    edx,DWORD PTR [rax]
  400f46:	83 c2 01             	add    edx,0x1
  400f49:	89 10                	mov    DWORD PTR [rax],edx
  400f4b:	eb 34                	jmp    400f81 <rand@plt+0x681>
  400f4d:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
  400f51:	8b 00                	mov    eax,DWORD PTR [rax]
  400f53:	8d 50 01             	lea    edx,[rax+0x1]
  400f56:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
  400f5a:	89 10                	mov    DWORD PTR [rax],edx
  400f5c:	eb 23                	jmp    400f81 <rand@plt+0x681>
  400f5e:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
  400f62:	48 05 d8 04 00 00    	add    rax,0x4d8
  400f68:	8b 10                	mov    edx,DWORD PTR [rax]
  400f6a:	83 ea 01             	sub    edx,0x1
  400f6d:	89 10                	mov    DWORD PTR [rax],edx
  400f6f:	eb 10                	jmp    400f81 <rand@plt+0x681>
  400f71:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
  400f75:	8b 00                	mov    eax,DWORD PTR [rax]
  400f77:	8d 50 ff             	lea    edx,[rax-0x1]
  400f7a:	48 8b 45 e8          	mov    rax,QWORD PTR [rbp-0x18]
  400f7e:	89 10                	mov    DWORD PTR [rax],edx
  400f80:	90                   	nop
  400f81:	90                   	nop
  400f82:	5d                   	pop    rbp
  400f83:	c3                   	ret    
```

direction は `ABCD` のいずれかで、それぞれ上下右左を意味しています。これを元に 0x400eb1 でヘビを動かしているようです。`call 400eb1` を nop で潰すと、ヘビが動かなくなりました。

2 つのパッチをあてた状態でしばらく放置すると、フラグが表示されました。

```
SECU[hack_is_the_wine_of_life._Let's_drink_it.]
```