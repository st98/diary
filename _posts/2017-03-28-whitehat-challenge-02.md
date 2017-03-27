---
layout: post
title: WhiteHat Challenge 02 の write-up
categories: [ctf]
date: 2017-03-28 02:04:02 +0900
---

チーム Harekaze で [WhiteHat Challenge 02](https://wargame.whitehat.vn/Contests/ChallengesContest/34) に参加しました。最終的にチームで 175 点を獲得し、順位は 6 位 (得点 81 チーム中) でした。うち、私は 9 問を解いて 160 点を入れました。

以下、解いた問題の write-up です。

## [Cryptography 20] Crypto001

RSA のようです。p と q をどうやって生成しているか見てみると、

```python
random_seed = urandom(128)

num = bytes_to_num(random_seed)
print num
# get 2 first prime number from random_seed
p, q = 0,0
while True:
    if is_prime(num):
        p = num
        break
    num+=1

while True:
    if is_prime(num):
        q = num
        break
    num+=1
```

Fermat 法で素因数分解すると簡単に p と q を得ることができました。これを使って暗号文を復号すると `flag is close_primes_is_bad` という文字列が得られました。

```
WhiteHat{0732e65c5c2769ffb5ea0e408f1bf13ae6288767}
```

## [Forensics 15] For001

アクセスログが与えられるので、それを解析して攻撃者の IP アドレスとリクエストの回数を答えろという問題でした。

適当に解析すると攻撃者の IP アドレスは `192.168.1.1`、リクエストの回数は `grep "192.168.1.1 - -" access.log | wc -l` で数えると 41326 回であると分かります。

```
WhiteHat{72f88f73b399453997d84d328edb9d8333e4f0f6}
```

## [Forensics  15] For002

pcapng ファイルが与えられます。pcap に変換して NetworkMiner に投げると、`Flag.zip` と `Secret.docx.vnd.openxmlformats-officedocument.wordprocessingml.document` が抽出できました。

`Flag.zip` は暗号化されているようです。`Secret.docx.(略)` を見ると白文字で `Pass: md5{G00dm4n}` とありました。`G00dm4n` を md5 でハッシュ化した値をパスワードとして入力すると `Flag.zip` を展開できました。

`Flag.zip` を展開して出てきた `goku.jpg` を strings にかけると `The flag is : Simple_Network_Forensic` という文字列が得られました。

```
WhiteHat{5fa814b2e92ea59d24e60b2728c5485e511b1147}
```

## [Web Security 15] Web001

与えられた URL にアクセスすると、難読化された JavaScript のコードが動いていました。

まず `eval = console.log.bind(console)` して `sayHello()` すると

```javascript
var enco='';
var enco2=126;
var enco3=33;
var ck=document.URL.substr(document.URL.indexOf('='));


for(i=1;i<122;i++)
{
enco=enco+String.fromCharCode(i,0);
}

function enco_(x)
{
return enco.charCodeAt(x);
}

if(ck=="="+String.fromCharCode(enco_(240))+String.fromCharCode(enco_(220))+String.fromCharCode(enco_(232))+String.fromCharCode(enco_(192))+String.fromCharCode(enco_(226))+String.fromCharCode(enco_(200))+String.fromCharCode(enco_(204))+String.fromCharCode(enco_(222-2))+String.fromCharCode(enco_(198))+"~~~~~~"+String.fromCharCode(enco2)+String.fromCharCode(enco3))
{
alert("Password is "+ck.replace("=",""));
}
```

というコードが得られました。

あとは適当に if まで実行して `String.fromCharCode(enco_(240))+String.fromCharCode(enco_(220))+String.fromCharCode(enco_(232))+String.fromCharCode(enco_(192))+String.fromCharCode(enco_(226))+String.fromCharCode(enco_(200))+String.fromCharCode(enco_(204))+String.fromCharCode(enco_(222-2))+String.fromCharCode(enco_(198))+"~~~~~~"+String.fromCharCode(enco2)+String.fromCharCode(enco3)` を実行すると `youaregod~~~~~~~!` という文字列が得られました。

```
WhiteHat{1c0e74d5f61b6c3901a277bdd490ad070265f027}
```

## [Web Security 20] Web002

`/?type=(ディレクトリ名、もしくはファイル名)` という感じでアクセスすると、もし type がディレクトリ名ならそのディレクトリのファイルとディレクトリの一覧を、ファイル名であればそのファイルを出力する Web サービスが動いていました。

`Web` と `Web/` は同じ出力でした。`.` と `./` の場合、前者はファイルとディレクトリの一覧を出力しましたが、後者は何も出力されませんでした。type に `./` が含まれていた場合は必ず何も出力されないようになっているようです。

`%252e` を試してみるとこれは回避できました。`%252e%252e/%252e%252e` で `forums/CTF/../../4HTzx6PGhDD` というディレクトリがあるのが分かります。`%252e%252e/%252e%252e/4HTzx6PGhDD` で `forums/CTF/../../4HTzx6PGhDD/passwd` というファイルがあるのが分かります。

あとは `%252e%252e/%252e%252e/4HTzx6PGhDD/passwd` で `Dot-Dot-Slash` と出力されました。

```
WhiteHat{7c412ca7ba95ecd156cd6782ff8f9d5479f0d483}
```

## [Pwnable 20] Pwn001

x86 の ELF が渡されます。3 秒 sleep した後、`srand(time(NULL))` して 3 回 `rand()%100+1` の結果とユーザ入力が一致すればフラグが表示されるという感じでした。

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main(void) {
  int i;
  srand(time(NULL) + 4);
  for (i = 0; i < 3; i++) {
    printf("%d\n", rand()%100+1);
  }
  return 0;
}
```

で当てにいきましょう。

```
$ gcc a.c -o a
$ ./a | nc 103.237.98.32 25032
-------- Guessing Game --------
You must guess 3 random number in range 1-100 to win the game!
Let's start...
Round 1: Round 2: Round 3: Congrast! You win the game Unbelievable!You_are_very_lucky
```

```
WhiteHat{7c952a8d157bbeb44dcc7ab9d9c6ba78e40b96bd}
```

## [Reverse Engineering 20] Re001

x86 の ELF が渡されます。適当に解析するとこんな感じになりました。

```c
int main(int argc, char **argv) {
  int fd;
  char *tp1, *tp2;
  long long a, b;
  char user_input[101], flag[501];
  if (argc != 2) {
    printf("Usage: %s gift_path", argv[0]);
    exit(1);
  }
  fd = open(argv[1], O_RDONLY);
  if (fd == -1) {
    perror("Error: ");
    exit(1);
  }
  memset(flag, 0, 501);
  read(fd, flag, 500);
  printf("Input your license key: ");
  scanf("%100s", user_input);
  if ((tp1 = strtok(user_input, "-")) == 0) {
    puts("Invalid key!");
    exit(1);
  }
  if ((tp2 = strtok(NULL, "-")) == 0) {
    puts("Invalid key!");
    exit(1);
  }
  a = strtoll(tp1, NULL, 0x10);
  b = strtoll(tp2, NULL, 0x10);
  if (a * b == 0xde0b6b76110a03fll) {
    puts("Activated!");
    printf("I give you a gift: %s\n", flag);
  } else {
    puts("Invalid key!");
  }
  return 0;
}
```

0xde0b6b76110a03f を素因数分解すると `1000000007*1000000009` であると分かりました。あとは `3b9aca07-3b9aca09` を投げると `I give you a gift: Difficulty of factoring a large integer yields good cryptosystems` と出力されました。

```
WhiteHat{361bfaa8736262a6a50dcd6e8c32b3c72a5784f3}
```

## [Reverse Engineering 15] Re002

`crack_me.exe` というファイルが与えられます。strcmp にブレークポイントを張って実行すると `1801351-0x123456789` と入力を比較していると分かります。

```
WhiteHat{60cb0bb662b61c6efa58650e5b5df7689c04cbb4}
```

## [Reverse Engineering 20] Re003

Python のバイトコードを逆アセンブルした結果が与えられました。

手でデコンパイルすると

```python
def f():
  n = 50
  tmp_list = [True] * n
  for i in xrange(3, int(n ** 0.5) + 1, 2):
    if tmp_list[i]:
      tmp_list[i * i::2 * i] = [False] * ((n - i * i - 1) / (2 * i) + 1) # TODO
  list = [2] + [i for i in xrange(3, n, 2) if tmp_list[i]] # TODO
  challenge = ['t', 'w', 'o', 'd', 'u', 'e', 't', '_', 'q', 'k', 'j', 'h', 'z', 'u', 'v', 'c', 'l', 'h', 'z', 'e', 'w', 'y', 'h', 'z', 'g', 'c', 'n', 'i', 'o', '_', 'p', 'b', 'i', 'r', 'd', 'v', 'd', 'y', 'y', 'q', 'o', 't', 'p', 'e', 'q', 'n', 'r', 'c', 'u', 'q']
  flag = raw_input('Give me your flag: ')
  flag = flag[-7:] + flag[:-7]
  location = 0
  tmp_str = ''
  for item in list:
    tmp_str += challenge[item]
  if tmp_str == flag:
    print 'Congratulation! Submit your flag'
  else:
    print 'Try your best, the rest will come'
```

という感じになりました。あとは `return tmp_str` を最後に付け足して `f()` すると `ez_bytecode_huh` という文字列が得られました。

```
WhiteHat{bd3dca037ff089cf77aa0ee09603357414ad72e3}
```

## 感想

全完でした。

Python のバイトコードは今までまともに読んだことがなかったのですが、結構読みやすいですね。
