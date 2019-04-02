---
layout: post
title: VolgaCTF 2019 Qualifier の write-up
categories: [ctf]
date: 2019-04-02 16:20:00 +0900
---

3 月 30 日から 4 月 1 日にかけて開催された [VolgaCTF 2019 Qualifier](https://q.2019.volgactf.ru/) に、チーム Harekaze で参加しました。最終的にチームで 900 点を獲得し、順位は得点 414 チーム中 64 位でした。うち、私は 3 問を解いて 350 点を入れました。

以下、私が解いた問題の write-up です。

## Crypto
### Shadow Cat (100)
> We only know that one used /etc/shadow file to encrypt important message for us.
> 添付ファイル: shadow.txt, encrypted.txt

添付ファイルはそれぞれ以下のような内容でした。

`shadow.txt`

```
︙
z:$6$AEqLtEqq$1ojEoCgug5dzqeNfjGNE9p5SZFwIul8uOFp9vMZEz50oiUXOVFW3lw1S0fuvFY5ggi5CfbfoWaMDr2bvtSNRC/:17930:0:99999:7:::
a:$6$9Eg69bYI$q75YWUVWb4MYzkcExXukpt.VJ3fX458iZJm1ygpTLwX.CgroHpmeSG88By.zQmKyOHCvBHoA0Q001aBqbkVpg/:17930:0:99999:7:::
x:$6$5TF0Txe3$APSNzUSjFmMbsmrkCS9qE84qfu4AI2dNEjqm2PRKgSjncBTI4lECXofQ8abdAtYX6tST6FGCgOdvLlDYQTCJx0:17930:0:99999:7:::
q:$6$I3iqZL0m$nxHWvcLz7lg/ZKoKfX9dq5k0uqkOtKgLdyREAQxQkfPkVvbNHPfQaoCFfnXl1BoX1vgOcEDghVPvfRUrs6dGp1:17930:0:99999:7:::
l:$6$n8iJWaW/$M1Od8seiEL6h3L.egHubBYAk.cd8/LUctESIm69/r.gvP0eqabusN5/D1rNu1qDHOkgRpHf8PWGSb8zoxrgrp1:17930:0:99999:7:::
v:$6$GatagTHS$I1UfNfn3NGP5Vre0z7s3DGqFpjN5Pw2XhAHSw6ZSMwaMAsf8IteFedXovNlHLuIXvR9ezeya89XEOq2We7CcW1:17930:0:99999:7:::
e:$6$ZO6YiExi$7DBV0zMIqf8iy.zVTL7gbHetCmJ3LL4ROEYG/UME4Tmym82vZYkFWjiNpCGapvF83QNJKFJOjkhXMgFLfkhza.:17930:0:99999:7:::
f:$6$HXoF2OZ1$onkVfp52IRdd2OipQv3rPPsGr7QradAFTFnmXv5c9xkGy4xcgJFkoaSJzMQCtfWuU2FQ3BN3lyL47SyoIoPmy0:17930:0:99999:7:::
b:$6$I9Uq9PRG$euVEYx5TR2lUFe/k7s0e8us8xgl7j/cbiYRnvba.eFfMSSPsm5I.gcShqOLqAa58m5VISomkPpHlJ1xLgCRxw/:17930:0:99999:7:::
r:$6$J.qms5y0$YOMnlR0V.WQjqAyik3nU7TDdy8hZQZWfhF8CTJHJtd/0mrANrxBvULoXNiJnvX.yn5T3QBFu4wk3xrFye.uus1:17930:0:99999:7:::
g:$6$b4GkIuzQ$j/prK.Jy304eu6W/NG0Yz4mHDOc3BavkYRBomdjVG.fAksRM/xIDRoWcKcJw66YZmVGcV51YkIwVZHVfA//KU.:17930:0:99999:7:::
n:$6$f2QD.cIu$n70jbCSe0QVz7M48SVE2Z..IPDV0QjIfZ8D40oQOO9smt0ZeA2I0sSO927VIr1SJwupjZairVR0T/pKQ0QG3N1:17930:0:99999:7:::
o:$6$qyBGOX79$OAvGVjmH69C.0ZfObcJ0DcKzoSWHhBBt9sPVjbIJtYmT4nV/TU/zCiKgCkSQaQJ.n.vTjAScdh9htzjBzTwOT/:17930:0:99999:7:::
p:$6$EW1gOlyH$omuxKElrI3DeVoxrLet3OW3MfuFPwLwefVxOr62E.wo7szQ6.swTec1edCFiKnPc42XxMRGsrNJn36mkc2dgH/:17930:0:99999:7:::
s:$6$TXxh4vV5$v1vF49YZQnonSZrKwBWNp7rpxIRoQY/ooEODqjsdwwdoY8sso.y/EOsoC3GFlpCLYnEY./n/1BuNID5njg0CV.:17930:0:99999:7:::
c:$6$IYxRoIyR$eEmGTNPNd6HPQibc/UBdQ5zgR/dGQ1dtCuSl0lUmvmbrSKbYEf/SEDlX4fgP.JQXlyFqEgu4NOBiu2eozpAM.0:17930:0:99999:7:::
w:$6$RmCyBroe$EovezmWQJVvQFGd6.ei2.SfzGJG22CsV47tTnyfKx30TbuG1VMgsk0de6NOQ04bKNML9fbuMu0Pw3TMf82zye1:17930:0:99999:7:::
d:$6$..CK41Sn$36X19X0jrviLxVVk.KtR9zbHMML0mg1XzMNQgP7eOpGMF1JYSbZHAyReDhNVkm1WaNn3lfO2CsAww14fZZads1:17930:0:99999:7:::
t:$6$zVFV5HoW$q9WyP6/D0kPL.n7s.FvPcOSRfvcUFQu5QMPps6VbQUD5RMozQsP14GtUiOa/H2V2pU6c6OxcgRqruaLejPaES1:17930:0:99999:7:::
h:$6$S1RnJ8DK$F/FWFf9En/mn6YqZ67/gOnMT0WdSuaEyn2OArTJbG1IGHd0pUs9TiGDE9P.PhRB6XyHUgA5l/LBmBW8PpJg9M.:17930:0:99999:7:::
m:$6$SqkKQRak$nZHDrq3vdnajdLzotrW3J9kYzUvzPaUrs6NZaKkkcVN0KiCfUhJfgM6WJvZjZR7hBGWkfIwhZymko7wtsq49s1:17930:0:99999:7:::
k:$6$ZLCr2itT$tZ0.u7TsXPc3nAntIOepETGkhqfVG1IKaiuW0mAH5QROVuc7fonE43qEhUFT2LHMftYDdTQRAMHpRNMM8Yn1c1:17930:0:99999:7:::
i:$6$ZlWmheB2$DBLJQPLVhhEdA/iATrOYiqFv4i5TcmBUSX6.tZDo63YP4dcdlAuBnFU65xXIRP1tpNsCS7kc6Fu6jPMS2F7aP1:17930:0:99999:7:::
y:$6$rIoO6U2u$c5usMXbFP9S75qmDyBBWz1QZuyGH0MGq3mXN32kYipoL5XCFEHjmTRVcuZkmed5OzAopV0CgyA49QzILz5Rmq/:17930:0:99999:7:::
j:$6$Gpavrajq$me1yxZQ0OiJFedrTmxFsyP5zwOePuFJmgujUWun0h5bCOIVeuJuaIUTDHGCYxkT6mw41BTjlx9c3QvdsG8o0o.:17930:0:99999:7:::
u:$6$0w3EeszD$bUDQorjCKku1sjtCWMQfJ3ZRmsC5N.LN7CQnjvyCbcq5wSD33x2t/TVXA6jnjtajv8nIZc.Aj.oY80lm44Dhy0:17930:0:99999:7:::
underscore:$6$RVUCQJFr$fsKkPUT9Pp5QlsZblSLJ4yKkfBxNMWN0TS.q7ticuEr/HQFdEbyiwK5JmaKKS9UDFzUsY6mhe1knnRbwy7K0s/:17930:0:99999:7:::
```

`encrypted.txt`

```
hajjzvajvzqyaqbendzvajvqauzarlapjzrkybjzenzuvczjvastlj
```

`shadow.txt` はおそらく `/etc/shadow` と同じ形式のテキストファイルでしょう。[John the Ripper](https://www.openwall.com/john/) を使って暗号化されたパスワードをクラックし、`encrypted.txt` について 1 文字ずつ、その文字と対応するユーザのパスワードに置換してみましょう。

```
$ python -c "open('wordlist', 'wb').write('\n'.join(chr(c) for c in range(0x20, 0x7f)))"
$ john --wordlist=./wordlist shadow.txt
Warning: detected hash type "sha512crypt", but the string is also recognized as "crypt"
Use the "--format=crypt" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 28 password hashes with 28 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
No password hashes left to crack (see FAQ)
$ john --show shadow.txt 
jr:1:17792:0:99999:7:::
z:_:17930:0:99999:7:::
a:a:17930:0:99999:7:::
x:b:17930:0:99999:7:::
q:c:17930:0:99999:7:::
l:w:17930:0:99999:7:::
v:h:17930:0:99999:7:::
e:i:17930:0:99999:7:::
f:j:17930:0:99999:7:::
b:k:17930:0:99999:7:::
r:l:17930:0:99999:7:::
g:m:17930:0:99999:7:::
n:n:17930:0:99999:7:::
o:x:17930:0:99999:7:::
p:y:17930:0:99999:7:::
s:d:17930:0:99999:7:::
c:e:17930:0:99999:7:::
w:f:17930:0:99999:7:::
d:g:17930:0:99999:7:::
t:o:17930:0:99999:7:::
h:p:17930:0:99999:7:::
m:q:17930:0:99999:7:::
k:u:17930:0:99999:7:::
i:v:17930:0:99999:7:::
y:r:17930:0:99999:7:::
j:s:17930:0:99999:7:::
u:t:17930:0:99999:7:::
underscore:z:17930:0:99999:7:::
28 password hashes cracked, 0 left
```

```javascript
const t = `z:_:17930:0:99999:7:::
a:a:17930:0:99999:7:::
x:b:17930:0:99999:7:::
q:c:17930:0:99999:7:::
l:w:17930:0:99999:7:::
v:h:17930:0:99999:7:::
e:i:17930:0:99999:7:::
f:j:17930:0:99999:7:::
b:k:17930:0:99999:7:::
r:l:17930:0:99999:7:::
g:m:17930:0:99999:7:::
n:n:17930:0:99999:7:::
o:x:17930:0:99999:7:::
p:y:17930:0:99999:7:::
s:d:17930:0:99999:7:::
c:e:17930:0:99999:7:::
w:f:17930:0:99999:7:::
d:g:17930:0:99999:7:::
t:o:17930:0:99999:7:::
h:p:17930:0:99999:7:::
m:q:17930:0:99999:7:::
k:u:17930:0:99999:7:::
i:v:17930:0:99999:7:::
y:r:17930:0:99999:7:::
j:s:17930:0:99999:7:::
u:t:17930:0:99999:7:::
_:z:17930:0:99999:7:::
jr:1:17792:0:99999:7:::`
const table = t.split('\n').reduce((p, c) => { let x = c.split(':'); p[x[0]] = x[1]; return p; }, {});
const enc = 'hajjzvajvzqyaqbendzvajvqauzarlapjzrkybjzenzuvczjvastlj';
console.log(enc.replace(/./g, c => table[c])); // => pass_hash_cracking_hashcat_always_lurks_in_the_shadows
```

フラグが得られました。

```
VolgaCTF{pass_hash_cracking_hashcat_always_lurks_in_the_shadows}
```

## Web
### Shop (100)
> Our famous shop is back!
> http://shop.q.2019.volgactf.ru/

与えられた URL にアクセスすると商品の一覧が表示されました。適当な名前でユーザ登録を行いログインしてみると、どうやら `$100` の残高があるようでした。しかし、フラグの価格は `$1,337` であり全然足りません。

他のユーザに送金できず、また一度商品を購入すると返品も売却もできないため、例えばユーザを大量に作ってひとつのユーザに送金しまくるとか、レースコンディションを起こしてタダで商品を購入するといったことはできそうにありません。

いろいろ試していると、`/profile` (購入済みの商品の一覧ページ) で `?name=hoge` のように GET パラメータを与えると、`Username: hoge` のように出力される HTML が変わることが確認できました。残高もこの方法で操作できるのではないかと思い、商品購入時に POST される先の `/buy` を `/buy?Balance=1000000` に書き換えるとフラグを購入することができました。

```
VolgaCTF{c6bc0c68f0d0dac189aa9031f8607dba}
```

## Stego
### JOI (150)
> All we have is just one image
> 添付ファイル: result.png

与えられた画像は QR コードのようですが、普通に読み取ってもフラグっぽくない文字列が出力されます。

```
>zbarimg result.png
QR-Code:C_F(n1, n2) = 14 * [C(n1,n2) / 14] + 7 * FLAG(n1,n2) + (C(n1,n2) mod 7)
scanned 1 barcode symbols from 1 images
```

stegsolve.jar を使って青の LSB を抽出し、これを読み取るとフラグが得られました。

```
>zbarimg b0.png
QR-Code:VolgaCTF{5t3g0_m4tr3shk4_in_4cti0n}
scanned 1 barcode symbols from 1 images
```

```
VolgaCTF{5t3g0_m4tr3shk4_in_4cti0n}
```