---
layout: post
title: SECCON 2017 x CEDEC CHALLENGE に参加しました
categories: [ctf, seccon]
date: 2017-09-08 15:00:00 +0900
---

チーム Harekaze で [SECCON 2017 x CEDEC CHALLENGE](https://2017.seccon.jp/news/seccon-2017-cedec-challenge.html) に参加し、優勝しました。

この記事では感想や発表資料の補足などについて書いていきたいと思います。

## SECCON 2017 x CEDEC CHALLENGE とは

まず SECCON 2017 x CEDEC CHALLENGE とはなんぞやということですが、これはゲームのクラッキングやチートを行い、その対策案を考えるという大会でした。

8/1 ~ 8/15 にかけて事前に予選が行われました。

この予選では 3 つのゲームが配布され、2 つは与えられた目標 (通常のプレイでは不可能なもの) を達成すること、1 つはセキュリティ上の問題点を探してその手法･影響度･対策案を調べることを目的に、最大 4 人のチームで調査を行い、その結果をプレゼンテーション資料としてまとめるという競技が行われました。

予選を勝ち抜いたチームは 9/1 の [CEDEC 2017 のセッション](http://cedec.cesa.or.jp/2017/session/ENG/s58d4fc6e62370/)で調査結果について発表するということで、Harekaze は 30 分ほどプレゼンを行いました。

ちなみに、今回予選で配布された問題は現在 [SECCON の公式サイト](https://2017.seccon.jp/news/seccon-2017-cedec-challenge.html)で公開されているので、興味のある方はぜひ挑戦してみてください。

## なぜ参加したか

いろいろ理由はあるのですが、私は特に

1. ゲームの解析に挑戦してみたかった
2. 調査を行ってプレゼン資料を作成するという競技の形式が面白そうだった
3. SECCON 2017 国内決勝大会の決勝進出権が欲しかった

といったことから参加を決めました。

## 発表資料

発表に用いた資料です。本編が約 90 ページ、おまけが約 30 ページです。

<script async class="speakerdeck-embed" data-id="5937a10051d14f66a4bdf00167fe6354" data-ratio="1.77777777777778" src="//speakerdeck.com/assets/embed.js"></script>

- [(要登録) SECCON 2017 x CEDEC CHALLENGE ゲームクラッキング＆チートチャレンジ](https://cedil.cesa.or.jp/cedil_sessions/view/1625)
- [SECCON 2017 × CEDEC CHALLENGE Harekaze // Speaker Deck](https://speakerdeck.com/harekaze/seccon-2017-x-cedec-challenge-harekaze)

## 発表資料の補足

大まかな内容は上記の発表資料に書いているので、この記事では発表資料には書かなかったことを補足として書いてみます。

### 通信の復号

ゲームサーバとの通信は SSL/TLS が利用されていたことから、[mitmproxy](https://mitmproxy.org/) を用いて復号を行いました。

ただし、通信は SSL/TLS の上に独自の暗号化が施されているため、このままではゲームサーバと何を通信しているか知ることができません。

まずどのような暗号化方式が使われているか調べるため、初回起動時の名前登録の通信をキャプチャしてみました。すると、`/2017/uuid` と以下のような通信を行っているのが確認できました。

```
(1 回目、名前は hirotasora)
Request: data=EFvo1xD5OLWuQbwCBsebTOolsz8f5AMiwdtTbFGNrv8=
Response: W8KR7sKvcgPdj3ysGPi5G6O8yrZZBOJiv0Cev0+wymIEu7+oPBW/G6GIv0AEwz2/fm5J/Ve3xAj6vj6YcdnsEECbjwGylC132mAr4xwFn54B9KxJrdyI1Q7pQ/QlG0lE

(2 回目、名前は hirotasora)
Request: data=EFvo1xD5OLWuQbwCBsebTOolsz8f5AMiwdtTbFGNrv8=
Response: W8KR7sKvcgPdj3ysGPi5G8Vd/MEzzFQW1uKgjVwWscvzyWJ5ucOE9kGN32A/M/Yf2UxgBJIKjJbWYic0Fq6CNARpUAN/A8gZQSQK+plet1TOtG6LlZ8JsEORBH0Apb4W

(3 回目、名前は hirotasoradayooo)
Request: data=EFvo1xD5OLWuQbwCBsebTKv09nPh5sk+jRboZJ017eM=
Response: W8KR7sKvcgPdj3ysGPi5G7ACRoBimDkOdAuKpNE9kTlA2L/ial1WxxjqRMEypt2yWLT9O1mQqnq8YB2gqvYHdqPGei69/F47rqZN5fCF+2E1QLCu1yicq/GNugxh52cZ

(4 回目、名前は hirotasoraaaaaaaaaaaaaaaaa)
Request: data=EFvo1xD5OLWuQbwCBsebTCI2jGWh/mYv16SbU5SwrFxd3wCrzD9cIlYZBlmEpoDx
Response: W8KR7sKvcgPdj3ysGPi5Gw+OvbVZL/dTliGe9A3Gf59Een0ZmkEvT6/yO77RsjKANcCZ6ZiZYzuwouIOemJowdpKYieBCbC4Nrj0HMlBIrEH6MTt+b4k/e29Ha4pf/xI
```

リクエストもレスポンスも Base64 エンコードが行われているようです。デコードするとリクエストのデータのサイズはそれぞれ 32, 32, 32, 48 になりました。16 バイト単位でサイズが変化していることから、`AES-CBC-128` のようなブロック暗号が用いられているのではないかと考えました。

鍵と IV はどのようにして設定しているのでしょうか。`/2017/uuid` に POST するより前にはゲームサーバとは通信を行っていないため、ゲームサーバから得ているのではなくクライアント側で保存されていそうです。

与えられた apk ファイルから何か情報が得られないか `assets/bin/Data/Managed/Metadata/global-metadata.dat` を strings にかけてみると以下のような文字列が見つかりました。

```
$ strings -a global-metadata.dat
...uuidTitleMenudef4ul7KeY1Z3456K33pK3y53cr3TYeaIVisNotSecret123game Key confusingCookieplainTextcipherTextcalcHmac...
```

IV は `IVisNotSecret123` でしょう。鍵はその前にある `def4ul7KeY1Z3456` `K33pK3y53cr3TYea` の 2 つが怪しそうです。

暗号化方式に `AES-CBC-128`、IV に `IVisNotSecret123`、鍵に `def4ul7KeY1Z3456` と `K33pK3y53cr3TYea` を xor した文字列を指定して 1 回目のリクエストとレスポンスを復号してみましょう。

```python
from Crypto.Cipher import AES

def xor(a, b):
  res = ''
  if len(a) < len(b):
    a, b = b, a
  for k, c in enumerate(a):
    res += chr(ord(c) ^ ord(b[k % len(b)]))
  return res

KEY = xor('def4ul7KeY1Z3456', 'K33pK3y53cr3TYea')
IV = 'IVisNotSecret123'

def decrypt(msg):
  cipher = AES.new(KEY, AES.MODE_CBC, IV=IV)
  return cipher.decrypt(msg)

request = 'EFvo1xD5OLWuQbwCBsebTOolsz8f5AMiwdtTbFGNrv8='
response = 'W8KR7sKvcgPdj3ysGPi5G6O8yrZZBOJiv0Cev0+wymIEu7+oPBW/G6GIv0AEwz2/fm5J/Ve3xAj6vj6YcdnsEECbjwGylC132mAr4xwFn54B9KxJrdyI1Q7pQ/QlG0lE'

print repr(decrypt(request.decode('base64')))
print repr(decrypt(response.decode('base64')))
```

```
$ python2 decrypt.py
Request: '{"name":"hirotasora"}\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
Response: '{"metadata": {"uuid": "1d372414d86e59ea1935518e8868b62b", "iv": "SCCdoLiO6Q5IuHif"}}\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
```

入力した名前を POST し、UUID が返ってきている様子が確認できました。

### 通信の復号を自動化

mitmproxy には便利なことに[スクリプティング機能](http://docs.mitmproxy.org/en/stable/scripting/overview.html)が存在します。

手作業でいちいち復号するのは面倒なので、この機能を使って自動で通信を復号してくれるスクリプトを書きましょう。以下のスクリプトを `mitmproxy_decrypt.py` として保存し、`mitmdump -s mitmproxy_decrypt.py` を実行すると復号された通信が出力されるようになります。

```python
import hashlib
import json
import sys

from mitmproxy import ctx
from Crypto.Cipher import AES

def xor(a, b):
  res = ''
  if len(a) < len(b):
    a, b = b, a
  for k, c in enumerate(a):
    res += chr(ord(c) ^ ord(b[k % len(b)]))
  return res

def unpad(msg):
  return msg[:-ord(msg[-1])]

def decrypt(key, iv, c):
  s = AES.new(key, AES.MODE_CBC, IV=iv).decrypt(c)
  return json.loads(unpad(s))

KEY_A = 'def4ul7KeY1Z3456'
KEY_B = 'K33pK3y53cr3TYea'
KEY = xor(KEY_A, KEY_B)
IV = 'IVisNotSecret123'

key, iv = KEY, IV

def request(flow):
  global key, iv
  if flow.request.path in ('/2017/key', '/2017/uuid'):
    key, iv = KEY, IV
  if flow.request.urlencoded_form:
    data = flow.request.urlencoded_form['data'].decode('base64')
    data = decrypt(key, iv, data)
    ctx.log.info('>%s: %s' % (flow.request.path, data))

def response(flow):
  global key, iv
  data = flow.response.get_content()
  if data:
    data = decrypt(key, iv, data.decode('base64'))
    if 'metadata' in data:
      metadata = data['metadata']
      if 'key' in metadata:
        key = metadata['key']
      if 'iv' in metadata:
        iv = metadata['iv']
    ctx.log.info('<%s: %s' % (flow.request.path, data))
```

```
$ mitmdump -s mitmproxy_decrypt.py
...
>/2017/key: {u'uuid': u'1d372414d86e59ea1935518e8868b62b'}
</2017/key: {u'metadata': {u'uuid': u'1d372414d86e59ea1935518e8868b62b', u'key': u'QyqxE262qG944kpX', u'iv': u'VEgFY2qx9GsIyJ0J'}}
192.168.11.4:50594: POST https://cedec.seccon.jp/2017/key
                 << 200 OK 168b
...
```

### 通信の偽造

ゲームサーバへのリクエスト時には常に `X-Signature` ヘッダが付与されています。名前からしてリクエストボディの内容の検証に使っていそうですが、どのようにして計算しているのでしょうか。

`/2017/uuid` との通信を観察してみると、以下のように `X-Signature` ヘッダの値が集められました。

```
(1 回目、名前は hirotasora)
X-Signature: 111d7cf2cd5dac5d0f23abd89ae4dc969c2eb4eb621447e81bfd9d9fb0dfc295

(2 回目、名前は hirotasora)
X-Signature: 111d7cf2cd5dac5d0f23abd89ae4dc969c2eb4eb621447e81bfd9d9fb0dfc295

(3 回目、名前は hirotasoraaaaaaaaaaaaaaaaa)
X-Signature: c1d3bf8c5d5c98c545681f36ec75e015d796fd5558cb1a47493504e9ed9e2eec
```

サイズは 32 バイトで固定されているようです。このことから、`HMAC-SHA256` が用いられているのではと考えました。

HMAC の秘密鍵には何が使われているのでしょうか。`assets/bin/Data/Managed/Metadata/global-metadata.dat` を見ると `calcHmac` という文字列が含まれているのが分かります。

ハッシュ関数に `SHA-256`、秘密鍵に `calcHmac` を指定して 1 回目のリクエストボディの HMAC を計算してみましょう。

```python
import hashlib
import hmac

HMAC_KEY = 'calcHmac'
def calc_hmac(msg):
  return hmac.new(HMAC_KEY, msg, hashlib.sha256).hexdigest()

request = '{"name":"hirotasora"}'
print repr(calc_hmac(request))
```

```
$ python2 calc_hmac.py
'c1d3bf8c5d5c98c545681f36ec75e015d796fd5558cb1a47493504e9ed9e2eec'
```

正規のリクエストに付与されている `X-Signature` ヘッダの値と同じ値になりました。

### 通信の解析

スクリプトを使いながら通信を観察すると、以下のような解析結果が得られました。

#### 基本

- 暗号化の方式は AES-CBC-128 でパディングは PKCS#7
- 初期状態は鍵が `xor('def4ul7KeY1Z3456', 'K33pK3y53cr3TYea')` 、IV が `IVisNotSecret123`
- `X-Signature` というヘッダでリクエストボディを検証
   - 方式は HMAC-SHA256 で秘密鍵は `calcHmac`
- リクエストごとに変わる `token` という Cookie が存在
   - 例: `token="!ROem1XSLfsXkWB6Y6Gw2zA==?gAJVBXRva2VucQFVIEVNTFBPNkxvbzJ6dG12enVaMzBaT0NKRUdickNCR1NncQKGcQMu"`

#### 初回起動時の通信の流れ (リクエスト･レスポンスは暗号化されている)

- `/2017/uuid` に対して `{"name":"(入力した名前)"}` を POST
   - `{"metadata": {"uuid": "(発行されたUUID)", "iv": "(次のIV)"}}` がレスポンスで返ってくる
- `/2017/key` に対して `{"uuid":"(UUID)"}` を POST
   - `{"metadata": {"uuid": "(UUID)", "key": "(次の鍵)", "iv": "(次の IV)"}}` がレスポンスで返ってくる

#### 2 回目以降の起動時の通信の流れ

- `/2017/key` に対して *初期状態の鍵とIVで* `{"uuid":"(UUID)"}` を POST
   - `{"metadata": {"uuid": "(UUID)", "key": "(次の鍵)", "iv": "(次の IV)"}}` がレスポンスで返ってくる
- (画面をタップ)
- `/2017/key` に対して *初期状態の鍵とIVで* `{"uuid":"(UUID)"}` を POST
- `/2017/skill` に対して GET
   - `{"skills": [], "metadata": {"uuid": "(UUID)", "iv": "(次の IV)"}}` がレスポンスで返ってくる
- `/2017/account` に対して GET
   - `{"userData": {"stone": (ダイヤ石の個数), "coin": (コインの枚数), "uuid": "(UUID)", "exp": (経験値), "maxStamina": (スタミナの最大値), "availableMusic": 1, "rank": (プレイヤーのランク), "name": "(ユーザ名)"}, "metadata": {"uuid": "(UUID)", "key": "(次の鍵)", "iv": "(次の IV)"}}` がレスポンスで返ってくる
- `/2017/key` に対して *初期状態の鍵とIVで* `{"uuid":"(UUID)"}` を POST
- `/2017/skill` に対して GET
- `/2017/account` に対して GET

#### Skill をタップ

- `/2017/skill` に対して GET

#### 1 Shot Gacha をタップ

- `/2017/gacha` に対して `{"gacha":1}` を POST
   - `{"skills": [{"param": (スキルの値), "id": (スキルの ID), "skillType": (スキルのタイプ), "name": "(スキルの名前)"}], "metadata": {"uuid": "(UUID)", "iv": "(次のIV)"}}` がレスポンスで返ってくる

#### 5 Shot Gacha をタップ

- `/2017/gacha` に対して `{"gacha":5}` を POST
   - `{"skills": [({"param": (スキルの値), "id": (スキルの ID), "skillType": (スキルのタイプ), "name": "(スキルの名前)"} が 5 つ)], "metadata": {"uuid": "(UUID)", "iv": "(次の IV)"}}` がレスポンスで返ってくる

#### ダイヤ石をタップしてスタミナを回復

- `/2017/useItem` に対して `{"item":"stone"}` を POST
   - `{"status": "ok", "metadata": {"uuid": "(UUID)", "iv": "(次の IV)"}}` がレスポンスで返ってくる

#### コインをタップしてスタミナを回復

- `/2017/useItem` に対して `{"item":"coin"}` を POST
   - `{"status": "ok", "metadata": {"uuid": "(UUID)", "iv": "(次の IV)"}}` がレスポンスで返ってくる

#### リザルト画面

- `/2017/score` に対して `{"myScore":{"musicId":(楽曲の ID),"difficulty":(難易度),"score":(スコア),"name":"","uuid":"(UUID)"}}` を POST
   - `{"gameScores": [{"score": (スコア), "name": "(ユーザ名)"}], "metadata": {"uuid": "(UUID)", "iv": "(次の IV)"}}` がレスポンスで返ってくる

## スクリプト

- [SECCON 2017 × CEDEC CHALLENGE - 通信の復号を行うスクリプト](https://gist.github.com/st98/e6f17c9fd574ff264a8173d4b651767a)
- [SECCON 2017 × CEDEC CHALLENGE - ガチャ](https://gist.github.com/st98/436a4972a36a811164bbf75127efde49)
- [SECCON 2017 × CEDEC CHALLENGE - スコアのチート 1](https://gist.github.com/st98/b340b5bc84415597687d9cae42b15d1b)
- [SECCON 2017 × CEDEC CHALLENGE - スコアのチート 2](https://gist.github.com/st98/1e6a3963e5122f715fbba75b746b6607)
- [SECCON 2017 × CEDEC CHALLENGE - リセマラ](https://gist.github.com/st98/c94395f3328f2d396a41349f96fe9659)

## デモ動画

- [[SECCON 2017 × CEDEC CHALLENGE] Climb up - 変更前](https://youtu.be/aN0L2ZEozz4)
- [[SECCON 2017 × CEDEC CHALLENGE] Climb up - 変更後](https://youtu.be/Ee0cdNQfwQg)
- [[SECCON 2017 × CEDEC CHALLENGE] CHUNI MUSIC - 通信の復号](https://youtu.be/PGL6lmuB7DI)
- [[SECCON 2017 × CEDEC CHALLENGE] CHUNI MUSIC - HPが減らないapk](https://youtu.be/zxfDEeKmNPI)

## 感想

私はゲームの解析も資料の作成も発表もあまり経験がなく、競技中は不安でいっぱいでしたが、優勝という結果を残すことができ大変嬉しい思いです。SECCON 2017 国内決勝大会でも頑張ります💪

チームメンバー、運営の皆様、セッションにお越し頂いた皆様ありがとうございました。
