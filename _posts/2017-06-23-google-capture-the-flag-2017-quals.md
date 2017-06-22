---
layout: post
title: Google Capture The Flag 2017 (Quals) の write-up
categories: [ctf]
date: 2017-06-23 04:03:00 +0900
---

チーム Harekaze で [Google Capture The Flag 2017 (Quals)](https://capturetheflag.withgoogle.com/) に参加しました。最終的にチームで 790 点を獲得し、順位は得点 1977 チーム中 69 位でした。うち、私は 2 問を解いて 365 点を入れました。

以下、解いた問題の write-up です。

## [Miscellaneous 178] Secret Notes

> YASCNSS (Yet another secure cloud notes storage solution).
> Hint: pyc
> Challenge running at https://notes-server-m8tv5txzzohwiznk.web.ctfcompetition.com/
> - NotesApp.apk

Notes.App.apk とサーバの URL が与えられました。

サーバの方を調べていきましょう。与えられた URL にアクセスすると、ユーザ名のみが入力できる登録フォームが表示されました。

適当なユーザ名 (`tekitou_na_username`) で登録すると、以下のようにアクセストークンが表示されました。

```
Your access token is 74656b69746f755f6e615f757365726e616d65-5b43ab349ad1ee01
```

ハイフンより前が hex エンコードされたユーザ名、ハイフンより後ろがアクセストークンのようです。

このアクセストークンは Cookie の auth にもセットされており、この状態で `/private` にアクセスすると空のファイルが降ってきました。

Cookie のアクセストークンを適当に変えて `/private` にアクセスすると `Bad Authentication` と表示されました。

レスポンスヘッダを見てみると `x-served-by:index.py` というヘッダが付与されています。ヒントから /index.pyc にアクセスすると、pyc ファイルが降ってきました。これをデコンパイルすると以下のようになりました。

```python
import os
import re
import sys
from hasher import ZXHash
import webapp2
import logging
import secrets
from google.appengine.ext import ndb
hexre = re.compile('^[a-fA-F0-9]+$')
pathre = re.compile('^[\\w_\\-/\\.]+$')

...

class Utils(object):

...

    @staticmethod
    def get_user(headers, hasher):
        results = Utils.parse_urlform(headers['cookie'])
        try:
            if results['auth']:
                user, hmac = results['auth'].split('-')
                if hexre.match(user) and hexre.match(hmac) and hasher.hash(user.strip()) == hmac.strip():
                    return (user.strip(), hmac.strip())
        except:
            pass

        return (None, None)

...

class PrivateNoteHandler(webapp2.RequestHandler):

    def get(self):
        user, _ = Utils.get_user(self.request.headers, hasher)
        if user:
            note = PrivateNote.get_by_id(user)
            if note:
                return Utils.reply(self.response, 200, note.content, 'application/octet-stream')
            else:
                return Utils.reply(self.response, 404, 'File Not Found')
        return Utils.reply(self.response, 401, 'Bad Authentication')

    def post(self):
        user, _ = Utils.get_user(self.request.headers, hasher)
        if user:
            if user in locked:
                return Utils.reply(self.response, 403, 'User is Locked')
            note = PrivateNote.get_by_id(user)
            if not note:
                note = PrivateNote(id=user)
            note.content = self.request.body
            note.put()
            return Utils.reply(self.response, 200, 'Success')
        return Utils.reply(self.response, 401, 'Bad Authentication')

key1, key2, db = secrets.get()
locked_id = '436f7267316c3076657239393c332121'
locked = list()
locked.append(locked_id)
hasher = ZXHash(key1.encode('hex'), key2)
note = PrivateNote.get_by_id(locked_id)
if not note:
    note = PrivateNote(id=locked_id, content=db)
else:
    note.content = db
note.put()
```

`436f7267316c3076657239393c332121` というユーザで `/private` にアクセスすればよさそうです。なんとかしてアクセストークンを手に入れましょう。

様々なユーザ名で登録していると、面白いことが起きました。

```
$ curl https://notes-server-m8tv5txzzohwiznk.web.ctfcompetition.com/register -d "username=436f7267316c3076657239393c33212101000000000000000000000000000000"
436f7267316c3076657239393c33212101000000000000000000000000000000-33e77228f277ba31
$ curl https://notes-server-m8tv5txzzohwiznk.web.ctfcompetition.com/register -d "username=436f7267316c3076657239393c33212102000000000000000000000000000000"
436f7267316c3076657239393c33212102000000000000000000000000000000-30e77228f277ba31
```

アクセストークンが少ししか変化していません。このアクセストークンを少しいじると、`436f7267316c3076657239393c332121` のアクセストークンを作ることができました。

```
$ curl -b "auth=436f7267316c3076657239393c332121-32e77228f277ba31" https://notes-server-m8tv5txzzohwiznk.web.ctfcompetition.com/private
U1FMaXRlIGZvcm1hdCAzABAAAQEAQCAgAAABewAAAAsAAAAAAAAAAAAAABAAAAAEAAAAAAAAAAkA
AAABAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAF7AC3mAg0PowAHDZgAD6cPHQ94
Dp4OQg3RDZgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
...
```

これを base64 デコードすると SQLite3 のデータベースが出てきました。

```
$ file private.bin
private.bin: SQLite 3.x database, user version 6
```

どのようなテーブルがあるか調べてみましょう。

```
sqlite> .tables
Diff              FLAG              Notes
DiffSet           NoteSet           android_metadata
sqlite> select * from FLAG;
ctf{with_crypt0_d0nt_ro11_with_it}
```

```
ctf{with_crypt0_d0nt_ro11_with_it}
```

## [Miscellaneous 187] Secret Notes 2

> There is a DIFFerent flag, can you find it?

Secret Notes で手に入れられたデータベースについて、Diff と DiffSet の構造を調べてみます。

```
sqlite> .schema Diff
CREATE TABLE Diff (ID INTEGER PRIMARY KEY, Insertion BOOLEAN, IDX INTEGER, Diff STRING(255), DiffSet ID);
sqlite> .schema DiffSet
CREATE TABLE DiffSet (ID INTEGER PRIMARY KEY, Note STRING(255));
```

Notes.App.apk を展開し、classes.dex を dex2jar で jar に変換、JD-GUI で読むと、どうやら Insertion が true であれば IDX の位置に Diff を挿入、false であれば IDX の位置の Diff を削除という意味であると分かりました。

Python で再現しましょう。

```python
import sqlite3
conn = sqlite3.connect('private.bin')
c = conn.cursor()

res = ''
for row in c.execute('SELECT Insertion, IDX, Diff FROM Diff INNER JOIN DiffSet ON Diff.DiffSet = DiffSet.ID WHERE DiffSet.Note = "flag.txt"'):
  insertion, idx, diff = row
  if insertion:
    res = res[:idx] + diff + res[idx:]
  else:
    res = res[:idx] + res[idx+len(diff):]
  print res

conn.close()
```

```
$ python2 solve.py | grep ctf
...
ctf{puZZ1e_As_old_as_tIme}
...
```

```
ctf{puZZ1e_As_old_as_tIme}
```