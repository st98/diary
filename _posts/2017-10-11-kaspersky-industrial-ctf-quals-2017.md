---
layout: post
title: Kaspersky Industrial CTF Quals 2017 の write-up
categories: [ctf]
date: 2017-10-11 16:25:00 +0900
---

チーム Harekaze で [Kaspersky Industrial CTF Quals 2017](https://ctf.kaspersky.com/contests/1/) に参加しました。最終的にチームで 2450 点を獲得し、順位は得点 227 チーム中 32 位でした。うち、私は 1 問を解いて 700 点を入れました。

以下、解いた問題の write-up です。

## [web 700] web keygen

与えられた URL にアクセスすると、パスワードの入力フォームが表示されました。

ソースを見てみると、以下のように難読化がされていました。

```javascript
class CoCoCoCoCoCoCoCoCoCoCoCoCo
{
    constructor(CoCo)
    {      
        this.CoCoCoCo = 0;
        
        var CoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCo.CoCoCoCoCo(); 
        
        while( CoCoCoCoCoCoCoCoCoCoCoCoCoCo-- )
        {
            this.CoCoCoCo += CoCo.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCo().CoCoCoCoCoCoCoCo();            
        }
        
        this.CoCoCoCo &= 0xFFFFFFFF;
        
        this.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo = CoCo.CoCoCoCoCoCoCoCoCoCoCoCoCoCoCoCo;
        this.CoCoCo = CoCo.CoCoCo;
    }
}
```

`Co` -> `aa`、`CoCo` -> `ab` という感じで置換して読みやすくして読んでいきましょう。([renamed.html](../files/20171011-kaspersky-industrial-ctf-quals-2017/renamed.html))

送信ボタンを押すと、入力したパスワードを第一引数として `GetFlag` を呼び出しています。`GetFlag` では、VM のインスタンスを作成してレジスタ (`ab.ac`) やメモリ (`at`) の初期化を行って、プログラムカウンタ (`ab.au`) が `0xffffffff` になるまでバイトコードの実行を行っています。

バイトコードはオペコード (1 バイト) とオペランド (可変長) からなり、更にオペランドはアドレッシングモード (1 バイト) と実際の値 (1 バイトか 4 バイト) から構成されています。

オペコードは push や mov など 18 種類、アドレッシングモードはレジスタ、即値、アドレス (1 バイトと 4 バイトの 2 種類) の 4 種類があります。

Python で逆アセンブラを書いてみましょう。

```python
import struct
import io

def u8(s):
  return struct.unpack('B', s)[0]

def u32(s):
  return struct.unpack('>I', s)[0]

def s32(s):
  return struct.unpack('>i', s)[0]

INSTRUCTIONS = [
  None,
  {'name': 'push', 'ops': 1},
  {'name': 'mov', 'ops': 2},
  {'name': 'sub', 'ops': 2},
  {'name': 'call', 'ops': 1},
  {'name': 'add', 'ops': 2},
  {'name': 'cmp', 'ops': 2},
  {'name': 'jne', 'ops': 1},
  {'name': 'jmp', 'ops': 1},
  {'name': 'jnc', 'ops': 1},
  {'name': 'mov_signed', 'ops': 2},
  {'name': 'xor', 'ops': 2},
  {'name': 'div', 'ops': 1},
  {'name': 'or', 'ops': 2},
  {'name': 'pop', 'ops': 1},
  {'name': 'ret', 'ops': 1},
  {'name': 'je', 'ops': 1},
  {'name': 'and', 'ops': 2},
  {'name': 'shr', 'ops': 2}
]
SIZES = [
  None,
  'BYTE',
  'WORD',
  None,
  'DWORD'
]

class Disassembler:
  def __init__(self, insts):
    self.mem = io.BytesIO(insts)
    self.size = len(insts)

  def read_uint8(self):
    return u8(self.mem.read(1))

  def read_uint32(self):
    return u32(self.mem.read(4))

  def read_int32(self):
    return s32(self.mem.read(4))

  def read_register(self):
    ad = self.read_uint8()
    size = self.read_uint8()
    ag = self.read_uint8()
    return 'r{:d}*{}'.format(ad, ag)

  def read_memory_addr(self, size):
    res = []
    n = self.read_uint8()
    for _ in range(n):
      res.append(self.get_value())
    return SIZES[size] + ' PTR [' + '+'.join(res) + ']'

  def get_value(self):
    op_type = self.read_uint8()
    if op_type == 1:
      return self.read_register()
    elif op_type == 2:
      return hex(self.read_uint32())
    elif op_type == 3:
      return self.read_memory_addr(1)
    elif op_type == 4:
      return self.read_memory_addr(4)
    return None

  def disassemble(self):
    res = []
    pc = 0
    while True:
      pc = self.mem.tell()
      code = self.read_uint8()
      if code >= len(INSTRUCTIONS):
        raise Exception('invalid instruction (0x{:x})'.format(code))
      inst = INSTRUCTIONS[code]
      if inst is None:
        break
      ops = []
      for _ in range(inst['ops']):
        ops.append(self.get_value())
      res.append('{:04x}: {} {}'.format(pc, inst['name'], ','.join(ops)))
    return '\n'.join(res)

if __name__ == '__main__':
  with open('prog.bin', 'rb') as f:
    prog = f.read()
  dis = Disassembler(prog)
  print(dis.disassemble())
```

[prog.bin](../files/20171011-kaspersky-industrial-ctf-quals-2017/prog.bin) を逆アセンブルすると [dis.txt](../files/20171011-kaspersky-industrial-ctf-quals-2017/dis.txt) のような結果になりました。

逆アセンブルの結果を見ると、0x0 と 0x4c1 の 2 つの関数で構成されていることが分かります。前者はおそらく main、後者は `0x77073096` や `0xee0e612c` のような値が含まれていることから CRC32 の計算を行う関数であると推測しました。

0x0 ~ を詳しく読んでいきましょう。まず `r20-0x2c` を `0x73, 0x14, 0x20, 0x17, 0x2, …` という感じの配列として初期化しています。その後第一引数に入力したパスワード、第二引数に `0x12345678` を指定して 0x4c1 を呼び出し、その返り値と `0x33e5ae40` を比較して、もし違っていればそこで処理を終了しています。返り値が `0x33e5ae40` だった場合には、`r20-0x2c` と入力したパスワードを xor しています。

フラグは他の問題から `KLCTF` で始まることが分かっているので、`0x73, 0x14, 0x20, 0x17, 0x2` と xor することでパスワードが `8XcCD` から始まることが分かります。ブルートフォースでパスワードを探してみましょう。

```python
import binascii
import itertools
import string
s = '8XcCD'
for i in range(4):
  for t in itertools.permutations(string.digits + string.letters, i):
    t = ''.join(t)
    if binascii.crc32(s + t, 0x12345678) == 0x33e5ae40:
      print '[!] %s' % s + t
```

```
$ python2 find.py
[!] 8XcCDUhG
```

パスワードが `8XcCDUhG` であると分かりました。これをフォームに入力するとフラグが得られました。

```
KLCTF7B0AEB2426A8F829276C73A32241ADBA
```