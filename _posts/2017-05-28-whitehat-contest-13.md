---
layout: post
title: WhiteHat Contest 13 の write-up
categories: [ctf]
date: 2017-05-28 22:45:00 +0900
---

チーム Harekaze で [WhiteHat Contest 13](https://wargame.whitehat.vn/Contests/ChallengesContest/37) に参加しました。最終的にチームで 700 点を獲得し、順位は得点 108 チーム中 25 位でした。うち、私は 2 問を解いて 300 点を入れました。

以下、解いた問題の write-up です。

## [Reverse Engineering 100] Tuy Hoa

re100 という 64 ビットの ELF が与えられました。objdump に投げてみると、main は以下のようになっていました。

```
0000000000400e4a <main>:
  400e4a:	55                   	push   rbp
  400e4b:	48 89 e5             	mov    rbp,rsp
  400e4e:	bf b3 0f 40 00       	mov    edi,0x400fb3
  400e53:	e8 88 f9 ff ff       	call   4007e0 <puts@plt>
  400e58:	48 8b 05 21 12 20 00 	mov    rax,QWORD PTR [rip+0x201221]        # 602080 <__TMC_END__>
  400e5f:	48 89 c2             	mov    rdx,rax
  400e62:	be 28 00 00 00       	mov    esi,0x28
  400e67:	bf c0 21 60 00       	mov    edi,0x6021c0
  400e6c:	e8 bf f9 ff ff       	call   400830 <fgets@plt>
  400e71:	e8 21 fb ff ff       	call   400997 <_Z5func0v>
  400e76:	e8 76 fb ff ff       	call   4009f1 <_Z5func1v>
  400e7b:	e8 cf fb ff ff       	call   400a4f <_Z5func2v>
  400e80:	e8 38 fc ff ff       	call   400abd <_Z5func3v>
  400e85:	e8 ad fc ff ff       	call   400b37 <_Z5func4v>
  400e8a:	e8 12 fd ff ff       	call   400ba1 <_Z5func5v>
  400e8f:	e8 77 fd ff ff       	call   400c0b <_Z5func6v>
  400e94:	e8 0c fe ff ff       	call   400ca5 <_Z5func7v>
  400e99:	e8 65 fe ff ff       	call   400d03 <_Z5func8v>
  400e9e:	e8 de fe ff ff       	call   400d81 <_Z5func9v>
  400ea3:	e8 52 ff ff ff       	call   400dfa <_Z6func10v>
  400ea8:	be c4 0f 40 00       	mov    esi,0x400fc4
  400ead:	bf a0 20 60 00       	mov    edi,0x6020a0
  400eb2:	e8 99 f9 ff ff       	call   400850 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
  400eb7:	be 70 08 40 00       	mov    esi,0x400870
  400ebc:	48 89 c7             	mov    rdi,rax
  400ebf:	e8 9c f9 ff ff       	call   400860 <_ZNSolsEPFRSoS_E@plt>
  400ec4:	b8 00 00 00 00       	mov    eax,0x0
  400ec9:	5d                   	pop    rbp
  400eca:	c3                   	ret    
```

`_Z5func0v` `_Z5func1v` … がどのような関数か調べてみましょう。

```
0000000000400997 <_Z5func0v>:
  400997:	55                   	push   rbp
  400998:	48 89 e5             	mov    rbp,rsp
  40099b:	48 83 ec 10          	sub    rsp,0x10
  40099f:	8b 05 23 18 20 00    	mov    eax,DWORD PTR [rip+0x201823]        # 6021c8 <key+0x8>
  4009a5:	8b 0d 31 18 20 00    	mov    ecx,DWORD PTR [rip+0x201831]        # 6021dc <key+0x1c>
  4009ab:	8b 15 13 18 20 00    	mov    edx,DWORD PTR [rip+0x201813]        # 6021c4 <key+0x4>
  4009b1:	01 ca                	add    edx,ecx
  4009b3:	31 d0                	xor    eax,edx
  4009b5:	2d bf 4c d5 7c       	sub    eax,0x7cd54cbf
  4009ba:	89 c0                	mov    eax,eax
  4009bc:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  4009c0:	8b 05 fa 17 20 00    	mov    eax,DWORD PTR [rip+0x2017fa]        # 6021c0 <key>
  4009c6:	8b 15 fc 17 20 00    	mov    edx,DWORD PTR [rip+0x2017fc]        # 6021c8 <key+0x8>
  4009cc:	8b 35 0a 18 20 00    	mov    esi,DWORD PTR [rip+0x20180a]        # 6021dc <key+0x1c>
  4009d2:	8b 0d ec 17 20 00    	mov    ecx,DWORD PTR [rip+0x2017ec]        # 6021c4 <key+0x4>
  4009d8:	01 f1                	add    ecx,esi
  4009da:	31 ca                	xor    edx,ecx
  4009dc:	81 ea bf 4c d5 7c    	sub    edx,0x7cd54cbf
  4009e2:	39 d0                	cmp    eax,edx
  4009e4:	74 05                	je     4009eb <_Z5func0v+0x54>
  4009e6:	e8 82 ff ff ff       	call   40096d <_Z14wrong_passwordv>
  4009eb:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  4009ef:	c9                   	leave  
  4009f0:	c3                   	ret    
```

```
00000000004009f1 <_Z5func1v>:
  4009f1:	55                   	push   rbp
  4009f2:	48 89 e5             	mov    rbp,rsp
  4009f5:	48 83 ec 10          	sub    rsp,0x10
  4009f9:	8b 15 c1 17 20 00    	mov    edx,DWORD PTR [rip+0x2017c1]        # 6021c0 <key>
  4009ff:	8b 05 df 17 20 00    	mov    eax,DWORD PTR [rip+0x2017df]        # 6021e4 <key+0x24>
  400a05:	01 c2                	add    edx,eax
  400a07:	8b 05 b3 17 20 00    	mov    eax,DWORD PTR [rip+0x2017b3]        # 6021c0 <key>
  400a0d:	29 c2                	sub    edx,eax
  400a0f:	89 d0                	mov    eax,edx
  400a11:	05 2f 31 02 61       	add    eax,0x6102312f
  400a16:	89 c0                	mov    eax,eax
  400a18:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  400a1c:	8b 05 a2 17 20 00    	mov    eax,DWORD PTR [rip+0x2017a2]        # 6021c4 <key+0x4>
  400a22:	8b 0d 98 17 20 00    	mov    ecx,DWORD PTR [rip+0x201798]        # 6021c0 <key>
  400a28:	8b 15 b6 17 20 00    	mov    edx,DWORD PTR [rip+0x2017b6]        # 6021e4 <key+0x24>
  400a2e:	01 d1                	add    ecx,edx
  400a30:	8b 15 8a 17 20 00    	mov    edx,DWORD PTR [rip+0x20178a]        # 6021c0 <key>
  400a36:	29 d1                	sub    ecx,edx
  400a38:	89 ca                	mov    edx,ecx
  400a3a:	81 c2 2f 31 02 61    	add    edx,0x6102312f
  400a40:	39 d0                	cmp    eax,edx
  400a42:	74 05                	je     400a49 <_Z5func1v+0x58>
  400a44:	e8 24 ff ff ff       	call   40096d <_Z14wrong_passwordv>
  400a49:	48 8b 45 f8          	mov    rax,QWORD PTR [rbp-0x8]
  400a4d:	c9                   	leave  
  400a4e:	c3                   	ret    
```

key (入力した文字列) を 4 文字ずつ、int の配列として扱い何かこねくり回して比較しています。z3 に投げて解いてもらいましょう。

```python
import re
from z3 import *

funcs = '''
...
'''.strip().split('\n\n')

regs = {
  'eax': 0,
  'ecx': 0,
  'edx': 0,
  'edi': 0,
  'esi': 0,
}

def get_value(v):
  if v in ['eax', 'ecx', 'edx', 'edi', 'esi']:
    return regs[v]
  if v.startswith('0x'):
    return int(v, 16)
  raise Exception(v)

key = [BitVec('key_%x' % x, 32) for x in range(0, 0x24+1, 4)]
s = Solver()

for func in funcs:
  for line in func.splitlines():
    t = line.split()
    if t[0] == 'add':
      a, b = t[1].split(',')
      regs[a] = get_value(a) + get_value(b)
    elif t[0] == 'sub':
      if 'rsp' in t[1]:
        continue
      a, b = t[1].split(',')
      regs[a] = get_value(a) - get_value(b)
    elif t[0] == 'xor':
      a, b = t[1].split(',')
      regs[a] = get_value(a) ^ get_value(b)
    elif t[0] == 'div':
      a = get_value(t[1])
      b, c = get_value('eax') / a, get_value('eax') % a
      regs['eax'] = b
      regs['edx'] = c
    elif t[0] == 'imul':
      a, b = t[1].split(',')
      regs[a] = get_value(a) * get_value(b)
    elif t[0] == 'mov':
      if 'QWORD' in t[1] or 'rbp' in t[1]:
        continue
      if len(t) == 7:
        m = re.findall(r'key\+?(.*).', t[-1])[0]
        m = (0 if m == '' else int(m, 16)) / 4
        a, _ = t[1].split(',')
        regs[a] = key[m]
      else:
        a, b = t[1].split(',')
        regs[a] = get_value(b)
    elif t[0] == 'cmp':
      a, b = t[1].split(',')
      a = get_value(a)
      b = get_value(b)
      s.add(a == b)

r = s.check()
m = s.model()
res = ''
for k in key:
  h = hex(m[k].as_long())[2:]
  res += ''.join(reversed(re.findall(r'.{2}', h)))
print res.decode('hex')
```

([solve.py](https://gist.github.com/st98/c5592d0b6e4eda1078df84b3ea13abed))

...

```
WhiteHat{5a62af9a23b56ee49370808a0cf1e80967572570}
```

## [Reverse Engineering 200] Da Nhay beach

Python のバイトコードを逆アセンブルした結果が与えられます。手でデコンパイルすると以下のようになりました。

```python
class A:
  def __init__(self):
    self.list_value = self.getvalue(225) # line 16
    self.LENGTH = len(self.list_value)

  def main(self):
    location = 0
    while location != self.LENGTH:
      self.draw(location)
      case = raw_input()
      if case == '1':
        step = randint(1, 6)
        location += step
        if location >= self.LENGTH - 1:
          print 'Something wrong here =.=!'
          return
      elif case == '2':
        save = 0
        for i in range(0, location):
          save += self.list_value[i]
        file = open('save', 'w')
        file.write(str(save))
        file.close()
      elif case == '3':
        file = open('save', 'r')
        load = int(file.read(), 10)
        location = 0
        tmp = 0
        while load != 0 and load >= tmp:
          load -= tmp
          location += 1
          try:
            tmp = self.list_value[location]
          except:
            break
          print load
          if load != 0:
            print 'Invalid save file'
      elif case == '4':
        return

    print 'Congratulation! Submit your flag ^-^'

  def getvalue(self, v):
    return [int(((1 + 2.23606797749979) ** n - (1 - 2.23606797749979) ** n) / (2 ** n * 2.23606797749979)) for n in range(v)]

  def draw(self, location):
    print '_' * location + 'x' + '_' * (self.LENGTH - location - 2) + 'F'
    print '1 - Continue'
    print '2 - Save'
    print '3 - Load'
    print '4 - Quit'
```

すごろくのプログラムのようです。ズルをしましょう。

```python
if __name__ == '__main__':
  import hashlib
  a = A()
  list_value = a.getvalue(225)
  save = 0
  for i in range(0, 225):
    save += list_value[i]
  print 'WhiteHat{' + hashlib.sha1(str(save)).hexdigest() + '}'
```

```
WhiteHat{6c3259e2196325a643e88f4ed443661522853c0b}
```

