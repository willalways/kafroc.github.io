---
layout: post
comments: true
title: RiftCTF 2020-03-21 writeup
category: 网络安全
keywords: writewp,CTF,2020
---

今天参加 RiftCTF 线上比赛，做了几道逆向题，这次比赛对像我这样的菜鸟比较友好，题目不会太难

比赛网址 [http://riftctf.iiitnr.ac.in:8000/](http://riftctf.iiitnr.ac.in:8000/)

所有比赛材料可查看 [https://github.com/riftctf2020/rift2020](https://github.com/riftctf2020/rift2020)

## 第一题 chall1.elf

### 题目

```
Value: 50 points

The file required to solve the challenge is attached in the directory with the name: chall1.elf

Message:
1. find the correct password for the crackme to display the "Correct
     Password" message.
2. your goal is not to make the app display "Correct Password" but to
     find the correct password which does that for you.
3. brute-forcing won't help but you can do whatever you want.
4. don't expose this challenge on a real work environment.
5. flag format riftCTF{<---flag-here--->}.
    Good Luck!
```

文件下载地址 [chall1.elf](https://github.com/riftctf2020/rift2020/blob/master/Reverse%20Engineering/chall1.elf)

题目是让你下载一个二进制文件，该二进制文件需要输入密码，密码正确程序会输出“Correct Password”。 flag 就是正确的密码.

### 解题

把 chall1.elf 用 IDA 打开，反编译为 C 代码，如下

```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char s; // [rsp+0h] [rbp-50h]
  unsigned __int64 v5; // [rsp+48h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("--=[ Super Easy Crackme ]=--");
  printf("passwd > ", a2);
  fgets(&s, 64, stdin);
  if ( !strncmp(&s, "riftCTF{tr4c1ng-mAkes-17-SUPeR-345Y}", 0x24uLL) )
    puts("Correct Password...");
  else
    puts("Wrong Password...");
  return 0LL;
}
```

从 strncmp 函数的参数中可以找到 flag

## 第二题 chall2.elf

### 题目

```
Value: 100points

The file required to solve the challenge is attached in the directory with the name: chall2.elf

Message:
1. find the correct password for the crackme to display the "Correct
    Password" message.
2. your goal is not to make the app display "Correct Password" but to
    find the correct
password which does that for you.
3. brute-forcing won't help but you can do whatever you want.
4. don't expose this challenge on a real work environment.
5. flag format ritsCTF{<---flag-here--->}.
   Good Luck!
```

文件下载地址 [chall2.elf](https://github.com/riftctf2020/rift2020/blob/master/Reverse%20Engineering/chall2.elf)

题目是让你下载一个二进制文件，该二进制文件需要输入密码，密码正确程序会输出“Correct Password”。 flag 就是正确的密码.

### 解题

把二进制用 IDA 打开，反编译查看代码逻辑

```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char s; // [rsp+0h] [rbp-50h]
  unsigned __int64 v5; // [rsp+48h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("--=[ Not So Easy Crackme ]=--");
  printf("passwd > ", a2);
  fgets(&s, 64, stdin);
  if ( (unsigned int)sub_1165((__int64)&s, (__int64)&unk_2030, 37) )
    puts("Wrong Password...");
  else
    puts("Correct Password...");
  return 0LL;
}

__int64 __fastcall sub_1165(__int64 a1, __int64 a2, int a3)
{
  unsigned int v4; // [rsp+1Ch] [rbp-8h]
  int i; // [rsp+20h] [rbp-4h]

  v4 = 0;
  for ( i = 0; i < a3 && *(_BYTE *)(i + a1) && *(_BYTE *)(i + a2); ++i )
    v4 |= (char)(*(_BYTE *)(i + a1) ^ 0x55 ^ *(_BYTE *)(i + a2));
  return v4;
}
```

输入密码，存放到 s，调用 sub_1165(s, unk_2030, 37)让返回值为 0 即可

来看看 sub_1165 函数，看上去很复杂，各种指针。简化以下，大概是这样的

```
int sub_1165(char *a1, char *a2, int a3)
{
  unsigned int v4; // [rsp+1Ch] [rbp-8h]
  int i; // [rsp+20h] [rbp-4h]

  v4 = 0;
  for ( i = 0; i < a3 && a1[i] && a2[i]; ++i )
    v4 |= a1[i] ^ 0x55 ^ a2[i];
  return v4;
}
```

要让返回值 v4 为零， 就必须要 for 循环每次 a1[i] ^ 0x55 ^ a2[i]均为零，那么只要让每次 a1[i] == 0x55 ^ a2[i]即可，而 a2 的内容是可以从二进制中获取的

把 a2 指向的 37 个字节提取出来，与 0x55 异或，即可求出 a1，也就是我要输入的 password

通过下面的代码可以求出 flag

```
#include <stdio.h>

int main(void)
{
    char *a2 = "\x27\x3C\x33\x21\x16\x01\x13\x2E\x21\x27\x61\x36\x3C\x3B\x32\x0A\x31\x65\x66\x26\x3B\x21\x0A\x22\x65\x27\x3E\x0A\x34\x3B\x2C\x18\x65\x27\x66\x66\x28";
    while (*a2)
        printf("%c", 0x55 ^ *a2++);

    return 0;
}
```

## 第 3 题 chall4.elf

### 题目

```
Value: 300 points

File Name for the challenge: chall4.elf

Message:

1. find the correct password for the crackme to display the "Correct
    Password" message.
2. your goal is not to make the app display "Correct Password" but to
    find the correct password which does that for you.
3. brute-forcing won't help but you can do whatever you want.
4. don't expose this challenge to a real work environment.
5. flag format ritsCTF{<---flag-here--->}.
   Good Luck!
```

文件下载地址 [chall4.elf](https://github.com/riftctf2020/rift2020/blob/master/Reverse%20Engineering/chall4.elf)

题目是让你下载一个二进制文件，该二进制文件需要输入密码，密码正确程序会输出“Correct Password”。 flag 就是正确的密码.

### 解题

按照惯例，拖进 IDA 分析反编译后的代码

```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  unsigned __int8 v3; // ST0B_1
  unsigned __int8 v4; // ST0B_1
  unsigned __int8 v5; // ST0B_1
  unsigned __int8 v6; // ST0B_1
  unsigned __int8 v7; // ST0B_1
  int v8; // eax
  unsigned int i; // [rsp+Ch] [rbp-A4h]
  char s; // [rsp+10h] [rbp-A0h]
  char v12; // [rsp+50h] [rbp-60h]
  char v13; // [rsp+51h] [rbp-5Fh]
  char v14; // [rsp+52h] [rbp-5Eh]
  char v15; // [rsp+53h] [rbp-5Dh]
  char v16; // [rsp+54h] [rbp-5Ch]
  char v17; // [rsp+55h] [rbp-5Bh]
  char v18; // [rsp+56h] [rbp-5Ah]
  char v19; // [rsp+57h] [rbp-59h]
  char v20; // [rsp+58h] [rbp-58h]
  char v21; // [rsp+59h] [rbp-57h]
  char v22; // [rsp+5Ah] [rbp-56h]
  char v23; // [rsp+5Bh] [rbp-55h]
  char v24; // [rsp+5Ch] [rbp-54h]
  char v25; // [rsp+5Dh] [rbp-53h]
  char v26; // [rsp+5Eh] [rbp-52h]
  char v27; // [rsp+5Fh] [rbp-51h]
  char v28; // [rsp+60h] [rbp-50h]
  char v29; // [rsp+61h] [rbp-4Fh]
  char v30; // [rsp+62h] [rbp-4Eh]
  char v31; // [rsp+63h] [rbp-4Dh]
  char v32; // [rsp+64h] [rbp-4Ch]
  char v33; // [rsp+65h] [rbp-4Bh]
  char v34; // [rsp+66h] [rbp-4Ah]
  char v35; // [rsp+67h] [rbp-49h]
  char v36; // [rsp+68h] [rbp-48h]
  char v37; // [rsp+69h] [rbp-47h]
  char v38; // [rsp+6Ah] [rbp-46h]
  char v39; // [rsp+6Bh] [rbp-45h]
  char v40; // [rsp+6Ch] [rbp-44h]
  char v41; // [rsp+6Dh] [rbp-43h]
  char v42; // [rsp+6Eh] [rbp-42h]
  char v43; // [rsp+6Fh] [rbp-41h]
  char v44; // [rsp+70h] [rbp-40h]
  char v45; // [rsp+71h] [rbp-3Fh]
  char v46; // [rsp+72h] [rbp-3Eh]
  char v47; // [rsp+73h] [rbp-3Dh]
  char v48; // [rsp+74h] [rbp-3Ch]
  char v49; // [rsp+75h] [rbp-3Bh]
  char v50; // [rsp+76h] [rbp-3Ah]
  char v51; // [rsp+77h] [rbp-39h]
  char v52; // [rsp+78h] [rbp-38h]
  char v53; // [rsp+79h] [rbp-37h]
  char v54; // [rsp+7Ah] [rbp-36h]
  char v55; // [rsp+7Bh] [rbp-35h]
  char v56; // [rsp+7Ch] [rbp-34h]
  char v57; // [rsp+7Dh] [rbp-33h]
  char v58; // [rsp+7Eh] [rbp-32h]
  char v59; // [rsp+7Fh] [rbp-31h]
  char v60; // [rsp+80h] [rbp-30h]
  char v61; // [rsp+81h] [rbp-2Fh]
  char v62; // [rsp+82h] [rbp-2Eh]
  char v63; // [rsp+83h] [rbp-2Dh]
  char v64; // [rsp+84h] [rbp-2Ch]
  char v65; // [rsp+85h] [rbp-2Bh]
  char v66; // [rsp+86h] [rbp-2Ah]
  char v67; // [rsp+87h] [rbp-29h]
  char v68; // [rsp+88h] [rbp-28h]
  char v69; // [rsp+89h] [rbp-27h]
  char v70; // [rsp+8Ah] [rbp-26h]
  char v71; // [rsp+8Bh] [rbp-25h]
  char v72; // [rsp+8Ch] [rbp-24h]
  char v73; // [rsp+8Dh] [rbp-23h]
  char v74; // [rsp+8Eh] [rbp-22h]
  char v75; // [rsp+8Fh] [rbp-21h]
  char v76; // [rsp+90h] [rbp-20h]
  char v77; // [rsp+91h] [rbp-1Fh]
  char v78; // [rsp+92h] [rbp-1Eh]
  char v79; // [rsp+93h] [rbp-1Dh]
  char v80; // [rsp+94h] [rbp-1Ch]
  char v81; // [rsp+95h] [rbp-1Bh]
  char v82; // [rsp+96h] [rbp-1Ah]
  char v83; // [rsp+97h] [rbp-19h]
  char v84; // [rsp+98h] [rbp-18h]
  char v85; // [rsp+99h] [rbp-17h]
  unsigned __int64 v86; // [rsp+A8h] [rbp-8h]

  v86 = __readfsqword(0x28u);
  puts("--=[ Very Hard Crackme ]=--");
  printf("passwd > ", a2);
  fgets(&s, 64, stdin);
  v12 = 110;
  v13 = -16;
  v14 = -20;
  v15 = 2;
  v16 = 107;
  v17 = 36;
  v18 = -79;
  v19 = 49;
  v20 = 6;
  v21 = -21;
  v22 = 87;
  v23 = -10;
  v24 = 95;
  v25 = -112;
  v26 = 21;
  v27 = -26;
  v28 = 26;
  v29 = 21;
  v30 = -109;
  v31 = 31;
  v32 = -70;
  v33 = 67;
  v34 = -41;
  v35 = 58;
  v36 = -46;
  v37 = -128;
  v38 = 122;
  v39 = 12;
  v40 = -85;
  v41 = -52;
  v42 = 10;
  v43 = -6;
  v44 = -109;
  v45 = -35;
  v46 = -24;
  v47 = -106;
  v48 = -89;
  v49 = 117;
  v50 = -23;
  v51 = 29;
  v52 = -4;
  v53 = 104;
  v54 = 125;
  v55 = 1;
  v56 = 84;
  v57 = -106;
  v58 = 90;
  v59 = -123;
  v60 = -49;
  v61 = -46;
  v62 = -56;
  v63 = -97;
  v64 = -19;
  v65 = 28;
  v66 = 106;
  v67 = 41;
  v68 = -38;
  v69 = -47;
  v70 = 48;
  v71 = -126;
  v72 = 125;
  v73 = -126;
  v74 = -15;
  v75 = -21;
  v76 = -32;
  v77 = 36;
  v78 = 21;
  v79 = 109;
  v80 = 50;
  v81 = 48;
  v82 = -121;
  v83 = 40;
  v84 = 92;
  v85 = -123;
  for ( i = 0; i <= 0x49; ++i )
  {
    v3 = ~-(char)~(i ^ ((((unsigned __int8)*(&v12 + i) >> 3) | 32 * *(&v12 + i)) + 99));
    v4 = i ^ ((i ^ ~(((i ^ (-(char)(((-(char)~((v3 >> 1) | (v3 << 7)) ^ 0x39) - 64) ^ 0x48) - i)) - 104) ^ 0xF3)) - i);
    v5 = ~(~(((v4 >> 2) | (v4 << 6)) - i) ^ 0x42);
    v6 = ~-(char)((i ^ (((((v5 >> 7) | 2 * v5) - 18) ^ 0x26) - i)) + 31);
    v7 = (~(i + ((i + ((-(char)(i ^ (i + (i ^ -(char)(((v6 >> 1) | (v6 << 7)) ^ 0x99)))) - i) ^ 0x83)) ^ 0x2B)) ^ 0x62)
       - 37;
    *(&v12 + i) = (v7 >> 1) | (v7 << 7);
  }
  v8 = strlen(&v12);
  if ( (unsigned int)sub_1175((__int64)&s, (__int64)&v12, v8) )
    puts("Wrong Password...");
  else
    puts("Correct Password...");
  return 0LL;
}

__int64 __fastcall sub_1175(__int64 a1, __int64 a2, int a3)
{
  unsigned int v4; // [rsp+1Ch] [rbp-8h]
  int i; // [rsp+20h] [rbp-4h]

  v4 = 0;
  for ( i = 0; i < a3 && *(_BYTE *)(i + a1) && *(_BYTE *)(i + a2); ++i )
    v4 |= (char)(*(_BYTE *)(i + a1) ^ *(_BYTE *)(i + a2));
  return v4;
}
```

和第二题一样， 也是要 sub_1175 函数返回 0，这题要求 a1 和 a2 一样，要知道 a2 的值，有两个思路

- 动态调试，用 gdb 打断点到 sub_1175， 把 a2 打出来即可
- 静态分析，编写模仿上面的 a2 生成算法生成 a2，把 a2 打印出来

好像这个程序有防 gdb 调试，我用 gdb 一直打不了断点，所以我只能用静态分析来解题

这题静态分析的难点倒不是 for 循环 循环体的那一串语句，那一串代码不用理会，直接拷贝下来即可，难点在于 v12-v85 这么多变量，好像没啥用。我们从 sub_1175 的第二个参数知道，v12 其实是一个 char 数组，

```
  char v12; // [rsp+50h] [rbp-60h]
  char v13; // [rsp+51h] [rbp-5Fh]
  char v14; // [rsp+52h] [rbp-5Eh]
  char v15; // [rsp+53h] [rbp-5Dh]
  char v16; // [rsp+54h] [rbp-5Ch]
```

看到 v13 只是比 v12 地址多一个字节，那么可以知道 v13 其实就是 v12[1],其他依次类推，编写代码如下

```
#include <stdio.h>

int main(int a1, char **a2, char **a3)
{
  unsigned char v3;
  unsigned char v4;
  unsigned char v5;
  unsigned char v6;
  unsigned char v7;
  int v8;
  unsigned int i;   // [rsp+Ch] [rbp-A4h]
  char s[64];       // [rsp+10h] [rbp-A0h]
  unsigned char v12[74] = {110, -16, -20, 2, 107, 36, -79, 49, 6, -21, 87, -10, 95, -112, 21, -26, 26, 21, -109, 31, -70, 67, -41, 58, -46, -128, 122, 12, -85, -52, 10, -6, -109, -35, -24, -106, -89, 117, -23, 29, -4, 104, 125, 1, 84, -106, 90, -123, -49, -46, -56, -97, -19, 28, 106, 41, -38, -47, 48, -126, 125, -126, -15, -21, -32, 36, 21, 109, 50, 48, -121, 40, 92, -123}; // [rsp+50h] [rbp-60h]

  for (i = 0; i <= 0x49; ++i)
  {
    v3 = ~-(char)~(i ^ (((v12[i] >> 3) | 32 * v12[i]) + 99));
    v4 = i ^ ((i ^ ~(((i ^ (-(char)(((-(char)~((v3 >> 1) | (v3 << 7)) ^ 0x39) - 64) ^ 0x48) - i)) - 104) ^ 0xF3)) - i);
    v5 = ~(~(((v4 >> 2) | (v4 << 6)) - i) ^ 0x42);
    v6 = ~-(char)((i ^ (((((v5 >> 7) | 2 * v5) - 18) ^ 0x26) - i)) + 31);
    v7 = (~(i + ((i + ((-(char)(i ^ (i + (i ^ -(char)(((v6 >> 1) | (v6 << 7)) ^ 0x99)))) - i) ^ 0x83)) ^ 0x2B)) ^ 0x62) - 37;
    v12[i] = (v7 >> 1) | (v7 << 7);
  }

  puts(v12);
  return 0LL;
}
```

运行上面的代码就能拿到 flag 了
