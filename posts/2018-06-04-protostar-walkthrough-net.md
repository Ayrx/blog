---
layout: post
title: Protostar Walkthrough - Net
---

Protostar is a virtual machine from [Exploit Exercises][exploit-exercises] that
goes through basic memory corruption issues.

This blog post is a continuation from my previous writeups on the
[stack exploitation][protostar-stack-writeup],
[format string exploitation][protostar-format-writeup] and
[heap exploitation][protostar-heap-writeup]  stages of Protostar.

The sha1sum of the ISO I am working with is d030796b11e9251f34ee448a95272a4d432cf2ce.

{:toc}

# net 0

We are given the below source code.

```c
#include "../common/common.c"

#define NAME "net0"
#define UID 999
#define GID 999
#define PORT 2999

void run()
{
  unsigned int i;
  unsigned int wanted;

  wanted = random();

  printf("Please send '%d' as a little endian 32bit int\n", wanted);

  if(fread(&i, sizeof(i), 1, stdin) == NULL) {
      errx(1, ":(\n");
  }

  if(i == wanted) {
      printf("Thank you sir/madam\n");
  } else {
      printf("I'm sorry, you sent %d instead\n", i);
  }
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID);

  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  /* Don't do this :> */
  srandom(time(NULL));

  run();
}
```

This is a program that listens on port 2999, sends the ASCII representation
of a number and expects the little-endian 32-bit representation of the number
back.

```
user@protostar:~$ nc 127.0.0.1 2999
Please send '1689310607' as a little endian 32bit int
1689310607
I'm sorry, you sent 959985201 instead
```

We can write a simple Python script that connects to port 2999, reads the
integer it expects, pack it in a little-endian format before sending it back
to the program.

```python
import socket
import re
import struct


HOST = "127.0.0.1"
PORT = 2999

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

data = s.recv(1024)
m = re.search("\'[0-9]*\'", data)
integer = m.group(0).replace("\'", "")
integer = int(integer)
s.send(struct.pack("<I", integer))

data = s.recv(1024)
print data

s.close()
```

Running the `net0.py` script, we see that it works.

```shell
user@protostar:~$ python net0.py
Thank you sir/madam
```

# net 1

We are given the below source code.

```c
#include "../common/common.c"

#define NAME "net1"
#define UID 998
#define GID 998
#define PORT 2998

void run()
{
  char buf[12];
  char fub[12];
  char *q;

  unsigned int wanted;

  wanted = random();

  sprintf(fub, "%d", wanted);

  if(write(0, &wanted, sizeof(wanted)) != sizeof(wanted)) {
      errx(1, ":(\n");
  }

  if(fgets(buf, sizeof(buf)-1, stdin) == NULL) {
      errx(1, ":(\n");
  }

  q = strchr(buf, '\r'); if(q) *q = 0;
  q = strchr(buf, '\n'); if(q) *q = 0;

  if(strcmp(fub, buf) == 0) {
      printf("you correctly sent the data\n");
  } else {
      printf("you didn't send the data properly\n");
  }
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID);

  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  /* Don't do this :> */
  srandom(time(NULL));

  run();
}
```

This is a program that listens on port 2998, sends the binary representation
of a number and expects the ASCII representation of the number back.

```shell
user@protostar:~$ nc 127.0.0.1 2998
0FOO
you didn't send the data properly
```

We can write a simple Python script that connects to port 2998, reads the
binary representation of the integer, unpacks it and sends it back as an ASCII
integer.

```python
import socket
import re
import struct


HOST = "127.0.0.1"
PORT = 2998

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

data = s.recv(1024)
data = struct.unpack("<I", data)[0]
print data

s.send(str(data))
data = s.recv(1024)
print data

s.close()
```

# net 2

We are given the below source code.

```c
#include "../common/common.c"

#define NAME "net2"
#define UID 997
#define GID 997
#define PORT 2997

void run()
{
  unsigned int quad[4];
  int i;
  unsigned int result, wanted;

  result = 0;
  for(i = 0; i < 4; i++) {
      quad[i] = random();
      result += quad[i];

      if(write(0, &(quad[i]), sizeof(result)) != sizeof(result)) {
          errx(1, ":(\n");
      }
  }

  if(read(0, &wanted, sizeof(result)) != sizeof(result)) {
      errx(1, ":<\n");
  }


  if(result == wanted) {
      printf("you added them correctly\n");
  } else {
      printf("sorry, try again. invalid\n");
  }
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID);

  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  /* Don't do this :> */
  srandom(time(NULL));

  run();
}
```

This is a program that listens on port 2997, sends the binary representation of
four numbers and expects the binary representation of the four numbers added
together back.

```shell
user@protostar:~$ nc 127.0.0.1 2997
3$Z^aASDF
sorry, try again. invalid
```

We extend upon our previous script to read four numbers, add them together and
packs the result into a little-endian 32-bit binary representation before
sending it back to the program.

The one thing to note is that we use a function (copied shamelessly from
StackOverflow) to mimick C's integer overflow behaviour on Python since Python
normally transparently promotes integers to longs.


```python
import socket
import re
import struct
import ctypes
import sys


def int_overflow(val):
    # Taken from https://stackoverflow.com/a/7771363
    if not -sys.maxint-1 <= val <= sys.maxint:
        val = (val + (sys.maxint + 1)) % (2 * (sys.maxint + 1)) - sys.maxint - 1
    return val


HOST = "127.0.0.1"
PORT = 2997

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

data = []

for i in range(0, 4):
    data.append(struct.unpack("<I", s.recv(4))[0])

print data

ret = 0
for i in data:
    ret = int_overflow(ret + i)

print ret

s.send(struct.pack("<I", ret))
data = s.recv(1024)
print data

s.close()
```

```shell
user@protostar:~$ python net2.py
[198149134, 1681498846, 1150524978, 908343567]
-356450771
net2.py:34: DeprecationWarning: struct integer overflow masking is deprecated
  s.send(struct.pack("<I", ret))
you added them correctly
```

# final 0

We are given the below source code.

```c
#include "../common/common.c"

#define NAME "final0"
#define UID 0
#define GID 0
#define PORT 2995

/*
 * Read the username in from the network
 */

char *get_username()
{
  char buffer[512];
  char *q;
  int i;

  memset(buffer, 0, sizeof(buffer));
  gets(buffer);

  /* Strip off trailing new line characters */
  q = strchr(buffer, '\n');
  if(q) *q = 0;
  q = strchr(buffer, '\r');
  if(q) *q = 0;

  /* Convert to lower case */
  for(i = 0; i < strlen(buffer); i++) {
      buffer[i] = toupper(buffer[i]);
  }

  /* Duplicate the string and return it */
  return strdup(buffer);
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID);

  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  username = get_username();

  printf("No such user %s\n", username);
}
```

We are actually given the root user (root // godmode) account to debug this
level. When developing exploits for network programs, we generally want to
test the exploit on a copy of the program that we control since an incorrect
exploit usually leads to the program crashing. The root account allows us to
mimick this since we can relaunch the `final0` binary as many times as we want.

We first want to find the PID of the `final0` program and attach GDB to the
process.

```shell
root@protostar:/# ps aux | grep final0
root      1597  0.0  0.1   1532   276 ?        Ss   10:23   0:00 /opt/protostar/bin/final0
root      2369  0.0  0.2   3296   724 pts/0    S+   12:37   0:00 grep final0

root@protostar:/# gdb -q --pid 1597
Attaching to process 1597
Reading symbols from /opt/protostar/bin/final0...done.
Reading symbols from /lib/libc.so.6...Reading symbols from /usr/lib/debug/lib/libc-2.11.2.so...done.
(no debugging symbols found)...done.
Loaded symbols for /lib/libc.so.6
Reading symbols from /lib/ld-linux.so.2...Reading symbols from /usr/lib/debug/lib/ld-2.11.2.so...done.
(no debugging symbols found)...done.
Loaded symbols for /lib/ld-linux.so.2
accept () at ../sysdeps/unix/sysv/linux/i386/socket.S:64
64      ../sysdeps/unix/sysv/linux/i386/socket.S: No such file or directory.
        in ../sysdeps/unix/sysv/linux/i386/socket.S
```

[exploit-exercises]: https://exploit-exercises.com
[protostar-stack-writeup]: 2018-05-22-protostar-walkthrough-stack
[protostar-format-writeup]: 2018-05-27-protostar-walkthrough-format
[protostar-heap-writeup]: 2018-06-03-protostar-walkthrough-heap
