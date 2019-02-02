---
layout: post
title: Look before you pip
---

For Python programmers, downloading Python packages from PyPI, the Python
Package Index, is second nature. Tools like `pip` and conventions like the
`requirements.txt` file that most Python projects follow provides a consistent
way of specifying project dependencies.

However, installing random packages from PyPI is actually very dangerous,
a fact that not many people are aware of. There are a few factors that
contribute to this.

1. Python packages can execute arbitrary Python code during the installation
process.

2. PyPI packages are not moderated. Unlike the package managers used in Linux
distros, anyone can register an account and upload Python packages without
going through a review process. While this is one factor contributing to
PyPI's success as a package repository, you will have to trust the maintainer
of the package that the package is safe.

As a proof of concept, I have written a `setup.py` file that connects to a
Metasploit listener and downloads a Meterpreter shell during installation.
This demonstrates that it is *trivial* for someone to execute arbitrary code
on a machine through the installation of a Python package. You can obtain the
code from [GitHub](https://github.com/Ayrx/malicious-python-package).

Run the Metasploit listener.

```shell
msf > use exploit/multi/handler
msf exploit(handler) > set payload python/meterpreter/reverse_tcp
msf exploit(handler) > set LHOST 127.0.0.1
```

Finally, run the setup.py file.

```shell
python setup.py install
```

You should obtain a Meterpreter shell with the same privileges that you ran
the `setup.py` script with.

While my example involves connecting to a Metasploit listener on `localhost`,
the same attack can be extended to install malware from remote systems or do
almost anything a Python script can do.

The problematic thing about this attack is that there *are* valid reasons for
Python packages to execute code during installation. This ranges from things
like OS version checks to compiling C code for packages that rely on C
extensions. Restricting `setuptools` to a subset of Python during installation
isn't exactly foolproof as demonstrated by the numerous Python sandbox escape
techniques. Moderating PyPI isn't a solution either as that will greatly
diminish PyPI's attractiveness as a package repository.

Here are two recommendations to limit the potential of such attacks.

1. **NEVER** install Python packages as root. This limits the privileges an
attacker has if the attack succeeds. `virtualenv` is incredibly useful for
this.

2. If you are in an organization with larger resources, *audit* the
third-party packages you depend on. Mirror trusted packages on an internal
[devpi](http://doc.devpi.net/latest/) server instead of installing packages
directly from PyPI.

While I am limiting the details in this post to Python packages as that is the
ecosystem I am most familiar with, I believe that this issue also extends to
other languages and ecosystems such as Ruby and the gems ecosystem. While there
has been an increased focus over the years on paying attention to good security
practices when writing code, many forget about third-party code. This worries
me because third-party code represents such a large attack surface open to
exploits. As we all know, security is only as strong as the weakest link.
