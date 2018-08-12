---
layout: page
title: Open Source Projects
---

I contribute to open source projects and release tools and libraries. A full
list of projects can be found on my [GitHub][github]. Here are some of the more
interesting ones:

# atriage

[atriage](https://github.com/Ayrx/atriage) is a triage tool for fl-fuzz that
is written in Python. It attempts to de-dupe crash cases and perform
exploitability analysis.

# python-fastpbkdf2

[python-fastpbkdf2](https://github.com/Ayrx/python-fastpbkdf2) are Python
bindings for the fastpbkdf2 library. It offers a standard library compatible
interface with a large improvement in speed.

# python-aead

[aead](https://github.com/Ayrx/python-aead) is a Python library that provides
authenticated encryption with associated data (AEAD) wrapped up in a simple to
use API. It is essentially `AES_128_CBC` and `HMAC_SHA_256` composed with an
encrypt-then-mac construction and relies on PyCA's `cryptography` library for
the cryptographic primitives.

See my [blog post](2014-12-29-python-aead) about the library for
more information.

# tlsenum

[tlsenum](https://github.com/Ayrx/tlsenum) is a pure Python TLS enumeration
tool that attempts to enumerate what TLS cipher suites a server supports and
list them in order of priority. It also performs various tests that checks
things like supported versions of TLS and support for TLS-level compression.

# PyCA's cryptography

[cryptography](https://cryptography.io/en/latest/) is the most up-to-date and
widely used cryptography library for Python. I contributed a fair amount of
patches to it. A full list of my merged commits can be found on
[GitHub](https://github.com/pyca/cryptography/commits?author=Ayrx).

[github]: https://github.com/Ayrx
