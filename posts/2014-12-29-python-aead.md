---
layout: post
title: Introducing python-aead
---

Cryptography libraries often have complicated APIs with many different options
to tweak. It is a goal PyCA's `cryptography` library to provide safe and easy
to use APIs for common cryptographic tasks. To that end, the `cryptography`
package has a `Fernet` recipe for symmetric encryption derived from the
original [Ruby implementation][ruby-fernet] and specification. However, the
Fernet recipe lacks the ability to authentiate (without encrypting) arbitrary
data.

To make up for that use case not being covered by Fernet, I have written and
released on PyPI a library called `aead`. It can be installed with `pip`.

```
$ pip install aead
```

The `aead` library is based on a [IETF Internet Draft][aead-draft] from David
McGrew. It is essentially `AES_128_CBC` and `HMAC_SHA_256` composed with an
encrypt-then-mac construction. It relies on the `cryptography` library for
the cryptographic primitives.

It has a simple to use API heavily inspired by the Fernet recipe in the
`cryptography` library.

The module contains a single class that can be imported.

```python
from aead import AEAD
```

The class takes requires an encryption key to be initialized. The key has to be
32 bytes long and encoded with base64url as specified in RFC 4648. The library
provides a `classmethod` to generate a suitable random key.

```python
cryptor = AEAD(AEAD.generate_key())
```

After initializing the object, encryption can be done by calling the
`.encrypt()` method. The `.encrypt()` method takes two paremeters, the first
being the data you want to encrypt and the second being associated data that
you want to authenticate but not encrypt. The second parameter is optional and
can be left out if there isn't any data to authenticate.

```python
ct = cryptor.encrypt(b"Hello, World!", b"Additional Data")
```python

`.encrypt()` returns base64url encoded cipher text.

Decrypting any data encrypted with `aead` is similar. Simply call `.decrypt()`
in place of `.encrypt()`. The `.decrypt()` method takes two parameters, the
first being the cipher text that needs decrypting and the second being the
associated data that was authenticated.

If the cipher text is corrupted or the associated data provided during the
decryption process does not match the associated data provided during
encryption, a `ValueError` is raised, otherwise the decrypted plain text is
returned.

The repository for `aead` can be found on [GitHub][aead-github] and the
`README.md` file in the repository should be treated as the source of truth
if any information there differs from this blog post due to changes over time.

[ruby-fernet]: https://github.com/fernet/fernet-rb
[aead-draft]: http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05
[aead-github]: https://github.com/Ayrx/python-aead
