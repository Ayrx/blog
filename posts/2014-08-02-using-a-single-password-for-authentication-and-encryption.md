---
layout: post
title: Using a single password for Authentication and Encryption
---

A common scenario in web applications involve using a single password as a
means of authentication as well as a means to derive a secret for use in
encrypting data.

Many strong key derivation functions like `pbkdf2`, `bcrypt` or `scrypt` have
properties that make them strong password hashing functions as well. However,
the same derived value cannot be used as an encryption key and a password hash.
The password hash value has to be stored by the server to compare against the
provided password in future authentication attempts. If this same value is
used as an encryption key, an attacker that compromises the server will be
able to decrypt the data easily.

There is an easy solution for this problem. While I will be using `pbkdf2` as
an example, `pbkdf2` can be substituted for any strong algorithm like `bcrypt`
or `scrypt`.

1. Generate a random key `k` using a cryptographically secure random number
generator. This means using `CryptGenRandom` on Windows and `/dev/urandom` on
*nix operating systems. This random key `k` will be used for encryption.

2. Generate two salts `s1` and `s2` and store them in plaintext.

3. Compute `pbkdf2(password, s1)` and store this value. This will be the
password hash you use to compare against for future authentication attempts.

4. Compute `pbkdf2(password, s2) xor k` and store this value.

5. When the random key `k` is required for encrypting or decrypting data,
simply `xor` the value of `pbkdf2(password, s2)` against the value computed in
step 4.

The advantage of this scheme is that the encryption key `k` is not tied to the
password. This means that passwords can be changed without re-encrypting
the data with a new key repeating steps 1 - 4. A very useful property to have
in the event of a server compromise where passwords have to be reset en masse.
