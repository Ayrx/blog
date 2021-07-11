---
layout: post
title: An interesting crypto vulnerability
---

I came across an interesting tweet by Juliano Rizzo.

![Tweet image](../images/julianor-tweet.png)

The correct answer is that the statement is true if several (very unlikely to
happen in the real world) conditions are met. Let us take a look at why it
happens and what conditions have to be met for this to work.

## 1. HMAC

I quote from [[RFC2104]] Section 2.

> The authentication key K can be of any length up to B, the block length of
the hash function. Applications that use keys longer than B bytes will first
hash the key using H and then use the resultant L byte string as the actual key
to HMAC.

This means that for keys that are longer than the block size of the hash used
for the HMAC (>64 bytes in the case of SHA1), `HMAC(key) == HMAC(HASH(key))`.

```python
>>> import hashlib
>>> import hmac
>>> key1 = b"This is a very long key, a very very long key indeed. This key is absurdly long."
>>> key2 = hashlib.sha1(key1).digest()
>>> hmac.new(key1, b"msg", "sha1").digest)
b'\xac\x87j&\xc6}\xa3\xc4\xf2$z\x06\x19\x87\\e\x81N\xcei'
>>> hmac.new(key2, b"msg", "sha1").digest)
b'\xac\x87j&\xc6}\xa3\xc4\xf2$z\x06\x19\x87\\e\x81N\xcei'
```

## 2. PBKDF2 (and Scrypt)

PBKDF2 essentially boils down to applying HMAC a number of times to a key in a
loop. Thus, the property of HMAC mentioned in the previous section applies to
PBKDF2(as well as Scrypt, which uses PBKDF2 internally).

```python
>>> import hashlib
>>> key1 = b"This is a very long key, a very very long key indeed. This key is absurdly long."
>>> key2 = hashlib.sha1(key1).digest()
>>> hashlib.pbkdf2_hmac("sha1", key1, b"salt", 1)
b'\xf1\x18\xa4J]y\xf6\x85J\x8eq\xef\xea\x16>\x826+\x7f\xc8'
>>> hashlib.pbkdf2_hmac("sha1", key2, b"salt", 1)
b'\xf1\x18\xa4J]y\xf6\x85J\x8eq\xef\xea\x16>\x826+\x7f\xc8'
```

So, how does this result in a vulnerability?

If Dropbox had decided to switch from SHA1 to PBKDF2\_HMAC\_SHA1 instead of
Bcrypt, any attacker that manage to obtain dumps of the SHA1 hashed password
_and_ the PBKDF2\_HMAC\_SHA1 hashed passwords can authenticate as any users
that a. have passwords longer than 64 bytes and b. reused the same password in
the switch without cracking the password hash.

So why isn't this likely to be a problem? There are a number of unlikely
conditions that have to be fulfilled first.

1. The attacker has to have access to both the SHA1 _and_ the
PBKDF2\_HMAC\_SHA1 password dumps. This would require Dropbox to keep the old
SHA1 hashed passwords around together with the new PBKDF2\_HMAC\_SHA1 hashed
passwords _or_ that the attacker managed to dump the database both before and
after the algorithm switch.

2. Users have to use passwords longer than 64 bytes. This is _very_ uncommon
even for users who use password managers or passphrases.

3. Users have to reuse the _same_ password before and after the algorithm
switch. This is especially unlikely to happen because users who are
security-consious enough to use passwords longer than 64 bytes most likely
will not reuse passwords.

So there you have it, a very unlikely set of circumstances that if fulfilled
can potentially result in a very interesting vulnerability.
