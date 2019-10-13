---
layout: post
title: Deconstructing Kony (7) Android Applications
---

_Note: A more complete writeup on Kony was published at [Analyzing Kony Mobile
Applications][analyzing-kony]_


# What is Kony?

Kony is a mobile app development platform that allows a developer to build
mobile applications in HTML5 and JavaScript that can be built for different
platforms like iOS and Android.

Analyzing an Android APK file built with Kony requires a different approach as
normal tools such as `apktool` do not work. This is because the application
logic is actually contained in a ZIP archive of JavaScript source files that
gets loaded into a JavaScript VM that is shipped in the APK.

# Previous Work

The BlackHat 2015 talk
["Deconstructing Kony Android Applications"][kony-blackhat] by Chris Weedon
contains detailed information on how to recover the JavaScript source files
from an APK file.

We will go briefly take a look at how to obtain the source files for each major
Kony revision. For more details, reading through the slide deck is highly
recommended.

## Kony versions < 6.0

In older versions of Kony, a Lua bytecode interpreter is used instead of a
JavaScript VM. The APK ships Lua bytecode instead of JavaScript source files.
We can recognize APKs built with this version of Kony if we find a
`konyappluabytecode.o.mp3` file in the unzipped APK directory.

If we encounter APKs built with this version of Kony, we can use
[`unluac.jar`][unluac] to decompile the Lua bytecode.

## Kony version 6.0+ (Unencrypted)

From Kony 6.0 on, Lua support was deprecated and JavaScript support was
introduced. We can recognize APKs built with the newer versions of Kony if we
find a `lib/libkonyjsvm.so` file in the unzipped APK directory.

Initially, the JavaScript source files was shipped as an unencrypted ZIP
archive. If we see that `assets/js/startup.js` is a ZIP archive, we can simply
unzip the archive to retrieve the JavaScript source files.

## Kony version 6.0+ (Encrypted)

At some point in the Kony 6 lifecycle (the BlackHat talk mentions 6.3), the
ZIP file is now encrypted. We can recognize APKs built with this version of
Kony if `assets/js/startup.js` is seen as a data file (instead of a ZIP
archive). The encryption scheme used is `AES_256_CBC` with a hardcoded key
that undergoes a series of transformations that is described in the BlackHat
talk.

We can use the method described in the talk to decrypt the ZIP archive without
reverse engineering the key transformation logic. This method takes advantage
of the fact that the `kony_loadfile.exe` binary which is used in the build
process to encrypt the ZIP archive calls out to OpenSSL's `EVP_CipherInit`
function that has an integer parameter to indicate whether the function is
used for encryption or decryption. If we patch that parameter in the binary,
we can change `kony_loadfile.exe` from an encryptor to a decryptor.

We can call the patched binary (`kony_decryptfile.exe`) like below to decrypt
the ZIP archive.

```shell
$ kony_decryptfile.exe <infile> <outfile> <app id> <package name> <timestamp>
```

The `package name` parameter can be found in the `AndroidManifest.xml` file
while the `app id` and `timestamp` parameters can be found in the
`assets/application.properties` file as the values of the `AppID` and `Var`
keys respectively.

The outfile file should be a ZIP archive containing the JavaScript source
files.

# Kony version 7.0+

In yet another update to Kony, `kony_loadfile.exe` has now been changed to use
OpenSSL's newer `EVP_EncryptInit` function. This means that the method of
patching a byte in `kony_loadfile.exe` to turn it into a decryptor no longer
works. It also appears that the hardcoded key has been changed so using an old
version of `kony_loadfile.exe` will not work.

However, since the encryption process still uses a hardcoded key, we can use
a debugger to pull the encryption key (after the `kony_loadfile.exe` binary
performs the key transformation logic) from process memory.

1. Set a breakpoint right before the call to `EVP_EncryptInit`. In the binary
I am working with, this is address `0x004013A9`.
2. Run the binary with the same parameters. `kony_loadfile.exe <infile> <outfile> <app id> <package name> <timestamp>`.
3. Step through the program until we hit the breakpoint.
4. Pull the 32 bytes of key material from the stack. In the binary I am working with, this is the stack address pointed at by the `eax` register.

Once we have the key material from the stack, we can write a Python script to
decrypt the file we want. After a little reverse engineering of the code, we
see that a static IV, `abcd1234efgh5678`, is used for the AES encryption step.

```python
import binascii

import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def main():

    if len(sys.argv) != 4:
        print("Usage: ./decrypt.py <infile> <outfile> <keyfile>")
        return

    IN_FILE = sys.argv[1]
    OUT_FILE = sys.argv[2]
    KEY_FILE = sys.argv[3]

    backend = default_backend()

    with open(KEY_FILE, "rb") as f:
    key = f.read()

    iv = b"abcd1234efgh5678"

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    with open(IN_FILE, "rb") as f:
        ciphertext = f.read()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(OUT_FILE, "wb") as f:
        f.write(plaintext)


    if __name__ == "__main__":
        main()
```

After we decrypt the file, we should see a ZIP archive.

```shell
$ python3 decrypt.py app/assets/js/startup.js startup.js.zip key.bin
$ file startup.js.zip
startup.js.zip: Zip archive data, at least v1.0 to extract
```

[analyzing-kony]: 2019-10-13-analyzing-kony-mobile-applications
[kony-blackhat]: https://www.blackhat.com/docs/ldn-15/materials/london-15-Weedon-Deconstructing-Kony-Android-Apps.pdf
[unluac]: http://hg.code.sf.net/p/unluac/hgcode
