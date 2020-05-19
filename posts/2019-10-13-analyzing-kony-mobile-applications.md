---
layout: post
title: Analyzing Kony Mobile Applications
---

<div class="note">
The content in this blog post was
<a href="https://www.infosec-city.org/sg19-1-kony">presented</a> at Infosec
In The City 2019.
</div>

{:toc}

# What is Kony?

[Kony Visualizer][kony] (or Quantum, they have renamed the product a few times)
is a cross-platform application development environment. With Kony Visualizer,
a single codebase can be used to built iOS and Android applications.

Reverse engineering mobile applications built with Kony can be a challenge due
to the way the application code is packaged. Instead of compiling application
code to DEX for Android apps and Mach-O for iOS apps, the application code is
JavaScript code that is packaged in the app and loaded at runtime. This
approach renders standard mobile application reverse engineering tooling
ineffective when used on apps built with Kony.

In this blog post, we shall explore how a Kony mobile application is packaged
and how the application code is loaded when an app is launched. We shall also
present several tools that can be used to "decompile" and debug a Kony mobile
application.

The bulk of this blog post will focus on an Android application built with
Kony. We will discuss the similarities and differences of Kony iOS applications
towards the end of the post.

# Identifying a Kony mobile application

There are two strong indications that an Android application is built with
Kony.

Firstly, a Kony mobile application will have a `application.properties` and a
`pluginversions.properties` file in the `assets/` directory.

```
ls assets/ | grep ".properties"
-rw-r--r--  1 ayrx ayrx  666 Dec 31  1979 application.properties
-rw-r--r--  1 ayrx ayrx 1.1K Dec 31  1979 pluginversions.properties
```

The `application.properties` file contain information about the specific
Kony application.

```
			Splash-FG: 000000
			Splash-BG: 252b32
			Splash-LI: true
			Splash-IMG: splashscreen_fp.png
			Splash-ANIM-DURATION:
			Splash-ANIM-IMGLIST:
            Splash-VIDEO:
            Splash-VIDEO-INTERRUPTIBLE: false
			Splash-ORIENTATION : both
			BUILD: release
			AppID: fpapp
			AppMode : native
			DevLang : js
			EnableActionBar : false
			AllowSelfSignedCerts : None
			UseGooglePlayLocationServices : true
			Var:20170920223752
			UseSQLCipherFIPS : false
			UseCryptoLibrary : false
			EnableIdForAutomation : false
			DisableApplicationScreenshot : false
			isUniversalApp : false

					DefaultLocale:en_US

			EnableJSBindings : true
```

The `pluginversions.properties` file contain the version numbers of the Kony
software used to build the application.

```
Branding=8.0.0.v201709142025
Kony_Studio=8.0.0.v201709121947
Third_Party_Jars_Plug-in=8.0.0.v201709062019
Soap_UI_Plugin=8.0.0.v201709062019
Kony_Codegenerator=8.0.0.v201709081740
Kony_Studio_Licensing=8.0.0.v201709062019
CloudMiddlewarePlugin=8.0.0.GA_v201709141404_r0
CloudThirdPartyPlugin=8.0.0.GA_v201709141404_r0
Visualizer_Integration_Plugin=8.0.0.v201709081515
Kony_Studio_Cloud_Integration=8.0.0.v201709081322
Kony_Functional_Preview_Plugin=8.0.0.v201709121919
StudioViz_API=8.0.0.v201709122338
StudioViz_Chrome_API=8.0.0.v201709122338
StudioViz_Chrome=8.0.0.v201709122338
StudioViz_Core=8.0.0.v201709122338
StudioViz_NodeJS=8.0.0.v201709122338
Reference_Architecture=8.0.0.v201709062110
Tablet_Android=8.0.0.v201709122126
Windows_Phone_8_Plug-in=8.0.0.201709052108
Windows_8.1_Plug-in=8.0.0.v201709071108
Windows_10_Plug-in=8.0.0.v201709141233
Android=8.0.0.v201709122126
Windows_Desktop_Plug-in=8.0.0.v201709071010
SPA=8.0.0.v201709121455
Kony_Desktop_Web=8.0.0.v201709121449
Kony_Web_Commons=8.0.0.201709061514
iOS_Plugin=8.0.0.v201709121902
MobileFabric_Client_SDK=8.0.0.v201709111725
```

The second indication is the presence of a `assets/js/` directory. The
directory contains the JavaScript source code of the application. In release
builds of a Kony application, the source files are encrypted.

```
$ ls assets/js/
total 428K
drwxr-xr-x 2 ayrx ayrx 4.0K Mar 13  2019 .
drwxr-xr-x 5 ayrx ayrx 4.0K Mar 13  2019 ..
-rw-r--r-- 1 ayrx ayrx  57K Dec 31  1979 common-jslibs.kfm
-rw-r--r-- 1 ayrx ayrx 312K Dec 31  1979 startup.js
-rw-r--r-- 1 ayrx ayrx  48K Dec 31  1979 workerthreads.kfm
```

# Reverse Engineering

The core of the Kony framework is contained in `libkonyjsvm.so`. The shared
object is loaded with `System.loadLibrary` when the app launches.

```java
public final boolean a(int i, JSDebugAgent jSDebugAgent) {
    int i2 = 0;
    if (!this.aDN) {
        System.loadLibrary("c++_shared");
        System.loadLibrary("konyjsvm");
    }
```

The `JNI_OnLoad` function of `libkonyjsvm.so` registers a bunch of JNI methods
with the use of `RegisterNatives` as seen in the decompiled function below:

```c
jint JNI_OnLoad(JavaVM *vm)

{
  JNIEnv *env;
  jclass clazz;

  jvm = vm;
  env = getEnv();
  clazz = (*(*env)->FindClass)(env,"com/konylabs/vmintf/KonyJavaScriptVM");
  (*(*env)->RegisterNatives)(env,clazz,&KonyJavaScriptVMFuncs,0xf);
  clazz = (*(*env)->FindClass)(env,"com/konylabs/vm/Function");
  (*(*env)->RegisterNatives)(env,clazz,&FunctionFuncs,1);
  clazz = (*(*env)->FindClass)(env,"com/konylabs/vmintf/KonyJSVM");
  (*(*env)->RegisterNatives)(env,clazz,&KonyJSVMFuncs,0xe);
  return 0x10006;
}
```

`libkonyjsvm.so` contains the symbols of v8 functions. This indicates that the
shared object contains the v8 JavaScript engine.

```
v8::Locker::Initialize(v8::Isolate*)
v8::HandleScope::HandleScope(v8::Isolate*)
v8::Context::Enter()
v8::Context::Global()
v8::String::NewFromUtf8(v8::Isolate*, char const*, v8::String::NewStringType, int)
v8::Object::Set(v8::Local<v8::Value>, v8::Local<v8::Value>)
v8::Context::Exit()
v8::HandleScope::~HandleScope()
v8::Locker::~Locker()
```

When the app is first launched, the `KonyJSVM_loadFilesToVM` function is
called. The `KonyJSVM_loadFilesToVM` function performs three main functions:

1. Derive the decryption key
2. Decrypt the application source code
3. Load the decrypted source code into v8

## Key Derivation Routine

The key derivation routine from `KonyJSVM_loadFilesToVM` is as follows:

```c
memset(passwdBeforeHash,0,0x100);
s1 = getTime(env,thiz);
s1_len = strlen(s1);
_charxor(s1,s1_len);
strcat(passwdBeforeHash,s1);
free(s1);
s2 = getN(env,thiz);
s2_len = strlen(s2);
_charxor(s2,s2_len);
s3 = getPackageName(env,thiz);
strcat(passwdBeforeHash,s2);
free(s2);
s3_len = strlen(s3);
charxor(s3,s3_len);
strcat(passwdBeforeHash,s3);
free(s3);

... snip ...

passwdBeforeHash_len = strlen(passwdBeforeHash);
simpleSHA256(passwdBeforeHash,passwdBeforeHash_len,&passwdAfterHash);
```

The `getTime`, `getN` and `getPackageName` functions call out to the
`getTimeStamp`, `getN` and `getName` Java methods in the class
`com.konylabs.android.KonyMain`.

The `getTimeStamp` method reads the "Var" key ("VmFy" base64 decoded) from the
`application.properties` file. The "Var" value is the timestamp of when the
APK file was built.

```java
public static String getTimeStamp() {
    return L.getProperty(new String(Base64.decode("VmFy", 0)));
}
```

The `getN` method reads the "AppID" key from the `application.properties` file.
The "AppID" value is a Kony specific identifier for the application.

```java
public static String getN() {
    return getActivityContext() != null ? getActivityContext().getClass().getSimpleName() : L.getProperty("AppID");
}
```

The `getName` method returns the Android package name of the application using
the `Context.getPackageName` Android API.

```java
public static String getName() {
    return I.getPackageName();
}
```

The bytes obtained from the `getTime`, `getN` and `getPackageName` function
calls are mixed with a secret key contained in the binary through the `charxor`
and `_charxor` functions. The (cleaned up) decompiled function implementations
are as follows:

```c
void charxor(byte *a0,int ao_len)
{
  byte tmp;
  int i;
  uint i2;
  byte charxor_key [16];
  uint i1;

  charxor_key._0_4_ = 0xdf337baa;
  charxor_key._4_4_ = 0xaf86c611;
  charxor_key._8_4_ = 0xb91e4d2b;
  charxor_key._12_4_ = 0xffb4416d;
  if (0 < ao_len) {
    i = 0;
    do {
      tmp = *a0;
      i1 = (i >> 0x1f) >> 0x1c;
      i2 = i + i1;
      i = i + 1;
      if (tmp == 0x2e) {
        tmp = 0x2d;
      }
      *a0 = tmp ^ charxor_key[(i2 & 0xf) - i1];
      a0 = a0 + 1;
    } while (i != ao_len);
  }
}

void _charxor(byte *a0,int a0_len)
{
  int i;
  uint i2;
  byte _charxor_key [12];
  byte tmp;
  uint i1;

  _charxor_key._0_4_ = 0xd235dfcc;
  _charxor_key._4_4_ = 0xf1f664f1;
  _charxor_key._8_4_ = 0x4a9f223d;
  if (0 < a0_len) {
    i = 0;
    do {
      tmp = *a0;
      i1 = (i >> 0x1f) >> 0x1c;
      i2 = i + i1;
      i = i + 1;
      *a0 = tmp + ((tmp / 0xd) * -9 - (tmp * 0x4ec4ec4f >> 0x20 & 0xfc)) ^
            _charxor_key[(i2 & 0xf) - i1] ^ tmp;
      a0 = a0 + 1;
    } while (i != a0_len);
  }
}
```

## Encryption Algorithm

It was difficult to determine the encryption algorithm used to encrypt the
source files from reverse engineering the `libkonyjsvm.so` shared object as
there were no obvious symbol names indicating the algorithm.
[FindCrypt][findcrypt] did not return any definitive results either.


However, we were able to determine the encryption algorithm from looking at the
`kony_loadfile.exe` binary. `kony_loadfile.exe` is a PE binary invoked by the
Windows version of the Kony IDE during the application build process and its
main task appears to be to encrypt the application source files during the
build.

After decompiling the application, we see references to the OpenSSL
function `EVP_aes_256_cbc` which indicates that the encryption algorithm is
AES-256 in CBC mode.

```c
alg = EVP_aes_256_cbc();

... snip ...

EVP_CIPHER_CTX_init(&ctx);
EVP_EncryptInit(&ctx, alg, &key, &iv);
```

We were also able to determine that the Initialization Vector (IV) is a fixed
string, `abcd1234efgh5678`.

# Kony Unpacker

The main requirement to decrypt the application source files will be deriving
the encryption key which is unique for each application (and each version of
the application) due to the components (timestamp, Kony AppID, Android package
name) used during the key derivation process.

The following options were considered:

1. Re-implement the key derivation algorithm.
2. Extract the derived key from the application at runtime.
3. Emulate the `libkonyjsvm.so` shared library and run the key derivation
function.

We decided on Option 2 as it requires the least amount of effort. However,
Option 3 should be kept in mind if the application being analyzed has strong
anti-debugging protections in place.

To extract the derived key at runtime, we wrote a Frida script. [Frida][frida]
is a Dynamic Binary Instrumentation (DBI) framework that allows us to
instrument, read and modify an application at runtime.

Revisiting the key derivation routine in `KonyJSVM_loadFilesToVM`, the most
appropriate location to hook is the call to `simpleSHA256` function at the end
of the routine. More specifically, we want to extract the contents of the
`passwdAfterHash` array after the function has ran as that is where the output
of the function is written to.

```c
simpleSHA256(passwdBeforeHash,passwdBeforeHash_len,&passwdAfterHash);
```

The core of the Frida script is as follows:

```js
Interceptor.attach(Module.getExportByName("libkonyjsvm.so", "simpleSHA256"), {
    onEnter: function(args) {
	    console.log("[+] Hooked simpleSHA256!");
	    this.a = args[2]
    },
    onLeave: function(retval) {
	    send("key", Memory.readByteArray(this.a, 32));
	    Interceptor.detachAll();
    }
})
```

We attach an Interceptor to the `simpleSHA256` function and read 32 bytes from
`passwordAfterHash` after the function has returned. We read 32 bytes from the
array as we know the encryption algorithm is AES-256 and the key length of
AES-256 is 32 bytes (256 bits).

After obtaining the derived key, we can easily write a Python script to
extract the encrypted source files from the APK file and decrypt them. A link
to a full implementation of an unpacker will be provided towards the end of the
post.

# Kony Debugger

A working debugger for Kony applications will be very useful for performing
dynamic analysis. While we can use `gdb` on a Kony application, it is not
feasible to map the view that `gdb` gives us back to the JavaScript code we
know a Kony application is written in. What we want is a debugger that
understands the semantics of the runtime environment.

Like very good application development platform, the Kony IDE has [debugging
capabilities][kony-debugger]. The official debugger requires the application
be built in debug mode, which makes it useless for reverse engineering release
builds of the applications. However, it was interesting to note that the
official Kony IDE debugger uses Chrome DevTools, which meant that debugging
capabilities were built around standard v8 functions.

## A detour into the history of v8 debugging

Old versions of v8 shipped with a debugging agent that listens on a TCP port
and waits for a debugger client to connect. This agent was enabled through the
`v8::Debug::EnableAgent` method.

Around v8 version 3.27, this debugging agent was removed. Consumers of v8 such as
node.js that wanted to maintain compatibility with existing debugger clients
reimplemented the agent themselves.

Eventually, the entire `v8::Debug` API was deprecated in favor of the new
[Inspector Protocol][inspector-protocol] which is what current versions of
Chrome (and Chrome DevTools) uses.

## What about Kony?

Current versions of Kony use a version of v8 that is post
`v8::Debug::EnableAgent` removal but before the Inspector Protocol was added.

```c
char * GetVersion(void)
{
  return "5.3.332.41";
}
```

This should mean that Kony has additional code in the debug builds of the
application that reimplemented the remote debugging agent. Looking at the
differences between a release build and a debug build, we found that the
application was almost exactly the same except that the debug build packaged
a different `libkonyjsvm.so` shared object.

A [binary diff][diaphora] between the release `libkonyjsvm.so` and the debug
`libkonyjsvm.so` showed that the debug shared object contained some additional
JNI functions:

```
JSDebugAgent_Start
JSDebugAgent_ProcessDebugMessages
JSDebugAgent_SendCommand
JSDebugAgent_Connect
JSDebugAgent_Disconnect
JSDebugAgent_MessageHandler
```

The corresponding `com.konylabs.js.debug.JSDebugAgent` Java class _was still
present_ in the compiled DEX files of the release APK.

## Implementing the debugger

The first step we need to do is repackage the APK file with the debug version
of `libkonyjsvm,so`. The shared object can be extracted from the Kony
IDE installer which can be downloaded from their [website][kony-installer].
The version of the installer should match the version of Kony used to build
the application to minimize any compatibility issues. A link to a patching
script will be provided towards the end of the post.

Once we have repackaged the APK and installed it on an Android device, we wrote
the following Frida script to call the neccessary Java methods to enable the
debugger.

```js
"use strict";

Java.perform(function() {

    var konyMain = Java.use("com.konylabs.android.KonyMain");
    console.log(konyMain);
    var c = Java.use("com.konylabs.vmintf.c");

    // The method called by konyMain will change depending on the specific
    // APK. Use dex2jar and look for the method that returns a Handler.
    Java.choose("com.konylabs.vmintf.KonyJavaScriptVM", {
        onMatch: function (instance) {
            konyMain.N().post(c.$new(instance, 9222));
        },
        onComplete: function() {}
    })
})
```

The script _will_ require app-specific modification as the method that we need
to call will have the name obfuscated. Decompile the APK with `jadx` or a
similar tool and look for the method in `com.konylabs.android.KonyMain` that
returns a `Handler` object (there will only be one such method) and modify
the script to call that method.

```java
public static Handler N() {
    return H.mHandler;
}
```

The final hurdle to overcome is the fact the modern Chrome DevTools _does not_
support the old Debug API any longer. The Kony IDE most likely has code
implemented to bridge between the old Debug API and the new Inspector protocol.

Instead of implementing the bridge, we use a debugger that still supports the
old Debug API. In this case, we can use [VSCode][vscode] with the `launch.json`
the specifies the `legacy` protocol.

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "node",
            "request": "attach",
            "name": "Attach to Remote",
            "address": "localhost",
            "port": 9222,
            "localRoot": "${workspaceFolder}",
            "remoteRoot": "Absolute path to the remote directory containing the program",
            "protocol": "legacy",
        },
    ]
}
```

# Kony on iOS

Due to time constraints, not much effort was spent on reversing the framework
on iOS. Instead, a quick runtime debugging effort was done to confirm the
assumption that Kony on iOS is implemented in a similar way as Kony on Android.

These are the findings:

1. The [CommonCrypto][commoncrypto] `CCCryptor*` family of functions were
present in the Mach-O binary.
2. The `CCCryptor*` functions were called when the application was launched.
3. Instead of a fixed IV, a different IV was used for each application.
4. JavaScriptCore was used instead of v8 (due to iOS restrictions on
third-party JS engines).

## Unpacker for iOS

We can hook the `CCCryptorCreate` function and extract the key and IV used
for decryption.

```c
CCCryptorStatus CCCryptorCreate(
    CCOperation op,             /* kCCEncrypt, etc. */
    CCAlgorithm alg,            /* kCCAlgorithmDES, etc. */
    CCOptions options,          /* kCCOptionPKCS7Padding, etc. */
    const void *key,            /* raw key material */
    size_t keyLength,
    const void *iv,             /* optional initialization vector */
    CCCryptorRef *cryptorRef)   /* RETURNED */
```

A link to a full implementation of an unpacker will be provided towards the
end of the post.

## Debugger for iOS

In the limited time spent looking at the framework on iOS, no easy method of
enabling the debugger was found. As a workaround, application logic can be
debugged on the Android version of the app as the two versions should share
similar code outside of platform specific interactions.

# Tools

All implemented unpacker and debugger scripts can be found on
[https://github.com/CenturionInfoSec/konyutils][konyutils]. The README files
in the repository should provide clear instructions on how to run the various
tools.

# Credits

The following links are previous efforts into reverse engineering the Kony
framework. While the content have been made obselete due to changes in more
recent versions of Kony, they were still very helpful as a starting point for
the research:

* [Kony 2013 - A different kind of Android reversing][ncc-kony]
* [Deconstructing Kony Android Applications (2015)][weedon-kony]

[kony]: https://www.kony.com/products/quantum/
[findcrypt]: https://github.com/d3v1l401/FindCrypt-Ghidra
[frida]: https://frida.re/
[kony-debugger]: https://docs.kony.com/konylibrary/visualizer/visualizer_user_guide/Content/Inline_Debugger.htm
[inspector-protocol]: https://v8.dev/docs/inspector
[diaphora]: https://github.com/joxeankoret/diaphora
[kony-installer]: https://community.kony.com/downloads/archive
[vscode]: https://code.visualstudio.com/
[commoncrypto]: https://opensource.apple.com/source/CommonCrypto/
[konyutils]: https://github.com/CenturionInfoSec/konyutils
[ncc-kony]: https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2013/june/kony-2013-a-different-kind-of-android-reversing/
[weedon-kony]: https://www.blackhat.com/docs/ldn-15/materials/london-15-Weedon-Deconstructing-Kony-Android-Apps.pdf
