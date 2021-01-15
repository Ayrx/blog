---
layout: post
title: Instrumenting JVM Programs With Frida
---

[Frida][frida] is very commonly used to instrument Android applications written in Java
and compiled to Dalvik bytecode. It is a less well known fact that Frida
gained support for instrumenting Java programs running on the HotSpot JVM in a
[recent version][frida-hotspot] which should work on most JVM versions running
on Linux and macOS.

Attempting to instrument a program using the default JVM shipped with most
Linux distributions should result in the following error:

```
[Local::PID::8297]-> Java.available
Error: Java API only partially available; please file a bug. Missing: _ZN6Method4sizeEb, _ZN6Method19set_native_functionEPhb, _ZN6Method21clear_native_functionEv, _ZN6Method24restore_unshareable_infoEP6Thread, _ZN6Method10jmethod_idEv, _ZN20ClassLoaderDataGraph10classes_doEP12KlassClosure, _ZN10JavaThread27thread_from_jni_environmentEP7JNIEnv_, _ZN8VMThread7executeEP12VM_Operation, _ZN11OopMapCache22flush_obsolete_entriesEv, _ZN14NMethodSweeper16sweep_code_cacheEv, _ZTV18VM_RedefineClasses, _ZN18VM_RedefineClasses4doitEv, _ZN18VM_RedefineClasses13doit_prologueEv, _ZN18VM_RedefineClasses13doit_epilogueEv, _ZNK18VM_RedefineClasses26allow_nested_vm_operationsEv, _ZN19Abstract_VM_Version19jre_release_versionEv, _ZN14NMethodSweeper11_traversalsE, _ZN14NMethodSweeper13_should_sweepE
    at P (frida/node_modules/frida-java-bridge/lib/jvm.js:143)
    at C (frida/node_modules/frida-java-bridge/lib/jvm.js:12)
    at _tryInitialize (frida/node_modules/frida-java-bridge/index.js:17)
    at v (frida/node_modules/frida-java-bridge/index.js:9)
    at <anonymous> (frida/node_modules/frida-java-bridge/index.js:312)
    at call (native)
    at o (/_java.js)
    at <anonymous> (/_java.js)
    at <anonymous> (frida/runtime/java.js:1)
    at call (native)
    at o (/_java.js)
    at r (/_java.js)
    at <eval> (frida/runtime/java.js:3)
    at _loadJava (native)
    at get (frida/runtime/core.js:114)
    at <anonymous> (<input>:22)
```

This is because Frida requires the JVM contain symbols in order to locate
specific functions required for instrumentation. The default JVM shopped with
most Linux distributions have symbols stripped.

```
$ nm /usr/lib/jvm/java-1.11.0-openjdk-amd64/lib/server/libjvm.so
nm: /usr/lib/jvm/java-1.11.0-openjdk-amd64/lib/server/libjvm.so: no symbols
```

The easiest way to obtain a JVM with symbols is by downloading a pre-built
binary from the [AdoptOpenJDK][adoptopenjdk] project. By configuring the
target program to use a JVM with symbols, Frida can then be used to instrument
the program.

```
     ____
    / _  |   Frida 14.2.3 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/

[Local::PID::10925]-> Java.available
true
```

The full power of Frida can then be leveraged for reverse engineering and
analysis of Java programs.

[frida]: https://frida.re/
[frida-hotspot]: https://frida.re/news/2020/06/29/frida-12-10-released/
[adoptopenjdk]: https://adoptopenjdk.net/index.html
