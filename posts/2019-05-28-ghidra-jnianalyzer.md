---
layout: post
title: "Ghidra Plugin: JNIAnalyzer"
---

When reversing Android applications with native code, providing type
information to your reverse engineering tool can make a decompilation a lot
more readable.

As an example, the following snippet of code is the Ghidra decompiler output of
a function from the `libfoo.so` of [UnCrackable-Level3][uncrackable-3]:

```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void Java_sg_vantagepoint_uncrackable3_MainActivity_init
               (int *param_1,undefined4 param_2,undefined4 param_3)

{
  char *__src;

  FUN_00013250();
  __src = (**(*param_1 + 0x2e0))(param_1,param_3,0);
  strncpy(&DAT_0001601c,__src,0x18);
  (**(*param_1 + 0x300))(param_1,param_3,__src,2);
  DAT_00016038 = DAT_00016038 + 1;
  return;
}
```

If we tell Ghidra that the first parameter has the type `JNIEnv *`, like all
JNI functions do, the decompiler output immediately becomes easier to parse.

```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void Java_sg_vantagepoint_uncrackable3_MainActivity_init
               (JNIEnv *env,jobject thiz,jbyteArray param_3)

{
  jbyte *__src;

  FUN_00013250();
  __src = (*(*env)->GetByteArrayElements)(env,param_3,NULL);
  strncpy(&DAT_0001601c,__src,0x18);
  (*(*env)->ReleaseByteArrayElements)(env,param_3,__src,2);
  DAT_00016038 = DAT_00016038 + 1;
  return;
}
```

For example, we now see that the third line in the function is actually a call
to the JNI function `GetByteArrayElements` instead of seeing it as a call to an
arbitrary function pointer at an offset.

```c
// before
__src = (**(*param_1 + 0x2e0))(param_1,param_3,0);

//after
__src = (*(*env)->GetByteArrayElements)(env,param_3,NULL);
```

Ghidra also helpfully detects that the third parameter has the type of
`jbyteArray` even if we did not define it as it gets passed to
`GetByteArrayElements`.

# Automation with the Ghidra API

<div class="note">

<p>
<b>Update: 2020-04-12</b>
</p>
<p>
JNIAnalyzer now contains the APK parsing function originally implemented in
FindNativeJNIMethods. The Ghidra extension will now ask for an APK file instead
of the FindNativeJNIMethods JSON output.
</p>
</div>

Defining the data type for JNI functions manually is a tedious task that can be
automated. As JNI functions will have a corresponding method in Java, we can
decompile the Dalvik bytecode in an Android app to look for those type
definitions. I wrote a simple wrapper around [JADX][jadx] called
[FindNativeJNIMethods][FindNativeJNIMethods] to do that automatically.

```shell
$ java -jar FindNativeJNIMethods.jar UnCrackable-Level3.apk defs.json
$ cat defs.json | python -m json.tool
{
    "methods": [
        {
            "argumentTypes": [
                "jbyteArray"
            ],
            "methodName": "sg.vantagepoint.uncrackable3.CodeCheck.bar"
        },
        {
            "argumentTypes": [],
            "methodName": "sg.vantagepoint.uncrackable3.MainActivity.baz"
        },
        {
            "argumentTypes": [
                "jbyteArray"
            ],
            "methodName": "sg.vantagepoint.uncrackable3.MainActivity.init"
        }
    ]
}
```

Next, I wrote a Ghidra plugin called [JNIAnalyzer][JNIAnalyzer] that parses
the JSON output of FindNativeJNIMethods and apply it to the binary being
analyzed. Once the extension has been loaded into Ghidra, run the
`JNI/JNIAnalyzer.java` script and select the `defs.json` file generated
previously.

You will see the following output in Ghidra's scripting console:

```shell
JNIAnalyzer.java> Running...
JNIAnalyzer.java> [+] Import jni_all.h...
JNIAnalyzer.java> [+] Enumerating JNI functions...
JNIAnalyzer.java> Java_sg_vantagepoint_uncrackable3_MainActivity_init
JNIAnalyzer.java> Java_sg_vantagepoint_uncrackable3_MainActivity_baz
JNIAnalyzer.java> Java_sg_vantagepoint_uncrackable3_CodeCheck_bar
JNIAnalyzer.java> Total JNI functions found: 3
JNIAnalyzer.java> [+] Applying function signatures...
JNIAnalyzer.java> Finished!
```

The function in `libfoo.so` now has the correct (and complete) type definition
for the parameters.

```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void Java_sg_vantagepoint_uncrackable3_MainActivity_init(JNIEnv *env,jobject thiz,jbyteArray a0)

{
  jbyte *__src;

  FUN_00013250();
  __src = (*(*env)->GetByteArrayElements)(env,a0,NULL);
  strncpy(&DAT_0001601c,__src,0x18);
  (*(*env)->ReleaseByteArrayElements)(env,a0,__src,2);
  DAT_00016038 = DAT_00016038 + 1;
  return;
}
```

As a quick explanation on how the extension works, the script does the
following:

1. Imports the JNI data types from an archive parsed from
[jni_all.h][jni_all.h].
2. Parses the selected JSON file containing the function definitions.
3. Iterates over all functions in the binary looking for those with names that
begin with `Java_`.
4. Based on the name, it looks up the corresponding function definition and
apply it. For example, the native method
`Java_sg_vantagepoint_uncrackable3_MainActivity_init` will be matched to the
`init` method of the `sg.vantagepoint.uncrackable3.MainActivity` class.


As the script assumes that all JNI functions have names that begin with
`Java_`, it will miss functions that are loaded at runtime through
`RegisterNatives` unless you first rename those functions to fit the expected
naming convention.

I have a few more potentially useful ideas to implement so I will probably
update the extension in the near future. I hope someone else also finds this
useful!

[uncrackable-3]: https://github.com/OWASP/owasp-mstg/blob/master/Crackmes/Android/Level_03/UnCrackable-Level3.apk
[jadx]: https://github.com/skylot/jadx
[FindNativeJNIMethods]: https://github.com/Ayrx/FindNativeJNIMethods
[JNIAnalyzer]: https://github.com/Ayrx/JNIAnalyzer
[jni_all.h]: https://gist.github.com/Jinmo/048776db75067dcd6c57f1154e65b868
