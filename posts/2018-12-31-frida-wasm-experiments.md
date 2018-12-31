---
layout: post
title: Experiments with Frida and WebAssembly
---

[Frida][frida] is a very powerful mobile Dynamic Binary Instrumentation
framework that should be familiar to penetration testers or security
researcher that have done mobile work in recent years. Frida works by
injecting a JS engine into the instrumented process and is typically
controlled with JS code. Frida supports two Javascript engines.
[Duktape][duktape] is used by default but V8 is also supported (on all
platforms except iOS currently).

Interestingly, the V8 engine used in Frida is built with WebAssembly support
and any language that can compile into WebAssembly can in theory be used to
control Frida. This blog post will cover a "Hello, World" of this process, as
it does not seem to be documented anywhere.

# Preamble

Before we begin, we will need a program to instrument. We will use the
following `test.c` that simply prints "0" in a loop.

```c
#include <stdio.h>
#include <unistd.h>

int a() {
    return 0;
}

void main() {

    while (1) {
        printf("%d\n", a());
        sleep(1);
    }
}
```

We can compile the program with any standard C compiler and run it.

<img src="assets/frida-webassembly-experiments-1.svg" class="center-image" >

A typical Frida script (`mod.js`) will look something like the following:

```js
'use strict';


Interceptor.attach(Module.findExportByName(null, "a"), {

    onEnter: function (args) {
    },

    onLeave: function (retval) {
        retval.replace(1);
    }
});
```

The above script replaces the return value of the function `int a()`, causing
the instrumented `test` process to print "1" instead of "0".

The script can be attached with the following shell command:

```shell
$ frida -n test -l mod.js
```

After the script is attached, you will see the program start printing "1".

<img src="assets/frida-webassembly-experiments-2.svg" class="center-image" >

# WASM Tooling Setup

For this experiment, we will use the [Emscripten][emscripten] tooling to
compile C code to WASM.

On MacOS, the following set of shell commands is sufficient to get a working
toolchain:

```shell
$ git clone https://github.com/juj/emsdk.git
$ cd emsdk
$ ./emsdk install latest
$ ./emsdk activate latest
$ source ./emsdk_env.sh
```

The Emscripten documentation should be referred to for detailed installation
instructions.

# Experiment 1: Calling a C function from Javascript

For the first test, we want to call a C function from a typical Frida script
and use the return value.

We use the following C program:

```c
#include <emscripten.h>

int a() {
    return 41;
}
```

The `emcc` command can be used to compile C code into WASM.

```shell
$ emcc a.c -o a.js -s EXPORTED_FUNCTIONS='["_a"]' -s EXTRA_EXPORTED_RUNTIME_METHODS='["ccall", "cwrap"]' -s SINGLE_FILE=1
```

Looking at the command in more detail, we are telling `emcc` to:

1. Compile `a.c`.
2. Generate `a.js` as the output.
3. `-s EXPORTED_FUNCTIONS` tells the compiler we want to export the `a`
function from the C program. This allows the function to be called from JS
code.
4. `-s EXPORTED_RUNTIME_METHODS` tells the compiler to also export `ccall` and
`cwrap`, which are WASM methods that can be used to access the exported C
function.
5. `-s SINGLE_FILE` tells the compiler that we want the output to be a single
JS file. If this option is omitted, the compiler will emit one `.js` file and
one `.wasm` file.

Let's modify our `mod.js` file from earlier to import `a.js`.

```js
'use strict';

const em_module = require("./a.js");

Interceptor.attach(Module.findExportByName(null, "a"), {

    onEnter: function (args) {
    },

    onLeave: function (retval) {
        retval.replace(1);
    }
});
```

You will notice the following error message if you attempt to inject
`mod.js` into the `test` process.

```
ReferenceError: require is not defined
    at /repl1.js:4:19
```

You cannot actually import additional JS files with `require` when using Frida!
However, Frida does provide a program, [`frida-compile`][frida-compile], that
solves this problem. `frida-compile` compiles a Frida script that uses one or
more NodeJS modules into a single script that can be injected with Frida.

This can be done with the following set of commands (after installing
`frida-compile`).

```shell
$ frida-compile mod -o compiled.js
$ frida -n test -l compiled.js --enable-jit
```

You will notice that we now pass the `--enable-jit` option when running Frida.
This tells Frida to use the V8 engine instead of the default Duktape engine.

Now, how do we actually call the `a` function provided by the C program?

Let us modify our `mod.js` program further.

```js
'use strict';

const em_module = require("./a.js");
var replaced = em_module.ccall("a");

Interceptor.attach(Module.findExportByName(null, "a"), {

    onEnter: function (args) {
    },

    onLeave: function (retval) {
        retval.replace(replaced);
    }
});
```

You will see that we call the `a` function with `ccall` and use the return
value of `a` with our Interceptor's

But! When we try injecting the compiled `mod.js` now we run into another error.

```
Assertion failed: you need to wait for the runtime to be ready (e.g. wait for main() to be called)
```

This is because we are attempting to use a WASM function before it has fully
loaded. The [Emscripten FAQ][faq] offers us a few solutions. For this example,
we will write a `main()` function in our C program that gets called when the
WASM runtime is fully loaded. In the `main()` function, we will call a
`global.js_run()` that contains the rest of the Frida code.

```c
#include <emscripten.h>

int a() {
    return 41;
}

int main() {
    emscripten_run_script( "global.js_run()" );
}
```

We modify the `emcc` command to also include the `main()` function.

```shell
$ emcc a.c -o a.js -s EXPORTED_FUNCTIONS='["_main", "_a"]' -s EXTRA_EXPORTED_RUNTIME_METHODS='["ccall", "cwrap"]' -s SINGLE_FILE=1
```

`mod.js` is then modified to wrap the code inside the `global.js_run()`
function.

```js
'use strict';

const em_module = require("./a.js");

const js_run = function() {
    var replaced = em_module.ccall("a");

    Interceptor.attach(Module.findExportByName(null, "a"), {

        onEnter: function (args) {
        },

        onLeave: function (retval) {
            retval.replace(replaced);
        }
    });
};

global.js_run = js_run;
```

With this, the meat of the Frida script only gets executed when the WASM
runtime is fully loaded.

When the compiled `mod.js` is injected, you will notice that the `test` process
starts printing "41" after some time. It appears that loading the WASM runtime
does take a significant (a few seconds) amount of time.

# Experiment 2: Calling a Javascript function from C

For the next test, we want to call Frida functions, which are JS functions,
from our C program. The easiest way to do this is through the
`emscripten_run_script` function, which we have already used. This essentially
`eval()` inline Javascript provided as a string.

We write the following C program:

```c
#include <emscripten.h>

char *js =
"Interceptor.attach(global.Module.findExportByName(null, 'a'), {"
    "onEnter: function (args) {"
    "},"
    "onLeave: function (retval) {"
        "retval.replace(41);"
    "}"
"});";

int main() {

    emscripten_run_script( js );
}
```

And we compile it with `emcc`.

```shell
$ emcc a.c -o a.js -s EXPORTED_FUNCTIONS='["_main"]' -s EXTRA_EXPORTED_RUNTIME_METHODS='["ccall", "cwrap"]' -s SINGLE_FILE=1
```

Our JS script simply needs to `require` the `a.js` file.
```js
'use strict';

const em_module = require("./a.js");
```

When the compiled `mod.js` is injected, the `test` process starts printing "41"
after some time.

Is this the best way to do things? Probably not.` emscripten_run_script` is
simply one of many ways provided by Emscripten to interact with JS code from
a C program. It is however sufficient as a proof-of-concept.

# Conclusion

We have shown that it is possible to control Frida with the use of WASM. The
techniques shown here is basically a "Hello, World" version of what WASM can
do. There are multiple, much more advanced, ways of calling a C function from
JS code and vice versa.

Why is WASM useful when used with Frida? The most immediate usecase that comes
up will be making use of existing C libraries when writing Frida scripts. It
also allows for writing Frida scripts in a language other than Javascript /
Typescript, which can be really nice. It can also be an alternative to using
the low level C bindings that Frida provides, which is a lot less documented
than the JS functions.

I hope this has been interesting and happy hacking!

[frida]: https://www.frida.re
[duktape]: https://duktape.org
[emscripten]: https://kripken.github.io/emscripten-site/index.html
[frida-compile]: https://github.com/frida/frida-compile
[faq]: https://kripken.github.io/emscripten-site/docs/getting_started/FAQ.html#how-can-i-tell-when-the-page-is-fully-loaded-and-it-is-safe-to-call-compiled-functions
