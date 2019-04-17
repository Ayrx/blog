---
layout: post
title: Notes on compiling the Android Kernel for AVD
---

Recently, I needed to compile a custom Android kernel for a research project
that required a newer kernel version (as well as a few kernel configs) than
what was available from the standard [Android emulator][avd] images.

It took a while for me to get things working properly so here are the steps I
used as documentation.

# Compiler Toolchain

The compilation process must be done with the toolchain provided by AOSP. A
prebuilt version can be found at
https://android.googlesource.com/platform/prebuilts/gcc/.

Set the following environmental variables on your build machine based on the
_target_ platform you are building for:

```shell
export ARCH=x86_64
export CROSS_COMPILE=x86_64-linux-android-
```

The `bin/` directory from the compiler toolchain repository should also be
added to the path.

# Kernel

The _goldfish_ kernel should be used when building for the Android emulator.
The repository can be found at https://android.googlesource.com/kernel/goldfish.

There are multiple branches depending on which kernel version you wish to
build. From _my_ results, the `android-*` branches do not work properly while
the `android-goldfish-*` branches do. If you have issues running your compiled
kernel, try using another branch instead.

Generate a default kernel config before customizing it with `make menuconfig`.
You should end up with a working kernel at `arch/x86/boot/bzImage` after
running the following series of commands:

```shell
make x86_64_ranchu_defconfig
make menuconfig
make -j4
```

# Running in the emulator

Start the AVD using the compiled kernel with the following command:

```shell
./emulator -avd <avd name> -kernel <bzImage> -show-kernel -no-snapshot-load -ranchu
```

The key flag here appears to be the `-ranchu` flag, which tells the emulator to
use the newer Ranchu engine instead of the old QEMU one. The emulator did not
boot properly for me without that flag.

[avd]: https://developer.android.com/studio/run/emulator.html
