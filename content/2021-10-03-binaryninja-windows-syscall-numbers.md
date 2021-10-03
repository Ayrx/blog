---
layout: post
title: Parsing Windows Syscall Numbers with Binary Ninja
---

Binary Ninja is a great platform for automating some reverse engineering tasks,
especially with the headless mode available for commercial licenses. In this
post, we will use Binary Ninja to automate extracting Windows syscall numbers
from `ntdll.dll`.

`binaryninja.open_view` is a convenient wrapper function provided by Binary
Ninja to open a binary with default analysis options and returns a `BinaryView`
object.

The `functions` property on the `BinaryView` can be used to iterate through all
the functions within the opened binary. As the names of all syscall functions
begin with `Zw`, checking the `name` property of each function can be used to
locate all syscall functions within the binary.

```python
import binaryninja

with binaryninja.open_view("ntdll.dll") as bv:
    ssn = [
        parse_syscall(func)
        for func in bv.functions if func.name.startswith("Zw")
    ]
```

Syscall functions in a 64-bit `ntdll.dll` follow a very consistent pattern.

1. The value of `RCX` is moved to `R10`. This is because the Windows x64
calling convention passes the first argument in the `RCX` register while the
syscall calling convention uses `R10` as the `syscall` instruction clobbers
`RCX`.
2. `EAX` is set to the syscall number.
3. The `syscall` (or `int 0x2e`) instruction is executed.

The following image shows the LLIL view of a typical syscall function. The
`undefined` branch is `int 0x2e`. The difference between the two branches is
not relavant to the task of extracting syscall numbers. However,
[this](https://blog.amossys.fr/windows10_TH2_int2E_mystery.html) blog post
contains an excellent explanation for the readers that are interested.

<img src="../images/binaryninja-1633257968.png" class="center-image" >

To extract the syscall number, Binary Ninja's LLIL API is used to find the
`LLIL_SYSCALL` instruction. Once the instruction is found, the `get_reg_value`
function is used to obtain the value of `EAX` at that point in the program's
execution as understood by Binary Ninja's data flow analysis.

```python
def parse_syscall_64(func):
    for inst in func.llil.instructions:
        if inst.operation == LowLevelILOperation.LLIL_SYSCALL:
            return (func.name, inst.get_reg_value("eax").value)
```

Syscall functions in a 32-bit `ntdll.dll` has a different pattern. `EAX` is set
to the syscall number.

<img src="../images/binaryninja-1633260814.png" class="center-image" >


A stub function is called to actually make the `sysenter` instruction. This is
because the syscall calling convention on 32-bit Windows expects `EDX` to point
to the return address for `sysenter` plus the arguments and the only way to
push `EIP` onto the stack, which is where `sysenter` needs to return to, is
through a `call` instruction.

<img src="../images/binaryninja-1633260823.png" class="center-image" >

The code required to account for this pattern is very similar to the 64-bit
version, except that we search for `LLIL_CALL` instead of `LLIL_SYSCALL`.

```python
def parse_syscall_32(func):
    for inst in func.llil.instructions:
        if inst.operation == LowLevelILOperation.LLIL_CALL:
            return (func.name, inst.get_reg_value("eax").value)
```

The `arch` property on the `BinaryView` object can be used to decide which
version of the parse function should be called.

```python
arch = bv.arch.name
click.echo("[+] Arch: {}".format(arch))
parse_syscall = parse_syscall_32 if arch == "x86" else parse_syscall_64
```

The full script, `parse_ntdll_ssn`, can be found on the
[reutils](https://github.com/Ayrx/reutils/blob/master/bin/parse_ntdll_ssn)
GitHub repository and produces a JSON file containing a mapping of all
syscalls to their syscall numbers.

```
parse_ntdll_ssn ntdll_32.dll ssn_32.json
Function at 0x6a20d32f has HLIL condition that exceeds maximum complexity, omitting condition
[+] Arch: x86
[+] Parsing syscall numbers from ntdll_32.dll
[+] Writing results to ssn_32.json
```
