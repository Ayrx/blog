---
layout: post
title: Lifting `int 0x2e` to `LLIL_SYSCALL` with Binary Ninja
---

Windows (at times) use the `int 0x2e` instruction to execute syscalls. The
following image shows a diassembly of the `ZwAccessCheck` syscall from
`ntdll.dll`:

<img src="../images/binaryninja-1633761402.png" class="center-image" >

Binary Ninja (as of Version 2.4.3050-dev) is not able to lift the `int 0x2e`
instruction. The `int 0x2e` branch in `ZwAccessCheck` is displayed as
"undefined" in LLIL view while the `syscall` instruction lifts cleanly to
`LLIL_SYSCALL`.

<img src="../images/binaryninja-1633761605.png" class="center-image" >

With Binary Ninja's API, a custom `ArchitectureHook` can be implemented to
lift specific instructions an IL instruction. The following
`WindowsX86SyscallHook` implements a custom `get_instruction_low_level_il`
that emits `LLIL_SYSCALL` whenever `int 0x2e` is seen:

```python
from binaryninja.architecture import Architecture, ArchitectureHook

class WindowsX86SyscallHook(ArchitectureHook):
    def get_instruction_low_level_il(self, data, addr, il):
        result, length = super().get_instruction_text(data, addr)

        if len(result) > 0 and result[0].text == "int" and result[2].value == 0x2E:
            il.append(il.system_call())
            return True

        return super().get_instruction_low_level_il(data, addr, il)


WindowsX86SyscallHook(Architecture["x86_64"]).register()
```

Once the plugin is installed, the LLIL view becomes more accurate. The change
also propagates to the higher level ILs like MLIL and HLIL.

<img src="../images/binaryninja-1633762622.png" class="center-image" >


The only downside to this approach is that the extension is done at the
_architecture_ level and not at the _platform_ level which would affect other
x86\_64 platforms that use `int 0x2e` for something besides syscalls. This is
hopefully not common enough to matter in practice.
