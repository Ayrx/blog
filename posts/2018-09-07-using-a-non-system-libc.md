---
layout: post
title: Using a non-system glibc
---

When developing exploits, especially heap exploits, the glibc version the
binary is linked against will affect the specific offsets that is used in the
exploit code. Efforts like the [libc-database][libc-database] help by making it
easy to look up memory addresses from a specific libc. When it comes to testing
out the exploit, the most common approach is probably to build an isolated
environment with the specific version of glibc with a tool like QEMU or Docker.
This approach can be annoying since it takes time and effort to install all
your tooling in the QEMU or Docker environment.

An alternative approach can be to rewrite the binary to link to a non-system
libc. This is not as easy as simply setting something like `LD_LIBRARY_PATH`.
With glibc, the path of the interpreter, `ld-linux.so.2` is  hardcoded into
the binary at build time. The version of `ld-linux.so.2` MUST match `libc.so.6`
or there will be errors when the binary is ran.

To use a non-system libc with a ELF binary, we must do two things:

1. Modify the interpreter path to point to a `ld-linux.so.2` that matches the
   version of the `libc.so.6` that we want to link with.
2. Modify the RUNPATH of the binary to point to the directory where our
   `libc.so.6` is.

While there are various tools, such as [patchelf][patchelf], that can used
for this, I found it simple to write a short script with [LIEF][lief] that does
the job.

```python
#!/usr/bin/env python3

import click
import lief
import pathlib


@click.command(
    help="Change the linked glibc of an ELF binary."
)
@click.argument("bin", type=click.Path(exists=True))
@click.argument("libc", type=click.Path(exists=True, resolve_path=True))
@click.argument("ld", type=click.Path(exists=True, resolve_path=True))
@click.argument("out", type=click.Path())
def cli(bin, libc, ld, out):
    binary = lief.parse(bin)

    libc_name = None
    for i in binary.libraries:
        if "libc.so.6" in i:
            libc_name = i
            break

    if libc_name is None:
        click.echo("No libc linked. Exiting.")

    click.echo("Current ld.so:")
    click.echo("Path: {}".format(binary.interpreter))
    click.echo()

    libc_path = str(pathlib.Path(str(libc)).parent)

    binary.interpreter = str(ld)
    click.echo("New ld.so:")
    click.echo("Path: {}".format(binary.interpreter))
    click.echo()

    binary += lief.ELF.DynamicEntryRunPath(libc_path)
    click.echo("Adding RUNPATH:")
    click.echo("Path: {}".format(libc_path))
    click.echo()

    click.echo("Writing new binary {}".format(out))
    click.echo("Please rename {} to {}/libc.so.6.".format(
        libc, libc_path
    ))
    binary.write(out)


if __name__ == "__main__":
    cli()
```

The canonical version of the script can be found on [GitHub][github-reutils].
With this approach, you can also place specific versions of any other libraries
the binary is linked against in the libc directory and it will be picked up by
the dynamic linker.

[libc-database]: https://github.com/niklasb/libc-database
[patchelf]: https://nixos.org/patchelf.html
[lief]: https://lief.quarkslab.com
[github-reutils]: https://github.com/Ayrx/reutils/blob/master/change_glibc
