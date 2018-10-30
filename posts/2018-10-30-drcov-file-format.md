---
layout: post
title: DrCov File Format
---

`drcov` is a DynamoRIO-based tool that collects coverage information from a
binary. There are many useful tools, such as [Lighthouse][lighthouse] that
make use of the `drcov` file format. This format is not strictly exclusive to
`drcov`. Any DBI tool or framework can be used to collect the neccessary
information. In fact, Lighthouse contains experimental scripts that use
[Frida][frida-drcov] and [Intel PIN][pin-drcov] to collect the same coverage
information.

As useful as it is, the `drcov` file format is not officially documented by
the DynamoRIO project. Hopefully, the information presented below will make it
easier to get started with the format, especially if you want to write your own
coverage collection tool with a different DBI.

The file format begins with a header containing some metadata.

```
DRCOV VERSION: 2
DRCOV FLAVOR: drcov
```

As Lighthouse only supports version 2 log files, I did not look into what the
version 1 log file format is. `DRCOV FLAVOR` is a string is used to describe
the tool that generated the coverage information and does not actually impact
anything.

Next, the log file has the module table that contains a map of the loaded
modules in the process that the coverage information is collected from.

```
Module Table: version 2, count 39
Columns: id, base, end, entry, checksum, timestamp, path
 0, 0x10c83b000, 0x10c83dfff, 0x0000000000000000, 0x00000000, 0x00000000, /Users/ayrx/code/frida-drcov/bar
 1, 0x112314000, 0x1123f4fff, 0x0000000000000000, 0x00000000, 0x00000000, /usr/lib/dyld
 2, 0x7fff5d866000, 0x7fff5d867fff, 0x0000000000000000, 0x00000000, 0x00000000, /usr/lib/libSystem.B.dylib
 3, 0x7fff5dac1000, 0x7fff5db18fff, 0x0000000000000000, 0x00000000, 0x00000000, /usr/lib/libc++.1.dylib
 4, 0x7fff5db19000, 0x7fff5db2efff, 0x0000000000000000, 0x00000000, 0x00000000, /usr/lib/libc++abi.dylib
 5, 0x7fff5f30d000, 0x7fff5fa93fff, 0x0000000000000000, 0x00000000, 0x00000000, /usr/lib/libobjc.A.dylib
 8, 0x7fff60617000, 0x7fff60647fff, 0x0000000000000000, 0x00000000, 0x00000000, /usr/lib/system/libxpc.dylib

 ... snip ...
```

This is probably the messiest part of the `drcov` file format as it has had
quite a few changes. I take the documentation in the Lighthouse project at
face value since my primary goal is to have coverage log files that work in
Lighthouse.

As documented by Lighthouse, the `Module Table` header has two variations,
both of which contain the number of entries in the module table.

```
Format used in DynamoRIO v6.1.1 through 6.2.0
   eg: 'Module Table: 11'
Format used in DynamoRIO v7.0.0-RC1 (and hopefully above)
   eg: 'Module Table: version X, count 11'
```

Each version has a slightly different table format.

```
DynamoRIO v6.1.1, table version 1:
   eg: (Not present)
DynamoRIO v7.0.0-RC1, table version 2:
   Windows:
     'Columns: id, base, end, entry, checksum, timestamp, path'
   Mac/Linux:
     'Columns: id, base, end, entry, path'
DynamoRIO v7.0.17594B, table version 3:
   Windows:
     'Columns: id, containing_id, start, end, entry, checksum, timestamp, path'
   Mac/Linux:
     'Columns: id, containing_id, start, end, entry, path'
DynamoRIO v7.0.17640, table version 4:
   Windows:
     'Columns: id, containing_id, start, end, entry, offset, checksum, timestamp, path'
   Mac/Linux:
     'Columns: id, containing_id, start, end, entry, offset, path'
```

Of the many values, only `id`, `start` (or `base`), `end`, and `path` are
actually required when it comes to interoperability with Lighthouse.

1. `id`: This is a sequential number assigned when generating the module table.
    It is later used to map a basic block to a module.
2. `start`, `base`: This is the memory address where the module starts.
3. `end`: This is the memory address where the module ends.
4. `path`: This is the path where the module is located on disk.

Finally, the log file has a basic block table that contains a list of basic
blocks that were executed when the coverage information is being collected.
While `drcov` can dump the basic block table in text format (with the
`-dump_text` option), it defaults to dumping the table in binary format which
is what will be most commonly seen.

```
BB Table: 861 bbs
<binary data>
```

The table starts with a header that indicates the number of basic blocks in the
table. The binary data that follows the `BB Table` header is an array of
`_bb_entry_t` structs that is 8 bytes each. The format of each `_bb_entry_t`
struct in the table is as follows:

```
typedef struct _bb_entry_t {
    uint   start;      /* offset of bb start from the image base */
    ushort size;
    ushort mod_id;
} bb_entry_t;
```

Each item in the struct is rather self-explanatory.

1. `start`: This is the offset from the base of the module where the basic
   block entry starts.
2. `size`: This is the size of the basic block.
3. `mod_id`: This is the id of the module where the basic block is found. This
corresponds to the id assigned to the module when generating the module table.

These 3 items, when combined with the module table, allows us to know which
basic blocks were executed when the coverage information was collected.

[lighthouse]: https://github.com/gaasedelen/lighthouse
[frida-drcov]: https://github.com/gaasedelen/lighthouse/tree/master/coverage/frida
[pin-drcov]: https://github.com/gaasedelen/lighthouse/tree/master/coverage/pin
