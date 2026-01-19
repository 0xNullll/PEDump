# PEDump Detailed Usage Guide

> **Note:** This file provides detailed command explanations, examples, and tips for using `PEDump`.
> For a quick reference, see [README.md](README.md).

---

## Overview

`PEDump` is a PE (Portable Executable) analysis tool that allows you to inspect headers, sections, data directories, extract strings, hash sections, and compare files.

---

## Table of Contents

- [General](#general)
- [Headers & PE Information](#headers--pe-information)
  - [DOS Header](#dos-header)
  - [File Header](#file-header)
  - [Optional Header](#optional-header)
  - [NT Headers](#nt-headers)
  - [Sections](#sections)
- [Data Directories](#data-directories)
  - [Individual Directories](#individual-directories)
  - [All Data Directories](#all-data-directories)
  - [All Information](#all-information)
- [CLR (Common Language Runtime)](#clr-common-language-runtime)
- [Miscellaneous](#miscellaneous)
- [Output Formatting](#output-formatting)
- [Strings Extraction](#strings-extraction)
- [Extraction](#extraction)
- [Hashing](#hashing)
- [Comparison](#comparison)

---

## General

***Basic usage, global flags, and help commands.***

---

### Help

**Syntax:**
```bash
PEDump -h
PEDump --help
```
**Description:**
Show this help message with all available commands and options.

**Example:**
```
# output example placeholder
```

---

## Headers & PE Information

***Commands to dump and inspect DOS, NT, File, Optional headers, and PE sections.***

---

### DOS Header
**Syntax:**
```bash
$ PEDump -dh <file>
$ PEDump --dos-header <file>
```
**Description:**
Print DOS header.

**Example:**
```
$ PEDump -dh C:\Windows\System32\notepad.exe

0000000140000000        - DOS HEADER -

VA                FO        Size        Value
0000000140000000  00000000  [2]         DOS signature                     : 5A4D  ("MZ")

0000000140000002  00000002  [2]         Bytes used on last page           : 0090
0000000140000004  00000004  [2]         Total pages count                 : 0003
0000000140000006  00000006  [2]         Relocation entries                : 0000
0000000140000008  00000008  [2]         Header size (in paragraphs)       : 0004
000000014000000A  0000000A  [2]         Minimum extra paragraphs required : 0000
000000014000000C  0000000C  [2]         Maximum extra paragraphs allowed  : FFFF  (65535)

000000014000000E  0000000E  [2]         Initial stack segment             : 0000
0000000140000010  00000010  [2]         Initial stack pointer             : 00B8
0000000140000012  00000012  [2]         Checksum                          : 0000
0000000140000014  00000014  [2]         Initial instruction pointer       : 0000
0000000140000016  00000016  [2]         Initial code segment              : 0000
0000000140000018  00000018  [2]         Relocation table file address     : 0040
000000014000001A  0000001A  [2]         Overlay number                    : 0000

000000014000001C  0000001C  [2]         Reserved words                    : 0.0.0.0

000000014000001E  0000001E  [2]         OEM identifier                    : 0000
0000000140000020  00000020  [2]         OEM information                   : 0000

0000000140000022  00000022  [2]         Reserved words 2                  : 0.0.0.0.0.0.0.0.0.0

0000000140000024  00000024  [4]         File address of new exe header    : 000000F8
```

### File Header
**Syntax:**
```bash
$ PEDump -fh <file>
$ PEDump --file-header <file>
```
**Description:**
Print File header.

**Example:**
```
$ PEDump -fh C:\Windows\System32\notepad.exe

00000001400000FC        - IMAGE FILE HEADER -

VA                FO        Size        Value
00000001400000FC  000000FC  [2]         Machine                 : 8664
                                                                + 8664  IMAGE_FILE_MACHINE_AMD64

00000001400000FE  000000FE  [2]         Number of sections      : 0008      (8)

0000000140000100  00000100  [4]         ReproChecksum           : 7C74B70C (2088023820)

0000000140000104  00000104  [4]         Pointer to symbol table : 00000000
0000000140000108  00000108  [4]         Number of symbols       : 00000000  (0)

000000014000010C  0000010C  [2]         Size of optional header : 00F0      (240)

000000014000010E  0000010E  [2]         Characteristics         : 0022
                                                                + 0002  IMAGE_FILE_EXECUTABLE_IMAGE
                                                                + 0020  IMAGE_FILE_LARGE_ADDRESS_AWARE
```

### Optional Header
**Syntax:**
```bash
$ PEDump -oh <file>
$ PEDump --optional-header <file>
```
**Description:**
Print Optional header.

**Example:**
```
$ PEDump -oh C:\Windows\System32\notepad.exe

0000000140000110        - IMAGE OPTIONAL HEADER -

VA                FO        Size        Value
0000000140000110  00000110  [2]         Machine                    : 020B
                                                                   + 020B  IMAGE_NT_OPTIONAL_HDR64_MAGIC

0000000140000112  00000112  [1]         Linker Version (Major)     : 0E        ( 14)
0000000140000113  00000113  [1]         Linker Version (Minor)     : 26        ( 38)

0000000140000114  00000114  [4]         Size of Code               : 00028000  (163840)

0000000140000118  00000118  [4]         Size of Initialized Data   : 00031000  (    200704)
000000014000011C  0000011C  [4]         Size of Uninitialized Data : 00000000  (         0)

0000000140000120  00000120  [4]         Entry Point (RVA)          : 000019B0  [VA: 1400019B0] [FO: 19B0] [  .text   ]
0000000140000124  00000124  [4]         Base of Code               : 00001000  [VA: 140001000] [FO: 1000] [  .text   ]

0000000140000128  00000128  [8]         Image Base                 : 0000000140000000

0000000140000130  00000130  [4]         Section Alignment          : 00001000
0000000140000134  00000134  [4]         File Alignment             : 00001000

0000000140000138  00000138  [2]         OS Version (Major)         : 000A
                                                                   + 000A  IMAGE_OS_WIN10
000000014000013A  0000013A  [2]         OS Version (Minor)         : 0000

000000014000013C  0000013C  [2]         Image Version (Major)      : 000A
                                                                   + 000A  IMAGE_VER_UNKNOWN
000000014000013E  0000013E  [2]         Image Version (Minor)      : 0000

0000000140000140  00000140  [2]         Subsystem Version (Major)  : 000A
                                                                   + 000A  IMAGE_SUBSYS_WIN10
0000000140000142  00000142  [2]         Subsystem Version (Minor)  : 0000

0000000140000144  00000144  [4]         Win32 Version Value        : 00000000

0000000140000148  00000148  [4]         Size of Image              : 0005A000
000000014000014C  0000014C  [4]         Size of Headers            : 00001000

0000000140000150  00000150  [4]         Checksum                   : 000661F6

0000000140000154  00000154  [2]         Subsystem                  : 0002
                                                                   + 0002  IMAGE_SUBSYSTEM_WINDOWS_GUI

0000000140000156  00000156  [2]         DLL Characteristics        : C160
                                                                   + 0020  IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
                                                                   + 0040  IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
                                                                   + 0100  IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                                                                   + 4000  IMAGE_DLLCHARACTERISTICS_GUARD_CF
                                                                   + 8000  IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE

0000000140000158  00000158  [8]         Size of Stack Reserve      : 0000000000011000
0000000140000160  00000160  [8]         Size of Stack Commit       : 0000000000011000

0000000140000168  00000168  [8]         Size of Heap  Reserve      : 0000000000100000
0000000140000170  00000170  [8]         Size of Heap  Commit       : 0000000000001000

0000000140000178  00000178  [4]         Loader Flags               : 00000000

000000014000017C  0000017C  [4]         Number of RVA and Size     : 00000010


0000000140000180         - DATA DIRECTORIES -

0000000140000180  00000180  [8]         Export Table
0000000140000184  00000184  [4]             Virtual Address         :  00000000
0000000140000188  00000188  [4]             Size                    :  00000000

0000000140000188  00000188  [8]         Import Table             [VA: 1400308D0] [FO: 308D0] [  .rdata  ]
000000014000018C  0000018C  [4]             Virtual Address         :  000308D0
0000000140000190  00000190  [4]             Size                    :  000003FC

0000000140000190  00000190  [8]         Resource Table           [VA: 14003A000] [FO: 38000] [  .rsrc   ]
0000000140000194  00000194  [4]             Virtual Address         :  0003A000
0000000140000198  00000198  [4]             Size                    :  0001E1D0

0000000140000198  00000198  [8]         Exception Table          [VA: 140037000] [FO: 35000] [  .pdata  ]
000000014000019C  0000019C  [4]             Virtual Address         :  00037000
00000001400001A0  000001A0  [4]             Size                    :  0000120C

00000001400001A0  000001A0  [8]         Security Table
00000001400001A4  000001A4  [4]             Virtual Address         :  00000000
00000001400001A8  000001A8  [4]             Size                    :  00000000

00000001400001A8  000001A8  [8]         Base Relocation Table    [VA: 140059000] [FO: 57000] [  .reloc  ]
00000001400001AC  000001AC  [4]             Virtual Address         :  00059000
00000001400001B0  000001B0  [4]             Size                    :  000002F8

00000001400001B0  000001B0  [8]         Debug                    [VA: 14002E2F0] [FO: 2E2F0] [  .rdata  ]
00000001400001B4  000001B4  [4]             Virtual Address         :  0002E2F0
00000001400001B8  000001B8  [4]             Size                    :  00000070

00000001400001B8  000001B8  [8]         Architecture
00000001400001BC  000001BC  [4]             Virtual Address         :  00000000
00000001400001C0  000001C0  [4]             Size                    :  00000000

00000001400001C0  000001C0  [8]         Global Pointer
00000001400001C4  000001C4  [4]             Virtual Address         :  00000000
00000001400001C8  000001C8  [4]             Size                    :  00000000

00000001400001C8  000001C8  [8]         TLS Table
00000001400001CC  000001CC  [4]             Virtual Address         :  00000000
00000001400001D0  000001D0  [4]             Size                    :  00000000

00000001400001D0  000001D0  [8]         Load Config Table        [VA: 140029790] [FO: 29790] [  .rdata  ]
00000001400001D4  000001D4  [4]             Virtual Address         :  00029790
00000001400001D8  000001D8  [4]             Size                    :  00000148

00000001400001D8  000001D8  [8]         Bound Import
00000001400001DC  000001DC  [4]             Virtual Address         :  00000000
00000001400001E0  000001E0  [4]             Size                    :  00000000

00000001400001E0  000001E0  [8]         Import Address Table     [VA: 1400298D8] [FO: 298D8] [  .rdata  ]
00000001400001E4  000001E4  [4]             Virtual Address         :  000298D8
00000001400001E8  000001E8  [4]             Size                    :  00000B68

00000001400001E8  000001E8  [8]         Delay Import Descriptor  [VA: 1400302F0] [FO: 302F0] [  .rdata  ]
00000001400001EC  000001EC  [4]             Virtual Address         :  000302F0
00000001400001F0  000001F0  [4]             Size                    :  000000E0

00000001400001F0  000001F0  [8]         CLR Runtime Header
00000001400001F4  000001F4  [4]             Virtual Address         :  00000000
00000001400001F8  000001F8  [4]             Size                    :  00000000

00000001400001F8  000001F8  [8]         Reserved
00000001400001FC  000001FC  [4]             Virtual Address         :  00000000
0000000140000200  00000200  [4]             Size                    :  00000000
```

### NT Headers
**Syntax:**
```bash
PEDump -nth <file>
PEDump --nt-headers <file>
```
**Description:**
Print NT headers.

**Example:**
```
# output example placeholder
```

### Sections
**Syntax:**
```bash
PEDump -s <file>
PEDump --sections <file>
```
**Description:**
Print Sections table.

**Example:**
```
# output example placeholder
```

---

## Data Directories

***Commands to display individual or all data directories for analysis.***

---

### Exports
**Syntax:**
```bash
PEDump -e <file>
PEDump --exports <file>
```
**Description:**
Print export directory.

**Example:**
```
# output example placeholder
```

### Imports
**Syntax:**
```bash
PEDump -i <file>
PEDump --imports <file>
```
**Description:**
Print import directory.

**Example:**
```
# output example placeholder
```

### Resources
**Syntax:**
```bash
PEDump -r <file>
PEDump --resources <file>
```
**Description:**
Print resources directory.

**Example:**
```
# output example placeholder
```

### Exception / Security / Debug / TLS / Base Reloc / Load Config / Bound Import / IAT / Delay Import / All Data Directories
**Syntax:**
```bash
PEDump -ex|-sec|-d|-tls|-br|-lc|-bi|-iat|-di|-dd <file>
```
**Description:**
Print the respective data directory.

**Example:**
```
# output example placeholder
```

---

## CLR (Common Language Runtime)

***Commands to show CLR headers and metadata for .NET assemblies.***

---

### CLR Header
**Syntax:**
```bash
PEDump -ch <file>
PEDump --clr-header <file>
```
**Description:**
Print CLR header (not fully implemented).

**Example:**
```
# output example placeholder
```

---

## Miscellaneous

***Commands for checksum, subsystem, alignment info, and other extra features.***

---

Commands include:
- Rich Header: `-rh`
- Version Info: `-vi`
- Symbol Table: `-sym`
- String Table: `-st`
- Overlay: `-o`
- Overview: `-ov`
- All Info: `-a` (not implemented yet)

**Example for Overview:**
```
# output example placeholder
```

---

## Output Formatting

***Commands to adjust how output is displayed, including tables, raw formats, or VA conversions.***

---

**Syntax:**
```bash
PEDump -f <type[:spec]> <file>
PEDump -v2f NUMBER <file>
```
**Description:**
Format output, convert VA to file offset.

**Types:** hex, dec, bin, table

**Range Specifiers:** :N, :start,max, 0xHEX

**Example:**
```
# output example placeholder
```

---

## Strings Extraction

***Commands to extract printable strings from the PE file or specific sections.***

---

**Syntax:**
```bash
PEDump -s [rgex:<pattern>] <file>
PEDump --strings [rgex:<pattern>] <file>
```
**Description:**
Dump ASCII/UTF-16LE strings with optional regex filtering.

**Example:**
```
# output example placeholder
```

---

## Extraction

***Commands to extract sections, resources, or data blocks from the PE file into separate files.***

---

**Syntax:**
```bash
PEDump -x <target[:spec]> <file>
```
**Targets:** section, export, import, RVA, FO, etc.

**Example:**
```
# output example placeholder
```

---

## Hashing

***Commands to compute hashes of sections or the whole file for verification or comparison.***

---

**Syntax:**
```bash
PEDump -H <target[@alg]> <file>
```
**Description:**
Compute hash of file, section, range, or rich header.

**Example:**
```
# output example placeholder
```

---

## Comparison

***Commands to compare files or sections using hashes or internal algorithms to detect differences.***

---

**Syntax:**
```bash
PEDump -cc <target1>::<target2[@alg]> <file1> [file2]
```
**Description:**
Compare two targets within the same file or between two files.

**Example:**
```
# output example placeholder