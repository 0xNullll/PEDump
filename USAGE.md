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
  - [Export Directory](#export-directory)
  - [Import Directory](#import-directory)
  - [Resource Directory](#resource-directory)
  - [Exception Directory](#exception-directory)
  - [Security Directory](#security-directory)
  - [Base Relocation Directory](#base-relocation-directory)
  - [Debug Directory](#debug-directory)
  - [Architecture Directory](#architecture-directory)
  - [Global Ptr Directory](#global-ptr-directory)
  - [TLS Directory](#tls-directory)
  - [Load Config Directory](#load-config-directory)
  - [Bound Import Directory](#bound-import-directory)
  - [IAT Directory](#iat-directory)
  - [Delay Import Directory](#delay-import-directory)
  - [CLR Runtime Header](#clr-runtime-header)
  - [Reserved Directory](#reserved-directory)
  - [All Data Directories](#all-data-directories)
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
$ PEDump -nth <file>
$ PEDump --nt-headers <file>
```
**Description:**
Print NT headers.

**Example:**
```
$ PEDump -nth C:\Windows\System32\notepad.exe

00000001400000F8        - IMAGE NT HEADERS -

VA                FO        Size        Value
00000001400000F8  000000F8  [4]         Signature : 00004550  ("PE")

00000001400000FC        - IMAGE FILE HEADER -
# ... same output as -fh ...

0000000140000110        - IMAGE OPTIONAL HEADER -
# ... same output as -oh ...
```

### Sections
**Syntax:**
```bash
$ PEDump -s <file>
$ PEDump --sections <file>
```
**Description:**
Print Sections table.

**Example:**
```
$ PEDump -s C:\Windows\System32\notepad.exe

0000000140001000  00001000      SECTION HEADERS - number of sections : 8

0000000140001000  00001000       - SECTION: #1 -

VA                FO        Size        Value
0000000140001000  00001000  [8]         Name                       : .text

0000000140001008  00001008  [4]         Virtual size               : 000266E2  (157410)
0000000140001008  00001008  [4]         (Relative) Virtual address : 00001000

000000014000100C  0000100C  [4]         Size of raw data           : 00027000  (159744)
0000000140001010  00001010  [4]         Pointer to raw data        : 00001000

0000000140001014  00001014  [4]         Pointer to relocations     : 00000000
0000000140001018  00001018  [4]         Pointer to linenumbers     : 00000000

000000014000101C  0000101C  [2]         Number of relocations      : 0000
000000014000101E  0000101E  [2]         Pointer to linenumbers     : 0000

0000000140001020  00001020  [4]         Characteristics            : 60000020
                                                                   + 00000020  IMAGE_SCN_CNT_CODE
                                                                   + 20000000  IMAGE_SCN_MEM_EXECUTE
                                                                   + 40000000  IMAGE_SCN_MEM_READ


[... skipped ...]


0000000140059000  00057000       - SECTION: #8 -

VA                FO        Size        Value
0000000140059000  00057000  [8]         Name                       : .reloc

0000000140059008  00057008  [4]         Virtual size               : 00000350  (848)
0000000140059008  00057008  [4]         (Relative) Virtual address : 00059000

000000014005900C  0005700C  [4]         Size of raw data           : 00001000  (4096)
0000000140059010  00057010  [4]         Pointer to raw data        : 00057000

0000000140059014  00057014  [4]         Pointer to relocations     : 00000000
0000000140059018  00057018  [4]         Pointer to linenumbers     : 00000000

000000014005901C  0005701C  [2]         Number of relocations      : 0000
000000014005901E  0005701E  [2]         Pointer to linenumbers     : 0000

0000000140059020  00057020  [4]         Characteristics            : 42000040
                                                                   + 00000040  IMAGE_SCN_CNT_INITIALIZED_DATA
                                                                   + 02000000  IMAGE_SCN_MEM_DISCARDABLE
                                                                   + 40000000  IMAGE_SCN_MEM_READ
```

---

## Data Directories

***Commands to display individual or all data directories for analysis.***

---

### Export Directory
**Syntax:**
```bash
$ PEDump -e <file>
$ PEDump --exports <file>
```
**Description:**
Print export directory.

**Example:**
```
$ PEDump -e C:\Windows\System32\kernel32.dll

00000001800A4B60        - EXPORTS DIRECTORY -

VA                FO        Size        Value
00000001800A4B60  000A4B60  [4]         Characteristics     : 00000000

00000001800A4B64  000A4B64  [4]         ReproChecksum       : D83A007F (3627679871)

00000001800A4B68  000A4B68  [2]         Major Version       : 0000
00000001800A4B6A  000A4B6A  [2]         Minor Version       : 0000

00000001800A4B6C  000A4B6C  [4]         Export DLL Name RVA : 000A8DA0  [VA: 1800A8DA0] [FO: A8DA0] [  .rdata  ]
00000001800A8DA0  000A8DA0 [12]         Export Table Name   : KERNEL32.dll

00000001800A4B70  000A4B70  [4]         Base                : 00000001

00000001800A4B74  000A4B74  [4]         Number Of Functions : 0000069C  (1692)
00000001800A4B78  000A4B78  [4]         Number Of Names     : 0000069C  (1692)

00000001800A4B7C  000A4B7C  [4]         Functions RVA       : 000A4B88  [VA: 1800A4B88] [FO: A4B88] [  .rdata  ]
00000001800A4B80  000A4B80  [4]         Names RVA           : 000A65F8  [VA: 1800A65F8] [FO: A65F8] [  .rdata  ]
00000001800A4B84  000A4B84  [4]         Name Ordinals RVA   : 000A8068  [VA: 1800A8068] [FO: A8068] [  .rdata  ]

                  ==== EXPORTED FUNCTIONS [1692 entries] ====

VA         FO      Idx  Ordinal  Func-RVA Name-RVA Name                                                                             Forwarded-To
1800A4B88  A4B88   1    1        000A8DC5 000A8DAD AcquireSRWLockExclusive                                                          NTDLL.RtlAcquireSRWLockExclusive
1800A4B8C  A4B8C   2    2        000A8DFB 000A8DE6 AcquireSRWLockShared                                                             NTDLL.RtlAcquireSRWLockShared
1800A4B90  A4B90   3    3        00037BA0 000A8E19 ActivateActCtx
1800A4B94  A4B94   4    4        0000E4E0 000A8E28 ActivateActCtxWorker
1800A4B98  A4B98   5    5        00057F60 000A8E3D ActivatePackageVirtualizationContext

[... skipped ...]

1800A65E4  A65E4   1688 698      00058240 000B3771 uaw_wcschr
1800A65E8  A65E8   1689 699      00058270 000B377C uaw_wcscpy
1800A65EC  A65EC   1690 69A      000582A0 000B3787 uaw_wcsicmp
1800A65F0  A65F0   1691 69B      000582C0 000B3793 uaw_wcslen
1800A65F4  A65F4   1692 69C      000582F0 000B379E uaw_wcsrchr

                  ==== END OF EXPORTED FUNCTIONS ====
```

### Import Directory
**Syntax:**
```bash
$ PEDump -i <file>
$ PEDump --imports <file>
```
**Description:**
Print import directory.

**Example:**
```
$ PEDump -i C:\Windows\System32\notepad.exe

00000001400308D0        - IMPORT DIRECTORY - number of import descriptors: 50

00000001400308D0        IMPORT descriptor: 1  - Library: GDI32.dll

VA                FO        Size        Value
00000001400308D0  000308D0  [ 4]        Hint name table       : 00030D30  [VA: 140030D30] [FO: 30D30] [  .rdata  ]

00000001400308D4  000308D4  [ 4]        Time Date Stamp       : 00000000

00000001400308D8  000308D8  [ 4]        Forwarder chain       : 00000000

00000001400308DC  000308DC  [ 4]        Library name RVA      : 000319B4  [VA: 1400319B4] [FO: 319B4] [  .rdata  ]
00000001400319B4  000319B4  [ 9]        Imports library name  : GDI32.dll

00000001400308E0  000308E0  [ 4]        Import address table  : 00029938  [VA: 140029938] [FO: 29938] [  .rdata  ]




0000000140030D30          HINT NAME TABLE: 25 Enties

0000000140030D30  00030D30  [8]         [VA: 140031904] [FO: 31904] [  .rdata  ]
0000000140031904                                             31904  [  2]            Hint : 0398  (920)
0000000140031906                                             31906  [ 10]            Name : SetMapMode

0000000140030D40  00030D40  [8]         [VA: 140031912] [FO: 31912] [  .rdata  ]
0000000140031912                                             31912  [  2]            Hint : 03AC  (940)
0000000140031914                                             31914  [ 16]            Name : SetViewportExtEx

0000000140030D50  00030D50  [8]         [VA: 140031926] [FO: 31926] [  .rdata  ]
0000000140031926                                             31926  [  2]            Hint : 03B0  (944)
0000000140031928                                             31928  [ 14]            Name : SetWindowExtEx

[... skipped ...]

0000000140030E90  00030E90  [8]         [VA: 14003184E] [FO: 3184E] [  .rdata  ]
000000014003184E                                             3184E  [  2]            Hint : 0031  (49)
0000000140031850                                             31850  [ 18]            Name : CreateCompatibleDC

0000000140030EA0  00030EA0  [8]         [VA: 140031960] [FO: 31960] [  .rdata  ]
0000000140031960                                             31960  [  2]            Hint : 01A1  (417)
0000000140031962                                             31962  [  7]            Name : EndPage

0000000140030EB0  00030EB0  [8]         [VA: 140031838] [FO: 31838] [  .rdata  ]
0000000140031838                                             31838  [  2]            Hint : 0043  (67)
000000014003183A                                             3183A  [ 19]            Name : CreateFontIndirectW




0000000140029938          IMPORT ADDRESS TABLE: 25 Entries

0000000140029938  00029938  [8]            31904
0000000140029940  00029940  [8]            31912
0000000140029948  00029948  [8]            31926

[... skipped ...]

00000001400299E8  000299E8  [8]            3184E
00000001400299F0  000299F0  [8]            31960
00000001400299F8  000299F8  [8]            31838

------------- END FO IMPORT DESCRIPTOR 1 (25 functions) -------------

[... skipped ...]

0000000140030CA4        IMPORT descriptor: 50  - Library: api-ms-win-core-delayload-l1-1-0.dll

VA                FO        Size        Value
0000000140030CA4  00030CA4  [ 4]        Hint name table       : 00031158  [VA: 140031158] [FO: 31158] [  .rdata  ]

0000000140030CA8  00030CA8  [ 4]        Time Date Stamp       : 00000000

0000000140030CAC  00030CAC  [ 4]        Forwarder chain       : 00000000

0000000140030CB0  00030CB0  [ 4]        Library name RVA      : 0003358A  [VA: 14003358A] [FO: 3358A] [  .rdata  ]
000000014003358A  0003358A  [36]        Imports library name  : api-ms-win-core-delayload-l1-1-0.dll

0000000140030CB4  00030CB4  [ 4]        Import address table  : 00029D60  [VA: 140029D60] [FO: 29D60] [  .rdata  ]




0000000140031158          HINT NAME TABLE: 1 Entry

0000000140031158  00031158  [8]         [VA: 14003354C] [FO: 3354C] [  .rdata  ]
000000014003354C                                             3354C  [  2]            Hint : 0000  (0)
000000014003354E                                             3354E  [ 20]            Name : DelayLoadFailureHook




0000000140029D60          IMPORT ADDRESS TABLE: 1 Entry

0000000140029D60  00029D60  [8]            3354C

------------- END FO IMPORT DESCRIPTOR 50 (1 function) -------------
```

### Resource Directory
**Syntax:**
```bash
$ PEDump -r <file>
$ PEDump --resources <file>
```
**Description:**
Print resources directory.

**Example:**
```
$ PEDump -r C:\Windows\System32\notepad.exe

                                  - RESOURCE DIRECTORY -

Root Directory (VA=14003A000, FO=38000):
    Characteristics=0x0, TimeDateStamp=00000000  , Version=0.0, NamedEntries=3, IDEntries=4


    subDir: EDPENLIGHTENEDAPPINFOID (ID=0x688, Named=EDPENLIGHTENEDAPPINFOID) [VA=14003A010, FO=38010]
        Characteristics=0x0, TimeDateStamp=00000000  , Version=0.0, NamedEntries=1, IDEntries=0

        subDir: #1 (ID=0x6B8, Named=MICROSOFTEDPENLIGHTENEDAPPINFO) [VA=14003A058, FO=38058]
            Characteristics=0x0, TimeDateStamp=00000000  , Version=0.0, NamedEntries=0, IDEntries=1

            Entry: (Lang=0x409 -> English (United States), named=N/A) [VA=14003A1C0, FO=381C0]
                    Data Offsets: (RVA=3AC58 FO=38C58), Size=0x2 (2), CodePage=0x0, Reserved=0


    subDir: EDPPERMISSIVEAPPINFOID (ID=0x6F6, Named=EDPPERMISSIVEAPPINFOID) [VA=14003A018, FO=38018]
        Characteristics=0x0, TimeDateStamp=00000000  , Version=0.0, NamedEntries=1, IDEntries=0

        subDir: #1 (ID=0x724, Named=MICROSOFTEDPPERMISSIVEAPPINFO) [VA=14003A070, FO=38070]
            Characteristics=0x0, TimeDateStamp=00000000  , Version=0.0, NamedEntries=0, IDEntries=1

            Entry: (Lang=0x409 -> English (United States), named=N/A) [VA=14003A1D8, FO=381D8]
                    Data Offsets: (RVA=3AC60 FO=38C60), Size=0x2 (2), CodePage=0x0, Reserved=0


    subDir: MUI (ID=0x760, Named=MUI) [VA=14003A020, FO=38020]
        Characteristics=0x0, TimeDateStamp=00000000  , Version=0.0, NamedEntries=0, IDEntries=1

        subDir: #1 (ID=0x1, Named=N/A) [VA=14003A088, FO=38088]
            Characteristics=0x0, TimeDateStamp=00000000  , Version=0.0, NamedEntries=0, IDEntries=1

            Entry: (Lang=0x409 -> English (United States), named=N/A) [VA=14003A1F0, FO=381F0]
                    Data Offsets: (RVA=58090 FO=56090), Size=0x140 (320), CodePage=0x0, Reserved=0


    subDir: ICON (ID=0x3, Named=N/A) [VA=14003A028, FO=38028]
        Characteristics=0x0, TimeDateStamp=00000000  , Version=0.0, NamedEntries=0, IDEntries=22

        [... skipped ...]

    subDir: GROUP_ICON (ID=0xE, Named=N/A) [VA=14003A030, FO=38030]
        Characteristics=0x0, TimeDateStamp=00000000  , Version=0.0, NamedEntries=0, IDEntries=4

        [... skipped ...]

    subDir: VERSION (ID=0x10, Named=N/A) [VA=14003A038, FO=38038]
        Characteristics=0x0, TimeDateStamp=00000000  , Version=0.0, NamedEntries=0, IDEntries=1

        subDir: #1 (ID=0x1, Named=N/A) [VA=14003A190, FO=38190]
            Characteristics=0x0, TimeDateStamp=00000000  , Version=0.0, NamedEntries=0, IDEntries=1

            Entry: (Lang=0x409 -> English (United States), named=N/A) [VA=14003A478, FO=38478]
                    Data Offsets: (RVA=57D18 FO=55D18), Size=0x374 (884), CodePage=0x0, Reserved=0


    subDir: MANIFEST (ID=0x18, Named=N/A) [VA=14003A040, FO=38040]
        Characteristics=0x0, TimeDateStamp=00000000  , Version=0.0, NamedEntries=0, IDEntries=1

        subDir: #1 (ID=0x1, Named=N/A) [VA=14003A1A8, FO=381A8]
            Characteristics=0x0, TimeDateStamp=00000000  , Version=0.0, NamedEntries=0, IDEntries=1

            Entry: (Lang=0x409 -> English (United States), named=N/A) [VA=14003A490, FO=38490]
                    Data Offsets: (RVA=3A770 FO=38770), Size=0x4E4 (1252), CodePage=0x0, Reserved=0
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