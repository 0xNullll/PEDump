# PEDump Detailed Usage Guide

> **Note:** This file provides detailed command explanations, examples, and tips for using `PEDump`.
> For a quick reference, see [README.md](README.md).
> **Windows Version for Examples:** All Windows files used in these tests are from Version 25H2 (OS Build 26200.7623).

---

## Summary

`PEDump` is a PE (Portable Executable) analysis tool that allows you to inspect headers, sections, data directories, extract strings, hash sections, and compare files.

---

## Table of Contents

- [Help & Usage](#help--usage)
- [Headers & PE Information](#headers--pe-information)
  - [DOS Header](#dos-header)
  - [File Header](#file-header)
  - [Optional Header](#optional-header)
  - [NT Headers](#nt-headers)
  - [Section Headers](#section-headers)
- [Data Directories](#data-directories)
  - [Export Directory](#export-directory)
  - [Import Directory](#import-directory)
  - [Resource Directory](#resource-directory)
  - [Exception Directory](#exception-directory)
  - [Security Directory](#security-directory)
  - [Base Relocation Directory](#base-Relocation-directory)
  - [Debug Directory](#debug-directory)
  - [TLS Directory](#tls-directory)
  - [Load Config Directory](#load-config-directory)
  - [Bound Import Directory](#bound-import-directory)
  - [IAT Directory](#iat-directory)
  - [Delay Import Directory](#delay-import-directory)
  - [CLR Header Directory](#clr-header-directory)
  - [All Data Directories](#all-data-directories)
- [Miscellaneous](#miscellaneous)
  - [Rich Header](#rich-header)
  - [Version Info](#version-info)
  - [Symbol Table](#symbol-table)
  - [String Table](#string-table)
  - [Overlay](#overlay)
  - [Overview](#overview)
- [Formatting](#formatting)
  - [Address Translation](#address-translation)
  - [Output Formatting](#output-formatting)
- [Data Extraction](#data-extraction)
  - [String Extraction](#string-extraction)
  - [Metadata Extraction](#metadata-extraction)
- [Hashing](#hashing)
- [Comparison](#comparison)

---

## Help & Usage

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
000000014000013A  0000013A  [2]         OS Version (Minor)         : 0000
                                                                   + 000A  IMAGE_OS_WIN10

000000014000013C  0000013C  [2]         Image Version (Major)      : 000A
000000014000013E  0000013E  [2]         Image Version (Minor)      : 0000
                                                                   + 000A  IMAGE_VER_10_0

0000000140000140  00000140  [2]         Subsystem Version (Major)  : 000A
0000000140000142  00000142  [2]         Subsystem Version (Minor)  : 0000
                                                                   + 000A  IMAGE_SUBSYS_WIN10

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

### Section Headers
**Syntax:**
```bash
$ PEDump -sh <file>
$ PEDump --section-headers <file>
```
**Description:**
Print Section Headers.

**Example:**
```
$ PEDump -sh C:\Windows\System32\notepad.exe

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

------------- END OF IMPORT DESCRIPTOR 1 (25 functions) -------------

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

------------- END OF IMPORT DESCRIPTOR 50 (1 function) -------------
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

### Exception Directory
**Syntax:**
```bash
$ PEDump -ex <file>
$ PEDump --exception <file>
```
**Description:**
Print the exception directory containing structured exception handling (SEH) information.

**Example:**
```
$ PEDump -ex C:/Windows/System32/notepad.exe

0000000140037000 - EXCEPTION DIRECTORY - number of entries: 385 (entry type: IMAGE_RUNTIME_FUNCTION_ENTRY (x64 / Itanium unwind))

Idx   VA               FO         Begin      End        UnwindInfo
1     0000000140037000 00035000   00001008   0000108E   0002FFF0
2     000000014003700C 0003500C   00001094   000011B5   0002FFCC
3     0000000140037018 00035018   000011BC   00001252   0002FFE0
4     0000000140037024 00035024   00001260   000012D4   0002F7A4
5     0000000140037030 00035030   000012DC   0000137A   0002F7A4

[... skipped ...]

381   00000001400381D0 000361D0   000275F0   00027612   0002F4F0
382   00000001400381DC 000361DC   00027620   00027642   0002F4F0
383   00000001400381E8 000361E8   00027650   00027672   0002F4F0
384   00000001400381F4 000361F4   00027680   000276AE   0002F4F0
385   0000000140038200 00036200   000276C0   000276E2   0002F4F0

                        [End of entries]

```

---

### Security Directory
**Syntax:**
```bash
$ PEDump -sec <file>
$ PEDump --security <file>
```
**Description:**
Print the security directory containing certificates and related metadata.

**Example:**
```
$ PEDump -sec C:/Windows/System32/kernel32.dll

000C8000                        - SECURITY DIRECTORY -

idx  FO        Length    Revision                     CertType
1    000C8000  00004230  0200-(WIN_CERT_REVISION_2_0) 0002-(WIN_CERT_TYPE_PKCS_SIGNED_DATA)

------------------------------------------ CertData -------------------------------------------
30 82 42 24 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 42 15 30 82 42 11 02 01 01 31 0F 30 0D 06 09
60 86 48 01 65 03 04 02 01 05 00 30 82 1C DC 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 82 1C CC 30
82 1C C8 30 82 1C 91 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 82 1C 81 03 01 00 A0 82 1C 7A A1 82
1C 76 04 10 A6 B5 86 D5 B4 A1 24 66 AE 05 A2 17 DA 8E 60 D6 04 82 1C 60 31 82 1C 5C 30 82 1C 58
06 0A 2B 06 01 04 01 82 37 02 03 02 31 82 1C 48 04 82 1C 44 00 00 00 00 AF 1B FC 09 9B 5C 1C 88

                                       [... skipped ...]

67 0C 5C 7F 8A 33 E1 52 47 4D C4 A0 08 D9 5E 82 5B 30 57 51 6A BB 36 E5 2F 19 3F 54 46 5F 7A E3
43 14 2C 4A F1 0A C3 09 98 01 91 EC E9 F2 0A A9 44 61 B6 5C 6E 1E 7C 36 74 D1 75 D5 AD F1 78 3B
63 B0 9C E3 BB 32 E7 72 08 52 23 BE B9 F5 4C 43 DE F8 4E 81 90 37 D4 A7 79 50 73 8A 34 EA F2 AF
40 B4 D1 64 E3 F3 C8 88 29 A2 FF 45 8A DF AD 96 B4 F5 5E 20 ED EE C5 17 44 DC 9C 32 75 61 37 8C
CC F8 49 4B 43 4F 62 7B
--------------------------------------- End Of CertData ---------------------------------------

```

---

### Base Relocation Directory
**Syntax:**
```bash
$ PEDump -br <file>
$ PEDump --basereloc <file>
```
**Description:**
Print the base relocation directory for address fixups when loading the PE in memory.

**Example:**
```
$ PEDump -br C:/Windows/System32/notepad.exe
[Note: Some entries are skipped in this example for readability]

0000000140059000        - BASE RELOCATION DIRECTORY -

Block VA: 0000000140029000  FO: 00029000  Size: 000001FC (508)  Entries: 250

  Entry #   Offset    Relocated VA        Type
  -------   ------    ----------------    ----------------
  1         0x0000    0x0000000140029000  RISCV_LOW12I
  2         0x0008    0x0000000140029008  RISCV_LOW12I
  3         0x0010    0x0000000140029010  RISCV_LOW12I
  4         0x0018    0x0000000140029018  RISCV_LOW12I
  5         0x0020    0x0000000140029020  RISCV_LOW12I

  [... skipped entries for brevity ...]

Block VA: 0000000140039000  FO: 00037000  Size: 0000003C (60)  Entries: 26

  Entry #   Offset    Relocated VA        Type
  -------   ------    ----------------    ----------------
  1         0x0000    0x0000000140039000  RISCV_LOW12I
  2         0x0008    0x0000000140039008  RISCV_LOW12I
  3         0x0018    0x0000000140039018  RISCV_LOW12I
  4         0x0020    0x0000000140039020  RISCV_LOW12I
  5         0x0028    0x0000000140039028  RISCV_LOW12I
  6         0x0030    0x0000000140039030  RISCV_LOW12I
  7         0x0038    0x0000000140039038  RISCV_LOW12I
  8         0x0040    0x0000000140039040  RISCV_LOW12I
  9         0x0048    0x0000000140039048  RISCV_LOW12I
  10        0x0050    0x0000000140039050  RISCV_LOW12I
  ...
  25        0x00E8    0x00000001400390E8  RISCV_LOW12I
  26        0x0000    0x0000000140039000  ABSOLUTE

  --------------------------------------------------------

```

---

### Debug Directory
**Syntax:**
```bash
$ PEDump -d <file>
$ PEDump --debug <file>
```
**Description:**
Print the debug directory with debugging information like PDB paths.

**Example:**
```
$ PEDump -d C:/Windows/System32/notepad.exe

0002E2F0        - DEBUG DIRECTORY - number of debug entries: 4 -

[1] Type Name: CODEVIEW (FO=2E2F0)
        Characteristics: 0 | ReproChecksum: 7C74B70C (2088023820) | Version: 0.0 | Type: 2 | Size Of Data: 24
        Address Of Raw Data: 0002ED50  [VA: 14002ED50] [FO: 2ED50] [.rdata  ] | Pointer To Raw Data: 0002ED50

            0002ED50    - CodeView pdb70 Debug Info -

            FO        Size              Field          Value
            0002ED50  [ 4]              CV Signature : RSDS
            0002ED54  [16]              Signature    : 44543F42-253F-628F-2EE1-6BFAF8488CA6
            0002ED64  [ 4]              Age          : 1
            0002ED68  [ 8]              PDB FileName : notepad.

[2] Type Name: POGO (FO=2E30C)
        Characteristics: 0 | ReproChecksum: 7C74B70C (2088023820) | Version: 0.0 | Type: D | Size Of Data: 47C
        Address Of Raw Data: 0002ED74  [VA: 14002ED74] [FO: 2ED74] [.rdata  ] | Pointer To Raw Data: 0002ED74

[3] Type Name: REPRO (FO=2E328)
        Characteristics: 0 | ReproChecksum: 7C74B70C (2088023820) | Version: 0.0 | Type: 10 | Size Of Data: 24
        Address Of Raw Data: 0002F218  [VA: 14002F218] [FO: 2F218] [.rdata  ] | Pointer To Raw Data: 0002F218

            00020000     - REPRO Debug Info -

            REPRO hash (hash type: SHA-256 (256-bit)): 423F54443F258F622EE16BFAF8488CA67FB28E16E050ED37B1D89FBB0CB7747C

[4] Type Name: EX_DLLCHARACTERISTICS (FO=2E344)
        Characteristics: 0 | ReproChecksum: 7C74B70C (2088023820) | Version: 0.0 | Type: 14 | Size Of Data: 4
        Address Of Raw Data: 0002F23C  [VA: 14002F23C] [FO: 2F23C] [.rdata  ] | Pointer To Raw Data: 0002F23C

```

---

### TLS Directory
**Syntax:**
```bash
$ PEDump -tls <file>
$ PEDump --tls <file>
```
**Description:**
Print the Thread Local Storage directory used for thread-specific data.

**Example:**
```
$ PEDump -tls C:\Tools\Sysinternals\Autoruns.exe   (Sysinternals Autoruns)

00000000004CDA00        - TLS DIRECTORY -

VA                FO        Field       Value
00000000004CDA00  000CCC00  [4]         Start Address Of Raw Data : 004D3A3C
00000000004CDA04  000CCC04  [4]         End Address Of Raw Data   : 004D3A98

00000000004CDA08  000CCC08  [4]         Address Of Index          : 004FCC44

00000000004CDA0C  000CCC0C  [4]         Address Of Call Backs     : 004B3884

00000000004CDA10  000CCC10  [4]         Size Of Zero Fill         : 00000000

00000000004CDA14  000CCC14  [4]         Characteristics           : 00300000


00000000004B3884        - CALL BACK ENTRIES -

Idx    AddrOfCallBacks   OffOfCallBacks    CallBackEntries
1      00000000004B3884  000B2A84          0047E667

                          [End of entries]

```

---

### Load Config Directory
**Syntax:**
```bash
$ PEDump -lc <file>
$ PEDump --load-config <file>
```
**Description:**
Print the load configuration directory with security and runtime flags.

**Example:**
```
PEDump -lc C:/Windows/System32/kernel32.dll
[Note: Some tables are skipped in this example for readability]

0000000180088E00        - LOAD CONFIG DIRECTORY -

VA                FO        Field       Value
0000000180088E00  00088E00  [4]         Size                                           : 00000148

0000000180088E04  00088E04  [4]         Time Date Stamp                                : 00000000

0000000180088E08  00088E08  [2]         Minor Version                                  : 0000
0000000180088E0A  00088E0A  [2]         Major Version                                  : 0000

0000000180088E0C  00088E0C  [4]         Global Flag Clear                              : 00000000
0000000180088E10  00088E10  [4]         Global Flag Set                                : 00000000

0000000180088E14  00088E14  [4]         Critical Section Default Timeout               : 00000000

0000000180088E18  00088E18  [8]         DeCommit Block Free Threshold                  : 0000000000000000
0000000180088E20  00088E20  [8]         DeCommit Total Free Threshold                  : 0000000000000000

0000000180088E28  00088E28  [8]         Lock Prefix Table                              : 0000000000000000
0000000180088E30  00088E30  [8]         Maximum Allocation Size                        : 0000000000000000

0000000180088E38  00088E38  [8]         Virtual Memory Threshold                       : 0000000000000000

0000000180088E40  00088E40  [8]         Process Affinity Mask                          : 0000000000000000

0000000180088E48  00088E48  [4]         Process Heap Flags                             : 00000000

0000000180088E4C  00088E4C  [2]         CSD Version                                    : 0000

0000000180088E4E  00088E4E  [2]         Dependent Load Flags                           : 0000

0000000180088E50  00088E50  [8]         Edit List                                      : 0000000000000000

0000000180088E58  00088E58  [8]         Security Cookie                                : 00000001800BF230

0000000180088E60  00088E60  [8]         SEHandler Table                                : 0000000000000000
0000000180088E68  00088E68  [8]         SEHandler Count                                : 0000000000000000

0000000180088E70  00088E70  [8]         Guard CF Check Function Pointer                : 000000018008BA50
0000000180088E78  00088E78  [8]         Guard CF Dispatch Function Pointer             : 000000018008BA58

0000000180088E80  00088E80  [8]         Guard CF Function Table                        : 000000000008BBCC  [VA: 18008BBCC] [FO: 8BBCC] [ .rdata  ]
0000000180088E88  00088E88  [8]         Guard CF Function Count                        : 00000000000005FA

0000000180088E90  00088E90  [4]         Guard Flags                                    : 10417500
                                                                                       + 00000100  IMAGE_GUARD_CF_INSTRUMENTED
                                                                                       + 00000400  IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
                                                                                       + 00001000  IMAGE_GUARD_PROTECT_DELAYLOAD_IAT
                                                                                       + 00002000  IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION
                                                                                       + 00004000  IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT
                                                                                       + 00010000  IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT
                                                                                       + 00400000  IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT
                                                                                       + 10000000  IMAGE_GUARD_JUMPTABLE_PRESENT

0000000180088E94  00088E94  [2]         CodeIntegrity.Flags                            : 0000
0000000180088E96  00088E96  [2]         CodeIntegrity.Catalog                          : 0000
0000000180088E98  00088E98  [4]         CodeIntegrity.CatalogOffset                    : 00000000
0000000180088E9C  00088E9C  [4]         CodeIntegrity.Reserved                         : 00000000

0000000180088EA0  00088EA0  [8]         Guard Address Taken IAT Entry Table            : 000000000008D9B0  [VA: 18008D9B0] [FO: 8D9B0] [ .rdata  ]
0000000180088EA8  00088EA8  [8]         Guard Address Taken IAT Entry Count            : 0000000000000003

0000000180088EB0  00088EB0  [8]         Guard Long Jump Target Table                   : 0000000000000000
0000000180088EB8  00088EB8  [8]         Guard Long Jump Target Count                   : 0000000000000000

0000000180088EC0  00088EC0  [8]         Dynamic Value Reloc Table                      : 0000000000000000

0000000180088EC8  00088EC8  [8]         CHPE Metadata Pointer                          : 0000000000000000

0000000180088ED0  00088ED0  [8]         Guard RF Failure Routine                       : 0000000000000000
0000000180088ED8  00088ED8  [8]         Guard RF Failure Routine Function Pointer      : 0000000000000000

0000000180088EE0  00088EE0  [4]         Dynamic Value Reloc Table Offset               : 000005F8
0000000180088EE4  00088EE4  [2]         Dynamic Value Reloc Table Section              : 0008

0000000180088EE6  00088EE6  [2]         Reserved2                                      : 0000

0000000180088EE8  00088EE8  [8]         Guard RF Verify Stack Pointer Function Pointer : 0000000000000000

0000000180088EF0  00088EF0  [4]         Hot Patch Table Offset                         : 00000000

0000000180088EF4  00088EF4  [4]         Reserved3                                      : 00000000

0000000180088EF8  00088EF8  [8]         Enclave Configuration Pointer                  : 0000000000000000

0000000180088F00  00088F00  [8]         Volatile Metadata Pointer                      : 0000000000000000

0000000180088F08  00088F08  [8]         Guard Address Taken IAT Entry Table            : 000000000008BA80  [VA: 18008BA80] [FO: 8BA80] [ .rdata  ]
0000000180088F10  00088F10  [8]         Guard EH Continuation Count                    : 0000000000000042

0000000180088F18  00088F18  [8]         Guard XFG Check Function Pointer               : 000000018008BA60
0000000180088F20  00088F20  [8]         Guard XFG Dispatch Function Pointer            : 000000018008BA68
0000000180088F28  00088F28  [8]         Guard XFG Table Dispatch Function Pointer      : 000000018008BA70

0000000180088F30  00088F30  [8]         Cast Guard Os Determined Failure Mode          : 000000018008BA78

0000000180088F38  00088F38  [8]         Guard Memcpy Function Pointer                  : 0000000000000000

        - GuardCFFunctionTable table (VA: 18008BBCC) - 1530 entries -

 ----------------------------------------------------------------------------------
  [0001] VA: 18008BBCC        FO: 8BBCC     Value: 1130     Meta: 0   [   .text   ]
  [0002] VA: 18008BBD1        FO: 8BBD1     Value: 1220     Meta: 0   [   .text   ]
  [0003] VA: 18008BBD6        FO: 8BBD6     Value: 2520     Meta: 0   [   .text   ]
  [0004] VA: 18008BBDB        FO: 8BBDB     Value: 5C40     Meta: 0   [   .text   ]
  [0005] VA: 18008BBE0        FO: 8BBE0     Value: ACF0     Meta: 2   [   .text   ]

  [... skipped entries for brevity ...]

        - GuardEHContinuationTable table (VA: 18008BA80) - 66 entries -

 ----------------------------------------------------------------------------------
  [01] VA: 18008BA80        FO: 8BA80     Value: D05E     Meta: 0   [   .text   ]
  [02] VA: 18008BA85        FO: 8BA85     Value: D172     Meta: 0   [   .text   ]
  [03] VA: 18008BA8A        FO: 8BA8A     Value: D733     Meta: 0   [   .text   ]
  [04] VA: 18008BA8F        FO: 8BA8F     Value: DD26     Meta: 0   [   .text   ]
  [05] VA: 18008BA94        FO: 8BA94     Value: 12AD5    Meta: 0   [   .text   ]
  [06] VA: 18008BA99        FO: 8BA99     Value: 19E16    Meta: 0   [   .text   ]
  [07] VA: 18008BA9E        FO: 8BA9E     Value: 19F8D    Meta: 0   [   .text   ]
  [08] VA: 18008BAA3        FO: 8BAA3     Value: 1A2AF    Meta: 0   [   .text   ]
  [09] VA: 18008BAA8        FO: 8BAA8     Value: 1A41E    Meta: 0   [   .text   ]
  [10] VA: 18008BAAD        FO: 8BAAD     Value: 1F078    Meta: 0   [   .text   ]
  ...
  [65] VA: 18008BBC0        FO: 8BBC0     Value: 7D983    Meta: 0   [   .text   ]
  [66] VA: 18008BBC5        FO: 8BBC5     Value: 7DBAF    Meta: 0   [   .text   ]
 ----------------------------------------------------------------------------------

```

---

### Bound Import Directory
**Syntax:**
```bash
$ PEDump -bi <file>
$ PEDump --bound-import <file>
```
**Description:**
Print the bound import directory containing precomputed import addresses.

**Example:**
```
$ PEDump -bi C:/Some/Random/Folder/calc.exe   (Classic Calculator from Windows XP v5.1, contains bound imports)
[Note: Some entries are skipped in this example for readability]

0000000001000260 - BOUND IMPORT DIRECTORY -

Bound Import: SHELL32.dll (FO=260 | VA=1000260)
    TimeDateStamp: 3B7DFE0F (Saturday 2001.08.18 08:33:03 UTC)
    Offset Module Name: 00000038 | Number Of Module Forwarder Refs: 0

Bound Import: msvcrt.dll (FO=268 | VA=1000268)
    TimeDateStamp: 3B7DFE0E (Saturday 2001.08.18 08:33:02 UTC)
    Offset Module Name: 00000044 | Number Of Module Forwarder Refs: 0

            [... skipped entries for brevity ...]

```

---

### IAT Directory
**Syntax:**
```bash
$ PEDump -iat <file>
$ PEDump --iat <file>
```
**Description:**
Print the import address table mapping imported functions to memory addresses.

**Example:**
```
$ PEDump -iat C:/Windows/System32/notepad.exe



00000001400298D8          IMPORT ADDRESS TABLE: 11 Entries

00000001400298D8  000298D8  [8]            3348E
00000001400298E0  000298E0  [8]            334A2
00000001400298E8  000298E8  [8] 800000000000017D
00000001400298F0  000298F0  [8]            334BA
00000001400298F8  000298F8  [8] 800000000000019A
0000000140029900  00029900  [8]            334D2
0000000140029908  00029908  [8]            334E4
0000000140029910  00029910  [8] 800000000000019D
0000000140029918  00029918  [8]            334FC
0000000140029920  00029920  [8] 8000000000000159
0000000140029928  00029928  [8]            33510
```

>**Note**: IAT output uses the same function as the Import Directory parser, so it’s just not perfectly aligned.

---

### Delay Import Directory
**Syntax:**
```bash
$ PEDump -di <file>
$ PEDump --delay-import <file>
```
**Description:**
Print the delay import directory for functions loaded only when first used.

**Example:**
```
$ PEDump -di C:/Windows/System32/notepad.exe
[Note: Some entries are skipped in this example for readability]

00000001400302F0 - DELAY IMPORT DIRECTORY - number of delay import descriptors: 6

00000001400302F0 DELAY IMPORT descriptor: 1  - Library: ADVAPI32.dll

VA                FO        Size        Value
00000001400302F0  000302F0  [ 4]        All Attributes                 : 00000001

00000001400302F4  000302F4  [ 4]        Dll Name RVA                   : 0002A800  [VA: 14002A800] [FO: 2A800] [  .rdata  ]
000000014002A800  0002A800  [12]        Dll Name                       : ADVAPI32.dll

00000001400302F8  000302F8  [ 4]        Module Handle RVA              : 000352A8  [VA: 1400352A8] [FO: 352A8] [  .data   ]

00000001400302FC  000302FC  [ 4]        Import Address Table RVA       : 00039000  [VA: 140039000] [FO: 37000] [  .didat  ]
0000000140030300  00030300  [ 4]        Import Name Table RVA          : 000303D0  [VA: 1400303D0] [FO: 303D0] [  .rdata  ]

0000000140030304  00030304  [ 4]        Bound Import Address Table RVA : 000306C0  [VA: 1400306C0] [FO: 306C0] [  .rdata  ]

0000000140030308  00030308  [ 4]        Unload Information Table RVA   : 00000000

000000014003030C  0003030C  [ 4]        Time Date Stamp                : 00000000




00000001400303D0          HINT NAME TABLE: 2 Enties

00000001400303D0  000303D0  [8]         [VA: 1400304E6] [FO: 304E6] [  .rdata  ]
00000001400304E6                                             304E6  [  2]            Hint : 00EA  (234)
00000001400304E8                                             304E8  [ 12]            Name : DecryptFileW

00000001400303E0  000303E0  [8]         [VA: 1400304C8] [FO: 304C8] [  .rdata  ]
00000001400304C8                                             304C8  [  2]            Hint : 00EF  (239)
00000001400304CA                                             304CA  [ 27]            Name : DuplicateEncryptionInfoFile




0000000140039000          IMPORT ADDRESS TABLE: 2 Entries

0000000140039000  00037000  [8]        140002B24
0000000140039008  00037008  [8]        140002B12

--------------------------- END OF DELAY IMPORT DESCRIPTOR 1 (2 functions) ---------------------------

[... skipped entries for brevity ...]

```

---

### CLR Header Directory
**Syntax:**
```bash
$ PEDump -ch <file>
$ PEDump --clr-header <file>
```
**Description:**
Print CLR header (not fully implemented).

**Example:**
```
$ PEDump -ch C:/Windows/Microsoft.NET/Framework/v4.0.30319/mscorlib.dll

0000000079722008        - CLR/.NET HEADER DIRECTORY -

VA                FO        Size        Value
0000000079722008  00000208  [4]         cb                           : 00000048

000000007972200C  0000020C  [2]         Major Runtime Version        : 0002
000000007972200E  0000020E  [2]         Minor Runtime Version        : 0005

0000000079722010  00000210  [4]         MetaData.VA                  : 001899E8
0000000079722014  00000214  [4]         MetaData.Size                : 0026A714

0000000079722018  00000218  [4]         Flags                        : 0000000B
                                                                     + 00000001  COMIMAGE_FLAGS_ILONLY
                                                                     + 00000002  COMIMAGE_FLAGS_32BITREQUIRED
                                                                     + 00000008  COMIMAGE_FLAGS_STRONGNAMESIGNED

000000007972201C  0000021C  [4]         Entry Point Token            : 00000000

0000000079722020  00000220  [4]         Resources.VA                 : 003F40FC
0000000079722024  00000224  [4]         Resources.Size               : 000F4D38

0000000079722028  00000228  [4]         StrongNameSignature.VA       : 004E8E34
000000007972202C  0000022C  [4]         StrongNameSignature.Size     : 00000100

0000000079722030  00000230  [4]         CodeManagerTable.VA          : 00000000
0000000079722034  00000234  [4]         CodeManagerTable.Size        : 00000000

0000000079722038  00000238  [4]         VTableFixups.VA              : 00000000
000000007972203C  0000023C  [4]         VTableFixups.Size            : 00000000

0000000079722040  00000240  [4]         ExportAddressTableJumps.VA   : 00000000
0000000079722044  00000244  [4]         ExportAddressTableJumps.Size : 00000000

0000000079722048  00000248  [4]         ManagedNativeHeader.VA       : 00000000
000000007972204C  0000024C  [4]         ManagedNativeHeader.Size     : 00000000

```

---

### All Data Directories
**Syntax:**
```bash
$ PEDump -dd <file>
$ PEDump --data-directories <file>
```
**Description:**
Prints all available data directories (Export, Import, Resource, Exception, Security, Relocations, Debug, TLS, Load Config, Bound Import, IAT, Delay Import, COM Descriptor) in a single command.

**Example:**
```
$ PEDump -dd C:\Windows\System32\notepad.exe

00000001400308D0        - IMPORT DIRECTORY - number of import descriptors: 50
# ... import directory details ...


========================================================================================================
========================================================================================================


000000004003a000        - RESOURCE DIRECTORY -
# ... import directory details ...


========================================================================================================
========================================================================================================


0000000140029790        - LOAD CONFIG DIRECTORY -
# ... resource directory details ...


# ... additional directories printed similarly ...
```

---

## Miscellaneous

***Commands for checksum, subsystem, alignment info, and other extra features.***

---

### Rich Header
**Syntax:**
```bash
$ PEDump -rh <file>
$ PEDump --rich-header <file>
```
**Description:**
Print Rich header (Microsoft-specific metadata in PE files, mostly used for compiler/tool identification). Not all values may be fully interpreted.

**Example:**
```
$ PEDump -rh C:\Windows\System32\kernel32.dll

00000080                                                        - RICH HEADER -

00000080  [4]  DanS marker      : 536E6144  ("DanS")

00000084  [4]  Checksum padding : 75037CFD
00000088  [4]  Checksum padding : 75037CFD
0000008C  [4]  Checksum padding : 75037CFD


Index | FO         | Value              | Unmasked Value     | Meaning                            | ProdID                               | BuildID  | Count
----------------------------------------------------------------------------------------------------------------------------------------------------------------
    1 | 0x00000090 | 0x75037CF97402FD84 | 0x0000000401018179 | 00033145.00000257.0000000000000004 | 00000257 - prodidImplib1400          | 00033145 |         4
    2 | 0x00000098 | 0x75037C2C759004F4 | 0x000000D100937809 | 00030729.00000147.0000000000000209 | 00000147 - prodidImplib900           | 00030729 |       209
...
    9 | 0x000000D0 | 0x75037CFC75FCFD84 | 0x0000000100FF8179 | 00033145.00000255.0000000000000001 | 00000255 - prodidCvtres1400          | 00033145 |         1
   10 | 0x000000D8 | 0x75037CFC7401FD84 | 0x0000000101028179 | 00033145.00000258.0000000000000001 | 00000258 - prodidLinker1400          | 00033145 |         1
----------------------------------------------------------------------------------------------------------------------------------------------------------------

000000E0  [4]  Rich marker      : 68636952  ("Rich")
000000E4  [4]  Checksum         : 75037CFD

```

---

### Version Info
**Syntax:**
```bash
$ PEDump -vi <file>
$ PEDump --version-info <file>
```
**Description:**
Print Version Information (VS_VERSION_INFO) resource, including fixed metadata and string tables (company, version, product, etc.).

**Example:**
```
$ PEDump -vi C:\Windows\System32\kernel32.dll

VS_VERSION_INFO - (VA=1800C70B0, FO=C60B0) [928 bytes]:
    wValueLength : 0034 (52)
    wType        : binary data

    VS_FIXEDFILEINFO - (VA=1800C70D8, FO=C60D8) [52 bytes]:
        dwSignature    : FEEF04BD
        StrucVersion   : 00010000
        FileVersion    : 10.0.26100.7623
        ProductVersion : 10.0.26100.7623
        FileFlagsMask  : 0000003F
        dwFileFlags    : 00000000
        FileOS         : 00040004 (VOS_NT_WINDOWS32)
        FileType       : 00000002 (VFT_DLL)
        FileSubtype    : 00000000
        FileDate       : 00000000

StringFileInfo - (VA=1800C710C, FO=C610C) [768 bytes]:
    040904B0 (U.S. English, Unicode) - (VA=1800C7130, FO=C6130) [732 bytes]:
        (VA=1800C7148, FO=C6148)   CompanyName        : Microsoft Corporation                                                [76 bytes]
        (VA=1800C7194, FO=C6194)   FileDescription    : Windows NT BASE API Client DLL                                       [102 bytes]
        (VA=1800C71FC, FO=C61FC)   FileVersion        : 10.0.26100.7623 (WinBuild.160101.0800)                               [110 bytes]
        (VA=1800C726C, FO=C626C)   InternalName       : kernel32                                                             [50 bytes]
        (VA=1800C72A0, FO=C62A0)   LegalCopyright     : ⌐ Microsoft Corporation. All rights reserved.                        [128 bytes]
        (VA=1800C7320, FO=C6320)   OriginalFilename   : kernel32                                                             [58 bytes]
        (VA=1800C735C, FO=C635C)   ProductName        : Microsoft« Windows« Operating System                                 [106 bytes]
        (VA=1800C73C8, FO=C63C8)   ProductVersion     : 10.0.26100.7623                                                      [68 bytes]

VarFileInfo - (VA=1800C740C, FO=C640C) [68 bytes]:
     Var - (VA=1800C742C, FO=C642C) [36 bytes]:
        Translation : 4B00409 (Unicode, U.S. English) - (VA=1800C744C, FO=C644C) [4 bytes]

```

---

### Symbol Table
**Syntax:**
```bash
$ PEDump -sym <file>
$ PEDump --symbol-table <file>
```
**Description:**
Print COFF symbol table, including symbol names, section references, and auxiliary symbol records.

**Example:**
```
$ PEDump -sym PEDump.exe

0008D000   - COFF SYMBOL TABLE: 3502 Entries -

    [0001] .file (FO=8D000)
        Value: 5F (RVA=0 | FO=0) | Type: (NULL, NULL) | Section: (DEBUG symbol) | Storage: (IMAGE_SYM_CLASS_FILE - File)
        Aux:
            [0002] Auxiliary File Symbol (FO=8D012)
                File Name : crtexe.c

    [0003] __mingw_invalidParameterHandler (FO=8D024)
        Value: 0 (RVA=0 | FO=0) | Type: (NULL, FUNCTION) | Section: (.text) | Storage: (IMAGE_SYM_CLASS_STATIC - Static Symbol)
        Aux:
            [0004] Auxiliary Section Definition Symbol (FO=0008D036)
                Length              : 0x00000000 (0)
                NumberOfRelocations : 0x0000 (0)
                NumberOfLinenumbers : 0x0000 (0)
                CheckSum            : 0x00000000
                Number              : 4 (0x4)
                Selection           : 0


    [... skipped entries for brevity ...]


    [3500] __imp_fputwc (FO=9C606)
        Value: 488 (RVA=58488 | FO=54488) | Type: (NULL, NULL) | Section: (.idata) | Storage: (IMAGE_SYM_CLASS_EXTERNAL - External Symbol)
        Aux: None

    [3501] free (FO=9C618)
        Value: 3ACA8 (RVA=3BCA8 | FO=3B2A8) | Type: (NULL, FUNCTION) | Section: (.text) | Storage: (IMAGE_SYM_CLASS_EXTERNAL - External Symbol)
        Aux: None

    [3502] __mingw_app_type (FO=9C62A)
        Value: 3A0 (RVA=0 | FO=0) | Type: (NULL, NULL) | Section: (.bss) | Storage: (IMAGE_SYM_CLASS_EXTERNAL - External Symbol)
        Aux: None

```

---

### String Table
**Syntax:**
```bash
$ PEDump -st <file>
$ PEDump --string-table <file>
```
**Description:**
Print PE string table, including all long COFF symbol names, their offsets, and references used by the symbol table.

**Example:**
```
$ PEDump -st PEDump.exe

0009CA3C        - COFF STRING TABLE -

Idx      FO        Length   String
-------  --------  -------  ------------------------------
1        0009CA40  14       .debug_aranges
2        0009CA4F  11       .debug_info
3        0009CA5B  13       .debug_abbrev
4        0009CA69  11       .debug_line
5        0009CA75  12       .debug_frame
6        0009CA82  10       .debug_str
7        0009CA8D  15       .debug_line_str
8        0009CA9D  15       .debug_loclists
9        0009CAAD  15       .debug_rnglists
10       0009CABD  31       __mingw_invalidParameterHandler
...
663      0009FBA0  12       __imp_fputwc
664      0009FBAD  16       __mingw_app_type
----------------------------------------------------------

```

---

### Overlay
**Syntax:**
```bash
$ PEDump -o <file>
$ PEDump --overlay <file>
```
**Description:**
Print PE overlay, including any extra data appended after the last section, and dump the raw bytes with offsets, showing the full content as-is.

**Example:**
```
PEDump -o C:\Windows\System32\kernel32.dll

[+] Dump
    Start offset : 0x000C8000
    End offset   : 0x000CC22F
    Size         : 0x00004230 (16944 bytes)
    Bytes/line   : 16

ADDR         HEX BYTES                                            ASCII              NAME
0x000C8000   30 42 00 00  00 02 02 00  30 82 42 24  06 09 2A 86   |0B......0.B$..*.| * Security Directory * Overlay (after last section)
0x000C8010   48 86 F7 0D  01 07 02 A0  82 42 15 30  82 42 11 02   |H........B.0.B..|
0x000C8020   01 01 31 0F  30 0D 06 09  60 86 48 01  65 03 04 02   |..1.0...`.H.e...|
0x000C8030   01 05 00 30  82 1C DC 06  0A 2B 06 01  04 01 82 37   |...0.....+.....7|
0x000C8040   02 01 04 A0  82 1C CC 30  82 1C C8 30  82 1C 91 06   |.......0...0....|

# ... additional lines printed similarly ...

```

---


### Overview
**Syntax:**
```bash
$ PEDump -ov <file>
$ PEDump --overview <file>
```
**Description:**
Print a computed overview of the PE file, summarizing disk vs memory layout, image size calculations, alignment effects, overlay presence, section statistics, and density metrics derived from headers and sections. Values are computed from the parsed PE structures and may differ from raw on-disk sizes.

**Example:**
```
$ PEDump -ov C:\Windows\System32\kernel32.dll

======================================================================
Computed Overview : C:\Windows\System32\kernel32.dll
----------------------------------------------------------------------
Disk File Size             : 836144 bytes
In Memory Size             : 823296 bytes
Computed Image Size        : 823296 bytes (from sections + SectionAlignment)
Disk vs Memory Delta       : -12848 bytes (Memory - Disk)
Memory vs Computed Delta   : 0 bytes (Memory - Computed Image Size)
Truncated                  : no

Overlay Present            : yes
Overlay Offset             : 0xC8000 bytes
Overlay Size               : 16944 bytes (2.03% of file)

File Alignment             : 0x1000 bytes
Memory Alignment           : 0x1000 bytes
Alignment Waste (disk)     : 0 bytes (0.00% of file)
Alignment Expansion (mem)  : 16532 bytes (2.01% of memory image)

Header + Section Table     : 824 bytes (DOS + NT + Sections)

Section Count              : 8
Executable Sections Count  : 2
Writable Sections Count    : 2
Total Raw Data             : 815104 bytes
Total Virtual Data         : 802668 bytes
Executable/Data Ratio      : 214.65% (RX vs RW)

Header Density             : 0.10% of file
Memory Density             : 97.49% of memory image
----------------------------------------------------------------------

```

---

## Formatting

***Commands for VA-to-file offset conversions and adjusting output formats, including tables and raw***

---

### Address Translation
**Syntax:**
```bash
$ PEDump -v2f NUMBER <file>
$ PEDump --va2file NUMBER <file>
```
**Description:**
convert VA to file offset.

**Example:**
```
$ PEDump -v2f 180016967 C:\Windows\System32\kernel32.dll

=== VA -> File Offset ===
VA  :  0x0000000180016967
RVA :  0x00016967
FO  :  0x00016967
Sec :  .text (Index 1)

```

---

### Output Formatting
**Syntax:**
```bash
$ PEDump -f <type[:spec]> <file>
$ PEDump --format <type[:spec]> <file>
$ PEDump -tf <type[:spec]> <file>
$ PEDump --temp-format <type[:spec]> <file>
```

**Description:**
Controls how PEDump formats its output and optionally restricts the displayed byte range.
- **-f / --format** sets the persistent output format, applied consistently across all streamed commands for the duration of the current run.
- **-tf / --temp-format** sets a temporary output format that overrides `-f` for the current command or operation only.
If no format is explicitly selected, PEDump defaults to the table view.

**Types:**
- `hex`   – display bytes in **hexadecimal**, 16 bytes per line
- `dec`   – display bytes as **decimal values** (0–255)
- `bin`   – display bytes in **binary**, 8 bits per byte
- `table` – combined view: `offset | hex | ASCII` (**range specifiers are ignored**)

**Range Specifiers (for hex/dec/bin only):**
- `:N`           – print the first N lines; if negative, print |N| lines from the end
- `:start,max`   – print from **start** to **max**
  - decimal → **line index**
  - `0xHEX` → **file offset**, rounded up to the nearest line boundary
  - **negative values are not allowed**
- `:start..end`  – print from **start** to **end** offsets
  - decimal → **byte offset**, rounded up to the nearest line boundary
  - `0xHEX` → **hex byte offset**
  - **negative values are not allowed**

**Notes:**
- The selected output format applies to **all streamed commands** for the duration of the current run (-f).
- Temporary format (-tf) overrides the persistent format only for the current operation.
- If no format is specified, PEDump uses the `table` format by default.
- Bytes-per-line depends on the format (16 for hex/dec/bin).
- Offsets starting with `0x` are treated as byte offsets and **aligned to the view's bytes-per-line**.

**Example:**
```
# Print the File Header in hexadecimal
PEDump -f hex -fh test.exe

# Print first 10 lines of the file in hexadecimal (:N syntax)
PEDump -f hex:10 -a test.exe

# Print last 10 lines of the file in decimal (:N syntax with negative value)
PEDump -f dec:-10 -a test.exe

# Print bytes from 0x100 to 0x1FF in binary (:start,max syntax using byte offsets)
PEDump -f bin:0x100,0x1FF -a test.exe

# Print lines 5 to 15 in hexadecimal (:start,max syntax using line numbers)
PEDump -f hex:5,15 -a test.exe

# Print byte offsets from 0x200 to 0x2FF in hexadecimal (:start,max syntax using byte offsets)
PEDump -f hex:0x200,0x2FF -a test.exe

# Print byte offsets from 0x300 to 0x350 in hexadecimal (:start..end syntax)
PEDump -f hex:0x300..0x350 -a test.exe

# Display a combined table view of the DOS header
PEDump -f table -dh test.exe

# Use a temporary format for a single operation
PEDump -tf dec:10 -a test.exe
```

---

## Data Extraction

***Commands to extract sections, resources, data blocks, or printable strings from the PE file or its specific sections into separate files.***

---
### String Extraction
**Syntax:**
```bash
$ PEDump -s [rgex:<pattern>] <file>
$ PEDump --strings [rgex:<pattern>] <file>
```

**Description:**
Dump ASCII and UTF-16LE strings from the file, with optional regex filtering.

- **-s / --strings** dumps all strings if no `<pattern>` is provided.
- Optional regex filtering allows you to extract only strings matching a specific pattern.

**Regex Filtering:**
- `rgex:<pattern>` – filters strings matching `<pattern>`
- Regex backend:
  - Uses system POSIX regex if available
  - Otherwise falls back to TinyRegex

**Notes:**
- Both ASCII and UTF-16LE strings are supported.
- If no regex is provided, all printable strings in the file are dumped.

**Examples:**
```
# Dump all strings
PEDump -s test.exe

# Dump strings starting with "Hello"
PEDump -s rgex:^Hello test.exe

# Dump strings containing digits
PEDump --strings rgex:\d+ test.exe
```

---

### Metadata Extraction
**Syntax:**
```bash
$ PEDump -x <target[:spec]> <file>
$ PEDump --extract <target[:spec]> <file>
```

**Description:**
Extract specific parts of a PE file according to the selected target.

- **-x / --extract** extracts a specific part of the PE file.
- `<target>` specifies what to extract, with optional `:spec` modifiers.

**Targets:**
- `section:NAME`        – extract a section by name (e.g., `section:.text`, `section:.rdata`)
- `section:#IDX`        – extract a section by index (e.g., `section:#2`)
- `section:rva/VAL`     – extract data at a specific RVA (e.g., `section:rva/0x401000`)
- `section:fo/VAL`      – extract data at a specific file offset (e.g., `section:fo/0x200`)

- `export:NAME`         – extract an exported function by name (e.g., `export:CreateFileA`)
- `export:#ORD`         – extract an exported function by ordinal (e.g., `export:#37`)
- `export:rva/VAL`      – extract an exported entry by RVA; matches either Func-RVA or Name-RVA (e.g., `export:rva/0x401000`)
- `export:FWD`          – extract a forwarded export (e.g., `export:KERNEL32.CreateFileA`)
- `export:LIB`          – extract ALL exports from the specified DLL (must include `.dll`, e.g., `export:KERNEL32.dll`)

- `import:NAME`         – extract a function by name globally (e.g., `CreateFileA`)
- `import:#ORD`         – extract a function by ordinal globally (e.g., `#0x287`)
- `import:@HNT`         – extract a function by hint globally (e.g., `@37`)
- `import:LIB`          – extract ALL imports from the specified DLL (must include `.dll`, e.g., `import:KERNEL32.dll`)
- `import:LIB/NAME`     – extract a function by name (e.g., `KERNEL32.dll/CreateFileA`)
- `import:LIB/#ORD`     – extract a function by ordinal (e.g., `KERNEL32.dll/#0x287`)
- `import:LIB/@HNT`     – extract a function by hint (e.g., `KERNEL32.dll/@37`)

**Address Specifiers:**
- `rva/VAL`             – use Relative Virtual Address (RVA)
- `fo/VAL`              – use File Offset (FO)

**Value Formats Accepted for VAL:**
- `HEX`                 – e.g., `rva/4198400`
- `0xHEX`               – e.g., `rva/0x401000`
- `HEXh` (Intel)        – e.g., `rva/401000h`
- Parsers are case-insensitive for hex digits and the trailing `h`.

**Examples:**
```
# Extract the .text section by name
PEDump -x section:.text test.exe

# Extract the second section by index
PEDump -x section:#2 test.exe

# Extract the section that contains the RVA 0x3050
PEDump -x section:rva/0x3050 test.exe

# Extract the section that contains the file offset 0x1100
PEDump -x section:fo/0x1100 test.exe

# Extract exported function by name
PEDump -x export:CreateFileA test.exe

# Extract exported function by ordinal
PEDump -x export:#37 test.exe

# Extract all exports from KERNEL32.dll
PEDump -x export:KERNEL32.dll test.exe

# Extract import function globally by name
PEDump -x import:CreateFileA test.exe

# Extract all imports from USER32.dll
PEDump -x import:USER32.dll test.exe

# Extract import by name from a specific DLL
PEDump -x import:KERNEL32.dll/CreateFileA test.exe
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
```