# PEDump Detailed Usage Guide

> **Note:** This file provides detailed command explanations, examples, and tips for using `PEDump`.
> For a quick reference, see [README.md](README.md).

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

***This section explains basic usage, global flags, and help commands.***

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

***Dump and inspect the DOS, NT, File, and Optional headers, as well as all sections of the PE file.***

---

### DOS Header
**Syntax:**
```bash
PEDump -dh <file>
PEDump --dos-header <file>
```
**Description:**
Print DOS header.

**Example:**
```
# output example placeholder
```

### File Header
**Syntax:**
```bash
PEDump -fh <file>
PEDump --file-header <file>
```
**Description:**
Print File header.

**Example:**
```
# output example placeholder
```

### Optional Header
**Syntax:**
```bash
PEDump -oh <file>
PEDump --optional-header <file>
```
**Description:**
Print Optional header.

**Example:**
```
# output example placeholder
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