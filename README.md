# PEDump

A cross-platform **Portable Executable (PE)** inspection and analysis tool written in C.  
`PEDump` performs static analysis of Windows PE files on Linux, Windows, with macOS support planned.

---

## Features

- **Comprehensive PE Analysis** – Full parsing of headers, sections, and directories; **CLR inspection limited to header only**
- **Cross-Platform Support** – Works on Windows, Linux; macOS support is planned
- **Robust Parsing** – Handles malformed or non-standard PE files
- **Stream Output** – Incremental or piped output for live analysis
- **Targeted Extraction** – Extract specific sections, imports, exports, or arbitrary ranges
- **Strings Extraction** – Extract ASCII and UTF-16LE strings from PE files
- **COFF Symbol & String Tables** – Access PE symbol and string tables not commonly exposed
- **Hashing** – Compute MD5, SHA1, and SHA2 hashes of files, sections, or ranges
- **Comparison** – Compare PE regions within the same file or between two files
- **Output Formatting** – Flexible formats: hex, dec, bin, table

---

## Build Requirements

- C11-compatible compiler (GCC, Clang, or MSVC)  
- CMake ≥ 3.20  
- Windows or POSIX environment

---

## Building

```powershell
mkdir build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The binary will be located in **build/bin/**:

- **Windows**: `PEDump.exe`  
- **Linux**: `PEDump`

---

## Usage

```bash
PEDump [options] file [file2]
```

---

## General

| Command | Description |
|--------|-------------|
| `-h`, `--help` | Show help message |

---

## Headers & PE Information

| Command | Description |
|--------|-------------|
| `-dh`, `--dos-header` | Print DOS header |
| `-fh`, `--file-header` | Print File header |
| `-oh`, `--optional-header` | Print Optional header |
| `-nth`, `--nt-headers` | Print NT headers |
| `-sh`, `--section-headers` | Print section headers |

---

## Data Directories

| Command | Description |
|--------|-------------|
| `-e`, `--exports` | Print export directory |
| `-i`, `--imports` | Print import directory |
| `-r`, `--resources` | Print resources directory |
| `-ex`, `--exception` | Print exception directory |
| `-sec`, `--security` | Print security directory |
| `-br`, `--basereloc` | Print base relocations |
| `-d`, `--debug` | Print debug directory |
| `-tls`, `--tls` | Print TLS directory |
| `-lc`, `--load-config` | Print load config directory |
| `-bi`, `--bound-import` | Print bound imports |
| `-iat`, `--iat` | Print Import Address Table |
| `-di`, `--delay-import` | Print delay imports |
| `-ch`, `--clr-header` | Print CLR header |
| `-dd`, `--data-directories` | Print all data directories |

---

## Miscellaneous

| Command | Description |
|--------|-------------|
| `-rh`, `--rich-header` | Print Rich header |
| `-vi`, `--version-info` | Print version information |
| `-sym`, `--symbol-table` | Print COFF symbol table |
| `-st`, `--string-table` | Print COFF string table |
| `-o`, `--overlay` | Print overlay data |
| `-ov`, `--overview` | Print high-level file overview |
| `-a`, `--all` | Print all available information |

---

## Output Formatting

| Command | Description |
|--------|-------------|
| `-v2f`, `--va2file <NUMBER>` | Convert virtual address to file offset |
| `-f`, `--format <type[:spec]>` | Output format and optional range |
| `-tf`, `--temp-format <type[:spec]>` | Temporary format override |

---

## Strings

| Command | Description |
|--------|-------------|
| `-str`, `--strings [rgex:<pattern>]` | Dump ASCII & UTF-16LE strings (minimum length: 5) |

---

## Extraction

| Command | Description |
|--------|-------------|
| `-x`, `--extract <target[:spec]>` | Extract sections, imports, exports, or regions |

**Targets**
- `section:NAME | #IDX | rva/VAL | fo/VAL`
- `export:NAME | #ORD | rva/VAL | FWD | LIB`
- `import:NAME | #ORD | @HNT | LIB | LIB/NAME`

**Address formats:** `HEX`, `0xHEX`, `HEXh`

---

## Hashing

| Command | Description |
|--------|-------------|
| `-H`, `--hash <target[@alg]>` | Hash file or region (MD5 / SHA family) |

Supported algorithms:
`md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha512_224`, `sha512_256`

---

## Comparison

| Command | Description |
|--------|-------------|
| `-cc`, `--compare-targets <target1>::<target2[@alg]>` | Compare regions between two targets |

---

## Example Usage

```bash
PEDump -ov test.exe
PEDump -i test.exe
PEDump -H section:.text@sha256 test.exe
```

> **Note:** For detailed usage examples, advanced options, and command demonstrations, see [USAGE.md](USAGE.md).

---

## Notes & Status

- All commands are implemented and fully tested on Windows.  
- Linux support is available but not yet fully verified; macOS support is planned and partially implemented.

---

## License

Released under the **MIT License**. See [LICENSE](LICENSE) for full text.