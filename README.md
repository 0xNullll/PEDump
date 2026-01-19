# PEDump

A cross-platform **Portable Executable (PE)** inspection and analysis tool written in C.  
`PEDump` performs static analysis of Windows PE files on Linux, Windows, and macOS.

---

## Platform Support

`PEDump` runs on:  
- Linux  
- Windows  
- macOS  

It analyzes **Windows PE binaries** on all supported platforms.

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
- **Linux / macOS**: `PEDump`

---

## Usage

```bash
PEDump [options] file [file2]
```

### General
- `-h`, `--help`                Show help message  

### Headers & PE Information
- `-dh`,  `--dos-header`        Print DOS header  
- `-fh`,  `--file-header`       Print File header  
- `-oh`,  `--optional-header`   Print Optional header  
- `-nth`, `--nt-headers`        Print NT headers  
- `-sec`, `--sections`          Print section table  

### Data Directories
- `-e`,    `--exports`          Print export directory  
- `-i`,    `--imports`          Print import directory  
- `-r`,    `--resources`        Print resources directory  
- `-ex`,   `--exception`        Print exception directory  
- `-sec`,  `--security`         Print security directory  
- `-br`,   `--basereloc`        Print base relocations  
- `-d`,    `--debug`            Print debug directory  
- `-tls`,  `--tls`              Print TLS directory  
- `-lc`,   `--load-config`      Print load config directory  
- `-bi`,   `--bound-import`     Print bound imports  
- `-iat`,  `--iat`              Print Import Address Table  
- `-di`,   `--delay-import`     Print delay imports  
- `-dd`,   `--data-directories` Print all data directories  

### CLR (Common Language Runtime)
- `-ch`, `--clr-header`         Print CLR header  

### Miscellaneous
- `-rh`,  `--rich`              Print Rich header  
- `-vi`,  `--version-info`      Print version information  
- `-sym`, `--symbol-table`      Print COFF symbol table  
- `-st`,  `--string-table`      Print COFF string table  
- `-o`,   `--overlay`           Print overlay data  
- `-ov`,  `--overview`          Print high-level file overview  
- `-a`,   `--all`               Print all available information  

### Strings
- `-str`, `--strings [rgex:<pattern>]`  
Dump ASCII and UTF-16LE strings. Optional regex filtering using POSIX regex or TinyRegex fallback.  

### Output Formatting
- `-v2f`, `--va2file <NUMBER>`  Convert virtual address to file offset  
- `-f`,   `--format <type[:spec]>` Output format:  
  - `hex`   Hexadecimal bytes (16 bytes per line)  
  - `dec`   Decimal bytes (0–255)  
  - `bin`   Binary bytes  
  - `table` Offset | Hex | ASCII  

Range specifiers:  
- `:N`              First N lines  
- `:start,max`      Line or byte range  
- `0x...`           Byte offset (aligned to line size)  

### Extraction
- `-x`, `--extract <target[:spec]>`  

Targets:  
- `section:NAME | #IDX | rva/VAL | fo/VAL`  
- `export:NAME | #ORD | rva/VAL | FWD | LIB`  
- `import:NAME | #ORD | @HNT | LIB | LIB/NAME`  

Address formats: `HEX`, `0xHEX`, `HEXh`  

### Hashing
- `-H`, `--hash <target[@alg]>`  
Supported algorithms: `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha512_224`, `sha512_256`  

### Comparison
- `-cc`, `--compare-targets <target1>::<target2[@alg]>`  
Compare regions between two files or within the same file.

---

## Example Usage

```bash
PEDump -ov sample.exe
PEDump -i sample.exe
PEDump -H section:.text@sha256 sample.exe
```

> **Note:** For detailed usage examples, advanced options, and command demonstrations, see [USAGE.md](USAGE.md).

---

## Features

- **🔹 Comprehensive PE header parsing** (DOS, NT, Optional) with detailed field inspection
- **🔹 Section table analysis** including sizes, permissions, and characteristics
- **🔹 Import and export directory analysis** with symbol resolution
- **🔹 Resource, TLS, debug, base reloc, security, and load-config directory inspection**
- **🔹 Rich header, version info, COFF symbol table, and string table extraction**
- **🔹 ASCII and UTF-16LE string extraction** with optional POSIX/TinyRegex filtering
- **🔹 Targeted extraction** of sections, imports, exports, and arbitrary file ranges
- **🔹 Flexible hashing** of PE regions with multiple algorithms (MD5, SHA variants)
- **🔹 Comparison** of PE regions across single or multiple files
- **🔹 Support for malformed or non-standard PE files** where feasible
- **🔹 Stream output**: Commands can be piped or streamed for live incremental analysis
- **🔹 Customizable output formatting**: hex, dec, bin, table views with range and offset specifiers

---

## Project Status

Under active development. Some options may be partially implemented or subject to change.

---

## Disclaimer

For educational and research purposes only.

---

## License

Released under the **MIT License**. See [LICENSE](LICENSE) for full text.