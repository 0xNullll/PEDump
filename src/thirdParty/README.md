# Third-Party / Internal Libraries

This directory contains minimal, self-contained C libraries used by this project. It currently includes:

1. **TinyRegex** – lightweight regex engine  
2. **Tiny SHA** – lightweight, portable SHA hashing library

---

## TinyRegex Integration

This directory contains a minimal regular expression (regex) engine based on  
**Tiny Regex C** by *Kokke* (https://github.com/kokke/tiny-regex-c).  
Minor modifications were made to allow `matchlength` to be optional (can be `NULL`) and to add additional safety checks.

### Overview

TinyRegex is a small and self-contained C library that provides simple regex  
matching functions. It’s designed to be portable and dependency-free, making it  
ideal for projects that need lightweight pattern matching without linking to  
the full POSIX regex library.

**Supported syntax:**

| Feature     | Description                                         |
|------------ |----------------------------------------------------|
| `.`         | Matches any single character                        |
| `^`         | Anchors to start of string                          |
| `$`         | Anchors to end of string                            |
| `*`         | Match zero or more (greedy)                         |
| `+`         | Match one or more (greedy)                          |
| `?`         | Match zero or one (non-greedy)                      |
| `[abc]`     | Character class                                     |
| `[^abc]`    | Inverted class *(partially broken in this version)* |
| `[a-zA-Z]`  | Character ranges                                    |
| `\s`, `\S`  | Whitespace / non-whitespace                         |
| `\w`, `\W`  | Alphanumeric / non-alphanumeric                     |
| `\d`, `\D`  | Digits / non-digits                                 |

### Usage in This Project

TinyRegex is used by this project to enable **regex-based string filtering** in dump commands.  
It allows users to match or exclude specific patterns within extracted data such as strings, imports, or symbols.

This lightweight implementation is included to ensure regex functionality is available  
**even in environments that lack a built-in or fully featured regex library**  
(e.g., certain Windows or embedded setups).

---

## Tiny SHA Integration

This directory contains **Tiny SHA**, a minimal and portable C library for computing SHA hash digests.  
All major SHA variants are supported, including **SHA-1, SHA-2, SHA-3, SHAKE, and Raw SHAKE**.  

### Overview

Tiny SHA is designed to be:

- Lightweight and self-contained (<50 KB)  
- Endian-aware (works on little-endian and big-endian systems)  
- Incremental (streaming API: `Init`, `Update` / `Absorb`, `Final` / `Squeeze`)  
- Single-shot (wrapper functions for hashing in one call)  
- Configurable (enable/disable algorithms via macros)  
- Prefixable (`TSHASH_PREFIX`) to avoid name collisions  
- Includes optional bit-level helpers for SHAKE/XOF:  
  - `Trunc_s` — truncate a byte array to a specific number of bits  
  - `concat_bits` — concatenate two sequences of bits  

### Usage in This Project

Tiny SHA is used for **hash computation, comparison, and PE dumping**.  
It provides fast, reliable, and fully self-contained SHA functionality, even in environments without a standard hashing library.