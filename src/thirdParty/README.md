# TinyRegex Integration

This directory contains a minimal regular expression (regex) engine based on
**Tiny Regex C** by *Kokke* (https://github.com/kokke/tiny-regex-c).  
Minor modifications were made in this project to allow `matchlength` to be optional (can be `NULL`) and to add some safety checks.

---

### Overview

TinyRegex is a small and self-contained C library that provides simple regex
matching functions. It’s designed to be portable and dependency-free, making it
ideal for projects that need lightweight pattern matching without linking to
the full POSIX regex library.

**Supported syntax:**
|   Feature   |                   Description                       |
|-------------|-----------------------------------------------------|
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

---

### Usage in This Project

TinyRegex is used by this project to enable **regex-based string filtering** in dump commands.  
It allows users to match or exclude specific patterns within extracted data such as strings, imports, or symbols.

This lightweight implementation is included to ensure regex functionality is available **even in environments that lack a built-in or fully featured regex library** (e.g., certain Windows or embedded setups).
