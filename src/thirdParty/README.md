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
| `\s`, `\S`| Whitespace / non-whitespace                         |
| `\w`, `\W`| Alphanumeric / non-alphanumeric                     |
| `\d`, `\D`| Digits / non-digits                                 |

### Usage in This Project

TinyRegex is used by this project to enable **regex-based string filtering** in dump commands.  
It allows users to match or exclude specific patterns within extracted data such as strings, imports, or symbols.

This lightweight implementation is included to ensure regex functionality is available  
**even in environments that lack a built-in or fully featured regex library**  
(e.g., certain Windows or embedded setups).

---

## Tiny SHA Integration

This project also includes **Tiny SHA**, a minimal and portable C library for computing  
SHA hash digests. All supported SHA variants are included: **SHA-1, SHA-224, SHA-256,  
SHA-384, SHA-512, SHA-512/224, and SHA-512/256**.  

### Overview

Tiny SHA is designed to be:

- Lightweight (<50 KB)
- Self-contained
- Endian-aware (works on both little-endian and big-endian systems)
- Incremental (supports streaming API with `Init`, `Update`, `Final`)
- Single-shot (wrapper functions that hash data in one call)
- Configurable (enable/disable algorithms via macros)
- Prefixable (avoid name collisions using `TSHASH_PREFIX`)

### Usage in This Project

Tiny SHA is used in PE dumping, hashing, or comparison tasks where quick  
and reliable SHA computation is required.  

**Single-shot hashing example:**

```c
#include <stdio.h>
#include "tiny_sha.h"

int main() {
    const char *msg = "Hello, Tiny SHA!";
    uint8_t hash[SHA256_DIGEST_SIZE];

    if (SHA256((const uint8_t*)msg, strlen(msg), hash)) {
        printf("SHA-256: ");
        for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
            printf("%02x", hash[i]);
        printf("\n");
    }
}
```

**Incremental / streaming example:**

```c
SHA256_CTX ctx;
SHA256Init(&ctx);
SHA256Update(&ctx, (const uint8_t*)msg, strlen(msg));
SHA256Final(&ctx, hash);
```

**Comparing hashes:**

```c
int cmp = SHA256CompareOrder(hash1, hash2);
if (cmp == 0)
    printf("Hashes are equal\n");
else if (cmp < 0)
    printf("hash1 < hash2\n");
else
    printf("hash1 > hash2\n");
```

### Notes

- No external dependencies — fully self-contained  
- All functions return `bool` to indicate success/failure  
- Can be compiled with optional prefix to avoid collisions:  

```c
#define TSHASH_PREFIX PEDumper_
#include "tiny_sha.h"
```

This ensures the SHA functions are namespaced specifically for this project.