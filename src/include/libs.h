#ifndef LIBS_H
#define LIBS_H

// =============================================================
//  Platform-Specific Includes and Feature Flags
// =============================================================

#ifdef _WIN32
    // Disable unnecessary Windows APIs to speed up compilation
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif

    #include <windows.h>
    #include <wincrypt.h>
    #include <wintrust.h>

    // Windows typically lacks POSIX <regex.h>, so disable system regex
    #define ENABLE_REGEX 0

#else
    // On non-Windows platforms, enable system regex
    #include <regex.h>
    #define ENABLE_REGEX 1
#endif


// =============================================================
//  Standard C Library Includes
// =============================================================
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <time.h>

// =============================================================
//  Optional Regex Fallback (TinyRegex)
// =============================================================

#if !ENABLE_REGEX
    #include "../thirdParty/tiny_regex.h"
#endif

#endif // LIBS_H