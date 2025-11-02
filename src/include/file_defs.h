#ifndef FILE_DEFS_H
#define FILE_DEFS_H

#include "libs.h"

//  Portable File Positioning (64-bit Safe) and portable Case-Insensitive String Comparison
#ifdef _WIN32
    #define FSEEK64(file, offset, whence) _fseeki64((file), (LONGLONG)(offset), (whence))
    #define FTELL64(file)                 _ftelli64(file)
    #define STREQI(a, b) _stricmp((a), (b))
#else
    #define FSEEK64(file, offset, whence) fseeko((file), (off_t)(offset), (whence))
    #define FTELL64(file)                 ftello(file)
    #define STREQI(a, b) strcasecmp((a), (b))
#endif

//  Optional Function Detection (if not available)
#ifndef FSEEK64
    #define FSEEK64(file, offset, whence) fseek((file), (long)(offset), (whence))
#endif

#ifndef FTELL64
    #define FTELL64(file) ftell((file))
#endif

#ifndef STREQI
    #define STREQI(a, b) strcmp((a), (b))
#endif

//  Regex Function Availability Control
#if ENABLE_REGEX
    // Use POSIX regex
    #define REGEX_COMPILE(pat)   regcomp(&(pat), pattern, REG_EXTENDED)
    #define REGEX_MATCH(pat, s)  regexec(&(pat), (s), 0, NULL, 0)
#else
    // Use TinyRegex
    #define REGEX_COMPILE(pat)   re_compile((pat))
    #define REGEX_MATCH(pat, s)  re_matchp((pat), (s), 0)
#endif

#define SAFE_FREE(ptr)  if (ptr) { free(ptr); ptr = NULL; }
#define MAX(a,b) ((a) > (b) ? (a) : (b))

#ifndef MAX_PATH_LENGTH
    #define MAX_PATH_LENGTH 260 // Maximum file path length
#endif

#ifndef MAX_DLL_NAME
    #define MAX_DLL_NAME 256   // Maximum length for DLL names in Import/Export tables
#endif

#ifndef MAX_FUNC_NAME
    #define MAX_FUNC_NAME 512  // Maximum length for function names in Export table
#endif

#ifndef IN
    #define IN // input parameter
#endif

#ifndef OUT
    #define OUT // output parameter
#endif

#ifndef INOUT 
    #define INOUT // input/output parameter
#endif

typedef enum _PE_ARCH{
    PE_INVALID, // 0
    PE_32,      // 1
    PE_64       // 2
} PE_ARCH;

typedef struct _FlagDesc{
    DWORD flag;
    const char* name;
} FlagDesc;

// return codes
typedef enum _RET_CODE {
    RET_SUCCESS         = 0,  // Operation completed successfully
    RET_ERROR           = 1,  // Generic failure (non-specific)
    RET_INVALID_PARAM   = 2,  // One or more invalid parameters were passed
    RET_NO_VALUE        = 3,  // Function completed but has no value to return
    RET_INVALID_BOUND   = 4,  // Index or offset out of valid range
    RET_BUFFER_OVERFLOW = 5,  // Provided buffer is too small
    RET_MALFORMED_FILE  = 6  //  File is malformed or corrupted
} RET_CODE;

//      -- Forward typedef prototypes --

// located in utils.h
typedef struct _SECTION_INFO        SECTION_INFO;
typedef struct _RVA_INFO            RVA_INFO;
typedef struct _FileSection         FileSection,       *PFileSection;
typedef struct _FileSectionList     FileSectionList,   *PFileSectionList;

// located in cmds.h
typedef struct _FormatConfig        FormatConfig,      *PFormatConfig;
typedef struct _ExtractConfig       ExtractConfig,     *PExtractConfig;
typedef struct _HashConfig          HashConfig,        *PHashConfig;
typedef struct _Config              Config,            *PConfig;

// located in pe_extract.h
typedef struct _PETypeInfo          PETypeInfo,        *PPETypeInfo;
typedef struct _EXPORT_MATCH        EXPORT_MATCH,      *EXMPORT_MATCH;
typedef struct _EXPORT_MATCH_LIST   EXPORT_MATCH_LIST, *PEXPORT_MATCH_LIST;
typedef struct _IMPORT_MATCH        IMPORT_MATCH,      *PIMPORT_MATCH;
typedef struct _MATCH_LIST          MATCH_LIST,        *PMATCH_LIST;

#endif