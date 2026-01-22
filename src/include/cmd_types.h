#ifndef CMD_TYPES_H
#define CMD_TYPES_H

/*
============================================================
 Command System Core Types
 -----------------------------------------------------------
 This header defines the foundational types, enums, and data
 structures that drive pedumper's command-handling system.

 Each supported command-line action (like "dos", "imports",
 "extract", "hash", etc.) is represented by a COMMAND enum
 value. These are registered in g_command_table[], which maps
 both short and long command names to their internal command
 IDs.

 The system is designed around three key configuration
 structures, each handling a specific category of operations:

   • FormatConfig
       Controls how data is displayed or dumped (table, hex,
       decimal, or binary). Used by formatting-related flags
       like "--format" or temporary format options.

   • ExtractConfig
       Defines what type of data entity the user wants to
       extract (section, import, or export), along with the
       identification and matching rules (e.g., by name,
       index, RVA, etc.). Used by the "--extract" command.

   • HashConfig
       Handles hashing and comparison operations for files,
       sections, and arbitrary ranges. It defines:
           - Which algorithm to use (MD5, SHA1, SHA256)
           - What targets are being hashed (TargetType)
           - Whether it’s a single-hash operation or a
             comparison between two targets/files

       The structure uses the HashCommandType enum to
       distinguish between:
           HASHCMD_HASH_TARGET     → single file/section/range
           HASHCMD_COMPARE_TARGETS → cross-file or cross-target
                                      comparison

 All of these are aggregated into a single Config structure,
 which represents the full state of a parsed pedumper
 invocation — ready for execution by the command dispatch
 system.

 In summary:
   - COMMAND           → identifies the selected user command
   - FormatConfig      → display style and view settings
   - ExtractConfig     → entity extraction and matching rules
   - HashConfig        → hashing or comparison setup
   - Config            → unified runtime command context
============================================================
*/

#include "libs.h"
#include "pe_structs.h"

typedef enum {
    CMD_HELP,

    CMD_DOS_HEADER,
    CMD_FILE_HEADER,
    CMD_OPTIONAL_HEADER,
    CMD_NT_HEADERS,
    CMD_SECTION_HEADERS,

    CMD_EXPORTS,
    CMD_IMPORTS,
    CMD_RESOURCES,
    CMD_EXCEPTION,
    CMD_SECURITY,
    CMD_BASERELOC,
    CMD_DEBUG,
    CMD_TLS,
    CMD_LOAD_CONFIG,
    CMD_BOUND_IMPORT,
    CMD_IAT,
    CMD_DELAY_IMPORT,
    CMD_DATA_DIRECTORIES,

    CMD_CLR_HEADER,
    CMD_CLR_METADATA,
    CMD_CLR_READYTORUN,
    CMD_CLR_STREAMS,
    CMD_CLR_STRINGS,
    CMD_CLR_TABLES,
    CMD_CLR_ALL,

    CMD_RICH,
    CMD_VERSION_INFO,
    CMD_SYMBOL_TABLE,
    CMD_STRING_TABLE,
    CMD_OVERLAY,
    CMD_OVERVIEW,
    CMD_ALL,

    CMD_VA2FILE,
    
    CMD_FORMAT,
    CMD_TEMP_FORMAT,

    CMD_STRINGS,
    CMD_EXTRACT,

    CMD_HASH,
    CMD_HASH_COMPARE,

    CMD_UNKNOWN
} COMMAND;

typedef struct {
    const char *name;   // long form
    const char *alias;  // short form
    COMMAND cmd;
} CommandEntry, *PCommandEntry;

extern CommandEntry g_command_table[]; // only declared here

typedef enum _ViewMode{
    VIEW_TABLE = 0,
    VIEW_HEX,
    VIEW_DEC,
    VIEW_BIN
} ViewMode;

typedef struct _FormatConfig{
    BYTE isTmp;

    int startIsLine; // true if start index is line-based
    int endIsLine  ; // true if end index is line-based

    ViewMode view;
    LONG startLine; // start line or offset (rounded to line)
    LONG maxLine;   // end line or offset (0 = full)
} FormatConfig, *PFormatConfig;

// What kind of thing we’re extracting
typedef enum {
    EXTRACT_NONE = 0,
    EXTRACT_SECTION,
    EXTRACT_EXPORT,
    EXTRACT_IMPORT,
} ExtractKind;

typedef struct _SectionExtract {
    char  name[IMAGE_SIZEOF_SHORT_NAME];
    WORD  index;
    BYTE  useName;
    BYTE  useIdx;
    BYTE  useRva;
    BYTE  useFo;
    union {
        DWORD rva;
        DWORD fo;
    } addr;
} SectionExtract, *PSectionExtract;

typedef struct _ExportExtract {
    char  dllName[MAX_DLL_NAME];
    char  funcName[MAX_FUNC_NAME];
    WORD  ordinal;
    char  forwarderName[MAX_FUNC_NAME];
    DWORD rva;
    BYTE  useDll;
    BYTE  useName;
    BYTE  useOrdinal;
    BYTE  useForwarder;
    BYTE  useRva;
} ExportExtract, *PExportExtract;

typedef struct _ImportExtract {
    char  dllName[MAX_DLL_NAME];
    char  funcName[MAX_FUNC_NAME];
    WORD  hint;
    WORD  ordinal;
    BYTE  useDll;
    BYTE  useName;
    BYTE  useHint;
    BYTE  useOrdinal;
    BYTE  isGlobal;
} ImportExtract, *PImportExtract;

typedef struct _ExtractConfig{
    struct {
        BYTE dumpHex;
        BYTE dumpDec;
        BYTE dumpBin;
    } DumpFlags;

    DWORD size;  // size of the extracted block

    ExtractKind kind; // what kind of data this represents

    union {
        SectionExtract section;
        ExportExtract export;
        ImportExtract import;
    };
} ExtractConfig, *PExtractConfig;

typedef enum {
    TARGET_NONE = 0,
    TARGET_FILE,
    TARGET_RANGE,
    TARGET_RICH_HEADER,
    TARGET_SECTION
} TargetType;

#define MAX_HASH_SIZE 64  // SHA512 digest length (in bytes)

typedef struct _Target {
    TargetType type; // Type of target (section, range, etc.)

    union {
        SectionExtract section;
    };

    ULONGLONG rangeStart; // for hash-range or compare
    ULONGLONG rangeEnd;   // for hash-range or compare

    bool ownsBuffer;
    PBYTE     buffer;     // Pointer to loaded data
    ULONGLONG bufferSize; // Size of the data in bytes

    BOOL      hashPresent;         // TRUE if the target data exists and can be hashed
    UCHAR     hash[MAX_HASH_SIZE]; // Fixed-size buffer for computed hash
    ULONGLONG hashLen;             // Actual length of the hash used
} Target, *PTarget;

typedef enum {
    ALG_MD5 = 0,
    ALG_SHA1,
    ALG_SHA224,
    ALG_SHA256,
    ALG_SHA384,
    ALG_SHA512,
    ALG_SHA512_256,
    ALG_SHA512_224
} HashAlg;

typedef enum {
    HASHCMD_NONE = 0,
    HASHCMD_HASH_TARGET,        // single target (file, section, or range)
    HASHCMD_COMPARE_TARGETS,    // compare between different files or targets
    HASHCMD_COMPARE_INTERNAL    // compare within the same file
} HashCommandType;


typedef struct _HashConfig {
    HashCommandType mode;     // Hash command mode (single / compare)
    HashAlg algorithm;        // Hash algorithm to use

    Target primaryTarget;     // Main target (file, section, or range)
    Target secondaryTarget;   // Optional target (for comparison mode)

    PPEContext primaryCtx;    // Parsed PE context for the first file
    PPEContext secondaryCtx;  // Parsed PE context for the second file (optional)
} HashConfig, *PHashConfig;

typedef struct _Config{
    PCommandEntry command_table; // pointer to command table
    FormatConfig  formatConfig;  // --format
    ExtractConfig extractConfig; // --extract ID
    HashConfig    hashConfig;    // --hash and --compare commands
    ULONGLONG     va2file;       // --va2file hex
} Config, *PConfig;

#endif