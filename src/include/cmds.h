#ifndef CMDS_H
#define CMDS_H

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
#include "file_defs.h"
#include "pe_utils.h"
#include "struct_io.h"
#include "pe_extract.h"
#include "pe_structs.h"
#include "dump_headers.h"
#include "dump_data_dirs.h"
#include "dump_raw.h"
#include "dump_misc.h"
#include "pe_extract.h"

typedef enum {
    CMD_HELP,

    CMD_DOS_HEADER,
    CMD_FILE_HEADER,
    CMD_OPTIONAL_HEADER,
    CMD_NT_HEADERS,
    CMD_SECTIONS,

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

typedef struct _ExtractConfig{
    struct {
        BYTE dumpHex;
        BYTE dumpDec;
        BYTE dumpBin;
    } DumpFlags;

    DWORD size;  // size of the extracted block

    ExtractKind kind; // what kind of data this represents

    union {
        struct { // For sections
            char  name[ IMAGE_SIZEOF_SHORT_NAME ];  // section name 
            WORD index;                             // section index in PE headers
            
            BYTE  useName;                          // if 1 → use name
            BYTE  useIdx;                           // if 1 → use index
            BYTE  useRva;                           // if 1 → use RVA
            BYTE  useFo;                            // if 1 → use file offset
            
            union {
                DWORD rva;   // relative virtual address (if used)
                DWORD fo;    // file offset (if used)
            } addr;
        } section;

        struct { // For exports
            char  dllName[ MAX_DLL_NAME ];          // DLL name
            char  funcName[ MAX_FUNC_NAME ];        // exported function name
            WORD  ordinal;                          // export ordinal
            char  forwarderName[ MAX_FUNC_NAME ];   // forwarder string (DLL.Function)
            DWORD rva;                              // relative virtual address (if used)

            BYTE  useDll;                           // Match all exports by DLL name
            BYTE  useName;                          // match by name
            BYTE  useOrdinal;                       // match by ordinal
            BYTE  useForwarder;                     // match by forwarder
            BYTE  useRva;                           // match by RVA
        } export;

        struct { // For imports
            char  dllName[ MAX_DLL_NAME ];    // DLL name
            char  funcName[ MAX_FUNC_NAME ];  // function name (PE spec allows up to 255)
            WORD  hint;                       // import hint
            WORD  ordinal;                    // import ordinal
            
            BYTE  useDll;                     // Match all exports by DLL name
            BYTE  useName;                    // match by name
            BYTE  useHint;                    // match by hint
            BYTE  useOrdinal;                 // match by ordinal
            BYTE  isGlobal;                   // Global search across all DLLs
        } import;
    };
} ExtractConfig, *PExtractConfig;

typedef enum {
    TARGET_NONE = 0,
    TARGET_FILE,
    TARGET_SECTION,
    TARGET_RANGE,
} TargetType;

typedef struct _Target{
    TargetType type;                    // Type of target (section, range, etc.)
    char name[IMAGE_SIZEOF_SHORT_NAME]; // Section name, export/import name
    WORD index;                         // section index in PE headers
    
    BYTE  useName;  // if 1 → use name
    BYTE  useIdx;   // if 1 → use index
    BYTE  useRva;   // if 1 → use RVA
    BYTE  useFo;    // if 1 → use file offset

    union {
        ULONGLONG rva; // Relative Virtual Address
        ULONGLONG fo;  // File offset
    } addr;

    ULONGLONG start;       // Range start (for hash-range or compare)
    ULONGLONG end;         // Range end (for hash-range or compare)
} Target, *PTarget;

typedef enum {
    ALG_MD5 = 0,
    ALG_SHA1,
    ALG_SHA256
} HashAlg;

typedef enum {
    HASHCMD_NONE = 0,
    HASHCMD_HASH_TARGET,   // single target (file, section, or range)
    HASHCMD_COMPARE_TARGETS
} HashCommandType;


typedef struct _HashConfig{
    HashCommandType cmdType; // Type of hash command
    HashAlg alg;             // Hash algorithm to use

    Target target1;          // First target (or only target)
    Target target2;          // Second target (for comparisons)

    char file1[MAX_PATH_LENGTH]; // File path for first file
    char file2[MAX_PATH_LENGTH]; // File path for second file (for compare)
} HashConfig, *PHashConfig;

typedef struct _Config{
    PCommandEntry command_table; // pointer to command table
    FormatConfig  formatConfig;  // --format
    ExtractConfig extractConfig; // --extract ID
    HashConfig    hashConfig;    // --hash and --compare commands
    ULONGLONG     va2file;       // --va2file hex
} Config, *PConfig;

// Checks whether the provided command-line arguments are valid.
// argc   : Number of command-line arguments.
// Returns: TRUE if the command is valid, FALSE otherwise.
BOOL isCmdValid(
    IN int argc
);

// Checks if the provided argument corresponds to the "help" command.
// arg    : Command-line argument string.
// Returns: TRUE if the argument requests help, FALSE otherwise.
BOOL isHelpCmd
(
    IN const char *arg
);

// Initializes a configuration structure to its default state.
// c      : Output pointer to the configuration structure to initialize.
void init_config
(
    OUT PConfig c
);

// Parses a single command-line argument and updates configuration accordingly.
// arg    : Command-line argument string.
// c      : Pointer to the configuration structure.
// Returns: The parsed COMMAND enumeration value indicating the recognized command.
COMMAND parse_command
(
    IN const char *arg, IN PConfig c
);

// Converts a string containing a hexadecimal value to its 64-bit integer equivalent.
// s      : Input string containing the hexadecimal representation.
// Returns: The converted 64-bit unsigned integer value.
ULONGLONG convert_to_hex(
    IN const char *s
);

// Converts a Virtual Address (VA) to a file offset based on section and image base information.
// VA              : Virtual Address to convert.
// sections        : Pointer to the PE section headers array.
// numberOfSections: Total number of sections.
// imageBase       : Image base address of the loaded module.
// Returns         : RET_SUCCESS on success, RET_ERROR otherwise.
RET_CODE va_to_fileOff_cmd
(
    IN ULONGLONG VA,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN ULONGLONG imageBase
);

// Parses a numeric string, supporting both direct numbers and line-based inputs.
// s      : Input numeric string.
// isLine : Output flag indicating whether the value was line-based (1) or numeric (0).
// Returns: Parsed number as a LONG value.
LONG parseNumber
(
    IN const char *s,
    IN int *isLine
);

// Parses and applies formatting-related arguments to the configuration.
// arg    : Format-related argument string.
// isTmp  : Flag indicating temporary configuration usage.
// c      : Output pointer to the configuration structure.
// Returns: RET_SUCCESS on success, RET_ERROR otherwise.
RET_CODE parse_format_arg
(
    IN  const char *arg,
    IN  BOOL isTmp,
    OUT PConfig c
);

// Handles extraction configuration for a section extraction command.
// val            : Argument value specifying section extraction parameters.
// extractConfig  : Output pointer to extraction configuration structure.
// Returns        : RET_SUCCESS on success, RET_ERROR otherwise.
RET_CODE handle_section_extract
(
    IN  char *val,
    OUT ExtractConfig *extractConfig
);

// Handles extraction configuration for an export extraction command.
// val            : Argument value specifying export extraction parameters.
// extractConfig  : Output pointer to extraction configuration structure.
// Returns        : RET_SUCCESS on success, RET_ERROR otherwise.
RET_CODE handle_export_extract
(
    IN  char *val,
    OUT ExtractConfig *extractConfig
);

// Handles extraction configuration for an import extraction command.
// val            : Argument value specifying import extraction parameters.
// extractConfig  : Output pointer to extraction configuration structure.
// Returns        : RET_SUCCESS on success, RET_ERROR otherwise.
RET_CODE handle_import_extract
(
    IN  char *val,
    OUT ExtractConfig *extractConfig
);

// Parses and processes extraction-related command-line arguments.
// arg    : Command-line argument specifying the extraction target.
// c      : Output pointer to the configuration structure.
// Returns: RET_SUCCESS on success, RET_ERROR otherwise.
RET_CODE parse_extract_arg
(
    IN  const char *arg,
    OUT PConfig c
);

RET_CODE parse_hash_arg
(
    IN  const char *arg,
    OUT PConfig c
);

// Handles all parsed commands and dispatches the corresponding operations.
// argc      : Number of command-line arguments.
// argv      : Array of command-line argument strings.
// peCtx     : Holds all the file structures and context
// Returns   : RET_SUCCESS on success, RET_ERROR otherwise.
RET_CODE handle_commands
(
    IN int          argc,
    IN char       **argv,
    IN PPEContext   peCtx
);

#endif