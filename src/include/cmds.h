#ifndef CMDS_H
#define CMDS_H

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

/*
============================================================
 Command System Core Types
 -----------------------------------------------------------
 This header defines the core structures, enums and functions
  that represent the entire PE command handling system.

 Each command (like "dos", "imports", "exports", etc.) is
 represented by a COMMAND enum value, with lookup info in
 g_command_table[].

 FormatConfig controls how data ranges are displayed or
 dumped (table, hex, decimal, binary, etc.).

 ExtractConfig describes what type of entity the user wants
 to extract (section, import, or export), along with the
 rules or identifiers for matching.

 These types collectively define how command-line arguments
 are parsed, mapped to PE operations, and formatted for
 output.
============================================================
*/

typedef enum {
    CMD_HELP,

    CMD_DOS_HEADER,
    CMD_FILE_HEADER,
    CMD_OPTIONAL_HEADER,
    CMD_NT_HEADERS,
    CMD_SECTIONS,

    CMD_DATA_DIRECTORIES,
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

    // CLR family
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

    CMD_UNKNOWN
} COMMAND;

typedef struct {
    const char *name;   // long form
    const char *alias;  // short form
    COMMAND cmd;
} CommandEntry, *PCommandEntry;

extern CommandEntry g_command_table[]; // only declared here

typedef enum _ViewMode{
    VIEW_TABLE,
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
    EXTRACT_NONE    = 0,
    EXTRACT_SECTION = 1 << 0,
    EXTRACT_EXPORT  = 1 << 1,
    EXTRACT_IMPORT  = 1 << 2,
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

typedef struct _Config{
    FormatConfig formatConfig;
    PCommandEntry command_table; // pointer to command table
    ExtractConfig extractConfig; // --extract ID
    char set_os_version[ 32 ]; // --set-os-version
    ULONGLONG va2file; // --va2file hex
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

// Handles all parsed commands and dispatches the corresponding operations.
// argc      : Number of command-line arguments.
// argv      : Array of command-line argument strings.
// peFile    : Pointer to the opened PE file.
// dosHeader : Pointer to IMAGE_DOS_HEADER structure.
// richHeader: Pointer to IMAGE_RICH_HEADER structure (optional).
// nt32      : Pointer to IMAGE_NT_HEADERS32 structure (for 32-bit binaries).
// nt64      : Pointer to IMAGE_NT_HEADERS64 structure (for 64-bit binaries).
// sections  : Pointer to PE section headers array.
// dirs      : Pointer to PEDataDirectories structure.
// is64bit   : Flag indicating PE architecture (1 = 64-bit, 0 = 32-bit).
// Returns   : RET_SUCCESS on success, RET_ERROR otherwise.
RET_CODE handle_commands
(
    IN int argc,
    IN char **argv,
    IN FILE *peFile,
    IN PIMAGE_DOS_HEADER dosHeader,
    IN PIMAGE_RICH_HEADER richHeader,
    IN PIMAGE_NT_HEADERS32 nt32,
    IN PIMAGE_NT_HEADERS64 nt64,
    IN PIMAGE_SECTION_HEADER sections,
    IN PPEDataDirectories dirs,
    IN int is64bit
);

#endif