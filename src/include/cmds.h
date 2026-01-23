#ifndef CMDS_H
#define CMDS_H

#include "libs.h"
#include "file_defs.h"
#include "cmd_types.h"
#include "pe_utils.h"
#include "struct_io.h"
#include "pe_extract.h"
#include "pe_structs.h"
#include "dump_headers.h"
#include "dump_data_dirs.h"
#include "dump_raw.h"
#include "dump_misc.h"
#include "pe_extract.h"

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
// Returns: Parsed number as a LONG value.
LONG parseNumber
(
    IN const char *s
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
// val      : Argument value specifying section extraction parameters.
// section  : Output pointer to section extraction configuration structure.
// Returns  : RET_SUCCESS on success, RET_ERROR otherwise.
RET_CODE handle_section_extract
(
    IN  char            *val,
    OUT PSectionExtract  section
);

// Handles extraction configuration for an export extraction command.
// val      : Argument value specifying export extraction parameters.
// exp      : Output pointer to export extraction configuration structure.
// Returns  : RET_SUCCESS on success, RET_ERROR otherwise.
RET_CODE handle_export_extract
(
    IN  char           *val,
    OUT PExportExtract  exp
);

// Handles extraction configuration for an import extraction command.
// val      : Argument value specifying import extraction parameters.
// imp      : Output pointer to import extraction configuration structure.
// Returns  : RET_SUCCESS on success, RET_ERROR otherwise.
RET_CODE handle_import_extract
(
    IN  char           *val,
    OUT PImportExtract  imp
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

// Parses a range argument from the command line.
// arg        : String specifying the range (e.g. "0x100-0x200" or "0x150").
// rangeStart : Output pointer receiving the parsed start offset.
// rangeEnd   : Output pointer receiving the parsed end offset (same as start if single value).
// Returns    : RET_SUCCESS on success, RET_ERROR otherwise.
RET_CODE parse_range_arg
(
    IN  const char *arg,
    OUT PULONGLONG rangeStart,
    OUT PULONGLONG rangeEnd
);

// Parses and initializes hash configuration arguments.
// arg : Command-line argument specifying the hash type, algorithm, etc
// hc  : Pointer to the hash configuration storing parsed options and targets.
// Returns: RET_SUCCESS on success, RET_ERROR otherwise.
RET_CODE parse_hash_config
(
    IN  const char *arg,
    OUT PHashConfig hc
);

// Parses and prepares PE file targets for hashing or comparison.
// At least one of (fileName1, peCtx1) must be provided.
// If comparison mode is active, (fileName2 or peCtx2) must also be provided.
//
// fileName1 : Optional. Path to the primary PE file.
// fileName2 : Optional. Path to the secondary PE file (for compare mode).
// peCtx1    : Optional. Existing context for the primary PE file.
// peCtx2    : Optional. Existing context for the secondary PE file.
// hc        : Pointer to the hash configuration storing parsed options and targets.
// Returns   : RET_SUCCESS on success, RET_ERROR otherwise.
RET_CODE parse_hash_targets
(
    IN    const char *fileName1, // optional
    IN    const char *fileName2, // optional
    IN    PPEContext  peCtx1,    // optional
    IN    PPEContext  peCtx2,    // optional
    INOUT PHashConfig hc
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