#ifndef DUMP_RAW_H
#define DUMP_RAW_H

#include "libs.h"
#include "pe_structs.h"
#include "file_defs.h"
#include "pe_utils.h"
#include "cmd_types.h"

// === Hex dump macros ===

// Number of bytes per line in the dump
#define BYTES_PER_LINE  16   // can set to 8, 16, 32...

// Printable ASCII range (classic convention: 0x20–0x7E)
#define IS_PRINTABLE(c) ((c) >= 0x20 && (c) <= 0x7E)

// Replacement for non-printable characters
#define NONPRINT_CHAR   '.'

// Prints a header for a raw memory/data range dump.
// start          : starting offset or VA of the memory/data range.
// size           : size of the range in bytes.
// dumpWidthBytes : number of bytes per row to display.
// Returns        : void.
void print_range_dump_header
(
    IN DWORD start,
    IN DWORD size,
    IN int dumpWidthBytes
);

// Prints a range of raw bytes from a PE file.
// peFile          : handle to the opened PE file.
// startOffset     : starting file offset to read from.
// sizeInByte      : number of bytes to read and print.
// fileSize        : total size of the file, used for bounds checking.
// formatConfig    : pointer to a configuration struct controlling display formatting.
// fileSectionList : pointer to a struct containing PE section info for VA/FO mapping.
// printHdr        : flag indicating whether to print the header (non-zero = print).
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE print_range
(
    IN FILE* peFile,
    IN DWORD startOffset,
    IN DWORD sizeInByte,
    IN LONGLONG fileSize,
    IN PFormatConfig formatConfig,
    IN PFileSectionList fileSectionList,
    IN BYTE printHdr
);

// Dumps all PE data directories as raw bytes.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections in the PE file.
// dataDirs        : pointer to the array of IMAGE_DATA_DIRECTORY structures.
// fileSize        : total size of the PE file, used for bounds checking.
// formatConfig    : pointer to a configuration struct controlling display formatting.
// fileSectionList : pointer to a struct containing PE section info for VA/FO mapping.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_all_data_directories_raw
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY dataDirs,
    IN LONGLONG fileSize,
    IN PFormatConfig formatConfig,
    IN PFileSectionList fileSectionList
);

#endif