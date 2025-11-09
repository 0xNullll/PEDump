#ifndef DUMP_MISC_H
#define DUMP_MISC_H

#include "libs.h"
#include "pe_structs.h"
#include "file_defs.h"
#include "cmd_types.h"
#include "pe_extract.h"

#define MAX_ASCII_STRING    2048
#define MAX_UTF16_STRING    1024
#define MAX_CONVERTED_STRING 2048

#define MIN_STR_LEN 5

#define IS_ASCII_PRINTABLE(c) ((c) >= 0x20 && (c) <= 0x7E)

#define LABEL_WIDTH 10

// Dumps strings from a PE file, optionally filtering them using a regex pattern.
// If regexFilter is provided, only strings matching the pattern are returned.
// peFile      : pointer to the open PE file
// regexFilter : regex pattern to filter strings (can be NULL to skip filtering)
// Returns     : RET_CODE indicating success or failure
RET_CODE dump_pe_strings
(
    IN FILE *peFile,
    IN const char* regexFilter
);

// Dumps a high-level overview of a PE file, including file headers, optional headers, 
// sections, and data directories. Prints key information such as architecture, PE type, 
// subsystem, image base, entry point, linker version, timestamps, and characteristics.
//
// filePath   : Path to the PE file
// nt32       : Pointer to IMAGE_NT_HEADERS32 structure (for 32-bit PE files)
// nt64       : Pointer to IMAGE_NT_HEADERS64 structure (for 64-bit PE files)
// sections   : Pointer to the array of section headers
// dataDirs   : Pointer to the PE data directories
// is64bit    : Flag indicating whether the PE is 64-bit (1 = 64-bit, 0 = 32-bit)
// fileSize   : Total size of the PE file in bytes
// Returns    : RET_CODE indicating success or failure of the dump operation
RET_CODE dump_pe_overview
(
    IN const char *filePath,
    IN PIMAGE_NT_HEADERS32 nt32,
    IN PIMAGE_NT_HEADERS64 nt64,
    IN PIMAGE_SECTION_HEADER sections,
    IN PIMAGE_DATA_DIRECTORY dataDirs,
    IN int is64bit,
    IN LONGLONG fileSize
);

// Dumps information about extracted exported functions to the console or log output.
// MatchList         : pointer to the list of matched exported functions
// sections          : pointer to array of section headers
// numberOfSections  : number of sections in the PE
// imageBase         : base address of the loaded PE image
// level             : output indentation depth for formatting
void dump_extracted_exports
(
    IN PMATCH_LIST           MatchList,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD                  numberOfSections,
    IN ULONGLONG             imageBase,
    IN int                   level
);

// Dumps information about extracted imported functions to the console or log output.
// MatchList         : pointer to the list of matched imported functions
// sections          : pointer to array of section headers
// numberOfSections  : number of sections in the PE
// imageBase         : base address of the loaded PE image
// level             : output indentation depth for formatting
void dump_extracted_imports
(
    IN PMATCH_LIST           MatchList,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD                  numberOfSections,
    IN ULONGLONG             imageBase,
    IN int                   level
);

void print_target_desc
(
    IN const char* label,
    IN PTarget target,
    IN int level
);

void print_digest_line
(
    IN const char* label,
    IN PTarget target,
    IN int level
);

void dump_extracted_hash
(
    IN PHashConfig hashCfg,
    IN int         level
);

#endif