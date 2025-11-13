#ifndef DUMP_MISC_H
#define DUMP_MISC_H

#include "libs.h"
#include "pe_structs.h"
#include "file_defs.h"
#include "cmd_types.h"
#include "pe_extract.h"
#include "md5.h"
#include "../thirdParty/tiny_sha.h"

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

RET_CODE dump_pe_overview
(
    IN PPEContext peCtx
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