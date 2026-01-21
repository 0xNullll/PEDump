#ifndef DUMP_HEADERS_H
#define DUMP_HEADERS_H

#include "libs.h"
#include "file_defs.h"
#include "pe_structs.h"
#include "pe_utils.h"
#include "dump_pe_flags.h"
#include "pe_parser.h"

// Dumps and analyzes the IMAGE_DOS_HEADER of a PE file.
// dosHeader      : pointer to the IMAGE_DOS_HEADER structure.
// imageBase      : base address of the loaded image (used for calculating VAs of DOS fields, e.g., e_lfanew).
// Returns        : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_dos_header
(
    IN PIMAGE_DOS_HEADER dosHeader,
    IN ULONGLONG imageBase
);

// Dumps and analyzes the Rich Header of a PE file.
// peFile         : handle to the opened PE file.
// encRichHeader  : pointer to the IMAGE_RICH_HEADER structure.
// Returns        : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_rich_header
(
    IN FILE *peFile,
    IN PIMAGE_RICH_HEADER encRichHeader
);

// Prints details of an Auxiliary Function Definition symbol.
// auxSym         : pointer to the IMAGE_AUX_SYMBOL structure.
// auxSymOffset   : file offset of the auxiliary symbol in the PE file.
// numDigits      : width for formatting the symbol index number.
// index          : current auxiliary symbol index (for numbering in output).
// level          : output indentation level for formatted output
void print_aux_symbol_function
(
    IN PIMAGE_AUX_SYMBOL auxSym,
    IN DWORD auxSymOffset,
    IN WORD numDigits,
    IN WORD index,
    IN WORD level
);
// Prints details of a "Begin Function" (BF) auxiliary symbol.
// auxSym            : pointer to the IMAGE_AUX_SYMBOL structure
// auxSymOffset      : file offset of the auxiliary symbol
// numDigits         : number of digits to use when formatting numeric fields
// index             : index of the current symbol in the symbol table
// level             : output indentation level for formatted output
void print_aux_symbol_bf
(
    IN PIMAGE_AUX_SYMBOL auxSym,
    IN DWORD auxSymOffset,
    IN WORD numDigits,
    IN WORD index,
    IN WORD level
);

// Prints details of an "End Function" (EF) auxiliary symbol.
// auxSym            : pointer to the IMAGE_AUX_SYMBOL structure
// auxSymOffset      : file offset of the auxiliary symbol
// numDigits         : number of digits to use when formatting numeric fields
// index             : index of the current symbol in the symbol table
// level             : output indentation level for formatted output
void print_aux_symbol_ef
(
    IN PIMAGE_AUX_SYMBOL auxSym,
    IN DWORD auxSymOffset,
    IN WORD numDigits,
    IN WORD index,
    IN WORD level
);

// Prints details of a Weak External auxiliary symbol.
// weakExtSym        : pointer to the IMAGE_AUX_SYMBOL_WEAK_EXTERN structure
// auxSymOffset      : file offset of the auxiliary symbol
// numDigits         : number of digits to use when formatting numeric fields
// index             : index of the current symbol in the symbol table
// level             : output indentation level for formatted output
void print_aux_symbol_weak_external
(
    IN PIMAGE_AUX_SYMBOL_WEAK_EXTERN weakExtSym,
    IN DWORD auxSymOffset,
    IN WORD numDigits,
    IN WORD index,
    IN WORD level
);

// Prints details of a File auxiliary symbol (used to store the source filename).
// auxSym            : pointer to the IMAGE_AUX_SYMBOL structure
// auxSymOffset      : file offset of the auxiliary symbol
// numDigits         : number of digits to use when formatting numeric fields
// index             : index of the current symbol in the symbol table
// level             : output indentation level for formatted output
void print_aux_symbol_file
(
    IN PIMAGE_AUX_SYMBOL auxSym,
    IN DWORD auxSymOffset,
    IN WORD numDigits,
    IN WORD index,
    IN WORD level
);

// Prints details of a Section Definition auxiliary symbol.
// auxSym            : pointer to the IMAGE_AUX_SYMBOL structure
// auxSymOffset      : file offset of the auxiliary symbol
// numDigits         : number of digits to use when formatting numeric fields
// index             : index of the current symbol in the symbol table
// level             : output indentation level for formatted output
void print_aux_symbol_sec_def
(
    IN PIMAGE_AUX_SYMBOL auxSym,
    IN DWORD auxSymOffset,
    IN WORD numDigits,
    IN WORD index,
    IN WORD level
);

// Prints details of a CLR token auxiliary symbol (used by managed .NET code).
// auxSym            : pointer to the IMAGE_AUX_SYMBOL structure
// auxSymOffset      : file offset of the auxiliary symbol
// numDigits         : number of digits to use when formatting numeric fields
// index             : index of the current symbol in the symbol table
// level             : output indentation level for formatted output
void print_clr_token
(
    IN PIMAGE_AUX_SYMBOL auxSym,
    IN DWORD auxSymOffset,
    IN WORD numDigits,
    IN WORD index,
    IN WORD level
);

// Dumps and analyzes a single auxiliary symbol from the COFF symbol table.
// peFile          : handle to the opened PE file.
// sections        : array of section headers for RVA-to-FO conversions.
// numberOfSections: total number of sections in the PE file.
// sym             : pointer to the main IMAGE_SYMBOL entry.
// auxSymOffset    : file offset of the auxiliary symbol.
// numDigits       : width for formatting the symbol index number.
// index           : current auxiliary symbol index.
// level           : output indentation level for formatted output
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_aux_symbol
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_SYMBOL sym,
    IN DWORD auxSymOffset,
    IN WORD numDigits,
    IN WORD index,
    IN WORD level
);

// Prints the value field of a COFF symbol, resolving FO and RVA if possible.
// sym             : pointer to the IMAGE_SYMBOL entry.
// sections        : array of section headers for RVA-to-FO conversions.
// numberOfSections: total number of sections in the PE file.
void print_symbol_value
(
    IN PIMAGE_SYMBOL sym,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections
);

// Dumps and analyzes the entire COFF symbol table.
// peFile          : handle to the opened PE file.
// symTableOffset  : file offset of the COFF symbol table.
// NumberOfSymbols : total number of symbols in the table.
// sections        : array of section headers for RVA-to-FO conversions.
// numberOfSections: total number of sections in the PE file.
// imageBase       : base address of the loaded image (used for VA calculations).
// level           : output indentation level for formatted output
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_symbol_table
(
    IN FILE *peFile,
    IN DWORD symTableOffset,
    IN DWORD NumberOfSymbols,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections
);

// Dumps and prints the COFF string table associated with a symbol table.
// peFile          : handle to the opened PE file.
// symTableOffset  : file offset of the symbol table.
// numberOfSymbols : total number of symbols in the symbol table.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_string_table
(
    IN FILE *peFile,
    IN DWORD symTableOffset,
    IN DWORD numberOfSymbols
);

// Dumps and analyzes the IMAGE_FILE_HEADER of a PE file.
// peFile          : handle to the opened PE file.
// foFileHeader    : file offset of the File Header in the PE file.
// fileHeader      : pointer to the IMAGE_FILE_HEADER structure.
// imageBase       : base address of the loaded image (used for VA calculations).
// printHeader     : 1 to print header info, 0 to skip printing.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_file_header
(
    IN FILE *peFile,
    IN DWORD foFileHeader,
    IN PIMAGE_FILE_HEADER fileHeader,
    IN ULONGLONG imageBase,
    IN int printHeader
);

// Dumps and analyzes the IMAGE_OPTIONAL_HEADER of a PE file.
// peFile          : handle to the opened PE file.
// sections        : array of section headers for RVA-to-FO conversions.
// numberOfSections: total number of sections in the PE file.
// foOptHeader     : file offset of the Optional Header in the PE file.
// optHeader       : pointer to IMAGE_OPTIONAL_HEADER32 or IMAGE_OPTIONAL_HEADER64.
// imageBase       : base address of the loaded image.
// is64bit         : 1 for PE32+, 0 for PE32.
// printHeader     : 1 to print header info, 0 to skip printing.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_optional_header
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN DWORD foOptHeader,
    IN PVOID optHeader,
    IN ULONGLONG imageBase,
    IN int is64bit,
    IN int printHeader
);

// Dumps and analyzes the IMAGE_NT_HEADERS (File Header + Optional Header).
// peFile          : handle to the opened PE file.
// sections        : array of section headers for RVA-to-FO conversions.
// numberOfSections: total number of sections in the PE file.
// foNtHeaders     : file offset of the NT Headers in the PE file.
// ntHeader        : pointer to IMAGE_NT_HEADERS32 or IMAGE_NT_HEADERS64.
// imageBase       : base address of the loaded image.
// is64bit         : 1 for PE32+, 0 for PE32.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_nt_headers
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN DWORD foNtHeaders,
    IN PVOID ntHeader,
    IN ULONGLONG imageBase,
    IN int is64bit
);

// Prints a single section header (part of symbol/section dump routines).
// peFile          : handle to the opened PE file.
// symTableOffset  : offset of the symbol table (may be used for indexing).
// NumberOfSymbols : total number of symbols.
// sec             : pointer to the IMAGE_SECTION_HEADER.
// index           : section index for display purposes.
// imageBase       : base address of the loaded image.
RET_CODE print_section_header
(
    IN FILE *peFile,
    IN DWORD symTableOffset,
    IN DWORD NumberOfSymbols,
    IN PIMAGE_SECTION_HEADER sec,
    IN WORD index,
    IN ULONGLONG imageBase
);

// Dumps and analyzes all section headers of a PE file.
// peFile          : handle to the opened PE file.
// symTableOffset  : offset of the COFF symbol table.
// NumberOfSymbols : total number of symbols in the symbol table.
// sections        : array to be filled with section headers.
// numberOfSections: total number of sections in the PE file.
// fileSize        : to check incase if sizeOfRaw is bigger than file size
// imageBase       : base address of the loaded image.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_section_headers
(
    IN FILE                  *peFile,
    IN DWORD                  symTableOffset,
    IN DWORD                  NumberOfSymbols,
    IN PIMAGE_SECTION_HEADER  sections,
    IN WORD                   numberOfSections,
    IN LONGLONG               fileSize,
    IN ULONGLONG              imageBase
);

#endif
