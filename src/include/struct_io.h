#ifndef STRUCT_IO_H
#define STRUCT_IO_H

#include "libs.h"
#include "pe_structs.h"
#include "file_defs.h"
#include "pe_extract.h"

void init_match_list
(
    OUT MATCH_LIST *list,
    IN  ULONGLONG initialCapacity,
    IN  ULONGLONG itemSize
);

RET_CODE ensure_match_capacity
(
    INOUT MATCH_LIST *list,
    IN    ULONGLONG additional
);

RET_CODE add_match(
    INOUT MATCH_LIST *list,
    IN    void *match
);

void free_match_list
(
    IN MATCH_LIST *list
);

// Adds a section entry to a FileSectionList structure.
// list   : pointer to section list
// offset : section file offset
// size   : section size
// name   : section name (string)
// Returns: void
void add_section
(
    INOUT PFileSectionList list,
    IN    DWORD offset,
    IN    DWORD size,
    IN    const char* name
);

// Manually fills PE section list combining DOS, Rich, NT, and section header data.
// peFile          : open file handle
// dosHeader       : pointer to DOS header
// richHeader      : pointer to Rich header
// nt32 / nt64     : optional NT headers (based on is64bit flag)
// sections        : section headers array
// numberOfSections: total number of sections
// is64bit         : nonzero if 64-bit PE
// fileSize        : total file size
// outList         : output section list structure
void fill_pe_sections_manual
(
    IN  FILE *peFile,
    IN  PIMAGE_DOS_HEADER dosHeader,
    IN  PIMAGE_RICH_HEADER richHeader,
    IN  PIMAGE_NT_HEADERS32 nt32,
    IN  PIMAGE_NT_HEADERS64 nt64,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    IN  int is64bit,
    IN  LONGLONG fileSize,
    OUT PFileSectionList outList
);

// Frees all memory associated with a FileSectionList.
// list : pointer to section list to free
void free_sections
(
    IN PFileSectionList list
);

// Frees all allocated fields within a PEDataDirectories structure.
// dirs : pointer to PEDataDirectories struct
void freePEDataDirectories
(
    IN PEDataDirectories *dirs
);

#endif