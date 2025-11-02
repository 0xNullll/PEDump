#ifndef STRUCT_IO_H
#define STRUCT_IO_H

#include "libs.h"
#include "pe_structs.h"
#include "file_defs.h"
#include "pe_extract.h"


void initPEContext
(
    IN  FILE       *peFile,
    IN  const char *fileName,
    OUT PPEContext  peContext
);

void init_match_list
(
    OUT MATCH_LIST *list,
    IN  ULONGLONG   initialCapacity,
    IN  ULONGLONG   itemSize
);

RET_CODE ensure_match_capacity
(
    INOUT MATCH_LIST *list,
    IN    ULONGLONG   additional
);

RET_CODE add_match(
    INOUT MATCH_LIST *list,
    IN    void       *match
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
    INOUT PFileSectionList  list,
    IN    DWORD             offset,
    IN    DWORD             size,
    IN    const char       *name
);

// Manually fills PE section list combining DOS, Rich, NT, and section header data.
// peCtx   : Holds all the file structures thats going to be used
// outList : Output section list structure
void fill_pe_sections_manual
(
    IN  PPEContext       peCtx,
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

void freePEContext
(
    IN PPEContext peContext
);

#endif