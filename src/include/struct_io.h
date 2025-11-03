#ifndef STRUCT_IO_H
#define STRUCT_IO_H

#include "libs.h"
#include "pe_structs.h"
#include "file_defs.h"
#include "pe_extract.h"

// Initializes a PEContext structure from a given PE file.
// peFile   : pointer to an open FILE representing the PE file
// fileName : name of the PE file
// peContext: pointer to a PEContext struct to initialize
void initPEContext
(
    IN  FILE       *peFile,
    IN  const char *fileName,
    OUT PPEContext  peContext
);

// Initializes a MATCH_LIST structure with a given initial capacity and item size.
// list           : pointer to MATCH_LIST struct to initialize
// initialCapacity: initial number of items the list can hold
// itemSize       : size of each item in the list
void init_match_list
(
    OUT MATCH_LIST *list,
    IN  ULONGLONG   initialCapacity,
    IN  ULONGLONG   itemSize
);

// Ensures a MATCH_LIST has enough capacity to hold additional items.
// list      : pointer to MATCH_LIST struct
// additional: number of additional items to reserve space for
// Returns RET_CODE indicating success or failure
RET_CODE ensure_match_capacity
(
    INOUT MATCH_LIST *list,
    IN    ULONGLONG   additional
);

// Adds a match item to a MATCH_LIST.
// list : pointer to MATCH_LIST struct
// match: pointer to the item to add
// Returns RET_CODE indicating success or failure
RET_CODE add_match(
    INOUT MATCH_LIST *list,
    IN    void       *match
);

// Frees all allocated memory within a MATCH_LIST.
// list : pointer to MATCH_LIST struct to free
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
// peCtx  : Holds all the file structures thats going to be used
// outList: Output section list structure
void fill_pe_sections_manual
(
    IN  PPEContext       peCtx,
    OUT PFileSectionList outList
);

// Frees all memory associated with a FileSectionList.
// list: pointer to section list to free
void free_sections
(
    IN PFileSectionList list
);

// Frees all allocated fields within a PEDataDirectories structure.
// dirs: pointer to PEDataDirectories struct
void freePEDataDirectories
(
    IN PEDataDirectories *dirs
);

// Frees all allocated fields within a PEContext structure, including
// headers, sections, and data directories.
// peContext: pointer to PEContext struct
void freePEContext
(
    IN PPEContext peContext
);

#endif