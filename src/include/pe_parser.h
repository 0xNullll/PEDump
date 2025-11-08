#ifndef PE_PARSER_H
#define PE_PARSER_H

#include "libs.h"
#include "pe_structs.h"
#include "struct_io.h"
#include "file_defs.h"
#include "pe_utils.h"
#include "dump_pe_flags.h"

// Checks if the given file is a valid PE file by verifying the DOS and NT header signatures.
// peFile : pointer to the opened PE file
// Returns: TRUE (1) if the file is a valid PE, FALSE (0) otherwise
BOOL isPE
(
    IN FILE* peFile
);

// Determines the architecture of a PE file (32-bit or 64-bit).
// peFile: pointer to the opened PE file
// Returns: one of the PE_ARCH enum values:
//          PE_INVALID (0) - not a valid PE
//          PE_32      (1) - 32-bit PE
//          PE_64      (2) - 64-bit PE
PE_ARCH get_pe_architecture
(
    IN FILE *peFile
);

// Parses the DOS header of a PE file.
// peFile   : pointer to the opened PE file
// dosHeader: pointer to an IMAGE_DOS_HEADER structure to fill
// Returns  : RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parse_dos_header
(
    IN  FILE* peFile,
    OUT PIMAGE_DOS_HEADER dosHeader
);
// Parses the Rich Header (if present) from a PE file.
// peFile     : Pointer to the opened PE file.
// StartOff   : File offset where the Rich Header search begins (typically after the DOS stub).
// endOff     : File offset marking the end of the search range (before the NT headers).
// richHeader : Output pointer to the IMAGE_RICH_HEADER structure, if found.
// Returns    : RET_SUCESS on success, RET_ERROR on error, RET_NO_VALUE if rich signature not found.
RET_CODE parse_rich_header
(
    IN  FILE* peFile,
    IN  DWORD StartOff,
    IN  DWORD endOff,
    OUT PIMAGE_RICH_HEADER *richHeader
);

// Parses the NT Headers of a PE file (handles both PE32 and PE64 formats).
// peFile   : Pointer to the opened PE file.
// nt32     : Output pointer to the IMAGE_NT_HEADERS32 structure (for 32-bit).
// nt64     : Output pointer to the IMAGE_NT_HEADERS64 structure (for 64-bit).
// is64bit  : Flag indicating the PE architecture (1 = 64-bit, 0 = 32-bit).
// offset   : File offset where the NT Headers begin (value of e_lfanew from DOS header).
// Returns  : RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parse_nt_headers
(
    IN  FILE *peFile,
    OUT PIMAGE_NT_HEADERS32 nt32,
    OUT PIMAGE_NT_HEADERS64 nt64,
    IN  int is64bit,
    IN  DWORD offset
);

// Parses the COFF Symbol Table of a PE file, extracting all symbol records.
// peFile          : Pointer to the opened PE file.
// symTable        : Output pointer to the array of IMAGE_SYMBOL structures.
// NumberOfSymbols : Total number of symbols to read (from FileHeader.NumberOfSymbols).
// offset          : File offset where the symbol table starts (from FileHeader.PointerToSymbolTable).
// Returns         : RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parse_symbol_table
(
    IN  FILE *peFile,
    OUT PIMAGE_SYMBOL *symTable,
    IN  DWORD NumberOfSymbols,
    IN  DWORD offset
);

// Parses the String Table used by the COFF Symbol Table for long symbol names.
// peFile         : Pointer to the opened PE file.
// stringTableOut : Output pointer to a buffer containing the entire string table data.
// offset         : File offset immediately following the symbol table.
// Returns        : RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parse_string_table
(
    IN  FILE *peFile,
    OUT char **stringTableOut,
    IN  DWORD offset
);

// Parses the section headers of a PE file.
// sections: pointer to a PIMAGE_SECTION_HEADER that will be allocated inside the function
// peFile: pointer to the opened PE file
// numberOfSections: number of section headers to parse
// offset: file offset where section headers begin
// fileSize: to check if rawDataSize is bigger than the file
// Returns: RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parse_section_headers
(
    IN  FILE* peFile,
    OUT PIMAGE_SECTION_HEADER *sections,
    IN  WORD numberOfSections,
    IN  DWORD offset,
    IN  LONGLONG fileSize
);

// Parse a table of elements from a PE file at a given RVA
// peFile         : opened PE file handle
// rva            : Relative Virtual Address of the table
// elementSize    : size of each element in bytes
// count          : number of elements to read
// sections       : array of PE section headers for RVA-to-offset translation
// numberOfSection: total number of sections
// Returns        : pointer to allocated array containing the table, or NULL on failure
void* parse_table_from_rva
(
    IN FILE *peFile,
    IN DWORD rva,
    IN ULONGLONG elementSize,
    IN DWORD count,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSection
);
// Reads a table from the PE file given its file offset (FO), element size, and element count.
// peFile       : Pointer to the opened PE file.
// fo           : File offset where the table starts.
// elementSize  : Size of each element (in bytes).
// count        : Number of elements to read.
// Returns      : Pointer to the allocated buffer containing the table data.
void *parse_table_from_fo
(
    IN FILE     *peFile,
    IN DWORD     fo,
    IN ULONGLONG elementSize,
    IN DWORD     count
);

// Fills a buffer with entries resolved from an RVA range within the PE file.
// peFile          : Pointer to the opened PE file.
// sections        : Array of section headers.
// numberOfSections: Total number of sections in the PE file.
// rvaBase         : Base RVA of the data to read.
// sizeInBytes     : Total size of the data to read.
// entriesBuffer   : Pointer to the buffer to fill.
// entrySize       : Size of each entry (in bytes).
// Returns         : Number of bytes successfully read and written to entriesBuffer.
ULONGLONG fill_entries
(
    IN  FILE *peFile,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    IN  DWORD rvaBase,
    IN  DWORD sizeInBytes,
    OUT void *entriesBuffer,
    IN  WORD entrySize
);

// Reads a Unicode (wide-character) string from raw data.
// data       : Pointer to the input data containing UTF-16 characters.
// out        : Output buffer to store the converted string (WCHAR).
// max_chars  : Maximum number of characters to read.
// Returns    : Number of characters read.
ULONGLONG read_unicode_string
(
    IN const UCHAR *data,
    OUT WCHAR *out,
    IN ULONGLONG max_chars
);

// ===== Data Directory Parsers =====

// Parses the Export Table of a PE file, extracting all exported function addresses, names, and ordinals.
// peFile           : Pointer to the opened PE file.
// dataDir          : Pointer to the export directory entry in the data directories array.
// sections         : Array of section headers.
// numberOfSections : Total number of sections.
// exportDir        : Output pointer to the IMAGE_EXPORT_DIRECTORY structure.
// Returns          : RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parse_export_table
(
    IN  FILE *peFile,
    IN  PIMAGE_DATA_DIRECTORY dataDir,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    OUT PIMAGE_EXPORT_DIRECTORY *exportDir
);

// Parses the Import Table, resolving all imported DLL names and function pointers.
// peFile           : Pointer to the opened PE file.
// dataDir          : Pointer to the import directory entry in the data directories array.
// sections         : Array of section headers.
// numberOfSections : Total number of sections.
// importDir        : Output pointer to the IMAGE_IMPORT_DESCRIPTOR structure array.
// Returns          : RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parse_import_table
(
    IN  FILE *peFile,
    IN  PIMAGE_DATA_DIRECTORY dataDir,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    OUT PIMAGE_IMPORT_DESCRIPTOR *importDir
);

// Parses the Resource Table, iterating nested directories and resource data entries.
// peFile           : Pointer to the opened PE file.
// dataDir          : Pointer to the resource directory entry in the data directories array.
// sections         : Array of section headers.
// numberOfSections : Total number of sections.
// rsrcDir          : Output pointer to the IMAGE_RESOURCE_DIRECTORY structure.
// rsrcEntriesDir   : Output pointer to the directory entry array.
// Returns          : RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parse_resource_table
(
    IN  FILE *peFile,
    IN  PIMAGE_DATA_DIRECTORY dataDir,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    OUT PIMAGE_RESOURCE_DIRECTORY *rsrcDir,
    OUT PIMAGE_RESOURCE_DIRECTORY_ENTRY *rsrcEntriesDir
);

// Reads resource directory entries from the given file offset.
// peFile    : Pointer to the opened PE file.
// dirFO     : File offset of the resource directory.
// outCount  : Output pointer receiving the number of directory entries read.
// Returns   : Pointer to the array of IMAGE_RESOURCE_DIRECTORY_ENTRY structures.
PIMAGE_RESOURCE_DIRECTORY_ENTRY read_resource_dir_entries
(
    IN  FILE *peFile,
    IN  DWORD dirFO,
    OUT PWORD outCount
);

// Parses the Debug Directory, extracting CodeView / PDB information if present.
// peFile           : Pointer to the opened PE file.
// dataDir          : Pointer to the debug directory entry in the data directories array.
// sections         : Array of section headers.
// numberOfSections : Total number of sections.
// debugDir         : Output pointer to the IMAGE_DEBUG_DIRECTORY structure array.
// Returns          : RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parse_debug_table
(
    IN  FILE *peFile,
    IN  PIMAGE_DATA_DIRECTORY dataDir,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    OUT PIMAGE_DEBUG_DIRECTORY *debugDir
);

// Parses the TLS Directory, retrieving TLS initialization data and callback addresses.
// peFile           : Pointer to the opened PE file.
// dataDir          : Pointer to the TLS directory entry in the data directories array.
// sections         : Array of section headers.
// numberOfSections : Total number of sections.
// tls32            : Output pointer to IMAGE_TLS_DIRECTORY32 (for 32-bit).
// tls64            : Output pointer to IMAGE_TLS_DIRECTORY64 (for 64-bit).
// is64bit          : Indicates if the PE is 64-bit.
// Returns          : RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parse_tls_table
(
    IN FILE *peFile,
    IN PIMAGE_DATA_DIRECTORY dataDir,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    OUT PIMAGE_TLS_DIRECTORY32 *tls32,
    OUT PIMAGE_TLS_DIRECTORY64 *tls64,
    IN int is64bit
);

// Parses the Load Config Directory, extracting heap, security, and memory configuration fields.
// peFile           : Pointer to the opened PE file.
// dataDir          : Pointer to the Load Config directory entry in the data directories array.
// sections         : Array of section headers.
// numberOfSections : Total number of sections.
// loadConfig32     : Output pointer to IMAGE_LOAD_CONFIG_DIRECTORY32 (for 32-bit).
// loadConfig64     : Output pointer to IMAGE_LOAD_CONFIG_DIRECTORY64 (for 64-bit).
// is64bit          : Indicates if the PE is 64-bit.
// Returns          : RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parse_load_config_table
(
    IN  FILE *peFile,
    IN  PIMAGE_DATA_DIRECTORY dataDir,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    OUT PIMAGE_LOAD_CONFIG_DIRECTORY32 *loadConfig32,
    OUT PIMAGE_LOAD_CONFIG_DIRECTORY64 *loadConfig64,
    IN int is64bit
);

// Parses the Delay Import Table, handling functions imported on-demand during runtime.
// peFile           : Pointer to the opened PE file.
// dataDir          : Pointer to the Delay Import directory entry in the data directories array.
// sections         : Array of section headers.
// numberOfSections : Total number of sections.
// delayImportDir   : Output pointer to the IMAGE_DELAYLOAD_DESCRIPTOR structure array.
// Returns          : RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parse_delay_import_table
(
    IN  FILE *peFile,
    IN  PIMAGE_DATA_DIRECTORY dataDir,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    OUT PIMAGE_DELAYLOAD_DESCRIPTOR *delayImportDir
);

// Parses the CLR (COM Descriptor) Table for managed PE files (.NET assemblies).
// peFile           : Pointer to the opened PE file.
// dataDir          : Pointer to the CLR directory entry in the data directories array.
// sections         : Array of section headers.
// numberOfSections : Total number of sections.
// clrHeader        : Output pointer to the IMAGE_COR20_HEADER structure.
// Returns          : RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parse_clr_table
(
    IN  FILE *peFile,
    IN  PIMAGE_DATA_DIRECTORY dataDir,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    OUT PIMAGE_COR20_HEADER *clrHeader
);

// Parses all Data Directory entries in a PE file, resolving each based on PE architecture.
// peFile   : Pointer to the opened PE file.
// nt32     : Pointer to IMAGE_NT_HEADERS32 (for 32-bit).
// nt64     : Pointer to IMAGE_NT_HEADERS64 (for 64-bit).
// dirs     : Output pointer to PEDataDirectories structure (holds all directory results).
// sections : Array of section headers.
// is64bit  : Indicates if the PE is 64-bit.
// Returns  : RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parse_all_data_directories
(
    IN  FILE *peFile,
    IN  PIMAGE_NT_HEADERS32 nt32,
    IN  PIMAGE_NT_HEADERS64 nt64,
    OUT PEDataDirectories *dirs,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  int is64bit
);

// ===== End of Data Directory Parsers =====

// Parses the entire PE structure, extracting all key headers and data directories.
// peCtx        : the stracture of the pe file to be filled
// Returns      : RET_SUCESS on success, RET_ERROR otherwise.
RET_CODE parsePE
(
    OUT PPEContext  peCtx
);

RET_CODE loadPEContext
(
    IN  const char  *fileName,
    OUT PPEContext  *outCtx,
    OUT FILE       **outFile
);

#endif