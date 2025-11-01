#ifndef PE_UTILS_H
#define PE_UTILS_H

#include "libs.h"
#include "pe_structs.h"
#include "file_defs.h"
#include "dump_pe_flags.h"

#define REPORT_MALFORMED(reason, context) ReportMalformed(reason, context, __FILE__, __LINE__)

// plausible build time range for export TimeDateStamp
#define SOME_REASONABLE_EPOCH       631152000  // Jan 1, 1990
#define CURRENT_EPOCH_PLUS_MARGIN   1893456000 // Jan 1, 2030

#define INDENT(n) ((n)==0?"": \
                   (n)==1?"    ": \
                   (n)==2?"        ": \
                   (n)==3?"            ": \
                   (n)==4?"                ": \
                   (n)==5?"                    ": \
                   (n)==6?"                        ":"")

// Clean indicator macros
#define END_DIR(void) \
    printf("\n\n========================================================================================================\n"); \
    printf("========================================================================================================\n\n")

// Combines a 16-bit BuildID (lower 16 bits) and a 16-bit ProdID (upper 16 bits)
// into a single 32-bit DWORD representing a comp.id entry in the Rich header.
#define REBUILD_RICH_COMID(BuildID, ProdID)  ((DWORD)(((WORD)(ProdID) << 16) | ((WORD)(BuildID))))

// Extracts the lower 16 bits (BuildID) from a 32-bit comp.id value.
// The BuildID typically represents the version/build of the specific tool.
#define GET_RICH_BUILDID(compid) ((WORD)((compid) & 0xFFFF))

// Extracts the upper 16 bits (ProdID) from a 32-bit comp.id value.
// The ProdID identifies the product/tool (compiler, linker, etc.) used.
#define GET_RICH_PRODID(compid)  ((WORD)(((compid) >> 16) & 0xFFFF))

// Extract the high WORD (major or build)
#define __HIWORD(dw) ((WORD)(((DWORD)(dw) >> 16) & 0xFFFF))

// Extract the low WORD (minor or revision)
#define __LOWORD(dw) ((WORD)((DWORD)(dw) & 0xFFFF))

#define ALIGN4(x)  ((ULONGLONG)((x) + 3ull) & ~3ull);

#define ALIGN2(x)  ((ULONGLONG)((x) + 1ull) & ~1ull);

// Groups section info for easier printing and tracking
typedef struct _SECTION_INFO{
    char *name;
    DWORD virtualAddress; 
    DWORD rawOffset;
    DWORD size;
} SECTION_INFO;

// Groups section info for easier printing and tracking
typedef struct _RVA_INFO{
    DWORD fileOffset;         // offset in the file
    DWORD rva;                // relative virtual address
    ULONGLONG va;             // virtual address (ImageBase + rva)
    char sectionName[9];      // section name + null terminator
    int sectionIndex;         // section number
    DWORD rawSize;            // SizeOfRawData
    DWORD virtualSize;        // Misc.VirtualSize
} RVA_INFO;

typedef struct _FileSection{
    DWORD offset;      // Start of the section in the file
    DWORD size;        // Size of the section
    DWORD endOffset;   // End offset (offset + size)
    char* name;        // Optional label or description
} FileSection, *PFileSection;

extern const char* PEDataDirectoryNames[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

typedef struct _FileSectionList{
    PFileSection sections; // Dynamic array of sections
    WORD count;            // Number of sections currently stored
    WORD capacity;         // Allocated capacity for the array
} FileSectionList, *PFileSectionList;

RET_CODE ReportMalformed
(
    IN const char *reason,
    IN const char *context,
    IN const char *file,
    IN int line
);

// Retrieves the total size of a given file in bytes.
// peFile : Open file handle (must be valid and readable)
// Returns: LONGLONG representing the total file size, or -1 on failure
LONGLONG get_file_size
(
    IN FILE *peFile
);


UCHAR* read_entire_file_fp
(
    IN  FILE* peFile,
    OUT PULONGLONG outSize
);

RET_CODE get_dll_from_forwarder
(
    IN  const char *forwarderName,
    OUT char *outDllName,
    IN  ULONGLONG strSize
);

// Retrieves a human-readable name for a Data Directory entry by index.
// index  : Index within IMAGE_OPTIONAL_HEADER.DataDirectory
// Returns: const char* name string (e.g., "Import Table", "Export Table"), or "Unknown"
const char* get_data_directory_name
(
    IN int index
);

// Calculates a symbol’s file offset based on section and value information.
// value            : Offset value inside the section
// sectionNumber    : COFF section number (1-based index)
// sections         : Pointer to the section headers array
// numberOfSections : Total number of sections
// offsetOut        : Output pointer to receive the calculated file offset
// Returns          : 0 if successful, else for error
RET_CODE get_symbol_file_offset
(
    IN  DWORD value,
    IN  SHORT sectionNumber,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    OUT PDWORD outOffset
);

// Prints the program’s help or usage information to stdout.
void print_help(void);

// Decrypts a Rich header (XOR-based obfuscation) into a readable format.
// encRichHdr : Pointer to encrypted Rich header
// decRichHdr : Pointer to structure that receives the decrypted result
// Returns    : RET_CODE (RET_SUCCESS on success, RET_ERROR on failure)
RET_CODE decrypt_rich_header
(
    IN  PIMAGE_RICH_HEADER encRichHdr,
    OUT PIMAGE_RICH_HEADER decRichHdr
);

// Converts all alphabetic characters in a buffer to lowercase.
// buf : Input/output character buffer
// len : Number of characters to process
void strToLower
(
    INOUT char *buf,
    IN    ULONGLONG len
);

// Converts a DWORD timestamp from the PE header into a human-readable string
// timestamp: DWORD representing seconds since Unix epoch (1970-01-01)
// Returns  : const char* formatted as "(YYYY/MM/DD HH:MM:SS)"
//         - If timestamp == 0, returns a single space " "
//         - If conversion fails, returns "(invalid)"
const char* format_timestamp
(
    IN DWORD timestamp
);

// Converts a Windows FILETIME (100-nanosecond intervals since 1601) to a formatted string.
// filetime : ULONGLONG FILETIME value
// Returns  : const char* formatted as "(YYYY/MM/DD HH:MM:SS)" or "(invalid)"
const char *format_filetime
(
    IN ULONGLONG filetime
);

// Converts a DWORD value into a formatted hexadecimal string (e.g., "0x1234ABCD").
// val     : DWORD to format
// Returns : Pointer to static or allocated string containing the hex representation
char* str_to_hex
(
    IN DWORD val
);

// Reads the name of a DLL from an Import Descriptor entry.
// peFile          : Opened PE file handle
// impDesc         : Pointer to IMAGE_IMPORT_DESCRIPTOR
// sections        : Array of section headers
// numberOfSections: Total number of sections
// outName         : Output buffer for the DLL name
// Returns         : TRUE if name successfully read, FALSE on error
BOOL read_import_dll_name
(
    IN  FILE *peFile,
    IN  const PIMAGE_IMPORT_DESCRIPTOR impDesc,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    OUT char *outName
);

// Converts a Relative Virtual Address (RVA) to a file offset within a section.
// rva             : the Relative Virtual Address to convert
// sections        : pointer to array of IMAGE_SECTION_HEADERs
// numberOfSections: total number of sections in the PE
// outOffset       : pointer to DWORD where result will be stored
// Returns         : 0 if successful, 2 if RVA not found in any section, 1 on invalid input
RET_CODE rva_to_offset
(
    IN  DWORD rva,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    OUT PDWORD outOffset
);

// Converts a raw file offset to its corresponding RVA (Relative Virtual Address).
// offset          : file offset to convert
// sections        : array of section headers
// numberOfSections: total number of sections
// outRva          : pointer to DWORD to receive resulting RVA
// Returns         : 0 if successful, 1 if invalid, 2 if offset not found
RET_CODE offset_to_rva
(
    IN  DWORD offset,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    OUT PDWORD outRva
);

// Returns basic information about the section containing the given RVA.
// rva             : the Relative Virtual Address to query
// sections        : pointer to array of IMAGE_SECTION_HEADERs
// numberOfSections: total number of sections in the PE
// Returns         : SECTION_INFO struct containing section name, virtual address, and raw offset
SECTION_INFO get_section_info
(
    IN DWORD rva,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections
);

// Checks whether a section with a specific name exists in the PE.
// sections        : pointer to section headers array
// numberOfSections: total number of sections
// sectionName     : name of section to search for (case-sensitive)
// Returns         : TRUE if found, FALSE otherwise
BOOL has_section
(
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN const char *sectionName
);

// Retrieves detailed RVA information including file offset, VA, section name, and validity
// rva             : Relative Virtual Address to query
// sections        : pointer to array of IMAGE_SECTION_HEADER pointers
// numberOfSections: total number of sections
// imageBase       : base address of the PE in memory
// Returns         : RVA_INFO struct (filled if RVA found, otherwise marked as not found)
RVA_INFO get_rva_info
(
    IN DWORD rva,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN ULONGLONG imageBase
);

// Retrieves the size of the COFF string table.
// peFile           : opened file handle
// stringTableOffset: file offset to string table
// fileSize         : total file size
// outSize          : output pointer for the string table size
// Returns          : RET_SUCCESS on success, RET_ERROR otherwise
RET_CODE get_string_table_size
(
    IN  FILE *peFile,
    IN  DWORD stringTableOffset,
    IN  LONGLONG fileSize,
    OUT PDWORD outSize
);

// Calculates overlay (extra data) information following the last section.
// sections        : section header array
// numberOfSections: total section count
// fileSize        : total file size
// foOut           : output pointer for overlay file offset
// sizeOut         : output pointer for overlay size
void getOverlayInfo
(
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    IN  LONGLONG fileSize,
    OUT PDWORD foOut,
    OUT PDWORD sizeOut
);

// Retrieves the section name for a given symbol
// sectionNumber     : COFF symbol’s SectionNumber field
// sections          : Pointer to IMAGE_SECTION_HEADER array
// numberOfSections  : Total count of sections
// Returns           : const char* with section name or predefined label
const char* get_symbol_sectionName
(
    IN SHORT sectionNumber,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections
);

// Determines if a COFF symbol is an auxiliary “Function Definition” record.
// sym : Pointer to IMAGE_SYMBOL
// Returns: TRUE if auxiliary function, FALSE otherwise
BOOL IsAuxFunction
(
    IN PIMAGE_SYMBOL sym
);

// Determines if a COFF symbol is an auxiliary “Begin Function” record.
BOOL IsAuxBf
(
    IN PIMAGE_SYMBOL sym
);

// Determines if a COFF symbol is an auxiliary “End Function” record.
BOOL IsAuxEf
(
    IN PIMAGE_SYMBOL sym
);

// Determines if a COFF symbol is an auxiliary “Weak External” record.
BOOL IsAuxWeakExternal
(
    IN PIMAGE_SYMBOL sym
);

// Determines if a COFF symbol is an auxiliary “File” record.
BOOL IsAuxFile
(
    IN PIMAGE_SYMBOL sym
);

// Determines if a COFF symbol is an auxiliary “Section Definition” record.
// sym            : Pointer to IMAGE_SYMBOL
// sections       : Pointer to section headers array
// numberOfSection: Total number of sections
// Returns        : TRUE if section definition, FALSE otherwise
BOOL IsAuxSecDef
(
    IN PIMAGE_SYMBOL sym,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSection
);

// Determines if a COFF symbol is an auxiliary “CLR Token Definition” record.
BOOL IsAuxClrToken
(
    IN PIMAGE_SYMBOL sym
);

// Checks if machine type corresponds to MIPS or Alpha 32-bit architectures.
BOOL IsMIPSOrAlpha32
(
    IN WORD machine
);

// Checks if machine type corresponds to Alpha 64-bit architecture.
BOOL IsAlpha64
(
    IN WORD machine
);

// Checks if machine type corresponds to Windows CE.
BOOL IsWinCE
(
    IN WORD machine
);

// Checks if machine type corresponds to ARM (NT) architecture.
BOOL IsARMNT
(
    IN WORD machine
);

// Checks if machine type corresponds to ARM64 architecture.
BOOL IsARM64
(
    IN WORD machine
);

// Checks if machine type corresponds to x64 or Itanium architectures.
BOOL IsX64OrItanium
(
    IN WORD machine
);

// Prints a centered title or header with padding characters.
// text  : text to display in center
// padChar: character to pad with (e.g., '-')
// width : total width of printed line
void print_centered_header
(
    IN const char *text,
    IN char padChar,
    IN int width
);

// Prints formatted information for the Exception Directory table.
// vaBase      : base virtual address of the directory
// headerName  : label to print
// entriesCount: number of directory entries
// machine     : target machine type (for entry decoding)
void printExceptionDirectoryHeader
(
    IN ULONGLONG vaBase,
    IN char const *headerName,
    IN DWORD entriesCount,
    IN WORD machine
);

// Counts number of digits in a given integer value.
// number : unsigned integer to measure
// Returns: WORD count of decimal digits
WORD count_digits
(
    IN ULONGLONG number
);

// Counts valid IMAGE_IMPORT_DESCRIPTOR entries in Import Directory.
// impDesc: pointer to first IMAGE_IMPORT_DESCRIPTOR
// Returns: number of valid descriptors before a zeroed entry
WORD count_imp_descriptors
(
    IN PIMAGE_IMPORT_DESCRIPTOR impDesc
);

// Counts the number of valid entries (thunks) in an Import Table (INT/IAT)
// peFile         : opened PE file handle
// thunkRva       : RVA of the first thunk (OriginalFirstThunk or FirstThunk)
// sections       : array of section headers for RVA-to-offset translation
// numberOfSection: total number of sections
// is64bit        : flag for 64-bit PE (1) or 32-bit PE (0)
// Returns        : number of thunk entries until a terminating NULL entry is found
ULONGLONG count_thunks
(
    IN FILE *peFile,
    IN DWORD thunkRva,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSection,
    IN int is64bit
);

// Counts the number of table entries in a generic PE data table (e.g., TLS, Exception).
// peFile         : open file handle
// tableVA        : virtual address of table start
// sections       : array of section headers
// numberOfSections: total section count
// imageBase      : image base of PE file
// Returns        : DWORD count of valid table entries
DWORD count_table_entries
(
    IN FILE *peFile,
    IN ULONGLONG tableVA,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN ULONGLONG imageBase
);

// Determines if a string is Unicode or ANSI encoded.
// data : pointer to start of data
// len  : length of data buffer
// Returns: RET_SUCCESS if Unicode, RET_NO_VALUE if ANSI, RET_ERROR otherwise
RET_CODE IsUnicodeString
(
    IN const BYTE *data,
    IN DWORD len
);

// Checks whether a given import library is present within Import Descriptors.
// peFile          : open file handle
// impDesc         : import descriptor array
// numberOfEntries : number of descriptors
// sections        : section headers array
// numberOfSections: total sections
// dllName         : library name to search for
// Returns         : TRUE if present, FALSE otherwise
BOOL is_import_library_present
(
    IN FILE *peFile,
    IN PIMAGE_IMPORT_DESCRIPTOR impDesc,
    IN WORD numberOfEntries,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN const char *dllName
);

int regex_search
(
    IN const char* pattern,
    IN const char* text
);

#endif