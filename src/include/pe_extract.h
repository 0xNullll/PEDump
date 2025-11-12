#ifndef PE_EXTRACT_H
#define PE_EXTRACT_H

#include "libs.h"
#include "pe_structs.h"
#include "file_defs.h"
#include "struct_io.h"
#include "pe_parser.h"
#include "dump_data_dirs.h"
#include "cmd_types.h"
#include "dump_raw.h"
#include "dump_misc.h"
#include "md5.h"
#include "../thirdParty/tiny_sha.h"

typedef enum _PE_MAIN_TYPE {
    PE_TYPE_UNKNOWN = 0,
    PE_TYPE_MUI,
    PE_TYPE_EXE,
    PE_TYPE_DLL,
    PE_TYPE_DRIVER,
    PE_TYPE_SYSTEM,
    PE_TYPE_EFI,
    PE_TYPE_CONTROL_PANEL,
    PE_TYPE_ACTIVEX,
    PE_TYPE_SCREENSAVER
} PE_MAIN_TYPE;

typedef struct _PETypeInfo {
    BYTE isConsole     : 1;
    BYTE isGui         : 1;
    BYTE isFirmware    : 1;
    BYTE isNative      : 1;
    BYTE hasExports    : 1;
    BYTE hasImports    : 1;
    BYTE hasSignature  : 1;

    PE_MAIN_TYPE mainType;

    char extension[32];
    char fileName[260];
} PETypeInfo, *PPETypeInfo;

typedef enum _EXPORT_TYPE {
    EXPORT_TYPE_NONE     = 0x00,  // no type
    EXPORT_TYPE_DLL_NAME = 0x01,  // match by dll name
    EXPORT_TYPE_NAME     = 0x02,  // match by name
    EXPORT_TYPE_ORDINAL  = 0x04,  // match by ordinal
    EXPORT_TYPE_RVA      = 0x08   // match by relative virtual address (could be function rva or name rva)
} EXPORT_TYPE;

typedef struct _EXPORT_MATCH {
    char dllName[MAX_DLL_NAME];          // name of module this export belongs to
    char funcName[MAX_FUNC_NAME];        // exported function name
    char forwarderName[MAX_FUNC_NAME];   // Optional: forwarded-to string (DLL.Function)
    DWORD funcRva;                       // RVA of the exported function
    DWORD nameRva;                       // RVA of the name string (0 if not used)
    DWORD ordinal;                       // export ordinal

    BYTE type;
    BYTE isForwarded;    // 1 if this is a forwarded export

    DWORD rva;                          // relative virtual address of this export entry
} EXPORT_MATCH, *PEXPORT_MATCH;

typedef enum _IMPORT_TYPE {
    IMPORT_TYPE_NONE     = 0x00,  // no type
    IMPORT_TYPE_DLL_NAME = 0x01,  // match by dll name
    IMPORT_TYPE_NAME     = 0x02,  // match by name
    IMPORT_TYPE_ORDINAL  = 0x04,  // match by ordinal
    IMPORT_TYPE_HINT     = 0x08   // match by hint
} IMPORT_TYPE;

typedef struct _IMPORT_MATCH {
    char  dllName[MAX_DLL_NAME];   // DLL name
    char  funcName[MAX_FUNC_NAME]; // Function name
    WORD  hint;                     // Hint value
    WORD  ordinal;                  // Ordinal value
    ULONGLONG rawOrd;               // Raw value of ordinal
    BYTE  type;                     // IMPORT_TYPE
    BYTE  isGlobal;                 // Flag for global match

    DWORD thunkDataRVA;         // The RVA value contained within the thunk
    DWORD thunkRVA;                 // The RVA of the thunk entry
} IMPORT_MATCH, *PIMPORT_MATCH;

typedef struct _MATCH_LIST{
    void *items;          // Generic pointer to items
    ULONGLONG count;      // Number of items currently stored
    ULONGLONG capacity;   // Allocated capacity
    size_t itemSize;      // Size of each item type (e.g. sizeof(IMPORT_MATCH))
} MATCH_LIST, *PMATCH_LIST;

// Identifies the type of a PE file (EXE, DLL, SYS, etc.) and fills type-related info.
// filePath          : path to the PE file
// dataDirs          : pointer to the PE file's data directories
// sections          : array of section headers
// numberOfSections  : number of sections in the PE
// fileFlags         : PE file flags
// addrOfEntryPoint  : Address of Entry Point from the PE header
// subsystem         : subsystem value from PE header
// majorSubVer       : major subsystem version
// minorSubVer       : minor subsystem version
// outPetypeinfo     : pointer to PPETypeInfo structure to receive type info
// Returns           : RET_CODE indicating success or failure
RET_CODE identify_pe_type
(
    IN  const char            *filePath,
    IN  PIMAGE_DATA_DIRECTORY dataDirs,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD                  numberOfSections,
    IN  WORD                  fileFlags,
    IN  DWORD                 addrOfEntryPoint,
    IN  WORD                  subsystem,
    IN  WORD                  majorSubVer,
    IN  WORD                  minorSubVer,
    OUT PPETypeInfo           outPetypeinfo
);

// Processes PE sections to extract data based on extraction configuration.
// sections          : pointer to array of section headers
// numberOfSections  : number of sections in the PE
// sectionCfg        : pointer to section extraction configuration
// outfo             : output pointer for the file offset of extracted section
// outSize           : output pointer for the size of extracted section
// outSectionIdx     : output pointer for index of the section extracted
// Returns           : RET_CODE indicating success or failure
RET_CODE extract_section
(
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD                  numberOfSections,
    IN  PSectionExtract       sectionCfg,
    IN  PDWORD                outfo,
    OUT PDWORD                outSize,
    OUT PWORD                 outSectionIdx
);

// Match if a given export entry matches the extraction configuration.
// expCfg         : pointer to export extraction configuration
// funcRva        : Relative Virtual Address of the function
// nameRva        : Relative Virtual Address of the function name
// ordinal        : export ordinal
// name           : export name string
// forwardName    : forwarder name string (if any)
// ExportDllName  : name of the DLL exporting the function
// forwardDllName : name of the DLL the function is forwarded to (if any)
// Returns        : TRUE if the export matches the configuration, FALSE otherwise
BOOL match_export_entry
(
    IN const PExportExtract expCfg,
    IN DWORD                funcRva,
    IN DWORD                nameRva,
    IN ULONGLONG            ordinal,
    IN const char           *name,
    IN const char           *forwardName,
    IN const char           *ExportDllName,
    IN const char           *forwardDllName
);

// Processes the export directory of a PE file to extract matching exports.
// peFile           : pointer to the open PE file
// sections         : array of section headers
// numberOfSections : number of sections in the PE file
// expDirData       : pointer to the export data directory
// expDesc          : pointer to the export directory descriptor
// expCfg           : pointer to export extraction configuration
// outMatchesList   : pointer to a MATCH_LIST to store found matches
// Returns          : RET_CODE indicating success or failure
RET_CODE extract_exports
(
    IN FILE                     *peFile,
    IN PIMAGE_SECTION_HEADER    sections,
    IN WORD                     numberOfSections,
    IN PIMAGE_DATA_DIRECTORY    expDirData,
    IN PIMAGE_EXPORT_DIRECTORY  expDesc,
    IN PExportExtract           expCfg,
    OUT PMATCH_LIST             outMatchesList
);

// Match if an imported function matches the given extraction criteria (name, dll name, hint, or ordinal).
// impCfg   : pointer to import extraction configuration
// ordinal  : function ordinal from import table
// hint     : function hint from import table
// funcName : function name from import table
// dllName  : dll name from import table
// Returns  : TRUE if the function matches the extraction criteria, FALSE otherwise
BOOL match_import_entry
(
    IN const PImportExtract impCfg,
    IN ULONGLONG            ordinal,
    IN WORD                 hint,
    IN const char           *funcName,
    IN const char           *dllName
);

// Processes PE import descriptors to extract matching imported functions based on configuration.
// peFile            : pointer to the opened PE file
// sections          : pointer to array of section headers
// numberOfSections  : number of sections in the PE
// impDesc           : pointer to the import descriptor table
// is64bit           : non-zero if the target PE is 64-bit, zero otherwise
// impCfg            : pointer to import extraction configuration
// outMatchesList    : output pointer to a list where matched imports are stored
// Returns           : RET_CODE indicating success or failure
RET_CODE extract_imports
(
    IN  FILE                     *peFile,
    IN  PIMAGE_SECTION_HEADER    sections,
    IN  WORD                     numberOfSections,
    IN  PIMAGE_IMPORT_DESCRIPTOR impDesc,
    IN  int                      is64bit,
    IN  PImportExtract           impCfg,
    OUT PMATCH_LIST              outMatchesList
);

// Executes the full extraction process on a PE file, including exports, imports, and data directories.
// peFile          : pointer to the open PE file
// sections        : array of section headers
// numberOfSections: number of sections in the PE file
// symTableOffset  : file offset to the symbol table
// NumberOfSymbols : number of symbols in the symbol table
// dataDirs        : pointer to the PE's data directories
// dirs            : pointer to PEDataDirectories structure
// fileSize        : size of the PE file
// imageBase       : base address of the image
// is64bit         : nonzero if the PE file is 64-bit
// config          : pointer to extraction configuration
// fileSectionList : list of file sections
// Returns         : RET_CODE indicating success or failure of the extraction
RET_CODE perform_extract
(
    IN FILE                  *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD                  numberOfSections,
    IN DWORD                 symTableOffset,
    IN DWORD                 NumberOfSymbols,
    IN PIMAGE_DATA_DIRECTORY dataDirs,
    IN PPEDataDirectories    dirs,
    IN LONGLONG              fileSize,
    IN ULONGLONG             imageBase,
    IN int                   is64bit,
    IN PConfig               config,
    IN PFileSectionList      fileSectionList
);

// Extracts the version resource from a PE file.
// peFile            : pointer to the opened PE file
// sections          : array of section headers
// numberOfSections  : number of sections
// rsrcDataDir       : pointer to the resource data directory
// rsrcDir           : pointer to the resource directory
// rsrcEntriesDir    : pointer to the resource directory entries
// outDataRVA        : output pointer to receive RVA of version resource data
// outSize           : output pointer to receive size of version resource
// Returns           : RET_CODE indicating success or failure
RET_CODE extract_version_resource
(
    IN  FILE                            *peFile,
    IN  PIMAGE_SECTION_HEADER           sections,
    IN  WORD                            numberOfSections,
    IN  PIMAGE_DATA_DIRECTORY           rsrcDataDir,
    IN  PIMAGE_RESOURCE_DIRECTORY       rsrcDir,
    IN  PIMAGE_RESOURCE_DIRECTORY_ENTRY rsrcEntriesDir,
    OUT PDWORD                          outDataRVA,
    OUT PDWORD                          outSize
);

RET_CODE load_target_buffer
(
    IN    PPEContext ctx,
    INOUT PTarget    target
);

RET_CODE compute_hash
(
    IN  PTarget target,
    IN  WORD algorithm,
    OUT PUCHAR outHash,
    OUT PULONGLONG outLen
);

RET_CODE perform_hash_extract(
    IN PHashConfig hashCfg
);

#endif