#ifndef DUMP_DATA_DIRS_H
#define DUMP_DATA_DIRS_H

#include "libs.h"
#include "pe_structs.h"
#include "file_defs.h"
#include "pe_utils.h"
#include "dump_pe_flags.h"
#include "dump_headers.h"

// Dumps and analyzes the Export Table of a PE file.
// peFile          : handle to the opened PE file (used for reading raw data).
// sections        : array of section headers, used for RVA-to-FO conversion.
// numberOfSections: total number of sections in the PE file.
// ExportDirData   : pointer to IMAGE_DATA_DIRECTORY of the Export Table.
// ExportDir       : pointer to IMAGE_EXPORT_DIRECTORY structure.
// EAT             : Export Address Table (array of RVAs).
// NameRVAArray    : Export Name Table (array of RVAs to names).
// NameOrdinalArray: Ordinal Table (array of WORDs).
// imageBase       : base address of the loaded image.
// truncateNames   : If non-zero, long function names are truncated with "..." for neat output.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_exported_functions
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY ExportDirData,
    IN PIMAGE_EXPORT_DIRECTORY ExportDir,
    IN PDWORD EAT,
    IN PDWORD NameRVAArray,
    IN PWORD  NameOrdinalArray,
    IN ULONGLONG imageBase,
    IN int truncateNames
);

// Dumps the Export Directory of a PE file.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// ExportDirData   : pointer to IMAGE_DATA_DIRECTORY of the Export Table.
// ExportDir       : pointer to IMAGE_EXPORT_DIRECTORY structure.
// imageBase       : base address of the loaded image.
// truncateNames   : If non-zero, long function names are truncated with "..." for neat output.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_export_dir
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY ExportDirData,
    IN PIMAGE_EXPORT_DIRECTORY ExportDir,
    IN ULONGLONG imageBase,
    IN int truncateNames
);

// Reads the hint and name of an imported function.
// peFile          : handle to the opened PE file.
// rva             : relative virtual address of the import entry.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// hintOut         : output pointer to store the hint value.
// nameOut         : output buffer to store the function name.
// Returns         : TRUE on success, FALSE on failure.
BOOL read_import_hint_and_name
(
    IN  FILE *peFile,
    IN  DWORD rva,
    IN  PIMAGE_SECTION_HEADER sections,
    IN  WORD numberOfSections,
    OUT PWORD hintOut,
    OUT char *nameOut
);

// Dumps the Import Name Table (INT).
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// OriginalFirstThunk: RVA of the INT.
// FirstThunk      : RVA of the IAT.
// imageBase       : base address of the loaded image.
// is64bit         : flag indicating PE architecture (1 = 64-bit, 0 = 32-bit).
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_int_table
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN DWORD OrignalFirstThunk,
    IN DWORD FirstThunk,
    IN ULONGLONG imageBase,
    IN int is64bit
);

// Dumps the Import Address Table (IAT).
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// FirstThunk      : RVA of the IAT.
// imageBase       : base address of the loaded image.
// is64bit         : flag indicating PE architecture (1 = 64-bit, 0 = 32-bit).
// fileSize        : total file size for bounds checking.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_iat_table
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN DWORD FirstThunk,
    IN ULONGLONG imageBase,
    IN int is64bit,
    IN LONGLONG fileSize
);

// Prints the header of an import descriptor for a DLL.
// peFile          : handle to the opened PE file.
// desc            : pointer to IMAGE_IMPORT_DESCRIPTOR for the DLL.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// vaBase          : pointer to store base virtual address of descriptor.
// foBase          : pointer to store base file offset of descriptor.
// imageBase       : base address of the loaded image.
// index           : index of the import descriptor in the array.
void print_import_descriptor_header
(
    IN FILE *peFile,
    IN PIMAGE_IMPORT_DESCRIPTOR desc,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PULONGLONG vaBase,
    IN PDWORD foBase,
    IN ULONGLONG imageBase,
    IN int index
);

// Dumps the Import Directory, combining INT and IAT info for each DLL.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// importDirData   : pointer to IMAGE_DATA_DIRECTORY of the Import Directory.
// importDir       : pointer to IMAGE_IMPORT_DESCRIPTOR array.
// imageBase       : base address of the loaded image.
// is64bit         : 1 for 64-bit, 0 for 32-bit PE.
// fileSize        : total file size for bounds checking.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_import_dir
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY importDirData,
    IN PIMAGE_IMPORT_DESCRIPTOR importDir,
    IN ULONGLONG imageBase,
    IN int is64bit,
    IN LONGLONG fileSize
);

// Dumps entries in a resource directory recursively.
// peFile           : handle to the opened PE file.
// entryOffset      : file offset of the resource entry.
// totalOfSubEntries: number of entries in this directory.
// sections         : array of section headers.
// numberOfSections : total number of sections.
// rsrcSecInfo      : pointer to SECTION_INFO array to store resource info.
// level            : recursion depth for nested directories.
// imageBase        : base address of the loaded image.
// Returns          : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_rsrc_entries
(
    IN FILE *peFile,
    IN DWORD entryOffset,
    IN WORD totalOfSubEntries,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN SECTION_INFO *rsrcSecInfo,
    IN int level,
    IN ULONGLONG imageBase
);

// Dumps a subdirectory within a resource directory.
// peFile          : handle to the opened PE file.
// subDirOffset    : file offset of the subdirectory.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// rsrcSecInfo     : pointer to SECTION_INFO array to store resource info.
// level           : recursion depth for nested directories.
// imageBase       : base address of the loaded image.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_rsrc_sub_dir
(
    IN FILE *peFile,
    IN DWORD subDirOffset,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN SECTION_INFO *rsrcSecInfo,
    IN int level,
    IN ULONGLONG imageBase
);

// Dumps the top-level resource directory of a PE file.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// rsrcDataDir     : pointer to IMAGE_DATA_DIRECTORY of the resources.
// rsrcDir         : pointer to IMAGE_RESOURCE_DIRECTORY structure.
// rsrcEntriesDir  : pointer to first IMAGE_RESOURCE_DIRECTORY_ENTRY array.
// imageBase       : base address of the loaded image.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_rsrc_dir
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY rsrcDataDir,
    IN PIMAGE_RESOURCE_DIRECTORY rsrcDir,
    IN PIMAGE_RESOURCE_DIRECTORY_ENTRY rsrcEntriesDir,
    IN ULONGLONG imageBase
);

// Prints version resource header info.
// versionInfo : pointer to VS_VERSIONINFO_HEADER.
// vaBase      : base virtual address for calculating VAs.
// foBase      : base file offset for calculating FOs.
// level       : output indentation depth for formatting.
void print_version_header
(
    IN VS_VERSIONINFO_HEADER *versionInfo,
    IN ULONGLONG vaBase,
    IN DWORD foBase,
    IN int level
);

// Prints fixed file info from a version resource.
// FixedFileInfo : pointer to VS_FIXEDFILEINFO.
// twValueLength : length of value structure.
// vaBase        : base virtual address.
// foBase        : base file offset.
// level         : output indentation depth for formatting.
void print_version_extras
(
    IN VS_FIXEDFILEINFO *FixedFileInfo,
    IN WORD twValueLength,
    IN ULONGLONG vaBase,
    IN DWORD foBase,
    IN int level
);

// Prints a StringFileInfo resource block.
// stringfileinfo : pointer to StringFileInfo structure.
// szKey          : pointer to the key string.
// szKeyLen       : length of the key string.
// vaBase         : base virtual address for VA calculations.
// foBase         : base file offset for FO calculations.
// level          : recursion/verbosity level.
void print_string_file_info
(
    IN StringFileInfo *stringfileinfo,
    IN WCHAR *szKey,
    IN ULONGLONG szKeyLen,
    IN ULONGLONG vaBase,
    IN DWORD foBase,
    IN int level
);

// Prints a StringTable within a version resource.
// stringtable : pointer to StringTable structure.
// vaBase      : base virtual address.
// foBase      : base file offset.
// level       : output indentation depth for formatting.
void print_string_table
(
    IN StringTable *stringtable,
    IN ULONGLONG vaBase,
    IN DWORD foBase,
    IN int level
);

// Prints a single string entry in a version resource.
// string      : pointer to String structure.
// szKey       : key name string.
// szKeyLen    : length of the key.
// value       : string value.
// valueLen    : length of the string value.
// vaBase      : base virtual address.
// foBase      : base file offset.
// level       : output indentation depth for formatting.
void print_string
(
    IN String *string,
    IN WCHAR *szKey,
    IN ULONGLONG szKeyLen,
    IN WCHAR* value,
    IN ULONGLONG valueLen,
    IN ULONGLONG vaBase,
    IN DWORD foBase,
    IN int level
);

// Prints VarFileInfo resource block.
// varfileinfo : pointer to VarFileInfo structure.
// szKey       : key string.
// szKeyLen    : key string length.
// vaBase      : base virtual address.
// foBase      : base file offset.
// level       : output indentation depth for formatting.
void print_var_file_info
(
    IN VarFileInfo *varfileinfo,
    IN WCHAR *szKey,
    IN ULONGLONG szKeyLen,
    IN ULONGLONG vaBase,
    IN DWORD foBase,
    IN int level
);

// Prints a Var entry inside a VarFileInfo.
// var          : pointer to Var structure.
// szKey        : key string.
// szKeyLen     : key string length.
// values       : array of DWORD values.
// valueCount   : number of DWORD values.
// valueVaBase  : VA base of values.
// valueFoBase  : FO base of values.
// VaBase       : base VA of the containing structure.
// FoBase       : base FO of the containing structure.
// level        : output indentation depth for formatting.
void print_var
(
    IN Var *var,
    IN WCHAR *szKey,
    IN ULONGLONG szKeyLen,
    IN PDWORD values,
    IN ULONGLONG valueCount,
    IN ULONGLONG valueVaBase,
    IN DWORD valueFoBase,
    IN ULONGLONG VaBase,
    IN DWORD FoBase,
    IN int level
);

// Dumps VS_FIXEDFILEINFO from a version resource.
// peFile : handle to PE file.
// vaBase : pointer to VA base (updated during read).
// foBase : pointer to FO base (updated during read).
// valueLength : length of the structure.
// Returns RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_fixed_file_info
(
    IN    FILE *peFile,
    INOUT PULONGLONG vaBase,
    INOUT PDWORD foBase,
    IN    WORD valueLength
);

// Dumps VS_VERSIONINFO_HEADER from a version resource.
// peFile        : handle to PE file.
// vaBase        : pointer to VA base (updated during read).
// foBase        : pointer to FO base (updated during read).
// outVersionInfo: output structure to fill.
// Returns RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_version_info_header
(
    IN    FILE *peFile,
    INOUT PULONGLONG vaBase,
    INOUT PDWORD foBase,
    OUT   VS_VERSIONINFO_HEADER *outVersionInfo
);

// Dumps a StringFileInfo structure.
// peFile           : handle to PE file.
// vaBase           : pointer to VA base (updated during read).
// foBase           : pointer to FO base (updated during read).
// outStringFileInfo: output structure to fill.
// outSzKeyBytesLen : pointer to receive key length.
// Returns RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_string_file_info
(
    IN    FILE *peFile,
    INOUT PULONGLONG vaBase,
    INOUT PDWORD foBase,
    OUT   StringFileInfo *outStringFileInfo,
    IN    PULONGLONG outSzKeyBytesLen
);

// Dumps all StringTables in a StringFileInfo block.
// peFile       : handle to PE file.
// vaBase       : pointer to VA base.
// foBase       : pointer to FO base.
// stringfileinfo: pointer to StringFileInfo structure.
// szKeyBytesLen: length of the key string.
// Returns RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_string_tables
(
    IN    FILE *peFile,
    INOUT PULONGLONG vaBase,
    INOUT PDWORD foBase,
    OUT   StringFileInfo *stringfileinfo,
    IN    ULONGLONG szKeyBytesLen
);

// Dumps VarFileInfo structure from a version resource.
// peFile           : handle to PE file.
// vaBase           : pointer to VA base.
// foBase           : pointer to FO base.
// outVarFileInfo   : output VarFileInfo structure.
// outSzKeyBytesLen : pointer to receive key length.
// Returns RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_var_file_info
(
    IN    FILE *peFile,
    INOUT PULONGLONG vaBase,
    INOUT PDWORD foBase,
    OUT   VarFileInfo *outVarFileInfo,
    IN    PULONGLONG outSzKeyBytesLen
);

// Dumps a Var entry inside VarFileInfo.
// peFile           : handle to PE file.
// vaBase           : pointer to VA base.
// foBase           : pointer to FO base.
// varfileinfo      : output VarFileInfo structure.
// vfiSzKeyBytesLen : length of the key string.
// Returns RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_var
(
    IN    FILE *peFile,
    INOUT PULONGLONG vaBase,
    INOUT PDWORD foBase,
    OUT   VarFileInfo *varfileinfo,
    IN    ULONGLONG vfiSzKeyBytesLen
);

// Dumps the complete version information resource.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// versionInfoRva  : RVA of the version resource.
// versionInfoSize : size of the version resource.
// imageBase       : base address of the loaded image.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_version_info
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN DWORD versionInfoRva,
    IN DWORD versionInfoSize,
    IN ULONGLONG imageBase
);

// Prints MIPS or Alpha32 runtime function entries.
// entries    : pointer to IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY array.
// vaBase     : base virtual address.
// foBase     : base file offset.
// maxEntries : maximum number of entries to print.
// sizeOfEntry: size of each entry in bytes.
void print_MIPS_or_alpha32_entries
(
    IN PIMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY entries,
    IN ULONGLONG vaBase,
    IN DWORD foBase,
    IN DWORD maxEntries,
    IN WORD sizeOfEntry
);

// Prints Alpha64 runtime function entries.
// entries    : pointer to an array of IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY structures.
// vaBase     : base virtual address used to calculate absolute VAs for entries.
// foBase     : base file offset used to calculate absolute FOs for entries.
// maxEntries : maximum number of entries to print.
// sizeOfEntry: size of each runtime function entry in bytes.
// Returns    : void.
void print_alpha64_entries
(
    IN PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY entries,
    IN ULONGLONG vaBase,
    IN DWORD foBase,
    IN DWORD maxEntries,
    IN WORD sizeOfEntry
);

// Prints Windows CE runtime function entries.
// entries    : pointer to an array of IMAGE_CE_RUNTIME_FUNCTION_ENTRY structures.
// vaBase     : base virtual address used to calculate absolute VAs for entries.
// foBase     : base file offset used to calculate absolute FOs for entries.
// maxEntries : maximum number of entries to print.
// sizeOfEntry: size of each runtime function entry in bytes.
// Returns    : void.
void print_winCE_entries
(
    IN PIMAGE_CE_RUNTIME_FUNCTION_ENTRY entries,
    IN ULONGLONG vaBase,
    IN DWORD foBase,
    IN DWORD maxEntries,
    IN WORD sizeOfEntry
);

// Prints ARM runtime function entries.
// entries    : pointer to an array of IMAGE_ARM_RUNTIME_FUNCTION_ENTRY structures.
// vaBase     : base virtual address used to calculate absolute VAs for entries.
// foBase     : base file offset used to calculate absolute FOs for entries.
// maxEntries : maximum number of entries to print.
// sizeOfEntry: size of each runtime function entry in bytes.
// Returns    : void.
void print_ARM_entries
(
    IN PIMAGE_ARM_RUNTIME_FUNCTION_ENTRY entries,
    IN ULONGLONG vaBase,
    IN DWORD foBase,
    IN DWORD maxEntries,
    IN WORD sizeOfEntry
);

// Prints ARM64 runtime function entries.
// entries    : pointer to an array of IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY structures.
// vaBase     : base virtual address used to calculate absolute VAs for entries.
// foBase     : base file offset used to calculate absolute FOs for entries.
// maxEntries : maximum number of entries to print.
// sizeOfEntry: size of each runtime function entry in bytes.
// Returns    : void.
void print_ARM64_entries
(
    IN PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY entries,
    IN ULONGLONG vaBase,
    IN DWORD foBase,
    IN DWORD maxEntries,
    IN WORD sizeOfEntry
);

// Prints x64 runtime function entries.
// entries    : pointer to an array of _IMAGE_RUNTIME_FUNCTION_ENTRY structures.
// vaBase     : base virtual address used to calculate absolute VAs for entries.
// foBase     : base file offset used to calculate absolute FOs for entries.
// maxEntries : maximum number of entries to print.
// sizeOfEntry: size of each runtime function entry in bytes.
// Returns    : void.
void print_x64_entries
(
    IN _PIMAGE_RUNTIME_FUNCTION_ENTRY entries,
    IN ULONGLONG vaBase,
    IN DWORD foBase,
    IN DWORD maxEntries,
    IN WORD sizeOfEntry
);

// Dumps the Exception Directory of a PE file.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// exceptionDirData: pointer to IMAGE_DATA_DIRECTORY of the Exception Directory.
// machine         : target machine type (IMAGE_FILE_MACHINE_*).
// imageBase       : base address of the loaded image.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_exception_dir
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY exceptionDirData,
    IN WORD machine,
    IN ULONGLONG imageBase
);

// Dumps the Security Directory of a PE file.
// peFile          : handle to the opened PE file.
// securityDirData : pointer to IMAGE_DATA_DIRECTORY of the Security Directory.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_security_dir
(
    IN FILE *peFile,
    IN PIMAGE_DATA_DIRECTORY securityDirData
);

// Dumps the Base Relocation Directory of a PE file.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// relocDirData    : pointer to IMAGE_DATA_DIRECTORY of relocations.
// imageBase       : base address of the loaded image.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_reloc_dir
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY relocDirData,
    IN ULONGLONG imageBase
);

// Dumps the COFF Debug Directory of a PE file.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// debugDir        : pointer to IMAGE_DEBUG_DIRECTORY for COFF debug data.
// level           : output indentation depth for formatting.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_COFF_debug_info
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DEBUG_DIRECTORY debugDir,
    IN WORD level
);

// Dumps the CodeView Debug Directory of a PE file.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// debugDir        : pointer to IMAGE_DEBUG_DIRECTORY for CodeView debug data.
// level           : output indentation depth for formatting.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_CodeView_debug_info
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DEBUG_DIRECTORY debugDir,
    IN WORD level
);

// Dumps the FPO (Frame Pointer Omission) Debug Directory of a PE file.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// debugDir        : pointer to IMAGE_DEBUG_DIRECTORY for FPO debug data.
// imageBase       : base address of the loaded image.
// level           : output indentation depth for formatting.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_FPO_debug_info
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DEBUG_DIRECTORY debugDir,
    IN WORD level
);

// Dumps the MISC Debug Directory of a PE file (IMAGE_DEBUG_TYPE_MISC).
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// debugDir        : pointer to IMAGE_DEBUG_DIRECTORY for MISC debug data.
// level           : output indentation depth for formatting.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_MISC_debug_info
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DEBUG_DIRECTORY debugDir,
    IN WORD level
);

// Prints the Exception Directory entries for 32-bit PE files.
// entries    : pointer to IMAGE_FUNCTION_ENTRY array.
// vaBase     : base virtual address of the PE image.
// foBase     : file offset base corresponding to the VA.
// maxEntries : maximum number of entries to print.
// sizeOfEntry: size of each function entry structure.
// level      : output indentation depth for formatting.
void print_exception_debug_entries
(
    IN PIMAGE_FUNCTION_ENTRY entries,
    IN ULONGLONG vaBase,
    IN DWORD foBase,
    IN DWORD maxEntries,
    IN WORD sizeOfEntry,
    IN WORD level
);

// Prints the Exception Directory entries for 64-bit PE files.
// entries    : pointer to IMAGE_FUNCTION_ENTRY64 array.
// machine    : target machine type (IMAGE_FILE_MACHINE_*).
// vaBase     : base virtual address of the PE image.
// foBase     : file offset base corresponding to the VA.
// maxEntries : maximum number of entries to print.
// sizeOfEntry: size of each function entry structure.
// level      : output indentation depth for formatting.
void print_exception_debug_entries64
(
    IN PIMAGE_FUNCTION_ENTRY64 entries,
    IN WORD machine,
    IN ULONGLONG vaBase,
    IN DWORD foBase,
    IN DWORD maxEntries,
    IN WORD sizeOfEntry,
    IN WORD level
);

// Dumps the Exception Directory debug information of a PE file.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// debugDir        : pointer to IMAGE_DEBUG_DIRECTORY for exception data.
// machine         : target machine type (IMAGE_FILE_MACHINE_*).
// imageBase       : base address of the loaded image.
// is64bit         : non-zero if PE is 64-bit, 0 if 32-bit.
// level           : output indentation depth for formatting.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_exception_debug_info
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DEBUG_DIRECTORY debugDir,
    IN WORD machine,
    IN ULONGLONG imageBase,
    IN int is64bit,
    IN WORD level
);

// Dumps the OMAP Debug Directory of a PE file.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// debugDir        : pointer to IMAGE_DEBUG_DIRECTORY for OMAP data.
// imageBase       : base address of the loaded image.
// isToSrc         : non-zero to map from OMAP to source, 0 for inverse mapping.
// level           : output indentation depth for formatting.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_OMAP_debug_info
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DEBUG_DIRECTORY debugDir,
    IN ULONGLONG imageBase,
    IN int isToSrc,
    IN WORD level
);

// Dumps the REPRO Debug Directory of a PE file (IMAGE_DEBUG_TYPE_REPRO).
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// debugDir        : pointer to IMAGE_DEBUG_DIRECTORY for REPRO data.
// level           : output indentation depth for formatting.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_REPRO_debug_info
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DEBUG_DIRECTORY debugDir,
    IN WORD level
);

// Dumps the VC Feature Debug Directory of a PE file.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// debugDir        : pointer to IMAGE_DEBUG_DIRECTORY for VC feature data.
// level           : output indentation depth for formatting.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_VC_feature_debug_info
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DEBUG_DIRECTORY debugDir,
    IN WORD level
);

// Dumps the Debug Directory of a PE file and dispatches to the appropriate
// debug information handler depending on type (COFF, CodeView, FPO, MISC, etc).
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// debugDataDir    : pointer to IMAGE_DATA_DIRECTORY of the Debug Directory.
// debugDir        : pointer to IMAGE_DEBUG_DIRECTORY entries.
// machine         : target machine type (IMAGE_FILE_MACHINE_*).
// imageBase       : base address of the loaded image.
// is64bit         : non-zero if PE is 64-bit, 0 if 32-bit.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_debug_dir
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY debugDataDir,
    IN PIMAGE_DEBUG_DIRECTORY debugDir,
    IN WORD machine,
    IN ULONGLONG imageBase,
    IN int is64bit
);

// Dumps the TLS (Thread Local Storage) Directory of a PE file.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// tlsDataDir      : pointer to IMAGE_DATA_DIRECTORY for TLS data.
// tls64           : pointer to 64-bit TLS directory structure.
// tls32           : pointer to 32-bit TLS directory structure.
// imageBase       : base address of the loaded image.
// is64bit         : non-zero if PE is 64-bit, 0 if 32-bit.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_tls_dir
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY tlsDataDir,
    IN PIMAGE_TLS_DIRECTORY64 tls64,
    IN PIMAGE_TLS_DIRECTORY32 tls32,
    IN ULONGLONG imageBase,
    IN int is64bit
);

// Prints entries of the Load Configuration Table (guard flags, SEH info, etc.).
// peFile          : handle to the opened PE file.
// tableVA         : virtual address of the table in memory.
// tableCount      : number of entries or size of table.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// imageBase       : base address of the loaded image.
// tableName       : descriptive name of the table.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE print_load_config_table
(
    IN FILE *peFile,
    IN ULONGLONG tableVA,
    IN ULONGLONG tableCount,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN ULONGLONG imageBase,
    IN const char* tableName
);

// Dumps the Load Configuration Directory of a PE file.
// Handles both 32-bit and 64-bit variants.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// lcfgDataDir     : pointer to IMAGE_DATA_DIRECTORY of the Load Config.
// loadConfig64    : pointer to 64-bit load config structure.
// loadConfig32    : pointer to 32-bit load config structure.
// imageBase       : base address of the loaded image.
// is64bit         : flag indicating PE architecture.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_load_config_dir
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY lcfgDataDir,
    IN PIMAGE_LOAD_CONFIG_DIRECTORY64 loadConfig64,
    IN PIMAGE_LOAD_CONFIG_DIRECTORY32 loadConfig32,
    IN ULONGLONG imageBase,
    IN int is64bit
);

// Dumps the Bound Import Directory of a PE file.
// peFile            : handle to the opened PE file.
// sections          : array of section headers.
// numberOfSections  : total number of sections.
// boundImportDataDir: pointer to IMAGE_DATA_DIRECTORY of Bound Imports.
// imageBase         : base address of the loaded image.
// Returns           : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_bound_import_dir
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY boundImportDataDir,
    IN ULONGLONG imageBase
);

// Dumps the Delay Import Directory of a PE file.
// peFile             : handle to the opened PE file.
// sections           : array of section headers.
// numberOfSections   : total number of sections.
// pDelayImportDataDir: pointer to IMAGE_DATA_DIRECTORY for delay imports.
// delayImportDir     : pointer to PIMAGE_DELAYLOAD_DESCRIPTOR structure.
// imageBase          : base address of the loaded image.
// is64bit            : non-zero if PE is 64-bit, 0 if 32-bit.
// fileSize           : total size of the PE file.
// Returns            : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_delay_import_dir
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY pDelayImportDataDir,
    IN PIMAGE_DELAYLOAD_DESCRIPTOR delayImportDir,
    IN ULONGLONG imageBase,
    IN int is64bit,
    IN LONGLONG fileSize
);

// Dumps the CLR Header Directory of a PE file (for .NET assemblies).
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// clrHeaderDataDir: pointer to IMAGE_DATA_DIRECTORY of CLR header.
// clrHeaderDir    : pointer to IMAGE_COR20_HEADER structure.
// imageBase       : base address of the loaded image.
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_clr_header_dir
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY clrHeaderDataDir,
    IN PIMAGE_COR20_HEADER clrHeaderDir,
    IN ULONGLONG imageBase
);

// Dumps all data directories of a PE file.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections.
// dataDirs        : pointer to IMAGE_DATA_DIRECTORY array.
// dirs            : pointer to PPEDataDirectories structure.
// imageBase       : base address of the loaded image.
// is64bit         : non-zero if PE is 64-bit, 0 if 32-bit.
// fileSize        : total size of the PE file.
// machine         : target machine type (IMAGE_FILE_MACHINE_*).
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_all_data_directories
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY dataDirs,
    IN PPEDataDirectories dirs,
    IN ULONGLONG imageBase,
    IN int is64bit,
    IN LONGLONG fileSize,
    IN WORD machine
);

// Dumps all data directories of a PE file.
// This function iterates through all standard PE data directories 
// (Export, Import, Resource, Exception, Security, Base Relocation, 
// Debug, TLS, Load Config, Bound Import, IAT, Delay Import, CLR, etc.) 
// and invokes the appropriate handler for each.
// peFile          : handle to the opened PE file.
// sections        : array of section headers.
// numberOfSections: total number of sections in the PE file.
// dataDirs        : pointer to the IMAGE_DATA_DIRECTORY array of all directories.
// dirs            : pointer to PPEDataDirectories structure containing parsed info.
// imageBase       : base address of the loaded image in memory.
// is64bit         : non-zero if PE is 64-bit, 0 if 32-bit.
// fileSize        : total size of the PE file on disk.
// machine         : target machine type (IMAGE_FILE_MACHINE_*).
// Returns         : RET_SUCCESS on success, RET_ERROR on failure.
RET_CODE dump_all_data_directories
(
    IN FILE *peFile,
    IN PIMAGE_SECTION_HEADER sections,
    IN WORD numberOfSections,
    IN PIMAGE_DATA_DIRECTORY dataDirs,
    IN PPEDataDirectories dirs,
    IN ULONGLONG imageBase,
    IN int is64bit,
    IN LONGLONG fileSize,
    IN WORD machine
);

#endif