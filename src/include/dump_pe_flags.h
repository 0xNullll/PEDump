#ifndef DUMP_PE_FLAGS_H
#define DUMP_PE_FLAGS_H

#include "libs.h"
#include "pe_structs.h"
#include "pe_flags.h"
#include "pe_utils.h"

// Converts a machine type to a human-readable string
// machine : IMAGE_FILE_HEADER.Machine value
// Returns : const char* string describing the machine type (e.g., "x86", "x64")
const char* fileHeaderMachineToString(IN WORD machine);
#define MAX_STR_LEN_FILE_HEADER_MACHINE 35

// Converts an OS version (Major.Minor) to a string
// major : Major OS version number
// minor : Minor OS version number
// Returns : const char* string representing the OS version flag
const char* osVersionToString(IN WORD major, IN WORD minor);
#define MAX_STR_LEN_OS_VERSION 20

// Converts an Image version (Major.Minor) to a string
// major : Major Image version number
// minor : Minor Image version number
// Returns : const char* string representing the Image version flag
const char* imageVersionToString(IN WORD major, IN WORD minor);
#define MAX_STR_LEN_IMAGE_VERSION 20

// Converts a Subsystem version (Major.Minor) to a string
// major : Major Subsystem version
// minor : Minor Subsystem version
// Returns : const char* string representing the Subsystem version flag
const char* subSystemVersionFlagToString(IN WORD major, IN WORD minor);
#define MAX_STR_LEN_SUBSYSTEM_VERSION_FLAG 25

// Converts a Subsystem type to a string
// subsystem : IMAGE_OPTIONAL_HEADER.Subsystem value
// Returns   : const char* string representing the Subsystem type flag
const char* subSystemTypeFlagToString(IN WORD subsystem);
#define MAX_STR_LEN_SUBSYSTEM_TYPE_FLAG 45

// Retrieves a string representation of a PE resource type
// type    : WORD value identifying the resource type (e.g., RT_ICON, RT_VERSION)
// Returns : const char* describing the resource type (e.g., "ICON", "VERSION")
const char* getResourceTypeName(IN WORD type);

// Retrieves a human-readable name for a resource language ID
// langId  : Language identifier (e.g., 0x409 for English - US)
// Returns : const char* describing the language name
const char* getResourceLangName(IN WORD langId);

// Converts a relocation type to a string
// type    : WORD relocation type (IMAGE_REL_BASED_* constants)
// Returns : const char* with relocation type name
const char* getRelocTypeName(IN WORD type);

// Converts a debug directory type to a string
// type    : DWORD debug type (IMAGE_DEBUG_TYPE_* constants)
// Returns : const char* with debug type name
const char* getDebugTypeName(IN DWORD type);

// Converts a COFF symbol type into a descriptive string (base + derived)
// type    : Symbol type value (combination of base/derived types)
// Returns : const char* describing both base and derived type (e.g., "INT, POINTER")
const char* getSymbolType(IN DWORD type);

// Converts a COFF symbol class constant into a readable description
// symClass : Symbol class (IMAGE_SYM_CLASS_* constants)
// Returns  : const char* descriptive string
const char* getSymbolClassName(IN DWORD symClass);

// Converts a weak external’s characteristics flag into a descriptive name
// characteristics : DWORD flag (low 2 bits define the kind)
// Returns         : const char* flag description
const char* getWeakExternCharFlag(IN DWORD characteristics);

// Converts a COMDAT selection type into a descriptive string
// Number : COMDAT selection type (IMAGE_COMDAT_SELECT_* constants)
// Returns: const char* with selection description
const char* getComdatSelectName(IN WORD Number);

// Determines the exception directory entry type based on the machine architecture
// machine : IMAGE_FILE_HEADER.Machine value
// Returns : const char* with exception entry type description
const char* getExceptionEntryType(IN WORD machine);

// Converts an ARM64 unwind flag to a descriptive string
// flag    : ARM64 unwind flag value
// Returns : const char* with flag description
const char* getArm64FlagToString(IN DWORD flag);

// Converts an ARM64 control record (CR) type to a descriptive string
// cr      : ARM64 control record type
// Returns : const char* describing the control record
const char* getArm64CrToString(IN DWORD cr);

// Converts a certificate revision constant to a string
// revision : WIN_CERT_REVISION_* constant
// Returns  : const char* with revision description
const char* getCertRevisionFlag(IN WORD revision);

// Converts a certificate type constant to a string
// type    : WIN_CERT_TYPE_* constant
// Returns : const char* describing the certificate type
const char* getCertTypeFlag(IN WORD type);

// Determines hash algorithm type based on digest size
// size    : Hash digest size in bytes (e.g., 16, 20, 32)
// Returns : const char* with hash algorithm name
const char* GetHashType(IN WORD size);

// Converts a FileOS flag from VS_FIXEDFILEINFO to string form
// dwFileOS : File OS flag (VOS_* constants)
// Returns  : const char* describing the OS environment
const char* GetFileOSString(IN DWORD dwFileOS);

// Converts a FileType flag from VS_FIXEDFILEINFO to string form
// dwFileType : File type (VFT_* constants)
// Returns    : const char* describing the file type (e.g., "VFT_APP")
const char* GetFileTypeString(IN DWORD dwFileType);

// Converts a driver file subtype flag into a readable name
// dwFileSubtype : Driver subtype (VFT2_DRV_* constants)
// Returns       : const char* describing the driver type
const char* GetDriverSubtypeString(IN DWORD dwFileSubtype);

// Converts a font file subtype flag into a descriptive name
// dwFileSubtype : Font subtype (VFT2_FONT_* constants)
// Returns       : const char* describing the font type
const char* GetFontSubtypeString(IN DWORD dwFileSubtype);

// Converts a version info language ID to a readable language name
// langID : Language ID from VERSIONINFO resource
// Returns: const char* describing the language
const char* getViLangName(IN WORD langID);

// Converts a charset ID from VERSIONINFO to readable charset name
// charsetID : Character set identifier (e.g., 1252, 932)
// Returns   : const char* describing the charset
const char* getViCharsetName(IN WORD charsetID);

// -----------------------------
//  Object Type Legend
// -----------------------------
// [ C ]   - obj file produced by C compiler
// [C++]   - obj file produced by C++ compiler
// [RES]   - obj file produced by CVTRES converter
// [C S]   - obj file produced by C "Std" compiler
// [C+S]   - obj file produced by C++ "Std" compiler
// [C B]   - obj file produced by C "Book" compiler
// [C+B]   - obj file produced by C++ "Book" compiler
// [BSC]   - obj file produced by Basic compiler
// [OMF]   - obj file produced by CVTOMF converter
// [PGD]   - obj file produced by CVTPGD converter
// [IMP]   - DLL import record in library file
// [EXP]   - DLL export record in library file
// [ASM]   - obj file produced by assembler
// [ILA]   - obj file produced by ILAssembler
// [AOb]   - AliasObj
// [CIL]   - CVTCIL C
// [CI+]   - CVTCIL C++
// [LTC]   - LTCG C (link-time code generation)
// [LT+]   - LTCG C++ (link-time code generation)
// [LTM]   - LTCG MSIL
// [PGO]   - POGO I profiling, C
// [PG+]   - POGO I profiling, C++
// [POC]   - POGO O, C
// [PO+]   - POGO O, C++
// (*)    - marks entries that are interpolated/calculated

// -----------------------------
//  Unmarked / Special Objects
// -----------------------------
// 00010000  [---] Unmarked objects
// 00000000  [---] Unmarked objects (old)
// 00970000  [---] Resource
// 00FE0000  [---] CVTPGD
// 00FE0001  [---] CVTPGD

// Data used from RichPrint by dishather (https://github.com/dishather)
// Copyright (c) 2015-2024 dishather
// Redistribution and use of this data permitted under the BSD-style license
const char* getRichProductIdName(IN WORD prodid);

// Data used from RichPrint by dishather (https://github.com/dishather)
// Copyright (c) 2015-2024 dishather
// Redistribution and use of this data permitted under the BSD-style license
const char* GetRichCompIdString(IN DWORD comp_id);

#endif