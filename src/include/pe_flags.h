#ifndef PE_FLAGS_H
#define PE_FLAGS_H

#include "libs.h"

// ---------------------------------------------------------------------
// IMAGE_FILE_HEADER Machine types
// ---------------------------------------------------------------------
#ifndef IMAGE_FILE_MACHINE_UNKNOWN
typedef enum _MACHINE_TYPE {
    IMAGE_FILE_MACHINE_UNKNOWN       = 0x0,
    IMAGE_FILE_MACHINE_ALPHA         = 0x0184,
    IMAGE_FILE_MACHINE_ALPHA64       = 0x0284, // same as AXP64
    IMAGE_FILE_MACHINE_AM33          = 0x01d3,
    IMAGE_FILE_MACHINE_AMD64         = 0x8664,
    IMAGE_FILE_MACHINE_ARM           = 0x01c0,
    IMAGE_FILE_MACHINE_ARM64         = 0xAA64,
    IMAGE_FILE_MACHINE_ARM64EC       = 0xA641,
    IMAGE_FILE_MACHINE_ARM64X        = 0xA64E,
    IMAGE_FILE_MACHINE_ARMNT         = 0x01c4,
    IMAGE_FILE_MACHINE_AXP64         = 0x0284, // duplicate of Alpha64
    IMAGE_FILE_MACHINE_EBC           = 0x0EBC,
    IMAGE_FILE_MACHINE_I386          = 0x014c,
    IMAGE_FILE_MACHINE_IA64          = 0x0200,
    IMAGE_FILE_MACHINE_LOONGARCH32   = 0x6232,
    IMAGE_FILE_MACHINE_LOONGARCH64   = 0x6264,
    IMAGE_FILE_MACHINE_M32R          = 0x9041,
    IMAGE_FILE_MACHINE_MIPS16        = 0x0266,
    IMAGE_FILE_MACHINE_MIPSFPU       = 0x0366,
    IMAGE_FILE_MACHINE_MIPSFPU16     = 0x0466,
    IMAGE_FILE_MACHINE_POWERPC       = 0x01f0,
    IMAGE_FILE_MACHINE_POWERPCFP     = 0x01f1,
    IMAGE_FILE_MACHINE_R3000         = 0x0162,
    IMAGE_FILE_MACHINE_R3000BE       = 0x0160,
    IMAGE_FILE_MACHINE_R4000         = 0x0166,
    IMAGE_FILE_MACHINE_R10000        = 0x0168,
    IMAGE_FILE_MACHINE_RISCV32       = 0x5032,
    IMAGE_FILE_MACHINE_RISCV64       = 0x5064,
    IMAGE_FILE_MACHINE_RISCV128      = 0x5128,
    IMAGE_FILE_MACHINE_SH3           = 0x01a2,
    IMAGE_FILE_MACHINE_SH3DSP        = 0x01a3,
    IMAGE_FILE_MACHINE_SH4           = 0x01a6,
    IMAGE_FILE_MACHINE_SH5           = 0x01a8,
    IMAGE_FILE_MACHINE_THUMB         = 0x01c2,
    IMAGE_FILE_MACHINE_WCEMIPSV2     = 0x0169
} MACHINE_TYPE;
#else
typedef enum _MACHINE_TYPE {
    IMAGE_FILE_MACHINE_ARM64EC       = 0xA641,
    IMAGE_FILE_MACHINE_ARM64X        = 0xA64E,
    IMAGE_FILE_MACHINE_LOONGARCH32   = 0x6232,
    IMAGE_FILE_MACHINE_LOONGARCH64   = 0x6264,
    IMAGE_FILE_MACHINE_R3000BE       = 0x0160,
    IMAGE_FILE_MACHINE_RISCV32       = 0x5032,
    IMAGE_FILE_MACHINE_RISCV64       = 0x5064,
    IMAGE_FILE_MACHINE_RISCV128      = 0x5128
} MACHINE_TYPE;
#endif

// ---------------------------------------------------------------------
// IMAGE_FILE_HEADER Characteristics
// ---------------------------------------------------------------------
#ifndef IMAGE_FILE_RELOCS_STRIPPED
typedef enum _IMAGE_FILE_CHARACTERISTICS {
    IMAGE_FILE_RELOCS_STRIPPED            = 0x0001,
    IMAGE_FILE_EXECUTABLE_IMAGE           = 0x0002,
    IMAGE_FILE_LINE_NUMS_STRIPPED         = 0x0004,
    IMAGE_FILE_LOCAL_SYMS_STRIPPED        = 0x0008,
    IMAGE_FILE_AGGRESIVE_WS_TRIM          = 0x0010,
    IMAGE_FILE_LARGE_ADDRESS_AWARE        = 0x0020,
    IMAGE_FILE_BYTES_REVERSED_LO          = 0x0040,
    IMAGE_FILE_32BIT_MACHINE              = 0x0080,
    IMAGE_FILE_DEBUG_STRIPPED             = 0x0100,
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP    = 0x0200,
    IMAGE_FILE_NET_RUN_FROM_SWAP          = 0x0400,
    IMAGE_FILE_SYSTEM                     = 0x0800,
    IMAGE_FILE_DLL                        = 0x1000,
    IMAGE_FILE_UP_SYSTEM_ONLY             = 0x2000,
    IMAGE_FILE_BYTES_REVERSED_HI          = 0x4000
} IMAGE_FILE_CHARACTERISTICS;
#endif

// ---------------------------------------------------------------------
// IMAGE_NT_HEADER Subsystem Types
// ---------------------------------------------------------------------
#ifndef IMAGE_SUBSYSTEM_UNKNOWN
typedef enum _IMAGE_SUBSYSTEMS {
    IMAGE_SUBSYSTEM_UNKNOWN                  = 0,
    IMAGE_SUBSYSTEM_NATIVE                   = 1,
    IMAGE_SUBSYSTEM_WINDOWS_GUI              = 2,
    IMAGE_SUBSYSTEM_WINDOWS_CUI              = 3,
    IMAGE_SUBSYSTEM_OS2_CUI                  = 5,
    IMAGE_SUBSYSTEM_POSIX_CUI                = 7,
    IMAGE_SUBSYSTEM_NATIVE_WINDOWS           = 8,
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           = 9,
    IMAGE_SUBSYSTEM_EFI_APPLICATION          = 10,
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = 11,
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       = 12,
    IMAGE_SUBSYSTEM_EFI_ROM                  = 13,
    IMAGE_SUBSYSTEM_XBOX                     = 14,
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
} IMAGE_SUBSYSTEMS;
#endif

// ---------------------------------------------------------------------
// IMAGE_SYMBOL_SECTION
// ---------------------------------------------------------------------
#ifndef MAXLONG
    #define MAXLONG 0x7fffffff
#endif

#ifndef IMAGE_SYM_UNDEFINED
typedef enum _IMAGE_SYMBOL_SECTION {
    IMAGE_SYM_UNDEFINED       = 0,        // Symbol is undefined or common
    IMAGE_SYM_ABSOLUTE        = -1,       // Symbol is an absolute value
    IMAGE_SYM_DEBUG           = -2,       // Symbol is a special debug item
    IMAGE_SYM_SECTION_MAX     = 0xFEFF,   // Values 0xFF00-0xFFFF are special
    IMAGE_SYM_SECTION_MAX_EX  = MAXLONG
} IMAGE_SYMBOL_SECTION;
#endif

// ---------------------------------------------------------------------
// IMAGE_SYMBOL_TYPE (fundamental/base types)
// ---------------------------------------------------------------------
#ifndef IMAGE_SYM_TYPE_NULL
typedef enum _IMAGE_SYMBOL_TYPE {
    IMAGE_SYM_TYPE_NULL       = 0x0000, // no type
    IMAGE_SYM_TYPE_VOID       = 0x0001,
    IMAGE_SYM_TYPE_CHAR       = 0x0002,
    IMAGE_SYM_TYPE_SHORT      = 0x0003,
    IMAGE_SYM_TYPE_INT        = 0x0004,
    IMAGE_SYM_TYPE_LONG       = 0x0005,
    IMAGE_SYM_TYPE_FLOAT      = 0x0006,
    IMAGE_SYM_TYPE_DOUBLE     = 0x0007,
    IMAGE_SYM_TYPE_STRUCT     = 0x0008,
    IMAGE_SYM_TYPE_UNION      = 0x0009,
    IMAGE_SYM_TYPE_ENUM       = 0x000A,
    IMAGE_SYM_TYPE_MOE        = 0x000B, // member of enumeration
    IMAGE_SYM_TYPE_BYTE       = 0x000C,
    IMAGE_SYM_TYPE_WORD       = 0x000D,
    IMAGE_SYM_TYPE_UINT       = 0x000E,
    IMAGE_SYM_TYPE_DWORD      = 0x000F,
    IMAGE_SYM_TYPE_PCODE      = 0x8000  // special
} IMAGE_SYMBOL_TYPE;
#endif

// ---------------------------------------------------------------------
// IMAGE_SYMBOL_DERIVED_TYPE
// ---------------------------------------------------------------------
#ifndef IMAGE_SYM_DTYPE_NULL
typedef enum _IMAGE_SYMBOL_DERIVED_TYPE {
    IMAGE_SYM_DTYPE_NULL      = 0, // no derived type
    IMAGE_SYM_DTYPE_POINTER   = 1, // pointer
    IMAGE_SYM_DTYPE_FUNCTION  = 2, // function
    IMAGE_SYM_DTYPE_ARRAY     = 3  // array
} IMAGE_SYMBOL_DERIVED_TYPE;
#endif

// ---------------------------------------------------------------------
// IMAGE_SYMBOL_STORAGE_CLASS
// ---------------------------------------------------------------------
#ifndef IMAGE_SYM_CLASS_END_OF_FUNCTION
    typedef enum _IMAGE_SYMBOL_STORAGE_CLASS {
        IMAGE_SYM_CLASS_END_OF_FUNCTION      = (BYTE)-1,
        IMAGE_SYM_CLASS_NULL                 = 0x00,
        IMAGE_SYM_CLASS_AUTOMATIC            = 0x01,
        IMAGE_SYM_CLASS_EXTERNAL             = 0x02,
        IMAGE_SYM_CLASS_STATIC               = 0x03,
        IMAGE_SYM_CLASS_REGISTER             = 0x04,
        IMAGE_SYM_CLASS_EXTERNAL_DEF         = 0x05,
        IMAGE_SYM_CLASS_LABEL                = 0x06,
        IMAGE_SYM_CLASS_UNDEFINED_LABEL      = 0x07,
        IMAGE_SYM_CLASS_MEMBER_OF_STRUCT     = 0x08,
        IMAGE_SYM_CLASS_ARGUMENT             = 0x09,
        IMAGE_SYM_CLASS_STRUCT_TAG           = 0x0A,
        IMAGE_SYM_CLASS_MEMBER_OF_UNION      = 0x0B,
        IMAGE_SYM_CLASS_UNION_TAG            = 0x0C,
        IMAGE_SYM_CLASS_TYPE_DEFINITION      = 0x0D,
        IMAGE_SYM_CLASS_UNDEFINED_STATIC     = 0x0E,
        IMAGE_SYM_CLASS_ENUM_TAG             = 0x0F,
        IMAGE_SYM_CLASS_MEMBER_OF_ENUM       = 0x10,
        IMAGE_SYM_CLASS_REGISTER_PARAM       = 0x11,
        IMAGE_SYM_CLASS_BIT_FIELD            = 0x12,
        IMAGE_SYM_CLASS_FAR_EXTERNAL         = 0x44,
        IMAGE_SYM_CLASS_BLOCK                = 0x64,
        IMAGE_SYM_CLASS_FUNCTION             = 0x65,
        IMAGE_SYM_CLASS_END_OF_STRUCT        = 0x66,
        IMAGE_SYM_CLASS_FILE                 = 0x67,
        IMAGE_SYM_CLASS_SECTION              = 0x68,
        IMAGE_SYM_CLASS_WEAK_EXTERNAL        = 0x69,
        IMAGE_SYM_CLASS_CLR_TOKEN            = 0x6B
    } IMAGE_SYMBOL_STORAGE_CLASS;
#endif

// ---------------------------------------------------------------------
// Type Packing Constants
// ---------------------------------------------------------------------
#ifndef N_BTMASK
    typedef enum _IMAGE_SYMBOL_TYPE_PACKING {
        N_BTMASK  = 0x0F,  // Base type mask
        N_TMASK   = 0x30,  // Type mask
        N_TMASK1  = 0xC0,  // Extended type mask 1
        N_TMASK2  = 0xF0,  // Extended type mask 2
        N_BTSHFT  = 4,     // Shift for base type
        N_TSHIFT  = 2      // Shift for type
    } IMAGE_SYMBOL_TYPE_PACKING;
#endif

// ---------------------------------------------------------------------
// Type Packing Constants
// ---------------------------------------------------------------------
typedef enum _WEAK_EXTERN_CHARACTERISTICS {
    WEAK_EXTERN_NOLIBRARY       = 1,  // IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY
    WEAK_EXTERN_LIBRARY         = 2,  // IMAGE_WEAK_EXTERN_SEARCH_LIBRARY
    WEAK_EXTERN_ALIAS           = 3,  // IMAGE_WEAK_EXTERN_SEARCH_ALIAS
    WEAK_EXTERN_ANTI_DEPENDENCY = 4   // IMAGE_WEAK_EXTERN_ANTI_DEPENDENCY
} WEAK_EXTERN_CHARACTERISTICS;

// ---------------------------------------------------------------------
// Type Of Comdat
// ---------------------------------------------------------------------
#ifndef IMAGE_COMDAT_SELECT_NODUPLICATES
typedef enum _IMAGE_COMDAT_SELECT_TYPE {
    IMAGE_COMDAT_SELECT_NODUPLICATES = 1,   // Multiply defined symbol error if already defined
    IMAGE_COMDAT_SELECT_ANY          = 2,   // Any section can be linked; rest removed
    IMAGE_COMDAT_SELECT_SAME_SIZE    = 3,   // Arbitrary section chosen; error if sizes differ
    IMAGE_COMDAT_SELECT_EXACT_MATCH  = 4,   // Arbitrary section chosen; error if contents differ
    IMAGE_COMDAT_SELECT_ASSOCIATIVE  = 5,   // Linked if associated section is linked
    IMAGE_COMDAT_SELECT_LARGEST      = 6    // Linker chooses largest definition
} IMAGE_COMDAT_SELECT_TYPE;
#endif

#ifndef _IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF
typedef enum __IMAGE_AUX_SYMBOL_TYPE {
    _IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF = 1,
} _IMAGE_AUX_SYMBOL_TYPE;
#endif

// ---------------------------------------------------------------------
// Relocation types for IMAGE_BASE_RELOCATION
// ---------------------------------------------------------------------
#ifndef IMAGE_REL_BASED_ABSOLUTE
typedef enum _IMAGE_RELOC_TYPE {
    IMAGE_REL_BASED_ABSOLUTE           = 0,   // No relocation required
    IMAGE_REL_BASED_HIGH               = 1,   // High 16-bit
    IMAGE_REL_BASED_LOW                = 2,   // Low 16-bit
    IMAGE_REL_BASED_HIGHLOW            = 3,   // High + Low 32-bit
    IMAGE_REL_BASED_HIGHADJ            = 4,   // High adjusted
    IMAGE_REL_BASED_MIPS_JMPADDR       = 5,   // MIPS jump address
    IMAGE_REL_BASED_SECTION            = 6,   // Section relative
    IMAGE_REL_BASED_REL32              = 7,   // 32-bit relative
    IMAGE_REL_BASED_RISCV_HIGH20       = 9,   // RISC-V high20
    IMAGE_REL_BASED_RISCV_LOW12I       = 10,  // RISC-V low12i
    IMAGE_REL_BASED_RISCV_LOW12S       = 11,  // RISC-V low12s
    IMAGE_REL_BASED_RISCV_JAL          = 12,  // RISC-V jal
    IMAGE_REL_BASED_RISCV_BRANCH       = 13,  // RISC-V branch
    IMAGE_REL_BASED_RISCV_GOT_HI20     = 14,  // RISC-V GOT hi20
    IMAGE_REL_BASED_RISCV_TLS_GD_HI20  = 15,  // RISC-V TLS GD hi20
    IMAGE_REL_BASED_RISCV_TLS_GD_LOW12 = 16,  // RISC-V TLS GD low12
    IMAGE_REL_BASED_RISCV_TLS_GD_ADD   = 17,  // RISC-V TLS GD add
    IMAGE_REL_BASED_RISCV_TLS_GD_CALL  = 18   // RISC-V TLS GD call
} IMAGE_RELOC_TYPE;
#else
typedef enum _IMAGE_RELOC_TYPE {
    IMAGE_REL_BASED_SECTION            = 6,   // Section relative
    IMAGE_REL_BASED_REL32              = 7,   // 32-bit relative
    IMAGE_REL_BASED_RISCV_HIGH20       = 9,   // RISC-V high20
    IMAGE_REL_BASED_RISCV_LOW12I       = 10,  // RISC-V low12i
    IMAGE_REL_BASED_RISCV_LOW12S       = 11,  // RISC-V low12s
    IMAGE_REL_BASED_RISCV_JAL          = 12,  // RISC-V jal
    IMAGE_REL_BASED_RISCV_BRANCH       = 13,  // RISC-V branch
    IMAGE_REL_BASED_RISCV_GOT_HI20     = 14,  // RISC-V GOT hi20
    IMAGE_REL_BASED_RISCV_TLS_GD_HI20  = 15,  // RISC-V TLS GD hi20
    IMAGE_REL_BASED_RISCV_TLS_GD_LOW12 = 16,  // RISC-V TLS GD low12
    IMAGE_REL_BASED_RISCV_TLS_GD_ADD   = 17,  // RISC-V TLS GD add
    IMAGE_REL_BASED_RISCV_TLS_GD_CALL  = 18   // RISC-V TLS GD call
} IMAGE_RELOC_TYPE;
#endif


// ---------------------------------------------------------------------
// OS version for IMAGE_OPTIONAL_HEADER
// ---------------------------------------------------------------------
#ifndef IMAGE_OS_UNKNOWN
typedef enum _IMAGE_OS_VERSION {
    IMAGE_OS_UNKNOWN  = 0x00030001,
    IMAGE_OS_WIN31    = 0x00030001,
    IMAGE_OS_WIN35    = 0x00030005,
    IMAGE_OS_WIN351   = 0x00030033,
    IMAGE_OS_WIN40    = 0x00040000,
    IMAGE_OS_WIN2000  = 0x00050000,
    IMAGE_OS_WINXP    = 0x00050001,
    IMAGE_OS_WINXP64  = 0x00050002,
    IMAGE_OS_VISTA    = 0x00060000,
    IMAGE_OS_WIN7     = 0x00060001,
    IMAGE_OS_WIN8     = 0x00060002,
    IMAGE_OS_WIN81    = 0x00060003,
    IMAGE_OS_WIN10    = 0x000A0000
} IMAGE_OS_VERSION;
#endif

// ---------------------------------------------------------------------
// Image version for IMAGE_OPTIONAL_HEADER
// ---------------------------------------------------------------------
#ifndef IMAGE_VER_UNKNOWN
typedef enum _IMAGE_FILE_VERSION {
    IMAGE_VER_UNKNOWN  = 0x00000000,
    IMAGE_VER_DEFAULT  = 0x00000000,
    IMAGE_VER_1_0      = 0x00010000,
    IMAGE_VER_1_1      = 0x00010001,
    IMAGE_VER_2_0      = 0x00020000,
    IMAGE_VER_2_1      = 0x00020001,
    IMAGE_VER_3_0      = 0x00030000,
    IMAGE_VER_3_1      = 0x00030001,
    IMAGE_VER_4_0      = 0x00040000,
    IMAGE_VER_4_1      = 0x00040001,
    IMAGE_VER_5_0      = 0x00050000,
    IMAGE_VER_5_1      = 0x00050001
} IMAGE_FILE_VERSION;
#endif

// ---------------------------------------------------------------------
// Subsystem version for IMAGE_OPTIONAL_HEADER
// ---------------------------------------------------------------------
#ifndef IMAGE_SUBSYS_UNKNOWN
typedef enum _IMAGE_SUBSYSTEM_VERSION {
    IMAGE_SUBSYS_UNKNOWN    = 0x00000000,
    IMAGE_SUBSYS_DEFAULT    = 0x00000000,
    IMAGE_SUBSYS_NT3_0      = 0x00030000,
    IMAGE_SUBSYS_NT3_1      = 0x00030001,
    IMAGE_SUBSYS_NT4_0      = 0x00040000,
    IMAGE_SUBSYS_WIN2000    = 0x00050000,
    IMAGE_SUBSYS_WINXP      = 0x00050001,
    IMAGE_SUBSYS_WINXP64    = 0x00050002,
    IMAGE_SUBSYS_VISTA      = 0x00060000,
    IMAGE_SUBSYS_WIN7       = 0x00060001,
    IMAGE_SUBSYS_WIN8       = 0x00060002,
    IMAGE_SUBSYS_WIN81      = 0x00060003,
    IMAGE_SUBSYS_WIN10      = 0x000A0000
} IMAGE_SUBSYSTEM_VERSION;
#endif

// ---------------------------------------------------------------------
// OptionalHeader DLL Characteristics
// ---------------------------------------------------------------------
#ifndef IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
typedef enum _IMAGE_DLL_CHARACTERISTICS_FLAGS {
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA             = 0x0020,
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE                = 0x0040,
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY             = 0x0080,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT                   = 0x0100,
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION                = 0x0200,
    IMAGE_DLLCHARACTERISTICS_NO_SEH                      = 0x0400,
    IMAGE_DLLCHARACTERISTICS_NO_BIND                     = 0x0800,
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER                = 0x1000,
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER                  = 0x2000,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF                    = 0x4000,
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE       = 0x8000,
    IMAGE_DLLCHARACTERISTICS_APPEXECCONTAINER            = 0x00010000,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF_EXPORT_SUPPRESSION = 0x00020000
} IMAGE_DLL_CHARACTERISTICS_FLAGS;
#else 
typedef enum _IMAGE_DLL_CHARACTERISTICS_FLAGS {
    IMAGE_DLLCHARACTERISTICS_APPEXECCONTAINER            = 0x00010000,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF_EXPORT_SUPPRESSION = 0x00020000
} IMAGE_DLL_CHARACTERISTICS_FLAGS;
#endif

// ---------------------------------------------------------------------
// SectionHeader characteristics
// ---------------------------------------------------------------------
#ifndef IMAGE_SCN_TYPE_NO_PAD
typedef enum _IMAGE_SECTION_FLAGS {
    IMAGE_SCN_TYPE_NO_PAD             = 0x00000008,
    IMAGE_SCN_CNT_CODE                = 0x00000020,
    IMAGE_SCN_CNT_INITIALIZED_DATA    = 0x00000040,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA  = 0x00000080,
    IMAGE_SCN_LNK_INFO                = 0x00000200,
    IMAGE_SCN_LNK_REMOVE              = 0x00000800,
    IMAGE_SCN_LNK_COMDAT              = 0x00001000,
    IMAGE_SCN_GPREL                   = 0x00008000,
    IMAGE_SCN_MEM_PURGEABLE           = 0x00020000,
    IMAGE_SCN_MEM_16BIT               = 0x00020000,  // intentional duplicate in legacy
    IMAGE_SCN_MEM_LOCKED              = 0x00040000,
    IMAGE_SCN_MEM_PRELOAD             = 0x00080000,
    IMAGE_SCN_ALIGN_1BYTES            = 0x00100000,
    IMAGE_SCN_ALIGN_2BYTES            = 0x00200000,
    IMAGE_SCN_ALIGN_4BYTES            = 0x00300000,
    IMAGE_SCN_ALIGN_8BYTES            = 0x00400000,
    IMAGE_SCN_ALIGN_16BYTES           = 0x00500000,
    IMAGE_SCN_ALIGN_32BYTES           = 0x00600000,
    IMAGE_SCN_ALIGN_64BYTES           = 0x00700000,
    IMAGE_SCN_ALIGN_128BYTES          = 0x00800000,
    IMAGE_SCN_ALIGN_256BYTES          = 0x00900000,
    IMAGE_SCN_ALIGN_512BYTES          = 0x00A00000,
    IMAGE_SCN_ALIGN_1024BYTES         = 0x00B00000,
    IMAGE_SCN_ALIGN_2048BYTES         = 0x00C00000,
    IMAGE_SCN_ALIGN_4096BYTES         = 0x00D00000,
    IMAGE_SCN_ALIGN_8192BYTES         = 0x00E00000,
    IMAGE_SCN_LNK_NRELOC_OVFL         = 0x01000000,
    IMAGE_SCN_MEM_DISCARDABLE         = 0x02000000,
    IMAGE_SCN_MEM_NOT_CACHED          = 0x04000000,
    IMAGE_SCN_MEM_WRITE               = 0x08000000,
    IMAGE_SCN_MEM_NOT_PAGED           = 0x10000000,
    IMAGE_SCN_MEM_SHARED              = 0x20000000,
    IMAGE_SCN_MEM_EXECUTE             = 0x40000000,
    IMAGE_SCN_MEM_READ                = 0x80000000
} IMAGE_SECTION_FLAGS;
#endif

// ---------------------------------------------------------------------
// Type bitmask for IMAGE_DEBUG_DIRECTORY
// ---------------------------------------------------------------------
#ifndef IMAGE_DEBUG_TYPE_UNKNOWN
typedef enum _IMAGE_DEBUG_TYPE {
    IMAGE_DEBUG_TYPE_UNKNOWN                = 0,   // Unknown, ignored by tools
    IMAGE_DEBUG_TYPE_COFF                   = 1,   // COFF debug info (line numbers, symbols, string table)
    IMAGE_DEBUG_TYPE_CODEVIEW               = 2,   // Visual C++ debug info (PDB)
    IMAGE_DEBUG_TYPE_FPO                    = 3,   // Frame Pointer Omission info
    IMAGE_DEBUG_TYPE_MISC                   = 4,   // DBG file location
    IMAGE_DEBUG_TYPE_EXCEPTION              = 5,   // Copy of .pdata section
    IMAGE_DEBUG_TYPE_FIXUP                  = 6,   // Reserved
    IMAGE_DEBUG_TYPE_OMAP_TO_SRC            = 7,   // RVA in image → RVA in source image
    IMAGE_DEBUG_TYPE_OMAP_FROM_SRC          = 8,   // RVA in source image → RVA in image
    IMAGE_DEBUG_TYPE_BORLAND                = 9,   // Reserved for Borland
    IMAGE_DEBUG_TYPE_RESERVED10             = 10,  // Reserved
    IMAGE_DEBUG_TYPE_BBT                    = IMAGE_DEBUG_TYPE_RESERVED10, // Alias
    IMAGE_DEBUG_TYPE_CLSID                  = 11,  // Reserved
    IMAGE_DEBUG_TYPE_VC_FEATURE             = 12,  // Visual C++ feature info
    IMAGE_DEBUG_TYPE_POGO                   = 13,  // Profile-guided optimization
    IMAGE_DEBUG_TYPE_ILTCG                  = 14,  // Inter-module LTO / cross-module optimization
    IMAGE_DEBUG_TYPE_MPX                    = 15,  // Intel MPX info
    IMAGE_DEBUG_TYPE_REPRO                  = 16,  // Deterministic/reproducible PE
    IMAGE_DEBUG_TYPE_SPGO                   = 18,  // Sample PGO info
    IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS  = 20   // Extended DLL characteristics bits
} IMAGE_DEBUG_TYPE;
#else
    #ifndef IMAGE_DEBUG_TYPE_BBT
        #define IMAGE_DEBUG_TYPE_BBT 10 // Reserved
    #endif

    #ifndef IMAGE_DEBUG_TYPE_VC_FEATURE
        #define IMAGE_DEBUG_TYPE_VC_FEATURE 12 // Visual C++ feature info
    #endif

    #ifndef IMAGE_DEBUG_TYPE_POGO
        #define IMAGE_DEBUG_TYPE_POGO  13 // Profile-guided optimization
    #endif

    #ifndef IMAGE_DEBUG_TYPE_ILTCG
        #define IMAGE_DEBUG_TYPE_ILTCG 14 // Inter-module LTO / cross-module optimization
    #endif

    #ifndef IMAGE_DEBUG_TYPE_MPX
        #define IMAGE_DEBUG_TYPE_MPX 15  // Intel MPX info
    #endif

    #ifndef IMAGE_DEBUG_TYPE_REPRO
        #define IMAGE_DEBUG_TYPE_REPRO 16  // Deterministic/reproducible PE
    #endif

    #ifndef IMAGE_DEBUG_TYPE_SPGO
        #define IMAGE_DEBUG_TYPE_SPGO 18  // Sample PGO info
    #endif

    #ifndef IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
        #define IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS 20   // Extended DLL characteristics bits
    #endif

#endif

#ifndef VC_FEATURE_FLAGS_H
#define VC_FEATURE_FLAGS_H
typedef enum _VC_FEATURE_FLAG {
    VC_FEATURE_FLAG_NONE       = 0x00000000, // No features
    VC_FEATURE_FLAG_EH         = 0x00000001, // C++ Exception Handling
    VC_FEATURE_FLAG_RTTI       = 0x00000002, // Run-Time Type Information
    VC_FEATURE_FLAG_COPY_CTOR  = 0x00000004, // Copy constructors
    VC_FEATURE_FLAG_OPENMP     = 0x00000008, // OpenMP
    VC_FEATURE_FLAG_CRT        = 0x00000010  // Uses CRT
} VC_FEATURE_FLAG;
#endif // VC_FEATURE_FLAGS_H


// ---------------------------------------------------------------------
// GlobalFlags bitmask for IMAGE_LOAD_CONFIG_DIRECTORY
// ---------------------------------------------------------------------
#ifndef FLG_STOP_ON_EXCEPTION
typedef enum _LOAD_CONFIG_GLOBAL_FLAG {
    FLG_STOP_ON_EXCEPTION            = 0x00000002,
    FLG_SHOW_LDR_SNAPS               = 0x00000004,
    FLG_DEBUG_INITIAL_COMMAND        = 0x00000008,
    FLG_STOP_ON_HUNG_GUI             = 0x00000010,
    FLG_HEAP_ENABLE_TAIL_CHECK       = 0x00000020,
    FLG_HEAP_ENABLE_FREE_CHECK       = 0x00000040,
    FLG_HEAP_VALIDATE_PARAMETERS     = 0x00000080,
    FLG_HEAP_VALIDATE_ALL            = 0x00000100,
    FLG_POOL_ENABLE_TAIL_CHECK       = 0x00000200,
    FLG_POOL_ENABLE_FREE_CHECK       = 0x00000400,
    FLG_POOL_ENABLE_TAGGING          = 0x00000800,
    FLG_HEAP_ENABLE_TAGGING          = 0x00001000,
    FLG_USER_STACK_TRACE_DB          = 0x00002000,
    FLG_KERNEL_STACK_TRACE_DB        = 0x00004000,
    FLG_MAINTAIN_OBJECT_TYPELIST     = 0x00008000,
    FLG_HEAP_ENABLE_TAG_BY_DLL       = 0x00010000,
    FLG_DISABLE_STACK_EXTENSION      = 0x00020000,
    FLG_ENABLE_CSRDEBUG              = 0x00040000,
    FLG_ENABLE_KDEBUG_SYMBOL_LOAD    = 0x00080000,
    FLG_DISABLE_PAGE_KERNEL_STACKS   = 0x00100000,
    FLG_ENABLE_SYSTEM_CRIT_BREAKS    = 0x00200000,
    FLG_HEAP_DISABLE_COALESCING      = 0x00400000,
    FLG_ENABLE_CLOSE_EXCEPTIONS      = 0x00800000,
    FLG_ENABLE_EXCEPTION_LOGGING     = 0x01000000,
    FLG_ENABLE_HANDLE_TYPE_TAGGING   = 0x02000000,
    FLG_HEAP_PAGE_ALLOCS             = 0x08000000,
    FLG_DEBUG_INITIAL_COMMAND_EX     = 0x10000000,
    FLG_DISABLE_DBGPRINT             = 0x20000000,
    FLG_CRITSEC_EVENT_CREATION       = 0x40000000,
    FLG_LDR_TOP_DOWN                 = 0x80000000
} LOAD_CONFIG_GLOBAL_FLAG;
#endif

#ifndef WIN_CERT_REVISION_1_0
typedef enum _SECURITY_CERT_REVISION_FLAGS {
    WIN_CERT_REVISION_1_0 = 0x0100,
    WIN_CERT_REVISION_2_0 = 0x0200,
} SECURITY_CERT_REVISION_FLAGS;
#endif

#ifndef WIN_CERT_TYPE_X509
typedef enum _SECURITY_CERT_TYPE_FLAGS {
    WIN_CERT_TYPE_X509              = 0x0001,  // bCertificate contains an X.509 Certificate
    WIN_CERT_TYPE_PKCS_SIGNED_DATA  = 0x0002,  // bCertificate contains a PKCS SignedData structure
    WIN_CERT_TYPE_RESERVED_1        = 0x0003,  // Reserved
    WIN_CERT_TYPE_TS_STACK_SIGNED   = 0x0004   // Terminal Server Protocol Stack Certificate signing
} SECURITY_CERT_TYPE_FLAGS;
#endif

// ---------------------------------------------------------------------
// HeapFlags bitmask for IMAGE_LOAD_CONFIG_DIRECTORY
// ---------------------------------------------------------------------
#ifndef HEAP_NO_SERIALIZE
typedef enum _HEAP_FLAGS {
    // Classic Heap Creation Flags
    HEAP_NO_SERIALIZE              = 0x00000001, // Do not serialize access to the heap
    HEAP_GROWABLE                  = 0x00000002, // Heap can grow dynamically
    HEAP_GENERATE_EXCEPTIONS       = 0x00000004, // Raise exceptions on allocation failure
    HEAP_ZERO_MEMORY               = 0x00000008, // Initialize allocated memory to zero
    HEAP_REALLOC_IN_PLACE_ONLY     = 0x00000010, // Only allow realloc in-place
    HEAP_TAIL_CHECKING_ENABLED     = 0x00000020, // Enable tail checking
    HEAP_FREE_CHECKING_ENABLED     = 0x00000040, // Enable free checking
    HEAP_DISABLE_COALESCE_ON_FREE  = 0x00000080, // Do not merge adjacent free blocks

    // Segmented / Hardened Heap Flags
    HEAP_CREATE_SEGMENT_HEAP       = 0x00000100, // Use the segment heap
    HEAP_CREATE_ALIGN_16           = 0x00010000, // Force 16-byte alignment
    HEAP_CREATE_ENABLE_TRACING     = 0x00020000, // Enable heap tracing
    HEAP_CREATE_ENABLE_EXECUTE     = 0x00040000, // Memory allocated can be executable
    HEAP_CREATE_HARDENED           = 0x00000200, // Hardened heap for security

    // Heap Tagging / Misc
    HEAP_MAXIMUM_TAG               = 0x0FFF,     // Maximum heap tag value
    HEAP_PSEUDO_TAG_FLAG           = 0x8000,     // Pseudo-tag marker
    HEAP_TAG_SHIFT                 = 18          // Shift for encoding heap tags
} HEAP_FLAGS;
#else
// Some Windows headers may not define HEAP_CREATE_SEGMENT_HEAP and HEAP_CREATE_HARDENED
// depending on _WIN32_WINNT or other SDK macros, or they may undef them later.
// This ensures the constants are always defined.
    #ifndef HEAP_CREATE_SEGMENT_HEAP
        #define HEAP_CREATE_SEGMENT_HEAP        0x00000100
    #endif
    #ifndef HEAP_CREATE_HARDENED      
        #define HEAP_CREATE_HARDENED            0x00000200
    #endif

#endif

// ---------------------------------------------------------------------
// Dependent Load Flags bitmask for IMAGE_LOAD_CONFIG_DIRECTORY
// ---------------------------------------------------------------------
#ifndef LOAD_FLAGS_NO_SEH
    typedef enum _DEPENDENT_LOAD_FLAGS {
        LOAD_FLAGS_NO_SEH                             = 0x00000001, // Disable structured exception handling for dependencies
        LOAD_FLAGS_NO_BIND                            = 0x00000002, // Skip binding imports at load time
        LOAD_FLAGS_NO_DELAYLOAD                       = 0x00000004, // Prevent delay-loaded modules from loading automatically
        LOAD_FLAGS_GUARD_CF                           = 0x00000008, // Enable Control Flow Guard for dependencies
        LOAD_FLAGS_GUARD_CF_EXPORT_SUPPRESSION        = 0x00000010, // Suppress CFG on exports
        LOAD_FLAGS_GUARD_CF_ENABLE_EXPORT_SUPPRESSION = 0x00000020  // CFG protection on exports
    } DEPENDENT_LOAD_FLAGS;
#endif

// ---------------------------------------------------------------------
// Code Integrity / Guard Flags for IMAGE_LOAD_CONFIG_DIRECTORY
// ---------------------------------------------------------------------
#ifndef IMAGE_GUARD_CF_INSTRUMENTED
typedef enum _IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_CF_INSTRUMENTED                     = 0x00000100, // Module performs control flow integrity checks using system support
    IMAGE_GUARD_CFW_INSTRUMENTED                    = 0x00000200, // Module performs control flow + write integrity checks
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT           = 0x00000400, // Module contains valid control flow target metadata
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED              = 0x00000800, // Module does not use /GS security cookie
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT               = 0x00001000, // Read-only delay-load IAT
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION    = 0x00002000, // Delay-load IAT isolated in its own section
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT  = 0x00004000, // Module contains suppressed export info
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION        = 0x00008000, // Enables suppression of exports
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT           = 0x00010000, // Contains longjmp target info
    IMAGE_GUARD_RF_INSTRUMENTED                     = 0x00020000, // Return Flow instrumentation present
    IMAGE_GUARD_RF_ENABLE                           = 0x00040000, // Requests OS to enable Return Flow protection
    IMAGE_GUARD_RF_STRICT                           = 0x00080000, // Requests strict Return Flow protection
    IMAGE_GUARD_RETPOLINE_PRESENT                   = 0x00100000, // Module was built with retpoline support
    IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT       = 0x00400000, // Contains EH continuation target info
    IMAGE_GUARD_XFG_ENABLED                         = 0x00800000, // Built with XFG (deprecated)
    IMAGE_GUARD_CASTGUARD_PRESENT                   = 0x01000000, // CastGuard instrumentation present
    IMAGE_GUARD_MEMCPY_PRESENT                      = 0x02000000, // Guarded Memcpy instrumentation present
    IMAGE_GUARD_HWINTRINSICS_PRESENT                = 0x04000000, // Hardware intrinsic instrumentation present
    IMAGE_GUARD_SHADOW_STACK_PRESENT                = 0x08000000, // Shadow Stack instrumentation present
    IMAGE_GUARD_JUMPTABLE_PRESENT                   = 0x10000000, // Contains jumptable target metadata
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK         = 0xF0000000  // Bits 28–31 encode stride of CFG function table
} IMAGE_GUARD_FLAGS;
#else 
typedef enum _IMAGE_GUARD_FLAGS {
    IMAGE_GUARD_HWINTRINSICS_PRESENT                = 0x04000000, // Hardware intrinsic instrumentation present
    IMAGE_GUARD_SHADOW_STACK_PRESENT                = 0x08000000, // Shadow Stack instrumentation present
    IMAGE_GUARD_JUMPTABLE_PRESENT                   = 0x10000000, // Contains jumptable target metadata
} IMAGE_GUARD_FLAGS;
#endif

#ifndef COMIMAGE_FLAGS_ILONLY
// define aliases to your portable versions
#define COMIMAGE_FLAGS_ILONLY            0x00000001
#define COMIMAGE_FLAGS_32BITREQUIRED     0x00000002
#define COMIMAGE_FLAGS_IL_LIBRARY        0x00000004
#define COMIMAGE_FLAGS_STRONGNAMESIGNED  0x00000008
#define COMIMAGE_FLAGS_NATIVE_ENTRYPOINT 0x00000010
#define COMIMAGE_FLAGS_TRACKDEBUGDATA    0x00010000
#define COMIMAGE_FLAGS_32BITPREFERRED    0x00020000
#endif

#ifndef VS_FF_DEBUG
typedef enum _VS_FF {
    VS_FF_DEBUG         = 0x00000001L,
    VS_FF_PRERELEASE    = 0x00000002L,
    VS_FF_PATCHED       = 0x00000004L,
    VS_FF_PRIVATEBUILD  = 0x00000008L,
    VS_FF_INFOINFERRED  = 0x00000010L,
    VS_FF_SPECIALBUILD  = 0x00000020L
} VS_FF;
#endif

#ifndef VOS_UNKNOWN
typedef enum _VOS_FLAGS {
    VOS_UNKNOWN         = 0x00000000L,
    VOS_DOS             = 0x00010000L,
    VOS_OS216           = 0x00020000L,
    VOS_OS232           = 0x00030000L,
    VOS_NT              = 0x00040000L,
    VOS_WINCE           = 0x00050000L,

    VOS__BASE           = 0x00000000L,
    VOS__WINDOWS16      = 0x00000001L,
    VOS__PM16           = 0x00000002L,
    VOS__PM32           = 0x00000003L,
    VOS__WINDOWS32      = 0x00000004L,

    // Combined OS + subsystem flags
    VOS_DOS_WINDOWS16   = 0x00010001L,
    VOS_DOS_WINDOWS32   = 0x00010004L,
    VOS_OS216_PM16      = 0x00020002L,
    VOS_OS232_PM32      = 0x00030003L,
    VOS_NT_WINDOWS32    = 0x00040004L
} VOS_FLAGS;
#endif

#ifndef VFT_UNKNOWN
typedef enum _VFT_FLAGS {
    VFT_UNKNOWN     = 0x00000000L,
    VFT_APP         = 0x00000001L,
    VFT_DLL         = 0x00000002L,
    VFT_DRV         = 0x00000003L,
    VFT_FONT        = 0x00000004L,
    VFT_VXD         = 0x00000005L,
    VFT_STATIC_LIB  = 0x00000007L
} VFT_FLAGS;
#endif

#ifndef VFT2_UNKNOWN
    #define VFT2_UNKNOWN 0x00000000L
#endif

#ifndef VFT2_DRV_PRINTER
    typedef enum _VFT2_DRV_SUBTYPE {
    VFT2_DRV_PRINTER           = 0x00000001L,
    VFT2_DRV_KEYBOARD          = 0x00000002L,
    VFT2_DRV_LANGUAGE          = 0x00000003L,
    VFT2_DRV_DISPLAY           = 0x00000004L,
    VFT2_DRV_MOUSE             = 0x00000005L,
    VFT2_DRV_NETWORK           = 0x00000006L,
    VFT2_DRV_SYSTEM            = 0x00000007L,
    VFT2_DRV_INSTALLABLE       = 0x00000008L,
    VFT2_DRV_SOUND             = 0x00000009L,
    VFT2_DRV_COMM              = 0x0000000AL,
    VFT2_DRV_VERSIONED_PRINTER = 0x0000000CL
} VFT2_DRV_SUBTYPE;
#endif

#ifndef VFT2_FONT_RASTER
    typedef enum _VFT2_FONT_SUBTYPE{
        VFT2_FONT_RASTER    = 0x00000001L,
        VFT2_FONT_VECTOR    = 0x00000002L,
        VFT2_FONT_TRUETYPE  = 0x00000003L
    } _VFT2_FONT_SUBTYPE;
#endif

#endif