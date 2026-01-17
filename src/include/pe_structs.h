#ifndef PE_STRUCTS_H
#define PE_STRUCTS_H

#include "libs.h"

#pragma pack(push,2)

#ifndef _WIN32
    // Number of data directory entries in optional header
    #define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

    // Size of short names in section headers
    #define IMAGE_SIZEOF_SHORT_NAME 8
    
    // Size of symbol table stracture
    #define IMAGE_SIZEOF_SYMBOL 18

    // Size of long names
    #define MAXLOGICALLOGNAMESIZE   256

    // Flags to detect import-by-ordinal
    #define IMAGE_ORDINAL_FLAG32 0x80000000
    #define IMAGE_ORDINAL_FLAG64 0x8000000000000000ULL

    // Extract ordinal value
    #define IMAGE_ORDINAL32(Ordinal) ((Ordinal) & 0xFFFF)
    #define IMAGE_ORDINAL64(Ordinal) ((Ordinal) & 0xFFFF)

    // Check if import is by ordinal
    #define IMAGE_SNAP_BY_ORDINAL32(Ordinal) (((Ordinal) & IMAGE_ORDINAL_FLAG32) != 0)
    #define IMAGE_SNAP_BY_ORDINAL64(Ordinal) (((Ordinal) & IMAGE_ORDINAL_FLAG64) != 0)

    #define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
    #define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
    #define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
    #define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
    #define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
    #define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
    #define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
    //#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT     7   // Obsolete (X86 usage)
    #define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
    #define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
    #define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
    #define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Config Directory
    #define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory
    #define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
    #define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
    #define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime Descriptor

    #ifndef DUMMYUNIONNAME
        #if defined(NONAMELESSUNION) || !defined(_MSC_EXTENSIONS)
            #define DUMMYUNIONNAME   u
            #define DUMMYUNIONNAME2  u2
            #define DUMMYUNIONNAME3  u3
            #define DUMMYUNIONNAME4  u4
            #define DUMMYUNIONNAME5  u5
            #define DUMMYUNIONNAME6  u6
            #define DUMMYUNIONNAME7  u7
            #define DUMMYUNIONNAME8  u8
            #define DUMMYUNIONNAME9  u9
        #else
            #define DUMMYUNIONNAME
            #define DUMMYUNIONNAME2
            #define DUMMYUNIONNAME3
            #define DUMMYUNIONNAME4
            #define DUMMYUNIONNAME5
            #define DUMMYUNIONNAME6
            #define DUMMYUNIONNAME7
            #define DUMMYUNIONNAME8
            #define DUMMYUNIONNAME9
        #endif
    #endif // DUMMYUNIONNAME

    #ifndef DUMMYSTRUCTNAME
        #if defined(NONAMELESSUNION) || !defined(_MSC_EXTENSIONS)
            #define DUMMYSTRUCTNAME  s
            #define DUMMYSTRUCTNAME2 s2
            #define DUMMYSTRUCTNAME3 s3
            #define DUMMYSTRUCTNAME4 s4
            #define DUMMYSTRUCTNAME5 s5
            #define DUMMYSTRUCTNAME6 s6
        #else
            #define DUMMYSTRUCTNAME
            #define DUMMYSTRUCTNAME2
            #define DUMMYSTRUCTNAME3
            #define DUMMYSTRUCTNAME4
            #define DUMMYSTRUCTNAME5
            #define DUMMYSTRUCTNAME6
        #endif
    #endif // DUMMYSTRUCTNAME

    #ifndef BOOL
        typedef int32_t BOOL;
    #endif

    #ifndef TRUE
        #define TRUE  1
    #endif

    #ifndef FALSE
        #define FALSE 0
    #endif


    // Basic integer types (you already have many of these)
    // Signed integer types
    typedef int8_t              CHAR;
    typedef int16_t             SHORT;
    typedef int32_t             LONG;
    typedef int32_t             INT;
    typedef int64_t             LONGLONG;

    // Unsigned integer types
    typedef uint8_t     BYTE;
    typedef uint16_t    WORD;
    typedef uint32_t    DWORD;
    typedef uint32_t    UINT;
    typedef uint64_t    ULONGLONG;
    typedef uint16_t    USHORT;

    // Pointer-sized integer types
    typedef uintptr_t           UINT_PTR;
    typedef intptr_t            INT_PTR;
    typedef uintptr_t           ULONG_PTR;
    typedef intptr_t            LONG_PTR;

    // Size types
    typedef size_t              SIZE_T;
    typedef ssize_t             SSIZE_T;    // signed size type

    // Windows-style char/wide types
    typedef char                CHAR;
    typedef uint16_t            WCHAR;      // UTF-16 code unit on Windows
    typedef CHAR*               PCHAR;
    typedef WCHAR*              PWCHAR;
    typedef CHAR*               PSTR;
    typedef const CHAR*         PCSTR;
    typedef const CHAR*         LPCSTR;
    typedef const WCHAR*        LPCWSTR;
    typedef WCHAR*              LPWSTR;

    // Generic pointer types
    typedef void*               PVOID;
    typedef const void*         PCVOID;
    typedef void*               LPVOID;
    typedef const void*         LPCVOID;

    // Common handle / module types
    typedef void*               HANDLE;
    typedef HANDLE*             PHANDLE;
    typedef void*               HMODULE;
    typedef void*               HINSTANCE;
    typedef void*               FARPROC;    // function pointer (platform-specific)

    // Convenience pointer typedefs often seen in headers
    typedef PVOID               LPWIN32_MEMORY; // generic alias (example)

    // Image File Signatures
    #define IMAGE_DOS_SIGNATURE 0x5A4D
    #define IMAGE_NT_SIGNATURE 0x00004550

    // IMAGE_DATA_DIRECTORY
    typedef struct _IMAGE_DATA_DIRECTORY {
        DWORD VirtualAddress;
        DWORD Size;
    } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

    // IMAGE_DOS_HEADER
    typedef struct _IMAGE_DOS_HEADER {
        WORD e_magic;
        WORD e_cblp;
        WORD e_cp;
        WORD e_crlc;
        WORD e_cparhdr;
        WORD e_minalloc;
        WORD e_maxalloc;
        WORD e_ss;
        WORD e_sp;
        WORD e_csum;
        WORD e_ip;
        WORD e_cs;
        WORD e_lfarlc;
        WORD e_ovno;
        WORD e_res[4];
        WORD e_oemid;
        WORD e_oeminfo;
        WORD e_res2[10];
        LONG e_lfanew;
    } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

    // IMAGE_FILE_HEADER
    typedef struct _IMAGE_FILE_HEADER {
        WORD Machine;
        WORD NumberOfSections;
        DWORD TimeDateStamp;
        DWORD PointerToSymbolTable;
        DWORD NumberOfSymbols;
        WORD SizeOfOptionalHeader;
        WORD Characteristics;
    } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

    #define IMAGE_SYM_UNDEFINED           (SHORT)0          // Symbol is undefined or is common.
    #define IMAGE_SYM_ABSOLUTE            (SHORT)-1         // Symbol is an absolute value.
    #define IMAGE_SYM_DEBUG               (SHORT)-2         // Symbol is a special debug item.
    #define IMAGE_SYM_SECTION_MAX         0xFEFF            // Values 0xFF00-0xFFFF are special
    #define IMAGE_SYM_SECTION_MAX_EX      MAXLONG

    typedef struct _IMAGE_SYMBOL {
        union {
            BYTE    ShortName[8]; // 8-byte name (if ≤ 8 chars)
            struct {
                DWORD   Short;
                DWORD   Long;   // offset into string table
            } Name;
            DWORD   LongName[2];
        } N;

        DWORD   Value;
        SHORT   SectionNumber;
        WORD    Type;
        BYTE    StorageClass;
        BYTE    NumberOfAuxSymbols;
    } IMAGE_SYMBOL;
    typedef IMAGE_SYMBOL, *PIMAGE_SYMBOL;

    typedef union _IMAGE_AUX_SYMBOL {
        struct {
            DWORD    TagIndex;                      // struct, union, or enum tag index
            union {
                struct {
                    WORD    Linenumber;             // declaration line number
                    WORD    Size;                   // size of struct, union, or enum
                } LnSz;
            DWORD    TotalSize;
            } Misc;
            union {
                struct {                            // if ISFCN, tag, or .bb
                    DWORD    PointerToLinenumber;
                    DWORD    PointerToNextFunction;
                } Function;
                struct {                            // if ISARY, up to 4 dimen.
                    WORD     Dimension[4];
                } Array;
            } FcnAry;
            WORD    TvIndex;                        // tv index
        } Sym; // For function symbols
        struct {
            BYTE    Name[IMAGE_SIZEOF_SYMBOL];
        } File; // For file symbols
        struct {
            DWORD   Length;                         // section length
            WORD    NumberOfRelocations;            // number of relocation entries
            WORD    NumberOfLinenumbers;            // number of line numbers
            DWORD   CheckSum;                       // checksum for communal
            SHORT   Number;                         // section number to associate with
            BYTE    Selection;                      // communal selection type
        BYTE    bReserved;
        SHORT   HighNumber;                     // high bits of the section number
        } Section; // For section symbols
        IMAGE_AUX_SYMBOL_TOKEN_DEF TokenDef;
        struct {
            DWORD crc;
            BYTE  rgbReserved[14];
        } CRC;
    } IMAGE_AUX_SYMBOL;
    typedef IMAGE_AUX_SYMBOL, *PIMAGE_AUX_SYMBOL;

    typedef struct IMAGE_AUX_SYMBOL_TOKEN_DEF {
        BYTE  bAuxType;                  // IMAGE_AUX_SYMBOL_TYPE
        BYTE  bReserved;                 // Must be 0
        DWORD SymbolTableIndex;
        BYTE  rgbReserved[12];           // Must be 0
    } IMAGE_AUX_SYMBOL_TOKEN_DEF;

    #define FRAME_FPO       0
    #define FRAME_TRAP      1
    #define FRAME_TSS       2
    #define FRAME_NONFPO    3

    typedef struct _FPO_DATA {
        DWORD       ulOffStart;             // offset 1st byte of function code
        DWORD       cbProcSize;             // # bytes in function
        DWORD       cdwLocals;              // # bytes in locals/4
        WORD        cdwParams;              // # bytes in params/4
        WORD        cbProlog : 8;           // # bytes in prolog
        WORD        cbRegs   : 3;           // # regs saved
        WORD        fHasSEH  : 1;           // TRUE if SEH in func
        WORD        fUseBP   : 1;           // TRUE if EBP has been allocated
        WORD        reserved : 1;           // reserved for future use
        WORD        cbFrame  : 2;           // frame type
    } FPO_DATA, *PFPO_DATA;
    #define SIZEOF_RFPO_DATA 16

    #define IMAGE_DEBUG_MISC_EXENAME    1

    typedef struct _IMAGE_DEBUG_MISC {
        DWORD       DataType;               // type of misc data, see defines
        DWORD       Length;                 // total length of record, rounded to four
                                            // byte multiple.
        BOOLEAN     Unicode;                // TRUE if data is unicode string
        BYTE        Reserved[ 3 ];
        BYTE        Data[ 1 ];              // Actual data
    } IMAGE_DEBUG_MISC, *PIMAGE_DEBUG_MISC;

    // IMAGE_OPTIONAL_HEADER32
    typedef struct _IMAGE_OPTIONAL_HEADER32 {
        WORD Magic;
        BYTE MajorLinkerVersion;
        BYTE MinorLinkerVersion;
        DWORD SizeOfCode;
        DWORD SizeOfInitializedData;
        DWORD SizeOfUninitializedData;
        DWORD AddressOfEntryPoint;
        DWORD BaseOfCode;
        DWORD BaseOfData;
        DWORD ImageBase;
        DWORD SectionAlignment;
        DWORD FileAlignment;
        WORD MajorOperatingSystemVersion;
        WORD MinorOperatingSystemVersion;
        WORD MajorImageVersion;
        WORD MinorImageVersion;
        WORD MajorSubsystemVersion;
        WORD MinorSubsystemVersion;
        DWORD Win32VersionValue;
        DWORD SizeOfImage;
        DWORD SizeOfHeaders;
        DWORD CheckSum;
        WORD Subsystem;
        WORD DllCharacteristics;
        DWORD SizeOfStackReserve;
        DWORD SizeOfStackCommit;
        DWORD SizeOfHeapReserve;
        DWORD SizeOfHeapCommit;
        DWORD LoaderFlags;
        DWORD NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

    // IMAGE_OPTIONAL_HEADER64
    typedef struct _IMAGE_OPTIONAL_HEADER64 {
        WORD Magic;
        BYTE MajorLinkerVersion;
        BYTE MinorLinkerVersion;
        DWORD SizeOfCode;
        DWORD SizeOfInitializedData;
        DWORD SizeOfUninitializedData;
        DWORD AddressOfEntryPoint;
        DWORD BaseOfCode;
        ULONGLONG ImageBase;
        DWORD SectionAlignment;
        DWORD FileAlignment;
        WORD MajorOperatingSystemVersion;
        WORD MinorOperatingSystemVersion;
        WORD MajorImageVersion;
        WORD MinorImageVersion;
        WORD MajorSubsystemVersion;
        WORD MinorSubsystemVersion;
        DWORD Win32VersionValue;
        DWORD SizeOfImage;
        DWORD SizeOfHeaders;
        DWORD CheckSum;
        WORD Subsystem;
        WORD DllCharacteristics;
        ULONGLONG SizeOfStackReserve;
        ULONGLONG SizeOfStackCommit;
        ULONGLONG SizeOfHeapReserve;
        ULONGLONG SizeOfHeapCommit;
        DWORD LoaderFlags;
        DWORD NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

    // IMAGE_NT_HEADERS32
    typedef struct _IMAGE_NT_HEADERS32 {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

    // IMAGE_NT_HEADERS64
    typedef struct _IMAGE_NT_HEADERS64 {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

    // IMAGE_SECTION_HEADER
    typedef struct _IMAGE_SECTION_HEADER {
        BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
        union {
            DWORD PhysicalAddress;
            DWORD VirtualSize;
        } Misc;
        DWORD VirtualAddress;
        DWORD SizeOfRawData;
        DWORD PointerToRawData;
        DWORD PointerToRelocations;
        DWORD PointerToLinenumbers;
        WORD  NumberOfRelocations;
        WORD  NumberOfLinenumbers;
        DWORD Characteristics;
    } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

    // Export Table
    typedef struct _IMAGE_EXPORT_DIRECTORY {
        DWORD   Characteristics;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        DWORD   Name;
        DWORD   Base;
        DWORD   NumberOfFunctions;
        DWORD   NumberOfNames;
        DWORD   AddressOfFunctions;     // RVA from base of image
        DWORD   AddressOfNames;         // RVA from base of image
        DWORD   AddressOfNameOrdinals;  // RVA from base of image
    } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

    // Import Table
    typedef struct _IMAGE_IMPORT_DESCRIPTOR {
        union {
            DWORD   Characteristics;    // 0 for terminating null import descriptor
            DWORD   OriginalFirstThunk; // RVA to IMAGE_THUNK_DATA (Import Lookup Table / ILT)
        };
        DWORD   TimeDateStamp;          // Usually 0, can be a "bound import" timestamp
        DWORD   ForwarderChain;         // Index of first forwarder reference, or -1 if none
        DWORD   Name;                   // RVA to ASCII string of DLL name
        DWORD   FirstThunk;             // RVA to Import Address Table (IAT)
    } IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

    typedef struct _IMAGE_THUNK_DATA32 {
        union {
            DWORD ForwarderString;
            DWORD Function;
            DWORD Ordinal;
            DWORD AddressOfData; // RVA to IMAGE_IMPORT_BY_NAME
        } u1;
    } IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

    typedef struct _IMAGE_THUNK_DATA64 {
        union {
            ULONGLONG ForwarderString;  // PUCHAR
            ULONGLONG Function;         // PULONG
            ULONGLONG Ordinal;
            ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
        } u1;
    } IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

    typedef struct _IMAGE_IMPORT_BY_NAME {
        WORD    Hint;
        BYTE    Name[1]; // variable length
    } IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

    // Resource Table
    typedef struct _IMAGE_RESOURCE_DIRECTORY {
        DWORD   Characteristics;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        WORD    NumberOfNamedEntries;
        WORD    NumberOfIdEntries;
    } IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

    typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {
        union {
            struct {
                DWORD NameOffset : 31;
                DWORD NameIsString : 1;
            };
            DWORD   Name;
            WORD    Id;
        };
        union {
            DWORD   OffsetToData;
            struct {
                DWORD OffsetToDirectory : 31;
                DWORD DataIsDirectory : 1;
            };
        };

    } IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

    typedef struct _IMAGE_RESOURCE_DIRECTORY_STRING {
        WORD    Length;
        CHAR    NameString[ 1 ];
    } IMAGE_RESOURCE_DIRECTORY_STRING, *PIMAGE_RESOURCE_DIRECTORY_STRING;


    typedef struct _IMAGE_RESOURCE_DIR_STRING_U {
        WORD    Length;
        WCHAR   NameString[ 1 ];
    } IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;

    typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
        DWORD   OffsetToData; // RVA
        DWORD   Size;
        DWORD   CodePage;
        DWORD   Reserved;
    } IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

    //
    // - Exception Table -
    //

    // ==========================================
    // Windows CE Runtime Function Entry (ARM, PPC, SH3/SH4 Windows CE)
    // ==========================================
    typedef struct _IMAGE_CE_RUNTIME_FUNCTION_ENTRY {
        DWORD FuncStart;
        DWORD PrologLen : 8;
        DWORD FuncLen : 22;
        DWORD ThirtyTwoBit : 1;
        DWORD ExceptionFlag : 1;
    } IMAGE_CE_RUNTIME_FUNCTION_ENTRY, *PIMAGE_CE_RUNTIME_FUNCTION_ENTRY;

    // ==========================================
    // ARM Runtime Function Entry
    // ==========================================
    typedef struct _IMAGE_ARM_RUNTIME_FUNCTION_ENTRY {
        DWORD BeginAddress;
        union {
            DWORD UnwindData;
            struct {
                DWORD Flag : 2;
                DWORD FunctionLength : 11;
                DWORD Ret : 2;
                DWORD H : 1;
                DWORD Reg : 3;
                DWORD R : 1;
                DWORD L : 1;
                DWORD C : 1;
                DWORD StackAdjust : 10;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;
    } IMAGE_ARM_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ARM_RUNTIME_FUNCTION_ENTRY;

    // ==========================================
    // ARM64 Runtime Function Entries + helpers
    // ==========================================
    typedef enum ARM64_FNPDATA_FLAGS {
        PdataRefToFullXdata = 0,
        PdataPackedUnwindFunction = 1,
        PdataPackedUnwindFragment = 2,
    } ARM64_FNPDATA_FLAGS;

    typedef enum ARM64_FNPDATA_CR {
        PdataCrUnchained = 0,
        PdataCrUnchainedSavedLr = 1,
        PdataCrChainedWithPac = 2,
        PdataCrChained = 3,
    } ARM64_FNPDATA_CR;

    typedef struct _IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY {
        DWORD BeginAddress;
        union {
            DWORD UnwindData;
            struct {
                DWORD Flag : 2;
                DWORD FunctionLength : 11;
                DWORD RegF : 3;
                DWORD RegI : 4;
                DWORD H : 1;
                DWORD CR : 2;
                DWORD FrameSize : 9;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;
    } IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY;

    typedef union IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA {
        DWORD HeaderData;
        struct {
            DWORD FunctionLength : 18;      // in words (2 bytes)
            DWORD Version : 2;
            DWORD ExceptionDataPresent : 1;
            DWORD EpilogInHeader : 1;
            DWORD EpilogCount : 5;          // number of epilogs or byte index of first unwind code
            DWORD CodeWords : 5;            // number of dwords with unwind codes
        } DUMMYSTRUCTNAME;
    } IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA;

    typedef union IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EXTENDED {
        DWORD ExtendedHeaderData;
        struct {
            DWORD ExtendedEpilogCount : 16;
            DWORD ExtendedCodeWords : 8;
        } DUMMYSTRUCTNAME;
    } IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EXTENDED;

    typedef union IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EPILOG_SCOPE {
        DWORD EpilogScopeData;
        struct {
            DWORD EpilogStartOffset : 18;   // offset in bytes / 4, relative to function start
            DWORD Res0 : 4;
            DWORD EpilogStartIndex : 10;    // byte index of first unwind code for this epilog
        } DUMMYSTRUCTNAME;
    } IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY_XDATA_EPILOG_SCOPE;

    // ==========================================
    // Alpha / Alpha64 Runtime Function Entries (same layout as MIPS docs)
    // ==========================================
    typedef struct _IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY {
        ULONGLONG BeginAddress;
        ULONGLONG EndAddress;
        ULONGLONG ExceptionHandler;
        ULONGLONG HandlerData;
        ULONGLONG PrologEndAddress;
    } IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY;

    typedef struct _IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY {
        DWORD BeginAddress;
        DWORD EndAddress;
        DWORD ExceptionHandler;
        DWORD HandlerData;
        DWORD PrologEndAddress;
    } IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY, *PIMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY;

    // ==========================================
    // x64 / IA64 Runtime Function Entries
    // ==========================================
    typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
        DWORD BeginAddress;
        DWORD EndAddress;
        union {
            DWORD UnwindInfoAddress;
            DWORD UnwindData;
        } DUMMYUNIONNAME;
    } _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;

    // Base Relocation Table
    typedef struct _IMAGE_BASE_RELOCATION {
        DWORD   VirtualAddress;
        DWORD   SizeOfBlock;
        WORD    TypeOffset[1]; // variable length
    } IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;

    //
    // Debug Directory
    //

    typedef struct _IMAGE_DEBUG_DIRECTORY {
        DWORD   Characteristics;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        DWORD   Type;
        DWORD   SizeOfData;
        DWORD   AddressOfRawData; // RVA
        DWORD   PointerToRawData; // file offset
    } IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

    typedef struct _IMAGE_FUNCTION_ENTRY {
      DWORD StartingAddress;
      DWORD EndingAddress;
      DWORD EndOfPrologue;
    } IMAGE_FUNCTION_ENTRY,*PIMAGE_FUNCTION_ENTRY;

    typedef struct _IMAGE_FUNCTION_ENTRY64 {
      ULONGLONG StartingAddress;
      ULONGLONG EndingAddress;
      __C89_NAMELESS union {
	ULONGLONG EndOfPrologue;
	ULONGLONG UnwindInfoAddress;
      } DUMMYUNIONNAME;
    } IMAGE_FUNCTION_ENTRY64,*PIMAGE_FUNCTION_ENTRY64;

    typedef struct _IMAGE_COFF_SYMBOLS_HEADER {
        DWORD   NumberOfSymbols;
        DWORD   LvaToFirstSymbol;
        DWORD   NumberOfLinenumbers;
        DWORD   LvaToFirstLinenumber;
        DWORD   RvaToFirstByteOfCode;
        DWORD   RvaToLastByteOfCode;
        DWORD   RvaToFirstByteOfData;
        DWORD   RvaToLastByteOfData;
    } IMAGE_COFF_SYMBOLS_HEADER, *PIMAGE_COFF_SYMBOLS_HEADER;

    //
    // TLS Directory
    //

    typedef struct _IMAGE_TLS_DIRECTORY64 {
        ULONGLONG StartAddressOfRawData;
        ULONGLONG EndAddressOfRawData;
        ULONGLONG AddressOfIndex;         // PDWORD
        ULONGLONG AddressOfCallBacks;     // PIMAGE_TLS_CALLBACK *;
        DWORD SizeOfZeroFill;
        union {
            DWORD Characteristics;
            struct {
                DWORD Reserved0 : 20;
                DWORD Alignment : 4;
                DWORD Reserved1 : 8;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;

    } IMAGE_TLS_DIRECTORY64;

    typedef IMAGE_TLS_DIRECTORY64 * PIMAGE_TLS_DIRECTORY64;

    typedef struct _IMAGE_TLS_DIRECTORY32 {
        DWORD   StartAddressOfRawData;
        DWORD   EndAddressOfRawData;
        DWORD   AddressOfIndex;             // PDWORD
        DWORD   AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
        DWORD   SizeOfZeroFill;
        union {
            DWORD Characteristics;
            struct {
                DWORD Reserved0 : 20;
                DWORD Alignment : 4;
                DWORD Reserved1 : 8;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;

    } IMAGE_TLS_DIRECTORY32;
    typedef IMAGE_TLS_DIRECTORY32 * PIMAGE_TLS_DIRECTORY32;

    // Load Config Directory // Code Integrity in loadconfig (CI)
    typedef struct _IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
        WORD    Flags;          // Flags to indicate if CI information is available, etc.
        WORD    Catalog;        // 0xFFFF means not available
        DWORD   CatalogOffset;
        DWORD   Reserved;       // Additional bitmask to be defined later
    } IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

    typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY32 {
        DWORD   Size;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        DWORD   GlobalFlagsClear;
        DWORD   GlobalFlagsSet;
        DWORD   CriticalSectionDefaultTimeout;
        DWORD   DeCommitFreeBlockThreshold;
        DWORD   DeCommitTotalFreeThreshold;
        DWORD   LockPrefixTable;                // VA
        DWORD   MaximumAllocationSize;
        DWORD   VirtualMemoryThreshold;
        DWORD   ProcessHeapFlags;
        DWORD   ProcessAffinityMask;
        WORD    CSDVersion;
        WORD    DependentLoadFlags;
        DWORD   EditList;                       // VA
        DWORD   SecurityCookie;                 // VA
        DWORD   SEHandlerTable;                 // VA
        DWORD   SEHandlerCount;
        DWORD   GuardCFCheckFunctionPointer;    // VA
        DWORD   GuardCFDispatchFunctionPointer; // VA
        DWORD   GuardCFFunctionTable;           // VA
        DWORD   GuardCFFunctionCount;
        DWORD   GuardFlags;
        IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
        DWORD   GuardAddressTakenIatEntryTable; // VA
        DWORD   GuardAddressTakenIatEntryCount;
        DWORD   GuardLongJumpTargetTable;       // VA
        DWORD   GuardLongJumpTargetCount;
        DWORD   DynamicValueRelocTable;         // VA
        DWORD   CHPEMetadataPointer;
        DWORD   GuardRFFailureRoutine;          // VA
        DWORD   GuardRFFailureRoutineFunctionPointer; // VA
        DWORD   DynamicValueRelocTableOffset;
        WORD    DynamicValueRelocTableSection;
        WORD    Reserved2;
        DWORD   GuardRFVerifyStackPointerFunctionPointer; // VA
        DWORD   HotPatchTableOffset;
        DWORD   Reserved3;
        DWORD   EnclaveConfigurationPointer;    // VA
        DWORD   VolatileMetadataPointer;        // VA
        DWORD   GuardEHContinuationTable;       // VA
        DWORD   GuardEHContinuationCount;
        DWORD   GuardXFGCheckFunctionPointer;   // VA
        DWORD   GuardXFGDispatchFunctionPointer; // VA
        DWORD   GuardXFGTableDispatchFunctionPointer; // VA
        DWORD   CastGuardOsDeterminedFailureMode; // VA
        DWORD   GuardMemcpyFunctionPointer;     // VA
        DWORD   UmaFunctionPointers;            // VA
    } IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

    typedef struct _IMAGE_LOAD_CONFIG_DIRECTORY64 {
        DWORD      Size;
        DWORD      TimeDateStamp;
        WORD       MajorVersion;
        WORD       MinorVersion;
        DWORD      GlobalFlagsClear;
        DWORD      GlobalFlagsSet;
        DWORD      CriticalSectionDefaultTimeout;
        ULONGLONG  DeCommitFreeBlockThreshold;
        ULONGLONG  DeCommitTotalFreeThreshold;
        ULONGLONG  LockPrefixTable;                // VA
        ULONGLONG  MaximumAllocationSize;
        ULONGLONG  VirtualMemoryThreshold;
        ULONGLONG  ProcessAffinityMask;
        DWORD      ProcessHeapFlags;
        WORD       CSDVersion;
        WORD       DependentLoadFlags;
        ULONGLONG  EditList;                       // VA
        ULONGLONG  SecurityCookie;                 // VA
        ULONGLONG  SEHandlerTable;                 // VA
        ULONGLONG  SEHandlerCount;
        ULONGLONG  GuardCFCheckFunctionPointer;    // VA
        ULONGLONG  GuardCFDispatchFunctionPointer; // VA
        ULONGLONG  GuardCFFunctionTable;           // VA
        ULONGLONG  GuardCFFunctionCount;
        DWORD      GuardFlags;
        IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
        ULONGLONG  GuardAddressTakenIatEntryTable; // VA
        ULONGLONG  GuardAddressTakenIatEntryCount;
        ULONGLONG  GuardLongJumpTargetTable;       // VA
        ULONGLONG  GuardLongJumpTargetCount;
        ULONGLONG  DynamicValueRelocTable;         // VA
        ULONGLONG  CHPEMetadataPointer;            // VA
        ULONGLONG  GuardRFFailureRoutine;          // VA
        ULONGLONG  GuardRFFailureRoutineFunctionPointer; // VA
        DWORD      DynamicValueRelocTableOffset;
        WORD       DynamicValueRelocTableSection;
        WORD       Reserved2;
        ULONGLONG  GuardRFVerifyStackPointerFunctionPointer; // VA
        DWORD      HotPatchTableOffset;
        DWORD      Reserved3;
        ULONGLONG  EnclaveConfigurationPointer;    // VA
        ULONGLONG  VolatileMetadataPointer;        // VA
        ULONGLONG  GuardEHContinuationTable;       // VA
        ULONGLONG  GuardEHContinuationCount;
        ULONGLONG  GuardXFGCheckFunctionPointer;   // VA
        ULONGLONG  GuardXFGDispatchFunctionPointer; // VA
        ULONGLONG  GuardXFGTableDispatchFunctionPointer; // VA
        ULONGLONG  CastGuardOsDeterminedFailureMode; // VA
        ULONGLONG  GuardMemcpyFunctionPointer;     // VA
        ULONGLONG  UmaFunctionPointers;            // VA
    } IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

    //
    // Bound Import Table
    //
    typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
        DWORD   TimeDateStamp;
        WORD    OffsetModuleName;
        WORD    NumberOfModuleForwarderRefs;
    // Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
    } IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;

    typedef struct _IMAGE_BOUND_FORWARDER_REF {
        DWORD   TimeDateStamp;
        WORD    OffsetModuleName;
        WORD    Reserved;
    } IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;

    //
    // Delay Import Descriptor
    //
    typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
        union {
            DWORD AllAttributes;
            struct {
                DWORD RvaBased : 1;             // Delay load version 2
                DWORD ReservedAttributes : 31;
            } DUMMYSTRUCTNAME;
        } Attributes;

        DWORD DllNameRVA;                       // RVA to the name of the target library (NULL-terminate ASCII string)
        DWORD ModuleHandleRVA;                  // RVA to the HMODULE caching location (PHMODULE)
        DWORD ImportAddressTableRVA;            // RVA to the start of the IAT (PIMAGE_THUNK_DATA)
        DWORD ImportNameTableRVA;               // RVA to the start of the name table (PIMAGE_THUNK_DATA::AddressOfData)
        DWORD BoundImportAddressTableRVA;       // RVA to an optional bound IAT
        DWORD UnloadInformationTableRVA;        // RVA to an optional unload info table
        DWORD TimeDateStamp;                    // 0 if not bound,
                                                // Otherwise, date/time of the target DLL

    } IMAGE_DELAYLOAD_DESCRIPTOR, *PIMAGE_DELAYLOAD_DESCRIPTOR;
    
    //
    // CLR (.NET) Directory
    //
    typedef struct _IMAGE_COR20_HEADER {
        DWORD   cb;
        WORD    MajorRuntimeVersion;
        WORD    MinorRuntimeVersion;
        DWORD   MetaData;          // RVA to metadata
        DWORD   Flags;
        DWORD   EntryPointToken;
        DWORD   Resources;
        DWORD   StrongNameSignature;
        DWORD   CodeManagerTable;
        DWORD   VTableFixups;
        DWORD   ExportAddressTableJumps;
        DWORD   ManagedNativeHeader;
    } IMAGE_COR20_HEADER, *PIMAGE_COR20_HEADER;



    // Binary representation of file version information
    typedef struct tagVS_FIXEDFILEINFO {
        DWORD dwSignature;       // Must be 0xFEEF04BD
        DWORD dwStrucVersion;    // Version of this structure
        DWORD dwFileVersionMS;   // High-order 32 bits of file version
        DWORD dwFileVersionLS;   // Low-order 32 bits of file version
        DWORD dwProductVersionMS;// High-order 32 bits of product version
        DWORD dwProductVersionLS;// Low-order 32 bits of product version
        DWORD dwFileFlagsMask;   // Mask of valid flags
        DWORD dwFileFlags;       // File flags (e.g., debug, prerelease)
        DWORD dwFileOS;          // Target operating system
        DWORD dwFileType;        // Type of file (application, DLL, etc.)
        DWORD dwFileSubtype;     // Subtype of file
        DWORD dwFileDateMS;      // High-order 32 bits of file's binary creation date
        DWORD dwFileDateLS;      // Low-order 32 bits of file's binary creation date
    } VS_FIXEDFILEINFO;
#endif

// size of safe symbol name
#define MAX_SYMBOL_NAME 512

#define RT_DLGINIT   240
#define RT_TOOLBAR   241

//
// IMAGE_RICH_HEADER
//

typedef enum _RICH_HEADER_TAGS {
    tagEndId = 0x536E6144, // "danS"
    tagBegId = 0x68636952 //  "rich"
} RICH_HEADER_TAGS;

typedef struct _RICH_ENTRY {
    WORD BuildID;   // Lower 16 bits of comp.id (msCV)
    WORD ProdID;    // Upper 16 bits of comp.id (product ID)
    DWORD Count;    // 32-bit number of times this tool was used
} RICH_ENTRY, *PRICH_ENTRY;

typedef struct _IMAGE_RICH_HEADER {
    DWORD DanS;                // 'DanS' marker (0x536E6144), marks the beginning of the Rich header
    DWORD checksumPadding1;    // Encrypted padding (should XOR-decrypt to 0x536E6144 again)
    DWORD checksumPadding2;    // Encrypted padding (same as above)
    DWORD checksumPadding3;    // Encrypted padding (same as above)

    DWORD richHdrOff;          // [Helper field] Not actually stored in the file.
    DWORD richHdrSize;         // [Helper field] Not actually stored in the file.
    
    WORD NumberOfEntries;      // [Helper field] Not actually stored in the file.
                               // Computed during parsing: (# of DWORDs between DanS and Rich) / 2.
                               // Makes iteration over the Entries array easier.

    PRICH_ENTRY Entries;       // Pointer to dynamically allocated array of entries.
                               // Each entry = 2 DWORDs (comp.id + count), both XOR-encrypted.

    DWORD Rich;                // 'Rich' marker (0x68636952), marks the end of the Rich header
    DWORD XORKey;              // The XOR key used to encode/decode all DWORDs in the Rich header
} IMAGE_RICH_HEADER, *PIMAGE_RICH_HEADER;

//
// special auxiliary symbol called Weak extern auxiliary symbols (not in winnt.h)
//
typedef struct _IMAGE_AUX_SYMBOL_WEAK_EXTERN {
    DWORD TagIndex;         // symbol-table index of sym2
    DWORD Characteristics;  // IMAGE_WEAK_EXTERN_SEARCH_* value
    WORD    Padding : 10;    // unused padding bits
} IMAGE_AUX_SYMBOL_WEAK_EXTERN, *PIMAGE_AUX_SYMBOL_WEAK_EXTERN;

//
// Old format: NB10
//
typedef struct _CV_INFO_PDB20 {
    DWORD CvSignature;     // "NB10" = 0x3031424E
    DWORD Offset;          // Reserved, usually 0
    DWORD Signature;       // TimeDateStamp (matches PE header)
    DWORD Age;             // Incremented every rebuild of the PDB
    // // Followed by:
    // PdbFileName[]  Null-terminated path to PDB
} CV_INFO_PDB20, *PCV_INFO_PDB20;

//
// New format: RSDS (PDB 7.0)
//
#ifndef GUID_DEFINED
#define GUID_DEFINED
#if defined(__midl)
typedef struct {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    byte           Data4[ 8 ];
} GUID;
#else
typedef struct _GUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[ 8 ];
} GUID;
#endif
#endif

typedef struct _CV_INFO_PDB70 {
    DWORD CvSignature;     // "RSDS" = 0x53445352
    GUID  Signature;       // Globally unique PDB identifier
    DWORD Age;             // Incremented every rebuild of the PDB
    // // Followed by:
    // PdbFileName[]  Null-terminated path to PDB
} CV_INFO_PDB70, *PCV_INFO_PDB70;
 
typedef struct _OMAP {
    ULONG  rva;    // original address
    ULONG  rvaTo;  // mapped address
} OMAP, *POMAP;

typedef struct _VC_FEATURE {
    DWORD Characteristics; // bit flags
} VC_FEATURE;

// Represents a single string in a StringTable
typedef struct {
    WORD  wLength;       // Total size of this String structure, including value
    WORD  wValueLength;  // Length of the string value in WCHARs
    WORD  wType;         // 1 for text, 0 for binary
    // WCHAR szKey;         // Key name of the string (usually a Unicode character array)
    // WORD  Padding;       // Alignment padding
    // WORD  Value;         // String value (for simple cases, could be expanded to WCHAR[])
} String;

// Represents a table of strings (e.g., "040904E4" for language/codepage)
typedef struct {
    WORD   wLength;       // Total size of StringTable
    WORD   wValueLength;  // Usually 0, as StringTable itself holds children
    WORD   wType;         // 1 for text
    WCHAR  szKey[8];         // Key identifying this StringTable (e.g., language-codepage)
    // WORD   Padding;       // Alignment padding
    // String Children;      // Array of String structures
} StringTable;

// Represents the StringFileInfo block in the version resource
typedef struct {
    WORD        wLength;       // Total size of StringFileInfo
    WORD        wValueLength;  // Usually 0, as it only contains children
    WORD        wType;         // 1 for text
    // WCHAR       szKey;         // Usually "StringFileInfo"
    // WORD        Padding;       // Alignment padding
    // String      Children;      // Array of String structures
} StringFileInfo;

// Represents a single Var structure (e.g., translation info)
typedef struct {
    WORD  wLength;       // Total size of Var
    WORD  wValueLength;  // Length of the DWORD value (usually 4)
    WORD  wType;         // 0 for binary
    // WCHAR szKey;         // Key identifying the Var
    // WORD  Padding;       // Alignment padding
    // DWORD Value;         // Value (e.g., language-codepage)
} Var;

// Represents the VarFileInfo block in the version resource
typedef struct {
    WORD  wLength;       // Total size of VarFileInfo
    WORD  wValueLength;  // Usually 0, contains only children
    WORD  wType;         // 1 for text
    // WCHAR szKey;         // Usually "VarFileInfo"
    // WORD  Padding;       // Alignment padding
    // Var   Children;      // Array of Var structures
} VarFileInfo;

//
// Represents the top-level version information structure in a PE resource
//
typedef struct {
    WORD             wLength;       // Total size of this VS_VERSIONINFO structure, including children
    WORD             wValueLength;  // Size of the Value member in bytes (VS_FIXEDFILEINFO)
    WORD             wType;         // 1 for text data, 0 for binary data
    WCHAR            szKey[16];     // Unicode string "VS_VERSION_INFO"
    WORD             Padding1;      // Alignment padding
    VS_FIXEDFILEINFO Value;         // Fixed file version info (binary)
    WORD             Padding2;      // Alignment padding
    WORD             Children;      // Number of child structures (StringFileInfo / VarFileInfo)
} VS_VERSIONINFO;


typedef struct {
    WORD wLength;       // total size of this child, including its own children
    WORD wValueLength;  // usually 0 for these blocks
    WORD wType;         // 1 for text
    WCHAR szKey[16];    // Unicode string identifying the block
    // followed by optional padding1, children and padding2
} VS_VERSIONINFO_HEADER;

typedef struct _PEDataDirectories {
    // Export Table
    PIMAGE_EXPORT_DIRECTORY        exportDir;

    // Import Table
    PIMAGE_IMPORT_DESCRIPTOR       importDir;

    // Resource Table
    PIMAGE_RESOURCE_DIRECTORY        rsrcDir;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY  rsrcEntriesDir;

    // Debug Directory
    PIMAGE_DEBUG_DIRECTORY         debugDir;

    // TLS Directory
    PIMAGE_TLS_DIRECTORY32         tls32;
    PIMAGE_TLS_DIRECTORY64         tls64;

    // Load Config Directory
    PIMAGE_LOAD_CONFIG_DIRECTORY32 loadConfig32;
    PIMAGE_LOAD_CONFIG_DIRECTORY64 loadConfig64;

    // Delay Import Descriptor
    PIMAGE_DELAYLOAD_DESCRIPTOR    delayImportDir;

    // CLR (.NET) Directory
    PIMAGE_COR20_HEADER            clrHeader;       // usually a single struct
} PEDataDirectories, *PPEDataDirectories;

typedef struct _PEContext {
    char filePath[MAXLOGICALLOGNAMESIZE]; // full path or label

    FILE *fileHandle;

    PIMAGE_DOS_HEADER      dosHeader;
    PIMAGE_RICH_HEADER     richHeader;
    PIMAGE_NT_HEADERS32    nt32;
    PIMAGE_NT_HEADERS64    nt64;
    PIMAGE_SECTION_HEADER  sections;
    PPEDataDirectories     dirs;

    WORD      numberOfSections;
    ULONGLONG imageBase;
    ULONGLONG sizeOfImage;
    LONGLONG  fileSize;

    BYTE is64Bit;
    BYTE valid;                           // 0 → invalid or failed load
} PEContext, *PPEContext;

#pragma pack(pop)

#endif