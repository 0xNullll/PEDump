#include "../include/dump_pe_flags.h"

const char* fileHeaderMachineToString(WORD machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_UNKNOWN:     return "IMAGE_FILE_MACHINE_UNKNOWN";
        case IMAGE_FILE_MACHINE_ALPHA:       return "IMAGE_FILE_MACHINE_ALPHA";
        case IMAGE_FILE_MACHINE_ALPHA64:     return "IMAGE_FILE_MACHINE_ALPHA64";
        case IMAGE_FILE_MACHINE_AM33:        return "IMAGE_FILE_MACHINE_AM33";
        case IMAGE_FILE_MACHINE_AMD64:       return "IMAGE_FILE_MACHINE_AMD64";
        case IMAGE_FILE_MACHINE_ARM:         return "IMAGE_FILE_MACHINE_ARM";
        case IMAGE_FILE_MACHINE_ARM64:       return "IMAGE_FILE_MACHINE_ARM64";
        case IMAGE_FILE_MACHINE_ARM64EC:     return "IMAGE_FILE_MACHINE_ARM64EC";
        case IMAGE_FILE_MACHINE_ARM64X:      return "IMAGE_FILE_MACHINE_ARM64X";
        case IMAGE_FILE_MACHINE_ARMNT:       return "IMAGE_FILE_MACHINE_ARMNT";
        case IMAGE_FILE_MACHINE_EBC:         return "IMAGE_FILE_MACHINE_EBC";
        case IMAGE_FILE_MACHINE_I386:        return "IMAGE_FILE_MACHINE_I386";
        case IMAGE_FILE_MACHINE_IA64:        return "IMAGE_FILE_MACHINE_IA64";
        case IMAGE_FILE_MACHINE_LOONGARCH32: return "IMAGE_FILE_MACHINE_LOONGARCH32";
        case IMAGE_FILE_MACHINE_LOONGARCH64: return "IMAGE_FILE_MACHINE_LOONGARCH64";
        case IMAGE_FILE_MACHINE_M32R:        return "IMAGE_FILE_MACHINE_M32R";
        case IMAGE_FILE_MACHINE_MIPS16:      return "IMAGE_FILE_MACHINE_MIPS16";
        case IMAGE_FILE_MACHINE_MIPSFPU:     return "IMAGE_FILE_MACHINE_MIPSFPU";
        case IMAGE_FILE_MACHINE_MIPSFPU16:   return "IMAGE_FILE_MACHINE_MIPSFPU16";
        case IMAGE_FILE_MACHINE_POWERPC:     return "IMAGE_FILE_MACHINE_POWERPC";
        case IMAGE_FILE_MACHINE_POWERPCFP:   return "IMAGE_FILE_MACHINE_POWERPCFP";
        case IMAGE_FILE_MACHINE_R3000BE:     return "IMAGE_FILE_MACHINE_R3000BE";
        case IMAGE_FILE_MACHINE_R3000:       return "IMAGE_FILE_MACHINE_R3000";
        case IMAGE_FILE_MACHINE_R4000:       return "IMAGE_FILE_MACHINE_R4000";
        case IMAGE_FILE_MACHINE_R10000:      return "IMAGE_FILE_MACHINE_R10000";
        case IMAGE_FILE_MACHINE_RISCV32:     return "IMAGE_FILE_MACHINE_RISCV32";
        case IMAGE_FILE_MACHINE_RISCV64:     return "IMAGE_FILE_MACHINE_RISCV64";
        case IMAGE_FILE_MACHINE_RISCV128:    return "IMAGE_FILE_MACHINE_RISCV128";
        case IMAGE_FILE_MACHINE_SH3:         return "IMAGE_FILE_MACHINE_SH3";
        case IMAGE_FILE_MACHINE_SH3DSP:      return "IMAGE_FILE_MACHINE_SH3DSP";
        case IMAGE_FILE_MACHINE_SH4:         return "IMAGE_FILE_MACHINE_SH4";
        case IMAGE_FILE_MACHINE_SH5:         return "IMAGE_FILE_MACHINE_SH5";
        case IMAGE_FILE_MACHINE_THUMB:       return "IMAGE_FILE_MACHINE_THUMB";
        case IMAGE_FILE_MACHINE_WCEMIPSV2:   return "IMAGE_FILE_MACHINE_WCEMIPSV2";
        default: return "IMAGE_FILE_MACHINE_UNKNOWN";
    }
}

const char* osVersionToString(WORD major, WORD minor) {
    switch ((major << 16) | minor) {
        case IMAGE_OS_WIN31:   return "IMAGE_OS_WIN31";
        case IMAGE_OS_WIN35:   return "IMAGE_OS_WIN35";
        case IMAGE_OS_WIN351:  return "IMAGE_OS_WIN351";
        case IMAGE_OS_WIN40:   return "IMAGE_OS_WIN40";
        case IMAGE_OS_WIN2000: return "IMAGE_OS_WIN2000";
        case IMAGE_OS_WINXP:   return "IMAGE_OS_WINXP";
        case IMAGE_OS_WINXP64: return "IMAGE_OS_WINXP64";
        case IMAGE_OS_VISTA:   return "IMAGE_OS_VISTA";
        case IMAGE_OS_WIN7:    return "IMAGE_OS_WIN7";
        case IMAGE_OS_WIN8:    return "IMAGE_OS_WIN8";
        case IMAGE_OS_WIN81:   return "IMAGE_OS_WIN81";
        case IMAGE_OS_WIN10:   return "IMAGE_OS_WIN10";
        default:               return "IMAGE_OS_UNKNOWN";
    }
}

const char* imageVersionToString(WORD major, WORD minor) {
    switch ((major << 16) | minor) {
        case IMAGE_VER_DEFAULT: return "IMAGE_VER_DEFAULT";
        case IMAGE_VER_1_0:     return "IMAGE_VER_1_0";
        case IMAGE_VER_1_1:     return "IMAGE_VER_1_1";
        case IMAGE_VER_2_0:     return "IMAGE_VER_2_0";
        case IMAGE_VER_2_1:     return "IMAGE_VER_2_1";
        case IMAGE_VER_3_0:     return "IMAGE_VER_3_0";
        case IMAGE_VER_3_1:     return "IMAGE_VER_3_1";
        case IMAGE_VER_4_0:     return "IMAGE_VER_4_0";
        case IMAGE_VER_4_1:     return "IMAGE_VER_4_1";
        case IMAGE_VER_5_0:     return "IMAGE_VER_5_0";
        case IMAGE_VER_5_1:     return "IMAGE_VER_5_1";
        default:                return "IMAGE_VER_UNKNOWN";
    }
}

const char* subSystemVersionFlagToString(WORD major, WORD minor) {
    switch ((major << 16) | minor) {
        case IMAGE_SUBSYS_DEFAULT:     return "IMAGE_SUBSYS_DEFAULT";
        case IMAGE_SUBSYS_NT3_0:      return "IMAGE_SUBSYS_NT3_0";
        case IMAGE_SUBSYS_NT3_1:      return "IMAGE_SUBSYS_NT3_1";
        case IMAGE_SUBSYS_NT4_0:      return "IMAGE_SUBSYS_NT4_0";
        case IMAGE_SUBSYS_WIN2000:    return "IMAGE_SUBSYS_WIN2000";
        case IMAGE_SUBSYS_WINXP:      return "IMAGE_SUBSYS_WINXP";
        case IMAGE_SUBSYS_WINXP64:    return "IMAGE_SUBSYS_WINXP64";
        case IMAGE_SUBSYS_VISTA:      return "IMAGE_SUBSYS_VISTA";
        case IMAGE_SUBSYS_WIN7:       return "IMAGE_SUBSYS_WIN7";
        case IMAGE_SUBSYS_WIN8:       return "IMAGE_SUBSYS_WIN8";
        case IMAGE_SUBSYS_WIN81:      return "IMAGE_SUBSYS_WIN81";
        case IMAGE_SUBSYS_WIN10:      return "IMAGE_SUBSYS_WIN10";
        default:                      return "IMAGE_SUBSYS_UNKNOWN";
    }
}

const char* subSystemTypeFlagToString(WORD subsystem) {
    switch (subsystem) {
        case IMAGE_SUBSYSTEM_UNKNOWN:                  return "IMAGE_SUBSYSTEM_UNKNOWN";
        case IMAGE_SUBSYSTEM_NATIVE:                   return "IMAGE_SUBSYSTEM_NATIVE";
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:              return "IMAGE_SUBSYSTEM_WINDOWS_GUI";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:              return "IMAGE_SUBSYSTEM_WINDOWS_CUI";
        case IMAGE_SUBSYSTEM_OS2_CUI:                  return "IMAGE_SUBSYSTEM_OS2_CUI";
        case IMAGE_SUBSYSTEM_POSIX_CUI:                return "IMAGE_SUBSYSTEM_POSIX_CUI";
        case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:           return "IMAGE_SUBSYSTEM_NATIVE_WINDOWS";
        case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:           return "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI";
        case IMAGE_SUBSYSTEM_EFI_APPLICATION:          return "IMAGE_SUBSYSTEM_EFI_APPLICATION";
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:  return "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER";
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:       return "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER";
        case IMAGE_SUBSYSTEM_EFI_ROM:                  return "IMAGE_SUBSYSTEM_EFI_ROM";
        case IMAGE_SUBSYSTEM_XBOX:                     return "IMAGE_SUBSYSTEM_XBOX";
        case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION";
        default:                                       return "IMAGE_SUBSYSTEM_UNKNOWN";
    }
}

const char* getResourceTypeName(WORD type) {
    switch(type) {
        case 1:   return "CURSOR";
        case 2:   return "BITMAP";
        case 3:   return "ICON";
        case 4:   return "MENU";
        case 5:   return "DIALOG";
        case 6:   return "STRING";
        case 7:   return "FONTDIR";
        case 8:   return "FONT";
        case 9:   return "ACCELERATOR";
        case 10:  return "RCDATA";
        case 11:  return "MESSAGETABLE";
        case 12:  return "GROUP_CURSOR";   // RT_CURSOR + 11
        case 14:  return "GROUP_ICON";     // RT_ICON + 11
        case 16:  return "VERSION";
        case 17:  return "DLGINCLUDE";
        case 19:  return "PLUGPLAY";
        case 20:  return "VXD";
        case 21:  return "ANICURSOR";
        case 22:  return "ANIICON";
        case 23:  return "HTML";
        case 24:  return "MANIFEST";
        case 26:  return "DLGINIT";        // undocumented, used in some resources
        case 28:  return "MUI";            // Multilingual User Interface
        case 241: return "TOOLBAR";        // not always official, but used in some apps
        default:  return "UNKNOWN";
    }
}

const char* getResourceLangName(WORD langId) {
    switch (langId) {
        case 0x409: return "English (United States)";
        case 0x809: return "English (United Kingdom)";
        case 0x407: return "German (Germany)";
        case 0x40C: return "French (France)";
        case 0x410: return "Italian (Italy)";
        case 0x411: return "Japanese";
        case 0x412: return "Korean";
        case 0x804: return "Chinese (Simplified)";
        case 0x404: return "Chinese (Traditional)";
        case 0x419: return "Russian";
        case 0x416: return "Portuguese (Brazil)";
        case 0x815: return "Portuguese (Portugal)";
        case 0x41D: return "Swedish";
        case 0x40A: return "Spanish (Spain)";
        case 0x80A: return "Spanish (Mexico)";
        case 0xC0A: return "Spanish (Modern Sort)";
        case 0x413: return "Dutch (Netherlands)";
        case 0x414: return "Norwegian (Bokmål)";
        case 0x415: return "Polish";
        case 0x418: return "Romanian";
        case 0x41F: return "Turkish";
        case 0x422: return "Ukrainian";
        case 0x420: return "Urdu (Pakistan)";
        case 0x421: return "Indonesian";
        default:    return "Unknown Language";
    }
}

const char* getRelocTypeName(WORD type) {
    switch(type) {
        case IMAGE_REL_BASED_ABSOLUTE:           return "ABSOLUTE";
        case IMAGE_REL_BASED_HIGH:               return "HIGH";
        case IMAGE_REL_BASED_LOW:                return "LOW";
        case IMAGE_REL_BASED_HIGHLOW:            return "HIGHLOW";
        case IMAGE_REL_BASED_HIGHADJ:            return "HIGHADJ";
        case IMAGE_REL_BASED_MIPS_JMPADDR:       return "MIPS_JMPADDR";
        case IMAGE_REL_BASED_SECTION:            return "SECTION";
        case IMAGE_REL_BASED_REL32:              return "REL32";
        case IMAGE_REL_BASED_RISCV_HIGH20:       return "RISCV_HIGH20";
        case IMAGE_REL_BASED_RISCV_LOW12I:       return "RISCV_LOW12I";
        case IMAGE_REL_BASED_RISCV_LOW12S:       return "RISCV_LOW12S";
        case IMAGE_REL_BASED_RISCV_JAL:          return "RISCV_JAL";
        case IMAGE_REL_BASED_RISCV_BRANCH:       return "RISCV_BRANCH";
        case IMAGE_REL_BASED_RISCV_GOT_HI20:     return "RISCV_GOT_HI20";
        case IMAGE_REL_BASED_RISCV_TLS_GD_HI20:  return "RISCV_TLS_GD_HI20";
        case IMAGE_REL_BASED_RISCV_TLS_GD_LOW12: return "RISCV_TLS_GD_LOW12";
        case IMAGE_REL_BASED_RISCV_TLS_GD_ADD:   return "RISCV_TLS_GD_ADD";
        case IMAGE_REL_BASED_RISCV_TLS_GD_CALL:  return "RISCV_TLS_GD_CALL";
        default:                                 return "UNKNOWN";
    }
}

const char* getDebugTypeName(DWORD type) {
    switch(type) {
        case IMAGE_DEBUG_TYPE_UNKNOWN:                return "UNKNOWN";
        case IMAGE_DEBUG_TYPE_COFF:                   return "COFF";
        case IMAGE_DEBUG_TYPE_CODEVIEW:               return "CODEVIEW";
        case IMAGE_DEBUG_TYPE_FPO:                    return "FPO";
        case IMAGE_DEBUG_TYPE_MISC:                   return "MISC";
        case IMAGE_DEBUG_TYPE_EXCEPTION:              return "EXCEPTION";
        case IMAGE_DEBUG_TYPE_FIXUP:                  return "FIXUP";
        case IMAGE_DEBUG_TYPE_OMAP_TO_SRC:            return "OMAP_TO_SRC";
        case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:          return "OMAP_FROM_SRC";
        case IMAGE_DEBUG_TYPE_BORLAND:                return "BORLAND";
        case IMAGE_DEBUG_TYPE_BBT:                    return "BBT";
        case IMAGE_DEBUG_TYPE_CLSID:                  return "CLSID";
        case IMAGE_DEBUG_TYPE_VC_FEATURE:             return "VC_FEATURE";
        case IMAGE_DEBUG_TYPE_POGO:                   return "POGO";
        case IMAGE_DEBUG_TYPE_ILTCG:                  return "ILTCG";
        case IMAGE_DEBUG_TYPE_MPX:                    return "MPX";
        case IMAGE_DEBUG_TYPE_REPRO:                  return "REPRO";
        case IMAGE_DEBUG_TYPE_SPGO:                   return "SPGO";
        case IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS:  return "EX_DLLCHARACTERISTICS";
        default:                                      return "UNKNOWN";
    }
}

const char* getSymbolType(DWORD type) {
    BYTE MSB = (type >> 4) & 0xf; // derived type
    BYTE LSB = type & 0xf;        // base type

    FlagDesc imageSymTypes[] = {
        {IMAGE_SYM_TYPE_NULL,   "NULL"},
        {IMAGE_SYM_TYPE_VOID,   "VOID"},
        {IMAGE_SYM_TYPE_CHAR,   "CHAR"},
        {IMAGE_SYM_TYPE_SHORT,  "SHORT"},
        {IMAGE_SYM_TYPE_INT,    "INT"},
        {IMAGE_SYM_TYPE_LONG,   "LONG"},
        {IMAGE_SYM_TYPE_FLOAT,  "FLOAT"},
        {IMAGE_SYM_TYPE_DOUBLE, "DOUBLE"},
        {IMAGE_SYM_TYPE_STRUCT, "STRUCT"},
        {IMAGE_SYM_TYPE_UNION,  "UNION"},
        {IMAGE_SYM_TYPE_ENUM,   "ENUM"},
        {IMAGE_SYM_TYPE_MOE,    "MOE"},
        {IMAGE_SYM_TYPE_BYTE,   "BYTE"},
        {IMAGE_SYM_TYPE_WORD,   "WORD"},
        {IMAGE_SYM_TYPE_UINT,   "UINT"},
        {IMAGE_SYM_TYPE_DWORD,  "DWORD"}
    };
    const size_t imageSymTypesCount = sizeof(imageSymTypes) / sizeof(imageSymTypes[0]);

    FlagDesc imageSymDerivedTypes[] = {
        {IMAGE_SYM_DTYPE_NULL,     "NULL"},
        {IMAGE_SYM_DTYPE_POINTER,  "POINTER"},
        {IMAGE_SYM_DTYPE_FUNCTION, "FUNCTION"},
        {IMAGE_SYM_DTYPE_ARRAY,    "ARRAY"}
    };
    const size_t imageSymDerivedTypesCount = sizeof(imageSymDerivedTypes) / sizeof(imageSymDerivedTypes[0]);

    static char symType[64]; 
    char baseType[16] = "UNKNOWN";
    char derivedType[16] = "UNKNOWN";

    // find base type (LSB)
    for (size_t i = 0; i < imageSymTypesCount; i++) {
        if (LSB == imageSymTypes[i].flag) {
            snprintf(baseType, sizeof(baseType), "%s", imageSymTypes[i].name);
            break;
        }
    }

    // find derived type (MSB)
    for (size_t i = 0; i < imageSymDerivedTypesCount; i++) {
        if (MSB == imageSymDerivedTypes[i].flag) {
            snprintf(derivedType, sizeof(derivedType), "%s", imageSymDerivedTypes[i].name);
            break;
        }
    }

    snprintf(symType, sizeof(symType), "%s, %s", baseType, derivedType);

    return symType;
}

const char* getSymbolClassName(DWORD symClass) {
    switch(symClass) {
        // Special / function markers
        case IMAGE_SYM_CLASS_END_OF_FUNCTION: return "IMAGE_SYM_CLASS_END_OF_FUNCTION - End of Function";
        case IMAGE_SYM_CLASS_FUNCTION:        return "IMAGE_SYM_CLASS_FUNCTION - Function";
        case IMAGE_SYM_CLASS_BLOCK:           return "IMAGE_SYM_CLASS_BLOCK - Block";
        case IMAGE_SYM_CLASS_END_OF_STRUCT:   return "IMAGE_SYM_CLASS_END_OF_STRUCT - End of Structure";

        // Storage classes
        case IMAGE_SYM_CLASS_NULL:            return "IMAGE_SYM_CLASS_NULL - None";
        case IMAGE_SYM_CLASS_AUTOMATIC:       return "IMAGE_SYM_CLASS_AUTOMATIC - Automatic (Stack Variable)";
        case IMAGE_SYM_CLASS_EXTERNAL:        return "IMAGE_SYM_CLASS_EXTERNAL - External Symbol";
        case IMAGE_SYM_CLASS_STATIC:          return "IMAGE_SYM_CLASS_STATIC - Static Symbol";
        case IMAGE_SYM_CLASS_REGISTER:        return "IMAGE_SYM_CLASS_REGISTER - Register Variable";
        case IMAGE_SYM_CLASS_EXTERNAL_DEF:    return "IMAGE_SYM_CLASS_EXTERNAL_DEF - Externally Defined Symbol";

        // Labels
        case IMAGE_SYM_CLASS_LABEL:           return "IMAGE_SYM_CLASS_LABEL - Label";
        case IMAGE_SYM_CLASS_UNDEFINED_LABEL: return "IMAGE_SYM_CLASS_UNDEFINED_LABEL - Undefined Label";

        // Struct / Union / Enum
        case IMAGE_SYM_CLASS_MEMBER_OF_STRUCT:return "IMAGE_SYM_CLASS_MEMBER_OF_STRUCT - Struct Member";
        case IMAGE_SYM_CLASS_STRUCT_TAG:      return "IMAGE_SYM_CLASS_STRUCT_TAG - Struct Tag";
        case IMAGE_SYM_CLASS_MEMBER_OF_UNION: return "IMAGE_SYM_CLASS_MEMBER_OF_UNION - Union Member";
        case IMAGE_SYM_CLASS_UNION_TAG:       return "IMAGE_SYM_CLASS_UNION_TAG - Union Tag";
        case IMAGE_SYM_CLASS_TYPE_DEFINITION: return "IMAGE_SYM_CLASS_TYPE_DEFINITION - Type Definition";
        case IMAGE_SYM_CLASS_ENUM_TAG:        return "IMAGE_SYM_CLASS_ENUM_TAG - Enum Tag";
        case IMAGE_SYM_CLASS_MEMBER_OF_ENUM:  return "IMAGE_SYM_CLASS_MEMBER_OF_ENUM - Enum Member";

        // Function / argument
        case IMAGE_SYM_CLASS_ARGUMENT:        return "IMAGE_SYM_CLASS_ARGUMENT - Function Argument";
        case IMAGE_SYM_CLASS_REGISTER_PARAM:  return "IMAGE_SYM_CLASS_REGISTER_PARAM - Register Parameter";
        case IMAGE_SYM_CLASS_BIT_FIELD:       return "IMAGE_SYM_CLASS_BIT_FIELD - Bit Field";

        // File / section / special
        case IMAGE_SYM_CLASS_FILE:            return "IMAGE_SYM_CLASS_FILE - File";
        case IMAGE_SYM_CLASS_SECTION:         return "IMAGE_SYM_CLASS_SECTION - Section";
        case IMAGE_SYM_CLASS_WEAK_EXTERNAL:   return "IMAGE_SYM_CLASS_WEAK_EXTERNAL - Weak External";
        case IMAGE_SYM_CLASS_CLR_TOKEN:       return "IMAGE_SYM_CLASS_CLR_TOKEN - CLR Token";

        default: return "UNKNOWN";
    }
}

const char* getWeakExternCharFlag(DWORD characteristics) {
    // Mask only the low 2 bits
    switch (characteristics & 0x3) {
        case WEAK_EXTERN_NOLIBRARY:       return "WEAK_EXTERN_NOLIBRARY";
        case WEAK_EXTERN_LIBRARY:         return "WEAK_EXTERN_LIBRARY";
        case WEAK_EXTERN_ALIAS:           return "WEAK_EXTERN_ALIAS";
        case WEAK_EXTERN_ANTI_DEPENDENCY: return "WEAK_EXTERN_ANTI_DEPENDENCY";
        default: return "UNKNOWN";
    }
}

const char* getComdatSelectName(WORD Number) {
    switch (Number) {
        case 0:                                return "";
        case IMAGE_COMDAT_SELECT_NODUPLICATES: return "(NODUPLICATES)";
        case IMAGE_COMDAT_SELECT_ANY:          return "(ANY)";
        case IMAGE_COMDAT_SELECT_SAME_SIZE:    return "(SAME_SIZE)";
        case IMAGE_COMDAT_SELECT_EXACT_MATCH:  return "(EXACT_MATCH)";
        case IMAGE_COMDAT_SELECT_ASSOCIATIVE:  return "(ASSOCIATIVE)";
        case IMAGE_COMDAT_SELECT_LARGEST:      return "(LARGEST)";
        default:                               return "(UNKNOWN)";
    }
}

const char* getExceptionEntryType(WORD machine) {
    if (IsMIPSOrAlpha32(machine))
        return "RUNTIME_FUNCTION (MIPS/Alpha32)";
    else if (IsAlpha64(machine))
        return "RUNTIME_FUNCTION (Alpha64)";
    else if (IsWinCE(machine))
        return "RUNTIME_FUNCTION (WinCE / ARM / PowerPC / SHx)";
    else if (IsARMNT(machine))
        return "IMAGE_RUNTIME_FUNCTION_ENTRY_ARM (ARM unwind)";
    else if (IsARM64(machine))
        return "IMAGE_RUNTIME_FUNCTION_ENTRY_ARM64 (ARM64 unwind)";
    else if (IsX64OrItanium(machine))
        return "IMAGE_RUNTIME_FUNCTION_ENTRY (x64 / Itanium unwind)";
    else
        return "Unknown entry type";
}

const char* getArm64FlagToString(DWORD flag) {
    switch (flag) {
        case 0: return "PdataRefToFullXdata";
        case 1: return "PdataPackedUnwindFunction";
        case 2: return "PdataPackedUnwindFragment";
        default: return "UnknownFlag";
    }
}

const char* getArm64CrToString(DWORD cr) {
    switch (cr) {
        case 0: return "PdataCrUnchained";
        case 1: return "PdataCrUnchainedSavedLr";
        case 2: return "PdataCrChainedWithPac";
        case 3: return "PdataCrChained";
        default: return "UnknownCR";
    }
}

const char* getCertRevisionFlag(WORD revision) {
    switch (revision) {
        case WIN_CERT_REVISION_1_0: return "WIN_CERT_REVISION_1_0";
        case WIN_CERT_REVISION_2_0: return "WIN_CERT_REVISION_2_0";
        default:                    return "UNKNOWN_CERT_REVISION";
    }
}

const char* getCertTypeFlag(WORD type) {
    switch (type) {
        case WIN_CERT_TYPE_X509:             return "WIN_CERT_TYPE_X509";
        case WIN_CERT_TYPE_PKCS_SIGNED_DATA: return "WIN_CERT_TYPE_PKCS_SIGNED_DATA";
        case WIN_CERT_TYPE_RESERVED_1:       return "WIN_CERT_TYPE_RESERVED_1";
        case WIN_CERT_TYPE_TS_STACK_SIGNED:  return "WIN_CERT_TYPE_TS_STACK_SIGNED";
        default:                             return "UNKNOWN_CERT_TYPE";
    }
}

const char* GetHashType(WORD size) {
    switch (size) {
        case 16: return "MD5 (128-bit)";
        case 20: return "SHA-1 (160-bit)";
        case 32: return "SHA-256 (256-bit)";
        case 48: return "SHA-384 (384-bit)";
        case 64: return "SHA-512 (512-bit)";
        default: return "Unknown / Unsupported hash";
    }
}

const char* GetFileOSString(DWORD dwFileOS) {
    switch (dwFileOS) {
        case VOS_UNKNOWN:        return "VOS__BASE";
        case VOS_DOS:            return "VOS_DOS";
        case VOS_OS216:          return "VOS_OS216";
        case VOS_OS232:          return "VOS_OS232";
        case VOS_NT:             return "VOS_NT";
        case VOS_WINCE:          return "VOS_WINCE";
        case VOS__WINDOWS16:     return "VOS__WINDOWS16";
        case VOS__PM16:          return "VOS__PM16";
        case VOS__PM32:          return "VOS__PM32";
        case VOS__WINDOWS32:     return "VOS__WINDOWS32";
        case VOS_DOS_WINDOWS16:  return "VOS_DOS_WINDOWS16";
        case VOS_DOS_WINDOWS32:  return "VOS_DOS_WINDOWS32";
        case VOS_OS216_PM16:     return "VOS_OS216_PM16";
        case VOS_OS232_PM32:     return "VOS_OS232_PM32";
        case VOS_NT_WINDOWS32:   return "VOS_NT_WINDOWS32";
        default:                 return "UNKNOWN";
    }
}

const char* GetFileTypeString(DWORD dwFileType) {
    switch (dwFileType) {
        case VFT_UNKNOWN:    return "VFT_UNKNOWN";
        case VFT_APP:        return "VFT_APP";
        case VFT_DLL:        return "VFT_DLL";
        case VFT_DRV:        return "VFT_DRV";
        case VFT_FONT:       return "VFT_FONT";
        case VFT_VXD:        return "VFT_VXD";
        case VFT_STATIC_LIB: return "VFT_STATIC_LIB";
        default:             return "VFT_UNKNOWN";
    }
}

const char* GetDriverSubtypeString(DWORD dwFileSubtype) {
    switch (dwFileSubtype) {
        case VFT2_UNKNOWN:               return "VFT2_UNKNOWN";
        case VFT2_DRV_PRINTER:           return "VFT2_DRV_PRINTER";
        case VFT2_DRV_KEYBOARD:          return "VFT2_DRV_KEYBOARD";
        case VFT2_DRV_LANGUAGE:          return "VFT2_DRV_LANGUAGE";
        case VFT2_DRV_DISPLAY:           return "VFT2_DRV_DISPLAY";
        case VFT2_DRV_MOUSE:             return "VFT2_DRV_MOUSE";
        case VFT2_DRV_NETWORK:           return "VFT2_DRV_NETWORK";
        case VFT2_DRV_SYSTEM:            return "VFT2_DRV_SYSTEM";
        case VFT2_DRV_INSTALLABLE:       return "VFT2_DRV_INSTALLABLE";
        case VFT2_DRV_SOUND:             return "VFT2_DRV_SOUND";
        case VFT2_DRV_COMM:              return "VFT2_DRV_COMM";
        case VFT2_DRV_VERSIONED_PRINTER: return "VFT2_DRV_VERSIONED_PRINTER";
        default:                         return "VFT2_UNKNOWN";
    }
}

const char* GetFontSubtypeString(DWORD dwFileSubtype) {
    switch (dwFileSubtype) {
        case VFT2_UNKNOWN:       return "VFT2_UNKNOWN";
        case VFT2_FONT_RASTER:   return "VFT2_FONT_RASTER";
        case VFT2_FONT_VECTOR:   return "VFT2_FONT_VECTOR";
        case VFT2_FONT_TRUETYPE: return "VFT2_FONT_TRUETYPE";
        default:                 return "VFT2_UNKNOWN";
    }
}

const char* getViLangName(WORD langID) {
    switch (langID) {
        case 0x0401: return "Arabic";
        case 0x0402: return "Bulgarian";
        case 0x0403: return "Catalan";
        case 0x0404: return "Traditional Chinese";
        case 0x0405: return "Czech";
        case 0x0406: return "Danish";
        case 0x0407: return "German";
        case 0x0408: return "Greek";
        case 0x0409: return "U.S. English";
        case 0x040A: return "Castilian Spanish";
        case 0x040B: return "Finnish";
        case 0x040C: return "French";
        case 0x040D: return "Hebrew";
        case 0x040E: return "Hungarian";
        case 0x040F: return "Icelandic";
        case 0x0410: return "Italian";
        case 0x0411: return "Japanese";
        case 0x0412: return "Korean";
        case 0x0413: return "Dutch";
        case 0x0414: return "Norwegian - Bokmal";
        case 0x0415: return "Polish";
        case 0x0416: return "Portuguese (Brazil)";
        case 0x0417: return "Rhaeto-Romanic";
        case 0x0418: return "Romanian";
        case 0x0419: return "Russian";
        case 0x041A: return "Croato-Serbian (Latin)";
        case 0x041B: return "Slovak";
        case 0x041C: return "Albanian";
        case 0x041D: return "Swedish";
        case 0x041E: return "Thai";
        case 0x041F: return "Turkish";
        case 0x0420: return "Urdu";
        case 0x0421: return "Bahasa";
        case 0x0804: return "Simplified Chinese";
        case 0x0807: return "Swiss German";
        case 0x0809: return "U.K. English";
        case 0x080A: return "Spanish (Mexico)";
        case 0x080C: return "Belgian French";
        case 0x0C0C: return "Canadian French";
        case 0x100C: return "Swiss French";
        case 0x0810: return "Swiss Italian";
        case 0x0813: return "Belgian Dutch";
        case 0x0814: return "Norwegian - Nynorsk";
        case 0x0816: return "Portuguese (Portugal)";
        case 0x081A: return "Serbo-Croatian (Cyrillic)";
        default: return "Unknown Language";
    }
}

const char* getViCharsetName(WORD charsetID) {
    switch (charsetID) {
        case 0: return "7-bit ASCII";
        case 932: return "Japan (Shift - JIS X-0208)";
        case 949: return "Korea (Shift - KSC 5601)";
        case 950: return "Taiwan (Big5)";
        case 1200: return "Unicode";
        case 1250: return "Latin-2 (Eastern European)";
        case 1251: return "Cyrillic";
        case 1252: return "Multilingual";
        case 1253: return "Greek";
        case 1254: return "Turkish";
        case 1255: return "Hebrew";
        case 1256: return "Arabic";
        default: return "Unknown Charset";
    }
}

// Data used from RichPrint by dishather (https://github.com/dishather)
// Copyright (c) 2015-2024 dishather
// Redistribution and use of this data permitted under the BSD-style license
const char* getRichProductIdName(WORD prodid) {
    switch (prodid) {
        case 0x0000: return "prodidUnknown";
        case 0x0001: return "prodidImport0";
        case 0x0002: return "prodidLinker510";
        case 0x0003: return "prodidCvtomf510";
        case 0x0004: return "prodidLinker600";
        case 0x0005: return "prodidCvtomf600";
        case 0x0006: return "prodidCvtres500";
        case 0x0007: return "prodidUtc11_Basic";
        case 0x0008: return "prodidUtc11_C";
        case 0x0009: return "prodidUtc12_Basic";
        case 0x000a: return "prodidUtc12_C";
        case 0x000b: return "prodidUtc12_CPP";
        case 0x000c: return "prodidAliasObj60";
        case 0x000d: return "prodidVisualBasic60";
        case 0x000e: return "prodidMasm613";
        case 0x000f: return "prodidMasm710";
        case 0x0010: return "prodidLinker511";
        case 0x0011: return "prodidCvtomf511";
        case 0x0012: return "prodidMasm614";
        case 0x0013: return "prodidLinker512";
        case 0x0014: return "prodidCvtomf512";
        case 0x0015: return "prodidUtc12_C_Std";
        case 0x0016: return "prodidUtc12_CPP_Std";
        case 0x0017: return "prodidUtc12_C_Book";
        case 0x0018: return "prodidUtc12_CPP_Book";
        case 0x0019: return "prodidImplib700";
        case 0x001a: return "prodidCvtomf700";
        case 0x001b: return "prodidUtc13_Basic";
        case 0x001c: return "prodidUtc13_C";
        case 0x001d: return "prodidUtc13_CPP";
        case 0x001e: return "prodidLinker610";
        case 0x001f: return "prodidCvtomf610";
        case 0x0020: return "prodidLinker601";
        case 0x0021: return "prodidCvtomf601";
        case 0x0022: return "prodidUtc12_1_Basic";
        case 0x0023: return "prodidUtc12_1_C";
        case 0x0024: return "prodidUtc12_1_CPP";
        case 0x0025: return "prodidLinker620";
        case 0x0026: return "prodidCvtomf620";
        case 0x0027: return "prodidAliasObj70";
        case 0x0028: return "prodidLinker621";
        case 0x0029: return "prodidCvtomf621";
        case 0x002a: return "prodidMasm615";
        case 0x002b: return "prodidUtc13_LTCG_C";
        case 0x002c: return "prodidUtc13_LTCG_CPP";
        case 0x002d: return "prodidMasm620";
        case 0x002e: return "prodidILAsm100";
        case 0x002f: return "prodidUtc12_2_Basic";
        case 0x0030: return "prodidUtc12_2_C";
        case 0x0031: return "prodidUtc12_2_CPP";
        case 0x0032: return "prodidUtc12_2_C_Std";
        case 0x0033: return "prodidUtc12_2_CPP_Std";
        case 0x0034: return "prodidUtc12_2_C_Book";
        case 0x0035: return "prodidUtc12_2_CPP_Book";
        case 0x0036: return "prodidImplib622";
        case 0x0037: return "prodidCvtomf622";
        case 0x0038: return "prodidCvtres501";
        case 0x0039: return "prodidUtc13_C_Std";
        case 0x003a: return "prodidUtc13_CPP_Std";
        case 0x003b: return "prodidCvtpgd1300";
        case 0x003c: return "prodidLinker622";
        case 0x003d: return "prodidLinker700";
        case 0x003e: return "prodidExport622";
        case 0x003f: return "prodidExport700";
        case 0x0040: return "prodidMasm700";
        case 0x0041: return "prodidUtc13_POGO_I_C";
        case 0x0042: return "prodidUtc13_POGO_I_CPP";
        case 0x0043: return "prodidUtc13_POGO_O_C";
        case 0x0044: return "prodidUtc13_POGO_O_CPP";
        case 0x0045: return "prodidCvtres700";
        case 0x0046: return "prodidCvtres710p";
        case 0x0047: return "prodidLinker710p";
        case 0x0048: return "prodidCvtomf710p";
        case 0x0049: return "prodidExport710p";
        case 0x004a: return "prodidImplib710p";
        case 0x004b: return "prodidMasm710p";
        case 0x004c: return "prodidUtc1310p_C";
        case 0x004d: return "prodidUtc1310p_CPP";
        case 0x004e: return "prodidUtc1310p_C_Std";
        case 0x004f: return "prodidUtc1310p_CPP_Std";
        case 0x0050: return "prodidUtc1310p_LTCG_C";
        case 0x0051: return "prodidUtc1310p_LTCG_CPP";
        case 0x0052: return "prodidUtc1310p_POGO_I_C";
        case 0x0053: return "prodidUtc1310p_POGO_I_CPP";
        case 0x0054: return "prodidUtc1310p_POGO_O_C";
        case 0x0055: return "prodidUtc1310p_POGO_O_CPP";
        case 0x0056: return "prodidLinker624";
        case 0x0057: return "prodidCvtomf624";
        case 0x0058: return "prodidExport624";
        case 0x0059: return "prodidImplib624";
        case 0x005a: return "prodidLinker710";
        case 0x005b: return "prodidCvtomf710";
        case 0x005c: return "prodidExport710";
        case 0x005d: return "prodidImplib710";
        case 0x005e: return "prodidCvtres710";
        case 0x005f: return "prodidUtc1310_C";
        case 0x0060: return "prodidUtc1310_CPP";
        case 0x0061: return "prodidUtc1310_C_Std";
        case 0x0062: return "prodidUtc1310_CPP_Std";
        case 0x0063: return "prodidUtc1310_LTCG_C";
        case 0x0064: return "prodidUtc1310_LTCG_CPP";
        case 0x0065: return "prodidUtc1310_POGO_I_C";
        case 0x0066: return "prodidUtc1310_POGO_I_CPP";
        case 0x0067: return "prodidUtc1310_POGO_O_C";
        case 0x0068: return "prodidUtc1310_POGO_O_CPP";
        case 0x0069: return "prodidAliasObj710";
        case 0x006a: return "prodidAliasObj710p";
        case 0x006b: return "prodidCvtpgd1310";
        case 0x006c: return "prodidCvtpgd1310p";
        case 0x006d: return "prodidUtc1400_C";
        case 0x006e: return "prodidUtc1400_CPP";
        case 0x006f: return "prodidUtc1400_C_Std";
        case 0x0070: return "prodidUtc1400_CPP_Std";
        case 0x0071: return "prodidUtc1400_LTCG_C";
        case 0x0072: return "prodidUtc1400_LTCG_CPP";
        case 0x0073: return "prodidUtc1400_POGO_I_C";
        case 0x0074: return "prodidUtc1400_POGO_I_CPP";
        case 0x0075: return "prodidUtc1400_POGO_O_C";
        case 0x0076: return "prodidUtc1400_POGO_O_CPP";
        case 0x0077: return "prodidCvtpgd1400";
        case 0x0078: return "prodidLinker800";
        case 0x0079: return "prodidCvtomf800";
        case 0x007a: return "prodidExport800";
        case 0x007b: return "prodidImplib800";
        case 0x007c: return "prodidCvtres800";
        case 0x007d: return "prodidMasm800";
        case 0x007e: return "prodidAliasObj800";
        case 0x007f: return "prodidPhoenixPrerelease";
        case 0x0080: return "prodidUtc1400_CVTCIL_C";
        case 0x0081: return "prodidUtc1400_CVTCIL_CPP";
        case 0x0082: return "prodidUtc1400_LTCG_MSIL";
        case 0x0083: return "prodidUtc1500_C";
        case 0x0084: return "prodidUtc1500_CPP";
        case 0x0085: return "prodidUtc1500_C_Std";
        case 0x0086: return "prodidUtc1500_CPP_Std";
        case 0x0087: return "prodidUtc1500_CVTCIL_C";
        case 0x0088: return "prodidUtc1500_CVTCIL_CPP";
        case 0x0089: return "prodidUtc1500_LTCG_C";
        case 0x008a: return "prodidUtc1500_LTCG_CPP";
        case 0x008b: return "prodidUtc1500_LTCG_MSIL";
        case 0x008c: return "prodidUtc1500_POGO_I_C";
        case 0x008d: return "prodidUtc1500_POGO_I_CPP";
        case 0x008e: return "prodidUtc1500_POGO_O_C";
        case 0x008f: return "prodidUtc1500_POGO_O_CPP";
        case 0x0090: return "prodidCvtpgd1500";
        case 0x0091: return "prodidLinker900";
        case 0x0092: return "prodidExport900";
        case 0x0093: return "prodidImplib900";
        case 0x0094: return "prodidCvtres900";
        case 0x0095: return "prodidMasm900";
        case 0x0096: return "prodidAliasObj900";
        case 0x0097: return "prodidResource";
        case 0x0098: return "prodidAliasObj1000";
        case 0x0099: return "prodidCvtpgd1600";
        case 0x009a: return "prodidCvtres1000";
        case 0x009b: return "prodidExport1000";
        case 0x009c: return "prodidImplib1000";
        case 0x009d: return "prodidLinker1000";
        case 0x009e: return "prodidMasm1000";
        case 0x009f: return "prodidPhx1600_C";
        case 0x00a0: return "prodidPhx1600_CPP";
        case 0x00a1: return "prodidPhx1600_CVTCIL_C";
        case 0x00a2: return "prodidPhx1600_CVTCIL_CPP";
        case 0x00a3: return "prodidPhx1600_LTCG_C";
        case 0x00a4: return "prodidPhx1600_LTCG_CPP";
        case 0x00a5: return "prodidPhx1600_LTCG_MSIL";
        case 0x00a6: return "prodidPhx1600_POGO_I_C";
        case 0x00a7: return "prodidPhx1600_POGO_I_CPP";
        case 0x00a8: return "prodidPhx1600_POGO_O_C";
        case 0x00a9: return "prodidPhx1600_POGO_O_CPP";
        case 0x00aa: return "prodidUtc1600_C";
        case 0x00ab: return "prodidUtc1600_CPP";
        case 0x00ac: return "prodidUtc1600_CVTCIL_C";
        case 0x00ad: return "prodidUtc1600_CVTCIL_CPP";
        case 0x00ae: return "prodidUtc1600_LTCG_C";
        case 0x00af: return "prodidUtc1600_LTCG_CPP";
        case 0x00b0: return "prodidUtc1600_LTCG_MSIL";
        case 0x00b1: return "prodidUtc1600_POGO_I_C";
        case 0x00b2: return "prodidUtc1600_POGO_I_CPP";
        case 0x00b3: return "prodidUtc1600_POGO_O_C";
        case 0x00b4: return "prodidUtc1600_POGO_O_CPP";
        case 0x00b5: return "prodidAliasObj1010";
        case 0x00b6: return "prodidCvtpgd1610";
        case 0x00b7: return "prodidCvtres1010";
        case 0x00b8: return "prodidExport1010";
        case 0x00b9: return "prodidImplib1010";
        case 0x00ba: return "prodidLinker1010";
        case 0x00bb: return "prodidMasm1010";
        case 0x00bc: return "prodidUtc1610_C";
        case 0x00bd: return "prodidUtc1610_CPP";
        case 0x00be: return "prodidUtc1610_CVTCIL_C";
        case 0x00bf: return "prodidUtc1610_CVTCIL_CPP";
        case 0x00c0: return "prodidUtc1610_LTCG_C";
        case 0x00c1: return "prodidUtc1610_LTCG_CPP";
        case 0x00c2: return "prodidUtc1610_LTCG_MSIL";
        case 0x00c3: return "prodidUtc1610_POGO_I_C";
        case 0x00c4: return "prodidUtc1610_POGO_I_CPP";
        case 0x00c5: return "prodidUtc1610_POGO_O_C";
        case 0x00c6: return "prodidUtc1610_POGO_O_CPP";
        case 0x00c7: return "prodidAliasObj1100";
        case 0x00c8: return "prodidCvtpgd1700";
        case 0x00c9: return "prodidCvtres1100";
        case 0x00ca: return "prodidExport1100";
        case 0x00cb: return "prodidImplib1100";
        case 0x00cc: return "prodidLinker1100";
        case 0x00cd: return "prodidMasm1100";
        case 0x00ce: return "prodidUtc1700_C";
        case 0x00cf: return "prodidUtc1700_CPP";
        case 0x00d0: return "prodidUtc1700_CVTCIL_C";
        case 0x00d1: return "prodidUtc1700_CVTCIL_CPP";
        case 0x00d2: return "prodidUtc1700_LTCG_C";
        case 0x00d3: return "prodidUtc1700_LTCG_CPP";
        case 0x00d4: return "prodidUtc1700_LTCG_MSIL";
        case 0x00d5: return "prodidUtc1700_POGO_I_C";
        case 0x00d6: return "prodidUtc1700_POGO_I_CPP";
        case 0x00d7: return "prodidUtc1700_POGO_O_C";
        case 0x00d8: return "prodidUtc1700_POGO_O_CPP";
        case 0x00d9: return "prodidAliasObj1200";
        case 0x00da: return "prodidCvtpgd1800";
        case 0x00db: return "prodidCvtres1200";
        case 0x00dc: return "prodidExport1200";
        case 0x00dd: return "prodidImplib1200";
        case 0x00de: return "prodidLinker1200";
        case 0x00df: return "prodidMasm1200";
        case 0x00e0: return "prodidUtc1800_C";
        case 0x00e1: return "prodidUtc1800_CPP";
        case 0x00e2: return "prodidUtc1800_CVTCIL_C";
        case 0x00e3: return "prodidUtc1800_CVTCIL_CPP";
        case 0x00e4: return "prodidUtc1800_LTCG_C";
        case 0x00e5: return "prodidUtc1800_LTCG_CPP";
        case 0x00e6: return "prodidUtc1800_LTCG_MSIL";
        case 0x00e7: return "prodidUtc1800_POGO_I_C";
        case 0x00e8: return "prodidUtc1800_POGO_I_CPP";
        case 0x00e9: return "prodidUtc1800_POGO_O_C";
        case 0x00ea: return "prodidUtc1800_POGO_O_CPP";
        case 0x00eb: return "prodidAliasObj1210";
        case 0x00ec: return "prodidCvtpgd1810";
        case 0x00ed: return "prodidCvtres1210";
        case 0x00ee: return "prodidExport1210";
        case 0x00ef: return "prodidImplib1210";
        case 0x00f0: return "prodidLinker1210";
        case 0x00f1: return "prodidMasm1210";
        case 0x00f2: return "prodidUtc1810_C";
        case 0x00f3: return "prodidUtc1810_CPP";
        case 0x00f4: return "prodidUtc1810_CVTCIL_C";
        case 0x00f5: return "prodidUtc1810_CVTCIL_CPP";
        case 0x00f6: return "prodidUtc1810_LTCG_C";
        case 0x00f7: return "prodidUtc1810_LTCG_CPP";
        case 0x00f8: return "prodidUtc1810_LTCG_MSIL";
        case 0x00f9: return "prodidUtc1810_POGO_I_C";
        case 0x00fa: return "prodidUtc1810_POGO_I_CPP";
        case 0x00fb: return "prodidUtc1810_POGO_O_C";
        case 0x00fc: return "prodidUtc1810_POGO_O_CPP";
        case 0x00fd: return "prodidAliasObj1400";
        case 0x00fe: return "prodidCvtpgd1900";
        case 0x00ff: return "prodidCvtres1400";
        case 0x0100: return "prodidExport1400";
        case 0x0101: return "prodidImplib1400";
        case 0x0102: return "prodidLinker1400";
        case 0x0103: return "prodidMasm1400";
        case 0x0104: return "prodidUtc1900_C";
        case 0x0105: return "prodidUtc1900_CPP";
        case 0x0106: return "prodidUtc1900_CVTCIL_C";
        case 0x0107: return "prodidUtc1900_CVTCIL_CPP";
        case 0x0108: return "prodidUtc1900_LTCG_C";
        case 0x0109: return "prodidUtc1900_LTCG_CPP";
        case 0x010a: return "prodidUtc1900_LTCG_MSIL";
        case 0x010b: return "prodidUtc1900_POGO_I_C";
        case 0x010c: return "prodidUtc1900_POGO_I_CPP";
        case 0x010d: return "prodidUtc1900_POGO_O_C";
        case 0x010e: return "prodidUtc1900_POGO_O_CPP";
        default: return "";
    }
}

// Data used from RichPrint by dishather (https://github.com/dishather)
// Copyright (c) 2015-2024 dishather
// Redistribution and use of this data permitted under the BSD-style license
const char* GetRichCompIdString(DWORD comp_id) {

    switch(comp_id){
        // MSVS2022 v17.14.15
        case 0x01048991: return "[ C ] VS2022 v17.14.15 build 35217";
        case 0x01038991: return "[ASM] VS2022 v17.14.15 build 35217";
        case 0x01058991: return "[C++] VS2022 v17.14.15 build 35217";
        case 0x00ff8991: return "[RES] VS2022 v17.14.15 build 35217";
        case 0x01028991: return "[LNK] VS2022 v17.14.15 build 35217";
        case 0x01008991: return "[EXP] VS2022 v17.14.15 build 35217";
        case 0x01018991: return "[IMP] VS2022 v17.14.15 build 35217";
        case 0x01088991: return "[LTC] VS2022 v17.14.15 build 35217";
        case 0x01098991: return "[LT+] VS2022 v17.14.15 build 35217";
        case 0x010b8991: return "[PGO] VS2022 v17.14.15 build 35217";
        case 0x010c8991: return "[PG+] VS2022 v17.14.15 build 35217";
        case 0x01068991: return "[CIL] VS2022 v17.14.15 build 35217 (*)";
        case 0x01078991: return "[CI+] VS2022 v17.14.15 build 35217 (*)";
        case 0x010a8991: return "[LTM] VS2022 v17.14.15 build 35217 (*)";
        case 0x010d8991: return "[POC] VS2022 v17.14.15 build 35217 (*)";
        case 0x010e8991: return "[PO+] VS2022 v17.14.15 build 35217 (*)";

        // MSVS2022 v17.14.13
        // MSVS2022 v17.14.13-pre.1.0
        case 0x0104898f: return "[ C ] VS2022 v17.14.13 build 35215";
        case 0x0103898f: return "[ASM] VS2022 v17.14.13 build 35215";
        case 0x0105898f: return "[C++] VS2022 v17.14.13 build 35215";
        case 0x00ff898f: return "[RES] VS2022 v17.14.13 build 35215";
        case 0x0102898f: return "[LNK] VS2022 v17.14.13 build 35215";
        case 0x0100898f: return "[EXP] VS2022 v17.14.13 build 35215";
        case 0x0101898f: return "[IMP] VS2022 v17.14.13 build 35215";
        case 0x0108898f: return "[LTC] VS2022 v17.14.13 build 35215";
        case 0x0109898f: return "[LT+] VS2022 v17.14.13 build 35215";
        case 0x010b898f: return "[PGO] VS2022 v17.14.13 build 35215";
        case 0x010c898f: return "[PG+] VS2022 v17.14.13 build 35215";
        case 0x0106898f: return "[CIL] VS2022 v17.14.13 build 35215 (*)";
        case 0x0107898f: return "[CI+] VS2022 v17.14.13 build 35215 (*)";
        case 0x010a898f: return "[LTM] VS2022 v17.14.13 build 35215 (*)";
        case 0x010d898f: return "[POC] VS2022 v17.14.13 build 35215 (*)";
        case 0x010e898f: return "[PO+] VS2022 v17.14.13 build 35215 (*)";

        // MSVS2022 v17.14.11
        // MSVS2022 v17.14.11-pre.1.0
        // MSVS2022 v17.14.12-pre.1.0
        // MSVS2022 v17.14.12
        case 0x0104898e: return "[ C ] VS2022 v17.14.11 build 35214";
        case 0x0103898e: return "[ASM] VS2022 v17.14.11 build 35214";
        case 0x0105898e: return "[C++] VS2022 v17.14.11 build 35214";
        case 0x00ff898e: return "[RES] VS2022 v17.14.11 build 35214";
        case 0x0102898e: return "[LNK] VS2022 v17.14.11 build 35214";
        case 0x0100898e: return "[EXP] VS2022 v17.14.11 build 35214";
        case 0x0101898e: return "[IMP] VS2022 v17.14.11 build 35214";
        case 0x0108898e: return "[LTC] VS2022 v17.14.11 build 35214";
        case 0x0109898e: return "[LT+] VS2022 v17.14.11 build 35214";
        case 0x010b898e: return "[PGO] VS2022 v17.14.11 build 35214";
        case 0x010c898e: return "[PG+] VS2022 v17.14.11 build 35214";
        case 0x0106898e: return "[CIL] VS2022 v17.14.11 build 35214 (*)";
        case 0x0107898e: return "[CI+] VS2022 v17.14.11 build 35214 (*)";
        case 0x010a898e: return "[LTM] VS2022 v17.14.11 build 35214 (*)";
        case 0x010d898e: return "[POC] VS2022 v17.14.11 build 35214 (*)";
        case 0x010e898e: return "[PO+] VS2022 v17.14.11 build 35214 (*)";

        // MSVS2022 v17.14.9
        // MSVS2022 v17.14.9-pre.1.0
        // MSVS2022 v17.14.10
        // MSVS2022 v17.14.10-pre.1.0
        case 0x0104898d: return "[ C ] VS2022 v17.14.9 build 35213";
        case 0x0103898d: return "[ASM] VS2022 v17.14.9 build 35213";
        case 0x0105898d: return "[C++] VS2022 v17.14.9 build 35213";
        case 0x00ff898d: return "[RES] VS2022 v17.14.9 build 35213";
        case 0x0102898d: return "[LNK] VS2022 v17.14.9 build 35213";
        case 0x0100898d: return "[EXP] VS2022 v17.14.9 build 35213";
        case 0x0101898d: return "[IMP] VS2022 v17.14.9 build 35213";
        case 0x0108898d: return "[LTC] VS2022 v17.14.9 build 35213";
        case 0x0109898d: return "[LT+] VS2022 v17.14.9 build 35213";
        case 0x010b898d: return "[PGO] VS2022 v17.14.9 build 35213";
        case 0x010c898d: return "[PG+] VS2022 v17.14.9 build 35213";
        case 0x0106898d: return "[CIL] VS2022 v17.14.9 build 35213 (*)";
        case 0x0107898d: return "[CI+] VS2022 v17.14.9 build 35213 (*)";
        case 0x010a898d: return "[LTM] VS2022 v17.14.9 build 35213 (*)";
        case 0x010d898d: return "[POC] VS2022 v17.14.9 build 35213 (*)";
        case 0x010e898d: return "[PO+] VS2022 v17.14.9 build 35213 (*)";

        // MSVS2022 v17.14.4
        // MSVS2022 v17.14.4-pre.1.0
        // MSVS2022 v17.14.5
        // MSVS2022 v17.14.5-pre.1.0
        case 0x01048989: return "[ C ] VS2022 v17.14.4 build 35209";
        case 0x01038989: return "[ASM] VS2022 v17.14.4 build 35209";
        case 0x01058989: return "[C++] VS2022 v17.14.4 build 35209";
        case 0x00ff8989: return "[RES] VS2022 v17.14.4 build 35209";
        case 0x01028989: return "[LNK] VS2022 v17.14.4 build 35209";
        case 0x01008989: return "[EXP] VS2022 v17.14.4 build 35209";
        case 0x01018989: return "[IMP] VS2022 v17.14.4 build 35209";
        case 0x01088989: return "[LTC] VS2022 v17.14.4 build 35209";
        case 0x01098989: return "[LT+] VS2022 v17.14.4 build 35209";
        case 0x010b8989: return "[PGO] VS2022 v17.14.4 build 35209";
        case 0x010c8989: return "[PG+] VS2022 v17.14.4 build 35209";
        case 0x01068989: return "[CIL] VS2022 v17.14.4 build 35209 (*)";
        case 0x01078989: return "[CI+] VS2022 v17.14.4 build 35209 (*)";
        case 0x010a8989: return "[LTM] VS2022 v17.14.4 build 35209 (*)";
        case 0x010d8989: return "[POC] VS2022 v17.14.4 build 35209 (*)";
        case 0x010e8989: return "[PO+] VS2022 v17.14.4 build 35209 (*)";

        // MSVS2022 v17.13.6
        case 0x010487fa: return "[ C ] VS2022 v17.13.6 build 34810";
        case 0x010387fa: return "[ASM] VS2022 v17.13.6 build 34810";
        case 0x010587fa: return "[C++] VS2022 v17.13.6 build 34810";
        case 0x00ff87fa: return "[RES] VS2022 v17.13.6 build 34810";
        case 0x010287fa: return "[LNK] VS2022 v17.13.6 build 34810";
        case 0x010087fa: return "[EXP] VS2022 v17.13.6 build 34810";
        case 0x010187fa: return "[IMP] VS2022 v17.13.6 build 34810";
        case 0x010887fa: return "[LTC] VS2022 v17.13.6 build 34810";
        case 0x010987fa: return "[LT+] VS2022 v17.13.6 build 34810";
        case 0x010b87fa: return "[PGO] VS2022 v17.13.6 build 34810";
        case 0x010c87fa: return "[PG+] VS2022 v17.13.6 build 34810";
        case 0x010687fa: return "[CIL] VS2022 v17.13.6 build 34810 (*)";
        case 0x010787fa: return "[CI+] VS2022 v17.13.6 build 34810 (*)";
        case 0x010a87fa: return "[LTM] VS2022 v17.13.6 build 34810 (*)";
        case 0x010d87fa: return "[POC] VS2022 v17.13.6 build 34810 (*)";
        case 0x010e87fa: return "[PO+] VS2022 v17.13.6 build 34810 (*)";

        // MSVS2022 v17.13.3
        // MSVS2022 v17.13.4
        // MSVS2022 v17.13.5
        case 0x010487f9: return "[ C ] VS2022 v17.13.3 build 34809";
        case 0x010387f9: return "[ASM] VS2022 v17.13.3 build 34809";
        case 0x010587f9: return "[C++] VS2022 v17.13.3 build 34809";
        case 0x00ff87f9: return "[RES] VS2022 v17.13.3 build 34809";
        case 0x010287f9: return "[LNK] VS2022 v17.13.3 build 34809";
        case 0x010087f9: return "[EXP] VS2022 v17.13.3 build 34809";
        case 0x010187f9: return "[IMP] VS2022 v17.13.3 build 34809";
        case 0x010887f9: return "[LTC] VS2022 v17.13.3 build 34809";
        case 0x010987f9: return "[LT+] VS2022 v17.13.3 build 34809";
        case 0x010b87f9: return "[PGO] VS2022 v17.13.3 build 34809";
        case 0x010c87f9: return "[PG+] VS2022 v17.13.3 build 34809";
        case 0x010687f9: return "[CIL] VS2022 v17.13.3 build 34809 (*)";
        case 0x010787f9: return "[CI+] VS2022 v17.13.3 build 34809 (*)";
        case 0x010a87f9: return "[LTM] VS2022 v17.13.3 build 34809 (*)";
        case 0x010d87f9: return "[POC] VS2022 v17.13.3 build 34809 (*)";
        case 0x010e87f9: return "[PO+] VS2022 v17.13.3 build 34809 (*)";

        // MSVS2022 v17.12.4
        case 0x01048684: return "[ C ] VS2022 v17.12.4 build 34436";
        case 0x01038684: return "[ASM] VS2022 v17.12.4 build 34436";
        case 0x01058684: return "[C++] VS2022 v17.12.4 build 34436";
        case 0x00ff8684: return "[RES] VS2022 v17.12.4 build 34436";
        case 0x01028684: return "[LNK] VS2022 v17.12.4 build 34436";
        case 0x01008684: return "[EXP] VS2022 v17.12.4 build 34436";
        case 0x01018684: return "[IMP] VS2022 v17.12.4 build 34436";
        case 0x01088684: return "[LTC] VS2022 v17.12.4 build 34436";
        case 0x01098684: return "[LT+] VS2022 v17.12.4 build 34436";
        case 0x010b8684: return "[PGO] VS2022 v17.12.4 build 34436";
        case 0x010c8684: return "[PG+] VS2022 v17.12.4 build 34436";
        case 0x01068684: return "[CIL] VS2022 v17.12.4 build 34436 (*)";
        case 0x01078684: return "[CI+] VS2022 v17.12.4 build 34436 (*)";
        case 0x010a8684: return "[LTM] VS2022 v17.12.4 build 34436 (*)";
        case 0x010d8684: return "[POC] VS2022 v17.12.4 build 34436 (*)";
        case 0x010e8684: return "[PO+] VS2022 v17.12.4 build 34436 (*)";

        // MSVS2022 v17.12.2
        // MSVS2022 v17.12.3
        case 0x01048683: return "[ C ] VS2022 v17.12.2 build 34435";
        case 0x01038683: return "[ASM] VS2022 v17.12.2 build 34435";
        case 0x01058683: return "[C++] VS2022 v17.12.2 build 34435";
        case 0x00ff8683: return "[RES] VS2022 v17.12.2 build 34435";
        case 0x01028683: return "[LNK] VS2022 v17.12.2 build 34435";
        case 0x01008683: return "[EXP] VS2022 v17.12.2 build 34435";
        case 0x01018683: return "[IMP] VS2022 v17.12.2 build 34435";
        case 0x01088683: return "[LTC] VS2022 v17.12.2 build 34435";
        case 0x01098683: return "[LT+] VS2022 v17.12.2 build 34435";
        case 0x010b8683: return "[PGO] VS2022 v17.12.2 build 34435";
        case 0x010c8683: return "[PG+] VS2022 v17.12.2 build 34435";
        case 0x01068683: return "[CIL] VS2022 v17.12.2 build 34435 (*)";
        case 0x01078683: return "[CI+] VS2022 v17.12.2 build 34435 (*)";
        case 0x010a8683: return "[LTM] VS2022 v17.12.2 build 34435 (*)";
        case 0x010d8683: return "[POC] VS2022 v17.12.2 build 34435 (*)";
        case 0x010e8683: return "[PO+] VS2022 v17.12.2 build 34435 (*)";

        // MSVS2022 v17.12.0
        // MSVS2022 v17.12.1
        case 0x01048681: return "[ C ] VS2022 v17.12.0 build 34433";
        case 0x01038681: return "[ASM] VS2022 v17.12.0 build 34433";
        case 0x01058681: return "[C++] VS2022 v17.12.0 build 34433";
        case 0x00ff8681: return "[RES] VS2022 v17.12.0 build 34433";
        case 0x01028681: return "[LNK] VS2022 v17.12.0 build 34433";
        case 0x01008681: return "[EXP] VS2022 v17.12.0 build 34433";
        case 0x01018681: return "[IMP] VS2022 v17.12.0 build 34433";
        case 0x01088681: return "[LTC] VS2022 v17.12.0 build 34433";
        case 0x01098681: return "[LT+] VS2022 v17.12.0 build 34433";
        case 0x010b8681: return "[PGO] VS2022 v17.12.0 build 34433";
        case 0x010c8681: return "[PG+] VS2022 v17.12.0 build 34433";
        case 0x01068681: return "[CIL] VS2022 v17.12.0 build 34433 (*)";
        case 0x01078681: return "[CI+] VS2022 v17.12.0 build 34433 (*)";
        case 0x010a8681: return "[LTM] VS2022 v17.12.0 build 34433 (*)";
        case 0x010d8681: return "[POC] VS2022 v17.12.0 build 34433 (*)";
        case 0x010e8681: return "[PO+] VS2022 v17.12.0 build 34433 (*)";

        // MSVS2022 v17.11.5
        case 0x0104854b: return "[ C ] VS2022 v17.11.5 build 34123";
        case 0x0103854b: return "[ASM] VS2022 v17.11.5 build 34123";
        case 0x0105854b: return "[C++] VS2022 v17.11.5 build 34123";
        case 0x00ff854b: return "[RES] VS2022 v17.11.5 build 34123";
        case 0x0102854b: return "[LNK] VS2022 v17.11.5 build 34123";
        case 0x0100854b: return "[EXP] VS2022 v17.11.5 build 34123";
        case 0x0101854b: return "[IMP] VS2022 v17.11.5 build 34123";
        case 0x0108854b: return "[LTC] VS2022 v17.11.5 build 34123";
        case 0x0109854b: return "[LT+] VS2022 v17.11.5 build 34123";
        case 0x010b854b: return "[PGO] VS2022 v17.11.5 build 34123";
        case 0x010c854b: return "[PG+] VS2022 v17.11.5 build 34123";
        case 0x0106854b: return "[CIL] VS2022 v17.11.5 build 34123 (*)";
        case 0x0107854b: return "[CI+] VS2022 v17.11.5 build 34123 (*)";
        case 0x010a854b: return "[LTM] VS2022 v17.11.5 build 34123 (*)";
        case 0x010d854b: return "[POC] VS2022 v17.11.5 build 34123 (*)";
        case 0x010e854b: return "[PO+] VS2022 v17.11.5 build 34123 (*)";

        // MSVS2022 v17.11.0
        // MSVS2022 v17.11.1
        // MSVS2022 v17.11.2
        // MSVS2022 v17.11.3
        // MSVS2022 v17.11.4
        case 0x01048548: return "[ C ] VS2022 v17.11.0 build 34120";
        case 0x01038548: return "[ASM] VS2022 v17.11.0 build 34120";
        case 0x01058548: return "[C++] VS2022 v17.11.0 build 34120";
        case 0x00ff8548: return "[RES] VS2022 v17.11.0 build 34120";
        case 0x01028548: return "[LNK] VS2022 v17.11.0 build 34120";
        case 0x01008548: return "[EXP] VS2022 v17.11.0 build 34120";
        case 0x01018548: return "[IMP] VS2022 v17.11.0 build 34120";
        case 0x01088548: return "[LTC] VS2022 v17.11.0 build 34120";
        case 0x01098548: return "[LT+] VS2022 v17.11.0 build 34120";
        case 0x010b8548: return "[PGO] VS2022 v17.11.0 build 34120";
        case 0x010c8548: return "[PG+] VS2022 v17.11.0 build 34120";
        case 0x01068548: return "[CIL] VS2022 v17.11.0 build 34120 (*)";
        case 0x01078548: return "[CI+] VS2022 v17.11.0 build 34120 (*)";
        case 0x010a8548: return "[LTM] VS2022 v17.11.0 build 34120 (*)";
        case 0x010d8548: return "[POC] VS2022 v17.11.0 build 34120 (*)";
        case 0x010e8548: return "[PO+] VS2022 v17.11.0 build 34120 (*)";

        // MSVS2022 v17.10.5
        case 0x01048415: return "[ C ] VS2022 v17.10.5 build 33813";
        case 0x01038415: return "[ASM] VS2022 v17.10.5 build 33813";
        case 0x01058415: return "[C++] VS2022 v17.10.5 build 33813";
        case 0x00ff8415: return "[RES] VS2022 v17.10.5 build 33813";
        case 0x01028415: return "[LNK] VS2022 v17.10.5 build 33813";
        case 0x01008415: return "[EXP] VS2022 v17.10.5 build 33813";
        case 0x01018415: return "[IMP] VS2022 v17.10.5 build 33813";
        case 0x01088415: return "[LTC] VS2022 v17.10.5 build 33813";
        case 0x01098415: return "[LT+] VS2022 v17.10.5 build 33813";
        case 0x010b8415: return "[PGO] VS2022 v17.10.5 build 33813";
        case 0x010c8415: return "[PG+] VS2022 v17.10.5 build 33813";
        case 0x01068415: return "[CIL] VS2022 v17.10.5 build 33813 (*)";
        case 0x01078415: return "[CI+] VS2022 v17.10.5 build 33813 (*)";
        case 0x010a8415: return "[LTM] VS2022 v17.10.5 build 33813 (*)";
        case 0x010d8415: return "[POC] VS2022 v17.10.5 build 33813 (*)";
        case 0x010e8415: return "[PO+] VS2022 v17.10.5 build 33813 (*)";

        // MSVS2022 v17.10.4
        case 0x01048414: return "[ C ] VS2022 v17.10.4 build 33812";
        case 0x01038414: return "[ASM] VS2022 v17.10.4 build 33812";
        case 0x01058414: return "[C++] VS2022 v17.10.4 build 33812";
        case 0x00ff8414: return "[RES] VS2022 v17.10.4 build 33812";
        case 0x01028414: return "[LNK] VS2022 v17.10.4 build 33812";
        case 0x01008414: return "[EXP] VS2022 v17.10.4 build 33812";
        case 0x01018414: return "[IMP] VS2022 v17.10.4 build 33812";
        case 0x01088414: return "[LTC] VS2022 v17.10.4 build 33812";
        case 0x01098414: return "[LT+] VS2022 v17.10.4 build 33812";
        case 0x010b8414: return "[PGO] VS2022 v17.10.4 build 33812";
        case 0x010c8414: return "[PG+] VS2022 v17.10.4 build 33812";
        case 0x01068414: return "[CIL] VS2022 v17.10.4 build 33812 (*)";
        case 0x01078414: return "[CI+] VS2022 v17.10.4 build 33812 (*)";
        case 0x010a8414: return "[LTM] VS2022 v17.10.4 build 33812 (*)";
        case 0x010d8414: return "[POC] VS2022 v17.10.4 build 33812 (*)";
        case 0x010e8414: return "[PO+] VS2022 v17.10.4 build 33812 (*)";

        // MSVS2022 v17.10.1
        // MSVS2022 v17.10.2
        // MSVS2022 v17.10.3
        case 0x01048413: return "[ C ] VS2022 v17.10.1 build 33811";
        case 0x01038413: return "[ASM] VS2022 v17.10.1 build 33811";
        case 0x01058413: return "[C++] VS2022 v17.10.1 build 33811";
        case 0x00ff8413: return "[RES] VS2022 v17.10.1 build 33811";
        case 0x01028413: return "[LNK] VS2022 v17.10.1 build 33811";
        case 0x01008413: return "[EXP] VS2022 v17.10.1 build 33811";
        case 0x01018413: return "[IMP] VS2022 v17.10.1 build 33811";
        case 0x01088413: return "[LTC] VS2022 v17.10.1 build 33811";
        case 0x01098413: return "[LT+] VS2022 v17.10.1 build 33811";
        case 0x010b8413: return "[PGO] VS2022 v17.10.1 build 33811";
        case 0x010c8413: return "[PG+] VS2022 v17.10.1 build 33811";
        case 0x01068413: return "[CIL] VS2022 v17.10.1 build 33811 (*)";
        case 0x01078413: return "[CI+] VS2022 v17.10.1 build 33811 (*)";
        case 0x010a8413: return "[LTM] VS2022 v17.10.1 build 33811 (*)";
        case 0x010d8413: return "[POC] VS2022 v17.10.1 build 33811 (*)";
        case 0x010e8413: return "[PO+] VS2022 v17.10.1 build 33811 (*)";

        // MSVS2022 v17.9.4
        // MSVS2022 v17.9.5
        // MSVS2022 v17.9.6
        // MSVS2022 v17.9.7
        case 0x010482f3: return "[ C ] VS2022 v17.9.4 build 33523";
        case 0x010382f3: return "[ASM] VS2022 v17.9.4 build 33523";
        case 0x010582f3: return "[C++] VS2022 v17.9.4 build 33523";
        case 0x00ff82f3: return "[RES] VS2022 v17.9.4 build 33523";
        case 0x010282f3: return "[LNK] VS2022 v17.9.4 build 33523";
        case 0x010082f3: return "[EXP] VS2022 v17.9.4 build 33523";
        case 0x010182f3: return "[IMP] VS2022 v17.9.4 build 33523";
        case 0x010882f3: return "[LTC] VS2022 v17.9.4 build 33523";
        case 0x010982f3: return "[LT+] VS2022 v17.9.4 build 33523";
        case 0x010b82f3: return "[PGO] VS2022 v17.9.4 build 33523";
        case 0x010c82f3: return "[PG+] VS2022 v17.9.4 build 33523";
        case 0x010682f3: return "[CIL] VS2022 v17.9.4 build 33523 (*)";
        case 0x010782f3: return "[CI+] VS2022 v17.9.4 build 33523 (*)";
        case 0x010a82f3: return "[LTM] VS2022 v17.9.4 build 33523 (*)";
        case 0x010d82f3: return "[POC] VS2022 v17.9.4 build 33523 (*)";
        case 0x010e82f3: return "[PO+] VS2022 v17.9.4 build 33523 (*)";

        // MSVS2022 v17.9.3
        case 0x010482f2: return "[ C ] VS2022 v17.9.3 build 33522";
        case 0x010382f2: return "[ASM] VS2022 v17.9.3 build 33522";
        case 0x010582f2: return "[C++] VS2022 v17.9.3 build 33522";
        case 0x00ff82f2: return "[RES] VS2022 v17.9.3 build 33522";
        case 0x010282f2: return "[LNK] VS2022 v17.9.3 build 33522";
        case 0x010082f2: return "[EXP] VS2022 v17.9.3 build 33522";
        case 0x010182f2: return "[IMP] VS2022 v17.9.3 build 33522";
        case 0x010882f2: return "[LTC] VS2022 v17.9.3 build 33522";
        case 0x010982f2: return "[LT+] VS2022 v17.9.3 build 33522";
        case 0x010b82f2: return "[PGO] VS2022 v17.9.3 build 33522";
        case 0x010c82f2: return "[PG+] VS2022 v17.9.3 build 33522";
        case 0x010682f2: return "[CIL] VS2022 v17.9.3 build 33522 (*)";
        case 0x010782f2: return "[CI+] VS2022 v17.9.3 build 33522 (*)";
        case 0x010a82f2: return "[LTM] VS2022 v17.9.3 build 33522 (*)";
        case 0x010d82f2: return "[POC] VS2022 v17.9.3 build 33522 (*)";
        case 0x010e82f2: return "[PO+] VS2022 v17.9.3 build 33522 (*)";

        // MSVS2022 v17.9.1
        case 0x010482f0: return "[ C ] VS2022 v17.9.1 build 33520";
        case 0x010382f0: return "[ASM] VS2022 v17.9.1 build 33520";
        case 0x010582f0: return "[C++] VS2022 v17.9.1 build 33520";
        case 0x00ff82f0: return "[RES] VS2022 v17.9.1 build 33520";
        case 0x010282f0: return "[LNK] VS2022 v17.9.1 build 33520";
        case 0x010082f0: return "[EXP] VS2022 v17.9.1 build 33520";
        case 0x010182f0: return "[IMP] VS2022 v17.9.1 build 33520";
        case 0x010882f0: return "[LTC] VS2022 v17.9.1 build 33520";
        case 0x010982f0: return "[LT+] VS2022 v17.9.1 build 33520";
        case 0x010b82f0: return "[PGO] VS2022 v17.9.1 build 33520";
        case 0x010c82f0: return "[PG+] VS2022 v17.9.1 build 33520";
        case 0x010682f0: return "[CIL] VS2022 v17.9.1 build 33520 (*)";
        case 0x010782f0: return "[CI+] VS2022 v17.9.1 build 33520 (*)";
        case 0x010a82f0: return "[LTM] VS2022 v17.9.1 build 33520 (*)";
        case 0x010d82f0: return "[POC] VS2022 v17.9.1 build 33520 (*)";
        case 0x010e82f0: return "[PO+] VS2022 v17.9.1 build 33520 (*)";

        // MSVS2022 v17.8.6
        case 0x0104816f: return "[ C ] VS2022 v17.8.6 build 33135";
        case 0x0103816f: return "[ASM] VS2022 v17.8.6 build 33135";
        case 0x0105816f: return "[C++] VS2022 v17.8.6 build 33135";
        case 0x00ff816f: return "[RES] VS2022 v17.8.6 build 33135";
        case 0x0102816f: return "[LNK] VS2022 v17.8.6 build 33135";
        case 0x0100816f: return "[EXP] VS2022 v17.8.6 build 33135";
        case 0x0101816f: return "[IMP] VS2022 v17.8.6 build 33135";
        case 0x0108816f: return "[LTC] VS2022 v17.8.6 build 33135";
        case 0x0109816f: return "[LT+] VS2022 v17.8.6 build 33135";
        case 0x010b816f: return "[PGO] VS2022 v17.8.6 build 33135";
        case 0x010c816f: return "[PG+] VS2022 v17.8.6 build 33135";
        case 0x0106816f: return "[CIL] VS2022 v17.8.6 build 33135 (*)";
        case 0x0107816f: return "[CI+] VS2022 v17.8.6 build 33135 (*)";
        case 0x010a816f: return "[LTM] VS2022 v17.8.6 build 33135 (*)";
        case 0x010d816f: return "[POC] VS2022 v17.8.6 build 33135 (*)";
        case 0x010e816f: return "[PO+] VS2022 v17.8.6 build 33135 (*)";

        // MSVS2022 v17.8.4
        // MSVS2022 v17.8.5
        case 0x0104816e: return "[ C ] VS2022 v17.8.4 build 33134";
        case 0x0103816e: return "[ASM] VS2022 v17.8.4 build 33134";
        case 0x0105816e: return "[C++] VS2022 v17.8.4 build 33134";
        case 0x00ff816e: return "[RES] VS2022 v17.8.4 build 33134";
        case 0x0102816e: return "[LNK] VS2022 v17.8.4 build 33134";
        case 0x0100816e: return "[EXP] VS2022 v17.8.4 build 33134";
        case 0x0101816e: return "[IMP] VS2022 v17.8.4 build 33134";
        case 0x0108816e: return "[LTC] VS2022 v17.8.4 build 33134";
        case 0x0109816e: return "[LT+] VS2022 v17.8.4 build 33134";
        case 0x010b816e: return "[PGO] VS2022 v17.8.4 build 33134";
        case 0x010c816e: return "[PG+] VS2022 v17.8.4 build 33134";
        case 0x0106816e: return "[CIL] VS2022 v17.8.4 build 33134 (*)";
        case 0x0107816e: return "[CI+] VS2022 v17.8.4 build 33134 (*)";
        case 0x010a816e: return "[LTM] VS2022 v17.8.4 build 33134 (*)";
        case 0x010d816e: return "[POC] VS2022 v17.8.4 build 33134 (*)";
        case 0x010e816e: return "[PO+] VS2022 v17.8.4 build 33134 (*)";

        // MSVS2022 v17.8.3
        case 0x0104816d: return "[ C ] VS2022 v17.8.3 build 33133";
        case 0x0103816d: return "[ASM] VS2022 v17.8.3 build 33133";
        case 0x0105816d: return "[C++] VS2022 v17.8.3 build 33133";
        case 0x00ff816d: return "[RES] VS2022 v17.8.3 build 33133";
        case 0x0102816d: return "[LNK] VS2022 v17.8.3 build 33133";
        case 0x0100816d: return "[EXP] VS2022 v17.8.3 build 33133";
        case 0x0101816d: return "[IMP] VS2022 v17.8.3 build 33133";
        case 0x0108816d: return "[LTC] VS2022 v17.8.3 build 33133";
        case 0x0109816d: return "[LT+] VS2022 v17.8.3 build 33133";
        case 0x010b816d: return "[PGO] VS2022 v17.8.3 build 33133";
        case 0x010c816d: return "[PG+] VS2022 v17.8.3 build 33133";
        case 0x0106816d: return "[CIL] VS2022 v17.8.3 build 33133 (*)";
        case 0x0107816d: return "[CI+] VS2022 v17.8.3 build 33133 (*)";
        case 0x010a816d: return "[LTM] VS2022 v17.8.3 build 33133 (*)";
        case 0x010d816d: return "[POC] VS2022 v17.8.3 build 33133 (*)";
        case 0x010e816d: return "[PO+] VS2022 v17.8.3 build 33133 (*)";

        // MSVS2022 v17.8.0
        // MSVS2022 v17.8.1
        // MSVS2022 v17.8.2
        case 0x0104816a: return "[ C ] VS2022 v17.8.0 build 33130";
        case 0x0103816a: return "[ASM] VS2022 v17.8.0 build 33130";
        case 0x0105816a: return "[C++] VS2022 v17.8.0 build 33130";
        case 0x00ff816a: return "[RES] VS2022 v17.8.0 build 33130";
        case 0x0102816a: return "[LNK] VS2022 v17.8.0 build 33130";
        case 0x0100816a: return "[EXP] VS2022 v17.8.0 build 33130";
        case 0x0101816a: return "[IMP] VS2022 v17.8.0 build 33130";
        case 0x0108816a: return "[LTC] VS2022 v17.8.0 build 33130";
        case 0x0109816a: return "[LT+] VS2022 v17.8.0 build 33130";
        case 0x010b816a: return "[PGO] VS2022 v17.8.0 build 33130";
        case 0x010c816a: return "[PG+] VS2022 v17.8.0 build 33130";
        case 0x0106816a: return "[CIL] VS2022 v17.8.0 build 33130 (*)";
        case 0x0107816a: return "[CI+] VS2022 v17.8.0 build 33130 (*)";
        case 0x010a816a: return "[LTM] VS2022 v17.8.0 build 33130 (*)";
        case 0x010d816a: return "[POC] VS2022 v17.8.0 build 33130 (*)";
        case 0x010e816a: return "[PO+] VS2022 v17.8.0 build 33130 (*)";

        // MSVS2022 v17.7.5
        // MSVS2022 v17.7.6
        case 0x01048039: return "[ C ] VS2022 v17.7.5 build 32825";
        case 0x01038039: return "[ASM] VS2022 v17.7.5 build 32825";
        case 0x01058039: return "[C++] VS2022 v17.7.5 build 32825";
        case 0x00ff8039: return "[RES] VS2022 v17.7.5 build 32825";
        case 0x01028039: return "[LNK] VS2022 v17.7.5 build 32825";
        case 0x01008039: return "[EXP] VS2022 v17.7.5 build 32825";
        case 0x01018039: return "[IMP] VS2022 v17.7.5 build 32825";
        case 0x01088039: return "[LTC] VS2022 v17.7.5 build 32825";
        case 0x01098039: return "[LT+] VS2022 v17.7.5 build 32825";
        case 0x010b8039: return "[PGO] VS2022 v17.7.5 build 32825";
        case 0x010c8039: return "[PG+] VS2022 v17.7.5 build 32825";
        case 0x01068039: return "[CIL] VS2022 v17.7.5 build 32825 (*)";
        case 0x01078039: return "[CI+] VS2022 v17.7.5 build 32825 (*)";
        case 0x010a8039: return "[LTM] VS2022 v17.7.5 build 32825 (*)";
        case 0x010d8039: return "[POC] VS2022 v17.7.5 build 32825 (*)";
        case 0x010e8039: return "[PO+] VS2022 v17.7.5 build 32825 (*)";

        // MSVS2022 v17.7.4
        case 0x01048038: return "[ C ] VS2022 v17.7.4 build 32824";
        case 0x01038038: return "[ASM] VS2022 v17.7.4 build 32824";
        case 0x01058038: return "[C++] VS2022 v17.7.4 build 32824";
        case 0x00ff8038: return "[RES] VS2022 v17.7.4 build 32824";
        case 0x01028038: return "[LNK] VS2022 v17.7.4 build 32824";
        case 0x01008038: return "[EXP] VS2022 v17.7.4 build 32824";
        case 0x01018038: return "[IMP] VS2022 v17.7.4 build 32824";
        case 0x01088038: return "[LTC] VS2022 v17.7.4 build 32824";
        case 0x01098038: return "[LT+] VS2022 v17.7.4 build 32824";
        case 0x010b8038: return "[PGO] VS2022 v17.7.4 build 32824";
        case 0x010c8038: return "[PG+] VS2022 v17.7.4 build 32824";
        case 0x01068038: return "[CIL] VS2022 v17.7.4 build 32824 (*)";
        case 0x01078038: return "[CI+] VS2022 v17.7.4 build 32824 (*)";
        case 0x010a8038: return "[LTM] VS2022 v17.7.4 build 32824 (*)";
        case 0x010d8038: return "[POC] VS2022 v17.7.4 build 32824 (*)";
        case 0x010e8038: return "[PO+] VS2022 v17.7.4 build 32824 (*)";

        // MSVS2022 v17.7.0
        // MSVS2022 v17.7.1
        // MSVS2022 v17.7.2
        // MSVS2022 v17.7.3
        case 0x01048036: return "[ C ] VS2022 v17.7.0 build 32822";
        case 0x01038036: return "[ASM] VS2022 v17.7.0 build 32822";
        case 0x01058036: return "[C++] VS2022 v17.7.0 build 32822";
        case 0x00ff8036: return "[RES] VS2022 v17.7.0 build 32822";
        case 0x01028036: return "[LNK] VS2022 v17.7.0 build 32822";
        case 0x01008036: return "[EXP] VS2022 v17.7.0 build 32822";
        case 0x01018036: return "[IMP] VS2022 v17.7.0 build 32822";
        case 0x01088036: return "[LTC] VS2022 v17.7.0 build 32822";
        case 0x01098036: return "[LT+] VS2022 v17.7.0 build 32822";
        case 0x010b8036: return "[PGO] VS2022 v17.7.0 build 32822";
        case 0x010c8036: return "[PG+] VS2022 v17.7.0 build 32822";
        case 0x01068036: return "[CIL] VS2022 v17.7.0 build 32822 (*)";
        case 0x01078036: return "[CI+] VS2022 v17.7.0 build 32822 (*)";
        case 0x010a8036: return "[LTM] VS2022 v17.7.0 build 32822 (*)";
        case 0x010d8036: return "[POC] VS2022 v17.7.0 build 32822 (*)";
        case 0x010e8036: return "[PO+] VS2022 v17.7.0 build 32822 (*)";

        // MSVS2022 v17.6.5
        case 0x01047f19: return "[ C ] VS2022 v17.6.5 build 32537";
        case 0x01037f19: return "[ASM] VS2022 v17.6.5 build 32537";
        case 0x01057f19: return "[C++] VS2022 v17.6.5 build 32537";
        case 0x00ff7f19: return "[RES] VS2022 v17.6.5 build 32537";
        case 0x01027f19: return "[LNK] VS2022 v17.6.5 build 32537";
        case 0x01007f19: return "[EXP] VS2022 v17.6.5 build 32537";
        case 0x01017f19: return "[IMP] VS2022 v17.6.5 build 32537";
        case 0x01087f19: return "[LTC] VS2022 v17.6.5 build 32537";
        case 0x01097f19: return "[LT+] VS2022 v17.6.5 build 32537";
        case 0x010b7f19: return "[PGO] VS2022 v17.6.5 build 32537";
        case 0x010c7f19: return "[PG+] VS2022 v17.6.5 build 32537";
        case 0x01067f19: return "[CIL] VS2022 v17.6.5 build 32537 (*)";
        case 0x01077f19: return "[CI+] VS2022 v17.6.5 build 32537 (*)";
        case 0x010a7f19: return "[LTM] VS2022 v17.6.5 build 32537 (*)";
        case 0x010d7f19: return "[POC] VS2022 v17.6.5 build 32537 (*)";
        case 0x010e7f19: return "[PO+] VS2022 v17.6.5 build 32537 (*)";

        // MSVS2022 v17.6.4
        case 0x01047f17: return "[ C ] VS2022 v17.6.4 build 32535";
        case 0x01037f17: return "[ASM] VS2022 v17.6.4 build 32535";
        case 0x01057f17: return "[C++] VS2022 v17.6.4 build 32535";
        case 0x00ff7f17: return "[RES] VS2022 v17.6.4 build 32535";
        case 0x01027f17: return "[LNK] VS2022 v17.6.4 build 32535";
        case 0x01007f17: return "[EXP] VS2022 v17.6.4 build 32535";
        case 0x01017f17: return "[IMP] VS2022 v17.6.4 build 32535";
        case 0x01087f17: return "[LTC] VS2022 v17.6.4 build 32535";
        case 0x01097f17: return "[LT+] VS2022 v17.6.4 build 32535";
        case 0x010b7f17: return "[PGO] VS2022 v17.6.4 build 32535";
        case 0x010c7f17: return "[PG+] VS2022 v17.6.4 build 32535";
        case 0x01067f17: return "[CIL] VS2022 v17.6.4 build 32535 (*)";
        case 0x01077f17: return "[CI+] VS2022 v17.6.4 build 32535 (*)";
        case 0x010a7f17: return "[LTM] VS2022 v17.6.4 build 32535 (*)";
        case 0x010d7f17: return "[POC] VS2022 v17.6.4 build 32535 (*)";
        case 0x010e7f17: return "[PO+] VS2022 v17.6.4 build 32535 (*)";

        // MSVS2022 v17.6.3
        case 0x01047f16: return "[ C ] VS2022 v17.6.3 build 32534";
        case 0x01037f16: return "[ASM] VS2022 v17.6.3 build 32534";
        case 0x01057f16: return "[C++] VS2022 v17.6.3 build 32534";
        case 0x00ff7f16: return "[RES] VS2022 v17.6.3 build 32534";
        case 0x01027f16: return "[LNK] VS2022 v17.6.3 build 32534";
        case 0x01007f16: return "[EXP] VS2022 v17.6.3 build 32534";
        case 0x01017f16: return "[IMP] VS2022 v17.6.3 build 32534";
        case 0x01087f16: return "[LTC] VS2022 v17.6.3 build 32534";
        case 0x01097f16: return "[LT+] VS2022 v17.6.3 build 32534";
        case 0x010b7f16: return "[PGO] VS2022 v17.6.3 build 32534";
        case 0x010c7f16: return "[PG+] VS2022 v17.6.3 build 32534";
        case 0x01067f16: return "[CIL] VS2022 v17.6.3 build 32534 (*)";
        case 0x01077f16: return "[CI+] VS2022 v17.6.3 build 32534 (*)";
        case 0x010a7f16: return "[LTM] VS2022 v17.6.3 build 32534 (*)";
        case 0x010d7f16: return "[POC] VS2022 v17.6.3 build 32534 (*)";
        case 0x010e7f16: return "[PO+] VS2022 v17.6.3 build 32534 (*)";

        // MSVS2022 v17.6.0
        // MSVS2022 v17.6.1
        // MSVS2022 v17.6.2
        case 0x01047f14: return "[ C ] VS2022 v17.6.0 build 32532";
        case 0x01037f14: return "[ASM] VS2022 v17.6.0 build 32532";
        case 0x01057f14: return "[C++] VS2022 v17.6.0 build 32532";
        case 0x00ff7f14: return "[RES] VS2022 v17.6.0 build 32532";
        case 0x01027f14: return "[LNK] VS2022 v17.6.0 build 32532";
        case 0x01007f14: return "[EXP] VS2022 v17.6.0 build 32532";
        case 0x01017f14: return "[IMP] VS2022 v17.6.0 build 32532";
        case 0x01087f14: return "[LTC] VS2022 v17.6.0 build 32532";
        case 0x01097f14: return "[LT+] VS2022 v17.6.0 build 32532";
        case 0x010b7f14: return "[PGO] VS2022 v17.6.0 build 32532";
        case 0x010c7f14: return "[PG+] VS2022 v17.6.0 build 32532";
        case 0x01067f14: return "[CIL] VS2022 v17.6.0 build 32532 (*)";
        case 0x01077f14: return "[CI+] VS2022 v17.6.0 build 32532 (*)";
        case 0x010a7f14: return "[LTM] VS2022 v17.6.0 build 32532 (*)";
        case 0x010d7f14: return "[POC] VS2022 v17.6.0 build 32532 (*)";
        case 0x010e7f14: return "[PO+] VS2022 v17.6.0 build 32532 (*)";

        // MSVS2022 v17.5.4
        // MSVS2022 v17.5.5
        case 0x01047dd9: return "[ C ] VS2022 v17.5.4 build 32217";
        case 0x01037dd9: return "[ASM] VS2022 v17.5.4 build 32217";
        case 0x01057dd9: return "[C++] VS2022 v17.5.4 build 32217";
        case 0x00ff7dd9: return "[RES] VS2022 v17.5.4 build 32217";
        case 0x01027dd9: return "[LNK] VS2022 v17.5.4 build 32217";
        case 0x01007dd9: return "[EXP] VS2022 v17.5.4 build 32217";
        case 0x01017dd9: return "[IMP] VS2022 v17.5.4 build 32217";
        case 0x01087dd9: return "[LTC] VS2022 v17.5.4 build 32217";
        case 0x01097dd9: return "[LT+] VS2022 v17.5.4 build 32217";
        case 0x010b7dd9: return "[PGO] VS2022 v17.5.4 build 32217";
        case 0x010c7dd9: return "[PG+] VS2022 v17.5.4 build 32217";
        case 0x01067dd9: return "[CIL] VS2022 v17.5.4 build 32217 (*)";
        case 0x01077dd9: return "[CI+] VS2022 v17.5.4 build 32217 (*)";
        case 0x010a7dd9: return "[LTM] VS2022 v17.5.4 build 32217 (*)";
        case 0x010d7dd9: return "[POC] VS2022 v17.5.4 build 32217 (*)";
        case 0x010e7dd9: return "[PO+] VS2022 v17.5.4 build 32217 (*)";

        // MSVS2022 v17.5.3
        case 0x01047dd8: return "[ C ] VS2022 v17.5.3 build 32216";
        case 0x01037dd8: return "[ASM] VS2022 v17.5.3 build 32216";
        case 0x01057dd8: return "[C++] VS2022 v17.5.3 build 32216";
        case 0x00ff7dd8: return "[RES] VS2022 v17.5.3 build 32216";
        case 0x01027dd8: return "[LNK] VS2022 v17.5.3 build 32216";
        case 0x01007dd8: return "[EXP] VS2022 v17.5.3 build 32216";
        case 0x01017dd8: return "[IMP] VS2022 v17.5.3 build 32216";
        case 0x01087dd8: return "[LTC] VS2022 v17.5.3 build 32216";
        case 0x01097dd8: return "[LT+] VS2022 v17.5.3 build 32216";
        case 0x010b7dd8: return "[PGO] VS2022 v17.5.3 build 32216";
        case 0x010c7dd8: return "[PG+] VS2022 v17.5.3 build 32216";
        case 0x01067dd8: return "[CIL] VS2022 v17.5.3 build 32216 (*)";
        case 0x01077dd8: return "[CI+] VS2022 v17.5.3 build 32216 (*)";
        case 0x010a7dd8: return "[LTM] VS2022 v17.5.3 build 32216 (*)";
        case 0x010d7dd8: return "[POC] VS2022 v17.5.3 build 32216 (*)";
        case 0x010e7dd8: return "[PO+] VS2022 v17.5.3 build 32216 (*)";

        // MSVS2022 v17.5.0
        // MSVS2022 v17.5.1
        // MSVS2022 v17.5.2
        case 0x01047dd7: return "[ C ] VS2022 v17.5.0 build 32215";
        case 0x01037dd7: return "[ASM] VS2022 v17.5.0 build 32215";
        case 0x01057dd7: return "[C++] VS2022 v17.5.0 build 32215";
        case 0x00ff7dd7: return "[RES] VS2022 v17.5.0 build 32215";
        case 0x01027dd7: return "[LNK] VS2022 v17.5.0 build 32215";
        case 0x01007dd7: return "[EXP] VS2022 v17.5.0 build 32215";
        case 0x01017dd7: return "[IMP] VS2022 v17.5.0 build 32215";
        case 0x01087dd7: return "[LTC] VS2022 v17.5.0 build 32215";
        case 0x01097dd7: return "[LT+] VS2022 v17.5.0 build 32215";
        case 0x010b7dd7: return "[PGO] VS2022 v17.5.0 build 32215";
        case 0x010c7dd7: return "[PG+] VS2022 v17.5.0 build 32215";
        case 0x01067dd7: return "[CIL] VS2022 v17.5.0 build 32215 (*)";
        case 0x01077dd7: return "[CI+] VS2022 v17.5.0 build 32215 (*)";
        case 0x010a7dd7: return "[LTM] VS2022 v17.5.0 build 32215 (*)";
        case 0x010d7dd7: return "[POC] VS2022 v17.5.0 build 32215 (*)";
        case 0x010e7dd7: return "[PO+] VS2022 v17.5.0 build 32215 (*)";

        // MSVS2022 v17.4.5
        case 0x01047cc6: return "[ C ] VS2022 v17.4.5 build 31942";
        case 0x01037cc6: return "[ASM] VS2022 v17.4.5 build 31942";
        case 0x01057cc6: return "[C++] VS2022 v17.4.5 build 31942";
        case 0x00ff7cc6: return "[RES] VS2022 v17.4.5 build 31942";
        case 0x01027cc6: return "[LNK] VS2022 v17.4.5 build 31942";
        case 0x01007cc6: return "[EXP] VS2022 v17.4.5 build 31942";
        case 0x01017cc6: return "[IMP] VS2022 v17.4.5 build 31942";
        case 0x01067cc6: return "[CIL] VS2022 v17.4.5 build 31942 (*)";
        case 0x01077cc6: return "[CI+] VS2022 v17.4.5 build 31942 (*)";
        case 0x01087cc6: return "[LTC] VS2022 v17.4.5 build 31942 (*)";
        case 0x01097cc6: return "[LT+] VS2022 v17.4.5 build 31942 (*)";
        case 0x010a7cc6: return "[LTM] VS2022 v17.4.5 build 31942 (*)";
        case 0x010b7cc6: return "[PGO] VS2022 v17.4.5 build 31942 (*)";
        case 0x010c7cc6: return "[PG+] VS2022 v17.4.5 build 31942 (*)";
        case 0x010d7cc6: return "[POC] VS2022 v17.4.5 build 31942 (*)";
        case 0x010e7cc6: return "[PO+] VS2022 v17.4.5 build 31942 (*)";

        // MSVS2022 v17.4.3
        case 0x01047cc1: return "[ C ] VS2022 v17.4.3 build 31937";
        case 0x01037cc1: return "[ASM] VS2022 v17.4.3 build 31937";
        case 0x01057cc1: return "[C++] VS2022 v17.4.3 build 31937";
        case 0x00ff7cc1: return "[RES] VS2022 v17.4.3 build 31937";
        case 0x01027cc1: return "[LNK] VS2022 v17.4.3 build 31937";
        case 0x01007cc1: return "[EXP] VS2022 v17.4.3 build 31937";
        case 0x01017cc1: return "[IMP] VS2022 v17.4.3 build 31937";
        case 0x01067cc1: return "[CIL] VS2022 v17.4.3 build 31937 (*)";
        case 0x01077cc1: return "[CI+] VS2022 v17.4.3 build 31937 (*)";
        case 0x01087cc1: return "[LTC] VS2022 v17.4.3 build 31937 (*)";
        case 0x01097cc1: return "[LT+] VS2022 v17.4.3 build 31937 (*)";
        case 0x010a7cc1: return "[LTM] VS2022 v17.4.3 build 31937 (*)";
        case 0x010b7cc1: return "[PGO] VS2022 v17.4.3 build 31937 (*)";
        case 0x010c7cc1: return "[PG+] VS2022 v17.4.3 build 31937 (*)";
        case 0x010d7cc1: return "[POC] VS2022 v17.4.3 build 31937 (*)";
        case 0x010e7cc1: return "[PO+] VS2022 v17.4.3 build 31937 (*)";

        // MSVS2022 v17.4.2
        case 0x01047cbf: return "[ C ] VS2022 v17.4.2 build 31935";
        case 0x01037cbf: return "[ASM] VS2022 v17.4.2 build 31935";
        case 0x01057cbf: return "[C++] VS2022 v17.4.2 build 31935";
        case 0x00ff7cbf: return "[RES] VS2022 v17.4.2 build 31935";
        case 0x01027cbf: return "[LNK] VS2022 v17.4.2 build 31935";
        case 0x01007cbf: return "[EXP] VS2022 v17.4.2 build 31935";
        case 0x01017cbf: return "[IMP] VS2022 v17.4.2 build 31935";
        case 0x01067cbf: return "[CIL] VS2022 v17.4.2 build 31935 (*)";
        case 0x01077cbf: return "[CI+] VS2022 v17.4.2 build 31935 (*)";
        case 0x01087cbf: return "[LTC] VS2022 v17.4.2 build 31935 (*)";
        case 0x01097cbf: return "[LT+] VS2022 v17.4.2 build 31935 (*)";
        case 0x010a7cbf: return "[LTM] VS2022 v17.4.2 build 31935 (*)";
        case 0x010b7cbf: return "[PGO] VS2022 v17.4.2 build 31935 (*)";
        case 0x010c7cbf: return "[PG+] VS2022 v17.4.2 build 31935 (*)";
        case 0x010d7cbf: return "[POC] VS2022 v17.4.2 build 31935 (*)";
        case 0x010e7cbf: return "[PO+] VS2022 v17.4.2 build 31935 (*)";

        // MSVS2022 v17.3.4
        case 0x01047b8e: return "[ C ] VS2022 v17.3.4 build 31630";
        case 0x01037b8e: return "[ASM] VS2022 v17.3.4 build 31630";
        case 0x01057b8e: return "[C++] VS2022 v17.3.4 build 31630";
        case 0x00ff7b8e: return "[RES] VS2022 v17.3.4 build 31630";
        case 0x01027b8e: return "[LNK] VS2022 v17.3.4 build 31630";
        case 0x01007b8e: return "[EXP] VS2022 v17.3.4 build 31630";
        case 0x01017b8e: return "[IMP] VS2022 v17.3.4 build 31630";
        case 0x01067b8e: return "[CIL] VS2022 v17.3.4 build 31630 (*)";
        case 0x01077b8e: return "[CI+] VS2022 v17.3.4 build 31630 (*)";
        case 0x01087b8e: return "[LTC] VS2022 v17.3.4 build 31630 (*)";
        case 0x01097b8e: return "[LT+] VS2022 v17.3.4 build 31630 (*)";
        case 0x010a7b8e: return "[LTM] VS2022 v17.3.4 build 31630 (*)";
        case 0x010b7b8e: return "[PGO] VS2022 v17.3.4 build 31630 (*)";
        case 0x010c7b8e: return "[PG+] VS2022 v17.3.4 build 31630 (*)";
        case 0x010d7b8e: return "[POC] VS2022 v17.3.4 build 31630 (*)";
        case 0x010e7b8e: return "[PO+] VS2022 v17.3.4 build 31630 (*)";

        // MSVS2022 v17.2.5
        case 0x01047a64: return "[ C ] VS2022 v17.2.5 build 31332";
        case 0x01037a64: return "[ASM] VS2022 v17.2.5 build 31332";
        case 0x01057a64: return "[C++] VS2022 v17.2.5 build 31332";
        case 0x00ff7a64: return "[RES] VS2022 v17.2.5 build 31332";
        case 0x01027a64: return "[LNK] VS2022 v17.2.5 build 31332";
        case 0x01007a64: return "[EXP] VS2022 v17.2.5 build 31332";
        case 0x01017a64: return "[IMP] VS2022 v17.2.5 build 31332";
        case 0x01067a64: return "[CIL] VS2022 v17.2.5 build 31332 (*)";
        case 0x01077a64: return "[CI+] VS2022 v17.2.5 build 31332 (*)";
        case 0x01087a64: return "[LTC] VS2022 v17.2.5 build 31332 (*)";
        case 0x01097a64: return "[LT+] VS2022 v17.2.5 build 31332 (*)";
        case 0x010a7a64: return "[LTM] VS2022 v17.2.5 build 31332 (*)";
        case 0x010b7a64: return "[PGO] VS2022 v17.2.5 build 31332 (*)";
        case 0x010c7a64: return "[PG+] VS2022 v17.2.5 build 31332 (*)";
        case 0x010d7a64: return "[POC] VS2022 v17.2.5 build 31332 (*)";
        case 0x010e7a64: return "[PO+] VS2022 v17.2.5 build 31332 (*)";

        // MSVS2022 v17.2.1 - 17.2.4
        case 0x01047a61: return "[ C ] VS2022 v17.2.1 build 31329";
        case 0x01037a61: return "[ASM] VS2022 v17.2.1 build 31329";
        case 0x01057a61: return "[C++] VS2022 v17.2.1 build 31329";
        case 0x00ff7a61: return "[RES] VS2022 v17.2.1 build 31329";
        case 0x01027a61: return "[LNK] VS2022 v17.2.1 build 31329";
        case 0x01007a61: return "[EXP] VS2022 v17.2.1 build 31329";
        case 0x01017a61: return "[IMP] VS2022 v17.2.1 build 31329";
        case 0x01067a61: return "[CIL] VS2022 v17.2.1 build 31329 (*)";
        case 0x01077a61: return "[CI+] VS2022 v17.2.1 build 31329 (*)";
        case 0x01087a61: return "[LTC] VS2022 v17.2.1 build 31329 (*)";
        case 0x01097a61: return "[LT+] VS2022 v17.2.1 build 31329 (*)";
        case 0x010a7a61: return "[LTM] VS2022 v17.2.1 build 31329 (*)";
        case 0x010b7a61: return "[PGO] VS2022 v17.2.1 build 31329 (*)";
        case 0x010c7a61: return "[PG+] VS2022 v17.2.1 build 31329 (*)";
        case 0x010d7a61: return "[POC] VS2022 v17.2.1 build 31329 (*)";
        case 0x010e7a61: return "[PO+] VS2022 v17.2.1 build 31329 (*)";

        // MSVS2022 v17.14.14-pre.1.0
        // MSVS2022 v17.14.14
        case 0x01048990: return "[ C ] VS2022 v17.14.14 pre 1.0 build 35216";
        case 0x01038990: return "[ASM] VS2022 v17.14.14 pre 1.0 build 35216";
        case 0x01058990: return "[C++] VS2022 v17.14.14 pre 1.0 build 35216";
        case 0x00ff8990: return "[RES] VS2022 v17.14.14 pre 1.0 build 35216";
        case 0x01028990: return "[LNK] VS2022 v17.14.14 pre 1.0 build 35216";
        case 0x01008990: return "[EXP] VS2022 v17.14.14 pre 1.0 build 35216";
        case 0x01018990: return "[IMP] VS2022 v17.14.14 pre 1.0 build 35216";
        case 0x01088990: return "[LTC] VS2022 v17.14.14 pre 1.0 build 35216";
        case 0x01098990: return "[LT+] VS2022 v17.14.14 pre 1.0 build 35216";
        case 0x010b8990: return "[PGO] VS2022 v17.14.14 pre 1.0 build 35216";
        case 0x010c8990: return "[PG+] VS2022 v17.14.14 pre 1.0 build 35216";
        case 0x01068990: return "[CIL] VS2022 v17.14.14 pre 1.0 build 35216 (*)";
        case 0x01078990: return "[CI+] VS2022 v17.14.14 pre 1.0 build 35216 (*)";
        case 0x010a8990: return "[LTM] VS2022 v17.14.14 pre 1.0 build 35216 (*)";
        case 0x010d8990: return "[POC] VS2022 v17.14.14 pre 1.0 build 35216 (*)";
        case 0x010e8990: return "[PO+] VS2022 v17.14.14 pre 1.0 build 35216 (*)";

        // MSVS2022 v17.14.6-pre.1.0
        // MSVS2022 v17.14.6
        // MSVS2022 v17.14.7
        // MSVS2022 v17.14.7-pre.1.0
        // MSVS2022 v17.14.8
        // MSVS2022 v17.14.8-pre.1.0
        case 0x0104898b: return "[ C ] VS2022 v17.14.6 pre 1.0 build 35211";
        case 0x0103898b: return "[ASM] VS2022 v17.14.6 pre 1.0 build 35211";
        case 0x0105898b: return "[C++] VS2022 v17.14.6 pre 1.0 build 35211";
        case 0x00ff898b: return "[RES] VS2022 v17.14.6 pre 1.0 build 35211";
        case 0x0102898b: return "[LNK] VS2022 v17.14.6 pre 1.0 build 35211";
        case 0x0100898b: return "[EXP] VS2022 v17.14.6 pre 1.0 build 35211";
        case 0x0101898b: return "[IMP] VS2022 v17.14.6 pre 1.0 build 35211";
        case 0x0108898b: return "[LTC] VS2022 v17.14.6 pre 1.0 build 35211";
        case 0x0109898b: return "[LT+] VS2022 v17.14.6 pre 1.0 build 35211";
        case 0x010b898b: return "[PGO] VS2022 v17.14.6 pre 1.0 build 35211";
        case 0x010c898b: return "[PG+] VS2022 v17.14.6 pre 1.0 build 35211";
        case 0x0106898b: return "[CIL] VS2022 v17.14.6 pre 1.0 build 35211 (*)";
        case 0x0107898b: return "[CI+] VS2022 v17.14.6 pre 1.0 build 35211 (*)";
        case 0x010a898b: return "[LTM] VS2022 v17.14.6 pre 1.0 build 35211 (*)";
        case 0x010d898b: return "[POC] VS2022 v17.14.6 pre 1.0 build 35211 (*)";
        case 0x010e898b: return "[PO+] VS2022 v17.14.6 pre 1.0 build 35211 (*)";

        // MSVS2022 v17.14.3-pre.1.0
        // MSVS2022 v17.14.3
        case 0x01048988: return "[ C ] VS2022 v17.14.3 pre 1.0 build 35208";
        case 0x01038988: return "[ASM] VS2022 v17.14.3 pre 1.0 build 35208";
        case 0x01058988: return "[C++] VS2022 v17.14.3 pre 1.0 build 35208";
        case 0x00ff8988: return "[RES] VS2022 v17.14.3 pre 1.0 build 35208";
        case 0x01028988: return "[LNK] VS2022 v17.14.3 pre 1.0 build 35208";
        case 0x01008988: return "[EXP] VS2022 v17.14.3 pre 1.0 build 35208";
        case 0x01018988: return "[IMP] VS2022 v17.14.3 pre 1.0 build 35208";
        case 0x01088988: return "[LTC] VS2022 v17.14.3 pre 1.0 build 35208";
        case 0x01098988: return "[LT+] VS2022 v17.14.3 pre 1.0 build 35208";
        case 0x010b8988: return "[PGO] VS2022 v17.14.3 pre 1.0 build 35208";
        case 0x010c8988: return "[PG+] VS2022 v17.14.3 pre 1.0 build 35208";
        case 0x01068988: return "[CIL] VS2022 v17.14.3 pre 1.0 build 35208 (*)";
        case 0x01078988: return "[CI+] VS2022 v17.14.3 pre 1.0 build 35208 (*)";
        case 0x010a8988: return "[LTM] VS2022 v17.14.3 pre 1.0 build 35208 (*)";
        case 0x010d8988: return "[POC] VS2022 v17.14.3 pre 1.0 build 35208 (*)";
        case 0x010e8988: return "[PO+] VS2022 v17.14.3 pre 1.0 build 35208 (*)";

        // MSVS2022 v17.14.0-pre.7.0
        // MSVS2022 v17.14.0
        // MSVS2022 v17.14.2
        // MSVS2022 v17.14.2-pre.1.0
        case 0x01048987: return "[ C ] VS2022 v17.14.0 pre 7.0 build 35207";
        case 0x01038987: return "[ASM] VS2022 v17.14.0 pre 7.0 build 35207";
        case 0x01058987: return "[C++] VS2022 v17.14.0 pre 7.0 build 35207";
        case 0x00ff8987: return "[RES] VS2022 v17.14.0 pre 7.0 build 35207";
        case 0x01028987: return "[LNK] VS2022 v17.14.0 pre 7.0 build 35207";
        case 0x01008987: return "[EXP] VS2022 v17.14.0 pre 7.0 build 35207";
        case 0x01018987: return "[IMP] VS2022 v17.14.0 pre 7.0 build 35207";
        case 0x01088987: return "[LTC] VS2022 v17.14.0 pre 7.0 build 35207";
        case 0x01098987: return "[LT+] VS2022 v17.14.0 pre 7.0 build 35207";
        case 0x010b8987: return "[PGO] VS2022 v17.14.0 pre 7.0 build 35207";
        case 0x010c8987: return "[PG+] VS2022 v17.14.0 pre 7.0 build 35207";
        case 0x01068987: return "[CIL] VS2022 v17.14.0 pre 7.0 build 35207 (*)";
        case 0x01078987: return "[CI+] VS2022 v17.14.0 pre 7.0 build 35207 (*)";
        case 0x010a8987: return "[LTM] VS2022 v17.14.0 pre 7.0 build 35207 (*)";
        case 0x010d8987: return "[POC] VS2022 v17.14.0 pre 7.0 build 35207 (*)";
        case 0x010e8987: return "[PO+] VS2022 v17.14.0 pre 7.0 build 35207 (*)";

        // MSVS2022 v17.14.0-pre.6.0
        case 0x01048938: return "[ C ] VS2022 v17.14.0 pre 6.0 build 35128";
        case 0x01038938: return "[ASM] VS2022 v17.14.0 pre 6.0 build 35128";
        case 0x01058938: return "[C++] VS2022 v17.14.0 pre 6.0 build 35128";
        case 0x00ff8938: return "[RES] VS2022 v17.14.0 pre 6.0 build 35128";
        case 0x01028938: return "[LNK] VS2022 v17.14.0 pre 6.0 build 35128";
        case 0x01008938: return "[EXP] VS2022 v17.14.0 pre 6.0 build 35128";
        case 0x01018938: return "[IMP] VS2022 v17.14.0 pre 6.0 build 35128";
        case 0x01088938: return "[LTC] VS2022 v17.14.0 pre 6.0 build 35128";
        case 0x01098938: return "[LT+] VS2022 v17.14.0 pre 6.0 build 35128";
        case 0x010b8938: return "[PGO] VS2022 v17.14.0 pre 6.0 build 35128";
        case 0x010c8938: return "[PG+] VS2022 v17.14.0 pre 6.0 build 35128";
        case 0x01068938: return "[CIL] VS2022 v17.14.0 pre 6.0 build 35128 (*)";
        case 0x01078938: return "[CI+] VS2022 v17.14.0 pre 6.0 build 35128 (*)";
        case 0x010a8938: return "[LTM] VS2022 v17.14.0 pre 6.0 build 35128 (*)";
        case 0x010d8938: return "[POC] VS2022 v17.14.0 pre 6.0 build 35128 (*)";
        case 0x010e8938: return "[PO+] VS2022 v17.14.0 pre 6.0 build 35128 (*)";

        // MSVS2022 v17.14.0-pre.4.0
        // MSVS2022 v17.14.0-pre.5.0
        case 0x01048928: return "[ C ] VS2022 v17.14.0 pre 4.0 build 35112";
        case 0x01038928: return "[ASM] VS2022 v17.14.0 pre 4.0 build 35112";
        case 0x01058928: return "[C++] VS2022 v17.14.0 pre 4.0 build 35112";
        case 0x00ff8928: return "[RES] VS2022 v17.14.0 pre 4.0 build 35112";
        case 0x01028928: return "[LNK] VS2022 v17.14.0 pre 4.0 build 35112";
        case 0x01008928: return "[EXP] VS2022 v17.14.0 pre 4.0 build 35112";
        case 0x01018928: return "[IMP] VS2022 v17.14.0 pre 4.0 build 35112";
        case 0x01088928: return "[LTC] VS2022 v17.14.0 pre 4.0 build 35112";
        case 0x01098928: return "[LT+] VS2022 v17.14.0 pre 4.0 build 35112";
        case 0x010b8928: return "[PGO] VS2022 v17.14.0 pre 4.0 build 35112";
        case 0x010c8928: return "[PG+] VS2022 v17.14.0 pre 4.0 build 35112";
        case 0x01068928: return "[CIL] VS2022 v17.14.0 pre 4.0 build 35112 (*)";
        case 0x01078928: return "[CI+] VS2022 v17.14.0 pre 4.0 build 35112 (*)";
        case 0x010a8928: return "[LTM] VS2022 v17.14.0 pre 4.0 build 35112 (*)";
        case 0x010d8928: return "[POC] VS2022 v17.14.0 pre 4.0 build 35112 (*)";
        case 0x010e8928: return "[PO+] VS2022 v17.14.0 pre 4.0 build 35112 (*)";

        // MSVS2022 v17.14.0-pre.3.0
        case 0x01048925: return "[ C ] VS2022 v17.14.0 pre 3.0 build 35109";
        case 0x01038925: return "[ASM] VS2022 v17.14.0 pre 3.0 build 35109";
        case 0x01058925: return "[C++] VS2022 v17.14.0 pre 3.0 build 35109";
        case 0x00ff8925: return "[RES] VS2022 v17.14.0 pre 3.0 build 35109";
        case 0x01028925: return "[LNK] VS2022 v17.14.0 pre 3.0 build 35109";
        case 0x01008925: return "[EXP] VS2022 v17.14.0 pre 3.0 build 35109";
        case 0x01018925: return "[IMP] VS2022 v17.14.0 pre 3.0 build 35109";
        case 0x01088925: return "[LTC] VS2022 v17.14.0 pre 3.0 build 35109";
        case 0x01098925: return "[LT+] VS2022 v17.14.0 pre 3.0 build 35109";
        case 0x010b8925: return "[PGO] VS2022 v17.14.0 pre 3.0 build 35109";
        case 0x010c8925: return "[PG+] VS2022 v17.14.0 pre 3.0 build 35109";
        case 0x01068925: return "[CIL] VS2022 v17.14.0 pre 3.0 build 35109 (*)";
        case 0x01078925: return "[CI+] VS2022 v17.14.0 pre 3.0 build 35109 (*)";
        case 0x010a8925: return "[LTM] VS2022 v17.14.0 pre 3.0 build 35109 (*)";
        case 0x010d8925: return "[POC] VS2022 v17.14.0 pre 3.0 build 35109 (*)";
        case 0x010e8925: return "[PO+] VS2022 v17.14.0 pre 3.0 build 35109 (*)";

        // MSVS2022 v17.14.0-pre.2.0
        case 0x01048866: return "[ C ] VS2022 v17.14.0 pre 2.0 build 34918";
        case 0x01038866: return "[ASM] VS2022 v17.14.0 pre 2.0 build 34918";
        case 0x01058866: return "[C++] VS2022 v17.14.0 pre 2.0 build 34918";
        case 0x00ff8866: return "[RES] VS2022 v17.14.0 pre 2.0 build 34918";
        case 0x01028866: return "[LNK] VS2022 v17.14.0 pre 2.0 build 34918";
        case 0x01008866: return "[EXP] VS2022 v17.14.0 pre 2.0 build 34918";
        case 0x01018866: return "[IMP] VS2022 v17.14.0 pre 2.0 build 34918";
        case 0x01088866: return "[LTC] VS2022 v17.14.0 pre 2.0 build 34918";
        case 0x01098866: return "[LT+] VS2022 v17.14.0 pre 2.0 build 34918";
        case 0x010b8866: return "[PGO] VS2022 v17.14.0 pre 2.0 build 34918";
        case 0x010c8866: return "[PG+] VS2022 v17.14.0 pre 2.0 build 34918";
        case 0x01068866: return "[CIL] VS2022 v17.14.0 pre 2.0 build 34918 (*)";
        case 0x01078866: return "[CI+] VS2022 v17.14.0 pre 2.0 build 34918 (*)";
        case 0x010a8866: return "[LTM] VS2022 v17.14.0 pre 2.0 build 34918 (*)";
        case 0x010d8866: return "[POC] VS2022 v17.14.0 pre 2.0 build 34918 (*)";
        case 0x010e8866: return "[PO+] VS2022 v17.14.0 pre 2.0 build 34918 (*)";

        // MSVS2022 v17.14.0-pre.1.0
        // MSVS2022 v17.14.0-pre.1.1
        case 0x01048807: return "[ C ] VS2022 v17.14.0 pre 1.0 build 34823";
        case 0x01038807: return "[ASM] VS2022 v17.14.0 pre 1.0 build 34823";
        case 0x01058807: return "[C++] VS2022 v17.14.0 pre 1.0 build 34823";
        case 0x00ff8807: return "[RES] VS2022 v17.14.0 pre 1.0 build 34823";
        case 0x01028807: return "[LNK] VS2022 v17.14.0 pre 1.0 build 34823";
        case 0x01008807: return "[EXP] VS2022 v17.14.0 pre 1.0 build 34823";
        case 0x01018807: return "[IMP] VS2022 v17.14.0 pre 1.0 build 34823";
        case 0x01088807: return "[LTC] VS2022 v17.14.0 pre 1.0 build 34823";
        case 0x01098807: return "[LT+] VS2022 v17.14.0 pre 1.0 build 34823";
        case 0x010b8807: return "[PGO] VS2022 v17.14.0 pre 1.0 build 34823";
        case 0x010c8807: return "[PG+] VS2022 v17.14.0 pre 1.0 build 34823";
        case 0x01068807: return "[CIL] VS2022 v17.14.0 pre 1.0 build 34823 (*)";
        case 0x01078807: return "[CI+] VS2022 v17.14.0 pre 1.0 build 34823 (*)";
        case 0x010a8807: return "[LTM] VS2022 v17.14.0 pre 1.0 build 34823 (*)";
        case 0x010d8807: return "[POC] VS2022 v17.14.0 pre 1.0 build 34823 (*)";
        case 0x010e8807: return "[PO+] VS2022 v17.14.0 pre 1.0 build 34823 (*)";

        // MSVS2022 v17.13.0-pre.4.0
        // MSVS2022 v17.13.0-pre.5.0
        // MSVS2022 v17.13.0
        // MSVS2022 v17.13.1
        // MSVS2022 v17.13.2
        case 0x010487f8: return "[ C ] VS2022 v17.13.0 pre 4.0 build 34808";
        case 0x010387f8: return "[ASM] VS2022 v17.13.0 pre 4.0 build 34808";
        case 0x010587f8: return "[C++] VS2022 v17.13.0 pre 4.0 build 34808";
        case 0x00ff87f8: return "[RES] VS2022 v17.13.0 pre 4.0 build 34808";
        case 0x010287f8: return "[LNK] VS2022 v17.13.0 pre 4.0 build 34808";
        case 0x010087f8: return "[EXP] VS2022 v17.13.0 pre 4.0 build 34808";
        case 0x010187f8: return "[IMP] VS2022 v17.13.0 pre 4.0 build 34808";
        case 0x010887f8: return "[LTC] VS2022 v17.13.0 pre 4.0 build 34808";
        case 0x010987f8: return "[LT+] VS2022 v17.13.0 pre 4.0 build 34808";
        case 0x010b87f8: return "[PGO] VS2022 v17.13.0 pre 4.0 build 34808";
        case 0x010c87f8: return "[PG+] VS2022 v17.13.0 pre 4.0 build 34808";
        case 0x010687f8: return "[CIL] VS2022 v17.13.0 pre 4.0 build 34808 (*)";
        case 0x010787f8: return "[CI+] VS2022 v17.13.0 pre 4.0 build 34808 (*)";
        case 0x010a87f8: return "[LTM] VS2022 v17.13.0 pre 4.0 build 34808 (*)";
        case 0x010d87f8: return "[POC] VS2022 v17.13.0 pre 4.0 build 34808 (*)";
        case 0x010e87f8: return "[PO+] VS2022 v17.13.0 pre 4.0 build 34808 (*)";

        // MSVS2022 v17.13.0-pre.2.0
        // MSVS2022 v17.13.0-pre.2.1
        // MSVS2022 v17.13.0-pre.3.0
        case 0x0104873a: return "[ C ] VS2022 v17.13.0 pre 2.0 build 34618";
        case 0x0103873a: return "[ASM] VS2022 v17.13.0 pre 2.0 build 34618";
        case 0x0105873a: return "[C++] VS2022 v17.13.0 pre 2.0 build 34618";
        case 0x00ff873a: return "[RES] VS2022 v17.13.0 pre 2.0 build 34618";
        case 0x0102873a: return "[LNK] VS2022 v17.13.0 pre 2.0 build 34618";
        case 0x0100873a: return "[EXP] VS2022 v17.13.0 pre 2.0 build 34618";
        case 0x0101873a: return "[IMP] VS2022 v17.13.0 pre 2.0 build 34618";
        case 0x0108873a: return "[LTC] VS2022 v17.13.0 pre 2.0 build 34618";
        case 0x0109873a: return "[LT+] VS2022 v17.13.0 pre 2.0 build 34618";
        case 0x010b873a: return "[PGO] VS2022 v17.13.0 pre 2.0 build 34618";
        case 0x010c873a: return "[PG+] VS2022 v17.13.0 pre 2.0 build 34618";
        case 0x0106873a: return "[CIL] VS2022 v17.13.0 pre 2.0 build 34618 (*)";
        case 0x0107873a: return "[CI+] VS2022 v17.13.0 pre 2.0 build 34618 (*)";
        case 0x010a873a: return "[LTM] VS2022 v17.13.0 pre 2.0 build 34618 (*)";
        case 0x010d873a: return "[POC] VS2022 v17.13.0 pre 2.0 build 34618 (*)";
        case 0x010e873a: return "[PO+] VS2022 v17.13.0 pre 2.0 build 34618 (*)";

        // MSVS2022 v17.13.0-pre.1.0
        case 0x0104872c: return "[ C ] VS2022 v17.13.0 pre 1.0 build 34604";
        case 0x0103872c: return "[ASM] VS2022 v17.13.0 pre 1.0 build 34604";
        case 0x0105872c: return "[C++] VS2022 v17.13.0 pre 1.0 build 34604";
        case 0x00ff872c: return "[RES] VS2022 v17.13.0 pre 1.0 build 34604";
        case 0x0102872c: return "[LNK] VS2022 v17.13.0 pre 1.0 build 34604";
        case 0x0100872c: return "[EXP] VS2022 v17.13.0 pre 1.0 build 34604";
        case 0x0101872c: return "[IMP] VS2022 v17.13.0 pre 1.0 build 34604";
        case 0x0108872c: return "[LTC] VS2022 v17.13.0 pre 1.0 build 34604";
        case 0x0109872c: return "[LT+] VS2022 v17.13.0 pre 1.0 build 34604";
        case 0x010b872c: return "[PGO] VS2022 v17.13.0 pre 1.0 build 34604";
        case 0x010c872c: return "[PG+] VS2022 v17.13.0 pre 1.0 build 34604";
        case 0x0106872c: return "[CIL] VS2022 v17.13.0 pre 1.0 build 34604 (*)";
        case 0x0107872c: return "[CI+] VS2022 v17.13.0 pre 1.0 build 34604 (*)";
        case 0x010a872c: return "[LTM] VS2022 v17.13.0 pre 1.0 build 34604 (*)";
        case 0x010d872c: return "[POC] VS2022 v17.13.0 pre 1.0 build 34604 (*)";
        case 0x010e872c: return "[PO+] VS2022 v17.13.0 pre 1.0 build 34604 (*)";

        // MSVS2022 v17.12.0-pre.5.0
        case 0x01048680: return "[ C ] VS2022 v17.12.0 pre 5.0 build 34432";
        case 0x01038680: return "[ASM] VS2022 v17.12.0 pre 5.0 build 34432";
        case 0x01058680: return "[C++] VS2022 v17.12.0 pre 5.0 build 34432";
        case 0x00ff8680: return "[RES] VS2022 v17.12.0 pre 5.0 build 34432";
        case 0x01028680: return "[LNK] VS2022 v17.12.0 pre 5.0 build 34432";
        case 0x01008680: return "[EXP] VS2022 v17.12.0 pre 5.0 build 34432";
        case 0x01018680: return "[IMP] VS2022 v17.12.0 pre 5.0 build 34432";
        case 0x01088680: return "[LTC] VS2022 v17.12.0 pre 5.0 build 34432";
        case 0x01098680: return "[LT+] VS2022 v17.12.0 pre 5.0 build 34432";
        case 0x010b8680: return "[PGO] VS2022 v17.12.0 pre 5.0 build 34432";
        case 0x010c8680: return "[PG+] VS2022 v17.12.0 pre 5.0 build 34432";
        case 0x01068680: return "[CIL] VS2022 v17.12.0 pre 5.0 build 34432 (*)";
        case 0x01078680: return "[CI+] VS2022 v17.12.0 pre 5.0 build 34432 (*)";
        case 0x010a8680: return "[LTM] VS2022 v17.12.0 pre 5.0 build 34432 (*)";
        case 0x010d8680: return "[POC] VS2022 v17.12.0 pre 5.0 build 34432 (*)";
        case 0x010e8680: return "[PO+] VS2022 v17.12.0 pre 5.0 build 34432 (*)";

        // MSVS2022 v17.12.0-pre.4.0
        case 0x0104867f: return "[ C ] VS2022 v17.12.0 pre 4.0 build 34431";
        case 0x0103867f: return "[ASM] VS2022 v17.12.0 pre 4.0 build 34431";
        case 0x0105867f: return "[C++] VS2022 v17.12.0 pre 4.0 build 34431";
        case 0x00ff867f: return "[RES] VS2022 v17.12.0 pre 4.0 build 34431";
        case 0x0102867f: return "[LNK] VS2022 v17.12.0 pre 4.0 build 34431";
        case 0x0100867f: return "[EXP] VS2022 v17.12.0 pre 4.0 build 34431";
        case 0x0101867f: return "[IMP] VS2022 v17.12.0 pre 4.0 build 34431";
        case 0x0108867f: return "[LTC] VS2022 v17.12.0 pre 4.0 build 34431";
        case 0x0109867f: return "[LT+] VS2022 v17.12.0 pre 4.0 build 34431";
        case 0x010b867f: return "[PGO] VS2022 v17.12.0 pre 4.0 build 34431";
        case 0x010c867f: return "[PG+] VS2022 v17.12.0 pre 4.0 build 34431";
        case 0x0106867f: return "[CIL] VS2022 v17.12.0 pre 4.0 build 34431 (*)";
        case 0x0107867f: return "[CI+] VS2022 v17.12.0 pre 4.0 build 34431 (*)";
        case 0x010a867f: return "[LTM] VS2022 v17.12.0 pre 4.0 build 34431 (*)";
        case 0x010d867f: return "[POC] VS2022 v17.12.0 pre 4.0 build 34431 (*)";
        case 0x010e867f: return "[PO+] VS2022 v17.12.0 pre 4.0 build 34431 (*)";

        // MSVS2022 v17.12.0-pre.3.0
        case 0x0104867e: return "[ C ] VS2022 v17.12.0 pre 3.0 build 34430";
        case 0x0103867e: return "[ASM] VS2022 v17.12.0 pre 3.0 build 34430";
        case 0x0105867e: return "[C++] VS2022 v17.12.0 pre 3.0 build 34430";
        case 0x00ff867e: return "[RES] VS2022 v17.12.0 pre 3.0 build 34430";
        case 0x0102867e: return "[LNK] VS2022 v17.12.0 pre 3.0 build 34430";
        case 0x0100867e: return "[EXP] VS2022 v17.12.0 pre 3.0 build 34430";
        case 0x0101867e: return "[IMP] VS2022 v17.12.0 pre 3.0 build 34430";
        case 0x0108867e: return "[LTC] VS2022 v17.12.0 pre 3.0 build 34430";
        case 0x0109867e: return "[LT+] VS2022 v17.12.0 pre 3.0 build 34430";
        case 0x010b867e: return "[PGO] VS2022 v17.12.0 pre 3.0 build 34430";
        case 0x010c867e: return "[PG+] VS2022 v17.12.0 pre 3.0 build 34430";
        case 0x0106867e: return "[CIL] VS2022 v17.12.0 pre 3.0 build 34430 (*)";
        case 0x0107867e: return "[CI+] VS2022 v17.12.0 pre 3.0 build 34430 (*)";
        case 0x010a867e: return "[LTM] VS2022 v17.12.0 pre 3.0 build 34430 (*)";
        case 0x010d867e: return "[POC] VS2022 v17.12.0 pre 3.0 build 34430 (*)";
        case 0x010e867e: return "[PO+] VS2022 v17.12.0 pre 3.0 build 34430 (*)";

        // MSVS2022 v17.12.0-pre.2.0
        // MSVS2022 v17.12.0-pre.2.1
        case 0x01048611: return "[ C ] VS2022 v17.12.0 pre 2.0 build 34321";
        case 0x01038611: return "[ASM] VS2022 v17.12.0 pre 2.0 build 34321";
        case 0x01058611: return "[C++] VS2022 v17.12.0 pre 2.0 build 34321";
        case 0x00ff8611: return "[RES] VS2022 v17.12.0 pre 2.0 build 34321";
        case 0x01028611: return "[LNK] VS2022 v17.12.0 pre 2.0 build 34321";
        case 0x01008611: return "[EXP] VS2022 v17.12.0 pre 2.0 build 34321";
        case 0x01018611: return "[IMP] VS2022 v17.12.0 pre 2.0 build 34321";
        case 0x01088611: return "[LTC] VS2022 v17.12.0 pre 2.0 build 34321";
        case 0x01098611: return "[LT+] VS2022 v17.12.0 pre 2.0 build 34321";
        case 0x010b8611: return "[PGO] VS2022 v17.12.0 pre 2.0 build 34321";
        case 0x010c8611: return "[PG+] VS2022 v17.12.0 pre 2.0 build 34321";
        case 0x01068611: return "[CIL] VS2022 v17.12.0 pre 2.0 build 34321 (*)";
        case 0x01078611: return "[CI+] VS2022 v17.12.0 pre 2.0 build 34321 (*)";
        case 0x010a8611: return "[LTM] VS2022 v17.12.0 pre 2.0 build 34321 (*)";
        case 0x010d8611: return "[POC] VS2022 v17.12.0 pre 2.0 build 34321 (*)";
        case 0x010e8611: return "[PO+] VS2022 v17.12.0 pre 2.0 build 34321 (*)";

        // MSVS2022 v17.12.0-pre.1.0
        case 0x010485b2: return "[ C ] VS2022 v17.12.0 pre 1.0 build 34226";
        case 0x010385b2: return "[ASM] VS2022 v17.12.0 pre 1.0 build 34226";
        case 0x010585b2: return "[C++] VS2022 v17.12.0 pre 1.0 build 34226";
        case 0x00ff85b2: return "[RES] VS2022 v17.12.0 pre 1.0 build 34226";
        case 0x010285b2: return "[LNK] VS2022 v17.12.0 pre 1.0 build 34226";
        case 0x010085b2: return "[EXP] VS2022 v17.12.0 pre 1.0 build 34226";
        case 0x010185b2: return "[IMP] VS2022 v17.12.0 pre 1.0 build 34226";
        case 0x010885b2: return "[LTC] VS2022 v17.12.0 pre 1.0 build 34226";
        case 0x010985b2: return "[LT+] VS2022 v17.12.0 pre 1.0 build 34226";
        case 0x010b85b2: return "[PGO] VS2022 v17.12.0 pre 1.0 build 34226";
        case 0x010c85b2: return "[PG+] VS2022 v17.12.0 pre 1.0 build 34226";
        case 0x010685b2: return "[CIL] VS2022 v17.12.0 pre 1.0 build 34226 (*)";
        case 0x010785b2: return "[CI+] VS2022 v17.12.0 pre 1.0 build 34226 (*)";
        case 0x010a85b2: return "[LTM] VS2022 v17.12.0 pre 1.0 build 34226 (*)";
        case 0x010d85b2: return "[POC] VS2022 v17.12.0 pre 1.0 build 34226 (*)";
        case 0x010e85b2: return "[PO+] VS2022 v17.12.0 pre 1.0 build 34226 (*)";

        // MSVS2022 v17.11.0-pre.7.0
        case 0x01048547: return "[ C ] VS2022 v17.11.0 pre 7.0 build 34119";
        case 0x01038547: return "[ASM] VS2022 v17.11.0 pre 7.0 build 34119";
        case 0x01058547: return "[C++] VS2022 v17.11.0 pre 7.0 build 34119";
        case 0x00ff8547: return "[RES] VS2022 v17.11.0 pre 7.0 build 34119";
        case 0x01028547: return "[LNK] VS2022 v17.11.0 pre 7.0 build 34119";
        case 0x01008547: return "[EXP] VS2022 v17.11.0 pre 7.0 build 34119";
        case 0x01018547: return "[IMP] VS2022 v17.11.0 pre 7.0 build 34119";
        case 0x01088547: return "[LTC] VS2022 v17.11.0 pre 7.0 build 34119";
        case 0x01098547: return "[LT+] VS2022 v17.11.0 pre 7.0 build 34119";
        case 0x010b8547: return "[PGO] VS2022 v17.11.0 pre 7.0 build 34119";
        case 0x010c8547: return "[PG+] VS2022 v17.11.0 pre 7.0 build 34119";
        case 0x01068547: return "[CIL] VS2022 v17.11.0 pre 7.0 build 34119 (*)";
        case 0x01078547: return "[CI+] VS2022 v17.11.0 pre 7.0 build 34119 (*)";
        case 0x010a8547: return "[LTM] VS2022 v17.11.0 pre 7.0 build 34119 (*)";
        case 0x010d8547: return "[POC] VS2022 v17.11.0 pre 7.0 build 34119 (*)";
        case 0x010e8547: return "[PO+] VS2022 v17.11.0 pre 7.0 build 34119 (*)";

        // MSVS2022 v17.11.0-pre.5.0
        // MSVS2022 v17.11.0-pre.6.0
        case 0x01048545: return "[ C ] VS2022 v17.11.0 pre 5.0 build 34117";
        case 0x01038545: return "[ASM] VS2022 v17.11.0 pre 5.0 build 34117";
        case 0x01058545: return "[C++] VS2022 v17.11.0 pre 5.0 build 34117";
        case 0x00ff8545: return "[RES] VS2022 v17.11.0 pre 5.0 build 34117";
        case 0x01028545: return "[LNK] VS2022 v17.11.0 pre 5.0 build 34117";
        case 0x01008545: return "[EXP] VS2022 v17.11.0 pre 5.0 build 34117";
        case 0x01018545: return "[IMP] VS2022 v17.11.0 pre 5.0 build 34117";
        case 0x01088545: return "[LTC] VS2022 v17.11.0 pre 5.0 build 34117";
        case 0x01098545: return "[LT+] VS2022 v17.11.0 pre 5.0 build 34117";
        case 0x010b8545: return "[PGO] VS2022 v17.11.0 pre 5.0 build 34117";
        case 0x010c8545: return "[PG+] VS2022 v17.11.0 pre 5.0 build 34117";
        case 0x01068545: return "[CIL] VS2022 v17.11.0 pre 5.0 build 34117 (*)";
        case 0x01078545: return "[CI+] VS2022 v17.11.0 pre 5.0 build 34117 (*)";
        case 0x010a8545: return "[LTM] VS2022 v17.11.0 pre 5.0 build 34117 (*)";
        case 0x010d8545: return "[POC] VS2022 v17.11.0 pre 5.0 build 34117 (*)";
        case 0x010e8545: return "[PO+] VS2022 v17.11.0 pre 5.0 build 34117 (*)";

        // MSVS2022 v17.11.0-pre.3.0
        // MSVS2022 v17.11.0-pre.4.0
        case 0x010484e5: return "[ C ] VS2022 v17.11.0 pre 3.0 build 34021";
        case 0x010384e5: return "[ASM] VS2022 v17.11.0 pre 3.0 build 34021";
        case 0x010584e5: return "[C++] VS2022 v17.11.0 pre 3.0 build 34021";
        case 0x00ff84e5: return "[RES] VS2022 v17.11.0 pre 3.0 build 34021";
        case 0x010284e5: return "[LNK] VS2022 v17.11.0 pre 3.0 build 34021";
        case 0x010084e5: return "[EXP] VS2022 v17.11.0 pre 3.0 build 34021";
        case 0x010184e5: return "[IMP] VS2022 v17.11.0 pre 3.0 build 34021";
        case 0x010884e5: return "[LTC] VS2022 v17.11.0 pre 3.0 build 34021";
        case 0x010984e5: return "[LT+] VS2022 v17.11.0 pre 3.0 build 34021";
        case 0x010b84e5: return "[PGO] VS2022 v17.11.0 pre 3.0 build 34021";
        case 0x010c84e5: return "[PG+] VS2022 v17.11.0 pre 3.0 build 34021";
        case 0x010684e5: return "[CIL] VS2022 v17.11.0 pre 3.0 build 34021 (*)";
        case 0x010784e5: return "[CI+] VS2022 v17.11.0 pre 3.0 build 34021 (*)";
        case 0x010a84e5: return "[LTM] VS2022 v17.11.0 pre 3.0 build 34021 (*)";
        case 0x010d84e5: return "[POC] VS2022 v17.11.0 pre 3.0 build 34021 (*)";
        case 0x010e84e5: return "[PO+] VS2022 v17.11.0 pre 3.0 build 34021 (*)";

        // MSVS2022 v17.11.0-pre.2.0
        // MSVS2022 v17.11.0-pre.2.1
        case 0x01048483: return "[ C ] VS2022 v17.11.0 pre 2.0 build 33923";
        case 0x01038483: return "[ASM] VS2022 v17.11.0 pre 2.0 build 33923";
        case 0x01058483: return "[C++] VS2022 v17.11.0 pre 2.0 build 33923";
        case 0x00ff8483: return "[RES] VS2022 v17.11.0 pre 2.0 build 33923";
        case 0x01028483: return "[LNK] VS2022 v17.11.0 pre 2.0 build 33923";
        case 0x01008483: return "[EXP] VS2022 v17.11.0 pre 2.0 build 33923";
        case 0x01018483: return "[IMP] VS2022 v17.11.0 pre 2.0 build 33923";
        case 0x01088483: return "[LTC] VS2022 v17.11.0 pre 2.0 build 33923";
        case 0x01098483: return "[LT+] VS2022 v17.11.0 pre 2.0 build 33923";
        case 0x010b8483: return "[PGO] VS2022 v17.11.0 pre 2.0 build 33923";
        case 0x010c8483: return "[PG+] VS2022 v17.11.0 pre 2.0 build 33923";
        case 0x01068483: return "[CIL] VS2022 v17.11.0 pre 2.0 build 33923 (*)";
        case 0x01078483: return "[CI+] VS2022 v17.11.0 pre 2.0 build 33923 (*)";
        case 0x010a8483: return "[LTM] VS2022 v17.11.0 pre 2.0 build 33923 (*)";
        case 0x010d8483: return "[POC] VS2022 v17.11.0 pre 2.0 build 33923 (*)";
        case 0x010e8483: return "[PO+] VS2022 v17.11.0 pre 2.0 build 33923 (*)";

        // MSVS2022 v17.11.0-pre.1.0
        // MSVS2022 v17.11.0-pre.1.1
        case 0x0104846d: return "[ C ] VS2022 v17.11.0 pre 1.0 build 33901";
        case 0x0103846d: return "[ASM] VS2022 v17.11.0 pre 1.0 build 33901";
        case 0x0105846d: return "[C++] VS2022 v17.11.0 pre 1.0 build 33901";
        case 0x00ff846d: return "[RES] VS2022 v17.11.0 pre 1.0 build 33901";
        case 0x0102846d: return "[LNK] VS2022 v17.11.0 pre 1.0 build 33901";
        case 0x0100846d: return "[EXP] VS2022 v17.11.0 pre 1.0 build 33901";
        case 0x0101846d: return "[IMP] VS2022 v17.11.0 pre 1.0 build 33901";
        case 0x0108846d: return "[LTC] VS2022 v17.11.0 pre 1.0 build 33901";
        case 0x0109846d: return "[LT+] VS2022 v17.11.0 pre 1.0 build 33901";
        case 0x010b846d: return "[PGO] VS2022 v17.11.0 pre 1.0 build 33901";
        case 0x010c846d: return "[PG+] VS2022 v17.11.0 pre 1.0 build 33901";
        case 0x0106846d: return "[CIL] VS2022 v17.11.0 pre 1.0 build 33901 (*)";
        case 0x0107846d: return "[CI+] VS2022 v17.11.0 pre 1.0 build 33901 (*)";
        case 0x010a846d: return "[LTM] VS2022 v17.11.0 pre 1.0 build 33901 (*)";
        case 0x010d846d: return "[POC] VS2022 v17.11.0 pre 1.0 build 33901 (*)";
        case 0x010e846d: return "[PO+] VS2022 v17.11.0 pre 1.0 build 33901 (*)";

        // MSVS2022 v17.10.0-pre.5.0
        // MSVS2022 v17.10.0-pre.6.0
        // MSVS2022 v17.10.0-pre.7.0
        // MSVS2022 v17.10.0
        case 0x01048410: return "[ C ] VS2022 v17.10.0 pre 5.0 build 33808";
        case 0x01038410: return "[ASM] VS2022 v17.10.0 pre 5.0 build 33808";
        case 0x01058410: return "[C++] VS2022 v17.10.0 pre 5.0 build 33808";
        case 0x00ff8410: return "[RES] VS2022 v17.10.0 pre 5.0 build 33808";
        case 0x01028410: return "[LNK] VS2022 v17.10.0 pre 5.0 build 33808";
        case 0x01008410: return "[EXP] VS2022 v17.10.0 pre 5.0 build 33808";
        case 0x01018410: return "[IMP] VS2022 v17.10.0 pre 5.0 build 33808";
        case 0x01088410: return "[LTC] VS2022 v17.10.0 pre 5.0 build 33808";
        case 0x01098410: return "[LT+] VS2022 v17.10.0 pre 5.0 build 33808";
        case 0x010b8410: return "[PGO] VS2022 v17.10.0 pre 5.0 build 33808";
        case 0x010c8410: return "[PG+] VS2022 v17.10.0 pre 5.0 build 33808";
        case 0x01068410: return "[CIL] VS2022 v17.10.0 pre 5.0 build 33808 (*)";
        case 0x01078410: return "[CI+] VS2022 v17.10.0 pre 5.0 build 33808 (*)";
        case 0x010a8410: return "[LTM] VS2022 v17.10.0 pre 5.0 build 33808 (*)";
        case 0x010d8410: return "[POC] VS2022 v17.10.0 pre 5.0 build 33808 (*)";
        case 0x010e8410: return "[PO+] VS2022 v17.10.0 pre 5.0 build 33808 (*)";

        // MSVS2022 v17.10.0-pre.4.0
        case 0x0104840f: return "[ C ] VS2022 v17.10.0 pre 4.0 build 33807";
        case 0x0103840f: return "[ASM] VS2022 v17.10.0 pre 4.0 build 33807";
        case 0x0105840f: return "[C++] VS2022 v17.10.0 pre 4.0 build 33807";
        case 0x00ff840f: return "[RES] VS2022 v17.10.0 pre 4.0 build 33807";
        case 0x0102840f: return "[LNK] VS2022 v17.10.0 pre 4.0 build 33807";
        case 0x0100840f: return "[EXP] VS2022 v17.10.0 pre 4.0 build 33807";
        case 0x0101840f: return "[IMP] VS2022 v17.10.0 pre 4.0 build 33807";
        case 0x0108840f: return "[LTC] VS2022 v17.10.0 pre 4.0 build 33807";
        case 0x0109840f: return "[LT+] VS2022 v17.10.0 pre 4.0 build 33807";
        case 0x010b840f: return "[PGO] VS2022 v17.10.0 pre 4.0 build 33807";
        case 0x010c840f: return "[PG+] VS2022 v17.10.0 pre 4.0 build 33807";
        case 0x0106840f: return "[CIL] VS2022 v17.10.0 pre 4.0 build 33807 (*)";
        case 0x0107840f: return "[CI+] VS2022 v17.10.0 pre 4.0 build 33807 (*)";
        case 0x010a840f: return "[LTM] VS2022 v17.10.0 pre 4.0 build 33807 (*)";
        case 0x010d840f: return "[POC] VS2022 v17.10.0 pre 4.0 build 33807 (*)";
        case 0x010e840f: return "[PO+] VS2022 v17.10.0 pre 4.0 build 33807 (*)";

        // MSVS2022 v17.10.0-pre.3.0
        case 0x010483b9: return "[ C ] VS2022 v17.10.0 pre 3.0 build 33721";
        case 0x010383b9: return "[ASM] VS2022 v17.10.0 pre 3.0 build 33721";
        case 0x010583b9: return "[C++] VS2022 v17.10.0 pre 3.0 build 33721";
        case 0x00ff83b9: return "[RES] VS2022 v17.10.0 pre 3.0 build 33721";
        case 0x010283b9: return "[LNK] VS2022 v17.10.0 pre 3.0 build 33721";
        case 0x010083b9: return "[EXP] VS2022 v17.10.0 pre 3.0 build 33721";
        case 0x010183b9: return "[IMP] VS2022 v17.10.0 pre 3.0 build 33721";
        case 0x010883b9: return "[LTC] VS2022 v17.10.0 pre 3.0 build 33721";
        case 0x010983b9: return "[LT+] VS2022 v17.10.0 pre 3.0 build 33721";
        case 0x010b83b9: return "[PGO] VS2022 v17.10.0 pre 3.0 build 33721";
        case 0x010c83b9: return "[PG+] VS2022 v17.10.0 pre 3.0 build 33721";
        case 0x010683b9: return "[CIL] VS2022 v17.10.0 pre 3.0 build 33721 (*)";
        case 0x010783b9: return "[CI+] VS2022 v17.10.0 pre 3.0 build 33721 (*)";
        case 0x010a83b9: return "[LTM] VS2022 v17.10.0 pre 3.0 build 33721 (*)";
        case 0x010d83b9: return "[POC] VS2022 v17.10.0 pre 3.0 build 33721 (*)";
        case 0x010e83b9: return "[PO+] VS2022 v17.10.0 pre 3.0 build 33721 (*)";

        // MSVS2022 v17.10.0-pre.2.0
        case 0x01048351: return "[ C ] VS2022 v17.10.0 pre 2.0 build 33617";
        case 0x01038351: return "[ASM] VS2022 v17.10.0 pre 2.0 build 33617";
        case 0x01058351: return "[C++] VS2022 v17.10.0 pre 2.0 build 33617";
        case 0x00ff8351: return "[RES] VS2022 v17.10.0 pre 2.0 build 33617";
        case 0x01028351: return "[LNK] VS2022 v17.10.0 pre 2.0 build 33617";
        case 0x01008351: return "[EXP] VS2022 v17.10.0 pre 2.0 build 33617";
        case 0x01018351: return "[IMP] VS2022 v17.10.0 pre 2.0 build 33617";
        case 0x01088351: return "[LTC] VS2022 v17.10.0 pre 2.0 build 33617";
        case 0x01098351: return "[LT+] VS2022 v17.10.0 pre 2.0 build 33617";
        case 0x010b8351: return "[PGO] VS2022 v17.10.0 pre 2.0 build 33617";
        case 0x010c8351: return "[PG+] VS2022 v17.10.0 pre 2.0 build 33617";
        case 0x01068351: return "[CIL] VS2022 v17.10.0 pre 2.0 build 33617 (*)";
        case 0x01078351: return "[CI+] VS2022 v17.10.0 pre 2.0 build 33617 (*)";
        case 0x010a8351: return "[LTM] VS2022 v17.10.0 pre 2.0 build 33617 (*)";
        case 0x010d8351: return "[POC] VS2022 v17.10.0 pre 2.0 build 33617 (*)";
        case 0x010e8351: return "[PO+] VS2022 v17.10.0 pre 2.0 build 33617 (*)";

        // MSVS2022 v17.10.0-pre.1.0
        // MSVS2022 v17.9.2
        case 0x010482f1: return "[ C ] VS2022 v17.10.0 pre 1.0 build 33521";
        case 0x010382f1: return "[ASM] VS2022 v17.10.0 pre 1.0 build 33521";
        case 0x010582f1: return "[C++] VS2022 v17.10.0 pre 1.0 build 33521";
        case 0x00ff82f1: return "[RES] VS2022 v17.10.0 pre 1.0 build 33521";
        case 0x010282f1: return "[LNK] VS2022 v17.10.0 pre 1.0 build 33521";
        case 0x010082f1: return "[EXP] VS2022 v17.10.0 pre 1.0 build 33521";
        case 0x010182f1: return "[IMP] VS2022 v17.10.0 pre 1.0 build 33521";
        case 0x010882f1: return "[LTC] VS2022 v17.10.0 pre 1.0 build 33521";
        case 0x010982f1: return "[LT+] VS2022 v17.10.0 pre 1.0 build 33521";
        case 0x010b82f1: return "[PGO] VS2022 v17.10.0 pre 1.0 build 33521";
        case 0x010c82f1: return "[PG+] VS2022 v17.10.0 pre 1.0 build 33521";
        case 0x010682f1: return "[CIL] VS2022 v17.10.0 pre 1.0 build 33521 (*)";
        case 0x010782f1: return "[CI+] VS2022 v17.10.0 pre 1.0 build 33521 (*)";
        case 0x010a82f1: return "[LTM] VS2022 v17.10.0 pre 1.0 build 33521 (*)";
        case 0x010d82f1: return "[POC] VS2022 v17.10.0 pre 1.0 build 33521 (*)";
        case 0x010e82f1: return "[PO+] VS2022 v17.10.0 pre 1.0 build 33521 (*)";

        // MSVS2022 v17.9.0-pre.5.0
        // MSVS2022 v17.9.0
        case 0x010482ef: return "[ C ] VS2022 v17.9.0 pre 5.0 build 33519";
        case 0x010382ef: return "[ASM] VS2022 v17.9.0 pre 5.0 build 33519";
        case 0x010582ef: return "[C++] VS2022 v17.9.0 pre 5.0 build 33519";
        case 0x00ff82ef: return "[RES] VS2022 v17.9.0 pre 5.0 build 33519";
        case 0x010282ef: return "[LNK] VS2022 v17.9.0 pre 5.0 build 33519";
        case 0x010082ef: return "[EXP] VS2022 v17.9.0 pre 5.0 build 33519";
        case 0x010182ef: return "[IMP] VS2022 v17.9.0 pre 5.0 build 33519";
        case 0x010882ef: return "[LTC] VS2022 v17.9.0 pre 5.0 build 33519";
        case 0x010982ef: return "[LT+] VS2022 v17.9.0 pre 5.0 build 33519";
        case 0x010b82ef: return "[PGO] VS2022 v17.9.0 pre 5.0 build 33519";
        case 0x010c82ef: return "[PG+] VS2022 v17.9.0 pre 5.0 build 33519";
        case 0x010682ef: return "[CIL] VS2022 v17.9.0 pre 5.0 build 33519 (*)";
        case 0x010782ef: return "[CI+] VS2022 v17.9.0 pre 5.0 build 33519 (*)";
        case 0x010a82ef: return "[LTM] VS2022 v17.9.0 pre 5.0 build 33519 (*)";
        case 0x010d82ef: return "[POC] VS2022 v17.9.0 pre 5.0 build 33519 (*)";
        case 0x010e82ef: return "[PO+] VS2022 v17.9.0 pre 5.0 build 33519 (*)";

        // MSVS2022 v17.9.0-pre.3.0
        // MSVS2022 v17.9.0-pre.4.0
        case 0x01048294: return "[ C ] VS2022 v17.9.0 pre 3.0 build 33428";
        case 0x01038294: return "[ASM] VS2022 v17.9.0 pre 3.0 build 33428";
        case 0x01058294: return "[C++] VS2022 v17.9.0 pre 3.0 build 33428";
        case 0x00ff8294: return "[RES] VS2022 v17.9.0 pre 3.0 build 33428";
        case 0x01028294: return "[LNK] VS2022 v17.9.0 pre 3.0 build 33428";
        case 0x01008294: return "[EXP] VS2022 v17.9.0 pre 3.0 build 33428";
        case 0x01018294: return "[IMP] VS2022 v17.9.0 pre 3.0 build 33428";
        case 0x01088294: return "[LTC] VS2022 v17.9.0 pre 3.0 build 33428";
        case 0x01098294: return "[LT+] VS2022 v17.9.0 pre 3.0 build 33428";
        case 0x010b8294: return "[PGO] VS2022 v17.9.0 pre 3.0 build 33428";
        case 0x010c8294: return "[PG+] VS2022 v17.9.0 pre 3.0 build 33428";
        case 0x01068294: return "[CIL] VS2022 v17.9.0 pre 3.0 build 33428 (*)";
        case 0x01078294: return "[CI+] VS2022 v17.9.0 pre 3.0 build 33428 (*)";
        case 0x010a8294: return "[LTM] VS2022 v17.9.0 pre 3.0 build 33428 (*)";
        case 0x010d8294: return "[POC] VS2022 v17.9.0 pre 3.0 build 33428 (*)";
        case 0x010e8294: return "[PO+] VS2022 v17.9.0 pre 3.0 build 33428 (*)";

        // MSVS2022 v17.9.0-pre.2.0
        // MSVS2022 v17.9.0-pre.2.1
        case 0x01048229: return "[ C ] VS2022 v17.9.0 pre 2.0 build 33321";
        case 0x01038229: return "[ASM] VS2022 v17.9.0 pre 2.0 build 33321";
        case 0x01058229: return "[C++] VS2022 v17.9.0 pre 2.0 build 33321";
        case 0x00ff8229: return "[RES] VS2022 v17.9.0 pre 2.0 build 33321";
        case 0x01028229: return "[LNK] VS2022 v17.9.0 pre 2.0 build 33321";
        case 0x01008229: return "[EXP] VS2022 v17.9.0 pre 2.0 build 33321";
        case 0x01018229: return "[IMP] VS2022 v17.9.0 pre 2.0 build 33321";
        case 0x01088229: return "[LTC] VS2022 v17.9.0 pre 2.0 build 33321";
        case 0x01098229: return "[LT+] VS2022 v17.9.0 pre 2.0 build 33321";
        case 0x010b8229: return "[PGO] VS2022 v17.9.0 pre 2.0 build 33321";
        case 0x010c8229: return "[PG+] VS2022 v17.9.0 pre 2.0 build 33321";
        case 0x01068229: return "[CIL] VS2022 v17.9.0 pre 2.0 build 33321 (*)";
        case 0x01078229: return "[CI+] VS2022 v17.9.0 pre 2.0 build 33321 (*)";
        case 0x010a8229: return "[LTM] VS2022 v17.9.0 pre 2.0 build 33321 (*)";
        case 0x010d8229: return "[POC] VS2022 v17.9.0 pre 2.0 build 33321 (*)";
        case 0x010e8229: return "[PO+] VS2022 v17.9.0 pre 2.0 build 33321 (*)";

        // MSVS2022 v17.9.0-pre.1.0
        // MSVS2022 v17.9.0-pre.1.1
        case 0x010481c2: return "[ C ] VS2022 v17.9.0 pre 1.0 build 33218";
        case 0x010381c2: return "[ASM] VS2022 v17.9.0 pre 1.0 build 33218";
        case 0x010581c2: return "[C++] VS2022 v17.9.0 pre 1.0 build 33218";
        case 0x00ff81c2: return "[RES] VS2022 v17.9.0 pre 1.0 build 33218";
        case 0x010281c2: return "[LNK] VS2022 v17.9.0 pre 1.0 build 33218";
        case 0x010081c2: return "[EXP] VS2022 v17.9.0 pre 1.0 build 33218";
        case 0x010181c2: return "[IMP] VS2022 v17.9.0 pre 1.0 build 33218";
        case 0x010881c2: return "[LTC] VS2022 v17.9.0 pre 1.0 build 33218";
        case 0x010981c2: return "[LT+] VS2022 v17.9.0 pre 1.0 build 33218";
        case 0x010b81c2: return "[PGO] VS2022 v17.9.0 pre 1.0 build 33218";
        case 0x010c81c2: return "[PG+] VS2022 v17.9.0 pre 1.0 build 33218";
        case 0x010681c2: return "[CIL] VS2022 v17.9.0 pre 1.0 build 33218 (*)";
        case 0x010781c2: return "[CI+] VS2022 v17.9.0 pre 1.0 build 33218 (*)";
        case 0x010a81c2: return "[LTM] VS2022 v17.9.0 pre 1.0 build 33218 (*)";
        case 0x010d81c2: return "[POC] VS2022 v17.9.0 pre 1.0 build 33218 (*)";
        case 0x010e81c2: return "[PO+] VS2022 v17.9.0 pre 1.0 build 33218 (*)";

        // MSVS2022 v17.8.0-pre.6.0
        case 0x01048169: return "[ C ] VS2022 v17.8.0 pre 6.0 build 33129";
        case 0x01038169: return "[ASM] VS2022 v17.8.0 pre 6.0 build 33129";
        case 0x01058169: return "[C++] VS2022 v17.8.0 pre 6.0 build 33129";
        case 0x00ff8169: return "[RES] VS2022 v17.8.0 pre 6.0 build 33129";
        case 0x01028169: return "[LNK] VS2022 v17.8.0 pre 6.0 build 33129";
        case 0x01008169: return "[EXP] VS2022 v17.8.0 pre 6.0 build 33129";
        case 0x01018169: return "[IMP] VS2022 v17.8.0 pre 6.0 build 33129";
        case 0x01088169: return "[LTC] VS2022 v17.8.0 pre 6.0 build 33129";
        case 0x01098169: return "[LT+] VS2022 v17.8.0 pre 6.0 build 33129";
        case 0x010b8169: return "[PGO] VS2022 v17.8.0 pre 6.0 build 33129";
        case 0x010c8169: return "[PG+] VS2022 v17.8.0 pre 6.0 build 33129";
        case 0x01068169: return "[CIL] VS2022 v17.8.0 pre 6.0 build 33129 (*)";
        case 0x01078169: return "[CI+] VS2022 v17.8.0 pre 6.0 build 33129 (*)";
        case 0x010a8169: return "[LTM] VS2022 v17.8.0 pre 6.0 build 33129 (*)";
        case 0x010d8169: return "[POC] VS2022 v17.8.0 pre 6.0 build 33129 (*)";
        case 0x010e8169: return "[PO+] VS2022 v17.8.0 pre 6.0 build 33129 (*)";

        // MSVS2022 v17.8.0-pre.5.0
        case 0x01048168: return "[ C ] VS2022 v17.8.0 pre 5.0 build 33128";
        case 0x01038168: return "[ASM] VS2022 v17.8.0 pre 5.0 build 33128";
        case 0x01058168: return "[C++] VS2022 v17.8.0 pre 5.0 build 33128";
        case 0x00ff8168: return "[RES] VS2022 v17.8.0 pre 5.0 build 33128";
        case 0x01028168: return "[LNK] VS2022 v17.8.0 pre 5.0 build 33128";
        case 0x01008168: return "[EXP] VS2022 v17.8.0 pre 5.0 build 33128";
        case 0x01018168: return "[IMP] VS2022 v17.8.0 pre 5.0 build 33128";
        case 0x01088168: return "[LTC] VS2022 v17.8.0 pre 5.0 build 33128";
        case 0x01098168: return "[LT+] VS2022 v17.8.0 pre 5.0 build 33128";
        case 0x010b8168: return "[PGO] VS2022 v17.8.0 pre 5.0 build 33128";
        case 0x010c8168: return "[PG+] VS2022 v17.8.0 pre 5.0 build 33128";
        case 0x01068168: return "[CIL] VS2022 v17.8.0 pre 5.0 build 33128 (*)";
        case 0x01078168: return "[CI+] VS2022 v17.8.0 pre 5.0 build 33128 (*)";
        case 0x010a8168: return "[LTM] VS2022 v17.8.0 pre 5.0 build 33128 (*)";
        case 0x010d8168: return "[POC] VS2022 v17.8.0 pre 5.0 build 33128 (*)";
        case 0x010e8168: return "[PO+] VS2022 v17.8.0 pre 5.0 build 33128 (*)";

        // MSVS2022 v17.8.0-pre.3.0
        // MSVS2022 v17.8.0-pre.4.0
        case 0x01048166: return "[ C ] VS2022 v17.8.0 pre 3.0 build 33126";
        case 0x01038166: return "[ASM] VS2022 v17.8.0 pre 3.0 build 33126";
        case 0x01058166: return "[C++] VS2022 v17.8.0 pre 3.0 build 33126";
        case 0x00ff8166: return "[RES] VS2022 v17.8.0 pre 3.0 build 33126";
        case 0x01028166: return "[LNK] VS2022 v17.8.0 pre 3.0 build 33126";
        case 0x01008166: return "[EXP] VS2022 v17.8.0 pre 3.0 build 33126";
        case 0x01018166: return "[IMP] VS2022 v17.8.0 pre 3.0 build 33126";
        case 0x01088166: return "[LTC] VS2022 v17.8.0 pre 3.0 build 33126";
        case 0x01098166: return "[LT+] VS2022 v17.8.0 pre 3.0 build 33126";
        case 0x010b8166: return "[PGO] VS2022 v17.8.0 pre 3.0 build 33126";
        case 0x010c8166: return "[PG+] VS2022 v17.8.0 pre 3.0 build 33126";
        case 0x01068166: return "[CIL] VS2022 v17.8.0 pre 3.0 build 33126 (*)";
        case 0x01078166: return "[CI+] VS2022 v17.8.0 pre 3.0 build 33126 (*)";
        case 0x010a8166: return "[LTM] VS2022 v17.8.0 pre 3.0 build 33126 (*)";
        case 0x010d8166: return "[POC] VS2022 v17.8.0 pre 3.0 build 33126 (*)";
        case 0x010e8166: return "[PO+] VS2022 v17.8.0 pre 3.0 build 33126 (*)";

        // MSVS2022 v17.8.0-pre.2.0
        case 0x01048106: return "[ C ] VS2022 v17.8.0 pre 2.0 build 33030";
        case 0x01038106: return "[ASM] VS2022 v17.8.0 pre 2.0 build 33030";
        case 0x01058106: return "[C++] VS2022 v17.8.0 pre 2.0 build 33030";
        case 0x00ff8106: return "[RES] VS2022 v17.8.0 pre 2.0 build 33030";
        case 0x01028106: return "[LNK] VS2022 v17.8.0 pre 2.0 build 33030";
        case 0x01008106: return "[EXP] VS2022 v17.8.0 pre 2.0 build 33030";
        case 0x01018106: return "[IMP] VS2022 v17.8.0 pre 2.0 build 33030";
        case 0x01088106: return "[LTC] VS2022 v17.8.0 pre 2.0 build 33030";
        case 0x01098106: return "[LT+] VS2022 v17.8.0 pre 2.0 build 33030";
        case 0x010b8106: return "[PGO] VS2022 v17.8.0 pre 2.0 build 33030";
        case 0x010c8106: return "[PG+] VS2022 v17.8.0 pre 2.0 build 33030";
        case 0x01068106: return "[CIL] VS2022 v17.8.0 pre 2.0 build 33030 (*)";
        case 0x01078106: return "[CI+] VS2022 v17.8.0 pre 2.0 build 33030 (*)";
        case 0x010a8106: return "[LTM] VS2022 v17.8.0 pre 2.0 build 33030 (*)";
        case 0x010d8106: return "[POC] VS2022 v17.8.0 pre 2.0 build 33030 (*)";
        case 0x010e8106: return "[PO+] VS2022 v17.8.0 pre 2.0 build 33030 (*)";

        // MSVS2022 v17.8.0-pre.1.0
        case 0x01048097: return "[ C ] VS2022 v17.8.0 pre 1.0 build 32919";
        case 0x01038097: return "[ASM] VS2022 v17.8.0 pre 1.0 build 32919";
        case 0x01058097: return "[C++] VS2022 v17.8.0 pre 1.0 build 32919";
        case 0x00ff8097: return "[RES] VS2022 v17.8.0 pre 1.0 build 32919";
        case 0x01028097: return "[LNK] VS2022 v17.8.0 pre 1.0 build 32919";
        case 0x01008097: return "[EXP] VS2022 v17.8.0 pre 1.0 build 32919";
        case 0x01018097: return "[IMP] VS2022 v17.8.0 pre 1.0 build 32919";
        case 0x01088097: return "[LTC] VS2022 v17.8.0 pre 1.0 build 32919";
        case 0x01098097: return "[LT+] VS2022 v17.8.0 pre 1.0 build 32919";
        case 0x010b8097: return "[PGO] VS2022 v17.8.0 pre 1.0 build 32919";
        case 0x010c8097: return "[PG+] VS2022 v17.8.0 pre 1.0 build 32919";
        case 0x01068097: return "[CIL] VS2022 v17.8.0 pre 1.0 build 32919 (*)";
        case 0x01078097: return "[CI+] VS2022 v17.8.0 pre 1.0 build 32919 (*)";
        case 0x010a8097: return "[LTM] VS2022 v17.8.0 pre 1.0 build 32919 (*)";
        case 0x010d8097: return "[POC] VS2022 v17.8.0 pre 1.0 build 32919 (*)";
        case 0x010e8097: return "[PO+] VS2022 v17.8.0 pre 1.0 build 32919 (*)";

        // MSVS2022 v17.7.0-pre.3.0
        // MSVS2022 v17.7.0-pre.4.0
        // MSVS2022 v17.7.0-pre.5.0
        // MSVS2022 v17.7.0-pre.6.0
        case 0x01048034: return "[ C ] VS2022 v17.7.0 pre 3.0 build 32820";
        case 0x01038034: return "[ASM] VS2022 v17.7.0 pre 3.0 build 32820";
        case 0x01058034: return "[C++] VS2022 v17.7.0 pre 3.0 build 32820";
        case 0x00ff8034: return "[RES] VS2022 v17.7.0 pre 3.0 build 32820";
        case 0x01028034: return "[LNK] VS2022 v17.7.0 pre 3.0 build 32820";
        case 0x01008034: return "[EXP] VS2022 v17.7.0 pre 3.0 build 32820";
        case 0x01018034: return "[IMP] VS2022 v17.7.0 pre 3.0 build 32820";
        case 0x01088034: return "[LTC] VS2022 v17.7.0 pre 3.0 build 32820";
        case 0x01098034: return "[LT+] VS2022 v17.7.0 pre 3.0 build 32820";
        case 0x010b8034: return "[PGO] VS2022 v17.7.0 pre 3.0 build 32820";
        case 0x010c8034: return "[PG+] VS2022 v17.7.0 pre 3.0 build 32820";
        case 0x01068034: return "[CIL] VS2022 v17.7.0 pre 3.0 build 32820 (*)";
        case 0x01078034: return "[CI+] VS2022 v17.7.0 pre 3.0 build 32820 (*)";
        case 0x010a8034: return "[LTM] VS2022 v17.7.0 pre 3.0 build 32820 (*)";
        case 0x010d8034: return "[POC] VS2022 v17.7.0 pre 3.0 build 32820 (*)";
        case 0x010e8034: return "[PO+] VS2022 v17.7.0 pre 3.0 build 32820 (*)";

        // MSVS2022 v17.7.0-pre.1.0
        // MSVS2022 v17.7.0-pre.2.0
        case 0x01047fc1: return "[ C ] VS2022 v17.7.0 pre 1.0 build 32705";
        case 0x01037fc1: return "[ASM] VS2022 v17.7.0 pre 1.0 build 32705";
        case 0x01057fc1: return "[C++] VS2022 v17.7.0 pre 1.0 build 32705";
        case 0x00ff7fc1: return "[RES] VS2022 v17.7.0 pre 1.0 build 32705";
        case 0x01027fc1: return "[LNK] VS2022 v17.7.0 pre 1.0 build 32705";
        case 0x01007fc1: return "[EXP] VS2022 v17.7.0 pre 1.0 build 32705";
        case 0x01017fc1: return "[IMP] VS2022 v17.7.0 pre 1.0 build 32705";
        case 0x01087fc1: return "[LTC] VS2022 v17.7.0 pre 1.0 build 32705";
        case 0x01097fc1: return "[LT+] VS2022 v17.7.0 pre 1.0 build 32705";
        case 0x010b7fc1: return "[PGO] VS2022 v17.7.0 pre 1.0 build 32705";
        case 0x010c7fc1: return "[PG+] VS2022 v17.7.0 pre 1.0 build 32705";
        case 0x01067fc1: return "[CIL] VS2022 v17.7.0 pre 1.0 build 32705 (*)";
        case 0x01077fc1: return "[CI+] VS2022 v17.7.0 pre 1.0 build 32705 (*)";
        case 0x010a7fc1: return "[LTM] VS2022 v17.7.0 pre 1.0 build 32705 (*)";
        case 0x010d7fc1: return "[POC] VS2022 v17.7.0 pre 1.0 build 32705 (*)";
        case 0x010e7fc1: return "[PO+] VS2022 v17.7.0 pre 1.0 build 32705 (*)";

        // MSVS2022 v17.6.0-pre.5.0
        // MSVS2022 v17.6.0-pre.6.0
        // MSVS2022 v17.6.0-pre.7.0
        case 0x01047f12: return "[ C ] VS2022 v17.6.0 pre 5.0 build 32530";
        case 0x01037f12: return "[ASM] VS2022 v17.6.0 pre 5.0 build 32530";
        case 0x01057f12: return "[C++] VS2022 v17.6.0 pre 5.0 build 32530";
        case 0x00ff7f12: return "[RES] VS2022 v17.6.0 pre 5.0 build 32530";
        case 0x01027f12: return "[LNK] VS2022 v17.6.0 pre 5.0 build 32530";
        case 0x01007f12: return "[EXP] VS2022 v17.6.0 pre 5.0 build 32530";
        case 0x01017f12: return "[IMP] VS2022 v17.6.0 pre 5.0 build 32530";
        case 0x01087f12: return "[LTC] VS2022 v17.6.0 pre 5.0 build 32530";
        case 0x01097f12: return "[LT+] VS2022 v17.6.0 pre 5.0 build 32530";
        case 0x010b7f12: return "[PGO] VS2022 v17.6.0 pre 5.0 build 32530";
        case 0x010c7f12: return "[PG+] VS2022 v17.6.0 pre 5.0 build 32530";
        case 0x01067f12: return "[CIL] VS2022 v17.6.0 pre 5.0 build 32530 (*)";
        case 0x01077f12: return "[CI+] VS2022 v17.6.0 pre 5.0 build 32530 (*)";
        case 0x010a7f12: return "[LTM] VS2022 v17.6.0 pre 5.0 build 32530 (*)";
        case 0x010d7f12: return "[POC] VS2022 v17.6.0 pre 5.0 build 32530 (*)";
        case 0x010e7f12: return "[PO+] VS2022 v17.6.0 pre 5.0 build 32530 (*)";

        // MSVS2022 v17.6.0-pre.3.0
        // MSVS2022 v17.6.0-pre.4.0
        case 0x01047f0a: return "[ C ] VS2022 v17.6.0 pre 3.0 build 32522";
        case 0x01037f0a: return "[ASM] VS2022 v17.6.0 pre 3.0 build 32522";
        case 0x01057f0a: return "[C++] VS2022 v17.6.0 pre 3.0 build 32522";
        case 0x00ff7f0a: return "[RES] VS2022 v17.6.0 pre 3.0 build 32522";
        case 0x01027f0a: return "[LNK] VS2022 v17.6.0 pre 3.0 build 32522";
        case 0x01007f0a: return "[EXP] VS2022 v17.6.0 pre 3.0 build 32522";
        case 0x01017f0a: return "[IMP] VS2022 v17.6.0 pre 3.0 build 32522";
        case 0x01087f0a: return "[LTC] VS2022 v17.6.0 pre 3.0 build 32522";
        case 0x01097f0a: return "[LT+] VS2022 v17.6.0 pre 3.0 build 32522";
        case 0x010b7f0a: return "[PGO] VS2022 v17.6.0 pre 3.0 build 32522";
        case 0x010c7f0a: return "[PG+] VS2022 v17.6.0 pre 3.0 build 32522";
        case 0x01067f0a: return "[CIL] VS2022 v17.6.0 pre 3.0 build 32522 (*)";
        case 0x01077f0a: return "[CI+] VS2022 v17.6.0 pre 3.0 build 32522 (*)";
        case 0x010a7f0a: return "[LTM] VS2022 v17.6.0 pre 3.0 build 32522 (*)";
        case 0x010d7f0a: return "[POC] VS2022 v17.6.0 pre 3.0 build 32522 (*)";
        case 0x010e7f0a: return "[PO+] VS2022 v17.6.0 pre 3.0 build 32522 (*)";

        // MSVS2022 v17.6.0-pre.2.0
        case 0x01047ef6: return "[ C ] VS2022 v17.6.0 pre 2.0 build 32502";
        case 0x01037ef6: return "[ASM] VS2022 v17.6.0 pre 2.0 build 32502";
        case 0x01057ef6: return "[C++] VS2022 v17.6.0 pre 2.0 build 32502";
        case 0x00ff7ef6: return "[RES] VS2022 v17.6.0 pre 2.0 build 32502";
        case 0x01027ef6: return "[LNK] VS2022 v17.6.0 pre 2.0 build 32502";
        case 0x01007ef6: return "[EXP] VS2022 v17.6.0 pre 2.0 build 32502";
        case 0x01017ef6: return "[IMP] VS2022 v17.6.0 pre 2.0 build 32502";
        case 0x01087ef6: return "[LTC] VS2022 v17.6.0 pre 2.0 build 32502";
        case 0x01097ef6: return "[LT+] VS2022 v17.6.0 pre 2.0 build 32502";
        case 0x010b7ef6: return "[PGO] VS2022 v17.6.0 pre 2.0 build 32502";
        case 0x010c7ef6: return "[PG+] VS2022 v17.6.0 pre 2.0 build 32502";
        case 0x01067ef6: return "[CIL] VS2022 v17.6.0 pre 2.0 build 32502 (*)";
        case 0x01077ef6: return "[CI+] VS2022 v17.6.0 pre 2.0 build 32502 (*)";
        case 0x010a7ef6: return "[LTM] VS2022 v17.6.0 pre 2.0 build 32502 (*)";
        case 0x010d7ef6: return "[POC] VS2022 v17.6.0 pre 2.0 build 32502 (*)";
        case 0x010e7ef6: return "[PO+] VS2022 v17.6.0 pre 2.0 build 32502 (*)";

        // MSVS2022 v17.6.0-pre.1.0
        case 0x01047e43: return "[ C ] VS2022 v17.6.0 pre 1.0 build 32323";
        case 0x01037e43: return "[ASM] VS2022 v17.6.0 pre 1.0 build 32323";
        case 0x01057e43: return "[C++] VS2022 v17.6.0 pre 1.0 build 32323";
        case 0x00ff7e43: return "[RES] VS2022 v17.6.0 pre 1.0 build 32323";
        case 0x01027e43: return "[LNK] VS2022 v17.6.0 pre 1.0 build 32323";
        case 0x01007e43: return "[EXP] VS2022 v17.6.0 pre 1.0 build 32323";
        case 0x01017e43: return "[IMP] VS2022 v17.6.0 pre 1.0 build 32323";
        case 0x01067e43: return "[CIL] VS2022 v17.6.0 pre 1.0 build 32323 (*)";
        case 0x01077e43: return "[CI+] VS2022 v17.6.0 pre 1.0 build 32323 (*)";
        case 0x01087e43: return "[LTC] VS2022 v17.6.0 pre 1.0 build 32323 (*)";
        case 0x01097e43: return "[LT+] VS2022 v17.6.0 pre 1.0 build 32323 (*)";
        case 0x010a7e43: return "[LTM] VS2022 v17.6.0 pre 1.0 build 32323 (*)";
        case 0x010b7e43: return "[PGO] VS2022 v17.6.0 pre 1.0 build 32323 (*)";
        case 0x010c7e43: return "[PG+] VS2022 v17.6.0 pre 1.0 build 32323 (*)";
        case 0x010d7e43: return "[POC] VS2022 v17.6.0 pre 1.0 build 32323 (*)";
        case 0x010e7e43: return "[PO+] VS2022 v17.6.0 pre 1.0 build 32323 (*)";

        // MSVS2022 v17.5.0-pre.4.0
        case 0x01047dd5: return "[ C ] VS2022 v17.5.0 pre 4.0 build 32213";
        case 0x01037dd5: return "[ASM] VS2022 v17.5.0 pre 4.0 build 32213";
        case 0x01057dd5: return "[C++] VS2022 v17.5.0 pre 4.0 build 32213";
        case 0x00ff7dd5: return "[RES] VS2022 v17.5.0 pre 4.0 build 32213";
        case 0x01027dd5: return "[LNK] VS2022 v17.5.0 pre 4.0 build 32213";
        case 0x01007dd5: return "[EXP] VS2022 v17.5.0 pre 4.0 build 32213";
        case 0x01017dd5: return "[IMP] VS2022 v17.5.0 pre 4.0 build 32213";
        case 0x01067dd5: return "[CIL] VS2022 v17.5.0 pre 4.0 build 32213 (*)";
        case 0x01077dd5: return "[CI+] VS2022 v17.5.0 pre 4.0 build 32213 (*)";
        case 0x01087dd5: return "[LTC] VS2022 v17.5.0 pre 4.0 build 32213 (*)";
        case 0x01097dd5: return "[LT+] VS2022 v17.5.0 pre 4.0 build 32213 (*)";
        case 0x010a7dd5: return "[LTM] VS2022 v17.5.0 pre 4.0 build 32213 (*)";
        case 0x010b7dd5: return "[PGO] VS2022 v17.5.0 pre 4.0 build 32213 (*)";
        case 0x010c7dd5: return "[PG+] VS2022 v17.5.0 pre 4.0 build 32213 (*)";
        case 0x010d7dd5: return "[POC] VS2022 v17.5.0 pre 4.0 build 32213 (*)";
        case 0x010e7dd5: return "[PO+] VS2022 v17.5.0 pre 4.0 build 32213 (*)";

        // MSVS2022 v17.5.0-pre.2.0
        case 0x01047d7c: return "[ C ] VS2022 v17.5.0 pre 2.0 build 32124";
        case 0x01037d7c: return "[ASM] VS2022 v17.5.0 pre 2.0 build 32124";
        case 0x01057d7c: return "[C++] VS2022 v17.5.0 pre 2.0 build 32124";
        case 0x00ff7d7c: return "[RES] VS2022 v17.5.0 pre 2.0 build 32124";
        case 0x01027d7c: return "[LNK] VS2022 v17.5.0 pre 2.0 build 32124";
        case 0x01007d7c: return "[EXP] VS2022 v17.5.0 pre 2.0 build 32124";
        case 0x01017d7c: return "[IMP] VS2022 v17.5.0 pre 2.0 build 32124";
        case 0x01067d7c: return "[CIL] VS2022 v17.5.0 pre 2.0 build 32124 (*)";
        case 0x01077d7c: return "[CI+] VS2022 v17.5.0 pre 2.0 build 32124 (*)";
        case 0x01087d7c: return "[LTC] VS2022 v17.5.0 pre 2.0 build 32124 (*)";
        case 0x01097d7c: return "[LT+] VS2022 v17.5.0 pre 2.0 build 32124 (*)";
        case 0x010a7d7c: return "[LTM] VS2022 v17.5.0 pre 2.0 build 32124 (*)";
        case 0x010b7d7c: return "[PGO] VS2022 v17.5.0 pre 2.0 build 32124 (*)";
        case 0x010c7d7c: return "[PG+] VS2022 v17.5.0 pre 2.0 build 32124 (*)";
        case 0x010d7d7c: return "[POC] VS2022 v17.5.0 pre 2.0 build 32124 (*)";
        case 0x010e7d7c: return "[PO+] VS2022 v17.5.0 pre 2.0 build 32124 (*)";

        // MSVS2022 v17.5.0-pre.1.0
        case 0x01047d13: return "[ C ] VS2022 v17.5.0 pre 1.0 build 32019";
        case 0x01037d13: return "[ASM] VS2022 v17.5.0 pre 1.0 build 32019";
        case 0x01057d13: return "[C++] VS2022 v17.5.0 pre 1.0 build 32019";
        case 0x00ff7d13: return "[RES] VS2022 v17.5.0 pre 1.0 build 32019";
        case 0x01027d13: return "[LNK] VS2022 v17.5.0 pre 1.0 build 32019";
        case 0x01007d13: return "[EXP] VS2022 v17.5.0 pre 1.0 build 32019";
        case 0x01017d13: return "[IMP] VS2022 v17.5.0 pre 1.0 build 32019";
        case 0x01067d13: return "[CIL] VS2022 v17.5.0 pre 1.0 build 32019 (*)";
        case 0x01077d13: return "[CI+] VS2022 v17.5.0 pre 1.0 build 32019 (*)";
        case 0x01087d13: return "[LTC] VS2022 v17.5.0 pre 1.0 build 32019 (*)";
        case 0x01097d13: return "[LT+] VS2022 v17.5.0 pre 1.0 build 32019 (*)";
        case 0x010a7d13: return "[LTM] VS2022 v17.5.0 pre 1.0 build 32019 (*)";
        case 0x010b7d13: return "[PGO] VS2022 v17.5.0 pre 1.0 build 32019 (*)";
        case 0x010c7d13: return "[PG+] VS2022 v17.5.0 pre 1.0 build 32019 (*)";
        case 0x010d7d13: return "[POC] VS2022 v17.5.0 pre 1.0 build 32019 (*)";
        case 0x010e7d13: return "[PO+] VS2022 v17.5.0 pre 1.0 build 32019 (*)";

        // MSVS2022 v17.4.0-pre.6.0
        case 0x01047cbd: return "[ C ] VS2022 v17.4.0 pre 6.0 build 31933";
        case 0x01037cbd: return "[ASM] VS2022 v17.4.0 pre 6.0 build 31933";
        case 0x01057cbd: return "[C++] VS2022 v17.4.0 pre 6.0 build 31933";
        case 0x00ff7cbd: return "[RES] VS2022 v17.4.0 pre 6.0 build 31933";
        case 0x01027cbd: return "[LNK] VS2022 v17.4.0 pre 6.0 build 31933";
        case 0x01007cbd: return "[EXP] VS2022 v17.4.0 pre 6.0 build 31933";
        case 0x01017cbd: return "[IMP] VS2022 v17.4.0 pre 6.0 build 31933";
        case 0x01067cbd: return "[CIL] VS2022 v17.4.0 pre 6.0 build 31933 (*)";
        case 0x01077cbd: return "[CI+] VS2022 v17.4.0 pre 6.0 build 31933 (*)";
        case 0x01087cbd: return "[LTC] VS2022 v17.4.0 pre 6.0 build 31933 (*)";
        case 0x01097cbd: return "[LT+] VS2022 v17.4.0 pre 6.0 build 31933 (*)";
        case 0x010a7cbd: return "[LTM] VS2022 v17.4.0 pre 6.0 build 31933 (*)";
        case 0x010b7cbd: return "[PGO] VS2022 v17.4.0 pre 6.0 build 31933 (*)";
        case 0x010c7cbd: return "[PG+] VS2022 v17.4.0 pre 6.0 build 31933 (*)";
        case 0x010d7cbd: return "[POC] VS2022 v17.4.0 pre 6.0 build 31933 (*)";
        case 0x010e7cbd: return "[PO+] VS2022 v17.4.0 pre 6.0 build 31933 (*)";

        // MSVS2022 v17.4.0-pre.5.0
        case 0x01047cbc: return "[ C ] VS2022 v17.4.0 pre 5.0 build 31932";
        case 0x01037cbc: return "[ASM] VS2022 v17.4.0 pre 5.0 build 31932";
        case 0x01057cbc: return "[C++] VS2022 v17.4.0 pre 5.0 build 31932";
        case 0x00ff7cbc: return "[RES] VS2022 v17.4.0 pre 5.0 build 31932";
        case 0x01027cbc: return "[LNK] VS2022 v17.4.0 pre 5.0 build 31932";
        case 0x01007cbc: return "[EXP] VS2022 v17.4.0 pre 5.0 build 31932";
        case 0x01017cbc: return "[IMP] VS2022 v17.4.0 pre 5.0 build 31932";
        case 0x01067cbc: return "[CIL] VS2022 v17.4.0 pre 5.0 build 31932 (*)";
        case 0x01077cbc: return "[CI+] VS2022 v17.4.0 pre 5.0 build 31932 (*)";
        case 0x01087cbc: return "[LTC] VS2022 v17.4.0 pre 5.0 build 31932 (*)";
        case 0x01097cbc: return "[LT+] VS2022 v17.4.0 pre 5.0 build 31932 (*)";
        case 0x010a7cbc: return "[LTM] VS2022 v17.4.0 pre 5.0 build 31932 (*)";
        case 0x010b7cbc: return "[PGO] VS2022 v17.4.0 pre 5.0 build 31932 (*)";
        case 0x010c7cbc: return "[PG+] VS2022 v17.4.0 pre 5.0 build 31932 (*)";
        case 0x010d7cbc: return "[POC] VS2022 v17.4.0 pre 5.0 build 31932 (*)";
        case 0x010e7cbc: return "[PO+] VS2022 v17.4.0 pre 5.0 build 31932 (*)";

        // MSVS2022 v17.4.0-pre.4.0
        case 0x01047cbb: return "[ C ] VS2022 v17.4.0 pre 4.0 build 31931";
        case 0x01037cbb: return "[ASM] VS2022 v17.4.0 pre 4.0 build 31931";
        case 0x01057cbb: return "[C++] VS2022 v17.4.0 pre 4.0 build 31931";
        case 0x00ff7cbb: return "[RES] VS2022 v17.4.0 pre 4.0 build 31931";
        case 0x01027cbb: return "[LNK] VS2022 v17.4.0 pre 4.0 build 31931";
        case 0x01007cbb: return "[EXP] VS2022 v17.4.0 pre 4.0 build 31931";
        case 0x01017cbb: return "[IMP] VS2022 v17.4.0 pre 4.0 build 31931";
        case 0x01067cbb: return "[CIL] VS2022 v17.4.0 pre 4.0 build 31931 (*)";
        case 0x01077cbb: return "[CI+] VS2022 v17.4.0 pre 4.0 build 31931 (*)";
        case 0x01087cbb: return "[LTC] VS2022 v17.4.0 pre 4.0 build 31931 (*)";
        case 0x01097cbb: return "[LT+] VS2022 v17.4.0 pre 4.0 build 31931 (*)";
        case 0x010a7cbb: return "[LTM] VS2022 v17.4.0 pre 4.0 build 31931 (*)";
        case 0x010b7cbb: return "[PGO] VS2022 v17.4.0 pre 4.0 build 31931 (*)";
        case 0x010c7cbb: return "[PG+] VS2022 v17.4.0 pre 4.0 build 31931 (*)";
        case 0x010d7cbb: return "[POC] VS2022 v17.4.0 pre 4.0 build 31931 (*)";
        case 0x010e7cbb: return "[PO+] VS2022 v17.4.0 pre 4.0 build 31931 (*)";

        // MSVS2022 v17.4.0-pre.3.0
        case 0x01047cb1: return "[ C ] VS2022 v17.4.0 pre 3.0 build 31921";
        case 0x01037cb1: return "[ASM] VS2022 v17.4.0 pre 3.0 build 31921";
        case 0x01057cb1: return "[C++] VS2022 v17.4.0 pre 3.0 build 31921";
        case 0x00ff7cb1: return "[RES] VS2022 v17.4.0 pre 3.0 build 31921";
        case 0x01027cb1: return "[LNK] VS2022 v17.4.0 pre 3.0 build 31921";
        case 0x01007cb1: return "[EXP] VS2022 v17.4.0 pre 3.0 build 31921";
        case 0x01017cb1: return "[IMP] VS2022 v17.4.0 pre 3.0 build 31921";
        case 0x01067cb1: return "[CIL] VS2022 v17.4.0 pre 3.0 build 31921 (*)";
        case 0x01077cb1: return "[CI+] VS2022 v17.4.0 pre 3.0 build 31921 (*)";
        case 0x01087cb1: return "[LTC] VS2022 v17.4.0 pre 3.0 build 31921 (*)";
        case 0x01097cb1: return "[LT+] VS2022 v17.4.0 pre 3.0 build 31921 (*)";
        case 0x010a7cb1: return "[LTM] VS2022 v17.4.0 pre 3.0 build 31921 (*)";
        case 0x010b7cb1: return "[PGO] VS2022 v17.4.0 pre 3.0 build 31921 (*)";
        case 0x010c7cb1: return "[PG+] VS2022 v17.4.0 pre 3.0 build 31921 (*)";
        case 0x010d7cb1: return "[POC] VS2022 v17.4.0 pre 3.0 build 31921 (*)";
        case 0x010e7cb1: return "[PO+] VS2022 v17.4.0 pre 3.0 build 31921 (*)";

        // MSVS2022 v17.4.0-pre.2.0
        case 0x01047c4f: return "[ C ] VS2022 v17.4.0 pre 2.0 build 31823";
        case 0x01037c4f: return "[ASM] VS2022 v17.4.0 pre 2.0 build 31823";
        case 0x01057c4f: return "[C++] VS2022 v17.4.0 pre 2.0 build 31823";
        case 0x00ff7c4f: return "[RES] VS2022 v17.4.0 pre 2.0 build 31823";
        case 0x01027c4f: return "[LNK] VS2022 v17.4.0 pre 2.0 build 31823";
        case 0x01007c4f: return "[EXP] VS2022 v17.4.0 pre 2.0 build 31823";
        case 0x01017c4f: return "[IMP] VS2022 v17.4.0 pre 2.0 build 31823";
        case 0x01067c4f: return "[CIL] VS2022 v17.4.0 pre 2.0 build 31823 (*)";
        case 0x01077c4f: return "[CI+] VS2022 v17.4.0 pre 2.0 build 31823 (*)";
        case 0x01087c4f: return "[LTC] VS2022 v17.4.0 pre 2.0 build 31823 (*)";
        case 0x01097c4f: return "[LT+] VS2022 v17.4.0 pre 2.0 build 31823 (*)";
        case 0x010a7c4f: return "[LTM] VS2022 v17.4.0 pre 2.0 build 31823 (*)";
        case 0x010b7c4f: return "[PGO] VS2022 v17.4.0 pre 2.0 build 31823 (*)";
        case 0x010c7c4f: return "[PG+] VS2022 v17.4.0 pre 2.0 build 31823 (*)";
        case 0x010d7c4f: return "[POC] VS2022 v17.4.0 pre 2.0 build 31823 (*)";
        case 0x010e7c4f: return "[PO+] VS2022 v17.4.0 pre 2.0 build 31823 (*)";

        // MSVS2022 v17.4.0-pre.1.0
        case 0x01047be9: return "[ C ] VS2022 v17.4.0 pre 1.0 build 31721";
        case 0x01037be9: return "[ASM] VS2022 v17.4.0 pre 1.0 build 31721";
        case 0x01057be9: return "[C++] VS2022 v17.4.0 pre 1.0 build 31721";
        case 0x00ff7be9: return "[RES] VS2022 v17.4.0 pre 1.0 build 31721";
        case 0x01027be9: return "[LNK] VS2022 v17.4.0 pre 1.0 build 31721";
        case 0x01007be9: return "[EXP] VS2022 v17.4.0 pre 1.0 build 31721";
        case 0x01017be9: return "[IMP] VS2022 v17.4.0 pre 1.0 build 31721";
        case 0x01067be9: return "[CIL] VS2022 v17.4.0 pre 1.0 build 31721 (*)";
        case 0x01077be9: return "[CI+] VS2022 v17.4.0 pre 1.0 build 31721 (*)";
        case 0x01087be9: return "[LTC] VS2022 v17.4.0 pre 1.0 build 31721 (*)";
        case 0x01097be9: return "[LT+] VS2022 v17.4.0 pre 1.0 build 31721 (*)";
        case 0x010a7be9: return "[LTM] VS2022 v17.4.0 pre 1.0 build 31721 (*)";
        case 0x010b7be9: return "[PGO] VS2022 v17.4.0 pre 1.0 build 31721 (*)";
        case 0x010c7be9: return "[PG+] VS2022 v17.4.0 pre 1.0 build 31721 (*)";
        case 0x010d7be9: return "[POC] VS2022 v17.4.0 pre 1.0 build 31721 (*)";
        case 0x010e7be9: return "[PO+] VS2022 v17.4.0 pre 1.0 build 31721 (*)";

        // MSVS2022 v17.3.0 (also 17.3.0 pre 5.0)
        case 0x01047b8d: return "[ C ] VS2022 v17.3.0 build 31629";
        case 0x01037b8d: return "[ASM] VS2022 v17.3.0 build 31629";
        case 0x01057b8d: return "[C++] VS2022 v17.3.0 build 31629";
        case 0x00ff7b8d: return "[RES] VS2022 v17.3.0 build 31629";
        case 0x01027b8d: return "[LNK] VS2022 v17.3.0 build 31629";
        case 0x01007b8d: return "[EXP] VS2022 v17.3.0 build 31629";
        case 0x01017b8d: return "[IMP] VS2022 v17.3.0 build 31629";
        case 0x01067b8d: return "[CIL] VS2022 v17.3.0 build 31629 (*)";
        case 0x01077b8d: return "[CI+] VS2022 v17.3.0 build 31629 (*)";
        case 0x01087b8d: return "[LTC] VS2022 v17.3.0 build 31629 (*)";
        case 0x01097b8d: return "[LT+] VS2022 v17.3.0 build 31629 (*)";
        case 0x010a7b8d: return "[LTM] VS2022 v17.3.0 build 31629 (*)";
        case 0x010b7b8d: return "[PGO] VS2022 v17.3.0 build 31629 (*)";
        case 0x010c7b8d: return "[PG+] VS2022 v17.3.0 build 31629 (*)";
        case 0x010d7b8d: return "[POC] VS2022 v17.3.0 build 31629 (*)";
        case 0x010e7b8d: return "[PO+] VS2022 v17.3.0 build 31629 (*)";

        // MSVS2022 v17.3.0-pre.4.0
        case 0x01047b8c: return "[ C ] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x01037b8c: return "[ASM] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x01057b8c: return "[C++] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x00ff7b8c: return "[RES] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x01027b8c: return "[LNK] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x01007b8c: return "[EXP] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x01017b8c: return "[IMP] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x01067b8c: return "[CIL] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x01077b8c: return "[CI+] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x01087b8c: return "[LTC] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x01097b8c: return "[LT+] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x010a7b8c: return "[LTM] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x010b7b8c: return "[PGO] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x010c7b8c: return "[PG+] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x010d7b8c: return "[POC] VS2022 v17.3.0 pre 4.0 build 31628 (*)";
        case 0x010e7b8c: return "[PO+] VS2022 v17.3.0 pre 4.0 build 31628 (*)";

        // MSVS2022 v17.3.0-pre.3.0
        case 0x01047b8b: return "[ C ] VS2022 v17.3.0 pre 3.0 build 31627";
        case 0x01037b8b: return "[ASM] VS2022 v17.3.0 pre 3.0 build 31627";
        case 0x01057b8b: return "[C++] VS2022 v17.3.0 pre 3.0 build 31627";
        case 0x00ff7b8b: return "[RES] VS2022 v17.3.0 pre 3.0 build 31627";
        case 0x01027b8b: return "[LNK] VS2022 v17.3.0 pre 3.0 build 31627";
        case 0x01007b8b: return "[EXP] VS2022 v17.3.0 pre 3.0 build 31627";
        case 0x01017b8b: return "[IMP] VS2022 v17.3.0 pre 3.0 build 31627";
        case 0x01067b8b: return "[CIL] VS2022 v17.3.0 pre 3.0 build 31627 (*)";
        case 0x01077b8b: return "[CI+] VS2022 v17.3.0 pre 3.0 build 31627 (*)";
        case 0x01087b8b: return "[LTC] VS2022 v17.3.0 pre 3.0 build 31627 (*)";
        case 0x01097b8b: return "[LT+] VS2022 v17.3.0 pre 3.0 build 31627 (*)";
        case 0x010a7b8b: return "[LTM] VS2022 v17.3.0 pre 3.0 build 31627 (*)";
        case 0x010b7b8b: return "[PGO] VS2022 v17.3.0 pre 3.0 build 31627 (*)";
        case 0x010c7b8b: return "[PG+] VS2022 v17.3.0 pre 3.0 build 31627 (*)";
        case 0x010d7b8b: return "[POC] VS2022 v17.3.0 pre 3.0 build 31627 (*)";
        case 0x010e7b8b: return "[PO+] VS2022 v17.3.0 pre 3.0 build 31627 (*)";

        // MSVS2022 v17.3.0-pre.2.0
        case 0x01047b1d: return "[ C ] VS2022 v17.3.0 pre 2.0 build 31517";
        case 0x01037b1d: return "[ASM] VS2022 v17.3.0 pre 2.0 build 31517";
        case 0x01057b1d: return "[C++] VS2022 v17.3.0 pre 2.0 build 31517";
        case 0x00ff7b1d: return "[RES] VS2022 v17.3.0 pre 2.0 build 31517";
        case 0x01027b1d: return "[LNK] VS2022 v17.3.0 pre 2.0 build 31517";
        case 0x01007b1d: return "[EXP] VS2022 v17.3.0 pre 2.0 build 31517";
        case 0x01017b1d: return "[IMP] VS2022 v17.3.0 pre 2.0 build 31517";
        case 0x01067b1d: return "[CIL] VS2022 v17.3.0 pre 2.0 build 31517 (*)";
        case 0x01077b1d: return "[CI+] VS2022 v17.3.0 pre 2.0 build 31517 (*)";
        case 0x01087b1d: return "[LTC] VS2022 v17.3.0 pre 2.0 build 31517 (*)";
        case 0x01097b1d: return "[LT+] VS2022 v17.3.0 pre 2.0 build 31517 (*)";
        case 0x010a7b1d: return "[LTM] VS2022 v17.3.0 pre 2.0 build 31517 (*)";
        case 0x010b7b1d: return "[PGO] VS2022 v17.3.0 pre 2.0 build 31517 (*)";
        case 0x010c7b1d: return "[PG+] VS2022 v17.3.0 pre 2.0 build 31517 (*)";
        case 0x010d7b1d: return "[POC] VS2022 v17.3.0 pre 2.0 build 31517 (*)";
        case 0x010e7b1d: return "[PO+] VS2022 v17.3.0 pre 2.0 build 31517 (*)";

        // MSVS2022 v17.3.0-pre.1.0
        case 0x01047ac0: return "[ C ] VS2022 v17.3.0 pre 1.0 build 31424";
        case 0x01037ac0: return "[ASM] VS2022 v17.3.0 pre 1.0 build 31424";
        case 0x01057ac0: return "[C++] VS2022 v17.3.0 pre 1.0 build 31424";
        case 0x00ff7ac0: return "[RES] VS2022 v17.3.0 pre 1.0 build 31424";
        case 0x01027ac0: return "[LNK] VS2022 v17.3.0 pre 1.0 build 31424";
        case 0x01007ac0: return "[EXP] VS2022 v17.3.0 pre 1.0 build 31424";
        case 0x01017ac0: return "[IMP] VS2022 v17.3.0 pre 1.0 build 31424";
        case 0x01067ac0: return "[CIL] VS2022 v17.3.0 pre 1.0 build 31424 (*)";
        case 0x01077ac0: return "[CI+] VS2022 v17.3.0 pre 1.0 build 31424 (*)";
        case 0x01087ac0: return "[LTC] VS2022 v17.3.0 pre 1.0 build 31424 (*)";
        case 0x01097ac0: return "[LT+] VS2022 v17.3.0 pre 1.0 build 31424 (*)";
        case 0x010a7ac0: return "[LTM] VS2022 v17.3.0 pre 1.0 build 31424 (*)";
        case 0x010b7ac0: return "[PGO] VS2022 v17.3.0 pre 1.0 build 31424 (*)";
        case 0x010c7ac0: return "[PG+] VS2022 v17.3.0 pre 1.0 build 31424 (*)";
        case 0x010d7ac0: return "[POC] VS2022 v17.3.0 pre 1.0 build 31424 (*)";
        case 0x010e7ac0: return "[PO+] VS2022 v17.3.0 pre 1.0 build 31424 (*)";

        // MSVS2022 v17.2.0 (also v17.2.0-pre.5.0)
        case 0x01047a60: return "[ C ] VS2022 v17.2.0 build 31328";
        case 0x01037a60: return "[ASM] VS2022 v17.2.0 build 31328";
        case 0x01057a60: return "[C++] VS2022 v17.2.0 build 31328";
        case 0x00ff7a60: return "[RES] VS2022 v17.2.0 build 31328";
        case 0x01027a60: return "[LNK] VS2022 v17.2.0 build 31328";
        case 0x01007a60: return "[EXP] VS2022 v17.2.0 build 31328";
        case 0x01017a60: return "[IMP] VS2022 v17.2.0 build 31328";
        case 0x01067a60: return "[CIL] VS2022 v17.2.0 build 31328 (*)";
        case 0x01077a60: return "[CI+] VS2022 v17.2.0 build 31328 (*)";
        case 0x01087a60: return "[LTC] VS2022 v17.2.0 build 31328 (*)";
        case 0x01097a60: return "[LT+] VS2022 v17.2.0 build 31328 (*)";
        case 0x010a7a60: return "[LTM] VS2022 v17.2.0 build 31328 (*)";
        case 0x010b7a60: return "[PGO] VS2022 v17.2.0 build 31328 (*)";
        case 0x010c7a60: return "[PG+] VS2022 v17.2.0 build 31328 (*)";
        case 0x010d7a60: return "[POC] VS2022 v17.2.0 build 31328 (*)";
        case 0x010e7a60: return "[PO+] VS2022 v17.2.0 build 31328 (*)";

        // MSVS2022 v17.2.0-pre.3.0
        case 0x01047a5e: return "[ C ] VS2022 v17.2.0 pre 3.0 build 31326";
        case 0x01037a5e: return "[ASM] VS2022 v17.2.0 pre 3.0 build 31326";
        case 0x01057a5e: return "[C++] VS2022 v17.2.0 pre 3.0 build 31326";
        case 0x00ff7a5e: return "[RES] VS2022 v17.2.0 pre 3.0 build 31326";
        case 0x01027a5e: return "[LNK] VS2022 v17.2.0 pre 3.0 build 31326";
        case 0x01007a5e: return "[EXP] VS2022 v17.2.0 pre 3.0 build 31326";
        case 0x01017a5e: return "[IMP] VS2022 v17.2.0 pre 3.0 build 31326";
        case 0x01067a5e: return "[CIL] VS2022 v17.2.0 pre 3.0 build 31326 (*)";
        case 0x01077a5e: return "[CI+] VS2022 v17.2.0 pre 3.0 build 31326 (*)";
        case 0x01087a5e: return "[LTC] VS2022 v17.2.0 pre 3.0 build 31326 (*)";
        case 0x01097a5e: return "[LT+] VS2022 v17.2.0 pre 3.0 build 31326 (*)";
        case 0x010a7a5e: return "[LTM] VS2022 v17.2.0 pre 3.0 build 31326 (*)";
        case 0x010b7a5e: return "[PGO] VS2022 v17.2.0 pre 3.0 build 31326 (*)";
        case 0x010c7a5e: return "[PG+] VS2022 v17.2.0 pre 3.0 build 31326 (*)";
        case 0x010d7a5e: return "[POC] VS2022 v17.2.0 pre 3.0 build 31326 (*)";
        case 0x010e7a5e: return "[PO+] VS2022 v17.2.0 pre 3.0 build 31326 (*)";

        // MSVS2022 v17.2.0-pre.2.1
        case 0x01047a46: return "[ C ] VS2022 v17.2.0 pre 2.1 build 31302";
        case 0x01037a46: return "[ASM] VS2022 v17.2.0 pre 2.1 build 31302";
        case 0x01057a46: return "[C++] VS2022 v17.2.0 pre 2.1 build 31302";
        case 0x00ff7a46: return "[RES] VS2022 v17.2.0 pre 2.1 build 31302";
        case 0x01027a46: return "[LNK] VS2022 v17.2.0 pre 2.1 build 31302";
        case 0x01007a46: return "[EXP] VS2022 v17.2.0 pre 2.1 build 31302";
        case 0x01017a46: return "[IMP] VS2022 v17.2.0 pre 2.1 build 31302";
        case 0x01067a46: return "[CIL] VS2022 v17.2.0 pre 2.1 build 31302 (*)";
        case 0x01077a46: return "[CI+] VS2022 v17.2.0 pre 2.1 build 31302 (*)";
        case 0x01087a46: return "[LTC] VS2022 v17.2.0 pre 2.1 build 31302 (*)";
        case 0x01097a46: return "[LT+] VS2022 v17.2.0 pre 2.1 build 31302 (*)";
        case 0x010a7a46: return "[LTM] VS2022 v17.2.0 pre 2.1 build 31302 (*)";
        case 0x010b7a46: return "[PGO] VS2022 v17.2.0 pre 2.1 build 31302 (*)";
        case 0x010c7a46: return "[PG+] VS2022 v17.2.0 pre 2.1 build 31302 (*)";
        case 0x010d7a46: return "[POC] VS2022 v17.2.0 pre 2.1 build 31302 (*)";
        case 0x010e7a46: return "[PO+] VS2022 v17.2.0 pre 2.1 build 31302 (*)";

        // MSVS2022 v17.2.0-pre.1.0
        case 0x0104798a: return "[ C ] VS2022 v17.2.0 pre 1.0 build 31114";
        case 0x0103798a: return "[ASM] VS2022 v17.2.0 pre 1.0 build 31114";
        case 0x0105798a: return "[C++] VS2022 v17.2.0 pre 1.0 build 31114";
        case 0x00ff798a: return "[RES] VS2022 v17.2.0 pre 1.0 build 31114";
        case 0x0102798a: return "[LNK] VS2022 v17.2.0 pre 1.0 build 31114";
        case 0x0100798a: return "[EXP] VS2022 v17.2.0 pre 1.0 build 31114";
        case 0x0101798a: return "[IMP] VS2022 v17.2.0 pre 1.0 build 31114";
        case 0x0106798a: return "[CIL] VS2022 v17.2.0 pre 1.0 build 31114 (*)";
        case 0x0107798a: return "[CI+] VS2022 v17.2.0 pre 1.0 build 31114 (*)";
        case 0x0108798a: return "[LTC] VS2022 v17.2.0 pre 1.0 build 31114 (*)";
        case 0x0109798a: return "[LT+] VS2022 v17.2.0 pre 1.0 build 31114 (*)";
        case 0x010a798a: return "[LTM] VS2022 v17.2.0 pre 1.0 build 31114 (*)";
        case 0x010b798a: return "[PGO] VS2022 v17.2.0 pre 1.0 build 31114 (*)";
        case 0x010c798a: return "[PG+] VS2022 v17.2.0 pre 1.0 build 31114 (*)";
        case 0x010d798a: return "[POC] VS2022 v17.2.0 pre 1.0 build 31114 (*)";
        case 0x010e798a: return "[PO+] VS2022 v17.2.0 pre 1.0 build 31114 (*)";

        // MSVS2022 v17.1.0-pre.5.0
        case 0x01047980: return "[ C ] VS2022 v17.1.0 pre 5.0 build 31104";
        case 0x01037980: return "[ASM] VS2022 v17.1.0 pre 5.0 build 31104";
        case 0x01057980: return "[C++] VS2022 v17.1.0 pre 5.0 build 31104";
        case 0x00ff7980: return "[RES] VS2022 v17.1.0 pre 5.0 build 31104";
        case 0x01027980: return "[LNK] VS2022 v17.1.0 pre 5.0 build 31104";
        case 0x01007980: return "[EXP] VS2022 v17.1.0 pre 5.0 build 31104";
        case 0x01017980: return "[IMP] VS2022 v17.1.0 pre 5.0 build 31104";
        case 0x01067980: return "[CIL] VS2022 v17.1.0 pre 5.0 build 31104 (*)";
        case 0x01077980: return "[CI+] VS2022 v17.1.0 pre 5.0 build 31104 (*)";
        case 0x01087980: return "[LTC] VS2022 v17.1.0 pre 5.0 build 31104 (*)";
        case 0x01097980: return "[LT+] VS2022 v17.1.0 pre 5.0 build 31104 (*)";
        case 0x010a7980: return "[LTM] VS2022 v17.1.0 pre 5.0 build 31104 (*)";
        case 0x010b7980: return "[PGO] VS2022 v17.1.0 pre 5.0 build 31104 (*)";
        case 0x010c7980: return "[PG+] VS2022 v17.1.0 pre 5.0 build 31104 (*)";
        case 0x010d7980: return "[POC] VS2022 v17.1.0 pre 5.0 build 31104 (*)";
        case 0x010e7980: return "[PO+] VS2022 v17.1.0 pre 5.0 build 31104 (*)";

        // MSVS2022 v17.1.0-pre.3.0
        case 0x0104797f: return "[ C ] VS2022 v17.1.0 pre 3.0 build 31103";
        case 0x0103797f: return "[ASM] VS2022 v17.1.0 pre 3.0 build 31103";
        case 0x0105797f: return "[C++] VS2022 v17.1.0 pre 3.0 build 31103";
        case 0x00ff797f: return "[RES] VS2022 v17.1.0 pre 3.0 build 31103";
        case 0x0102797f: return "[LNK] VS2022 v17.1.0 pre 3.0 build 31103";
        case 0x0100797f: return "[EXP] VS2022 v17.1.0 pre 3.0 build 31103";
        case 0x0101797f: return "[IMP] VS2022 v17.1.0 pre 3.0 build 31103";
        case 0x0106797f: return "[CIL] VS2022 v17.1.0 pre 3.0 build 31103 (*)";
        case 0x0107797f: return "[CI+] VS2022 v17.1.0 pre 3.0 build 31103 (*)";
        case 0x0108797f: return "[LTC] VS2022 v17.1.0 pre 3.0 build 31103 (*)";
        case 0x0109797f: return "[LT+] VS2022 v17.1.0 pre 3.0 build 31103 (*)";
        case 0x010a797f: return "[LTM] VS2022 v17.1.0 pre 3.0 build 31103 (*)";
        case 0x010b797f: return "[PGO] VS2022 v17.1.0 pre 3.0 build 31103 (*)";
        case 0x010c797f: return "[PG+] VS2022 v17.1.0 pre 3.0 build 31103 (*)";
        case 0x010d797f: return "[POC] VS2022 v17.1.0 pre 3.0 build 31103 (*)";
        case 0x010e797f: return "[PO+] VS2022 v17.1.0 pre 3.0 build 31103 (*)";

        // MSVS2022 v17.1.0-pre.2.0
        case 0x010478c7: return "[ C ] VS2022 v17.1.0 pre 2.0 build 30919";
        case 0x010378c7: return "[ASM] VS2022 v17.1.0 pre 2.0 build 30919";
        case 0x010578c7: return "[C++] VS2022 v17.1.0 pre 2.0 build 30919";
        case 0x00ff78c7: return "[RES] VS2022 v17.1.0 pre 2.0 build 30919";
        case 0x010278c7: return "[LNK] VS2022 v17.1.0 pre 2.0 build 30919";
        case 0x010078c7: return "[EXP] VS2022 v17.1.0 pre 2.0 build 30919";
        case 0x010178c7: return "[IMP] VS2022 v17.1.0 pre 2.0 build 30919";
        case 0x010678c7: return "[CIL] VS2022 v17.1.0 pre 2.0 build 30919 (*)";
        case 0x010778c7: return "[CI+] VS2022 v17.1.0 pre 2.0 build 30919 (*)";
        case 0x010878c7: return "[LTC] VS2022 v17.1.0 pre 2.0 build 30919 (*)";
        case 0x010978c7: return "[LT+] VS2022 v17.1.0 pre 2.0 build 30919 (*)";
        case 0x010a78c7: return "[LTM] VS2022 v17.1.0 pre 2.0 build 30919 (*)";
        case 0x010b78c7: return "[PGO] VS2022 v17.1.0 pre 2.0 build 30919 (*)";
        case 0x010c78c7: return "[PG+] VS2022 v17.1.0 pre 2.0 build 30919 (*)";
        case 0x010d78c7: return "[POC] VS2022 v17.1.0 pre 2.0 build 30919 (*)";
        case 0x010e78c7: return "[PO+] VS2022 v17.1.0 pre 2.0 build 30919 (*)";

        // MSVS2022 v17.1.0-pre.1.0
        case 0x01047862: return "[ C ] VS2022 v17.1.0 pre 1.0 build 30818";
        case 0x01037862: return "[ASM] VS2022 v17.1.0 pre 1.0 build 30818";
        case 0x01057862: return "[C++] VS2022 v17.1.0 pre 1.0 build 30818";
        case 0x00ff7862: return "[RES] VS2022 v17.1.0 pre 1.0 build 30818";
        case 0x01027862: return "[LNK] VS2022 v17.1.0 pre 1.0 build 30818";
        case 0x01007862: return "[EXP] VS2022 v17.1.0 pre 1.0 build 30818";
        case 0x01017862: return "[IMP] VS2022 v17.1.0 pre 1.0 build 30818";
        case 0x01067862: return "[CIL] VS2022 v17.1.0 pre 1.0 build 30818 (*)";
        case 0x01077862: return "[CI+] VS2022 v17.1.0 pre 1.0 build 30818 (*)";
        case 0x01087862: return "[LTC] VS2022 v17.1.0 pre 1.0 build 30818 (*)";
        case 0x01097862: return "[LT+] VS2022 v17.1.0 pre 1.0 build 30818 (*)";
        case 0x010a7862: return "[LTM] VS2022 v17.1.0 pre 1.0 build 30818 (*)";
        case 0x010b7862: return "[PGO] VS2022 v17.1.0 pre 1.0 build 30818 (*)";
        case 0x010c7862: return "[PG+] VS2022 v17.1.0 pre 1.0 build 30818 (*)";
        case 0x010d7862: return "[POC] VS2022 v17.1.0 pre 1.0 build 30818 (*)";
        case 0x010e7862: return "[PO+] VS2022 v17.1.0 pre 1.0 build 30818 (*)";

        // MSVS2022 v17.0.0-pre.7.0
        case 0x010477f1: return "[ C ] VS2022 v17.0.0 pre 7.0 build 30705";
        case 0x010377f1: return "[ASM] VS2022 v17.0.0 pre 7.0 build 30705";
        case 0x010577f1: return "[C++] VS2022 v17.0.0 pre 7.0 build 30705";
        case 0x00ff77f1: return "[RES] VS2022 v17.0.0 pre 7.0 build 30705";
        case 0x010277f1: return "[LNK] VS2022 v17.0.0 pre 7.0 build 30705";
        case 0x010077f1: return "[EXP] VS2022 v17.0.0 pre 7.0 build 30705";
        case 0x010177f1: return "[IMP] VS2022 v17.0.0 pre 7.0 build 30705";
        case 0x010677f1: return "[CIL] VS2022 v17.0.0 pre 7.0 build 30705 (*)";
        case 0x010777f1: return "[CI+] VS2022 v17.0.0 pre 7.0 build 30705 (*)";
        case 0x010877f1: return "[LTC] VS2022 v17.0.0 pre 7.0 build 30705 (*)";
        case 0x010977f1: return "[LT+] VS2022 v17.0.0 pre 7.0 build 30705 (*)";
        case 0x010a77f1: return "[LTM] VS2022 v17.0.0 pre 7.0 build 30705 (*)";
        case 0x010b77f1: return "[PGO] VS2022 v17.0.0 pre 7.0 build 30705 (*)";
        case 0x010c77f1: return "[PG+] VS2022 v17.0.0 pre 7.0 build 30705 (*)";
        case 0x010d77f1: return "[POC] VS2022 v17.0.0 pre 7.0 build 30705 (*)";
        case 0x010e77f1: return "[PO+] VS2022 v17.0.0 pre 7.0 build 30705 (*)";

        // MSVS2022 v17.0.0-pre.5.0
        case 0x010477f0: return "[ C ] VS2022 v17.0.0 pre 5.0 build 30704";
        case 0x010377f0: return "[ASM] VS2022 v17.0.0 pre 5.0 build 30704";
        case 0x010577f0: return "[C++] VS2022 v17.0.0 pre 5.0 build 30704";
        case 0x00ff77f0: return "[RES] VS2022 v17.0.0 pre 5.0 build 30704";
        case 0x010277f0: return "[LNK] VS2022 v17.0.0 pre 5.0 build 30704";
        case 0x010077f0: return "[EXP] VS2022 v17.0.0 pre 5.0 build 30704";
        case 0x010177f0: return "[IMP] VS2022 v17.0.0 pre 5.0 build 30704";
        case 0x010677f0: return "[CIL] VS2022 v17.0.0 pre 5.0 build 30704 (*)";
        case 0x010777f0: return "[CI+] VS2022 v17.0.0 pre 5.0 build 30704 (*)";
        case 0x010877f0: return "[LTC] VS2022 v17.0.0 pre 5.0 build 30704 (*)";
        case 0x010977f0: return "[LT+] VS2022 v17.0.0 pre 5.0 build 30704 (*)";
        case 0x010a77f0: return "[LTM] VS2022 v17.0.0 pre 5.0 build 30704 (*)";
        case 0x010b77f0: return "[PGO] VS2022 v17.0.0 pre 5.0 build 30704 (*)";
        case 0x010c77f0: return "[PG+] VS2022 v17.0.0 pre 5.0 build 30704 (*)";
        case 0x010d77f0: return "[POC] VS2022 v17.0.0 pre 5.0 build 30704 (*)";
        case 0x010e77f0: return "[PO+] VS2022 v17.0.0 pre 5.0 build 30704 (*)";

        // MSVS2022 v17.0.0-pre.4.0
        case 0x01047740: return "[ C ] VS2022 v17.0.0 pre 4.0 build 30528";
        case 0x01037740: return "[ASM] VS2022 v17.0.0 pre 4.0 build 30528";
        case 0x01057740: return "[C++] VS2022 v17.0.0 pre 4.0 build 30528";
        case 0x00ff7740: return "[RES] VS2022 v17.0.0 pre 4.0 build 30528";
        case 0x01027740: return "[LNK] VS2022 v17.0.0 pre 4.0 build 30528";
        case 0x01007740: return "[EXP] VS2022 v17.0.0 pre 4.0 build 30528";
        case 0x01017740: return "[IMP] VS2022 v17.0.0 pre 4.0 build 30528";
        case 0x01067740: return "[CIL] VS2022 v17.0.0 pre 4.0 build 30528 (*)";
        case 0x01077740: return "[CI+] VS2022 v17.0.0 pre 4.0 build 30528 (*)";
        case 0x01087740: return "[LTC] VS2022 v17.0.0 pre 4.0 build 30528 (*)";
        case 0x01097740: return "[LT+] VS2022 v17.0.0 pre 4.0 build 30528 (*)";
        case 0x010a7740: return "[LTM] VS2022 v17.0.0 pre 4.0 build 30528 (*)";
        case 0x010b7740: return "[PGO] VS2022 v17.0.0 pre 4.0 build 30528 (*)";
        case 0x010c7740: return "[PG+] VS2022 v17.0.0 pre 4.0 build 30528 (*)";
        case 0x010d7740: return "[POC] VS2022 v17.0.0 pre 4.0 build 30528 (*)";
        case 0x010e7740: return "[PO+] VS2022 v17.0.0 pre 4.0 build 30528 (*)";

        // MSVS2022 v17.0.0-pre-3.1
        case 0x010476d7: return "[ C ] VS2022 v17.0.0 pre 3.1 build 30423";
        case 0x010376d7: return "[ASM] VS2022 v17.0.0 pre 3.1 build 30423";
        case 0x010576d7: return "[C++] VS2022 v17.0.0 pre 3.1 build 30423";
        case 0x00ff76d7: return "[RES] VS2022 v17.0.0 pre 3.1 build 30423";
        case 0x010276d7: return "[LNK] VS2022 v17.0.0 pre 3.1 build 30423";
        case 0x010076d7: return "[EXP] VS2022 v17.0.0 pre 3.1 build 30423";
        case 0x010176d7: return "[IMP] VS2022 v17.0.0 pre 3.1 build 30423";
        case 0x010676d7: return "[CIL] VS2022 v17.0.0 pre 3.1 build 30423 (*)";
        case 0x010776d7: return "[CI+] VS2022 v17.0.0 pre 3.1 build 30423 (*)";
        case 0x010876d7: return "[LTC] VS2022 v17.0.0 pre 3.1 build 30423 (*)";
        case 0x010976d7: return "[LT+] VS2022 v17.0.0 pre 3.1 build 30423 (*)";
        case 0x010a76d7: return "[LTM] VS2022 v17.0.0 pre 3.1 build 30423 (*)";
        case 0x010b76d7: return "[PGO] VS2022 v17.0.0 pre 3.1 build 30423 (*)";
        case 0x010c76d7: return "[PG+] VS2022 v17.0.0 pre 3.1 build 30423 (*)";
        case 0x010d76d7: return "[POC] VS2022 v17.0.0 pre 3.1 build 30423 (*)";
        case 0x010e76d7: return "[PO+] VS2022 v17.0.0 pre 3.1 build 30423 (*)";

        // MSVS2022 v17.0.0-preview2
        case 0x010476c1: return "[ C ] VS2022 v17.0.0 preview2 build 30401";
        case 0x010376c1: return "[ASM] VS2022 v17.0.0 preview2 build 30401";
        case 0x010576c1: return "[C++] VS2022 v17.0.0 preview2 build 30401";
        case 0x00ff76c1: return "[RES] VS2022 v17.0.0 preview2 build 30401";
        case 0x010276c1: return "[LNK] VS2022 v17.0.0 preview2 build 30401";
        case 0x010076c1: return "[EXP] VS2022 v17.0.0 preview2 build 30401";
        case 0x010176c1: return "[IMP] VS2022 v17.0.0 preview2 build 30401";
        case 0x010676c1: return "[CIL] VS2022 v17.0.0 preview2 build 30401 (*)";
        case 0x010776c1: return "[CI+] VS2022 v17.0.0 preview2 build 30401 (*)";
        case 0x010876c1: return "[LTC] VS2022 v17.0.0 preview2 build 30401 (*)";
        case 0x010976c1: return "[LT+] VS2022 v17.0.0 preview2 build 30401 (*)";
        case 0x010a76c1: return "[LTM] VS2022 v17.0.0 preview2 build 30401 (*)";
        case 0x010b76c1: return "[PGO] VS2022 v17.0.0 preview2 build 30401 (*)";
        case 0x010c76c1: return "[PG+] VS2022 v17.0.0 preview2 build 30401 (*)";
        case 0x010d76c1: return "[POC] VS2022 v17.0.0 preview2 build 30401 (*)";
        case 0x010e76c1: return "[PO+] VS2022 v17.0.0 preview2 build 30401 (*)";

        // MSVS2019 v16.11.45
        // MSVS2019 v16.11.46
        // MSVS2019 v16.11.47
        // MSVS2019 v16.11.48
        // MSVS2019 v16.11.49
        // MSVS2019 v16.11.50
        // MSVS2019 v16.11.51
        case 0x010475cf: return "[ C ] VS2019 v16.11.45 build 30159";
        case 0x010375cf: return "[ASM] VS2019 v16.11.45 build 30159";
        case 0x010575cf: return "[C++] VS2019 v16.11.45 build 30159";
        case 0x00ff75cf: return "[RES] VS2019 v16.11.45 build 30159";
        case 0x010275cf: return "[LNK] VS2019 v16.11.45 build 30159";
        case 0x010075cf: return "[EXP] VS2019 v16.11.45 build 30159";
        case 0x010175cf: return "[IMP] VS2019 v16.11.45 build 30159";
        case 0x010875cf: return "[LTC] VS2019 v16.11.45 build 30159";
        case 0x010975cf: return "[LT+] VS2019 v16.11.45 build 30159";
        case 0x010b75cf: return "[PGO] VS2019 v16.11.45 build 30159";
        case 0x010c75cf: return "[PG+] VS2019 v16.11.45 build 30159";
        case 0x010675cf: return "[CIL] VS2019 v16.11.45 build 30159 (*)";
        case 0x010775cf: return "[CI+] VS2019 v16.11.45 build 30159 (*)";
        case 0x010a75cf: return "[LTM] VS2019 v16.11.45 build 30159 (*)";
        case 0x010d75cf: return "[POC] VS2019 v16.11.45 build 30159 (*)";
        case 0x010e75cf: return "[PO+] VS2019 v16.11.45 build 30159 (*)";

        // MSVS2019 v16.11.43
        // MSVS2019 v16.11.44
        case 0x010475ce: return "[ C ] VS2019 v16.11.43 build 30158";
        case 0x010375ce: return "[ASM] VS2019 v16.11.43 build 30158";
        case 0x010575ce: return "[C++] VS2019 v16.11.43 build 30158";
        case 0x00ff75ce: return "[RES] VS2019 v16.11.43 build 30158";
        case 0x010275ce: return "[LNK] VS2019 v16.11.43 build 30158";
        case 0x010075ce: return "[EXP] VS2019 v16.11.43 build 30158";
        case 0x010175ce: return "[IMP] VS2019 v16.11.43 build 30158";
        case 0x010875ce: return "[LTC] VS2019 v16.11.43 build 30158";
        case 0x010975ce: return "[LT+] VS2019 v16.11.43 build 30158";
        case 0x010b75ce: return "[PGO] VS2019 v16.11.43 build 30158";
        case 0x010c75ce: return "[PG+] VS2019 v16.11.43 build 30158";
        case 0x010675ce: return "[CIL] VS2019 v16.11.43 build 30158 (*)";
        case 0x010775ce: return "[CI+] VS2019 v16.11.43 build 30158 (*)";
        case 0x010a75ce: return "[LTM] VS2019 v16.11.43 build 30158 (*)";
        case 0x010d75ce: return "[POC] VS2019 v16.11.43 build 30158 (*)";
        case 0x010e75ce: return "[PO+] VS2019 v16.11.43 build 30158 (*)";

        // MSVS2019 v16.11.42
        case 0x010475cd: return "[ C ] VS2019 v16.11.42 build 30157";
        case 0x010375cd: return "[ASM] VS2019 v16.11.42 build 30157";
        case 0x010575cd: return "[C++] VS2019 v16.11.42 build 30157";
        case 0x00ff75cd: return "[RES] VS2019 v16.11.42 build 30157";
        case 0x010275cd: return "[LNK] VS2019 v16.11.42 build 30157";
        case 0x010075cd: return "[EXP] VS2019 v16.11.42 build 30157";
        case 0x010175cd: return "[IMP] VS2019 v16.11.42 build 30157";
        case 0x010875cd: return "[LTC] VS2019 v16.11.42 build 30157";
        case 0x010975cd: return "[LT+] VS2019 v16.11.42 build 30157";
        case 0x010b75cd: return "[PGO] VS2019 v16.11.42 build 30157";
        case 0x010c75cd: return "[PG+] VS2019 v16.11.42 build 30157";
        case 0x010675cd: return "[CIL] VS2019 v16.11.42 build 30157 (*)";
        case 0x010775cd: return "[CI+] VS2019 v16.11.42 build 30157 (*)";
        case 0x010a75cd: return "[LTM] VS2019 v16.11.42 build 30157 (*)";
        case 0x010d75cd: return "[POC] VS2019 v16.11.42 build 30157 (*)";
        case 0x010e75cd: return "[PO+] VS2019 v16.11.42 build 30157 (*)";

        // MSVS2019 v16.11.41
        case 0x010475cc: return "[ C ] VS2019 v16.11.41 build 30156";
        case 0x010375cc: return "[ASM] VS2019 v16.11.41 build 30156";
        case 0x010575cc: return "[C++] VS2019 v16.11.41 build 30156";
        case 0x00ff75cc: return "[RES] VS2019 v16.11.41 build 30156";
        case 0x010275cc: return "[LNK] VS2019 v16.11.41 build 30156";
        case 0x010075cc: return "[EXP] VS2019 v16.11.41 build 30156";
        case 0x010175cc: return "[IMP] VS2019 v16.11.41 build 30156";
        case 0x010875cc: return "[LTC] VS2019 v16.11.41 build 30156";
        case 0x010975cc: return "[LT+] VS2019 v16.11.41 build 30156";
        case 0x010b75cc: return "[PGO] VS2019 v16.11.41 build 30156";
        case 0x010c75cc: return "[PG+] VS2019 v16.11.41 build 30156";
        case 0x010675cc: return "[CIL] VS2019 v16.11.41 build 30156 (*)";
        case 0x010775cc: return "[CI+] VS2019 v16.11.41 build 30156 (*)";
        case 0x010a75cc: return "[LTM] VS2019 v16.11.41 build 30156 (*)";
        case 0x010d75cc: return "[POC] VS2019 v16.11.41 build 30156 (*)";
        case 0x010e75cc: return "[PO+] VS2019 v16.11.41 build 30156 (*)";

        // MSVS2019 v16.11.34
        // MSVS2019 v16.11.35
        // MSVS2019 v16.11.36
        // MSVS2019 v16.11.37
        // MSVS2019 v16.11.38
        // MSVS2019 v16.11.39
        // MSVS2019 v16.11.40
        case 0x010475ca: return "[ C ] VS2019 v16.11.34 build 30154";
        case 0x010375ca: return "[ASM] VS2019 v16.11.34 build 30154";
        case 0x010575ca: return "[C++] VS2019 v16.11.34 build 30154";
        case 0x00ff75ca: return "[RES] VS2019 v16.11.34 build 30154";
        case 0x010275ca: return "[LNK] VS2019 v16.11.34 build 30154";
        case 0x010075ca: return "[EXP] VS2019 v16.11.34 build 30154";
        case 0x010175ca: return "[IMP] VS2019 v16.11.34 build 30154";
        case 0x010875ca: return "[LTC] VS2019 v16.11.34 build 30154";
        case 0x010975ca: return "[LT+] VS2019 v16.11.34 build 30154";
        case 0x010b75ca: return "[PGO] VS2019 v16.11.34 build 30154";
        case 0x010c75ca: return "[PG+] VS2019 v16.11.34 build 30154";
        case 0x010675ca: return "[CIL] VS2019 v16.11.34 build 30154 (*)";
        case 0x010775ca: return "[CI+] VS2019 v16.11.34 build 30154 (*)";
        case 0x010a75ca: return "[LTM] VS2019 v16.11.34 build 30154 (*)";
        case 0x010d75ca: return "[POC] VS2019 v16.11.34 build 30154 (*)";
        case 0x010e75ca: return "[PO+] VS2019 v16.11.34 build 30154 (*)";

        // MSVS2019 v16.11.32
        // MSVS2019 v16.11.33
        case 0x010475c9: return "[ C ] VS2019 v16.11.32 build 30153";
        case 0x010375c9: return "[ASM] VS2019 v16.11.32 build 30153";
        case 0x010575c9: return "[C++] VS2019 v16.11.32 build 30153";
        case 0x00ff75c9: return "[RES] VS2019 v16.11.32 build 30153";
        case 0x010275c9: return "[LNK] VS2019 v16.11.32 build 30153";
        case 0x010075c9: return "[EXP] VS2019 v16.11.32 build 30153";
        case 0x010175c9: return "[IMP] VS2019 v16.11.32 build 30153";
        case 0x010875c9: return "[LTC] VS2019 v16.11.32 build 30153";
        case 0x010975c9: return "[LT+] VS2019 v16.11.32 build 30153";
        case 0x010b75c9: return "[PGO] VS2019 v16.11.32 build 30153";
        case 0x010c75c9: return "[PG+] VS2019 v16.11.32 build 30153";
        case 0x010675c9: return "[CIL] VS2019 v16.11.32 build 30153 (*)";
        case 0x010775c9: return "[CI+] VS2019 v16.11.32 build 30153 (*)";
        case 0x010a75c9: return "[LTM] VS2019 v16.11.32 build 30153 (*)";
        case 0x010d75c9: return "[POC] VS2019 v16.11.32 build 30153 (*)";
        case 0x010e75c9: return "[PO+] VS2019 v16.11.32 build 30153 (*)";

        // MSVS2019 v16.11.30
        // MSVS2019 v16.11.31
        case 0x010475c8: return "[ C ] VS2019 v16.11.30 build 30152";
        case 0x010375c8: return "[ASM] VS2019 v16.11.30 build 30152";
        case 0x010575c8: return "[C++] VS2019 v16.11.30 build 30152";
        case 0x00ff75c8: return "[RES] VS2019 v16.11.30 build 30152";
        case 0x010275c8: return "[LNK] VS2019 v16.11.30 build 30152";
        case 0x010075c8: return "[EXP] VS2019 v16.11.30 build 30152";
        case 0x010175c8: return "[IMP] VS2019 v16.11.30 build 30152";
        case 0x010875c8: return "[LTC] VS2019 v16.11.30 build 30152";
        case 0x010975c8: return "[LT+] VS2019 v16.11.30 build 30152";
        case 0x010b75c8: return "[PGO] VS2019 v16.11.30 build 30152";
        case 0x010c75c8: return "[PG+] VS2019 v16.11.30 build 30152";
        case 0x010675c8: return "[CIL] VS2019 v16.11.30 build 30152 (*)";
        case 0x010775c8: return "[CI+] VS2019 v16.11.30 build 30152 (*)";
        case 0x010a75c8: return "[LTM] VS2019 v16.11.30 build 30152 (*)";
        case 0x010d75c8: return "[POC] VS2019 v16.11.30 build 30152 (*)";
        case 0x010e75c8: return "[PO+] VS2019 v16.11.30 build 30152 (*)";

        // MSVS2019 v16.11.27
        // MSVS2019 v16.11.28
        // MSVS2019 v16.11.29
        case 0x010475c7: return "[ C ] VS2019 v16.11.27 build 30151";
        case 0x010375c7: return "[ASM] VS2019 v16.11.27 build 30151";
        case 0x010575c7: return "[C++] VS2019 v16.11.27 build 30151";
        case 0x00ff75c7: return "[RES] VS2019 v16.11.27 build 30151";
        case 0x010275c7: return "[LNK] VS2019 v16.11.27 build 30151";
        case 0x010075c7: return "[EXP] VS2019 v16.11.27 build 30151";
        case 0x010175c7: return "[IMP] VS2019 v16.11.27 build 30151";
        case 0x010875c7: return "[LTC] VS2019 v16.11.27 build 30151";
        case 0x010975c7: return "[LT+] VS2019 v16.11.27 build 30151";
        case 0x010b75c7: return "[PGO] VS2019 v16.11.27 build 30151";
        case 0x010c75c7: return "[PG+] VS2019 v16.11.27 build 30151";
        case 0x010675c7: return "[CIL] VS2019 v16.11.27 build 30151 (*)";
        case 0x010775c7: return "[CI+] VS2019 v16.11.27 build 30151 (*)";
        case 0x010a75c7: return "[LTM] VS2019 v16.11.27 build 30151 (*)";
        case 0x010d75c7: return "[POC] VS2019 v16.11.27 build 30151 (*)";
        case 0x010e75c7: return "[PO+] VS2019 v16.11.27 build 30151 (*)";

        // MSVS2019 v16.11.24
        // MSVS2019 v16.11.25
        // MSVS2019 v16.11.26
        case 0x010475c4: return "[ C ] VS2019 v16.11.24 build 30148";
        case 0x010375c4: return "[ASM] VS2019 v16.11.24 build 30148";
        case 0x010575c4: return "[C++] VS2019 v16.11.24 build 30148";
        case 0x00ff75c4: return "[RES] VS2019 v16.11.24 build 30148";
        case 0x010275c4: return "[LNK] VS2019 v16.11.24 build 30148";
        case 0x010075c4: return "[EXP] VS2019 v16.11.24 build 30148";
        case 0x010175c4: return "[IMP] VS2019 v16.11.24 build 30148";
        case 0x010875c4: return "[LTC] VS2019 v16.11.24 build 30148";
        case 0x010975c4: return "[LT+] VS2019 v16.11.24 build 30148";
        case 0x010b75c4: return "[PGO] VS2019 v16.11.24 build 30148";
        case 0x010c75c4: return "[PG+] VS2019 v16.11.24 build 30148";
        case 0x010675c4: return "[CIL] VS2019 v16.11.24 build 30148 (*)";
        case 0x010775c4: return "[CI+] VS2019 v16.11.24 build 30148 (*)";
        case 0x010a75c4: return "[LTM] VS2019 v16.11.24 build 30148 (*)";
        case 0x010d75c4: return "[POC] VS2019 v16.11.24 build 30148 (*)";
        case 0x010e75c4: return "[PO+] VS2019 v16.11.24 build 30148 (*)";

        // MSVS2019 v16.11.21
        case 0x010475c3: return "[ C ] VS2019 v16.11.21 build 30147";
        case 0x010375c3: return "[ASM] VS2019 v16.11.21 build 30147";
        case 0x010575c3: return "[C++] VS2019 v16.11.21 build 30147";
        case 0x00ff75c3: return "[RES] VS2019 v16.11.21 build 30147";
        case 0x010275c3: return "[LNK] VS2019 v16.11.21 build 30147";
        case 0x010075c3: return "[EXP] VS2019 v16.11.21 build 30147";
        case 0x010175c3: return "[IMP] VS2019 v16.11.21 build 30147";
        case 0x010675c3: return "[CIL] VS2019 v16.11.21 build 30147 (*)";
        case 0x010775c3: return "[CI+] VS2019 v16.11.21 build 30147 (*)";
        case 0x010875c3: return "[LTC] VS2019 v16.11.21 build 30147 (*)";
        case 0x010975c3: return "[LT+] VS2019 v16.11.21 build 30147 (*)";
        case 0x010a75c3: return "[LTM] VS2019 v16.11.21 build 30147 (*)";
        case 0x010b75c3: return "[PGO] VS2019 v16.11.21 build 30147 (*)";
        case 0x010c75c3: return "[PG+] VS2019 v16.11.21 build 30147 (*)";
        case 0x010d75c3: return "[POC] VS2019 v16.11.21 build 30147 (*)";
        case 0x010e75c3: return "[PO+] VS2019 v16.11.21 build 30147 (*)";

        // MSVS2019 v16.11.17
        case 0x010475c2: return "[ C ] VS2019 v16.11.17 build 30146";
        case 0x010375c2: return "[ASM] VS2019 v16.11.17 build 30146";
        case 0x010575c2: return "[C++] VS2019 v16.11.17 build 30146";
        case 0x00ff75c2: return "[RES] VS2019 v16.11.17 build 30146";
        case 0x010275c2: return "[LNK] VS2019 v16.11.17 build 30146";
        case 0x010075c2: return "[EXP] VS2019 v16.11.17 build 30146";
        case 0x010175c2: return "[IMP] VS2019 v16.11.17 build 30146";
        case 0x010675c2: return "[CIL] VS2019 v16.11.17 build 30146 (*)";
        case 0x010775c2: return "[CI+] VS2019 v16.11.17 build 30146 (*)";
        case 0x010875c2: return "[LTC] VS2019 v16.11.17 build 30146 (*)";
        case 0x010975c2: return "[LT+] VS2019 v16.11.17 build 30146 (*)";
        case 0x010a75c2: return "[LTM] VS2019 v16.11.17 build 30146 (*)";
        case 0x010b75c2: return "[PGO] VS2019 v16.11.17 build 30146 (*)";
        case 0x010c75c2: return "[PG+] VS2019 v16.11.17 build 30146 (*)";
        case 0x010d75c2: return "[POC] VS2019 v16.11.17 build 30146 (*)";
        case 0x010e75c2: return "[PO+] VS2019 v16.11.17 build 30146 (*)";

        // MSVS2019 v16.11.15
        case 0x010475c1: return "[ C ] VS2019 v16.11.15 build 30145";
        case 0x010375c1: return "[ASM] VS2019 v16.11.15 build 30145";
        case 0x010575c1: return "[C++] VS2019 v16.11.15 build 30145";
        case 0x00ff75c1: return "[RES] VS2019 v16.11.15 build 30145";
        case 0x010275c1: return "[LNK] VS2019 v16.11.15 build 30145";
        case 0x010075c1: return "[EXP] VS2019 v16.11.15 build 30145";
        case 0x010175c1: return "[IMP] VS2019 v16.11.15 build 30145";
        case 0x010675c1: return "[CIL] VS2019 v16.11.15 build 30145 (*)";
        case 0x010775c1: return "[CI+] VS2019 v16.11.15 build 30145 (*)";
        case 0x010875c1: return "[LTC] VS2019 v16.11.15 build 30145 (*)";
        case 0x010975c1: return "[LT+] VS2019 v16.11.15 build 30145 (*)";
        case 0x010a75c1: return "[LTM] VS2019 v16.11.15 build 30145 (*)";
        case 0x010b75c1: return "[PGO] VS2019 v16.11.15 build 30145 (*)";
        case 0x010c75c1: return "[PG+] VS2019 v16.11.15 build 30145 (*)";
        case 0x010d75c1: return "[POC] VS2019 v16.11.15 build 30145 (*)";
        case 0x010e75c1: return "[PO+] VS2019 v16.11.15 build 30145 (*)";

        // MSVS2019 v16.11.14
        // from https://walbourn.github.io/vs-2019-update-11/
        case 0x010475c0: return "[ C ] VS2019 v16.11.14 build 30144 (*)";
        case 0x010375c0: return "[ASM] VS2019 v16.11.14 build 30144 (*)";
        case 0x010575c0: return "[C++] VS2019 v16.11.14 build 30144 (*)";
        case 0x00ff75c0: return "[RES] VS2019 v16.11.14 build 30144 (*)";
        case 0x010275c0: return "[LNK] VS2019 v16.11.14 build 30144 (*)";
        case 0x010075c0: return "[EXP] VS2019 v16.11.14 build 30144 (*)";
        case 0x010175c0: return "[IMP] VS2019 v16.11.14 build 30144 (*)";
        case 0x010675c0: return "[CIL] VS2019 v16.11.14 build 30144 (*)";
        case 0x010775c0: return "[CI+] VS2019 v16.11.14 build 30144 (*)";
        case 0x010875c0: return "[LTC] VS2019 v16.11.14 build 30144 (*)";
        case 0x010975c0: return "[LT+] VS2019 v16.11.14 build 30144 (*)";
        case 0x010a75c0: return "[LTM] VS2019 v16.11.14 build 30144 (*)";
        case 0x010b75c0: return "[PGO] VS2019 v16.11.14 build 30144 (*)";
        case 0x010c75c0: return "[PG+] VS2019 v16.11.14 build 30144 (*)";
        case 0x010d75c0: return "[POC] VS2019 v16.11.14 build 30144 (*)";
        case 0x010e75c0: return "[PO+] VS2019 v16.11.14 build 30144 (*)";

        // MSVS2019 v16.11.13
        case 0x010475bf: return "[ C ] VS2019 v16.11.13 build 30143";
        case 0x010375bf: return "[ASM] VS2019 v16.11.13 build 30143";
        case 0x010575bf: return "[C++] VS2019 v16.11.13 build 30143";
        case 0x00ff75bf: return "[RES] VS2019 v16.11.13 build 30143";
        case 0x010275bf: return "[LNK] VS2019 v16.11.13 build 30143";
        case 0x010075bf: return "[EXP] VS2019 v16.11.13 build 30143";
        case 0x010175bf: return "[IMP] VS2019 v16.11.13 build 30143";
        case 0x010675bf: return "[CIL] VS2019 v16.11.13 build 30143 (*)";
        case 0x010775bf: return "[CI+] VS2019 v16.11.13 build 30143 (*)";
        case 0x010875bf: return "[LTC] VS2019 v16.11.13 build 30143 (*)";
        case 0x010975bf: return "[LT+] VS2019 v16.11.13 build 30143 (*)";
        case 0x010a75bf: return "[LTM] VS2019 v16.11.13 build 30143 (*)";
        case 0x010b75bf: return "[PGO] VS2019 v16.11.13 build 30143 (*)";
        case 0x010c75bf: return "[PG+] VS2019 v16.11.13 build 30143 (*)";
        case 0x010d75bf: return "[POC] VS2019 v16.11.13 build 30143 (*)";
        case 0x010e75bf: return "[PO+] VS2019 v16.11.13 build 30143 (*)";

        // MSVS2019 v16.11.12
        // from https://walbourn.github.io/vs-2019-update-11/
        case 0x010475be: return "[ C ] VS2019 v16.11.12 build 30142 (*)";
        case 0x010375be: return "[ASM] VS2019 v16.11.12 build 30142 (*)";
        case 0x010575be: return "[C++] VS2019 v16.11.12 build 30142 (*)";
        case 0x00ff75be: return "[RES] VS2019 v16.11.12 build 30142 (*)";
        case 0x010275be: return "[LNK] VS2019 v16.11.12 build 30142 (*)";
        case 0x010075be: return "[EXP] VS2019 v16.11.12 build 30142 (*)";
        case 0x010175be: return "[IMP] VS2019 v16.11.12 build 30142 (*)";
        case 0x010675be: return "[CIL] VS2019 v16.11.12 build 30142 (*)";
        case 0x010775be: return "[CI+] VS2019 v16.11.12 build 30142 (*)";
        case 0x010875be: return "[LTC] VS2019 v16.11.12 build 30142 (*)";
        case 0x010975be: return "[LT+] VS2019 v16.11.12 build 30142 (*)";
        case 0x010a75be: return "[LTM] VS2019 v16.11.12 build 30142 (*)";
        case 0x010b75be: return "[PGO] VS2019 v16.11.12 build 30142 (*)";
        case 0x010c75be: return "[PG+] VS2019 v16.11.12 build 30142 (*)";
        case 0x010d75be: return "[POC] VS2019 v16.11.12 build 30142 (*)";
        case 0x010e75be: return "[PO+] VS2019 v16.11.12 build 30142 (*)";

        // MSVS2019 v16.11.11
        // from https://walbourn.github.io/vs-2019-update-11/
        case 0x010475bd: return "[ C ] VS2019 v16.11.11 build 30141 (*)";
        case 0x010375bd: return "[ASM] VS2019 v16.11.11 build 30141 (*)";
        case 0x010575bd: return "[C++] VS2019 v16.11.11 build 30141 (*)";
        case 0x00ff75bd: return "[RES] VS2019 v16.11.11 build 30141 (*)";
        case 0x010275bd: return "[LNK] VS2019 v16.11.11 build 30141 (*)";
        case 0x010075bd: return "[EXP] VS2019 v16.11.11 build 30141 (*)";
        case 0x010175bd: return "[IMP] VS2019 v16.11.11 build 30141 (*)";
        case 0x010675bd: return "[CIL] VS2019 v16.11.11 build 30141 (*)";
        case 0x010775bd: return "[CI+] VS2019 v16.11.11 build 30141 (*)";
        case 0x010875bd: return "[LTC] VS2019 v16.11.11 build 30141 (*)";
        case 0x010975bd: return "[LT+] VS2019 v16.11.11 build 30141 (*)";
        case 0x010a75bd: return "[LTM] VS2019 v16.11.11 build 30141 (*)";
        case 0x010b75bd: return "[PGO] VS2019 v16.11.11 build 30141 (*)";
        case 0x010c75bd: return "[PG+] VS2019 v16.11.11 build 30141 (*)";
        case 0x010d75bd: return "[POC] VS2019 v16.11.11 build 30141 (*)";
        case 0x010e75bd: return "[PO+] VS2019 v16.11.11 build 30141 (*)";

        // MSVS2019 v16.11.10
        case 0x010475bc: return "[ C ] VS2019 v16.11.10 build 30140";
        case 0x010375bc: return "[ASM] VS2019 v16.11.10 build 30140";
        case 0x010575bc: return "[C++] VS2019 v16.11.10 build 30140";
        case 0x00ff75bc: return "[RES] VS2019 v16.11.10 build 30140";
        case 0x010275bc: return "[LNK] VS2019 v16.11.10 build 30140";
        case 0x010075bc: return "[EXP] VS2019 v16.11.10 build 30140";
        case 0x010175bc: return "[IMP] VS2019 v16.11.10 build 30140";
        case 0x010675bc: return "[CIL] VS2019 v16.11.10 build 30140 (*)";
        case 0x010775bc: return "[CI+] VS2019 v16.11.10 build 30140 (*)";
        case 0x010875bc: return "[LTC] VS2019 v16.11.10 build 30140 (*)";
        case 0x010975bc: return "[LT+] VS2019 v16.11.10 build 30140 (*)";
        case 0x010a75bc: return "[LTM] VS2019 v16.11.10 build 30140 (*)";
        case 0x010b75bc: return "[PGO] VS2019 v16.11.10 build 30140 (*)";
        case 0x010c75bc: return "[PG+] VS2019 v16.11.10 build 30140 (*)";
        case 0x010d75bc: return "[POC] VS2019 v16.11.10 build 30140 (*)";
        case 0x010e75bc: return "[PO+] VS2019 v16.11.10 build 30140 (*)";

        // MSVS2019 v16.11.9
        case 0x010475bb: return "[ C ] VS2019 v16.11.9 build 30139";
        case 0x010375bb: return "[ASM] VS2019 v16.11.9 build 30139";
        case 0x010575bb: return "[C++] VS2019 v16.11.9 build 30139";
        case 0x00ff75bb: return "[RES] VS2019 v16.11.9 build 30139";
        case 0x010275bb: return "[LNK] VS2019 v16.11.9 build 30139";
        case 0x010075bb: return "[EXP] VS2019 v16.11.9 build 30139";
        case 0x010175bb: return "[IMP] VS2019 v16.11.9 build 30139";
        case 0x010675bb: return "[CIL] VS2019 v16.11.9 build 30139 (*)";
        case 0x010775bb: return "[CI+] VS2019 v16.11.9 build 30139 (*)";
        case 0x010875bb: return "[LTC] VS2019 v16.11.9 build 30139 (*)";
        case 0x010975bb: return "[LT+] VS2019 v16.11.9 build 30139 (*)";
        case 0x010a75bb: return "[LTM] VS2019 v16.11.9 build 30139 (*)";
        case 0x010b75bb: return "[PGO] VS2019 v16.11.9 build 30139 (*)";
        case 0x010c75bb: return "[PG+] VS2019 v16.11.9 build 30139 (*)";
        case 0x010d75bb: return "[POC] VS2019 v16.11.9 build 30139 (*)";
        case 0x010e75bb: return "[PO+] VS2019 v16.11.9 build 30139 (*)";

        // MSVS2019 v16.11.8
        case 0x010475ba: return "[ C ] VS2019 v16.11.8 build 30138";
        case 0x010375ba: return "[ASM] VS2019 v16.11.8 build 30138";
        case 0x010575ba: return "[C++] VS2019 v16.11.8 build 30138";
        case 0x00ff75ba: return "[RES] VS2019 v16.11.8 build 30138";
        case 0x010275ba: return "[LNK] VS2019 v16.11.8 build 30138";
        case 0x010075ba: return "[EXP] VS2019 v16.11.8 build 30138";
        case 0x010175ba: return "[IMP] VS2019 v16.11.8 build 30138";
        case 0x010675ba: return "[CIL] VS2019 v16.11.8 build 30138 (*)";
        case 0x010775ba: return "[CI+] VS2019 v16.11.8 build 30138 (*)";
        case 0x010875ba: return "[LTC] VS2019 v16.11.8 build 30138 (*)";
        case 0x010975ba: return "[LT+] VS2019 v16.11.8 build 30138 (*)";
        case 0x010a75ba: return "[LTM] VS2019 v16.11.8 build 30138 (*)";
        case 0x010b75ba: return "[PGO] VS2019 v16.11.8 build 30138 (*)";
        case 0x010c75ba: return "[PG+] VS2019 v16.11.8 build 30138 (*)";
        case 0x010d75ba: return "[POC] VS2019 v16.11.8 build 30138 (*)";
        case 0x010e75ba: return "[PO+] VS2019 v16.11.8 build 30138 (*)";

        // MSVS2019 v16.11.6
        case 0x010475b9: return "[ C ] VS2019 v16.11.6 build 30137";
        case 0x010375b9: return "[ASM] VS2019 v16.11.6 build 30137";
        case 0x010575b9: return "[C++] VS2019 v16.11.6 build 30137";
        case 0x00ff75b9: return "[RES] VS2019 v16.11.6 build 30137";
        case 0x010275b9: return "[LNK] VS2019 v16.11.6 build 30137";
        case 0x010075b9: return "[EXP] VS2019 v16.11.6 build 30137";
        case 0x010175b9: return "[IMP] VS2019 v16.11.6 build 30137";
        case 0x010675b9: return "[CIL] VS2019 v16.11.6 build 30137 (*)";
        case 0x010775b9: return "[CI+] VS2019 v16.11.6 build 30137 (*)";
        case 0x010875b9: return "[LTC] VS2019 v16.11.6 build 30137 (*)";
        case 0x010975b9: return "[LT+] VS2019 v16.11.6 build 30137 (*)";
        case 0x010a75b9: return "[LTM] VS2019 v16.11.6 build 30137 (*)";
        case 0x010b75b9: return "[PGO] VS2019 v16.11.6 build 30137 (*)";
        case 0x010c75b9: return "[PG+] VS2019 v16.11.6 build 30137 (*)";
        case 0x010d75b9: return "[POC] VS2019 v16.11.6 build 30137 (*)";
        case 0x010e75b9: return "[PO+] VS2019 v16.11.6 build 30137 (*)";

        // MSVS2019 v16.11.5
        case 0x010475b8: return "[ C ] VS2019 v16.11.5 build 30136";
        case 0x010375b8: return "[ASM] VS2019 v16.11.5 build 30136";
        case 0x010575b8: return "[C++] VS2019 v16.11.5 build 30136";
        case 0x00ff75b8: return "[RES] VS2019 v16.11.5 build 30136";
        case 0x010275b8: return "[LNK] VS2019 v16.11.5 build 30136";
        case 0x010075b8: return "[EXP] VS2019 v16.11.5 build 30136";
        case 0x010175b8: return "[IMP] VS2019 v16.11.5 build 30136";
        case 0x010675b8: return "[CIL] VS2019 v16.11.5 build 30136 (*)";
        case 0x010775b8: return "[CI+] VS2019 v16.11.5 build 30136 (*)";
        case 0x010875b8: return "[LTC] VS2019 v16.11.5 build 30136 (*)";
        case 0x010975b8: return "[LT+] VS2019 v16.11.5 build 30136 (*)";
        case 0x010a75b8: return "[LTM] VS2019 v16.11.5 build 30136 (*)";
        case 0x010b75b8: return "[PGO] VS2019 v16.11.5 build 30136 (*)";
        case 0x010c75b8: return "[PG+] VS2019 v16.11.5 build 30136 (*)";
        case 0x010d75b8: return "[POC] VS2019 v16.11.5 build 30136 (*)";
        case 0x010e75b8: return "[PO+] VS2019 v16.11.5 build 30136 (*)";

        // MSVS2019 v16.11.1
        case 0x010475b5: return "[ C ] VS2019 v16.11.1 build 30133";
        case 0x010375b5: return "[ASM] VS2019 v16.11.1 build 30133";
        case 0x010575b5: return "[C++] VS2019 v16.11.1 build 30133";
        case 0x00ff75b5: return "[RES] VS2019 v16.11.1 build 30133";
        case 0x010275b5: return "[LNK] VS2019 v16.11.1 build 30133";
        case 0x010075b5: return "[EXP] VS2019 v16.11.1 build 30133";
        case 0x010175b5: return "[IMP] VS2019 v16.11.1 build 30133";
        case 0x010675b5: return "[CIL] VS2019 v16.11.1 build 30133 (*)";
        case 0x010775b5: return "[CI+] VS2019 v16.11.1 build 30133 (*)";
        case 0x010875b5: return "[LTC] VS2019 v16.11.1 build 30133 (*)";
        case 0x010975b5: return "[LT+] VS2019 v16.11.1 build 30133 (*)";
        case 0x010a75b5: return "[LTM] VS2019 v16.11.1 build 30133 (*)";
        case 0x010b75b5: return "[PGO] VS2019 v16.11.1 build 30133 (*)";
        case 0x010c75b5: return "[PG+] VS2019 v16.11.1 build 30133 (*)";
        case 0x010d75b5: return "[POC] VS2019 v16.11.1 build 30133 (*)";
        case 0x010e75b5: return "[PO+] VS2019 v16.11.1 build 30133 (*)";

        // MSVS2019 v16.10.4
        case 0x01047558: return "[ C ] VS2019 v16.10.4 build 30040";
        case 0x01037558: return "[ASM] VS2019 v16.10.4 build 30040";
        case 0x01057558: return "[C++] VS2019 v16.10.4 build 30040";
        case 0x00ff7558: return "[RES] VS2019 v16.10.4 build 30040";
        case 0x01027558: return "[LNK] VS2019 v16.10.4 build 30040";
        case 0x01007558: return "[EXP] VS2019 v16.10.4 build 30040";
        case 0x01017558: return "[IMP] VS2019 v16.10.4 build 30040";
        case 0x01067558: return "[CIL] VS2019 v16.10.4 build 30040 (*)";
        case 0x01077558: return "[CI+] VS2019 v16.10.4 build 30040 (*)";
        case 0x01087558: return "[LTC] VS2019 v16.10.4 build 30040 (*)";
        case 0x01097558: return "[LT+] VS2019 v16.10.4 build 30040 (*)";
        case 0x010a7558: return "[LTM] VS2019 v16.10.4 build 30040 (*)";
        case 0x010b7558: return "[PGO] VS2019 v16.10.4 build 30040 (*)";
        case 0x010c7558: return "[PG+] VS2019 v16.10.4 build 30040 (*)";
        case 0x010d7558: return "[POC] VS2019 v16.10.4 build 30040 (*)";
        case 0x010e7558: return "[PO+] VS2019 v16.10.4 build 30040 (*)";

        // MSVS2019 v16.10.3
        case 0x01047556: return "[ C ] VS2019 v16.10.3 build 30038";
        case 0x01037556: return "[ASM] VS2019 v16.10.3 build 30038";
        case 0x01057556: return "[C++] VS2019 v16.10.3 build 30038";
        case 0x00ff7556: return "[RES] VS2019 v16.10.3 build 30038";
        case 0x01027556: return "[LNK] VS2019 v16.10.3 build 30038";
        case 0x01007556: return "[EXP] VS2019 v16.10.3 build 30038";
        case 0x01017556: return "[IMP] VS2019 v16.10.3 build 30038";
        case 0x01067556: return "[CIL] VS2019 v16.10.3 build 30038 (*)";
        case 0x01077556: return "[CI+] VS2019 v16.10.3 build 30038 (*)";
        case 0x01087556: return "[LTC] VS2019 v16.10.3 build 30038 (*)";
        case 0x01097556: return "[LT+] VS2019 v16.10.3 build 30038 (*)";
        case 0x010a7556: return "[LTM] VS2019 v16.10.3 build 30038 (*)";
        case 0x010b7556: return "[PGO] VS2019 v16.10.3 build 30038 (*)";
        case 0x010c7556: return "[PG+] VS2019 v16.10.3 build 30038 (*)";
        case 0x010d7556: return "[POC] VS2019 v16.10.3 build 30038 (*)";
        case 0x010e7556: return "[PO+] VS2019 v16.10.3 build 30038 (*)";

        // MSVS2019 v16.10.0
        case 0x01047555: return "[ C ] VS2019 v16.10.0 build 30037";
        case 0x01037555: return "[ASM] VS2019 v16.10.0 build 30037";
        case 0x01057555: return "[C++] VS2019 v16.10.0 build 30037";
        case 0x00ff7555: return "[RES] VS2019 v16.10.0 build 30037";
        case 0x01027555: return "[LNK] VS2019 v16.10.0 build 30037";
        case 0x01007555: return "[EXP] VS2019 v16.10.0 build 30037";
        case 0x01017555: return "[IMP] VS2019 v16.10.0 build 30037";
        case 0x01067555: return "[CIL] VS2019 v16.10.0 build 30037 (*)";
        case 0x01077555: return "[CI+] VS2019 v16.10.0 build 30037 (*)";
        case 0x01087555: return "[LTC] VS2019 v16.10.0 build 30037 (*)";
        case 0x01097555: return "[LT+] VS2019 v16.10.0 build 30037 (*)";
        case 0x010a7555: return "[LTM] VS2019 v16.10.0 build 30037 (*)";
        case 0x010b7555: return "[PGO] VS2019 v16.10.0 build 30037 (*)";
        case 0x010c7555: return "[PG+] VS2019 v16.10.0 build 30037 (*)";
        case 0x010d7555: return "[POC] VS2019 v16.10.0 build 30037 (*)";
        case 0x010e7555: return "[PO+] VS2019 v16.10.0 build 30037 (*)";

        // MSVS2019 v16.9.5
        case 0x010474db: return "[ C ] VS2019 v16.9.5 build 29915";
        case 0x010374db: return "[ASM] VS2019 v16.9.5 build 29915";
        case 0x010574db: return "[C++] VS2019 v16.9.5 build 29915";
        case 0x00ff74db: return "[RES] VS2019 v16.9.5 build 29915";
        case 0x010274db: return "[LNK] VS2019 v16.9.5 build 29915";
        case 0x010074db: return "[EXP] VS2019 v16.9.5 build 29915";
        case 0x010174db: return "[IMP] VS2019 v16.9.5 build 29915";
        case 0x010674db: return "[CIL] VS2019 v16.9.5 build 29915 (*)";
        case 0x010774db: return "[CI+] VS2019 v16.9.5 build 29915 (*)";
        case 0x010874db: return "[LTC] VS2019 v16.9.5 build 29915 (*)";
        case 0x010974db: return "[LT+] VS2019 v16.9.5 build 29915 (*)";
        case 0x010a74db: return "[LTM] VS2019 v16.9.5 build 29915 (*)";
        case 0x010b74db: return "[PGO] VS2019 v16.9.5 build 29915 (*)";
        case 0x010c74db: return "[PG+] VS2019 v16.9.5 build 29915 (*)";
        case 0x010d74db: return "[POC] VS2019 v16.9.5 build 29915 (*)";
        case 0x010e74db: return "[PO+] VS2019 v16.9.5 build 29915 (*)";

        // MSVS2019 v16.9.4
        case 0x010474da: return "[ C ] VS2019 v16.9.4 build 29914";
        case 0x010374da: return "[ASM] VS2019 v16.9.4 build 29914";
        case 0x010574da: return "[C++] VS2019 v16.9.4 build 29914";
        case 0x00ff74da: return "[RES] VS2019 v16.9.4 build 29914";
        case 0x010274da: return "[LNK] VS2019 v16.9.4 build 29914";
        case 0x010074da: return "[EXP] VS2019 v16.9.4 build 29914";
        case 0x010174da: return "[IMP] VS2019 v16.9.4 build 29914";
        case 0x010674da: return "[CIL] VS2019 v16.9.4 build 29914 (*)";
        case 0x010774da: return "[CI+] VS2019 v16.9.4 build 29914 (*)";
        case 0x010874da: return "[LTC] VS2019 v16.9.4 build 29914 (*)";
        case 0x010974da: return "[LT+] VS2019 v16.9.4 build 29914 (*)";
        case 0x010a74da: return "[LTM] VS2019 v16.9.4 build 29914 (*)";
        case 0x010b74da: return "[PGO] VS2019 v16.9.4 build 29914 (*)";
        case 0x010c74da: return "[PG+] VS2019 v16.9.4 build 29914 (*)";
        case 0x010d74da: return "[POC] VS2019 v16.9.4 build 29914 (*)";
        case 0x010e74da: return "[PO+] VS2019 v16.9.4 build 29914 (*)";

        // MSVS2019 v16.9.2
        case 0x010474d9: return "[ C ] VS2019 v16.9.2 build 29913";
        case 0x010374d9: return "[ASM] VS2019 v16.9.2 build 29913";
        case 0x010574d9: return "[C++] VS2019 v16.9.2 build 29913";
        case 0x00ff74d9: return "[RES] VS2019 v16.9.2 build 29913";
        case 0x010274d9: return "[LNK] VS2019 v16.9.2 build 29913";
        case 0x010074d9: return "[EXP] VS2019 v16.9.2 build 29913";
        case 0x010174d9: return "[IMP] VS2019 v16.9.2 build 29913";
        case 0x010674d9: return "[CIL] VS2019 v16.9.2 build 29913 (*)";
        case 0x010774d9: return "[CI+] VS2019 v16.9.2 build 29913 (*)";
        case 0x010874d9: return "[LTC] VS2019 v16.9.2 build 29913 (*)";
        case 0x010974d9: return "[LT+] VS2019 v16.9.2 build 29913 (*)";
        case 0x010a74d9: return "[LTM] VS2019 v16.9.2 build 29913 (*)";
        case 0x010b74d9: return "[PGO] VS2019 v16.9.2 build 29913 (*)";
        case 0x010c74d9: return "[PG+] VS2019 v16.9.2 build 29913 (*)";
        case 0x010d74d9: return "[POC] VS2019 v16.9.2 build 29913 (*)";
        case 0x010e74d9: return "[PO+] VS2019 v16.9.2 build 29913 (*)";

        // MSVS2019 v16.9.0
        // from https://walbourn.github.io/vs-2019-update-9/
        case 0x010474d6: return "[ C ] VS2019 v16.9.0 build 29910 (*)";
        case 0x010374d6: return "[ASM] VS2019 v16.9.0 build 29910 (*)";
        case 0x010574d6: return "[C++] VS2019 v16.9.0 build 29910 (*)";
        case 0x00ff74d6: return "[RES] VS2019 v16.9.0 build 29910 (*)";
        case 0x010274d6: return "[LNK] VS2019 v16.9.0 build 29910 (*)";
        case 0x010074d6: return "[EXP] VS2019 v16.9.0 build 29910 (*)";
        case 0x010174d6: return "[IMP] VS2019 v16.9.0 build 29910 (*)";
        case 0x010674d6: return "[CIL] VS2019 v16.9.0 build 29910 (*)";
        case 0x010774d6: return "[CI+] VS2019 v16.9.0 build 29910 (*)";
        case 0x010874d6: return "[LTC] VS2019 v16.9.0 build 29910 (*)";
        case 0x010974d6: return "[LT+] VS2019 v16.9.0 build 29910 (*)";
        case 0x010a74d6: return "[LTM] VS2019 v16.9.0 build 29910 (*)";
        case 0x010b74d6: return "[PGO] VS2019 v16.9.0 build 29910 (*)";
        case 0x010c74d6: return "[PG+] VS2019 v16.9.0 build 29910 (*)";
        case 0x010d74d6: return "[POC] VS2019 v16.9.0 build 29910 (*)";
        case 0x010e74d6: return "[PO+] VS2019 v16.9.0 build 29910 (*)";

        // MSVS2019 v16.8.5
        case 0x01047299: return "[ C ] VS2019 v16.8.5 build 29337";
        case 0x01037299: return "[ASM] VS2019 v16.8.5 build 29337";
        case 0x01057299: return "[C++] VS2019 v16.8.5 build 29337";
        case 0x00ff7299: return "[RES] VS2019 v16.8.5 build 29337";
        case 0x01027299: return "[LNK] VS2019 v16.8.5 build 29337";
        case 0x01007299: return "[EXP] VS2019 v16.8.5 build 29337";
        case 0x01017299: return "[IMP] VS2019 v16.8.5 build 29337";
        case 0x01067299: return "[CIL] VS2019 v16.8.5 build 29337 (*)";
        case 0x01077299: return "[CI+] VS2019 v16.8.5 build 29337 (*)";
        case 0x01087299: return "[LTC] VS2019 v16.8.5 build 29337 (*)";
        case 0x01097299: return "[LT+] VS2019 v16.8.5 build 29337 (*)";
        case 0x010a7299: return "[LTM] VS2019 v16.8.5 build 29337 (*)";
        case 0x010b7299: return "[PGO] VS2019 v16.8.5 build 29337 (*)";
        case 0x010c7299: return "[PG+] VS2019 v16.8.5 build 29337 (*)";
        case 0x010d7299: return "[POC] VS2019 v16.8.5 build 29337 (*)";
        case 0x010e7299: return "[PO+] VS2019 v16.8.5 build 29337 (*)";

        // MSVS2019 v16.8.4
        case 0x01047298: return "[ C ] VS2019 v16.8.4 build 29336";
        case 0x01037298: return "[ASM] VS2019 v16.8.4 build 29336";
        case 0x01057298: return "[C++] VS2019 v16.8.4 build 29336";
        case 0x00ff7298: return "[RES] VS2019 v16.8.4 build 29336";
        case 0x01027298: return "[LNK] VS2019 v16.8.4 build 29336";
        case 0x01007298: return "[EXP] VS2019 v16.8.4 build 29336";
        case 0x01017298: return "[IMP] VS2019 v16.8.4 build 29336";
        case 0x01067298: return "[CIL] VS2019 v16.8.4 build 29336 (*)";
        case 0x01077298: return "[CI+] VS2019 v16.8.4 build 29336 (*)";
        case 0x01087298: return "[LTC] VS2019 v16.8.4 build 29336 (*)";
        case 0x01097298: return "[LT+] VS2019 v16.8.4 build 29336 (*)";
        case 0x010a7298: return "[LTM] VS2019 v16.8.4 build 29336 (*)";
        case 0x010b7298: return "[PGO] VS2019 v16.8.4 build 29336 (*)";
        case 0x010c7298: return "[PG+] VS2019 v16.8.4 build 29336 (*)";
        case 0x010d7298: return "[POC] VS2019 v16.8.4 build 29336 (*)";
        case 0x010e7298: return "[PO+] VS2019 v16.8.4 build 29336 (*)";

        // MSVS2019 v16.8.3
        case 0x01047297: return "[ C ] VS2019 v16.8.3 build 29335";
        case 0x01037297: return "[ASM] VS2019 v16.8.3 build 29335";
        case 0x01057297: return "[C++] VS2019 v16.8.3 build 29335";
        case 0x00ff7297: return "[RES] VS2019 v16.8.3 build 29335";
        case 0x01027297: return "[LNK] VS2019 v16.8.3 build 29335";
        case 0x01007297: return "[EXP] VS2019 v16.8.3 build 29335";
        case 0x01017297: return "[IMP] VS2019 v16.8.3 build 29335";
        case 0x01067297: return "[CIL] VS2019 v16.8.3 build 29335 (*)";
        case 0x01077297: return "[CI+] VS2019 v16.8.3 build 29335 (*)";
        case 0x01087297: return "[LTC] VS2019 v16.8.3 build 29335 (*)";
        case 0x01097297: return "[LT+] VS2019 v16.8.3 build 29335 (*)";
        case 0x010a7297: return "[LTM] VS2019 v16.8.3 build 29335 (*)";
        case 0x010b7297: return "[PGO] VS2019 v16.8.3 build 29335 (*)";
        case 0x010c7297: return "[PG+] VS2019 v16.8.3 build 29335 (*)";
        case 0x010d7297: return "[POC] VS2019 v16.8.3 build 29335 (*)";
        case 0x010e7297: return "[PO+] VS2019 v16.8.3 build 29335 (*)";

        // MSVS2019 v16.8.2
        case 0x01047296: return "[ C ] VS2019 v16.8.2 build 29334";
        case 0x01037296: return "[ASM] VS2019 v16.8.2 build 29334";
        case 0x01057296: return "[C++] VS2019 v16.8.2 build 29334";
        case 0x00ff7296: return "[RES] VS2019 v16.8.2 build 29334";
        case 0x01027296: return "[LNK] VS2019 v16.8.2 build 29334";
        case 0x01007296: return "[EXP] VS2019 v16.8.2 build 29334";
        case 0x01017296: return "[IMP] VS2019 v16.8.2 build 29334";
        case 0x01067296: return "[CIL] VS2019 v16.8.2 build 29334 (*)";
        case 0x01077296: return "[CI+] VS2019 v16.8.2 build 29334 (*)";
        case 0x01087296: return "[LTC] VS2019 v16.8.2 build 29334 (*)";
        case 0x01097296: return "[LT+] VS2019 v16.8.2 build 29334 (*)";
        case 0x010a7296: return "[LTM] VS2019 v16.8.2 build 29334 (*)";
        case 0x010b7296: return "[PGO] VS2019 v16.8.2 build 29334 (*)";
        case 0x010c7296: return "[PG+] VS2019 v16.8.2 build 29334 (*)";
        case 0x010d7296: return "[POC] VS2019 v16.8.2 build 29334 (*)";
        case 0x010e7296: return "[PO+] VS2019 v16.8.2 build 29334 (*)";

        // MSVS2019 v16.8.0
        // from https://walbourn.github.io/vs-2019-update-8/
        case 0x01047295: return "[ C ] VS2019 v16.8.0 build 29333 (*)";
        case 0x01037295: return "[ASM] VS2019 v16.8.0 build 29333 (*)";
        case 0x01057295: return "[C++] VS2019 v16.8.0 build 29333 (*)";
        case 0x00ff7295: return "[RES] VS2019 v16.8.0 build 29333 (*)";
        case 0x01027295: return "[LNK] VS2019 v16.8.0 build 29333 (*)";
        case 0x01007295: return "[EXP] VS2019 v16.8.0 build 29333 (*)";
        case 0x01017295: return "[IMP] VS2019 v16.8.0 build 29333 (*)";
        case 0x01067295: return "[CIL] VS2019 v16.8.0 build 29333 (*)";
        case 0x01077295: return "[CI+] VS2019 v16.8.0 build 29333 (*)";
        case 0x01087295: return "[LTC] VS2019 v16.8.0 build 29333 (*)";
        case 0x01097295: return "[LT+] VS2019 v16.8.0 build 29333 (*)";
        case 0x010a7295: return "[LTM] VS2019 v16.8.0 build 29333 (*)";
        case 0x010b7295: return "[PGO] VS2019 v16.8.0 build 29333 (*)";
        case 0x010c7295: return "[PG+] VS2019 v16.8.0 build 29333 (*)";
        case 0x010d7295: return "[POC] VS2019 v16.8.0 build 29333 (*)";
        case 0x010e7295: return "[PO+] VS2019 v16.8.0 build 29333 (*)";

        // MSVS2019 v16.7.5
        case 0x010471b8: return "[ C ] VS2019 v16.7.5 build 29112";
        case 0x010371b8: return "[ASM] VS2019 v16.7.5 build 29112";
        case 0x010571b8: return "[C++] VS2019 v16.7.5 build 29112";
        case 0x00ff71b8: return "[RES] VS2019 v16.7.5 build 29112";
        case 0x010271b8: return "[LNK] VS2019 v16.7.5 build 29112";
        case 0x010071b8: return "[EXP] VS2019 v16.7.5 build 29112";
        case 0x010171b8: return "[IMP] VS2019 v16.7.5 build 29112";
        case 0x010671b8: return "[CIL] VS2019 v16.7.5 build 29112 (*)";
        case 0x010771b8: return "[CI+] VS2019 v16.7.5 build 29112 (*)";
        case 0x010871b8: return "[LTC] VS2019 v16.7.5 build 29112 (*)";
        case 0x010971b8: return "[LT+] VS2019 v16.7.5 build 29112 (*)";
        case 0x010a71b8: return "[LTM] VS2019 v16.7.5 build 29112 (*)";
        case 0x010b71b8: return "[PGO] VS2019 v16.7.5 build 29112 (*)";
        case 0x010c71b8: return "[PG+] VS2019 v16.7.5 build 29112 (*)";
        case 0x010d71b8: return "[POC] VS2019 v16.7.5 build 29112 (*)";
        case 0x010e71b8: return "[PO+] VS2019 v16.7.5 build 29112 (*)";

        // MSVS2019 v16.7.1 .. 16.7.4
        case 0x010471b7: return "[ C ] VS2019 v16.7.1 build 29111";
        case 0x010371b7: return "[ASM] VS2019 v16.7.1 build 29111";
        case 0x010571b7: return "[C++] VS2019 v16.7.1 build 29111";
        case 0x00ff71b7: return "[RES] VS2019 v16.7.1 build 29111";
        case 0x010271b7: return "[LNK] VS2019 v16.7.1 build 29111";
        case 0x010071b7: return "[EXP] VS2019 v16.7.1 build 29111";
        case 0x010171b7: return "[IMP] VS2019 v16.7.1 build 29111";
        case 0x010671b7: return "[CIL] VS2019 v16.7.1 build 29111 (*)";
        case 0x010771b7: return "[CI+] VS2019 v16.7.1 build 29111 (*)";
        case 0x010871b7: return "[LTC] VS2019 v16.7.1 build 29111 (*)";
        case 0x010971b7: return "[LT+] VS2019 v16.7.1 build 29111 (*)";
        case 0x010a71b7: return "[LTM] VS2019 v16.7.1 build 29111 (*)";
        case 0x010b71b7: return "[PGO] VS2019 v16.7.1 build 29111 (*)";
        case 0x010c71b7: return "[PG+] VS2019 v16.7.1 build 29111 (*)";
        case 0x010d71b7: return "[POC] VS2019 v16.7.1 build 29111 (*)";
        case 0x010e71b7: return "[PO+] VS2019 v16.7.1 build 29111 (*)";

        // MSVS2019 v16.7.0
        case 0x010471b6: return "[ C ] VS2019 v16.7.0 build 29110";
        case 0x010371b6: return "[ASM] VS2019 v16.7.0 build 29110";
        case 0x010571b6: return "[C++] VS2019 v16.7.0 build 29110";
        case 0x00ff71b6: return "[RES] VS2019 v16.7.0 build 29110";
        case 0x010271b6: return "[LNK] VS2019 v16.7.0 build 29110";
        case 0x010071b6: return "[EXP] VS2019 v16.7.0 build 29110";
        case 0x010171b6: return "[IMP] VS2019 v16.7.0 build 29110";
        case 0x010671b6: return "[CIL] VS2019 v16.7.0 build 29110 (*)";
        case 0x010771b6: return "[CI+] VS2019 v16.7.0 build 29110 (*)";
        case 0x010871b6: return "[LTC] VS2019 v16.7.0 build 29110 (*)";
        case 0x010971b6: return "[LT+] VS2019 v16.7.0 build 29110 (*)";
        case 0x010a71b6: return "[LTM] VS2019 v16.7.0 build 29110 (*)";
        case 0x010b71b6: return "[PGO] VS2019 v16.7.0 build 29110 (*)";
        case 0x010c71b6: return "[PG+] VS2019 v16.7.0 build 29110 (*)";
        case 0x010d71b6: return "[POC] VS2019 v16.7.0 build 29110 (*)";
        case 0x010e71b6: return "[PO+] VS2019 v16.7.0 build 29110 (*)";

        // MSVS2019 v16.6.2 ... 16.6.5
        case 0x01047086: return "[ C ] VS2019 v16.6.2 build 28806";
        case 0x01037086: return "[ASM] VS2019 v16.6.2 build 28806";
        case 0x01057086: return "[C++] VS2019 v16.6.2 build 28806";
        case 0x00ff7086: return "[RES] VS2019 v16.6.2 build 28806";
        case 0x01027086: return "[LNK] VS2019 v16.6.2 build 28806";
        case 0x01007086: return "[EXP] VS2019 v16.6.2 build 28806";
        case 0x01017086: return "[IMP] VS2019 v16.6.2 build 28806";
        case 0x01067086: return "[CIL] VS2019 v16.6.2 build 28806 (*)";
        case 0x01077086: return "[CI+] VS2019 v16.6.2 build 28806 (*)";
        case 0x01087086: return "[LTC] VS2019 v16.6.2 build 28806 (*)";
        case 0x01097086: return "[LT+] VS2019 v16.6.2 build 28806 (*)";
        case 0x010a7086: return "[LTM] VS2019 v16.6.2 build 28806 (*)";
        case 0x010b7086: return "[PGO] VS2019 v16.6.2 build 28806 (*)";
        case 0x010c7086: return "[PG+] VS2019 v16.6.2 build 28806 (*)";
        case 0x010d7086: return "[POC] VS2019 v16.6.2 build 28806 (*)";
        case 0x010e7086: return "[PO+] VS2019 v16.6.2 build 28806 (*)";

        // MSVS2019 v16.6.0
        case 0x01047085: return "[ C ] VS2019 v16.6.0 build 28805";
        case 0x01037085: return "[ASM] VS2019 v16.6.0 build 28805";
        case 0x01057085: return "[C++] VS2019 v16.6.0 build 28805";
        case 0x00ff7085: return "[RES] VS2019 v16.6.0 build 28805";
        case 0x01027085: return "[LNK] VS2019 v16.6.0 build 28805";
        case 0x01007085: return "[EXP] VS2019 v16.6.0 build 28805";
        case 0x01017085: return "[IMP] VS2019 v16.6.0 build 28805";
        case 0x01067085: return "[CIL] VS2019 v16.6.0 build 28805 (*)";
        case 0x01077085: return "[CI+] VS2019 v16.6.0 build 28805 (*)";
        case 0x01087085: return "[LTC] VS2019 v16.6.0 build 28805 (*)";
        case 0x01097085: return "[LT+] VS2019 v16.6.0 build 28805 (*)";
        case 0x010a7085: return "[LTM] VS2019 v16.6.0 build 28805 (*)";
        case 0x010b7085: return "[PGO] VS2019 v16.6.0 build 28805 (*)";
        case 0x010c7085: return "[PG+] VS2019 v16.6.0 build 28805 (*)";
        case 0x010d7085: return "[POC] VS2019 v16.6.0 build 28805 (*)";
        case 0x010e7085: return "[PO+] VS2019 v16.6.0 build 28805 (*)";

        // MSVS2019 v16.5.5 (also 16.5.4)
        case 0x01046fc6: return "[ C ] VS2019 v16.5.5 build 28614";
        case 0x01036fc6: return "[ASM] VS2019 v16.5.5 build 28614";
        case 0x01056fc6: return "[C++] VS2019 v16.5.5 build 28614";
        case 0x00ff6fc6: return "[RES] VS2019 v16.5.5 build 28614";
        case 0x01026fc6: return "[LNK] VS2019 v16.5.5 build 28614";
        case 0x01006fc6: return "[EXP] VS2019 v16.5.5 build 28614";
        case 0x01016fc6: return "[IMP] VS2019 v16.5.5 build 28614";
        case 0x01066fc6: return "[CIL] VS2019 v16.5.5 build 28614 (*)";
        case 0x01076fc6: return "[CI+] VS2019 v16.5.5 build 28614 (*)";
        case 0x01086fc6: return "[LTC] VS2019 v16.5.5 build 28614 (*)";
        case 0x01096fc6: return "[LT+] VS2019 v16.5.5 build 28614 (*)";
        case 0x010a6fc6: return "[LTM] VS2019 v16.5.5 build 28614 (*)";
        case 0x010b6fc6: return "[PGO] VS2019 v16.5.5 build 28614 (*)";
        case 0x010c6fc6: return "[PG+] VS2019 v16.5.5 build 28614 (*)";
        case 0x010d6fc6: return "[POC] VS2019 v16.5.5 build 28614 (*)";
        case 0x010e6fc6: return "[PO+] VS2019 v16.5.5 build 28614 (*)";

        // Visual Studio 2019 version 16.5.2 (values are interpolated)
        // source: https://walbourn.github.io/vs-2019-update-5/
        case 0x01046fc4: return "[ C ] VS2019 v16.5.2 build 28612 (*)";
        case 0x01036fc4: return "[ASM] VS2019 v16.5.2 build 28612 (*)";
        case 0x01056fc4: return "[C++] VS2019 v16.5.2 build 28612 (*)";
        case 0x00ff6fc4: return "[RES] VS2019 v16.5.2 build 28612 (*)";
        case 0x01026fc4: return "[LNK] VS2019 v16.5.2 build 28612 (*)";
        case 0x01016fc4: return "[IMP] VS2019 v16.5.2 build 28612 (*)";
        case 0x01006fc4: return "[EXP] VS2019 v16.5.2 build 28612 (*)";
        case 0x01066fc4: return "[CIL] VS2019 v16.5.2 build 28612 (*)";
        case 0x01076fc4: return "[CI+] VS2019 v16.5.2 build 28612 (*)";
        case 0x01086fc4: return "[LTC] VS2019 v16.5.2 build 28612 (*)";
        case 0x01096fc4: return "[LT+] VS2019 v16.5.2 build 28612 (*)";
        case 0x010a6fc4: return "[LTM] VS2019 v16.5.2 build 28612 (*)";
        case 0x010b6fc4: return "[PGO] VS2019 v16.5.2 build 28612 (*)";
        case 0x010c6fc4: return "[PG+] VS2019 v16.5.2 build 28612 (*)";
        case 0x010d6fc4: return "[POC] VS2019 v16.5.2 build 28612 (*)";
        case 0x010e6fc4: return "[PO+] VS2019 v16.5.2 build 28612 (*)";

        // Visual Studio 2019 version 16.5.1 (values are interpolated)
        case 0x01046fc3: return "[ C ] VS2019 v16.5.1 build 28611 (*)";
        case 0x01036fc3: return "[ASM] VS2019 v16.5.1 build 28611 (*)";
        case 0x01056fc3: return "[C++] VS2019 v16.5.1 build 28611 (*)";
        case 0x00ff6fc3: return "[RES] VS2019 v16.5.1 build 28611 (*)";
        case 0x01026fc3: return "[LNK] VS2019 v16.5.1 build 28611 (*)";
        case 0x01016fc3: return "[IMP] VS2019 v16.5.1 build 28611 (*)";
        case 0x01006fc3: return "[EXP] VS2019 v16.5.1 build 28611 (*)";
        case 0x01066fc3: return "[CIL] VS2019 v16.5.1 build 28611 (*)";
        case 0x01076fc3: return "[CI+] VS2019 v16.5.1 build 28611 (*)";
        case 0x01086fc3: return "[LTC] VS2019 v16.5.1 build 28611 (*)";
        case 0x01096fc3: return "[LT+] VS2019 v16.5.1 build 28611 (*)";
        case 0x010a6fc3: return "[LTM] VS2019 v16.5.1 build 28611 (*)";
        case 0x010b6fc3: return "[PGO] VS2019 v16.5.1 build 28611 (*)";
        case 0x010c6fc3: return "[PG+] VS2019 v16.5.1 build 28611 (*)";
        case 0x010d6fc3: return "[POC] VS2019 v16.5.1 build 28611 (*)";
        case 0x010e6fc3: return "[PO+] VS2019 v16.5.1 build 28611 (*)";

        // Visual Studio 2019 version 16.5.0 (values are interpolated)
        // source: https://walbourn.github.io/vs-2019-update-5/
        case 0x01046fc2: return "[ C ] VS2019 v16.5.0 build 28610 (*)";
        case 0x01036fc2: return "[ASM] VS2019 v16.5.0 build 28610 (*)";
        case 0x01056fc2: return "[C++] VS2019 v16.5.0 build 28610 (*)";
        case 0x00ff6fc2: return "[RES] VS2019 v16.5.0 build 28610 (*)";
        case 0x01026fc2: return "[LNK] VS2019 v16.5.0 build 28610 (*)";
        case 0x01016fc2: return "[IMP] VS2019 v16.5.0 build 28610 (*)";
        case 0x01006fc2: return "[EXP] VS2019 v16.5.0 build 28610 (*)";
        case 0x01066fc2: return "[CIL] VS2019 v16.5.0 build 28610 (*)";
        case 0x01076fc2: return "[CI+] VS2019 v16.5.0 build 28610 (*)";
        case 0x01086fc2: return "[LTC] VS2019 v16.5.0 build 28610 (*)";
        case 0x01096fc2: return "[LT+] VS2019 v16.5.0 build 28610 (*)";
        case 0x010a6fc2: return "[LTM] VS2019 v16.5.0 build 28610 (*)";
        case 0x010b6fc2: return "[PGO] VS2019 v16.5.0 build 28610 (*)";
        case 0x010c6fc2: return "[PG+] VS2019 v16.5.0 build 28610 (*)";
        case 0x010d6fc2: return "[POC] VS2019 v16.5.0 build 28610 (*)";
        case 0x010e6fc2: return "[PO+] VS2019 v16.5.0 build 28610 (*)";

        // MSVS2019 v16.4.6 (values are interpolated)
        // source: https://walbourn.github.io/vs-2019-update-4/
        case 0x01046e9f: return "[ C ] VS2019 v16.4.6 build 28319 (*)";
        case 0x01036e9f: return "[ASM] VS2019 v16.4.6 build 28319 (*)";
        case 0x01056e9f: return "[C++] VS2019 v16.4.6 build 28319 (*)";
        case 0x00ff6e9f: return "[RES] VS2019 v16.4.6 build 28319 (*)";
        case 0x01026e9f: return "[LNK] VS2019 v16.4.6 build 28319 (*)";
        case 0x01006e9f: return "[EXP] VS2019 v16.4.6 build 28319 (*)";
        case 0x01016e9f: return "[IMP] VS2019 v16.4.6 build 28319 (*)";
        case 0x01066e9f: return "[CIL] VS2019 v16.4.6 build 28319 (*)";
        case 0x01076e9f: return "[CI+] VS2019 v16.4.6 build 28319 (*)";
        case 0x01086e9f: return "[LTC] VS2019 v16.4.6 build 28319 (*)";
        case 0x01096e9f: return "[LT+] VS2019 v16.4.6 build 28319 (*)";
        case 0x010a6e9f: return "[LTM] VS2019 v16.4.6 build 28319 (*)";
        case 0x010b6e9f: return "[PGO] VS2019 v16.4.6 build 28319 (*)";
        case 0x010c6e9f: return "[PG+] VS2019 v16.4.6 build 28319 (*)";
        case 0x010d6e9f: return "[POC] VS2019 v16.4.6 build 28319 (*)";
        case 0x010e6e9f: return "[PO+] VS2019 v16.4.6 build 28319 (*)";

        // MSVS2019 v16.4.4 (values are interpolated)
        // source: https://walbourn.github.io/vs-2019-update-4/
        case 0x01046e9c: return "[ C ] VS2019 v16.4.4 build 28316 (*)";
        case 0x01036e9c: return "[ASM] VS2019 v16.4.4 build 28316 (*)";
        case 0x01056e9c: return "[C++] VS2019 v16.4.4 build 28316 (*)";
        case 0x00ff6e9c: return "[RES] VS2019 v16.4.4 build 28316 (*)";
        case 0x01026e9c: return "[LNK] VS2019 v16.4.4 build 28316 (*)";
        case 0x01006e9c: return "[EXP] VS2019 v16.4.4 build 28316 (*)";
        case 0x01016e9c: return "[IMP] VS2019 v16.4.4 build 28316 (*)";
        case 0x01066e9c: return "[CIL] VS2019 v16.4.4 build 28316 (*)";
        case 0x01076e9c: return "[CI+] VS2019 v16.4.4 build 28316 (*)";
        case 0x01086e9c: return "[LTC] VS2019 v16.4.4 build 28316 (*)";
        case 0x01096e9c: return "[LT+] VS2019 v16.4.4 build 28316 (*)";
        case 0x010a6e9c: return "[LTM] VS2019 v16.4.4 build 28316 (*)";
        case 0x010b6e9c: return "[PGO] VS2019 v16.4.4 build 28316 (*)";
        case 0x010c6e9c: return "[PG+] VS2019 v16.4.4 build 28316 (*)";
        case 0x010d6e9c: return "[POC] VS2019 v16.4.4 build 28316 (*)";
        case 0x010e6e9c: return "[PO+] VS2019 v16.4.4 build 28316 (*)";

        // MSVS2019 v16.4.3
        case 0x01046e9b: return "[ C ] VS2019 v16.4.3 build 28315";
        case 0x01036e9b: return "[ASM] VS2019 v16.4.3 build 28315";
        case 0x01056e9b: return "[C++] VS2019 v16.4.3 build 28315";
        case 0x00ff6e9b: return "[RES] VS2019 v16.4.3 build 28315";
        case 0x01026e9b: return "[LNK] VS2019 v16.4.3 build 28315";
        case 0x01006e9b: return "[EXP] VS2019 v16.4.3 build 28315";
        case 0x01016e9b: return "[IMP] VS2019 v16.4.3 build 28315";
        case 0x01066e9b: return "[CIL] VS2019 v16.4.3 build 28315 (*)";
        case 0x01076e9b: return "[CI+] VS2019 v16.4.3 build 28315 (*)";
        case 0x01086e9b: return "[LTC] VS2019 v16.4.3 build 28315 (*)";
        case 0x01096e9b: return "[LT+] VS2019 v16.4.3 build 28315 (*)";
        case 0x010a6e9b: return "[LTM] VS2019 v16.4.3 build 28315 (*)";
        case 0x010b6e9b: return "[PGO] VS2019 v16.4.3 build 28315 (*)";
        case 0x010c6e9b: return "[PG+] VS2019 v16.4.3 build 28315 (*)";
        case 0x010d6e9b: return "[POC] VS2019 v16.4.3 build 28315 (*)";
        case 0x010e6e9b: return "[PO+] VS2019 v16.4.3 build 28315 (*)";

        // Visual Studio 2019 version 16.4.0 (values are interpolated)
        case 0x01046e9a: return "[ C ] VS2019 v16.4.0 build 28314 (*)";
        case 0x01036e9a: return "[ASM] VS2019 v16.4.0 build 28314 (*)";
        case 0x01056e9a: return "[C++] VS2019 v16.4.0 build 28314 (*)";
        case 0x00ff6e9a: return "[RES] VS2019 v16.4.0 build 28314 (*)";
        case 0x01026e9a: return "[LNK] VS2019 v16.4.0 build 28314 (*)";
        case 0x01016e9a: return "[IMP] VS2019 v16.4.0 build 28314 (*)";
        case 0x01006e9a: return "[EXP] VS2019 v16.4.0 build 28314 (*)";
        case 0x01066e9a: return "[CIL] VS2019 v16.4.0 build 28314 (*)";
        case 0x01076e9a: return "[CI+] VS2019 v16.4.0 build 28314 (*)";
        case 0x01086e9a: return "[LTC] VS2019 v16.4.0 build 28314 (*)";
        case 0x01096e9a: return "[LT+] VS2019 v16.4.0 build 28314 (*)";
        case 0x010a6e9a: return "[LTM] VS2019 v16.4.0 build 28314 (*)";
        case 0x010b6e9a: return "[PGO] VS2019 v16.4.0 build 28314 (*)";
        case 0x010c6e9a: return "[PG+] VS2019 v16.4.0 build 28314 (*)";
        case 0x010d6e9a: return "[POC] VS2019 v16.4.0 build 28314 (*)";
        case 0x010e6e9a: return "[PO+] VS2019 v16.4.0 build 28314 (*)";

        // Visual Studio 2019 version 16.3.2 (values are interpolated)
        case 0x01046dc9: return "[ C ] VS2019 v16.3.2 build 28105 (*)";
        case 0x01036dc9: return "[ASM] VS2019 v16.3.2 build 28105 (*)";
        case 0x01056dc9: return "[C++] VS2019 v16.3.2 build 28105 (*)";
        case 0x00ff6dc9: return "[RES] VS2019 v16.3.2 build 28105 (*)";
        case 0x01026dc9: return "[LNK] VS2019 v16.3.2 build 28105 (*)";
        case 0x01016dc9: return "[IMP] VS2019 v16.3.2 build 28105 (*)";
        case 0x01006dc9: return "[EXP] VS2019 v16.3.2 build 28105 (*)";
        case 0x01066dc9: return "[CIL] VS2019 v16.3.2 build 28105 (*)";
        case 0x01076dc9: return "[CI+] VS2019 v16.3.2 build 28105 (*)";
        case 0x01086dc9: return "[LTC] VS2019 v16.3.2 build 28105 (*)";
        case 0x01096dc9: return "[LT+] VS2019 v16.3.2 build 28105 (*)";
        case 0x010a6dc9: return "[LTM] VS2019 v16.3.2 build 28105 (*)";
        case 0x010b6dc9: return "[PGO] VS2019 v16.3.2 build 28105 (*)";
        case 0x010c6dc9: return "[PG+] VS2019 v16.3.2 build 28105 (*)";
        case 0x010d6dc9: return "[POC] VS2019 v16.3.2 build 28105 (*)";
        case 0x010e6dc9: return "[PO+] VS2019 v16.3.2 build 28105 (*)";

        // Visual Studio 2019 version 16.2.3 (values are interpolated)
        case 0x01046d01: return "[ C ] VS2019 v16.2.3 build 27905 (*)";
        case 0x01036d01: return "[ASM] VS2019 v16.2.3 build 27905 (*)";
        case 0x01056d01: return "[C++] VS2019 v16.2.3 build 27905 (*)";
        case 0x00ff6d01: return "[RES] VS2019 v16.2.3 build 27905 (*)";
        case 0x01026d01: return "[LNK] VS2019 v16.2.3 build 27905 (*)";
        case 0x01016d01: return "[IMP] VS2019 v16.2.3 build 27905 (*)";
        case 0x01006d01: return "[EXP] VS2019 v16.2.3 build 27905 (*)";
        case 0x01066d01: return "[CIL] VS2019 v16.2.3 build 27905 (*)";
        case 0x01076d01: return "[CI+] VS2019 v16.2.3 build 27905 (*)";
        case 0x01086d01: return "[LTC] VS2019 v16.2.3 build 27905 (*)";
        case 0x01096d01: return "[LT+] VS2019 v16.2.3 build 27905 (*)";
        case 0x010a6d01: return "[LTM] VS2019 v16.2.3 build 27905 (*)";
        case 0x010b6d01: return "[PGO] VS2019 v16.2.3 build 27905 (*)";
        case 0x010c6d01: return "[PG+] VS2019 v16.2.3 build 27905 (*)";
        case 0x010d6d01: return "[POC] VS2019 v16.2.3 build 27905 (*)";
        case 0x010e6d01: return "[PO+] VS2019 v16.2.3 build 27905 (*)";

        // Visual Studio 2019 version 16.1.2 (values are interpolated)
        case 0x01046c36: return "[ C ] VS2019 v16.1.2 build 27702 (*)";
        case 0x01036c36: return "[ASM] VS2019 v16.1.2 build 27702 (*)";
        case 0x01056c36: return "[C++] VS2019 v16.1.2 build 27702 (*)";
        case 0x00ff6c36: return "[RES] VS2019 v16.1.2 build 27702 (*)";
        case 0x01026c36: return "[LNK] VS2019 v16.1.2 build 27702 (*)";
        case 0x01016c36: return "[IMP] VS2019 v16.1.2 build 27702 (*)";
        case 0x01006c36: return "[EXP] VS2019 v16.1.2 build 27702 (*)";
        case 0x01066c36: return "[CIL] VS2019 v16.1.2 build 27702 (*)";
        case 0x01076c36: return "[CI+] VS2019 v16.1.2 build 27702 (*)";
        case 0x01086c36: return "[LTC] VS2019 v16.1.2 build 27702 (*)";
        case 0x01096c36: return "[LT+] VS2019 v16.1.2 build 27702 (*)";
        case 0x010a6c36: return "[LTM] VS2019 v16.1.2 build 27702 (*)";
        case 0x010b6c36: return "[PGO] VS2019 v16.1.2 build 27702 (*)";
        case 0x010c6c36: return "[PG+] VS2019 v16.1.2 build 27702 (*)";
        case 0x010d6c36: return "[POC] VS2019 v16.1.2 build 27702 (*)";
        case 0x010e6c36: return "[PO+] VS2019 v16.1.2 build 27702 (*)";

        // MSVS2019 v16.0.0
        case 0x01046b74: return "[ C ] VS2019 v16.0.0 build 27508";
        case 0x01036b74: return "[ASM] VS2019 v16.0.0 build 27508";
        case 0x01056b74: return "[C++] VS2019 v16.0.0 build 27508";
        case 0x00ff6b74: return "[RES] VS2019 v16.0.0 build 27508";
        case 0x01026b74: return "[LNK] VS2019 v16.0.0 build 27508";
        case 0x01006b74: return "[EXP] VS2019 v16.0.0 build 27508";
        case 0x01016b74: return "[IMP] VS2019 v16.0.0 build 27508";
        case 0x01066b74: return "[CIL] VS2019 v16.0.0 build 27508 (*)";
        case 0x01076b74: return "[CI+] VS2019 v16.0.0 build 27508 (*)";
        case 0x01086b74: return "[LTC] VS2019 v16.0.0 build 27508 (*)";
        case 0x01096b74: return "[LT+] VS2019 v16.0.0 build 27508 (*)";
        case 0x010a6b74: return "[LTM] VS2019 v16.0.0 build 27508 (*)";
        case 0x010b6b74: return "[PGO] VS2019 v16.0.0 build 27508 (*)";
        case 0x010c6b74: return "[PG+] VS2019 v16.0.0 build 27508 (*)";
        case 0x010d6b74: return "[POC] VS2019 v16.0.0 build 27508 (*)";
        case 0x010e6b74: return "[PO+] VS2019 v16.0.0 build 27508 (*)";

        // Visual Studio 2017 version 15.9.11 (values are interpolated)
        case 0x01046996: return "[ C ] VS2017 v15.9.11 build 27030 (*)";
        case 0x01036996: return "[ASM] VS2017 v15.9.11 build 27030 (*)";
        case 0x01056996: return "[C++] VS2017 v15.9.11 build 27030 (*)";
        case 0x00ff6996: return "[RES] VS2017 v15.9.11 build 27030 (*)";
        case 0x01026996: return "[LNK] VS2017 v15.9.11 build 27030 (*)";
        case 0x01016996: return "[IMP] VS2017 v15.9.11 build 27030 (*)";
        case 0x01006996: return "[EXP] VS2017 v15.9.11 build 27030 (*)";
        case 0x01066996: return "[CIL] VS2017 v15.9.11 build 27030 (*)";
        case 0x01076996: return "[CI+] VS2017 v15.9.11 build 27030 (*)";
        case 0x01086996: return "[LTC] VS2017 v15.9.11 build 27030 (*)";
        case 0x01096996: return "[LT+] VS2017 v15.9.11 build 27030 (*)";
        case 0x010a6996: return "[LTM] VS2017 v15.9.11 build 27030 (*)";
        case 0x010b6996: return "[PGO] VS2017 v15.9.11 build 27030 (*)";
        case 0x010c6996: return "[PG+] VS2017 v15.9.11 build 27030 (*)";
        case 0x010d6996: return "[POC] VS2017 v15.9.11 build 27030 (*)";
        case 0x010e6996: return "[PO+] VS2017 v15.9.11 build 27030 (*)";

        // Visual Studio 2017 version 15.9.7 (values are interpolated)
        case 0x01046993: return "[ C ] VS2017 v15.9.7 build 27027 (*)";
        case 0x01036993: return "[ASM] VS2017 v15.9.7 build 27027 (*)";
        case 0x01056993: return "[C++] VS2017 v15.9.7 build 27027 (*)";
        case 0x00ff6993: return "[RES] VS2017 v15.9.7 build 27027 (*)";
        case 0x01026993: return "[LNK] VS2017 v15.9.7 build 27027 (*)";
        case 0x01016993: return "[IMP] VS2017 v15.9.7 build 27027 (*)";
        case 0x01006993: return "[EXP] VS2017 v15.9.7 build 27027 (*)";
        case 0x01066993: return "[CIL] VS2017 v15.9.7 build 27027 (*)";
        case 0x01076993: return "[CI+] VS2017 v15.9.7 build 27027 (*)";
        case 0x01086993: return "[LTC] VS2017 v15.9.7 build 27027 (*)";
        case 0x01096993: return "[LT+] VS2017 v15.9.7 build 27027 (*)";
        case 0x010a6993: return "[LTM] VS2017 v15.9.7 build 27027 (*)";
        case 0x010b6993: return "[PGO] VS2017 v15.9.7 build 27027 (*)";
        case 0x010c6993: return "[PG+] VS2017 v15.9.7 build 27027 (*)";
        case 0x010d6993: return "[POC] VS2017 v15.9.7 build 27027 (*)";
        case 0x010e6993: return "[PO+] VS2017 v15.9.7 build 27027 (*)";

        // Visual Studio 2017 version 15.9.5 (values are interpolated)
        case 0x01046992: return "[ C ] VS2017 v15.9.5 build 27026 (*)";
        case 0x01036992: return "[ASM] VS2017 v15.9.5 build 27026 (*)";
        case 0x01056992: return "[C++] VS2017 v15.9.5 build 27026 (*)";
        case 0x00ff6992: return "[RES] VS2017 v15.9.5 build 27026 (*)";
        case 0x01026992: return "[LNK] VS2017 v15.9.5 build 27026 (*)";
        case 0x01016992: return "[IMP] VS2017 v15.9.5 build 27026 (*)";
        case 0x01006992: return "[EXP] VS2017 v15.9.5 build 27026 (*)";
        case 0x01066992: return "[CIL] VS2017 v15.9.5 build 27026 (*)";
        case 0x01076992: return "[CI+] VS2017 v15.9.5 build 27026 (*)";
        case 0x01086992: return "[LTC] VS2017 v15.9.5 build 27026 (*)";
        case 0x01096992: return "[LT+] VS2017 v15.9.5 build 27026 (*)";
        case 0x010a6992: return "[LTM] VS2017 v15.9.5 build 27026 (*)";
        case 0x010b6992: return "[PGO] VS2017 v15.9.5 build 27026 (*)";
        case 0x010c6992: return "[PG+] VS2017 v15.9.5 build 27026 (*)";
        case 0x010d6992: return "[POC] VS2017 v15.9.5 build 27026 (*)";
        case 0x010e6992: return "[PO+] VS2017 v15.9.5 build 27026 (*)";

        // Visual Studio 2017 version 15.9.4 (values are interpolated)
        case 0x01046991: return "[ C ] VS2017 v15.9.4 build 27025 (*)";
        case 0x01036991: return "[ASM] VS2017 v15.9.4 build 27025 (*)";
        case 0x01056991: return "[C++] VS2017 v15.9.4 build 27025 (*)";
        case 0x00ff6991: return "[RES] VS2017 v15.9.4 build 27025 (*)";
        case 0x01026991: return "[LNK] VS2017 v15.9.4 build 27025 (*)";
        case 0x01016991: return "[IMP] VS2017 v15.9.4 build 27025 (*)";
        case 0x01006991: return "[EXP] VS2017 v15.9.4 build 27025 (*)";
        case 0x01066991: return "[CIL] VS2017 v15.9.4 build 27025 (*)";
        case 0x01076991: return "[CI+] VS2017 v15.9.4 build 27025 (*)";
        case 0x01086991: return "[LTC] VS2017 v15.9.4 build 27025 (*)";
        case 0x01096991: return "[LT+] VS2017 v15.9.4 build 27025 (*)";
        case 0x010a6991: return "[LTM] VS2017 v15.9.4 build 27025 (*)";
        case 0x010b6991: return "[PGO] VS2017 v15.9.4 build 27025 (*)";
        case 0x010c6991: return "[PG+] VS2017 v15.9.4 build 27025 (*)";
        case 0x010d6991: return "[POC] VS2017 v15.9.4 build 27025 (*)";
        case 0x010e6991: return "[PO+] VS2017 v15.9.4 build 27025 (*)";

        // Visual Studio 2017 version 15.9.1 (values are interpolated)
        case 0x0104698f: return "[ C ] VS2017 v15.9.1 build 27023 (*)";
        case 0x0103698f: return "[ASM] VS2017 v15.9.1 build 27023 (*)";
        case 0x0105698f: return "[C++] VS2017 v15.9.1 build 27023 (*)";
        case 0x00ff698f: return "[RES] VS2017 v15.9.1 build 27023 (*)";
        case 0x0102698f: return "[LNK] VS2017 v15.9.1 build 27023 (*)";
        case 0x0101698f: return "[IMP] VS2017 v15.9.1 build 27023 (*)";
        case 0x0100698f: return "[EXP] VS2017 v15.9.1 build 27023 (*)";
        case 0x0106698f: return "[CIL] VS2017 v15.9.1 build 27023 (*)";
        case 0x0107698f: return "[CI+] VS2017 v15.9.1 build 27023 (*)";
        case 0x0108698f: return "[LTC] VS2017 v15.9.1 build 27023 (*)";
        case 0x0109698f: return "[LT+] VS2017 v15.9.1 build 27023 (*)";
        case 0x010a698f: return "[LTM] VS2017 v15.9.1 build 27023 (*)";
        case 0x010b698f: return "[PGO] VS2017 v15.9.1 build 27023 (*)";
        case 0x010c698f: return "[PG+] VS2017 v15.9.1 build 27023 (*)";
        case 0x010d698f: return "[POC] VS2017 v15.9.1 build 27023 (*)";
        case 0x010e698f: return "[PO+] VS2017 v15.9.1 build 27023 (*)";

        // Visual Studio 2017 version 15.8.5 (values are interpolated)
        // source: https://walbourn.github.io/vs-2017-15-8-update/
        case 0x0104686c: return "[ C ] VS2017 v15.8.5 build 26732 (*)";
        case 0x0103686c: return "[ASM] VS2017 v15.8.5 build 26732 (*)";
        case 0x0105686c: return "[C++] VS2017 v15.8.5 build 26732 (*)";
        case 0x00ff686c: return "[RES] VS2017 v15.8.5 build 26732 (*)";
        case 0x0102686c: return "[LNK] VS2017 v15.8.5 build 26732 (*)";
        case 0x0101686c: return "[IMP] VS2017 v15.8.5 build 26732 (*)";
        case 0x0100686c: return "[EXP] VS2017 v15.8.5 build 26732 (*)";
        case 0x0106686c: return "[CIL] VS2017 v15.8.5 build 26732 (*)";
        case 0x0107686c: return "[CI+] VS2017 v15.8.5 build 26732 (*)";
        case 0x0108686c: return "[LTC] VS2017 v15.8.5 build 26732 (*)";
        case 0x0109686c: return "[LT+] VS2017 v15.8.5 build 26732 (*)";
        case 0x010a686c: return "[LTM] VS2017 v15.8.5 build 26732 (*)";
        case 0x010b686c: return "[PGO] VS2017 v15.8.5 build 26732 (*)";
        case 0x010c686c: return "[PG+] VS2017 v15.8.5 build 26732 (*)";
        case 0x010d686c: return "[POC] VS2017 v15.8.5 build 26732 (*)";
        case 0x010e686c: return "[PO+] VS2017 v15.8.5 build 26732 (*)";

        // Visual Studio 2017 version 15.8.9 (sic!) (values are interpolated)
        // source: https://walbourn.github.io/vs-2017-15-8-update/
        case 0x0104686a: return "[ C ] VS2017 v15.8.9? build 26730 (*)";
        case 0x0103686a: return "[ASM] VS2017 v15.8.9? build 26730 (*)";
        case 0x0105686a: return "[C++] VS2017 v15.8.9? build 26730 (*)";
        case 0x00ff686a: return "[RES] VS2017 v15.8.9? build 26730 (*)";
        case 0x0102686a: return "[LNK] VS2017 v15.8.9? build 26730 (*)";
        case 0x0101686a: return "[IMP] VS2017 v15.8.9? build 26730 (*)";
        case 0x0100686a: return "[EXP] VS2017 v15.8.9? build 26730 (*)";
        case 0x0106686a: return "[CIL] VS2017 v15.8.9? build 26730 (*)";
        case 0x0107686a: return "[CI+] VS2017 v15.8.9? build 26730 (*)";
        case 0x0108686a: return "[LTC] VS2017 v15.8.9? build 26730 (*)";
        case 0x0109686a: return "[LT+] VS2017 v15.8.9? build 26730 (*)";
        case 0x010a686a: return "[LTM] VS2017 v15.8.9? build 26730 (*)";
        case 0x010b686a: return "[PGO] VS2017 v15.8.9? build 26730 (*)";
        case 0x010c686a: return "[PG+] VS2017 v15.8.9? build 26730 (*)";
        case 0x010d686a: return "[POC] VS2017 v15.8.9? build 26730 (*)";
        case 0x010e686a: return "[PO+] VS2017 v15.8.9? build 26730 (*)";

        // Visual Studio 2017 version 15.8.4 (values are interpolated)
        // source: https://walbourn.github.io/vs-2017-15-8-update/
        case 0x01046869: return "[ C ] VS2017 v15.8.4 build 26729 (*)";
        case 0x01036869: return "[ASM] VS2017 v15.8.4 build 26729 (*)";
        case 0x01056869: return "[C++] VS2017 v15.8.4 build 26729 (*)";
        case 0x00ff6869: return "[RES] VS2017 v15.8.4 build 26729 (*)";
        case 0x01026869: return "[LNK] VS2017 v15.8.4 build 26729 (*)";
        case 0x01016869: return "[IMP] VS2017 v15.8.4 build 26729 (*)";
        case 0x01006869: return "[EXP] VS2017 v15.8.4 build 26729 (*)";
        case 0x01066869: return "[CIL] VS2017 v15.8.4 build 26729 (*)";
        case 0x01076869: return "[CI+] VS2017 v15.8.4 build 26729 (*)";
        case 0x01086869: return "[LTC] VS2017 v15.8.4 build 26729 (*)";
        case 0x01096869: return "[LT+] VS2017 v15.8.4 build 26729 (*)";
        case 0x010a6869: return "[LTM] VS2017 v15.8.4 build 26729 (*)";
        case 0x010b6869: return "[PGO] VS2017 v15.8.4 build 26729 (*)";
        case 0x010c6869: return "[PG+] VS2017 v15.8.4 build 26729 (*)";
        case 0x010d6869: return "[POC] VS2017 v15.8.4 build 26729 (*)";
        case 0x010e6869: return "[PO+] VS2017 v15.8.4 build 26729 (*)";

        // Visual Studio 2017 version 15.8.0 (values are interpolated)
        // source: https://walbourn.github.io/vs-2017-15-8-update/
        case 0x01046866: return "[ C ] VS2017 v15.8.0 build 26726 (*)";
        case 0x01036866: return "[ASM] VS2017 v15.8.0 build 26726 (*)";
        case 0x01056866: return "[C++] VS2017 v15.8.0 build 26726 (*)";
        case 0x00ff6866: return "[RES] VS2017 v15.8.0 build 26726 (*)";
        case 0x01026866: return "[LNK] VS2017 v15.8.0 build 26726 (*)";
        case 0x01016866: return "[IMP] VS2017 v15.8.0 build 26726 (*)";
        case 0x01006866: return "[EXP] VS2017 v15.8.0 build 26726 (*)";
        case 0x01066866: return "[CIL] VS2017 v15.8.0 build 26726 (*)";
        case 0x01076866: return "[CI+] VS2017 v15.8.0 build 26726 (*)";
        case 0x01086866: return "[LTC] VS2017 v15.8.0 build 26726 (*)";
        case 0x01096866: return "[LT+] VS2017 v15.8.0 build 26726 (*)";
        case 0x010a6866: return "[LTM] VS2017 v15.8.0 build 26726 (*)";
        case 0x010b6866: return "[PGO] VS2017 v15.8.0 build 26726 (*)";
        case 0x010c6866: return "[PG+] VS2017 v15.8.0 build 26726 (*)";
        case 0x010d6866: return "[POC] VS2017 v15.8.0 build 26726 (*)";
        case 0x010e6866: return "[PO+] VS2017 v15.8.0 build 26726 (*)";

        // Visual Studio 2017 version 15.7.5 (values are interpolated)
        case 0x01046741: return "[ C ] VS2017 v15.7.5 build 26433 (*)";
        case 0x01036741: return "[ASM] VS2017 v15.7.5 build 26433 (*)";
        case 0x01056741: return "[C++] VS2017 v15.7.5 build 26433 (*)";
        case 0x00ff6741: return "[RES] VS2017 v15.7.5 build 26433 (*)";
        case 0x01026741: return "[LNK] VS2017 v15.7.5 build 26433 (*)";
        case 0x01016741: return "[IMP] VS2017 v15.7.5 build 26433 (*)";
        case 0x01006741: return "[EXP] VS2017 v15.7.5 build 26433 (*)";
        case 0x01066741: return "[CIL] VS2017 v15.7.5 build 26433 (*)";
        case 0x01076741: return "[CI+] VS2017 v15.7.5 build 26433 (*)";
        case 0x01086741: return "[LTC] VS2017 v15.7.5 build 26433 (*)";
        case 0x01096741: return "[LT+] VS2017 v15.7.5 build 26433 (*)";
        case 0x010a6741: return "[LTM] VS2017 v15.7.5 build 26433 (*)";
        case 0x010b6741: return "[PGO] VS2017 v15.7.5 build 26433 (*)";
        case 0x010c6741: return "[PG+] VS2017 v15.7.5 build 26433 (*)";
        case 0x010d6741: return "[POC] VS2017 v15.7.5 build 26433 (*)";
        case 0x010e6741: return "[PO+] VS2017 v15.7.5 build 26433 (*)";

        // Visual Studio 2017 version 15.7.4 (values are interpolated)
        // source: https://walbourn.github.io/vs-2017-15-7-update/
        case 0x0104673f: return "[ C ] VS2017 v15.7.4 build 26431 (*)";
        case 0x0103673f: return "[ASM] VS2017 v15.7.4 build 26431 (*)";
        case 0x0105673f: return "[C++] VS2017 v15.7.4 build 26431 (*)";
        case 0x00ff673f: return "[RES] VS2017 v15.7.4 build 26431 (*)";
        case 0x0102673f: return "[LNK] VS2017 v15.7.4 build 26431 (*)";
        case 0x0101673f: return "[IMP] VS2017 v15.7.4 build 26431 (*)";
        case 0x0100673f: return "[EXP] VS2017 v15.7.4 build 26431 (*)";
        case 0x0106673f: return "[CIL] VS2017 v15.7.4 build 26431 (*)";
        case 0x0107673f: return "[CI+] VS2017 v15.7.4 build 26431 (*)";
        case 0x0108673f: return "[LTC] VS2017 v15.7.4 build 26431 (*)";
        case 0x0109673f: return "[LT+] VS2017 v15.7.4 build 26431 (*)";
        case 0x010a673f: return "[LTM] VS2017 v15.7.4 build 26431 (*)";
        case 0x010b673f: return "[PGO] VS2017 v15.7.4 build 26431 (*)";
        case 0x010c673f: return "[PG+] VS2017 v15.7.4 build 26431 (*)";
        case 0x010d673f: return "[POC] VS2017 v15.7.4 build 26431 (*)";
        case 0x010e673f: return "[PO+] VS2017 v15.7.4 build 26431 (*)";

        // Visual Studio 2017 version 15.7.3 (values are interpolated)
        case 0x0104673e: return "[ C ] VS2017 v15.7.3 build 26430 (*)";
        case 0x0103673e: return "[ASM] VS2017 v15.7.3 build 26430 (*)";
        case 0x0105673e: return "[C++] VS2017 v15.7.3 build 26430 (*)";
        case 0x00ff673e: return "[RES] VS2017 v15.7.3 build 26430 (*)";
        case 0x0102673e: return "[LNK] VS2017 v15.7.3 build 26430 (*)";
        case 0x0101673e: return "[IMP] VS2017 v15.7.3 build 26430 (*)";
        case 0x0100673e: return "[EXP] VS2017 v15.7.3 build 26430 (*)";
        case 0x0106673e: return "[CIL] VS2017 v15.7.3 build 26430 (*)";
        case 0x0107673e: return "[CI+] VS2017 v15.7.3 build 26430 (*)";
        case 0x0108673e: return "[LTC] VS2017 v15.7.3 build 26430 (*)";
        case 0x0109673e: return "[LT+] VS2017 v15.7.3 build 26430 (*)";
        case 0x010a673e: return "[LTM] VS2017 v15.7.3 build 26430 (*)";
        case 0x010b673e: return "[PGO] VS2017 v15.7.3 build 26430 (*)";
        case 0x010c673e: return "[PG+] VS2017 v15.7.3 build 26430 (*)";
        case 0x010d673e: return "[POC] VS2017 v15.7.3 build 26430 (*)";
        case 0x010e673e: return "[PO+] VS2017 v15.7.3 build 26430 (*)";

        // Visual Studio 2017 version 15.7.2 (values are interpolated)
        case 0x0104673d: return "[ C ] VS2017 v15.7.2 build 26429 (*)";
        case 0x0103673d: return "[ASM] VS2017 v15.7.2 build 26429 (*)";
        case 0x0105673d: return "[C++] VS2017 v15.7.2 build 26429 (*)";
        case 0x00ff673d: return "[RES] VS2017 v15.7.2 build 26429 (*)";
        case 0x0102673d: return "[LNK] VS2017 v15.7.2 build 26429 (*)";
        case 0x0101673d: return "[IMP] VS2017 v15.7.2 build 26429 (*)";
        case 0x0100673d: return "[EXP] VS2017 v15.7.2 build 26429 (*)";
        case 0x0106673d: return "[CIL] VS2017 v15.7.2 build 26429 (*)";
        case 0x0107673d: return "[CI+] VS2017 v15.7.2 build 26429 (*)";
        case 0x0108673d: return "[LTC] VS2017 v15.7.2 build 26429 (*)";
        case 0x0109673d: return "[LT+] VS2017 v15.7.2 build 26429 (*)";
        case 0x010a673d: return "[LTM] VS2017 v15.7.2 build 26429 (*)";
        case 0x010b673d: return "[PGO] VS2017 v15.7.2 build 26429 (*)";
        case 0x010c673d: return "[PG+] VS2017 v15.7.2 build 26429 (*)";
        case 0x010d673d: return "[POC] VS2017 v15.7.2 build 26429 (*)";
        case 0x010e673d: return "[PO+] VS2017 v15.7.2 build 26429 (*)";

        // Visual Studio 2017 version 15.7.1 (values are interpolated)
        case 0x0104673c: return "[ C ] VS2017 v15.7.1 build 26428 (*)";
        case 0x0103673c: return "[ASM] VS2017 v15.7.1 build 26428 (*)";
        case 0x0105673c: return "[C++] VS2017 v15.7.1 build 26428 (*)";
        case 0x00ff673c: return "[RES] VS2017 v15.7.1 build 26428 (*)";
        case 0x0102673c: return "[LNK] VS2017 v15.7.1 build 26428 (*)";
        case 0x0101673c: return "[IMP] VS2017 v15.7.1 build 26428 (*)";
        case 0x0100673c: return "[EXP] VS2017 v15.7.1 build 26428 (*)";
        case 0x0106673c: return "[CIL] VS2017 v15.7.1 build 26428 (*)";
        case 0x0107673c: return "[CI+] VS2017 v15.7.1 build 26428 (*)";
        case 0x0108673c: return "[LTC] VS2017 v15.7.1 build 26428 (*)";
        case 0x0109673c: return "[LT+] VS2017 v15.7.1 build 26428 (*)";
        case 0x010a673c: return "[LTM] VS2017 v15.7.1 build 26428 (*)";
        case 0x010b673c: return "[PGO] VS2017 v15.7.1 build 26428 (*)";
        case 0x010c673c: return "[PG+] VS2017 v15.7.1 build 26428 (*)";
        case 0x010d673c: return "[POC] VS2017 v15.7.1 build 26428 (*)";
        case 0x010e673c: return "[PO+] VS2017 v15.7.1 build 26428 (*)";

        // Visual Studio 2017 version 15.6.7 (values are interpolated)
        case 0x01046614: return "[ C ] VS2017 v15.6.7 build 26132 (*)";
        case 0x01036614: return "[ASM] VS2017 v15.6.7 build 26132 (*)";
        case 0x01056614: return "[C++] VS2017 v15.6.7 build 26132 (*)";
        case 0x00ff6614: return "[RES] VS2017 v15.6.7 build 26132 (*)";
        case 0x01026614: return "[LNK] VS2017 v15.6.7 build 26132 (*)";
        case 0x01016614: return "[IMP] VS2017 v15.6.7 build 26132 (*)";
        case 0x01006614: return "[EXP] VS2017 v15.6.7 build 26132 (*)";
        case 0x01066614: return "[CIL] VS2017 v15.6.7 build 26132 (*)";
        case 0x01076614: return "[CI+] VS2017 v15.6.7 build 26132 (*)";
        case 0x01086614: return "[LTC] VS2017 v15.6.7 build 26132 (*)";
        case 0x01096614: return "[LT+] VS2017 v15.6.7 build 26132 (*)";
        case 0x010a6614: return "[LTM] VS2017 v15.6.7 build 26132 (*)";
        case 0x010b6614: return "[PGO] VS2017 v15.6.7 build 26132 (*)";
        case 0x010c6614: return "[PG+] VS2017 v15.6.7 build 26132 (*)";
        case 0x010d6614: return "[POC] VS2017 v15.6.7 build 26132 (*)";
        case 0x010e6614: return "[PO+] VS2017 v15.6.7 build 26132 (*)";

        // Visual Studio 2017 version 15.6.6 (values are interpolated)
        case 0x01046613: return "[ C ] VS2017 v15.6.6 build 26131 (*)";
        case 0x01036613: return "[ASM] VS2017 v15.6.6 build 26131 (*)";
        case 0x01056613: return "[C++] VS2017 v15.6.6 build 26131 (*)";
        case 0x00ff6613: return "[RES] VS2017 v15.6.6 build 26131 (*)";
        case 0x01026613: return "[LNK] VS2017 v15.6.6 build 26131 (*)";
        case 0x01016613: return "[IMP] VS2017 v15.6.6 build 26131 (*)";
        case 0x01006613: return "[EXP] VS2017 v15.6.6 build 26131 (*)";
        case 0x01066613: return "[CIL] VS2017 v15.6.6 build 26131 (*)";
        case 0x01076613: return "[CI+] VS2017 v15.6.6 build 26131 (*)";
        case 0x01086613: return "[LTC] VS2017 v15.6.6 build 26131 (*)";
        case 0x01096613: return "[LT+] VS2017 v15.6.6 build 26131 (*)";
        case 0x010a6613: return "[LTM] VS2017 v15.6.6 build 26131 (*)";
        case 0x010b6613: return "[PGO] VS2017 v15.6.6 build 26131 (*)";
        case 0x010c6613: return "[PG+] VS2017 v15.6.6 build 26131 (*)";
        case 0x010d6613: return "[POC] VS2017 v15.6.6 build 26131 (*)";
        case 0x010e6613: return "[PO+] VS2017 v15.6.6 build 26131 (*)";

        // Visual Studio 2017 version 15.6.4 has the same build number
        // Visual Studio 2017 version 15.6.3 (values are interpolated)
        case 0x01046611: return "[ C ] VS2017 v15.6.3 build 26129 (*)";
        case 0x01036611: return "[ASM] VS2017 v15.6.3 build 26129 (*)";
        case 0x01056611: return "[C++] VS2017 v15.6.3 build 26129 (*)";
        case 0x00ff6611: return "[RES] VS2017 v15.6.3 build 26129 (*)";
        case 0x01026611: return "[LNK] VS2017 v15.6.3 build 26129 (*)";
        case 0x01016611: return "[IMP] VS2017 v15.6.3 build 26129 (*)";
        case 0x01006611: return "[EXP] VS2017 v15.6.3 build 26129 (*)";
        case 0x01066611: return "[CIL] VS2017 v15.6.3 build 26129 (*)";
        case 0x01076611: return "[CI+] VS2017 v15.6.3 build 26129 (*)";
        case 0x01086611: return "[LTC] VS2017 v15.6.3 build 26129 (*)";
        case 0x01096611: return "[LT+] VS2017 v15.6.3 build 26129 (*)";
        case 0x010a6611: return "[LTM] VS2017 v15.6.3 build 26129 (*)";
        case 0x010b6611: return "[PGO] VS2017 v15.6.3 build 26129 (*)";
        case 0x010c6611: return "[PG+] VS2017 v15.6.3 build 26129 (*)";
        case 0x010d6611: return "[POC] VS2017 v15.6.3 build 26129 (*)";
        case 0x010e6611: return "[PO+] VS2017 v15.6.3 build 26129 (*)";

        // Visual Studio 2017 version 15.6.2 has the same build number
        // Visual Studio 2017 version 15.6.1 has the same build number
        // Visual Studio 2017 version 15.6.0 (values are interpolated)
        case 0x01046610: return "[ C ] VS2017 v15.6.0 build 26128 (*)";
        case 0x01036610: return "[ASM] VS2017 v15.6.0 build 26128 (*)";
        case 0x01056610: return "[C++] VS2017 v15.6.0 build 26128 (*)";
        case 0x00ff6610: return "[RES] VS2017 v15.6.0 build 26128 (*)";
        case 0x01026610: return "[LNK] VS2017 v15.6.0 build 26128 (*)";
        case 0x01016610: return "[IMP] VS2017 v15.6.0 build 26128 (*)";
        case 0x01006610: return "[EXP] VS2017 v15.6.0 build 26128 (*)";
        case 0x01066610: return "[CIL] VS2017 v15.6.0 build 26128 (*)";
        case 0x01076610: return "[CI+] VS2017 v15.6.0 build 26128 (*)";
        case 0x01086610: return "[LTC] VS2017 v15.6.0 build 26128 (*)";
        case 0x01096610: return "[LT+] VS2017 v15.6.0 build 26128 (*)";
        case 0x010a6610: return "[LTM] VS2017 v15.6.0 build 26128 (*)";
        case 0x010b6610: return "[PGO] VS2017 v15.6.0 build 26128 (*)";
        case 0x010c6610: return "[PG+] VS2017 v15.6.0 build 26128 (*)";
        case 0x010d6610: return "[POC] VS2017 v15.6.0 build 26128 (*)";
        case 0x010e6610: return "[PO+] VS2017 v15.6.0 build 26128 (*)";

        // Visual Studio 2017 version 15.5.7 has the same build number
        // Visual Studio 2017 version 15.5.6 (values are interpolated)
        case 0x010464eb: return "[ C ] VS2017 v15.5.6 build 25835 (*)";
        case 0x010364eb: return "[ASM] VS2017 v15.5.6 build 25835 (*)";
        case 0x010564eb: return "[C++] VS2017 v15.5.6 build 25835 (*)";
        case 0x00ff64eb: return "[RES] VS2017 v15.5.6 build 25835 (*)";
        case 0x010264eb: return "[LNK] VS2017 v15.5.6 build 25835 (*)";
        case 0x010164eb: return "[IMP] VS2017 v15.5.6 build 25835 (*)";
        case 0x010064eb: return "[EXP] VS2017 v15.5.6 build 25835 (*)";
        case 0x010664eb: return "[CIL] VS2017 v15.5.6 build 25835 (*)";
        case 0x010764eb: return "[CI+] VS2017 v15.5.6 build 25835 (*)";
        case 0x010864eb: return "[LTC] VS2017 v15.5.6 build 25835 (*)";
        case 0x010964eb: return "[LT+] VS2017 v15.5.6 build 25835 (*)";
        case 0x010a64eb: return "[LTM] VS2017 v15.5.6 build 25835 (*)";
        case 0x010b64eb: return "[PGO] VS2017 v15.5.6 build 25835 (*)";
        case 0x010c64eb: return "[PG+] VS2017 v15.5.6 build 25835 (*)";
        case 0x010d64eb: return "[POC] VS2017 v15.5.6 build 25835 (*)";
        case 0x010e64eb: return "[PO+] VS2017 v15.5.6 build 25835 (*)";

        // MSVS2017 v15.5.4 (15.5.3 has the same build number)
        case 0x010464ea: return "[ C ] VS2017 v15.5.4 build 25834";
        case 0x010364ea: return "[ASM] VS2017 v15.5.4 build 25834";
        case 0x010564ea: return "[C++] VS2017 v15.5.4 build 25834";
        case 0x00ff64ea: return "[RES] VS2017 v15.5.4 build 25834";
        case 0x010264ea: return "[LNK] VS2017 v15.5.4 build 25834";
        case 0x010064ea: return "[EXP] VS2017 v15.5.4 build 25834";
        case 0x010164ea: return "[IMP] VS2017 v15.5.4 build 25834";
        case 0x010664ea: return "[CIL] VS2017 v15.5.4 build 25834 (*)";
        case 0x010764ea: return "[CI+] VS2017 v15.5.4 build 25834 (*)";
        case 0x010864ea: return "[LTC] VS2017 v15.5.4 build 25834 (*)";
        case 0x010964ea: return "[LT+] VS2017 v15.5.4 build 25834 (*)";
        case 0x010a64ea: return "[LTM] VS2017 v15.5.4 build 25834 (*)";
        case 0x010b64ea: return "[PGO] VS2017 v15.5.4 build 25834 (*)";
        case 0x010c64ea: return "[PG+] VS2017 v15.5.4 build 25834 (*)";
        case 0x010d64ea: return "[POC] VS2017 v15.5.4 build 25834 (*)";
        case 0x010e64ea: return "[PO+] VS2017 v15.5.4 build 25834 (*)";

        // Visual Studio 2017 version 15.5.2 (values are interpolated)
        case 0x010464e7: return "[ C ] VS2017 v15.5.2 build 25831 (*)";
        case 0x010364e7: return "[ASM] VS2017 v15.5.2 build 25831 (*)";
        case 0x010564e7: return "[C++] VS2017 v15.5.2 build 25831 (*)";
        case 0x00ff64e7: return "[RES] VS2017 v15.5.2 build 25831 (*)";
        case 0x010264e7: return "[LNK] VS2017 v15.5.2 build 25831 (*)";
        case 0x010164e7: return "[IMP] VS2017 v15.5.2 build 25831 (*)";
        case 0x010064e7: return "[EXP] VS2017 v15.5.2 build 25831 (*)";
        case 0x010664e7: return "[CIL] VS2017 v15.5.2 build 25831 (*)";
        case 0x010764e7: return "[CI+] VS2017 v15.5.2 build 25831 (*)";
        case 0x010864e7: return "[LTC] VS2017 v15.5.2 build 25831 (*)";
        case 0x010964e7: return "[LT+] VS2017 v15.5.2 build 25831 (*)";
        case 0x010a64e7: return "[LTM] VS2017 v15.5.2 build 25831 (*)";
        case 0x010b64e7: return "[PGO] VS2017 v15.5.2 build 25831 (*)";
        case 0x010c64e7: return "[PG+] VS2017 v15.5.2 build 25831 (*)";
        case 0x010d64e7: return "[POC] VS2017 v15.5.2 build 25831 (*)";
        case 0x010e64e7: return "[PO+] VS2017 v15.5.2 build 25831 (*)";

        // Visual Studio 2017 version 15.4.5 (values are interpolated)
        case 0x010463cb: return "[ C ] VS2017 v15.4.5 build 25547 (*)";
        case 0x010363cb: return "[ASM] VS2017 v15.4.5 build 25547 (*)";
        case 0x010563cb: return "[C++] VS2017 v15.4.5 build 25547 (*)";
        case 0x00ff63cb: return "[RES] VS2017 v15.4.5 build 25547 (*)";
        case 0x010263cb: return "[LNK] VS2017 v15.4.5 build 25547 (*)";
        case 0x010163cb: return "[IMP] VS2017 v15.4.5 build 25547 (*)";
        case 0x010063cb: return "[EXP] VS2017 v15.4.5 build 25547 (*)";
        case 0x010663cb: return "[CIL] VS2017 v15.4.5 build 25547 (*)";
        case 0x010763cb: return "[CI+] VS2017 v15.4.5 build 25547 (*)";
        case 0x010863cb: return "[LTC] VS2017 v15.4.5 build 25547 (*)";
        case 0x010963cb: return "[LT+] VS2017 v15.4.5 build 25547 (*)";
        case 0x010a63cb: return "[LTM] VS2017 v15.4.5 build 25547 (*)";
        case 0x010b63cb: return "[PGO] VS2017 v15.4.5 build 25547 (*)";
        case 0x010c63cb: return "[PG+] VS2017 v15.4.5 build 25547 (*)";
        case 0x010d63cb: return "[POC] VS2017 v15.4.5 build 25547 (*)";
        case 0x010e63cb: return "[PO+] VS2017 v15.4.5 build 25547 (*)";

        // Visual Studio 2017 version 15.4.4 (values are interpolated)
        case 0x010463c6: return "[ C ] VS2017 v15.4.4 build 25542 (*)";
        case 0x010363c6: return "[ASM] VS2017 v15.4.4 build 25542 (*)";
        case 0x010563c6: return "[C++] VS2017 v15.4.4 build 25542 (*)";
        case 0x00ff63c6: return "[RES] VS2017 v15.4.4 build 25542 (*)";
        case 0x010263c6: return "[LNK] VS2017 v15.4.4 build 25542 (*)";
        case 0x010163c6: return "[IMP] VS2017 v15.4.4 build 25542 (*)";
        case 0x010063c6: return "[EXP] VS2017 v15.4.4 build 25542 (*)";
        case 0x010663c6: return "[CIL] VS2017 v15.4.4 build 25542 (*)";
        case 0x010763c6: return "[CI+] VS2017 v15.4.4 build 25542 (*)";
        case 0x010863c6: return "[LTC] VS2017 v15.4.4 build 25542 (*)";
        case 0x010963c6: return "[LT+] VS2017 v15.4.4 build 25542 (*)";
        case 0x010a63c6: return "[LTM] VS2017 v15.4.4 build 25542 (*)";
        case 0x010b63c6: return "[PGO] VS2017 v15.4.4 build 25542 (*)";
        case 0x010c63c6: return "[PG+] VS2017 v15.4.4 build 25542 (*)";
        case 0x010d63c6: return "[POC] VS2017 v15.4.4 build 25542 (*)";
        case 0x010e63c6: return "[PO+] VS2017 v15.4.4 build 25542 (*)";

        // Visual Studio 2017 version 15.3.3 (values are interpolated)
        case 0x010463a3: return "[ C ] VS2017 v15.3.3 build 25507 (*)";
        case 0x010363a3: return "[ASM] VS2017 v15.3.3 build 25507 (*)";
        case 0x010563a3: return "[C++] VS2017 v15.3.3 build 25507 (*)";
        case 0x00ff63a3: return "[RES] VS2017 v15.3.3 build 25507 (*)";
        case 0x010263a3: return "[LNK] VS2017 v15.3.3 build 25507 (*)";
        case 0x010163a3: return "[IMP] VS2017 v15.3.3 build 25507 (*)";
        case 0x010063a3: return "[EXP] VS2017 v15.3.3 build 25507 (*)";
        case 0x010663a3: return "[CIL] VS2017 v15.3.3 build 25507 (*)";
        case 0x010763a3: return "[CI+] VS2017 v15.3.3 build 25507 (*)";
        case 0x010863a3: return "[LTC] VS2017 v15.3.3 build 25507 (*)";
        case 0x010963a3: return "[LT+] VS2017 v15.3.3 build 25507 (*)";
        case 0x010a63a3: return "[LTM] VS2017 v15.3.3 build 25507 (*)";
        case 0x010b63a3: return "[PGO] VS2017 v15.3.3 build 25507 (*)";
        case 0x010c63a3: return "[PG+] VS2017 v15.3.3 build 25507 (*)";
        case 0x010d63a3: return "[POC] VS2017 v15.3.3 build 25507 (*)";
        case 0x010e63a3: return "[PO+] VS2017 v15.3.3 build 25507 (*)";

        // Visual Studio 2017 version 15.3 (values are interpolated)
        // source: https://twitter.com/visualc/status/897853176002433024
        case 0x010463a2: return "[ C ] VS2017 v15.3 build 25506 (*)";
        case 0x010363a2: return "[ASM] VS2017 v15.3 build 25506 (*)";
        case 0x010563a2: return "[C++] VS2017 v15.3 build 25506 (*)";
        case 0x00ff63a2: return "[RES] VS2017 v15.3 build 25506 (*)";
        case 0x010263a2: return "[LNK] VS2017 v15.3 build 25506 (*)";
        case 0x010163a2: return "[IMP] VS2017 v15.3 build 25506 (*)";
        case 0x010063a2: return "[EXP] VS2017 v15.3 build 25506 (*)";
        case 0x010663a2: return "[CIL] VS2017 v15.3 build 25506 (*)";
        case 0x010763a2: return "[CI+] VS2017 v15.3 build 25506 (*)";
        case 0x010863a2: return "[LTC] VS2017 v15.3 build 25506 (*)";
        case 0x010963a2: return "[LT+] VS2017 v15.3 build 25506 (*)";
        case 0x010a63a2: return "[LTM] VS2017 v15.3 build 25506 (*)";
        case 0x010b63a2: return "[PGO] VS2017 v15.3 build 25506 (*)";
        case 0x010c63a2: return "[PG+] VS2017 v15.3 build 25506 (*)";
        case 0x010d63a2: return "[POC] VS2017 v15.3 build 25506 (*)";
        case 0x010e63a2: return "[PO+] VS2017 v15.3 build 25506 (*)";

        // Visual Studio 2017 version 15.2 has the same build number
        // Visual Studio 2017 version 15.1 has the same build number
        // Visual Studio 2017 version 15.0 (values are interpolated)
        case 0x010461b9: return "[ C ] VS2017 v15.0 build 25017 (*)";
        case 0x010361b9: return "[ASM] VS2017 v15.0 build 25017 (*)";
        case 0x010561b9: return "[C++] VS2017 v15.0 build 25017 (*)";
        case 0x00ff61b9: return "[RES] VS2017 v15.0 build 25017 (*)";
        case 0x010261b9: return "[LNK] VS2017 v15.0 build 25017 (*)";
        case 0x010161b9: return "[IMP] VS2017 v15.0 build 25017 (*)";
        case 0x010061b9: return "[EXP] VS2017 v15.0 build 25017 (*)";
        case 0x010661b9: return "[CIL] VS2017 v15.0 build 25017 (*)";
        case 0x010761b9: return "[CI+] VS2017 v15.0 build 25017 (*)";
        case 0x010861b9: return "[LTC] VS2017 v15.0 build 25017 (*)";
        case 0x010961b9: return "[LT+] VS2017 v15.0 build 25017 (*)";
        case 0x010a61b9: return "[LTM] VS2017 v15.0 build 25017 (*)";
        case 0x010b61b9: return "[PGO] VS2017 v15.0 build 25017 (*)";
        case 0x010c61b9: return "[PG+] VS2017 v15.0 build 25017 (*)";
        case 0x010d61b9: return "[POC] VS2017 v15.0 build 25017 (*)";
        case 0x010e61b9: return "[PO+] VS2017 v15.0 build 25017 (*)";

        // MSVS Community 2015 UPD3.1 (cl version 19.00.24215.1) - some IDs are interpolated
        //[ASM] is the same as in UPD3 build 24213
        case 0x01045e97: return "[ C ] VS2015 UPD3.1 build 24215";
        case 0x01055e97: return "[C++] VS2015 UPD3.1 build 24215";
        case 0x01025e97: return "[LNK] VS2015 UPD3.1 build 24215";
        case 0x01005e97: return "[EXP] VS2015 UPD3.1 build 24215";
        case 0x01015e97: return "[IMP] VS2015 UPD3.1 build 24215";
        case 0x00ff5e97: return "[RES] VS2015 UPD3.1 build 24215 (*)";
        case 0x01035e97: return "[ASM] VS2015 UPD3.1 build 24215 (*)";
        case 0x01065e97: return "[CIL] VS2015 UPD3.1 build 24215 (*)";
        case 0x01075e97: return "[CI+] VS2015 UPD3.1 build 24215 (*)";
        case 0x01085e97: return "[LTC] VS2015 UPD3.1 build 24215 (*)";
        case 0x01095e97: return "[LT+] VS2015 UPD3.1 build 24215 (*)";
        case 0x010a5e97: return "[LTM] VS2015 UPD3.1 build 24215 (*)";
        case 0x010b5e97: return "[PGO] VS2015 UPD3.1 build 24215 (*)";
        case 0x010c5e97: return "[PG+] VS2015 UPD3.1 build 24215 (*)";
        case 0x010d5e97: return "[POC] VS2015 UPD3.1 build 24215 (*)";
        case 0x010e5e97: return "[PO+] VS2015 UPD3.1 build 24215 (*)";

        // MSVS Community 2015 UPD3 (cl version 19.00.24213.1)
        case 0x01045e95: return "[ C ] VS2015 UPD3 build 24213";
        case 0x01055e95: return "[C++] VS2015 UPD3 build 24213";
        // asm and cvtres are from previous build smh
        case 0x01035e92: return "[ASM] VS2015 UPD3 build 24210";
        case 0x00ff5e92: return "[RES] VS2015 UPD3 build 24210";
        case 0x01025e95: return "[LNK] VS2015 UPD3 build 24213";
        case 0x01005e95: return "[EXP] VS2015 UPD3 build 24213";
        case 0x01015e95: return "[IMP] VS2015 UPD3 build 24213";
        case 0x01065e95: return "[CIL] VS2015 UPD3 build 24213 (*)";
        case 0x01075e95: return "[CI+] VS2015 UPD3 build 24213 (*)";
        case 0x01085e95: return "[LTC] VS2015 UPD3 build 24213 (*)";
        case 0x01095e95: return "[LT+] VS2015 UPD3 build 24213 (*)";
        case 0x010a5e95: return "[LTM] VS2015 UPD3 build 24213 (*)";
        case 0x010b5e95: return "[PGO] VS2015 UPD3 build 24213 (*)";
        case 0x010c5e95: return "[PG+] VS2015 UPD3 build 24213 (*)";
        case 0x010d5e95: return "[POC] VS2015 UPD3 build 24213 (*)";
        case 0x010e5e95: return "[PO+] VS2015 UPD3 build 24213 (*)";

        // Visual Studio 2015 Update 3[14.0] (values are interpolated)
        case 0x01045e92: return "[ C ] VS2015 Update 3[14.0] build 24210 (*)";
        // 01035e92[ASM] VS2015 Update 3[14.0] build 24210 (*)
        case 0x01055e92: return "[C++] VS2015 Update 3[14.0] build 24210 (*)";
        // 00ff5e92[RES] VS2015 Update 3[14.0] build 24210 (*)
        case 0x01025e92: return "[LNK] VS2015 Update 3[14.0] build 24210 (*)";
        case 0x01015e92: return "[IMP] VS2015 Update 3[14.0] build 24210 (*)";
        case 0x01005e92: return "[EXP] VS2015 Update 3[14.0] build 24210 (*)";
        case 0x01065e92: return "[CIL] VS2015 Update 3[14.0] build 24210 (*)";
        case 0x01075e92: return "[CI+] VS2015 Update 3[14.0] build 24210 (*)";
        case 0x01085e92: return "[LTC] VS2015 Update 3[14.0] build 24210 (*)";
        case 0x01095e92: return "[LT+] VS2015 Update 3[14.0] build 24210 (*)";
        case 0x010a5e92: return "[LTM] VS2015 Update 3[14.0] build 24210 (*)";
        case 0x010b5e92: return "[PGO] VS2015 Update 3[14.0] build 24210 (*)";
        case 0x010c5e92: return "[PG+] VS2015 Update 3[14.0] build 24210 (*)";
        case 0x010d5e92: return "[POC] VS2015 Update 3[14.0] build 24210 (*)";
        case 0x010e5e92: return "[PO+] VS2015 Update 3[14.0] build 24210 (*)";

        // MSVS Community 2015 UPD2 (14.0.25123.0?)
        case 0x01045d6e: return "[ C ] VS2015 UPD2 build 23918";
        case 0x01035d6e: return "[ASM] VS2015 UPD2 build 23918";
        case 0x01055d6e: return "[C++] VS2015 UPD2 build 23918";
        case 0x00ff5d6e: return "[RES] VS2015 UPD2 build 23918";
        case 0x01025d6e: return "[LNK] VS2015 UPD2 build 23918";
        case 0x01005d6e: return "[EXP] VS2015 UPD2 build 23918";
        case 0x01015d6e: return "[IMP] VS2015 UPD2 build 23918";
        case 0x01065d6e: return "[CIL] VS2015 UPD2 build 23918 (*)";
        case 0x01075d6e: return "[CI+] VS2015 UPD2 build 23918 (*)";
        case 0x01085d6e: return "[LTC] VS2015 UPD2 build 23918 (*)";
        case 0x01095d6e: return "[LT+] VS2015 UPD2 build 23918 (*)";
        case 0x010a5d6e: return "[LTM] VS2015 UPD2 build 23918 (*)";
        case 0x010b5d6e: return "[PGO] VS2015 UPD2 build 23918 (*)";
        case 0x010c5d6e: return "[PG+] VS2015 UPD2 build 23918 (*)";
        case 0x010d5d6e: return "[POC] VS2015 UPD2 build 23918 (*)";
        case 0x010e5d6e: return "[PO+] VS2015 UPD2 build 23918 (*)";

        // MSVS Community 2015 14.0.24728.2 (UPD 1) 14.0.24720.0 D14REL
        case 0x01045bd2: return "[ C ] VS2015 UPD1 build 23506";
        case 0x01035bd2: return "[ASM] VS2015 UPD1 build 23506";
        case 0x01055bd2: return "[C++] VS2015 UPD1 build 23506";
        case 0x00ff5bd2: return "[RES] VS2015 UPD1 build 23506";
        case 0x01025bd2: return "[LNK] VS2015 UPD1 build 23506";
        case 0x01005bd2: return "[EXP] VS2015 UPD1 build 23506";
        case 0x01015bd2: return "[IMP] VS2015 UPD1 build 23506";
        case 0x01065bd2: return "[CIL] VS2015 UPD1 build 23506 (*)";
        case 0x01075bd2: return "[CI+] VS2015 UPD1 build 23506 (*)";
        case 0x01085bd2: return "[LTC] VS2015 UPD1 build 23506 (*)";
        case 0x01095bd2: return "[LT+] VS2015 UPD1 build 23506 (*)";
        case 0x010a5bd2: return "[LTM] VS2015 UPD1 build 23506 (*)";
        case 0x010b5bd2: return "[PGO] VS2015 UPD1 build 23506 (*)";
        case 0x010c5bd2: return "[PG+] VS2015 UPD1 build 23506 (*)";
        case 0x010d5bd2: return "[POC] VS2015 UPD1 build 23506 (*)";
        case 0x010e5bd2: return "[PO+] VS2015 UPD1 build 23506 (*)";

        // MSVS Community 2015[14.0]
        case 0x010459f2: return "[ C ] VS2015[14.0] build 23026";
        case 0x010359f2: return "[ASM] VS2015[14.0] build 23026";
        case 0x010559f2: return "[C++] VS2015[14.0] build 23026";
        case 0x00ff59f2: return "[RES] VS2015[14.0] build 23026";
        case 0x010259f2: return "[LNK] VS2015[14.0] build 23026";
        case 0x010059f2: return "[EXP] VS2015[14.0] build 23026";
        case 0x010159f2: return "[IMP] VS2015[14.0] build 23026";
        case 0x010659f2: return "[CIL] VS2015[14.0] build 23026 (*)";
        case 0x010759f2: return "[CI+] VS2015[14.0] build 23026 (*)";
        case 0x010859f2: return "[LTC] VS2015[14.0] build 23026 (*)";
        case 0x010959f2: return "[LT+] VS2015[14.0] build 23026 (*)";
        case 0x010a59f2: return "[LTM] VS2015[14.0] build 23026 (*)";
        case 0x010b59f2: return "[PGO] VS2015[14.0] build 23026 (*)";
        case 0x010c59f2: return "[PG+] VS2015[14.0] build 23026 (*)";
        case 0x010d59f2: return "[POC] VS2015[14.0] build 23026 (*)";
        case 0x010e59f2: return "[PO+] VS2015[14.0] build 23026 (*)";

        // Visual Studio 2013 November CTP[12.0] (values are interpolated)
        case 0x00e0527a: return "[ C ] VS2013 November CTP[12.0] build 21114 (*)";
        case 0x00df527a: return "[ASM] VS2013 November CTP[12.0] build 21114 (*)";
        case 0x00e1527a: return "[C++] VS2013 November CTP[12.0] build 21114 (*)";
        case 0x00db527a: return "[RES] VS2013 November CTP[12.0] build 21114 (*)";
        case 0x00de527a: return "[LNK] VS2013 November CTP[12.0] build 21114 (*)";
        case 0x00dd527a: return "[IMP] VS2013 November CTP[12.0] build 21114 (*)";
        case 0x00dc527a: return "[EXP] VS2013 November CTP[12.0] build 21114 (*)";

        // MSVS2013 12.0.40629.00 Update 5
        case 0x00e09eb5: return "[ C ] VS2013 UPD5 build 40629";
        case 0x00e19eb5: return "[C++] VS2013 UPD5 build 40629";
        // cvtres not updated since RTM version, so add interpolated one
        case 0x00db9eb5: return "[RES] VS2013 Update 5[12.0] build 40629 (*)";
        case 0x00de9eb5: return "[LNK] VS2013 UPD5 build 40629";
        case 0x00dc9eb5: return "[EXP] VS2013 UPD5 build 40629";
        case 0x00dd9eb5: return "[IMP] VS2013 UPD5 build 40629";
        case 0x00df9eb5: return "[ASM] VS2013 UPD5 build 40629";

        // MSVS2013 12.0.31101.00 Update 4 - not attested in real world, @comp.id is
        // calculated.
        case 0x00e0797d: return "[ C ] VS2013 UPD4 build 31101 (*)";
        case 0x00e1797d: return "[C++] VS2013 UPD4 build 31101 (*)";
        case 0x00db797d: return "[RES] VS2013 UPD4 build 31101 (*)";
        case 0x00de797d: return "[LNK] VS2013 UPD4 build 31101 (*)";
        case 0x00dc797d: return "[EXP] VS2013 UPD4 build 31101 (*)";
        case 0x00dd797d: return "[IMP] VS2013 UPD4 build 31101 (*)";
        case 0x00df797d: return "[ASM] VS2013 UPD4 build 31101 (*)";

        // MSVS2013 12.0.30723.00 Update 3 - not attested in real world, @comp.id is
        // calculated.
        case 0x00e07803: return "[ C ] VS2013 UPD3 build 30723 (*)";
        case 0x00e17803: return "[C++] VS2013 UPD3 build 30723 (*)";
        case 0x00db7803: return "[RES] VS2013 UPD3 build 30723 (*)";
        case 0x00de7803: return "[LNK] VS2013 UPD3 build 30723 (*)";
        case 0x00dc7803: return "[EXP] VS2013 UPD3 build 30723 (*)";
        case 0x00dd7803: return "[IMP] VS2013 UPD3 build 30723 (*)";
        case 0x00df7803: return "[ASM] VS2013 UPD3 build 30723 (*)";

        // MSVS2013 12.0.30501.00 Update 2 - not attested in real world, @comp.id is
        // calculated.
        case 0x00e07725: return "[ C ] VS2013 UPD2 build 30501";
        case 0x00e17725: return "[C++] VS2013 UPD2 build 30501";
        // cvtres not updated since RTM version, so add interpolated one
        case 0x00db7725: return "[RES] VS2013 Update 2[12.0] build 30501 (*)";
        case 0x00de7725: return "[LNK] VS2013 UPD2 build 30501";
        case 0x00dc7725: return "[EXP] VS2013 UPD2 build 30501";
        case 0x00dd7725: return "[IMP] VS2013 UPD2 build 30501";
        case 0x00df7725: return "[ASM] VS2013 UPD2 build 30501";

        // Visual Studio 2013 Update2 RC[12.0] (values are interpolated)
        case 0x00e07674: return "[ C ] VS2013 Update2 RC[12.0] build 30324 (*)";
        case 0x00df7674: return "[ASM] VS2013 Update2 RC[12.0] build 30324 (*)";
        case 0x00e17674: return "[C++] VS2013 Update2 RC[12.0] build 30324 (*)";
        case 0x00db7674: return "[RES] VS2013 Update2 RC[12.0] build 30324 (*)";
        case 0x00de7674: return "[LNK] VS2013 Update2 RC[12.0] build 30324 (*)";
        case 0x00dd7674: return "[IMP] VS2013 Update2 RC[12.0] build 30324 (*)";
        case 0x00dc7674: return "[EXP] VS2013 Update2 RC[12.0] build 30324 (*)";

        // MSVS2013 RTM
        // Looks like it doesn't always dump linker's comp.id
        // Visual Studio 2013 Update 1[12.0] also has this build number
        case 0x00e0520d: return "[ C ] VS2013 build 21005";
        case 0x00e1520d: return "[C++] VS2013 build 21005";
        case 0x00db520d: return "[RES] VS2013 build 21005";
        case 0x00de520d: return "[LNK] VS2013 build 21005";
        case 0x00dc520d: return "[EXP] VS2013 build 21005";
        case 0x00dd520d: return "[IMP] VS2013 build 21005";
        case 0x00df520d: return "[ASM] VS2013 build 21005";

        // Visual Studio 2013 RC[12.0] (values are interpolated)
        case 0x00e0515b: return "[ C ] VS2013 RC[12.0] build 20827 (*)";
        case 0x00df515b: return "[ASM] VS2013 RC[12.0] build 20827 (*)";
        case 0x00e1515b: return "[C++] VS2013 RC[12.0] build 20827 (*)";
        case 0x00db515b: return "[RES] VS2013 RC[12.0] build 20827 (*)";
        case 0x00de515b: return "[LNK] VS2013 RC[12.0] build 20827 (*)";
        case 0x00dd515b: return "[IMP] VS2013 RC[12.0] build 20827 (*)";
        case 0x00dc515b: return "[EXP] VS2013 RC[12.0] build 20827 (*)";

        // Visual Studio 2013 Preview[12.0] (values are interpolated)
        case 0x00e05089: return "[ C ] VS2013 Preview[12.0] build 20617 (*)";
        case 0x00df5089: return "[ASM] VS2013 Preview[12.0] build 20617 (*)";
        case 0x00e15089: return "[C++] VS2013 Preview[12.0] build 20617 (*)";
        case 0x00db5089: return "[RES] VS2013 Preview[12.0] build 20617 (*)";
        case 0x00de5089: return "[LNK] VS2013 Preview[12.0] build 20617 (*)";
        case 0x00dd5089: return "[IMP] VS2013 Preview[12.0] build 20617 (*)";
        case 0x00dc5089: return "[EXP] VS2013 Preview[12.0] build 20617 (*)";

        // MSVS2012 Premium Update 4 (11.0.61030.00 Update 4)
        case 0x00ceee66: return "[ C ] VS2012 UPD4 build 61030";
        case 0x00cfee66: return "[C++] VS2012 UPD4 build 61030";
        case 0x00cdee66: return "[ASM] VS2012 UPD4 build 61030";
        case 0x00c9ee66: return "[RES] VS2012 UPD4 build 61030";
        case 0x00ccee66: return "[LNK] VS2012 UPD4 build 61030";
        case 0x00caee66: return "[EXP] VS2012 UPD4 build 61030";
        case 0x00cbee66: return "[IMP] VS2012 UPD4 build 61030";

        // MSVS2012 Update 3 (17.00.60610.1 Update 3) - not attested in real world,
        // @comp.id is calculated.
        case 0x00ceecc2: return "[ C ] VS2012 UPD3 build 60610 (*)";
        case 0x00cfecc2: return "[C++] VS2012 UPD3 build 60610 (*)";
        case 0x00cdecc2: return "[ASM] VS2012 UPD3 build 60610 (*)";
        case 0x00c9ecc2: return "[RES] VS2012 UPD3 build 60610 (*)";
        case 0x00ccecc2: return "[LNK] VS2012 UPD3 build 60610 (*)";
        case 0x00caecc2: return "[EXP] VS2012 UPD3 build 60610 (*)";
        case 0x00cbecc2: return "[IMP] VS2012 UPD3 build 60610 (*)";

        // MSVS2012 Update 2 (17.00.60315.1 Update 2) - not attested in real world,
        // @comp.id is calculated.
        case 0x00ceeb9b: return "[ C ] VS2012 UPD2 build 60315 (*)";
        case 0x00cfeb9b: return "[C++] VS2012 UPD2 build 60315 (*)";
        case 0x00cdeb9b: return "[ASM] VS2012 UPD2 build 60315 (*)";
        case 0x00c9eb9b: return "[RES] VS2012 UPD2 build 60315 (*)";
        case 0x00cceb9b: return "[LNK] VS2012 UPD2 build 60315 (*)";
        case 0x00caeb9b: return "[EXP] VS2012 UPD2 build 60315 (*)";
        case 0x00cbeb9b: return "[IMP] VS2012 UPD2 build 60315 (*)";

        // MSVS2012 Update 1 (17.00.51106.1 Update 1) - not attested in real world,
        // @comp.id is calculated.
        case 0x00cec7a2: return "[ C ] VS2012 UPD1 build 51106 (*)";
        case 0x00cfc7a2: return "[C++] VS2012 UPD1 build 51106 (*)";
        case 0x00cdc7a2: return "[ASM] VS2012 UPD1 build 51106 (*)";
        case 0x00c9c7a2: return "[RES] VS2012 UPD1 build 51106 (*)";
        case 0x00ccc7a2: return "[LNK] VS2012 UPD1 build 51106 (*)";
        case 0x00cac7a2: return "[EXP] VS2012 UPD1 build 51106 (*)";
        case 0x00cbc7a2: return "[IMP] VS2012 UPD1 build 51106 (*)";

        // Visual Studio 2012 November CTP[11.0] (values are interpolated)
        case 0x00cec751: return "[ C ] VS2012 November CTP[11.0] build 51025 (*)";
        case 0x00cdc751: return "[ASM] VS2012 November CTP[11.0] build 51025 (*)";
        case 0x00cfc751: return "[C++] VS2012 November CTP[11.0] build 51025 (*)";
        case 0x00c9c751: return "[RES] VS2012 November CTP[11.0] build 51025 (*)";
        case 0x00ccc751: return "[LNK] VS2012 November CTP[11.0] build 51025 (*)";
        case 0x00cbc751: return "[IMP] VS2012 November CTP[11.0] build 51025 (*)";
        case 0x00cac751: return "[EXP] VS2012 November CTP[11.0] build 51025 (*)";

        // MSVS2012 Premium (11.0.50727.1 RTMREL)
        case 0x00cec627: return "[ C ] VS2012 build 50727";
        case 0x00cfc627: return "[C++] VS2012 build 50727";
        case 0x00c9c627: return "[RES] VS2012 build 50727";
        case 0x00cdc627: return "[ASM] VS2012 build 50727";
        case 0x00cac627: return "[EXP] VS2012 build 50727";
        case 0x00cbc627: return "[IMP] VS2012 build 50727";
        case 0x00ccc627: return "[LNK] VS2012 build 50727";

        // MSVS2010 SP1 kb 983509 (10.0.40219.1 SP1Rel)
        case 0x00aa9d1b: return "[ C ] VS2010 SP1 build 40219";
        case 0x00ab9d1b: return "[C++] VS2010 SP1 build 40219";
        case 0x009d9d1b: return "[LNK] VS2010 SP1 build 40219";
        case 0x009a9d1b: return "[RES] VS2010 SP1 build 40219";
        case 0x009b9d1b: return "[EXP] VS2010 SP1 build 40219";
        case 0x009c9d1b: return "[IMP] VS2010 SP1 build 40219";
        case 0x009e9d1b: return "[ASM] VS2010 SP1 build 40219";

        // MSVS2010 (10.0.30319.1 RTMRel)
        case 0x00aa766f: return "[ C ] VS2010 build 30319";
        case 0x00ab766f: return "[C++] VS2010 build 30319";
        case 0x009d766f: return "[LNK] VS2010 build 30319";
        case 0x009a766f: return "[RES] VS2010 build 30319";
        case 0x009b766f: return "[EXP] VS2010 build 30319";
        case 0x009c766f: return "[IMP] VS2010 build 30319";
        case 0x009e766f: return "[ASM] VS2010 build 30319";

        // Visual Studio 2010 Beta 2[10.0] (values are interpolated)
        case 0x00aa520b: return "[ C ] VS2010 Beta 2[10.0] build 21003 (*)";
        case 0x009e520b: return "[ASM] VS2010 Beta 2[10.0] build 21003 (*)";
        case 0x00ab520b: return "[C++] VS2010 Beta 2[10.0] build 21003 (*)";
        case 0x009a520b: return "[RES] VS2010 Beta 2[10.0] build 21003 (*)";
        case 0x009d520b: return "[LNK] VS2010 Beta 2[10.0] build 21003 (*)";
        case 0x009c520b: return "[IMP] VS2010 Beta 2[10.0] build 21003 (*)";
        case 0x009b520b: return "[EXP] VS2010 Beta 2[10.0] build 21003 (*)";

        // Visual Studio 2010 Beta 1[10.0] (values are interpolated)
        case 0x00aa501a: return "[ C ] VS2010 Beta 1[10.0] build 20506 (*)";
        case 0x009e501a: return "[ASM] VS2010 Beta 1[10.0] build 20506 (*)";
        case 0x00ab501a: return "[C++] VS2010 Beta 1[10.0] build 20506 (*)";
        case 0x009a501a: return "[RES] VS2010 Beta 1[10.0] build 20506 (*)";
        case 0x009d501a: return "[LNK] VS2010 Beta 1[10.0] build 20506 (*)";
        case 0x009c501a: return "[IMP] VS2010 Beta 1[10.0] build 20506 (*)";
        case 0x009b501a: return "[EXP] VS2010 Beta 1[10.0] build 20506 (*)";

        // MSVS2008 SP1 (9.0.30729.1 SP)
        case 0x00837809: return "[ C ] VS2008 SP1 build 30729";
        case 0x00847809: return "[C++] VS2008 SP1 build 30729";
        // cvtres is the same as in VS2008, so add interpolated
        case 0x00947809: return "[RES] VS2008 SP1[9.0] build 30729 (*)";
        case 0x00957809: return "[ASM] VS2008 SP1 build 30729";
        case 0x00927809: return "[EXP] VS2008 SP1 build 30729";
        case 0x00937809: return "[IMP] VS2008 SP1 build 30729";
        case 0x00917809: return "[LNK] VS2008 SP1 build 30729";

        // MSVS2008 (9.0.21022.8 RTM)
        case 0x0083521e: return "[ C ] VS2008 build 21022";
        case 0x0084521e: return "[C++] VS2008 build 21022";
        case 0x0091521e: return "[LNK] VS2008 build 21022";
        case 0x0094521e: return "[RES] VS2008 build 21022";
        case 0x0092521e: return "[EXP] VS2008 build 21022";
        case 0x0093521e: return "[IMP] VS2008 build 21022";
        case 0x0095521e: return "[ASM] VS2008 build 21022";

        // Visual Studio 2008 Beta 2[9.0] (values are interpolated)
        case 0x008350e2: return "[ C ] VS2008 Beta 2[9.0] build 20706 (*)";
        case 0x009550e2: return "[ASM] VS2008 Beta 2[9.0] build 20706 (*)";
        case 0x008450e2: return "[C++] VS2008 Beta 2[9.0] build 20706 (*)";
        case 0x009450e2: return "[RES] VS2008 Beta 2[9.0] build 20706 (*)";
        case 0x009150e2: return "[LNK] VS2008 Beta 2[9.0] build 20706 (*)";
        case 0x009350e2: return "[IMP] VS2008 Beta 2[9.0] build 20706 (*)";
        case 0x009250e2: return "[EXP] VS2008 Beta 2[9.0] build 20706 (*)";

        // MSVS2005 (RTM.50727-4200) cl version: 14.00.50727.42
        // MSVS2005-SP1 dumps the same comp.id's.
        // It is strange, but there exists VS2012 with the same build number:
        // 11 Build 50727.1
        case 0x006dc627: return "[ C ] VS2005 build 50727";
        case 0x006ec627: return "[C++] VS2005 build 50727";
        case 0x0078c627: return "[LNK] VS2005 build 50727";
        case 0x007cc627: return "[RES] VS2005 build 50727";
        case 0x007ac627: return "[EXP] VS2005 build 50727";
        case 0x007bc627: return "[IMP] VS2005 build 50727";
        case 0x007dc627: return "[ASM] VS2005 build 50727";

        // Visual Studio 2005[8.0] (values are interpolated)
        case 0x006dc490: return "[ C ] VS2005[8.0] build 50320 (*)";
        case 0x007dc490: return "[ASM] VS2005[8.0] build 50320 (*)";
        case 0x006ec490: return "[C++] VS2005[8.0] build 50320 (*)";
        case 0x007cc490: return "[RES] VS2005[8.0] build 50320 (*)";
        case 0x0078c490: return "[LNK] VS2005[8.0] build 50320 (*)";
        case 0x007bc490: return "[IMP] VS2005[8.0] build 50320 (*)";
        case 0x007ac490: return "[EXP] VS2005[8.0] build 50320 (*)";

        // Visual Studio 2005 Beta 2[8.0] (values are interpolated)
        case 0x006dc427: return "[ C ] VS2005 Beta 2[8.0] build 50215 (*)";
        case 0x007dc427: return "[ASM] VS2005 Beta 2[8.0] build 50215 (*)";
        case 0x006ec427: return "[C++] VS2005 Beta 2[8.0] build 50215 (*)";
        case 0x007cc427: return "[RES] VS2005 Beta 2[8.0] build 50215 (*)";
        case 0x0078c427: return "[LNK] VS2005 Beta 2[8.0] build 50215 (*)";
        case 0x007bc427: return "[IMP] VS2005 Beta 2[8.0] build 50215 (*)";
        case 0x007ac427: return "[EXP] VS2005 Beta 2[8.0] build 50215 (*)";

        // Visual Studio 2005 Beta 1[8.0] (values are interpolated)
        case 0x006d9e9f: return "[ C ] VS2005 Beta 1[8.0] build 40607 (*)";
        case 0x007d9e9f: return "[ASM] VS2005 Beta 1[8.0] build 40607 (*)";
        case 0x006e9e9f: return "[C++] VS2005 Beta 1[8.0] build 40607 (*)";
        case 0x007c9e9f: return "[RES] VS2005 Beta 1[8.0] build 40607 (*)";
        case 0x00789e9f: return "[LNK] VS2005 Beta 1[8.0] build 40607 (*)";
        case 0x007b9e9f: return "[IMP] VS2005 Beta 1[8.0] build 40607 (*)";
        case 0x007a9e9f: return "[EXP] VS2005 Beta 1[8.0] build 40607 (*)";

        // Windows Server 2003 SP1 DDK (for AMD64) (values are interpolated)
        case 0x006d9d76: return "[ C ] Windows Server 2003 SP1 DDK (for AMD64) build 40310 (*)";
        case 0x007d9d76: return "[ASM] Windows Server 2003 SP1 DDK (for AMD64) build 40310 (*)";
        case 0x006e9d76: return "[C++] Windows Server 2003 SP1 DDK (for AMD64) build 40310 (*)";
        case 0x007c9d76: return "[RES] Windows Server 2003 SP1 DDK (for AMD64) build 40310 (*)";
        case 0x00789d76: return "[LNK] Windows Server 2003 SP1 DDK (for AMD64) build 40310 (*)";
        case 0x007b9d76: return "[IMP] Windows Server 2003 SP1 DDK (for AMD64) build 40310 (*)";
        case 0x007a9d76: return "[EXP] Windows Server 2003 SP1 DDK (for AMD64) build 40310 (*)";

        // MSVS2003 (.NET) SP1 (kb918007)
        case 0x005f178e: return "[ C ] VS2003 (.NET) SP1 build 6030";
        case 0x0060178e: return "[C++] VS2003 (.NET) SP1 build 6030";
        case 0x005a178e: return "[LNK] VS2003 (.NET) SP1 build 6030";
        case 0x000f178e: return "[ASM] VS2003 (.NET) SP1 build 6030";
        // cvtres is the same version as without SP1
        case 0x005e178e: return "[RES] VS.NET 2003 SP1[7.1] build 6030 (*)";
        case 0x005c178e: return "[EXP] VS2003 (.NET) SP1 build 6030";
        case 0x005d178e: return "[IMP] VS2003 (.NET) SP1 build 6030";

        // Windows Server 2003 SP1 DDK (values are interpolated)
        case 0x005f0fc3: return "[ C ] Windows Server 2003 SP1 DDK build 4035 (*)";
        case 0x000f0fc3: return "[ASM] Windows Server 2003 SP1 DDK build 4035 (*)";
        case 0x00600fc3: return "[C++] Windows Server 2003 SP1 DDK build 4035 (*)";
        case 0x005e0fc3: return "[RES] Windows Server 2003 SP1 DDK build 4035 (*)";
        case 0x005a0fc3: return "[LNK] Windows Server 2003 SP1 DDK build 4035 (*)";
        case 0x005d0fc3: return "[IMP] Windows Server 2003 SP1 DDK build 4035 (*)";
        case 0x005c0fc3: return "[EXP] Windows Server 2003 SP1 DDK build 4035 (*)";

        // MSVS2003 (.NET) 7.0.1.3088
        case 0x005f0c05: return "[ C ] VS2003 (.NET) build 3077";
        case 0x00600c05: return "[C++] VS2003 (.NET) build 3077";
        case 0x000f0c05: return "[ASM] VS2003 (.NET) build 3077";
        case 0x005e0bec: return "[RES] VS2003 (.NET) build 3052";
        case 0x005c0c05: return "[EXP] VS2003 (.NET) build 3077";
        case 0x005d0c05: return "[IMP] VS2003 (.NET) build 3077";
        case 0x005a0c05: return "[LNK] VS2003 (.NET) build 3077";
        // Visual Studio .NET 2003[7.1] (values are interpolated)
        case 0x005e0c05: return "[RES] VS.NET 2003[7.1] build 3077 (*)";

        // MSVS2002 (.NET) 7.0.9466
        case 0x001c24fa: return "[ C ] VS2002 (.NET) build 9466";
        case 0x001d24fa: return "[C++] VS2002 (.NET) build 9466";
        case 0x004024fa: return "[ASM] VS2002 (.NET) build 9466";
        case 0x003d24fa: return "[LNK] VS2002 (.NET) build 9466";
        case 0x004524fa: return "[RES] VS2002 (.NET) build 9466";
        case 0x003f24fa: return "[EXP] VS2002 (.NET) build 9466";
        case 0x001924fa: return "[IMP] VS2002 (.NET) build 9466";

        // Windows XP SP1 DDK (values are interpolated)
        case 0x001c23d8: return "[ C ] Windows XP SP1 DDK build 9176 (*)";
        case 0x004023d8: return "[ASM] Windows XP SP1 DDK build 9176 (*)";
        case 0x001d23d8: return "[C++] Windows XP SP1 DDK build 9176 (*)";
        case 0x004523d8: return "[RES] Windows XP SP1 DDK build 9176 (*)";
        case 0x003d23d8: return "[LNK] Windows XP SP1 DDK build 9176 (*)";
        case 0x001923d8: return "[IMP] Windows XP SP1 DDK build 9176 (*)";
        case 0x003f23d8: return "[EXP] Windows XP SP1 DDK build 9176 (*)";

        // MSVS98 6.0 SP6 (Enterprise edition)
        // Looks like linker may mix compids for C and C++ objects (why?)
        case 0x000a2636: return "[ C ] VS98 (6.0) SP6 build 8804";
        case 0x000b2636: return "[C++] VS98 (6.0) SP6 build 8804";

        // MSVC++ 6.0 SP5 (Enterprise edition)
        case 0x00152306: return "[ C ] VC++ 6.0 SP5 build 8804";
        case 0x00162306: return "[C++] VC++ 6.0 SP5 build 8804";
        case 0x000420ff: return "[LNK] VC++ 6.0 SP5 imp/exp build 8447";
        case 0x000606c7: return "[RES] VS98 (6.0) SP6 cvtres build 1736";

        // MSVS6.0 (no servicepacks)
        case 0x000a1fe8: return "[ C ] VS98 (6.0) build 8168";
        case 0x000b1fe8: return "[C++] VS98 (6.0) build 8168";
        case 0x000606b8: return "[RES] VS98 (6.0) cvtres build 1720";
        case 0x00041fe8: return "[LNK] VS98 (6.0) imp/exp build 8168";

        // MSVS97 5.0 Enterprise Edition (cl 11.00.7022, link 5.00.7022)
        // Does NOT generate any @comp.id records, nor Rich headers.
        // SP3 added Rich-generating linker (albeit it doesn't identify itself),
        // and CVTRES and LIB(?) utilities that generate @comp.id records. There is no
        // distinction between import and export records yet. I marked the records as
        //[IMP] because VS98 linker seems to omit export records from the header; VS97
        // linker might do the same.
        case 0x00060684: return "[RES] VS97 (5.0) SP3 cvtres 5.00.1668";
        case 0x00021c87: return "[IMP] VS97 (5.0) SP3 link 5.10.730";
        default: return "";
    }
}
