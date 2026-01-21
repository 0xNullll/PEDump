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
        case IMAGE_VER_6_0:     return "IMAGE_VER_6_0";
        case IMAGE_VER_6_1:     return "IMAGE_VER_6_1";
        case IMAGE_VER_6_2:     return "IMAGE_VER_6_2";
        case IMAGE_VER_6_3:     return "IMAGE_VER_6_3";
        case IMAGE_VER_10_0:    return "IMAGE_VER_10_0";
        case IMAGE_VER_11_0:    return "IMAGE_VER_11_0";
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