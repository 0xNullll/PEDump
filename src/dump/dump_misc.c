#include "../include/dump_misc.h"

RET_CODE dump_pe_strings(FILE* peFile, const char* regexFilter) {
    if (!peFile) return RET_INVALID_PARAM;

    ULONGLONG fileSize = 0;
    UCHAR* fileBuffer = read_entire_file_fp(peFile, &fileSize);
    if (!fileBuffer) return RET_ERROR;

    CHAR asciiTemp[MAX_ASCII_STRING];
    WCHAR uniTemp[MAX_UTF16_STRING];
    CHAR uniConverted[MAX_CONVERTED_STRING];
    ULONGLONG i = 0;
    ULONG stringNum = 0;

    printf("%-5s    %-10s    %-4s    %-6s    %-s\n",
           "Idx", "Offset", "Type", "Length", "String");

    while (i < fileSize) {
        // ---- Detect UTF-16LE strings ----
        if (i + 1 < fileSize) {
            UCHAR low = fileBuffer[i];
            UCHAR high = fileBuffer[i + 1];

            if (high == 0x00 && IS_ASCII_PRINTABLE(low)) {
                ULONGLONG j = 0, start = i;
                while (i + 1 < fileSize &&
                       fileBuffer[i + 1] == 0x00 &&
                       IS_ASCII_PRINTABLE(fileBuffer[i]) &&
                       j < (sizeof(uniTemp) / sizeof(WCHAR)) - 1) {
                    uniTemp[j++] = (WCHAR)fileBuffer[i];
                    i += 2;
                }

                if (j >= MIN_STR_LEN) {
                    for (ULONGLONG k = 0; k < j && k < sizeof(uniConverted) - 1; k++)
                        uniConverted[k] = (CHAR)uniTemp[k];
                    uniConverted[j] = '\0';

                    if (regexFilter != NULL) {
                        if (!regex_search(regexFilter, uniConverted)) continue;
                    }
                    printf("%-5lu    0x%8llX    %-4c    %-6zu    %s\n",
                           ++stringNum, start, 'W', j, uniConverted);
                }
                continue;
            }
        }

        // ---- ASCII fallback ----
        if (IS_ASCII_PRINTABLE(fileBuffer[i])) {
            ULONGLONG start = i, len = 0;
            while (i < fileSize &&
                   isprint(fileBuffer[i]) &&
                   len < sizeof(asciiTemp) - 1) {
                asciiTemp[len++] = (CHAR)fileBuffer[i++];
            }

            if (len >= MIN_STR_LEN) {
                asciiTemp[len] = '\0';

                if (regexFilter != NULL) {
                    if (!regex_search(regexFilter, asciiTemp)) continue;
                }

                printf("-%5lu    0x%8llX    %-4c    %-6zu    %s\n",
                       ++stringNum, start, 'A', len, asciiTemp);
            }
            continue;
        }

        i++;
    }

    free(fileBuffer);
    return RET_SUCCESS;
}

RET_CODE dump_pe_overview(
    const char *fileName,
    PIMAGE_NT_HEADERS32 nt32,
    PIMAGE_NT_HEADERS64 nt64,
    PIMAGE_SECTION_HEADER sections,
    PIMAGE_DATA_DIRECTORY dataDirs,
    int is64bit,
    LONGLONG fileSize) {

    int status = RET_ERROR;

    // Basic header extraction
    WORD Characteristics       = is64bit ? nt64->FileHeader.Characteristics      : nt32->FileHeader.Characteristics;
    DWORD timestamp            = is64bit ? nt64->FileHeader.TimeDateStamp        : nt32->FileHeader.TimeDateStamp;
    WORD  numberOfSections     = is64bit ? nt64->FileHeader.NumberOfSections     : nt32->FileHeader.NumberOfSections;
    WORD  machine              = is64bit ? nt64->FileHeader.Machine              : nt32->FileHeader.Machine;

    // Optional header extraction
    DWORD      addressOfEntryPoint     = is64bit ? nt64->OptionalHeader.AddressOfEntryPoint     : nt32->OptionalHeader.AddressOfEntryPoint;
    ULONGLONG  imageBase               = is64bit ? nt64->OptionalHeader.ImageBase               : nt32->OptionalHeader.ImageBase;
    BYTE       majorLinker             = is64bit ? nt64->OptionalHeader.MajorLinkerVersion      : nt32->OptionalHeader.MajorLinkerVersion;
    BYTE       minorLinker             = is64bit ? nt64->OptionalHeader.MinorLinkerVersion      : nt32->OptionalHeader.MinorLinkerVersion;
    WORD       subsystem               = is64bit ? nt64->OptionalHeader.Subsystem               : nt32->OptionalHeader.Subsystem;
    WORD       majorSubsystemVersion   = is64bit ? nt64->OptionalHeader.MajorSubsystemVersion   : nt32->OptionalHeader.MajorSubsystemVersion;
    WORD       minorSubsystemVersion   = is64bit ? nt64->OptionalHeader.MinorSubsystemVersion   : nt32->OptionalHeader.MinorSubsystemVersion;
    WORD       dllChars                = is64bit ? nt64->OptionalHeader.DllCharacteristics      : nt32->OptionalHeader.DllCharacteristics;

    // Overlay and PE type detection
    DWORD overlayOffset = 0, overlaySize = 0;
    getOverlayInfo(sections, numberOfSections, fileSize, &overlayOffset, &overlaySize);

    PETypeInfo peTypeInfo;

    status = identify_pe_type(
        fileName,
        dataDirs,
        sections,
        numberOfSections,
        Characteristics,
        addressOfEntryPoint,
        subsystem,
        majorSubsystemVersion,
        minorSubsystemVersion,
        &peTypeInfo
    );

    // Timestamp formatting
    char timeStampStr[64];
    if ((timestamp >= SOME_REASONABLE_EPOCH && timestamp <= CURRENT_EPOCH_PLUS_MARGIN) || timestamp == 0)
        sprintf(timeStampStr, "%08lX  %s", timestamp, format_timestamp(timestamp));
    else
        sprintf(timeStampStr, "%08lX", timestamp);

    // PE Overview
    printf("======================================================================\n");
    printf("PE Overview : %s\n", fileName);
    printf("----------------------------------------------------------------------\n");
    printf("File Size              : %lld bytes\n", fileSize);
    printf("Architecture           : %s %s\n", is64bit ? "x64" : "x86", file_header_machine_to_string(machine));
    printf("PE Type                : %s\n", peTypeInfo.extension);
    printf("Subsystem              : %s\n", subsystem_type_flag_to_string(subsystem));
    printf("Subsystem Type         : %s\n", subsystem_version_flag_to_string(majorSubsystemVersion, minorSubsystemVersion));
    printf("Image Base             : 0x%llX\n", imageBase);
    printf("Address Of Entry Point : 0x%llX\n", imageBase + addressOfEntryPoint);
    printf("Linker Version         : %u.%u\n", majorLinker, minorLinker);
    printf("Timestamp              : %s\n", timeStampStr);
    printf("Overlay Size           : %lu bytes\n", overlaySize);
    printf("======================================================================\n\n");

    printf("Characteristics        : 0x%04X\n", Characteristics);

    // Characteristics Flags
    FlagDesc characteristics_flags[] = {
        {IMAGE_FILE_RELOCS_STRIPPED,         "IMAGE_FILE_RELOCS_STRIPPED"},
        {IMAGE_FILE_EXECUTABLE_IMAGE,        "IMAGE_FILE_EXECUTABLE_IMAGE"},
        {IMAGE_FILE_LINE_NUMS_STRIPPED,      "IMAGE_FILE_LINE_NUMS_STRIPPED"},
        {IMAGE_FILE_LOCAL_SYMS_STRIPPED,     "IMAGE_FILE_LOCAL_SYMS_STRIPPED"},
        {IMAGE_FILE_AGGRESIVE_WS_TRIM,       "IMAGE_FILE_AGGRESIVE_WS_TRIM"},
        {IMAGE_FILE_LARGE_ADDRESS_AWARE,     "IMAGE_FILE_LARGE_ADDRESS_AWARE"},
        {IMAGE_FILE_BYTES_REVERSED_LO,       "IMAGE_FILE_BYTES_REVERSED_LO"},
        {IMAGE_FILE_32BIT_MACHINE,           "IMAGE_FILE_32BIT_MACHINE"},
        {IMAGE_FILE_DEBUG_STRIPPED,          "IMAGE_FILE_DEBUG_STRIPPED"},
        {IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"},
        {IMAGE_FILE_NET_RUN_FROM_SWAP,       "IMAGE_FILE_NET_RUN_FROM_SWAP"},
        {IMAGE_FILE_SYSTEM,                  "IMAGE_FILE_SYSTEM"},
        {IMAGE_FILE_DLL,                     "IMAGE_FILE_DLL"},
        {IMAGE_FILE_UP_SYSTEM_ONLY,          "IMAGE_FILE_UP_SYSTEM_ONLY"},
        {IMAGE_FILE_BYTES_REVERSED_HI,       "IMAGE_FILE_BYTES_REVERSED_HI"}
    };

    DWORD characteristics_flags_count = (sizeof(characteristics_flags)/sizeof(characteristics_flags[0]));

    for (DWORD i = 0; i < characteristics_flags_count; i++) {
        if (Characteristics & characteristics_flags[i].flag) {
            printf("\t\t       + 0x%04lX  %-50s\n",
                    characteristics_flags[i].flag,
                    characteristics_flags[i].name);
        }
    }

    if (Characteristics) putchar('\n');

    printf("Dll Characteristics    : 0x%04X\n", dllChars);

    // Dll Characteristics Flags
    FlagDesc dll_characteristics_flags[] = { 
        {IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,             "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA"},
        {IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,                "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"},
        {IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,             "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"},
        {IMAGE_DLLCHARACTERISTICS_NX_COMPAT,                   "IMAGE_DLLCHARACTERISTICS_NX_COMPAT"},
        {IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,                "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION"},
        {IMAGE_DLLCHARACTERISTICS_NO_SEH,                      "IMAGE_DLLCHARACTERISTICS_NO_SEH"},
        {IMAGE_DLLCHARACTERISTICS_NO_BIND,                     "IMAGE_DLLCHARACTERISTICS_NO_BIND"},
        {IMAGE_DLLCHARACTERISTICS_APPCONTAINER,                "IMAGE_DLLCHARACTERISTICS_APPCONTAINER"},
        {IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,                  "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER"},
        {IMAGE_DLLCHARACTERISTICS_GUARD_CF,                    "IMAGE_DLLCHARACTERISTICS_GUARD_CF"},
        {IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,       "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"}
    };

    DWORD flagCount = sizeof(dll_characteristics_flags) / sizeof(dll_characteristics_flags[0]);
    for (DWORD i = 0; i < flagCount; i++) {
        if (dllChars & dll_characteristics_flags[i].flag) {
            printf("\t\t       + 0x%04lX  %-50s\n",
                dll_characteristics_flags[i].flag,
                dll_characteristics_flags[i].name);
        }
    }
    if (dllChars) putchar('\n');

    printf("----------------------------------------------------------------------\n");

    // Section Summary
    printf("\t\t-- Section Summary (%u sections) --\n\n", numberOfSections);

    printf("Name       | VirtualAddress     | Virt Size  | Raw Size  | Perms\n");
    for (int i = 0; i < numberOfSections; i++) {
        char perms[4] = "---";
        if (sections[i].Characteristics & IMAGE_SCN_MEM_READ)    perms[0] = 'R';
        if (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE)   perms[1] = 'W';
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) perms[2] = 'X';

        printf("%-10s | 0x%016llX | 0x%08lX | 0x%08lX | %s\n",
            sections[i].Name,
            (ULONGLONG)sections[i].VirtualAddress + imageBase,
            sections[i].Misc.VirtualSize,
            sections[i].SizeOfRawData,
            perms
        );
    }

    printf("======================================================================\n");
    return status;
}

void dump_extracted_exports(PMATCH_LIST MatchList, PIMAGE_SECTION_HEADER sections, WORD numberOfSections, ULONGLONG imageBase, int level) {
    PEXPORT_MATCH expMatchHdr = &((PEXPORT_MATCH)MatchList->items)[0];

    int entries_level = level;
    
    // printing the extraction dump header
    if (expMatchHdr->type & EXPORT_TYPE_DLL_NAME && expMatchHdr->isForwarded) {
        printf("%s[ Forward DLL Export: %s ] Export Entries : %llu\n\n", INDENT(entries_level), expMatchHdr->dllName, MatchList->count);
        entries_level++;
    }
    else if ((expMatchHdr->type & EXPORT_TYPE_DLL_NAME) == 0 && expMatchHdr->isForwarded) {
        printf("%s[ Forwarded Export: %s ]\n", INDENT(entries_level + 1), expMatchHdr->forwarderName);
    } else {
        switch (expMatchHdr->type) {
            case EXPORT_TYPE_NAME:
                printf("%s[ Export: %s ]\n",
                    INDENT(entries_level), expMatchHdr->funcName);
                break;
            case EXPORT_TYPE_DLL_NAME:
                printf("%s[ DLL Export : %s ] Export Entries : %llu\n\n",
                    INDENT(entries_level), expMatchHdr->dllName, MatchList->count); 
                    entries_level++;
                break;
            case EXPORT_TYPE_RVA:
                printf("%s[ Export RVA: 0x%lX ]\n",
                    INDENT(entries_level), expMatchHdr->rva);
                break;
            case EXPORT_TYPE_ORDINAL:
                printf("%s[ Export Ordinal: #%lu ]\n",
                    INDENT(entries_level), expMatchHdr->ordinal); 
                break;
            default:
                printf("%s[ UNKNOWN ]\n",
                    INDENT(entries_level));
                break;
        }
    }

    // --- Loop through exports ---
    for (ULONGLONG i = 0; i < MatchList->count; i++) {
        PEXPORT_MATCH expMatch = &((PEXPORT_MATCH)MatchList->items)[i];
        RVA_INFO funcRvaInfo = get_rva_info(expMatch->rva, sections, numberOfSections, imageBase);
        RVA_INFO funcDataRvaInfo = get_rva_info(expMatch->funcRva, sections, numberOfSections, imageBase);
        
        if (expMatch->type & EXPORT_TYPE_DLL_NAME) {
            if (expMatch->nameRva) {
                    RVA_INFO nameDataRvaInfo = get_rva_info(expMatch->nameRva, sections, numberOfSections, imageBase);

                if (expMatch->isForwarded) {
                    printf("%s[ Forwarded Export: %s ]\n", INDENT(entries_level + 1), expMatch->forwarderName);
                    printf("%sFunction      : %s\n", INDENT(entries_level + 2), expMatch->funcName);
                } else {
                    printf("%s[ Export: %s ]\n", INDENT(entries_level + 1), expMatch->funcName);
                }

                printf("%sOrdinal       : #%lu\n", INDENT(entries_level + 2), expMatch->ordinal);

                printf("%sFunc RVA      : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
                    INDENT(entries_level + 2), expMatch->funcRva, funcDataRvaInfo.va, funcDataRvaInfo.fileOffset, funcDataRvaInfo.sectionName);
                printf("%sName RVA      : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
                    INDENT(entries_level + 2), expMatch->nameRva, nameDataRvaInfo.va, nameDataRvaInfo.fileOffset, nameDataRvaInfo.sectionName);


            } else if (!expMatch->isForwarded && !expMatch->nameRva) {
                printf("%s[ Export Ordinal: #%lu ]\n", INDENT(entries_level + 1), expMatch->ordinal);

                printf("%sFunc RVA      : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
                    INDENT(entries_level + 2), expMatch->funcRva, funcDataRvaInfo.va, funcDataRvaInfo.fileOffset, funcDataRvaInfo.sectionName);
            }

        } else {
            printf("%sDLL Name      : %s\n",   INDENT(entries_level + 2), expMatch->dllName);

            if ((expMatch->type & EXPORT_TYPE_ORDINAL) == 0) {
                RVA_INFO nameDataRvaInfo = get_rva_info(expMatch->nameRva, sections, numberOfSections, imageBase);

                if (expMatch->type & EXPORT_TYPE_RVA || expMatch->isForwarded) {
                    printf("%sFunction      : %s\n",   INDENT(entries_level + 2), expMatch->funcName);
                }

                printf("%sOrdinal       : #%lu\n", INDENT(entries_level + 2), expMatch->ordinal);

                printf("%sFunc RVA      : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
                    INDENT(entries_level + 2), expMatch->funcRva, funcDataRvaInfo.va, funcDataRvaInfo.fileOffset, funcDataRvaInfo.sectionName);
                printf("%sName RVA      : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
                    INDENT(entries_level + 2), expMatch->nameRva, nameDataRvaInfo.va, nameDataRvaInfo.fileOffset, nameDataRvaInfo.sectionName);
            } else {
                printf("%sFunc RVA      : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
                    INDENT(entries_level + 2), expMatch->funcRva, funcDataRvaInfo.va, funcDataRvaInfo.fileOffset, funcDataRvaInfo.sectionName);              
            }
        }

        printf("%sEAT Entry RVA : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
            INDENT(entries_level + 2), expMatch->rva, funcRvaInfo.va, funcRvaInfo.fileOffset, funcRvaInfo.sectionName);

        putchar('\n');
    }

    fflush(stdout);
    return;
}

void dump_extracted_imports(PMATCH_LIST MatchList, PIMAGE_SECTION_HEADER sections, WORD numberOfSections, ULONGLONG imageBase, int level) {
    PIMPORT_MATCH impMatchHdr = &((PIMPORT_MATCH)MatchList->items)[0];

    // printing the extraction dump header
    if (impMatchHdr->isGlobal && (impMatchHdr->type & IMPORT_TYPE_DLL_NAME) == 0) {
        switch (impMatchHdr->type) {
            case IMPORT_TYPE_NAME:    printf("%s[ Function Import: %s ]", INDENT(level), impMatchHdr->funcName); break;
            case IMPORT_TYPE_HINT:    printf("%s[ Hint Import: 0x%X ]",   INDENT(level), impMatchHdr->hint);     break;
            case IMPORT_TYPE_ORDINAL: printf("%s[ Ordinal Import: #%u ]", INDENT(level), impMatchHdr->ordinal);  break;
            default: printf("%s[ UNKNOWN ]", INDENT(level)); break;
        }
    }
    else if (!impMatchHdr->isGlobal || impMatchHdr->type & IMPORT_TYPE_DLL_NAME) {
        printf("%s[ DLL Import %s ]", INDENT(level), impMatchHdr->dllName);
    }
    
    printf(" Import Entries : %llu\n\n", MatchList->count);

    // --- Loop through imports ---
    for (ULONGLONG i = 0; i < MatchList->count; i++) {
        PIMPORT_MATCH impMatch = &((PIMPORT_MATCH)MatchList->items)[i];
        RVA_INFO thunkRvaInfo = get_rva_info(impMatch->thunkRVA, sections, numberOfSections, imageBase);

        // --- Standard imports by name / hint / ordinal ---
        if (impMatch->type & (IMPORT_TYPE_NAME | IMPORT_TYPE_HINT | IMPORT_TYPE_ORDINAL)) {
            RVA_INFO thunkDataRvaInfo = {0};

            if ((impMatch->type & IMPORT_TYPE_ORDINAL) == 0) {
                thunkDataRvaInfo = get_rva_info(impMatch->thunkDataRVA, sections, numberOfSections, imageBase);
            }

            if (impMatch->type & IMPORT_TYPE_NAME) {
                if (impMatch->isGlobal)
                    printf("%s* Import DLL: %s\n", INDENT(level + 1), impMatch->dllName);
                else
                    printf("%s* Import Function: %s\n", INDENT(level + 1), impMatch->funcName);

                printf("%sHint    : 0x%04X\n", INDENT(level + 2), impMatch->hint);
                printf("%sThunk   : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
                    INDENT(level + 2), impMatch->thunkDataRVA, thunkDataRvaInfo.va,
                    thunkDataRvaInfo.fileOffset, thunkDataRvaInfo.sectionName);
                printf("%sCallVia : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
                    INDENT(level + 2), impMatch->thunkRVA, thunkRvaInfo.va,
                    thunkRvaInfo.fileOffset, thunkRvaInfo.sectionName);
            }
            else if (impMatch->type & IMPORT_TYPE_HINT) {
                if (impMatch->isGlobal)
                    printf("%s* Import DLL: %s\n", INDENT(level + 1), impMatch->dllName);
                else
                    printf("%s* Import Hint: 0x%X\n", INDENT(level + 1), impMatch->hint);

                printf("%sFunction: %s\n", INDENT(level + 2), impMatch->funcName);
                printf("%sThunk   : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
                    INDENT(level + 2), impMatch->thunkDataRVA, thunkDataRvaInfo.va,
                    thunkDataRvaInfo.fileOffset, thunkDataRvaInfo.sectionName);
                printf("%sCallVia : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
                    INDENT(level + 2), impMatch->thunkRVA, thunkRvaInfo.va,
                    thunkRvaInfo.fileOffset, thunkRvaInfo.sectionName);
            }
            else if (impMatch->type & IMPORT_TYPE_ORDINAL) {
                if (impMatch->isGlobal)
                    printf("%s* Import DLL: %s\n", INDENT(level + 1), impMatch->dllName);
                else
                    printf("%s* Import Ordinal: 0x%X*\n", INDENT(level + 1), impMatch->ordinal);

                printf("%sCallVia : 0x%08lX [VA: %llX] [FO: %lX] [%-8s]\n",
                    INDENT(level + 2), impMatch->thunkRVA, thunkRvaInfo.va,
                    thunkRvaInfo.fileOffset, thunkRvaInfo.sectionName);
            }
        }

        // --- DLL-only section ---
        else if (impMatch->type & IMPORT_TYPE_DLL_NAME) {
            RVA_INFO thunkDataRvaInfo = get_rva_info(impMatch->thunkDataRVA, sections, numberOfSections, imageBase);

            printf("%s* IAT Entry: %llu\n", INDENT(level + 1), i + 1);

            if (impMatch->ordinal) {
                printf("%sOrdinal  : 0x%X\n", INDENT(level + 2), impMatch->ordinal);
            } else {
                printf("%sFunction : %s\n", INDENT(level + 2), impMatch->funcName);
                printf("%sHint     : 0x%04X\n", INDENT(level + 2), impMatch->hint);
            }

            if (!impMatch->ordinal) {
                printf("%sThunk    : 0x%08lX [VA: %llX] [FO: %lX] [%-8s]\n",
                    INDENT(level + 2), impMatch->thunkDataRVA, thunkDataRvaInfo.va,
                    thunkDataRvaInfo.fileOffset, thunkDataRvaInfo.sectionName);
            } else {
                printf("%sThunk    : 0x%016llX\n", INDENT(level + 2), impMatch->rawOrd);
            }

            printf("%sCallVia  : 0x%08lX [VA: %llX] [FO: %lX] [%-8s]\n",
                INDENT(level + 2), impMatch->thunkRVA, thunkRvaInfo.va,
                thunkRvaInfo.fileOffset, thunkRvaInfo.sectionName);
        }

        putchar('\n');
    }

    fflush(stdout);
    return;
}
