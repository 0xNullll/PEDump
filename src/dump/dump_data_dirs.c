#include "../include/dump_data_dirs.h"

RET_CODE dump_exported_functions(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY ExportDirData,
    PIMAGE_EXPORT_DIRECTORY ExportDir,
    PDWORD EAT,
    PDWORD NameRVAArray,
    PWORD  NameOrdinalArray,
    ULONGLONG imageBase)  {
        
    ULONGLONG vaBase = imageBase + ExportDir->AddressOfFunctions;
    DWORD foBase;
    if (rva_to_offset(ExportDir->AddressOfFunctions, sections, numberOfSections, &foBase) != RET_SUCCESS) {
        return RET_ERROR;
    }

    printf("\n\t\t  ==== EXPORTED FUNCTIONS [%u %s] ====\n\n",
           (unsigned)ExportDir->NumberOfFunctions,
           ExportDir->NumberOfFunctions == 1 ? "entry" : "entries");

    WORD vaOffDigit = count_digits(vaBase);
    WORD foOffDigit = count_digits(foBase);

    printf("%-*s%-*s  %-4s %-8s %-8s %-8s %-80s %s\n",
           vaOffDigit, "VA", foOffDigit, "FO", "Idx", "Ordinal", "Func-RVA", "Name-RVA", "Name", "Forwarded-To");

    for (DWORD funcIdx = 0; funcIdx < ExportDir->NumberOfFunctions; funcIdx++) {
        DWORD funcRVA = EAT[funcIdx];
        DWORD nameRVA = 0;
        char funcName[256] = {0};
        char forwardName[256] = {0};
        int hasName = 0;

        // Resolve function name
        for (DWORD j = 0; j < ExportDir->NumberOfNames; j++) {
            if (NameOrdinalArray[j] == funcIdx) {
                nameRVA = NameRVAArray[j];
                DWORD nameOffset;
                if (rva_to_offset(nameRVA, sections, numberOfSections, &nameOffset) == RET_SUCCESS &&
                    FSEEK64(peFile, nameOffset, SEEK_SET) == 0) {
                    fread(funcName, 1, sizeof(funcName) - 1, peFile);
                }
                hasName = 1;
                break;
            }
        }

        // Resolve forwarder name
        if (funcRVA >= ExportDirData->VirtualAddress &&
            funcRVA < ExportDirData->VirtualAddress + ExportDirData->Size) {
            DWORD fwdOffset;
            if (rva_to_offset(funcRVA, sections, numberOfSections, &fwdOffset) == RET_SUCCESS &&
                FSEEK64(peFile, fwdOffset, SEEK_SET) == 0) {
                fread(forwardName, 1, sizeof(forwardName) - 1, peFile);
            }
        }

        // Decide which strings to print
        char *printFuncName = funcName[0] ? funcName : "-";
        char *printForwardName = forwardName[0] ? forwardName : " ";

        printf("%llX %lX   %-4lu %-8lX %08lX %-8s %-80s %s\n",
               vaBase, foBase,
               funcIdx + 1,
               funcIdx + ExportDir->Base,
               funcRVA,
               hasName ? str_to_hex(nameRVA) : "0",
               printFuncName,
               printForwardName);

        vaBase += sizeof(DWORD);
        foBase += sizeof(DWORD);
    }

    printf("\n\t\t  ==== END FO EXPORTED FUNCTIONS ====\n\n");
    fflush(stdout);
    return RET_SUCCESS;
}

RET_CODE dump_export_dir(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY ExportDirData,
    PIMAGE_EXPORT_DIRECTORY ExportDir,
    ULONGLONG imageBase) {

    if (!peFile || !ExportDirData || !ExportDir)
        return RET_INVALID_PARAM;

    // completely empty = skip gracefully
    if (ExportDirData->VirtualAddress == 0 && ExportDirData->Size == 0)
        return RET_MALFORMED_FILE;

    // partially defined = suspicious
    if (ExportDirData->VirtualAddress == 0 || ExportDirData->Size == 0)
        return REPORT_MALFORMED("Export directory partially empty (RVA=0 or Size=0)", "Export Data Directory");


    ULONGLONG vaBase = imageBase + ExportDirData->VirtualAddress;
    DWORD foBase;
    if (rva_to_offset(ExportDirData->VirtualAddress, sections, numberOfSections, &foBase) != RET_SUCCESS) {
        return RET_ERROR;
    }

    // Try to resolve DLL name string from section        
    char ExportName[MAX_DLL_NAME] = {0};

    SECTION_INFO secExportName = get_section_info(ExportDir->Name, sections, numberOfSections);
    if (secExportName.size != 0) {
        if (ExportDir->Name - secExportName.virtualAddress < secExportName.size) {
            if (FSEEK64(peFile, secExportName.rawOffset + ExportDir->Name - secExportName.virtualAddress, SEEK_SET) != 0) return RET_ERROR;
            fread(ExportName, 1, MAX_DLL_NAME - 1, peFile);
            ExportName[MAX_DLL_NAME - 1] = '\0'; // safety null-termination
        } else {
            strcpy(ExportName, "<invalid>");
        }
    } else {
        strcpy(ExportName, "<invalid>");
    }

    printf("\n%016llX\t- EXPORTS DIRECTORY -\n\n", vaBase);

    printf("VA                FO        Size        Value\n");

    printf("%016llX  %08lX  [4]\t\tCharacteristics     : %08lX\n\n",
    vaBase, foBase, ExportDir->Characteristics);

    vaBase += 4; foBase += 4;

    DWORD ts = ExportDir->TimeDateStamp;

    if ((ts >= SOME_REASONABLE_EPOCH && ts <= CURRENT_EPOCH_PLUS_MARGIN) || ts == 0) {
        printf("%016llX  %08lX  [4]\t\tTime Date Stamp     : %08lX  %s\n\n", 
            vaBase, foBase, ts, format_timestamp(ts));
    } else {
        printf("%016llX  %08lX  [4]\t\tReproChecksum       : %08lX (%lu)\n\n", 
            vaBase, foBase, ts, ts);
    }


    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [2]\t\tMajor Version       : %04X\n",
    vaBase, foBase, ExportDir->MajorVersion);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tMinor Version       : %04X\n\n",
    vaBase, foBase, ExportDir->MinorVersion);

    vaBase += 2; foBase += 2;

    RVA_INFO ExportNameRvaInfo = get_rva_info(ExportDir->Name, sections, numberOfSections, imageBase);

    printf("%016llX  %08lX  [4]\t\tExport DLL Name RVA : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n",
    vaBase, foBase, ExportDir->Name, ExportNameRvaInfo.va, ExportNameRvaInfo.fileOffset, ExportNameRvaInfo.sectionName);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX [%-2zu]\t\tExport Table Name   : %s\n\n",
        ExportNameRvaInfo.va, ExportNameRvaInfo.fileOffset,
        strlen(ExportName), ExportName);

    printf("%016llX  %08lX  [4]\t\tBase                : %08lX\n\n",
    vaBase, foBase, ExportDir->Base);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tNumber Of Functions : %08lX  (%u)\n",
    vaBase, foBase, ExportDir->NumberOfFunctions, (unsigned) ExportDir->NumberOfFunctions);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tNumber Of Names     : %08lX  (%u)\n\n",
    vaBase, foBase, ExportDir->NumberOfNames, (unsigned) ExportDir->NumberOfNames);

    vaBase += 4; foBase += 4;
    
    RVA_INFO FuncRVAInfo = get_rva_info(ExportDir->AddressOfFunctions, sections, numberOfSections, imageBase);

    printf("%016llX  %08lX  [4]\t\tFunctions RVA       : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n",
    vaBase, foBase, ExportDir->AddressOfFunctions, FuncRVAInfo.va, FuncRVAInfo.fileOffset, FuncRVAInfo.sectionName);

    vaBase += 4; foBase += 4;

    RVA_INFO NameRVAInfo = get_rva_info(ExportDir->AddressOfNames, sections, numberOfSections, imageBase);

    printf("%016llX  %08lX  [4]\t\tNames RVA           : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n",
    vaBase, foBase, ExportDir->AddressOfNames, NameRVAInfo.va, NameRVAInfo.fileOffset, NameRVAInfo.sectionName);

    vaBase += 4; foBase += 4;

    RVA_INFO OrdinalRVAInfo = get_rva_info(ExportDir->AddressOfNameOrdinals, sections, numberOfSections, imageBase);

    printf("%016llX  %08lX  [4]\t\tName Ordinals RVA   : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n\n",
    vaBase, foBase, ExportDir->AddressOfNameOrdinals, OrdinalRVAInfo.va, OrdinalRVAInfo.fileOffset, OrdinalRVAInfo.sectionName);

    vaBase += 4; foBase += 4;

    DWORD *EAT = parse_table_from_rva(peFile, ExportDir->AddressOfFunctions,
                                    sizeof(DWORD), ExportDir->NumberOfFunctions,
                                    sections, numberOfSections);

    DWORD *NameRVAArray = parse_table_from_rva(peFile, ExportDir->AddressOfNames,
                                            sizeof(DWORD), ExportDir->NumberOfNames,
                                            sections, numberOfSections);

    WORD *NameOrdinalArray = parse_table_from_rva(peFile, ExportDir->AddressOfNameOrdinals,
                                                sizeof(WORD), ExportDir->NumberOfNames,
                                                sections, numberOfSections);

    if (dump_exported_functions(peFile, sections, numberOfSections, ExportDirData, ExportDir, EAT, NameRVAArray, NameOrdinalArray, imageBase) != RET_SUCCESS) {
        printf("[!!] Failed to dump Exported Functions\n");
        return RET_ERROR;
    }

    return RET_SUCCESS;
}

BOOL read_import_hint_and_name(
    FILE *peFile,
    DWORD rva,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PWORD hintOut,
    char *nameOut) {
        
    if (!peFile || !hintOut || !nameOut) return FALSE;

    DWORD offset;
    if (rva_to_offset(rva, sections, numberOfSections, &offset) != RET_SUCCESS)
        return FALSE;

    FSEEK64(peFile, offset, SEEK_SET);
    if (fread(hintOut, sizeof(WORD), 1, peFile) != 1) return FALSE;

    ULONGLONG j = 0;
    int c;
    while (j < MAX_FUNC_NAME - 1 && (c = fgetc(peFile)) != EOF && c != '\0') {
        nameOut[j++] = (char)c;
    }
    nameOut[j] = '\0';
    return TRUE;
}

RET_CODE dump_int_table(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    DWORD OriginalFirstThunk,
    DWORD FirstThunk,
    ULONGLONG imageBase,
    int is64bit) {
    if (!peFile || !OriginalFirstThunk) return RET_INVALID_PARAM; 

    // --- ORIGINAL FIRST THUNK LOOP ---
    // Count INT entries (functions imported)
    ULONGLONG numImports = count_thunks(peFile, OriginalFirstThunk, sections, numberOfSections, is64bit);

    // --- INT / OriginalFirstThunk ---
    RVA_INFO ThunkRVAInfo = get_rva_info(OriginalFirstThunk, sections, numberOfSections, imageBase);

    printf("\n\n\n%016llX\t  HINT NAME TABLE: %llu %s\n\n",
        ThunkRVAInfo.va, numImports, numImports < 2 ? "Entry" : "Enties");

    // Jump to INT location (OriginalFirstThunk, fallback to FirstThunk if zero)
    DWORD INToffset;
    DWORD rvaINT = OriginalFirstThunk ? OriginalFirstThunk
                                                : FirstThunk;

    if (rva_to_offset(rvaINT, sections, numberOfSections, &INToffset) != RET_SUCCESS) {
        return RET_ERROR;
    }

    if (FSEEK64(peFile, INToffset, SEEK_SET) != 0) return RET_ERROR;

    ULONGLONG vaBase = ThunkRVAInfo.va;
    DWORD foBase     = ThunkRVAInfo.fileOffset;

    IMAGE_THUNK_DATA64 thunk64 = {0};
    IMAGE_THUNK_DATA32 thunk32 = {0};

    // Walk through thunk entries
    for (int entry = 0;; entry++) {
        ULONGLONG ordinal = 0;
        // DWORD addressOfDataOffset = 0;
        WORD hint = 0;
        char name[MAX_FUNC_NAME] = {0};

        LONGLONG thunkOffset = FTELL64(peFile);

        if (is64bit) {
            // Read 64-bit thunk entry
            if (fread(&thunk64, sizeof(thunk64), 1, peFile) != 1 || thunk64.u1.AddressOfData == 0)
                break;

            // Import by ordinal
            if (IMAGE_SNAP_BY_ORDINAL64(thunk64.u1.Ordinal)) {
                ordinal = IMAGE_ORDINAL64(thunk64.u1.Ordinal);

                printf("%016llX  \t\t\t\t\t     %lX  [8]      Hint/Ordinal : #%04hX (%hu)\n\n",
                    vaBase, foBase, (WORD)ordinal, (WORD)ordinal);

            } else {
                if (!read_import_hint_and_name(peFile, (DWORD)thunk64.u1.AddressOfData, sections, numberOfSections, &hint, name)) {
                    fprintf(stderr, "[!!!] Failed to read thunk hint and name of thunk number: %d\n", entry + 1);
                    vaBase += sizeof(thunk64); foBase += sizeof(thunk64);
                    continue;
                }

                // printing
                RVA_INFO HintNameRvaInfo = get_rva_info((DWORD)thunk64.u1.AddressOfData, sections, numberOfSections, imageBase);

                printf("%016llX  %08lX  [8]\t\t[VA: %llX] [FO: %lX] [  %-8s]\n",
                vaBase, foBase, HintNameRvaInfo.va, HintNameRvaInfo.fileOffset, HintNameRvaInfo.sectionName);             

                vaBase += sizeof(thunk64); foBase += sizeof(thunk64);

                printf("%016llX  \t\t\t\t\t     %lX  [  2]            Hint : %04hX  (%hu)\n",
                HintNameRvaInfo.va, HintNameRvaInfo.fileOffset, hint, hint);

                printf("%016llX  \t\t\t\t\t     %lX  [%3zu]            Name : %s\n\n",
                HintNameRvaInfo.va + 2, HintNameRvaInfo.fileOffset + 2, strlen(name), name);

                FSEEK64(peFile, (ULONGLONG)thunkOffset + sizeof(thunk64), SEEK_SET);
            }
            vaBase += sizeof(thunk64); foBase += sizeof(thunk64);
        } else {
            // Read 32-bit thunk entry
            if (fread(&thunk32, sizeof(thunk32), 1, peFile) != 1 || thunk32.u1.AddressOfData == 0)
                break;

            // Import by ordinal
            if (IMAGE_SNAP_BY_ORDINAL32(thunk32.u1.Ordinal)) {
                ordinal = IMAGE_ORDINAL32(thunk32.u1.Ordinal);

                printf("%016llX  \t\t\t\t\t     %lX  [4]      Hint/Ordinal :  #%04hX (%hu)\n\n",
                vaBase, foBase, (WORD)ordinal, (WORD)ordinal);

            } else {
                if (!read_import_hint_and_name(peFile, thunk32.u1.AddressOfData, sections, numberOfSections, &hint, name)) {
                    fprintf(stderr, "[!!!] Failed to read thunk hint and name of thunk number: %d\n", entry + 1);
                    vaBase += sizeof(thunk32); foBase += sizeof(thunk32);
                    continue;
                }

                // printing
                RVA_INFO HintNameRvaInfo = get_rva_info(thunk32.u1.AddressOfData, sections, numberOfSections, imageBase);

                printf("%016llX  %08lX  [4]\t\t[VA: %llX] [FO: %lX] [  %-8s]\n",
                vaBase, foBase, HintNameRvaInfo.va, HintNameRvaInfo.fileOffset, HintNameRvaInfo.sectionName);             

                printf("%016llX  \t\t\t\t\t     %lX  [  2]            Hint : %04hX  (%hu)\n",
                HintNameRvaInfo.va, HintNameRvaInfo.fileOffset, hint, hint);

                printf("%016llX  \t\t\t\t\t     %lX  [%3zu]            Name : %s\n\n",
                HintNameRvaInfo.va + 2, HintNameRvaInfo.fileOffset + 2, strlen(name), name);

                FSEEK64(peFile, (ULONGLONG)thunkOffset + sizeof(thunk32), SEEK_SET);
            }
            vaBase += sizeof(thunk32); foBase += sizeof(thunk32);
        }
    }

    fflush(stdout);
    
    return RET_SUCCESS;
}

RET_CODE dump_iat_table(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    DWORD FirstThunk,
    ULONGLONG imageBase,
    int is64bit,
    LONGLONG fileSize) {
    if (!peFile || !FirstThunk || fileSize <= 0) return RET_INVALID_PARAM; 

    // --- FIRST THUNK OFFSET ---
    DWORD iatOffset;
    if (rva_to_offset(FirstThunk, sections, numberOfSections, &iatOffset) != RET_SUCCESS)
        return RET_ERROR;

    // --- IAT / FirstThunk RVA info ---
    RVA_INFO ImportTableRvaInfo = get_rva_info(FirstThunk, sections, numberOfSections, imageBase);

    ULONGLONG numIAT = count_thunks(peFile, FirstThunk, sections, numberOfSections, is64bit);

    printf("\n\n\n%016llX\t  IMPORT ADDRESS TABLE: %llu %s\n\n",
        ImportTableRvaInfo.va, numIAT, numIAT < 2 ? "Entry" : "Entries");

    if (FSEEK64(peFile, iatOffset, SEEK_SET) != 0) return RET_ERROR;

    ULONGLONG FirstThunkVaBase = ImportTableRvaInfo.va;
    DWORD FirstThunkOfBase     = ImportTableRvaInfo.fileOffset;

    // Size of one thunk entry
    ULONGLONG thunkSize = is64bit ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);

    // Maximum number of thunks we can safely read without going past the file
    DWORD maxSafeThunks = (DWORD)(((DWORD)fileSize - iatOffset) / thunkSize);
    if ((DWORD)numIAT > maxSafeThunks) {
        printf("[WARN] IAT size exceeds file bounds, truncating to safe limit.\n");
        numIAT = (ULONGLONG)maxSafeThunks;
    }

    // Walk through IAT entries
    for (ULONGLONG j = 0; j < numIAT; j++) {
        ULONGLONG value = 0;

        if (is64bit) {
            IMAGE_THUNK_DATA64 t;
            if (fread(&t, sizeof(t), 1, peFile) != 1) return RET_ERROR;
            value = t.u1.AddressOfData;
        } else {
            IMAGE_THUNK_DATA32 t;
            if (fread(&t, sizeof(t), 1, peFile) != 1) return RET_ERROR;
            value = t.u1.AddressOfData;
        }

        printf("%016llX  %08llX  [%zu]\t\t%8llX\n",
            FirstThunkVaBase + j * thunkSize,
            FirstThunkOfBase + j * thunkSize,
            thunkSize,
            value);
    }

    fflush(stdout);
    return RET_SUCCESS;
}

void print_import_descriptor_header(
    FILE *peFile,
    PIMAGE_IMPORT_DESCRIPTOR desc,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PULONGLONG vaBase,
    PDWORD foBase,
    ULONGLONG imageBase,
    int index) {

    char dllName[MAX_DLL_NAME] = {0};

    if (!read_import_dll_name(peFile, desc, sections, numberOfSections, dllName)) {
        strcpy(dllName, "<invalid>"); 
    }

    printf("%016llX\tIMPORT descriptor: %d  - Library: %s\n\n",
        *vaBase, index + 1, dllName);

    printf("VA                FO        Size        Value\n");

    RVA_INFO ThunkRVAInfo = get_rva_info(desc->OriginalFirstThunk, sections, numberOfSections, imageBase);

    printf("%016llX  %08lX  [ 4]\tHint name table       : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n\n",
        *vaBase, *foBase, desc->OriginalFirstThunk,
        ThunkRVAInfo.va, ThunkRVAInfo.fileOffset, ThunkRVAInfo.sectionName);

    *vaBase += 4; *foBase += 4;

    DWORD ts = desc->TimeDateStamp;

    if ((ts >= SOME_REASONABLE_EPOCH && ts <= CURRENT_EPOCH_PLUS_MARGIN) || ts == 0) {
        printf("%016llX  %08lX  [ 4]\tTime Date Stamp       : %08lX  %s\n\n", 
            *vaBase, *foBase, ts, format_timestamp(ts));
    } else {
        printf("%016llX  %08lX  [ 4]\tReproChecksum         : %08lX (%lu)\n\n", 
            *vaBase, *foBase, ts, ts);
    }

    *vaBase += 4; *foBase += 4;

    printf("%016llX  %08lX  [ 4]\tForwarder chain       : %08lX\n\n",
        *vaBase, *foBase, desc->ForwarderChain);

    *vaBase += 4;
    *foBase += 4;

    RVA_INFO LibNameRvaInfo = get_rva_info(desc->Name, sections, numberOfSections, imageBase);

    printf("%016llX  %08lX  [ 4]\tLibrary name RVA      : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n",
        *vaBase, *foBase, desc->Name,
        LibNameRvaInfo.va, LibNameRvaInfo.fileOffset, LibNameRvaInfo.sectionName);

    *vaBase += 4; *foBase += 4;

    printf("%016llX  %08lX  [%2zu]\tImports library name  : %s\n\n",
        LibNameRvaInfo.va, LibNameRvaInfo.fileOffset,
        strlen(dllName), dllName);

    RVA_INFO ImportTableRvaInfo = get_rva_info(desc->FirstThunk, sections, numberOfSections, imageBase);

    printf("%016llX  %08lX  [ 4]\tImport address table  : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n\n",
        *vaBase, *foBase, desc->FirstThunk, 
        ImportTableRvaInfo.va, ImportTableRvaInfo.fileOffset, ImportTableRvaInfo.sectionName);

    *vaBase += 4; *foBase += 4;
}

RET_CODE dump_import_dir(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY importDirData,
    PIMAGE_IMPORT_DESCRIPTOR importDir,
    ULONGLONG imageBase,
    int is64bit,
    LONGLONG fileSize) {
    if (!peFile || !importDirData || !importDir) return RET_INVALID_PARAM;   // sanity check

    // completely empty = skip gracefully
    if (importDirData->VirtualAddress == 0 && importDirData->Size == 0)
        return RET_MALFORMED_FILE;

    // partially defined = suspicious
    if (importDirData->VirtualAddress == 0 || importDirData->Size == 0)
        return REPORT_MALFORMED("Import directory partially empty (RVA=0 or Size=0)", "Import Data Directory");

    ULONGLONG vaBase = imageBase + importDirData->VirtualAddress;   

    DWORD foBase;
    if (rva_to_offset(importDirData->VirtualAddress, sections, numberOfSections, &foBase) != RET_SUCCESS) {
        return RET_ERROR;
    } 

    WORD count = count_imp_descriptors(importDir);

    // Print import directory header
    printf("\n%016llX\t- IMPORT DIRECTORY - number of import descriptors: %d\n\n",
        vaBase, count);

    for (WORD i = 0; i < count; i++) {
        // setup
        ULONGLONG numIAT = count_thunks(peFile, importDir[i].FirstThunk, sections, numberOfSections, is64bit);

        // --- DLL import descriptor header print ---
        print_import_descriptor_header(
            peFile,
            &importDir[i],
            sections,
            numberOfSections,
            &vaBase,
            &foBase,
            imageBase,
            i);

        // --- ORIGINAL FIRST THUNK LOOP ---
        if (dump_int_table(
            peFile,
            sections,
            numberOfSections,
            importDir[i].OriginalFirstThunk,
            importDir[i].FirstThunk,
            imageBase,
            is64bit) != RET_SUCCESS) {
            printf("[!!] Failed to dump INT Table number: %d\n", i + 1);
        }

        // --- FIRST THUNK LOOP ---
        if (dump_iat_table(
            peFile,
            sections,
            numberOfSections,
            importDir[i].FirstThunk,
            imageBase,
            is64bit,
            fileSize) != RET_SUCCESS) {
            printf("[!!] Failed to dump IAT Table number: %d\n", i + 1);
        }

        // End of one DLL import descriptor
        printf("\n------------- END FO IMPORT DESCRIPTOR %d (%llu function%s) -------------\n\n", 
            i + 1, numIAT, numIAT == 1 ? "" : "s");

        fflush(stdout);
    }

    return RET_SUCCESS;
}

RET_CODE dump_rsrc_entries(
    FILE *peFile,
    DWORD entryOffset,
    WORD totalOfSubEntries,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    SECTION_INFO *rsrcSecInfo,
    int level,
    ULONGLONG imageBase) {
    if (!peFile || !rsrcSecInfo || !entryOffset || !totalOfSubEntries) return RET_INVALID_PARAM;   // sanity check

    DWORD entriesRva = 0;
    if (offset_to_rva(entryOffset, sections, numberOfSections, &entriesRva) != RET_SUCCESS) {
        printf("[!!] Failed to convert file offset to RVA\n");
        return RET_ERROR;
    }

    PIMAGE_RESOURCE_DIRECTORY_ENTRY entries_array = parse_table_from_fo(
        peFile, entryOffset, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), totalOfSubEntries
    );

    if (!entries_array) {
        printf("[!!] Failed to allocate memory for entries_array\n");
        return RET_ERROR;
    }

    for (int i = 0; i < totalOfSubEntries; i++) {
        ULONGLONG entryVA = imageBase + entriesRva + (ULONGLONG)i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
        DWORD entryFO = (DWORD)(entryOffset + (ULONGLONG)i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));

        BYTE *stringBuf = NULL;
        WORD stringLength = 0;
        int isUnicode = 0;

        // ---------------------------
        // Handle Name field (string)
        // ---------------------------
        if (entries_array[i].NameIsString) {
            DWORD nameFO = rsrcSecInfo->rawOffset + (entries_array[i].NameOffset & 0x7FFFFFFF);
            if (FSEEK64(peFile, nameFO, SEEK_SET)) continue;

            if (fread(&stringLength, sizeof(WORD), 1, peFile) != 1) continue;
            if (stringLength == 0) continue;

            stringBuf = malloc(stringLength * 2);
            if (!stringBuf) continue;

            if (fread(stringBuf, 1, stringLength * 2, peFile) != stringLength * 2) {
                SAFE_FREE(stringBuf);
                continue;
            }

            isUnicode = IsUnicodeString(stringBuf, stringLength * 2);
        }

        // ---------------------------
        // Subdirectory or Data Entry
        // ---------------------------
        if (entries_array[i].DataIsDirectory) {
            DWORD subDirOffset = rsrcSecInfo->rawOffset + (entries_array[i].OffsetToDirectory & 0x7FFFFFFF);

            // Print subdirectory
            printf("%ssubDir: #%d (ID=0x%lX, Named=", INDENT(level), i + 1, (ULONG)entries_array[i].Id);
            if (entries_array[i].NameIsString) {
                if (isUnicode) {
                    WCHAR *wstr = (WCHAR*)stringBuf;
                    for (WORD c = 0; c < stringLength; c++) wprintf(L"%c", wstr[c]);
                } else {
                    printf("%.*s", stringLength, stringBuf);
                }
            } else {
                printf("N/A"); 
            }
            printf(") [VA=%llX, FO=%lX]\n", entryVA, entryFO);

            if (dump_rsrc_sub_dir(
                peFile,
                subDirOffset,
                sections,
                numberOfSections,
                rsrcSecInfo,
                level + 1,
                imageBase) != RET_SUCCESS) {
                printf("[!!] Failed to dump Resource Sub Directory level %d\n", level + 1);
            }

        } else {
            // Leaf -> IMAGE_RESOURCE_DATA_ENTRY
            DWORD dataEntryOffset = rsrcSecInfo->rawOffset + (entries_array[i].OffsetToData & 0x7FFFFFFF);
            IMAGE_RESOURCE_DATA_ENTRY dataEntry;

            FSEEK64(peFile, dataEntryOffset, SEEK_SET);
            fread(&dataEntry, sizeof(dataEntry), 1, peFile);

            // Print entry
            printf("%sEntry: (Lang=0x%lX -> %s, named=", INDENT(level), (ULONG)entries_array[i].Id, Get_resource_Lang_Name(entries_array[i].Id));
            if (entries_array[i].NameIsString) {
                if (isUnicode) {
                    WCHAR *wstr = (WCHAR*)stringBuf;
                    for (WORD c = 0; c < stringLength; c++) wprintf(L"%c", wstr[c]);
                } else {
                    printf("%.*s", stringLength, stringBuf);
                }
            } else {
                printf("N/A"); 
            }
           printf(") [VA=%llX, FO=%lX]\n", entryVA, entryFO);

            DWORD dataOff; 
            if (rva_to_offset(dataEntry.OffsetToData, sections, numberOfSections, &dataOff) != RET_SUCCESS) {
                dataOff = 0;
            }  

            // Print data info
            printf("%s    Data Offsets: (RVA=%lX FO=%lX), Size=0x%lX (%u), CodePage=0x%lX, Reserved=%u\n",
                   INDENT(level + 1),
                   dataEntry.OffsetToData,
                   dataOff,
                   dataEntry.Size,
                   (unsigned)dataEntry.Size,
                   dataEntry.CodePage,
                   (unsigned)dataEntry.Reserved);
        }

        if (stringBuf) {
            SAFE_FREE(stringBuf);
            stringBuf = NULL;
        }
    }

    SAFE_FREE(entries_array);
    printf("\n");

    fflush(stdout);
    return RET_SUCCESS;
}

RET_CODE dump_rsrc_sub_dir(
    FILE *peFile,
    DWORD subDirOffset,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    SECTION_INFO *rsrcSecInfo, int level,
    ULONGLONG imageBase) {
    if (!peFile || !rsrcSecInfo || !subDirOffset) return RET_INVALID_PARAM;   // sanity check

            // Read the subdir header
            IMAGE_RESOURCE_DIRECTORY subDir;
            if (FSEEK64(peFile, subDirOffset, SEEK_SET) != 0) return RET_ERROR;
            if (fread(&subDir, sizeof(subDir), 1, peFile) != 1) return RET_ERROR;

            // Pretty-print subdir header
            DWORD tsSubDir = subDir.TimeDateStamp;
            char tsSubDirStr[64];
            if ((tsSubDir >= SOME_REASONABLE_EPOCH && tsSubDir <= CURRENT_EPOCH_PLUS_MARGIN) || tsSubDir == 0) {
                snprintf(tsSubDirStr, sizeof(tsSubDirStr), "TimeDateStamp=%08lX %s", tsSubDir, format_timestamp(tsSubDir));
            } else {
                snprintf(tsSubDirStr, sizeof(tsSubDirStr), "ReproChecksum=%lX", tsSubDir);
            }

            printf("%sCharacteristics=0x%lX, %s, Version=%u.%u, NamedEntries=%u, IDEntries=%u\n\n",
                INDENT(level),
                subDir.Characteristics,
                tsSubDirStr,
                (unsigned)subDir.MajorVersion,
                (unsigned)subDir.MinorVersion,
                (unsigned)subDir.NumberOfNamedEntries,
                (unsigned)subDir.NumberOfIdEntries);

            // Entries immediately follow this subdir header
            DWORD entriesFoNext = subDirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);
            WORD  totalOfSubEntries = subDir.NumberOfNamedEntries + subDir.NumberOfIdEntries;

            // Recurse into the entries table at the next level
            if (dump_rsrc_entries(peFile,
                                entriesFoNext,
                                totalOfSubEntries,
                                sections,
                                numberOfSections,
                                rsrcSecInfo,
                                level,
                                imageBase) != RET_SUCCESS) {
                printf("[!!] Failed to dump Resource Entries level %d\n", level + 1);
            }

    fflush(stdout);

    return RET_SUCCESS;
}

RET_CODE dump_rsrc_dir(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY rsrcDataDir,
    PIMAGE_RESOURCE_DIRECTORY rsrcDir,
    PIMAGE_RESOURCE_DIRECTORY_ENTRY rsrcEntriesDir,
    ULONGLONG imageBase) {
    if (!peFile || !rsrcDataDir || !rsrcDir) return RET_INVALID_PARAM; // sanity check

    // completely empty = skip gracefully
    if (rsrcDataDir->VirtualAddress == 0 && rsrcDataDir->Size == 0)
        return RET_MALFORMED_FILE;

    // partially defined = suspicious
    if (rsrcDataDir->VirtualAddress == 0 || rsrcDataDir->Size == 0)
        return REPORT_MALFORMED("Resource directory partially empty (RVA=0 or Size=0)", "Resource Data Directory");

    ULONGLONG vaBase = imageBase + rsrcDataDir->VirtualAddress;

    DWORD foBase = 0;
    if (rva_to_offset(rsrcDataDir->VirtualAddress, sections, numberOfSections, &foBase) != RET_SUCCESS) {
        return RET_ERROR;
    }

    int level = 0;
             
    // Print resource directory header (root)
    printf("\n\t\t\t\t  - RESOURCE DIRECTORY -\n\n");
    printf("Root Directory (VA=%llX, FO=%lX):\n", vaBase, foBase);

    level += 1;

    // Timestamp pretty-print
    DWORD ts = rsrcDir->TimeDateStamp;
    char tsStr[64];
    if ((ts >= SOME_REASONABLE_EPOCH && ts <= CURRENT_EPOCH_PLUS_MARGIN) || ts == 0) {
        snprintf(tsStr, sizeof(tsStr), "TimeDateStamp=%08lX %s", ts, format_timestamp(ts));
    } else {
        snprintf(tsStr, sizeof(tsStr), "ReproChecksum=%lX", ts);
    }

    // Print root directory fields (Version as Major.Minor)
    printf("%sCharacteristics=0x%lX, %s, Version=%u.%u, NamedEntries=%u, IDEntries=%u\n\n\n",
           INDENT(level),
           rsrcDir->Characteristics,
           tsStr,
           (unsigned)rsrcDir->MajorVersion,
           (unsigned)rsrcDir->MinorVersion,
           (unsigned)rsrcDir->NumberOfNamedEntries,
           (unsigned)rsrcDir->NumberOfIdEntries);

    // Compute the base of the root *entries table* (immediately after the header)
    ULONGLONG entriesVA = vaBase + sizeof(IMAGE_RESOURCE_DIRECTORY);
    DWORD     entriesFO = foBase + sizeof(IMAGE_RESOURCE_DIRECTORY);

    SECTION_INFO rsrcSecInfo = get_section_info(rsrcDataDir->VirtualAddress, sections, numberOfSections);

    WORD totalOfEntries = rsrcDir->NumberOfNamedEntries + rsrcDir->NumberOfIdEntries;

    for (int i = 0; i < totalOfEntries; i++) {
        // Compute this entry's own VA/FO (do NOT bump shared bases; compute per-index)
        ULONGLONG entryVA = entriesVA + (ULONGLONG)i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
        DWORD     entryFO = (DWORD)(entriesFO + (DWORD)i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));

        BYTE *stringBuf = NULL;
        WORD stringLength = 0;
        int isUnicode = 0;
        
        // ---------------------------
        // Handle Name field (string)
        // ---------------------------
        if (rsrcEntriesDir[i].NameIsString) {
            DWORD nameFO = rsrcSecInfo.rawOffset + (rsrcEntriesDir[i].NameOffset & 0x7FFFFFFF);
            if (FSEEK64(peFile, nameFO, SEEK_SET)) continue;

            if (fread(&stringLength, sizeof(WORD), 1, peFile) != 1) continue;
            if (stringLength == 0) continue;

            stringBuf = malloc(stringLength * 2);
            if (!stringBuf) continue;

            if (fread(stringBuf, 1, stringLength * 2, peFile) != stringLength * 2) {
                SAFE_FREE(stringBuf);
                continue;
            }

            isUnicode = IsUnicodeString(stringBuf, stringLength * 2);
        }

        char nameBuf[256];
        const char* subDirId = get_resource_type_name(rsrcEntriesDir[i].Id);

        if (strcmp(subDirId, "UNKNOWN") == 0) {
            if (rsrcEntriesDir[i].NameIsString) {
                if (isUnicode) {
                    WCHAR *wstr = (WCHAR*)stringBuf;
                    int len = 0;
                    for (WORD c = 0; c < stringLength; c++) {
                        len += sprintf(nameBuf + len, "%lc", wstr[c]);
                    }
                } else {
                    snprintf(nameBuf, sizeof(nameBuf), "%.*s", stringLength, stringBuf);
                }
                subDirId = nameBuf; // point to constructed name
            }
        }

        // Print the TYPE-level entry line
        printf("%ssubDir: %s (ID=0x%lX, Named=", INDENT(level), subDirId, (ULONG)rsrcEntriesDir[i].Id);
        if (rsrcEntriesDir[i].NameIsString) {
            if (isUnicode) {
                WCHAR *wstr = (WCHAR*)stringBuf;
                for (WORD c = 0; c < stringLength; c++) wprintf(L"%c", wstr[c]);
            } else {
                printf("%.*s", stringLength, stringBuf);
            }
        } else {
            printf("N/A"); 
        }
        printf(") [VA=%llX, FO=%lX]\n", entryVA, entryFO);

        // If this entry is not a directory, skip (it would be a leaf data entry at this level, which is unusual for root)
        if (!rsrcEntriesDir[i].DataIsDirectory) {
            // You could handle a leaf here by reading IMAGE_RESOURCE_DATA_ENTRY
            // but for TYPE level it should normally be a subdirectory.

            REPORT_MALFORMED("Resource root entry is not a directory", "Resource Directory Entry");
            return RET_MALFORMED_FILE;
            continue;
        }

        // sub-directory header lives at: .rsrc raw base + (OffsetToDirectory & 0x7FFFFFFF)
        DWORD subDirOffset = rsrcSecInfo.rawOffset + (rsrcEntriesDir[i].OffsetToDirectory & 0x7FFFFFFF);

        if (dump_rsrc_sub_dir(
            peFile,
            subDirOffset,
            sections,
            numberOfSections,
            &rsrcSecInfo,
            level + 1,
            imageBase) != RET_SUCCESS) {
            printf("[!!] Failed to dump resource sub directory number %d\n", i);
            continue;
        }
    }

    fflush(stdout);

    return RET_SUCCESS;
}


void print_version_header(VS_VERSIONINFO_HEADER *versionInfo, ULONGLONG vaBase, DWORD foBase, int level) {
    printf("%s", INDENT(level));
    wprintf(L"%ls", versionInfo->szKey);
    printf(" - (VA=%llX, FO=%lX) [%u bytes]:\n", vaBase, foBase, versionInfo->wLength);

    printf("%swValueLength : %04X (%u)\n", INDENT(level + 1), versionInfo->wValueLength, versionInfo->wValueLength);

    printf("%swType        : %s\n\n", INDENT(level + 1), versionInfo->wType == 1 ? "text data" : "binary data");
}

void print_version_extras(VS_FIXEDFILEINFO *FixedFileInfo, WORD twValueLength, ULONGLONG vaBase, DWORD foBase, int level) {
    printf("%sVS_FIXEDFILEINFO - (VA=%llX, FO=%lX) [%u bytes]:\n", INDENT(level), vaBase, foBase, twValueLength);

    printf("%sdwSignature    : %08lX\n", INDENT(level + 1),  FixedFileInfo->dwSignature);

    printf("%sStrucVersion   : %08lX\n", INDENT(level + 1),  FixedFileInfo->dwStrucVersion);

    printf("%sFileVersion    : %u.%u.%u.%u\n",
        INDENT(level + 1),
        __HIWORD(FixedFileInfo->dwFileVersionMS),
        __LOWORD(FixedFileInfo->dwFileVersionMS),
        __HIWORD(FixedFileInfo->dwFileVersionLS),
        __LOWORD(FixedFileInfo->dwFileVersionLS));

    printf("%sProductVersion : %u.%u.%u.%u\n",
        INDENT(level + 1),
        __HIWORD(FixedFileInfo->dwProductVersionMS),
        __LOWORD(FixedFileInfo->dwProductVersionMS),
        __HIWORD(FixedFileInfo->dwProductVersionLS),
        __LOWORD(FixedFileInfo->dwProductVersionLS));

    printf("%sFileFlagsMask  : %08lX\n", INDENT(level + 1),  FixedFileInfo->dwFileFlagsMask);  ;

    printf("%sdwFileFlags    : %08lX\n", INDENT(level + 1),  FixedFileInfo->dwFileFlags);  ;


    static const FlagDesc vsFlags[] = {
        {VS_FF_DEBUG,        "VS_FF_DEBUG"},
        {VS_FF_PRERELEASE,   "VS_FF_PRERELEASE"},
        {VS_FF_PATCHED,      "VS_FF_PATCHED"},
        {VS_FF_INFOINFERRED, "VS_FF_INFOINFERRED"},
        {VS_FF_SPECIALBUILD, "VS_FF_SPECIALBUILD"}
    };

    int vsFlagsCount = sizeof(vsFlags) / sizeof(vsFlags[0]);

    for (int i = 0; i < vsFlagsCount; i++) {
        if (FixedFileInfo->dwFileFlags & vsFlags[i].flag) {
            printf("\t\t   + %08lX  %-20s\n",
                    vsFlags[i].flag,
                    vsFlags[i].name);
        }
    }
    if (FixedFileInfo->dwFileFlags) {
        putchar('\n');
    }

    printf("%sFileOS         : %08lX (%s)\n", INDENT(level + 1),  FixedFileInfo->dwFileOS, GetFileOSString(FixedFileInfo->dwFileOS));

    printf("%sFileType       : %08lX (%s)\n", INDENT(level + 1),  FixedFileInfo->dwFileType, GetFileTypeString(FixedFileInfo->dwFileType));

    char subTypeString[64] = {0};

    if (FixedFileInfo->dwFileType == VFT_DRV || FixedFileInfo->dwFileType == VFT_FONT) {
        if (FixedFileInfo->dwFileType == VFT_DRV) {
            sprintf(subTypeString, "(%s)", GetDriverSubtypeString(FixedFileInfo->dwFileSubtype));
        } else {
            sprintf(subTypeString, "(%s)", GetFontSubtypeString(FixedFileInfo->dwFileSubtype));
        }
        subTypeString[sizeof(subTypeString) - 1] = '\0';
    } else {
        subTypeString[0] = '\0';
    }

    printf("%sFileSubtype    : %08lX %s\n", INDENT(level + 1),  FixedFileInfo->dwFileSubtype, subTypeString);

    ULONGLONG FileDate = ((ULONGLONG)FixedFileInfo->dwFileDateMS << 32) | FixedFileInfo->dwFileDateLS;

    if ((FileDate >= SOME_REASONABLE_EPOCH && FileDate <= CURRENT_EPOCH_PLUS_MARGIN)) {
        printf("%sFileDate       : %08llX  %s\n\n", INDENT(level + 1),  FileDate, format_filetime(FileDate));
    } else {
        printf("%sFileDate       : %08llX\n\n", INDENT(level + 1),  FileDate);

    }
}

void print_string_file_info(StringFileInfo *stringFileInfo, WCHAR *szKey, ULONGLONG szKeyLen, ULONGLONG vaBase, DWORD foBase, int level) {
    printf("%s", INDENT(level));
    for (ULONGLONG i = 0; i < szKeyLen; i++) wprintf(L"%lc", szKey[i]);
    printf(" - (VA=%llX, FO=%lX) [%u bytes]:\n", vaBase, foBase, stringFileInfo->wLength);
}

void print_string_table(StringTable *stringtable, ULONGLONG vaBase, DWORD foBase, int level) {
    DWORD ID;

    ID = wcstoul(stringtable->szKey, NULL, 16);

    WORD langID    = (WORD)((ID >> 16) & 0xFFFF);  // high word = LangID
    WORD charsetID = (WORD)(ID & 0xFFFF);          // low word  = CharsetID

    printf("%s%08lX (%s, %s) - (VA=%llX, FO=%lX) [%u bytes]:\n",
        INDENT(level), ID, getViLangName(langID), getViCharsetName(charsetID), vaBase, foBase, stringtable->wLength);
}

void print_string(String *string, WCHAR *szKey, ULONGLONG szKeyLen, WCHAR* value, ULONGLONG valueLen, ULONGLONG vaBase, DWORD foBase, int level) {
    const ULONGLONG KEY_COL_WIDTH   = 20;   // fixed key name width
    const ULONGLONG VALUE_COL_WIDTH = 70;   // fixed value field width
    
    // 1. print VA and FO part
    printf("%s(VA=%llX, FO=%lX)  ", INDENT(level), vaBase, foBase);

    // 2. print key
    putchar(' ');
    for (ULONGLONG i = 0; i < szKeyLen; i++)
        wprintf(L"%lc", szKey[i]);

    // pad key only if it fits
    if (szKeyLen < KEY_COL_WIDTH) {
        ULONGLONG keyPadding = KEY_COL_WIDTH - szKeyLen;
        for (ULONGLONG i = 0; i < keyPadding; i++)
            putchar(' ');
    }

    // 3. separator
    printf(": ");

    // 4. print value
    for (ULONGLONG i = 0; i < valueLen; i++)
        wprintf(L"%lc", value[i]);

    // pad value only if it fits
    if (valueLen < VALUE_COL_WIDTH) {
        ULONGLONG valPadding = VALUE_COL_WIDTH - valueLen;
        for (ULONGLONG i = 0; i < valPadding; i++)
            putchar(' ');
    }

    // 5. size at the end
    printf("[%u bytes]\n", string->wLength);
}

void print_var_file_info(VarFileInfo *varfileinfo, WCHAR *szKey, ULONGLONG szKeyLen, ULONGLONG vaBase, DWORD foBase, int level) {
    printf("\n%s", INDENT(level));
    for (ULONGLONG i = 0; i < szKeyLen; i++) wprintf(L"%lc", szKey[i]);
    printf(" - (VA=%llX, FO=%lX) [%u bytes]:\n", vaBase, foBase, varfileinfo->wLength);
}

void print_var(
    Var *var,
    WCHAR *szKey, ULONGLONG szKeyLen,
    PDWORD values, ULONGLONG valueCount,
    ULONGLONG valueVaBase, DWORD valueFoBase,
    ULONGLONG VaBase, DWORD FoBase,
    int level) {

    printf("%s Var - (VA=%llX, FO=%lX) [%u bytes]:\n", INDENT(level), VaBase, FoBase, var->wLength);

    for (ULONGLONG i = 0; i < valueCount; i++) {
        WORD charsetID = (WORD)((values[i] >> 16) & 0xFFFF);  // high word = charsetID
        WORD langID    = (WORD)(values[i] & 0xFFFF);          // low word  = langID

        printf("%s", INDENT(level + 1));
        for (ULONGLONG j = 0; j < szKeyLen; j++) wprintf(L"%lc", szKey[j]);
        printf(" : %lX (%s, %s) - (VA=%llX, FO=%lX) [%llu bytes]\n",
            values[i],
            getViCharsetName(charsetID),
            getViLangName(langID),
            valueVaBase,
            valueFoBase,
            sizeof(DWORD));

            valueVaBase += sizeof(DWORD); valueFoBase += sizeof(DWORD);
        }
}


RET_CODE dump_version_info_header(FILE *peFile, PULONGLONG vaBase, PDWORD foBase, VS_VERSIONINFO_HEADER *outVersionInfo) {
    VS_VERSIONINFO_HEADER versionInfo;
    if (FSEEK64(peFile, *foBase, SEEK_SET) != 0) return RET_ERROR;
    if (fread(&versionInfo, sizeof(VS_VERSIONINFO_HEADER), 1, peFile) != 1) return RET_ERROR;

    print_version_header(&versionInfo, *vaBase, *foBase, 0);

    *vaBase = ALIGN4(*vaBase + sizeof(VS_VERSIONINFO_HEADER));
    *foBase = (DWORD)ALIGN4(*foBase + sizeof(VS_VERSIONINFO_HEADER));

    if (outVersionInfo) *outVersionInfo = versionInfo; // optionally return structure

    return RET_SUCCESS;
}

RET_CODE dump_fixed_file_info(FILE *peFile, PULONGLONG vaBase, PDWORD foBase, WORD valueLength) {
    VS_FIXEDFILEINFO fixedFileInfo;
    if (FSEEK64(peFile, *foBase, SEEK_SET) != 0) return RET_ERROR;
    if (fread(&fixedFileInfo, sizeof(fixedFileInfo), 1, peFile) != 1) return RET_ERROR;

    print_version_extras(&fixedFileInfo, valueLength, *vaBase, *foBase, 1);

    *vaBase = ALIGN4(*vaBase + sizeof(VS_FIXEDFILEINFO));
    *foBase = (DWORD)ALIGN4(*foBase + sizeof(VS_FIXEDFILEINFO));
    return RET_SUCCESS;
}

RET_CODE dump_string_file_info(FILE *peFile, PULONGLONG vaBase, PDWORD foBase, StringFileInfo *outStringFileInfo, PULONGLONG outSzKeyBytesLen) {

    if (FSEEK64(peFile, *foBase, SEEK_SET) != 0) return RET_ERROR;

    StringFileInfo stringfileinfo;
    if (fread(&stringfileinfo, sizeof(stringfileinfo), 1, peFile) != 1) return RET_ERROR;

    UCHAR rawBytes[MAXLOGICALLOGNAMESIZE / 2] = {0}; // safe max
    WCHAR szKey[MAXLOGICALLOGNAMESIZE / 2] = {0};

    if (fread(rawBytes, 1, sizeof(rawBytes), peFile) != sizeof(rawBytes)) return RET_ERROR;

    ULONGLONG szKeyBytesLen = read_unicode_string(rawBytes, szKey, MAXLOGICALLOGNAMESIZE / 2);

    print_string_file_info(&stringfileinfo, szKey, szKeyBytesLen / 2, *vaBase, *foBase, 0);

    // Move past StringFileInfo + szKey and align to nearest WORD
    *vaBase = ALIGN4(*vaBase + sizeof(StringFileInfo) + szKeyBytesLen);
    *foBase = (DWORD)ALIGN4(*foBase + sizeof(StringFileInfo) + szKeyBytesLen);

    if (outStringFileInfo) *outStringFileInfo = stringfileinfo; // optionally return structure
    if (outSzKeyBytesLen) *outSzKeyBytesLen = szKeyBytesLen; // optionally return structure

    return RET_SUCCESS;
}

RET_CODE dump_string_tables(FILE *peFile, PULONGLONG vaBase, PDWORD foBase, StringFileInfo *stringfileinfo, ULONGLONG szKeyBytesLen) {

    UCHAR rawBytes[MAXLOGICALLOGNAMESIZE / 2] = {0}; // safe max
    WCHAR szKey[MAXLOGICALLOGNAMESIZE / 2] = {0};

    DWORD foEnd = (DWORD)ALIGN4(*foBase + stringfileinfo->wLength - sizeof(StringFileInfo) - szKeyBytesLen);


    while (*foBase < foEnd) {
        if (FSEEK64(peFile, *foBase, SEEK_SET) != 0) return RET_ERROR;

        StringTable stringtable;
        if (fread(&stringtable, sizeof(stringtable), 1, peFile) != 1) return RET_ERROR;

        DWORD strEnd = (DWORD)ALIGN4(*foBase + stringtable.wLength);

        print_string_table(&stringtable, *vaBase, *foBase, 1);

        // Advance past StringTable header
        *vaBase = ALIGN4(*vaBase + sizeof(StringTable));
        *foBase = (DWORD)ALIGN4(*foBase + sizeof(StringTable));

        while (*foBase < strEnd) {
            if (FSEEK64(peFile, *foBase, SEEK_SET) != 0) return RET_ERROR;

            String string;
            if (fread(&string, sizeof(string), 1, peFile) != 1) return RET_ERROR;

            memset(rawBytes, 0, sizeof(rawBytes));
            memset(szKey, 0, sizeof(szKey));

            if (fread(rawBytes, 1, sizeof(rawBytes), peFile) != sizeof(rawBytes)) return RET_ERROR;
            szKeyBytesLen = read_unicode_string(rawBytes, szKey, MAXLOGICALLOGNAMESIZE / 2);

            DWORD tempFoBase = (DWORD)ALIGN4(*foBase + sizeof(String) + szKeyBytesLen);
            if (FSEEK64(peFile, tempFoBase, SEEK_SET) != 0) return RET_ERROR;

            UCHAR value[MAXLOGICALLOGNAMESIZE] = {0};
            WCHAR valueStr[MAXLOGICALLOGNAMESIZE] = {0};
            ULONGLONG valueLen = string.wValueLength * sizeof(WORD);
            ULONGLONG valueStrLen = 0;

            if (valueLen != 0) {
                if (fread(value, sizeof(UCHAR), valueLen, peFile) != valueLen) return RET_ERROR;
                valueStrLen = read_unicode_string(value, valueStr, MAXLOGICALLOGNAMESIZE);
            }

            print_string(&string, szKey, szKeyBytesLen / 2, valueStr, valueStrLen / 2, *vaBase, *foBase, 2);

            *vaBase = ALIGN4(*vaBase + string.wLength);
            *foBase = (DWORD)ALIGN4(*foBase + string.wLength);
        }
    }


    return RET_SUCCESS;
}

RET_CODE dump_var_file_info(FILE *peFile, PULONGLONG vaBase, PDWORD foBase, VarFileInfo *outVarFileInfo, PULONGLONG outSzKeyBytesLen) {

    UCHAR rawBytes[MAXLOGICALLOGNAMESIZE / 2] = {0}; // safe max
    WCHAR szKey[MAXLOGICALLOGNAMESIZE / 2] = {0};

    if (FSEEK64(peFile, *foBase, SEEK_SET) != 0) return RET_ERROR;

    if (fread(outVarFileInfo, sizeof(*outVarFileInfo), 1, peFile) != 1) return RET_ERROR;

    // read rawBytes
    if (fread(rawBytes, 1, sizeof(rawBytes), peFile) != sizeof(rawBytes)) return RET_ERROR;

    // read szKey from rawBytes
    *outSzKeyBytesLen = read_unicode_string(rawBytes, szKey, MAXLOGICALLOGNAMESIZE / 2);

    print_var_file_info(outVarFileInfo, szKey, *outSzKeyBytesLen / 2, *vaBase, *foBase, 0);

    // go past varFileINfo
    *vaBase = ALIGN4(*vaBase +  sizeof(VarFileInfo) + *outSzKeyBytesLen);
    *foBase = (DWORD)ALIGN4(*foBase +  sizeof(VarFileInfo) + *outSzKeyBytesLen);

    return RET_SUCCESS;
}

RET_CODE dump_var(FILE *peFile, PULONGLONG vaBase, PDWORD foBase, VarFileInfo *varfileinfo, ULONGLONG vfiSzKeyBytesLen) {
    Var var;

    UCHAR rawBytes[MAXLOGICALLOGNAMESIZE / 2] = {0}; // safe max
    WCHAR szKey[MAXLOGICALLOGNAMESIZE / 2] = {0};

    DWORD foEnd = (DWORD)ALIGN4(*foBase + varfileinfo->wLength - sizeof(StringFileInfo) - vfiSzKeyBytesLen);

    while (*foBase < foEnd) {
        if (FSEEK64(peFile, *foBase, SEEK_SET) != 0) return RET_ERROR;

        if (fread(&var, sizeof(var), 1, peFile) != 1) return RET_ERROR;

        // read rawBytes
        if (fread(rawBytes, 1, sizeof(rawBytes), peFile) != sizeof(rawBytes)) return RET_ERROR;

        ULONGLONG szKeyBytesLen = read_unicode_string(rawBytes, szKey, sizeof(szKey));

        DWORD valueCount = var.wValueLength / sizeof(DWORD);
        if (valueCount == 0 || valueCount > 16) return RET_ERROR; // sanity check

        PDWORD translations = malloc(var.wValueLength);
        if (!translations) return RET_ERROR;

        ULONGLONG valueVa = ALIGN4(*vaBase + sizeof(Var) + szKeyBytesLen);
        DWORD valueFo = (DWORD)ALIGN4(*foBase + sizeof(Var) + szKeyBytesLen);

        if (FSEEK64(peFile, valueFo, SEEK_SET) != 0) {
            SAFE_FREE(translations);
            return RET_ERROR;
        }

        if (fread(translations, sizeof(DWORD), valueCount, peFile) != valueCount) {
            SAFE_FREE(translations);
            return RET_ERROR;
        }

        print_var(&var, szKey, szKeyBytesLen / 2, translations, valueCount, valueVa, valueFo, *vaBase, *foBase, 1);

        *vaBase = ALIGN4(vaBase + var.wLength);
        *foBase = (DWORD)ALIGN4(foBase + var.wLength);

        SAFE_FREE(translations);
    }
    return RET_SUCCESS;
}

RET_CODE dump_version_info(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    DWORD versionInfoRva,
    DWORD versionInfoSize,
    ULONGLONG imageBase) {

    int status;
    VS_VERSIONINFO_HEADER versionInfo;
    StringFileInfo stringfileinfo;
    VarFileInfo varfileinfo;
    ULONGLONG szKeyBytesLen;

    ULONGLONG vaBase;
    DWORD foBase;

    // sanity check
    if (!peFile || !versionInfoRva || !versionInfoSize) {
        status = RET_INVALID_PARAM;
        goto cleanup;
    }

    vaBase = imageBase + versionInfoRva;

    status = rva_to_offset(versionInfoRva, sections, numberOfSections, &foBase);
    if (status != RET_SUCCESS) goto cleanup;

    if ((LONGLONG)foBase + versionInfoSize > get_file_size(peFile)) {
        status = RET_INVALID_BOUND;
        goto cleanup;
    }

    // -- parsing/dumping of VS_VERSIONINFO_HEADER --
    status = dump_version_info_header(peFile, &vaBase, &foBase, &versionInfo);
    if (status != RET_SUCCESS) goto cleanup;

    // -- parsing/dumping of VS_FIXEDFILEINFO --
    if (versionInfo.wValueLength == 0) {
        printf("%s(no VS_FIXEDFILEINFO present)\n\n", INDENT(1));
    } else {
        status = dump_fixed_file_info(peFile, &vaBase, &foBase, versionInfo.wValueLength);
        if (status != RET_SUCCESS) goto cleanup;
    }

    // -- parsing/dumping of StringFileInfo --
    status = dump_string_file_info(peFile, &vaBase, &foBase, &stringfileinfo, &szKeyBytesLen);
    if (status != RET_SUCCESS) goto cleanup;

    // -- parsing/dumping of StringTable --
    status = dump_string_tables(peFile, &vaBase, &foBase, &stringfileinfo, szKeyBytesLen);
    if (status != RET_SUCCESS) goto cleanup;

    // -- parsing/dumping of VarFileInfo --
    status = dump_var_file_info(peFile, &vaBase, &foBase, &varfileinfo, &szKeyBytesLen);
    if (status != RET_SUCCESS) goto cleanup;

    // -- parsing/dumping of Var --
    status = dump_var(peFile, &vaBase, &foBase, &varfileinfo, szKeyBytesLen);
    if (status != RET_SUCCESS) goto cleanup;

    cleanup:
    fflush(stdout);

    return status;
}

void print_MIPS_or_alpha32_entries(PIMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY entries, ULONGLONG vaBase, DWORD foBase, DWORD maxEntries, WORD sizeOfEntry) {
    ULONGLONG currentVa = vaBase;
    DWORD currentFo = foBase;

    // Header includes Index, File Offset, Virtual Address, and entry fields
    printf("%-5s %-12s %-8s   %-10s %-10s %-10s %-10s %-10s\n",
           "Idx", "VirtAddr", "FileOff", "Begin", "End", "Handler", "Data", "Prolog");

    for (DWORD i = 0; i < maxEntries; i++, currentFo += sizeOfEntry, currentVa += sizeOfEntry) {

        printf("%-5lu %012llX %08lX   %08lX   %08lX   %08lX   %08lX   %08lX\n",
               i + 1,
               currentVa,        // virtual address
               currentFo,        // file offset 
               entries[i].BeginAddress,
               entries[i].EndAddress,
               entries[i].ExceptionHandler,
               entries[i].HandlerData,
               entries[i].PrologEndAddress);
    }
    printf("\n\t\t\t[End of entries]\n");
    fflush(stdout);
}

void print_alpha64_entries(PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY entries, ULONGLONG vaBase, DWORD foBase, DWORD maxEntries, WORD sizeOfEntry) {
    ULONGLONG currentVa = vaBase;
    DWORD currentFo = foBase;

    // Header includes Index, File Offset, Virtual Address, and entry fields
    // Longer header for clarity and 64-bit addresses
    printf("%-5s %-16s %-8s   %-16s   %-16s   %-16s   %-16s   %-16s\n",
           "Idx", "VirtAddr", "FileOff", "Begin", "End", "Handler", "Data", "Prolog");

    for (DWORD i = 0; i < maxEntries; i++, currentVa += sizeOfEntry, currentFo += sizeOfEntry) {

        printf("%-5lu %016llX %08lX   %016llX   %016llX   %016llX   %016llX   %016llX\n",
               i + 1,
               currentVa,                 // virtual address
               currentFo,                 // file offset
               entries[i].BeginAddress,
               entries[i].EndAddress,
               entries[i].ExceptionHandler,
               entries[i].HandlerData,
               entries[i].PrologEndAddress);
    }
    printf("\n\t\t\t[End of entries]\n");
    fflush(stdout);
}

void print_winCE_entries(PIMAGE_CE_RUNTIME_FUNCTION_ENTRY entries, ULONGLONG vaBase, DWORD foBase, DWORD maxEntries, WORD sizeOfEntry) {
    ULONGLONG currentVa = vaBase;
    DWORD currentFo = foBase;

    // Compact header
    printf("%-5s %-16s %-8s   %-8s   %-6s   %-6s   %-4s   %-4s\n",
           "Idx", "VirtAddr", "FileOff", "FuncStart", "Prolog", "FuncLen", "32Bit", "Flag");

    for (DWORD i = 0; i < maxEntries; i++, currentVa += sizeOfEntry, currentFo += sizeOfEntry) {
        printf("%-5lu %016llX %08lX   %08lX   %03X   %03X   %02X   %02X\n",
               i + 1,
               currentVa,                             // virtual address
               currentFo,                             // file offset
               entries[i].FuncStart,                  // 4 bytes
               entries[i].PrologLen,       // 1 byte
               entries[i].FuncLen,         // 22 bits ~ 3 bytes
               entries[i].ThirtyTwoBit,    // 1 bit
               entries[i].ExceptionFlag);  // 1 bit
    }
    printf("\n\t\t\t[End of entries]\n");
    fflush(stdout);
}

void print_ARM_entries(PIMAGE_ARM_RUNTIME_FUNCTION_ENTRY entries, ULONGLONG vaBase, DWORD foBase, DWORD maxEntries, WORD sizeOfEntry) {
    ULONGLONG currentVa = vaBase;
    DWORD currentFo = foBase;
    
    // Compact header for ARM runtime entries
    printf("%-5s %-16s %-8s %-8s %-12s %-4s %-4s %-4s %-2s %-4s %-2s %-2s %-2s %-10s\n",
           "Idx", "VirtAddr", "FileOff", "Begin", "UnwindData",
           "Flg", "FnLen", "Ret", "H", "Reg", "R", "L", "C", "StackAdj");

    for (DWORD i = 0; i < maxEntries; i++, currentVa += sizeOfEntry, currentFo += sizeOfEntry) {
        printf("%-5lu %016llX %08lX %08lX %08lX %01X %03X %01X %01X %01X %01X %01X %01X %03X\n",
               i + 1,
               currentVa,                        // virtual address
               currentFo,                        // file offset
               entries[i].BeginAddress,          // function start
               entries[i].UnwindData,            // raw unwind data
               entries[i].Flag,
               entries[i].FunctionLength,
               entries[i].Ret,
               entries[i].H,
               entries[i].Reg,
               entries[i].R,
               entries[i].L,
               entries[i].C,
               entries[i].StackAdjust);
    }

    // Simple consistent ending
    printf("\n\t\t\t[End of entries]\n");
    fflush(stdout);
}

void print_ARM64_entries(PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY entries, ULONGLONG vaBase, DWORD foBase, DWORD maxEntries, WORD sizeOfEntry) {
    ULONGLONG currentVa = vaBase;
    DWORD currentFo = foBase;

    // Compact header for ARM64 runtime entries
    printf("%-5s %-16s %-10s %-10s %-12s %-3s %-26s %-5s %-5s %-3s %-30s %-7s\n",
        "Idx", "VirtAddr", "FileOff", "Begin", "UnwindData",
        "Flg", "FnLen", "RegF", "RegI", "H", "CR", "FrameSz");

    for (DWORD i = 0; i < maxEntries; i++, currentVa += sizeOfEntry, currentFo += sizeOfEntry) {
        printf("%-5lu %016llX %-10lX %-10lX %-12lX %-3X %-26s %-5X %-5X %-3X %-3X %-30s %-7X\n",
            i + 1,
            currentVa,
            currentFo,
            entries[i].BeginAddress,
            entries[i].UnwindData,
            entries[i].Flag,
            get_arm64_flag_to_string(entries[i].Flag),
            entries[i].FunctionLength,
            entries[i].RegF,
            entries[i].RegI,
            entries[i].H,
            get_arm64_cr_to_string(entries[i].CR),
            entries[i].FrameSize);
    }

    // Simple consistent ending
    printf("\n\t\t\t[End of entries]\n");
    fflush(stdout);
}

void print_x64_entries(_PIMAGE_RUNTIME_FUNCTION_ENTRY entries, ULONGLONG vaBase, DWORD foBase, DWORD maxEntries, WORD sizeOfEntry) {
    ULONGLONG currentVa = vaBase;
    DWORD currentFo = foBase;

    // Header
    printf("%-5s %-16s %-8s   %-8s   %-8s   %-12s\n",
           "Idx", "VirtAddr", "FileOff", "Begin", "End", "UnwindInfo");

    for (DWORD i = 0; i < maxEntries; i++, currentVa += sizeOfEntry, currentFo += sizeOfEntry) {
        printf("%-5lu %016llX %08lX   %08lX   %08lX   %08lX\n",
            i + 1,
            currentVa,                    // virtual address of entry
            currentFo,                    // file offset of entry
            entries[i].BeginAddress,      // RVA Begin
            entries[i].EndAddress,        // RVA End
            entries[i].UnwindInfoAddress  // RVA of UNWIND_INFO
        );
    }
    // Simple consistent ending
    printf("\n\t\t\t[End of entries]\n");
    fflush(stdout);
}

RET_CODE dump_exception_dir(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY exceptionDirData,
    WORD machine,
    ULONGLONG imageBase) {

    if (!peFile || !exceptionDirData) return RET_INVALID_PARAM; // sanity check

    // completely empty = skip gracefully
    if (exceptionDirData->VirtualAddress == 0 && exceptionDirData->Size == 0)
        return RET_MALFORMED_FILE;

    // partially defined = suspicious
    if (exceptionDirData->VirtualAddress == 0 || exceptionDirData->Size == 0)
        return REPORT_MALFORMED("Exception directory partially empty (RVA=0 or Size=0)", "Exception Data Directory");
    
    DWORD rvaBase = exceptionDirData->VirtualAddress;
    ULONGLONG vaBase = imageBase + exceptionDirData->VirtualAddress;

    DWORD foBase = 0;
    if (rva_to_offset(rvaBase, sections, numberOfSections, &foBase) != RET_SUCCESS) {
        fprintf(stderr, "[!!] Failed to map Exception Directory RVA to file offset\n");
        return RET_ERROR;
    }

    DWORD size = exceptionDirData->Size;

    // === MACHINE-SPECIFIC BRANCHING ===
    if (IsMIPSOrAlpha32(machine)) {
        WORD entrySize = sizeof(IMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY);
        DWORD maxEntries = size / (DWORD)entrySize;

        PIMAGE_ALPHA_RUNTIME_FUNCTION_ENTRY entries = calloc(maxEntries, entrySize);
        if (!entries) {
            fprintf(stderr, "[!!] calloc failed\n"); 
            return RET_ERROR;
        }

        DWORD entriesCount = (DWORD)fill_entries(peFile, sections, numberOfSections,
                                        rvaBase, size, entries, entrySize);

        printExceptionDirectoryHeader(vaBase, "EXCEPTION DIRECTORY", entriesCount, machine);

        if (entriesCount > 0)
            print_MIPS_or_alpha32_entries(entries, vaBase, foBase, entriesCount, entrySize);

        SAFE_FREE(entries);
    }

    else if (IsAlpha64(machine)) {
        WORD entrySize = sizeof(IMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY);
        DWORD maxEntries = size / (DWORD)entrySize;

        PIMAGE_ALPHA64_RUNTIME_FUNCTION_ENTRY entries = calloc(maxEntries, entrySize);
        if (!entries) {
            fprintf(stderr, "[!!] calloc failed\n");
            return RET_ERROR;
        }
        

        DWORD entriesCount = (DWORD)fill_entries(peFile, sections, numberOfSections,
                                        rvaBase, size, entries, entrySize);

        printExceptionDirectoryHeader(vaBase, "EXCEPTION DIRECTORY", entriesCount, machine);

        if (entriesCount > 0)
            print_alpha64_entries(entries, vaBase, foBase, entriesCount, entrySize);

        SAFE_FREE(entries);
    }

    else if (IsWinCE(machine)) {
        WORD entrySize = sizeof(IMAGE_CE_RUNTIME_FUNCTION_ENTRY);
        DWORD maxEntries = size / (DWORD)entrySize;

        PIMAGE_CE_RUNTIME_FUNCTION_ENTRY entries = calloc(maxEntries, entrySize);
        if (!entries) {
            fprintf(stderr, "[!!] calloc failed\n");
            return RET_ERROR;
        }

        DWORD entriesCount = (DWORD)fill_entries(peFile, sections, numberOfSections,
                                        rvaBase, size, entries, entrySize);

        printExceptionDirectoryHeader(vaBase, "EXCEPTION DIRECTORY", entriesCount, machine);

        if (entriesCount > 0)
            print_winCE_entries(entries, vaBase, foBase, entriesCount, entrySize);

        SAFE_FREE(entries);
    }

    else if (IsARMNT(machine)) {
        WORD entrySize = sizeof(IMAGE_ARM_RUNTIME_FUNCTION_ENTRY);
        DWORD maxEntries = size / (DWORD)entrySize;

        PIMAGE_ARM_RUNTIME_FUNCTION_ENTRY entries = calloc(maxEntries, entrySize);
        if (!entries) {
            fprintf(stderr, "[!!] calloc failed\n"); 
            return RET_ERROR;
        }

        DWORD entriesCount = (DWORD)fill_entries(peFile, sections, numberOfSections,
                                        rvaBase, size, entries, entrySize);

        printExceptionDirectoryHeader(vaBase, "EXCEPTION DIRECTORY", entriesCount, machine);

        if (entriesCount > 0)
            print_ARM_entries(entries, vaBase, foBase, entriesCount, entrySize);

        SAFE_FREE(entries);
    }

    else if (IsARM64(machine)) {
        WORD entrySize = sizeof(IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY);
        DWORD maxEntries = size / (DWORD)entrySize;

        PIMAGE_ARM64_RUNTIME_FUNCTION_ENTRY entries = calloc(maxEntries, entrySize);
        if (!entries) {
            fprintf(stderr, "[!!] calloc failed\n"); 
            return RET_ERROR;
        }

        DWORD entriesCount = (DWORD)fill_entries(peFile, sections, numberOfSections,
                                        rvaBase, size, entries, entrySize);

        printExceptionDirectoryHeader(vaBase, "EXCEPTION DIRECTORY", entriesCount, machine);

        if (entriesCount > 0)
            print_ARM64_entries(entries, vaBase, foBase, entriesCount, entrySize);

        SAFE_FREE(entries);
    }

    else if (IsX64OrItanium(machine)) {
        WORD entrySize = sizeof(_IMAGE_RUNTIME_FUNCTION_ENTRY);
        DWORD maxEntries = size / (DWORD)entrySize;

        _PIMAGE_RUNTIME_FUNCTION_ENTRY entries = calloc(maxEntries, entrySize);
        if (!entries) {
            fprintf(stderr, "[!!] calloc failed\n"); 
            return RET_ERROR;
        }

        DWORD entriesCount = (DWORD)fill_entries(peFile, sections, numberOfSections,
                                        rvaBase, size, entries, entrySize);

        printExceptionDirectoryHeader(vaBase, "EXCEPTION DIRECTORY", entriesCount, machine);

        if (entriesCount > 0)
            print_x64_entries(entries, vaBase, foBase, entriesCount, entrySize);

        SAFE_FREE(entries);
    }

    else {
        fprintf(stderr, "[!!] Unknown machine type\n");
        return RET_ERROR;
    }

    fflush(stdout);
    return RET_SUCCESS;
}

// TODO: parse the secuurity certificate
// PE SecurityDir -> WIN_CERTIFICATE -> PKCS#7 (DER)
// use OpenSSL: d2i_PKCS7 -> PKCS7_get0_signers -> X509_get_subject_name/issue
RET_CODE dump_security_dir(FILE *peFile, PIMAGE_DATA_DIRECTORY securityDirData) {
    if (!peFile || !securityDirData) return RET_INVALID_PARAM; // sanity check

    // completely empty = skip gracefully
    if (securityDirData->VirtualAddress == 0 && securityDirData->Size == 0)
        return RET_MALFORMED_FILE;

    // partially defined = suspicious
    if (securityDirData->VirtualAddress == 0 || securityDirData->Size == 0)
        return REPORT_MALFORMED("Security directory partially empty (RVA=0 or Size=0)", "Security Data Directory");

    DWORD start = securityDirData->VirtualAddress;
    DWORD size  = securityDirData->Size;

    printf("\n%08lX\t- SECURITY DIRECTORY -\n\n", start);

    BYTE *buffer = parse_table_from_fo(peFile, start, size, 1);
    if (!buffer) return RET_ERROR;

    DWORD offset = 0;
    int certNumber = 1;

    while (offset < size) {
        WIN_CERTIFICATE *cert = (WIN_CERTIFICATE *)(buffer + offset);

        printf("%-3s  %-8s  %-8s  %-20s         %-20s\n", "idx", "FileOff", "Length", "Revision", "CertType");

        printf("%-3d  %08lX  %08lX  %04X-(%s) %04X-(%s)\n",
            certNumber,
            start + offset,
            cert->dwLength,
            cert->wRevision, get_certificate_revision_flag(cert->wRevision),
            cert->wCertificateType, get_certificate_type_flag(cert->wCertificateType));

        printf("\n");
        print_centered_header("CertData", '-', 95);

        // Print certificate data (bytes)
        PBYTE certData = (PBYTE)(buffer + offset + offsetof(WIN_CERTIFICATE, bCertificate));
        DWORD dataSize = cert->dwLength - (DWORD)offsetof(WIN_CERTIFICATE, bCertificate);

        for (DWORD i = 0; i < dataSize; i++) {
            printf("%02X ", certData[i]);
            if ((i + 1) % 32 == 0) printf("\n");
        }

        printf("\n");
        print_centered_header("End Of CertData", '-', 95);
        printf("\n");

        // move to next entry (aligned on 8 bytes)
        offset += (DWORD)(cert->dwLength + 7UL) & ~7UL;
        certNumber++;
    }

    SAFE_FREE(buffer);
    return RET_SUCCESS;
}

RET_CODE dump_reloc_dir(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY relocDirData,
    ULONGLONG imageBase) {

    if (!peFile || !relocDirData) return RET_INVALID_PARAM; // sanity check

    // completely empty = skip gracefully
    if (relocDirData->VirtualAddress == 0 && relocDirData->Size == 0)
        return RET_MALFORMED_FILE;

    // partially defined = suspicious
    if (relocDirData->VirtualAddress == 0 || relocDirData->Size == 0)
        return REPORT_MALFORMED("Reloc directory partially empty (RVA=0 or Size=0)", "Reloc Data Directory");

    // Map RVA to file offset
    DWORD foBase;
    if (rva_to_offset(relocDirData->VirtualAddress, sections, numberOfSections, &foBase) != RET_SUCCESS) {
        printf("[!!] Failed to map Base Relocation Directory RVA to file offset\n");
        return RET_ERROR;
    }

    ULONGLONG dirVA = imageBase + relocDirData->VirtualAddress;
    printf("\n%016llX\t- BASE RELOCATION DIRECTORY -\n\n", dirVA);

    // Allocate buffer for the entire relocation table
    BYTE *buffer = malloc(relocDirData->Size);
    if (!buffer) return RET_ERROR;

    FSEEK64(peFile, foBase, SEEK_SET);
    if (fread(buffer, 1, relocDirData->Size, peFile) != relocDirData->Size) {
        SAFE_FREE(buffer);
        return RET_ERROR;
    }

    DWORD offset = 0;
    while (offset < relocDirData->Size) {
        IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION*)(buffer + offset);
        if (block->SizeOfBlock == 0) break;

        WORD entryCount = (WORD)(block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *entries = (WORD*)(block + 1);

        ULONGLONG blockVA = imageBase + block->VirtualAddress;
        DWORD blockFO;
        if (rva_to_offset(block->VirtualAddress, sections, numberOfSections, &blockFO) != RET_SUCCESS) {
            printf("[!!] Failed to map RVA %lX to file offset\n", block->VirtualAddress);
            blockFO = 0;
            continue;
        }

        printf("Block VA: %016llX  FO: %08lX  Size: %08lX (%u)  Entries: %d\n\n",
               blockVA, blockFO, block->SizeOfBlock, (unsigned)block->SizeOfBlock, entryCount);

        printf("  Entry #   Offset    Relocated VA        Type\n");
        printf("  -------   ------    ----------------    ----------------\n");

        for (WORD i = 0; i < entryCount; i++) {
            WORD type = entries[i] >> 12;
            WORD off  = entries[i] & 0x0FFF;
            ULONGLONG entryVA = blockVA + off;

            printf("  %-8u  0x%04X    0x%016llX  %s\n",
                   i, off, entryVA, get_reloc_type_name(type));
        }

        printf("  --------------------------------------------------------\n");

        printf("\n");
        offset += block->SizeOfBlock;
    }

    SAFE_FREE(buffer);

    fflush(stdout);

    return RET_SUCCESS;
}

RET_CODE dump_COFF_debug_info(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DEBUG_DIRECTORY debugDir,
    WORD level) {

    if (!peFile || !debugDir) return RET_INVALID_PARAM; // sanity check

    DWORD foBase = debugDir->PointerToRawData ? debugDir->PointerToRawData : 0;
    if (!foBase) {
        if (rva_to_offset(debugDir->AddressOfRawData, sections, numberOfSections, &foBase) != RET_SUCCESS) {
            fprintf(stderr, "%s[!!] Failed to map COFF Debug info RVA to file offse\n", INDENT(level));
            return RET_ERROR;
        }
    }

    IMAGE_COFF_SYMBOLS_HEADER symbolsHeader = {0};

    if (FSEEK64(peFile, foBase, SEEK_SET) != 0) return RET_ERROR;

    if (fread(&symbolsHeader, sizeof(symbolsHeader), 1, peFile) != 1) return RET_ERROR;

    printf("\n%s%08lX\t- COFF SYMBOLS HEADER -\n\n", INDENT(level), foBase);
    printf("%sFO        Field       Value\n", INDENT(level));

    printf("%s%08lX  [4]\t\tNumber Of Symbols         : %08lX (%u)\n",
        INDENT(level),
        foBase, 
        symbolsHeader.NumberOfSymbols,
        (unsigned) symbolsHeader.NumberOfSymbols);

    foBase += 4;

    // NOTE: LvaToFirstSymbol is a file offset, not RVA
    printf("%s%08lX  [4]\t\tLva To First Symbol       : %08lX\n\n",
        INDENT(level),
        foBase,
        symbolsHeader.LvaToFirstSymbol);

    foBase += 4;

    printf("%s%08lX  [4]\t\tNumber Of Linenumbers     : %08lX (%u)\n",
        INDENT(level),
        foBase, 
        symbolsHeader.NumberOfLinenumbers,
        (unsigned) symbolsHeader.NumberOfLinenumbers);

    foBase += 4;

    printf("%s%08lX  [4]\t\tLva To First Linenumber   : %08lX\n\n",
        INDENT(level),
        foBase,
        symbolsHeader.LvaToFirstLinenumber);

    foBase += 4;

    printf("%s%08lX  [4]\t\tRva To First Byte Of Code : %08lX\n",
        INDENT(level),
        foBase,
        symbolsHeader.RvaToFirstByteOfCode);

    foBase += 4;
    
    printf("%s%08lX  [4]\t\tRva To Last Byte Of Code  : %08lX\n\n",
        INDENT(level),
        foBase,
        symbolsHeader.RvaToLastByteOfCode);

    foBase += 4;
    
    printf("%s%08lX  [4]\t\tRva To First Byte Of Data : %08lX\n",
        INDENT(level),
        foBase,
        symbolsHeader.RvaToFirstByteOfData);

    foBase += 4;

    printf("%s%08lX  [4]\t\tRva To Last Byte Of Data  : %08lX\n\n",
        INDENT(level),
        foBase,
        symbolsHeader.RvaToLastByteOfData);

    foBase += 4;

    if (symbolsHeader.NumberOfSymbols) {
        if (dump_symbol_table(peFile, symbolsHeader.LvaToFirstSymbol, symbolsHeader.NumberOfSymbols, sections, numberOfSections) != RET_SUCCESS) {
            fprintf(stderr, "%s[!!] Failed to dump Symbol Table\n", INDENT(level));
            return RET_ERROR;
        }
    }

    fflush(stdout);

    return RET_SUCCESS;
}

RET_CODE dump_CodeView_debug_info(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DEBUG_DIRECTORY debugDir,
    WORD level) {
    if (!peFile || !debugDir) return RET_INVALID_PARAM; // sanity check

    DWORD foBase = debugDir->PointerToRawData;
    if (!foBase) {
        if (rva_to_offset(debugDir->AddressOfRawData, sections, numberOfSections, &foBase) != RET_SUCCESS) {
            fprintf(stderr, "%s[!!] Failed to map CodeView Debug info RVA to file offset\n", INDENT(level));
            return RET_ERROR;
        }
    }

    if (FSEEK64(peFile, foBase, SEEK_SET) != 0) return RET_ERROR;

    char sig[4];
    if (fread(sig, 1, 4, peFile) != 4) return RET_ERROR;

    int isPdb70 = (memcmp(sig, "RSDS", 4) == 0);
    printf("%s%08lX\t- CodeView %s Debug Info -\n\n", INDENT(level), foBase, 
           isPdb70 ? "pdb70" : "pdb20");
    printf("%sFO        Field         Value\n", INDENT(level));

    CV_INFO_PDB70 pdb70 = {0};
    CV_INFO_PDB20 pdb20 = {0};

    if (isPdb70) {
        memcpy(&pdb70.CvSignature, sig, 4);
        if (fread(((char*)&pdb70) + 4, sizeof(pdb70) - 4, 1, peFile) != 1) return RET_ERROR;
    } else if (memcmp(sig, "NB10", 4) == 0) {
        memcpy(&pdb20.CvSignature, sig, 4);
        if (fread(((char*)&pdb20) + 4, sizeof(pdb20) - 4, 1, peFile) != 1) return RET_ERROR;
    } else {
        fprintf(stderr, "%s[!!] Unknown CodeView signature: %.4s\n", INDENT(level), sig);
        return 1;
    }

    // CV Signature
    printf("%s%08lX  [ 4]\t\tCV Signature : %.4s\n",
        INDENT(level), foBase,
        isPdb70 ? (char*)&pdb70.CvSignature : (char*)&pdb20.CvSignature);
    foBase += 4;

    if (!isPdb70) {
        // PDB20 (NB10) layout
        printf("%s%08lX  [ 4]\t\tOffset        : %lX\n",
            INDENT(level), foBase,
            pdb20.Offset);
        foBase += 4;

        printf("%s%08lX  [ 4]\t\tSignature     : %lX\n",
            INDENT(level), foBase,
            pdb20.Signature);
        foBase += 4;

        printf("%s%08lX  [ 4]\t\tAge           : %lX\n",
            INDENT(level), foBase,
            pdb20.Age);
        foBase += 4;

    } else {
        // PDB70 (RSDS) layout

    printf("%s%08lX  [16]\t\tSignature    : %08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
        INDENT(level), foBase,
        (ULONG)pdb70.Signature.Data1,
        (USHORT)pdb70.Signature.Data2,
        (USHORT)pdb70.Signature.Data3,
        pdb70.Signature.Data4[0], pdb70.Signature.Data4[1],
        pdb70.Signature.Data4[2], pdb70.Signature.Data4[3],
        pdb70.Signature.Data4[4], pdb70.Signature.Data4[5],
        pdb70.Signature.Data4[6], pdb70.Signature.Data4[7]);

        foBase += sizeof(GUID);

        printf("%s%08lX  [ 4]\t\tAge          : %8lX\n",
            INDENT(level), foBase,
            pdb70.Age);

        foBase += 4;
    }

    char pdbFileName[100] = {0};

    if (FSEEK64(peFile, foBase, SEEK_SET) != 0) return RET_ERROR;

    if (fread(pdbFileName, sizeof(pdbFileName - 1), 1, peFile) != 1) return RET_ERROR;

    pdbFileName [99] = '\0';

    WORD nameSize = 0;
    while (pdbFileName[nameSize] != '\0') nameSize++;

    printf("%s%08lX  [%2d]\t\tPDB FileName : %s\n",
        INDENT(level), foBase, nameSize, pdbFileName);

    printf("\n");

    fflush(stdout);

    return RET_SUCCESS;
}

RET_CODE dump_FPO_debug_info(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DEBUG_DIRECTORY debugDir,
    WORD level) {
    
    if (!peFile || !debugDir) return RET_INVALID_PARAM; // sanity check

    DWORD foBase = debugDir->PointerToRawData;
    if (!foBase) {
        if (rva_to_offset(debugDir->AddressOfRawData, sections, numberOfSections, &foBase) != RET_SUCCESS) {
            fprintf(stderr, "%s[!!] Failed to map FPO Debug info RVA to file offset\n", INDENT(level));
            return RET_ERROR;
        }
    }

    if (FSEEK64(peFile, foBase, SEEK_SET) != 0) return RET_ERROR;

    WORD fpoCount = (WORD)(debugDir->SizeOfData / SIZEOF_RFPO_DATA);
    WORD maxDigit = count_digits(fpoCount); 

    printf("%s%08lX\t- FPO Debug Info - %s : %lX -\n\n",
        INDENT(level), foBase,
        fpoCount < 2 ? "Entry" : "Entries", (ULONG)fpoCount);

    for (WORD i = 0; i < fpoCount; i++) {
        FPO_DATA fpo = {0};

        if (fread(&fpo, SIZEOF_RFPO_DATA, 1, peFile) != 1) continue;

        const char* frameTypes[] = {"FPO", "TRAP", "TSS"};

        printf("%s[%0*d]  Frame Type (%s):", INDENT(level), maxDigit, i + 1, frameTypes[(int)fpo.cbFrame]);


        printf("%sOffset Start: %8lX | Function Size: %lX | Local Vars: %lu | Params: %u byte%c\n",
            INDENT(level + 1),
            fpo.ulOffStart,
            fpo.cbProcSize,
            (ULONG)fpo.cdwLocals * 4,
            fpo.cdwParams * 4,
            (fpo.cdwParams == 1) ? '\0' : 's');

        printf("%sRegisters Saved: %u | Has SEH: %s | Uses EBP: %s | Frame Type: %s\n",
            INDENT(level + 1),
            fpo.cbRegs,
            fpo.fHasSEH ? "Yes" : "No",
            fpo.fUseBP ? "Yes" : "No",
            frameTypes[fpo.cbFrame]);
            }

    printf("\n");

    fflush(stdout);

    return RET_SUCCESS;
}

// TODO : test this function to see if it working or not
RET_CODE dump_MISC_debug_info(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DEBUG_DIRECTORY debugDir,
    WORD level) {
    
    if (!peFile || !debugDir) return RET_INVALID_PARAM; // sanity check

    DWORD foBase = debugDir->PointerToRawData;
    if (!foBase) {
        if (rva_to_offset(debugDir->AddressOfRawData, sections, numberOfSections, &foBase) != RET_SUCCESS) {
            fprintf(stderr, "%s[!!] Failed to map MISC Debug info RVA to file offset\n", INDENT(level));
            return RET_ERROR;
        }
    }

    if (FSEEK64(peFile, foBase, SEEK_SET) != 0) return RET_ERROR;

    IMAGE_DEBUG_MISC misc = {0};

    if (fread(&misc, sizeof(misc), 1, peFile) != 1) return RET_ERROR;

    WORD maxDigit = count_digits(misc.Unicode ? misc.Length / 2 : misc.Length); 

    printf("%s%08lX\t- MISC Debug Info -\n\n", INDENT(level), foBase);
    printf("%sFO        Field         ", INDENT(level));
    for (int i = 1; i < maxDigit; i++) putchar(' ');
    printf("Value\n");

    // Print DataType
    printf("%s%08lX  [%0*d]\t\tDataType  : %lX %s\n",
        INDENT(level), foBase, maxDigit, 4,
        misc.DataType,
        misc.DataType == IMAGE_DEBUG_MISC_EXENAME ? "(IMAGE_DEBUG_MISC_EXENAME)" : "");

    foBase += 4;

    printf("%s%08lX  [%0*d]\t\tLength    : %lu bytes\n\n",
        INDENT(level), foBase, maxDigit, 4,
        misc.Length);

    foBase += 4;

    // Print Unicode flag and length
    printf("%s%08lX  [%0*zu]\t\tUnicode   : %s\n",
        INDENT(level), foBase, (int)maxDigit, sizeof(BOOLEAN),
        misc.Unicode ? "Yes" : "No");

    foBase += sizeof(BOOLEAN);

    // Print actual Data content
    printf("%s%08lX  [%0*ld]\t\tData      : \n",
        INDENT(level), foBase, maxDigit, misc.Unicode ? misc.Length / 2 : misc.Length);

    if (misc.Unicode) {
        wchar_t *wdata = (wchar_t*)misc.Data;
        for (DWORD i = 0; i < misc.Length / 2; i++) {
            if (iswprint(wdata[i]))
                wprintf(L"%s\t\t\t%04X : %c\n", INDENT(level + 1), i, wdata[i]);
            else
                wprintf(L"%s\t\t\t%04X : 0x%04X\n", INDENT(level + 1), i, wdata[i]);
        }
    } else {
        BYTE *bdata = misc.Data;
        for (DWORD i = 0; i < misc.Length; i++) {
            if (isprint(bdata[i]))
                printf("%s\t\t\t%04lX : %c\n", INDENT(level + 1), i, bdata[i]);
            else
                printf("%s\t\t\t%04lX : 0x%02lX\n", INDENT(level + 1), i, (ULONG)bdata[i]);
        }
    }

    printf("\n");

    fflush(stdout);

    return RET_SUCCESS;
}
     
void print_exception_debug_entries(
    PIMAGE_FUNCTION_ENTRY entries,
    ULONGLONG vaBase,
    DWORD foBase,
    DWORD maxEntries,
    WORD sizeOfEntry,
    WORD level) {

    ULONGLONG currentVa = vaBase;
    DWORD currentFo = foBase;

    // Header
    printf("%s%-5s %-16s %-8s   %-10s   %-10s   %-10s\n",
           INDENT(level), "Idx", "VirtAddr", "FileOff",
           "StartingAddr", "EndingAddr", "EndOfPrologue");

    for (DWORD i = 0; i < maxEntries; i++, currentVa += sizeOfEntry, currentFo += sizeOfEntry) {
        printf("%s%-5lu %016llX %08lX   %08lX   %08lX   %08lX\n",
            INDENT(level), i + 1,
            currentVa,
            currentFo,
            entries[i].StartingAddress,
            entries[i].EndingAddress,
            entries[i].EndOfPrologue
        );
    }

    // Consistent footer
    printf("\n%s\t\t\t[End of entries]\n", INDENT(level));
    fflush(stdout);
}

void print_exception_debug_entries64(
    PIMAGE_FUNCTION_ENTRY64 entries,
    WORD machine,
    ULONGLONG vaBase,
    DWORD foBase,
    DWORD maxEntries,
    WORD sizeOfEntry,
    WORD level) {

    ULONGLONG currentVa = vaBase;
    DWORD currentFo = foBase;

    int isAlpha = 0;
    if (machine == IMAGE_FILE_MACHINE_ALPHA || machine == IMAGE_FILE_MACHINE_ALPHA64) {
        isAlpha = 1;
    } else if (machine == IMAGE_FILE_MACHINE_AMD64 || machine == IMAGE_FILE_MACHINE_IA64) {
        isAlpha = 0;
    }

    // Header
    printf("%s%-5s %-16s %-8s   %-16s   %-16s   %-16s\n",
           INDENT(level), "Idx", "VirtAddr", "FileOff",
           "StartingAddr", "EndingAddr",
           isAlpha ? "EndOfPrologue" : "UnwindInfoAddr");

    for (DWORD i = 0; i < maxEntries; i++, currentVa += sizeOfEntry, currentFo += sizeOfEntry) {
        printf("%s%-5lu %016llX %08lX   %016llX   %016llX   %016llX\n",
            INDENT(level), i + 1,
            currentVa,
            currentFo,
            entries[i].StartingAddress,
            entries[i].EndingAddress,
            isAlpha ? entries[i].EndOfPrologue
                    : entries[i].UnwindInfoAddress
        );
    }

    // Consistent footer
    printf("\n%s\t\t\t[End of entries]\n", INDENT(level));
    fflush(stdout);
}

// TODO : test this function to see if it working or not
RET_CODE dump_exception_debug_info(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DEBUG_DIRECTORY debugDir,
    WORD machine,
    ULONGLONG imageBase,
    int is64bit,
    WORD level) {

    if (! !peFile || !debugDir) return RET_INVALID_PARAM; // sanity check

    DWORD rvaBase = debugDir->AddressOfRawData;
    ULONGLONG vaBase = imageBase + rvaBase;

    DWORD foBase = debugDir->PointerToRawData;
    if (!foBase) {
        if (rva_to_offset(rvaBase, sections, numberOfSections, &foBase) != RET_SUCCESS) {
            fprintf(stderr, "%s[!!] Failed to map Exception Debug info RVA to file offset\n", INDENT(level));
            return RET_ERROR;
        }
    }

    DWORD size = debugDir->SizeOfData;

    if (is64bit) {
        WORD entrySize = sizeof(IMAGE_FUNCTION_ENTRY64);
        DWORD maxEntries = size / (DWORD)entrySize;

        PIMAGE_FUNCTION_ENTRY64 entries = calloc(maxEntries, entrySize);
        if (!entries) {
            fprintf(stderr, "[!!] calloc failed\n"); 
            return RET_ERROR;
        }

        DWORD entriesCount = (DWORD)fill_entries(peFile, sections, numberOfSections, rvaBase, size, entries, entrySize);

        printf("\n%s%08lX\t- EXCEPTION DEBUG INFO - number of entries: %lu (entry type: %s)\n\n",
                INDENT(level), foBase, entriesCount, "IMAGE_FUNCTION_ENTRY64");

        print_exception_debug_entries64(entries, machine, vaBase, foBase, maxEntries, entrySize, level);
        SAFE_FREE(entries);
    }

    else {
        WORD entrySize = sizeof(IMAGE_FUNCTION_ENTRY);
        DWORD maxEntries = size / (DWORD)entrySize;

        PIMAGE_FUNCTION_ENTRY entries = calloc(maxEntries, entrySize);
        if (!entries) {
            fprintf(stderr, "[!!] calloc failed\n"); 
            return RET_ERROR;
        }

        DWORD entriesCount = (DWORD)fill_entries(peFile, sections, numberOfSections, rvaBase, size, entries, entrySize);
    
        printf("\n%s%08lX\t- EXCEPTION DEBUG INFO - number of entries: %lu (entry type: %s)\n\n",
                INDENT(level), foBase, entriesCount, "IMAGE_FUNCTION_ENTRY");

        print_exception_debug_entries(entries, vaBase, foBase, maxEntries, entrySize, level);
        SAFE_FREE(entries);
    }


    printf("\n");

    fflush(stdout);

    return RET_SUCCESS;
}

// TODO : test this function to see if it working or not
RET_CODE dump_OMAP_debug_info(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DEBUG_DIRECTORY debugDir,
    ULONGLONG imageBase,
    int isToSrc,
    WORD level) {

    if (!peFile || !debugDir) return RET_INVALID_PARAM; // sanity check

    DWORD rvaBase = debugDir->AddressOfRawData;
    ULONGLONG vaBase = imageBase + rvaBase;

    DWORD foBase = debugDir->PointerToRawData;
    if (!foBase) {
        if (rva_to_offset(rvaBase, sections, numberOfSections, &foBase) != RET_SUCCESS) {
            fprintf(stderr, "%s[!!] Failed to map OMAP Debug info RVA to file offset\n", INDENT(level));
            return RET_ERROR;
        }
    }

    DWORD size = debugDir->SizeOfData;

    WORD entrySize = sizeof(OMAP);
    DWORD maxEntries =  size / (DWORD)entrySize;

    POMAP entries = calloc(maxEntries, entrySize);
    if (!entries) {
        fprintf(stderr, "[!!] calloc failed\n"); 
        return RET_ERROR;
    }

    DWORD entriesCount = (DWORD)fill_entries(peFile, sections, numberOfSections, rvaBase, size, entries, entrySize);

    printf("\n%s%08lX\t- OMAP DEBUG INFO - number of entries: %lu (entry type: %s)\n\n",
            INDENT(level), foBase, entriesCount, isToSrc ? "To Source" : "From Source");


    WORD digitMax = count_digits(entriesCount); 

    printf("%s%-*s %-16s %-8s   %-8s   %-8s\n",
        INDENT(level), digitMax + 2,
        "idx", "virtualAddrOff", "fileOff", "RVA", "RVA To");

    for (DWORD i = 0; i < entriesCount; i++, vaBase += entrySize, foBase += entrySize) {
        printf("%s[%0*lu] %016llX %08lX   %08lX   %08lX\n",
        INDENT(level), digitMax, i,
        vaBase, foBase,
        entries[i].rva, entries[i].rvaTo);
    }

    SAFE_FREE(entries);

    fflush(stdout);

    return RET_SUCCESS;
}

RET_CODE dump_REPRO_debug_info(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DEBUG_DIRECTORY debugDir,
    WORD level) {

    if (!peFile || !debugDir) return RET_INVALID_PARAM;

    DWORD rvaBase = debugDir->AddressOfRawData;
    DWORD foBase  = debugDir->PointerToRawData;

    if (!foBase) {
        if (rva_to_offset(rvaBase, sections, numberOfSections, &foBase) != RET_SUCCESS) {
            fprintf(stderr, "%s[!!] Failed to map REPRO Debug info RVA to file offset\n", INDENT(level));
            return RET_ERROR;
        }
    }

    if (FSEEK64(peFile, foBase, SEEK_SET) != 0) return RET_ERROR;

    WORD size = 0;
    if (fread(&size, sizeof(DWORD), 1, peFile) != 1) return RET_ERROR;

    if (size > debugDir->SizeOfData - sizeof(DWORD)) {
        fprintf(stderr, "%s[!!] Invalid REPRO hash length (%d)\n", INDENT(level), size);
        return 1;
    }

    BYTE hash[64];
    if (size > sizeof(hash)) {
        fprintf(stderr, "%s[!!] Unexpectedly large REPRO hash length (%d)\n", INDENT(level), size);
        return 1;
    }

    if (fread(hash, 1, size, peFile) != size) return RET_ERROR;

    printf("%s%08lX\t - REPRO Debug Info -\n\n", INDENT(level), foBase);

    printf("%sREPRO hash (hash type: %s): ", INDENT(level), GetHashType(size));
    for (WORD i = 0; i < size; i++) {
        printf("%02X", hash[i]);
    }

    printf("\n\n");

    return RET_SUCCESS;
}

RET_CODE dump_VC_feature_debug_info(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DEBUG_DIRECTORY debugDir,
    WORD level) {

    if (!peFile || !debugDir) return RET_INVALID_PARAM;

    DWORD rvaBase = debugDir->AddressOfRawData;
    DWORD foBase  = debugDir->PointerToRawData;

    if (!foBase) {
        if (rva_to_offset(rvaBase, sections, numberOfSections, &foBase) != RET_SUCCESS) {
            fprintf(stderr, "%s[!!] Failed to map VC Feature Debug info RVA to file offset\n", INDENT(level));
            return RET_ERROR;
        }
    }

    if (FSEEK64(peFile, foBase, SEEK_SET) != 0) return RET_ERROR;

    VC_FEATURE entry = {0};

    if (fread(&entry, sizeof(entry), 1, peFile) != 1) return RET_ERROR;
 
    printf("%s%08lX\t - VC Feature Debug Info -\n\n", INDENT(level), foBase);

    printf("%s%08lX\tCharacteristics: %08lX\n", INDENT(level), foBase, entry.Characteristics);

    static const FlagDesc vcFeaturesFlags[] = {
        {VC_FEATURE_FLAG_NONE, "VC_FEATURE_FLAG_NONE"},
        {VC_FEATURE_FLAG_EH, "VC_FEATURE_FLAG_EH"},
        {VC_FEATURE_FLAG_RTTI, "VC_FEATURE_FLAG_RTTI"},
        {VC_FEATURE_FLAG_COPY_CTOR, "VC_FEATURE_FLAG_COPY_CTOR"},
        {VC_FEATURE_FLAG_OPENMP, "VC_FEATURE_FLAG_OPENMP"},
        {VC_FEATURE_FLAG_CRT, "VC_FEATURE_FLAG_CRT"}
    };

    int vcFeaturesFlagsCount = sizeof(vcFeaturesFlags) / sizeof(vcFeaturesFlags[0]);

    for (int i = 0; i < vcFeaturesFlagsCount; i++) {
        if (entry.Characteristics & vcFeaturesFlags[i].flag) {
            printf("%s\t\t+ %08lX  %-50s\n",
                    INDENT(level),
                     vcFeaturesFlags[i].flag,
                    vcFeaturesFlags[i].name);
        }
    } 

    printf("\n");

    fflush(stdout);

    return RET_SUCCESS;
}

RET_CODE dump_debug_dir( // NOT FINISHED YET
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY debugDataDir,
    PIMAGE_DEBUG_DIRECTORY debugDir,
    WORD machine,
    ULONGLONG imageBase,
    int is64bit) {

    if (!peFile || !debugDataDir || !debugDir) return RET_INVALID_PARAM; // sanity check

    // completely empty = skip gracefully
    if (debugDataDir->VirtualAddress == 0 && debugDataDir->Size == 0)
        return RET_MALFORMED_FILE;

    // partially defined = suspicious
    if (debugDataDir->VirtualAddress == 0 || debugDataDir->Size == 0)
        return REPORT_MALFORMED("Debug directory partially empty (RVA=0 or Size=0)", "Debug Data Directory");

    DWORD foBase;
    if (rva_to_offset(debugDataDir->VirtualAddress, sections, numberOfSections, &foBase) != RET_SUCCESS) {
        fprintf(stderr, "[!!] Failed to map Debug Directory RVA to file offset\n");
        return RET_ERROR;
    }

    // Calculate the number of IMAGE_DEBUG_DIRECTORY entries
    // The Size field in the Data Directory tells us total bytes for all entries
    DWORD totalEntries = debugDataDir->Size / sizeof(IMAGE_DEBUG_DIRECTORY);

    WORD maxDigit = count_digits(totalEntries); 

    // Print debug directory header
    printf("\n%08lX\t- DEBUG DIRECTORY - number of debug %s: %ld -\n\n",
        foBase, totalEntries < 2 ? "entry" : "entries", totalEntries);    

    for (DWORD i = 0; i < totalEntries; i++) {

        printf("[%0*ld] Type Name: %s (FO=%lX)\n", maxDigit, i + 1, get_debug_type_name(debugDir[i].Type), foBase);

        DWORD ts = debugDir[i].TimeDateStamp;

        char tsStr[42];
        if ((ts >= SOME_REASONABLE_EPOCH && ts <= CURRENT_EPOCH_PLUS_MARGIN) || ts == 0) {
            snprintf(tsStr, sizeof(tsStr), "Time Data Stamp: %lX %s", ts, format_timestamp(ts));
        } else {
            snprintf(tsStr, sizeof(tsStr), "ReproChecksum: %lu", ts);
        }

        // Prepare RVA/Raw Data info
        char rvaStr[64] = {0};
        if (debugDir[i].AddressOfRawData != 0) {
            RVA_INFO r = get_rva_info(debugDir[i].AddressOfRawData, sections, numberOfSections, imageBase);
            snprintf(rvaStr, sizeof(rvaStr), "  [VA: %llX] [FO: %lX] [%-8s]", r.va, r.fileOffset, r.sectionName);
        }

        // First line: core info only
        printf("%sCharacteristics: %lX | %s | Version: %lX.%lX | Type: %lX | Size Of Data: %lX\n",
            INDENT(2), debugDir[i].Characteristics,
            tsStr,
            (ULONG)debugDir[i].MajorVersion, (ULONG)debugDir[i].MinorVersion,
            debugDir[i].Type, debugDir[i].SizeOfData);

        // Second line: everything related to addresses, pointers, and offsets
        printf("%sAddress Of Raw Data: %08lX%s | Pointer To Raw Data: %08lX\n\n",
            INDENT(2), debugDir[i].AddressOfRawData, rvaStr,
            debugDir[i].PointerToRawData);

        WORD debugInfoLevel = 3;

        switch(debugDir[i].Type) {
            case IMAGE_DEBUG_TYPE_UNKNOWN:
                fprintf(stderr, "%s[!!] Failed to identify the debug info structure\n", INDENT(debugInfoLevel)); 
                break;

            case IMAGE_DEBUG_TYPE_COFF: // COFF symbol table (legacy). Rarely used in modern MSVC, but format is documented.
                if(dump_COFF_debug_info(peFile, sections, numberOfSections, &debugDir[i], debugInfoLevel) != RET_SUCCESS) {
                    fprintf(stderr, "%s[!!] Failed to dump / parse COFF debug info\n", INDENT(debugInfoLevel)); 
                    break;
                }
                break;
            
            case IMAGE_DEBUG_TYPE_CODEVIEW: // CodeView -> points to PDB info (modern compilers). Well documented.
                if(dump_CodeView_debug_info(peFile, sections, numberOfSections, &debugDir[i], debugInfoLevel) != RET_SUCCESS) {
                    fprintf(stderr, "%s[!!] Failed to dump / parse CodeView debug info\n", INDENT(debugInfoLevel)); 
                    break;
                }
                break;

            case IMAGE_DEBUG_TYPE_FPO: // Frame Pointer Omission info (stack unwinding for x86). Documented but old.
                if(dump_FPO_debug_info(peFile, sections, numberOfSections, &debugDir[i], debugInfoLevel) != RET_SUCCESS) {
                    fprintf(stderr, "%s[!!] Failed to dump / parse FPO debug info\n", INDENT(2)); 
                    break;
                }
                break;

            case IMAGE_DEBUG_TYPE_MISC: // Miscellaneous info (e.g., path to PDB). Format documented.
                if(dump_MISC_debug_info(peFile, sections, numberOfSections, &debugDir[i], debugInfoLevel) != RET_SUCCESS) {
                    fprintf(stderr, "%s[!!] Failed to dump / parse MISC debug info\n", INDENT(2)); 
                    break;
                }
                break;

            case IMAGE_DEBUG_TYPE_EXCEPTION: // Exception handling data (unwind info). Documented.
                if(dump_exception_debug_info(peFile, sections, numberOfSections, &debugDir[i], machine, imageBase, is64bit, debugInfoLevel) != RET_SUCCESS) {
                    fprintf(stderr, "%s[!!] Failed to dump / parse Exception debug info\n", INDENT(debugInfoLevel)); 
                    break;
                }
                break;

            case IMAGE_DEBUG_TYPE_FIXUP: 
                // Obsolete, never really standardized. Was meant for incremental linking fixups.
                break;

            case IMAGE_DEBUG_TYPE_OMAP_TO_SRC: // Address mapping tables (for /OPT:REF & profile-guided builds). Documented.
                if(dump_OMAP_debug_info(peFile, sections, numberOfSections, &debugDir[i], imageBase, 1, debugInfoLevel) != RET_SUCCESS) {
                    fprintf(stderr, "%s[!!] Failed to dump / parse OMAP debug info\n", INDENT(debugInfoLevel)); 
                    break;
                }
                break;

            case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC: // Reverse address mapping. Documented.
                if(dump_OMAP_debug_info(peFile, sections, numberOfSections, &debugDir[i], imageBase, 0, debugInfoLevel) != RET_SUCCESS) {
                    fprintf(stderr, "%s[!!] Failed to dump / parse OMAP debug info\n", INDENT(debugInfoLevel)); 
                    break;
                }
                break;

            case IMAGE_DEBUG_TYPE_BORLAND: 
                // Borland-specific debug format (private). Points to a symbol table, but structure not published.
                break;

            case IMAGE_DEBUG_TYPE_BBT: 
                // Binary Block Transfer (MS internal profiling/optimization data). Undocumented, toolchain-private.
                break;

            case IMAGE_DEBUG_TYPE_CLSID: 
                // Embeds a GUID to uniquely identify the binary. Very rare. Structure is just a GUID, not widely used.
                break;

            case IMAGE_DEBUG_TYPE_VC_FEATURE: 
                // VC++ feature metadata (e.g., /GS, /guard flags). Very lightly documented by MS. Payload is a bitfield.
                if(dump_VC_feature_debug_info(peFile, sections, numberOfSections, &debugDir[i], debugInfoLevel) != RET_SUCCESS) {
                    fprintf(stderr, "%s[!!] Failed to dump / parse VC Feature debug info\n", INDENT(debugInfoLevel)); 
                    break;
                }
                break;

            case IMAGE_DEBUG_TYPE_POGO: 
                // Profile-Guided Optimization data. Undocumented format. 
                // Exists only for MSVC toolchain; other tools just skip or dump raw bytes.
                break;

            case IMAGE_DEBUG_TYPE_ILTCG: 
                // Incremental Link-Time Code Generation info. Undocumented, internal to MSVC linker.
                break;

            case IMAGE_DEBUG_TYPE_MPX: 
                // Multiplexed Profile-Guided Optimization data (older/experimental). Undocumented.
                break;

            case IMAGE_DEBUG_TYPE_REPRO: 
                // Reproducibility checksum. Documented: a hash of sections for build reproducibility.
                if(dump_REPRO_debug_info(peFile, sections, numberOfSections, &debugDir[i], debugInfoLevel) != RET_SUCCESS) {
                    fprintf(stderr, "%s[!!] Failed to dump / parse REPRO debug info\n", INDENT(debugInfoLevel)); 
                    break;
                }
                break;

            case IMAGE_DEBUG_TYPE_SPGO: 
                // Static Profile Guided Optimization metadata. Undocumented, used only by MSVC toolchain.
                break;

            case IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS:
                // Extended DLL characteristics flags. Very rarely seen, and not documented in PE/COFF spec.
                break;

            default:  
                // Unknown or reserved type. Treat as opaque blob.
                break;
        }

        foBase += sizeof(IMAGE_DEBUG_DIRECTORY);

    }

    fflush(stdout);

    return RET_SUCCESS;
}

RET_CODE dump_tls_dir(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY tlsDataDir,
    PIMAGE_TLS_DIRECTORY64 tls64,
    PIMAGE_TLS_DIRECTORY32 tls32,
    ULONGLONG imageBase,
    int is64bit) {

    if (!peFile || !tlsDataDir || (!tls64 && !tls32)) return RET_INVALID_PARAM; // sanity check

    // completely empty = skip gracefully
    if (tlsDataDir->VirtualAddress == 0 && tlsDataDir->Size == 0)
        return RET_MALFORMED_FILE;

    // partially defined = suspicious
    if (tlsDataDir->VirtualAddress == 0 || tlsDataDir->Size == 0)
        return REPORT_MALFORMED("TLS directory partially empty (RVA=0 or Size=0)", "TLS Data Directory");

    ULONGLONG vaBase = imageBase + tlsDataDir->VirtualAddress;

    DWORD foBase;
    if (rva_to_offset(tlsDataDir->VirtualAddress, sections, numberOfSections, &foBase) != RET_SUCCESS) {
        printf("[!!] Failed to map TLS Directory RVA to file offset\n");
        return RET_ERROR;
    }

    printf("\n%016llX\t- TLS DIRECTORY -\n\n", vaBase);

    printf("VA                FO        Field       Value\n");


    if (is64bit) {
        printf("%016llX  %08lX  [8]\t\tStart Address Of Raw Data : %016llX\n",
            vaBase, foBase, tls64->StartAddressOfRawData);
            vaBase += 8; foBase += 8;

        printf("%016llX  %08lX  [8]\t\tEnd Address Of Raw Data   : %016llX\n\n",
            vaBase, foBase, tls64->EndAddressOfRawData);
            vaBase += 8; foBase += 8;
    
        printf("%016llX  %08lX  [8]\t\tAddress Of Index          : %016llX\n\n",
            vaBase, foBase, tls64->AddressOfIndex);
            vaBase += 8; foBase += 8;

        printf("%016llX  %08lX  [8]\t\tAddress Of Call Backs     : %016llX\n\n",
            vaBase, foBase, tls64->AddressOfCallBacks);
            vaBase += 8; foBase += 8;

    } else {
        printf("%016llX  %08lX  [4]\t\tStart Address Of Raw Data : %08lX\n",
            vaBase, foBase, tls32->StartAddressOfRawData);
            vaBase += 4; foBase += 4;

        printf("%016llX  %08lX  [4]\t\tEnd Address Of Raw Data   : %08lX\n\n",
            vaBase, foBase, tls32->EndAddressOfRawData);
            vaBase += 4; foBase += 4;

        printf("%016llX  %08lX  [4]\t\tAddress Of Index          : %08lX\n\n",
            vaBase, foBase, tls32->AddressOfIndex);
            vaBase += 4; foBase += 4;

        printf("%016llX  %08lX  [4]\t\tAddress Of Call Backs     : %08lX\n\n",
            vaBase, foBase, tls32->AddressOfCallBacks);
            vaBase += 4; foBase += 4;
    }

    printf("%016llX  %08lX  [4]\t\tSize Of Zero Fill         : %08lX\n\n",
        vaBase, foBase, is64bit ? tls64->SizeOfZeroFill : tls32->SizeOfZeroFill);
        vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tCharacteristics           : %08lX\n\n",
        vaBase, foBase, is64bit ? tls64->Characteristics : tls32->Characteristics);
        vaBase += 4; foBase += 4;

    ULONGLONG addressOfCallBacks = is64bit ? tls64->AddressOfCallBacks : tls32->AddressOfCallBacks;

    if (addressOfCallBacks) {
        DWORD rvaOfCallBacks = (DWORD)(addressOfCallBacks - imageBase);

        DWORD offOfCallBacks;
        if (rva_to_offset(rvaOfCallBacks, sections, numberOfSections, &offOfCallBacks) != RET_SUCCESS) {
            printf("[!!] Failed to map Call Backs RVA to file offset\n");
            return RET_ERROR;
        }

        if (FSEEK64(peFile, offOfCallBacks, SEEK_SET) != 0) return RET_ERROR;

        printf("\n%016llX\t- CALL BACK ENTRIES -\n\n", addressOfCallBacks);


        printf("%-5s  %-16s  %-16s  %-16s\n",
            "Idx", "AddrOfCallBacks", "OffOfCallBacks", "CallBackEntries");

        int i = 0;

        while (1) {
            DWORD callBackEntry;

            if (fread(&callBackEntry, sizeof(DWORD), 1, peFile) != 1) continue;

            if (callBackEntry == 0) break;

            printf("%-5d  %016llX  %08lX          %08lX\n",
                i + 1, addressOfCallBacks, offOfCallBacks, callBackEntry);
                addressOfCallBacks += 4; offOfCallBacks += 4;            

            i++;
        }
        printf("\n");
    }

    fflush(stdout);

    return RET_SUCCESS;
}

RET_CODE print_load_config_table(
    FILE* peFile,
    ULONGLONG tableVA,
    ULONGLONG tableCount,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    ULONGLONG imageBase,
    const char* tableName) {

    if (!peFile || tableVA == 0 || tableCount == 0) return RET_INVALID_PARAM;
    

    printf("\t- %s table (VA: %llX) - %llu entries -\n\n",
           tableName, tableVA, tableCount);

    printf(" ----------------------------------------------------------------------------------\n");
        
    // Calculate number of digits for zero-padded index
    WORD digits = count_digits(tableCount);
    
    ULONGLONG currentVA = tableVA;
    DWORD fileOffset = 0;

    if (rva_to_offset((DWORD)(tableVA - imageBase), sections, numberOfSections, &fileOffset) != RET_SUCCESS) {
        printf(" VA: 0x%llX  [Could not map to file offset]\n", tableVA);
        return RET_ERROR;
    }

    for (ULONGLONG i = 0; i < tableCount; i++) {
        // Seek to the current entry
        if (FSEEK64(peFile, fileOffset, SEEK_SET) != 0) {
            printf("  [%0*llu] VA: 0x%llX  [Failed to seek]\n", digits, i, currentVA);
            break;
        }

        // Read the entry value
        DWORD value = 0;
        if (fread(&value, sizeof(DWORD), 1, peFile) != 1) break;

        BYTE meta = 0;
        if (fread(&meta, sizeof(BYTE), 1, peFile) != 1) break;

        // Stop if entry is null (common for pointer tables)
        if (value == 0) break;

        RVA_INFO valueInfo = get_rva_info(value, sections, numberOfSections, imageBase);

        printf("  [%0*llu] VA: %-16llX FO: %-8lX  Value: %-8lX Meta: %-1X  [   %-8s]\n",
               digits, i + 1, currentVA, fileOffset, value, meta, valueInfo.sectionName);

        currentVA += sizeof(DWORD) + sizeof(BYTE);  // 5 bytes per entry
        fileOffset += sizeof(DWORD) + sizeof(BYTE);
    }

    printf(" ----------------------------------------------------------------------------------\n");

    printf("\n");
    fflush(stdout);
    return RET_SUCCESS;
}

// TODO: Dump the Catalog Certificate (Security Directory)
// TODO: Parse and dump the Hotpatch Table
// TODO: Parse and dump IMAGE_ENCLAVE_CONFIG32 & IMAGE_ENCLAVE_CONFIG64
// TODO: Research the windows sdk 11 and windows sdk 10 for the UmaFunctionPointers
RET_CODE dump_load_config_dir(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY lcfgDataDir,
    PIMAGE_LOAD_CONFIG_DIRECTORY64 loadConfig64,
    PIMAGE_LOAD_CONFIG_DIRECTORY32 loadConfig32,
    ULONGLONG imageBase,
    int is64bit) {
    if (!peFile || !lcfgDataDir || (!loadConfig64 && !loadConfig32)) return RET_INVALID_PARAM; // sanity check

    // completely empty = skip gracefully
    if (lcfgDataDir->VirtualAddress == 0 && lcfgDataDir->Size == 0)
        return RET_MALFORMED_FILE;

    // partially defined = suspicious
    if (lcfgDataDir->VirtualAddress == 0 || lcfgDataDir->Size == 0)
        return REPORT_MALFORMED("Load Config directory partially empty (RVA=0 or Size=0)", "Load Config Data Directory");

    ULONGLONG vaBase = imageBase + lcfgDataDir->VirtualAddress;

    DWORD foBase;
    if (rva_to_offset(lcfgDataDir->VirtualAddress, sections, numberOfSections, &foBase) != RET_SUCCESS) {
        printf("[!!] Failed to map Load Config Directory RVA to file offset\n");
        return RET_ERROR;
    }

    printf("\n%016llX\t- LOAD CONFIG DIRECTORY -\n\n", vaBase);
    printf("VA                FO        Field       Value\n");
 
    printf("%016llX  %08lX  [4]\t\tSize                                           : %08lX\n\n",
           vaBase, foBase,
           is64bit ? loadConfig64->Size : loadConfig32->Size);

    vaBase += 4; foBase += 4;

    DWORD ts = is64bit ? loadConfig64->TimeDateStamp : loadConfig32->TimeDateStamp;

    if ((ts >= SOME_REASONABLE_EPOCH && ts <= CURRENT_EPOCH_PLUS_MARGIN) || ts == 0) {
        printf("%016llX  %08lX  [4]\t\tTime Date Stamp                                : %08lX  %s\n\n", 
            vaBase, foBase, ts, format_timestamp(ts));
    } else {
        printf("%016llX  %08lX  [4]\t\tReproChecksum                                  : %08lX (%lu)\n\n", 
            vaBase, foBase, ts, ts);
    }

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [2]\t\tMinor Version                                  : %04X\n",
           vaBase, foBase,
           is64bit ? loadConfig64->MinorVersion : loadConfig32->MinorVersion);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tMajor Version                                  : %04X\n\n",
           vaBase, foBase,
           is64bit ? loadConfig64->MajorVersion : loadConfig32->MajorVersion);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [4]\t\tGlobal Flag Clear                              : %08lX\n",
           vaBase, foBase,
           is64bit ? loadConfig64->GlobalFlagsClear : loadConfig32->GlobalFlagsClear);

    vaBase += 4; foBase += 4;

    static const FlagDesc GlobalFlagsTable[] = {
        {FLG_STOP_ON_EXCEPTION,           "FLG_STOP_ON_EXCEPTION"},
        {FLG_SHOW_LDR_SNAPS,              "FLG_SHOW_LDR_SNAPS"},
        {FLG_DEBUG_INITIAL_COMMAND,       "FLG_DEBUG_INITIAL_COMMAND"},
        {FLG_STOP_ON_HUNG_GUI,            "FLG_STOP_ON_HUNG_GUI"},
        {FLG_HEAP_ENABLE_TAIL_CHECK,      "FLG_HEAP_ENABLE_TAIL_CHECK"},
        {FLG_HEAP_ENABLE_FREE_CHECK,      "FLG_HEAP_ENABLE_FREE_CHECK"},
        {FLG_HEAP_VALIDATE_PARAMETERS,    "FLG_HEAP_VALIDATE_PARAMETERS"},
        {FLG_HEAP_VALIDATE_ALL,           "FLG_HEAP_VALIDATE_ALL"},
        {FLG_POOL_ENABLE_TAIL_CHECK,      "FLG_POOL_ENABLE_TAIL_CHECK"},
        {FLG_POOL_ENABLE_FREE_CHECK,      "FLG_POOL_ENABLE_FREE_CHECK"},
        {FLG_POOL_ENABLE_TAGGING,         "FLG_POOL_ENABLE_TAGGING"},
        {FLG_HEAP_ENABLE_TAGGING,         "FLG_HEAP_ENABLE_TAGGING"},
        {FLG_USER_STACK_TRACE_DB,         "FLG_USER_STACK_TRACE_DB"},
        {FLG_KERNEL_STACK_TRACE_DB,       "FLG_KERNEL_STACK_TRACE_DB"},
        {FLG_MAINTAIN_OBJECT_TYPELIST,    "FLG_MAINTAIN_OBJECT_TYPELIST"},
        {FLG_HEAP_ENABLE_TAG_BY_DLL,      "FLG_HEAP_ENABLE_TAG_BY_DLL"},
        {FLG_DISABLE_STACK_EXTENSION,     "FLG_DISABLE_STACK_EXTENSION"},
        {FLG_ENABLE_CSRDEBUG,             "FLG_ENABLE_CSRDEBUG"},
        {FLG_ENABLE_KDEBUG_SYMBOL_LOAD,   "FLG_ENABLE_KDEBUG_SYMBOL_LOAD"},
        {FLG_DISABLE_PAGE_KERNEL_STACKS,  "FLG_DISABLE_PAGE_KERNEL_STACKS"},
        {FLG_ENABLE_SYSTEM_CRIT_BREAKS,   "FLG_ENABLE_SYSTEM_CRIT_BREAKS"},
        {FLG_HEAP_DISABLE_COALESCING,     "FLG_HEAP_DISABLE_COALESCING"},
        {FLG_ENABLE_CLOSE_EXCEPTIONS,     "FLG_ENABLE_CLOSE_EXCEPTIONS"},
        {FLG_ENABLE_EXCEPTION_LOGGING,    "FLG_ENABLE_EXCEPTION_LOGGING"},
        {FLG_ENABLE_HANDLE_TYPE_TAGGING,  "FLG_ENABLE_HANDLE_TYPE_TAGGING"},
        {FLG_HEAP_PAGE_ALLOCS,            "FLG_HEAP_PAGE_ALLOCS"},
        {FLG_DEBUG_INITIAL_COMMAND_EX,    "FLG_DEBUG_INITIAL_COMMAND_EX"},
        {FLG_DISABLE_DBGPRINT,            "FLG_DISABLE_DBGPRINT"},
        {FLG_CRITSEC_EVENT_CREATION,      "FLG_CRITSEC_EVENT_CREATION"},
        {FLG_LDR_TOP_DOWN,                "FLG_LDR_TOP_DOWN"}
    };

    DWORD GlobalFlagsCount = sizeof(GlobalFlagsTable) / sizeof(GlobalFlagsTable[0]);

    for (DWORD i = 0; i < GlobalFlagsCount; i++) {
        if ((is64bit ? loadConfig64->GlobalFlagsClear : loadConfig32->GlobalFlagsClear) & GlobalFlagsTable[i].flag) {
            printf("\t\t\t\t\t\t\t\t\t               + %08lX  %-50s\n",
                    GlobalFlagsTable[i].flag,
                    GlobalFlagsTable[i].name);
        }
    }

    if (is64bit ? loadConfig64->GlobalFlagsClear != 0 : loadConfig32->GlobalFlagsClear != 0) printf("\n");

    printf("%016llX  %08lX  [4]\t\tGlobal Flag Set                                : %08lX\n",
           vaBase, foBase,
           is64bit ? loadConfig64->GlobalFlagsSet : loadConfig32->GlobalFlagsSet);

    vaBase += 4; foBase += 4;

    for (DWORD i = 0; i < GlobalFlagsCount; i++) {
        if ((is64bit ? loadConfig64->GlobalFlagsSet : loadConfig32->GlobalFlagsSet) & GlobalFlagsTable[i].flag) {
            printf("\t\t\t\t\t\t\t\t\t               + %08lX  %-50s\n",
                    GlobalFlagsTable[i].flag,
                    GlobalFlagsTable[i].name);
        }
    }

    printf("\n");

    printf("%016llX  %08lX  [4]\t\tCritical Section Default Timeout               : %08lX\n\n",
           vaBase, foBase,
           is64bit ? loadConfig64->CriticalSectionDefaultTimeout : loadConfig32->CriticalSectionDefaultTimeout);

    vaBase += 4; foBase += 4;

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tDeCommit Block Free Threshold                  : %0*llX\n",
            vaBase, foBase, 8,
            16, loadConfig64->DeCommitFreeBlockThreshold);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tDeCommit Block Free Threshold                  : %0*lX\n",
            vaBase, foBase, 4,
            8, loadConfig32->DeCommitFreeBlockThreshold);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tDeCommit Total Free Threshold                  : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->DeCommitTotalFreeThreshold);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tDeCommit Total Free Threshold                  : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->DeCommitTotalFreeThreshold);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        if (loadConfig64->LockPrefixTable == 0) {
            printf("%016llX  %08lX  [%d]\t\tLock Prefix Table                              : %0*llX\n",
                vaBase, foBase, 8,
                16, loadConfig64->LockPrefixTable);
        } else {
            RVA_INFO PrefixTableRvaInfo = get_rva_info((DWORD)loadConfig64->LockPrefixTable, sections, numberOfSections, imageBase);
            
            printf("%016llX  %08lX  [%d]\t\tLock Prefix Table                              : %0*llX  [VA: %llX] [FO: %lX] [  %-8s]\n",
                vaBase, foBase, 8,
                16, loadConfig64->LockPrefixTable,
                PrefixTableRvaInfo.va, PrefixTableRvaInfo.fileOffset, PrefixTableRvaInfo.sectionName);
        }
        vaBase += 8; foBase += 8;
    } else {
        if (loadConfig32->LockPrefixTable == 0) {
            printf("%016llX  %08lX  [%d]\t\tLock Prefix Table                              : %0*lX\n",
                vaBase, foBase, 4,
                8, loadConfig32->LockPrefixTable);
        } else {
            RVA_INFO PrefixTableRvaInfo = get_rva_info(loadConfig32->LockPrefixTable, sections, numberOfSections, imageBase);
            
            printf("%016llX  %08lX  [%d]\t\tLock Prefix Table                              : %0*lX  [VA: %llX] [FO: %lX] [  %-8s]\n",
                vaBase, foBase, 4,
                8, loadConfig32->LockPrefixTable,
                PrefixTableRvaInfo.va, PrefixTableRvaInfo.fileOffset, PrefixTableRvaInfo.sectionName);
        }
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tMaximum Allocation Size                        : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->MaximumAllocationSize);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tMaximum Allocation Size                        : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->MaximumAllocationSize);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tVirtual Memory Threshold                       : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->VirtualMemoryThreshold);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tVirtual Memory Threshold                       : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->VirtualMemoryThreshold);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tProcess Affinity Mask                          : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->ProcessAffinityMask);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tProcess Affinity Mask                          : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->ProcessAffinityMask);
        vaBase += 4; foBase += 4;
    }

    printf("%016llX  %08lX  [4]\t\tProcess Heap Flags                             : %08lX\n",
           vaBase, foBase,
           is64bit ? loadConfig64->ProcessHeapFlags : loadConfig32->ProcessHeapFlags);

    vaBase += 4; foBase += 4;

    static const FlagDesc ProcessHeapFlagsTable[] = {
        {HEAP_NO_SERIALIZE,             "HEAP_NO_SERIALIZE"},
        {HEAP_GROWABLE,                 "HEAP_GROWABLE"},
        {HEAP_GENERATE_EXCEPTIONS,      "HEAP_GENERATE_EXCEPTIONS"},
        {HEAP_ZERO_MEMORY,              "HEAP_ZERO_MEMORY"},
        {HEAP_REALLOC_IN_PLACE_ONLY,    "HEAP_REALLOC_IN_PLACE_ONLY"},
        {HEAP_TAIL_CHECKING_ENABLED,    "HEAP_TAIL_CHECKING_ENABLED"},
        {HEAP_FREE_CHECKING_ENABLED,    "HEAP_FREE_CHECKING_ENABLED"},
        {HEAP_DISABLE_COALESCE_ON_FREE, "HEAP_DISABLE_COALESCE_ON_FREE"},
        {HEAP_CREATE_SEGMENT_HEAP,      "HEAP_CREATE_SEGMENT_HEAP"},
        {HEAP_CREATE_HARDENED,          "HEAP_CREATE_HARDENED"},
        {HEAP_CREATE_ALIGN_16,          "HEAP_CREATE_ALIGN_16"},
        {HEAP_CREATE_ENABLE_TRACING,    "HEAP_CREATE_ENABLE_TRACING"},
        {HEAP_CREATE_ENABLE_EXECUTE,    "HEAP_CREATE_ENABLE_EXECUTE"}
    };

    DWORD ProcessHeapFlagsCount = sizeof(ProcessHeapFlagsTable) / sizeof(ProcessHeapFlagsTable[0]);

    for (DWORD i = 0; i < ProcessHeapFlagsCount; i++) {
        if ((is64bit ? loadConfig64->ProcessHeapFlags : loadConfig32->ProcessHeapFlags) & ProcessHeapFlagsTable[i].flag) {
            printf("\t\t\t\t\t\t\t\t\t               + %08lX  %-35s\n",
                    ProcessHeapFlagsTable[i].flag,
                    ProcessHeapFlagsTable[i].name);
        }
    }

    printf("\n");

    printf("%016llX  %08lX  [2]\t\tCSD Version                                    : %04X\n\n",
           vaBase, foBase,
           is64bit ? loadConfig64->CSDVersion : loadConfig32->CSDVersion);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tDependent Load Flags                           : %04X\n",
           vaBase, foBase,
           is64bit ? loadConfig64->DependentLoadFlags : loadConfig32->DependentLoadFlags);

    vaBase += 2; foBase += 2;

    static const FlagDesc DependentLoadFlagsTable[] = {
        {LOAD_FLAGS_NO_SEH,                             "LOAD_FLAGS_NO_SEH"},
        {LOAD_FLAGS_NO_BIND,                            "LOAD_FLAGS_NO_BIND"},
        {LOAD_FLAGS_NO_DELAYLOAD,                       "LOAD_FLAGS_NO_DELAYLOAD"},
        {LOAD_FLAGS_GUARD_CF,                           "LOAD_FLAGS_GUARD_CF"},
        {LOAD_FLAGS_GUARD_CF_EXPORT_SUPPRESSION,        "LOAD_FLAGS_GUARD_CF_EXPORT_SUPPRESSION"},
        {LOAD_FLAGS_GUARD_CF_ENABLE_EXPORT_SUPPRESSION, "LOAD_FLAGS_GUARD_CF_ENABLE_EXPORT_SUPPRESSION"}
    };

    DWORD DependentLoadFlagsTableCount = sizeof(DependentLoadFlagsTable) / sizeof(DependentLoadFlagsTable[0]);

    for (DWORD i = 0; i < DependentLoadFlagsTableCount; i++) {
        if ((is64bit ? loadConfig64->DependentLoadFlags : loadConfig32->DependentLoadFlags) & DependentLoadFlagsTable[i].flag) {
            printf("\t\t\t\t\t\t\t\t\t               + %08lX  %-50s\n",
                    DependentLoadFlagsTable[i].flag,
                    DependentLoadFlagsTable[i].name);
        }
    }

    printf("\n");

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tEdit List                                      : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->EditList);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tEdit List                                      : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->EditList);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tSecurity Cookie                                : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->SecurityCookie);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tSecurity Cookie                                : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->SecurityCookie);
        vaBase += 4; foBase += 4;
    }

    // Determine pointer size and get SEHandler Table
    if (is64bit) {
        if (loadConfig64->SEHandlerTable == 0) {
            printf("%016llX  %08lX  [8]\t\tSEHandler Table                                : %016llX\n",
                vaBase, foBase, loadConfig64->SEHandlerTable);
        } else {
            ULONGLONG SEHandlerTable = loadConfig64->SEHandlerTable - imageBase;

            RVA_INFO SEHandlerTableRvaInfo = get_rva_info((DWORD)SEHandlerTable, sections, numberOfSections, imageBase);
            printf("%016llX  %08lX  [8]\t\tSEHandler Table                                : %016llX  [VA: %llX] [FO: %lX] [ %-8s]\n",
                vaBase, foBase,
                SEHandlerTable,
                SEHandlerTableRvaInfo.va, SEHandlerTableRvaInfo.fileOffset, SEHandlerTableRvaInfo.sectionName);
        }

        vaBase += 8; foBase += 8;

    } else {
        if (loadConfig32->GuardCFFunctionTable == 0) {
            printf("%016llX  %08lX  [4]\t\tSEHandler Table                                : %08lX\n",
                vaBase, foBase, loadConfig32->GuardCFFunctionTable);
        } else {
            ULONGLONG SEHandlerTable = loadConfig32->GuardCFFunctionTable - imageBase;

            RVA_INFO SEHandlerTableRvaInfo = get_rva_info((DWORD)SEHandlerTable, sections, numberOfSections, imageBase);
            printf("%016llX  %08lX  [4]\t\tSEHandler Table                                : %08llX  [VA: %llX] [FO: %lX] [%-8s]\n",
                vaBase, foBase,
                SEHandlerTable,
                SEHandlerTableRvaInfo.va, SEHandlerTableRvaInfo.fileOffset, SEHandlerTableRvaInfo.sectionName);
        }

        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tSEHandler Count                                : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->SEHandlerCount);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tSEHandler Count                                : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->SEHandlerCount);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tGuard CF Check Function Pointer                : %0*llX\n",
            vaBase, foBase, 8,
            16, loadConfig64->GuardCFCheckFunctionPointer);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tGuard CF Check Function Pointer                : %0*lX\n",
            vaBase, foBase, 4,
            8, loadConfig32->GuardCFCheckFunctionPointer);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tGuard CF Dispatch Function Pointer             : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->GuardCFDispatchFunctionPointer);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tGuard CF Dispatch Function Pointer             : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->GuardCFDispatchFunctionPointer);
        vaBase += 4; foBase += 4;
    }

    // Determine pointer size and get Guard CF Function Table
    if (is64bit) {
        if (loadConfig64->GuardCFFunctionTable == 0) {
            printf("%016llX  %08lX  [8]\t\tGuard CF Function Table                        : %016llX\n",
                vaBase, foBase, loadConfig64->GuardCFFunctionTable);
        } else {
            ULONGLONG guardTable = loadConfig64->GuardCFFunctionTable - imageBase;

            RVA_INFO CFFuncTableInfo = get_rva_info((DWORD)guardTable, sections, numberOfSections, imageBase);
            printf("%016llX  %08lX  [8]\t\tGuard CF Function Table                        : %016llX  [VA: %llX] [FO: %lX] [ %-8s]\n",
                vaBase, foBase,
                guardTable,
                CFFuncTableInfo.va, CFFuncTableInfo.fileOffset, CFFuncTableInfo.sectionName);
        }

        vaBase += 8; foBase += 8;

    } else {
        if (loadConfig32->GuardCFFunctionTable == 0) {
            printf("%016llX  %08lX  [4]\t\tGuard CF Function Table                        : %08lX\n",
                vaBase, foBase, loadConfig32->GuardCFFunctionTable);
        } else {
            ULONGLONG guardTable = loadConfig32->GuardCFFunctionTable - imageBase;
            
            RVA_INFO CFFuncTableInfo = get_rva_info((DWORD)guardTable, sections, numberOfSections, imageBase);
            printf("%016llX  %08lX  [4]\t\tGuard CF Function Table                        : %08llX  [VA: %llX] [FO: %lX] [%-8s]\n",
                vaBase, foBase,
                guardTable,
                CFFuncTableInfo.va, CFFuncTableInfo.fileOffset, CFFuncTableInfo.sectionName);
        }

        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tGuard CF Function Count                        : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->GuardCFFunctionCount);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tGuard CF Function Count                        : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->GuardCFFunctionCount);
        vaBase += 4; foBase += 4;
    }

    printf("%016llX  %08lX  [4]\t\tGuard Flags                                    : %08lX\n",
           vaBase, foBase,
           is64bit ? loadConfig64->GuardFlags : loadConfig32->GuardFlags);

    vaBase += 4; foBase += 4;

    static const FlagDesc GuardFlagsMasterTable[] = {
        {IMAGE_GUARD_CF_INSTRUMENTED,                    "IMAGE_GUARD_CF_INSTRUMENTED"},
        {IMAGE_GUARD_CFW_INSTRUMENTED,                   "IMAGE_GUARD_CFW_INSTRUMENTED"},
        {IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT,          "IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT"},
        {IMAGE_GUARD_SECURITY_COOKIE_UNUSED,             "IMAGE_GUARD_SECURITY_COOKIE_UNUSED"},
        {IMAGE_GUARD_PROTECT_DELAYLOAD_IAT,              "IMAGE_GUARD_PROTECT_DELAYLOAD_IAT"},
        {IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION,   "IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION"},
        {IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT, "IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT"},
        {IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION,       "IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION"},
        {IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT,          "IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT"},
        {IMAGE_GUARD_RF_INSTRUMENTED,                    "IMAGE_GUARD_RF_INSTRUMENTED"},
        {IMAGE_GUARD_RF_ENABLE,                          "IMAGE_GUARD_RF_ENABLE"},
        {IMAGE_GUARD_RF_STRICT,                          "IMAGE_GUARD_RF_STRICT"},
        {IMAGE_GUARD_RETPOLINE_PRESENT,                  "IMAGE_GUARD_RETPOLINE_PRESENT"},
        {IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT,      "IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT"},
        {IMAGE_GUARD_XFG_ENABLED,                        "IMAGE_GUARD_XFG_ENABLED"},
        {IMAGE_GUARD_CASTGUARD_PRESENT,                  "IMAGE_GUARD_CASTGUARD_PRESENT"},
        {IMAGE_GUARD_MEMCPY_PRESENT,                     "IMAGE_GUARD_MEMCPY_PRESENT"},
        {IMAGE_GUARD_HWINTRINSICS_PRESENT,               "IMAGE_GUARD_HWINTRINSICS_PRESENT"},
        {IMAGE_GUARD_SHADOW_STACK_PRESENT,               "IMAGE_GUARD_SHADOW_STACK_PRESENT"},
        {IMAGE_GUARD_JUMPTABLE_PRESENT,                  "IMAGE_GUARD_JUMPTABLE_PRESENT"}
    };

    DWORD GuardFlagsTableCount = sizeof(GuardFlagsMasterTable) / sizeof(GuardFlagsMasterTable[0]);

    for (DWORD i = 0; i < GuardFlagsTableCount; i++) {
        if ((is64bit ? loadConfig64->GuardFlags : loadConfig32->GuardFlags) & GuardFlagsMasterTable[i].flag) {
            printf("\t\t\t\t\t\t\t\t\t               + %08lX  %-50s\n",
                    GuardFlagsMasterTable[i].flag,
                    GuardFlagsMasterTable[i].name);
        }
    }

    printf("\n");

    printf("%016llX  %08lX  [2]\t\tCodeIntegrity.Flags                            : %04X\n",
           vaBase, foBase,
           is64bit ? loadConfig64->CodeIntegrity.Flags : loadConfig32->CodeIntegrity.Flags);

    vaBase += 2; foBase += 2;

    for (DWORD i = 0; i < GuardFlagsTableCount; i++) {
        if ((is64bit ? loadConfig64->CodeIntegrity.Flags : loadConfig32->CodeIntegrity.Flags) & GuardFlagsMasterTable[i].flag) {
            printf("\t\t\t\t\t\t\t\t\t               + %08lX  %-50s\n",
                    GuardFlagsMasterTable[i].flag,
                    GuardFlagsMasterTable[i].name);
        }
    }

    if(is64bit ? loadConfig64->CodeIntegrity.Flags : loadConfig32->CodeIntegrity.Flags) printf("\n");

    printf("%016llX  %08lX  [2]\t\tCodeIntegrity.Catalog                          : %04X\n",
           vaBase, foBase,
           is64bit ? loadConfig64->CodeIntegrity.Catalog : loadConfig32->CodeIntegrity.Catalog);

    vaBase += 2; foBase += 2;

    // ------ TODO: dump the catalog certifacate ------
    printf("%016llX  %08lX  [4]\t\tCodeIntegrity.CatalogOffset                    : %08lX\n",
           vaBase, foBase,
           is64bit ? loadConfig64->CodeIntegrity.CatalogOffset : loadConfig32->CodeIntegrity.CatalogOffset);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tCodeIntegrity.Reserved                         : %08lX\n\n",
           vaBase, foBase,
           is64bit ? loadConfig64->CodeIntegrity.Reserved : loadConfig32->CodeIntegrity.Reserved);

    vaBase += 4; foBase += 4;

    // Determine pointer size and get Guard Address Taken IAT Entry Table
    if (is64bit) {
        if (loadConfig64->GuardAddressTakenIatEntryTable == 0) {
            printf("%016llX  %08lX  [8]\t\tGuard Address Taken IAT Entry Table            : %016llX\n",
                vaBase, foBase, loadConfig64->GuardAddressTakenIatEntryTable);
        } else {
            ULONGLONG GuardIATTable = loadConfig64->GuardAddressTakenIatEntryTable - imageBase;

            RVA_INFO GuardIATRVAInfo = get_rva_info((DWORD)GuardIATTable, sections, numberOfSections, imageBase);
            printf("%016llX  %08lX  [8]\t\tGuard Address Taken IAT Entry Table            : %016llX  [VA: %llX] [FO: %lX] [ %-8s]\n",
                vaBase, foBase,
                GuardIATTable,
                GuardIATRVAInfo.va, GuardIATRVAInfo.fileOffset, GuardIATRVAInfo.sectionName);
        }

        vaBase += 8; foBase += 8;

    } else {
        if (loadConfig32->GuardAddressTakenIatEntryTable == 0) {
            printf("%016llX  %08lX  [4]\t\tGuard Address Taken IAT Entry Table            : %08lX\n",
                vaBase, foBase, loadConfig32->GuardAddressTakenIatEntryTable);
        } else {
            ULONGLONG GuardIATTable = loadConfig32->GuardAddressTakenIatEntryTable - imageBase;

            RVA_INFO GuardIATRVAInfo = get_rva_info((DWORD)GuardIATTable, sections, numberOfSections, imageBase);
            printf("%016llX  %08lX  [4]\t\tGuard Address Taken IAT Entry Table            : %08llX  [VA: %llX] [FO: %lX] [%-8s]\n",
                vaBase, foBase,
                GuardIATTable,
                GuardIATRVAInfo.va, GuardIATRVAInfo.fileOffset, GuardIATRVAInfo.sectionName);
        }

        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tGuard Address Taken IAT Entry Count            : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->GuardAddressTakenIatEntryCount);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tGuard Address Taken IAT Entry Count            : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->GuardAddressTakenIatEntryCount);
        vaBase += 4; foBase += 4;
    }

    // Determine pointer size and get Guard Long Jump Target Table 
    if (is64bit) {
        if (loadConfig64->GuardLongJumpTargetTable == 0) {
            printf("%016llX  %08lX  [8]\t\tGuard Long Jump Target Table                   : %016llX\n",
                vaBase, foBase, loadConfig64->GuardLongJumpTargetTable);
        } else {
            ULONGLONG GuardLJTable = loadConfig64->GuardLongJumpTargetTable - imageBase;

            RVA_INFO GuardLJRVAInfo = get_rva_info((DWORD)GuardLJTable, sections, numberOfSections, imageBase);
            printf("%016llX  %08lX  [8]\t\tGuard Long Jump Target Table                   : %016llX  [VA: %llX] [FO: %lX] [ %-8s]\n",
                vaBase, foBase,
                GuardLJTable,
                GuardLJRVAInfo.va, GuardLJRVAInfo.fileOffset, GuardLJRVAInfo.sectionName);
        }

        vaBase += 8; foBase += 8;

    } else {
        if (loadConfig32->GuardLongJumpTargetTable == 0) {
            printf("%016llX  %08lX  [4]\t\tGuard Long Jump Target Table                   : %08lX\n",
                vaBase, foBase, loadConfig32->GuardLongJumpTargetTable);
        } else {
            ULONGLONG GuardLJTable = loadConfig32->GuardLongJumpTargetTable - imageBase;

            RVA_INFO GuardLJRVAInfo = get_rva_info((DWORD)GuardLJTable, sections, numberOfSections, imageBase);
            printf("%016llX  %08lX  [4]\t\tGuard Long Jump Target Table                   : %08llX  [VA: %llX] [FO: %lX] [%-8s]\n",
                vaBase, foBase,
                GuardLJTable,
                GuardLJRVAInfo.va, GuardLJRVAInfo.fileOffset, GuardLJRVAInfo.sectionName);
        }

        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tGuard Long Jump Target Count                   : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->GuardLongJumpTargetCount);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tGuard Long Jump Target Count                   : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->GuardLongJumpTargetCount);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tDynamic Value Reloc Table                      : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->DynamicValueRelocTable);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tDynamic Value Reloc Table                      : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->DynamicValueRelocTable);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tCHPE Metadata Pointer                          : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->CHPEMetadataPointer);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tCHPE Metadata Pointer                          : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->CHPEMetadataPointer);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tGuard RF Failure Routine                       : %0*llX\n",
            vaBase, foBase, 8,
            16, loadConfig64->GuardRFFailureRoutine);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tGuard RF Failure Routine                       : %0*lX\n",
            vaBase, foBase, 4,
            8, loadConfig32->GuardRFFailureRoutine);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tGuard RF Failure Routine Function Pointer      : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->GuardRFFailureRoutineFunctionPointer);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tGuard RF Failure Routine Function Pointer      : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->GuardRFFailureRoutineFunctionPointer);
        vaBase += 4; foBase += 4;
    }

    // TODO: COVER THE BASE RELOC TABLE WITH THIS WAY TOO LATER ON
    printf("%016llX  %08lX  [4]\t\tDynamic Value Reloc Table Offset               : %08lX\n",
           vaBase, foBase,
           is64bit ? loadConfig64->DynamicValueRelocTableOffset : loadConfig32->DynamicValueRelocTableOffset);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [2]\t\tDynamic Value Reloc Table Section              : %04X\n\n",
           vaBase, foBase,
           is64bit ? loadConfig64->DynamicValueRelocTableSection : loadConfig32->DynamicValueRelocTableSection);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tReserved2                                      : %04X\n\n",
           vaBase, foBase,
           is64bit ? loadConfig64->Reserved2 : loadConfig32->Reserved2);

    vaBase += 2; foBase += 2;


    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tGuard RF Verify Stack Pointer Function Pointer : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->GuardRFVerifyStackPointerFunctionPointer);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tGuard RF Verify Stack Pointer Function Pointer : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->GuardRFVerifyStackPointerFunctionPointer);
        vaBase += 4; foBase += 4;
    }

    printf("%016llX  %08lX  [4]\t\tHot Patch Table Offset                         : %08lX\n\n",
           vaBase, foBase,
           is64bit ? loadConfig64->HotPatchTableOffset : loadConfig32->HotPatchTableOffset);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tReserved3                                      : %08lX\n\n",
           vaBase, foBase,
           is64bit ? loadConfig64->Reserved3 : loadConfig32->Reserved3);

    vaBase += 4; foBase += 4;

    // TODO: parse and dump the IMAGE_ENCLAVE_CONFIG32 & IMAGE_ENCLAVE_CONFIG64
    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tEnclave Configuration Pointer                  : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->EnclaveConfigurationPointer);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tEnclave Configuration Pointer                  : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->EnclaveConfigurationPointer);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tVolatile Metadata Pointer                      : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->VolatileMetadataPointer);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tVolatile Metadata Pointer                      : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->VolatileMetadataPointer);
        vaBase += 4; foBase += 4;
    }

    // Determine pointer size and get Guard EH Continuation Table
    if (is64bit) {
        if (loadConfig64->GuardEHContinuationTable == 0) {
            printf("%016llX  %08lX  [8]\t\tGuard Address Taken IAT Entry Table            : %016llX\n",
                vaBase, foBase, loadConfig64->GuardEHContinuationTable);
        } else {
            ULONGLONG GuardEHCTable = loadConfig64->GuardEHContinuationTable - imageBase;

            RVA_INFO GuardEHCRVAInfo = get_rva_info((DWORD)GuardEHCTable, sections, numberOfSections, imageBase);
            printf("%016llX  %08lX  [8]\t\tGuard Address Taken IAT Entry Table            : %016llX  [VA: %llX] [FO: %lX] [ %-8s]\n",
                vaBase, foBase,
                GuardEHCTable,
                GuardEHCRVAInfo.va, GuardEHCRVAInfo.fileOffset, GuardEHCRVAInfo.sectionName);
        }

        vaBase += 8; foBase += 8;

    } else {
        if (loadConfig32->GuardEHContinuationTable == 0) {
            printf("%016llX  %08lX  [4]\t\tGuard Address Taken IAT Entry Table            : %08lX\n",
                vaBase, foBase, loadConfig32->GuardEHContinuationTable);
        } else {
            ULONGLONG GuardEHCTable = loadConfig32->GuardEHContinuationTable - imageBase;

            RVA_INFO GuardEHCRVAInfo = get_rva_info((DWORD)GuardEHCTable, sections, numberOfSections, imageBase);
            printf("%016llX  %08lX  [4]\t\tGuard Address Taken IAT Entry Table            : %08llX  [VA: %llX] [FO: %lX] [%-8s]\n",
                vaBase, foBase,
                GuardEHCTable,
                GuardEHCRVAInfo.va, GuardEHCRVAInfo.fileOffset, GuardEHCRVAInfo.sectionName);
        }

        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tGuard EH Continuation Count                    : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->GuardEHContinuationCount);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tGuard EH Continuation Count                    : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->GuardEHContinuationCount);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tGuard XFG Check Function Pointer               : %0*llX\n",
            vaBase, foBase, 8,
            16, loadConfig64->GuardXFGCheckFunctionPointer);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tGuard XFG Check Function Pointer               : %0*lX\n",
            vaBase, foBase, 4,
            8, loadConfig32->GuardXFGCheckFunctionPointer);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tGuard XFG Dispatch Function Pointer            : %0*llX\n",
            vaBase, foBase, 8,
            16, loadConfig64->GuardXFGDispatchFunctionPointer);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tGuard XFG Dispatch Function Pointer            : %0*lX\n",
            vaBase, foBase, 4,
            8, loadConfig32->GuardXFGDispatchFunctionPointer);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tGuard XFG Table Dispatch Function Pointer      : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->GuardXFGTableDispatchFunctionPointer);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tGuard XFG Table Dispatch Function Pointer      : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->GuardXFGTableDispatchFunctionPointer);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tCast Guard Os Determined Failure Mode          : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->CastGuardOsDeterminedFailureMode);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tCast Guard Os Determined Failure Mode          : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->CastGuardOsDeterminedFailureMode);
        vaBase += 4; foBase += 4;
    }

    if (is64bit) {
        printf("%016llX  %08lX  [%d]\t\tGuard Memcpy Function Pointer                  : %0*llX\n\n",
            vaBase, foBase, 8,
            16, loadConfig64->GuardMemcpyFunctionPointer);
        vaBase += 8; foBase += 8;
    } else {
        printf("%016llX  %08lX  [%d]\t\tGuard Memcpy Function Pointer                  : %0*lX\n\n",
            vaBase, foBase, 4,
            8, loadConfig32->GuardMemcpyFunctionPointer);
        vaBase += 4; foBase += 4;
    }

    // Assume loadConfig64 points to the start of IMAGE_LOAD_CONFIG_DIRECTORY64
    // Same idea for 32-bit

    // DWORD size = loadConfig64->Size;   // total size of this struct in the PE

    // // UmaFunctionPointers is after GuardMemcpyFunctionPointer
    // DWORD offsetUma = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, UmaFunctionPointers);

    // if (is64bit) {
    //     if (size >= offsetUma + sizeof(ULONGLONG)) {
    //         printf("%016llX  %08lX  [%d]\t\tUma Function Pointers                          : %0*llX\n\n",
    //             vaBase, foBase, 8,
    //             16, loadConfig64->UmaFunctionPointers);
    //         vaBase += 8; foBase += 8;
    //     }
    // } else {
    //     DWORD offsetUma32 = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, UmaFunctionPointers);
    //     if (size >= offsetUma32 + sizeof(DWORD)) {
    //         printf("%016llX  %08lX  [%d]\t\tUma Function Pointers                          : %0*lX\n\n",
    //             vaBase, foBase, 4,
    //             8, loadConfig32->UmaFunctionPointers);
    //         vaBase += 4; foBase += 4;
    //     }
    // }

    if (is64bit) { // First in tables
        if (loadConfig64->LockPrefixTable != 0) {
            DWORD maxEntries = count_table_entries(peFile, loadConfig64->LockPrefixTable, sections, numberOfSections, imageBase);

            if (print_load_config_table(
                peFile,
                loadConfig64->LockPrefixTable,
                maxEntries,
                sections, numberOfSections,
                imageBase,
                "LockPrefixTable") != RET_SUCCESS) {
                    fprintf(stderr, "[!!] Failed to dump Lock Prefix Table");
                    return RET_ERROR;
                }
        }
    } else {
        if (loadConfig32->LockPrefixTable != 0) {
            DWORD maxEntries = count_table_entries(peFile, loadConfig32->LockPrefixTable, sections, numberOfSections, imageBase);

            if (print_load_config_table(
                peFile,
                loadConfig32->LockPrefixTable,
                maxEntries,
                sections, numberOfSections,
                imageBase,
                "LockPrefixTable") != RET_SUCCESS) {
                    fprintf(stderr, "[!!] Failed to dump Lock Prefix Table");
                    return RET_ERROR;
                }
        }
    }

    if (is64bit) { // Second in tables
        if (loadConfig64->SEHandlerTable != 0) {

            if (loadConfig64->SEHandlerCount == 0) {
                printf("[!!] SEHandlerTable present but count is zero.\n");
            }
    
            if (print_load_config_table(
                peFile,
                loadConfig64->SEHandlerTable,
                loadConfig64->SEHandlerCount,
                sections, numberOfSections,
                imageBase,
                "SEHandlerTable") != RET_SUCCESS) {
                    fprintf(stderr, "[!!] Failed to dump SEHandler Table");
                    return RET_ERROR;
                }
        }
    } else {
        if (loadConfig32->SEHandlerTable != 0) {

            if (loadConfig32->SEHandlerCount == 0) {
                printf("[!!] SEHandlerTable present but count is zero.\n");
            }

            if (print_load_config_table(
                peFile,
                loadConfig32->SEHandlerTable,
                loadConfig32->SEHandlerCount,
                sections, numberOfSections,
                imageBase,
                "SEHandlerTable") != RET_SUCCESS) {
                    fprintf(stderr, "[!!] Failed to dump SEHandler Table");
                    return RET_ERROR;
                }
        }
    }

    if (is64bit) { // Third in tables
        if (loadConfig64->GuardCFFunctionTable != 0) {
        
            if (loadConfig64->GuardCFFunctionCount == 0) {
                printf("[!!] GuardCFFunctionTable present but count is zero.\n");
            }

            if (print_load_config_table(
                peFile,
                loadConfig64->GuardCFFunctionTable,
                loadConfig64->GuardCFFunctionCount,
                sections, numberOfSections,
                imageBase,
                "GuardCFFunctionTable") != RET_SUCCESS) {
                    fprintf(stderr, "[!!] Failed to dump Guard CF Function Table");
                    return RET_ERROR;
                }
            }
    } else {
        if (loadConfig32->GuardCFFunctionTable != 0) {
            
            if (loadConfig32->GuardCFFunctionCount == 0) {
                printf("[!!] GuardCFFunctionTable present but count is zero.\n");
            }

            if (print_load_config_table(
                peFile,
                loadConfig32->GuardCFFunctionTable,
                loadConfig32->GuardCFFunctionCount,
                sections, numberOfSections,
                imageBase,
                "GuardCFFunctionTable") != RET_SUCCESS) {
                    fprintf(stderr, "[!!] Failed to dump Guard CF Function Table");
                    return RET_ERROR;
                }
        }
    }

    if (is64bit) { // Fourth in tables
        if (loadConfig64->GuardAddressTakenIatEntryTable != 0) {
        
            if (loadConfig64->GuardAddressTakenIatEntryCount == 0) {
                printf("[!!] GuardAddressTakenIatEntryCount present but count is zero.\n");
            }

            if (print_load_config_table(
                peFile,
                loadConfig64->GuardAddressTakenIatEntryTable,
                loadConfig64->GuardAddressTakenIatEntryCount,
                sections, numberOfSections,
                imageBase,
                "GuardAddressTakenIatEntryTable") != RET_SUCCESS) {
                    fprintf(stderr, "[!!] Failed to dump Guard Address Taken Iat Entry Table");
                    return RET_ERROR;
                }
            }
    } else {
        if (loadConfig32->GuardAddressTakenIatEntryTable != 0) {
            
            if (loadConfig32->GuardAddressTakenIatEntryCount == 0) {
                printf("[!!] GuardAddressTakenIatEntryCount present but count is zero.\n");
            }

            if (print_load_config_table(
                peFile,
                loadConfig32->GuardAddressTakenIatEntryTable,
                loadConfig32->GuardAddressTakenIatEntryCount,
                sections, numberOfSections,
                imageBase,
                "GuardAddressTakenIatEntryTable") != RET_SUCCESS) {
                    fprintf(stderr, "[!!] Failed to dump Guard Address Taken Iat Entry Table");
                    return RET_ERROR;
                }
        }
    }

    if (is64bit) { // Fifth in tables
        if (loadConfig64->GuardLongJumpTargetTable != 0) {
        
            if (loadConfig64->GuardLongJumpTargetCount == 0) {
                printf("[!!] GuardLongJumpTargetCount present but count is zero.\n");
            }

            if (print_load_config_table(
                peFile,
                loadConfig64->GuardLongJumpTargetTable,
                loadConfig64->GuardLongJumpTargetCount,
                sections, numberOfSections,
                imageBase,
                "GuardLongJumpTargetTable") != RET_SUCCESS) {
                    fprintf(stderr, "[!!] Failed to dump Guard Long Jump Target Table");
                    return RET_ERROR;
                }
            }
    } else {
        if (loadConfig32->GuardLongJumpTargetTable != 0) {
            
            if (loadConfig32->GuardLongJumpTargetCount == 0) {
                printf("[!!] GuardLongJumpTargetCount present but count is zero.\n");
            }

            if (print_load_config_table(
                peFile,
                loadConfig32->GuardLongJumpTargetTable,
                loadConfig32->GuardLongJumpTargetCount,
                sections, numberOfSections,
                imageBase,
                "GuardLongJumpTargetTable") != RET_SUCCESS) {
                    fprintf(stderr, "[!!] Failed to dump Guard Long Jump Target Table");
                    return RET_ERROR;
                }
        }
    }

    if (is64bit) { // Sixth in tables
        if (loadConfig64->GuardEHContinuationTable != 0) {
        
            if (loadConfig64->GuardEHContinuationCount == 0) {
                printf("[!!] GuardEHContinuationCount present but count is zero.\n");
            }

            if (print_load_config_table(
                peFile,
                loadConfig64->GuardEHContinuationTable,
                loadConfig64->GuardEHContinuationCount,
                sections, numberOfSections,
                imageBase,
                "GuardEHContinuationTable") != RET_SUCCESS) {
                    fprintf(stderr, "[!!] Failed to dump Table");
                    return RET_ERROR;
                }
            }
    } else {
        if (loadConfig32->GuardEHContinuationTable != 0) {
            
            if (loadConfig32->GuardEHContinuationCount == 0) {
                printf("[!!] GuardEHContinuationCount present but count is zero.\n");
            }

            if (print_load_config_table(
                peFile,
                loadConfig32->GuardEHContinuationTable,
                loadConfig32->GuardEHContinuationCount,
                sections, numberOfSections,
                imageBase,
                "GuardEHContinuationTable") != RET_SUCCESS) {
                    fprintf(stderr, "[!!] Failed to dump Table");
                    return RET_ERROR;
                }
        }
    }

    fflush(stdout);

    return RET_SUCCESS;
}

// TODO: test this function and see if it works 
RET_CODE dump_bound_import_dir(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY boundImportDataDir,
    ULONGLONG imageBase) {

    if (!peFile || !boundImportDataDir) return RET_INVALID_PARAM;

    // completely empty = skip gracefully
    if (boundImportDataDir->VirtualAddress == 0 && boundImportDataDir->Size == 0)
        return RET_MALFORMED_FILE;

    // partially defined = suspicious
    if (boundImportDataDir->VirtualAddress == 0 || boundImportDataDir->Size == 0)
        return REPORT_MALFORMED("Bound Import directory partially empty (RVA=0 or Size=0)", "Bound Import Data Directory");

    DWORD foBase;
    if (rva_to_offset(boundImportDataDir->VirtualAddress, sections, numberOfSections, &foBase) != RET_SUCCESS) {
        printf("[!!] Failed to map Bound Import Directory RVA to file offset\n");
        return RET_ERROR;
    }

    DWORD curOff     = foBase;
    DWORD dirSize    = boundImportDataDir->Size;
    ULONGLONG curVa  = imageBase + boundImportDataDir->VirtualAddress;

    // Print bound import directory header
    printf("\n%016llX - BOUND IMPORT DIRECTORY -\n\n",
        curVa);

    while (1) {
        IMAGE_BOUND_IMPORT_DESCRIPTOR desc;
        FSEEK64(peFile, curOff, SEEK_SET);
        if (fread(&desc, sizeof(desc), 1, peFile) != 1) break;

        // Stop on null descriptor
        if (desc.TimeDateStamp == 0 &&
            desc.OffsetModuleName == 0 &&
            desc.NumberOfModuleForwarderRefs == 0) break;

        // Resolve DLL name
        char dllName[MAX_DLL_NAME] = {0};
        DWORD dllNameOffset = foBase + desc.OffsetModuleName;
        FSEEK64(peFile, dllNameOffset, SEEK_SET);
        fread(dllName, 1, MAX_DLL_NAME - 1, peFile);
        dllName[MAX_DLL_NAME - 1] = '\0';

        printf("Bound Import: %s (FO=%lX | VA=%llX)\n",
               dllName,
               curOff,
               curVa);

        // Timestamp pretty-print
        DWORD ts = desc.TimeDateStamp;
        char tsStr[64];
        if ((ts >= SOME_REASONABLE_EPOCH && ts <= CURRENT_EPOCH_PLUS_MARGIN) || ts == 0) {
            snprintf(tsStr, sizeof(tsStr), "TimeDateStamp: %08lX %s", ts, format_timestamp(ts));
        } else {
            snprintf(tsStr, sizeof(tsStr), "ReproChecksum: %u", (unsigned) ts);
        }

        printf("%s%s | Offset Module Name: %08lX | Number Of Module Forwarder Refs: %lX\n\n",
               INDENT(1), tsStr, (ULONG)desc.OffsetModuleName, (ULONG)desc.NumberOfModuleForwarderRefs);

        // Forwarder refs follow immediately after the descriptor
        DWORD fwdRefOffset = curOff + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);
        ULONGLONG fwdRefVa = curVa  + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);

        for (WORD j = 0; j < desc.NumberOfModuleForwarderRefs; j++) {
            IMAGE_BOUND_FORWARDER_REF fwdRef;
            DWORD fwdCurOff    = fwdRefOffset + (DWORD)j * (DWORD)sizeof(fwdRef);
            ULONGLONG fwdCurVa = fwdRefVa     + (DWORD)j * sizeof(fwdRef);

            FSEEK64(peFile, fwdCurOff, SEEK_SET);
            fread(&fwdRef, sizeof(fwdRef), 1, peFile);

            char fwdName[MAX_DLL_NAME] = {0};
            DWORD fwdNameOffset = foBase + fwdRef.OffsetModuleName;
            FSEEK64(peFile, fwdNameOffset, SEEK_SET);
            fread(fwdName, 1, MAX_DLL_NAME - 1, peFile);
            fwdName[MAX_DLL_NAME - 1] = '\0';

            // Timestamp pretty-print
            DWORD fwrdTs = fwdRef.TimeDateStamp;
            char fwdTsStr[64];
            if ((fwrdTs >= SOME_REASONABLE_EPOCH && fwrdTs <= CURRENT_EPOCH_PLUS_MARGIN) || fwrdTs == 0) {
                snprintf(fwdTsStr, sizeof(fwdTsStr), "TimeDateStamp: %08lX %s", fwrdTs, format_timestamp(fwrdTs));
            } else {
                snprintf(fwdTsStr, sizeof(fwdTsStr), "ReproChecksum: %u", (unsigned) fwrdTs);
            }

            printf("%sForwarder Module Name: %s (FO=%lX | VA=%llX)\n",
                INDENT(2), fwdName, fwdCurOff, fwdCurVa);

            printf("%s%s | Offset Forwarder Module Name: %08lX | Reserved: %lX\n\n",
                INDENT(3), fwdTsStr, (ULONG) fwdRef.OffsetModuleName, (ULONG)fwdRef.Reserved);
        }

        // Move to next descriptor: skip this descriptor + its forwarders
        curOff += (DWORD)(sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) +
                  desc.NumberOfModuleForwarderRefs * sizeof(IMAGE_BOUND_FORWARDER_REF));

        curVa += sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) +
                  desc.NumberOfModuleForwarderRefs * sizeof(IMAGE_BOUND_FORWARDER_REF);

        if (curOff - foBase >= dirSize) break; // safety bound check
    }

    return RET_SUCCESS;
}

RET_CODE dump_delay_import_dir(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY delayImportDataDir,
    PIMAGE_DELAYLOAD_DESCRIPTOR delayImportDir,
    ULONGLONG imageBase,
    int is64bit,
    LONGLONG fileSize) {

    if (!peFile || !delayImportDataDir || !delayImportDir) return RET_INVALID_PARAM; // sanity check

    // completely empty = skip gracefully
    if (delayImportDataDir->VirtualAddress == 0 && delayImportDataDir->Size == 0)
        return RET_MALFORMED_FILE;

    // partially defined = suspicious
    if (delayImportDataDir->VirtualAddress == 0 || delayImportDataDir->Size == 0)
        return REPORT_MALFORMED("Delay Import directory partially empty (RVA=0 or Size=0)", "Delay Import Data Directory");

    ULONGLONG vaBase = imageBase + delayImportDataDir->VirtualAddress;

    DWORD foBase;
    if (rva_to_offset(delayImportDataDir->VirtualAddress, sections, numberOfSections, &foBase) != RET_SUCCESS) {
        printf("[!!] Failed to map Delay Import Directory RVA to file offset\n");
        return RET_ERROR;
    }

    // Count how many valid descriptors are presents
    int count = 0;
    while (delayImportDir[count].DllNameRVA != 0 ||
        delayImportDir[count].ModuleHandleRVA != 0 ||
        delayImportDir[count].ImportAddressTableRVA != 0 ||
        delayImportDir[count].ImportNameTableRVA != 0 ||
        delayImportDir[count].BoundImportAddressTableRVA != 0 ||
        delayImportDir[count].UnloadInformationTableRVA != 0 ||
        delayImportDir[count].TimeDateStamp != 0) {
        count++;
    }

    // Print delay import directory header
    printf("\n%016llX - DELAY IMPORT DIRECTORY - number of delay import descriptors: %d\n\n",
        vaBase, count);


   for (int i = 0; i < count; i++) {
        char dllName[MAX_DLL_NAME] = {0};

        // Try to resolve DLL name string from section
        SECTION_INFO secLIB = get_section_info(delayImportDir[i].DllNameRVA, sections, numberOfSections);
        if (secLIB.size != 0) {
            if (delayImportDir[i].DllNameRVA - secLIB.virtualAddress < secLIB.size) {
                if (FSEEK64(peFile, secLIB.rawOffset + delayImportDir[i].DllNameRVA - secLIB.virtualAddress, SEEK_SET) != 0) return RET_ERROR;
                fread(dllName, 1, MAX_DLL_NAME - 1, peFile);
                dllName[MAX_DLL_NAME - 1] = '\0'; // safety null-termination
            } else {
                strcpy(dllName, "<invalid>");
            }
        } else {
            strcpy(dllName, "<invalid>");
        }

        // Descriptor heading for this DLL
        printf("%016llX DELAY IMPORT descriptor: %d  - Library: %s\n\n",
            vaBase, i + 1, dllName);

        printf("VA                FO        Size        Value\n");
                
        printf("%016llX  %08lX  [ 4]\tAll Attributes                 : %08lX\n\n",
            vaBase, foBase, delayImportDir[i].Attributes.AllAttributes);

        vaBase += 4; foBase += 4;

        // --- dll name RVA ---
        RVA_INFO dllNameRvaInfo = get_rva_info(delayImportDir[i].DllNameRVA, sections, numberOfSections, imageBase);

        printf("%016llX  %08lX  [ 4]\tDll Name RVA                   : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n",
            vaBase, foBase, delayImportDir[i].DllNameRVA,
            dllNameRvaInfo.va, dllNameRvaInfo.fileOffset, dllNameRvaInfo.sectionName);

        vaBase += 4; foBase += 4;

        printf("%016llX  %08lX  [%2zu]\tDll Name                       : %s\n\n",
            dllNameRvaInfo.va, dllNameRvaInfo.fileOffset,
            strlen(dllName), dllName);


        if (delayImportDir[i].ModuleHandleRVA) {
            RVA_INFO ModuleHandleRvaInfo = get_rva_info(delayImportDir[i].ModuleHandleRVA, sections, numberOfSections, imageBase);

            printf("%016llX  %08lX  [ 4]\tModule Handle RVA              : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n\n",
                vaBase, foBase, delayImportDir[i].ModuleHandleRVA,
                ModuleHandleRvaInfo.va, ModuleHandleRvaInfo.fileOffset, ModuleHandleRvaInfo.sectionName);
        } else {
            printf("%016llX  %08lX  [ 4]\tModule Handle RVA              : %08lX\n\n",
                vaBase, foBase, delayImportDir[i].DllNameRVA);  
        }
        vaBase += 4; foBase += 4;

        if (delayImportDir[i].ImportAddressTableRVA) {
            RVA_INFO ImpAddrRvaInfo = get_rva_info(delayImportDir[i].ImportAddressTableRVA, sections, numberOfSections, imageBase);

            printf("%016llX  %08lX  [ 4]\tImport Address Table RVA       : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n",
                vaBase, foBase, delayImportDir[i].ImportAddressTableRVA,
                ImpAddrRvaInfo.va, ImpAddrRvaInfo.fileOffset, ImpAddrRvaInfo.sectionName);
        } else {
            printf("%016llX  %08lX  [ 4]\tImport Address Table RVA       : %08lX\n",
                vaBase, foBase, delayImportDir[i].ImportAddressTableRVA);  
        }
        vaBase += 4; foBase += 4;

        if (delayImportDir[i].ImportNameTableRVA) {
            RVA_INFO ImpNameRvaInfo = get_rva_info(delayImportDir[i].ImportNameTableRVA, sections, numberOfSections, imageBase);

            printf("%016llX  %08lX  [ 4]\tImport Name Table RVA          : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n\n",
                vaBase, foBase, delayImportDir[i].ImportNameTableRVA,
                ImpNameRvaInfo.va, ImpNameRvaInfo.fileOffset, ImpNameRvaInfo.sectionName);
        } else {
            printf("%016llX  %08lX  [ 4]\tImport Name Table RVA          : %08lX\n\n",
                vaBase, foBase, delayImportDir[i].ImportNameTableRVA);  
        }
        vaBase += 4; foBase += 4;

        if (delayImportDir[i].BoundImportAddressTableRVA) {
            RVA_INFO BoundImpAddrRvaInfo = get_rva_info(delayImportDir[i].BoundImportAddressTableRVA, sections, numberOfSections, imageBase);

            printf("%016llX  %08lX  [ 4]\tBound Import Address Table RVA : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n\n",
                vaBase, foBase, delayImportDir[i].BoundImportAddressTableRVA,
                BoundImpAddrRvaInfo.va, BoundImpAddrRvaInfo.fileOffset, BoundImpAddrRvaInfo.sectionName);
        } else {
            printf("%016llX  %08lX  [ 4]\tBound Import Address Table RVA : %08lX\n\n",
                vaBase, foBase, delayImportDir[i].BoundImportAddressTableRVA);  
        }
        vaBase += 4; foBase += 4;

        if (delayImportDir[i].UnloadInformationTableRVA) {
            RVA_INFO UnloadInfoTableRvaInfo = get_rva_info(delayImportDir[i].UnloadInformationTableRVA, sections, numberOfSections, imageBase);

            printf("%016llX  %08lX  [ 4]\tUnload Information Table RVA   : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n\n",
                vaBase, foBase, delayImportDir[i].UnloadInformationTableRVA,
                UnloadInfoTableRvaInfo.va, UnloadInfoTableRvaInfo.fileOffset, UnloadInfoTableRvaInfo.sectionName);
        } else {
            printf("%016llX  %08lX  [ 4]\tUnload Information Table RVA   : %08lX\n\n",
                vaBase, foBase, delayImportDir[i].UnloadInformationTableRVA);  
        }
        vaBase += 4; foBase += 4;

        DWORD ts = delayImportDir[i].TimeDateStamp;

        if ((ts >= SOME_REASONABLE_EPOCH && ts <= CURRENT_EPOCH_PLUS_MARGIN) || ts == 0) {
            printf("%016llX  %08lX  [ 4]\tTime Date Stamp                : %08X  %s\n\n", 
                vaBase, foBase, (unsigned) ts, format_timestamp(ts));
        } else {
            printf("%016llX  %08lX  [ 4]\tReproChecksum                  : %08X (%u)\n\n", 
                vaBase, foBase, (unsigned) ts, (unsigned) ts);
        }

        if (delayImportDir[i].ImportAddressTableRVA) {
            if (dump_int_table(peFile, sections, numberOfSections, delayImportDir[i].ImportNameTableRVA, delayImportDir[i].ImportAddressTableRVA, imageBase, is64bit) != RET_SUCCESS) {
                fprintf(stderr, "[!!] Failed to dump Import Name Table for descriptor: %d\n", i + 1);
            }
        }

        if (delayImportDir[i].ImportAddressTableRVA) {
            if (dump_iat_table(peFile, sections, numberOfSections, delayImportDir[i].ImportAddressTableRVA, imageBase, is64bit, fileSize) != RET_SUCCESS) {
                fprintf(stderr, "[!!] Failed to dump Import Address Table for descriptor: %d\n", i + 1);
            }
        }

        DWORD numIAT = (DWORD)count_thunks(peFile, delayImportDir[i].ImportAddressTableRVA, sections, numberOfSections, is64bit);

        // End of one DLL import descriptor
        char header[64];
        sprintf(header, "END FO DELAY IMPORT DESCRIPTOR %d (%ld function%s)", i + 1, numIAT, numIAT == 1 ? "" : "s");

        printf("\n");
        print_centered_header(header, '-', 102);
        printf("\n");

        fflush(stdout);
    }

    return RET_SUCCESS;
}

// TODO: Add new functions to dump all clr info
RET_CODE dump_clr_header_dir(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY clrHeaderDataDir,
    PIMAGE_COR20_HEADER clrHeaderDir,
    ULONGLONG imageBase) {

    if (! !peFile || !clrHeaderDataDir || !clrHeaderDir) return RET_INVALID_PARAM; // sanity check

    // completely empty = skip gracefully
    if (clrHeaderDataDir->VirtualAddress == 0 && clrHeaderDataDir->Size == 0)
        return RET_MALFORMED_FILE;

    // partially defined = suspicious
    if (clrHeaderDataDir->VirtualAddress == 0 || clrHeaderDataDir->Size == 0)
        return REPORT_MALFORMED("CLR/.NET Header partially empty (RVA=0 or Size=0)", "CLR/.NET Header directory");


    ULONGLONG vaBase = imageBase + clrHeaderDataDir->VirtualAddress;

    DWORD foBase;
    if (rva_to_offset(clrHeaderDataDir->VirtualAddress, sections, numberOfSections, &foBase) != RET_SUCCESS) {
        printf("[!!] Failed to map CLR/.NET Header Directory RVA to file offset\n");
        return RET_ERROR;
    }

    // Print CLR/.NET Header directory header
    printf("\n%016llX - CLR/.NET HEADER DIRECTORY -\n\n",
        vaBase); 

    printf("VA                FO        Size        Value\n");

    printf("%016llX  %08lX  [4]\t\tcb                           : %08lX\n\n",
    vaBase, foBase, clrHeaderDir->cb);

    vaBase += 4; foBase += 4;  

    printf("%016llX  %08lX  [2]\t\tMajor Runtime Version        : %04X\n",
    vaBase, foBase, clrHeaderDir->MajorRuntimeVersion);

    vaBase += 2; foBase += 2;  

    printf("%016llX  %08lX  [2]\t\tMinor Runtime Version        : %04X\n\n",
    vaBase, foBase, clrHeaderDir->MinorRuntimeVersion);

    vaBase += 2; foBase += 2;  

    printf("%016llX  %08lX  [4]\t\tMetaData.VA                  : %08lX\n",
    vaBase, foBase, clrHeaderDir->MetaData.VirtualAddress);

    vaBase += 4; foBase += 4;  

    printf("%016llX  %08lX  [4]\t\tMetaData.Size                : %08lX\n\n",
    vaBase, foBase, clrHeaderDir->MetaData.Size);

    vaBase += 4; foBase += 4;  

    printf("%016llX  %08lX  [4]\t\tFlags                        : %08lX\n",
    vaBase, foBase, clrHeaderDir->Flags);

    vaBase += 4; foBase += 4;

    static const FlagDesc ClrFlags[] = {
        { COMIMAGE_FLAGS_ILONLY,           "COMIMAGE_FLAGS_ILONLY" },
        { COMIMAGE_FLAGS_32BITREQUIRED,    "COMIMAGE_FLAGS_32BITREQUIRED" },
        { COMIMAGE_FLAGS_IL_LIBRARY,       "COMIMAGE_FLAGS_IL_LIBRARY" },
        { COMIMAGE_FLAGS_STRONGNAMESIGNED, "COMIMAGE_FLAGS_STRONGNAMESIGNED" },
        { COMIMAGE_FLAGS_NATIVE_ENTRYPOINT,"COMIMAGE_FLAGS_NATIVE_ENTRYPOINT" },
        { COMIMAGE_FLAGS_TRACKDEBUGDATA,   "COMIMAGE_FLAGS_TRACKDEBUGDATA" },
        { COMIMAGE_FLAGS_32BITPREFERRED,   "COMIMAGE_FLAGS_32BITPREFERRED" },
    };

    DWORD ClrFlagsCount = sizeof(ClrFlags) / sizeof(ClrFlags[0]);

    for (DWORD i = 0; i < ClrFlagsCount; i++) {
        if (clrHeaderDir->Flags & ClrFlags[i].flag) {
            printf("\t\t\t\t\t\t\t\t     + %08lX  %-50s\n",
                     ClrFlags[i].flag,
                    ClrFlags[i].name);
        }
    } 

    printf("\n");

    if (clrHeaderDir->Flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) {
        printf("%016llX  %08lX  [4]\t\tEntry Point RVA              : %08lX\n\n",
        vaBase, foBase, clrHeaderDir->EntryPointRVA);
    } else {
        printf("%016llX  %08lX  [4]\t\tEntry Point Token            : %08lX\n\n",
        vaBase, foBase, clrHeaderDir->EntryPointToken);
    }
    
    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tResources.VA                 : %08lX\n",
    vaBase, foBase, clrHeaderDir->Resources.VirtualAddress);

    vaBase += 4; foBase += 4;
 
    printf("%016llX  %08lX  [4]\t\tResources.Size               : %08lX\n\n",
    vaBase, foBase, clrHeaderDir->Resources.Size);

    vaBase += 4; foBase += 4;

    
    printf("%016llX  %08lX  [4]\t\tStrongNameSignature.VA       : %08lX\n",
    vaBase, foBase, clrHeaderDir->StrongNameSignature.VirtualAddress);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tStrongNameSignature.Size     : %08lX\n\n",
    vaBase, foBase, clrHeaderDir->StrongNameSignature.Size);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tCodeManagerTable.VA          : %08lX\n",
    vaBase, foBase, clrHeaderDir->CodeManagerTable.VirtualAddress);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tCodeManagerTable.Size        : %08lX\n\n",
    vaBase, foBase, clrHeaderDir->CodeManagerTable.Size);

    vaBase += 4; foBase += 4;


    printf("%016llX  %08lX  [4]\t\tVTableFixups.VA              : %08lX\n",
    vaBase, foBase, clrHeaderDir->VTableFixups.VirtualAddress);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tVTableFixups.Size            : %08lX\n\n",
    vaBase, foBase, clrHeaderDir->VTableFixups.Size);
   
    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tExportAddressTableJumps.VA   : %08lX\n",
    vaBase, foBase, clrHeaderDir->ExportAddressTableJumps.VirtualAddress);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tExportAddressTableJumps.Size : %08lX\n\n",
    vaBase, foBase, clrHeaderDir->ExportAddressTableJumps.Size);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tManagedNativeHeader.VA       : %08lX\n",
    vaBase, foBase, clrHeaderDir->ManagedNativeHeader.VirtualAddress);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tManagedNativeHeader.Size     : %08lX\n\n",
    vaBase, foBase, clrHeaderDir->ManagedNativeHeader.Size);

    vaBase += 4; foBase += 4;

    fflush(stdout);

    return RET_SUCCESS;
}

RET_CODE dump_all_data_directories(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY dataDirs,
    PPEDataDirectories dirs,
    ULONGLONG imageBase,
    int is64bit,
    LONGLONG fileSize,
    WORD machine) {
    int status = RET_NO_VALUE;

    //
    // Directory pointers
    //
    PIMAGE_DATA_DIRECTORY pExportDataDir       = &dataDirs[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_DATA_DIRECTORY pImportDataDir       = &dataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_DATA_DIRECTORY pRsrcDataDir         = &dataDirs[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    PIMAGE_DATA_DIRECTORY pExceptionDataDir    = &dataDirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    PIMAGE_DATA_DIRECTORY pSecurityDataDir     = &dataDirs[IMAGE_DIRECTORY_ENTRY_SECURITY];
    PIMAGE_DATA_DIRECTORY pRelocDataDir        = &dataDirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    PIMAGE_DATA_DIRECTORY pDebugDataDir        = &dataDirs[IMAGE_DIRECTORY_ENTRY_DEBUG];
    PIMAGE_DATA_DIRECTORY pTlsDataDir          = &dataDirs[IMAGE_DIRECTORY_ENTRY_TLS];
    PIMAGE_DATA_DIRECTORY pLcfgDataDir         = &dataDirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    PIMAGE_DATA_DIRECTORY pBoundImportDataDir  = &dataDirs[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    PIMAGE_DATA_DIRECTORY pIatDataDir          = &dataDirs[IMAGE_DIRECTORY_ENTRY_IAT];
    PIMAGE_DATA_DIRECTORY pDelayImportDataDir  = &dataDirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    PIMAGE_DATA_DIRECTORY pClrHeaderDataDir    = &dataDirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];

    //
    // EXPORT
    //
    if (pExportDataDir->VirtualAddress) {
        if (dump_export_dir(peFile, sections, numberOfSections, pExportDataDir, dirs->exportDir, imageBase) != RET_SUCCESS)
            fprintf(stderr, "[!] Failed to dump Export Directory\n");
        END_DIR();
    }

    //
    // IMPORT
    //
    if (pImportDataDir->VirtualAddress) {
        if (dump_import_dir(peFile, sections, numberOfSections, pImportDataDir, dirs->importDir, imageBase, is64bit, fileSize) != RET_SUCCESS)
            fprintf(stderr, "[!] Failed to dump Import Directory\n");
        END_DIR();
    }

    //
    // RESOURCE
    //
    if (pRsrcDataDir->VirtualAddress) {
        if (dump_rsrc_dir(peFile, sections, numberOfSections, pRsrcDataDir, dirs->rsrcDir, dirs->rsrcEntriesDir, imageBase) != RET_SUCCESS)
            fprintf(stderr, "[!] Failed to dump Resource Directory\n");
        END_DIR();
    }

    //
    // EXCEPTION
    //
    if (pExceptionDataDir->VirtualAddress) {
        if (dump_exception_dir(peFile, sections, numberOfSections, pExceptionDataDir, machine, imageBase) != RET_SUCCESS)
            fprintf(stderr, "[!] Failed to dump Exception Directory\n");
        END_DIR();
    }

    //
    // SECURITY
    //
    if (pSecurityDataDir->VirtualAddress) {
        if (dump_security_dir(peFile, pSecurityDataDir) != RET_SUCCESS)
            fprintf(stderr, "[!] Failed to dump Security Directory\n");
        END_DIR();
    }

    //
    // BASE RELOC
    //
    if (pRelocDataDir->VirtualAddress) {
        if (dump_reloc_dir(peFile, sections, numberOfSections, pRelocDataDir, imageBase) != RET_SUCCESS)
            fprintf(stderr, "[!] Failed to dump Base Relocation Directory\n");
        END_DIR();
    }

    //
    // DEBUG
    //
    if (pDebugDataDir->VirtualAddress) {
        if (dump_debug_dir(peFile, sections, numberOfSections, pDebugDataDir, dirs->debugDir, machine, imageBase, is64bit) != RET_SUCCESS)
            fprintf(stderr, "[!] Failed to dump Debug Directory\n");
        END_DIR();
    }

    //
    // TLS
    //
    if (pTlsDataDir->VirtualAddress) {
        if (dump_tls_dir(peFile, sections, numberOfSections, pTlsDataDir, dirs->tls64, dirs->tls32, imageBase, is64bit) != RET_SUCCESS)
            fprintf(stderr, "[!] Failed to dump TLS Directory\n");
        END_DIR();
    }

    //
    // LOAD CONFIG
    //
    if (pLcfgDataDir->VirtualAddress) {
        if (dump_load_config_dir(peFile, sections, numberOfSections, pLcfgDataDir, dirs->loadConfig64, dirs->loadConfig32, imageBase, is64bit) != RET_SUCCESS)
            fprintf(stderr, "[!] Failed to dump Load Config Directory\n");
        END_DIR();
    }

    //
    // BOUND IMPORT
    //
    if (pBoundImportDataDir->VirtualAddress) {
        if (dump_bound_import_dir(peFile, sections, numberOfSections, pBoundImportDataDir, imageBase) != RET_SUCCESS)
            fprintf(stderr, "[!] Failed to dump Bound Import Directory\n");
        END_DIR();
    }

    //
    // IAT
    //
    if (pIatDataDir->VirtualAddress) {
        if (dump_iat_table(peFile, sections, numberOfSections, pIatDataDir->VirtualAddress, imageBase, is64bit, fileSize) != RET_SUCCESS)
            fprintf(stderr, "[!] Failed to dump IAT Directory\n");
        END_DIR();
    }

    //
    // DELAY IMPORT
    //
    if (pDelayImportDataDir->VirtualAddress) {
        if (dump_delay_import_dir(peFile, sections, numberOfSections, pDelayImportDataDir, dirs->delayImportDir, imageBase, is64bit, fileSize) != RET_SUCCESS)
            fprintf(stderr, "[!] Failed to dump Delay Import Directory\n");
        END_DIR();
    }

    //
    // CLR HEADER
    //
    if (pClrHeaderDataDir->VirtualAddress) {
        if (dump_clr_header_dir(peFile, sections, numberOfSections, pClrHeaderDataDir, dirs->clrHeader, imageBase) != RET_SUCCESS)
            fprintf(stderr, "[!] Failed to dump CLR/.NET Header Directory\n");
        END_DIR();
    }

    return status;
}
