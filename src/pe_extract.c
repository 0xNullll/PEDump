#include "include/pe_extract.h"

// typedef enum _PE_MAIN_TYPE {
//     PE_TYPE_UNKNOWN = 0,
//     PE_TYPE_EXE,
//     PE_TYPE_DLL,
//     PE_TYPE_DRIVER,
//     PE_TYPE_SYSTEM,
//     PE_TYPE_EFI,
//     PE_TYPE_CONTROL_PANEL,
//     PE_TYPE_ACTIVEX,
//     PE_TYPE_SCREENSAVER
// } PE_MAIN_TYPE;

// typedef struct _PETypeInfo {
//     BYTE isConsole     : 1;
//     BYTE isGui         : 1;
//     BYTE isFirmware    : 1;
//     BYTE isNative      : 1;
//     BYTE hasExports    : 1;
//     BYTE hasImports    : 1;
//     BYTE hasSignature  : 1;
//     BYTE reserved      : 2;   // keep alignment to 8 bits

//     PE_MAIN_TYPE mainType;

//     char extension[32];
//     char fileName[260];
// } PETypeInfo, *PPETypeInfo;

// TODO Add deeper detection logic for native drivers (check for DriverEntry and kernel exports)
RET_CODE identify_pe_type(
    const char *filePath,
    PIMAGE_DATA_DIRECTORY dataDirs,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    WORD fileFlags,
    DWORD addrOfEntryPoint,
    WORD subsystem,
    WORD majorSubVer, WORD minorSubVer,
    PPETypeInfo outPetypeinfo) {
    
    PETypeInfo petypeinfo = {0};
    petypeinfo.mainType = PE_TYPE_UNKNOWN;
    int status;
    
    // Store file name (if your struct supports it)
    if (filePath) strncpy(petypeinfo.fileName, filePath, sizeof(petypeinfo.fileName) - 1);
    
    // EFI / Boot Application detection
    if (subsystem == IMAGE_SUBSYSTEM_EFI_APPLICATION ||
        subsystem == IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER ||
        subsystem == IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER ||
        subsystem == IMAGE_SUBSYSTEM_EFI_ROM ||
        subsystem == IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION)
        {
            petypeinfo.isFirmware = 1;
            petypeinfo.mainType = PE_TYPE_EFI;
            strncpy(petypeinfo.extension, ".efi", sizeof(petypeinfo.extension) - 1);
            status = RET_SUCCESS;
        }
    
    // Native subsystem (kernel / system binaries)
    if (subsystem == IMAGE_SUBSYSTEM_NATIVE) {
        petypeinfo.isNative = 1;
        // Kernel-mode binary
        if (fileFlags & IMAGE_FILE_DLL) {
            // find if the main entry point function is DriverEntry() and other symbols inside the file later on to identify a sys file

            // Usually a .sys driver or a kernel DLL
            petypeinfo.mainType = PE_TYPE_DLL;
            strncpy(petypeinfo.extension, ".dll", sizeof(petypeinfo.extension) - 1);
        } else {
            // Kernel EXE (e.g., ntoskrnl.exe)
            petypeinfo.mainType = PE_TYPE_SYSTEM;
            strncpy(petypeinfo.extension, ".exe", sizeof(petypeinfo.extension) - 1);
            }
            status = RET_SUCCESS;
        }
        
    // DLLs (user-mode libraries)
    if ((fileFlags & IMAGE_FILE_DLL) && subsystem != IMAGE_SUBSYSTEM_NATIVE) {
        petypeinfo.mainType = PE_TYPE_DLL;
        strncpy(petypeinfo.extension, ".dll", sizeof(petypeinfo.extension) - 1);
        status = RET_SUCCESS;
    }

    // Executables (GUI or Console)
    if (!(fileFlags & IMAGE_FILE_DLL) && addrOfEntryPoint != 0) {
        petypeinfo.mainType = PE_TYPE_EXE;
        strncpy(petypeinfo.extension, ".exe", sizeof(petypeinfo.extension) - 1);

        if (subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) petypeinfo.isGui = 1;
        else if (subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) petypeinfo.isConsole = 1;
        
        status = RET_SUCCESS;
    }
    
    // MUI Resource-Only DLLs
    if ((fileFlags & IMAGE_FILE_DLL) &&
    addrOfEntryPoint == 0 &&
    has_section(sections, numberOfSections, ".rsrc") &&
    !has_section(sections, numberOfSections, ".text"))
    {
        petypeinfo.mainType = PE_TYPE_MUI;
        strncpy(petypeinfo.extension, ".dll.mui", sizeof(petypeinfo.extension) - 1);
        status = RET_SUCCESS;
    }
    
    // Unknown fallback
    if (status != RET_SUCCESS) strncpy(petypeinfo.extension, ".bin", sizeof(petypeinfo.extension) - 1);
    *outPetypeinfo = petypeinfo;
    return status;
}


RET_CODE extract_section(
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PSectionExtract sectionCfg,
    PDWORD outFo,
    PDWORD outSize,
    PWORD outSectionIdx) {

    int status = RET_NO_VALUE;

    BYTE match = 0;  // reset here each iteration
    for (WORD i = 0; i < numberOfSections && !match; i++) {
        if (sectionCfg->useName) {
            if (memcmp(sectionCfg->name, sections[i].Name,
                       sizeof(sectionCfg->name)) == 0) {
                match = 1;
            }
        }
        else if (sectionCfg->useIdx) {
            if (sectionCfg->index == (ULONG)i + 1) {
                match = 1;
            }
        }
        else if (sectionCfg->useRva) {
            if (sectionCfg->addr.rva >= sections[i].VirtualAddress &&
                sectionCfg->addr.rva < sections[i].VirtualAddress + max(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData)) {
                match = 1;
            }
        }
        else if (sectionCfg->useFo) {
            if (sectionCfg->addr.fo >= sections[i].PointerToRawData &&
                sectionCfg->addr.fo < sections[i].PointerToRawData + sections[i].SizeOfRawData) {
                match = 1;
            }
        }

        if (match) { 
            *outFo      = sections[i].PointerToRawData;
            *outSize    = sections[i].SizeOfRawData;
            *outSectionIdx = i + 1;
            status = RET_SUCCESS;  // exits loop immediately on first match
        }
    }

    return status; // no match after full loop
}

BOOL match_export_entry(
    const PExportExtract expCfg,
    DWORD funcRva, DWORD nameRva, ULONGLONG ordinal,
    const char *name, const char *forwardName, const char *ExportDllName, const char *forwardDllName) {
    
    if (expCfg->useRva && (expCfg->rva == funcRva || expCfg->rva == nameRva)) return TRUE;
    if (expCfg->useOrdinal && expCfg->ordinal == ordinal) return TRUE;

    if (expCfg->useName &&
        strncmp(expCfg->funcName, name, sizeof(expCfg->funcName)) == 0) return TRUE;

    if (expCfg->useForwarder && 
        strncmp(expCfg->forwarderName, forwardName, sizeof(expCfg->forwarderName)) == 0) return TRUE;

    if (expCfg->useDll && (
        strncmp(expCfg->dllName, ExportDllName, sizeof(expCfg->dllName)) == 0 ||
        strncmp(expCfg->dllName, forwardDllName, sizeof(expCfg->dllName)) == 0 )) return TRUE;

    return FALSE;
}

RET_CODE extract_exports(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY expDirData,
    PIMAGE_EXPORT_DIRECTORY expDir,
    PExportExtract expCfg,
    PMATCH_LIST outMatchesList) {

    if (!peFile || !expDirData || !expDir) return RET_INVALID_PARAM;

    RET_CODE status = RET_NO_VALUE;

    init_match_list(outMatchesList, 1, sizeof(EXPORT_MATCH));

    // === Resolve export DLL name ===
    char ExportDllName[MAX_DLL_NAME] = {0};
    SECTION_INFO secExportName = get_section_info(expDir->Name, sections, numberOfSections);
    if (secExportName.size != 0 &&
        expDir->Name - secExportName.virtualAddress < secExportName.size)
    {
        if (FSEEK64(peFile, secExportName.rawOffset + expDir->Name - secExportName.virtualAddress, SEEK_SET) == 0)
            fread(ExportDllName, 1, MAX_DLL_NAME - 1, peFile);
    } 
    else strcpy(ExportDllName, "<invalid>");

    // === Parse Export Tables ===
    DWORD *EAT = parse_table_from_rva(peFile, expDir->AddressOfFunctions,
                                      sizeof(DWORD), expDir->NumberOfFunctions,
                                      sections, numberOfSections);

    DWORD *NameRVAArray = parse_table_from_rva(peFile, expDir->AddressOfNames,
                                               sizeof(DWORD), expDir->NumberOfNames,
                                               sections, numberOfSections);

    WORD *NameOrdinalArray = parse_table_from_rva(peFile, expDir->AddressOfNameOrdinals,
                                                  sizeof(WORD), expDir->NumberOfNames,
                                                  sections, numberOfSections);

    if (!EAT || !NameRVAArray || !NameOrdinalArray)
        return RET_ERROR;

    // getting the virtual address of function addresses located after the IMAGE_EXPORT_DIRECTORY 
    DWORD rvaBase = expDir->AddressOfFunctions + sizeof(IMAGE_EXPORT_DIRECTORY);

    // === Iterate over exports ===
    for (DWORD funcIdx = 0; funcIdx < expDir->NumberOfFunctions; funcIdx++) {
        EXPORT_MATCH ExportMatch = {0};
        DWORD funcRVA = EAT[funcIdx];
        DWORD nameRVA = 0;
        char funcName[MAX_FUNC_NAME] = {0};
        char forwardName[MAX_FUNC_NAME] = {0};
        char forwardDllName[MAX_DLL_NAME] = {0};
        int entryMatched = 0;

        // Resolve function name
        for (DWORD j = 0; j < expDir->NumberOfNames; j++) {
            if (NameOrdinalArray[j] == funcIdx) {
                nameRVA = NameRVAArray[j];
                DWORD nameOffset;
                if (rva_to_offset(nameRVA, sections, numberOfSections, &nameOffset) == RET_SUCCESS &&
                    FSEEK64(peFile, nameOffset, SEEK_SET) == 0) {
                    fread(funcName, 1, sizeof(funcName) - 1, peFile);
                    funcName[sizeof(funcName) - 1] = '\0';
                }
                break;
            }
        }

        // Resolve forwarder name (if forwarder RVA)
        bool isForwarded = false;
        if (strncmp(expCfg->dllName, ExportDllName, sizeof(expCfg->dllName)) != 0 &&
            funcRVA >= expDirData->VirtualAddress &&
            funcRVA < expDirData->VirtualAddress + expDirData->Size) {
            DWORD fwdOffset;
            if (rva_to_offset(funcRVA, sections, numberOfSections, &fwdOffset) == RET_SUCCESS &&
                FSEEK64(peFile, fwdOffset, SEEK_SET) == 0) {
                fread(forwardName, 1, sizeof(forwardName) - 1, peFile);

                get_dll_from_forwarder(forwardName, forwardDllName, sizeof(forwardDllName));

                isForwarded = true;
            }
        }

        if (match_export_entry(expCfg, funcRVA, nameRVA, funcIdx + expDir->Base, funcName, forwardName, ExportDllName, forwardDllName)) {
            if (expCfg->useDll)
                ExportMatch.type |= EXPORT_TYPE_DLL_NAME;

            if (expCfg->useName)
                ExportMatch.type |= EXPORT_TYPE_NAME;

            if (expCfg->useOrdinal)
                ExportMatch.type |= EXPORT_TYPE_ORDINAL;

            if (expCfg->useRva)
                ExportMatch.type |= EXPORT_TYPE_RVA;
                
            ExportMatch.isForwarded = isForwarded;

            ExportMatch.funcRva = funcRVA;
            ExportMatch.nameRva = nameRVA;

            ExportMatch.ordinal = funcIdx + expDir->Base;

            if (ExportMatch.type & EXPORT_TYPE_DLL_NAME) {
                strncpy(ExportMatch.dllName, forwardDllName, sizeof(ExportMatch.dllName) - 1);
            } else {
                strncpy(ExportMatch.dllName, ExportDllName, sizeof(ExportMatch.dllName) - 1);
            }

            strncpy(ExportMatch.funcName, funcName, sizeof(ExportMatch.funcName) - 1);
            strncpy(ExportMatch.forwarderName, forwardName, sizeof(ExportMatch.forwarderName) - 1);

            ExportMatch.rva = rvaBase;

            entryMatched = 1;
        }

        if (entryMatched) {
            if (ensure_match_capacity(outMatchesList, 1) != RET_SUCCESS) goto cleanup;
            if (add_match(outMatchesList, &ExportMatch) != RET_SUCCESS) goto cleanup;
            status = RET_SUCCESS;

            if ((ExportMatch.type & EXPORT_TYPE_DLL_NAME) == 0) break;
        }

        rvaBase += sizeof(DWORD);
    }

cleanup:
    if (status != RET_SUCCESS) {
        free_match_list(outMatchesList);
    }

    return status;
}

BOOL match_import_entry(const PImportExtract impCfg,  ULONGLONG ordinal, WORD hint, const char *funcName, const char *dllName) {
    if (impCfg->useOrdinal && impCfg->ordinal == ordinal) return TRUE;
    if (impCfg->useHint && impCfg->hint == hint) return TRUE;

    if (impCfg->useName &&
        strncmp(impCfg->funcName, funcName, sizeof(impCfg->funcName)) == 0) return TRUE;
    if (impCfg->useDll &&
        strncmp(impCfg->dllName, dllName, sizeof(impCfg->dllName)) == 0) return TRUE;

    return FALSE;
}

RET_CODE extract_imports(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_IMPORT_DESCRIPTOR impDesc,
    int is64bit,
    PImportExtract impCfg,
    PMATCH_LIST outMatchesList) {

    if (!peFile || !impDesc) return RET_INVALID_PARAM;

    RET_CODE status = RET_NO_VALUE;
    WORD count = count_imp_descriptors(impDesc);

    init_match_list(outMatchesList, 1, sizeof(IMPORT_MATCH));

    for (WORD i = 0; i < count; i++) {
        char dllName[MAX_DLL_NAME] = {0};
        
        if (!read_import_dll_name(peFile, &impDesc[i], sections, numberOfSections, dllName)) {
            strcpy(dllName, "<invalid>");
        }

        // Skip DLLs if not global and DLL doesn't match
        if (!impCfg->isGlobal && STREQI(impCfg->dllName, dllName) != 0) {
            continue;
        }

        DWORD rvaINT = impDesc[i].OriginalFirstThunk ? impDesc[i].OriginalFirstThunk : impDesc[i].FirstThunk;
        DWORD INToffset;
        if (rva_to_offset(rvaINT, sections, numberOfSections, &INToffset) != RET_SUCCESS) {
            goto cleanup;
        }

        ULONGLONG numImports = count_thunks(peFile, rvaINT, sections, numberOfSections, is64bit);

        if (FSEEK64(peFile, INToffset, SEEK_SET) != 0) {
            goto cleanup;
        }
    
        DWORD thunkSize = is64bit ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);    

        for (ULONGLONG entry = 0; entry < numImports; entry++) {
            IMPORT_MATCH importMatch = {0};
            LONGLONG thunkPos = FTELL64(peFile);
            ULONGLONG ordinal = 0;
            WORD hint = 0;
            char name[MAX_FUNC_NAME] = {0};
            int entryMatched = 0;

            // calculate the RVA directly
            DWORD currentThunkRVA = impDesc[i].FirstThunk + (DWORD)(entry * thunkSize);

            if (impCfg->isGlobal || impCfg->useDll) importMatch.isGlobal = 1;

            if (is64bit) {
                IMAGE_THUNK_DATA64 thunk64 = {0};
                if (fread(&thunk64, sizeof(thunk64), 1, peFile) != 1 || thunk64.u1.AddressOfData == 0)
                    break;

                if (IMAGE_SNAP_BY_ORDINAL64(thunk64.u1.Ordinal)) {
                    ordinal = IMAGE_ORDINAL64(thunk64.u1.Ordinal);
                    if (match_import_entry(impCfg, ordinal, 0, "", dllName)) {
                        strncpy(importMatch.dllName, dllName, sizeof(importMatch.dllName));
                        strncpy(importMatch.funcName, "<unknown>", sizeof(importMatch.funcName));
                        importMatch.ordinal = (WORD)ordinal;
                        importMatch.type = impCfg->useOrdinal ? IMPORT_TYPE_ORDINAL : IMPORT_TYPE_DLL_NAME;
                        importMatch.rawOrd = thunk64.u1.Ordinal;
                        importMatch.thunkDataRVA = 0;
                        importMatch.thunkRVA = currentThunkRVA;
                        entryMatched = 1;
                    }
                } else {
                    if (!read_import_hint_and_name(peFile, (DWORD)thunk64.u1.AddressOfData,
                                                  sections, numberOfSections, &hint, name))
                        continue;

                    if (match_import_entry(impCfg, 0, hint, name, dllName)) {
                        strncpy(importMatch.dllName, dllName, sizeof(importMatch.dllName));
                        strncpy(importMatch.funcName, name, sizeof(importMatch.funcName));
                        importMatch.hint = hint;
                        importMatch.type =
                            impCfg->useName ? IMPORT_TYPE_NAME :
                            (impCfg->useHint ? IMPORT_TYPE_HINT : IMPORT_TYPE_DLL_NAME);
                        importMatch.rawOrd = 0;
                        importMatch.thunkDataRVA = (DWORD)thunk64.u1.AddressOfData;
                        importMatch.thunkRVA = currentThunkRVA;
                        entryMatched = 1;
                    }
                }

                FSEEK64(peFile, (ULONGLONG)thunkPos + sizeof(thunk64), SEEK_SET);
            } else {
                IMAGE_THUNK_DATA32 thunk32 = {0};
                if (fread(&thunk32, sizeof(thunk32), 1, peFile) != 1 || thunk32.u1.AddressOfData == 0)
                    break;

                if (IMAGE_SNAP_BY_ORDINAL32(thunk32.u1.Ordinal)) {
                    ordinal = IMAGE_ORDINAL32(thunk32.u1.Ordinal);
                    if (match_import_entry(impCfg, ordinal, 0, "", dllName)) {
                        strncpy(importMatch.dllName, dllName, sizeof(importMatch.dllName));
                        strncpy(importMatch.funcName, "<unknown>", sizeof(importMatch.funcName));
                        importMatch.ordinal = (WORD)ordinal;
                        importMatch.type = impCfg->useOrdinal ? IMPORT_TYPE_ORDINAL : IMPORT_TYPE_DLL_NAME;
                        importMatch.rawOrd = thunk32.u1.Ordinal;
                        importMatch.thunkDataRVA = 0;
                        importMatch.thunkRVA = currentThunkRVA;
                        entryMatched = 1;
                    }
                } else {
                    if (!read_import_hint_and_name(peFile, thunk32.u1.AddressOfData,
                                                  sections, numberOfSections, &hint, name))
                        continue;

                    if (match_import_entry(impCfg, 0, hint, name, dllName)) {
                        strncpy(importMatch.dllName, dllName, sizeof(importMatch.dllName));
                        strncpy(importMatch.funcName, name, sizeof(importMatch.funcName));
                        importMatch.hint = hint;
                        importMatch.type =
                            impCfg->useName ? IMPORT_TYPE_NAME :
                            (impCfg->useHint ? IMPORT_TYPE_HINT : IMPORT_TYPE_DLL_NAME);
                        importMatch.rawOrd = 0;
                        importMatch.thunkDataRVA = thunk32.u1.AddressOfData;
                        importMatch.thunkRVA = currentThunkRVA;
                        entryMatched = 1;
                    }
                }

                FSEEK64(peFile, (ULONGLONG)thunkPos + sizeof(thunk32), SEEK_SET);
            }

            if (entryMatched) {
                if (ensure_match_capacity(outMatchesList, 1) != RET_SUCCESS) goto cleanup;
                if (add_match(outMatchesList, &importMatch) != RET_SUCCESS) goto cleanup;
                status = RET_SUCCESS;
            }
        }
    }

cleanup:
    if (status != RET_SUCCESS) {
        free_match_list(outMatchesList);
    }

    return status;
}

RET_CODE perform_extract(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    DWORD symTableOffset,
    DWORD NumberOfSymbols,
    PIMAGE_DATA_DIRECTORY dataDirs,
    PPEDataDirectories dirs,
    LONGLONG fileSize,
    ULONGLONG imageBase,
    int is64bit,
    PConfig config,
    PFileSectionList fileSectionList) {

    if (!peFile || !sections || !numberOfSections) return RET_INVALID_PARAM;

    DWORD inFo = 0, inSize = 0;
    PMATCH_LIST MatchList = NULL;
    WORD dataDirIndex = 0;
    RET_CODE status = RET_SUCCESS;

    switch (config->extractConfig.kind) {
        case EXTRACT_SECTION:
            status = extract_section(sections, numberOfSections, &config->extractConfig.section, &inFo, &inSize, &dataDirIndex); 
            
            if (status != RET_SUCCESS) {
                fprintf(stderr,"[!!] Section info not found\n");
                break;
            }

            if (config->formatConfig.view == VIEW_TABLE) {
                WORD sectionIdx = config->extractConfig.section.index;
                status = print_section_header(peFile, symTableOffset, NumberOfSymbols, &sections[sectionIdx], sectionIdx, imageBase);
            } else {
                status = print_range(peFile, inFo,  inSize, fileSize, &config->formatConfig, fileSectionList, 1);
            }

            if (status != RET_SUCCESS) {
                fprintf(stderr, "[!!] Failed to dump extracted Section info\n");
            }
            break;

        case EXTRACT_EXPORT: 
            MatchList = calloc(1, sizeof(MATCH_LIST));
            if (!MatchList) return RET_ERROR;

            status = extract_exports(
                peFile, sections, numberOfSections, &dataDirs[IMAGE_DIRECTORY_ENTRY_EXPORT], dirs->exportDir,
                &config->extractConfig.export, MatchList);

            if (status != RET_SUCCESS) {
                free_match_list(MatchList);
                SAFE_FREE(MatchList);

                if (status == RET_NO_VALUE) fprintf(stderr,"[!!] Export info not found\n");
                else if (status == RET_ERROR) fprintf(stderr, "[!!] Failed to extract Export info\n");       
                break;
            }

            dump_extracted_exports(MatchList, sections, numberOfSections, imageBase, 0);
            free_match_list(MatchList);
            SAFE_FREE(MatchList);
            break;

        case EXTRACT_IMPORT:
            MatchList = calloc(1, sizeof(MATCH_LIST));
            if (!MatchList) return RET_ERROR;

            status = extract_imports(
                peFile, sections, numberOfSections, dirs->importDir,
                is64bit, &config->extractConfig.import, MatchList);

            if (status != RET_SUCCESS) {
                free_match_list(MatchList);
                SAFE_FREE(MatchList);

                if (status == RET_NO_VALUE) fprintf(stderr,"[!!] Import info not found\n");
                else if (status == RET_ERROR) fprintf(stderr, "[!!] Failed to extract Import info\n");       
                break;
            }

            dump_extracted_imports(MatchList, sections, numberOfSections, imageBase, 0);
            free_match_list(MatchList);
            SAFE_FREE(MatchList);
            break;

        default:
            fprintf(stderr,"[!!] Unknown extracting kind\n");
            status = RET_NO_VALUE;
            break;
    }

    return status;
}

RET_CODE extract_version_resource(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY rsrcDataDir,
    PIMAGE_RESOURCE_DIRECTORY rsrcDir,
    PIMAGE_RESOURCE_DIRECTORY_ENTRY rsrcEntriesDir,
    PDWORD outDataRVA,
    PDWORD outSize) {

    if (!peFile || !sections || !rsrcDataDir || !rsrcDir || !rsrcEntriesDir || !outDataRVA || !outSize)
        return RET_INVALID_PARAM;

    *outDataRVA = 0;
    *outSize    = 0;

    // Convert .rsrc RVA to file offset
    DWORD rsrcFO = 0;
    if (rva_to_offset(rsrcDataDir->VirtualAddress, sections, numberOfSections, &rsrcFO) != RET_SUCCESS)
        return RET_ERROR;

    SECTION_INFO rsrcSecInfo = get_section_info(rsrcDataDir->VirtualAddress, sections, numberOfSections);

    WORD totalTypeEntries = rsrcDir->NumberOfNamedEntries + rsrcDir->NumberOfIdEntries;

    // --------------------------
    // Level 1: Resource Type
    // --------------------------
    for (WORD i = 0; i < totalTypeEntries; i++) {
        if (!rsrcEntriesDir[i].NameIsString && rsrcEntriesDir[i].Id == 16) { // VERSIONINFO
            if (!rsrcEntriesDir[i].DataIsDirectory)
                continue; // unexpected leaf

            DWORD nameDirFO = rsrcSecInfo.rawOffset + (rsrcEntriesDir[i].OffsetToDirectory & 0x7FFFFFFF);

            WORD totalNameEntries = 0;
            PIMAGE_RESOURCE_DIRECTORY_ENTRY nameEntries = read_resource_dir_entries(peFile, nameDirFO, &totalNameEntries);
            if (!nameEntries) return RET_ERROR;

            // --------------------------
            // Level 2: Name
            // --------------------------
            for (WORD j = 0; j < totalNameEntries; j++) {
                if (!nameEntries[j].DataIsDirectory)
                    continue;

                DWORD langDirFO = rsrcSecInfo.rawOffset + (nameEntries[j].OffsetToDirectory & 0x7FFFFFFF);

                WORD totalLangEntries = 0;
                PIMAGE_RESOURCE_DIRECTORY_ENTRY langEntries = read_resource_dir_entries(peFile, langDirFO, &totalLangEntries);
                if (!langEntries) {
                    SAFE_FREE(nameEntries);
                    return RET_ERROR;
                }

                // --------------------------
                // Level 3: Language
                // --------------------------
                for (WORD k = 0; k < totalLangEntries; k++) {
                    if (langEntries[k].DataIsDirectory)
                        continue; // should be leaf

                    DWORD dataEntryFO = rsrcSecInfo.rawOffset + (langEntries[k].OffsetToData & 0x7FFFFFFF);
                    IMAGE_RESOURCE_DATA_ENTRY dataEntry;

                    if (FSEEK64(peFile, dataEntryFO, SEEK_SET) != 0){
                        SAFE_FREE(nameEntries);
                        SAFE_FREE(langEntries);  
                        return RET_ERROR;
                    }

                    if (fread(&dataEntry, sizeof(dataEntry), 1, peFile) != 1) {
                        SAFE_FREE(nameEntries);
                        SAFE_FREE(langEntries);
                        return RET_ERROR;              
                    }

                    *outDataRVA = dataEntry.OffsetToData;
                    *outSize    = dataEntry.Size;

                    SAFE_FREE(nameEntries);
                    SAFE_FREE(langEntries);
                    return RET_SUCCESS; // first VERSIONINFO found
                }

                SAFE_FREE(langEntries);
            }

            SAFE_FREE(nameEntries);
        }
    }

    return RET_NO_VALUE; // no VERSIONINFO resource found
}


// RET_CODE load_target_buffer(PPEContext ctx, PTarget target) {
//     RET_CODE status = RET_ERROR;

//     if (!ctx || !target)
//         return status;

//     switch (target->type) {

//         case TARGET_FILE:
//             target->buffer = (PBYTE)read_entire_file_fp(
//                 ctx->fileHandle,
//                 &target->bufferSize
//             );

//             if (!target->buffer && target->bufferSize == 0) {
//                 fprintf(stderr, "[!!] Failed to allocate memory for memory buffer\n");
//                 return status;
//             }

//             target->hashPresent = true;
//             break;

//         case TARGET_RICH_HEADER:
//             if (!ctx->richHeader || ctx->richHeader->richHdrSize == 0) {
//                 target->buffer = NULL;
//                 target->bufferSize = 0;
//                 target->hashPresent = false;
//                 break;
//             }

//             // Read the raw Rich header from the file
//             target->buffer = (PBYTE)parse_table_from_fo(
//                 ctx->fileHandle,
//                 ctx->richHeader->richHdrOff,
//                 ctx->richHeader->richHdrOff + ctx->richHeader->richHdrSize,
//                 1
//             );

//             if (!target->buffer) {
//                 fprintf(stderr, "[!!] Failed to read raw Rich header from file\n");
//                 target->bufferSize = 0;
//                 target->hashPresent = false;
//                 break;
//             }

//             target->bufferSize = ctx->richHeader->richHdrSize;
//             target->hashPresent = true;
//             break;

//         case TARGET_SECTION: {
//             DWORD inFo = 0, inSize = 0;
//             WORD dataDirIndex = 0;

//             status = extract_section(
//                 ctx->sections,
//                 ctx->numberOfSections,
//                 &target->section,
//                 &inFo,
//                 &inSize,
//                 &dataDirIndex
//             );

//             target->bufferSize = (ULONGLONG)inSize;

//             if (status != RET_SUCCESS) {
//                 fprintf(stderr, "[!!] Failed to locate the target section\n");
//                 return status;
//             }

//             target->buffer = (PBYTE)parse_table_from_fo(
//                 ctx->fileHandle,
//                 inFo,
//                 target->bufferSize,
//                 1
//             );

//             if (!target->buffer && target->bufferSize == 0) {
//                 fprintf(stderr, "[!!] Failed to allocate memory for memory buffer\n");
//                 return status;
//             }

//             target->hashPresent = true;
//             break;
//         }

//         case TARGET_RANGE:
//             target->buffer = (PBYTE)parse_table_from_fo(
//                 ctx->fileHandle,
//                 (DWORD)target->rangeStart,
//                 target->rangeEnd,
//                 1
//             );

//             if (!target->buffer && target->bufferSize == 0) {
//                 fprintf(stderr, "[!!] Failed to allocate memory for memory buffer\n");
//                 return status;
//             }

//             target->hashPresent = true;
//             break;

//         default:
//             fprintf(stderr, "[!!] Unknown target type (%d) passed to load_target_buffer\n", target->type);
//             return status;
//     }

//     return RET_SUCCESS;
// }

RET_CODE load_target_buffer(PPEContext ctx, PTarget target) {
    RET_CODE status = RET_ERROR;
    if (!ctx || !target)
        return status;

    target->ownsBuffer = true; // by default, buffer is allocated here

    switch (target->type) {
        case TARGET_FILE:
            target->buffer = (PBYTE)read_entire_file_fp(ctx->fileHandle, &target->bufferSize);
            if (!target->buffer || target->bufferSize == 0) {
                fprintf(stderr, "[!!] Failed to allocate memory for file buffer\n");
                target->ownsBuffer = false;
                return status;
            }
            target->hashPresent = true;
            break;

        case TARGET_RICH_HEADER:
            if (!ctx->richHeader || ctx->richHeader->richHdrSize == 0) {
                target->buffer = NULL;
                target->bufferSize = 0;
                target->hashPresent = false;
                target->ownsBuffer = false;
                break;
            }
            target->buffer = (PBYTE)parse_table_from_fo(
                ctx->fileHandle,
                ctx->richHeader->richHdrOff,
                ctx->richHeader->richHdrOff + ctx->richHeader->richHdrSize,
                1
            );
            if (!target->buffer) {
                fprintf(stderr, "[!!] Failed to read Rich header\n");
                target->bufferSize = 0;
                target->hashPresent = false;
                target->ownsBuffer = false;
                break;
            }
            target->bufferSize = ctx->richHeader->richHdrSize;
            target->hashPresent = true;
            break;

        case TARGET_SECTION: {
            DWORD inFo = 0, inSize = 0;
            WORD dataDirIndex = 0;
            status = extract_section(ctx->sections, ctx->numberOfSections, &target->section, &inFo, &inSize, &dataDirIndex);
            target->bufferSize = (ULONGLONG)inSize;
            if (status != RET_SUCCESS) {
                fprintf(stderr, "[!!] Failed to locate section\n");
                target->ownsBuffer = false;
                return status;
            }
            target->buffer = (PBYTE)parse_table_from_fo(ctx->fileHandle, inFo, target->bufferSize, 1);
            if (!target->buffer && target->bufferSize == 0) {
                fprintf(stderr, "[!!] Failed to allocate memory for section buffer\n");
                target->ownsBuffer = false;
                return status;
            }
            target->hashPresent = true;
            break;
        }

        case TARGET_RANGE:
            target->buffer = (PBYTE)parse_table_from_fo(ctx->fileHandle, (DWORD)target->rangeStart, target->rangeEnd, 1);
            if (!target->buffer && target->bufferSize == 0) {
                fprintf(stderr, "[!!] Failed to allocate memory for range buffer\n");
                target->ownsBuffer = false;
                return status;
            }
            target->hashPresent = true;
            break;

        default:
            fprintf(stderr, "[!!] Unknown target type (%d)\n", target->type);
            return status;
    }

    return RET_SUCCESS;
}

RET_CODE compute_hash(PTarget target, WORD algorithm, PUCHAR outHash, PULONGLONG outLen) {
    if (!target || !outHash || !outLen)
        return RET_INVALID_PARAM;

    // If the target is empty / not present, skip hashing
    if (!target->hashPresent || !target->buffer || target->bufferSize == 0) {
        *outLen = 0;
        return RET_SUCCESS; // not an error; just mark it as missing
    }

    switch (algorithm) {
        case ALG_MD5: {
            UCHAR md5_digest[MD5_DIGEST_SIZE] = {0};
            if (!MD5(target->buffer, target->bufferSize, md5_digest)) {
                fprintf(stderr, "[!!] Failed to compute MD5 hash\n");
                return RET_ERROR;
            }
            memcpy(outHash, md5_digest, MD5_DIGEST_SIZE);
            *outLen = MD5_DIGEST_SIZE;
            break;
        }

        case ALG_SHA1: {
            UCHAR sha1_digest[SHA1_DIGEST_SIZE] = {0};
            if (!SHA1((uint8_t*)target->buffer, (size_t)target->bufferSize, sha1_digest)) {
                fprintf(stderr, "[!!] Failed to compute SHA1 hash\n");
                return RET_ERROR;
            }
            memcpy(outHash, sha1_digest, SHA1_DIGEST_SIZE);
            *outLen = SHA1_DIGEST_SIZE;
            break;
        }

        case ALG_SHA224: {
            UCHAR sha224_digest[SHA224_DIGEST_SIZE] = {0};
            if (!SHA224((uint8_t*)target->buffer, (size_t)target->bufferSize, sha224_digest)) {
                fprintf(stderr, "[!!] Failed to compute SHA224 hash\n");
                return RET_ERROR;
            }
            memcpy(outHash, sha224_digest, SHA224_DIGEST_SIZE);
            *outLen = SHA224_DIGEST_SIZE;
            break;
        }

        case ALG_SHA256: {
            UCHAR sha256_digest[SHA256_DIGEST_SIZE] = {0};
            if (!SHA256((uint8_t*)target->buffer, (size_t)target->bufferSize, sha256_digest)) {
                fprintf(stderr, "[!!] Failed to compute SHA256 hash\n");
                return RET_ERROR;
            }
            memcpy(outHash, sha256_digest, SHA256_DIGEST_SIZE);
            *outLen = SHA256_DIGEST_SIZE;
            break;
        }

        case ALG_SHA384: {
            UCHAR sha384_digest[SHA384_DIGEST_SIZE] = {0};
            if (!SHA384((uint8_t*)target->buffer, (size_t)target->bufferSize, sha384_digest)) {
                fprintf(stderr, "[!!] Failed to compute SHA384 hash\n");
                return RET_ERROR;
            }
            memcpy(outHash, sha384_digest, SHA384_DIGEST_SIZE);
            *outLen = SHA384_DIGEST_SIZE;
            break;
        }

        case ALG_SHA512: {
            UCHAR sha512_digest[SHA512_DIGEST_SIZE] = {0};
            if (!SHA512((uint8_t*)target->buffer, (size_t)target->bufferSize, sha512_digest)) {
                fprintf(stderr, "[!!] Failed to compute SHA512 hash\n");
                return RET_ERROR;
            }
            memcpy(outHash, sha512_digest, SHA512_DIGEST_SIZE);
            *outLen = SHA512_DIGEST_SIZE;
            break;
        }

        case ALG_SHA512_224: {
            UCHAR sha512_224_digest[SHA512_224_DIGEST_SIZE] = {0};
            if (!SHA512_224((uint8_t*)target->buffer, (size_t)target->bufferSize, sha512_224_digest)) {
                fprintf(stderr, "[!!] Failed to compute SHA512/224 hash\n");
                return RET_ERROR;
            }
            memcpy(outHash, sha512_224_digest, SHA512_224_DIGEST_SIZE);
            *outLen = SHA512_224_DIGEST_SIZE;
            break;
        }

        case ALG_SHA512_256: {
            UCHAR sha512_256_digest[SHA512_256_DIGEST_SIZE] = {0};
            if (!SHA512_256((uint8_t*)target->buffer, (size_t)target->bufferSize, sha512_256_digest)) {
                fprintf(stderr, "[!!] Failed to compute SHA512/256 hash\n");
                return RET_ERROR;
            }
            memcpy(outHash, sha512_256_digest, SHA512_256_DIGEST_SIZE);
            *outLen = SHA512_256_DIGEST_SIZE;
            break;
        }

        default:
            fprintf(stderr, "[!!] Unknown algorithm type (%d) passed to compute_hash\n", algorithm);
            return RET_ERROR;
    }

    return RET_SUCCESS;
}

// RET_CODE perform_hash_extract(PHashConfig hashCfg) {
//     RET_CODE status = RET_ERROR;

//     if (!hashCfg->primaryCtx && !hashCfg->secondaryCtx)
//         return status;

//     if (hashCfg->primaryCtx) {
//         status = load_target_buffer(hashCfg->primaryCtx, &hashCfg->primaryTarget);
//         if (status != RET_SUCCESS) goto mem_cleanup;

//         status = compute_hash(&hashCfg->primaryTarget, hashCfg->algorithm, hashCfg->primaryTarget.hash, &hashCfg->primaryTarget.hashLen);
//         if (status != RET_SUCCESS) goto alg_cleanup;
//     }

//     if (hashCfg->secondaryCtx) {
//         status = load_target_buffer(hashCfg->secondaryCtx, &hashCfg->secondaryTarget);
//         if (status != RET_SUCCESS) goto mem_cleanup;
    
//         status = compute_hash(&hashCfg->secondaryTarget, hashCfg->algorithm, hashCfg->secondaryTarget.hash, &hashCfg->secondaryTarget.hashLen);
//         if (status != RET_SUCCESS) goto alg_cleanup;
//     }

//     dump_extracted_hash(hashCfg, 0);

//     SAFE_FREE(hashCfg->primaryTarget.buffer);
//     SAFE_FREE(hashCfg->secondaryTarget.buffer);
//     return RET_SUCCESS;

// mem_cleanup:
//     SAFE_FREE(hashCfg->primaryTarget.buffer);
//     SAFE_FREE(hashCfg->secondaryTarget.buffer);
//     fprintf(stderr, "[!!] Failed to allocate memory for memory buffer\n");
//     return status;

// alg_cleanup:
//     SAFE_FREE(hashCfg->primaryTarget.buffer);
//     SAFE_FREE(hashCfg->secondaryTarget.buffer);
//     fprintf(stderr, "[!!] Failed to compute a hash\n");
//     return status;
// }

RET_CODE perform_hash_extract(PHashConfig hashCfg) {
    RET_CODE status = RET_ERROR;
    if (!hashCfg->primaryCtx && !hashCfg->secondaryCtx)
        return status;

    // --- Primary target ---
    if (hashCfg->primaryCtx) {
        status = load_target_buffer(hashCfg->primaryCtx, &hashCfg->primaryTarget);
        if (status != RET_SUCCESS) goto mem_cleanup;

        status = compute_hash(&hashCfg->primaryTarget, hashCfg->algorithm,
                              hashCfg->primaryTarget.hash, &hashCfg->primaryTarget.hashLen);
        if (status != RET_SUCCESS) goto alg_cleanup;
    }

    // --- Secondary target ---
    // Only load if a different file OR secondary target exists for internal compare
    if ((hashCfg->mode == HASHCMD_COMPARE_TARGETS && hashCfg->secondaryCtx) ||
        (hashCfg->mode == HASHCMD_COMPARE_INTERNAL && hashCfg->secondaryTarget.bufferSize == 0)) {
        
        status = load_target_buffer(hashCfg->secondaryCtx ? hashCfg->secondaryCtx : hashCfg->primaryCtx,
                                    &hashCfg->secondaryTarget);
        if (status != RET_SUCCESS) goto mem_cleanup;

        status = compute_hash(&hashCfg->secondaryTarget, hashCfg->algorithm,
                              hashCfg->secondaryTarget.hash, &hashCfg->secondaryTarget.hashLen);
        if (status != RET_SUCCESS) goto alg_cleanup;
    }

    dump_extracted_hash(hashCfg, 0);

    if (hashCfg->primaryTarget.ownsBuffer) SAFE_FREE(hashCfg->primaryTarget.buffer);
    if (hashCfg->secondaryTarget.ownsBuffer) SAFE_FREE(hashCfg->secondaryTarget.buffer);

    return RET_SUCCESS;

mem_cleanup:
    if (hashCfg->primaryTarget.ownsBuffer) SAFE_FREE(hashCfg->primaryTarget.buffer);
    if (hashCfg->secondaryTarget.ownsBuffer) SAFE_FREE(hashCfg->secondaryTarget.buffer);
    fprintf(stderr, "[!!] Memory allocation failed\n");
    return status;

alg_cleanup:
    if (hashCfg->primaryTarget.ownsBuffer) SAFE_FREE(hashCfg->primaryTarget.buffer);
    if (hashCfg->secondaryTarget.ownsBuffer) SAFE_FREE(hashCfg->secondaryTarget.buffer);
    fprintf(stderr, "[!!] Failed to compute hash\n");
    return status;
}