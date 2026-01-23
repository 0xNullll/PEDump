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

    printf("\n%-5s    %-10s    %-4s    %-6s    %-s\n",
           "Idx", "FO", "Type", "Length", "String");

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
                        if (!regex_search(regexFilter, (const char *)uniConverted)) continue;
                    }
                    printf("%-5lu    0x%08llX    %-4c    %-6zu    %s\n",
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
                    if (!regex_search(regexFilter, (const char *)asciiTemp)) continue;
                }

                printf("%-5lu    0x%08llX    %-4c    %-6zu    %s\n",
                       ++stringNum, start, 'A', len, asciiTemp);
            }
            continue;
        }

        i++;
    }
    putchar('\n');
    fflush(stdout);

    SAFE_FREE(fileBuffer);
    return RET_SUCCESS;
}

RET_CODE dump_pe_overview(PPEContext peCtx) {
    if (!peCtx || !peCtx->valid) return RET_INVALID_PARAM;

    // Overlay info
    DWORD overlayFo = 0, overlaySize = 0;
    getOverlayInfo(peCtx->sections, peCtx->numberOfSections, peCtx->fileSize, &overlayFo, &overlaySize);

    // Alignment info
    DWORD fileAlign = peCtx->is64Bit ? peCtx->nt64->OptionalHeader.FileAlignment
                                     : peCtx->nt32->OptionalHeader.FileAlignment;
    DWORD memAlign  = peCtx->is64Bit ? peCtx->nt64->OptionalHeader.SectionAlignment
                                     : peCtx->nt32->OptionalHeader.SectionAlignment;

    // Alignment waste/expansion
    ULONGLONG wasteDisk = computeAlignmentWasteDisk(peCtx);
    ULONGLONG expansionMem = computeAlignmentExpansionMem(peCtx);

    // Header footprint
    ULONGLONG headerFootprint = computeHeaderFootprint(peCtx);

    // Section counts
    WORD rxCount = 0, rwCount = 0;
    for (WORD i = 0; i < peCtx->numberOfSections; i++) {
        IMAGE_SECTION_HEADER *sec = &peCtx->sections[i];
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) rxCount++;
        if (sec->Characteristics & IMAGE_SCN_MEM_WRITE)   rwCount++;
    }

    // Compute densities
    ULONGLONG totalRawData     = computeTotalRawData(peCtx);
    ULONGLONG totalVirtualData = computeTotalVirtualData(peCtx);
    double execDataRatio       = computeExecDataRatio(peCtx);
    double headerDensity       = computeHeaderDensity(peCtx);
    double memDensity          = peCtx->sizeOfImage ? (double)totalVirtualData / (double)peCtx->sizeOfImage * 100.0 : 0.0;
    double overlayDensity      = overlaySize ? (double)overlaySize / (double)peCtx->fileSize * 100.0 : 0.0;

    // ----------------------------------------------------------------------
    printf("\n======================================================================\n");
    printf("Computed Overview : %s\n", peCtx->filePath);
    printf("----------------------------------------------------------------------\n");

    // -------------------- Basic Sizes --------------------
    printf("Disk File Size             : %llu bytes\n", (ULONGLONG)peCtx->fileSize);
    printf("In Memory Size             : %llu bytes\n", peCtx->sizeOfImage);
    printf("Computed Image Size        : %lu bytes (from sections + SectionAlignment)\n", computeImpliedImageSize(peCtx));
    printf("Disk vs Memory Delta       : %lld bytes (Memory - Disk)\n", (LONGLONG)peCtx->sizeOfImage - peCtx->fileSize);
    printf("Memory vs Computed Delta   : %lld bytes (Memory - Computed Image Size)\n", getLoadedVsImpliedDelta(peCtx));
    printf("Truncated                  : %s\n", isTruncated(peCtx) ? "yes" : "no");

    putchar('\n');

    // -------------------- Overlay Info --------------------
    if (overlaySize) {
        printf("Overlay Present            : yes\n");
        printf("Overlay Offset             : 0x%lX bytes\n", overlayFo);
        printf("Overlay Size               : %lu bytes (%.2f%% of file)\n", overlaySize, overlayDensity);
    } else {
        printf("Overlay Present            : no\n");
    }

    putchar('\n');

    // -------------------- Alignment Info --------------------
    printf("File Alignment             : 0x%lX bytes\n", fileAlign);
    printf("Memory Alignment           : 0x%lX bytes\n", memAlign);
    printf("Alignment Waste (disk)     : %llu bytes (%.2f%% of file)\n",
           wasteDisk, peCtx->fileSize ? (double)wasteDisk / (double)peCtx->fileSize * 100.0 : 0.0);
    printf("Alignment Expansion (mem)  : %llu bytes (%.2f%% of memory image)\n",
           expansionMem, peCtx->sizeOfImage ? (double)expansionMem / (double)peCtx->sizeOfImage * 100.0 : 0.0);

    putchar('\n');

    // -------------------- Header Info --------------------
    printf("Header + Section Table     : %llu bytes (DOS + NT + Sections)\n", headerFootprint);
    
    putchar('\n');

    // -------------------- Section Info --------------------
    printf("Section Count              : %u\n", peCtx->numberOfSections);
    printf("Executable Sections Count  : %u\n", rxCount);
    printf("Writable Sections Count    : %u\n", rwCount);
    printf("Total Raw Data             : %llu bytes\n", totalRawData);
    printf("Total Virtual Data         : %llu bytes\n", totalVirtualData);
    printf("Executable/Data Ratio      : %.2f%% (RX vs RW)\n", execDataRatio);

    putchar('\n');

    // -------------------- Density Info --------------------
    printf("Header Density             : %.2f%% of file\n", headerDensity);
    printf("Memory Density             : %.2f%% of memory image\n", memDensity);
    printf("----------------------------------------------------------------------\n\n");

    fflush(stdout);
    return RET_SUCCESS;
}

void dump_extracted_exports(PMATCH_LIST MatchList, PIMAGE_SECTION_HEADER sections, WORD numberOfSections, ULONGLONG imageBase, int level) {
    PEXPORT_MATCH expMatchHdr = &((PEXPORT_MATCH)MatchList->items)[0];

    int entries_level = level;
    
    putchar('\n');

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

            /* Function name (may exist even for ordinal exports) */
            if ((expMatch->type & EXPORT_TYPE_NAME) == 0 && expMatch->funcName && expMatch->funcName[0]) {
                printf("%sFunction      : %s\n",
                    INDENT(entries_level + 2), expMatch->funcName);
            }

            /* Print ordinal ONLY if NOT ordinal-only */
            if ((expMatch->type & EXPORT_TYPE_ORDINAL) == 0) {
                printf("%sOrdinal       : #%lu\n",
                    INDENT(entries_level + 2), expMatch->ordinal);
            }

            /* Function RVA (always valid) */
            printf("%sFunc RVA      : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
                INDENT(entries_level + 2),
                expMatch->funcRva,
                funcDataRvaInfo.va,
                funcDataRvaInfo.fileOffset,
                funcDataRvaInfo.sectionName);
        }

        /* Name RVA only if present */
        if (expMatch->nameRva != 0) {
            RVA_INFO nameDataRvaInfo =
                get_rva_info(expMatch->nameRva, sections, numberOfSections, imageBase);

            printf("%sName RVA      : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
                INDENT(entries_level + 2),
                expMatch->nameRva,
                nameDataRvaInfo.va,
                nameDataRvaInfo.fileOffset,
                nameDataRvaInfo.sectionName);
        }

        /* EAT entry */
        printf("%sEAT Entry RVA : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
            INDENT(entries_level + 2),
            expMatch->rva,
            funcRvaInfo.va,
            funcRvaInfo.fileOffset,
            funcRvaInfo.sectionName);

        // printf("%sEAT Entry RVA : 0x%08lX [VA: %llX] [FO: %lX] [  %-8s]\n",
        //     INDENT(entries_level + 2), expMatch->rva, funcRvaInfo.va, funcRvaInfo.fileOffset, funcRvaInfo.sectionName);

        putchar('\n');
    }

    fflush(stdout);
    return;
}

void dump_extracted_imports(PMATCH_LIST MatchList, PIMAGE_SECTION_HEADER sections, WORD numberOfSections, ULONGLONG imageBase, int level) {
    PIMPORT_MATCH impMatchHdr = &((PIMPORT_MATCH)MatchList->items)[0];

    putchar('\n');

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


void print_target_desc(const char* label, PTarget target, int level) {
    printf("%s%-*s: ", INDENT(level), LABEL_WIDTH, label);
    if (!target || target->bufferSize == 0) {
        printf("<NOT PRESENT>\n");
        return;
    }

    switch (target->type) {
        case TARGET_FILE:
            printf("File (entire, %llu bytes)\n", target->bufferSize);
            break;
        case TARGET_SECTION:
            printf("Section (%s, %llu bytes)\n", target->section.name, target->bufferSize);
            break;
        case TARGET_RANGE:
            printf("Range (0x%llX-0x%llX, %llu bytes)\n", target->rangeStart, target->rangeEnd, target->bufferSize);
            break;
        case TARGET_RICH_HEADER:
            printf("Rich Header (%llu bytes)\n", target->bufferSize);
            break;
        default:
            printf("<UNKNOWN TYPE>\n");
            break;
    }
}

void print_digest_line(const char* label, PTarget target, int level) {
    printf("%s%-*s: ", INDENT(level), LABEL_WIDTH, label);
    if (!target || !target->hashPresent || target->hashLen == 0) {
        printf("<NOT PRESENT>\n");
        return;
    }

    for (ULONGLONG i = 0; i < target->hashLen; i++)
        printf("%02x", target->hash[i]);
    printf("\n");
}

void dump_extracted_hash(PHashConfig hashCfg, int level) {
    if (!hashCfg) return;

    printf("\n%s[HASH %s]\n", INDENT(level),
           hashCfg->mode == HASHCMD_HASH_TARGET ? "INFO" : "COMPARE");

    // --- Algorithm ---
    const char* algoName = "UNKNOWN";
    unsigned bitLen = 0;
    switch (hashCfg->algorithm) {
        case ALG_MD5:        algoName = "MD5";        bitLen = MD5_DIGEST_SIZE * 8; break;
        case ALG_SHA1:       algoName = "SHA1";       bitLen = SHA1_DIGEST_SIZE * 8; break;
        case ALG_SHA224:     algoName = "SHA224";     bitLen = SHA224_DIGEST_SIZE * 8; break;
        case ALG_SHA256:     algoName = "SHA256";     bitLen = SHA256_DIGEST_SIZE * 8; break;
        case ALG_SHA384:     algoName = "SHA384";     bitLen = SHA384_DIGEST_SIZE * 8; break;
        case ALG_SHA512:     algoName = "SHA512";     bitLen = SHA512_DIGEST_SIZE * 8; break;
        case ALG_SHA512_224: algoName = "SHA512_224"; bitLen = SHA512_224_DIGEST_SIZE * 8; break;
        case ALG_SHA512_256: algoName = "SHA512_256"; bitLen = SHA512_256_DIGEST_SIZE * 8; break;
        default: bitLen = 0; break;
    }
    printf("%s%-*s: %s (%u-bit)\n", INDENT(level), LABEL_WIDTH, "Algorithm", algoName, bitLen);

    // --- Targets ---
    if (hashCfg->mode == HASHCMD_HASH_TARGET) {
        putchar('\n');

        printf("%s%-*s: %s\n", INDENT(level), LABEL_WIDTH, "File",
               hashCfg->primaryCtx ? hashCfg->primaryCtx->filePath : "(null)");
        print_target_desc("Target", &hashCfg->primaryTarget, level);
    } else {
        printf("%s%-*s: %s\n", INDENT(level), LABEL_WIDTH, "Mode",
               hashCfg->mode == HASHCMD_COMPARE_INTERNAL ? "Internal Compare" : "Target Compare");

        const char* fileA = hashCfg->primaryCtx ? hashCfg->primaryCtx->filePath : "(null)";
        const char* fileB = hashCfg->secondaryCtx ? hashCfg->secondaryCtx->filePath : "(null)";

        putchar('\n');

        if (hashCfg->mode == HASHCMD_COMPARE_TARGETS) {
            printf("%s%-*s: %s\n", INDENT(level), LABEL_WIDTH, "File A", fileA);
            print_target_desc("Target A", &hashCfg->primaryTarget, level);

            putchar('\n');

            printf("%s%-*s: %s\n", INDENT(level), LABEL_WIDTH, "File B", fileB);
            print_target_desc("Target B", &hashCfg->secondaryTarget, level);
        } else { // Internal compare
            printf("%s%-*s: %s\n", INDENT(level), LABEL_WIDTH, "File", fileA);
            print_target_desc("Target A", &hashCfg->primaryTarget, level);
            print_target_desc("Target B", &hashCfg->secondaryTarget, level);
        }
    }

    putchar('\n');

    // --- Digests ---
    print_digest_line(hashCfg->mode == HASHCMD_COMPARE_TARGETS ? "Digest A" : "Digest", &hashCfg->primaryTarget, level);
    if (hashCfg->mode != HASHCMD_HASH_TARGET)
        print_digest_line(hashCfg->mode == HASHCMD_COMPARE_TARGETS ? "Digest B" : "Digest", &hashCfg->secondaryTarget, level);

    // --- Comparison result ---
    if (hashCfg->mode != HASHCMD_HASH_TARGET) {
        bool match = false;
        if (hashCfg->primaryTarget.hashPresent && hashCfg->secondaryTarget.hashPresent) {
            if (hashCfg->algorithm == ALG_MD5)
                match = (MD5Compare(hashCfg->primaryTarget.hash, hashCfg->secondaryTarget.hash) == 0);
            else if (hashCfg->algorithm == ALG_SHA1)
                match = (SHA1CompareOrder(hashCfg->primaryTarget.hash, hashCfg->secondaryTarget.hash) == 0);
            else if (hashCfg->algorithm == ALG_SHA224)
                match = (SHA224CompareOrder(hashCfg->primaryTarget.hash, hashCfg->secondaryTarget.hash) == 0);
            else if (hashCfg->algorithm == ALG_SHA256)
                match = (SHA256CompareOrder(hashCfg->primaryTarget.hash, hashCfg->secondaryTarget.hash) == 0);
            else if (hashCfg->algorithm == ALG_SHA384)
                match = (SHA384CompareOrder(hashCfg->primaryTarget.hash, hashCfg->secondaryTarget.hash) == 0);
            else if (hashCfg->algorithm == ALG_SHA512)
                match = (SHA512CompareOrder(hashCfg->primaryTarget.hash, hashCfg->secondaryTarget.hash) == 0);
            else if (hashCfg->algorithm == ALG_SHA512_224)
                match = (SHA512_224CompareOrder(hashCfg->primaryTarget.hash, hashCfg->secondaryTarget.hash) == 0);
            else if (hashCfg->algorithm == ALG_SHA512_256)
                match = (SHA512_256CompareOrder(hashCfg->primaryTarget.hash, hashCfg->secondaryTarget.hash) == 0);
        }
        printf("%s%-*s: %s\n", INDENT(level), LABEL_WIDTH, "Result", match ? "MATCH" : "DIFFERENT");
    }

    // --- Footer ---
    ULONGLONG footerLen = 0;
    if (hashCfg->primaryTarget.hashPresent)
        footerLen = hashCfg->primaryTarget.hashLen * 2;
    else if (hashCfg->secondaryTarget.hashPresent)
        footerLen = hashCfg->secondaryTarget.hashLen * 2;

    // printf("%s%-*s", INDENT(level), LABEL_WIDTH, ""); // align with labels
    printf("%s------------", INDENT(level));
    for (ULONGLONG i = 0; i < footerLen; i++)
        putchar('-');
    printf("\n\n");

    fflush(stdout);
}

