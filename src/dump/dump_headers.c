#include "../include/dump_headers.h"

RET_CODE dump_dos_header(PIMAGE_DOS_HEADER dosHeader, ULONGLONG imageBase) {
    if (!dosHeader) return RET_INVALID_PARAM;   // sanity check

    ULONGLONG vaBase = imageBase;
    DWORD     foBase = 0;

    printf("\n%016llX\t- DOS HEADER -\n\n", vaBase);
    printf("VA                FO        Size        Value\n");

    printf("%016llX  %08lX  [2]\t\tDOS signature                     : %04X  (\"%c%c\")\n\n",
        vaBase, foBase,
        dosHeader->e_magic,
        (char)(dosHeader->e_magic & 0xFF),           // 'M'
        (char)((dosHeader->e_magic >> 8) & 0xFF));   // 'Z'

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tBytes used on last page           : %04X\n",
        vaBase, foBase, dosHeader->e_cblp);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tTotal pages count                 : %04X\n",
        vaBase, foBase, dosHeader->e_cp);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tRelocation entries                : %04X\n",
        vaBase, foBase, dosHeader->e_crlc);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tHeader size (in paragraphs)       : %04X\n",
        vaBase, foBase, dosHeader->e_cparhdr);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tMinimum extra paragraphs required : %04X\n",
        vaBase, foBase, dosHeader->e_minalloc);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tMaximum extra paragraphs allowed  : %04X  (%u)\n\n",
        vaBase, foBase, dosHeader->e_maxalloc, (unsigned)dosHeader->e_maxalloc);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tInitial stack segment             : %04X\n",
        vaBase, foBase, dosHeader->e_ss);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tInitial stack pointer             : %04X\n",
        vaBase, foBase, dosHeader->e_sp);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tChecksum                          : %04X\n",
        vaBase, foBase, dosHeader->e_csum);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tInitial instruction pointer       : %04X\n",
        vaBase, foBase, dosHeader->e_ip);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tInitial code segment              : %04X\n",
        vaBase, foBase, dosHeader->e_cs);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tRelocation table file address     : %04X\n",
        vaBase, foBase, dosHeader->e_lfarlc);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tOverlay number                    : %04X\n\n",
        vaBase, foBase, dosHeader->e_ovno);

    vaBase += 2; foBase += 2;

    // Reserved words (e_res[4])
    printf("%016llX  %08lX  [2]\t\tReserved words                    : ",
        vaBase, foBase);
    for (int i = 0; i < 4; i++) {
        printf("%01X", dosHeader->e_res[i]);
        if (i < 3) printf(".");
    }
    printf("\n\n");

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tOEM identifier                    : %04X\n",
        vaBase, foBase, dosHeader->e_oemid);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tOEM information                   : %04X\n\n",
        vaBase, foBase, dosHeader->e_oeminfo);

    vaBase += 2; foBase += 2;

    // Reserved words 2 (e_res2[10])
    printf("%016llX  %08lX  [2]\t\tReserved words 2                  : ",
        vaBase, foBase);
    for (int i = 0; i < 10; i++) {
        printf("%01X", dosHeader->e_res2[i]);
        if (i < 9) printf(".");
    }
    printf("\n\n");

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [4]\t\tFile address of new exe header    : %08lX\n",
        vaBase, foBase, dosHeader->e_lfanew);
    
    vaBase += 4; foBase += 4;

    fflush(stdout);

    return RET_SUCCESS;
}

RET_CODE dump_rich_header(
    FILE *peFile,
    PIMAGE_RICH_HEADER encRichHeader) {

    if (!peFile || !encRichHeader) return RET_INVALID_PARAM;

    PIMAGE_RICH_HEADER decRichHdr = NULL;
    DWORD foBase;


    foBase = encRichHeader->richHdrOff;

    decRichHdr = malloc(sizeof(IMAGE_RICH_HEADER)); 

    // Allocate memory for the decrypted entries
    decRichHdr->Entries = calloc(encRichHeader->NumberOfEntries, sizeof(RICH_ENTRY));
    if (!decRichHdr->Entries) {
        SAFE_FREE(encRichHeader);
        SAFE_FREE(decRichHdr);
        return RET_ERROR;
    }
    
    if (decrypt_rich_header(encRichHeader, decRichHdr) != RET_SUCCESS) {
        fprintf(stderr, "[!!] Failed to decrypt Rich Header\n");
        SAFE_FREE(encRichHeader);
        SAFE_FREE(decRichHdr);
        return RET_ERROR;
    }

    printf("\n%08lX\t\t\t\t\t\t\t- RICH HEADER -\n\n", foBase);

    // DanS marker
    printf("%08lX  [4]  DanS marker      : %08X  (\"%c%c%c%c\")\n\n",
        foBase, decRichHdr->DanS,
        (decRichHdr->DanS & 0xFF),
        (decRichHdr->DanS >> 8) & 0xFF,
        (decRichHdr->DanS >> 16) & 0xFF,
        (decRichHdr->DanS >> 24) & 0xFF);
    foBase += 4;

    // Checksum paddings
    printf("%08lX  [4]  Checksum padding : %08X\n",
        foBase, decRichHdr->checksumPadding1);
    foBase += 4;

    printf("%08lX  [4]  Checksum padding : %08X\n",
        foBase, decRichHdr->checksumPadding2);
    foBase += 4;

    printf("%08lX  [4]  Checksum padding : %08X\n\n\n",
        foBase, decRichHdr->checksumPadding3);
    foBase += 4;

    printf("Index | FO         | Value              | Unmasked Value     | Meaning                            | ProdID                               | BuildID  | Count\n");
    printf("----------------------------------------------------------------------------------------------------------------------------------------------------------------\n");

    // Note: RICH entries are cross-packed:
    // ProdID, BuildID, and Count are shifted across adjacent entries,
    // so I did use i-1 and i in different fields to match the original encoding.
    for (WORD i = 1; i < decRichHdr->NumberOfEntries; i++) {
        ULONGLONG encRawEntry =
            ((ULONGLONG)encRichHeader->Entries[i - 1].ProdID  << 48) |  // top 16 bits
            ((ULONGLONG)encRichHeader->Entries[i].BuildID << 32) |      // next 16 bits
            ((ULONGLONG)encRichHeader->Entries[i - 1].Count);           // lower 32 bits (END)

        ULONGLONG decRawEntry =
            ((ULONGLONG)decRichHdr->Entries[i].Count << 32) |        // top 32 bits
            ((ULONGLONG)decRichHdr->Entries[i - 1].ProdID  << 16) |  // next 16 bits
            ((ULONGLONG)decRichHdr->Entries[i - 1].BuildID);         // lower 16 bits (END)

        printf("%5d | 0x%08lX | 0x%016llX | 0x%016llX | %08u.%08u.%016u | %08u - %-25s | %08u | %9lu\n",
            i,
            foBase,
            encRawEntry,
            decRawEntry,
            (unsigned) decRichHdr->Entries[i - 1].BuildID,
            (unsigned) decRichHdr->Entries[i - 1].ProdID,
            (unsigned) decRichHdr->Entries[i].Count,
            decRichHdr->Entries[i - 1].ProdID,
            getRichProductIdName(decRichHdr->Entries[i - 1].ProdID),
            decRichHdr->Entries[i - 1].BuildID,
            decRichHdr->Entries[i].Count);

        foBase += 8; // size of ULONGLONG
    }

    printf("----------------------------------------------------------------------------------------------------------------------------------------------------------------\n\n");


    // Rich marker and XOR key
    printf("%08lX  [4]  Rich marker      : %08X  (\"%c%c%c%c\")\n",
        foBase, decRichHdr->Rich,
        (decRichHdr->Rich & 0xFF),            // lowest byte
        (decRichHdr->Rich >> 8) & 0xFF,
        (decRichHdr->Rich >> 16) & 0xFF,
        (decRichHdr->Rich >> 24) & 0xFF);
    foBase += 4;

    printf("%08lX  [4]  Checksum         : %08X\n",
        foBase, decRichHdr->XORKey);
    foBase += 4;

    printf("\n");

    fflush(stdout);

    return RET_SUCCESS;
}

void print_aux_symbol_function(
    PIMAGE_AUX_SYMBOL auxSym,
    DWORD auxSymOffset,
    WORD numDigits,
    WORD index, WORD level) {

    DWORD foBase = auxSymOffset;

    printf("%s[%0*d] Auxiliary Function Symbol (FO=%lX)\n", INDENT(level), (int)numDigits, index + 1, foBase);

    printf("%sTagIndex              : 0x%lX\n",
           INDENT(level + 1), auxSym->Sym.TagIndex);

    printf("%sTotalSize             : 0x%lX\n",
           INDENT(level + 1), auxSym->Sym.Misc.TotalSize);

    printf("%sPointerToLinenumber   : 0x%lX\n",
           INDENT(level + 1), auxSym->Sym.FcnAry.Function.PointerToLinenumber);

    printf("%sPointerToNextFunction : 0x%lX\n",
           INDENT(level + 1), auxSym->Sym.FcnAry.Function.PointerToNextFunction);
}

void print_aux_symbol_bf(
    PIMAGE_AUX_SYMBOL auxSym,
    DWORD auxSymOffset,
    WORD numDigits,
    WORD index, WORD level) {

    DWORD foBase = auxSymOffset;

    printf("%s[%0*d] Auxiliary Bf Symbol (FO=%lX)\n", INDENT(level), (int)numDigits, index + 1, foBase);

    printf("%sLinenumber : 0x%lX | PointerToNextFunction : 0x%lX\n",
        INDENT(level + 1),
        (ULONG)auxSym->Sym.Misc.LnSz.Linenumber,
        (ULONG)auxSym->Sym.FcnAry.Function.PointerToNextFunction);
}

void print_aux_symbol_ef(
    PIMAGE_AUX_SYMBOL auxSym,
    DWORD auxSymOffset,
    WORD numDigits,
    WORD index, WORD level) {

    DWORD foBase = auxSymOffset;

    printf("%s[%0*d] Auxiliary Ef Symbol (FO=%lX)\n", INDENT(level), (int)numDigits, index + 1, foBase);

    printf("%sLinenumber : 0x%lX\n", INDENT(level + 1),
    (ULONG) auxSym->Sym.Misc.LnSz.Linenumber);
}

void print_aux_symbol_weak_external(
    PIMAGE_AUX_SYMBOL_WEAK_EXTERN weakExtSym,
    DWORD auxSymOffset,
    WORD numDigits,
    WORD index, WORD level) {

    DWORD foBase = auxSymOffset;

printf("%s[%0*lu] Auxiliary Weak External Symbol (FO=%lX)\n",
       INDENT(level),
       (int)numDigits,
       (ULONG)index + 1,
       foBase);

    printf("%sTagIndex : 0x%lX | Characteristics : 0x%lX (%s)\n",
        INDENT(level + 1),
        weakExtSym->TagIndex,
        weakExtSym->Characteristics,
        getWeakExternCharFlag(weakExtSym->Characteristics));
}

void print_aux_symbol_file(
    PIMAGE_AUX_SYMBOL auxSym,
    DWORD auxSymOffset,
    WORD numDigits,
    WORD index, WORD level) {

    DWORD foBase = auxSymOffset;

    printf("%s[%0*lu] Auxiliary File Symbol (FO=%lX)\n",
       INDENT(level), (int)numDigits, (ULONG)index + 1, foBase);

    printf("%sFile Name : %s\n", INDENT(level + 1), auxSym->File.Name);
}

void print_aux_symbol_sec_def(
    PIMAGE_AUX_SYMBOL auxSym,
    DWORD auxSymOffset,
    WORD numDigits,
    WORD index,
    WORD level) {
    DWORD foBase = auxSymOffset;

    printf("%s[%0*lu] Auxiliary Section Definition Symbol (FO=%08lX)\n",
           INDENT(level), numDigits, (unsigned long)index + 1, (unsigned long)foBase);

    printf("%sLength              : 0x%08lX (%lu)\n",
           INDENT(level + 1),
           (unsigned long)auxSym->Section.Length,
           (unsigned long)auxSym->Section.Length);

    printf("%sNumberOfRelocations : 0x%04hX (%hu)\n",
           INDENT(level + 1),
           auxSym->Section.NumberOfRelocations,
           auxSym->Section.NumberOfRelocations);

    printf("%sNumberOfLinenumbers : 0x%04hX (%hu)\n",
           INDENT(level + 1),
           auxSym->Section.NumberOfLinenumbers,
           auxSym->Section.NumberOfLinenumbers);

    printf("%sCheckSum            : 0x%08lX\n",
           INDENT(level + 1),
           (unsigned long)auxSym->Section.CheckSum);

    printf("%sNumber              : %hd (0x%hX)\n",
           INDENT(level + 1),
           auxSym->Section.Number,
           (unsigned short)auxSym->Section.Number);

    printf("%sSelection           : %u %s\n",
           INDENT(level + 1),
           (unsigned)auxSym->Section.Selection,
           getComdatSelectName(auxSym->Section.Selection));
}

void print_clr_token(
    PIMAGE_AUX_SYMBOL auxSym,
    DWORD auxSymOffset,
    WORD numDigits,
    WORD index,
    WORD level) {

    DWORD foBase = auxSymOffset;
    
    printf("%s[%0*lu] CLR Token (FO=%lX)\n",
        INDENT(level),
        (int)numDigits,
        (ULONG)index + 1,
        foBase);
 
    printf("%sbAuxType : 0x%X %s| SymbolTableIndex : 0x%lX\n",
        INDENT(level + 1),
        (unsigned)auxSym->TokenDef.bAuxType,
        auxSym->TokenDef.bAuxType == _IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF ? "(IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF)" : "",
        (unsigned long)auxSym->TokenDef.SymbolTableIndex);

    // printf("%sbAuxType : 0x%lX %s| SymbolTableIndex : 0x%lX\n",
    //     INDENT(level + 1),
    // auxSym->TokenDef.bAuxType, auxSym->TokenDef.bAuxType == IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF ? "(IMAGE_AUX_SYMBOL_TYPE_TOKEN_DEF)" : "",
    // auxSym->TokenDef.SymbolTableIndex);
    }

void print_symbol_value(PIMAGE_SYMBOL sym, PIMAGE_SECTION_HEADER sections, WORD numberOfSections) {
    const char* sectionName = get_symbol_sectionName(sym->SectionNumber, sections, numberOfSections);
    const char* typeName    = getSymbolType(sym->Type);
    const char* className   = getSymbolClassName(sym->StorageClass);

    DWORD valueOffset = 0, valueRVA = 0;
    if (sym->Value) {
        if (get_symbol_file_offset(sym->Value, sym->SectionNumber, sections, numberOfSections, &valueOffset) != RET_SUCCESS) {
            valueOffset = 0;
        }
        if (offset_to_rva(valueOffset, sections, numberOfSections, &valueRVA) != RET_SUCCESS) {
            valueRVA = 0;
        }
    }

    printf("%sValue: %lX (RVA=%lX | FO=%lX) | Type: (%s) | Section: (%s) | Storage: (%s)\n",
        INDENT(2),
        sym->Value,
        valueRVA,
        valueOffset,
        typeName,
        sectionName,
        className
    );
}


RET_CODE dump_aux_symbol(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_SYMBOL sym,
    DWORD auxSymOffset,
    WORD numDigits,
    WORD index, WORD level) {

    if (FSEEK64(peFile, auxSymOffset, SEEK_SET) != 0) {
        fprintf(stderr, "%s[!!] Failed to fseek to auxiliary symbol offset\n", INDENT(level));
        return RET_ERROR;
    }

    IMAGE_AUX_SYMBOL auxSym = {0};
    if (fread(&auxSym, sizeof(auxSym), 1, peFile) != 1) {
        fprintf(stderr, "%s[!!] Failed to read auxiliary symbol\n", INDENT(level));
        return RET_ERROR;
    }

    if (IsAuxFunction(sym))
        print_aux_symbol_function(&auxSym, auxSymOffset, numDigits, index, level);
    else if (IsAuxBf(sym))
        print_aux_symbol_bf(&auxSym, auxSymOffset, numDigits, index, level);
    else if (IsAuxEf(sym))
        print_aux_symbol_ef(&auxSym, auxSymOffset, numDigits, index, level);
    else if (IsAuxWeakExternal(sym)) {
        if (FSEEK64(peFile, auxSymOffset, SEEK_SET) != 0) {
            fprintf(stderr, "%s[!!] Failed to fseek to auxiliary symbol offset\n", INDENT(level));
            return RET_ERROR;
        }

        IMAGE_AUX_SYMBOL_WEAK_EXTERN weakExtSym = {0};
        if (fread(&weakExtSym, sizeof(weakExtSym), 1, peFile) != 1) {
            fprintf(stderr, "%s[!!] Failed to read auxiliary symbol\n", INDENT(level));
            return RET_ERROR;
        }

        print_aux_symbol_weak_external(&weakExtSym, auxSymOffset, numDigits, index, level);
    }
    else if (IsAuxFile(sym))
        print_aux_symbol_file(&auxSym, auxSymOffset, numDigits, index, level);

    else if (IsAuxSecDef(sym, sections, numberOfSections))
        print_aux_symbol_sec_def(&auxSym, auxSymOffset, numDigits, index, level);

    else if (IsAuxClrToken(sym))
        print_clr_token(&auxSym, auxSymOffset, numDigits, index, level);

    return RET_SUCCESS;
}

RET_CODE dump_symbol_table(
    FILE *peFile,
    DWORD symTableOffset,
    DWORD numberOfSymbols,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections) {
    if (!peFile || !symTableOffset || !numberOfSymbols) return RET_INVALID_PARAM;

    PIMAGE_SYMBOL symTable = NULL;
    char *stringTable = NULL;
    int status = RET_ERROR;  // standard failure
    DWORD stringTableOffset = 0;
    DWORD stringTableSize = 0;
    WORD numDigits = 0;
    DWORD foBase = 0;
    DWORD i;
    DWORD skip;

    if (parse_symbol_table(peFile, &symTable, numberOfSymbols, symTableOffset) != RET_SUCCESS) {
        fprintf(stderr, "[!!] Failed to parse Symbol Table\n");
        goto cleanup;
    }

    stringTableOffset = (DWORD)(symTableOffset + sizeof(IMAGE_SYMBOL) * numberOfSymbols);
    if (parse_string_table(peFile, &stringTable, stringTableOffset) != RET_SUCCESS) {
        fprintf(stderr, "[!!] Failed to parse String Table\n");
        goto cleanup;
    }

    memcpy(&stringTableSize, stringTable, sizeof(DWORD));

    printf("\n%08lX   - COFF SYMBOL TABLE: %lu %s -\n\n",
        symTableOffset,
        numberOfSymbols,
        numberOfSymbols < 2 ? "Entry" : "Entries"
    );

    numDigits = count_digits(numberOfSymbols - 1);
    foBase = symTableOffset;

    i = 0;
    while (i < numberOfSymbols) {
        PIMAGE_SYMBOL sym = &symTable[i];
        char nameBuffer[MAX_SYMBOL_NAME] = {0};

        if (sym->N.Name.Short != 0) {
            memcpy(nameBuffer, sym->N.ShortName, IMAGE_SIZEOF_SHORT_NAME);
            nameBuffer[IMAGE_SIZEOF_SHORT_NAME] = '\0';
        } else {
            DWORD longOffset = sym->N.Name.Long;
            if (longOffset < stringTableSize) {
                strncpy(nameBuffer, stringTable + longOffset, MAX_SYMBOL_NAME - 1);
                nameBuffer[MAX_SYMBOL_NAME - 1] = '\0';
            } else {
                strcpy(nameBuffer, "<invalid offset>");
            }
        }

        printf("%s[%0*lu] %s (FO=%lX)\n", INDENT(1), numDigits, i + 1, nameBuffer, foBase);
        print_symbol_value(sym, sections, numberOfSections);

        printf("%sAux: %s\n", INDENT(2), sym->NumberOfAuxSymbols ? "" : "None");
        if (sym->NumberOfAuxSymbols) {
            for (DWORD j = 0; j < sym->NumberOfAuxSymbols; j++) {
                DWORD auxFoBase = foBase + 18 * (j + 1);
                if (dump_aux_symbol(peFile, sections, numberOfSections, sym, auxFoBase, numDigits, (WORD)i + 1, 3)) {
                    fprintf(stderr, "%s[!!] Failed to dump auxiliary symbol #%lu\n", INDENT(3), j + 1);
                }
                if (sym->NumberOfAuxSymbols > 2 && (int)j != sym->NumberOfAuxSymbols - 1) printf("\n");
            }
        }

        printf("\n");

        skip = 1 + sym->NumberOfAuxSymbols;
        foBase += (DWORD)sizeof(IMAGE_SYMBOL) * skip;
        i += skip;
    }

    status = RET_SUCCESS;

cleanup:
    fflush(stdout);
    if (symTable) SAFE_FREE(symTable);
    if (stringTable) SAFE_FREE(stringTable);
    return status;
}

RET_CODE dump_string_table(FILE *peFile, DWORD symTableOffset, DWORD numberOfSymbols) {

    char *stringTable = NULL;
    int status = RET_ERROR;
    DWORD stringTableOffset = (DWORD)(symTableOffset + sizeof(IMAGE_SYMBOL) * numberOfSymbols);
    DWORD stringTableSize = 0;
    DWORD foBase;
    char *cursor;
    char *end;
    ULONGLONG len;
    
    if (parse_string_table(peFile, &stringTable, stringTableOffset) != RET_SUCCESS) {
        fprintf(stderr, "[!!] Failed to parse String Table\n");
        goto cleanup;
    }

    memcpy(&stringTableSize, stringTable, sizeof(DWORD));

    if (stringTableSize <= 4) {
        fprintf(stderr, "[!] Empty or invalid String Table\n");
        goto cleanup;
    }

    printf("\n%08lX\t- COFF STRING TABLE -\n\n", stringTableOffset);
    printf("Idx      FO        Length   String\n");
    printf("-------  --------  -------  ------------------------------\n");

    foBase = stringTableOffset + sizeof(DWORD);
    cursor = stringTable + sizeof(DWORD);
    end    = stringTable + stringTableSize;

    DWORD idx = 1;
    while (cursor < end) {
        if (*cursor == '\0') {
            printf("%08lX  %-7d  \n", foBase, 0);
            cursor++;
            foBase++;
            continue;
        }

        len = strlen(cursor);
        printf("%-7u  %08lX  %-7zu  %s\n", idx, foBase, len, cursor);
        idx++;
        cursor += len + 1;
        foBase += (DWORD)(len + 1);
    }
    printf("----------------------------------------------------------\n");

    status = RET_SUCCESS;

cleanup:
    fflush(stdout);
    if (stringTable) SAFE_FREE(stringTable);
    return status;
}

RET_CODE dump_file_header(
    FILE *peFile,
    DWORD foFileHeader,
    PIMAGE_FILE_HEADER fileHeader,
    ULONGLONG imageBase,
    int printHeader) {
    if (!fileHeader || !foFileHeader || !peFile) return RET_INVALID_PARAM;   // sanity check

    ULONGLONG vaBase = imageBase + foFileHeader;
    DWORD     foBase = foFileHeader;

    printf("\n%016llX\t- IMAGE FILE HEADER -\n\n", vaBase);

    if (printHeader) printf("VA                FO        Size        Value\n");

    printf("%016llX  %08lX  [2]\t\tMachine                 : %04X\n",
    vaBase, foBase, fileHeader->Machine);

    vaBase += 2; foBase += 2;
    
    printf("\t\t\t\t\t\t\t\t+ %04X  %-*s\n\n",
            fileHeader->Machine, MAX_STR_LEN_FILE_HEADER_MACHINE,
            fileHeaderMachineToString(fileHeader->Machine));

    printf("%016llX  %08lX  [2]\t\tNumber of sections      : %04X      (%u)\n\n", 
    vaBase, foBase, fileHeader->NumberOfSections, (unsigned)fileHeader->NumberOfSections);

    vaBase += 2; foBase += 2;

    DWORD ts = fileHeader->TimeDateStamp;

    if ((ts >= SOME_REASONABLE_EPOCH && ts <= CURRENT_EPOCH_PLUS_MARGIN) || ts == 0) {
        printf("%016llX  %08lX  [4]\t\tTime Date Stamp         : %08lX  %s\n\n", 
            vaBase, foBase, ts, format_timestamp(ts));
    } else {
        printf("%016llX  %08lX  [4]\t\tReproChecksum           : %08lX (%lu)\n\n", 
            vaBase, foBase, ts, ts);
    }

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tPointer to symbol table : %08lX\n", 
    vaBase, foBase, fileHeader->PointerToSymbolTable);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tNumber of symbols       : %08lX  (%u)\n\n", 
    vaBase, foBase, fileHeader->NumberOfSymbols, (unsigned)fileHeader->NumberOfSymbols);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [2]\t\tSize of optional header : %04X      (%u)\n\n", 
    vaBase, foBase, fileHeader->SizeOfOptionalHeader, (unsigned)fileHeader->SizeOfOptionalHeader);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tCharacteristics         : %04X\n", 
    vaBase, foBase, fileHeader->Characteristics);

    vaBase += 2; foBase += 2;

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
        if (fileHeader->Characteristics & characteristics_flags[i].flag) {
            printf("\t\t\t\t\t\t\t\t+ %04lX  %-30s\n",
                    characteristics_flags[i].flag,
                    characteristics_flags[i].name);
        }
    }

    // if (fileHeader->PointerToSymbolTable && fileHeader->NumberOfSymbols) {
    //     if (dump_symbol_table(peFile, fileHeader->PointerToSymbolTable, fileHeader->NumberOfSymbols, sections, numberOfSections, imageBase, 1)) {
    //         fprintf(stderr, "[!!] Failed to dump Symbol Table\n");
    //         return 1;
    //     }
    // }

    fflush(stdout);

    return RET_SUCCESS;
}

RET_CODE dump_optional_header(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    DWORD foOptHeader,
    PVOID optHeader,
    ULONGLONG imageBase,
    int is64bit,
    int printHeader) {
    if (!peFile || !optHeader || !foOptHeader) return RET_INVALID_PARAM;   // sanity check

    ULONGLONG vaBase = imageBase + foOptHeader;
    DWORD     foBase = foOptHeader;

    PIMAGE_OPTIONAL_HEADER64 opt64 = NULL;
    PIMAGE_OPTIONAL_HEADER32 opt32 = NULL;

    if (is64bit) {
        opt64 = (PIMAGE_OPTIONAL_HEADER64)optHeader;
    } else {
        opt32 = (PIMAGE_OPTIONAL_HEADER32)optHeader;
    }
    
    printf("\n%016llX\t- IMAGE OPTIONAL HEADER -\n\n", vaBase);

    if (printHeader) printf("VA                FO        Size        Value\n"); 

    printf("%016llX  %08lX  [2]\t\tMachine                    : %04lX\n",
    vaBase, foBase, (ULONG)(is64bit ? opt64->Magic : opt32->Magic));

    vaBase += 2; foBase += 2;

    printf("\t\t\t\t\t\t\t\t   + %04X  %-35s\n\n",        
        is64bit ? IMAGE_NT_OPTIONAL_HDR64_MAGIC : IMAGE_NT_OPTIONAL_HDR32_MAGIC,
        is64bit ? "IMAGE_NT_OPTIONAL_HDR64_MAGIC" : "IMAGE_NT_OPTIONAL_HDR32_MAGIC");

    printf("%016llX  %08lX  [1]\t\tLinker Version (Major)     : %02lX        (%3lu)\n",
        vaBase, foBase,
        (ULONG)(is64bit ? opt64->MajorLinkerVersion : opt32->MajorLinkerVersion),
        (ULONG)(is64bit ? opt64->MajorLinkerVersion : opt32->MajorLinkerVersion));

    vaBase += 1; foBase += 1;

    printf("%016llX  %08lX  [1]\t\tLinker Version (Minor)     : %02lX        (%3lu)\n\n",
        vaBase, foBase,
        (ULONG)(is64bit ? opt64->MinorLinkerVersion : opt32->MinorLinkerVersion),
        (ULONG)(is64bit ? opt64->MinorLinkerVersion : opt32->MinorLinkerVersion));

    vaBase += 1; foBase += 1;

    printf("%016llX  %08lX  [4]\t\tSize of Code               : %08lX  (%lu)\n\n",
    vaBase, foBase,
        (ULONG)(is64bit ? opt64->SizeOfCode : opt32->SizeOfCode),
        (ULONG)(is64bit ? opt64->SizeOfCode : opt32->SizeOfCode));

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tSize of Initialized Data   : %08lX  (%10lu)\n",
    vaBase, foBase,
        (ULONG)(is64bit ? opt64->SizeOfInitializedData : opt32->SizeOfInitializedData),
        (ULONG)(is64bit ? opt64->SizeOfInitializedData : opt32->SizeOfInitializedData));

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tSize of Uninitialized Data : %08lX  (%10lu)\n\n",
    vaBase, foBase,
        (ULONG)(is64bit ? opt64->SizeOfUninitializedData : opt32->SizeOfUninitializedData),
        (ULONG)(is64bit ? opt64->SizeOfUninitializedData : opt32->SizeOfUninitializedData));

    vaBase += 4; foBase += 4;

    RVA_INFO EntryPoinRVAInfo = get_rva_info(is64bit ? opt64->AddressOfEntryPoint : opt32->AddressOfEntryPoint, sections, numberOfSections, imageBase);
    printf("%016llX  %08lX  [4]\t\tEntry Point (RVA)          : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n",
    vaBase, foBase,
        is64bit ? opt64->AddressOfEntryPoint : opt32->AddressOfEntryPoint,
        EntryPoinRVAInfo.va, EntryPoinRVAInfo.fileOffset, EntryPoinRVAInfo.sectionName);

    vaBase += 4; foBase += 4;

    RVA_INFO BaseOfCodeRVAInfo = get_rva_info(is64bit ? opt64->BaseOfCode : opt32->BaseOfCode, sections, numberOfSections, imageBase);
    printf("%016llX  %08lX  [4]\t\tBase of Code               : %08lX  [VA: %llX] [FO: %lX] [  %-8s]\n%s",
    vaBase, foBase,
        is64bit ? opt64->BaseOfCode : opt32->BaseOfCode,
        BaseOfCodeRVAInfo.va, BaseOfCodeRVAInfo.fileOffset, BaseOfCodeRVAInfo.sectionName,
    is64bit ? "\n" : "");

    vaBase += 4; foBase += 4;

    if (!is64bit) {
        printf("%016llX  %08lX  [4]\t\tBase of Data               : %08lX\n\n",
        vaBase, foBase, opt32->BaseOfData);

        vaBase += 4; foBase += 4;
    }

    printf("%016llX  %08lX  [%c]\t\tImage Base                 : %0*llX\n\n",
        vaBase, foBase, is64bit ? '8' : '4',
        is64bit ? 16 : 8, imageBase);

    vaBase += is64bit ? 8 : 4; foBase += is64bit ? 8 : 4;

    printf("%016llX  %08lX  [4]\t\tSection Alignment          : %08lX\n",
    vaBase, foBase, is64bit ? opt64->SectionAlignment : opt32->SectionAlignment);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tFile Alignment             : %08lX\n\n",
    vaBase, foBase, is64bit ? opt64->FileAlignment : opt32->FileAlignment);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [2]\t\tOS Version (Major)         : %04X\n",
    vaBase, foBase, is64bit ? opt64->MajorOperatingSystemVersion : opt32->MajorOperatingSystemVersion);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tOS Version (Minor)         : %04X\n",
    vaBase, foBase, is64bit ? opt64->MinorOperatingSystemVersion : opt32->MinorOperatingSystemVersion);

    vaBase += 2; foBase += 2;

    printf("\t\t\t\t\t\t\t\t   + %04X  %-*s\n\n",
            is64bit ? opt64->MajorOperatingSystemVersion : opt32->MajorOperatingSystemVersion,
            MAX_STR_LEN_OS_VERSION,
            osVersionToString(
                is64bit ? opt64->MajorOperatingSystemVersion : opt32->MajorOperatingSystemVersion,
                is64bit ? opt64->MinorOperatingSystemVersion : opt32->MinorOperatingSystemVersion));

    printf("%016llX  %08lX  [2]\t\tImage Version (Major)      : %04X\n",
    vaBase, foBase, is64bit ? opt64->MajorImageVersion : opt32->MajorImageVersion);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tImage Version (Minor)      : %04X\n",
    vaBase, foBase, is64bit ? opt64->MinorImageVersion : opt32->MinorImageVersion);

    vaBase += 2; foBase += 2;

    printf("\t\t\t\t\t\t\t\t   + %04X  %-*s\n\n",
            is64bit ? opt64->MajorImageVersion : opt32->MinorImageVersion,
            MAX_STR_LEN_IMAGE_VERSION,
            imageVersionToString(
                is64bit ? opt64->MajorImageVersion : opt32->MajorImageVersion,
                is64bit ? opt64->MinorImageVersion: opt32->MinorImageVersion));

    printf("%016llX  %08lX  [2]\t\tSubsystem Version (Major)  : %04X\n",
    vaBase, foBase, is64bit ? opt64->MajorSubsystemVersion : opt32->MajorSubsystemVersion);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tSubsystem Version (Minor)  : %04X\n",
    vaBase, foBase, is64bit ? opt64->MinorSubsystemVersion : opt32->MinorSubsystemVersion);

    vaBase += 2; foBase += 2;

    printf("\t\t\t\t\t\t\t\t   + %04X  %-*s\n\n",
            is64bit ? opt64->MajorSubsystemVersion : opt32->MinorSubsystemVersion,
            MAX_STR_LEN_SUBSYSTEM_VERSION_FLAG,
            subSystemVersionFlagToString(
                is64bit ? opt64->MajorSubsystemVersion : opt32->MajorSubsystemVersion,
                is64bit ? opt64->MinorSubsystemVersion: opt32->MinorSubsystemVersion));

    printf("%016llX  %08lX  [4]\t\tWin32 Version Value        : %08lX\n\n",
    vaBase, foBase, is64bit ? opt64->Win32VersionValue : opt32->Win32VersionValue);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tSize of Image              : %08lX\n",
    vaBase, foBase, is64bit ? opt64->SizeOfImage : opt32->SizeOfImage);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tSize of Headers            : %08lX\n\n",
    vaBase, foBase, is64bit ? opt64->SizeOfHeaders : opt32->SizeOfHeaders);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tChecksum                   : %08lX\n\n",
    vaBase, foBase, is64bit ? opt64->CheckSum : opt32->CheckSum);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [2]\t\tSubsystem                  : %04X\n",
    vaBase, foBase, is64bit ? opt64->Subsystem : opt32->Subsystem);

    vaBase += 2; foBase += 2;

    printf("\t\t\t\t\t\t\t\t   + %04X  %-*s\n\n",
            is64bit ? opt64->Subsystem : opt32->Subsystem,
            MAX_STR_LEN_SUBSYSTEM_TYPE_FLAG,
            subSystemTypeFlagToString(is64bit ? opt64->Subsystem : opt32->Subsystem));
        
    printf("%016llX  %08lX  [2]\t\tDLL Characteristics        : %04X\n",
    vaBase, foBase,
    is64bit ? opt64->DllCharacteristics : opt32->DllCharacteristics);

    vaBase += 2; foBase += 2;

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

    DWORD dll_characteristics_flags_count = (sizeof(dll_characteristics_flags)/sizeof(dll_characteristics_flags[0]));

    for (DWORD i = 0; i < dll_characteristics_flags_count; i++) {
        if ((is64bit ? opt64->DllCharacteristics : opt32->DllCharacteristics) & dll_characteristics_flags[i].flag) {
            printf("\t\t\t\t\t\t\t\t   + %04lX  %-50s\n",
                    dll_characteristics_flags[i].flag,
                    dll_characteristics_flags[i].name);
        }
    }

    printf("\n");

    printf("%016llX  %08lX  [%c]\t\tSize of Stack Reserve      : %0*llX\n",
        vaBase, foBase, is64bit ? '8' : '4',
        is64bit ? 16 : 8, is64bit ? opt64->SizeOfStackCommit : opt32->SizeOfStackCommit);

    vaBase += is64bit ? 8 : 4; foBase += is64bit ? 8 : 4;

    printf("%016llX  %08lX  [%c]\t\tSize of Stack Commit       : %0*llX\n\n",
        vaBase, foBase, is64bit ? '8' : '4',
        is64bit ? 16 : 8, is64bit ? opt64->SizeOfStackCommit : opt32->SizeOfStackCommit);

    vaBase += is64bit ? 8 : 4; foBase += is64bit ? 8 : 4;

    printf("%016llX  %08lX  [%c]\t\tSize of Heap  Reserve      : %0*llX\n",
        vaBase, foBase, is64bit ? '8' : '4',
        is64bit ? 16 : 8, is64bit ? opt64->SizeOfHeapReserve : opt32->SizeOfHeapReserve);

    vaBase += is64bit ? 8 : 4; foBase += is64bit ? 8 : 4;

    printf("%016llX  %08lX  [%c]\t\tSize of Heap  Commit       : %0*llX\n\n",
        vaBase, foBase, is64bit ? '8' : '4',
        is64bit ? 16 : 8, is64bit ? opt64->SizeOfHeapCommit : opt32->SizeOfHeapCommit);

    vaBase += is64bit ? 8 : 4; foBase += is64bit ? 8 : 4;

    printf("%016llX  %08lX  [4]\t\tLoader Flags               : %08lX\n\n",
    vaBase, foBase, is64bit ? opt64->LoaderFlags : opt32->LoaderFlags);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tNumber of RVA and Size     : %08lX\n\n",
    vaBase, foBase, is64bit ? opt64->NumberOfRvaAndSizes : opt32->NumberOfRvaAndSizes);

    vaBase += 4; foBase += 4;

    printf("\n%016llX\t - DATA DIRECTORIES -\n\n",
    vaBase);

    const char* data_directory_names[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = {
        "Export Table            ",  // 0
        "Import Table            ",  // 1
        "Resource Table          ",  // 2
        "Exception Table         ",  // 3
        "Security Table          ",  // 4
        "Base Relocation Table   ",  // 5
        "Debug                   ",  // 6
        "Architecture            ",  // 7
        "Global Pointer          ",  // 8
        "TLS Table               ",  // 9
        "Load Config Table       ",  // 10
        "Bound Import            ",  // 11
        "Import Address Table    ",  // 12
        "Delay Import Descriptor ",  // 13
        "CLR Runtime Header      ",  // 14
        "Reserved                ",  // 15
    };

    PIMAGE_DATA_DIRECTORY dir = is64bit ? opt64->DataDirectory : opt32->DataDirectory;

    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
        if (dir[i].Size != 0 && dir[i].VirtualAddress != 0)  {

            // Security Table and Bound Import exist only at file offsets, not in memory (no VA)
            if (i == 4 || i == 11) {
                printf("%016llX  %08lX  [8]\t\t%s\n", vaBase, foBase, data_directory_names[i]);
            } else {
                RVA_INFO DataDirectoryRvaInfo = get_rva_info(dir[i].VirtualAddress, sections, numberOfSections, imageBase);
                printf("%016llX  %08lX  [8]\t\t%s [VA: %llX] [FO: %lX] [  %-8s]\n",
                vaBase, foBase, data_directory_names[i], DataDirectoryRvaInfo.va, DataDirectoryRvaInfo.fileOffset, DataDirectoryRvaInfo.sectionName);
            }

            printf("%016llX  %08lX  [4]\t\t    Virtual Address         :  %08lX\n",
            vaBase + 4, foBase + 4, dir[i].VirtualAddress);

            printf("%016llX  %08lX  [4]\t\t    Size                    :  %08lX\n\n",
            vaBase + 8, foBase + 8, dir[i].Size);

        } else {
            printf("%016llX  %08lX  [8]\t\t%s\n",
            vaBase, foBase, data_directory_names[i]);             

            printf("%016llX  %08lX  [4]\t\t    Virtual Address         :  %08lX\n",
            vaBase + 4, foBase + 4, dir[i].VirtualAddress);

            printf("%016llX  %08lX  [4]\t\t    Size                    :  %08lX\n\n",
            vaBase + 8, foBase + 8, dir[i].Size);      
        }
        vaBase += 8; foBase += 8;
    }

    fflush(stdout);

    return RET_SUCCESS;
}

RET_CODE dump_nt_headers(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    DWORD foNtHeaders,
    PVOID ntHeader,
    ULONGLONG imageBase,
    int is64bit) {
    
    if (!peFile || !ntHeader) return RET_INVALID_PARAM;

    PIMAGE_NT_HEADERS64 nt64 = NULL;
    PIMAGE_NT_HEADERS32 nt32 = NULL;

    if (is64bit) {
        nt64 = (PIMAGE_NT_HEADERS64)ntHeader;
    } else { 
        nt32 = (PIMAGE_NT_HEADERS32)ntHeader;
    }

    ULONGLONG vaBase = imageBase + foNtHeaders; 

    printf("\n%016llX\t- IMAGE NT HEADERS -\n\n", vaBase);

    printf("VA                FO        Size        Value\n");

    DWORD PEsignature = is64bit ? nt64->Signature : nt32->Signature;

    printf("%016llX  %08lX  [4]\t\tSignature : %08lX  (\"%c%c\")\n\n",
        vaBase, foNtHeaders, PEsignature,
        (char)(PEsignature & 0xFF),          // 'P'
        (char)((PEsignature >> 8) & 0xFF)   // 'E'
    );

    // pick the correct File header
    PVOID fileHeader = is64bit ? (PVOID)&nt64->FileHeader : (PVOID)&nt32->FileHeader;
    DWORD foFileHeader = foNtHeaders + sizeof(DWORD);

    if(dump_file_header(peFile, foFileHeader, fileHeader, imageBase, 0) != RET_SUCCESS) {
        printf("[!] Failed to dump File Header\n");
        return RET_ERROR;
    }

    // pick the correct optional header
    PVOID optHeader = is64bit ? (PVOID)&nt64->OptionalHeader : (PVOID)&nt32->OptionalHeader;

    DWORD foOptHeader = foFileHeader + sizeof(IMAGE_FILE_HEADER);
    if(dump_optional_header(peFile, sections, numberOfSections, foOptHeader, optHeader, imageBase, is64bit, 0) != RET_SUCCESS) {
        printf("[!] Failed to dump Optional Header\n");
        return RET_ERROR;
    }

    fflush(stdout);

    return RET_SUCCESS;
}

RET_CODE print_section_header(
    FILE *peFile,
    DWORD symTableOffset,
    DWORD NumberOfSymbols,
    PIMAGE_SECTION_HEADER sec,
    WORD index,
    ULONGLONG imageBase) {
        
    ULONGLONG vaBase = imageBase + sec->VirtualAddress;
    DWORD     foBase = sec->PointerToRawData;

    printf("\n%016llX  %08lX\t - SECTION: #%u -\n\n",
           vaBase, foBase, index);

    printf("VA                FO        Size        Value\n");

    // --- Handle name ---
    if (sec->Name[0] == '/') {
        DWORD offsetToStringTable = symTableOffset + (DWORD)sizeof(IMAGE_SYMBOL) * NumberOfSymbols;

        char *stringTable = NULL;
        if (parse_string_table(peFile, &stringTable, offsetToStringTable) != RET_SUCCESS) {
            return RET_ERROR;
        }

        DWORD stringTableSize;
        memcpy(&stringTableSize, stringTable, 4);

        char nameBuffer[512] = {0}; 
        DWORD nameOffset = (DWORD)atol((char*)(sec->Name + 1)); 

        WORD nameLen = 0;
        if (nameOffset < stringTableSize) {                
            strncpy(nameBuffer, stringTable + nameOffset, sizeof(nameBuffer) - 1);
            nameBuffer[sizeof(nameBuffer) - 1] = '\0';

            while (nameOffset + nameLen < stringTableSize && stringTable[nameOffset + nameLen] != '\0') {
                nameLen++;
            }
            SAFE_FREE(stringTable);
        } else {
            strcpy(nameBuffer, "<invalid offset>");
        }

        printf("\t\t  %08lX  [%-3lu]\tName                       : %s (%s)\n\n",
               offsetToStringTable + nameOffset, (ULONG)nameLen, sec->Name, nameBuffer);
    } else {
        printf("%016llX  %08lX  [8]\t\tName                       : %s\n\n",
               vaBase, foBase, sec->Name);
    }

    // --- Print fields (rest unchanged) ---
    vaBase += 8; foBase += 8;

    printf("%016llX  %08lX  [4]\t\tVirtual size               : %08lX  (%lu)\n",
           vaBase, foBase, sec->Misc.VirtualSize, (long unsigned) sec->Misc.VirtualSize);

    printf("%016llX  %08lX  [4]\t\t(Relative) Virtual address : %08lX\n\n",
           vaBase, foBase, sec->VirtualAddress);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tSize of raw data           : %08lX  (%lu)\n",
           vaBase, foBase, sec->SizeOfRawData, (long unsigned) sec->SizeOfRawData);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tPointer to raw data        : %08lX\n\n", 
           vaBase, foBase, sec->PointerToRawData);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tPointer to relocations     : %08lX\n", 
           vaBase, foBase, sec->PointerToRelocations);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [4]\t\tPointer to linenumbers     : %08lX\n\n", 
           vaBase, foBase, sec->PointerToLinenumbers);

    vaBase += 4; foBase += 4;

    printf("%016llX  %08lX  [2]\t\tNumber of relocations      : %04X\n", 
           vaBase, foBase, sec->NumberOfRelocations);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [2]\t\tPointer to linenumbers     : %04X\n\n", 
           vaBase, foBase, sec->NumberOfLinenumbers);

    vaBase += 2; foBase += 2;

    printf("%016llX  %08lX  [4]\t\tCharacteristics            : %08lX\n", 
           vaBase, foBase, sec->Characteristics);

    vaBase += 4; foBase += 4;

    FlagDesc section_flags[] = {
        {IMAGE_SCN_TYPE_NO_PAD,             "IMAGE_SCN_TYPE_NO_PAD"},
        {IMAGE_SCN_CNT_CODE,                "IMAGE_SCN_CNT_CODE"},
        {IMAGE_SCN_CNT_INITIALIZED_DATA,    "IMAGE_SCN_CNT_INITIALIZED_DATA"},
        {IMAGE_SCN_CNT_UNINITIALIZED_DATA,  "IMAGE_SCN_CNT_UNINITIALIZED_DATA"},
        {IMAGE_SCN_LNK_INFO,                "IMAGE_SCN_LNK_INFO"},
        {IMAGE_SCN_LNK_REMOVE,              "IMAGE_SCN_LNK_REMOVE"},
        {IMAGE_SCN_LNK_COMDAT,              "IMAGE_SCN_LNK_COMDAT"},
        {IMAGE_SCN_GPREL,                   "IMAGE_SCN_GPREL"},
        {IMAGE_SCN_MEM_PURGEABLE,           "IMAGE_SCN_MEM_PURGEABLE"},
        {IMAGE_SCN_MEM_16BIT,               "IMAGE_SCN_MEM_16BIT"},
        {IMAGE_SCN_MEM_LOCKED,              "IMAGE_SCN_MEM_LOCKED"},
        {IMAGE_SCN_MEM_PRELOAD,             "IMAGE_SCN_MEM_PRELOAD"},
        {IMAGE_SCN_ALIGN_1BYTES,            "IMAGE_SCN_ALIGN_1BYTES"},
        {IMAGE_SCN_ALIGN_2BYTES,            "IMAGE_SCN_ALIGN_2BYTES"},
        {IMAGE_SCN_ALIGN_4BYTES,            "IMAGE_SCN_ALIGN_4BYTES"},
        {IMAGE_SCN_ALIGN_8BYTES,            "IMAGE_SCN_ALIGN_8BYTES"},
        {IMAGE_SCN_ALIGN_16BYTES,           "IMAGE_SCN_ALIGN_16BYTES"},
        {IMAGE_SCN_ALIGN_32BYTES,           "IMAGE_SCN_ALIGN_32BYTES"},
        {IMAGE_SCN_ALIGN_64BYTES,           "IMAGE_SCN_ALIGN_64BYTES"},
        {IMAGE_SCN_ALIGN_128BYTES,          "IMAGE_SCN_ALIGN_128BYTES"},
        {IMAGE_SCN_ALIGN_256BYTES,          "IMAGE_SCN_ALIGN_256BYTES"},
        {IMAGE_SCN_ALIGN_512BYTES,          "IMAGE_SCN_ALIGN_512BYTES"},
        {IMAGE_SCN_ALIGN_1024BYTES,         "IMAGE_SCN_ALIGN_1024BYTES"},
        {IMAGE_SCN_ALIGN_2048BYTES,         "IMAGE_SCN_ALIGN_2048BYTES"},
        {IMAGE_SCN_ALIGN_4096BYTES,         "IMAGE_SCN_ALIGN_4096BYTES"},
        {IMAGE_SCN_ALIGN_8192BYTES,         "IMAGE_SCN_ALIGN_8192BYTES"},
        {IMAGE_SCN_LNK_NRELOC_OVFL,         "IMAGE_SCN_LNK_NRELOC_OVFL"},
        {IMAGE_SCN_MEM_DISCARDABLE,         "IMAGE_SCN_MEM_DISCARDABLE"},
        {IMAGE_SCN_MEM_NOT_CACHED,          "IMAGE_SCN_MEM_NOT_CACHED"},
        {IMAGE_SCN_MEM_WRITE,               "IMAGE_SCN_MEM_WRITE"},
        {IMAGE_SCN_MEM_NOT_PAGED,           "IMAGE_SCN_MEM_NOT_PAGED"},
        {IMAGE_SCN_MEM_SHARED,              "IMAGE_SCN_MEM_SHARED"},
        {IMAGE_SCN_MEM_EXECUTE,             "IMAGE_SCN_MEM_EXECUTE"},
        {IMAGE_SCN_MEM_READ,                "IMAGE_SCN_MEM_READ"}
    };

    DWORD section_characteristics_count = (sizeof(section_flags)/sizeof(FlagDesc));

    for (DWORD i = 0; i < section_characteristics_count; i++) {
        if (sec->Characteristics & section_flags[i].flag) {
            printf("\t\t\t\t\t\t\t\t   + %08lX  %-40s\n",
                    section_flags[i].flag,
                    section_flags[i].name);
        }
    }

    putchar('\n');

    fflush(stdout);
    return RET_SUCCESS;
}

RET_CODE dump_section_headers(
    FILE *peFile,
    DWORD symTableOffset,
    DWORD NumberOfSymbols,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    LONGLONG fileSize,
    ULONGLONG imageBase) {

    if (!peFile || !sections) return RET_INVALID_PARAM;

    printf("\n%016llX  %08lX\tSECTION HEADERS - number of sections : %u\n\n",
        (ULONGLONG) sections[0].VirtualAddress + imageBase,
        sections[0].PointerToRawData,
        numberOfSections);

    for (WORD i = 0; i < numberOfSections; i++) {
        char secName[9] = {0};
        memcpy(secName, sections[i].Name, 8);
        secName[8] = '\0';

        // If raw size is zero, just print a note and skip
        if (sections[i].SizeOfRawData == 0) {
            printf("[!] Section '%s' has zero raw size, skipping dump\n", secName);
            continue;
        }

        // Raw size larger than file size
        if (sections[i].SizeOfRawData > fileSize) {
            REPORT_MALFORMED("Section raw size exceeds file size (invalid or corrupted section)", secName);
            continue;
        }

        // Packed section: VirtualSize=0 but raw data exists (warn only)
        if (sections[i].Misc.VirtualSize == 0 && sections[i].SizeOfRawData > 0) {
            REPORT_MALFORMED("VirtualSize=0 but raw data exists (possible packed section)", secName);
        }

        if (print_section_header(peFile,
                                 symTableOffset,
                                 NumberOfSymbols,
                                 &sections[i],
                                 i + 1,
                                 imageBase) != RET_SUCCESS)
        {
            return RET_ERROR;
        }
    }

    fflush(stdout);
    return RET_SUCCESS;
}
