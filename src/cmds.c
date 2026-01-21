/*
  cmds.c
  Simple argument parsing where the first arg is always the filename.
  Add your dump routines into the handler blocks below.
*/

#include "include/cmds.h"

CommandEntry g_command_table[] = {
    {"--help",             "-h",    CMD_HELP},
    {"--dos-header",       "-dh",   CMD_DOS_HEADER},
    {"--file-header",      "-fh",   CMD_FILE_HEADER},
    {"--optional-header",  "-oh",   CMD_OPTIONAL_HEADER},
    {"--nt-headers",       "-nth",  CMD_NT_HEADERS},
    {"--sections",         "-s",    CMD_SECTIONS},

    {"--exports",          "-e",    CMD_EXPORTS},
    {"--imports",          "-i",    CMD_IMPORTS},
    {"--resources",        "-r",    CMD_RESOURCES},
    {"--exception",        "-ex",   CMD_EXCEPTION},
    {"--security",         "-sec",  CMD_SECURITY},
    {"--basereloc",        "-br",   CMD_BASERELOC},
    {"--debug",            "-d",    CMD_DEBUG},
    {"--tls",              "-tls",  CMD_TLS},
    {"--load-config",      "-lc",   CMD_LOAD_CONFIG},
    {"--bound-import",     "-bi",   CMD_BOUND_IMPORT},
    {"--iat",              "-iat",  CMD_IAT},
    {"--delay-import",     "-di",   CMD_DELAY_IMPORT},
    {"--clr-header",       "-ch",   CMD_CLR_HEADER},
    {"--data-directories", "-dd",   CMD_DATA_DIRECTORIES},

    // CLR family
    // {"--clr-metadata",   "-cm",  CMD_CLR_METADATA},
    // {"--clr-readytorun", "-crr", CMD_CLR_READYTORUN},
    // {"--clr-streams",    "-cs",  CMD_CLR_STREAMS},
    // {"--clr-strings",    "-csg", CMD_CLR_STRINGS},
    // {"--clr-tables",     "-ct",  CMD_CLR_TABLES},
    // {"--clr-all",        "-ca",  CMD_CLR_ALL},

    {"--rich-header",      "-rh",   CMD_RICH},
    {"--version-info",     "-vi",   CMD_VERSION_INFO},
    {"--symbol-table",     "-sym",  CMD_SYMBOL_TABLE},
    {"--string-table",     "-st",   CMD_STRING_TABLE},
    {"--overlay",          "-o",    CMD_OVERLAY},
    {"--overview",         "-ov",   CMD_OVERVIEW},
    {"--all",              "-a",    CMD_ALL},

    {"--va2file",          "-v2f",  CMD_VA2FILE},
    {"--format",           "-f",    CMD_FORMAT},
    {"--temp-format",      "-tf",   CMD_TEMP_FORMAT},
    {"--extract",          "-x",    CMD_EXTRACT},
    {"--strings",          "-s",    CMD_STRINGS},

    {"--hash",             "-H",  CMD_HASH},
    {"--compare-targets",  "-cc", CMD_HASH_COMPARE},

    {NULL,                 NULL,  CMD_UNKNOWN}
};


BOOL isCmdValid(int argc) {
    if (argc < 2) {
        print_help();
        return FALSE;
    }
    return TRUE;
}

BOOL isHelpCmd(const char *arg) {
    if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) return TRUE;
    return FALSE;
}

void init_config(PConfig c) {
    if (!c) return; // safety

    memset(c, 0, sizeof(Config));

    c->command_table = g_command_table; // point to global table

    // default settings
    c->formatConfig.view = VIEW_TABLE;
}

COMMAND parse_command(const char *arg, PConfig c) {
    if (!arg) return CMD_UNKNOWN;

    for (int i = 0; c->command_table[i].name; i++) {
        if (strcmp(arg, c->command_table[i].name) == 0 ||
            strcmp(arg, c->command_table[i].alias) == 0) {
            return c->command_table[i].cmd;
        }
    }
    return CMD_UNKNOWN;
}

ULONGLONG convert_to_hex(const char *s) {
    if (!s || !*s) return 0;

    size_t len = strlen(s);

    // check 0x/0X prefix
    if (len > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        return strtoull(s + 2, NULL, 16);
    }

    // check trailing h/H
    if (s[len - 1] == 'h' || s[len - 1] == 'H') {
        char buf[64];
        if (len - 1 >= sizeof(buf)) return 0; // prevent overflow
        memcpy(buf, s, len - 1);
        buf[len - 1] = '\0';
        return strtoull(buf, NULL, 16);
    }

    // default: interpret directly as hex
    return strtoull(s, NULL, 16);
}

RET_CODE va_to_fileOff_cmd(
    ULONGLONG VA,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    ULONGLONG imageBase) {
    if (VA < imageBase) {
        fprintf(stderr,
            "[!] Invalid VA: 0x%016llX (ImageBase=0x%016llX)\n",
            VA, imageBase);
        return RET_INVALID_PARAM;
    }

    DWORD rva = (DWORD)(VA - imageBase);
    DWORD fo = 0;
    int status = rva_to_offset(rva, sections, numberOfSections, &fo);

    if (status == RET_SUCCESS) {
        RVA_INFO rvaInfo = get_rva_info(rva, sections, numberOfSections, imageBase);

        printf("\n=== VA -> File Offset ===\n");
        printf("VA  :  0x%016llX\n", VA);
        printf("RVA :  0x%08lX\n", rva);
        printf("FO  :  0x%08lX\n", fo);

        if (rvaInfo.sectionName[0] != '\0') {
            printf("Sec :  %s (Index %d)\n",
                   rvaInfo.sectionName, rvaInfo.sectionIndex);
        }

        printf("\n");
    }
    else if (status == RET_NO_VALUE) {
        printf("\n[*] RVA not found in any section, using direct RVA as FO.\n");
        printf("=== VA -> File Offset ===\n");
        printf("VA  :  0x%016llX\n", VA);
        printf("RVA :  0x%08lX\n", rva);
        printf("FO  :  0x%08lX\n\n", rva);
        status = RET_SUCCESS;
    }
    else {
        fprintf(stderr, "[!] Failed to resolve VA 0x%016llX\n", VA);
    }

    return status;
}

LONG parseNumber(const char *s, int *isLine) {
    char buf[128];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    int hex = 0;

    // 0x prefix
    if (buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X')) {
        hex = 1;
        memmove(buf, buf + 2, strlen(buf + 2) + 1);
    }

    // trailing h/H
    size_t len = strlen(buf);
    if (!hex && len > 0 && (buf[len - 1] == 'h' || buf[len - 1] == 'H')) {
        hex = 1;
        buf[len - 1] = '\0';
    }

    LONG val = (LONG)strtol(buf, NULL, hex ? 16 : 10);

    if (hex) {
        *isLine = 0;
        // round up to nearest line
        return val;
        // return (val + bytesPerLine - 1) / bytesPerLine;
    } else {
        *isLine = 1;
        return val;
    }
}

RET_CODE parse_format_arg(const char *arg, BOOL isTmp, PConfig c) {
    FormatConfig formatCfg = {0};
    formatCfg.view = VIEW_TABLE;
    formatCfg.startLine = 0;
    formatCfg.maxLine = 0;
    formatCfg.startIsLine = 0;
    formatCfg.endIsLine = 0;

    if (!arg) {
        c->formatConfig = formatCfg;
        return RET_INVALID_PARAM;
    }

    if (isTmp) formatCfg.isTmp = 1;

    char buf[64];
    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    strToLower(buf, strlen(buf));

    char *sep = strchr(buf, ':');
    if (sep) {
        *sep = '\0';
        char *rangeStr = sep + 1;

        char *comma = strchr(rangeStr, ',');
        if (comma) {
            *comma = '\0';
            char *startStr = rangeStr;
            char *endStr   = comma + 1;

            formatCfg.startLine = parseNumber(startStr, &formatCfg.startIsLine);
            formatCfg.maxLine   = parseNumber(endStr, &formatCfg.endIsLine);
        } else {
            // single value
            formatCfg.startLine = parseNumber(rangeStr, &formatCfg.startIsLine);
            formatCfg.endIsLine = formatCfg.startIsLine;
            formatCfg.maxLine = (formatCfg.startIsLine) ? 0 : formatCfg.startLine; // 0 = full for lines
        }
    }

    // select view mode
    if (strcmp(buf, "table") == 0)      formatCfg.view = VIEW_TABLE;
    else if (strcmp(buf, "hex") == 0)   formatCfg.view = VIEW_HEX;
    else if (strcmp(buf, "dec") == 0)   formatCfg.view = VIEW_DEC;
    else if (strcmp(buf, "bin") == 0)   formatCfg.view = VIEW_BIN;
    else                                formatCfg.view = VIEW_TABLE;

    c->formatConfig = formatCfg;
    return RET_SUCCESS;
}


RET_CODE handle_section_extract(char *val, PSectionExtract section) {
    if (!val || !section) return RET_INVALID_PARAM;

    // Reset section config flags
    memset(section, 0, sizeof(*section));

    if (*val == '/' || *val == '.') {
        strncpy(section->name, val, sizeof(section->name) - 1);
        section->useName = 1;
    }
    else if (*val == '#') {
        section->index  = (WORD)convert_to_hex(val + 1);
        section->useIdx = 1;
    }
    else if (strncmp(val, "rva", 3) == 0) {
        char *cmd = strchr(val, '/');
        if (!cmd) return RET_INVALID_PARAM;
        *cmd++ = '\0';
        section->addr.rva = (DWORD)convert_to_hex(cmd);
        section->useRva   = 1;
    }
    else if (strncmp(val, "fo", 2) == 0) {
        char *cmd = strchr(val, '/');
        if (!cmd) return RET_INVALID_PARAM;
        *cmd++ = '\0';
        section->addr.fo = (DWORD)convert_to_hex(cmd);
        section->useFo   = 1;
    }
    else {
        return RET_INVALID_PARAM;
    }

    return RET_SUCCESS;
}

RET_CODE handle_export_extract(char *val, PExportExtract exp) {
    if (!val || !exp) return RET_INVALID_PARAM;

    memset(exp, 0, sizeof(*exp));

    if (*val == '#') {
        exp->ordinal     = (WORD)convert_to_hex(val + 1);
        exp->useOrdinal  = 1;
    }
    else if (strncmp(val, "rva/", 4) == 0) {
        exp->rva     = (DWORD)convert_to_hex(val + 4);
        exp->useRva  = 1;
    }
    else {
        size_t len = strlen(val);

        if (len >= 4 && STREQI(val + len - 4, ".dll") == 0) {
            strncpy(exp->dllName, val, sizeof(exp->dllName) - 1);
            exp->useDll = 1;
            return RET_SUCCESS;
        }

        if (strchr(val, '.')) {
            strncpy(exp->forwarderName, val, sizeof(exp->forwarderName) - 1);
            exp->useForwarder = 1;
            return RET_SUCCESS;
        }

        strncpy(exp->funcName, val, sizeof(exp->funcName) - 1);
        exp->useName = 1;
        return RET_SUCCESS;
    }

    return RET_SUCCESS;
}

RET_CODE handle_import_extract(char *val, PImportExtract imp) {
    if (!val || !imp) return RET_INVALID_PARAM;

    memset(imp, 0, sizeof(*imp));

    char *slash = strchr(val, '/');
    size_t len = strlen(val);

    if (slash) {
        *slash++ = '\0';
        strncpy(imp->dllName, val, sizeof(imp->dllName) - 1);
        imp->isGlobal = 0;
    }
    else {
        if (len >= 4 && STREQI(val + len - 4, ".dll") == 0) {
            strncpy(imp->dllName, val, sizeof(imp->dllName) - 1);
            imp->useDll   = 1;
            imp->isGlobal = 0;
            return RET_SUCCESS;
        }
        imp->dllName[0] = '\0';
        imp->isGlobal   = 1;
    }

    if (!slash || *slash == '\0') return RET_INVALID_PARAM;

    if (*slash == '#') {
        imp->ordinal    = (WORD)convert_to_hex(slash + 1);
        imp->useOrdinal = 1;
    }
    else if (*slash == '@') {
        imp->hint      = (WORD)convert_to_hex(slash + 1);
        imp->useHint   = 1;
    }
    else {
        strncpy(imp->funcName, slash, sizeof(imp->funcName) - 1);
        imp->useName = 1;
    }

    return RET_SUCCESS;
}

RET_CODE parse_extract_arg(const char *arg, PConfig c) {
    int ret = RET_INVALID_PARAM;

    ExtractConfig extractConfig = {0};

    if (!arg) {
        c->extractConfig = extractConfig;
        return ret;
    }

    ViewMode format = c->formatConfig.view;

    // Determine dump format
    if (format == VIEW_HEX)      extractConfig.DumpFlags.dumpHex = 1;
    else if (format == VIEW_DEC) extractConfig.DumpFlags.dumpDec = 1;
    else if (format == VIEW_BIN) extractConfig.DumpFlags.dumpBin = 1;
    else                         extractConfig.DumpFlags.dumpHex = 1; // default

    // Copy arg safely
    char buf[564];
    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    if (strncmp(buf, "section:", 8) == 0) {
        extractConfig.kind = EXTRACT_SECTION;
        ret = handle_section_extract(buf + 8, &extractConfig.section);
    }
    else if (strncmp(buf, "export:", 7) == 0) {
        extractConfig.kind = EXTRACT_EXPORT;
        ret = handle_export_extract(buf + 7, &extractConfig.export);
    }
    else if (strncmp(buf, "import:", 7) == 0) {
        extractConfig.kind = EXTRACT_IMPORT;
        ret = handle_import_extract(buf + 7, &extractConfig.import);
    }

    if (ret != RET_SUCCESS)
        return ret;

    c->extractConfig = extractConfig;
    return RET_SUCCESS;
}


RET_CODE parse_range_arg(const char *arg, PULONGLONG rangeStart, PULONGLONG rangeEnd) {
    if (!arg || !rangeStart || !rangeEnd)
        return RET_INVALID_PARAM;

    const char *dash = strchr(arg, '-');
    if (!dash) {
        fprintf(stderr, "[!!!] Invalid range format (expected start-end)\n");
        return RET_INVALID_PARAM;
    }

    // Split temporarily
    char startStr[32] = {0};
    char endStr[32] = {0};

    ULONGLONG startLen = (ULONGLONG)(dash - arg);
    ULONGLONG endLen = strlen(dash + 1);

    // Basic sanity check
    if (startLen == 0 || endLen == 0 ||
        startLen >= sizeof(startStr) || endLen >= sizeof(endStr)) {
        fprintf(stderr, "[!!!] Invalid range format length\n");
        return RET_INVALID_PARAM;
    }

    memcpy(startStr, arg, startLen);
    memcpy(endStr, dash + 1, endLen);

    *rangeStart = convert_to_hex(startStr);
    *rangeEnd   = convert_to_hex(endStr);

    return RET_SUCCESS;
}

RET_CODE parse_hash_config(const char *arg, HashConfig *hc) {
    if (!hc)
        return RET_INVALID_PARAM;

    RET_CODE ret = RET_SUCCESS;
    memset(hc, 0, sizeof(HashConfig));

    if (!arg || !*arg)
        return RET_INVALID_PARAM;

    // Copy arg safely
    char buf[564];
    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    // Parse algorithm after '@'
    char *alg = strchr(buf, '@');
    if (alg) {
        *alg++ = '\0';

        if (strncmp(alg, "sha1", 4) == 0)
            hc->algorithm = ALG_SHA1;
        else if (strncmp(alg, "sha224", 6) == 0)
            hc->algorithm = ALG_SHA224;
        else if (strncmp(alg, "sha256", 6) == 0)
            hc->algorithm = ALG_SHA256;
        else if (strncmp(alg, "sha384", 6) == 0)
            hc->algorithm = ALG_SHA384;
        else if (strncmp(alg, "sha512_224", 10) == 0)
            hc->algorithm = ALG_SHA512_224;
        else if (strncmp(alg, "sha512_256", 10) == 0)
            hc->algorithm = ALG_SHA512_256;
        else if (strncmp(alg, "sha512", 6) == 0)
            hc->algorithm = ALG_SHA512;
        else
            hc->algorithm = ALG_MD5; // default
    } else {
        hc->algorithm = ALG_MD5;
    }

    // Detect comparison (::)
    char *split = strstr(buf, "::");
    if (split) {
        *split = '\0';
        split += 2;
        hc->mode = HASHCMD_COMPARE_TARGETS;

        // Parse secondary target
        if (strncmp(split, "richheader", 10) == 0) {
            hc->secondaryTarget.type = TARGET_RICH_HEADER;
        } else if (strncmp(split, "section:", 8) == 0) {
            hc->secondaryTarget.type = TARGET_SECTION;
            ret = handle_section_extract(split + 8, &hc->secondaryTarget.section);
        } else if (strncmp(split, "range:", 6) == 0) {
            hc->secondaryTarget.type = TARGET_RANGE;
            ret = parse_range_arg(split + 6, &hc->secondaryTarget.rangeStart, &hc->secondaryTarget.rangeEnd);
        } else {
            hc->secondaryTarget.type = TARGET_FILE;
        }

        if (ret != RET_SUCCESS)
            return ret;
    } else {
        hc->mode = HASHCMD_HASH_TARGET;
    }

    // Parse primary target
    if (strncmp(buf, "richheader", 10) == 0) {
        hc->primaryTarget.type = TARGET_RICH_HEADER;
    } else if (strncmp(buf, "section:", 8) == 0) {
        hc->primaryTarget.type = TARGET_SECTION;
        ret = handle_section_extract(buf + 8, &hc->primaryTarget.section);
    } else if (strncmp(buf, "range:", 6) == 0) {
        hc->primaryTarget.type = TARGET_RANGE;
        ret = parse_range_arg(buf + 6, &hc->primaryTarget.rangeStart, &hc->primaryTarget.rangeEnd);
    } else {
        hc->primaryTarget.type = TARGET_FILE;
    }

    return ret;
}

RET_CODE parse_hash_targets(
    const char *fileName1,
    const char *fileName2,
    PPEContext  peCtx1,
    PPEContext  peCtx2,
    PHashConfig hc) {

    RET_CODE ret = RET_INVALID_PARAM;

    if (!hc || (!fileName1 && !fileName2))
        return ret;

    FILE *peFile1 = NULL;
    FILE *peFile2 = NULL;
    PPEContext pPeCtx1 = NULL;
    PPEContext pPeCtx2 = NULL;

    // Handle first file
    if (fileName1) {
        // If only one file but not in single-hash mode, switch to internal compare
        if (hc->mode != HASHCMD_HASH_TARGET && !fileName2)
                hc->mode = HASHCMD_COMPARE_INTERNAL;

        if (peCtx1) {
            pPeCtx1 = peCtx1;
            ret = RET_SUCCESS;
        } else {
            ret = loadPEContext(fileName1, &pPeCtx1, &peFile1);
            if (ret != RET_SUCCESS)
                goto cleanup;
        }
    }

    // Handle second file
    if (fileName2) {
        if (hc->mode != HASHCMD_COMPARE_TARGETS)
                hc->mode = HASHCMD_COMPARE_TARGETS;

        if (peCtx2) {
            pPeCtx2 = peCtx2;
            ret = RET_SUCCESS;
        } else {
            ret = loadPEContext(fileName2, &pPeCtx2, &peFile2);
            if (ret != RET_SUCCESS)
                goto cleanup;
        }
    }

    // Assign loaded contexts
    hc->primaryCtx   = pPeCtx1;
    hc->secondaryCtx = pPeCtx2;

    return RET_SUCCESS;

cleanup:
    // Only clean up non-main resources (first file)
    if (hc->mode == HASHCMD_COMPARE_TARGETS && peFile1) {
        freePEContext(pPeCtx1);
        fclose(peFile1);
    }
    return ret;
}


RET_CODE handle_commands(int argc, char **argv, PPEContext peCtx) {
    if (!peCtx || !peCtx->valid) {
        fprintf(stderr, "[!] Invalid or uninitialized PE context\n");
        return RET_INVALID_PARAM;
    }

    // --- Initialize configuration ---
    Config config;
    init_config(&config);

    // --- Use values directly from context ---
    BOOL is64bit = peCtx->is64Bit;
    PIMAGE_DOS_HEADER dosHeader = peCtx->dosHeader;
    PIMAGE_NT_HEADERS32 nt32 = peCtx->nt32;
    PIMAGE_NT_HEADERS64 nt64 = peCtx->nt64;

    LONGLONG fileSize = peCtx->fileSize;
    ULONGLONG imageBase = peCtx->imageBase;
    WORD numberOfSections = peCtx->numberOfSections;

    // --- Use values from inside context ---
    DWORD PointerToSymbolTable = is64bit ? nt64->FileHeader.PointerToSymbolTable : nt32->FileHeader.PointerToSymbolTable;
    DWORD NumberOfSymbols      = is64bit ? nt64->FileHeader.NumberOfSymbols      : nt32->FileHeader.NumberOfSymbols;
    WORD machine               = is64bit ? nt64->FileHeader.Machine              : nt32->FileHeader.Machine;

    // --- Offsets (relative to file start) ---
    DWORD foNtHeaders  = (DWORD)dosHeader->e_lfanew;
    DWORD foFileHeader = foNtHeaders  + sizeof(DWORD); // PE signature
    DWORD foOptHeader  = foFileHeader + sizeof(IMAGE_FILE_HEADER);
    DWORD foSecHeaders = foOptHeader  +
        (DWORD)(is64bit ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32));

    // --- Pointers (in-memory views) ---
    PIMAGE_FILE_HEADER fileHeader = is64bit
        ? (PIMAGE_FILE_HEADER)&nt64->FileHeader
        : (PIMAGE_FILE_HEADER)&nt32->FileHeader;

    PVOID optHeader = peCtx->is64Bit
        ? (PVOID)&nt64->OptionalHeader
        : (PVOID)&nt32->OptionalHeader;

    PVOID ntHeaders = peCtx->is64Bit ? (PVOID)nt64 : (PVOID)nt32;

    // --- Data Directories ---
    PIMAGE_DATA_DIRECTORY dataDirs = is64bit
        ? nt64->OptionalHeader.DataDirectory
        : nt32->OptionalHeader.DataDirectory;

    PIMAGE_DATA_DIRECTORY pExportDataDir      = &dataDirs[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_DATA_DIRECTORY pImportDataDir      = &dataDirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_DATA_DIRECTORY pRsrcDataDir        = &dataDirs[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    PIMAGE_DATA_DIRECTORY pExceptionDataDir   = &dataDirs[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    PIMAGE_DATA_DIRECTORY pSecurityDataDir    = &dataDirs[IMAGE_DIRECTORY_ENTRY_SECURITY];
    PIMAGE_DATA_DIRECTORY pRelocDataDir       = &dataDirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    PIMAGE_DATA_DIRECTORY pDebugDataDir       = &dataDirs[IMAGE_DIRECTORY_ENTRY_DEBUG];
    PIMAGE_DATA_DIRECTORY pTlsDataDir         = &dataDirs[IMAGE_DIRECTORY_ENTRY_TLS];
    PIMAGE_DATA_DIRECTORY pLcfgDataDir        = &dataDirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    PIMAGE_DATA_DIRECTORY pBoundImportDataDir = &dataDirs[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    PIMAGE_DATA_DIRECTORY pIatDataDir         = &dataDirs[IMAGE_DIRECTORY_ENTRY_IAT];
    PIMAGE_DATA_DIRECTORY pDelayImportDataDir = &dataDirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    PIMAGE_DATA_DIRECTORY pClrHeaderDataDir   = &dataDirs[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];

    // --- File Section List ---
    PFileSectionList file_section_list = malloc(sizeof(FileSectionList));
    if (!file_section_list) {
        fprintf(stderr, "[!] Failed to allocate memory for FileSectionList\n");
        return RET_ERROR;
    }

    // Fill section information manually (using already parsed context)
    fill_pe_sections_manual(peCtx, file_section_list);

    // A helper flag indicating that the next argument should trigger a reset
    // of the temporary format configuration.
    BOOL resetNextArg = FALSE;

    FormatConfig tempFormatConfig = {0};

    RET_CODE status = RET_SUCCESS;

   // iterate over arguments
    for (int i = 1; i < argc - 1; i++) {
        if (argv[i] == NULL) break;

        if (resetNextArg) {
            resetNextArg = FALSE;
            config.formatConfig = tempFormatConfig;
        }

        // If the current argument is a temporary format, set the flag
        if (config.formatConfig.isTmp) {
            resetNextArg = TRUE;
        }

        COMMAND command = parse_command(argv[i], &config);

        
        switch (command) {
            case CMD_UNKNOWN:
                fprintf(stderr, "Error: Invalid command '%s'. Try --help for a list of valid commands.\n", argv[i]);
                break;

            case CMD_HELP:
                print_help();
                break;

            case CMD_DOS_HEADER:
                if (config.formatConfig.view == VIEW_TABLE) {
                    if (dump_dos_header(dosHeader, imageBase) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump Dos Header\n");
                    }
                } else {
                    if (print_range(peCtx->fileHandle, 0, sizeof(IMAGE_DOS_HEADER), fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump Dos Header\n");
                    }
                }
                break;

            case CMD_FILE_HEADER:
                if (config.formatConfig.view == VIEW_TABLE) {
                    if (dump_file_header(peCtx->fileHandle, foFileHeader, fileHeader, imageBase, 1) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump File Header\n");
                    }
                } else {
                    if (print_range(peCtx->fileHandle, foFileHeader, sizeof(IMAGE_FILE_HEADER), fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump File Header\n");
                    }                      
                }
                break;

            case CMD_OPTIONAL_HEADER:
                if (config.formatConfig.view == VIEW_TABLE) {
                    if (dump_optional_header(peCtx->fileHandle, peCtx->sections, numberOfSections, foOptHeader, optHeader, imageBase, is64bit, 1) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump Optional Header\n");
                    }
                } else {
                    if (print_range(peCtx->fileHandle, foOptHeader, is64bit ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32), fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump Optional Header\n");
                    }
                }
                break;

            case CMD_NT_HEADERS:
                if (config.formatConfig.view == VIEW_TABLE) {
                    if (dump_nt_headers(peCtx->fileHandle, peCtx->sections, numberOfSections, foNtHeaders, ntHeaders, imageBase, is64bit) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump NT Headers\n");
                    }
                } else {
                    if (print_range(peCtx->fileHandle, foNtHeaders, is64bit ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32), fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump NT Headers\n");
                    }
                }
                break;

            case CMD_SECTIONS:
                if (config.formatConfig.view == VIEW_TABLE) {
                    if (dump_section_headers(peCtx->fileHandle, PointerToSymbolTable, NumberOfSymbols, peCtx->sections, numberOfSections, fileSize, imageBase) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump Section Headers\n");
                    }
                } else {
                    if (print_range(peCtx->fileHandle, foSecHeaders, sizeof(IMAGE_SECTION_HEADER) * numberOfSections, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump Section Headers\n");
                    }
                }
                break;

            case CMD_EXPORTS:
                if (pExportDataDir->VirtualAddress) {
                    DWORD fo = 0;
                    status = rva_to_offset(pExportDataDir->VirtualAddress, peCtx->sections, numberOfSections, &fo);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to convert Export Directory RVA to file offset\n");
                        break;
                    }

                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_export_dir(peCtx->fileHandle, peCtx->sections, numberOfSections, pExportDataDir, peCtx->dirs->exportDir, imageBase) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Export Directory\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, fo, pExportDataDir->Size, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Export Directory\n");
                        }
                    }
                }
                break;

            case CMD_IMPORTS:
                if (pImportDataDir->VirtualAddress) {
                    DWORD fo = 0;
                    status = rva_to_offset(pImportDataDir->VirtualAddress, peCtx->sections, numberOfSections, &fo);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to convert Import Directory RVA to file offset\n");
                        break;
                    }

                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_import_dir(peCtx->fileHandle, peCtx->sections, numberOfSections, pImportDataDir, peCtx->dirs->importDir, imageBase, is64bit, fileSize) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Import Directory\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, fo, pImportDataDir->Size, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Import Directory\n");
                        }
                    }
                }
                break;

            case CMD_RESOURCES:
                if (pRsrcDataDir->VirtualAddress) {
                    DWORD fo = 0;
                    status = rva_to_offset(pRsrcDataDir->VirtualAddress, peCtx->sections, numberOfSections, &fo);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to convert Resource Directory RVA to file offset\n");
                        break;
                    }

                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_rsrc_dir(peCtx->fileHandle, peCtx->sections, numberOfSections, pRsrcDataDir, peCtx->dirs->rsrcDir, peCtx->dirs->rsrcEntriesDir, imageBase) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Resource Directory\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, fo, pRsrcDataDir->Size, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Resource Directory\n");
                        }
                    }
                }
                break;

            case CMD_EXCEPTION:
                if (pExceptionDataDir->VirtualAddress) {
                    DWORD fo = 0;
                    status = rva_to_offset(pExceptionDataDir->VirtualAddress, peCtx->sections, numberOfSections, &fo);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to convert Exception Directory RVA to file offset\n");
                        break;
                    }

                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_exception_dir(peCtx->fileHandle, peCtx->sections, numberOfSections, pExceptionDataDir, machine, imageBase) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Exception Directory\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, fo, pExceptionDataDir->Size, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Exception Directory\n");
                        }
                    }
                }
                break;

            case CMD_SECURITY:
                if (pSecurityDataDir->VirtualAddress) {
                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_security_dir(peCtx->fileHandle, pSecurityDataDir) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Security Directory\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, pSecurityDataDir->VirtualAddress, pSecurityDataDir->Size, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Security Directory\n");
                        }
                    }
                }
                break;

            case CMD_BASERELOC:
                if (pRelocDataDir->VirtualAddress) {
                    DWORD fo = 0;
                    status = rva_to_offset(pRelocDataDir->VirtualAddress, peCtx->sections, numberOfSections, &fo);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to convert Base Relocation Directory RVA to file offset\n");
                        break;
                    }

                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_reloc_dir(peCtx->fileHandle, peCtx->sections, numberOfSections, pRelocDataDir, imageBase) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Base Relocation Directory\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, fo, pRelocDataDir->Size, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Base Relocation Directory\n");
                        }
                    }
                }
                break;

            case CMD_DEBUG:
                if (pDebugDataDir->VirtualAddress) {
                    DWORD fo = 0;
                    status = rva_to_offset(pDebugDataDir->VirtualAddress, peCtx->sections, numberOfSections, &fo);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to convert Debug Directory RVA to file offset\n");
                        break;
                    }

                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_debug_dir(peCtx->fileHandle, peCtx->sections, numberOfSections, pDebugDataDir, peCtx->dirs->debugDir, machine, imageBase, is64bit) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Debug Directory\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, fo, pDebugDataDir->Size, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Debug Directory\n");
                        }
                    }
                }
                break;

            case CMD_TLS:
                if (pTlsDataDir->VirtualAddress) {
                    DWORD fo = 0;
                    status = rva_to_offset(pTlsDataDir->VirtualAddress, peCtx->sections, numberOfSections, &fo);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to convert TLS Directory RVA to file offset\n");
                        break;
                    }

                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_tls_dir(peCtx->fileHandle, peCtx->sections, numberOfSections, pTlsDataDir, peCtx->dirs->tls64, peCtx->dirs->tls32, imageBase, is64bit) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump TLS Directory\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, fo, pTlsDataDir->Size, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump TLS Directory\n");
                        }
                    }
                }
                break;

            case CMD_LOAD_CONFIG:
                if (pLcfgDataDir->VirtualAddress) {
                    DWORD fo = 0;
                    status = rva_to_offset(pLcfgDataDir->VirtualAddress, peCtx->sections, numberOfSections, &fo);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to convert Load Config Directory RVA to file offset\n");
                        break;
                    }

                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_load_config_dir(peCtx->fileHandle, peCtx->sections, numberOfSections, pLcfgDataDir, peCtx->dirs->loadConfig64, peCtx->dirs->loadConfig32, imageBase, is64bit) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Load Config Directory\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, fo, pLcfgDataDir->Size, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Load Config Directory\n");
                        }
                    }
                }
                break;

            case CMD_BOUND_IMPORT:
                if (pBoundImportDataDir->VirtualAddress) {
                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_bound_import_dir(peCtx->fileHandle, peCtx->sections, numberOfSections, pBoundImportDataDir, imageBase) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Bound Import Directory\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, pBoundImportDataDir->VirtualAddress, pBoundImportDataDir->Size, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Bound Import Directory\n");
                        }
                    }
                }
                break;

            case CMD_IAT:
                if (pIatDataDir->VirtualAddress) {
                    DWORD fo = 0;
                    status = rva_to_offset(pIatDataDir->VirtualAddress, peCtx->sections, numberOfSections, &fo);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to convert IAT Directory RVA to file offset\n");
                        break;
                    }

                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_iat_table(peCtx->fileHandle, peCtx->sections, numberOfSections, pIatDataDir->VirtualAddress, imageBase, is64bit, fileSize) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump IAT Directory\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, fo, pIatDataDir->Size, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump IAT Directory\n");
                        }
                    }
                }
                break;

            case CMD_DELAY_IMPORT:
                if (pDelayImportDataDir->VirtualAddress) {
                    DWORD fo = 0;
                    status = rva_to_offset(pDelayImportDataDir->VirtualAddress, peCtx->sections, numberOfSections, &fo);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to convert Delay Import Directory RVA to file offset\n");
                        break;
                    }

                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_delay_import_dir(peCtx->fileHandle, peCtx->sections, numberOfSections, pDelayImportDataDir, peCtx->dirs->delayImportDir, imageBase, is64bit, fileSize) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Delay Import Directory\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, fo, pDelayImportDataDir->Size, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Delay Import Directory\n");
                        }
                    }
                }
                break;

            case CMD_CLR_HEADER:
                if (pClrHeaderDataDir->VirtualAddress) {
                    DWORD fo = 0;
                    status = rva_to_offset(pClrHeaderDataDir->VirtualAddress, peCtx->sections, numberOfSections, &fo);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to convert CLR/.NET Header Directory RVA to file offset\n");
                        break;
                    }

                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_clr_header_dir(peCtx->fileHandle, peCtx->sections, numberOfSections, pClrHeaderDataDir, peCtx->dirs->clrHeader, imageBase) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump CLR/.NET Header Directory\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, fo, pClrHeaderDataDir->Size, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump CLR/.NET Header Directory\n");
                        }
                    }
                }
                break;

            case CMD_DATA_DIRECTORIES:
                if (config.formatConfig.view == VIEW_TABLE) {
                    status = dump_all_data_directories(peCtx->fileHandle, peCtx->sections, numberOfSections, dataDirs, peCtx->dirs, imageBase, is64bit, fileSize, machine);
                } else {
                    status = dump_all_data_directories_raw(peCtx->fileHandle, peCtx->sections, numberOfSections, dataDirs, fileSize, &config.formatConfig, file_section_list);
                }
                if (status != RET_SUCCESS) {
                    if (status == RET_ERROR) {
                        fprintf(stderr, "[!] Failed to dump Data Directories\n");    
                    }
                }
                break;

            //
            // to be continued
            //

            // case CMD_CLR_METADATA:
            //     break;
            // case CMD_CLR_READYTORUN:
            //     break;
            // case CMD_CLR_STREAMS:
            //     break;
            // case CMD_CLR_STRINGS:
            //     break;
            // case CMD_CLR_TABLES:
            //     break;
            // case CMD_CLR_ALL:
            //     // handle CLR family
            //     break;

            case CMD_RICH:
                if (peCtx->richHeader) {
                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_rich_header(peCtx->fileHandle, peCtx->richHeader) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Rich Header\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, peCtx->richHeader->richHdrOff, peCtx->richHeader->richHdrSize, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Rich Header\n");
                        }
                    }
                }
                break;

            case CMD_VERSION_INFO:
                if (pRsrcDataDir->VirtualAddress) {
                    DWORD versionInfoRva = 0, versionInfoSize = 0;

                    status = extract_version_resource(
                        peCtx->fileHandle, peCtx->sections, numberOfSections, pRsrcDataDir,
                        peCtx->dirs->rsrcDir, peCtx->dirs->rsrcEntriesDir, &versionInfoRva, &versionInfoSize);
                    
                    if (status != RET_SUCCESS) {
                        fprintf(stderr,"[!] Version Info was not found\n");
                        break;
                    }

                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_version_info(peCtx->fileHandle, peCtx->sections, numberOfSections, versionInfoRva, versionInfoSize, imageBase) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Version Info\n");
                        }
                    } else {
                        DWORD versionInfoFO = 0;

                        status = rva_to_offset(versionInfoRva, peCtx->sections, numberOfSections, &versionInfoFO);
                        if (status != RET_SUCCESS) {
                            break;
                        }

                        if (print_range(peCtx->fileHandle, versionInfoFO, versionInfoSize, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Version Info\n");
                        }
                    }
                }
                break;

            case CMD_SYMBOL_TABLE:
                if (PointerToSymbolTable && NumberOfSymbols) {
                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_symbol_table(peCtx->fileHandle, PointerToSymbolTable, NumberOfSymbols, peCtx->sections, numberOfSections) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump COFF Symbol Table\n");
                        }
                    } else {
                        DWORD symbolTableSize = NumberOfSymbols * IMAGE_SIZEOF_SYMBOL;

                        if (print_range(peCtx->fileHandle, PointerToSymbolTable, symbolTableSize, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump COFF Symbol Table\n");
                        }
                    }
                }
                break;

            case CMD_STRING_TABLE:
                if (PointerToSymbolTable && NumberOfSymbols) {
                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_string_table(peCtx->fileHandle, PointerToSymbolTable, NumberOfSymbols) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump COFF String Table\n");    
                        }
                    } else {
                        DWORD stringTableOffset = (DWORD)(PointerToSymbolTable + sizeof(IMAGE_SYMBOL) * NumberOfSymbols);
                        DWORD stringTableSize;

                        // Calculate offset to string table
                        status = get_string_table_size(peCtx->fileHandle, stringTableOffset, fileSize, &stringTableSize);
                        if (status != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to get the size of COFF String Table\n");
                            break;
                        }

                        if (print_range(peCtx->fileHandle, stringTableOffset, stringTableSize, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump COFF String Table\n");
                        }
                    }
                }
                break;

            case CMD_OVERLAY:
                DWORD overlayFo, overlaySize;

                getOverlayInfo(peCtx->sections, numberOfSections, fileSize, &overlayFo, &overlaySize);
                
                if (overlayFo != 0 && overlaySize != 0) {
                    if (print_range(peCtx->fileHandle, overlayFo, overlaySize, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump Overlay\n");
                    }
                }
                break;

            case CMD_OVERVIEW:
                if (dump_pe_overview(peCtx) != RET_SUCCESS) {
                    fprintf(stderr, "[!] Failed to dump PE Over View info\n");   
                }
                break;

            case CMD_ALL: // NOT FINSHED
                // Dump PE Overview
                if (dump_pe_overview(peCtx) != RET_SUCCESS) {
                    fprintf(stderr, "[!] Failed to dump PE Overview\n");
                }

                if (config.formatConfig.view == VIEW_TABLE) {
                    // Dump DOS Header
                    if (dump_dos_header(dosHeader, imageBase) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump Dos Header\n");
                    }

                    // Dump File Header
                    if (dump_file_header(peCtx->fileHandle, foFileHeader, fileHeader, imageBase, 1) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump File Header\n");
                    }

                    // Dump Optional Header
                    if (dump_optional_header(peCtx->fileHandle, peCtx->sections, numberOfSections, foOptHeader, optHeader, imageBase, is64bit, 1) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump Optional Header\n");
                    }

                    // Dump NT Headers
                    if (dump_nt_headers(peCtx->fileHandle, peCtx->sections, numberOfSections, foNtHeaders, ntHeaders, imageBase, is64bit) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump NT Headers\n");
                    }

                    // Dump Section Headers
                    if (dump_section_headers(peCtx->fileHandle, PointerToSymbolTable, NumberOfSymbols, peCtx->sections, numberOfSections, fileSize, imageBase) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump Section Headers\n");
                    }

                    // Dump Data Directories
                    if (dump_all_data_directories(peCtx->fileHandle, peCtx->sections, numberOfSections, dataDirs, peCtx->dirs, imageBase, is64bit, fileSize, machine) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump Data Directories\n");
                    }

                    // Dump Rich Header if present
                    if (peCtx->richHeader) {
                        if (dump_rich_header(peCtx->fileHandle, peCtx->richHeader) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Rich Header\n");
                        }
                    }

                    // Dump COFF Symbol Table and String Table
                    if (PointerToSymbolTable && NumberOfSymbols) {
                        if (dump_symbol_table(peCtx->fileHandle, PointerToSymbolTable, NumberOfSymbols, peCtx->sections, numberOfSections) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump COFF Symbol Table\n");
                        }
                        if (dump_string_table(peCtx->fileHandle, PointerToSymbolTable, NumberOfSymbols) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump COFF String Table\n");
                        }
                    }

                    // Dump Overlay
                    overlayFo = 0; overlaySize = 0;
                    getOverlayInfo(peCtx->sections, numberOfSections, fileSize, &overlayFo, &overlaySize);

                    if (overlayFo != 0 && overlaySize != 0) {
                        if (print_range(peCtx->fileHandle, overlayFo, overlaySize, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Overlay\n");
                        }
                    }
                } else {
                    // Raw view: dump the whole file at once
                    if (print_range(peCtx->fileHandle, 0, (DWORD)fileSize, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump the whole file\n");
                    }
                }                
                break;

            case CMD_VA2FILE:
                if (argv[i + 1] && argv[i + 1][0] != '\0') {
                    ULONGLONG VA = convert_to_hex(argv[++i]);

                    status = va_to_fileOff_cmd(VA, peCtx->sections, numberOfSections, imageBase);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to convert VA=0x%llX to file offset\n", VA);
                    }
                }
                break;

            case CMD_FORMAT:
                if (argv[i + 1] && argv[i + 1][0] != '\0') {
                    status = parse_format_arg(argv[++i], FALSE, &config);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Invalid format: %s\n", argv[i]);
                    }
                }
                break;

            case CMD_TEMP_FORMAT:
                if (argv[i + 1] && argv[i + 1][0] != '\0') {
                    // save the format config state
                    tempFormatConfig = config.formatConfig;

                    status = parse_format_arg(argv[++i], TRUE, &config);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Invalid format: %s\n", argv[i]);
                    }
                }
                break;

            case CMD_STRINGS: // NOT FINSHED
                char *regexFilter;

                if (argv[i + 1] && argv[i + 1][0] != '\0' && strncmp(argv[i + 1], "rgex:", strlen("rgex:")) == 0) {
                    regexFilter = argv[++i] + strlen("rgex:");
                } else {
                    regexFilter = NULL;
                }

                status = dump_pe_strings(peCtx->fileHandle, regexFilter);
                if (status != RET_SUCCESS) {
                    fprintf(stderr, "[!] Failed to dump file strings\n");
                }

                break;

            case CMD_EXTRACT:
                // handle extraction of data
                if (argv[i + 1] && argv[i + 1][0] != '\0') {

                    status = parse_extract_arg(argv[++i], &config);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Invalid Extract Command: %s\n", argv[i]);
                        break;
                    }

                    status = perform_extract(
                        peCtx->fileHandle, peCtx->sections, numberOfSections,
                        PointerToSymbolTable, NumberOfSymbols, dataDirs, peCtx->dirs,
                        fileSize, imageBase, is64bit, &config, file_section_list);
                    
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to perform extraction\n");
                    }
                }
                break;

            case CMD_HASH:
                if (argv[i + 1] && argv[i + 1][0] != '\0') {

                    status = parse_hash_config(argv[++i], &config.hashConfig);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Invalid hash command: %s\n", argv[i]);
                        break;
                    }

                    // Single file target
                    if (argv[i + 1] && argv[i + 1][0] != '\0') {
                        status = parse_hash_targets(argv[++i], NULL, peCtx, NULL, &config.hashConfig);
                        if (status != RET_SUCCESS) {
                            fprintf(stderr, "[!] Invalid hash command: %s %s\n", argv[i - 1], argv[i]);
                            break;
                        }
                    } else {
                            fprintf(stderr, "[!] Invalid hash command: %s %s\n", argv[i - 1], argv[i]);
                    }

                    status = perform_hash_extract(&config.hashConfig);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to perform hash extraction\n");
                    }
                    // handle dumping and extracting the rest of the info
                }
                break;

            case CMD_HASH_COMPARE:
                if (argv[i + 1] && argv[i + 1][0] != '\0') {

                    status = parse_hash_config(argv[++i], &config.hashConfig);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Invalid compare command: %s\n", argv[i]);
                        break;
                    }

                    // Three possible cases:
                    // 1. Two file args -> external compare
                    // 2. One file arg  -> internal compare
                    // 3. None -> invalid

                    const char *file1 = NULL;
                    const char *file2 = NULL;

                    if (argv[i + 1] && argv[i + 1][0] != '\0') {
                        file1 = argv[++i];

                        if (argv[i + 1] && argv[i + 1][0] != '\0')
                            file2 = argv[++i]; // optional
                    }

                    if (!file1) {
                        fprintf(stderr, "[!] Missing file argument(s) for compare command\n");
                        break;
                    }

                    // file2 may be NULL → internal compare
                    status = parse_hash_targets(file1, file2, NULL, peCtx, &config.hashConfig);
                    if (status != RET_SUCCESS) {
                        if (file2)
                            fprintf(stderr, "[!] Invalid compare command: %s %s %s\n", argv[i - 2], argv[i - 1], argv[i]);
                        else
                            fprintf(stderr, "[!] Invalid compare command: %s %s\n", argv[i - 1], argv[i]);
                        break;
                    }

                    status = perform_hash_extract(&config.hashConfig);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to perform comperation extraction\n");
                    }
                }

                freePEContext(config.hashConfig.primaryCtx);

                break;

            default:
                fprintf(stderr, "[!!!] Unhandled command code %d. Please report this.\n", command);
                break;
        }
    }

    // Free section list from the info its carrying
    if (file_section_list->count) {
        free_sections(file_section_list);
    }

    SAFE_FREE(file_section_list);
    
    return status;
}
