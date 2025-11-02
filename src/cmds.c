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
    {"--data-directories", "-dd",   CMD_DATA_DIRECTORIES},

    // CLR family
    {"--clr-header",     "-ch",  CMD_CLR_HEADER},
    {"--clr-metadata",   "-cm",  CMD_CLR_METADATA},
    {"--clr-readytorun", "-crr", CMD_CLR_READYTORUN},
    {"--clr-streams",    "-cs",  CMD_CLR_STREAMS},
    {"--clr-strings",    "-csg", CMD_CLR_STRINGS},
    {"--clr-tables",     "-ct",  CMD_CLR_TABLES},
    {"--clr-all",        "-ca",  CMD_CLR_ALL},

    {"--rich",             "-rh",   CMD_RICH},
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

    {"-h",                 "--hash",             CMD_HASH},
    {"-cc",                "--compare-targets",  CMD_HASH_COMPARE},

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

    LONG val = strtol(buf, NULL, hex ? 16 : 10);

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


RET_CODE handle_section_extract(char *val, ExtractConfig *extractConfig) {
    if (!val || !extractConfig) return RET_INVALID_PARAM;

    // Reset section config flags
    memset(&extractConfig->section, 0, sizeof(extractConfig->section));

    if (*val == '/' || *val == '.') {
        strncpy(extractConfig->section.name, val, sizeof(extractConfig->section.name) - 1);
        extractConfig->section.useName = 1;
    }
    else if (*val == '#') {
        extractConfig->section.index = (WORD)convert_to_hex(val + 1);
        extractConfig->section.useIdx = 1;
    }
    else if (strncmp(val, "rva", 3) == 0) {
        char *cmd = strchr(val, '/');
        if (!cmd) return RET_INVALID_PARAM;
        *cmd++ = '\0';
        if (!cmd) return RET_INVALID_PARAM;

        extractConfig->section.addr.rva = (DWORD)convert_to_hex(cmd);
        extractConfig->section.useRva = 1;
    }
    else if (strncmp(val, "fo", 2) == 0) {
        char *cmd = strchr(val, '/');
        if (!cmd) return RET_INVALID_PARAM;
        *cmd++ = '\0';
        if (!cmd) return RET_INVALID_PARAM;

        extractConfig->section.addr.fo = (DWORD)convert_to_hex(cmd);
        extractConfig->section.useFo = 1;
    }
    else {
        return RET_INVALID_PARAM;
    }

    return RET_SUCCESS;
}

RET_CODE handle_export_extract(char *val, ExtractConfig *extractConfig) {
    if (!val || !extractConfig) return RET_INVALID_PARAM;

    // Reset export config flags
    memset(&extractConfig->export, 0, sizeof(extractConfig->export));

    // === export:#ORD ===
    if (*val == '#') {
        extractConfig->export.ordinal = (WORD)convert_to_hex(val + 1);
        extractConfig->export.useOrdinal = 1;
    }

    // === export:rva/VAL ===
    else if (strncmp(val, "rva/", 4) == 0) {
        const char *numStr = val + 4;
        if (!*numStr) return RET_INVALID_PARAM;

        extractConfig->export.rva = (DWORD)convert_to_hex(numStr);
        extractConfig->export.useRva = 1;
    }

    // === export:NAME ===
    else {
        ULONGLONG len = strlen(val);

        // Check if it ends with ".dll" safely
        if (len >= 4 && STREQI(val + len - 4, ".dll") == 0) {
            strncpy(extractConfig->export.dllName, val,
                    sizeof(extractConfig->export.dllName) - 1);
            extractConfig->export.dllName[sizeof(extractConfig->export.dllName) - 1] = '\0';
            extractConfig->export.useDll = 1;
            return RET_SUCCESS;
        }

        // Check if it’s a forwarded name (contains a dot)
        if (strchr(val, '.')) {
            strncpy(extractConfig->export.forwarderName, val,
                    sizeof(extractConfig->export.forwarderName) - 1);
            extractConfig->export.forwarderName[sizeof(extractConfig->export.forwarderName) - 1] = '\0';
            extractConfig->export.useForwarder = 1;
            return RET_SUCCESS;
        }

        // Otherwise, normal function
        strncpy(extractConfig->export.funcName, val,
                sizeof(extractConfig->export.funcName) - 1);
        extractConfig->export.funcName[sizeof(extractConfig->export.funcName) - 1] = '\0';
        extractConfig->export.useName = 1;
        return RET_SUCCESS;
    }

    return RET_SUCCESS;
}

RET_CODE handle_import_extract(char *val, ExtractConfig *extractConfig) {
    if (!val || !extractConfig) return RET_INVALID_PARAM;

    // Reset import config flags
    memset(&extractConfig->import, 0, sizeof(extractConfig->import));

    char *slash = strchr(val, '/');
    size_t len = strlen(val);

    // === Case 1: import:LIB/NAME or import:LIB ===
    if (slash) {
        *slash = '\0';
        slash++; // move past '/'

        strncpy(extractConfig->import.dllName, val, sizeof(extractConfig->import.dllName) - 1);
        extractConfig->import.dllName[sizeof(extractConfig->import.dllName) - 1] = '\0';
        extractConfig->import.isGlobal = 0;
    }
    // === Case 2: No slash, may be DLL or global name ===
    else {
        slash = val;

        if (len > 0 && STREQI(val + (len - 5), ".dll") == 0) {
            strncpy(extractConfig->import.dllName, val, sizeof(extractConfig->import.dllName) - 1);
            extractConfig->import.dllName[sizeof(extractConfig->import.dllName) - 1] = '\0';
            extractConfig->import.useDll   = 1;
            extractConfig->import.isGlobal = 0;
            return RET_SUCCESS; // import by DLL — nothing after '.dll'
        }
            // Global import (e.g., "CreateFileA")
            extractConfig->import.dllName[0] = '\0';
            extractConfig->import.useDll     = 0;
            extractConfig->import.isGlobal   = 1;
    }

    if (*slash == '\0') {
        // Nothing after '/'
        return RET_INVALID_PARAM;
    }

    // === Handle specific match type ===
    if (*slash == '#') {
        slash++;
        extractConfig->import.ordinal    = (WORD)convert_to_hex(slash);
        extractConfig->import.useOrdinal = 1;
    }
    else if (*slash == '@') {
        slash++;
        extractConfig->import.hint    = (WORD)convert_to_hex(slash);
        extractConfig->import.useHint = 1;
    }
    else {
        strncpy(extractConfig->import.funcName, slash, sizeof(extractConfig->import.funcName) - 1);
        extractConfig->import.funcName[sizeof(extractConfig->import.funcName) - 1] = '\0';
        extractConfig->import.useName = 1;
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
        ret = handle_section_extract(buf + 8, &extractConfig);
    }
    else if (strncmp(buf, "export:", 7) == 0) {
        extractConfig.kind = EXTRACT_EXPORT;
        ret = handle_export_extract(buf + 7, &extractConfig);
    }
    else if (strncmp(buf, "import:", 7) == 0) {
        extractConfig.kind = EXTRACT_IMPORT;
        ret = handle_import_extract(buf + 7, &extractConfig);
    } 

    if (ret != RET_SUCCESS)
        return ret;

    c->extractConfig = extractConfig;
    return RET_SUCCESS;
}


// typedef struct _HashConfig{
//     HashCommandType cmdType; // Type of hash command
//     HashAlg alg;             // Hash algorithm to use

//     Target target1;          // First target (or only target)
//     Target target2;          // Second target (for comparisons)

//     char file1[MAX_PATH_LENGTH]; // File path for first file
//     char file2[MAX_PATH_LENGTH]; // File path for second file (for compare)
// } HashConfig, *PHashConfig;


RET_CODE parse_hash_arg(const char *arg, PConfig c) {
    RET_CODE ret = RET_INVALID_PARAM;

    HashConfig hashConfig = {0};

    if (!arg) {
        c->hashConfig = hashConfig;
        return ret;
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

    PVOID ntHeaders = peCtx->is64Bit ? (PVOID)&nt64 : (PVOID)&nt32;

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

    int status;

   // iterate over arguments
    for (int i = 1; i < argc - 2; i++) {
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
                    DWORD fo = 0;
                    status = rva_to_offset(pBoundImportDataDir->VirtualAddress, peCtx->sections, numberOfSections, &fo);
                    if (status != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to convert Bound Import Directory RVA to file offset\n");
                        break;
                    }

                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_bound_import_dir(peCtx->fileHandle, peCtx->sections, numberOfSections, pBoundImportDataDir, imageBase) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Bound Import Directory\n");
                        }
                    } else {
                        if (print_range(peCtx->fileHandle, fo, pBoundImportDataDir->Size, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
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

                // to be continued
            case CMD_CLR_METADATA:
                break;
            case CMD_CLR_READYTORUN:
                break;
            case CMD_CLR_STREAMS:
                break;
            case CMD_CLR_STRINGS:
                break;
            case CMD_CLR_TABLES:
                break;
            case CMD_CLR_ALL:
                // handle CLR family
                break;

            case CMD_RICH:
                if (peCtx->richHeader) {
                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_rich_header(peCtx->fileHandle, 0x40, (DWORD)dosHeader->e_lfanew, peCtx->richHeader) != RET_SUCCESS) {
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

                    if (extract_version_resource(peCtx->fileHandle, peCtx->sections, numberOfSections, pRsrcDataDir, peCtx->dirs->rsrcDir, peCtx->dirs->rsrcEntriesDir, &versionInfoRva, &versionInfoSize) == RET_NO_VALUE) {
                        fprintf(stderr,"[!] Version Info was not found\n");
                        break;
                    }

                    if (config.formatConfig.view == VIEW_TABLE) {
                        if (dump_version_info(peCtx->fileHandle, peCtx->sections, numberOfSections, versionInfoRva, versionInfoSize, imageBase) != RET_SUCCESS) {
                            fprintf(stderr, "[!] Failed to dump Version Info\n");
                        }
                    } else {
                        DWORD versionInfoFO = 0;

                        if (rva_to_offset(versionInfoRva, peCtx->sections, numberOfSections, &versionInfoFO) != RET_SUCCESS) {
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
                        if (get_string_table_size(peCtx->fileHandle, stringTableOffset, fileSize, &stringTableSize) != RET_SUCCESS) {
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
                
                if (print_range(peCtx->fileHandle, overlayFo, overlaySize, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                    fprintf(stderr, "[!] Failed to dump Overlay\n");
                }
                break;

            case CMD_OVERVIEW:
                if (dump_pe_overview(peCtx->filePath, nt32, nt64, peCtx->sections, dataDirs, is64bit, fileSize) != RET_SUCCESS) {
                    fprintf(stderr, "[!] Failed to dump PE Over View info\n");   
                }
                break;

            case CMD_ALL: // NOT FINSHED
                if (config.formatConfig.view == VIEW_TABLE) {
                // havent been handled yet.
                } else {
                    if (print_range(peCtx->fileHandle, 0, (DWORD)fileSize, fileSize, &config.formatConfig, file_section_list, 1) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to dump the whole file\n");
                    }
                }
                
                break;

            case CMD_VA2FILE:
                if (argv[i + 1] && argv[i + 1][0] != '\0') {
                    i++;
                    ULONGLONG VA = convert_to_hex(argv[i]);
                    if (va_to_fileOff_cmd(VA, peCtx->sections, numberOfSections, imageBase) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to convert VA=0x%llX to file offset\n", VA);
                    }
                }
                break;

            case CMD_FORMAT:
                if (argv[i + 1] && argv[i + 1][0] != '\0') {
                    i++;
                    if (parse_format_arg(argv[i], FALSE, &config) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Invalid format: %s\n", argv[i]);
                    }
                }
                break;

            case CMD_TEMP_FORMAT:
                if (argv[i + 1] && argv[i + 1][0] != '\0') {
                    i++;
    
                    // save the format config state
                    tempFormatConfig = config.formatConfig;

                    if (parse_format_arg(argv[i], TRUE, &config) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Invalid format: %s\n", argv[i]);
                    }
                }
                break;

            case CMD_STRINGS: // NOT FINSHED
                char *regexFilter;

                if (argv[i + 1] && argv[i + 1][0] != '\0' && strncmp(argv[i + 1], "rgex:", strlen("rgex:")) == 0) {
                    regexFilter = argv[i + 1] + strlen("rgex:");
                    i++;
                } else {
                    regexFilter = NULL;
                }

                if (dump_pe_strings(peCtx->fileHandle, regexFilter) != RET_SUCCESS) {
                    fprintf(stderr, "[!] Failed to dump file strings\n");
                }

                break;

            case CMD_EXTRACT:
                // handle extraction of data
                if (argv[i + 1] && argv[i + 1][0] != '\0') {
                    i++;
                    if (parse_extract_arg(argv[i], &config) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Invalid Extract Command: %s\n", argv[i]);
                        break;
                    }
                    if (execute_extract(
                        peCtx->fileHandle, peCtx->sections, numberOfSections,
                        PointerToSymbolTable, NumberOfSymbols, dataDirs, peCtx->dirs,
                        fileSize, imageBase, is64bit, &config, file_section_list) != RET_SUCCESS) {
                        fprintf(stderr, "[!] Failed to execute extraction\n");
                    }
                }
                break;

            case CMD_HASH:
                if (argv[i + 1] && argv[i + 1][0] != '\0') {
                    i++;
                }
                break;

            case CMD_HASH_COMPARE:
                if (argv[i + 1] && argv[i + 1][0] != '\0') {
                    i++;
                }                    
                break;

            default:
                fprintf(stderr, "Error: Unhandled command code %d. Please report this.\n", command);
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
