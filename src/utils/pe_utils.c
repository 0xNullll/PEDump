#include "../include/pe_utils.h"

RET_CODE ReportMalformed(const char *reason, const char *context, const char *file, int line) {
    fprintf(stderr, "[!] Malformed file detected: %s\n", reason);
    fprintf(stderr, "   Context  : %s\n", context ? context : "Unknown");
    fprintf(stderr, "   Location : %s:%d\n\n", file, line);

    // Optional: append to global log buffer or counter
    // malformedCount++;
    return RET_MALFORMED_FILE;
}

UCHAR* read_entire_file_fp(FILE* peFile, PULONGLONG outSize) {
    UCHAR* buffer = NULL;

    if (!peFile) {
        fprintf(stderr, "[!!] Invalid file pointer.\n");
        return NULL;
    }

    // Remember current position (in case file pointer is not at start)
    LONGLONG originalPos = FTELL64(peFile);
    if (originalPos < 0) {
        perror("ftell failed");
        return NULL;
    }

    // Determine file size
    if (FSEEK64(peFile, 0, SEEK_END) != 0) {
        perror("fseek failed");
        return NULL;
    }

    LONGLONG fileSize = FTELL64(peFile);
    if (fileSize < 0) {
        perror("ftell failed");
        FSEEK64(peFile, originalPos, SEEK_SET);
        return NULL;
    }

    // Allocate buffer and read
    buffer = (UCHAR*)malloc((ULONGLONG)fileSize);
    if (!buffer) {
        perror("Memory allocation failed");
        FSEEK64(peFile, originalPos, SEEK_SET);
        return NULL;
    }

    rewind(peFile);  // Move to start
    ULONGLONG bytesRead = fread(buffer, 1, (ULONGLONG)fileSize, peFile);
    if (bytesRead != (ULONGLONG)fileSize) {
        fprintf(stderr, "[!!] read only %zu of %lld bytes\n", bytesRead, fileSize);
        SAFE_FREE(buffer);
        FSEEK64(peFile, originalPos, SEEK_SET);
        return NULL;
    }

    // Restore original position
    FSEEK64(peFile, originalPos, SEEK_SET);

    if (outSize) *outSize = (ULONGLONG)fileSize;
    return buffer;
}

LONGLONG get_file_size(FILE *peFile) {
    if (!peFile) return 0;

    // Save the current file position
    LONGLONG currentPos = _ftelli64(peFile);
    if (currentPos < 0) return 0;

    // Seek to the end to get total file size
    if (FSEEK64(peFile, 0, SEEK_END) != 0) return 0;

    LONGLONG size = FTELL64(peFile);

    // Restore the original position
    FSEEK64(peFile, currentPos, SEEK_SET);

    return size;
}

RET_CODE get_dll_from_forwarder(const char *forwarderName, char *outDllName, ULONGLONG strSize) {
    if (!forwarderName || !outDllName || strSize == 0) {
        if (strSize > 0) outDllName[0] = '\0';
        return RET_INVALID_PARAM;
    }

    const char *dot = strchr(forwarderName, '.');
    if (!dot) {  // just in case, but shouldn't happen for forwarded exports
        outDllName[0] = '\0';
        return RET_INVALID_PARAM;
    }

    ULONGLONG dllLen = (ULONGLONG)(dot - forwarderName);
    if (dllLen >= strSize) dllLen = strSize - 1;

    // Copy DLL name portion
    strncpy(outDllName, forwarderName, dllLen);
    outDllName[dllLen] = '\0';

    // Append ".dll" if space allows
    if (dllLen + 4 < strSize)
        strcat(outDllName, ".dll");
    else
        return RET_BUFFER_OVERFLOW;

    return RET_SUCCESS;
}

const char* get_data_directory_name(int index) {
    switch (index) {
        case IMAGE_DIRECTORY_ENTRY_EXPORT:         return "Export";
        case IMAGE_DIRECTORY_ENTRY_IMPORT:         return "Import";
        case IMAGE_DIRECTORY_ENTRY_RESOURCE:       return "Resource";
        case IMAGE_DIRECTORY_ENTRY_EXCEPTION:      return "Exception";
        case IMAGE_DIRECTORY_ENTRY_SECURITY:       return "Security";
        case IMAGE_DIRECTORY_ENTRY_BASERELOC:      return "Base Relocation";
        case IMAGE_DIRECTORY_ENTRY_DEBUG:          return "Debug";
        case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:   return "Architecture Specific Data";
        case IMAGE_DIRECTORY_ENTRY_GLOBALPTR:      return "RVA of GlobalPtr";
        case IMAGE_DIRECTORY_ENTRY_TLS:            return "TLS";
        case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:    return "Load Config";
        case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:   return "Bound Import";
        case IMAGE_DIRECTORY_ENTRY_IAT:            return "IAT";
        case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:   return "Delay Import";
        case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: return "CLR Runtime Header";
        default:                                   return "Unknown";
    }
}

RET_CODE get_symbol_file_offset(
    DWORD value, SHORT sectionNumber, PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections, PDWORD outOffset) {

    if (!sections || !numberOfSections || !outOffset) return RET_INVALID_PARAM;

    // Handle special or invalid section numbers
    if (sectionNumber <= 0 || sectionNumber > numberOfSections) return RET_INVALID_BOUND;

    // Convert 1-based SectionNumber to 0-based index
    PIMAGE_SECTION_HEADER section = &sections[sectionNumber - 1];

    DWORD start = section->PointerToRawData;
    DWORD size  = section->SizeOfRawData;

    if (value < size) {
        *outOffset = start + value;
        return RET_SUCCESS; // success
    }

    return RET_NO_VALUE; // value out of section bounds
}

void print_help(void) {
    printf(
        "# pedumper -h\n"
        "\n"
        "Usage: pedumper [options]\n"
        "Options:\n"
        "  -h,    --help                                Show this help message\n"
        "\n"
        "Headers & PE info:\n"
        "  -dh,   --dos-header                          Print DOS header\n"
        "  -fh,   --file-header                         Print File header\n"
        "  -oh,   --optional-header                     Print Optional header\n"
        "  -nth,  --nt-headers                          Print NT headers\n"
        "  -s,    --sections                            Print Sections\n"
        "\n"
        "Data Directories:\n"
        "  -e,    --exports                             Print Exports\n"
        "  -i,    --imports                             Print Imports\n"
        "  -r,    --resources                           Print Resources\n"
        "  -ex,   --exception                           Print Exception directory\n"
        "  -sec,  --security                            Print Security info\n"
        "  -br,   --basereloc                           Print Base relocations\n"
        "  -d,    --debug                               Print Debug directory\n"
        "  -tls,  --tls                                 Print TLS directory\n"
        "  -lc,   --load-config                         Print Load Config directory\n"
        "  -bi,   --bound-import                        Print Bound imports\n"
        "  -iat,  --iat                                 Print IAT\n"
        "  -di,   --delay-import                        Print Delay imports\n"
        "  -dd,   --data-directories                    Print all Data directories\n"
        "\n"

        "CLR Directories:\n"
        "  -ch,   --clr-header                          Print CLR Header\n"
        "  -cm,   --clr-metadata                        Print CLR Metadata\n"
        "  -crr,  --clr-readytorun                      Print CLR ReadyToRun info\n"
        "  -cs,   --clr-streams                         Print CLR Streams\n"
        "  -csg,  --clr-strings                         Print CLR Strings\n"
        "  -ct,   --clr-tables                          Print CLR Tables\n"
        "  -ca,   --clr-all                             Print all CLR-related info\n"
        "\n"
        "Miscellaneous:\n"
        "  -rh,   --rich                                Print Rich header\n"
        "  -vi,   --version-info                        Print Version info\n"
        "  -sym,  --symbol-table                        Print Symbol table\n"
        "  -st,   --string-table                        Print String table\n"
        "  -o,    --overlay                             Print Overlay\n"
        "  -ov,   --overview                            Print Overview info about the file\n"
        "  -a,    --all                                 Print all available info\n"
        "\n"

        "Output formatting:\n"
        "  -v2f,  --va2file NUMBER                      Convert virtual address to file offset\n"
        "  -f,    --format <type[:spec]>                Set output format and optionally limit range\n"
        "                                               <type> can be:\n"
        "                                                   hex   - bytes in hexadecimal (16 bytes/line)\n"
        "                                                   dec   - bytes as decimal values (0-255)\n"
        "                                                   bin   - bytes in binary (8 bits per byte)\n"
        "                                                   table - combined view: offset | hex | ASCII\n"
        "                                               Range specifiers (ignored for table):\n"
        "                                                   :N            - print first N lines\n"
        "                                                   :start,max    - print from 'start' to 'max' (line or offset)\n"
        "                                                                   - decimal = line index\n"
        "                                                                   - 0x...   = byte offset (rounded up to nearest line boundary)\n"
        "                                               Note: offsets starting with '0x' are treated as byte offsets\n"
        "                                                     and are aligned to the view's bytes-per-line.\n"
        "\n"
        "  -s,    --strings [rgex:<pattern>]            Dump ASCII/UTF-16LE strings from the file\n"
        "                                                   If no <pattern> is provided, all strings are dumped.\n"
        "                                                   Optional regex filtering:\n"
        "                                                       rgex:pattern  - filters strings matching <pattern>\n"
        "                                                   Examples:\n"
        "                                                       -s                          Dump all strings\n"
        "                                                       --strings rgex:^Hello       Dump strings starting with 'Hello'\n"
        "                                                   Regex backend:\n"
        "                                                       Uses system POSIX regex if available,\n"
        "                                                       otherwise falls back to TinyRegex.\n"
        "\n"
        "  -x,    --extract <target[:spec]>             Extract a specific part of the PE file\n"
        "                                               <target> can be:\n"
        "                                                   section:NAME        - extract a section by name (e.g., section:.text, section:.rdata)\n"
        "                                                   section:#IDX        - extract a section by index (e.g., section:#2)\n"
        "                                                   section:rva/VAL     - extract data at a specific RVA (e.g., section:rva/0x401000)\n"
        "                                                   section:fo/VAL      - extract data at a specific file offset (e.g., section:fo/0x200)\n"
        "\n"
        "                                                   export:NAME         - extract an exported function by name (e.g., export:CreateFileA)\n"
        "                                                   export:#ORD         - extract an exported function by ordinal (e.g., export:#37)\n"
        "                                                   export:rva/VAL      - extract an exported entry by RVA; matches either Func-RVA or Name-RVA (e.g., export:rva/0x401000)\n"
        "                                                   export:FWD          - extract a forwarded export (e.g., export:KERNEL32.CreateFileA)\n"
        "                                                   export:LIB          - extract ALL exports from the specified DLL\n"
        "                                                                           (must include the '.dll' extension, e.g., export:KERNEL32.dll)\n"
        "\n"
        "                                                   import:NAME         - extract a function by name globally  (e.g., CreateFileA)\n"
        "                                                   import:#ORD         - extract a function by ordinal globally (e.g, #0x287)\n"
        "                                                   import:@HNT         - extract a function by hint globally (e.g., @37)\n"
        "                                                   import:LIB          - extract ALL imports from the specified DLL\n"
        "                                                                           (must include the '.dll' extension, e.g., import:KERNEL32.dll)\n"
        "                                                   import:LIB/NAME     - extract a function by name (e.g., KERNEL32.dll/CreateFileA)\n"
        "                                                   import:LIB/#ORD     - extract a function by ordinal (e.g, KERNEL32.DLL/#0x287)\n"
        "                                                   import:LIB/@HNT     - extract a function by hint (e.g., KERNEL32.dll/@37)\n"
        "\n"
        "                                               Address specifiers:\n"
        "                                                   rva/VAL             - use Relative Virtual Address (RVA)\n"
        "                                                   fo/VAL              - use File Offset (FO)\n"
        "\n"
        "                                               Value formats accepted for VAL:\n"
        "                                                   HEX                 e.g. rva/4198400\n"
        "                                                   0xHEX               e.g. rva/0x401000\n"
        "                                                   HEXh (Intel)        e.g. rva/401000h\n"
        "                                                   (Parsers are case-insensitive for hex digits and the trailing 'h')\n"
        "\n"
    );
}

RET_CODE decrypt_rich_header(PIMAGE_RICH_HEADER encRichHdr, PIMAGE_RICH_HEADER decRichHdr) {
    if (!encRichHdr || !decRichHdr || encRichHdr->NumberOfEntries == 0)
        return RET_INVALID_PARAM;

    DWORD XORKey = encRichHdr->XORKey;
    PULONGLONG rawEntries = (PULONGLONG)encRichHdr->Entries;
    WORD numberOfEntries = encRichHdr->NumberOfEntries;

    // Copy and decrypt the header markers
    decRichHdr->DanS   = encRichHdr->DanS ^ XORKey;
    decRichHdr->Rich   = encRichHdr->Rich;  // Rich marker usually stored plain
    decRichHdr->XORKey = XORKey;

    decRichHdr->checksumPadding1 = XORKey;
    decRichHdr->checksumPadding2 = XORKey;
    decRichHdr->checksumPadding3 = XORKey;

    decRichHdr->richHdrOff = encRichHdr->richHdrOff;
    decRichHdr->richHdrSize = encRichHdr->richHdrSize;

    decRichHdr->NumberOfEntries = numberOfEntries;

    // Decrypt each entry (each = 1 ULONGLONG: compid + count)
    for (int i = 0; i < (int)numberOfEntries; i++) {
        ULONGLONG encEntry = rawEntries[i];

        DWORD compid = (DWORD)(encEntry & 0xFFFFFFFFULL) ^ XORKey;      // low 32 bits
        DWORD count  = (DWORD)((encEntry >> 32) & 0xFFFFFFFFULL) ^ XORKey; // high 32 bits

        decRichHdr->Entries[i].BuildID = compid & 0xFFFF;         // low 16 bits
        decRichHdr->Entries[i].ProdID  = (WORD)((compid >> 16) & 0xFFFF); // high 16 bits
        decRichHdr->Entries[i].Count   = count;
    }

    return RET_SUCCESS;
}

void strToLower(char *buf, ULONGLONG len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (char)tolower((unsigned char)buf[i]);
    }
}

const char * format_timestamp(DWORD timestamp) {
    static char buffer[64];
    if (timestamp == 0) {
        snprintf(buffer, sizeof(buffer), " ");
        return buffer;
    }

    time_t raw = (time_t)timestamp;
    struct tm *ptm = localtime(&raw);
    if (!ptm) {
        snprintf(buffer, sizeof(buffer), "(invalid)");
        return buffer;
    }

    // %A = full weekday name, e.g., Monday
    strftime(buffer, sizeof(buffer), "(%A %Y.%m.%d %H:%M:%S UTC)", ptm);
    return buffer;
}

const char *format_filetime(ULONGLONG filetime) {
    static char buf[64];
    const ULONGLONG WINDOWS_TICK = 10000000ULL;
    const ULONGLONG SEC_TO_UNIX_EPOCH = 11644473600ULL;

    if (filetime == 0) {
        return "(none)";
    }

    time_t unix_time = (time_t)((filetime / WINDOWS_TICK) - SEC_TO_UNIX_EPOCH);
    struct tm *ptm = gmtime(&unix_time);

    if (!ptm) {
        snprintf(buf, sizeof(buf), "(invalid)");
    } else {
        strftime(buf, sizeof(buf), "(%Y-%m-%d %H:%M:%S UTC)", ptm);
    }

    return buf;
}

char* str_to_hex(DWORD val) {
    static char buf[16];
    snprintf(buf, sizeof(buf), "%08lX", val);
    return buf;
}

BOOL read_import_dll_name(
    FILE *peFile, const PIMAGE_IMPORT_DESCRIPTOR impDesc, PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections, char *outName) {
    if (!peFile || !impDesc || !outName)
        return FALSE;

    SECTION_INFO sec = get_section_info(impDesc->Name, sections, numberOfSections);
    if (sec.size == 0 || impDesc->Name - sec.virtualAddress >= sec.size)
        return FALSE;

    FSEEK64(peFile, sec.rawOffset + impDesc->Name - sec.virtualAddress, SEEK_SET);
    fread(outName, 1, MAX_DLL_NAME - 1, peFile);
    outName[MAX_DLL_NAME - 1] = '\0';

    return TRUE;
}

RET_CODE rva_to_offset(DWORD rva, PIMAGE_SECTION_HEADER sections, WORD numberOfSections, PDWORD outOffset) {
    if (!sections || !outOffset) return RET_INVALID_PARAM;  // sanity check

    // Loop through all sections to find which one contains the RVA
    for (int i = 0; i < numberOfSections; i++) {
        DWORD start = sections[i].VirtualAddress;
        DWORD end   = start + (sections[i].Misc.VirtualSize ? sections[i].Misc.VirtualSize
                                                                : sections[i].SizeOfRawData);

        // Check if the RVA lies within this section's virtual address range
        if (rva >= start && rva < end) {
            // Compute file offset = RVA relative to section + raw data pointer
            *outOffset = (rva - start) + sections[i].PointerToRawData;
            return RET_SUCCESS; // found
        }
    }
    return RET_NO_VALUE; // not found in any section
}

RET_CODE offset_to_rva(DWORD offset, PIMAGE_SECTION_HEADER sections, WORD numberOfSections, PDWORD outRva) {
    if (!sections || !outRva) return RET_INVALID_PARAM;  // sanity check

    for (int i = 0; i < numberOfSections; i++) {
        DWORD start = sections[i].PointerToRawData;
        DWORD end   = start + sections[i].SizeOfRawData;

        if (offset >= start && offset < end) {
            *outRva = (offset - start) + sections[i].VirtualAddress;
            return RET_SUCCESS; // success
        }
    }

    return RET_NO_VALUE; // not found in any section
}

SECTION_INFO get_section_info(DWORD rva, PIMAGE_SECTION_HEADER sections, WORD numberOfSections) {
    SECTION_INFO info = { "Unknown", 0, 0, 0 };  // default if not found

    for (int i = 0; i < numberOfSections; i++) {
        DWORD startVA = sections[i].VirtualAddress;
        DWORD endVA = startVA + sections[i].Misc.VirtualSize;

        if (rva >= startVA && rva < endVA) {
            // Copy section name safely and sanitize
            static char name[9];  // 8 chars max + null terminator
            for (int j = 0; j < 8; j++) {
                if (sections[i].Name[j] >= 32 && sections[i].Name[j] <= 126)
                    name[j] = (char)sections[i].Name[j];
                else
                    name[j] = '.';  // replace non-printable
            }
            name[8] = '\0';

            // Trim trailing dots
            for (int j = 7; j >= 0 && name[j] == '.'; j--) name[j] = '\0';

            info.name = name;
            info.virtualAddress = sections[i].VirtualAddress;
            info.rawOffset = sections[i].PointerToRawData;
            info.size = sections[i].SizeOfRawData;
            return info;
        }
    }
    return info;
}

BOOL has_section(PIMAGE_SECTION_HEADER sections, WORD numberOfSections, const char *sectionName) {
    for (WORD i = 0; i < numberOfSections; i++) {
        // Section names are up to 8 bytes (no guaranteed null terminator)
        char name[9] = {0};  
        memcpy(name, sections[i].Name, 8);

        if (_stricmp(name, sectionName) == 0)
            return TRUE;
    }
    return FALSE;
}

RVA_INFO get_rva_info(DWORD rva, PIMAGE_SECTION_HEADER sections, WORD numberOfSections, ULONGLONG imageBase) {
    RVA_INFO info = {0}; // zero-initialize

    if (!sections) // safety check
        return info;

    for (WORD i = 0; i < numberOfSections; i++) {
        DWORD startVA = sections[i].VirtualAddress;
        DWORD endVA   = startVA + sections[i].Misc.VirtualSize;

        if (rva >= startVA && rva < endVA) {
            // Calculate file offset
            info.fileOffset = sections[i].PointerToRawData + ((DWORD)rva - startVA);

            // Store RVA and VA
            info.rva = rva;
            info.va  = imageBase + rva;

            // Copy section name and null-terminate
            memcpy(info.sectionName, sections[i].Name, 8);
            info.sectionName[8] = '\0';

            info.sectionIndex = i + 1;

            // Store section sizes
            info.rawSize     = sections[i].SizeOfRawData;
            info.virtualSize = sections[i].Misc.VirtualSize;

            return info;
        }
    }

    return info; // RVA not found
}

RET_CODE get_string_table_size(FILE *peFile, DWORD stringTableOffset, LONGLONG fileSize, PDWORD outSize) {

    if (!peFile || !outSize) return RET_INVALID_PARAM;

    if (stringTableOffset + sizeof(DWORD) > (DWORD)fileSize) {
        return RET_ERROR; // out of file bounds
    }

    if (fseek(peFile, (LONG)stringTableOffset, SEEK_SET) != 0) {
        return RET_ERROR;
    }

    DWORD stringTableSize = 0;
    if (fread(&stringTableSize, sizeof(DWORD), 1, peFile) != 1) {
        return RET_ERROR;
    }

    if (stringTableSize <= 4 || stringTableOffset + stringTableSize > (DWORD)fileSize) {
        return RET_ERROR; // invalid table
    }

    *outSize = stringTableSize;
    return RET_SUCCESS;
}

void getOverlayInfo(PIMAGE_SECTION_HEADER sections, WORD numberOfSections, LONGLONG fileSize, PDWORD foOut, PDWORD sizeOut) {
    DWORD lastSectionEnd = 0;

    for (WORD i = 0; i < numberOfSections; i++) {
        DWORD secStart = sections[i].PointerToRawData;
        DWORD secSize  = sections[i].SizeOfRawData;

        // check for overflow and invalid values
        if (secStart < (DWORD)fileSize && secSize <= (DWORD)fileSize - secStart) {
            DWORD secEnd = secStart + secSize;
            if (secEnd > lastSectionEnd) {
                lastSectionEnd = secEnd;
            }
        }
    }

    *foOut  = lastSectionEnd;
    *sizeOut = (lastSectionEnd < (DWORD)fileSize) ? ((DWORD)fileSize - lastSectionEnd) : 0;
    return;
}

const char* get_symbol_sectionName(SHORT sectionNumber, PIMAGE_SECTION_HEADER sections, WORD numberOfSections) {
    if (sectionNumber == 0) return "UNDEFINED / EXTERNAL symbol";
    if (sectionNumber == -1) return "ABSOLUTE symbol";
    if (sectionNumber == -2) return "DEBUG symbol";

    // Positive section numbers: map to actual section headers
    if (sectionNumber > 0 && sectionNumber <= numberOfSections) {
        return (const char*)sections[sectionNumber - 1].Name;
    }

    return "UNKNOWN SECTION";
}

BOOL IsAuxFunction(PIMAGE_SYMBOL sym) {
    if (!sym) return FALSE;

    return sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL &&
           ((sym->Type >> 4) & 0xF) == IMAGE_SYM_DTYPE_FUNCTION &&
           sym->NumberOfAuxSymbols > 0;
}

BOOL IsAuxBf(PIMAGE_SYMBOL sym) {
    if (!sym) return FALSE;

    return sym->StorageClass == IMAGE_SYM_CLASS_NULL &&
           sym->Type == IMAGE_SYM_TYPE_NULL &&
           strncmp((char*)sym->N.ShortName, ".bf", 8) == 0;
}

BOOL IsAuxEf(PIMAGE_SYMBOL sym) {
    if (!sym) return FALSE;

    return sym->StorageClass == IMAGE_SYM_CLASS_NULL &&
           sym->Type == IMAGE_SYM_TYPE_NULL &&
           strncmp((char*)sym->N.ShortName, ".ef", 8) == 0;
}

BOOL IsAuxWeakExternal(PIMAGE_SYMBOL sym) {
    if (!sym) return FALSE;

    return sym->StorageClass == IMAGE_SYM_CLASS_WEAK_EXTERNAL &&
           sym->Type == IMAGE_SYM_TYPE_NULL &&
           sym->SectionNumber == IMAGE_SYM_UNDEFINED &&
           sym->NumberOfAuxSymbols > 0;
}

BOOL IsAuxFile(PIMAGE_SYMBOL sym) {
    if (!sym) return FALSE;

    return sym->StorageClass == IMAGE_SYM_CLASS_FILE &&
           sym->NumberOfAuxSymbols > 0;
}

BOOL IsAuxSecDef(PIMAGE_SYMBOL sym, PIMAGE_SECTION_HEADER sections, WORD numberOfSections) {
    if (!sym) return FALSE;

    // Must be a static symbol with at least one aux
    if (sym->StorageClass != IMAGE_SYM_CLASS_STATIC ||
        sym->NumberOfAuxSymbols == 0)
        return FALSE;

    // Copy and trim symbol name (stop at '$' if present)
    char symName[9] = {0}; // +1 for null terminator
    for (int i = 0; i < 8; i++) {
        if (sym->N.ShortName[i] == '$' || sym->N.ShortName[i] == '\0')
            break;
        symName[i] = (char)sym->N.ShortName[i];
    }

    // Case 1: matches a real section name
    for (int i = 0; i < numberOfSections; i++) {
        if (memcmp(symName, sections[i].Name, 8) == 0) {
            return TRUE;
        }
    }

    // Case 2: section contribution (.ctors, .idata$, etc.)
    // Still treat it as a Section Definition
    return TRUE;
}

BOOL IsAuxClrToken(PIMAGE_SYMBOL sym) {
    if (!sym) return FALSE;

    return sym->StorageClass == IMAGE_SYM_CLASS_CLR_TOKEN &&
           sym->NumberOfAuxSymbols > 0;
}

BOOL IsMIPSOrAlpha32(WORD machine) {
    return (machine == 0x0162   || // IMAGE_FILE_MACHINE_MIPS
            machine == IMAGE_FILE_MACHINE_MIPS16 ||
            machine == IMAGE_FILE_MACHINE_MIPSFPU ||
            machine == IMAGE_FILE_MACHINE_MIPSFPU16 ||
            machine == IMAGE_FILE_MACHINE_ALPHA);
}

BOOL IsAlpha64(WORD machine) {
    return (machine == IMAGE_FILE_MACHINE_ALPHA64);
}

BOOL IsWinCE(WORD machine) {
    return (machine == IMAGE_FILE_MACHINE_ARM ||
            machine == IMAGE_FILE_MACHINE_POWERPC ||
            machine == IMAGE_FILE_MACHINE_SH3 ||
            machine == IMAGE_FILE_MACHINE_SH4);
}

BOOL IsARMNT(WORD machine) {
    return (machine == IMAGE_FILE_MACHINE_ARMNT);
}

BOOL IsARM64(WORD machine) {
    return (machine == IMAGE_FILE_MACHINE_ARM64);
}

BOOL IsX64OrItanium(WORD machine) {
    return (machine == IMAGE_FILE_MACHINE_AMD64 ||
            machine == IMAGE_FILE_MACHINE_IA64);
}

void print_centered_header(const char *text, char padChar, int width) {
    size_t len = strlen(text);
    if ((int)len >= width) {
        printf("%s\n", text);
        return;
    }

    int totalPadding = width - (int)len - 2;
    int left = totalPadding / 2;
    int right = totalPadding - left;

    for (int i = 0; i < left; i++) putchar(padChar);
    printf(" %s ", text);
    for (int i = 0; i < right; i++) putchar(padChar);
    putchar('\n');
}

void printExceptionDirectoryHeader(ULONGLONG vaBase, char const *headerName, DWORD entriesCount, WORD machine) {
    printf("\n%016llX - %s - number of entries: %lu (entry type: %s)\n\n",
           vaBase, headerName, (ULONG) entriesCount, getExceptionEntryType(machine));
}

WORD count_digits(ULONGLONG number) {
    WORD digits = 1;
    while (number >= 10) {
        number /= 10;
        digits++;
    }
    return digits;
}

WORD count_imp_descriptors(PIMAGE_IMPORT_DESCRIPTOR impDesc) {
    WORD count = 0;
    while (impDesc[count].OriginalFirstThunk != 0 ||
            impDesc[count].FirstThunk != 0 ||
            impDesc[count].Name != 0) {
        count++;
    }
    return count;
}

ULONGLONG count_thunks(FILE *peFile, DWORD thunkRva, PIMAGE_SECTION_HEADER sections, WORD numberOfSection, int is64bit) {
    DWORD offset;
    if (rva_to_offset(thunkRva, sections, numberOfSection, &offset)) return 0;

    if (fseek(peFile, (LONG)offset, SEEK_SET) != 0) return 0; // move to INT/IAT start

    ULONGLONG count = 0;

    if (is64bit) {
        IMAGE_THUNK_DATA64 thunk;
        while (fread(&thunk, sizeof(IMAGE_THUNK_DATA64), 1, peFile) == 1) {
            if (thunk.u1.AddressOfData == 0) break;  // terminating NULL entry
            count++;
        }
    } else {
        IMAGE_THUNK_DATA32 thunk;
        while (fread(&thunk, sizeof(IMAGE_THUNK_DATA32), 1, peFile) == 1) {
            if (thunk.u1.AddressOfData == 0) break;  // terminating NULL entry
            count++;
        }
    }

    return count;
}

DWORD count_table_entries(FILE *peFile, ULONGLONG tableVA, PIMAGE_SECTION_HEADER sections, WORD numberOfSections, ULONGLONG imageBase) {
    if (!peFile || tableVA == 0) return 0;

    DWORD entryCount = 0;
    DWORD fileOffset;

    // Convert RVA to file offset
    if (rva_to_offset((DWORD)(tableVA - imageBase), sections, numberOfSections, &fileOffset))
        return 0;

    DWORD currentOffset = fileOffset;

    while (1) {
        if (fseek(peFile, (LONG)currentOffset, SEEK_SET) != 0)
            break;

        DWORD value = 0;
        if (fread(&value, sizeof(DWORD), 1, peFile) != 1)
            break;

        BYTE meta = 0;
        if (fread(&meta, sizeof(BYTE), 1, peFile) != 1)
            break;

        if (value == 0)  // terminating entry
            break;

        entryCount++;
        currentOffset += sizeof(DWORD) + sizeof(BYTE);
    }

    return entryCount;
}

RET_CODE IsUnicodeString(const BYTE *data, DWORD len) {
    // Heuristic: check if most high bytes are 0x00
    DWORD nulls = 0;
    for (DWORD i = 1; i < len; i += 2) {
        if (data[i] == 0x00) nulls++;
    }
    return (nulls > len / 4); // arbitrary threshold
}

BOOL is_import_library_present(
    FILE *peFile, PIMAGE_IMPORT_DESCRIPTOR impDesc, WORD numberOfEntries,
    PIMAGE_SECTION_HEADER sections, WORD numberOfSections, const char *dllName) {

    if (!peFile || !impDesc || !dllName || numberOfEntries == 0)
        return FALSE;

    for (WORD i = 0; i < numberOfEntries; i++) {
        char currentName[MAX_DLL_NAME] = {0};
        if (!read_import_dll_name(peFile, &impDesc[i], sections, numberOfSections, currentName)) {
            strcpy(currentName, "<invalid>"); 
        }

        if (STREQI(currentName, dllName) == 0)
            return TRUE; // DLL exists
    }

    return FALSE; // DLL not found
}

int regex_search(const char* pattern, const char* text) {
#if ENABLE_REGEX
    // ---------------------------------------------------------
    // POSIX regex (Linux, macOS, etc.)
    // ---------------------------------------------------------
    regex_t regex;
    int ret;

    // Compile regex
    ret = regcomp(&regex, pattern, REG_EXTENDED);
    if (ret) {
        fprintf(stderr, "Could not compile regex\n");
        return 0;
    }

    // Execute regex
    ret = regexec(&regex, text, 0, NULL, 0);
    regfree(&regex);

    return (ret == 0); // match found if ret == 0

#else
    // ---------------------------------------------------------
    // TinyRegex fallback (Windows / environments w/o regex.h)
    // ---------------------------------------------------------
    re_t re = re_compile(pattern);
    if (!re) {
        fprintf(stderr, "Could not compile tiny-regex pattern\n");
        return 0;
    }

    int match = re_matchp(re, text, NULL);
    return (match != -1); // tiny-regex returns -1 for no match
#endif
}
