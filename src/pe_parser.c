#include "include/pe_parser.h"

BOOL isPE(FILE *peFile) {
    if (!peFile) 
        return FALSE;

    // Go to beginning of file
    if (FSEEK64(peFile, 0, SEEK_SET) != 0) 
        return FALSE;

    IMAGE_DOS_HEADER dosHeader;
    if (fread(&dosHeader, sizeof(dosHeader), 1, peFile) != 1) 
        return FALSE;

    // DOS header magic
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        REPORT_MALFORMED("DOS Magic missing", "DOS Header");
        return FALSE;
    }

    // e_lfanew should not exceed file size
    LONGLONG cur = FTELL64(peFile);
    if (FSEEK64(peFile, 0, SEEK_END) != 0) 
        return FALSE;
    LONGLONG fileSize = FTELL64(peFile);
    if (fileSize < 0 || (ULONGLONG)dosHeader.e_lfanew + sizeof(DWORD) > (DWORD)fileSize) {
        FSEEK64(peFile, cur, SEEK_SET);
        REPORT_MALFORMED("e_lfanew beyond file size", "PE Header");
        return FALSE;
    }

    // Read NT header signature
    if (FSEEK64(peFile, dosHeader.e_lfanew, SEEK_SET) != 0) 
        return FALSE;

    DWORD signature;
    if (fread(&signature, sizeof(signature), 1, peFile) != 1) 
        return FALSE;

    return (signature == IMAGE_NT_SIGNATURE); // 'PE\0\0'
}

PE_ARCH get_pe_architecture(FILE *peFile) {
    if (!peFile) return PE_INVALID;

    IMAGE_DOS_HEADER dosHeader;
    if (FSEEK64(peFile, 0, SEEK_SET) != 0) return PE_INVALID;
    if (fread(&dosHeader, sizeof(dosHeader), 1, peFile) != 1) return PE_INVALID;

    if (FSEEK64(peFile, dosHeader.e_lfanew + 4 + (LONG)sizeof(IMAGE_FILE_HEADER), SEEK_SET) != 0) return PE_INVALID;

    WORD Magic;
    if (fread(&Magic, sizeof(Magic), 1, peFile) != 1) return PE_INVALID;

    switch (Magic) {
        case 0x10b: return PE_32;
        case 0x20b: return PE_64;
        default: return PE_INVALID;
    }
}

RET_CODE parse_dos_header(FILE *peFile, PIMAGE_DOS_HEADER dosHeader) {
    if (FSEEK64(peFile, 0, SEEK_SET) != 0) return RET_ERROR;
    if (fread(dosHeader, sizeof(IMAGE_DOS_HEADER), 1, peFile) != 1) return RET_ERROR;
    return RET_SUCCESS;
}

RET_CODE parse_rich_header(FILE *peFile, DWORD StartOff, DWORD endOff, PIMAGE_RICH_HEADER *richHeader) {
    PDWORD raw = NULL;               // temporary buffer for raw DWORDs
    PBYTE rawBytes = NULL;           // temporary buffer for raw Bytes
    DWORD bufferSize = endOff - StartOff;
    DWORD bufferCount = bufferSize / sizeof(DWORD);

    DWORD rawEntryDWORDs = 0;           // counts DWORDs in the raw entries
    WORD numberOfEntries = 0;           // actual logical entries (each 2 DWORDs)
    int entryIdx = 0;                   // index where entries start
    int danSIdx = 0;                    // index of the DanS tag

    DWORD begStructOff = 0;             // offset of the beginning of structure
    DWORD richHdrStartOff = 0;          // offset of the beginning offset of the rich header
    int richIdx = 0;                    // index of the Rich signature
    DWORD checksum = 0;                 // XOR key / checksum

    if (!peFile || !StartOff || !endOff) return RET_INVALID_PARAM;

    if (FSEEK64(peFile, StartOff, SEEK_SET) != 0) return RET_ERROR;

    rawBytes = malloc(bufferSize);
    if (!rawBytes) {
        printf("[!!] Failed to malloc\n");
        return RET_ERROR;
    }

    if (fread(rawBytes, 1, bufferSize, peFile) != bufferSize) {
        SAFE_FREE(rawBytes);
        return RET_ERROR;
    }

    raw = (PDWORD)rawBytes;

    for (int i = 0; i < (int)bufferCount; i++) {
        if (tagBegId == raw[i]) {
            richIdx = i;
            checksum = raw[i + 1];
            break; // found it, stop loop
        }
    }

    if (!richIdx) { SAFE_FREE(rawBytes); return RET_NO_VALUE; }

    for (int i = richIdx - 1; i >= 0; i--) {
        DWORD decrypted = raw[i] ^ checksum;

        if (decrypted == tagEndId) {

            begStructOff = (DWORD)i * (DWORD)sizeof(DWORD);
            richHdrStartOff = StartOff + begStructOff;
            danSIdx = i;
            entryIdx += i + 1;
            break; // found it, stop loop
        } 
        else if (decrypted != tagEndId && raw[i] != checksum) {
            rawEntryDWORDs += 1;
        } 
        else if (raw[i] == checksum) {
            entryIdx += 1;
        }
        
    }

    if (!danSIdx) { SAFE_FREE(rawBytes); return RET_NO_VALUE; }

    numberOfEntries = (WORD)rawEntryDWORDs / 2;


    *richHeader = calloc(1, sizeof(IMAGE_RICH_HEADER));
    if (!*richHeader) {
        printf("[!!] Failed to calloc\n");
        SAFE_FREE(rawBytes);
        return RET_ERROR;
    }

    // allocate memory for the Entries pointer inside the struct
    (*richHeader)->Entries = calloc(numberOfEntries, sizeof(RICH_ENTRY));
    if (!(*richHeader)->Entries) {
        printf("[!!] Failed to calloc Entries\n");
        SAFE_FREE(*richHeader);
        SAFE_FREE(rawBytes);
        return RET_ERROR;
    }

    // Fill header fields
    (*richHeader)->checksumPadding1 = checksum;
    (*richHeader)->checksumPadding2 = checksum;
    (*richHeader)->checksumPadding3 = checksum;
    (*richHeader)->XORKey = checksum;

    (*richHeader)->DanS = raw[danSIdx];

    (*richHeader)->Rich = raw[richIdx];

    (*richHeader)->NumberOfEntries = numberOfEntries;

    memcpy((*richHeader)->Entries, &raw[entryIdx], numberOfEntries * sizeof(RICH_ENTRY));

    (*richHeader)->richHdrOff = richHdrStartOff;

    // danS signature (DWORD), 3 checksum padding (DWORD), rich signature (DWORD), checksum (DWORD)
    (*richHeader)->richHdrSize = (DWORD)(6 * sizeof(DWORD) + (ULONGLONG)(sizeof(RICH_ENTRY) * numberOfEntries)
    
    );
    SAFE_FREE(rawBytes);
    return RET_SUCCESS;
}

RET_CODE parse_nt_headers(FILE *peFile, PIMAGE_NT_HEADERS32 nt32, PIMAGE_NT_HEADERS64 nt64, int is64bit, DWORD offset) {
    if (FSEEK64(peFile, offset, SEEK_SET) != 0) return RET_ERROR;

    if (is64bit) {
        if (fread(nt64, sizeof(IMAGE_NT_HEADERS64), 1, peFile) != 1) return RET_ERROR;
    } else {
        if (fread(nt32, sizeof(IMAGE_NT_HEADERS32), 1, peFile) != 1) return RET_ERROR;
    }

    return RET_SUCCESS;
}

RET_CODE parse_symbol_table(FILE *peFile, PIMAGE_SYMBOL *symTable, DWORD NumberOfSymbols, DWORD offset) {
    *symTable = calloc(NumberOfSymbols, sizeof(IMAGE_SYMBOL));
    if (!*symTable) {
        fprintf(stderr, "[!!] calloc for Symbol Table failed\n");
        return RET_ERROR;
    }
    
    if (FSEEK64(peFile, offset, SEEK_SET) != 0) {
        fprintf(stderr, "[!!] fseek failed\n");
        SAFE_FREE(*symTable);
        *symTable = NULL;
        return RET_ERROR;
    }

    if (fread(*symTable, sizeof(IMAGE_SYMBOL), NumberOfSymbols, peFile) != NumberOfSymbols) {
        fprintf(stderr, "[!!] Failed to read Symbol Table\n");
        SAFE_FREE(*symTable);
        *symTable = NULL;
        return RET_ERROR;
    }

    return RET_SUCCESS;
}

RET_CODE parse_string_table(FILE *peFile, char **stringTableOut, DWORD offset) {
    if (FSEEK64(peFile, offset, SEEK_SET) != 0) return RET_ERROR;

    DWORD stringTableSize = 0;
    if (fread(&stringTableSize, sizeof(DWORD), 1, peFile) != 1) return RET_ERROR;

    if (stringTableSize < 4) return RET_NO_VALUE; // nothing useful

    char *stringTable = malloc(stringTableSize);
    if (!stringTable) return RET_ERROR;

    // store the size in first 4 bytes
    *(DWORD*)stringTable = stringTableSize;

    DWORD rest = stringTableSize - 4;
    if (fread(stringTable + 4, 1, rest, peFile) != rest) {
        SAFE_FREE(stringTable);
        return RET_ERROR;
    }

    *stringTableOut = stringTable;
    return RET_SUCCESS;
}

RET_CODE parse_section_headers(FILE *peFile, PIMAGE_SECTION_HEADER *sections, WORD numberOfSections, DWORD offset, LONGLONG fileSize) {
    if (!peFile || offset == 0) return RET_INVALID_PARAM;

    if (numberOfSections == 0)
        return REPORT_MALFORMED("Empty section table (NumberOfSections = 0)", "Section Table");

    *sections = malloc(sizeof(IMAGE_SECTION_HEADER) * numberOfSections);
    if (!*sections) {
        fprintf(stderr, "[!] Failed to allocate section headers\n");
        return RET_ERROR;
    }

    if (FSEEK64(peFile, offset, SEEK_SET) != 0) {
        fprintf(stderr, "[!] Failed to seek to section headers\n");
        SAFE_FREE(*sections);
        return RET_ERROR;
    }

    if (fread(*sections, sizeof(IMAGE_SECTION_HEADER), numberOfSections, peFile) != numberOfSections) {
        fprintf(stderr, "[!] Failed to read section headers\n");
        SAFE_FREE(*sections);
        return RET_ERROR;
    }

    // --- Validation of sections ---
    for (int i = 0; i < numberOfSections; i++) {
        PIMAGE_SECTION_HEADER sec = &(*sections)[i];

        char secName[9] = {0};
        memcpy(secName, sec->Name, 8);
        secName[8] = '\0';

        // Zero raw size
        if (sec->SizeOfRawData == 0) {
            REPORT_MALFORMED("Section has zero raw size", secName);
        }

        else if (sec->SizeOfRawData > fileSize) {
            REPORT_MALFORMED("Section raw size exceeds file size (invalid or corrupted section)", secName);
        }

        // Packed section: VirtualSize=0 but raw data exists
        if (sec->Misc.VirtualSize == 0 && sec->SizeOfRawData > 0) {
            REPORT_MALFORMED("VirtualSize=0 but raw data exists (possible packed section)", secName);
        }
    }

    return RET_SUCCESS;
}

void* parse_table_from_rva(
    FILE *peFile, DWORD rva, DWORD elementSize, DWORD count,
    PIMAGE_SECTION_HEADER sections, WORD numberOfSection) {

    DWORD fileOffset;
    if (rva_to_offset(rva, sections, numberOfSection, &fileOffset)) {
        fprintf(stderr, "[!!] failed to map RVA %08lX\n", rva);
        return NULL;
    }

    if (FSEEK64(peFile, fileOffset, SEEK_SET) != 0) {
        fprintf(stderr, "[!!] failed to seek to RVA %08lX\n", rva);
        return NULL;
    }

    void *array = calloc(count, elementSize);
    if (!array) {
        perror("[!!] calloc failed");
        return NULL;
    }

    if (fread(array, elementSize, count, peFile) != count) {
        fprintf(stderr, "[!!] failed to read table at RVA %08lX\n", rva);
        SAFE_FREE(array);
        return NULL;
    }

    return array;
}

void* parse_table_from_fo(FILE *peFile, DWORD fo, DWORD elementSize, DWORD count) {

    if (FSEEK64(peFile, fo, SEEK_SET) != 0) {
        fprintf(stderr, "[!!] failed to seek to file offset %08lX\n", fo);
        return NULL;
    }

    void *array = calloc(count, elementSize);
    if (!array) {
        perror("[!!] calloc failed");
        return NULL;
    }

    if (fread(array, elementSize, count, peFile) != count) {
        fprintf(stderr, "[!!] failed to read table at file offset %08lX\n", fo);
        SAFE_FREE(array);
        return NULL;
    }

    return array;
}

ULONGLONG fill_entries(
    FILE *peFile, PIMAGE_SECTION_HEADER sections, WORD numberOfSections,
    DWORD rvaBase, DWORD sizeInBytes, void *entriesBuffer, WORD entrySize) {

    if (!peFile || !entriesBuffer || entrySize == 0) return 0;

    DWORD foBase = 0;
    if (rva_to_offset(rvaBase, sections, numberOfSections, &foBase))
        return 0;

    DWORD maxEntries = sizeInBytes / entrySize;

    if (FSEEK64(peFile, foBase, SEEK_SET) != 0) return 0;

    ULONGLONG readCount = fread(entriesBuffer, entrySize, maxEntries, peFile);
    return readCount;
}

ULONGLONG read_unicode_string(const UCHAR *data, WCHAR *out, ULONGLONG max_chars) {
    ULONGLONG i = 0;

    // Read UTF-16LE characters until null or max_chars
    while (i < max_chars - 1) {
        USHORT ch = (USHORT)(data[i * 2] | (data[i * 2 + 1] << 8));

        if (ch == 0x0000) {
            out[i] = L'\0';
            i++;
            break;
        }

        out[i++] = (WCHAR)ch;
    }

    // Ensure null-termination even if no null found
    if (i == max_chars - 1)
        out[i] = L'\0';

    return i * 2;
}

// ===== Data Directory Parsers ===== *** NOT FINISHED YET ***

RET_CODE parse_export_table(
    FILE *peFile, PIMAGE_DATA_DIRECTORY dataDir, PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections, PIMAGE_EXPORT_DIRECTORY *exportDir) {

    if (!peFile || !dataDir) {
        fprintf(stderr, "[!!] Invalid arguments (no PE file or data directory)\n");
        return RET_INVALID_PARAM;
    }

    // Convert the RVA of the export directory into a raw file offset
    DWORD expDirOffset;
    if (rva_to_offset(dataDir->VirtualAddress, sections, numberOfSections, &expDirOffset)) {
        fprintf(stderr, "[!!] failed to map Export Directory RVA to file offset\n");
        return RET_ERROR;        
    }

    // Allocate zero-initialized memory for the export directory structure
    *exportDir = calloc(1, sizeof(IMAGE_EXPORT_DIRECTORY));
    if (!*exportDir) {
        fprintf(stderr, "[!!] calloc for Export Directory failed\n");
        return RET_ERROR;
    }

    // Seek to the export directory offset inside the file
    if (FSEEK64(peFile, expDirOffset, SEEK_SET) != 0) {
        fprintf(stderr, "[!!] fseek failed\n");
        SAFE_FREE(*exportDir);
        *exportDir = NULL;
        return RET_ERROR;
    }

    // Read the IMAGE_EXPORT_DIRECTORY structure from the file into memory
    if (fread(*exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), 1, peFile) != 1) {
        fprintf(stderr, "[!!] failed to read Export Directory structure\n");
        SAFE_FREE(*exportDir);
        *exportDir = NULL;
        return RET_ERROR;        
    }

    return RET_SUCCESS;
}

RET_CODE parse_import_table(
    FILE *peFile, PIMAGE_DATA_DIRECTORY dataDir, PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections, PIMAGE_IMPORT_DESCRIPTOR *importDir) {

    if (!dataDir || !peFile) {
        fprintf(stderr, "[!!] Invalid arguments (no PE file or data directory)\n");
        return RET_INVALID_PARAM;
    }

    DWORD ImpdirOffset;
    if (rva_to_offset(dataDir->VirtualAddress, sections, numberOfSections, &ImpdirOffset)) {
        fprintf(stderr, "[!!] failed to map Import Directory RVA\n");
        return RET_ERROR;
    }

    if (FSEEK64(peFile, ImpdirOffset, SEEK_SET) != 0) return 1;

    IMAGE_IMPORT_DESCRIPTOR tmp;
    ULONGLONG count = 0;

    // Count import descriptors
    while (fread(&tmp, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, peFile) == 1) {
        if (tmp.OriginalFirstThunk == 0 && tmp.FirstThunk == 0) break;
        count++;
    }

    // Allocate array of structs
    *importDir = calloc(count + 1, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    if (!*importDir) {
        fprintf(stderr, "[!!] calloc Import Directory failed\n");
        return RET_ERROR;
    }

    // Go back to start and read descriptors
    if (FSEEK64(peFile, ImpdirOffset, SEEK_SET) != 0) return 1;
    if (fread(*importDir, sizeof(IMAGE_IMPORT_DESCRIPTOR), count, peFile) != count) {
        fprintf(stderr, "[!!] failed to read Import Descriptors\n");
        SAFE_FREE(*importDir);
        return RET_ERROR;
    }

    return RET_SUCCESS;
}

RET_CODE parse_resource_table(
    FILE *peFile, PIMAGE_DATA_DIRECTORY dataDir, PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections, PIMAGE_RESOURCE_DIRECTORY *rsrcDir, PIMAGE_RESOURCE_DIRECTORY_ENTRY *rsrcEntriesDir) {

    if (!dataDir || !peFile) {
        fprintf(stderr, "[!!] Invalid arguments (no PE file or data directory)\n");
        return RET_ERROR;
    }

    // Convert the RVA of the resource directory into a raw file offset
    DWORD rsrcDirOffset;
    if (rva_to_offset(dataDir->VirtualAddress, sections, numberOfSections, &rsrcDirOffset)) {
        fprintf(stderr, "[!!] failed to map Resource Directory RVA to file offset\n");
        return RET_ERROR;
    }

    // Allocate zero-initialized memory for the resource directory structure
    *rsrcDir = calloc(1, sizeof(IMAGE_RESOURCE_DIRECTORY));
    if (!*rsrcDir) {
        fprintf(stderr, "[!!] calloc for Resource Directory failed\n");
        return RET_ERROR;
    }

    // Seek to the resource directory offset inside the file
    if (FSEEK64(peFile, rsrcDirOffset, SEEK_SET) != 0) {
        fprintf(stderr, "[!!] fseek failed\n");
        SAFE_FREE(*rsrcDir);
        *rsrcDir = NULL;
        return RET_ERROR;
    }

    // Read the IMAGE_RESOURCE_DIRECTORY structure from the file into memory
    if (fread(*rsrcDir, sizeof(IMAGE_RESOURCE_DIRECTORY), 1, peFile) != 1) {
        fprintf(stderr, "[!!] failed to read Resource Directory structure\n");
        SAFE_FREE(*rsrcDir);
        *rsrcDir = NULL;
        return RET_ERROR;
    }

    // Calculate total number of directory entries
    WORD totalEntries = (*rsrcDir)->NumberOfNamedEntries + (*rsrcDir)->NumberOfIdEntries;
    if (totalEntries > 0) {
        *rsrcEntriesDir = calloc(totalEntries, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
        if (!*rsrcEntriesDir) return 1;

        if (fread(*rsrcEntriesDir, sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), totalEntries, peFile) != totalEntries) {
        fprintf(stderr, "[!!] failed to read Debug Descriptors\n");
        SAFE_FREE(*rsrcDir);
        *rsrcDir = NULL;
        return RET_ERROR;
        }

    } else {
        *rsrcEntriesDir = NULL;
    }


    return RET_SUCCESS;
}

PIMAGE_RESOURCE_DIRECTORY_ENTRY read_resource_dir_entries(FILE *peFile, DWORD dirFO, PWORD outCount) {
    if (!peFile || !outCount) return NULL;

    IMAGE_RESOURCE_DIRECTORY dirHeader;

    if (FSEEK64(peFile, dirFO, SEEK_SET) != 0) return NULL;

    if (fread(&dirHeader, sizeof(dirHeader), 1, peFile) != 1) return NULL;

    WORD totalEntries = dirHeader.NumberOfNamedEntries + dirHeader.NumberOfIdEntries;
    *outCount = totalEntries;

    if (totalEntries == 0) return NULL;

    PIMAGE_RESOURCE_DIRECTORY_ENTRY entries = malloc(totalEntries * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
    if (!entries) return NULL;

    entries = parse_table_from_fo(peFile, dirFO + sizeof(IMAGE_RESOURCE_DIRECTORY), sizeof(IMAGE_RESOURCE_DIRECTORY), totalEntries);
    if (!entries) {    
        SAFE_FREE(entries);
        return NULL;
    }

    return entries;
}

RET_CODE parse_debug_table(
    FILE *peFile, PIMAGE_DATA_DIRECTORY dataDir, PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections, PIMAGE_DEBUG_DIRECTORY *debugDir) {

    if (!dataDir || !peFile) return RET_INVALID_PARAM;

    // Convert the RVA of the Debug Directory into a raw file offset.
    DWORD debugDirOffset;
    if (rva_to_offset(dataDir->VirtualAddress, sections, numberOfSections, &debugDirOffset)) {
        fprintf(stderr, "[!!] Failed to map Debug Directory RVA to file offset\n");
        return RET_ERROR;
    }

    // Move the file pointer to the start of the Debug Directory
    if (FSEEK64(peFile, debugDirOffset, SEEK_SET) != 0) {
        fprintf(stderr, "[!!] fseek to Debug Directory failed\n");
        return RET_ERROR;
    }

    // Calculate the number of IMAGE_DEBUG_DIRECTORY entries
    // The Size field in the Data Directory tells us total bytes for all entries
    DWORD totalEntries = dataDir->Size / sizeof(IMAGE_DEBUG_DIRECTORY);

    // Allocate memory for all debug directory entries
    *debugDir = calloc(totalEntries, sizeof(IMAGE_DEBUG_DIRECTORY));
    if (!*debugDir) {
        fprintf(stderr, "[!!] Memory allocation for Debug Directory failed\n");
        return RET_ERROR;
    }

    // Read all entries from the file into memory
    if (fread(*debugDir, sizeof(IMAGE_DEBUG_DIRECTORY), totalEntries, peFile) != totalEntries) {
        fprintf(stderr, "[!!] Failed to read all Debug Directory entries\n");
        SAFE_FREE(*debugDir);
        *debugDir = NULL;
        return RET_ERROR;   
    }

    return RET_SUCCESS;
}

RET_CODE parse_tls_table(
    FILE *peFile, PIMAGE_DATA_DIRECTORY dataDir, PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections, PIMAGE_TLS_DIRECTORY32 *tls32, PIMAGE_TLS_DIRECTORY64 *tls64, int is64bit) {

    if (!dataDir || !peFile) return RET_INVALID_PARAM;

    if (tls32) *tls32 = NULL;
    if (tls64) *tls64 = NULL;

    // Map TLS RVA to file offset
    DWORD tlsDirOffset;
    if (rva_to_offset(dataDir->VirtualAddress, sections, numberOfSections, &tlsDirOffset)) {
        fprintf(stderr, "[!!] Failed to map TLS Directory RVA to file offset\n");
        return 1;
    }

    // Determine struct size
    DWORD structSize = is64bit ? sizeof(IMAGE_TLS_DIRECTORY64)
                                : sizeof(IMAGE_TLS_DIRECTORY32);

    // Allocate memory for the TLS directory (just 1 struct)
    void *buffer = malloc(structSize);
    if (!buffer) {
        fprintf(stderr, "[!!] Memory allocation failed\n");
        return RET_ERROR;
    }

    // Seek and read the TLS directory
    if (FSEEK64(peFile, tlsDirOffset, SEEK_SET) != 0 ||
        fread(buffer, structSize, 1, peFile) != 1) {
        fprintf(stderr, "[!!] Failed to read TLS Directory\n");
        SAFE_FREE(buffer);
        return RET_ERROR;
    }

    // Assign to output pointers
    if (is64bit && tls64) {
        *tls64 = (PIMAGE_TLS_DIRECTORY64)buffer;
    } else if (!is64bit && tls32) {
        *tls32 = (PIMAGE_TLS_DIRECTORY32)buffer;
    } else {
        // No pointer provided to store result
        SAFE_FREE(buffer);
        return RET_ERROR;
    }

    return RET_SUCCESS;
}

RET_CODE parse_load_config_table(
    FILE *peFile, PIMAGE_DATA_DIRECTORY dataDir, PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections, PIMAGE_LOAD_CONFIG_DIRECTORY32 *loadConfig32, PIMAGE_LOAD_CONFIG_DIRECTORY64 *loadConfig64, int is64bit) {

    if (!dataDir || !peFile) return RET_INVALID_PARAM;


    if (loadConfig32) *loadConfig32 = NULL;
    if (loadConfig64) *loadConfig64 = NULL;

    DWORD lcfgDirOffset;
    if (rva_to_offset(dataDir->VirtualAddress, sections, numberOfSections, &lcfgDirOffset)) {
        fprintf(stderr, "[!!] failed to map Load Config Directory RVA to file offset\n");
        return RET_ERROR;
    }

    DWORD structSize = is64bit ? sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64)
                                : sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32);

    // handle older PE files with shorter Load Config structures
    DWORD readSize = (dataDir->Size < structSize) ? dataDir->Size : structSize;

    void *buffer = calloc(1, structSize);
    if (!buffer) {
        fprintf(stderr, "[!!] calloc for Load Config Directory failed\n");
        return RET_ERROR;
    }

    if (FSEEK64(peFile, lcfgDirOffset, SEEK_SET) != 0) {
        fprintf(stderr, "[!!] fseek failed\n");
        SAFE_FREE(buffer);
        return RET_ERROR;
    }

    if (fread(buffer, readSize, 1, peFile) != 1) {
        fprintf(stderr, "[!!] failed to read Load Config Directory structure\n");
        SAFE_FREE(buffer);
        return RET_ERROR;
    }

    if (is64bit && loadConfig64) {
        *loadConfig64 = (PIMAGE_LOAD_CONFIG_DIRECTORY64)buffer;
    } else if (!is64bit && loadConfig32) {
        *loadConfig32 = (PIMAGE_LOAD_CONFIG_DIRECTORY32)buffer;
    } else {
        // No pointer provided to store result
        SAFE_FREE(buffer);
        return RET_ERROR;
    }

    return RET_SUCCESS;
}

RET_CODE parse_delay_import_table(
    FILE *peFile, PIMAGE_DATA_DIRECTORY dataDir, PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections, PIMAGE_DELAYLOAD_DESCRIPTOR *delayImportDir) {

    if (!dataDir || !peFile) return RET_INVALID_PARAM;

    DWORD delayImpdirOffset;
    if (rva_to_offset(dataDir->VirtualAddress, sections, numberOfSections, &delayImpdirOffset)) {
        fprintf(stderr, "[!!] failed to map Delay Import Directory RVA\n");
        return RET_ERROR;
    }

    if (FSEEK64(peFile, delayImpdirOffset, SEEK_SET) != 0) return 1;

    IMAGE_DELAYLOAD_DESCRIPTOR tmp;
    ULONGLONG count = 0;

    // Count import descriptors
    while (fread(&tmp, sizeof(IMAGE_DELAYLOAD_DESCRIPTOR), 1, peFile) == 1) {
        if (tmp.DllNameRVA != 0 ||
        tmp.ModuleHandleRVA != 0 ||
        tmp.ImportAddressTableRVA != 0 ||
        tmp.ImportNameTableRVA != 0)
        count++;
    }
 
    // Allocate array of structs
    *delayImportDir = calloc(count + 1, sizeof(IMAGE_DELAYLOAD_DESCRIPTOR));
    if (!*delayImportDir) {
        fprintf(stderr, "[!!] calloc Delay Import Directory failed\n");
        return RET_ERROR;
    }

    // Go back to start and read descriptors
    if (FSEEK64(peFile, delayImpdirOffset, SEEK_SET) != 0) return 1;
    if (fread(*delayImportDir, sizeof(IMAGE_DELAYLOAD_DESCRIPTOR), count, peFile) != count) {
        fprintf(stderr, "[!!] failed to read Delay Import Descriptors\n");
        SAFE_FREE(*delayImportDir);
        *delayImportDir = NULL;
        return RET_ERROR;
    }

    return RET_SUCCESS;
}

RET_CODE parse_clr_table(
    FILE *peFile, PIMAGE_DATA_DIRECTORY dataDir, PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections, PIMAGE_COR20_HEADER *clrHeader) {

    if (!dataDir || !peFile) return RET_INVALID_PARAM;
    

    // If CLR header RVA is zero, file is not a .NET assembly
    if (dataDir->VirtualAddress == 0) {
        fprintf(stderr, "[!!] No CLR/.NET Header Directory present\n");
        return RET_ERROR;
    }

    DWORD clrHeaderOffset;
    if (rva_to_offset(dataDir->VirtualAddress, sections, numberOfSections, &clrHeaderOffset)) {
        fprintf(stderr, "[!!] Failed to map CLR/.NET Header Directory RVA\n");
        return RET_ERROR;
    }

    if (FSEEK64(peFile, clrHeaderOffset, SEEK_SET) != 0) {
        fprintf(stderr, "[!!] Failed to seek to CLR header offset\n");
        return RET_ERROR;
    }

    DWORD structSize = sizeof(IMAGE_COR20_HEADER);
    DWORD readSize = (dataDir->Size < structSize) ? dataDir->Size : structSize;

    *clrHeader = calloc(1, structSize);
    if (!*clrHeader) {
        fprintf(stderr, "[!!] calloc for CLR/.NET Header Directory failed\n");
        return RET_ERROR;
    }

    if (fread(*clrHeader, 1, readSize, peFile) != readSize) {
        fprintf(stderr, "[!!] Failed to read CLR/.NET Header Directory\n");
        SAFE_FREE(*clrHeader);
        *clrHeader = NULL;
        return RET_ERROR;
    }

    return RET_SUCCESS;
}

RET_CODE parse_all_data_directories(
    FILE *peFile, PIMAGE_NT_HEADERS32 nt32, PIMAGE_NT_HEADERS64 nt64,
    PEDataDirectories *dirs, PIMAGE_SECTION_HEADER sections, int is64bit) {
        
    PIMAGE_FILE_HEADER headerPtr = is64bit ? &nt64->FileHeader : &nt32->FileHeader;
    PIMAGE_DATA_DIRECTORY dataDirs = is64bit ? nt64->OptionalHeader.DataDirectory : nt32->OptionalHeader.DataDirectory;
    DWORD numDirs = is64bit ? nt64->OptionalHeader.NumberOfRvaAndSizes : nt32->OptionalHeader.NumberOfRvaAndSizes;
    WORD numberOfSections = headerPtr->NumberOfSections;

    int status = 0;

    for (DWORD i = 0; i < numDirs; i++) {
        if (dataDirs[i].VirtualAddress == 0 && i != IMAGE_DIRECTORY_ENTRY_SECURITY) continue;

        switch (i) {
            case IMAGE_DIRECTORY_ENTRY_EXPORT:
                if (parse_export_table(peFile, &dataDirs[i], sections, numberOfSections, &dirs->exportDir)) status = RET_ERROR;
                break;

            case IMAGE_DIRECTORY_ENTRY_IMPORT:
                if (parse_import_table(peFile, &dataDirs[i], sections, numberOfSections, &dirs->importDir)) status = RET_ERROR;
                break;

            case IMAGE_DIRECTORY_ENTRY_RESOURCE:
                if (parse_resource_table(peFile, &dataDirs[i], sections, numberOfSections, &dirs->rsrcDir, &dirs->rsrcEntriesDir)) status = RET_ERROR;
                break;

            // case IMAGE_DIRECTORY_ENTRY_EXCEPTION: // for better easier dumping the parsing is in the dump function itself

            // case IMAGE_DIRECTORY_ENTRY_SECURITY:  // for better easier dumping the parsing is in the dump function itself

            // case IMAGE_DIRECTORY_ENTRY_BASERELOC: // for better easier dumping the parsing is in the dump function itself
            
            case IMAGE_DIRECTORY_ENTRY_DEBUG:
                if (parse_debug_table(peFile, &dataDirs[i], sections, numberOfSections, &dirs->debugDir)) status = RET_ERROR;
                break;

            case IMAGE_DIRECTORY_ENTRY_TLS:
                if (parse_tls_table(peFile, &dataDirs[i], sections, numberOfSections, &dirs->tls32, &dirs->tls64, is64bit)) status = RET_ERROR;
                break;

            case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
                if (parse_load_config_table(peFile, &dataDirs[i], sections, numberOfSections, &dirs->loadConfig32, &dirs->loadConfig64, is64bit)) status = RET_ERROR;
                break;

            // case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:  // for better easier dumping the parsing is in the dump function itself

            // case IMAGE_DIRECTORY_ENTRY_IAT:           // for better easier dumping the parsing is in the dump function itself

            case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
                if (parse_delay_import_table(peFile, &dataDirs[i], sections, numberOfSections, &dirs->delayImportDir)) status = RET_ERROR;
                break;

            case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: // CLR
                if (parse_clr_table(peFile, &dataDirs[i], sections, numberOfSections, &dirs->clrHeader)) status = RET_ERROR;
                break;

            default:
                // Optional: log unknown directory index for debugging
                // printf("Unknown data directory index: %u\n", i);
                break;
        }
    }

    return status;
}

RET_CODE parsePE(PPEContext peCtx) {
    if (!peCtx || !peCtx->fileHandle) {
        fprintf(stderr, "[!] Invalid arguments passed to parsePE\n");
        return RET_ERROR;
    }

    // === DOS HEADER ===
    if (parse_dos_header(peCtx->fileHandle, peCtx->dosHeader) != RET_SUCCESS) {
        fprintf(stderr, "[!] Failed to parse DOS header\n");
        return RET_ERROR;
    }

    // === RICH HEADER ===
    int richHdrStatus = parse_rich_header(
        peCtx->fileHandle,
        0x40,
        (ULONG)peCtx->dosHeader->e_lfanew,
        &peCtx->richHeader
    );

    if (richHdrStatus != RET_SUCCESS) {
        if (richHdrStatus == RET_ERROR) {
            fprintf(stderr, "[!] Failed to parse Rich Header\n");
        } else if (richHdrStatus == RET_NO_VALUE) {
            peCtx->richHeader = NULL;
        }
        // Not fatal — continue parsing
    }

    // === ARCHITECTURE DETECTION ===
    PE_ARCH arch = get_pe_architecture(peCtx->fileHandle);
    if (arch == PE_INVALID) {
        fprintf(stderr, "[!] Unknown PE architecture\n");
        return RET_ERROR;
    }

    peCtx->is64Bit = (arch == PE_64);

    // === NT HEADERS ===
    if (parse_nt_headers(
            peCtx->fileHandle,
            peCtx->nt32,
            peCtx->nt64,
            peCtx->is64Bit,
            (DWORD)peCtx->dosHeader->e_lfanew
        ) != RET_SUCCESS) {
        fprintf(stderr, "[!] Failed to parse NT headers\n");
        return RET_ERROR;
    }

    PIMAGE_FILE_HEADER fileHdr = peCtx->is64Bit
        ? &peCtx->nt64->FileHeader
        : &peCtx->nt32->FileHeader;

    PIMAGE_OPTIONAL_HEADER32 opt32 = peCtx->is64Bit ? NULL : &peCtx->nt32->OptionalHeader;
    PIMAGE_OPTIONAL_HEADER64 opt64 = peCtx->is64Bit ? &peCtx->nt64->OptionalHeader : NULL;

    // === CORE STATE FILL ===
    peCtx->numberOfSections = fileHdr->NumberOfSections;
    peCtx->imageBase        = peCtx->is64Bit ? opt64->ImageBase : opt32->ImageBase;
    peCtx->sizeOfImage      = peCtx->is64Bit ? opt64->SizeOfImage : opt32->SizeOfImage;

    // === SECTION HEADERS ===
    DWORD sectionOffset = (DWORD)(
        (ULONGLONG)peCtx->dosHeader->e_lfanew +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        fileHdr->SizeOfOptionalHeader
    );

    if (parse_section_headers(
            peCtx->fileHandle,
            &peCtx->sections,
            peCtx->numberOfSections,
            sectionOffset,
            peCtx->fileSize
        ) != RET_SUCCESS) {
        fprintf(stderr, "[!] Failed to parse section headers\n");
        return RET_ERROR;
    }

    // === DATA DIRECTORIES ===
    if (parse_all_data_directories(
            peCtx->fileHandle,
            peCtx->nt32,
            peCtx->nt64,
            peCtx->dirs,
            peCtx->sections,
            peCtx->is64Bit
        ) != RET_SUCCESS) {
        fprintf(stderr, "[!] Failed to parse data directories\n");
        return RET_ERROR;
    }

    // === SUCCESS ===
    peCtx->valid = 1;
    return RET_SUCCESS;
}