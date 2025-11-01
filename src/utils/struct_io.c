#include "../include/struct_io.h"

void init_match_list(MATCH_LIST *list, ULONGLONG initialCapacity, ULONGLONG itemSize) {
    list->items = malloc(initialCapacity * itemSize);
    list->count = 0;
    list->capacity = initialCapacity;
    list->itemSize = itemSize;
}

RET_CODE ensure_match_capacity(MATCH_LIST *list, ULONGLONG additional) {
    if (list->count + additional > list->capacity) {
        ULONGLONG newCapacity = list->capacity * 2;
        if (newCapacity < list->count + additional)
            newCapacity = list->count + additional;

        void *tmp = realloc(list->items, newCapacity * list->itemSize);
        if (!tmp) return RET_ERROR;

        list->items = tmp;
        list->capacity = newCapacity;
    }
    return RET_SUCCESS;
}

RET_CODE add_match(MATCH_LIST *list, void *match) {
    if (ensure_match_capacity(list, 1) != RET_SUCCESS)
        return RET_ERROR;

    void *target = (char *)list->items + (list->count * list->itemSize);
    memcpy(target, match, list->itemSize);
    list->count++;
    return RET_SUCCESS;
}

void free_match_list(MATCH_LIST *list) {
    SAFE_FREE(list->items);
    list->count = 0;
    list->capacity = 0;
    list->itemSize = 0;
}


void add_section(PFileSectionList list, DWORD offset, DWORD size, const char* name) {
    if (list->count >= list->capacity) {
        list->capacity = list->capacity ? list->capacity * 2 : 4;
        list->sections = realloc(list->sections, list->capacity * sizeof(FileSection));
    }
    list->sections[list->count].offset = offset;
    list->sections[list->count].size = size;
    list->sections[list->count].endOffset = offset + size;
    list->sections[list->count].name = strdup(name); // allocate and copy string
    list->count++;
}

void fill_pe_sections_manual(
    FILE *peFile, PIMAGE_DOS_HEADER dosHeader, PIMAGE_RICH_HEADER richHeader,
    PIMAGE_NT_HEADERS32 nt32, PIMAGE_NT_HEADERS64 nt64, PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections, int is64bit, LONGLONG fileSize, PFileSectionList outList) {
    if (!outList || !dosHeader) return;

    outList->sections = NULL;
    outList->count = 0;
    outList->capacity = 0;

    DWORD ntOffset = (DWORD)dosHeader->e_lfanew;
    PIMAGE_OPTIONAL_HEADER32 opt32 = NULL;
    PIMAGE_OPTIONAL_HEADER64 opt64 = NULL;
    DWORD foOfEntryPoint = 0;

    // 1. DOS Header
    add_section(outList, 0, sizeof(IMAGE_DOS_HEADER), "DOS Header");

    // 2. RICH Header
    if (richHeader) {
        add_section(outList, richHeader->richHdrOff, richHeader->richHdrSize, "RICH Header");
    }

    // 3. NT Headers
    DWORD fileHeaderSize     = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    DWORD optionalHeaderSize = is64bit
        ? sizeof(IMAGE_OPTIONAL_HEADER64)
        : sizeof(IMAGE_OPTIONAL_HEADER32);
    DWORD ntHeadersSize = fileHeaderSize + optionalHeaderSize;

    add_section(outList, ntOffset, ntHeadersSize,
                is64bit ? "NT Headers 64" : "NT Headers 32");
    add_section(outList, ntOffset + sizeof(DWORD),
                sizeof(IMAGE_FILE_HEADER), "File Header");
    add_section(outList, ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER),
                optionalHeaderSize,
                is64bit ? "Optional Header 64" : "Optional Header 32");

    // Entry Point
    DWORD epRva = 0;
    if (is64bit && nt64) {
        opt64 = &nt64->OptionalHeader;
        epRva = opt64->AddressOfEntryPoint;
    } else if (!is64bit && nt32) {
        opt32 = &nt32->OptionalHeader;
        epRva = opt32->AddressOfEntryPoint;
    }
    if (epRva &&
        rva_to_offset(epRva, sections, numberOfSections, &foOfEntryPoint) != RET_SUCCESS) {
        foOfEntryPoint = 0;
    }

    // 4. COFF Symbol Table + String Table
    if ((is64bit && nt64) || (!is64bit && nt32)) {
        DWORD pointerToSymbolTable = is64bit
            ? nt64->FileHeader.PointerToSymbolTable
            : nt32->FileHeader.PointerToSymbolTable;
        DWORD numberOfSymbols = is64bit
            ? nt64->FileHeader.NumberOfSymbols
            : nt32->FileHeader.NumberOfSymbols;

        if (pointerToSymbolTable && numberOfSymbols) {
            // Symbol Table
            DWORD symTableSize = numberOfSymbols * sizeof(IMAGE_SYMBOL);
            add_section(outList, pointerToSymbolTable, symTableSize, "COFF Symbol Table");

            // String Table
            DWORD stringTableOffset = pointerToSymbolTable + symTableSize;
            DWORD stringTableSize   = 0;
            if (get_string_table_size(peFile, stringTableOffset, fileSize, &stringTableSize) == RET_SUCCESS &&
                stringTableSize > 0) {
                add_section(outList, stringTableOffset, stringTableSize, "COFF String Table");
            }
        }
    }

    // 5. Sections
    DWORD lastSectionEnd = 0;
    DWORD maxOffset = 0; // for overlay detection

    for (WORD i = 0; i < numberOfSections; i++) {
        char secName[32] = {0};
        strncpy(secName, (char*)sections[i].Name, 8);
        strcat(secName, " section");

        DWORD secStart = sections[i].PointerToRawData;
        DWORD secSize  = sections[i].SizeOfRawData;
        DWORD secEnd   = secStart + secSize;

        // Entry point marker
        if (foOfEntryPoint >= secStart && foOfEntryPoint < secEnd) {
            strcat(secName, " * Entry Point");
            DWORD epSize = (secEnd - foOfEntryPoint > 16) ? 16 : (secEnd - foOfEntryPoint);
            add_section(outList, foOfEntryPoint, epSize, "Entry Point");
        }

        add_section(outList, secStart, secSize, secName);

        if (secEnd > lastSectionEnd) lastSectionEnd = secEnd;
        if (secEnd > maxOffset) maxOffset = secEnd;
    }

    // 6. Data directories
    PIMAGE_DATA_DIRECTORY dataDirs = NULL;
    if (is64bit && opt64) dataDirs = opt64->DataDirectory;
    else if (!is64bit && opt32) dataDirs = opt32->DataDirectory;

    if (dataDirs) {
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
            DWORD dirSize = dataDirs[i].Size;
            if (dirSize == 0) continue;

            DWORD fo = 0, endOffset = 0;
            char name[64];

            BOOL needsDirectorySuffix =
                (i != IMAGE_DIRECTORY_ENTRY_ARCHITECTURE &&
                i != IMAGE_DIRECTORY_ENTRY_GLOBALPTR &&
                i != IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);

            snprintf(name, sizeof(name), "%s %s", get_data_directory_name(i), needsDirectorySuffix ? "Directory" : "");

            if (i == IMAGE_DIRECTORY_ENTRY_SECURITY) {
                DWORD secOff = dataDirs[i].VirtualAddress; // this is a file offset
                if (secOff >= (ULONG)fileSize) continue;

                DWORD usable = (dirSize > (ULONG)fileSize - secOff) ? ((ULONG)fileSize - secOff) : dirSize;
                add_section(outList, secOff, usable, name);
                endOffset = secOff + usable;
            } else {
                if (rva_to_offset(dataDirs[i].VirtualAddress, sections, numberOfSections, &fo) != RET_SUCCESS ||
                    fo >= (ULONG)fileSize) continue;

                DWORD usable = (dirSize > (ULONG)fileSize - fo) ? ((ULONG)fileSize - fo) : dirSize;
                add_section(outList, fo, usable, name);
                endOffset = fo + usable;
            }

            if (endOffset > maxOffset) maxOffset = endOffset;
        }
    }

    // 7. Overlay detection
    if ((ULONG)fileSize > lastSectionEnd) {
        add_section(outList, lastSectionEnd, (ULONG)fileSize - lastSectionEnd, "Overlay (after last section)");
    }
    if ((ULONG)fileSize > maxOffset && maxOffset != lastSectionEnd) {
        add_section(outList, maxOffset, (ULONG)fileSize - maxOffset, "Overlay (after all data)");
    }
}

void free_sections(PFileSectionList list) {
    for (WORD i = 0; i < list->count; i++) {
        SAFE_FREE(list->sections[i].name);
    }
    SAFE_FREE(list->sections);
}


void freePEDataDirectories(PEDataDirectories *dirs) {
    if (!dirs) return;

    if (dirs->exportDir) {
        SAFE_FREE(dirs->exportDir);
        dirs->exportDir = NULL;
    }

    if (dirs->importDir) {
        SAFE_FREE(dirs->importDir);
        dirs->importDir = NULL;
    }

    if (dirs->rsrcDir) {
        SAFE_FREE(dirs->rsrcDir);
        dirs->rsrcDir = NULL;
    }

    if (dirs->rsrcEntriesDir) {
        SAFE_FREE(dirs->rsrcEntriesDir);
        dirs->rsrcEntriesDir = NULL;
    }

    if (dirs->debugDir) {
        SAFE_FREE(dirs->debugDir);
        dirs->debugDir = NULL;
    }

    if (dirs->tls32) {
        SAFE_FREE(dirs->tls32);
        dirs->tls32 = NULL;
    }

    if (dirs->tls64) {
        SAFE_FREE(dirs->tls64);
        dirs->tls64 = NULL;
    }

    if (dirs->loadConfig32) {
        SAFE_FREE(dirs->loadConfig32);
        dirs->loadConfig32 = NULL;
    }

    if (dirs->loadConfig64) {
        SAFE_FREE(dirs->loadConfig64);
        dirs->loadConfig64 = NULL;
    }

    if (dirs->delayImportDir) {
        SAFE_FREE(dirs->delayImportDir);
        dirs->delayImportDir = NULL;
    }

    if (dirs->clrHeader) {
        SAFE_FREE(dirs->clrHeader);
        dirs->clrHeader = NULL;
    }
}
