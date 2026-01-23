#include "../include/struct_io.h"

void initPEContext(FILE *peFile, const char *fileName, PPEContext peCtx) {
    if (!peCtx)
        return;

    memset(peCtx, 0, sizeof(*peCtx));

    // Associate the file handle immediately
    peCtx->fileHandle = peFile;

    // Get and store file size safely
    peCtx->fileSize = (peFile != NULL) ? get_file_size(peFile) : 0;

    // Copy file name/path safely
    if (fileName && *fileName) {
        STRNCPY(peCtx->filePath, fileName);
    } else {
        STRNCPY(peCtx->filePath, "<unknown>");
    }

    // Allocate essential headers
    peCtx->dosHeader = calloc(1, sizeof(IMAGE_DOS_HEADER));
    peCtx->nt32      = calloc(1, sizeof(IMAGE_NT_HEADERS32));
    peCtx->nt64      = calloc(1, sizeof(IMAGE_NT_HEADERS64));
    peCtx->dirs      = calloc(1, sizeof(PEDataDirectories));

    // Optional / dynamic parts
    peCtx->sections   = NULL;
    peCtx->richHeader = NULL;

    // Structural / state defaults
    peCtx->is64Bit          = 0;
    peCtx->valid            = 0;
    peCtx->numberOfSections = 0;
    peCtx->imageBase        = 0;
    peCtx->sizeOfImage      = 0;
}


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


RET_CODE add_section(PFileSectionList list, DWORD offset, DWORD size, const char* name) {
    if (!list || !name) return RET_ERROR;

    // Reallocate if needed
    if (list->count >= list->capacity) {
        WORD newCap = list->capacity ? list->capacity * 2 : 4;
        FileSection *tmp = realloc(list->sections, newCap * sizeof(FileSection));
        if (!tmp) return RET_BUFFER_OVERFLOW; // out-of-memory
        list->sections = tmp;
        list->capacity = newCap;
    }

    // Copy values
    list->sections[list->count].offset = offset;
    list->sections[list->count].size = size;
    list->sections[list->count].endOffset = offset + size;

    size_t nameLen = strlen(name) + 1;
    list->sections[list->count].name = malloc(nameLen);
    if (!list->sections[list->count].name) return RET_ERROR;
    memcpy(list->sections[list->count].name, name, nameLen);

    list->count++;
    return RET_SUCCESS;
}

void fill_pe_sections_manual(PPEContext peCtx, PFileSectionList outList) {
    if (!peCtx || !peCtx->dosHeader || !outList) return;

    // Init output
    outList->sections = NULL;
    outList->count = 0;
    outList->capacity = 0;

    int is64bit = peCtx->is64Bit;
    LONGLONG fileSize = peCtx->fileSize;
    DWORD ntOffset = (DWORD)peCtx->dosHeader->e_lfanew;
    DWORD foOfEntryPoint = 0;

    PIMAGE_NT_HEADERS32 nt32 = peCtx->nt32;
    PIMAGE_NT_HEADERS64 nt64 = peCtx->nt64;
    PIMAGE_SECTION_HEADER sections = peCtx->sections;

    if ((!is64bit && !nt32) || (is64bit && !nt64) || !sections) return;

    PIMAGE_FILE_HEADER fileHdr = is64bit ? &nt64->FileHeader : &nt32->FileHeader;
    WORD numberOfSections = fileHdr->NumberOfSections;

    // --- DOS Header ---
    if (add_section(outList, 0, sizeof(IMAGE_DOS_HEADER), "DOS Header") != RET_SUCCESS) goto cleanup;

    // --- Rich Header ---
    if (peCtx->richHeader) {
        if (add_section(outList, peCtx->richHeader->richHdrOff,
                        peCtx->richHeader->richHdrSize, "RICH Header") != RET_SUCCESS) goto cleanup;
    }

    // --- NT Headers ---
    DWORD ntHeadersSize = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + fileHdr->SizeOfOptionalHeader;

    if (add_section(outList, ntOffset, ntHeadersSize,
                    is64bit ? "NT Headers 64" : "NT Headers 32") != RET_SUCCESS) goto cleanup;

    if (add_section(outList, ntOffset + sizeof(DWORD), sizeof(IMAGE_FILE_HEADER), "File Header") != RET_SUCCESS) goto cleanup;;

    if (add_section(outList, ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER),
                    fileHdr->SizeOfOptionalHeader,
                    is64bit ? "Optional Header 64" : "Optional Header 32") != RET_SUCCESS) goto cleanup;

    // --- Optional Header + Entry Point ---
    DWORD epRva = 0;
    PIMAGE_DATA_DIRECTORY dataDirs = NULL;

    if (is64bit) {
        epRva = nt64->OptionalHeader.AddressOfEntryPoint;
        dataDirs = nt64->OptionalHeader.DataDirectory;
    } else {
        epRva = nt32->OptionalHeader.AddressOfEntryPoint;
        dataDirs = nt32->OptionalHeader.DataDirectory;
    }

    if (epRva && rva_to_offset(epRva, sections, numberOfSections, &foOfEntryPoint) != RET_SUCCESS)
        foOfEntryPoint = 0;

    // --- Sections ---
    DWORD lastSectionEnd = 0;
    DWORD maxOffset = 0;

    for (WORD i = 0; i < numberOfSections; i++) {
        char secName[64] = {0};
        // ensure null termination
        STRNCPY(secName, (char*)sections[i].Name);
        strncat(secName, " section", sizeof(secName) - strlen(secName) - 1);


        DWORD secStart = sections[i].PointerToRawData;
        DWORD secSize  = sections[i].SizeOfRawData;
        DWORD secEnd   = secStart + secSize;

        // Entry point marker
        if (foOfEntryPoint >= secStart && foOfEntryPoint < secEnd) {
            DWORD epSize = (secEnd - foOfEntryPoint > 16) ? 16 : (secEnd - foOfEntryPoint);
            if (add_section(outList, foOfEntryPoint, epSize, "Entry Point") != RET_SUCCESS) goto cleanup;
            strncat(secName, " * Entry Point", sizeof(secName) - strlen(secName) - 1);
        }

        if (add_section(outList, secStart, secSize, secName) != RET_SUCCESS) goto cleanup;

        if (secEnd > lastSectionEnd) lastSectionEnd = secEnd;
        if (secEnd > maxOffset) maxOffset = secEnd;
    }

    // --- Data Directories ---
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

            snprintf(name, sizeof(name), "%s %s",
                     get_data_directory_name(i),
                     needsDirectorySuffix ? "Directory" : "");

            if (i == IMAGE_DIRECTORY_ENTRY_SECURITY) {
                DWORD secOff = dataDirs[i].VirtualAddress;
                if (secOff >= (ULONG)fileSize) continue;

                DWORD usable = (dirSize > (ULONG)fileSize - secOff)
                                 ? ((ULONG)fileSize - secOff)
                                 : dirSize;
                if (add_section(outList, secOff, usable, name) != RET_SUCCESS) goto cleanup;
                endOffset = secOff + usable;
            } else {
                if (rva_to_offset(dataDirs[i].VirtualAddress, sections,
                                  numberOfSections, &fo) != RET_SUCCESS ||
                    fo >= (ULONG)fileSize)
                    continue;

                DWORD usable = (dirSize > (ULONG)fileSize - fo)
                                 ? ((ULONG)fileSize - fo)
                                 : dirSize;
                if (add_section(outList, fo, usable, name) != RET_SUCCESS) goto cleanup;
                endOffset = fo + usable;
            }

            if (endOffset > maxOffset) maxOffset = endOffset;
        }
    }

    // --- Overlay detection ---
    if ((ULONG)fileSize > lastSectionEnd) {
        add_section(outList, lastSectionEnd, (ULONG)fileSize - lastSectionEnd,
                    "Overlay (after last section)");
    }
    if ((ULONG)fileSize > maxOffset && maxOffset != lastSectionEnd) {
        add_section(outList, maxOffset, (ULONG)fileSize - maxOffset,
                    "Overlay (after all data)");
    }

    return;

cleanup:
    free_sections(outList);
    return;
}

void free_sections(PFileSectionList list) {
    if (!list) return;

    if (list->sections) {
        for (WORD i = 0; i < list->count; i++) {
            SAFE_FREE(list->sections[i].name);  // only free allocated memory
        }
        SAFE_FREE(list->sections);
    }
}


void freePEDataDirectories(PEDataDirectories *dirs) {
    if (!dirs) return;

    SAFE_FREE(dirs->exportDir);
    SAFE_FREE(dirs->importDir);
    SAFE_FREE(dirs->rsrcDir);
    SAFE_FREE(dirs->rsrcEntriesDir);
    SAFE_FREE(dirs->debugDir);
    SAFE_FREE(dirs->tls32);
    SAFE_FREE(dirs->tls64);
    SAFE_FREE(dirs->loadConfig32);
    SAFE_FREE(dirs->loadConfig64);
    SAFE_FREE(dirs->delayImportDir);
    SAFE_FREE(dirs->clrHeader);
}

void freePEContext(PPEContext peContext) {
    if (!peContext)
        return;

    if (peContext->dirs) {
        freePEDataDirectories(peContext->dirs);
        SAFE_FREE(peContext->dirs);
    }

    SAFE_FREE(peContext->dosHeader);
    if (peContext->richHeader)
        SAFE_FREE(peContext->richHeader->Entries);
    SAFE_FREE(peContext->richHeader);
    SAFE_FREE(peContext->nt32);
    SAFE_FREE(peContext->nt64);
    SAFE_FREE(peContext->sections);

    peContext->numberOfSections = 0;
    peContext->imageBase = 0;
    peContext->sizeOfImage = 0;
    peContext->is64Bit = 0;
    peContext->valid = 0;

    memset(peContext->filePath, 0, sizeof(peContext->filePath));
}
