#include "../include/dump_raw.h"

void print_range_dump_header(DWORD start, DWORD size, int dumpWidthBytes) {
    printf("\n[+] Dump\n");
    printf("    Start offset : 0x%08lX\n", start);
    printf("    End offset   : 0x%08lX\n", start + size - 1);
    printf("    Size         : 0x%08lX (%u bytes)\n", size, (unsigned)size);
    printf("    Bytes/line   : %d\n\n", dumpWidthBytes);
}

RET_CODE print_range(
    FILE* peFile,
    DWORD startOffset,
    DWORD sizeInByte,
    LONGLONG fileSize,
    PFormatConfig formatConfig,
    PFileSectionList fileSectionList,
    BYTE printHdr) {
    if (!peFile || sizeInByte == 0 || startOffset >= (DWORD)fileSize)
        return RET_INVALID_PARAM;

    // clamp sizeInByte to the actual remaining file size
    if (startOffset + sizeInByte > (DWORD)fileSize)
        sizeInByte = (DWORD)fileSize - startOffset;

    PBYTE rawByte = malloc(sizeInByte);
    if (!rawByte) return RET_ERROR;

    if (FSEEK64(peFile, (LONGLONG)startOffset, SEEK_SET) != 0 ||
        fread(rawByte, 1, sizeInByte, peFile) != sizeInByte) {
        SAFE_FREE(rawByte);
        return RET_ERROR;
    }

    int multiNum = (formatConfig->view == VIEW_HEX) ? 3 : // defualt
                   (formatConfig->view == VIEW_DEC) ? 4 :
                   (formatConfig->view == VIEW_BIN) ? 4 : 3;

    const char* formatName = (formatConfig->view == VIEW_HEX) ? "HEX BYTES" : // defualt
                             (formatConfig->view == VIEW_DEC) ? "DECIMAL BYTES" :
                             (formatConfig->view == VIEW_BIN) ? "BINARY BYTES" : "HEX BYTES";

    // -----------------------------
    // Compute preview start offset and size
    // -----------------------------
    DWORD previewStartOffset = startOffset;
    DWORD previewSizeBytes = sizeInByte;
    DWORD dumpWidthBytes = (formatConfig->view == VIEW_BIN) ? BYTES_PER_LINE / 2 : BYTES_PER_LINE;

    // ----------- START OFFSET -----------
    if (formatConfig->startIsLine) {
        // Line-based
        if (formatConfig->startLine > 0) {
            DWORD forwardOffset = (DWORD)formatConfig->startLine * dumpWidthBytes;
            if (forwardOffset < sizeInByte)
                previewStartOffset = startOffset + forwardOffset;
            // else keep original start
        } else if (formatConfig->startLine < 0) {
            DWORD backOffset = llabs(formatConfig->startLine) * dumpWidthBytes;
            if (backOffset < sizeInByte)
                previewStartOffset = startOffset + sizeInByte - backOffset;
            // else keep original start
        }
    } else {
        // Hex/absolute offset
        LONG hexStart = formatConfig->startLine; // already in bytes
        if (hexStart < 0) hexStart = 0;           // clamp negative
        if ((DWORD)hexStart <= sizeInByte)
            previewStartOffset = startOffset + (DWORD)hexStart;
        else
            previewStartOffset = startOffset + sizeInByte; // clamp to end
    }

    // ----------- PREVIEW SIZE -----------
    if (formatConfig->endIsLine) {
        // Line-based maxLine
        if (formatConfig->maxLine != 0) {
            DWORD requestedBytes = llabs(formatConfig->maxLine) * dumpWidthBytes;

            if (formatConfig->maxLine < 0 && formatConfig->startLine == 0) {
                // last N lines
                if (requestedBytes > sizeInByte) requestedBytes = sizeInByte;
                previewStartOffset = startOffset + sizeInByte - requestedBytes;
                previewSizeBytes = requestedBytes;
            } else {
                // positive maxLine -> limit lines after start
                if (requestedBytes > previewStartOffset + sizeInByte - startOffset)
                    requestedBytes = previewStartOffset + sizeInByte - startOffset;
                previewSizeBytes = requestedBytes;
            }
        } else {
            // maxLine == 0 -> dump everything after start
            previewSizeBytes = startOffset + sizeInByte - previewStartOffset;
        }
    } else {
        // Hex/offset mode: maxLine counts bytes after start
        if (formatConfig->maxLine > 0) {
            if ((DWORD)formatConfig->maxLine <= startOffset + sizeInByte - previewStartOffset)
                previewSizeBytes = (DWORD)formatConfig->maxLine;
            else
                previewSizeBytes = startOffset + sizeInByte - previewStartOffset; // clamp
        }
    }

    // Finally, clamp to file size just in case
    if (previewStartOffset + previewSizeBytes > (DWORD)fileSize)
        previewSizeBytes = (DWORD)fileSize - previewStartOffset;

    if (printHdr) {
        print_range_dump_header(previewStartOffset, previewSizeBytes, (int)dumpWidthBytes);
    }

    int finalHeaderOff = BYTES_PER_LINE * multiNum + 5 + (formatConfig->view == VIEW_BIN ? 6 : 0);
    printf("%-13s%-*s%-*s%s\n", "ADDR", finalHeaderOff, formatName, (int)dumpWidthBytes + 3, "ASCII", "NAME");

    // -----------------------------
    // Dump loop
    // -----------------------------
    DWORD lineOff = previewStartOffset;
    DWORD endOffset = previewStartOffset + previewSizeBytes;
    LONG printedLines = 0;

    for (DWORD i = previewStartOffset; i < endOffset; i += dumpWidthBytes) {
        // compute remaining bytes for this line
        DWORD remaining = endOffset - i;
        if (remaining == 0) break;

        DWORD lineSize = (remaining >= dumpWidthBytes) ? dumpWidthBytes : remaining;

        // stop if maxLine limit reached
        if (formatConfig->maxLine != 0 && printedLines >= formatConfig->maxLine)
            break;

        // print address
        printf("0x%08lX   ", lineOff);

        // print bytes
        for (DWORD j = 0; j < dumpWidthBytes; j++) {
            if (j < lineSize) {
                unsigned char byte = rawByte[i - startOffset + j];
                switch (formatConfig->view) {
                    case VIEW_HEX: printf("%02X ", byte); break;
                    case VIEW_DEC: printf("%03u ", byte); break;
                    case VIEW_BIN:
                        for (int b = 7; b >= 0; b--)
                            putchar((byte & (1 << b)) ? '1' : '0');
                        putchar(' ');
                        break;

                    default: printf("%02X ", byte); break;

                }
            } else {
                // pad if line shorter than dumpWidthBytes
                switch (formatConfig->view) {
                    case VIEW_HEX: printf("   "); break;
                    case VIEW_DEC: printf("    "); break;
                    case VIEW_BIN: printf("         "); break;

                    default: printf("   "); break;
                }
            }
            if ((j + 1) % 4 == 0) putchar(' ');
        }

        // ASCII column
        printf(" |");
        for (DWORD j = 0; j < lineSize; j++) {
            unsigned char byte = rawByte[i - startOffset + j];
            putchar(IS_PRINTABLE(byte) ? byte : NONPRINT_CHAR);
        }
        for (DWORD j = lineSize; j < dumpWidthBytes; j++) putchar(' ');

        printf("|");

        if (fileSectionList->count) {
            for (WORD j = 0; j < fileSectionList->count; j++) {
                
                // Only consider sections that are within the range of this dump
                if (fileSectionList->sections[j].offset >= previewStartOffset && fileSectionList->sections[j].offset < endOffset) {

                    DWORD lineStartOff = (fileSectionList->sections[j].offset / dumpWidthBytes) * dumpWidthBytes;
                    DWORD currentLineStartOff = (lineOff / dumpWidthBytes) * dumpWidthBytes; 

                    if (lineStartOff == currentLineStartOff) {
                        printf(" * %s", fileSectionList->sections[j].name);
                    }
                }
            }
        }
        printf("\n");

        printedLines++;
        lineOff += dumpWidthBytes;

        if (printedLines % 100 == 0) {
           fflush(stdout);
        } 
    }

    fflush(stdout);

    SAFE_FREE(rawByte);

    return RET_SUCCESS;
}

RET_CODE dump_all_data_directories_raw(
    FILE *peFile,
    PIMAGE_SECTION_HEADER sections,
    WORD numberOfSections,
    PIMAGE_DATA_DIRECTORY dataDirs,
    LONGLONG fileSize,
    PFormatConfig formatConfig,
    PFileSectionList fileSectionList) {

    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {

        PIMAGE_DATA_DIRECTORY dir = &dataDirs[i];
        if (!dir->VirtualAddress || !dir->Size)
            continue;

        DWORD fileOffset;

        // IMAGE_DIRECTORY_ENTRY_SECURITY uses raw file offset instead of RVA
        if (i != IMAGE_DIRECTORY_ENTRY_SECURITY) {
            if (rva_to_offset(dir->VirtualAddress, sections, numberOfSections, &fileOffset) != RET_SUCCESS) {
                fprintf(stderr, "[!!] Failed to map file offset for data directory #%d\n", i + 1);
                continue;
            }
        } else {
            fileOffset = dir->VirtualAddress;
        }

        if (fileOffset == 0xFFFFFFFF)
            continue;

        print_range(peFile, fileOffset, dir->Size, fileSize, formatConfig, fileSectionList, 1);
        END_DIR();
    }

    return RET_SUCCESS;
}