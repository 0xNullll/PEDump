#include "include/pe_parser.h"
#include "include/file_defs.h"
#include "include/struct_io.h"
#include "include/cmds.h"

int main(void) {

    // Fake argc/argv
    int argc = 5;
    char *argv[] = {
        "PEdump", // argv[0] = program name
        // "-h",
        // "C:\\Users\\agent\\OneDrive\\Desktop\\pe_dumper\\src\\test2.exe",
        // "C:/Users/agent/AppData/Local/FiveM/FiveM.exe",
        "-H",
        // "-x",
        "section:.text",
        // "--strings",
        // "rgex:.*\\.exe",
        // "-x",
        // "export:NTDLL.RtlAcquireSRWLockExclusive",
        // "import:@4",
        // "-h",
        "C:\\Windows\\System32\\kernel32.dll", // argv[1] = test subject,
        NULL
    };

    if (isHelpCmd(argv[1])) {
        print_help();
        return RET_SUCCESS;
    }

    if (!isCmdValid(argc)) {
        perror("Error invalid command file\n");
        return RET_ERROR;
    }

    char *fileName = argv[argc - 2]; 

    FILE *peFile = fopen(fileName, "rb");
    if (!peFile) {
        perror("Error opening file");
        return 1;
    }

    PEContext peCtx;
    initPEContext(peFile, fileName, &peCtx);

    int status = RET_SUCCESS;

    if (!isPE(peFile)) {
        fprintf(stderr, "[!] File is not a valid PE\n");
        status = RET_ERROR;
        goto cleanup;
    }

    if (parsePE(&peCtx) != RET_SUCCESS) {
        fprintf(stderr, "[!] Failed to parse PE\n");
        status = RET_ERROR;
        goto cleanup;
    }

    if (handle_commands(argc, argv, &peCtx) != RET_SUCCESS) {
        fprintf(stderr, "[!] Invalid command\n");
        status = RET_ERROR;
        goto cleanup;    
    }

    // If you reach here, parsing succeeded
    printf("PE parsing completed successfully.\n");

cleanup:
    freePEContext(&peCtx);
    fclose(peFile);
    return status;
}
