#include "include/pe_parser.h"
#include "include/file_defs.h"
#include "include/struct_io.h"
#include "include/cmds.h"

int main(void) {

    // Fake argc/argv
    int argc = 4;
    char *argv[] = {
        "PEdump", // argv[0] = program name
        // "-h",
        // "C:\\Users\\agent\\OneDrive\\Desktop\\pe_dumper\\src\\test2.exe",
        // "C:/Users/agent/AppData/Local/FiveM/FiveM.exe",
        // "-x",
        // "import:ntdll.dll",
        // "-ov",
        "-e",
        // "file@sha512_224",
        // "file::file@sha512",
        // "section:.text::section:.text",
        // "--strings",
        // "rgex:.*\\.exe",
        // "-x",
        // "export:NTDLL.RtlAcquireSRWLockExclusive",
        // "import:@4",
        // "-h",
        // "C:\\Windows\\System32\\kernel32.dll", // argv[1] = test subject,
        "C:\\Users\\agent\\OneDrive\\Desktop\\CryptoForge\\bin\\run_all_demos.exe",
        // "C:/Program Files/CrystalDiskMark9/unins000.exe",
        NULL
    };

    if (isHelpCmd(argv[1])) {
        print_help();
        return RET_SUCCESS;
    }

    if (!isCmdValid(argc)) {
        perror("[!] invalid command file\n");
        return RET_ERROR;
    }

    char *fileName = argv[argc - 2]; 

    FILE *peFile = NULL;
    PPEContext peCtx = NULL;
    int status = RET_SUCCESS;

    status = loadPEContext(fileName, &peCtx, &peFile);
    if (status != RET_SUCCESS) {
        fprintf(stderr, "[!] Failed to load PE context from file: %s\n", fileName);
        return status;
    }

    // Now just handle your logic
    status = handle_commands(argc, argv, peCtx);
    if (status != RET_SUCCESS) {
        fprintf(stderr, "[!] Invalid command\n");
        goto cleanup;
    }

    // for debuging
    printf("PE parsing completed successfully.\n");

cleanup:
    freePEContext(peCtx);
    fclose(peFile);
    return status;
}