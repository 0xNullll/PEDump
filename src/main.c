#include "include/pe_parser.h"
#include "include/file_defs.h"
#include "include/struct_io.h"
#include "include/cmds.h"

int main(void) {

    // Fake argc/argv
    int argc = 5;
    char *argv[] = {
        "pe_parser", // argv[0] = program name
        // "C:\\Users\\agent\\OneDrive\\Desktop\\pe_dumper\\src\\test2.exe",
        "C:\\Windows\\System32\\kernel32.dll", // argv[1] = test subject,
        // "C:/Users/agent/AppData/Local/FiveM/FiveM.exe",
        // "-e",
        // "--strings",
        // "rgex:.*\\.exe",
        "-x",
        // "export:NTDLL.RtlAcquireSRWLockExclusive",
        "import:@4",
        // "-h",
        NULL
    };

    // int argc = 3;
    // char *argv[] = {
    //     "pe_parser", // argv[0] = program name
    //     // "C:\\Users\\agent\\OneDrive\\Desktop\\pe_dumper\\src\\test2.exe",
    //     "C:\\Users\\agent\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
    //     // "C:\\Windows\\System32\\kernel32.dll", // argv[1] = test subject
    //     "-i",
    //     NULL
    // };

    // int argc = 9;
    // char *argv[] = {
    //     "pe_parser", // argv[0] = program name
    //     "C:\\Windows\\System32\\kernel32.dll", // argv[1] = test subject
    //     // "C:\\Users\\agent\\OneDrive\\Desktop\\pe_dumper\\src\\test2.exe",
    //     "-f",
    //     "hex:0x200,0x405",
    //     "-a",
    //     "-f",
    //     "hex:-5,5",
    //     "-a",
    //     NULL
    // };

    if (isHelpCmd(argv[1])) {
        print_help();
        return RET_SUCCESS;
    }

    if (!isCmdValid(argc)) {
        perror("Error invalid command file\n");
        return RET_ERROR;
    }

    char *file_name = argv[1]; 

    // C:\\Windows\\System32\\kernel32.dll
    // C:\\Users\\agent\\AppData\\Local\\Roblox\\Versions\\RobloxStudioInstaller.exe
    // C:\\Users\\agent\\AppData\\Local\\Roblox\\Versions\\version-c1ac69007bdc4e48\\RobloxPlayerBeta.exe
    // C:\\Program Files\\Bridge\\Bridge.exe
    // C:\\Windows\\System32\\drivers\\adp80xx.sys
    // C:\\Users\\agent\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe
    // C:\\Users\\agent\\AppData\\Local\\osu!\\osu!.exe
    // char *file_name = "C:\\Windows\\System32\\kernel32.dll"; // test subject
    FILE *peFile = fopen(file_name, "rb");
    if (!peFile) {
        perror("Error opening file");
        return 1;
    }

    int is64bit;
    IMAGE_DOS_HEADER dosHeader;
    PIMAGE_RICH_HEADER richHeader = NULL;
    IMAGE_NT_HEADERS32 nt32 = {0};
    IMAGE_NT_HEADERS64 nt64 = {0};
    PIMAGE_SECTION_HEADER sections = NULL;
    PEDataDirectories dirs = {0}; // initialize all pointers to NULL

    int status = RET_SUCCESS;

    if (!isPE(peFile)) {
        fprintf(stderr, "[!] File is not a valid PE\n");
        status = RET_ERROR;
        goto cleanup;
    }

    if (parsePE(peFile, &dosHeader, &richHeader, &nt32, &nt64, &sections, &dirs, &is64bit) != RET_SUCCESS) {
        fprintf(stderr, "[!] Failed to parse PE\n");
        status = RET_ERROR;
        goto cleanup;
    }

    if(handle_commands(argc, argv, peFile, &dosHeader, richHeader, &nt32, &nt64, sections, &dirs, is64bit) != RET_SUCCESS) {
        fprintf(stderr, "[!] Invalid command\n");
        status = RET_ERROR;
        goto cleanup;
    }

    // If you reach here, parsing succeeded
    printf("PE parsing completed successfully.\n");

    cleanup:
    if (sections) {
        SAFE_FREE(sections);
        sections = NULL;
    }

    if (richHeader) {
        SAFE_FREE(richHeader);
        richHeader = NULL;        
    }

    freePEDataDirectories(&dirs);
    
    fclose(peFile);
    return status;
}
