#include "include/pe_parser.h"
#include "include/file_defs.h"
#include "include/struct_io.h"
#include "include/cmds.h"

int main(int argc, char *argv[]) {
    // Check for at least one argument before accessing argv[1]
    if (argc > 1 && isHelpCmd(argv[1])) {
        print_help();
        return RET_SUCCESS;
    }

    // Ensure there are enough arguments
    if (argc < 2) {
        fprintf(stderr, "[!] Not enough arguments. Expected file name.\n");
        return RET_ERROR;
    }

    char *fileName = argv[argc - 1];  // The first-to-last argument is the file name

    FILE *peFile = NULL;
    PPEContext peCtx = NULL;
    int status = RET_SUCCESS;

    // Load PE context
    status = loadPEContext(fileName, &peCtx, &peFile);
    if (status != RET_SUCCESS) {
        fprintf(stderr, "[!] Failed to load PE context from file: %s\n", fileName);
        return status;
    }

    // Handle commands
    status = handle_commands(argc, argv, peCtx);
    if (status != RET_SUCCESS) {
        fprintf(stderr, "[!] Invalid command\n");
        goto cleanup;
    }

    // For debugging
    // printf("PE parsing completed successfully.\n");
    fflush(stdout);
    
cleanup:
    // Cleanup resources safely
    if (peCtx) {
        freePEContext(peCtx);
    }
    if (peFile) {
        fclose(peFile);
    }
    return status;
}
