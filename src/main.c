#include "include/pe_parser.h"
#include "include/file_defs.h"
#include "include/struct_io.h"
#include "include/cmds.h"

int main(int argc, char *argv[]) {
    // If no arguments, or first argument is a help command, print help
    if (argc < 2 || isHelpCmd(argv[1])) {
        print_help();
        return RET_SUCCESS;
    }

    char *fileName = argv[argc - 1];  // last argument is the file name

    FILE *peFile = NULL;
    PPEContext peCtx = NULL;
    int status = RET_SUCCESS;

    // Load PE context
    status = loadPEContext(fileName, &peCtx, &peFile);
    if (status != RET_SUCCESS) {
        fprintf(stderr, "[!] Failed to load PE context from file: %s\n", fileName);

    peFile = fopen(fileName, "rb");
        if (!peFile) {
            fprintf(stderr, "[!] You must provide a valid file name to open: %s\n", fileName);
            return RET_ERROR;
        }
        fclose(peFile);  // close after validation
        return status;
    }

    // Handle commands
    status = handle_commands(argc, argv, peCtx);
    if (status != RET_SUCCESS) {
        fprintf(stderr, "[!] Invalid command\n");
        goto cleanup;
    }

    fflush(stdout);

cleanup:
    if (peCtx) {
        freePEContext(peCtx);
    }
    if (peFile) {
        fclose(peFile);
    }
    return status;
}
