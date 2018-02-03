#include <stdio.h>
#include <string.h> // for strcmp
#include <stdlib.h> // for malloc
#include <unistd.h> // for getpass

void printhelp(const char* prog)
{
    printf("Usage:\n");
    printf("%s <username> <program> [arg1 arg2 arg3 ...]\n\n", prog);
    printf("Options:\n");
    printf("-h: show this help text\n");
    printf("username: the username that you want to run the specified program as\n");
    printf("program: the program that you want to run, followed by the arguments to the program\n");
}

void log()
{
    FILE* f = fopen("/var/tmp/runaslog", "a");

    fclose(f);
}

int main(int argc, char* argv[])
{
    if (argc < 3 || !strcmp(argv[0], "-h")) {
        // Minimum arguments not passed
        printhelp(argv[0]);
        return 1;
    }

    // username = args[1]
    // program = args[2]
    // args = [args 3..(argc - 1)]

    // This is all kinda unnecessary ...
    const char* username = argv[1];
    const char* program = argv[2];
    char** args;

    int nargs = argc - 3;
    if (argc > 3) {
        args = (char**) malloc(nargs * sizeof(char*));
        int i;
        for (i=0; i<nargs; i++) {
            args[i] = argv[i+2];
        }
    }
    // ...

    // Linter complains about getpass but it should work
    char* password = getpass("Password: ");

    // if not authorized, return with error code

    // otherwise, use exec() family to run program (execvp I think?)
    // How to get return code??

    return 0;
}
