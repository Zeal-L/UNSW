
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Record.h"
#include "StudentDb.h"

#define MAX 8192

static void processOptions(int argc, char *argv[]);
static void showUsage(char *progName);
static void showWelcomeMessage(void);
static bool getCommand(char *buf);
static char **tokenise(char *s, int *ntokens);
static void showHelp(void);

static void runInsertRecord(StudentDb db, char **tokens);
static void runListByZid(StudentDb db, char **tokens);
static void runListByName(StudentDb db, char **tokens);
static void runDeleteByZid(StudentDb db, char **tokens);
static void runFindByZid(StudentDb db, char **tokens);
static void runFindByName(StudentDb db, char **tokens);

static void showRecordList(List l);

////////////////////////////////////////////////////////////////////////

typedef struct command {
    char  *code;
    int    numArgs;
    void (*fn)(StudentDb, char **);
    char  *argHint;
    char  *helpMsg;
} Command;

#define NUM_COMMANDS 8
static Command COMMANDS[NUM_COMMANDS] = {
    {"+",  3, runInsertRecord, "<zid> <family name> <given name>",
                               "add a student record"},
    {"lz", 0, runListByZid,    "",
                               "list all records in order of zid"},
    {"ln", 0, runListByName,   "",
                               "list all records in order of name"},
    {"d",  1, runDeleteByZid,  "<zid>",
                               "delete a student record"},
    {"fz", 1, runFindByZid,    "<zid>",
                               "find a student record by zid"},
    {"fn", 2, runFindByName,   "<family name> <given name>",
                               "find student records by name"},
    
    // Meta-commands
    {"?",  0, NULL,            "", "show this message"},
    {"q",  0, NULL,            "", "quit"},
};

////////////////////////////////////////////////////////////////////////

bool ECHO = false;

int main(int argc, char *argv[])
{
    processOptions(argc, argv);
    showWelcomeMessage();

    StudentDb db = DbNew();
    bool done = false;
    char cmd[MAX] = {0};

    while (!done && getCommand(cmd)) {
        if (ECHO) {
            printf("%s", cmd);
        }

        int ntokens = 0;
        char **tokens = tokenise(cmd, &ntokens);
        if (ntokens == 0) {
        	free(tokens);
        	continue;
        }
        
        char *cmd = tokens[0];

        // Meta-commands
        if (strcmp(cmd, "?") == 0) {
            showHelp();
        } else if (strcmp(cmd, "q") == 0) {
            done = true;
        
        // Actual commands
        } else {
            bool validCommand = false;

            for (int i = 0; i < NUM_COMMANDS; i++) {
                if (strcmp(cmd, COMMANDS[i].code) == 0) {
                    validCommand = true;
                    if (ntokens - 1 == COMMANDS[i].numArgs) {
                        COMMANDS[i].fn(db, tokens);
                    } else {
                        printf("Usage: %s %s\n", COMMANDS[i].code,
                                                 COMMANDS[i].argHint);
                    }
                }
            }

            if (!validCommand) {
                printf("Unknown command '%s'\n", cmd);
            }
        }
        free(tokens);
    }

    DbFree(db);
}

static void processOptions(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            showUsage(argv[0]);
            exit(EXIT_SUCCESS);
        } else if (strcmp(argv[i], "-e") == 0) {
            ECHO = true;
        }
    }
}

static void showUsage(char *progName) {
    printf("Usage: %s [options]...\n"
           "Options:\n"
           "    -h      show this help message\n"
           "    -e      echo - echo all commands\n",
           progName);
}

static void showWelcomeMessage(void) {
    printf("StudentDb v1.0\n");
    printf("Enter ? to see the list of commands.\n");
}

static bool getCommand(char *buf) {
    printf("> ");
    return (fgets(buf, MAX, stdin) != NULL);
}

static char **tokenise(char *s, int *ntokens) {
    char p;

    // count number of tokens
    *ntokens = 0;
    p = ' ';
    for (char *c = s; *c != '\0'; p = *c, c++) {
        if (isspace(p) && !isspace(*c)) {
            (*ntokens)++;
        }
    }

    char **tokens = malloc((*ntokens + 1) * sizeof(char *));
    int i = 0;
    p = ' ';
    for (char *c = s; *c != '\0'; p = *c, c++) {
        if ((p == '\0' || isspace(p)) && !isspace(*c)) {
            tokens[i++] = c;
        } else if (!isspace(p) && isspace(*c)) {
            *c = '\0';
        }
    }
    tokens[i] = NULL;
    
    return tokens;
}

static void showHelp(void) {
    printf("Commands:\n");
    for (int i = 0; i < NUM_COMMANDS; i++) {
        printf("%5s %-36s %s\n", COMMANDS[i].code, COMMANDS[i].argHint,
                                 COMMANDS[i].helpMsg);
    }
    printf("\n");
}

////////////////////////////////////////////////////////////////////////
// Commands

static void runInsertRecord(StudentDb db, char **tokens) {
    char *zidStr = tokens[1];
    char *familyName = tokens[2];
    char *givenName = tokens[3];

    int zid = atoi(zidStr);
    if (zid == 0 || zid < MIN_ZID || zid > MAX_ZID) {
        fprintf(stderr, "Invalid zid '%s'\n", zidStr);
        return;
    }

    Record r = RecordNew(zid, familyName, givenName);
    if (r == NULL) {
        return;
    }

    if (DbInsertRecord(db, r)) {
        printf("Successfully inserted record!\n");
    } else {
        printf("There is already a record with zid '%d'\n", zid);
        RecordFree(r);
    }
}

static void runListByZid(StudentDb db, char **tokens) {
    DbListByZid(db);
}

static void runListByName(StudentDb db, char **tokens) {
    DbListByName(db);
}

static void runDeleteByZid(StudentDb db, char **tokens) {
    char *zidStr = tokens[1];

    int zid = atoi(zidStr);
    if (zid == 0 || zid < MIN_ZID || zid > MAX_ZID) {
        fprintf(stderr, "Invalid zid '%s'\n", zidStr);
        return;
    }

    if (DbDeleteByZid(db, zid)) {
        printf("Successfully deleted record!\n");
    } else {
        printf("Could not find a record with zid '%d' to delete\n", zid);
    }
}

static void runFindByZid(StudentDb db, char **tokens) {
    char *zidStr = tokens[1];

    int zid = atoi(zidStr);
    if (zid == 0 || zid < MIN_ZID || zid > MAX_ZID) {
        fprintf(stderr, "Invalid zid '%s'\n", zidStr);
        return;
    }

    Record r = DbFindByZid(db, zid);
    if (r == NULL) {
        printf("No records with zid '%d'\n", zid);
    } else {
        printf("Found a record:\n");
        RecordShow(r);
        printf("\n");
    }
}

static void runFindByName(StudentDb db, char **tokens) {
    char *familyName = tokens[1];
    char *givenName  = tokens[2];

    List l = DbFindByName(db, familyName, givenName);
    if (ListSize(l) == 0) {
        printf("No records found\n");
    } else {
        printf("Found records:\n");
        showRecordList(l);
    }
    ListFree(l);
}

////////////////////////////////////////////////////////////////////////

static void showRecordList(List l) {
    ListIterator it = ListItNew(l);
    while (ListItHasNext(it)) {
        RecordShow(ListItNext(it));
        printf("\n");
    }
    ListItFree(it);
}
