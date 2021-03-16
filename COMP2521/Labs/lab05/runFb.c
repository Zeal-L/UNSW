// runFb.c - a command-line interface to Friendbook

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Fb.h"
#include "List.h"

#define MAX 8192

static void processOptions(int argc, char *argv[]);
static void showUsage(char *progName);
static void showWelcomeMessage(void);
static int getCommand(char *buf);
static char **tokenise(char *s, int *ntokens);
static void showHelp(void);

static void runAddPerson(Fb fb, char **tokens);
static void runListPeople(Fb fb, char **tokens);
static void runFriend(Fb fb, char **tokens);
static void runUnfriend(Fb fb, char **tokens);
static void runFriendshipStatus(Fb fb, char **tokens);
static void runNumFriends(Fb fb, char **tokens);
static void runListFriends(Fb fb, char **tokens);
static void runMutualFriends(Fb fb, char **tokens);
static void runFriendRecs1(Fb fb, char **tokens);
static void runFriendRecs2(Fb fb, char **tokens);

static void showList(List l);

////////////////////////////////////////////////////////////////////////

typedef struct command {
    char  *code;
    int    numArgs;
    void (*fn)(Fb, char **); // function that executes the command
    char  *argHint;
    char  *helpMsg;
} Command;

#define NUM_COMMANDS 12
static Command COMMANDS[NUM_COMMANDS] = {
    {"+", 1, runAddPerson,         "<name>",
                                   "add a new person"},
    {"l", 0, runListPeople,        "",
                                   "list the names of all people"},
    {"f", 2, runFriend,            "<name1> <name2>",
                                   "friend two people"},
    {"u", 2, runUnfriend,          "<name1> <name2>",
                                   "unfriend two people"},
    {"s", 2, runFriendshipStatus,  "<name1> <name2>",
                                   "get the friendship status of two people"},
    {"n", 1, runNumFriends,        "<name>",
                                   "get the number of friends a person has"},
    {"F", 1, runListFriends,       "<name>",
                                   "list a person's friends"},
    {"m", 2, runMutualFriends,     "<name1> <name2>",
                                   "list all mutual friends of two people"},
    {"r", 1, runFriendRecs1,       "<name>",
                                   "get friend recommendations for a person "
                                   "based on mutual friends"},
    {"R", 1, runFriendRecs2,       "<name>",
                                   "get friend recommendations for a person "
                                   "based on friendship closeness"},
    // Meta-commands
    {"?", 0, NULL,                 "", "show this message"},
    {"q", 0, NULL,                 "", "quit"},
};

////////////////////////////////////////////////////////////////////////

bool ECHO = false;

int main(int argc, char *argv[])
{
    processOptions(argc, argv);
    showWelcomeMessage();

    Fb fb = FbNew();
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
                        COMMANDS[i].fn(fb, tokens);
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

    FbFree(fb);
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
    printf("Friendbook v1.0\n");
    printf("Enter ? to see the list of commands.\n");
}

static int getCommand(char *buf) {
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
        printf("%5s %-18s %s\n", COMMANDS[i].code, COMMANDS[i].argHint,
                                 COMMANDS[i].helpMsg);
    }
    printf("\n");
}

////////////////////////////////////////////////////////////////////////
// Commands

static void runAddPerson(Fb fb, char **tokens) {
    char *name = tokens[1];

    if (FbAddPerson(fb, name)) {
        printf("%s was successfully added to Friendbook!\n", name);
    } else {
        printf("There is already a person named %s\n", name);
    }
}

static void runListPeople(Fb fb, char **tokens) {
    List l = FbGetPeople(fb);
    printf("People:\n");
    showList(l);
    ListFree(l);
}

static void runFriend(Fb fb, char **tokens) {
    char *name1 = tokens[1];
    char *name2 = tokens[2];

    if (FbFriend(fb, name1, name2)) {
        printf("Successfully friended %s and %s!\n", name1, name2);
    } else {
        printf("Could not friend %s and %s - they are already friends.\n",
               name1, name2);
    }
}

static void runUnfriend(Fb fb, char **tokens) {
    char *name1 = tokens[1];
    char *name2 = tokens[2];

    if (FbUnfriend(fb, name1, name2)) {
        printf("Successfully unfriended %s and %s!\n", name1, name2);
    } else {
        printf("Could not unfriend %s and %s - they are not friends.\n",
               name1, name2);
    }
}

static void runFriendshipStatus(Fb fb, char **tokens) {
    char *name1 = tokens[1];
    char *name2 = tokens[2];

    bool status = FbIsFriend(fb, name1, name2);
    printf("%s and %s %s friends.\n", name1, name2,
                                      status ? "are" : "are not");
}

static void runNumFriends(Fb fb, char **tokens) {
    char *name = tokens[1];

    int res = FbNumFriends(fb, name);
    printf("%s has %d friend%s.\n", name, res, res == 1 ? "" : "s");
}

static void runListFriends(Fb fb, char **tokens) {
    char *name = tokens[1];
    
    List l = FbGetFriends(fb, name);
    printf("%s's friends:\n", name);
    ListSort(l);
    showList(l);
    ListFree(l);
}

static void runMutualFriends(Fb fb, char **tokens) {
    char *name1 = tokens[1];
    char *name2 = tokens[2];

    List l = FbMutualFriends(fb, tokens[1], tokens[2]);
    printf("%s and %s's mutual friends:\n", name1, name2);
    ListSort(l);
    showList(l);
    ListFree(l);
}

static void runFriendRecs1(Fb fb, char **tokens) {
    char *name = tokens[1];

    FbFriendRecs1(fb, name);
}

static void runFriendRecs2(Fb fb, char **tokens) {
    char *name = tokens[1];

    FbFriendRecs2(fb, name);
}

////////////////////////////////////////////////////////////////////////

static void showList(List l) {
    ListIterator it = ListItNew(l);
    while (ListItHasNext(it)) {
        char *name = ListItNext(it);
        printf("\t%s\n", name);
    }
    ListItFree(it);
    printf("\n");
}

