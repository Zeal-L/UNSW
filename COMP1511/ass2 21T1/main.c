//
// DO NOT CHANGE THIS FILE
//
// You do not submit this file. This file is not marked.
// If you think you need to change this file you have
// misunderstood the assignment - ask in the course forum.
//
// Assignment 2 21T1 COMP1511: CS Beats
// main.c
//
// Version 1.0.0: Release
// Version 1.0.1: note_number should be key_number in help text.
//
// This file allows you to interactively test the functions you
// implement in beats.c

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "beats.h"

#define MAX_LINE 2048

// Complete
#define COMMAND_HELP '?'
#define COMMAND_COMMENT '/'
#define COMMAND_QUIT 'q'

// Stage 1
#define COMMAND_ADD_NOTE 'a'
#define COMMAND_PRINT_BEAT 'p'
#define COMMAND_COUNT_NOTES_IN_OCTAVE 'c'

// Stage 2
#define COMMAND_ADD_BEAT 'A'
#define COMMAND_PRINT_TRACK 'P'
#define COMMAND_NEXT_BEAT '>'
#define COMMAND_COUNT_BEATS_REMAINING 'C'

// Stage 3
#define COMMAND_REMOVE_BEAT 'R'

// Command Returns
#define RETURN_EXIT 0
#define RETURN_SILENT 1
#define RETURN_PRINT 2


typedef struct _state {
    Beat building_beat;
    Track track;
} *State;


// Helper Functions
static void do_print_intro(void);
static void *not_null(void *ptr);
static int get_command(char *command, int max_command_length);
static int run_command(State state, char *line);

// Do: Completed
static void do_print_help();

// Do: Stage 1
static void do_add_note(State state, char *line);
static void do_print_beat(State state, char *line);
static void do_count_notes_in_octave(State state, char *line);

// Do: Stage 2
static void do_add_beat(State state, char *line);
static void do_select_next_beat(State state, char *line);
static void do_print_track(State state, char *line);
static void do_count_beats_left_in_track(State state, char *line);

// Do: Stage 3
static void do_remove_beat(State state, char *line);


int main(void) {
    do_print_intro();

    char line[MAX_LINE];
    int command_number = 1;

    struct _state state_struct;
    State state = &state_struct;

    state->track = create_track();

    state->building_beat = NULL;

    int read_command = RETURN_PRINT;
    while (read_command) {
        if (state->building_beat == NULL) {
            state->building_beat = create_beat();
        }
        if (read_command == RETURN_PRINT) {
            printf("\n");
            printf("[%03d] Beat Being Constructed: ", command_number);
            print_beat(state->building_beat);
        }
        printf("[%03d]: ", command_number++);
        read_command = get_command(line, MAX_LINE);
        if (read_command) read_command *= run_command(state, line);
    }

    free_beat(state->building_beat);
    free_track(state->track);

    return 0;
}

static void do_print_intro(void) {
    printf("============================[ CS bEats ]============================\n");
    printf("Welcome to CS bEats! Type '?' to see help.\n");
    printf("====================================================================\n");
}

static void *not_null(void *ptr) {
    if (ptr != NULL) {
        return ptr;
    }
    fprintf(stderr, "This solution was going to pass a NULL pointer.\n");
    fprintf(stderr, "You have probably not implemented a required function.\n");
    fprintf(stderr, "If you believe this message is in error, post on the course forum.\n");
    exit(1);
}

static int get_command(char *command, int max_command_length) {

    if (fgets(command, max_command_length, stdin) == NULL) {
        return 0;
    }

    // remove '\n' if present
    command[strcspn(command, "\n")] = '\0';

    int leading_whitespace = 0;
    while (isspace(command[leading_whitespace])) {
        leading_whitespace++;
    }
    memmove(command, command+leading_whitespace, MAX_LINE - leading_whitespace);

    return 1;
}

static int run_command(State state, char *line) {
    if (line[0] == COMMAND_HELP) {
        do_print_help();
        return RETURN_SILENT;
    } else if (line[0] == COMMAND_COMMENT) {
        return RETURN_SILENT;
    } else if (line[0] == COMMAND_QUIT) {
        return RETURN_EXIT;
    } else if (line[0] == COMMAND_ADD_NOTE) {
        do_add_note(state, line);
        return RETURN_PRINT;
    } else if (line[0] == COMMAND_PRINT_BEAT) {
        do_print_beat(state, line);
        return RETURN_PRINT;
    } else if (line[0] == COMMAND_COUNT_NOTES_IN_OCTAVE) {
        do_count_notes_in_octave(state, line);
        return RETURN_PRINT;
    } else if (line[0] == COMMAND_ADD_BEAT) {
        do_add_beat(state, line);
        return RETURN_PRINT;
    } else if (line[0] == COMMAND_NEXT_BEAT) {
        do_select_next_beat(state, line);
        return RETURN_PRINT;
    } else if (line[0] == COMMAND_COUNT_BEATS_REMAINING) {
        do_count_beats_left_in_track(state, line);
        return RETURN_PRINT;
    } else if (line[0] == COMMAND_PRINT_TRACK) {
        do_print_track(state, line);
        return RETURN_PRINT;
    } else if (line[0] == COMMAND_REMOVE_BEAT) {
        do_remove_beat(state, line);
        return RETURN_PRINT;
    } else if (line[0] == '\0') {
        return RETURN_SILENT;
    } else {
        printf("Invalid command %c, use '?' to get help!\n", line[0]);
        return RETURN_SILENT;
    }
}


static void do_print_help() {
    printf(""
        "============================[ Help ]============================\n"
    );

    printf(""
        "  %c\n"
        "    Show this help screen\n",
        COMMAND_HELP
    );
    printf(""
        "  %c\n"
        "    Quit this program.\n",
        COMMAND_QUIT
    );
    printf("\n---------------------------[ Stage 1 ]---------------------------\n");
    printf(""
        "  %c <octave_number> <key_number>\n"
        "    Add a note to the current beat.\n",
        COMMAND_ADD_NOTE
    );
    printf(""
        "  %c\n"
        "    Print the beat you are constructing (happens automatically).\n",
        COMMAND_PRINT_BEAT
    );
    printf(""
        "  %c <octave>\n"
        "    Count the number of notes in the beat you are constructing that\n"
        "    are in the given octave.\n",
        COMMAND_COUNT_NOTES_IN_OCTAVE
    );
    printf("\n---------------------------[ Stage 2 ]---------------------------\n");
    printf(""
        "  %c\n"
        "    Adds the beat you are building to the track, after the currently \n"
        "    selected beat. If there is no selected beat, the beat you are\n"
        "    building becomes the first beat. The beat you are building is\n"
        "    cleared, ready to build another beat.\n",
        COMMAND_ADD_BEAT
    );
    printf(""
        "  %c\n"
        "    Print the whole track, beat by beat.\n",
        COMMAND_PRINT_TRACK
    );
    printf(""
        "  %c\n"
        "    Move the currently selected beat to the next beat. \n"
        "    Stop the track if the currently selected is the last beat.\n"
        "    If the track is stopped, this command sets the currently selected \n"
        "    beat to the first beat.\n",
        COMMAND_NEXT_BEAT
    );
    printf(""
        "  %c\n"
        "    Count the number of beats left in the track.\n",
        COMMAND_COUNT_BEATS_REMAINING
    );
    printf("\n---------------------------[ Stage 3 ]---------------------------\n");
    printf(""
        "  %c\n"
        "    Remove the currently selected beat, if there is one.\n",
        COMMAND_REMOVE_BEAT
    );

}

////////////////////////////////////////////////////////////////////////
//                         Stage 1 Functions                          //
////////////////////////////////////////////////////////////////////////

static void do_add_note(State state, char *line) {
    int octave, key;
    char command;

    int scanf_return = sscanf(line, "%c %d %d", &command, &octave, &key);

    if (scanf_return != 3) {
        printf("Command Invalid. The correct format is: %c <octave> <key>.\n", command);
        return;
    }

    int add_note_return = add_note_to_beat(not_null(state->building_beat), octave, key);

    if (add_note_return == INVALID_OCTAVE) {
        printf("Invalid octave - octave %d must non-negative and less than 10.\n", octave);
    } else if (add_note_return == INVALID_KEY) {
        printf("Invalid key - key %d must be non-negative and less than 12.\n", key);
    } else if (add_note_return == NOT_HIGHEST_NOTE) {
        printf("Invalid note - Notes must be entered in strictly ascending order!\n");
    } else if (add_note_return == VALID_NOTE) {
        printf("Added note successfully!\n");
    } else {
        printf("ERROR: Unknown return value!\n");
    }
}

static void do_print_beat(State state, char *line) {
    // we pass line for consistency, but don't need it.
    (void) line;

    print_beat(not_null(state->building_beat));
}

static void do_count_notes_in_octave(State state, char *line) {
    int octave;
    char command;

    int scanf_return = sscanf(line, "%c %d", &command, &octave);

    if (scanf_return != 2) {
        printf("Command Invalid. The correct format is: %c <octave> .\n", command);
        return;
    }

    int count = count_notes_in_octave(not_null(state->building_beat), octave);
    printf("In the beat being constructed, there are %d notes in octave %d.\n", count, octave);
    
}

////////////////////////////////////////////////////////////////////////
//                         Stage 2 Functions                          //
////////////////////////////////////////////////////////////////////////

static void do_add_beat(State state, char *line) {
    // we pass line for consistency, but don't need it.
    (void) line;

    add_beat_to_track(state->track, state->building_beat);

    state->building_beat = NULL;
}

static void do_select_next_beat(State state, char *line) {
    // we pass line for consistency, but don't need it.
    (void) line;

    int track_status = select_next_beat(
        not_null(state->track)
    );

    if (track_status == TRACK_PLAYING) {
        printf("Moved to next Beat.\n");
    } else if (track_status == TRACK_STOPPED) {
        printf("Track Stopped.\n");
    } else {
        printf("ERROR: Unknown return value!\n");
    }

}

static void do_print_track(State state, char *line) {
    // we pass line for consistency, but don't need it.
    (void) line;

    print_track(not_null(state->track));
}

static void do_count_beats_left_in_track(State state, char *line) {
    // we pass line for consistency, but don't need it.
    (void) line;

    int count = count_beats_left_in_track(not_null(state->track));
    printf("There are %d beats left in the track.\n", count);
    
}


////////////////////////////////////////////////////////////////////////
//                         Stage 3 Functions                          //
////////////////////////////////////////////////////////////////////////

static void do_remove_beat(State state, char *line) {
    // we pass line for consistency, but don't need it.
    (void) line;

    int rm_beat_return = remove_selected_beat(not_null(state->track));

    if (rm_beat_return == TRACK_PLAYING) {
        printf("Track Still Playing.\n");
    } else if (rm_beat_return == TRACK_STOPPED) {
        printf("Track Stopped.\n");
    } else {
        printf("ERROR: Unknown return value!\n");
    }

}

