// Assignment 2 21T1 COMP1511: Beats by CSE
// beats.c
//
// This program was written by YOUR-NAME-HERE (z5555555)
// on INSERT-DATE-HERE
//
// Version 1.0.0: Assignment released.

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

// Add any extra #includes your code needs here.

#include "beats.h"

// Add your own #defines here.
typedef struct note *Note;

int checkHigestOctave(Beat beat, int octave, int key);
static void do_free_beat(Beat beat);
static void do_free_notes(Note n);

//////////////////////////////////////////////////////////////////////

// You don't have to use the provided struct track, you are free to
// make your own struct instead.
// If you use the provided struct track, you will have to add fields
// to store other information.

struct track {
    struct beat *curr;
    struct beat *head;
};

// You don't have to use the provided struct beat, you are free to
// make your own struct instead.
// If you use the provided struct beat, you may add fields
// to it to store other information.

struct beat {
    // You may choose to add or change fields in this struct.
    struct note *notes;
    struct beat *next;
};

// You don't have to use the provided struct note, you are free to
// make your own struct instead.
// If you use the provided struct note, you add fields
// to it to store other information.

struct note {
    // You may choose to add or change fields in this struct.
    int octave;
    int key;
    struct note *next;
};

// Add any other structs you define here.

//////////////////////////////////////////////////////////////////////

// Add prototypes for any extra functions you create here.



// Return a malloced Beat with fields initialized.
Beat create_beat(void) {
    Beat new_beat = malloc(sizeof (struct beat));
    assert(new_beat != NULL);

    new_beat->next = NULL;
    new_beat->notes = NULL;

    // You do not need to change this function, unless you change
    // the implementation of struct beat.

    return new_beat;
}

// You need to implement the following functions.
// You can find descriptions of what each function should do in beats.h

//////////////////////////////////////////////////////////////////////
//                        Stage 1 Functions                         //
//////////////////////////////////////////////////////////////////////

// Add a note to the end of a beat.
int add_note_to_beat(Beat beat, int octave, int key) {
    
    if (octave < 0 || octave >= 10) {
        return INVALID_OCTAVE;
    }
    if (key < 0 || key > 11) {
        return INVALID_KEY;
    }
    if (checkHigestOctave(beat, octave, key)) {
        return NOT_HIGHEST_NOTE;
    }
    

    struct note *new_note = malloc(sizeof(struct note));
    assert(new_note != NULL);
    new_note->octave = octave;
    new_note->key = key;
    new_note->next = NULL;


    if (beat->notes == NULL) {
        beat->notes = new_note;
        return VALID_NOTE;
    }

    struct note *curr = beat->notes;
    while (curr->next != NULL) {
        curr = curr->next;
    }
    curr->next = new_note;

    return VALID_NOTE;
}

// Print the contents of a beat.
void print_beat(Beat beat) {
    struct note *curr = beat->notes;
    while (curr != NULL) {
        printf("%d %02d", curr->octave, curr->key);
        curr = curr->next;
        if (curr != NULL) {
            printf(" | ");
        }
    }
    printf("\n");
    return;
}

// Count the number of notes in a beat that are in a given octave.
int count_notes_in_octave(Beat beat, int octave) {
    if (octave < 0 || octave >= 10 || beat->notes == NULL) {
        return 0;
    }

    int counter = 0;
    struct note *curr = beat->notes;
    while (curr != NULL) {

        if (curr->octave == octave) {
            counter++;
        }
        curr = curr->next;
    }

    return counter;
}

//////////////////////////////////////////////////////////////////////
//                        Stage 2 Functions                         //
//////////////////////////////////////////////////////////////////////

// Return a malloced track with fields initialized.
Track create_track(void) {
    
    Track new_track = malloc(sizeof(struct track));
    assert(new_track != NULL);

    new_track->curr = NULL;
    new_track->head = NULL;
    
    return new_track;
}

// Add a beat after the current beat in a track.
void add_beat_to_track(Track track, Beat beat) {
    if (track->head == NULL) {
        track->head = beat;
        return;
    }

    if (track->curr == NULL) {
        Beat temp = track->head;
        track->head = beat;
        beat->next = temp;

    } else {
        Beat temp = track->curr->next;
        if (track->curr->next == NULL) beat->next = NULL;
        track->curr->next = beat;
        beat->next = temp;
    }

}

// Set a track's current beat to the next beat.
int select_next_beat(Track track) {
    if (track->curr == NULL && track->head != NULL) {
        track->curr = track->head;
        return TRACK_PLAYING;
    } 

    if (track->curr != NULL) {
        if (track->curr->next == NULL) {
            track->curr = NULL;
            return TRACK_STOPPED;
        } else {
            track->curr = track->curr->next;
            return TRACK_PLAYING;
        }
    } 
    
    return TRACK_STOPPED;
}

// Print the contents of a track.
void print_track(Track track) {
    if (track == NULL || track->head == NULL) {
        return;
    }
    int i = 1;

    Beat curr = track->head;
    while (curr != NULL) {

        if (curr == track->curr) {
            printf(">");
        }
        printf("[%d]", i++);
        print_beat(curr);
        curr = curr->next;
    }

}

// Count beats after the current beat in a track.
int count_beats_left_in_track(Track track) {
    
    int counter = 0;

    if (track->curr == NULL) {
        Beat curr = track->head;
        while (curr != NULL) {
            counter++;
            curr = curr->next;
        }
        return counter;
    }

    Beat curr = track->curr;
    while (curr != NULL) {
        counter++;
        curr = curr->next;
    }
    
    return counter-1;
}

//////////////////////////////////////////////////////////////////////
//                        Stage 3 Functions                         //
//////////////////////////////////////////////////////////////////////

// Free the memory of a beat, and any memory it points to.
void free_beat(Beat beat) {
    if (beat == NULL) return;
    do_free_notes(beat->notes);
    free(beat);
}

static void do_free_notes(Note n) {
    if (n == NULL) return;
    do_free_notes(n->next);
    free(n);
}

// Free the memory of a track, and any memory it points to.
void free_track(Track track) {
    free_beat(track->head);
    free(track);
}

static void do_free_beat(Beat beat) {
    if (beat == NULL) return;
    free_beat(beat->next);
    do_free_notes(beat->notes);
}

// Remove the currently selected beat from a track.
int remove_selected_beat(Track track) {
    
    if (track->curr == NULL) return TRACK_STOPPED;

    if (track->curr == track->head) {
        Beat temp = track->head->next;
        free_beat(track->head);
        if (temp != NULL) {
            track->curr = temp;
            track->head = temp;
            return TRACK_PLAYING;
        } else {
            track->curr = NULL;
            track->head = NULL;
            return TRACK_STOPPED;
        }
        
    } else {
        Beat curr = track->head;
        Beat prev = curr;
        while (curr != track->curr) {
            prev = curr;
            curr = curr->next;
        }
        
        prev->next = curr->next;
        free_beat(curr);

        if (prev->next != NULL) {
            track->curr = prev->next;
            return TRACK_PLAYING;
        } else {
            track->curr = NULL;
            return TRACK_STOPPED;
        }
    }
}


int checkHigestOctave(Beat beat, int octave, int key) {
    struct note *curr = beat->notes;
    while (curr != NULL) {
        if (curr->octave > octave) {
            return 1;
        } else if (curr->octave >= octave && curr->key >= key) {
            return 1;
        }
        curr = curr->next;
    }
    return 0;
}