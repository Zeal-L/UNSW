/*******************************************************************************
> CSpotify - 20T3 COMP1511 Assignment 2
| cspotify.c
|
| zID: z5325156
| Name: Zeal Liang
| Date: 2020/11/8
| Program Description:
| CSpotify is our implementation of a song library using 
| linked lists as the primary data structure
|
| Version 1.0.0: Assignment released.
|
 *******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cspotify.h"

/******************************************************************************/
// TODO: Add any other #defines you need.


/******************************************************************************/
// 'struct library' represents a library, which represents the state of the
// entire program. It is mainly used to point to a linked list of 
// playlists, though you may want to add other fields to it.
//
// You may choose to add or change fields in this struct.
struct library {
    struct playlist *head;
};

// 'struct playlist' represents a playlist. 
// You may choose to add or change fields in this struct.
struct playlist {
    char name[MAX_LEN];
    int selected;
    struct track *tracks;
    int size;
    struct playlist *next;
};

// 'struct trackLength' represents the length of a track. 
// You may choose to add or change fields in this struct.
struct trackLength {
    int minutes;
    int seconds;
};

// 'struct track' represents a track. 
// You may choose to add or change fields in this struct.
struct track {
    char title[MAX_LEN];
    char artist[MAX_LEN];
    struct trackLength length;
    struct track *next;
};

/******************************************************************************/
// TODO: Add any other structs you define here.


/******************************************************************************/
// TODO: Add prototypes for any extra functions you create here.

// Create and initialize a new Playlist.
Playlist newPlaylist(char name[MAX_LEN], int selected);
// Create and initialize a new Track.
Track newTrack(char title[MAX_LEN], char artist[MAX_LEN], 
    int minutes, int seconds);
// Check if the strings are alphanumeric.
int checkValidStrings(char string[MAX_LEN]);
// Looking for a Playlist with the same name.
Playlist searchPlaylist(Library library, char target[MAX_LEN]);
// Find the selected Playlist.
Playlist findSelectPlaylist(Playlist curr_p);
// Looking for a Track with the same name, and cut it out from the Playlist.
Track cutTrack(Playlist curr_p, char target[MAX_LEN]);
// Soundex encoding from a string.
char *soundexAlg(char artist[MAX_LEN]);
// Removes a specific element from a string.
void deleteElement(char *artist, int index);
// Moves the specified Track from the 
// current Playlist to the specified Playlist.
void moveTrack(Track curr_track, Playlist curr_p, Playlist p_to_paste);

// Function prototypes for helper functions. 
static void print_playlist(int number, char playlistName[MAX_LEN]);
static void print_selected_playlist(int number, char playlistName[MAX_LEN]);
static void print_track(
    char title[MAX_LEN], char artist[MAX_LEN], 
    int minutes, int seconds
);

/******************************************************************************/
// You need to implement the following functions.
// In other words, write code to make the function work as described 
// in cspotify.h

/*********
> STAGE 1
*********/

// Create a new Library and return a pointer to it.
Library create_library(void) {
    Library newLibrary = malloc(sizeof(struct library));
    newLibrary->head = NULL;
    return newLibrary;
}

// Add a new Playlist to the Library.
int add_playlist(Library library, char playlistName[MAX_LEN]) {
    // Check if the Playlist name is valid.
    if (checkValidStrings(playlistName) == 0) {
        return ERROR_INVALID_INPUTS;
    }

    // If the library is empty.
    if (library->head == NULL) {
        Playlist new_p = newPlaylist(playlistName, 1);
        library->head = new_p;

        // If there's already a Playlist in the library.
    } else if (library->head != NULL) {
        Playlist new_p = newPlaylist(playlistName, 0);
        Playlist curr_p = library->head;
        while (curr_p->next != NULL) {
            curr_p = curr_p->next;
        }
        curr_p->next = new_p;
    }

    return SUCCESS;
}

// Print out the Library.
void print_library(Library library) {

    Playlist curr_p = library->head;

    for(int i = 0; curr_p != NULL; i++) {
        // If this playlist is selected
        if (curr_p->selected == 1) {
            print_selected_playlist(i, curr_p->name);
        } else {
            print_playlist(i, curr_p->name);
        }

        // Print all the tracks in the Playlist (if any).
        Track curr_track = curr_p->tracks;
        while (curr_track != NULL) {
            print_track(
                curr_track->title, 
                curr_track->artist, 
                curr_track->length.minutes,
                curr_track->length.seconds
            );
            curr_track = curr_track->next;
        }
        curr_p = curr_p->next;
    }
}

// Rename the name of an existing Playlist.
int rename_playlist(Library library, char playlistName[MAX_LEN],
    char newPlaylistName[MAX_LEN]) {
    // Check if the playlist name is valid.
    if (checkValidStrings(newPlaylistName) == 0) {
        return ERROR_INVALID_INPUTS;
    }

    Playlist rename_p = searchPlaylist(library, playlistName);

    if (rename_p == NULL) {
        return ERROR_NOT_FOUND;
    }

    strcpy(rename_p->name, newPlaylistName);
    return SUCCESS;
}


/*********
> STAGE 2
*********/

// Selects the next Playlist in the Library.
void select_next_playlist(Library library) {
    if (library->head == NULL) {
        return;
    }
    Playlist curr_p = library->head;
    Playlist new_selected = NULL;
    while (curr_p != NULL) {
        // If the currently selected Playlist is the last Playlist in the Library, 
        // make the first Playlist in the Library become the new selected Playlist.
        if (curr_p->selected == 1 && curr_p->next == NULL) {
            curr_p->selected = 0;
            library->head->selected = 1;
        } else if (curr_p->selected == 1 && curr_p->next != NULL) {
            curr_p->selected = 0;
            new_selected = curr_p->next;
        }
        curr_p = curr_p->next;
    }
    if (new_selected != NULL) {
        new_selected->selected = 1;
    }
}

// Selects the previous Playlist in the Library.
void select_previous_playlist(Library library) {
    if (library->head == NULL) {
        return;
    }
    Playlist curr_p = library->head;
    Playlist prev_p = NULL;
    // If the currently selected Playlist is the first Playlist in the Library, 
    // make the last Playlist in the Library become the new selected Playlist.
    if (curr_p->selected == 1) {
        curr_p->selected = 0;
        while (curr_p != NULL) {
            prev_p = curr_p;
            curr_p = curr_p->next;
        }
        prev_p->selected = 1;
    } else {
        while (curr_p != NULL) {
            if (curr_p->selected == 1) {
                curr_p->selected = 0;
                prev_p->selected = 1;
            }
            prev_p = curr_p;
            curr_p = curr_p->next;
        }
    }
}

// Add a new Track to the selected Playlist.
int add_track(Library library, char title[MAX_LEN], char artist[MAX_LEN], 
    int trackLengthInSec, int position) {
    // If the library is empty.
    if (library->head == NULL) {
        return ERROR_NOT_FOUND;
    }

    // Find the selected Playlist.
    Playlist curr_p = library->head;
    Playlist selected_p = findSelectPlaylist(curr_p);

    // Check if the input is valid.
    if (checkValidStrings(title) == 0 
        || checkValidStrings(artist) == 0
        || trackLengthInSec <= 0 || position < 0 
        || position > selected_p->size) {
        return ERROR_INVALID_INPUTS;
    }

    // Create and initialize a new Track.
    Track new_track = newTrack(title, artist, 
        trackLengthInSec / 60, trackLengthInSec % 60);
    
    // Inserting at the front of the Playlist.
    Track curr_t = selected_p->tracks;
    if (position == 0) {
        new_track->next = selected_p->tracks;
        selected_p->tracks = new_track;

        // Inserting at the end of the Playlist.
    } else if (position == selected_p->size) {
        // If there's no tracks.
        if (selected_p->size == 0) {
            selected_p->tracks = new_track;

        } else {
            while (curr_t->next != NULL) {
                curr_t = curr_t->next;
            }
            curr_t->next = new_track;
        }

        // Inserting in the middle of the Playlist.
    } else {
        for (int i = 0; i < position-1; i++) {
            curr_t = curr_t->next;
        }
        new_track->next = curr_t->next;
        curr_t->next = new_track;
    }
    selected_p->size++;
    return SUCCESS;
}

// Calculate the total length of the selected Playlist in minutes and seconds.
void playlist_length(Library library, int *playlistMinutes, int *playlistSeconds) {

    if (library->head == NULL) {
        *playlistMinutes = -1;
        *playlistSeconds = -1;
        return;
    }

    // Find the selected Playlist.
    Playlist curr_p = library->head;
    Playlist selected_p = findSelectPlaylist(curr_p);

    // Initializing
    *playlistMinutes = 0;
    *playlistSeconds = 0;
    if (selected_p->tracks == NULL) {
        return;
    }

    Track curr_track = selected_p->tracks;
    while (curr_track != NULL) {
        *playlistMinutes += curr_track->length.minutes;
        *playlistSeconds += curr_track->length.seconds;
        curr_track = curr_track->next;
    }
    *playlistMinutes += *playlistSeconds / 60;
    *playlistSeconds = *playlistSeconds % 60;

}


/*********
> STAGE 3
*********/

// Delete the first instance of the given track in the selected Playlist
// of the Library.
void delete_track(Library library, char track[MAX_LEN]) {

    if (library->head == NULL) {
        return;
    }

    // Find the selected Playlist.
    Playlist curr_p = library->head;
    Playlist selected_p = findSelectPlaylist(curr_p);

    if (selected_p->tracks == NULL) {
        return;
    }

    Track curr_track = selected_p->tracks;
    Track prev_track = NULL;
    // deleting the first track in the playlist.
    if (strcmp(track, curr_track->title) == 0) {
        Track to_delete = curr_track;
        selected_p->tracks = curr_track->next;
        free(to_delete);

        // deliting the middle or the end track in the playlist.
    } else {
        while (curr_track != NULL) {
            if (strcmp(track, curr_track->title) == 0) {
                Track to_delete = curr_track;
                prev_track->next = to_delete->next;
                free(to_delete);
            }
            prev_track = curr_track;
            curr_track = curr_track->next;
        }
    }

}

// Delete the selected Playlist and select the next Playlist in the Library.
void delete_playlist(Library library) {
    if (library->head == NULL) {
        return;
    }

    // Find the selected Playlist and the Playlist before it.
    Playlist curr_p = library->head;
    Playlist selected_p = NULL;
    Playlist prev_p = NULL;
    Playlist selected_prev = NULL;
    while (curr_p != NULL) {
        if (curr_p->selected == 1) {
            selected_prev = prev_p;
            selected_p = curr_p;
        } 
        prev_p = curr_p;
        curr_p = curr_p->next;
    }

    // Deliting all Tracks (if any)
    if (selected_p->tracks != NULL) {
        Track curr_track = selected_p->tracks;
        while (curr_track != NULL) {
            Track to_delete = curr_track;
            curr_track = curr_track->next;
            free(to_delete);
        }
    }
    // Deliting the first Playlist.
    if (selected_p == library->head) {
        library->head = selected_p->next;
        free(selected_p);
        // If the first playlist is not the last Playlist.
        if (library->head != NULL) {
            library->head->selected = 1;
        } 
    } else {
        // Deliting the last Playlist.
        if (selected_p->next == NULL) {
            selected_prev->next = NULL;
            library->head->selected = 1;
            free(selected_p);

            // Deliting the middle Playlist.
        } else {
            selected_p->next->selected = 1;
            selected_prev->next = selected_p->next;
            free(selected_p);
        }
        
    }
    
}

// Delete an entire Library and its associated Playlists and Tracks.
void delete_library(Library library) {

    if (library->head == NULL) {
        free(library);
        return;
    }

    // Deliting all Playlists (if any)
    Playlist curr_p = library->head;
    while (curr_p != NULL) {
        // Deliting all Tracks (if any)
        Track curr_track = curr_p->tracks;
        while (curr_track != NULL) {
            Track to_delete = curr_track;
            curr_track = curr_track->next;
            free(to_delete);
        }
        Playlist to_delete = curr_p;
        curr_p = curr_p->next;
        free(to_delete);
    }
    free(library);
}


/*********
> STAGE 4
*********/

// Cut the given track in selected Playlist and paste it into the given 
// destination Playlist.
int cut_and_paste_track(Library library, char trackTitle[MAX_LEN], 
    char destPlaylist[MAX_LEN]) {
    if (library->head == NULL) {
        return ERROR_NOT_FOUND;
    }

    // Find the selected Playlist.
    Playlist curr_p = library->head;
    Playlist selected_p = findSelectPlaylist(curr_p);

    // Looking for the destination Playlist.
    Playlist p_to_paste = searchPlaylist(library, destPlaylist);
    if (p_to_paste == NULL) {
        return ERROR_NOT_FOUND;
    }

    // Looking for a Track with the same name, and cut it out from the Playlist.
    Track track_been_cut = cutTrack(selected_p, trackTitle);
    if (track_been_cut == NULL) {
        return ERROR_NOT_FOUND;
    }
    
    // If the Playlist has no existing tracks, add it into the head.
    if (p_to_paste->tracks == NULL) {
        p_to_paste->tracks = track_been_cut;

        // If has, add it into the end of the Playlist
    } else {
        Track curr_track = p_to_paste->tracks;
        while (curr_track->next != NULL) {
            curr_track = curr_track->next;
        }
        curr_track->next = track_been_cut;
    }

    // The Track has been successfully moved.
    return SUCCESS;
}


// Print out all Tracks with artists that have the same Soundex Encoding 
// as the given artist.
void soundex_search(Library library, char artist[MAX_LEN]) {

    if (library->head == NULL) {
        return;
    }
    // check that the given artist name contains only 
    // alphabetical letters.
    for (int i = 0; artist[i] != '\0' && artist[i] != '\n'; i++) {
        if (! ((artist[i] >= 'A' && artist[i] <= 'Z') 
            || (artist[i] >= 'a' && artist[i] <= 'z'))) {
            return;
        }
    }

    // Searching through all Playlists (if any)
    Playlist curr_p = library->head;
    while (curr_p != NULL) {
        Track curr_track = curr_p->tracks;
        // Searching through all Tracks (if any)
        while (curr_track != NULL) {
            char *encoded_a = soundexAlg(curr_track->artist);
            char *encoded_b = soundexAlg(artist);
            if (strcmp(encoded_a, encoded_b) == 0) {
                print_track(
                    curr_track->title, 
                    curr_track->artist, 
                    curr_track->length.minutes,
                    curr_track->length.seconds
                );
            }
            free(encoded_a);
            free(encoded_b);
            curr_track = curr_track->next;
        }
        curr_p = curr_p->next;
    }
}


/*********
> STAGE 5
*********/

// Move all Tracks matching the Soundex encoding of the given artist 
// to a new Playlist.
int add_filtered_playlist(Library library, char artist[MAX_LEN]) {

    // Check that the given artist name contains only 
    // alphabetical letters.
    for (int i = 0; artist[i] != '\0' && artist[i] != '\n'; i++) {
        if (! ((artist[i] >= 'A' && artist[i] <= 'Z') 
            || (artist[i] >= 'a' && artist[i] <= 'z'))) {
            return ERROR_INVALID_INPUTS;
        }
    }

    // Check if a Playlist with the same artist name already exists.
    Playlist curr_p = library->head;
    while (curr_p != NULL) {
        if (strcmp(curr_p->name, artist) == 0) {
            return ERROR_INVALID_INPUTS;
        } 
        curr_p = curr_p->next;
    }

    add_playlist(library, artist);
    Playlist p_to_paste = searchPlaylist(library, artist);

    // Searching through all Playlists (if any)
    curr_p = library->head;
    while (curr_p->next != NULL) {
        Track curr_track = curr_p->tracks;
        // Searching through all Tracks (if any)
        while (curr_track != NULL) {
            char *encoded_a = soundexAlg(curr_track->artist);
            char *encoded_b = soundexAlg(artist);
            if (strcmp(encoded_a, encoded_b) == 0) {
                // Move all Tracks matching the Soundex encoding 
                // of the given artist to a new Playlist.
                moveTrack(curr_track, curr_p, p_to_paste);
                curr_track = curr_p->tracks;
            } else {
                curr_track = curr_track->next;
            }
            free(encoded_a);
            free(encoded_b);
        }
        curr_p = curr_p->next;
    }

    return SUCCESS;
}


// Reorder the selected Playlist in the given order specified by the order array.
void reorder_playlist(Library library, int order[MAX_LEN], int length) {

    if (library->head == NULL) {
        return;
    }

    // Find the selected Playlist.
    Playlist curr_p = library->head;
    Playlist selected_p = findSelectPlaylist(curr_p);
    if (selected_p->tracks == NULL) {
        return;
    }

    Playlist new_p = newPlaylist(selected_p->name, 1);

    // Copy the Tracks to the new Playlist in the order given
    for (int i = 0; i < length; i++) {
        Track curr_track =  selected_p->tracks;
        // Find the Track you currently need to copy.
        for (int j = 0; j != order[i]; j++) {
            curr_track = curr_track->next;
        }
        // Create and initialize a new Track.
        Track new_track = newTrack(curr_track->title, curr_track->artist, 
            curr_track->length.minutes, curr_track->length.seconds);
        new_p->size++;

        // If the Playlist has no existing tracks, add it into the head.
        if (new_p->tracks == NULL) {
            new_p->tracks = new_track;

            // If has, add it into the end of the Playlist.
        } else {
            Track temp_track = new_p->tracks;
            while (temp_track->next != NULL) {
                temp_track = temp_track->next;
            }
            temp_track->next = new_track;
        }
    }

    // Replace the old Playlist with the new Playlist.
    Playlist temp_p = library->head;
    Playlist prev_p = NULL;
    while (temp_p != selected_p) {
        prev_p = temp_p;
        temp_p = temp_p->next;
    }
    if (prev_p == NULL) {
        new_p->next = temp_p->next;
        library->head = new_p;
    } else {
        prev_p->next = new_p;
        new_p->next = temp_p->next;
    }
    
    // Delite all Tracks in the old Playlist(if any).
    Track curr_track = selected_p->tracks;
    while (curr_track != NULL) {
        Track to_delete = curr_track;
        curr_track = curr_track->next;
        free(to_delete);
    }
    // Then delete the old Playlist.
    free(selected_p);
}

/*****************
> Helper Functions
*****************/

static void print_playlist(int number, char playlistName[MAX_LEN]) {
    printf("[ ] %d. %s\n", number, playlistName);
}

static void print_selected_playlist(int number, char playlistName[MAX_LEN]) {
    printf("[*] %d. %s\n", number, playlistName);
}

static void print_track(
    char title[MAX_LEN], char artist[MAX_LEN], 
    int minutes, int seconds
) {
    printf("       - %-32s    %-24s    %02d:%02d\n", title, artist, 
        minutes, seconds);
}

// Create and initialize a new Playlist.
Playlist newPlaylist(char name[MAX_LEN], int selected) {
    Playlist new_playlist = malloc(sizeof(struct playlist));
    strcpy(new_playlist->name, name);
    new_playlist->selected = selected;
    new_playlist->tracks = NULL;
    new_playlist->size = 0;
    new_playlist->next = NULL;
    return new_playlist;
}

// Create and initialize a new Track.
Track newTrack(char title[MAX_LEN], char artist[MAX_LEN], 
    int minutes, int seconds) {

    Track new_track = malloc(sizeof(struct track));
    strcpy(new_track->title, title);
    strcpy(new_track->artist, artist);
    new_track->length.minutes = minutes;
    new_track->length.seconds = seconds;
    new_track->next = NULL;

    return new_track;
}

// Check if the strings are alphanumeric.
int checkValidStrings(char string[MAX_LEN]) {
    // Invalid
    for (int i = 0; string[i] != '\0' && string[i] != '\n'; i++) {
        if (! ((string[i] >= 'A' && string[i] <= 'Z') 
            || (string[i] >= 'a' && string[i] <= 'z')
            || (string[i] >= '0' && string[i] <= '9'))) {
            return 0;
        }
    }
    // Valid
    return 1;
}

// Looking for a Playlist with the same name.
Playlist searchPlaylist(Library library, char target[MAX_LEN]) {
    Playlist curr_p = library->head;
    while (curr_p != NULL) {
        if (strcmp(target, curr_p->name) == 0) {
            return curr_p;
        }
        curr_p = curr_p->next;
    }

    // NULL is returned if there is no matching Playlist.
    return NULL;
}

// Find the selected Playlist.
Playlist findSelectPlaylist(Playlist curr_p) {
    Playlist selected_p = NULL;
    while (curr_p != NULL) {
        if (curr_p->selected == 1) {
            selected_p = curr_p;
        } 
        curr_p = curr_p->next;
    }
    return selected_p;
}

// Looking for a Track with the same name, and cut it out from the Playlist.
Track cutTrack(Playlist curr_p, char target[MAX_LEN]) {

    Track curr_track = curr_p->tracks;
    Track prev_track = NULL;
    while (curr_track != NULL) {
        if (strcmp(target, curr_track->title) == 0) {
            // Cutting the first track from the Playlist.
            if (curr_track == curr_p->tracks) {
                curr_p->tracks = curr_track->next;

                // Cutting the milddle or the last track from the Playlist.
            } else {
                prev_track->next = curr_track->next;
            }
            curr_track->next = NULL;
            return curr_track;
        }
        prev_track = curr_track;
        curr_track = curr_track->next;
    }

    // NULL is returned if there is no matching Track.
    return NULL;
}

// Soundex encoding from a string.
char *soundexAlg(char artist[MAX_LEN]) {

    char *encoded = malloc(sizeof(char[MAX_LEN]));
    strcpy(encoded, artist);

    // Replace all uppercase letters in the string with 
    // lowercase letters.
    for (int i = 0; encoded[i] != '\0'; i++) {
        if (encoded[i] >= 'A' && encoded[i] <= 'Z') {
            encoded[i] += 32;
        }
    }

    // Save the first letter in advance.
    char first_letter = encoded[0];

    // Map all occurrences of a, e, i, o, u, y, h, w. to zero (0).
    for (int i = 0; encoded[i] != '\0'; i++) {
        if (encoded[i] == 'a' || encoded[i] == 'e' 
            || encoded[i] == 'i' || encoded[i] == 'o' 
            || encoded[i] == 'u' || encoded[i] == 'y' 
            || encoded[i] == 'h' || encoded[i] == 'w') {
            encoded[i] = '0';
            // Replace all consonants after the first letter with digits based on the 
            // b, f, p, v → 1
        } else if (encoded[i] == 'b' || encoded[i] == 'f' 
                || encoded[i] == 'p' || encoded[i] == 'v') {
            encoded[i] = '1';
            // c, g, j, k, q, s, x, z → 2
        } else if (encoded[i] == 'c' || encoded[i] == 'g' 
                || encoded[i] == 'j' || encoded[i] == 'k' 
                || encoded[i] == 'q' || encoded[i] == 's' 
                || encoded[i] == 'x' || encoded[i] == 'z') {
            encoded[i] = '2';
            // d，t → 3
        } else if (encoded[i] == 'd' || encoded[i] == 't') {
            encoded[i] = '3';
            // l → 4
        } else if (encoded[i] == 'l') {
            encoded[i] = '4';
            // m, n → 5
        } else if (encoded[i] == 'm' || encoded[i] == 'n') {
            encoded[i] = '5';
            // r → 6
        } else if (encoded[i] == 'r') {
            encoded[i] = '6';
        }
    }
    
    // Replace all adjacent same digits with one digit, 
    // and then remove all the zero (0) digits
    for (int i = 0; encoded[i] != '\0'; i++) {
        if (encoded[i] == encoded[i+1] || encoded[i] == '0') {
            deleteElement(encoded, i);
            i--;
        }
    }

    // If the first digit matches the numerical encoding 
    // of the first letter, remove the digit. (done before)
    encoded[0] = first_letter-32;

    // Append 3 zeros if result contains less than 3 digits. 
    // Remove all except first letter and 3 digits after it.
    int counter = 0;
    while (encoded[counter] != '\0') {
        counter++;
    }
    if (counter < 4) {
        for (int i = counter; i < 4; i++) {
            encoded[i] = '0';
        }
    }
    return encoded;
}

// Removes a specific element from a string.
void deleteElement(char *encoded, int index) {
    for(int i = index; encoded[i] != '\0'; i++) {
        encoded[i] = encoded[i+1];
    }
}

// Moves the specified Track from the 
// current Playlist to the specified Playlist.
void moveTrack(Track curr_track, Playlist curr_p, Playlist p_to_paste) {
    // Looking for a Track with the same name, 
    // and cut it out from the Playlist.
    Track track_been_cut = cutTrack(curr_p, curr_track->title);

    // If the Playlist has no existing tracks, add it into the head.
    if (p_to_paste->tracks == NULL) {
        p_to_paste->tracks = track_been_cut;

        // If has, add it into the end of the Playlist
    } else {
        Track temp_track = p_to_paste->tracks;
        while (temp_track->next != NULL) {
            temp_track = temp_track->next;
        }
        temp_track->next = track_been_cut;
    }
}