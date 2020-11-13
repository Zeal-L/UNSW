/*******************************************************************************
> CSpotify - 20T3 COMP1511 Assignment 2
| test_cspotify.c
|
| zID: z5325156
| Name: Zeal Liang
| Date: 2020/11/7
| Program Description:
| CSpotify is our implementation of a song library using 
| linked lists as the primary data structure
|
| Version 1.0.0: Assignment released.
 *******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_cspotify.h"
#include "cspotify.h"
#include "capture.h"

/*********************************************
> Test Functions
| These tests are explained in test_cspotify.h
*********************************************/

/*********
> STAGE 1
*********/

// Test function for 'add_playlist'
void test_add_playlist(void) {

    // Test 1: Does add_playlist return SUCCESS and add 
    // when adding one Playlist with a valid name?
    Library testLibrary = create_library();

    int result = add_playlist(testLibrary, "Favourites");
    if (result != SUCCESS) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    char printText[10000];
    CAPTURE(print_library(testLibrary), printText, 10000);
    if (!string_contains(printText, "Favourites")) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    // Test 2: Does add_playlist return ERROR_INVALID_INPUTS
    // and not add the playlist into the Library
    // when trying to add a Playlist with an invalid name?
    // TODO: Add your test for Test 2

    // Test 3: ???
    // TODO: Add your own test, and explain it.

    printf("MEETS SPEC\n");
}

// Test function for 'rename_playlist'
void test_rename_playlist(void) {
    // Test 1: Does rename_playlist return ERROR_NOT_FOUND 
    // when trying to rename a playlist when the Library is empty
    Library testLibrary = create_library();

    int result = rename_playlist(testLibrary, "Favourites", "Dislikes");
    if (result != ERROR_NOT_FOUND) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    // Test 2: Does rename_playlist successfully
    // rename a Playlist
    // when a valid new Playlist name is given to 
    // rename an existing Playlist in the Library?
    // TODO: Add your test for Test 2

    // Test 3: ???
    // TODO: Add your own test, and explain it.

    printf("MEETS SPEC\n");
}


/*********
> STAGE 2
*********/

// Test function for 'add_track'
void test_add_track(void) {
    // Test 1: Does add_track successfully add 
    // multiple (more than 3 Tracks) Tracks 
    // to the Library?
    // TODO: Add your test for Test 1

    // Test 2: ???
    // TODO: Add your own test, and explain it.

    printf("MEETS SPEC\n");
}

// Test function for 'playlist_length'
void test_playlist_length(void) {
    // Test 1: Does playlist_length work for Tracks 
    // with lengths greater than 60 seconds?
    // TODO: Add your test for Test 1

    // Test 2: ???
    // TODO: Add your own test, and explain it.

    printf("MEETS SPEC\n");
}


/*********
> STAGE 3
*********/

// Test function for 'delete_playlist'
void test_delete_playlist(void) {
    // Test 1: Does delete_playlist work if
    // the selected Playlist is the first Playlist
    // in the Library?
    // TODO: Add your test for Test 1

    // Test 2: ???
    // TODO: Add your own test, and explain it.

    printf("MEETS SPEC\n");
}


/*********
> STAGE 4
*********/

// Test function for 'soundex_search'
void test_soundex_search(void) {
    // Test 1: ???
    // TODO: Add your own test, and explain it.

    // Test 2: ???
    // TODO: Add your own test, and explain it.

    printf("MEETS SPEC\n");
}


/*********
> EXTRA
*********/

//  Your extra tests (Not worth marks)
void extra_tests(void) {
    // TODO: Add any extra tests you have here
    printf("MEETS SPEC\n");
}

/*****************
> Helper Functions
*****************/

// Find the string 'needle' in 'haystack'
int string_contains(char *haystack, char *needle) {
    return strstr(haystack, needle) != NULL;
}
