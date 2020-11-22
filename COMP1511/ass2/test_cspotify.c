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
    Library testLibrary2 = create_library();

    int result2 = add_playlist(testLibrary2, "/*-+*/*-/*+");
    if (result2 != ERROR_INVALID_INPUTS) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    // Test 3: add playlist multiple
    Library testLibrary3 = create_library();

    add_playlist(testLibrary3, "123");
    add_playlist(testLibrary3, "456");
    add_playlist(testLibrary3, "789");

    char printText2[10000];
    CAPTURE(print_library(testLibrary3), printText2, 10000);
    if (!string_contains(printText2, "[*] 0. 123\n[ ] 1. 456\n[ ] 2. 789")) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

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
    Library testLibrary1 = create_library();
    add_playlist(testLibrary1, "Favourites");
    rename_playlist(testLibrary1, "Favourites", "Dislikes");
    char printText1[10000];
    CAPTURE(print_library(testLibrary1), printText1, 10000);
    if (!string_contains(printText1, "Dislikes")) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    // Test 3: rename playlist multiple
    Library testLibrary2 = create_library();
    add_playlist(testLibrary2, "Favourites");
    rename_playlist(testLibrary2, "Favourites", "Dislikes");
    rename_playlist(testLibrary2, "Dislikes", "aaa");
    rename_playlist(testLibrary2, "aaa", "bbb");
    char printText2[10000];
    CAPTURE(print_library(testLibrary2), printText2, 10000);
    if (!string_contains(printText2, "bbb")) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    // Test 4: Rename playlist multiple
    Library testLibrary3 = create_library();
    add_playlist(testLibrary3, "Favourites");
    int result_2 = rename_playlist(testLibrary3, "Favourites", "/-*+++&(#&^%");
    if (result_2 != ERROR_INVALID_INPUTS) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

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
    Library testLibrary_1 = create_library();
    add_playlist(testLibrary_1, "Favourites");
    add_track(testLibrary_1, "aaa", "Zeal", 100, 0);
    add_track(testLibrary_1, "bbb", "Zeal", 100, 1);
    add_track(testLibrary_1, "ccc", "Zeal", 100, 2);
    add_track(testLibrary_1, "zzz", "Zeal", 100, 0);
    add_track(testLibrary_1, "www", "Zeal", 100, 2);
    char printText_1[10000];
    CAPTURE(print_library(testLibrary_1), printText_1, 10000);
    if (!(string_contains(printText_1, "zzz                                 Zeal                        01:40\n       - aaa")
        && string_contains(printText_1, "aaa                                 Zeal                        01:40\n       - www")
        && string_contains(printText_1, "www                                 Zeal                        01:40\n       - bbb") 
        && string_contains(printText_1, "bbb                                 Zeal                        01:40\n       - ccc")
        && string_contains(printText_1, "ccc                                 Zeal                        01:40"))) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }


    // Test 2: Invalid inputs
    Library testLibrary_2 = create_library();
    add_playlist(testLibrary_2, "Favourites");
    int result = add_track(testLibrary_2, "+++", "---", 100, 0);
    if (result != ERROR_INVALID_INPUTS) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }
    int result_1 = add_track(testLibrary_2, "aaa", "aaa", -1, -1);
    if (result_1 != ERROR_INVALID_INPUTS) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    // Test 3: If Library is empty
    Library testLibrary_3 = create_library();
    int result_2 = add_track(testLibrary_3, "aaa", "aaa", 100, 0);
    if (result_2 != ERROR_NOT_FOUND) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }
    
    printf("MEETS SPEC\n");
}

// Test function for 'playlist_length'
void test_playlist_length(void) {
    // Test 1: Does playlist_length work for Tracks 
    // with lengths greater than 60 seconds?
    Library testLibrary_1 = create_library();
    add_playlist(testLibrary_1, "123");
    add_track(testLibrary_1, "aaa", "Zeal", 101, 0);
    add_track(testLibrary_1, "bbb", "Zeal", 100, 1);
    add_track(testLibrary_1, "ccc", "Zeal", 100, 2);
    char printText_1[10000];
    int playlistMinutes, playlistSeconds;
    playlist_length(testLibrary_1, &playlistMinutes, &playlistSeconds);
    CAPTURE(printf("Selected playlist total length: "
                "%d minutes %d seconds\n", 
                playlistMinutes, playlistSeconds);, printText_1, 10000);
    if (!string_contains(printText_1, "Selected playlist total length: 5 minutes 1 seconds")) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    // Test 2: If Playlist is empty
    Library testLibrary_2 = create_library();
    add_playlist(testLibrary_2, "123");
    char printText_2[10000];
    int playlistMinutes_1, playlistSeconds_1;
    playlist_length(testLibrary_2, &playlistMinutes_1, &playlistSeconds_1);
    CAPTURE(printf("Selected playlist total length: "
                "%d minutes %d seconds\n", 
                playlistMinutes_1, playlistSeconds_1);, printText_2, 10000);
    if (!string_contains(printText_2, "Selected playlist total length: 0 minutes 0 seconds")) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    // Test 3: If Library is empty
    Library testLibrary_3 = create_library();
    char printText_3[10000];
    int playlistMinutes_2, playlistSeconds_2;
    playlist_length(testLibrary_3, &playlistMinutes_2, &playlistSeconds_2);
    CAPTURE(printf("Selected playlist total length: "
                "%d minutes %d seconds\n", 
                playlistMinutes_2, playlistSeconds_2);, printText_3, 10000);
    if (!string_contains(printText_3, "Selected playlist total length: -1 minutes -1 seconds")) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

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
    Library testLibrary_1 = create_library();
    add_playlist(testLibrary_1, "aaa");
    delete_playlist(testLibrary_1);
    char printText_1[10000];
    CAPTURE(print_library(testLibrary_1), printText_1, 10000);
    if (string_contains(printText_1, "aaa")) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    // Test 2: Delete the middle Playlist.
    Library testLibrary_2 = create_library();
    add_playlist(testLibrary_2, "aaa");
    add_playlist(testLibrary_2, "bbb");
    add_playlist(testLibrary_2, "ccc");
    select_next_playlist(testLibrary_2);
    delete_playlist(testLibrary_2);
    char printText_2[10000];
    CAPTURE(print_library(testLibrary_2), printText_2, 10000);
    if (!string_contains(printText_2, "[ ] 0. aaa\n[*] 1. ccc")) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    printf("MEETS SPEC\n");
}


/*********
> STAGE 4
*********/

// Test function for 'soundex_search'
void test_soundex_search(void) {
    // Test 1: 
    Library testLibrary_1 = create_library();
    add_playlist(testLibrary_1, "123");
    add_playlist(testLibrary_1, "456");
    add_playlist(testLibrary_1, "789");
    add_track(testLibrary_1, "aaa", "zeal", 100, 0);
    add_track(testLibrary_1, "bbb", "ZEAL", 100, 1);
    select_next_playlist(testLibrary_1);
    add_track(testLibrary_1, "ccc", "zeall", 100, 0);
    select_next_playlist(testLibrary_1);
    add_track(testLibrary_1, "ddd", "zeeal", 100, 0);
    char printText_1[10000];
    CAPTURE(soundex_search(testLibrary_1, "Zeal"), printText_1, 10000);
    if (!(string_contains(printText_1, "aaa                                 zeal                        01:40\n       - bbb")
        && string_contains(printText_1, "bbb                                 ZEAL                        01:40\n       - ccc")
        && string_contains(printText_1, "ccc                                 zeall                       01:40\n       - ddd")
        && string_contains(printText_1, "ddd                                 zeeal                       01:40"))) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    // Test 2: 
    Library testLibrary_2 = create_library();
    add_playlist(testLibrary_2, "Workout");
    add_playlist(testLibrary_2, "Sleep");
    add_track(testLibrary_2, "Red", "Taylor", 130, 0);
    add_track(testLibrary_2, "BlankSpace", "teylor", 194, 1);
    add_track(testLibrary_2, "22", "Tailor", 130, 2);
    add_track(testLibrary_2, "Dynamite", "BTS", 120, 3);
    select_next_playlist(testLibrary_2);
    add_track(testLibrary_2, "Wonder", "Shawn", 195, 0);
    add_track(testLibrary_2, "LoveStory", "Taylar", 236, 1);
    add_track(testLibrary_2, "Stay", "BLACKPINK", 223, 2);
    select_previous_playlist(testLibrary_2);
    char printText_2[10000];
    CAPTURE(soundex_search(testLibrary_2, "Taylor"), printText_2, 10000);
    if (!(string_contains(printText_2, "Red                                 Taylor                      02:10\n       - BlankSpace")
        && string_contains(printText_2, "BlankSpace                          teylor                      03:14\n       - 22")
        && string_contains(printText_2, "22                                  Tailor                      02:10\n       - LoveStory")
        && string_contains(printText_2, "LoveStory                           Taylar                      03:56"))) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    // Test 3:  Check invalid inputs
    Library testLibrary_3 = create_library();
    add_playlist(testLibrary_3, "123");
    add_track(testLibrary_3, "aaa", "zeal", 100, 0);
    char printText_3[10000];
    CAPTURE(soundex_search(testLibrary_3, "++++"), printText_3, 10000);
    if (string_contains(printText_3, "aaa")) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

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
