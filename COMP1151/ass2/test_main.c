/*******************************************************************************
| DO NOT CHANGE THIS FILE
|
| You do not submit this file. This file is not marked.
| If you think you need to change this file you have
| misunderstood the assignment - ask in the course forum.
|
> CSpotify - 20T3 COMP1511 Assignment 2
| test_main.c
|
| You must not change this file.
|
| Version 1.0.0: Assignment released.
 *******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_cspotify.h"
#include "capture.h"

int main(void) {
    printf("\n*~~~~~~~~~~~~~~~~~~~~~~~{ CSpotify Tests }~~~~~~~~~~~~~~~~~~~~~~~*\n");

    printf("Stage 1 - Test add_playlist: ");
    test_add_playlist();

    printf("Stage 1 - Test rename_playlist: ");
    test_rename_playlist();

    printf("Stage 2 - Test add_track: ");
    test_add_track();

    printf("Stage 2 - Test playlist_length: ");
    test_playlist_length();

    printf("Stage 3 - Test delete_playlist: ");
    test_delete_playlist();

    printf("Stage 4 - Test soundex_search: ");
    test_soundex_search();

    printf("Your extra tests: ");
    extra_tests();

    return 0;
}