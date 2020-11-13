/*******************************************************************************
| DO NOT CHANGE THIS FILE
|
| You do not submit this file. This file is not marked.
| If you think you need to change this file you have
| misunderstood the assignment - ask in the course forum.
|
> CSpotify - 20T3 COMP1511 Assignment 2
| test_cspotify.h
|
| You must not change this file.
|
| Version 1.0.0: Assignment released.
 ******************************************************************************/

/*********
> STAGE 1
*********/

// TEST ADD PLAYLIST
// Test whether 'add_playlist' is doing the right thing.
//
// You should 'printf("MEETS SPEC\n");' if 'add_playlist'
// is working as the spec describes. If it doesn't do what
// the spec says it should 'printf("DOES NOT MEET SPEC\n");'.
//
// For full marks in this function, you should test at least
// two different cases of using the 'add_playlist' function.
// One test has already been provided to you, which you may
// keep or modify. It counts towards the two ways you are
// supposed to test.
// For instance:
//  - What if 'add_playlist' is given an invalid input?
//  - What if 'add_playlist' is used to add many Playlists 
//
// You should only need if statements and the functions in
// `cspotify.h` to test it, though you may use any C language
// features you have learned. You do not need to free memory.
void test_add_playlist(void);

// TEST RENAME PLAYLIST
// Test whether 'rename_playlist' is doing the right thing.
//
// You should 'printf("MEETS SPEC\n");' if 'rename_playlist'
// is working as the spec describes. If it doesn't do what
// the spec says it should 'printf("DOES NOT MEET SPEC\n");'.
//
// For full marks in this function, you should test at least
// two different cases of using the 'rename_playlist' function.
// One test has already been provided to you, which you may
// keep or modify. It counts towards the two ways you are
// supposed to test.
//
// You should only need if statements and the functions in
// `cspotify.h` to test it, though you may use any C language
// features you have learned. You do not need to free memory.
void test_rename_playlist(void);


/*********
> STAGE 2
*********/

// TEST ADD TRACK
// Test whether 'add_track' is doing the right thing.
//
// You should 'printf("MEETS SPEC\n");' if 'add_track'
// is working as the spec describes. If it doesn't do what
// the spec says it should 'printf("DOES NOT MEET SPEC\n");'.
//
// For full marks in this function, you should test at least
// two different cases of using the 'add_track' function.
//
// You should only need if statements and the functions in
// `cspotify.h` to test it, though you may use any C language
// features you have learned. You do not need to free memory.
void test_add_track(void);

// TEST PLAYLIST LENGTH
// Test whether 'playlist_length' is doing the right thing.
//
// You should 'printf("MEETS SPEC\n");' if 'playlist_length'
// is working as the spec describes. If it doesn't do what
// the spec says it should 'printf("DOES NOT MEET SPEC\n");'.
//
// For full marks in this function, you should test at least
// two different cases of using the 'playlist_length' function.
//
// You should only need if statements and the functions in
// `cspotify.h` to test it, though you may use any C language
// features you have learned. You do not need to free memory.
void test_playlist_length(void);


/*********
> STAGE 3
*********/

// TEST DELETE PLAYLIST
// Test whether 'delete_playlist' is doing the right thing.
//
// You should 'printf("MEETS SPEC\n");' if 'delete_playlist'
// is working as the spec describes. If it doesn't do what
// the spec says it should 'printf("DOES NOT MEET SPEC\n");'.
//
// For full marks in this function, you should test at least
// two different cases of using the 'delete_playlist' function.
//
// You should only need if statements and the functions in
// `cspotify.h` to test it, though you may use any C language
// features you have learned. You do not need to free memory.
void test_delete_playlist(void);


/*********
> STAGE 4
*********/

// TEST SOUNDEX SEARCH
// Test whether 'soundex_search' is doing the right thing.
//
// You should 'printf("MEETS SPEC\n");' if 'soundex_search'
// is working as the spec describes. If it doesn't do what
// the spec says it should 'printf("DOES NOT MEET SPEC\n");'.
//
// For full marks in this function, you should test at least
// two different cases of using the 'soundex_search' function.
//
// You should only need if statements and the functions in
// 'cspotify.h' to test it, though you may use any C language
// features you have learned. You do not need to free memory.
void test_soundex_search(void);


/*********
> EXTRA
*********/

// EXTRA TESTS
// Add any extra tests you'd like to write here!
void extra_tests(void);

// This is a helper function that lets you test if one
// string occurs in another string.
//
// For example:
// `string_contains("hello", "hi")` returns 0
// `string_contains("hello", "lo")` returns 1
int string_contains(char *haystack, char *needle);
