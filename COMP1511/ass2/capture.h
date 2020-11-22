//
// DO NOT CHANGE THIS FILE
//
// This file contains the `CAPTURE()` macro. To use this macro,
// you should define a large, empty string. Lets say your string is:
//   char str[MAX_LENGTH];
// Then you can do the following:
//   CAPTURE(my_function(), str, MAX_LENGTH)
// Which will put the output of `my_function()` into str.
//
// This file contains C features that have not been covered
// in COMP1511. You do not need to understand below this comment.
//
// You do not submit this file. This file is not marked.
// If you think you need to change this file you have
// misunderstood the assignment - ask in the course forum.
//
// Assignment 2 20T3 COMP1511: CSpotify
// capture.h
//
// You must not change this file.
//
// Version 1.0.0: Release

#include <stdio.h>

// Stores the stdout we cache.
struct cookie_cache;

// Starts redirecting stdout to a string.
struct cookie_cache *start_capture(char *buf, int size);

// Ends redirecting stdout to a file.
// Returns number of bytes read.
void end_capture(struct cookie_cache *cc);

// Macro to do capture without using two functions
#define CAPTURE(_FUNCTION_CALL, _STRING, _LEN) {                 \
        struct cookie_cache *cc = start_capture(_STRING, _LEN);  \
        _FUNCTION_CALL;                                          \
        end_capture(cc);                                         \
    }

