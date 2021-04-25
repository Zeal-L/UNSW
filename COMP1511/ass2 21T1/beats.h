//
// DO NOT CHANGE THIS FILE
//
// You do not submit this file. This file is not marked.
// If you think you need to change this file you have
// misunderstood the assignment - ask in the course forum.
//
// Assignment 2 21T1 COMP1511: CS bEats
// beats.h
//
// You must not change this file.
//
// Version 1.0.0: Release

#ifndef _BEATS_H_
#define _BEATS_H_

#define VALID_NOTE 0
#define INVALID_KEY -1
#define INVALID_OCTAVE -2
#define NOT_HIGHEST_NOTE -3

#define TRACK_PLAYING 1
#define TRACK_STOPPED 0

typedef struct track *Track;
typedef struct beat *Beat;


////////////////////////////////////////////////////////////////////////
//                         Stage 1 Functions                          //
////////////////////////////////////////////////////////////////////////



// Create a new Beat and return a pointer to it.
//
// The pointer is allocated memory to point to using malloc, 
// and it is the caller (the function that calls create_beat)'s
// responsibility to free the memory (using remove_selected_beat -
// a function you have to implement in Stage 3).
//
// This function has been implemented, though you may need to modify
// it if you change the provided struct beat. 
Beat create_beat(void);

////////////////////////////////////////////////////////////////////////
// ADD NOTE TO BEAT - Command 'a'

// Add a new Note to the Beat, if it's a valid octave & key, and if
// it's larger than the Notes in the Beat. Otherwise, return an
// error code.
//
// New Notes are only allowed to be added to a Beat if:
/// - They have a valid octave. 
//    An octave is valid if it is a non-negative integer less than 10. 
//    For example:
//      - -1 is negative, so not a valid octave.
//      - 10 is not less than 10, so not a valid octave.
//      - 0, 1, ..., 8, 9 are all valid octaves.
//  - They have a valid key. 
//    A key is valid if it is a non-negative integer less than 12. 
//    For example:
//      - -1 is negative, so not a valid key.
//      - 12 is not less than 12, so not a valid key.
//      - 0, 1, ..., 10, 11 are all valid keys.
//  - The new Note is higher than the Notes in the beat, that is:
//    - The new Note is not a lower octave than any Note in the Beat.
//      For example, in a beat with one Note with octave 2, and note 5:
//        - You could not add a note with octave 1 and note 6,
//          since the Beat already has a higher octave.
//        - You could add a note with octave 2 and note 6, since
//          the Beat's highest octave is 2.
//    - If the octaves are the same, the new Note's key must be higher.
//      For example, in a beat with one note; octave 2, and key 5
//        - You could not add a Note with octave 2 and key 4,
//          since there is a Note with octave 2 and a higher note (5).
//        - You could not add a Note with octave 2 and key 5,
//          since there is already a Note with octave 2 and key 5.
//        - You could add a note with octave 2 and key 6, since
//          there is no Note with octave 2, and a higher key.
//
// The new Note should be added to the end of the Beat's
// list of notes. This means that you should add the Note
// directly after the Note that was added the last time
// `add_note_to_beat` was called.
//
// If a Note exists in the Beat already, you should not add it again. 
// For instance:
// If a Beat contains the Note with octave 3 and key 11, you should
// not add another Note with the same octave and key. You should return
// `NOT_HIGHEST_NOTE`.
//
// Notes in a Beat should always be sorted in ascending order, first by
// octave, then by key. 
// For instance, "3 10" comes before "3 11" which comes before "4 0".
//
// `add_note_to_beat` will be passed:
// - `beat`, a pointer to a Beat, created with `create_beat`. You
//   are guaranteed `beat` will not be NULL.
// - `octave`, an int that may or may not be a valid octave.
// - `key`, an int that may or may not be a valid note.
//
// `add_note_to_beat` should return one of the following #defines from beats.h:
// - `INVALID_OCTAVE` if the octave is not valid.
// - `INVALID_KEY` if the octave is valid, but the key is not.
// - `NOT_HIGHEST_NOTE` if the key is valid, but is not the
//    highest note in the Beat.
// - `VALID_NOTE` otherwise.
//
int add_note_to_beat(Beat beat, int octave, int key);

////////////////////////////////////////////////////////////////////////
// PRINT BEAT - Command 'p'

// Print out the beat passed to the function.
//
// print_beat should print out all the Notes in the given Beat on one line.
// Each Beat consists of two numbers, the octave then the key.
// They will be separated by the characters " | " and the line will end in
// a newline ('\n').
// The notes will be printed out in ascending order, which is the same
// order that the list should be in.
//
// For a Beat containing no notes, `print_beat` should print an empty line:
// "\n"
//
// For a Beat containing a note with octave 0, and note 9,
// `print_beat` should print:
// "0 09\n"
//
// For a Beat containing:
//   - A Note with octave 0, and note 10.
//   - A Note with octave 2, and note 10.
// `print_beat` should print:
// "0 10 | 2 10\n"
//
// For a beat containing:
//   - A Note with octave 1, and note 10.
//   - A Note with octave 2, and note 10.
//   - A Note with octave 3, and note 10.
// "1 10 | 2 10 | 3 10\n"
//
// `print_beat` will be passed:
// - `beat`, a pointer to a Beat, created with `create_beat`, and possibly
//   with notes added by `add_note_to_beat`. You are guaranteed `beat`
//   will not be NULL.
//
// `print_beat` will not return a value, but should print to stdout.
void print_beat(Beat beat);

////////////////////////////////////////////////////////////////////////
// COUNT NOTES IN OCTAVE - Command 'c'

// Return the number of Notes in a Beat that are within a given octave.
//
// This function should return the number of Notes in the given Beat
// that are in the given octave.
//
// It is possible that `octave` will not represent a valid octave, or
// that the given beat will not have any notes with the given octave.
// In these cases, this function should return 0.
//
// `count_notes_in_octave` will be passed:
// - `beat`, a pointer to a Beat, created with `create_beat`, and possibly
//   with notes added by `add_note_to_beat`. You are guaranteed `beat`
//   will not be NULL.
// - `octave`, an integer.
//
// `count_notes_in_octave` should return the number of notes in `beat` 
// that match the same octave as `octave`.
int count_notes_in_octave(Beat beat, int octave);

////////////////////////////////////////////////////////////////////////
//                         Stage 2 Functions                          //
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// CREATE TRACK

// Create a new Track and return a pointer to it.
//
// The pointer should be created using malloc, and it is the caller's
// responsibility to free the memory (using free_track).
//
// A track will need to store information about a 'currently selected Beat'.
// A track starts off with no currently selected Beat. We call a track with
// no currently selected beat a 'stopped' track. Later in Stage 2, you will
// be able to change the currently selected beat. If a Track has a currently
// selected Beat, we can say that track is 'playing'.
//
// The Track should have no Beats, and should be 'stopped' (that is,
// it should have no currently selected Beat).
//
// `create_track` is passed no arguments.
//
// `create_track` should return a pointer to a new Track.
Track create_track(void);

////////////////////////////////////////////////////////////////////////
// ADD BEAT TO TRACK - Command 'A'

// Add a Beat after the currently selected Beat in a Track.
//
// If a Track is 'playing' (it has a currently selected Beat),
// insert the given Beat into the Track after the currently selected Beat.
//
// If a Track is 'stopped' (it has no currently selected Beat),
// add the Beat as the first element of the Track.
//
// Adding a Beat does not change whether a Track is started or stopped,
// and does not change what the currently selected Beat is, if there is one.
//
// `add_beat_to_track` will be passed:
// - `track`, a pointer to a Track, created with `create_track`. You
//   are guaranteed `track` will not be NULL.
// - `beat`, a pointer to a Beat, created with `create_beat`. You
//   are guaranteed `beat` will not be NULL.
//
// `add_beat_to_track` should not return a value.
void add_beat_to_track(Track track, Beat beat);

////////////////////////////////////////////////////////////////////////
// SELECT NEXT BEAT - Command '>'

// Given a Track, select the Beat in that Track after the
// currently selected Beat, then return the status of the Track.
//
// If the Track is 'stopped', and contains at least one Beat,
// the first Beat in the track should become the selected Beat.
// Otherwise, the track should remain 'stopped'.
//
// If the currently selected beat in the track is the last Beat
// currently in the track, the track should become 'stopped', and
// it should have no currently selected Beat.
//
// `select_next_beat` will be passed:
// - `track`, a pointer to a Track, created with `create_track`. You
//   are guaranteed `track` will not be NULL.
//
// `select_next_beat` should return one of the following #defines:
// - `TRACK_PLAYING` if after this function is called, the track is playing.
// - `TRACK_STOPPED` if after this function is called, the track is stopped.
int select_next_beat(Track track);

////////////////////////////////////////////////////////////////////////
// PRINT TRACK - Command 'P'

// Print the current state of a Track.
//
// If the Track currently has no Beat, this function should not print anything.
//
// Otherwise, print one line for each Beat in the Track, containing:
// - '>' as the first character, if the Beat is the currently selected Beat.
//   otherwise, a ' '.
// - '[', then the index of this Beat, starting at 1, then by a ']', and a ' '.
// - If the Beat has any Notes, each Note in the Beat, in ascending order,
//   separated by the characters " | ".
// - A newline ('\n')
//
// As an example. If a Track has 4 Beats (with the 3rd one being selected):
// - The first has the Note 1 02.
// - The second has no notes.
// - The third has the Notes 1 03, 1 04, 1 05. This note is selected.
// - The fourth has the Notes 1 04, 1 05, 1 06.
// Then `print_track` would print:
//   [1] 1 02
//   [2]
//  >[3] 1 03 | 1 04 | 1 05
//   [4] 1 04 | 1 05 | 1 06
//
// `print_track` will be passed:
// - `track`, a pointer to a Track, created with `create_track`.
//   You are guaranteed `track` will not be NULL.
//
// `print_track` will not return a value, but should print to stdout.
void print_track(Track track);

////////////////////////////////////////////////////////////////////////
// COUNT BEATS LEFT IN TRACK - Command 'C'

// Return the number of beats left in the track.
//
// This function should return the number of beats after the currently
// selected beat in the given track. Should the track be 'stopped',
// this function should return the number of beats in the track.
//
// This function should not modify the Track in any way.
//
// As an example, if `print_track` shows the following:
//   [1] 1 02
//   [2]
//  >[3] 1 03 | 1 04 | 1 05
//   [4] 1 04 | 1 05 | 1 06
// Then calling `count_beats_left_in_track` on that track would return 1.
//
// As an example, if `print_track` shows the following:
//  >[1] 1 02
//   [2]
//   [3] 1 03 | 1 04 | 1 05
//   [4] 1 04 | 1 05 | 1 06
// Then calling `count_beats_left_in_track` on that track would return 3.
//
// `count_beats_left_in_track` will be passed:
// - `track`, a pointer to a Track, created with `create_track`.
//   You are guaranteed `track` will not be NULL.
//
// `count_beats_left_in_track` will return the number of beats in the track
// if the track is 'stopped', and the number of beats after the
// currently selected beat otherwise.
int count_beats_left_in_track(Track track);

////////////////////////////////////////////////////////////////////////
//                         Stage 3 Functions                          //
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// FREE BEAT

// Call free on a Beat, and free all associated memory. You will need 
// to free the memory associated with the notes in the beat before
// freeing the beat itself.
//
// `free_beat` will be passed:
// - `beat`, a pointer to a Beat, created with `create_beat`.
//   `beat` may be NULL; if it is, `free_beat` should do nothing.
//
// `free_beat` will not return a value, and should not print to stdout
// or stderr (even if beat is NULL).
void free_beat(Beat beat);

////////////////////////////////////////////////////////////////////////
// FREE TRACK

// Call free on a Track, and free all associated memory. You will need
// to free the memory associated with the beats in the track before
// freeing the track itself.
//
// `free_track` will be passed:
// - `track`, a pointer to a Track, created with `create_track`.
//   `track` may be NULL; if it is, `free_track` should do nothing.
//
// `free_track` will not return a value, and should not print to stdout
// or stderr (even if track is NULL).
void free_track(Track track);

////////////////////////////////////////////////////////////////////////
// REMOVE SELECTED BEAT - Command 'R'

// Remove the selected Beat from the given Track.
//
// If the Track is playing, this function should remove the
// currently selected Beat from the Track.
// The next Beat should become the selected Beat.
// If there is no next Beat (i.e the selected beat was the last beat
// in the Track), the Track becomes stopped, and there should be no
// selected Beat.
//
// If the Track is stopped, this function should do nothing.
//
// For example, this Track gives the following output with `print_track`:
//   [1] 1 02
//   [2]
//  >[3] 1 03 | 1 04
//   [4] 1 04 | 1 05 | 1 06
//
// After calling `remove_selected_beat` on the track, `print_track` would show:
//   [1] 1 02
//   [2]
//  >[3] 1 04 | 1 05 | 1 06
//
// After calling `remove selected_beat` again, `print_track` would show:
//   [1] 1 02
//   [2]
//
// `remove_selected_beat` will be passed:
// - `track`, a pointer to a Track, created with `create_track`. You
//   are guaranteed `track` will not be NULL.
//
// `remove_selected_beat` should return one of the following #defines:
// - `TRACK_PLAYING` if after this function is called, the track is playing.
// - `TRACK_STOPPED` if after this function is called, the track is stopped.
int remove_selected_beat(Track track);

// Extension content is in ext_beats.h

#endif //  _BEATS_H_
