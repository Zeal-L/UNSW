/*******************************************************************************
| DO NOT CHANGE THIS FILE
|
| You do not submit this file. This file is not marked.
| If you think you need to change this file you have
| misunderstood the assignment - ask in the course forum.
|
> CSpotify - 20T3 COMP1511 Assignment 2
| cspotify.h
|
| You must not change this file.
|
| Version 1.0.0: Assignment released.
| Version 1.0.1: Clarification on rename_playlist and add_track.
| Version 1.0.2: Style fixes.
 ******************************************************************************/

#ifndef _CSPOTIFY_H_
#define _CSPOTIFY_H_

#define MAX_LEN 1024

#define SUCCESS 0

#define ERROR_INVALID_INPUTS -1
#define ERROR_NOT_FOUND -2

typedef struct library *Library;
typedef struct playlist *Playlist;
typedef struct track *Track;

/*******************************************************************************
> Getting Started
| Press '?' for help.
| Press 'q' to quit the program.
*******************************************************************************/


/*******************************************************************************
> STAGE 1 - Overview
| CREATE LIBRARY [Implemented]
| ADD PLAYLIST
| PRINT LIBRARY
| RENAME PLAYLIST
*******************************************************************************/

// CREATE LIBRARY
// Create a new Library and return a pointer to it.
//
// The pointer is allocated memory to point to using malloc, 
// and it is the caller's responsibility to free the memory
// using delete_library (a function you have to implement in Stage 3)
//
// This function has been implemented, though you may need to modify
// it if you change the provided struct library. 
Library create_library(void);

// ADD PLAYLIST - Command: A <playlistName>
// Add a new Playlist to the Library.
//
// Given:
//      - the name of a new Playlist
//      - a Library
// insert a new Playlist node at the end of the Playlists in the Library.
//
// If the given Playlist name contains character(s) other than alphabetical
// characters and/or digits, the Playlist name is invalid and 
// should not be added.
//
// You can assume that there will be no duplicates in the Playlist names given
// as input.
//
// All strings in this assignment are case sensitive and 
// are invalid if they are not alphanumeric.
//
// The first Playlist added to the Library should by default be "selected".
// When a selected Playlist is printed out in print_library 
// (next function to implement),
// the Playlist in the Library should be shown as the selected Playlist.
//
// The function should return one of the following #defines from cspotify.h:
//      - ERROR_INVALID_INPUTS if the given Playlist name is invalid.
//      - SUCCESS if a new Playlist node with the given name is 
//        successfully added.
//
// Hint: You will need to malloc new memory. 
// You will need to come up with a way to make a Playlist "selected".
int add_playlist(Library library, char playlistName[MAX_LEN]);

// PRINT LIBRARY - Command: P 
// Print out the Library.
//
// Given:
//      - a Library
// print out the details of the Library.
// 
// For example, for a Library containing the following Playlists:
//      - playlist1 <--- this being the "selected" Playlist
//      - playlist2
//      - playlist3
// Your function should print the following where each Playlist is numbered 
// to indicate the order of the Playlists in the Library:
// "[*] 0. playlist1\n"
// "[ ] 1. playlist2\n"
// "[ ] 2. playlist3\n"
//
// If Library does not have Playlists, the function should not print anything.
//
// You can assume that the given Library will not be NULL.
// 
// You should use the helper functions given in the starter code to print it
// out, instead of calling printf yourself, namely print_playlist, 
// print_selected_playlist and print_track.
//
// You may need to come back and modify this function after implementing
// Stage 2.
//
// The function should not return anything.
void print_library(Library library);

// RENAME PLAYLIST - Command: R <playlistName> <newPlaylistName>
// Rename the name of an existing Playlist.
// 
// Given:
//      - a Library
//      - a Playlist name
//      - a new Playlist name
// If the given Playlist name exists in the Library, rename the name of the 
// Playlist to the new Playlist name.
//
// You can assume that the given new Playlist name will not cause there to be 
// a duplicate of Playlist names in the Library.
//
// All strings in this assignment are case sensitive and 
// are invalid if they are not alphanumeric.
// 
// The function should return one of the following #defines from cspotify.h:
//      - ERROR_NOT_FOUND if the given Playlist name is not found otherwise,
//      - ERROR_INVALID_INPUTS if the new Playlist name is invalid
//      - SUCCESS if the Playlist was found and successfully renamed
// You should check for these cases in the same order as specified here.
int rename_playlist(Library library, char playlistName[MAX_LEN],
    char newPlaylistName[MAX_LEN]);


/*******************************************************************************
> STAGE 2 - Overview
| SELECT NEXT PLAYLIST
| SELECT PREVIOUS PLAYLIST
| ADD TRACK
| PLAYLIST LENGTH 
*******************************************************************************/

// SELECT NEXT PLAYLIST - Command: S
// Selects the next Playlist in the Library.
//
// Given:
//      - a Library
// change the selected Playlist to the Playlist after the currently selected
// Playlist in the Library based on the order in which the Playlists are stored
// in the Library.
//
// You cannot assume that the given Library has Playlists. 
//
// By default, if there are Playlists in the Library, the first Playlist in the 
// Library is selected 
// (as you would have implemented in Stage 1 in add_playlist).
//
// If the currently selected Playlist has no next Playlist, change the selected
// Playlist to the first Playlist in the Library.
//
// For example, for a Library containing the following Playlists:
//      - playlist1 
//      - playlist2
//      - playlist3 <--- this being the "selected" Playlist
//
// Calling select_next_playlist will make "playlist1" the new selected Playlist;
//      - playlist1 <--- this is now the "selected" Playlist
//      - playlist2
//      - playlist3 
//
// The function should not return anything.
void select_next_playlist(Library library);

// SELECT PREVIOUS PLAYLIST - Command: W
// Selects the previous Playlist in the Library.
//
// Given:
//      - a Library
// change the selected Playlist to the Playlist before the currently selected
// Playlist in the Library based on the order in which the Playlists are stored
// in the Library.
// 
// You cannot assume that the given Library has Playlists. 
//
// By default, if there are Playlists in the Library, the first Playlist in the 
// Library is selected 
// (as you would have implemented in Stage 1 in add_playlist).
//
// If the currently selected Playlist has no Playlist before it, 
// change the selected Playlist to the last Playlist in the Library.
//
// For example, for a Library containing the following Playlists:
//      - playlist1 <--- this being the "selected" Playlist
//      - playlist2
//      - playlist3 
//
// Calling select_previous_playlist will make "playlist3" the 
// new selected Playlist;
//      - playlist1 
//      - playlist2
//      - playlist3 <--- this is now the "selected" Playlist
//
// The function should not return anything.
void select_previous_playlist(Library library);

// ADD TRACK - Command: a <title> <artist> <trackLengthInSec> <position>
// Add a new Track to the selected Playlist.
//
// Given:
//      - the title
//      - the artist
//      - the track length (in seconds)
//      - the position number to insert at 
// insert a new Track node in the selected Playlist at the position specified by
// the position number only if the position number and 
// the track length is valid.
//
// Assume that position numbers start from 0 where inserting at the 0th position
// means inserting at the beginning of the Tracks in the Playlist. If there are
// no Tracks in the Playlist, inserting into the 0th position 
// will insert the Track.
// 
// For example:
// [ ] 0. playlist1
// [*] 1. playlist2
//        - LovesickGirls                       BLACKPINK                   02:10
//        - Dynamite                            BTS                         02:00
// [ ] 2. playlist3
// 
// After executing "a Wonder ShawnMendes 195 2", the above Library becomes:
// [ ] 0. playlist1
// [*] 1. playlist2
//        - LovesickGirls                       BLACKPINK                   02:10
//        - Dynamite                            BTS                         02:00
//        - Wonder                              ShawnMendes                 03:15
// [ ] 2. playlist3
//
// The position number is invalid if it is negative or greater than 
// the number of Tracks in the selected Playlist. 
//
// The track length is invalid if it is a negative number or 0.
//
// All strings in this assignment are case sensitive and 
// are invalid if they are not alphanumeric.
//
// It is possible to have the same Track appear multiple times in the Playlist.
//
// The function should return one of the following #defines from cspotify.h:
//      - ERROR_NOT_FOUND if there are no Playlists in the Library, otherwise
//      - ERROR_INVALID_INPUTS if the title/artist/position/track length is 
//        invalid.
//      - SUCCESS if a new Track node with the given information is successfully
//        added.
// You should check for these cases in the same order as specified here.
//
// Hint: You will need to malloc new memory. You will need to make changes
// to your print_library function in Stage 1 to call print_track
// so that it prints out the Tracks in Library Playlists.
int add_track(Library library, char title[MAX_LEN], char artist[MAX_LEN], 
    int trackLengthInSec, int position);

// PLAYLIST LENGTH - Command: T
// Calculate the total length of the selected Playlist in minutes and seconds.
//
// Given:
//      - a Library
//      - an int variable to store Playlist minutes (passed in by reference)
//      - an int variable to store Playlist seconds (passed in by reference)
// Calculate the total length of the selected Playlist and store the results in
// 'playlistLengthMin' and 'playlistLengthSec'
//
// For example, for a Library containing:
// [ ] 0. playlist1
// [*] 1. playlist2
//        - LovesickGirls                       BLACKPINK                   02:10
//        - Dynamite                            BTS                         02:00
//        - Wonder                              ShawnMendes                 03:15
// [ ] 2. playlist3
//
// The total length of the selected Playlist (playlist2) 
// is 7 minutes and 25 seconds.
// So the value of 7 should be stored in 'playlistLengthMin' and 25 should be
// stored in 'playlistLengthSec'.  
//
// If the selected Playlist has no Tracks, both `playlistLengthMin` and
// `playlistLengthSec` should store the values of 0.
//
// If the Library is empty with no Playlists, both `playlistLengthMin` and
// `playlistLengthSec` should store the values of -1.
//
// The function should not return anything.
void playlist_length(Library library, int *playlistLengthMin, 
    int *playlistLengthSec);


/*******************************************************************************
> STAGE 3 - Overview 
| DELETE TRACK
| DELETE PLAYLIST
| DELETE LIBRARY 
*******************************************************************************/
// DELETE TRACK - Command: d <track>
// Delete the first instance of the given Track in the selected Playlist
// of the Library.
//
// Given:
//      - a Library
//      - a Track name
// Delete the first instance of a Track with the given Track name in the 
// selected Playlist and free all associated memory.
//
// The function should not return anything.
void delete_track(Library library, char track[MAX_LEN]);

// DELETE PLAYLIST - Command: D
// Delete the selected Playlist and select the next Playlist in the Library.
//
// Given:
//      - a Library
// Delete the selected Playlist (and its Tracks) from the Library
// and free all associated memory. Select the next Playlist after the deleted 
// Playlist in the Library unless there are no more Playlists in the Library.
//
// If the currently selected deleted Playlist has no next Playlist, change the 
// selected Playlist to the first Playlist in the Library.
//
// The function should not return anything.
void delete_playlist(Library library);

// DELETE LIBRARY - Command: X 
// Delete an entire Library and its associated Playlists and Tracks.
//
// Given:
//      - a Library
// Free all associated memory. You will need to free all the memory associated 
// with each Playlist before freeing the Library itself.
//
// You can assume that this function will only be called right before you
// quit the program.
//
// The function should not return anything.
void delete_library(Library library);


/*******************************************************************************
> STAGE 4 - Overview
| CUT AND PASTE TRACK 
| SOUNDEX SEARCH
*******************************************************************************/
// CUT AND PASTE TRACK - Command: c <trackName> <destPlaylist>
// Cut the given Track in the selected Playlist and paste it into the given 
// destination Playlist.
// 
// Given: 
//      - a Library
//      - a track name
//      - a destination playlist name
// Remove the first Track instance which matches the given trackName from 
// the selected Playlist and add it into the end of the Playlist with the given 
// destination playlist name.
//
// If no Tracks in selected Playlist match the given Track name, do nothing.
//
// If the destination Playlist does not exist, do nothing.
//
// The function should return one of the following #defines from cspotify.h:
//      - ERROR_NOT_FOUND if any of the following is true:
//              - the given Track does not exist
//              - the given destination Playlist does not exist 
//              - the Library is empty
//      - SUCCESS if the Track has been successfully moved.
int cut_and_paste_track(Library library, char trackName[MAX_LEN], 
    char destPlaylist[MAX_LEN]);

// SOUNDEX SEARCH - Command: s <artist>
// Prints out all Tracks with artists that have the same Soundex Encoding 
// as the given artist.
//
// Given:
//      - a Library
//      - an artist
// Go through all the Tracks within the Library and print out the Tracks with 
// artists that have the same Soundex Encoding as the given artist.
//
// The Tracks should be printed in the order in which they are stored in the
// Library. 
//
// If there are Tracks to be printed from multiple Playlists, 
// the existing order of the Playlists should be preserved.
// If there are multiple Tracks from the same Playlist, 
// the existing order of the Tracks within that Playlist should be preserved.
//
// There are different variations of the Soundex Algorithm. For this function,
// the following algorithm (set of rules) should be followed to formulate a 
// Soundex encoding from a string;
//
// 1. Retain the first letter. 
// 2. Map all occurrences of a, e, i, o, u, y, h, w. to zero (0).
// 3. Replace all consonants after the first letter with digits based on the 
//    following mapping;
//    - b, f, p, v → 1
//    - c, g, j, k, q, s, x, z → 2
//    - d, t → 3
//    - l → 4
//    - m, n → 5
//    - r → 6
// 4. Replace all adjacent same digits with one digit, and then remove all the 
//    zero (0) digits
// 5. If the first digit matches the numerical encoding of the first letter,
//    remove the digit.
// 6. Append 3 zeros if result contains less than 3 digits. Remove all except 
//    first letter and 3 digits after it.
//
// For example, a Library containing:
// [*] 0. Workout
//        - Red                                 Taylor                      02:10
//        - BlankSpace                          teylor                      03:14
//        - 22                                  Tailor                      02:10
//        - Dynamite                            BTS                         02:00
// [ ] 1. Sleep
//        - Wonder                              Shawn                       03:15
//        - LoveStory                           Taylar                      03:56
//        - Stay                                BLACKPINK                   03:43
//
// 's Taylor' would produce the following output:
//        - Red                                 Taylor                      02:10
//        - BlankSpace                          teylor                      03:14
//        - 22                                  Tailor                      02:10
//        - LoveStory                           Taylar                      03:56
//
// Here are some more examples of the Soundex encodings:
//  - the encoding for "Marc" is M620.
//  - the encoding for "Taylor" is T460.
//
// For this function, the search for artists should be case insensitive.
// The output should retain the original letter case. 
// You can assume that all artists of Tracks already
// in the Library contain only alphabetical letters. 
// You will also need to check that the given artist name contains only 
// alphabetical letters.
//
// You should use the helper function given in the starter code to print the 
// Tracks out, instead of calling printf yourself, namely print_track. 
//
// The function should not return anything.
void soundex_search(Library library, char artist[MAX_LEN]);


/*******************************************************************************
> STAGE 5 - Overview
| ADD FILTERED PLAYLIST
| REORDER PLAYLIST
*******************************************************************************/
// ADD FILTERED PLAYLIST - Command: F <artist>
// Move all Tracks matching the Soundex encoding of the given artist 
// to a new Playlist.
//
// Given:
//      - a Library
//      - an artist name
// Move all Tracks in the Library matching the Soundex encoding of the given 
// artist name to a new Playist with the artist name. The new Playlist should 
// be appended at the end of the Library.
// The order of the Tracks should be preserved in the new Playlist.
// The Tracks should be the same order as they were in the Playlist 
// they came from.
//
// For example, a Library containing:
// [ ] 0. RoadTrip
//        - HowYouLikeThat                      BLaCkPiNk                   03:00
//        - IceCream                            BLACKPINK                   02:56
//        - IceBlock                            BLOCKPINK                   01:30
// [ ] 1. StudyMusic
// [*] 2. Hype
//        - Whistle                             blackpink                   02:10
//        - BadGuy                              BillieEilish                03:14
//        - PrettySavage                        BLACKPINK                   02:10
//        - LovesickGirls                       BLACKPINK                   02:10
//        - Dynamite                            BTS                         02:00
// [ ] 3. SleepMusic
//        - Wonder                              ShawnMendes                 03:15
//        - LoveStory                           TaylorSwift                 03:56
//        - Stay                                BLACKPINK                   03:43
// 
// 'F BLOCKPINK' would produce the following when the Library is printed:
// [ ] 0. RoadTrip
// [ ] 1. StudyMusic
// [*] 2. Hype
//        - BadGuy                              BillieEilish                03:14
//        - Dynamite                            BTS                         02:00
// [ ] 3. SleepMusic
//        - Wonder                              ShawnMendes                 03:15
//        - LoveStory                           TaylorSwift                 03:56
// [ ] 4. BLOCKPINK
//        - HowYouLikeThat                      BLaCkPiNk                   03:00
//        - IceCream                            BLACKPINK                   02:56
//        - IceBlock                            BLOCKPINK                   01:30
//        - Whistle                             blackpink                   02:10
//        - PrettySavage                        BLACKPINK                   02:10
//        - LovesickGirls                       BLACKPINK                   02:10
//        - Stay                                BLACKPINK                   03:43
//
// A Playlist with the given artist name BLOCKPINK was created. BLOCKPINK has a
// Soundex encoding of B421. BLACKPINK's (case insensitive) encoding is also 
// B421.
// Hence the new Playlist BLOCKPINK contains both Tracks from BLOCKPINK and 
// BLACKPINK. 
//
// If there are no Tracks by the specified artist, a new Playlist with the 
// artist name should still be created without any Tracks and appended to 
// the end of the Library.
//
// The new Playlist should not be created and added 
// if the artist name is invalid.
//
// The new Playlist should not be created and added if a Playlist with 
// this artist name already exists.
//
// For this function, the search for artists should be case insensitive. 
// Artists of Tracks that have been moved to the new Playlist should
// retain their original letter case. 
// You can assume that all artists of Tracks already
// in the Library contain only alphabetical letters. You will also need to 
// check that the given artist name contain only alphabetical letters.
//
// The function should return one of the following #defines from cspotify.h:
//      - ERROR_INVALID_INPUTS if the given artist name contains characters 
//          other than alphabetical letters or if a Playlist with the same 
//          artist name already exists.
//      - SUCCESS if the Playlist has been successfully added.
int add_filtered_playlist(Library library, char artist[MAX_LEN]);

// REORDER PLAYLIST - Command: r <length>
// Reorder the selected Playlist in the given order specified 
// by the order array.
//
// This function differs slightly in the way in which the command is executed.
// To execute the command for this program, use the command r <length> where
// <length> is the number of Tracks in the selected Playlist. Then the program
// will prompt you to enter an order where you will input all integers from
// 0 to length - 1 without duplicates in a random order. 
//
// Given:
//      - a Library
//      - an int array specifying an order
//      - the length of the order array
// Reorder the Tracks in the selected Playlist based on the order in the given
// array.
//
// For example, for a Library containing:
// [ ] 0. RoadTrip
//        - HowYouLikeThat                      BLACKPINK                   03:00
//        - IceCream                            BLACKPINK                   02:56
// [ ] 1. StudyMusic
// [*] 2. Hype
//        - Whistle                             BLACKPINK                   02:10
//        - BadGuy                              BillieEilish                03:14
//        - PrettySavage                        BLACKPINK                   02:10
//        - LovesickGirls                       BLACKPINK                   02:10
//        - Dynamite                            BTS                         02:00
// [ ] 3. SleepMusic
//        - Wonder                              ShawnMendes                 03:15
//        - LoveStory                           TaylorSwift                 03:56
//        - Stay                                BLACKPINK                   03:43
//
// If the following were executed:
// Please Enter Command: r 5
// Enter order:
// 4 3 2 0 1
// 
// Then the resulting selected Playlist will follow the given order:
// [ ] 0. RoadTrip
//        - HowYouLikeThat                      BLACKPINK                   03:00
//        - IceCream                            BLACKPINK                   02:56
// [ ] 1. StudyMusic
// [*] 2. Hype
//        - Dynamite                            BTS                         02:00
//        - LovesickGirls                       BLACKPINK                   02:10
//        - PrettySavage                        BLACKPINK                   02:10
//        - Whistle                             BLACKPINK                   02:10
//        - BadGuy                              BillieEilish                03:14
// [ ] 3. SleepMusic
//        - Wonder                              ShawnMendes                 03:15
//        - LoveStory                           TaylorSwift                 03:56
//        - Stay                                BLACKPINK                   03:43
// 
// You can assume that the input order array and the input length is valid and 
// do not have to handle cases otherwise.
// 
// The function should not return anything.
void reorder_playlist(Library library, int order[MAX_LEN], int length);

#endif //  _CSPOTIFY_H_
