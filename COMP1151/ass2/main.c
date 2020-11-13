/*******************************************************************************
| DO NOT CHANGE THIS FILE
|
| You do not submit this file. This file is not marked.
| If you think you need to change this file you have
| misunderstood the assignment - ask in the course forum.
|
> CSpotify - 20T3 COMP1511 Assignment 2
| main.c
|
| You must not change this file.
|
| Version 1.0.0: Assignment released.
| Version 1.0.1: Style and typo fixes. Error message added.
 *******************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include "cspotify.h"

#define MAX_COMMAND_LENGTH 2048

#define COMMAND_HELP '?'
#define COMMAND_QUIT 'q'

#define COMMAND_ADD_PLAYLIST 'A'
#define COMMAND_PRINT_LIBRARY 'P'
#define COMMAND_RENAME_PLAYLIST 'R'

#define COMMAND_NEXT_PLAYLIST 'S'
#define COMMAND_PREVIOUS_PLAYLIST 'W'
#define COMMAND_ADD_TRACK 'a'
#define COMMAND_PLAYLIST_LENGTH 'T'

#define COMMAND_DELETE_LIBRARY 'X'
#define COMMAND_DELETE_PLAYLIST 'D'
#define COMMAND_DELETE_TRACK 'd'

#define COMMAND_CUT_AND_PASTE_TRACK 'c'
#define COMMAND_SOUNDEX_SEARCH 's'

#define COMMAND_ADD_FILTERED_PLAYLIST 'F'
#define COMMAND_REORDER_PLAYLIST 'r'

void do_print_help(void);

int main(void) {
    printf("\n");
    printf("* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~{ CSpotify }~~~~~~~~~~~~~~~~~~~~~~~"
        "~~~~~~ *\n");
    printf("|                                                                 "
        "        |\n");
    printf("| CSpotify says hello world!                                      "
        "        |\n");
    printf("| We are a local music streaming service that does not stream any "
        "music.  |\n");
    printf("| Enter '?' for help. Press 'q' to quit the program.              "
        "        |\n");
    printf("|                                                                 "
        "        |\n");
    printf("* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        "~~~~~~ *\n");

    Library library = create_library();

    char ignoreChar;
    int keepLooping = 1;
    while (keepLooping) {
        char command[MAX_COMMAND_LENGTH];
        printf("\n");
        printf("Please Enter Command: ");

        if (fgets(command, MAX_COMMAND_LENGTH, stdin) == NULL) {
            return 0;
        }
        if (command[0] == COMMAND_QUIT 
            && (command[1] == ' ' || command[1] == '\n')) {
            if (library != NULL) {
                printf("delete_library not called before quitting...\n"
                    "Calling delete_library...\n");
                delete_library(library);
            }
            printf("Quitting the program...\n");
            return 0;
        }
        
        if (command[0] == COMMAND_ADD_PLAYLIST 
            && (command[1] == ' ' || command[1] == '\n')) {
            char newPlaylistName[MAX_LEN];
            int numScanned = sscanf(command, "%c %s", &ignoreChar, 
                newPlaylistName);
            if (numScanned != 2) {
                printf("Invalid command!\n");
                continue;
            }
            if (library == NULL) {
                printf("The library has been deleted. "
                    "You do not need to consider this case.\n");
                exit(1);
            }
            int result = add_playlist(library, newPlaylistName);
            if (result == ERROR_INVALID_INPUTS) {
                printf("The given playlist name is invalid!\n");
            } else if (result == SUCCESS) {
                printf("New playlist added successfully!\n");
            }
        } else if (command[0] == COMMAND_PRINT_LIBRARY 
            && (command[1] == ' ' || command[1] == '\n')) {
            printf("Your Library "
                "(Empty if nothing has been added/printed): \n");
            print_library(library);
        } 

        // STAGE 2
        else if (command[0] == COMMAND_RENAME_PLAYLIST 
            && (command[1] == ' ' || command[1] == '\n')) {
            char oldPlaylistName[MAX_LEN];
            char newPlaylistName[MAX_LEN];
            int numScanned = sscanf(command, "%c %s %s", &ignoreChar, 
                oldPlaylistName, newPlaylistName);
            if (numScanned != 3) {
                printf("Invalid command!\n");
                continue;
            }
            if (library == NULL) {
                printf("The library has been deleted. "
                    "You do not need to consider this case.\n");
                exit(1);
            }
            int result = rename_playlist(library, oldPlaylistName, 
                newPlaylistName);
            if (result == ERROR_NOT_FOUND) {
                printf("The given playlist does not exist!\n");
            } else if (result == ERROR_INVALID_INPUTS) {
                printf("The new playlist name is invalid!\n");
            } else if (result == SUCCESS) {
                printf("The playlist has been successfully renamed!\n");
            }
        } else if (command[0] == COMMAND_NEXT_PLAYLIST 
            && (command[1] == ' ' || command[1] == '\n')) {
            if (library == NULL) {
                printf("The library has been deleted. "
                    "You do not need to consider this case.\n");
                exit(1);
            }
            select_next_playlist(library);
            printf("Selected next playlist.\n");
        } else if (command[0] == COMMAND_PREVIOUS_PLAYLIST 
            && (command[1] == ' ' || command[1] == '\n')) {
            if (library == NULL) {
                printf("The library has been deleted. "
                    "You do not need to consider this case.\n");
                exit(1);
            }
            select_previous_playlist(library);
            printf("Selected previous playlist.\n");
        } else if (command[0] == COMMAND_ADD_TRACK 
            && (command[1] == ' ' || command[1] == '\n')) {
            char title[MAX_LEN]; 
            char artist[MAX_LEN];
            int trackLength;
            int position;
            int numScanned = sscanf(command, "%c %s %s %d %d", &ignoreChar, 
                title, artist, &trackLength, &position);
            if (numScanned != 5) {
                printf("Invalid command!\n");
                continue;
            }
            if (library == NULL) {
                printf("The library has been deleted. "
                    "You do not need to consider this case.\n");
                exit(1);
            }

            int result = add_track(library, title, artist, trackLength, 
                position);
            if (result == ERROR_INVALID_INPUTS) {
                printf("The given input(s) may be invalid!\n");
            } else if (result == ERROR_NOT_FOUND) {
                printf("There is no playlist to add track to!\n");
            } else if (result == SUCCESS) {
                printf("Track has been successfully added to playlist!\n");
            }
        } else if (command[0] == COMMAND_PLAYLIST_LENGTH 
            && (command[1] == ' ' || command[1] == '\n')) {
            if (library == NULL) {
                printf("The library has been deleted. "
                    "You do not need to consider this case.\n");
                exit(1);
            }
            int playlistMinutes, playlistSeconds;
            playlist_length(library, &playlistMinutes, &playlistSeconds);
            printf("Selected playlist total length: "
                "%d minutes %d seconds\n", 
                playlistMinutes, playlistSeconds);
        } 

        // STAGE 3
        else if (command[0] == COMMAND_DELETE_LIBRARY 
            && (command[1] == ' ' || command[1] == '\n')) {
            if (library == NULL) {
                printf("The library has been deleted. "
                    "You do not need to consider this case.\n");
                exit(1);
            }
            delete_library(library);
            library = NULL;
            printf("Deleted library.\n");
        } else if (command[0] == COMMAND_DELETE_PLAYLIST 
            && (command[1] == ' ' || command[1] == '\n')) {
            if (library == NULL) {
                printf("The library has been deleted. "
                    "You do not need to consider this case.\n");
                exit(1);
            }
            delete_playlist(library);
            printf("Deleted selected playlist.\n");
        } else if (command[0] == COMMAND_DELETE_TRACK  
            && (command[1] == ' ' || command[1] == '\n')) {
            char trackTitle[MAX_LEN];
            int numScanned = sscanf(command, "%c %s", &ignoreChar, trackTitle);
            if (numScanned != 2) {
                printf("Invalid command!\n");
                continue;
            }
            if (library == NULL) {
                printf("The library has been deleted. "
                    "You do not need to consider this case.\n");
                exit(1);
            }
            delete_track(library, trackTitle);
            printf("Deleted track (if it existed).\n");
        }

        // STAGE 4
        else if (command[0] == COMMAND_CUT_AND_PASTE_TRACK 
            && (command[1] == ' ' || command[1] == '\n')) {
            char trackTitle[MAX_LEN];
            char destPlaylist[MAX_LEN];
            int numScanned = sscanf(command, "%c %s %s", &ignoreChar, 
                trackTitle, destPlaylist);
            if (numScanned != 3) {
                printf("Invalid command!\n");
                continue;
            }
            if (library == NULL) {
                printf("The library has been deleted. "
                    "You do not need to consider this case.\n");
                exit(1);
            }
            int result = cut_and_paste_track(library, trackTitle, destPlaylist);
            if (result == ERROR_NOT_FOUND) {
                printf("The given track/playlist does not exist.\n");
            } else if (result == SUCCESS) {
                printf("Track has been successfully moved.\n");
            }
        } else if (command[0] == COMMAND_SOUNDEX_SEARCH 
            && (command[1] == ' ' || command[1] == '\n')) {
            char artist[MAX_LEN];
            int numScanned = sscanf(command, "%c %s", &ignoreChar, artist);
            if (numScanned != 2) {
                printf("Invalid command!\n");
                continue;
            }
            if (library == NULL) {
                printf("The library has been deleted. "
                    "You do not need to consider this case.\n");
                exit(1);
            }
            printf("Search Results (empty if no match): \n");
            soundex_search(library, artist);
        }
        
        // STAGE 5
        else if (command[0] == COMMAND_ADD_FILTERED_PLAYLIST
            && (command[1] == ' ' || command[1] == '\n')) {
            char artist[MAX_LEN];
            int numScanned = sscanf(command, "%c %s", &ignoreChar, artist);
            if (numScanned != 2) {
                printf("Invalid command!\n");
                continue;
            }
            if (library == NULL) {
                printf("The library has been deleted. "
                    "You do not need to consider this case.\n");
                exit(1);
            }
            int result = add_filtered_playlist(library, artist);
            if (result == ERROR_INVALID_INPUTS) {
                printf("The given artist name is invalid.\n");
            } else if (result == SUCCESS) {
                printf("Filtered playlist has been successfully added!\n");
            }
        } else if (command[0] == COMMAND_REORDER_PLAYLIST
            && (command[1] == ' ' || command[1] == '\n')) {
            int length;
            int order[MAX_LEN];
            int numScanned = sscanf(command, "%c %d", &ignoreChar, &length);
            
            if (numScanned != 2) {
                printf("Invalid command!\n");
                continue;
            }
            if (library == NULL) {
                printf("The library has been deleted. "
                    "You do not need to consider this case.\n");
                exit(1);
            }
            printf("Enter order: \n"); 
            
            int counter = 0;
            while (counter < length) {
                int result = scanf("%d", &order[counter]);
                if (result != 1) { 
                    printf("You have entered an invalid input.\n");
                }
                counter++;
            }
            getchar();
            reorder_playlist(library, order, length);
            printf("Reordered playlist.\n");
        } 

        // Help/invalid
        else if (command[0] == COMMAND_HELP 
            && (command[1] == ' ' || command[1] == '\n')) {
            do_print_help();
        } else /* Invalid Command */ {
            printf("Invalid Command. Enter '?' for help.\n");
        }
    }

    printf("Go Premium. Be happy.\n");

    return 0;
}

void do_print_help(void) {
    printf(""
        "*~~~~~~~~~~~~~~~~~~~~~~~~~~~~{ Help }~~~~~~~~~~~~~~~~~~~~~~~~~~~~*\n"
    );

    printf(""
        "  %c\n"
        "     Show this Help Screen\n",
        COMMAND_HELP
    );
    printf(""
        "\n  %c\n"
        "     Quit program\n",
        COMMAND_QUIT
    );
    printf(""
        "\n  %c <playlistName>\n"
        "     Add a new Playlist to the Library.\n",
        COMMAND_ADD_PLAYLIST
    );
    printf(""
        "\n  %c\n"
        "     Print out the Library.\n",
        COMMAND_PRINT_LIBRARY
    );
    printf(""
        "\n  %c <playlistName> <newPlaylistName>\n"
        "     Rename the name of an existing Playlist.\n",
        COMMAND_RENAME_PLAYLIST
    );
    printf(""
        "\n  %c\n"
        "     Selects the next Playlist in the Library.\n",
        COMMAND_NEXT_PLAYLIST
    );
    printf(""
        "\n  %c\n"
        "     Selects the previous Playlist in the Library.\n",
        COMMAND_PREVIOUS_PLAYLIST
    );
    printf(""
        "\n  %c <title> <artist> <trackLengthInSec> <position>\n"
        "     Add a new Track to the selected Playlist.\n",
        COMMAND_ADD_TRACK
    );
    printf(""
        "\n  %c\n"
        "     Calculate the total length of the selected Playlist "
        "in minutes and seconds.\n",
        COMMAND_PLAYLIST_LENGTH
    );
    printf(""
        "\n  %c <track>\n"
        "     Delete the first instance of the given track "
        "in the selected Playlist of the Library.\n",
        COMMAND_DELETE_TRACK
    );
    printf(""
        "\n  %c\n"
        "     Delete the selected Playlist and "
        "select the next Playlist in the Library.\n",
        COMMAND_DELETE_PLAYLIST
    );
    printf(""
        "\n  %c\n"
        "     Delete an entire Library and "
        "its associated Playlists and Tracks.\n",
        COMMAND_DELETE_LIBRARY
    );
    printf(""
        "\n  %c <trackName> <destPlaylist>\n"
        "     Cut the given track in selected Playlist and "
        "paste it into the given destination Playlist.\n",
        COMMAND_CUT_AND_PASTE_TRACK
    );
    printf(""
        "\n  %c <artist>\n"
        "     Print out all Tracks with artists that have "
        "the same Soundex Encoding  "
        "as the given artist.\n",
        COMMAND_SOUNDEX_SEARCH
    );

    printf(""
        "\n  %c <artist>\n"
        "     Move all Tracks of the given artist to a new Playlist.\n",
        COMMAND_ADD_FILTERED_PLAYLIST
    );
    printf(""
        "\n  %c <length>\n"
        "     Reorder the selected Playlist in the given order "
        "specified by the order array.\n",
        COMMAND_REORDER_PLAYLIST
    );
}