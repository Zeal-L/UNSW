// Zeal L (abc982210694@gmail.com)
// 2020-11-18 16:52:42
// Tenth week in COMP1511
// Zid:z5325156

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NAME_LENGTH 100

// Do not edit these structs. You may use them exactly as
// they are but you cannot make changes to them

// A node in a linked list of characters
struct character_node {
    char data;
    struct character_node *next;
};

// DECLARE ANY FUNCTIONS YOU WRITE HERE

// Given a list of characters, move each character
// along one, putting "pad_character" in the first place,
// and ignoring the last character.
//
// Given the list 'c' 'e' 'l' 'l' 'o'; calling left_pad
// once with pad_character = 'x' results in the list:
// 'x' 'c' 'e' 'l' 'l'. Calling it again with pad_character = 'e'
// results in the list: 'e' 'x' 'c' 'e' 'l'
//
// Note that you can't malloc, or modify the lists' nodes
// You can only move data around the list.
void pad_left(struct character_node *characters, char pad_character) {
    if (characters == NULL) {
        return;
    }
    char temp = characters->data;
    characters->data = pad_character;
    pad_left(characters->next, temp);
}

// These helper functions are only for this main, but
// may help you to both understand and test this exercise.
// They will not help you in the above exercise.
// You may use these functions for testing, but
// YOU CANNOT CHANGE THESE FUNCTIONS

// Convert a string to a linked list of nodes, one per character
struct character_node *string_to_characters(char* string) {
    struct character_node *list_head = NULL;
    
    int curr_char = strlen(string) - 1;
    while (curr_char >= 0) {
        struct character_node *n = malloc(sizeof(struct character_node));
        n->data = string[curr_char];
        n->next = list_head;
        list_head = n;
        curr_char -= 1;
    }

    return list_head;
}

void print_characters(struct character_node *c) {
    while (c != NULL) {
        putchar(c->data);
        c = c->next;
    }
    putchar('\n');
}

void free_characters(struct character_node *c) {
    if (c == NULL) {
        return;
    }
    free_characters(c->next);
    free(c);
}

// This is a main function which could be used
// to test your pad_left function.
// It will not be marked.
// Only your pad_left function will be marked.
int main(int argc, char * argv[]) {
    if (argc != 2) {
        printf("Usage: %s a_string_to_pad\n", argv[0]);
        return 0;
    }
    char *string = argv[1];
    struct character_node *characters = string_to_characters(string);
    int pad_character;
    while ((pad_character = getchar()) != -1){
        if (pad_character == '\n') {
            print_characters(characters);
        } else {
            pad_left(characters, pad_character);
        }
    }
    free_characters(characters);
        
    return 0;
}

// DEFINE ANY FUNCTIONS YOU WRITE HERE


