// Zeal L (abc982210694@gmail.com)
// 2020-11-06 21:45:35
// Eighth week in COMP1511
// Zid:z5325156

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NAME_SIZE 50

// Do not edit this struct. You may use it exactly as it is
// but you cannot make changes to it
struct pokemon {
    char name[MAX_NAME_SIZE];
    struct pokemon *evolution;
};

// Create a pokemon 
struct pokemon *create_pokemon(char name[MAX_NAME_SIZE]) {
    // PUT YOUR CODE HERE (you must change the next line!)
    struct pokemon *pp = malloc(sizeof(struct pokemon));
    strcpy(pp->name, name);
    pp->evolution = NULL;
    return pp;
}

// Link a pokemon to another that it evolves into
void evolve_pokemon(struct pokemon *base, struct pokemon *evolution) {
    // PUT YOUR CODE HERE
    base->evolution = evolution;
}

// Print out the evolution of a pokemon
void print_evolution(struct pokemon *p) {
    // PUT YOUR CODE HERE
    while (p != NULL) {
        printf("%s\n", p->name);
        p = p->evolution;
    }
}

// This is a simple main function which could be used
// to test your pokemon functions.
// It will not be marked.
// Only your pokemon functions will be marked.

int main(void) {
    struct pokemon *pikachu = create_pokemon("Pikachu");
    struct pokemon *raichu = create_pokemon("Raichu");
    evolve_pokemon(pikachu, raichu);
    print_evolution(pikachu);
    return 0;
}
