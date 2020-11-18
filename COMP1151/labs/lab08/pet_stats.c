// Zeal L (abc982210694@gmail.com)
// 2020-11-03 19:02:04
// Eighth week in COMP1511
// Zid:z5325156
// 
// A program to track statistics of pets
// Written for COMP1511 tutorials by 
// Marc Chee (marc.chee@unsw.edu.au)
// July 2019

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_NAME_LENGTH 50
#define MAX_TYPE_LENGTH 50

struct pet {
    char name[MAX_NAME_LENGTH];
    char type[MAX_TYPE_LENGTH];
    int age;
    int weight;
};

// function declarations, do not change these
void setup_pet(
    struct pet *my_pet,
    char *name, 
    char *type, 
    char *age, 
    char *weight
);
void print_pet(struct pet *my_pet);

// do not change any code in the main function
int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("%s should receive four extra command line arguments.\n", argv[0]);
        return 1;
    }
    struct pet new_pet;
    setup_pet(&new_pet, argv[1], argv[2], argv[3], argv[4]);
    print_pet(&new_pet);
    return 0;
}

// A function that takes in four strings
// (given from the command line arguments in the main function)
// and stores their data in the pet struct.
//
// Note: you will need to convert the 'age' and 'weight' strings 
// to an integer before storing them in the struct.
void setup_pet(
    struct pet *my_pet, 
    char *name, 
    char *type, 
    char *age, 
    char *weight
) {
    // YOUR CODE GOES HERE
    strcpy(my_pet->name, name);
    strcpy(my_pet->type, type);
    strcpy(my_pet->name, name);
    my_pet->age = strtol(age, NULL, 10);
    my_pet->weight = strtol(weight, NULL, 10);
}

// A function that prints out a human readable
// description of the pet:
// "<name> is a <type> who is <age> years old and weighs <weight>kg\n"
void print_pet(struct pet *my_pet) {
    // YOUR CODE GOES HERE
    printf("%s is a %s who is %d years old and weighs %dkg\n", my_pet->name, my_pet->type, my_pet->age, my_pet->weight);
}
