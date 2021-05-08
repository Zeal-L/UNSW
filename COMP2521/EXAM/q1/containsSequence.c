// containsSequence.c ... implementation of containsSequence function

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "list.h"

/*
    You will submit only this one file.

    Implement the function "containsSequence" below. Read the exam paper
    for a detailed specification and description of your task.

    - DO NOT modify the code in any other files except for debugging
      purposes.
    - If you wish, you can add static variables and/or helper functions
      to this file.
    - DO NOT add a "main" function to this file.
*/

int containsSequence(List seq1, List seq2) {
    
    Node curr_1 = seq1->first;
    Node curr_2 = seq2->first;

    while(curr_2) {
      while (curr_2->value != curr_1->value) {
        curr_1 = curr_1->next;
        if (curr_1 == NULL) return 0;
      }

      curr_2 = curr_2->next;
    }
    return 1;
}

