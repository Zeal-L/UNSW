# COMP2521 21T1 Final Exam
# containsSequence
# Written by Ashesh Mahidadia, May 2021

CC = gcc
CFLAGS = -Wall -Werror -g

all: testContainsSequence

testContainsSequence: list.o containsSequence.o testContainsSequence.o
	$(CC) $(CFLAGS) -o testContainsSequence testContainsSequence.c containsSequence.o list.o

testContainsSequence.o: testContainsSequence.c list.h
containsSequence.o: containsSequence.c list.h
list.o: list.c list.h

clean:
	rm -f testContainsSequence *.o core

