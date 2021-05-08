# COMP2521 21T1 Final Exam
# isBST
# Written by Ashesh Mahidadia, May 2021

CC = gcc
CFLAGS = -Wall -Werror -g

all: testIsBST

testIsBST: testIsBST.o isBST.o Tree.o Record.o
	$(CC) $(CFLAGS) -o testIsBST testIsBST.o isBST.o Tree.o Record.o

testIsBST.o: testIsBST.c Tree.h Record.h
isBST.o: isBST.c Tree.h Record.h
Tree.o: Tree.c Tree.h Record.h
Record.o: Record.c Record.h

clean:
	rm -f testIsBST *.o core

