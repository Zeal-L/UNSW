
CC = gcc
CFLAGS = -Wall -Werror -Wno-unused-function -g

COMMON = FlightDb.c AVLTree.c List.c Record.c

.PHONY: all
all: test testAss1

test: test.c $(COMMON)
	$(CC) $(CFLAGS) -o test test.c $(COMMON)

testAss1: testAss1.c $(COMMON)
	$(CC) $(CFLAGS) -o testAss1 testAss1.c $(COMMON)

clean:
	rm -f test testAss1

