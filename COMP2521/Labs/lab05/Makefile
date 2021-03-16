
CC = gcc
CFLAGS = -Wall -Werror -g

COMMON = Fb.o List.o Map.o Queue.o

.PHONY: all
all: runFb

runFb: runFb.o $(COMMON)
	$(CC) $(CFLAGS) -o runFb runFb.o $(COMMON)

runFb.o: runFb.c

Fb.o: Fb.c
List.o: List.c
Map.o: Map.c
Queue.o: Queue.c

.PHONY: clean
clean:
	rm -f *.o runFb

