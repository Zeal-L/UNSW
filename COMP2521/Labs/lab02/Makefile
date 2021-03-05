# COMP2521 ... Lab 02 Makefile

CC = gcc
CFLAGS = -Wall -Werror -g

.PHONY: noargs
noargs:
	@echo "Usage: make <test|benchmark|clean>"

.PHONY: test
test: testListQueue testArrayQueue testCircularArrayQueue

.PHONY: benchmark
benchmark: benchmarkArrayQueue benchmarkCircularArrayQueue

testListQueue: testQueue.o ListQueue.o
	$(CC) $(CFLAGS) -o testListQueue testQueue.o ListQueue.o

testArrayQueue: testQueue.o ArrayQueue.o
	$(CC) $(CFLAGS) -o testArrayQueue testQueue.o ArrayQueue.o

testCircularArrayQueue: testQueue.o CircularArrayQueue.o
	$(CC) $(CFLAGS) -o testCircularArrayQueue testQueue.o CircularArrayQueue.o

benchmarkArrayQueue: benchmarkQueue.o ArrayQueue.o
	$(CC) $(CFLAGS) -o benchmarkArrayQueue benchmarkQueue.o ArrayQueue.o

benchmarkCircularArrayQueue: benchmarkQueue.o CircularArrayQueue.o
	$(CC) $(CFLAGS) -o benchmarkCircularArrayQueue benchmarkQueue.o CircularArrayQueue.o

testQueue.o: testQueue.c Queue.h
benchmarkQueue.o: benchmarkQueue.c Queue.h

ListQueue.o: ListQueue.c Queue.h
ArrayQueue.o: ArrayQueue.c Queue.h
CircularArrayQueue.o: CircularArrayQueue.c Queue.h

.PHONY: clean
clean:
	rm -f testListQueue testArrayQueue testCircularArrayQueue
	rm -f benchmarkArrayQueue benchmarkCircularArrayQueue
	rm -f *.o

