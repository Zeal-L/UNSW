# Makefile for Assignment 2

CC = gcc 
CFLAGS = -Wall -Werror -g

all: testFloydWarshall testCentralityMeasures testGirvanNewman

testFloydWarshall: testFloydWarshall.c FloydWarshall.c Graph.c GraphRead.c
	$(CC) $(CFLAGS) -o testFloydWarshall testFloydWarshall.c FloydWarshall.c Graph.c GraphRead.c

testCentralityMeasures: testCentralityMeasures.c CentralityMeasures.c FloydWarshall.c Graph.c GraphRead.c
	$(CC) $(CFLAGS) -o testCentralityMeasures testCentralityMeasures.c CentralityMeasures.c FloydWarshall.c Graph.c GraphRead.c

testGirvanNewman: testGirvanNewman.c GirvanNewman.c CentralityMeasures.c FloydWarshall.c Graph.c GraphRead.c BSTree.c
	$(CC) $(CFLAGS) -o testGirvanNewman testGirvanNewman.c GirvanNewman.c CentralityMeasures.c FloydWarshall.c Graph.c GraphRead.c BSTree.c

clean:
	rm -rf testFloydWarshall testCentralityMeasures testGirvanNewman

