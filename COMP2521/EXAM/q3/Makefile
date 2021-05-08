# COMP2521 21T1 Final Exam
# calculateViralTransmission
# Written by Ashesh Mahidadia, May 2021

CC = gcc
CFLAGS = -Wall -Werror -Wno-unused-command-line-argument -g

TEST_DRIVER = testTransmissionAmts.c
EXERCISE_FILE = calculateViralTransmission.c
COMMON = Graph.c Queue.c

SRC_FILES = $(TEST_DRIVER) $(EXERCISE_FILE) $(COMMON)

all: testTransmissionAmts

testTransmissionAmts: $(SRC_FILES)
	$(CC) $(CFLAGS) -o testTransmissionAmts $(SRC_FILES) -lm

clean:
	rm -f testTransmissionAmts

