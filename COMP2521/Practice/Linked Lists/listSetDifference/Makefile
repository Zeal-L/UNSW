
CC = gcc
CFLAGS = -Wall -Werror -std=c11 -g

TEST_DRIVER = testListSetDifference.c
EXERCISE_FILE = listSetDifference.c
COMMON = list.c

SRC_FILES = $(TEST_DRIVER) $(EXERCISE_FILE) $(COMMON)

all: testListSetDifference

testListSetDifference: $(SRC_FILES)
	$(CC) $(CFLAGS) -o testListSetDifference $(SRC_FILES)

clean:
	rm -f testListSetDifference

