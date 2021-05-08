
CC = gcc
CFLAGS = -Wall -Werror -std=c11 -g

TEST_DRIVER = testTreeCopy.c
EXERCISE_FILE = TreeCopy.c
COMMON = tree.c

SRC_FILES = $(TEST_DRIVER) $(EXERCISE_FILE) $(COMMON)

all: testTreeCopy

testTreeCopy: $(SRC_FILES)
	$(CC) $(CFLAGS) -o testTreeCopy $(SRC_FILES)

clean:
	rm -f testTreeCopy

