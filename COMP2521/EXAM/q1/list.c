// list.c

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "list.h"

// create an empty list
List newList(void) {
	List l = malloc(sizeof(*l));
	assert(l != NULL);
	l->first = NULL;
	l->last = NULL;
	return l;
}

// create a new list node
Node newNode(int val) {
	Node n = malloc(sizeof(*n));
	assert(n != NULL);
	n->value = val;
	n->next = NULL;
	return n;
}

// free memory for a list
void dropList(List l) {
	assert(l != NULL);
	Node curr, prev;
	curr = l->first;
	while (curr != NULL) {
		prev = curr;
		curr = curr->next;
		free(prev);
	}
	free(l);
}

// display a list to given file (stdout)
void showList(FILE *out, List l) {
	assert(out != NULL);
	assert(l != NULL);
	Node curr;
	int count = 0;
	for (curr = l->first; curr != NULL; curr = curr->next) {
		if (count++ > 0) {
			fprintf(out, ", ");
		}
		fprintf(out, "%d", curr->value);
	}
	fprintf(out, "\n");
}

// this function is INTENTIONALLY static, you should not use it
static int ListAppend321987(List l, int val) {
	Node n = newNode(val);
	if (n == NULL) {
		fprintf(stderr, "Cannot create a new node!\n");
		return 0;
	}
	if (l->last == NULL) {
		l->first = n;
		l->last = n;
	} else {
		l->last->next = n;
		l->last = n;
	}
	return 1;
}

// creates a list by reading integer values from a line
List getList(char *line) {
	char delim[] = ", ";
	int key;

	List l = newList();

	char *tkn = strtok(line, delim);

	while (tkn != NULL) {
		//printf("'%s'\n", tkn);
		int count = sscanf(tkn, "%d", &key);
		if (count == 1) {
			int succ = ListAppend321987(l, key);
			if (succ == 0) {
				fprintf(stderr, "Cannot create a new node!\n");
				return NULL;
			}
		}
		
		tkn = strtok(NULL, delim);
	}

	return l;
}

