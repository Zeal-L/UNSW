#include <stdio.h>
#include <stdlib.h>

int get_min(int argc, char **argv);
int get_max(int argc, char **argv);
int get_sum(int argc, char **argv);
int get_prod(int argc, char **argv);
int get_mean(int argc, char **argv);

int main(int argc, char **argv) {
	
	printf("MIN:  %d\n", get_min(argc, argv));
	printf("MAX:  %d\n", get_max(argc, argv));
	printf("SUM:  %d\n", get_sum(argc, argv));
	printf("PROD: %d\n", get_prod(argc, argv));
	printf("MEAN: %d\n", get_mean(argc, argv));
	
	return 0;
}

int get_min(int argc, char **argv) {
	int min = 99999999;
	for (int i = 1; i < argc; i++) {
		if (atoi(argv[i]) < min) min = atoi(argv[i]);
	}
	return min;
}
int get_max(int argc, char **argv) {
	int max = -99999999;
	for (int i = 1; i < argc; i++) {
		if (atoi(argv[i]) > max) max = atoi(argv[i]);
	}
	return max;
}
int get_sum(int argc, char **argv) {
	int sum = 0;
	for (int i = 1; i < argc; i++) {
		sum += atoi(argv[i]);
	}
	return sum;
}
int get_prod(int argc, char **argv) {
	int prod = 1;
	for (int i = 1; i < argc; i++) {
		prod *= atoi(argv[i]);
	}
	return prod;
}
int get_mean(int argc, char **argv) {
	int sum = 0;
	for (int i = 1; i < argc; i++) {
		sum += atoi(argv[i]);
	}
	return sum / (argc - 1);
}

