#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <assert.h>
#include <dirent.h>
#include <string.h>

void compare(char *tree1, char *tree2, char *pathname, int* identical,
                int *different_size, int *only_tree1, int *only_tree2);

int main(int argc, char *argv[]) {
    assert(argc == 3);
    int identical = 0;
    int different_size = 0;
    int only_tree1 = 0;
    int only_tree2 = 0;
    compare(argv[1], argv[2], ".",
        &identical, &different_size, &only_tree1, &only_tree2);
    printf("%d %d %d %d\n", identical, different_size, only_tree1, only_tree2);
}

void compare(char *tree1, char *tree2, char *pathname, int *identical,
                int *different_size, int *only_tree1, int *only_tree2) {
    //printf("compare(%s %s %s)\n", tree1, tree2, pathname);
    struct stat s1, s2;
    char pathname1[PATH_MAX + 1];
    char pathname2[PATH_MAX + 1];
    snprintf(pathname1, sizeof pathname1,  "%s/%s", tree1, pathname);
    snprintf(pathname2, sizeof pathname2,  "%s/%s", tree2, pathname);
    int r1 = stat(pathname1, &s1);
    int r2 = stat(pathname2, &s2);
    //printf("stat %d %s\n", r1, pathname1);
    //printf("stat %d %s\n", r2, pathname2);

    if (r1 == 0 && S_ISREG(s1.st_mode)) {
        if (r2 == 0 && S_ISREG(s2.st_mode)) {
            if (s1.st_size == s2.st_size) {
                (*identical)++;
            } else {
                (*different_size)++;
            }
        } else {
            (*only_tree1)++;
        }
    } else if (r2 == 0 && S_ISREG(s2.st_mode)) {
        (*only_tree2)++;
    }

    char p[2*PATH_MAX + 1];
    if (r1 == 0 && S_ISDIR(s1.st_mode)) {
        DIR *dirp = opendir(pathname1);
        assert(dirp);
        struct dirent *de;
        while ((de = readdir(dirp)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
                continue;
            }
            snprintf(p, sizeof p,  "%s/%s", pathname, de->d_name);
            compare(tree1, tree2, p, identical, different_size, only_tree1, only_tree2);
        }
        closedir(dirp);
    }

    if (r2 == 0 && S_ISDIR(s2.st_mode)) {
        DIR *dirp = opendir(pathname2);
        assert(dirp);
        struct dirent *de;
        while ((de = readdir(dirp)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
                continue;
            }
            // check name isn't in tree 1 to avoid double counting
            snprintf(p, sizeof p,  "%s/%s", pathname1, de->d_name);
            struct stat s;
            if (stat(p, &s) == 0) {
                continue;
            }
            snprintf(p, sizeof p,  "%s/%s", pathname, de->d_name);
            compare(tree1, tree2, p, identical, different_size, only_tree1, only_tree2);
        }
        closedir(dirp);
    }
}