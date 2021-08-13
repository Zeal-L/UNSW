// COMP1521 21T2 ... final exam, question 7

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const mode_t NEW_DIR_MODE = S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH;

void cp_directory (char *D_From, char *dir_to) {

    struct stat a, b;
    char D_F[BUFSIZ], D_T[BUFSIZ];
    stat(D_From, &a);
    DIR *d1 = opendir(D_From);
    DIR *d2 = opendir(D_To);
    if(d2 != NULL) {
        mkdir(D_To, a.st_mode);
        d2 = opendir(D_To);
 	}
    while(1) {
        struct dirent *dirp = readdir(d1);
        if(!dirp) break;
        if(!strcmp(dirp->d_name, ".") ||
			!strcmp(dirp->d_name, "..")) {
			continue;
		}
        sprintf(D_F, "%s/%s",
			D_From, dirp -> d_name);
        sprintf(D_T, "%s/%s",
			D_To, dirp -> d_name);
        stat(D_F, &b);
        if (S_ISDIR(b.st_mode)) {
			mkdir(D_T, a.st_mode);
			cp_directory(D_F, D_T);
		} else if(S_ISREG(b.st_mode)) {
            FILE *f1 = fopen(D_F, "r");
            FILE *f2 = fopen(D_T, "w");
            for(char line[BUFSIZ]; fgets(line, sizeof(line), f1); fputs(line, f2));
            fclose(f1);
            fclose(f2);
        }
    }
}