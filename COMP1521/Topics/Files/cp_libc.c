// cp <file1> <file2>
// implemented with libc and *zero* error handling

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
    // open takes 3 arguments:
    //   1) address of zero-terminated string containing pathname of file to open
    //   2) bitmap indicating whether to write, read, ... file
    //   3) permissions if file will be newly created
    //      0644 == readable to everyone, writeable by owner

    int read_file_descriptor = open(argv[1], O_RDONLY);
    int write_file_descriptor = open(argv[2], O_WRONLY | O_CREAT, 0644);

    while (1) {
        char bytes[4096];
        ssize_t bytes_read = read(read_file_descriptor, bytes, 4096);
        if (bytes_read <= 0) {
            break;
        }
        write(write_file_descriptor, bytes, bytes_read);
    }

    return 0;
}