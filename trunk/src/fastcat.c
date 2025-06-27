/*
 * fastcat.c
 */

#define _FILE_OFFSET_BITS 64

#include "sys_dep.h"

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#define MAX_WRITE (1024 * 1024)

static int do_copy(int, int);
static int do_file_send(int, int);
static int do_fifo_transfer(int, int);

static int
do_copy(int fd_in, int fd_out)
{
    char buf[MAX_WRITE];
    ssize_t num_written, ret, to_write;

    ret = read(fd_in, buf, sizeof(buf));
    if (ret <= 0)
        goto err;

    for (to_write = ret; to_write > 0; to_write -= num_written) {
        num_written = write(fd_out, buf, to_write);
        if (num_written < 0)
            goto err;
    }

    return 0;

err:
    return -errno;
}

static int
do_file_send(int fd_in, int fd_out)
{
    for (;;) {
        ssize_t ret;

        ret = file_send(fd_out, fd_in, NULL, MAX_WRITE);
        if (ret <= 0) {
            if (ret == 0)
                break;
            return -errno;
        }
    }

    return 0;
}

static int
do_fifo_transfer(int fd_in, int fd_out)
{
    for (;;) {
        ssize_t ret;

        ret = fifo_transfer(fd_in, NULL, fd_out, NULL, MAX_WRITE, 1);
        if (ret <= 0) {
            if (ret == 0)
                break;
            return -errno;
        }
    }

    return 0;
}

int
main(int argc, char **argv)
{
    char **files;
    int fd_in;
    int fl_out;
    int i;
    struct stat s_out;

    if (argc < 2)
        error(EXIT_FAILURE, 0, "Must specify file");
    files = &argv[1];

    if (fstat(STDOUT_FILENO, &s_out) == -1)
        error(EXIT_FAILURE, errno, "Couldn't get file status");

    fl_out = fcntl(STDOUT_FILENO, F_GETFL);
    if (fl_out == -1 || fcntl(STDOUT_FILENO, F_SETFL, fl_out & ~O_APPEND) == -1)
        error(EXIT_FAILURE, errno, "Error");

    for (i = 0; files[i] != NULL; i++) {
        const char *path = files[i];
        int err;
        struct stat s_in;

        if (strcmp("-", path) == 0) {
            fd_in = STDIN_FILENO;
            path = "standard input";
        } else {
            fd_in = open(path, O_RDONLY);
            if (fd_in == -1)
                error(EXIT_FAILURE, errno, "Couldn't open %s", path);
        }

        if (fstat(fd_in, &s_in) == -1) {
            error(0, errno, "Couldn't get file status of %s", path);
            goto err;
        }

        if (S_ISFIFO(s_out.st_mode) || S_ISFIFO(s_in.st_mode))
            err = do_fifo_transfer(fd_in, STDOUT_FILENO);
        else if (S_ISREG(s_in.st_mode))
            err = do_file_send(fd_in, STDOUT_FILENO);
        else
            err = do_copy(fd_in, STDOUT_FILENO);
        if (err) {
            error(0, -err, "Error copying from %s", path);
            goto err;
        }

        close(fd_in);
    }

    return EXIT_SUCCESS;

err:
    close(fd_in);
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
