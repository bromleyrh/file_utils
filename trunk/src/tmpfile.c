/*
 * tmpfile.c
 */

#define _FILE_OFFSET_BITS 64

#include "sys_dep.h"

#include <strings_ext.h>

#include <files/acc_ctl.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#ifdef SYS_DEP_OPENAT_TMPFILE
static size_t dirname_len(const char *);

#endif
static int parse_cmdline(int, char **, char *, int *);

static int get_stdout(int [2], int *);
static int close_stdout_pipe(int [2]);

static int open_file(char *);

static ssize_t do_copy(int, int);
static ssize_t do_fifo_copy(int, int);
static ssize_t do_fifo_transfer(int, int);

static int copy_file(int, int, int [2], int);

static int link_file(int, const char *);

#ifdef SYS_DEP_OPENAT_TMPFILE
static size_t
dirname_len(const char *path)
{
    const char *last_slash = strrchr(path, '/');

    return last_slash == NULL ? 0 : last_slash - path;
}

#endif
static int
parse_cmdline(int argc, char **argv, char *file, int *write_to_stdout)
{
    char cwd[PATH_MAX];
    char *path;

    if (argc < 2) {
        error(0, 0, "No file specified");
        return -1;
    }
    path = argv[1];

    if (path[0] == '/') {
        if (snprintf(file, PATH_MAX, "%s", path) >= PATH_MAX)
            return -1;
    } else {
        if (getcwd(cwd, sizeof(cwd)) == NULL) {
            error(0, errno, "Error getting current working directory");
            return -1;
        }
        if (snprintf(file, PATH_MAX, "%s/%s", cwd, path) >= PATH_MAX)
            return -1;
    }

    if (argc > 2 && strcmp(argv[2], "-t") == 0)
        *write_to_stdout = 1;

    return 0;
}

static int
get_stdout(int pipefd[2], int *stdout_splice)
{
    struct stat s;

    if (fstat(STDOUT_FILENO, &s) == -1)
        return -errno;

    if (S_ISFIFO(s.st_mode)) {
        pipefd[0] = STDOUT_FILENO;
        pipefd[1] = -1;
        *stdout_splice = 0;
        return 0;
    }

    if (pipe(pipefd) == -1)
        return -errno;
    *stdout_splice = S_ISREG(s.st_mode);
    return 0;
}

static int
close_stdout_pipe(int pipefd[2])
{
    int ret, tmp;

    if (pipefd[0] == STDOUT_FILENO || pipefd[0] == -1)
        return 0;

    ret = close(pipefd[0]);
    tmp = close(pipefd[1]);
    if (tmp != 0)
        ret = tmp;

    return ret;
}

static int
open_file(char *path)
{
#ifdef SYS_DEP_OPENAT_TMPFILE
    int ret;
    size_t dnlen;

    dnlen = dirname_len(path);
    if (dnlen == 0)
        return -EISDIR;

    path[dnlen] = '\0';
    ret = openat_tmpfile(AT_FDCWD, path, O_WRONLY, ACC_MODE_DEFAULT);
    path[dnlen] = '/';

    return ret == -1 ? -errno : ret;
#else
    (void)path;

    return -ENOTSUP;
#endif
}

#define MAX_LEN 4096

static ssize_t
do_copy(int fd_in, int fd_out)
{
    char buf[MAX_LEN];
    ssize_t num_written, ret, to_write;

    ret = read(fd_in, buf, sizeof(buf));
    if (ret < 0)
        return ret;

    for (to_write = ret; to_write > 0; to_write -= num_written) {
        num_written = write(fd_out, buf, to_write);
        if (num_written < 0)
            return num_written;
    }

    return ret;
}

static ssize_t
do_fifo_copy(int fd_in, int fd_out)
{
    return fifo_copy(fd_in, fd_out, MAX_LEN, 0);
}

static ssize_t
do_fifo_transfer(int fd_in, int fd_out)
{
    return fifo_transfer(fd_in, NULL, fd_out, NULL, MAX_LEN, 0);
}

#undef MAX_LEN

static int
copy_file(int fd_in, int fd_out, int stdout_pipe[2], int stdout_splice)
{
    ssize_t ret;

    if (stdout_pipe[0] == STDOUT_FILENO) {
        for (;;) {
            ret = do_fifo_copy(fd_in, STDOUT_FILENO);
            if (ret < 1)
                break;

            ret = do_fifo_transfer(fd_in, fd_out);
            if (ret < 1)
                break;
        }
    } else if (stdout_splice) {
        for (;;) {
            ret = do_fifo_copy(fd_in, stdout_pipe[1]);
            if (ret < 1)
                break;
            ret = do_fifo_transfer(stdout_pipe[0], STDOUT_FILENO);
            if (ret < 0)
                break;

            ret = do_fifo_transfer(fd_in, fd_out);
            if (ret < 1)
                break;
        }
    } else if (stdout_pipe[0] >= 0) {
        for (;;) {
            ret = do_fifo_copy(fd_in, stdout_pipe[1]);
            if (ret < 1)
                break;
            ret = do_copy(stdout_pipe[0], STDOUT_FILENO);
            if (ret < 0)
                break;

            ret = do_fifo_transfer(fd_in, fd_out);
            if (ret < 1)
                break;
        }
    } else {
        for (;;) {
            ret = do_fifo_transfer(fd_in, fd_out);
            if (ret < 1)
                break;
        }
    }

    return ret == 0 ? 0 : -errno;
}

static int
link_file(int fd, const char *name)
{
    char path[PATH_MAX];

    if (fmtbuf(path, "/proc/self/fd/%d", fd) != 0)
        return -ENAMETOOLONG;

    return linkat(AT_FDCWD, path, AT_FDCWD, name, AT_SYMLINK_FOLLOW) == 0
           ? 0 : -errno;
}

int
main(int argc, char **argv)
{
    char file[PATH_MAX];
    int err;
    int fd, stdout_pipe[2] = {-1, -1};
    int stdout_splice = 0;
    int write_to_stdout = 0;

    if (parse_cmdline(argc, argv, file, &write_to_stdout) == -1)
        return EXIT_FAILURE;

    fd = open_file(file);
    if (fd < 0)
        error(EXIT_FAILURE, -fd, "Error opening %s", file);

    if (write_to_stdout && get_stdout(stdout_pipe, &stdout_splice) < 0)
        goto err1;

    err = copy_file(STDIN_FILENO, fd, stdout_pipe, stdout_splice);
    if (err) {
        error(0, -err, "Error copying %s", file);
        goto err2;
    }

    err = link_file(fd, file);
    if (err) {
        error(0, -err, "Error linking %s", file);
        goto err2;
    }

    if (close(fd) == -1)
        error(EXIT_FAILURE, errno, "Error closing %s", file);
    close_stdout_pipe(stdout_pipe);

    return EXIT_SUCCESS;

err2:
    close_stdout_pipe(stdout_pipe);
err1:
    close(fd);
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
