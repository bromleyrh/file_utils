/*
 * tmpfile.c
 */

#define _FILE_OFFSET_BITS 64

#define _GNU_SOURCE

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

static int parse_cmdline(int, char **, char *);

static size_t dirname_len(const char *);

static int open_file(char *);
static int copy_file(int, int);
static int link_file(int, const char *);

static size_t
dirname_len(const char *path)
{
    const char *last_slash = strrchr(path, '/');

    return (last_slash == NULL) ? 0 : last_slash - path;
}

static int
parse_cmdline(int argc, char **argv, char *file)
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

    return 0;
}

static int
open_file(char *path)
{
    int ret;
    size_t dnlen;

    dnlen = dirname_len(path);
    if (dnlen == 0)
        return -EISDIR;

    path[dnlen] = '\0';
    ret = open(path, O_TMPFILE | O_WRONLY, S_IRUSR | S_IWUSR);
    path[dnlen] = '/';

    return (ret == -1) ? -errno : ret;
}

#define MAX_LEN 4096

static int
copy_file(int fd_in, int fd_out)
{
    for (;;) {
        ssize_t ret;

        ret = splice(fd_in, NULL, fd_out, NULL, MAX_LEN, 0);
        if (ret < 1) {
            if (ret == 0)
                break;
            return -errno;
        }
    }

    return 0;
}

#undef MAX_LEN

static int
link_file(int fd, const char *name)
{
    char path[PATH_MAX];

    if (snprintf(path, sizeof(path), "/proc/self/fd/%d", fd)
        >= (int)sizeof(path))
        return -ENAMETOOLONG;

    return (linkat(AT_FDCWD, path, AT_FDCWD, name, AT_SYMLINK_FOLLOW) == 0)
           ? 0 : -errno;
}

int
main(int argc, char **argv)
{
    char file[PATH_MAX];
    int err;
    int fd;

    if (parse_cmdline(argc, argv, file) == -1)
        return EXIT_FAILURE;

    fd = open_file(file);
    if (fd < 0)
        error(EXIT_FAILURE, -fd, "Error opening %s", file);

    err = copy_file(STDIN_FILENO, fd);
    if (err) {
        error(0, -err, "Error copying %s", file);
        goto err;
    }

    err = link_file(fd, file);
    if (err) {
        error(0, -err, "Error linking %s", file);
        goto err;
    }

    if (close(fd) == -1)
        error(EXIT_FAILURE, errno, "Error closing %s", file);

    return EXIT_SUCCESS;

err:
    close(fd);
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
