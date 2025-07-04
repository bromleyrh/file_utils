/*
 * fastcp.c
 */

#include "sys_dep.h"

#include <option_parsing.h>
#include <strings_ext.h>

#include <files/util.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

static void print_usage(const char *);
static void print_version(void);
static int parse_cmdline(int, char **, const char **, const char **, int *);

static int do_backup(int, const char *);

static void
print_usage(const char *progname)
{
    printf("Usage: %s [options] <source_path> <destination_path>\n"
           "\n"
           "    -b back up existing destination file\n"
           "    -h output help\n",
           progname);
}

static void
print_version()
{
#include <myutil/version.h>
    puts("libutil version " LIBUTIL_VERSION);
}

static int
parse_cmdline(int argc, char **argv, const char **src, const char **dst,
              int *back_up)
{
    static const struct option longopts[] = {
        {"help", 0, NULL, 'h'},
        {"version", 0, NULL, '.'},
        {NULL, 0, NULL, 0}
    };

    GET_LONG_OPTIONS(argc, argv, "bh.", longopts) {
    case 'b':
        *back_up = 1;
        break;
    case 'h':
        print_usage(argv[0]);
        return -2;
    case '.':
        print_version();
        return -2;
    default:
        return -1;
    } END_GET_LONG_OPTIONS;

    if (optind != argc - 2) {
        error(0, 0, optind > argc - 2
                    ? "Must specify source and destination paths"
                    : "Unrecognized arguments");
        return -1;
    }

    *src = argv[optind];
    *dst = argv[optind+1];

    return 0;
}

static int
do_backup(int dirfd, const char *name)
{
    char backup_name[PATH_MAX];

    if (fmtbuf(backup_name, "%s~", name) != 0)
        return -ENAMETOOLONG;

    if (linkat(dirfd, name, dirfd, backup_name, 0) == -1)
        return (errno == ENOENT) ? 0 : -errno;

    if (unlinkat(dirfd, name, 0) == -1) {
        unlinkat(dirfd, backup_name, 0);
        return -errno;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    char *dstbn, tmp = '\0';
    const char *dstdn;
    const char *dst, *src;
    int back_up = 0;
    int dstdirfd;
    int fd1, fd2;
    int ret;
    static const char dot[] = ".";

    ret = parse_cmdline(argc, argv, &src, &dst, &back_up);
    if (ret != 0)
        return ret == -1 ? EXIT_FAILURE : EXIT_SUCCESS;

    fd1 = open(src, O_RDONLY);
    if (fd1 == -1)
        error(EXIT_FAILURE, errno, "Error opening %s", src);

    dstbn = basename_safe(dst);
    if (dstbn == NULL)
        goto err1;
    if (dstbn == dst)
        dstdn = dot;
    else {
        tmp = *dstbn;
        *dstbn = '\0';
        dstdn = dst;
    }
    dstdirfd = openat_directory(AT_FDCWD, dstdn, O_RDONLY, 0);
    if (dstdirfd == -1) {
        error(0, errno, "Error opening %s", dstdn);
        goto err1;
    }
    if (dstdn != dot)
        *dstbn = tmp;

    if (back_up) {
        ret = do_backup(dstdirfd, dstbn);
        if (ret != 0) {
            error(0, -ret, "Error creating backup");
            close(dstdirfd);
            goto err1;
        }
    }

    fd2 = openat(dstdirfd, dstbn, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR);
    if (fd2 == -1) {
        error(0, errno, "Error opening %s", dst);
        close(dstdirfd);
        goto err1;
    }

    close(dstdirfd);

    if ((ret = file_copy_fd(fd1, fd2, 0)) != 0
        || (ret = file_copy_attrs_fd(fd1, fd2, 0)) != 0) {
        error(0, -ret, "Error copying file");
        goto err2;
    }

    close(fd1);
    if (close(fd2) == -1)
        error(EXIT_FAILURE, errno, "Error closing file");

    return EXIT_SUCCESS;

err2:
    close(fd2);
err1:
    close(fd1);
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
