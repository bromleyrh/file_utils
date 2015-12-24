/*
 * cp_mem.c
 */

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

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BLKSIZE 512

static const char *src;
static const char *dst;
static int hugetlbfs;

static int
parse_cmdline(int argc, char **argv)
{
    struct stat dsts;

    if (argc < 3) {
        error(0, 0, "Must specify source and destination files");
        return -1;
    }

    src = argv[1];
    dst = argv[2];
    if ((stat(dst, &dsts) == 0) && S_ISDIR(dsts.st_mode)) {
        char *tmpdst;

        if (asprintf(&tmpdst, "%s/%s", dst, basename(strdupa(src))) == -1) {
            error(0, 0, "Out of memory");
            return -1;
        }
        dst = tmpdst;
    }

    if ((argc > 3) && (strcmp(argv[3], "-t") == 0))
        hugetlbfs = 1;

    return 0;
}

#define BUFSIZE (1024 * 1024)

static int
do_copy(int fd1, int fd2, int hugetlbfs)
{
    char *dest;
    int err = 0;
    off_t off;
    struct stat srcs;

    (void)hugetlbfs;

    if (fstat(fd1, &srcs) == -1) {
        error(0, errno, "Couldn't stat %s", src);
        return -1;
    }

    if (ftruncate(fd2, srcs.st_size) == -1) {
        error(0, errno, "Couldn't extend %s", dst);
        return -1;
    }

    dest = (char *)mmap(0, srcs.st_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                        fd2, 0);
    if (dest == MAP_FAILED) {
        error(0, errno, "Memory mapping %s failed", dst);
        return -1;
    }

    for (off = 0; off < srcs.st_size; off += BUFSIZE) {
        char buf[BUFSIZE];
        size_t blockbytes, bytesread, to_read;
        ssize_t ret;
        static char zeroblock[BLKSIZE];

        to_read = srcsb.st_size - off;
        if (to_read > sizeof(buf))
            to_read = sizeof(buf);

        for (bytesread = 0; bytesread < to_read; bytesread += ret) {
            ret = read(fd1, buf + bytesread, to_read - bytesread);
            if (ret == 0)
                goto end;
            if (ret == -1) {
                error(0, errno, "Couldn't read %s", src);
                err = -1;
                goto end;
            }
        }
        for (bytesread = 0; bytesread < to_read; bytesread += blockbytes) {
            if (to_read - bytesread < BLKSIZE)
                blockbytes = to_read - bytesread;
            else {
                blockbytes = BLKSIZE;
                if (memcmp(buf + bytesread, zeroblock, BLKSIZE) == 0)
                    continue;
            }
            memcpy(dest + off + bytesread, buf + bytesread, blockbytes);
        }
    }

end:
    munmap(dest, srcs.st_size);
    return err;
}

#undef BUFSIZE

static int
copy_mode(int fd1, int fd2)
{
    struct stat srcs;

    if (fstat(fd1, &srcs) == -1) {
        error(0, errno, "Couldn't stat %s", src);
        return -1;
    }
    if (fchmod(fd2, srcs.st_mode) == -1) {
        error(0, errno, "Couldn't set file mode of %s", dst);
        return -1;
    }

    return 0;
}

static int
do_link(int fd, const char *name)
{
    const char *oldpath;

    if (asprintf((char **)&oldpath, "/proc/self/fd/%d", fd) == -1) {
        error(0, 0, "Out of memory");
        return -1;
    }

    if (linkat(fd, oldpath, 0, name, AT_SYMLINK_FOLLOW) == -1) {
        error(0, errno, "Couldn't link %s", name);
        free((void *)oldpath);
        return -1;
    }

    free((void *)oldpath);

    return 0;
}

int
main(int argc, char **argv)
{
    int fd1, fd2;

    if (parse_cmdline(argc, argv) == -1)
        return EXIT_FAILURE;

    fd1 = open(src, O_RDONLY);
    if (fd1 == -1)
        error(EXIT_FAILURE, errno, "Couldn't open %s", src);

    if (hugetlbfs)
        fd2 = open(dst, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    else {
        fd2 = open(dirname(strdupa(dst)), O_RDWR | O_TMPFILE,
                   S_IRUSR | S_IWUSR);
    }
    if (fd2 == -1) {
        error(0, errno, "Couldn't open %s", dst);
        goto err1;
    }

    if (do_copy(fd1, fd2, hugetlbfs) == -1)
        goto err2;
    if (copy_mode(fd1, fd2) == -1)
        goto err2;

    close(fd1);
    if (!hugetlbfs)
        do_link(fd2, dst);
    if (close(fd2) == -1) {
        error(0, errno, "Couldn't close %s", dst);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

err2:
    close(fd2);
err1:
    close(fd1);
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
