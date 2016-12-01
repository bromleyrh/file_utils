/*
 * replicate.c
 */

#include <json.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define CONFIG_PATH "replicate.conf"

static int parse_json_config(const char *, json_val_t *);

static int parse_config(const char *);

static int
parse_json_config(const char *path, json_val_t *config)
{
    char *conf;
    int err;
    int fd;
    struct stat s;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        error(0, errno, "Error opening %s", path);
        return -1;
    }

    if (fstat(fd, &s) == -1) {
        error(0, errno, "Error accessing %s", path);
        goto err;
    }

    conf = mmap(NULL, s.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (conf == MAP_FAILED) {
        error(0, errno, "Error accessing %s", path);
        goto err;
    }
    conf[s.st_size-1] = '\0';

    close(fd);

    err = json_parse(conf, s.st_size, config);

    munmap((void *)conf, s.st_size);

    if (err) {
        error(0, -err, "Error parsing %s", path);
        return -1;
    }

    return 0;

err:
    close(fd);
    return -1;
}

static int
parse_config(const char *path)
{
    int err;
    json_val_t config;

    err = parse_json_config(path, &config);
    if (err)
        return err;

    json_val_free(config);

    return 0;
}

int
main(int argc, char **argv)
{
    int ret;

    (void)argc;
    (void)argv;

    ret = parse_config(CONFIG_PATH);
    if (ret != 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
