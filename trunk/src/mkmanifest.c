/*
 * mkmanifest.c
 */

#define _GNU_SOURCE

#include "common.h"

#include <option_parsing.h>
#include <proc_ext.h>
#include <strings_ext.h>

#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wordexp.h>

#include <sys/wait.h>

#define CONF_PATH "\"$HOME/.verify.conf\""
#define TEMPLATE_PATH "\"$HOME/.manifest_temp\""

#define MKV_PLUGIN_PATH "/usr/local/lib/libverify_mkv_plugin.so"

static void print_usage(const char *);
static void print_version(void);
static int parse_cmdline(int, char **, char *, char *);

static int get_path(const char *, char *);

static int set_signal_handlers(void);

static void
print_usage(const char *progname)
{
    printf("Usage: %s [options]\n"
           "\n"
           "    -c PATH use specified verify configuration file\n"
           "    -h      output help\n"
           "    -t PATH use specified manifest template file\n",
           progname);
}

static void
print_version()
{
#include <myutil/version.h>
    puts("libutil version " LIBUTIL_VERSION);
}

static int
parse_cmdline(int argc, char **argv, char *conf_path, char *template_path)
{
    static const struct option longopts[] = {
        {"help", 0, NULL, 'h'},
        {"version", 0, NULL, '.'},
        {NULL, 0, NULL, 0}
    };

    GET_LONG_OPTIONS(argc, argv, "c:ht:.", longopts) {
    case 'c':
        if (strlcpy(conf_path, optarg, PATH_MAX) >= PATH_MAX)
            goto path_err;
        break;
    case 'h':
        print_usage(argv[0]);
        return -2;
    case 't':
        if (strlcpy(template_path, optarg, PATH_MAX) >= PATH_MAX)
            goto path_err;
        break;
    case '.':
        print_version();
        return -2;
    default:
        return -1;
    } END_GET_LONG_OPTIONS;

    if (optind != argc) {
        errmsg("Unrecognized arguments\n");
        return -1;
    }

    return 0;

path_err:
    error(0, 0, "Path name too long");
    return -1;
}

static int
get_path(const char *pathspec, char *path)
{
    wordexp_t words;

    if (wordexp(pathspec, &words, WRDE_NOCMD | WRDE_UNDEF) != 0)
        goto err1;

    if (words.we_wordc != 1)
        goto err2;

    strlcpy(path, words.we_wordv[0], PATH_MAX);

    wordfree(&words);

    return 0;

err2:
    wordfree(&words);
err1:
    return -EIO;
}

static int
set_signal_handlers()
{
    size_t i;
    struct sigaction sa;

    static const int intsignals[] = {SIGINT, SIGTERM};

    omemset(&sa, 0);
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESETHAND;

    for (i = 0; i < ARRAY_SIZE(intsignals); i++) {
        if (sigaction(intsignals[i], &sa, NULL) == -1)
            return -errno;
    }

    return 0;
}

int
main(int argc, char **argv)
{
    int ret;

    static char conf_path[PATH_MAX] = "", template_path[PATH_MAX] = "";
    static char plugin_path[] = MKV_PLUGIN_PATH;

    static char *const cmd1[] = {"verify", "-a", "-c", conf_path, "-p",
                                 plugin_path, NULL};
    static char *const cmd2[] = {"osort", "-k3", NULL};
    static char *const cmd3[] = {"fastcat", template_path, "-", NULL};

    struct proc cmds[] = {
        {.file = "verify", .argv = cmd1},
        {.file = "osort", .argv = cmd2},
        {.file = "fastcat", .argv = cmd3}
    };
    static const int ncmds = (int)ARRAY_SIZE(cmds);

    ret = parse_cmdline(argc, argv, conf_path, template_path);
    if (ret != 0)
        return ret == -1 ? EXIT_FAILURE : EXIT_SUCCESS;

    if ((conf_path[0] == '\0' && get_path(CONF_PATH, conf_path) != 0)
        || (template_path[0] == '\0'
            && get_path(TEMPLATE_PATH, template_path) != 0))
        return EXIT_FAILURE;

    errno = 0;
    if (isatty(fileno(stdout))) {
        int rem;

        infomsg("Warning: Standard output is a terminal device: waiting 10 "
                "seconds\n");
        for (rem = 10; rem > 0; rem = sleep(rem))
            ;
    } else if (errno != ENOTTY)
        return EXIT_FAILURE;

    if (set_signal_handlers() != 0)
        return EXIT_FAILURE;

    ret = pipeline(cmds, ncmds);
    if (ret != 0)
        error(EXIT_FAILURE, -ret, "Error executing");

    for (;;) {
        int status;

        if (wait(&status) == -1) {
            if (errno == ECHILD)
                break;
            error(EXIT_FAILURE, errno, "Error");
        }
        if (ret == 0 && (!WIFEXITED(status) || WEXITSTATUS(status) != 0))
            ret = -EIO;
    }

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
