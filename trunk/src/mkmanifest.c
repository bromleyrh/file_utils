/*
 * mkmanifest.c
 */

#include <proc_ext.h>
#include <strings_ext.h>

#include <errno.h>
#include <error.h>
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

static void print_usage(const char *);
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

static int
parse_cmdline(int argc, char **argv, char *conf_path, char *template_path)
{
    for (;;) {
        int opt = getopt(argc, argv, "c:ht:");

        if (opt == -1)
            break;

        switch (opt) {
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
        default:
            return -1;
        }
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

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESETHAND;

    for (i = 0; i < sizeof(intsignals)/sizeof(intsignals[0]); i++) {
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

    static char *const cmd1[] = {"verify", "-c", conf_path, NULL};
    static char *const cmd2[] = {"osort", "-k3", NULL};
    static char *const cmd3[] = {"cat", template_path, "-", NULL};

    struct proc cmds[] = {
        {.file = "verify", .argv = cmd1},
        {.file = "osort", .argv = cmd2},
        {.file = "cat", .argv = cmd3}
    };
    static const int ncmds = (int)(sizeof(cmds)/sizeof(cmds[0]));

    ret = parse_cmdline(argc, argv, conf_path, template_path);
    if (ret != 0)
        return (ret == -1) ? EXIT_FAILURE : EXIT_SUCCESS;

    if (((conf_path[0] == '\0') && (get_path(CONF_PATH, conf_path) != 0))
        || ((template_path[0] == '\0')
            && (get_path(TEMPLATE_PATH, template_path) != 0)))
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
        if ((ret == 0) && (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)))
            ret = -EIO;
    }

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
