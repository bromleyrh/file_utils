#!/bin/awk -f

#
# format_line.awk
#
# This script reformats a given line of a UTF-8-encoded text file so that each
# character of the line is preceded by a given character or combined with the
# character (if the character is a combining character).
#

function parse_cmdline()
{
    if (ARGC < 3) {
        printf("Must specify line number\n");
        return -1;
    }

    linenum = ARGV[2];

    i = 3;
    while (i < ARGC) {
        if (ARGV[i] == "-r") {
            remove = 1;
            ++i;
        } else if ((ARGV[i] == "-s") && (i < ARGC - 1)) {
            sep = ARGV[i+1];
            i += 2;
        } else
            ++i;
    }

    ARGC = 2;

    return 0;
}

function addsep(line, sep)
{
    gsub(/./, sep "&", line);

    return line;
}

function remsep(line, sep)
{
    seplen = length(sep);

    split(line, linearr, "");
    res = "";
    for (i = 1; i < len - 2; i += seplen + 1)
        res = res sprintf("%s", linearr[i+seplen]);

    return res;
}

BEGIN {
    remove = 0;
    sep = "\xE2\x83\xA8";
    if (parse_cmdline() == -1)
        exit 1;
}

{
    len = length();
    if ((FNR == linenum) && (len > 2)) {
        split($0, arr, "");
        line = substr($0, 2, len - 2);
        line = remove ? remsep(line, sep) : addsep(line, sep);
        printf("%c%s%c\n", arr[1], line, arr[len]);
    } else
        print;
}

# vi: set expandtab sw=4 ts=4:
