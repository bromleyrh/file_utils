#!/bin/awk -f

#
# format_line.awk
#
# This script reformats a given line of a UTF-8-encoded text file so that each
# character of the line is preceded by a given character or combined with the
# character (if the character is a combining character).
#

BEGIN {
    if (ARGC < 3) {
        printf("Must specify line number\n");
        exit 1;
    }
    line = ARGV[2];
    sep = (ARGC > 3) ? ARGV[3] : "\xE2\x83\xA8";
    ARGC = 2;
}

{
    len = length();
    if ((FNR == line) && (len > 2)) {
        line = substr($0, 2, len - 2);
        gsub(/./, sep "&", line);
        split($0, arr, "");
        printf("%c%s%c\n", arr[1], line, arr[len]);
    } else
        print;
}

# vi: set expandtab sw=4 ts=4:
