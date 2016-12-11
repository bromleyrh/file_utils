#!/usr/bin/env perl

#
# spec_to_h.pl
#

use strict;
use warnings;

sub print_usage;
sub parse_cmdline;

sub process_file;

sub print_usage {
    print("Usage: $0 FILE_NAME MACRO_NAME\n");
}

sub parse_cmdline {
    if (@ARGV < 2) {
        print_usage();
        exit(1);
    }

    return ($ARGV[0], $ARGV[1]);
}

sub process_file {
    my ($filename, $macroname) = @_;

    open(my $f, "<", "$filename") or do {
        warn("Couldn't open $filename: $!\n");
        return -1;
    };

    print("#define _$macroname(text) #text\n",
          "\n",
          "#define $macroname _$macroname( \\\n");

    while () {
        my $ln = <$f>;
        last if (not defined($ln));

        my $s = substr($ln, 0, -1);
        my $sep = (length($s) == 0) ? "\\" : " \\";
        print("$s$sep\n");
    }

    close($f);

    print(")\n");

    return 0;
}

(my $filename, my $macroname) = parse_cmdline();
(process_file($filename, $macroname) == 0) or exit(1);

# vi: set expandtab sw=4 ts=4:
