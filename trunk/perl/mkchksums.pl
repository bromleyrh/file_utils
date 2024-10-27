#!/usr/bin/env perl

#
# mkchksums.pl
#

use strict;
use warnings;

use Digest::SHA;
use File::Find;
use POSIX qw(:errno_h);

use xattrs;

my $attrname = "user.sha1";

sub print_usage;
sub parse_cmdline;

sub print_err;

sub do_set;
sub do_print;
sub do_verify;
sub do_remove;

sub print_usage {
    print("Usage: $0 MODE DIRECTORY\n");
}

sub parse_cmdline {
    if (@ARGV < 2) {
        print_usage();
        exit(1);
    }

    return ($ARGV[0], $ARGV[1]);
}

sub print_err {
    (my $err, my $filename, my $errmsg) = @_;

    print("$filename: $errmsg: " . POSIX::strerror($err < 0 ? -$err : $err)
          . "\n");
}

sub do_set {
    (-f and open(my $f, "<", $_)) or return;

    my $sha1ctx = Digest::SHA->new("sha1");
    $sha1ctx->addfile($f);
    my $sum = $sha1ctx->hexdigest;

    my $err = xattrs::fsetxattr(fileno($f), $attrname, $sum, 0);

    close($f);

    ($err != 0) and print_err($err, $_,
                              "Error setting $attrname extended attribute");
}

sub do_print {
    -f or return;

    my $err = xattrs::getxattr($_, $attrname, my $sum, 0);
    if ($err != 0) {
        print_err($err, $_, "Error getting $attrname extended attribute");
    } else {
        printf("%32s: %s\n", $_, $sum);
    }
}

sub do_verify {
    (-f and open(my $f, "<", $_)) or return;

    my $err = xattrs::fgetxattr(fileno($f), $attrname, my $sum, 0);
    ($err != 0) and do {
        print_err($err, $_, "Error getting $attrname extended attribute");
        return;
    };

    my $sha1ctx = Digest::SHA->new("sha1");
    $sha1ctx->addfile($f);
    my $sumcalc = $sha1ctx->hexdigest;

    close($f);

    ($sum eq $sumcalc)
    or print_err(EIO, $_, "$attrname checksum ($sum) does not match calculated "
                          . "checksum");
}

sub do_remove {
    -f or return;

    my $err = xattrs::removexattr($_, $attrname, 0);
    ($err != 0) and print_err($err, $_,
                              "Error removing $attrname extended attribute");
}

(my $mode, my $rootdir) = parse_cmdline();

my $func;
if ($mode eq "-s") {
    $func = \&do_set;
} elsif ($mode eq "-p") {
    $func = \&do_print;
} elsif ($mode eq "-c") {
    $func = \&do_verify;
} elsif ($mode eq "-r") {
    $func = \&do_remove;
} else {
    print("Invalid mode \"$mode\"\n");
    exit(1);
}

finddepth($func, $rootdir);

# vi: set expandtab sw=4 ts=4:
