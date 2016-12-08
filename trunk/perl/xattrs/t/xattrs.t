#!/usr/bin/env perl

#
# xattrs.t
#

use strict;
use warnings;

use POSIX qw(:errno_h);

use Test::More tests => 42;
use ExtUtils::testlib;

use xattrs;

my $testfile = "testfile";

sub print_err;

sub print_xattr_flags;

sub test_setxattr;
sub test_getxattr;
sub test_listxattr;
sub test_removexattr;

sub print_err {
    my ($msg, $err) = @_;

    if ($err != 0) {
        my $errstr = POSIX::strerror($err < 0 ? -$err : $err);
        diag("$msg: $errstr\n");
    }
}

sub print_xattr_flags {
    my @flags = (
        "XATTR_CREATE",
        "XATTR_MAXNAMELEN",
        "XATTR_NOFOLLOW",
        "XATTR_REPLACE",
        "XATTR_SHOWCOMPRESSION"
    );

    for my $flag (@flags) {
        my $val = xattrs::constant($flag);
        diag("$flag = $val\n");
    }
}

sub test_setxattr {
    my ($f, $path, $keyvals) = @_;

    my $fd = fileno($f);
    my $flags = xattrs::constant("XATTR_CREATE");

    for my $key (keys %{$keyvals}) {
        my $val = $keyvals->{$key};

        my $err = xattrs::setxattr($path, $key, $val, $flags);
        ok($err == 0, "setxattr($key, $val) == 0");
        print_err("setxattr($key, $val)", $err);

        $err = xattrs::fsetxattr($fd, $key, $val, $flags);
        ok($err == EEXIST, "fsetxattr($key, $val) == EEXIST");
        print_err("fsetxattr($key, $val)", $err);
    }
}

sub test_getxattr {
    my ($f, $path, $keyvals) = @_;

    my $fd = fileno($f);

    for my $key (keys %{$keyvals}) {
        my $retval;
        my $val = $keyvals->{$key};

        $retval = undef;
        my $err = xattrs::getxattr($path, $key, $retval, 0);
        ok($err == 0, "getxattr($key) == 0");
        print_err("getxattr($key)", $err);
        if (defined($retval)) {
            ok($retval eq $val, "getxattr($key) == $val");
        }

        $retval = undef;
        $err = xattrs::fgetxattr($fd, $key, $retval, 0);
        ok($err == 0, "fgetxattr($key) == 0");
        print_err("fgetxattr($key)", $err);
        if (defined($retval)) {
            ok($retval eq $val, "fgetxattr($key) == $val");
        }
    }
}

sub test_listxattr {
    my ($f, $path, $keyvals) = @_;

    my $fd = fileno($f);
    my @namebuf;

    my $err = xattrs::listxattr($path, \@namebuf, 0);
    ok($err >= 0, "listxattr() >= 0");
    if ($err < 0) {
        print_err("listxattr()", $err);
    }
    for my $key (@namebuf) {
        print(STDERR "$key\n");
    }

    $err = xattrs::flistxattr($fd, \@namebuf, 0);
    ok($err >= 0, "flistxattr() >= 0");
    if ($err < 0) {
        print_err("flistxattr()", $err);
    }
    for my $key (@namebuf) {
        print(STDERR "$key\n");
    }
}

sub test_removexattr {
    my ($f, $path, $keyvals) = @_;

    my $fd = fileno($f);

    for my $key (keys %{$keyvals}) {
        my $err = xattrs::removexattr($path, $key, 0); 
        ok($err == 0, "removexattr($key) == 0");
        print_err("removexattr($key)", $err);

        $err = xattrs::fremovexattr($fd, $key, 0);
        ok($err != 0, "fremovexattr($key) != 0");
        print_err("fremovexattr($key)", $err);
    }
}

my $keyvals = {
    "key1" => "value1",
    "key2" => "value2",
    "key3" => "value3",
    "key4" => "value4",
    "key5" => "value5"
};

print_xattr_flags();

open(my $f, ">>", $testfile) or do {
    warn("Couldn't open $testfile: $!\n");
    exit(1);
};

test_setxattr($f, $testfile, $keyvals);
test_getxattr($f, $testfile, $keyvals);
test_listxattr($f, $testfile, $keyvals);
test_removexattr($f, $testfile, $keyvals);

close($f);

# vi: set expandtab sw=4 ts=4:
