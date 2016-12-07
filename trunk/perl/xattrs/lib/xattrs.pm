package xattrs;

use 5.022002;
use strict;
use warnings;

require Exporter;

our @ISA = qw(Exporter);

our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.01';

require XSLoader;
XSLoader::load('xattrs', $VERSION);

# Preloaded methods go here.

1;
__END__

=head1 NAME

xattrs - Perl extension providing an interface to file extended attributes

=head1 SYNOPSIS

  use xattrs;

  $err = xattrs::setxattr($path, $name, $value, $options);
  $err = xattrs::fsetxattr($fileno, $name, $value, $options);

  $err = xattrs::getxattr($path, $name, $value, $options);
  $err = xattrs::fgetxattr($fileno, $name, $value, $options);

  $nattrs = xattrs::listxattr($path, \@namebuf, $options);
  $nattrs = xattrs::flistxattr($fileno, \@namebuf, $options);

  $err = xattrs::removexattr($path, $name, $options);
  $err = xattrs::fremovexattr($fileno, $name, $options);

  $option = xattrs::constant($name);

=head1 DESCRIPTION

See the manual pages in the following section for further documentation for
these routines.

Errors returned by these functions are errno.h error numbers that can be
interpreted using POSIX::strerror(). All functions return a negative error
number on failure and, with the exception of listxattr() and flistxattr(),
return 0 on success.

The listxattr() and flistxattr() functions return the names of the referenced
file's extended attributes in the array of strings referenced by namebuf. On
success, these functions return the number of extended attribute names
retrieved.

The fsetxattr(), fgetxattr(), flistxattr(), and fremovexattr() functions
operate on a file number returned by fileno(), whose argument is a file handle
returned by open(), instead of a path name.

The options flag to these functions is the bitwise or of one or more option
constants, retrieved using the constant() function, whose argument is a string
containing an option's name. The available options are:

  XATTR_CREATE            setxattr(), fsetxattr()
  XATTR_REPLACE           setxattr(), fsetxattr()
  XATTR_NOFOLLOW          all functions
  XATTR_SHOWCOMPRESSION   all functions

For documentation of these options' effects, see the manual pages below.

=head1 SEE ALSO

setxattr(2), getxattr(2), listxattr(2), removexattr(2)

=cut
