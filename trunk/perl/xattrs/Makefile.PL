use 5.022002;
use ExtUtils::Constant qw(WriteConstants);
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'xattrs',
    VERSION_FROM      => 'lib/xattrs.pm', # finds $VERSION, requires EU::MM from perl >= 5.5
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ABSTRACT_FROM     => 'lib/xattrs.pm', # retrieve abstract from module
    AUTHOR            => 'Richard H. Bromley <bromleyrh@gmail.com>',
    #LICENSE           => 'perl',
    #Value must be from legacy list of licenses here
    #http://search.cpan.org/perldoc?Module%3A%3ABuild%3A%3AAPI
    LIBS              => [''], # e.g., '-lm'
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I.', # e.g., '-I. -I/usr/include/other'
	# Un-comment this if you add C files to link with later:
    # OBJECT            => '$(O_FILES)', # link all the C files too
);
WriteConstants(
    NAME              => 'xattrs',
    NAMES             => [qw(XATTR_CREATE
                             XATTR_MAXNAMELEN
                             XATTR_NOFOLLOW
                             XATTR_REPLACE
                             XATTR_SHOWCOMPRESSION)],
);
