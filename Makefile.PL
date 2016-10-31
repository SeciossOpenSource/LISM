use 5.008004;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'LISM',
    VERSION_FROM      => 'lib/LISM.pm', # finds $VERSION
    PREREQ_PM         => {
        "Net::LDAP"   => 0,
	"XML::Simple" => 0,
	"Digest::SHA1" => 0,
	"Sys::Syslog" => 0,
    },
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/LISM.pm', # retrieve abstract from module
       AUTHOR         => 'Kaoru Sekiguchi <sekiguchi.kaoru@secioss.co.jp>') : ()),
);
