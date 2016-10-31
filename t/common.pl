BEGIN {
  use Cwd;

  foreach (qw(my.cfg test.cfg)) {
    -f and require "$_" and last;
  }

  undef $LISM_SERVER unless $LISM_SERVER and -x $LISM_SERVER;
  undef $SQL_SERVER unless $SQL_SERVER and -x $SQL_SERVER;
  undef $LDAP_SERVER unless $LDAP_SERVER and -x $LDAP_SERVER;
  undef $HTTP_SERVER unless $HTTP_SERVER and -x $HTTP_SERVER;

  # If your host cannot be contacted as localhost, change this
  $HOST     ||= '127.0.0.1';

  # Where to put temporary files while testing
  # the Makefile is setup to delete temp/ when make clean is run
  $USER = $ENV{'USER'};
  $WD = Cwd::getcwd();
  $TEMPDIR  = "$WD/temp";
  $DATADIR  = "$WD/data";
  if (!$TRANSACTION) {
    $TRANSACTION = 'off';
  }

  $TESTDB   = "$TEMPDIR/test-db";
  $CONF     = "$TEMPDIR/conf";
  $LISMCONF = "$TEMPDIR/lism.conf";
  $PASSWD   = 'secret';
  $BASEDN   = "dc=lism,dc=com";
  $MANAGERDN= "cn=Manager,dc=lism,dc=com";
  $PORT     = 9009;
  @URL      = ();

  $CONF_IN	  = "$DATADIR/conf.in";
  $LISMCONF_IN    = "$DATADIR/lism-conf.in";
  push @URL, "ldap://${HOST}:$PORT/";
  @LISMD	  = ($LISM_SERVER, '-f',$CONF,'-h', "@URL",qw(-d 256));
  $LDAP_VERSION = 3;

  $LDAP_VERSION ||= 2;

  $MASTERDN = "ou=Master,dc=lism,dc=com";
  $TESTSQL  = "$TEMPDIR/test-sql";
  $SQLCONF  = "$TEMPDIR/my.cnf";
  $SQLDN    = "ou=SQL,dc=lism,dc=com";
  $SQLCONF_IN     = "$DATADIR/my-cnf.in";
  @SQLD           = ($SQL_SERVER, "--defaults-file=$SQLCONF");
  @SQL_OPTS       = ('--user=root', "--socket=$TEMPDIR/mysqld.sock");

  $TESTLDAP = "$TEMPDIR/test-ldap";
  $LDAPCONF = "$TEMPDIR/slapd.conf";
  $LDAPDN   = "ou=LDAP,dc=lism,dc=com";
  $LDAPCONF_IN    = "$DATADIR/slapd-conf.in";
  push @LDAPURL, "ldap://${HOST}:9011/";
  @LDAPD          = ($LDAP_SERVER, '-f',$LDAPCONF,'-h', "@LDAPURL",qw(-d 256));
  @LDAP_OPTS      = ('-x', '-H', 'ldap://localhost:9011', '-D', 'cn=Manager,dc=example,dc=com', '-w', 'secret');

  $TESTSLAVE = "$TEMPDIR/test-slave";
  $SLAVECONF = "$TEMPDIR/slapd-slave.conf";
  $SLAVEDN   = "ou=Slave,dc=lism,dc=com";
  $SLAVECONF_IN    = "$DATADIR/slave-conf.in";
  push @SLAVEURL, "ldap://${HOST}:9012/";
  @SLAVED          = ($LDAP_SERVER, '-f',$SLAVECONF,'-h', "@SLAVEURL",qw(-d 256));
  @SLAVE_OPTS      = ('-x', '-H', 'ldap://localhost:9012', '-D', 'cn=Manager,dc=example,dc=com', '-w', 'secret');

  $TESTCSV  = "$TEMPDIR/test-csv";
  $CSVDN    = "ou=CSV,dc=lism,dc=com";

  $SOAPCONF = "$TEMPDIR/httpd.conf";
  $SOAPDN   = "ou=SOAP,dc=lism,dc=com";
  $SOAPCONF_IN    = "$DATADIR/httpd-conf.in";
  @HTTPD          = ($HTTP_SERVER, '-f',$SOAPCONF);

  mkdir($TEMPDIR,0777);
  die "$TEMPDIR is not a directory" unless -d $TEMPDIR;
}

use Net::LDAP;
use Net::LDAP::LDIF;
use Net::LDAP::Util qw(canonical_dn);
use File::Path qw(rmtree);
use File::Basename qw(basename);

my $pid;
my $sqlpid;
my $ldappid;
my $slavepid;
my $httpdpid;

sub start_server {
  my %arg = (version => 2, @_);

  unless ($LDAP_VERSION >= $arg{version}
	and $LISMD[0] and -x $LISMD[0])
  {
    print "1..0 # Skip No server\n";
    exit;
  }

  if ($CONF_IN and -f $CONF_IN) {
    # Create slapd config file
    open(CONFI,"<$CONF_IN") or die "$!";
    open(CONFO,">$CONF") or die "$!";
    while(<CONFI>) {
      s/\$([A-Z]\w*)/${$1}/g;
      print CONFO;
    }
    close(CONFI);
    close(CONFO);
  }

  if ($LISMCONF_IN and -f $LISMCONF_IN) {
    # Create LISM config file
    open(LISMCONFI,"<$LISMCONF_IN") or die "$!";
    open(LISMCONFO,">$LISMCONF") or die "$!";
    while(<LISMCONFI>) {
      s/\$([A-Z]\w*)/${$1}/g;
      print LISMCONFO;
    }
    close(LISMCONFI);
    close(LISMCONFO);
  }

  if ($SQLCONF_IN and -f $SQLCONF_IN) {
    # Create SQL config file
    open(SQLCONFI,"<$SQLCONF_IN") or die "$!";
    open(SQLCONFO,">$SQLCONF") or die "$!";
    while(<SQLCONFI>) {
      s/\$([A-Z]\w*)/${$1}/g;
      print SQLCONFO;
    }
    close(SQLCONFI);
    close(SQLCONFO);
  }

  if ($LDAPCONF_IN and -f $LDAPCONF_IN) {
    # Create slapd config file
    open(LDAPCONFI,"<$LDAPCONF_IN") or die "$!";
    open(LDAPCONFO,">$LDAPCONF") or die "$!";
    while(<LDAPCONFI>) {
      s/\$([A-Z]\w*)/${$1}/g;
      print LDAPCONFO;
    }
    close(LDAPCONFI);
    close(LDAPCONFO);
  }

  if ($SLAVECONF_IN and -f $SLAVECONF_IN) {
    # Create slapd config file
    open(SLAVECONFI,"<$SLAVECONF_IN") or die "$!";
    open(SLAVECONFO,">$SLAVECONF") or die "$!";
    while(<SLAVECONFI>) {
      s/\$([A-Z]\w*)/${$1}/g;
      print SLAVECONFO;
    }
    close(SLAVECONFI);
    close(SLAVECONFO);
  }

  if ($SOAPCONF_IN and -f $SOAPCONF_IN) {
    # Create slapd config file
    open(SOAPCONFI,"<$SOAPCONF_IN") or die "$!";
    open(SOAPCONFO,">$SOAPCONF") or die "$!";
    while(<SOAPCONFI>) {
      s/\$([A-Z]\w*)/${$1}/g;
      print SOAPCONFO;
    }
    close(SOAPCONFI);
    close(SOAPCONFO);
  }

  rmtree($TESTDB) if ( -d $TESTDB );
  mkdir($TESTDB,0777);
  die "$TESTDB is not a directory" unless -d $TESTDB;

  rmtree($TESTSQL) if ( -d $TESTSQL );
  mkdir($TESTSQL,0777);
  die "$TESTSQL is not a directory" unless -d $TESTSQL;

  rmtree($TESTLDAP) if ( -d $TESTLDAP );
  mkdir($TESTLDAP,0777);
  die "$TESTLDAP is not a directory" unless -d $TESTLDAP;

  rmtree($TESTSLAVE) if ( -d $TESTSLAVE );
  mkdir($TESTSLAVE,0777);
  die "$TESTSLAVE is not a directory" unless -d $TESTSLAVE;

  rmtree($TESTCSV) if ( -d $TESTCSV );
  mkdir($TESTCSV,0777);
  die "$TESTCSV is not a directory" unless -d $TESTCSV;

  unlink("$TEMPDIR/syncfail-SQL.log");
  unlink("$TEMPDIR/syncfail-CSV.log");
  unlink("$TEMPDIR/check.log");

  open SAVEOUT, ">&STDERR";
  open STDERR, "> /dev/null";

  system($SQL_INIT, "--datadir=$TESTSQL");

  unless ($sqlpid = fork) {
    die "fork: $!" unless defined $sqlpid;

    exec(@SQLD) or die "cannot exec @SQLD";
  }
  close STDERR;
  open STDERR, ">&SAVEOUT";
  close SAVEOUT;

  sleep 6; # wait for server to start

  system($SQL_ADMIN, @SQL_OPTS, 'create', 'LISM');
  open SQLCMD, "|mysql ".join(" ", @SQL_OPTS)." LISM";
  open INITDB, "< $DATADIR/initdb.sql";
  while (<INITDB>) {
    print SQLCMD $_;
  }
  close INITDB;
  close SQLCMD;

  my $log = $TEMPDIR . "/" . basename($0,'.t') . "-ldap";

  unless ($ldappid = fork) {
    die "fork: $!" unless defined $ldappid;

    open(STDERR,">$log");
    open(STDOUT,">&STDERR");
    close(STDIN);

    exec(@LDAPD) or die "cannot exec @LDAPD";
  }

  sleep 2; # wait for server to start

  system($LDAPADD, @LDAP_OPTS, '-f', "$DATADIR/initldap.ldif");

  $log = $TEMPDIR . "/" . basename($0,'.t') . "-slave";

  unless ($slavepid = fork) {
    die "fork: $!" unless defined $slavepid;

    open(STDERR,">$log");
    open(STDOUT,">&STDERR");
    close(STDIN);

    exec(@SLAVED) or die "cannot exec @SLAVED";
  }

  sleep 2; # wait for server to start

  system($LDAPADD, @SLAVE_OPTS, '-f', "$DATADIR/initldap.ldif");

  unlink("$TEMPDIR/access_log");
  unlink("$TEMPDIR/error_log");

  unless ($httpdpid = fork) {
    die "fork: $!" unless defined $httpdpid;

    exec(@HTTPD) or die "cannot exec @HTTPD";
  }

  sleep 2;

  warn "@LISMD" if $ENV{TEST_VERBOSE};

  $log = $TEMPDIR . "/" . basename($0,'.t');

  unless ($pid = fork) {
    die "fork: $!" unless defined $pid;

    open(STDERR,">$log");
    open(STDOUT,">&STDERR");
    close(STDIN);

    exec(@LISMD) or die "cannot exec @LISMD";
  }

  sleep 6;
}

sub kill_server {
  if ($pid) {
    kill 9, $pid;
    sleep 1;
    undef $pid;
  }

  if ($sqlpid) {
    system($SQL_ADMIN, '--user=root', "--socket=$TEMPDIR/mysqld.sock", 'shutdown');
    sleep 1;
    undef $sqlpid;
  }

  if ($ldappid) {
    kill 9, $ldappid;
    sleep 1;
    undef $ldappid;
  }

  if ($slavepid) {
    kill 9, $slavepid;
    sleep 1;
    undef $slavepid;
  }

  if ($httpdpid) {
    open(PIDF, "< $TEMPDIR/httpd.pid");
    while (<PIDF>) {
      chop;
      kill 15, $_;
      last;
    }
    close(PIDF);
    sleep 1;
    undef $httpdpid;
  }
}

END {
  kill_server();
}

sub client {
  my %arg = @_;
  my $ldap;
  my $count;
  local $^W = 0;
  if ($arg{ssl}) {
    require Net::LDAPS;
    until($ldap = Net::LDAPS->new($HOST, port => $SSL_PORT, version => 3)) {
      die "ldaps://$HOST:$SSL_PORT/ $@" if ++$count > 10;
      sleep 1;
    }
  }
  elsif ($arg{ipc}) {
    require Net::LDAPI;
    until($ldap = Net::LDAPI->new($IPC_SOCK)) {
      die "ldapi://$IPC_SOCK/ $@" if ++$count > 10;
      sleep 1;
    }
  }
  elsif ($arg{url}) {
    print "Trying $arg{url}\n";
    until($ldap = Net::LDAP->new($arg{url})) {
      die "$arg{url} $@" if ++$count > 10;
      sleep 1;
    }
  }
  else {
    until($ldap = Net::LDAP->new($HOST, port => $PORT, version => $LDAP_VERSION)) {
      die "ldap://$HOST:$PORT/ $@" if ++$count > 10;
      sleep 1;
    }
  }
  $ldap;
}

sub compare_ldif {
  my($test,$mesg) = splice(@_,0,2);

  if ($mesg->code) {
    return;
  }

  my $ldif = Net::LDAP::LDIF->new("$TEMPDIR/${test}-out.tmp","w", lowercase => 1);
  unless ($ldif) {
    return;
  }

  my @canon_opt = (casefold => 'lower', separator => ', ');
  foreach $entry (@_) {
    $entry->dn(canonical_dn($entry->dn, @canon_opt));
    foreach $attr ($entry->attributes) {
      $entry->delete($attr) if $attr =~ /^(modifiersname|creatorsname|modifytimestamp|createtimestamp)$/i;
      if ($attr =~ /^(seealso|member|owner)$/i) {
        $entry->replace($attr => [ map { canonical_dn($_, @canon_opt) } $entry->get_value($attr) ]);
      }
      my @vals = $entry->get_value($attr);
      if (!@vals) {
        @vals = ('attrOnly');
      }
      $entry->replace($attr => [ sort @vals ]);
    }
    $ldif->write($entry);
  }

  $ldif->done; # close the file;

  open(TMP, "<$TEMPDIR/${test}-out.tmp");
  open(LDIF, ">$TEMPDIR/${test}-out.ldif");

  my $first = <TMP>;
  if (!($first =~ /^\n$/)) {
    print LDIF $first;
  }
  while (<TMP>) {
    print LDIF $_;
  }

  close(TMP);
  close(LDIF);
  unlink("$TEMPDIR/${test}-out.tmp");

  ok(!compare("$TEMPDIR/${test}-out.ldif","data/${test}-cmp.ldif"), "data/${test}-cmp.ldif");
}

require File::Compare;

sub compare($$) {
  local(*FH1,*FH2);
  not( open(FH1,"<".$_[0])
       && open(FH2,"<".$_[1])
       && 0 == File::Compare::compare(*FH1,*FH2, -s FH1)
  );
}

sub compare_regex {
  my ($file1, $file2) = @_;

  return File::Compare::compare_text($file1, $file2,
      sub {chop($_[1]);$_[0] !~ /$_[1]/});
}

sub compare_log {
  my ($file1, $file2) = @_;

  return File::Compare::compare_text($file1, $file2,
      sub {if ($_[0] =~ /^#/) {0} else {$_[0] ne $_[1]}});
}

sub ldif_populate {
  my ($ldap, $file, $change) = @_;
  my $ok = 1;

  my $ldif = Net::LDAP::LDIF->new($file,"r", changetype => $change || 'add')
	or return;

  while (my $e = $ldif->read_entry) {
    $mesg = $e->update($ldap);
    if ($mesg->code) {
      $ok = 0;
      Net::LDAP::LDIF->new(qw(- w))->write_entry($e);
      print "# ",$mesg->code,": ",$mesg->error,"\n";
    }
  }
  $ok;
}

1;
