#!perl

use Test::More tests => 1;

BEGIN {
  require "t/common.pl";
  start_server();
}

$ldap = client();
if (!$ldap) {
  die "can't contact ldap server";
}

$mesg = $ldap->bind($MANAGERDN, password => $PASSWD);

if ($mesg->code) {
  die "can't bind: ".$mesg->error;
}


# Add
ldif_populate($ldap, "data/14-in.ldif");

# Defalut value
$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
ok(!compare_regex("$TEMPDIR/check.log", "$DATADIR/check.log"));

