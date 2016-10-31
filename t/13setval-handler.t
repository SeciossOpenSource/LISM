#!perl

use Test::More tests => 4;

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
ldif_populate($ldap, "data/13-in.ldif");

# Defalut value
$mesg = $ldap->search(base => $BASEDN, filter => 'uid=user1301');
compare_ldif("1301",$mesg,$mesg->sorted);

# Addition value
$mesg = $ldap->search(base => $BASEDN, filter => 'cn=user1302');
compare_ldif("1302",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => $BASEDN, filter => 'cn=user1303');
compare_ldif("1303",$mesg,$mesg->sorted);

# Replace value
$mesg = $ldap->search(base => $BASEDN, filter => 'mail=user1304@lism.com');
compare_ldif("1304",$mesg,$mesg->sorted);
