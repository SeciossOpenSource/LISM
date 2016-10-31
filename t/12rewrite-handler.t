#!perl

use Test::More tests => 5;

BEGIN {
  $TRANSACTION = "off";
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
ldif_populate($ldap, "data/12-in.ldif");

ok(!compare_regex("$TESTCSV/user.csv","data/1201-cmp.csv"), "data/1201-cmp.csv");

ok(!compare("$TESTCSV/group.csv","data/1202-cmp.csv"), "data/1202-cmp.csv");

$mesg = $ldap->search(base => "ou=Roles,$CSVDN", filter => '(cn=*)');
compare_ldif("1203",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=People,$CSVDN", filter => '(uid=user1201)');
compare_ldif("1204",$mesg,$mesg->sorted);

ldif_populate($ldap, "data/1205-in.ldif");
$mesg = $ldap->search(base => "ou=People,$CSVDN", filter => '(uid=orguser1202)');
compare_ldif("1205",$mesg,$mesg->sorted);
