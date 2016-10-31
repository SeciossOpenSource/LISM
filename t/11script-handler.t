#!perl

use Test::More tests => 9;

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
ldif_populate($ldap, "data/11-in.ldif");

ok(!compare("$TEMPDIR/user11.csv","data/1101-cmp.csv"), "data/1101-cmp.csv");

ok(!-f "$TEMPDIR/user12.csv", "add uid=user12");

$dn = "uid=user11,ou=Tech,ou=IT,ou=People,$LDAPDN";

# Modify
$mesg = $ldap->modify($dn, replace => {'mail' => 'user01@lism.org'});
ok(!compare("$TEMPDIR/user11.csv","data/1102-cmp.csv"), "data/1102-cmp.csv");

$mesg = $ldap->modify("uid=user12,ou=Tech,ou=IT,ou=People,$LDAPDN", replace => {'userPassword' => 'passwd12'});
ok(!-f "$TEMPDIR/user12.csv", "modify uid=user12");

$mesg = $ldap->modify($dn, delete => ['mail']);
ok(!compare("$TEMPDIR/user11.csv","data/1103-cmp.csv"), "data/1103-cmp.csv");

# Rollback
ldif_populate($ldap, "data/1104-in.ldif");
$mesg = $ldap->modify("uid=user13,ou=Tech,ou=IT,ou=People,$LDAPDN", replace => {'mail' => 'user13@lism.org'});
$mesg = $ldap->search(base => $LDAPDN, filter => 'uid=user13');
compare_ldif("1104",$mesg,$mesg->sorted);

$mesg = $ldap->delete("uid=user13,ou=Tech,ou=IT,ou=People,$LDAPDN");
$mesg = $ldap->search(base => $LDAPDN, filter => 'uid=user13');
compare_ldif("1105",$mesg,$mesg->sorted);

ldif_populate($ldap, "data/1106-in.ldif");
$mesg = $ldap->modify("uid=user14,ou=Tech,ou=IT,ou=People,$MASTERDN",
                           replace => {'mail' => 'user14@lism.org'});
$mesg = $ldap->search(base => $LDAPDN, filter => 'uid=user14');
compare_ldif("1106",$mesg,$mesg->sorted);

# Delete
$mesg = $ldap->delete($dn);
ok(!-f "$TEMPDIR/user11.csv", "delete uid=user11");
