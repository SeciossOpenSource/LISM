#!perl

use Test::More tests => 18;

BEGIN {
  $TRANSACTION = "on";
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
ldif_populate($ldap, "data/02-in.ldif");

$mesg = $ldap->search(base => $LDAPDN, filter => 'objectClass=*');
compare_ldif("0201",$mesg,$mesg->sorted);


$dn = "uid=user0201,ou=Tech,ou=IT,ou=People,$LDAPDN";

# Modify
$mesg = $ldap->modify($dn, replace => {'mail' => 'user0201@lism.org',
                                       'employeeType' => '派遣'});
$mesg = $ldap->search(base => $LDAPDN, filter => 'uid=user0201');
compare_ldif("0202",$mesg,$mesg->sorted);


# Search
$mesg = $ldap->search(base => $LDAPDN, filter => 'objectClass=*', scope => 'base', typesonly => 1);
compare_ldif("0203",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => $LDAPDN, filter => 'objectClass=*', scope => 'one', attrs => ['ou']);
compare_ldif("0204",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => $LDAPDN, filter => 'cn=ユーザー0201', attrs => ['cn']);
compare_ldif("0205",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => $LDAPDN, filter => 'employeeType=派遣', attrs => ['employeeType']);
compare_ldif("0206",$mesg,$mesg->sorted);

# Compare
$mesg = $ldap->compare($dn, attr => 'cn', value => 'ユーザー0201');
ok($mesg->code == 6, "compare uid=user0201 true");

$mesg = $ldap->compare($dn, attr => 'cn', value => 'ユーザー0200');
ok($mesg->code == 5, "compare uid=user0201 false");


# Bind
$mesg = $ldap->bind($dn, password => 'user0201');
ok($mesg->code == 0, "bind uid=user0201 success");

$mesg = $ldap->bind($dn, password => 'user0200');
ok($mesg->code == 49, "bind uid=user0201 failure");

$mesg = $ldap->bind($MANAGERDN, password => $PASSWD);

# Delete
$mesg = $ldap->delete($dn);
$mesg = $ldap->search(base => $LDAPDN, filter => 'uid=user0201');
ok($mesg->count == 0, "delete uid=user0201");

# Rollback
ldif_populate($ldap, "data/0212-in.ldif");
$mesg = $ldap->search(base => $SQLDN, filter => 'cn=user0201');
ok($mesg->count == 0, "rollback uid=user0201");

$mesg = $ldap->modify("uid=user0202,ou=Tech,ou=IT,ou=People,$MASTERDN",
                           replace => {'mail' => 'user0202@lism.org',
                                       'employeeType' => '派遣'});
$mesg = $ldap->search(base => $LDAPDN, filter => 'uid=user0202');
compare_ldif("0213",$mesg,$mesg->sorted);

ldif_populate($ldap, "data/0214-in.ldif");
$mesg = $ldap->delete("ou=Consulting,ou=People,$MASTERDN");
$mesg = $ldap->search(base => $SLAVEDN, filter => 'ou=Consulting');
compare_ldif("0214",$mesg,$mesg->sorted);

# Move
$mesg = $ldap->modify("uid=user0202,ou=Tech,ou=IT,ou=People,$LDAPDN", replace => {'lismParentDN' => "ou=Sales,ou=IT,ou=People,$LDAPDN"});

$mesg = $ldap->search(base => $LDAPDN, filter => 'uid=user0202');
compare_ldif("0215",$mesg,$mesg->sorted);

# LDAP Control
ldif_populate($ldap, "data/0216-in.ldif");
$mesg = $ldap->search(base => $LDAPDN, filter => '(objectClass=posixGroup)');
compare_ldif("0216",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => $LDAPDN, filter => '(&(lismControl=paged=3,2)(objectClass=posixGroup))');
compare_ldif("0217",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => $LDAPDN, filter => '(&(lismControl=vlv=2,2&sort=gidNumber:2.5.13.3)(objectClass=posixGroup))');
compare_ldif("0218",$mesg,$mesg->sorted);
