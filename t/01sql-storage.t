#!perl

use Test::More tests => 32;
use POSIX qw(strftime);
use Data::Dumper;

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
ldif_populate($ldap, "data/01-in.ldif");

$mesg = $ldap->search(base => $SQLDN, filter => '(objectClass=*)');
compare_ldif("0101",$mesg,$mesg->sorted);


$dn = "uid=user0101,ou=Tech,ou=IT,ou=People,$SQLDN";

# Modify
$mesg = $ldap->modify($dn,
                        changes => [
                          add => ['telephoneNumber' => '23-4567-8901'],
                          add => ['facsimileTelephoneNumber' => ['23-4567-8901', '34-5678-9012']],
                          add => ['businessCategory' => 'cn=Admin,ou=App,ou=Roles,ou=SQL,dc=lism,dc=com'],
                          delete => ['telephoneNumber' => '12-3456-7890'],
                          delete => ['facsimileTelephoneNumber' => '01-2345-6789'],
                          delete => ['businessCategory' => 'cn=Guest,ou=App,ou=Roles,ou=SQL,dc=lism,dc=com']
                       ]
                     );
$mesg = $ldap->search(base => $SQLDN, filter => 'uid=user0101');
compare_ldif("0102",$mesg,$mesg->sorted);

$mesg = $ldap->modify($dn,
                        changes => [
                          replace => ['cn' => '\'更新\'ユーザ0101'],
                          replace => ['mail' => 'user0101@lism.org'],
                          replace => ['telephoneNumber' => ['01-2345-6789', '34-5678-9012']],
                          replace => ['facsimileTelephoneNumber' => ['01-2345-6789', '34-5678-9012']],
                          replace => ['businessCategory' => ['cn=Admin,ou=App,ou=Roles,ou=SQL,dc=lism,dc=com', 'cn=Guest,ou=App,ou=Roles,ou=SQL,dc=lism,dc=com']]
                       ]
                     );
$mesg = $ldap->search(base => $SQLDN, filter => 'uid=user0101');
compare_ldif("0103",$mesg,$mesg->sorted);

$mesg = $ldap->modify($dn,
                        changes => [
			  delete => ['mail' => []],
                          delete => ['telephoneNumber' => []],
                          delete => ['facsimileTelephoneNumber' => []],
                          delete => ['businessCategory' => []]
                        ]
                     );
$mesg = $ldap->search(base => $SQLDN, filter => 'uid=user0101');
compare_ldif("0104",$mesg,$mesg->sorted);


# Search
$mesg = $ldap->search(base => $SQLDN, filter => 'objectClass=*', scope => 'base');
compare_ldif("0105",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => $SQLDN, filter => 'objectClass=*', scope => 'one', typesonly => 1);
compare_ldif("0106",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=People,$SQLDN", filter => 'objectClass=*', scope => 'base', attrs => ['ou']);
compare_ldif("0107",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=People,$SQLDN", filter => 'objectClass=*', scope => 'one');
compare_ldif("0108",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=Tech,ou=IT,ou=People,$SQLDN", filter => 'objectClass=*', scope => 'base');
compare_ldif("0109",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=Tech,ou=IT,ou=People,$SQLDN", filter => 'objectClass=*', scope => 'one', typesonly => 1);
compare_ldif("0110",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=Tech,ou=IT,ou=People,$SQLDN", filter => 'objectClass=*', attrs => ['objectClass', 'uid']);
compare_ldif("0111",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "uid=user0101,ou=Tech,ou=IT,ou=People,$SQLDN", filter => 'objectClass=*', typesonly => 1, attrs => ['cn', 'userPassword']);
compare_ldif("0112",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "uid=user0101,ou=Tech,ou=IT,ou=People,$SQLDN", filter => 'cn=\'更新\'ユーザ0101', attrs => ['cn', 'modifyTimestamp']);
$timestamp = ($mesg->entries)[0]->get_value('modifyTimestamp');
$date = strftime("%Y%m%d", localtime);

ok($timestamp =~ /^$date.*Z$/, "modifyTimestamp");

# Compare
$mesg = $ldap->compare($dn, attr => 'cn', value => '\'更新\'ユーザ0101');
ok($mesg->code == 6, "compare uid=user0101 true");

$mesg = $ldap->compare($dn, attr => 'cn', value => '更新ユーザ0100');
ok($mesg->code == 5, "compare uid=user0101 false");


# Bind
$mesg = $ldap->bind($dn, password => 'user0101');
ok($mesg->code == 0, "bind uid=user0101 success");

$mesg = $ldap->bind($dn, password => 'user0100');
ok($mesg->code == 49, "bind uid=user0101 failure");


# Delete
$mesg = $ldap->delete($dn);
$mesg = $ldap->search(base => $SQLDN, filter => 'cn=user01');
ok($mesg->count == 0, "delete uid=user0101");


# Rollback
ldif_populate($ldap, "data/0113-in.ldif");
$mesg = $ldap->search(base => $SQLDN, filter => 'cn=user01');
ok($mesg->count == 0, "rollback uid=user0101");

# Special characters
$mesg = $ldap->bind($MANAGERDN, password => $PASSWD);

$mesg = $ldap->modify("uid=user(),ou=Tech,ou=IT,ou=People,$SQLDN", replace => {'mail' => 'user()@lism.org'});

$mesg = $ldap->search(base => $SQLDN, filter => 'uid=user\(\)');
compare_ldif("0120",$mesg,$mesg->sorted);

# Move
$mesg = $ldap->modify("uid=user0102,ou=Tech,ou=IT,ou=People,$SQLDN", replace => {'lismParentDN' => "ou=Sales,ou=IT,ou=People,$SQLDN"});

$mesg = $ldap->search(base => $SQLDN, filter => 'uid=user0102');
compare_ldif("0121",$mesg,$mesg->sorted);

$mesg = $ldap->modify("uid=user0103,ou=Sales,ou=IT,ou=People,$SQLDN", replace => {'lismParentDN' => "ou=Tech,ou=Machine,ou=People,$SQLDN"});

$mesg = $ldap->search(base => $SQLDN, filter => 'uid=user0103');
compare_ldif("0122",$mesg,$mesg->sorted);

#  Recursive object
# Add
ldif_populate($ldap, "data/0123-in.ldif");

$mesg = $ldap->search(base => "ou=Groups,ou=SQL,$BASEDN", filter => 'objectClass=*');
compare_ldif("0123",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=SQL,$BASEDN", filter => 'uid=user0105');
compare_ldif("0124",$mesg,$mesg->sorted);

# Modify
$mesg = $ldap->modify("cn=Group111,cn=Unit11,cn=Department1,ou=Groups,ou=SQL,$BASEDN", replace => {'description' => 'Group111'});
$mesg = $ldap->search(base => "ou=SQL,$BASEDN", filter => '(cn=Group111)');
compare_ldif("0125",$mesg,$mesg->sorted);

$mesg = $ldap->modify("uid=user0105,ou=Tech,ou=IT,ou=People,ou=SQL,$BASEDN",
                        changes => [
                             replace => ['seeAlso' => ["cn=Group111,cn=Unit11,cn=Department1,ou=Groups,ou=SQL,$BASEDN", "cn=Group221,cn=Unit22,cn=Department2,ou=Groups,ou=SQL,$BASEDN"]]
                           ]
                     );
$mesg = $ldap->search(base => "ou=SQL,$BASEDN", filter => 'uid=user0105');
compare_ldif("0126",$mesg,$mesg->sorted);

# Search
$mesg = $ldap->search(base => "cn=Department1,ou=Groups,ou=SQL,$BASEDN", filter => 'objectClass=*', scope => 'base');
compare_ldif("0127",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=Department1,ou=Groups,ou=SQL,$BASEDN", filter => 'objectClass=*', scope => 'one');
compare_ldif("0128",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=Department1,ou=Groups,ou=SQL,$BASEDN", filter => 'objectClass=*');
compare_ldif("0129",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=Unit11,cn=Department1,ou=Groups,ou=SQL,$BASEDN", filter => 'objectClass=*', scope => 'base');
compare_ldif("0130",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=Unit11,cn=Department1,ou=Groups,ou=SQL,$BASEDN", filter => 'objectClass=*', scope => 'one');
compare_ldif("0131",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=Unit11,cn=Department1,ou=Groups,ou=SQL,$BASEDN", filter => 'objectClass=*');
compare_ldif("0132",$mesg,$mesg->sorted);
