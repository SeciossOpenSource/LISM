#!perl

use Test::More tests => 32;
use POSIX qw(strftime);
use Data::Dumper;

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
ldif_populate($ldap, "data/03-in.ldif");

$mesg = $ldap->search(base => $CSVDN, filter => '(objectClass=*)');
compare_ldif("0301",$mesg,$mesg->sorted);


$dn = "uid=user0301,ou=Tech,ou=IT,ou=People,$CSVDN";

# Modify
$mesg = $ldap->modify($dn,
                        changes => [
                          add => ['telephoneNumber' => '23-4567-8901'],
                          add => ['businessCategory' => 'cn=Admin,ou=App,ou=Roles,ou=CSV,dc=lism,dc=com'],
                          add => ['o' => 'Machine(ou=Machine,ou=People,ou=CSV,dc=lism,dc=com)'],
                          delete => ['telephoneNumber' => '12-3456-7890'],
                          delete => ['businessCategory' => 'cn=Guest,ou=App,ou=Roles,ou=CSV,dc=lism,dc=com'],
                          delete => ['o' => 'IT(ou=IT,ou=People,ou=CSV,dc=lism,dc=com)']
                        ]
                     );
$mesg = $ldap->search(base => $CSVDN, filter => 'uid=user0301');
compare_ldif("0302",$mesg,$mesg->sorted);

$mesg = $ldap->modify($dn,
                       changes => [
                         replace => ['cn' => '更新ユーザー0301'],
                         replace => ['mail' => 'user03@lism.org'],
                         replace => ['telephoneNumber' => ['01-2345-6789', '34-5678-9012']],
                         replace => ['businessCategory' => ['cn=Admin,ou=App,ou=Roles,ou=CSV,dc=lism,dc=com', 'cn=Guest,ou=App,ou=Roles,ou=CSV,dc=lism,dc=com']],
                         replace => ['o' => ['IT(ou=IT,ou=People,ou=CSV,dc=lism,dc=com)',  'Machine(ou=Machine,ou=People,ou=CSV,dc=lism,dc=com)']]
                       ]
                     );
$mesg = $ldap->search(base => $CSVDN, filter => 'uid=user0301');
compare_ldif("0303",$mesg,$mesg->sorted);

$mesg = $ldap->modify($dn,
                       changes => [
                         delete => ['mail' => []],
                         delete => ['telephoneNumber' => []],
                         delete => ['businessCategory' => []]
                       ]
                     );
$mesg = $ldap->search(base => $CSVDN, filter => 'uid=user0301');
compare_ldif("0304",$mesg,$mesg->sorted);


# Search
$mesg = $ldap->search(base => $CSVDN, filter => 'objectClass=*', scope => 'base');
compare_ldif("0305",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => $CSVDN, filter => 'objectClass=*', scope => 'one', typesonly => 1);
compare_ldif("0306",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=People,$CSVDN", filter => 'objectClass=*', scope => 'base', attrs => ['ou']);
compare_ldif("0307",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=People,$CSVDN", filter => 'objectClass=*', scope => 'one');
compare_ldif("0308",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=Tech,ou=IT,ou=People,$CSVDN", filter => 'objectClass=*', scope => 'base');
compare_ldif("0309",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=Tech,ou=IT,ou=People,$CSVDN", filter => 'objectClass=*', scope => 'one', typesonly => 1);
compare_ldif("0310",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=Tech,ou=IT,ou=People,$CSVDN", filter => 'objectClass=*', attrs => ['objectClass', 'uid']);
compare_ldif("0311",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "uid=user0301,ou=Tech,ou=IT,ou=People,$CSVDN", filter => 'objectClass=*', typesonly => 1, attrs => ['cn', 'userPassword']);
compare_ldif("0312",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "uid=user0301,ou=Tech,ou=IT,ou=People,$CSVDN", filter => 'cn=更新ユーザー0301', attrs => ['cn', 'modifyTimestamp']);
$timestamp = ($mesg->entries)[0]->get_value('modifyTimestamp');
$date = strftime("%Y%m%d", localtime);
ok($timestamp =~ /^$date.*Z$/, "modifyTimestamp");

# Compare
$mesg = $ldap->compare($dn, attr => 'cn', value => '更新ユーザー0301');
ok($mesg->code == 6, "compare uid=user0301 true");

$mesg = $ldap->compare($dn, attr => 'cn', value => '更新ユーザー0300');
ok($mesg->code == 5, "compare uid=user0301 false");


# Bind
$mesg = $ldap->bind($dn, password => 'user0301');
ok($mesg->code == 0, "bind uid=user0301 success");

$mesg = $ldap->bind($dn, password => 'user0300');
ok($mesg->code == 49, "bind uid=user0301 failure");


$mesg = $ldap->bind($MANAGERDN, password => $PASSWD);

# Delete
$mesg = $ldap->delete($dn);
$mesg = $ldap->search(base => $CSVDN, filter => 'uid=user0301');
ok($mesg->count == 0, "delete uid=user0301");


# Rollback
ldif_populate($ldap, "data/0313-in.ldif");
$mesg = $ldap->search(base => $CSVDN, filter => 'uid=user0301');
ok($mesg->count == 0, "rollback uid=user0301");

# Special characters
$mesg = $ldap->bind($MANAGERDN, password => $PASSWD);

$mesg = $ldap->modify("uid=user(),ou=Tech,ou=IT,ou=People,$CSVDN", replace => {'mail' => 'user()@lism.org'});

$mesg = $ldap->search(base => $CSVDN, filter => 'uid=user\(\)');
compare_ldif("0320",$mesg,$mesg->sorted);

# Multi-byte characters
$mesg = $ldap->modify("uid=ユーザー0305,ou=Tech,ou=IT,ou=People,$CSVDN", replace => {'mail' => 'user0305@lism.org'});

$mesg = $ldap->search(base => $CSVDN, filter => 'uid=ユーザー0305');
compare_ldif("0321",$mesg,$mesg->sorted);

$mesg = $ldap->delete("uid=ユーザー0305,ou=Tech,ou=IT,ou=People,$CSVDN");
$mesg = $ldap->search(base => $CSVDN, filter => 'uid=ユーザー0305');
ok($mesg->count == 0, "delete uid=ユーザー0305");

#  Recursive object
# Add
ldif_populate($ldap, "data/0323-in.ldif");

$mesg = $ldap->search(base => "ou=Groups,ou=CSV,$BASEDN", filter => 'objectClass=*');
compare_ldif("0323",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=CSV,$BASEDN", filter => 'uid=user0306');
compare_ldif("0324",$mesg,$mesg->sorted);

# Modify
$mesg = $ldap->modify("cn=Group111,cn=Unit11,cn=Department1,ou=Groups,ou=CSV,$BASEDN", replace => {'description' => 'Group111'});
$mesg = $ldap->search(base => "ou=CSV,$BASEDN", filter => '(cn=Group111)');
compare_ldif("0325",$mesg,$mesg->sorted);

$mesg = $ldap->modify("uid=user0306,ou=Tech,ou=IT,ou=People,ou=CSV,$BASEDN",
                        changes => [
                             replace => ['seeAlso' => ["cn=Group111,cn=Unit11,cn=Department1,ou=Groups,ou=CSV,$BASEDN", "cn=Group221,cn=Unit22,
cn=Department2,ou=Groups,ou=CSV,$BASEDN"]]
                           ]
                     );
$mesg = $ldap->search(base => "ou=CSV,$BASEDN", filter => 'uid=user0306');
compare_ldif("0326",$mesg,$mesg->sorted);

# Search
$mesg = $ldap->search(base => "cn=Department1,ou=Groups,ou=CSV,$BASEDN", filter => 'objectClass=*', scope => 'base');
compare_ldif("0327",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=Department1,ou=Groups,ou=CSV,$BASEDN", filter => 'objectClass=*', scope => 'one');
compare_ldif("0328",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=Department1,ou=Groups,ou=CSV,$BASEDN", filter => 'objectClass=*');
compare_ldif("0329",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=Unit11,cn=Department1,ou=Groups,ou=CSV,$BASEDN", filter => 'objectClass=*', scope => 'base');
compare_ldif("0330",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=Unit11,cn=Department1,ou=Groups,ou=CSV,$BASEDN", filter => 'objectClass=*', scope => 'one');
compare_ldif("0331",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=Unit11,cn=Department1,ou=Groups,ou=CSV,$BASEDN", filter => 'objectClass=*');
compare_ldif("0332",$mesg,$mesg->sorted);
