#!perl

use Test::More tests => 13;
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
ldif_populate($ldap, "data/04-in.ldif");

$mesg = $ldap->search(base => $SOAPDN, filter => '(objectClass=*)');
compare_ldif("0401",$mesg,$mesg->sorted);


$dn = "uid=user0401,ou=Tech,ou=IT,ou=People,$SOAPDN";

# Modify
$mesg = $ldap->modify($dn,
                        changes => [
                          add => ['telephoneNumber' => '23-4567-8901'],
                          add => ['businessCategory' => 'cn=Admin,ou=App,ou=Roles,ou=SOAP,dc=lism,dc=com'],
                          delete => ['telephoneNumber' => '12-3456-7890'],
                          delete => ['businessCategory' => 'cn=Guest,ou=App,ou=Roles,ou=SOAP,dc=lism,dc=com'],
                        ]
                     );
$mesg = $ldap->search(base => $SOAPDN, filter => 'uid=user0401');
compare_ldif("0402",$mesg,$mesg->sorted);

$mesg = $ldap->modify($dn,
                       changes => [
                         replace => ['cn' => '更新ユーザー0401'],
                         replace => ['mail' => 'user0401@lism.org'],
                         replace => ['telephoneNumber' => ['01-2345-6789', '34-5678-9012']],
                         replace => ['businessCategory' => ['cn=Admin,ou=App,ou=Roles,ou=SOAP,dc=lism,dc=com', 'cn=Guest,ou=App,ou=Roles,ou=SOAP,dc=lism,dc=com']]
                       ]
                     );
$mesg = $ldap->search(base => $SOAPDN, filter => 'uid=user0401');
compare_ldif("0403",$mesg,$mesg->sorted);

$mesg = $ldap->modify($dn,
                       changes => [
                         delete => ['mail' => []],
                         delete => ['telephoneNumber' => []],
                         delete => ['businessCategory' => []]
                       ]
                     );
$mesg = $ldap->search(base => $SOAPDN, filter => 'uid=user0401');
compare_ldif("0404",$mesg,$mesg->sorted);


# Search
$mesg = $ldap->search(base => $SOAPDN, filter => 'objectClass=*', scope => 'one', typesonly => 1);
compare_ldif("0405",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=People,$SOAPDN", filter => 'objectClass=*', scope => 'base', attrs => ['ou']);
compare_ldif("0406",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=Tech,ou=IT,ou=People,$SOAPDN", filter => 'objectClass=*', attrs => ['objectClass', 'uid']);
compare_ldif("0407",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "uid=user0401,ou=Tech,ou=IT,ou=People,$SOAPDN", filter => 'objectClass=*', typesonly => 1, attrs => ['cn', 'userPassword']);
compare_ldif("0408",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "uid=user0401,ou=Tech,ou=IT,ou=People,$SOAPDN", filter => 'cn=更新ユーザー0401', attrs => ['cn', 'modifyTimestamp']);
$timestamp = ($mesg->entries)[0]->get_value('modifyTimestamp');
$date = strftime("%Y%m%d", localtime);
ok($timestamp =~ /^$date.*Z$/, "modifyTimestamp");

# Bind
$mesg = $ldap->bind($dn, password => 'user0401');
ok($mesg->code == 0, "bind uid=user0401 success");

$mesg = $ldap->bind($dn, password => 'user0400');
ok($mesg->code == 49, "bind uid=user0401 failure");


$mesg = $ldap->bind($MANAGERDN, password => $PASSWD);

# Delete
$mesg = $ldap->delete($dn);
$mesg = $ldap->search(base => $SOAPDN, filter => 'uid=user0401');
ok($mesg->count == 0, "delete uid=user0401");

# Web server down
$mesg = $ldap->search(base => "ou=BADSOAP,$BASEDN", filter => '(objectClass=*)');
ok($mesg->code == 1);
