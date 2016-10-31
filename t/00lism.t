#!perl

use Test::More tests => 99;

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

if($mesg->code) {
  die "can't bind: ".$mesg->error;
}

ldif_populate($ldap, "data/00-in.ldif");

# Add
$mesg = $ldap->search(base => $BASEDN, filter => 'objectClass=*');
compare_ldif("0001",$mesg,$mesg->sorted);

$dn = "uid=user0001,ou=Tech,ou=IT,ou=People,$MASTERDN";

# Modify
$mesg = $ldap->modify($dn, replace => {'mail' => 'user0001@lism.org'});
$mesg = $ldap->search(base => $BASEDN, filter => 'uid=user0001');
compare_ldif("0002",$mesg,$mesg->sorted);

$mesg = $ldap->modify("uid=user0005,ou=Tech,ou=Machine,ou=People,$MASTERDN", add => {'mail' => 'user0005@lism.org'});
$mesg = $ldap->search(base => $BASEDN, filter => 'uid=user0005');
compare_ldif("0003",$mesg,$mesg->sorted);

$mesg = $ldap->modify("uid=user0005,ou=Tech,ou=Machine,ou=People,$MASTERDN", delete => {'mail' => 'user0005@lism.org'});
$mesg = $ldap->search(base => $BASEDN, filter => 'uid=user0005');
compare_ldif("0004",$mesg,$mesg->sorted);

# search on subcontainer
$mesg = $ldap->search(base => "c=Japan,ou=Company,ou=CSV,$BASEDN", filter => 'objectClass=*');
compare_ldif("0005",$mesg,$mesg->sorted);

# Sync Information
## Synchronization
$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0006",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=sync,$BASEDN", replace => {'lismSyncStatus' => 'sync'});

$mesg = $ldap->search(base => $BASEDN, filter => '(|(uid=user0001)(uid=user0004))');
compare_ldif("0007",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0008",$mesg,$mesg->sorted);

## Add entry
ldif_populate($ldap, "data/0009-in.ldif");

# master sync
$mesg = $ldap->search(base => "cn=master-sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0009",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=master-sync,$BASEDN", replace => {'lismSyncStatus' => 'sync'});

$mesg = $ldap->search(base => $BASEDN, filter => '(|(uid=user0004)(|(uid=user0006)(uid=user0007)))');
compare_ldif("0010",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=master-sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0011",$mesg,$mesg->sorted);

# cluster sync
$mesg = $ldap->modify("uid=user0006,ou=Tech,ou=IT,ou=People,$MASTERDN", replace => {'userPassword' => 'user0006'});
$mesg = $ldap->modify("uid=user0007,ou=Sales,ou=IT,ou=People,$CSVDN", add => {'mail' => 'user0007@lism.org'});

$mesg = $ldap->search(base => "cn=cluster-sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0012",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=cluster-sync,$BASEDN", replace => {'lismSyncStatus' => 'sync'});

$mesg = $ldap->search(base => $BASEDN, filter => '(|(uid=user0006)(uid=user0007))');
compare_ldif("0013",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=cluster-sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0014",$mesg,$mesg->sorted);

# Delete entry
$mesg = $ldap->delete("uid=user0002,ou=Tech,ou=IT,ou=People,$CSVDN");

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0015",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=master-sync,$BASEDN", replace => {'lismSyncStatus' => 'sync'});

$mesg = $ldap->search(base => $BASEDN, filter => 'uid=user0002');
ok($mesg->count == 0, "delete uid=user0002");

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0017",$mesg,$mesg->sorted);

$mesg = $ldap->delete("uid=user0003,ou=Sales,ou=IT,ou=People,$SQLDN");

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0018",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=sync,$BASEDN", replace => {'lismSyncStatus' => 'sync'});

$mesg = $ldap->search(base => $BASEDN, filter => 'uid=user0003');
compare_ldif("0019",$mesg,$mesg->sorted);

ldif_populate($ldap, "data/0020-in.ldif");

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0020",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=sync,$BASEDN", replace => {'lismSyncStatus' => 'sync'});
$mesg = $ldap->search(base => $BASEDN, filter => 'uid=admin');
compare_ldif("0021",$mesg,$mesg->sorted);

# Modify passowrd
$mesg = $ldap->modify("uid=user0001,ou=Tech,ou=IT,ou=People,$SQLDN", replace => {'userpassword' => 'sql0001'});

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0022",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=master-sync,$BASEDN", replace => {'lismSyncStatus' => 'sync'});

$mesg = $ldap->search(base => $BASEDN, filter => 'uid=user0001');
compare_ldif("0023",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0024",$mesg,$mesg->sorted);

# synchronize specified data
ldif_populate($ldap, "data/0025-in.ldif");

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'lismSyncErrNode=CSV' , scope => 'base');
compare_ldif("0025",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'lismSyncErrNode=SQL' , scope => 'base');
compare_ldif("0026",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=master-sync,$BASEDN", delete => {'lismSyncErrNode' => 'CSV'});

$mesg = $ldap->search(base => $BASEDN, filter => '(uid=user0001)');
compare_ldif("0027",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0028",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=sync,$BASEDN", delete => {'lismSyncErrNode' => 'SQL'});

$mesg = $ldap->search(base => $BASEDN, filter => '(uid=user0004)');
compare_ldif("0029",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0030",$mesg,$mesg->sorted);

# sync filter, sync base
$mesg = $ldap->modify("uid=user0001,ou=Tech,ou=IT,ou=People,$SQLDN", add => {'telephoneNumber' => '23-4567-8910'});

$mesg = $ldap->modify("uid=user0003,ou=Sales,ou=IT,ou=People,$CSVDN", replace => {'sn' => 'csv0003'});

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0031",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'lismSyncFilter=\(uid=user0001\)' , scope => 'base');
compare_ldif("0032",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => "lismSyncBase=ou=Tech,ou=IT,ou=People,ou=Master,$BASEDN", scope => 'base');
compare_ldif("0032.1",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'lismSyncFilter=\(uid=user0003\)' , scope => 'base');
compare_ldif("0033",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => "lismSyncBase=ou=Sales,ou=IT,ou=People,ou=Master,$BASEDN", scope => 'base');
compare_ldif("0033.1",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=sync,$BASEDN", replace => {'lismSyncFilter' => '(uid=user0001)'});

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0034",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=sync,$BASEDN", replace => {'lismSyncFilter' => '(uid=user0003)'});

$mesg = $ldap->search(base => "cn=sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0035",$mesg,$mesg->sorted);

# syncfail log
# Add
ldif_populate($ldap, "data/0036-in.ldif");

$mesg = $ldap->delete("uid=user0008,ou=Tech,ou=IT,ou=people,$CSVDN");
# Modify
$mesg = $ldap->modify("uid=user0008,ou=Tech,ou=IT,ou=people,$MASTERDN",
                      add => {'telephoneNumber' => '01-2345-6789'},
                      replace => {'userPassword' => 'passwd0008',
                                  'mail' => 'user0008@lism.org'});

# Delete
$mesg = $ldap->delete("uid=user0008,ou=Tech,ou=IT,ou=people,$MASTERDN");

ok(!-f "$TEMPDIR/syncfail-CSV.log", "data/0036-cmp.log");

# Cluster
$mesg = $ldap->search(base => "cn=cluster,$BASEDN", filter => 'objectClass=*', scope => 'base');
compare_ldif("0037",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=cluster,$BASEDN", delete => {'lismClusterActive' => 'SQL'});
$mesg = $ldap->modify("uid=user0001,ou=Tech,ou=IT,ou=People,$MASTERDN", replace => {'mail' => 'user0001@lism.org'});
$mesg = $ldap->search(base => $BASEDN, filter => 'uid=user0001');
compare_ldif("0038",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=cluster,$BASEDN", add => {'lismClusterActive' => 'SQL'});
$mesg = $ldap->search(base => $BASEDN, filter => 'uid=user0001');
compare_ldif("0039",$mesg,$mesg->sorted);

# Failover and Failback
$mesg = $ldap->modify("cn=cluster,$BASEDN", delete => {'lismClusterActive' => 'LDAP'});
$mesg = $ldap->search(base => "cn=cluster,$BASEDN", filter => 'objectClass=*', scope => 'base');
compare_ldif("0040",$mesg,$mesg->sorted);

$mesg = $ldap->modify("uid=user0001,ou=Tech,ou=IT,ou=People,$MASTERDN", replace => {'mail' => 'user0001@lism.com'});
$mesg = $ldap->search(base => $BASEDN, filter => 'uid=user0001');
compare_ldif("0041",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=cluster,$BASEDN", add => {'lismClusterActive' => 'LDAP'});
$mesg = $ldap->search(base => $BASEDN, filter => 'uid=user0001');
compare_ldif("0042",$mesg,$mesg->sorted);

$mesg = $ldap->modify("uid=user0001,ou=Tech,ou=IT,ou=People,$MASTERDN", replace => {'mail' => 'user0001@lism.org'});
$mesg = $ldap->search(base => $BASEDN, filter => 'uid=user0001');
compare_ldif("0043",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=cluster,$BASEDN", delete => {'lismClusterActive' => 'SQL'});
$mesg = $ldap->modify("uid=user0001,ou=Tech,ou=IT,ou=People,$MASTERDN", replace => {'mail' => 'user0001@lism.com'});
$mesg = $ldap->modify("cn=cluster,$BASEDN", add => {'lismClusterActive' => 'SQL', 'lismCmdOption' => 'nosync'});
$mesg = $ldap->search(base => $BASEDN, filter => 'uid=user0001');
compare_ldif("0044",$mesg,$mesg->sorted);

# Access rule
ldif_populate($ldap, "data/0045-in.ldif");

$mesg = $ldap->bind("uid=user0009,ou=Tech,ou=IT,ou=People,$LDAPDN", password => 'user0009');
$mesg = $ldap->modify("uid=wuser0001,ou=Tech,ou=IT,ou=People,$LDAPDN", replace => {'mail' => 'wuser0001@lism.org'});
$mesg = $ldap->search(base => $LDAPDN, filter => 'uid=wuser0001');
compare_ldif("0045",$mesg,$mesg->sorted); 

$mesg = $ldap->bind("uid=wuser0001,ou=Tech,ou=IT,ou=People,$LDAPDN", password => 'wuser0001');
$mesg = $ldap->modify("uid=user0009,ou=Tech,ou=IT,ou=People,$LDAPDN", replace => {'mail' => 'user0009@lism.org'});
$mesg = $ldap->search(base => $LDAPDN, filter => 'uid=user0009');
compare_ldif("0046",$mesg,$mesg->sorted);

$mesg = $ldap->bind("uid=ruser0001,ou=Tech,ou=IT,ou=People,$LDAPDN", password => 'ruser0001');
$mesg = $ldap->modify("uid=ruser0001,ou=Tech,ou=IT,ou=People,$LDAPDN", replace => {'mail' => 'ruser0001@lism.org'});
$mesg = $ldap->search(base => $LDAPDN, filter => 'uid=ruser0001');
compare_ldif("0047",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => $LDAPDN, filter => 'uid=*');
compare_ldif("0048",$mesg,$mesg->sorted);

$mesg = $ldap->bind("uid=wuser0001,ou=Tech,ou=IT,ou=People,$LDAPDN", password => 'wuser0001');
ldif_populate($ldap, "data/0049-in.ldif");
$mesg = $ldap->search(base => "ou=App,ou=Roles,$LDAPDN", filter => 'cn=*');
compare_ldif("0049",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=Guest,ou=App,ou=Roles,$LDAPDN", replace => {'description' => 'Guest'});
ok($mesg->code == 50);

# Delete
$mesg = $ldap->bind($MANAGERDN, password => $PASSWD);
$mesg = $ldap->delete($dn);
$mesg = $ldap->search(base => $SQLDN, filter => 'uid=user0001');
ok($mesg->count == 0, "delete uid=user0001");

$mesg = $ldap->search(base => $LDAPDN, filter => 'uid=user0001');
ok($mesg->count == 0, "delete uid=user0001");

$mesg = $ldap->search(base => $CSVDN, filter => 'uid=user0001');
ok($mesg->count == 0, "delete uid=user0001");


# Synchronize different level tree
# Add
ldif_populate($ldap, "data/0054-in.ldif");
$mesg = $ldap->search(base => $BASEDN, filter => 'cn=LDAP-Server');
compare_ldif("0054",$mesg,$mesg->sorted);

# Modify
$mesg = $ldap->modify("cn=LDAP-Server,c=Japan,ou=Computers,$MASTERDN", replace => {'l' => 'Tokyo'});
$mesg = $ldap->search(base => $BASEDN, filter => 'cn=LDAP-Server');
compare_ldif("0055",$mesg,$mesg->sorted);

# delete
$mesg = $ldap->delete("cn=LDAP-Server,c=USA,ou=Computers,$MASTERDN");
$mesg = $ldap->search(base => "ou=CSV,$BASEDN", filter => 'cn=LDAP-Server');
ok($mesg->count == 1, "delete cn=LDAP-Server");

$mesg = $ldap->delete("cn=LDAP-Server,c=Japan,ou=Computers,$MASTERDN");
$mesg = $ldap->search(base => $BASEDN, filter => 'cn=LDAP-Server');
ok($mesg->count == 0, "delete cn=LDAP-Server");

# master sync
# Modify
$mesg = $ldap->modify("cn=DB-Server,ou=Computers,$CSVDN", replace => {'ou' => 'Tech'});

$mesg = $ldap->search(base => "cn=master-sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0057",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=master-sync,$BASEDN", replace => {'lismSyncStatus' => 'sync'});

$mesg = $ldap->search(base => $BASEDN, filter => 'cn=DB-Server');
compare_ldif("0058",$mesg,$mesg->sorted);

# cluster sync
# Add
ldif_populate($ldap, "data/0059-in.ldif");
$mesg = $ldap->search(base => "cn=cluster-sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0059",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=cluster-sync,$BASEDN", replace => {'lismSyncStatus' => 'sync'});

$mesg = $ldap->search(base => $BASEDN, filter => 'cn=Mail-Server');
compare_ldif("0060",$mesg,$mesg->sorted);

# Modify
$mesg = $ldap->modify("cn=Mail-Server,c=Japan,ou=Computers,$LDAPDN", replace => {'l' => 'Tokyo'});

$mesg = $ldap->search(base => "cn=cluster-sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0061",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=cluster-sync,$BASEDN", replace => {'lismSyncStatus' => 'sync'});

$mesg = $ldap->search(base => $BASEDN, filter => 'cn=Mail-Server');
compare_ldif("0062",$mesg,$mesg->sorted);

# Delete
$mesg = $ldap->delete("cn=Mail-Server,c=Japan,ou=Computers,$LDAPDN");

$mesg = $ldap->search(base => "cn=cluster-sync,$BASEDN", filter => 'objectClass=*' , scope => 'base');
compare_ldif("0063",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=cluster-sync,$BASEDN", replace => {'lismSyncStatus' => 'sync'});

$mesg = $ldap->search(base => $BASEDN, filter => 'cn=Mail-Server');
ok($mesg->count == 0, "delete cn=Mail-Server");

# Reload configuration
open(CONF, "<$LISMCONF");
open(TMP, ">$TEMPDIR/lism.tmp");
while (<CONF>) {
    s/ou=LDAP/ou=LDAP2/g;
    print TMP $_;
}
close(CONF);
close(TMP);
rename("$TEMPDIR/lism.tmp", $LISMCONF);

$mesg = $ldap->modify("cn=config,$BASEDN", replace => {'lismConfigOperation' => 'reload'});
$mesg = $ldap->search(base => "ou=LDAP2,$BASEDN", filter => 'uid=*');
compare_ldif("0065",$mesg,$mesg->sorted);

# Complex LDAP DIT
# Add
ldif_populate($ldap, "data/0066-in.ldif");
$mesg = $ldap->search(base => "ou=CMPLXDB,$BASEDN", filter => 'objectClass=*');
compare_ldif("0066",$mesg,$mesg->sorted);

# Modify
$mesg = $ldap->modify("uid=user0020,ou=People,ou=Tech,ou=IT,ou=CMPLXDB,$BASEDN", replace => {'mail' => 'user0020@lism.org'});
$mesg = $ldap->search(base => "ou=CMPLXDB,$BASEDN", filter => 'uid=user0020');
compare_ldif("0067",$mesg,$mesg->sorted);

$mesg = $ldap->modify("uid=user0021,ou=People,ou=Sales,ou=Machine,ou=CMPLXDB,$BASEDN",
                        changes => [
                             replace => ['businessCategory' => ["cn=Admin,ou=Roles,ou=IT,ou=CMPLXDB,$BASEDN", "cn=Manager,cn=Group1,cn=Unit1,cn=Tech,ou=Roles,ou=Machine,ou=CMPLXDB,$BASEDN"]]
                           ]
                     );
$mesg = $ldap->search(base => "ou=CMPLXDB,$BASEDN", filter => 'uid=user0021');
compare_ldif("0068",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=Admin,ou=Roles,ou=IT,ou=CMPLXDB,$BASEDN", replace => {'description' => 'Administrator'});
$mesg = $ldap->search(base => "ou=CMPLXDB,$BASEDN", filter => 'cn=Admin');
compare_ldif("0069",$mesg,$mesg->sorted);

# Search
$mesg = $ldap->search(base => "ou=IT,ou=CMPLXDB,$BASEDN", filter => 'objectClass=*', scope => 'base');
compare_ldif("0070",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=CMPLXDB,$BASEDN", filter => 'objectClass=*', scope => 'one');
compare_ldif("0071",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=IT,ou=CMPLXDB,$BASEDN", filter => 'objectClass=*');
compare_ldif("0072",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=IT,ou=CMPLXDB,$BASEDN", filter => 'objectClass=*', scope => 'one');
compare_ldif("0073",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=Roles,ou=IT,ou=CMPLXDB,$BASEDN", filter => 'objectClass=*', scope => 'base');
compare_ldif("0074",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "ou=Roles,ou=IT,ou=CMPLXDB,$BASEDN", filter => 'objectClass=*', scope => 'one');
compare_ldif("0075",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=Admin,ou=Roles,ou=IT,ou=CMPLXDB,$BASEDN", filter => 'objectClass=*');
compare_ldif("0076",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=Admin,ou=Roles,ou=IT,ou=CMPLXDB,$BASEDN", filter => 'objectClass=*', scope => 'base');
compare_ldif("0077",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "uid=user0020,ou=People,ou=Tech,ou=IT,ou=CMPLXDB,$BASEDN", filter => 'objectClass=*', );
compare_ldif("0078",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "uid=user0020,ou=People,ou=Tech,ou=IT,ou=CMPLXDB,$BASEDN", filter => 'objectClass=*', scope => 'base');
compare_ldif("0079",$mesg,$mesg->sorted);

# Delete
$mesg = $ldap->delete("uid=user0020,ou=People,ou=Tech,ou=IT,ou=CMPLXDB,$BASEDN");
$mesg = $ldap->search(base => "ou=CMPLXDB,$BASEDN", filter => 'uid=user0020');
ok($mesg->count == 0, "delete uid=user0020");

$mesg = $ldap->delete("cn=Admin,ou=Roles,ou=IT,ou=CMPLXDB,$BASEDN");
$mesg = $ldap->search(base => "ou=CMPLXDB,$BASEDN", filter => 'cn=Admin');
ok($mesg->count == 0, "delete cn=Admin");

$mesg = $ldap->delete("ou=Roles,ou=Support,ou=CMPLXDB,$BASEDN");
ok($mesg->code == 53, "delete ou=Roles");

# Special characters
$mesg = $ldap->modify("uid=user(),ou=Tech,ou=IT,ou=People,$SQLDN", replace => {'mail' => 'user()@lism.org'});

$mesg = $ldap->search(base => "cn=cluster-sync,$BASEDN", filter => '(lismSyncFilter=\28uid=user\5C\(\5C\)\29)' , scope => 'base');
compare_ldif("0085",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=cluster-sync,$BASEDN", replace => {'lismSyncStatus' => 'sync'});

$mesg = $ldap->search(base => $SQLDN, filter => 'uid=user\(\)');
compare_ldif("0086",$mesg,$mesg->sorted);

# synchronization flag
ldif_populate($ldap, "data/0087-in.ldif");
$mesg = $ldap->search(base => "ou=Services,ou=Slave,$BASEDN", filter => 'objectClass=*');
compare_ldif("0087",$mesg,$mesg->sorted);

$mesg = $ldap->search(base => "cn=cluster-sync,$BASEDN", filter => "lismSyncBase=ou=Services,ou=Master,$BASEDN", scope => 'base');
compare_ldif("0088",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=admin,ou=Tech,ou=IT,ou=Services,ou=Master,$BASEDN", replace => {'ou' => 'nosync'});
$mesg = $ldap->search(base => "cn=cluster-sync,$BASEDN", filter => "lismSyncBase=ou=Services,ou=Master,$BASEDN", scope => 'base');
compare_ldif("0089",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=cluster-sync,$BASEDN", replace => {'lismSyncBase' => "ou=Services,ou=Master,$BASEDN", 'lismSyncStatus' => 'sync'});
$mesg = $ldap->search(base => "ou=Services,ou=Slave,$BASEDN", filter => 'objectClass=*');
compare_ldif("0090",$mesg,$mesg->sorted);

# unique synchronization
ldif_populate($ldap, "data/0091-in.ldif");
$mesg = $ldap->search(base => "cn=master-sync,$BASEDN", filter => "objectClass=*", scope => 'base');
compare_ldif("0091",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=master-sync,$BASEDN", replace => {'lismSyncStatus' => 'sync'});
$mesg = $ldap->search(base => "$BASEDN", filter => 'uid=user0010');
compare_ldif("0092",$mesg,$mesg->sorted);

ldif_populate($ldap, "data/0093-in.ldif");
$mesg = $ldap->search(base => "cn=cluster-sync,$BASEDN", filter => "(lismSyncErrNode=SQL)", scope => 'base');
compare_ldif("0093",$mesg,$mesg->sorted);

$mesg = $ldap->modify("cn=cluster-sync,$BASEDN", delete => {'lismSyncErrNode' => 'SQL'});
$mesg = $ldap->search(base => "$BASEDN", filter => 'uid=user0011');
compare_ldif("0094",$mesg,$mesg->sorted);

# proxy authorization
ldif_populate($ldap, "data/0095-in.ldif");
$mesg = $ldap->bind("uid=pauser0001,ou=People,o=company01.com,ou=Master,$BASEDN", password => 'pauser0001');

$mesg = $ldap->search(base => "o=company01.com,ou=Master,$BASEDN", filter => 'objectClass=*');
compare_ldif("0095",$mesg,$mesg->sorted);

$mesg = $ldap->bind("authzFrom=uid=pauser0001,ou=People,o=company01.com,ou=Master,$BASEDN,authzTo=uid=pauser0003,ou=People,o=company01.com,ou=Master,$BASEDN,cn=authz,$BASEDN", password => 'pauser0001');
ok($mesg->code == 0, "proxy authorization uid=pauser0003 success");
$mesg = $ldap->search(base => "o=company01.com,ou=Master,$BASEDN", filter => 'objectClass=*');
compare_ldif("0096",$mesg,$mesg->sorted);

$mesg = $ldap->bind("authzFrom=uid=pauser0002,ou=People,o=company01.com,ou=Master,$BASEDN,authzTo=uid=pauser0003,ou=People,o=company01.com,ou=Master,$BASEDN,cn=authz,$BASEDN", password => 'pauser0002');
ok($mesg->code == 49, "proxy authorization uid=pauser0003 failure");
