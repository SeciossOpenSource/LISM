package LISM;

use strict;
use Module::Load qw(load);
use Net::LDAP::Filter;
use LISM::Constant;
use XML::Simple;
use MIME::Base64;
use POSIX qw(strftime);
use Encode;
use LISM::Storage;
use Data::Dumper;
if ($^O ne 'MSWin32') {
    eval "load(Secioss::Auth::Util, 'openlog', 'syslog')";
    if ($@) {
        load(Sys::Syslog, 'openlog', 'syslog');
    }
    use Sys::Syslog qw(:macros);
} else {
    load(Log::Dispatch::FileRotate);
}

our $VERSION = '4.3.0';

our $lism_master = 'lism_master';
our $syncrdn = 'cn=sync';
our $master_syncrdn = 'cn=master-sync';
our $cluster_syncrdn = 'cn=cluster-sync';
our $syncInfoEntry = "objectClass: lismSync\n";
our $syncInfoAttr = "lismSyncStatus";
our $nosyncAttr = "lismSyncErrMessage";
our $syncDataAttr = "lismSyncErrNode";
our $syncFilterAttr = "lismSyncFilter";
our $syncBaseAttr = "lismSyncBase";
our $syncSizeAttr = "lismSyncSizeLimit";
our $clusterrdn = 'cn=cluster';
our $clusterEntry = "objectClass: lismCluster\n";
our $masterAttr = "lismClusterMaster";
our $clusterAttr = "lismClusterNode";
our $activeAttr = "lismClusterActive";
our $optionAttr = "lismCmdOption";
our $confrdn = 'cn=config';
our $confOpAttr = "lismConfigOperation";
our $authzdn = 'cn=authz';
our $syncFailLog = 'syncfail';
our $sizeLimit = 1000000;
our $lockFile = 'lism.lock';

=head1 NAME

LISM - an OpenLDAP backend for accessing and synchronizaing data of CSV, SQL etc via LDAP

=head1 SYNOPSIS

In slapd.conf:

  database          perl
  suffix            "dc=my-domain,dc=com"
  perlModulePath    /path/to/LISM/module/files
  perlModule        LISM
  admindn           "cn=Manager,dc=my-domain,dc=com"
  adminpw           secret
  conf              /path/to/LISM/configuration/file

=head1 DESCRIPTION

When you use several RDB, LDAP and the other system, you will have a hard time synchronizing their data. LISM(LDAP Identity Synchronization Manager) solves this problem. LISM eables to update the all systems to update LDAP server of LISM.

=head1 CONSTRUCTOR

This is a plain constructor.

=cut

sub new
{
    my $class = shift;

    my $this = {};
    bless $this, $class;

    return $this;
}

=head1 METHODS

=head2 config($k, @v)

This method is called by back-perl for every configuration line. This parses XML configuration of L<LISM>.
Returns 0 if the configuration directive is valid, non-0 if it isn't.

=cut

sub config
{
    my $self = shift;
    my ($k, @v) = @_;

    if (!defined($self->{_config})) {$self->{_config} = {}}

    if ( @v > 1 ) {
        $self->{_config}->{$k} = \@v;
    } else {
        if ($k eq 'admindn' || $k eq 'basedn') {
            ($self->{_config}->{$k} = $v[0]) =~ tr/A-Z/a-z/;
        } else {
            $self->{_config}->{$k} = $v[0];
        }
    }

    return 0;
}

=pod

=head2 init

This method is called after the configuration is parsed. This create the storage object that is needed.
Returns 0 if it complete successfully, non-0 otherwise.

=cut

sub init
{
    my $self = shift;
    my $conf;
    my $lism;

    if (!defined($self->{_config})) {$self->{_config} = {}}
    $conf = $self->{_config};

    # check slapd configuration
    if ($self->_slapdConfig()) {
        $self->log(level => 'alert', message => "slapd configuration error");
        return 1;
    }

    $self->log(level => 'info', message => "LISM $VERSION starting");

    return $self->_startup();
}

=pod

=head2 bind($binddn, $passwd)

This method is called when a client tries to bind to slapd.
Returns 0 if the authentication succeeds.

=cut

sub bind
{
    my $self = shift;
    my $rc;

    eval "\$rc = \$self->_bind(\@_)";
    if ($@) {
        $self->log(level => 'err', message => "Bind operation failed: $@");
        $rc = LDAP_OPERATIONS_ERROR;
    }
    return $rc;
}

sub _bind
{
    my $self = shift;
    my($binddn, $passwd, $ip) = @_;
    my $conf = $self->{_lism};
    my $timeout = $self->{_config}->{timeout};
    my $dn;
    my $filterStr;
    my $rc = LDAP_NO_SUCH_OBJECT;

    if (!$binddn) {
        return LDAP_INSUFFICIENT_ACCESS;
    }

    undef($self->{bind});

    DO: {
        # decode bind dn
        $binddn = decode('utf8', $binddn);

        $binddn =~ s/,\s+/,/;

        if ($binddn =~ /$authzdn,$self->{_config}->{basedn}$/i) {
            ($binddn, $dn) = ($binddn =~ /^seciossSystemId=(.+),seciossLoginId=(.+),$authzdn,$self->{_config}->{basedn}$/i);
            $binddn =~ s/\\3D/=/g;
            $dn =~ s/\\3D/=/g;
            if ($binddn =~ /^$self->{_config}->{admindn}$/i) {
                $filterStr = '(objectClass=*)';
            } else {
                $filterStr = "(authzFrom=$binddn)";
            }
        }
        $dn = $dn ? $dn : $binddn;
        $filterStr = $filterStr ? $filterStr : '(objectClass=*)';

        # check bind by administration user
        if ($binddn =~ /^$self->{_config}->{admindn}$/i) {
            if (defined($self->{_config}->{adminpw}) && $passwd eq $self->{_config}->{adminpw}) {
                $rc = LDAP_SUCCESS;
                if ($binddn eq $dn) {
                    $self->{bind}{dn} = $dn;
                    if ($ip) {
                        $self->{bind}{ip} = $ip;
                    }
                    last DO;
                }
            } else {
                $rc = LDAP_INVALID_CREDENTIALS;
                last DO;
            }
        } else {
            my $dname = $self->_getDataName($binddn);
            if (!$dname) {
                $rc = LDAP_INVALID_CREDENTIALS;
                last DO;
            }

            my $dconf = $self->{data}{$dname}->{conf};

            # call bind of the appropriate storage
            my $storage = $self->_getStorage($dname);
            if (defined($storage)) {
                # do pre handler
                $rc = $self->_doHandler('pre', 'bind', $dname, \$binddn);

                if (!$rc) {
                    $rc = $storage->bind($binddn, $passwd);
                }
            } else {
                $rc = LDAP_INVALID_CREDENTIALS;
                last DO;
            }

            if (!$rc) {
                # do post handler
                $self->_doHandler('post', 'bind', $dname, \$binddn);
            }
        }

        if (!$rc) {
            # set binddn
            my @entries = ();
            ($rc, @entries) = $self->_do_search($dn, 0, 0, 1, $timeout, $filterStr, 0);
            if (!$rc && @entries) {
                $self->{bind}{dn} = $self->_replMasterDn($dn);
                $self->{bind}{entryStr} = $self->_replMasterDn($entries[0]);
                if ($ip) {
                    $self->{bind}{ip} = $ip;
                }
            } elsif ($rc == LDAP_NO_SUCH_OBJECT || !@entries) {
                $rc = LDAP_INVALID_CREDENTIALS;
            } else {
                $rc = LDAP_OTHER;
            }
        }
    }

    if ($rc < 0) {
        $rc = LDAP_OTHER;
    }

    $self->auditlog('bind', $binddn, $rc);

    return $rc;
}

=pod

=head2 search($base, $scope, $deref, $sizeLim, $timeLim, $filterStr, $attrOnly, @attrs)

This method is called when a client tries to search to slapd.
Returns 0 if it completes successfully.

=cut

sub search
{
    my $self = shift;
    my $rc;
    my @match_entries;

    eval "(\$rc, \@match_entries) = \$self->_search(\@_)";
    if ($@) {
        $self->log(level => 'err', message => "Search operation failed: $@");
        $rc = LDAP_OPERATIONS_ERROR;
    }
    return ($rc, @match_entries);
}

sub _search
{
    my $self = shift;
    my($base, $scope, $deref, $sizeLim, $timeLim, $filterStr, $attrOnly, @attrs) = @_;
    my $conf = $self->{_lism};
    my @match_entries = ();

    if (!$base) {
        return (LDAP_UNWILLING_TO_PERFORM, @match_entries);
    }

    # set size limit
    $sizeLim = $sizeLim < 0 ? $sizeLimit : $sizeLim;

    # set timeout
    $timeLim = $timeLim > 0 ? $timeLim : $self->{_config}->{timeout};

    # decode base
    $base = decode('utf8', $base);

    # get cluster information
    if ($base =~ /^$clusterrdn,$self->{_config}->{basedn}$/i) {
        if (!$self->_accessAllowed($base, 'read')) {
            return(LDAP_INSUFFICIENT_ACCESS, @match_entries);
        }

        return $self->_getClusterInfo($base, $scope, $filterStr, $attrOnly, @attrs);
    }

    # get synchronization information
    if (defined($conf->{sync})) {
        if ($base =~ /^($syncrdn|$master_syncrdn|$cluster_syncrdn),$self->{_config}->{basedn}$/i) {
            $self->{operation} = 'sync';
            my($rc, @entries) = $self->_getSyncInfo($base, $scope, $filterStr, $attrOnly, @attrs);
            $self->{operation} = '';
            return ($rc, @entries);
        }
    }

    my ($rc, @entries) = $self->_do_search($base, $scope, $deref, $sizeLim, $timeLim, $filterStr, $attrOnly, @attrs);

    foreach my $entry (@entries) {
        if ($self->_accessAllowed(($entry =~ /^dn: (.*)\n/)[0], 'read')) {
            push(@match_entries, $entry);
        }
    }

    return ($rc, @match_entries);
}

=pod

=head2 compare($dn, $avaStr)

This method is called when a client tries to compare to slapd.
Returns 6 if the compared value exist, 5 if it doesn't exist.

=cut

sub compare
{
    my $self = shift;
    my ($dn, $avaStr) = @_;
    my $conf = $self->{_lism};
    my $rc = LDAP_NO_SUCH_OBJECT;

    # decode dn, value
    $dn = decode('utf8', $dn);
    $avaStr = decode('utf8', $avaStr);

    $dn =~ s/,\s+/,/g;

    if ($dn eq $self->{_config}{basedn}) {
        # basedn can't be compared
        return LDAP_UNWILLING_TO_PERFORM;
    }

    if (!$self->_accessAllowed($dn, 'read')) {
        return LDAP_INSUFFICIENT_ACCESS;
    }

    my $dname = $self->_getDataName($dn);
    if (!$dname) {
        return LDAP_NO_SUCH_OBJECT;
    }

    my $dconf = $self->{data}{$dname}->{conf};

    # call compare of the appropriate storage
    my $storage = $self->_getStorage($dname);
    if (defined($storage)) {
        # do pre handler
        $rc = $self->_doHandler('pre', 'compare', \$dn, \$avaStr);

        if (!$rc) {
            $rc = $storage->compare($dn, $avaStr);
        }

        if (!$rc) {
            # do post handler
            $self->_doHandler('post', 'compare', \$dn, \$avaStr);
        }
    }

    if ($rc < 0) {
        $rc = LDAP_OTHER;
    }

    return $rc;
}

=pod

=head2 modify($dn, @list)

This method is called when a client tries to modify to slapd. This can modify all storages required in configuration.
Returns 0 if it modify the data of one storage or all storages successfully.

=cut

sub modify
{
    my $self = shift;
    my $rc;

    eval "\$rc = \$self->_modify(\@_)";
    if ($@) {
        $self->log(level => 'err', message => "Modify operation failed: $@");
        $rc = LDAP_OPERATIONS_ERROR;
    }
    return $rc;
}

sub _modify
{
    my $self = shift;
    my ($dn, @list) = @_;
    my $conf = $self->{_lism};
    my @pwd_mod_list;
    my $rc;
    my $oldentry;

    # decode dn, values
    $dn = decode('utf8', $dn);
    for (my $i = 0; $i < @list; $i++) {
        $list[$i] = decode('utf8', $list[$i]);
        if ($list[$i] =~ /^userpassword$/i && $list[$i + 1] && $list[$i + 1] !~ /^{[^}]+}/) {
            # add plain text password
            push(@pwd_mod_list, ($list[$i - 1], 'plainpassword', $list[$i + 1 ]));
        } elsif ($list[$i] =~ /(\r\n|\r|\n)/ && $list[$i - 1] !~ /^lismPreviousEntry$/i) {
            $list[$i] =~ s/(\r\n|\r|\n)/\r/g;
        }
    }
    if (@pwd_mod_list) {
        push(@list, @pwd_mod_list);
    }

    my $case_exact = 0;
    my $dname = $self->_getDataName($dn);
    if ($dname) {
        my $dconf = $self->{data}{$dname}->{conf};
        if (defined($dconf->{caseexact})) {
            $case_exact = 1;
        }

        if ($list[1] =~ /^lismPreviousEntry$/i && $dname !~ /^(?:IdSync|Lifecycle|Task)$/) {
            shift(@list);
            shift(@list);
            $oldentry = shift(@list);
        }
    }
    if (!$case_exact) {
        $dn =~ tr/A-Z/a-z/;
    }
    $dn =~ s/,\s+/,/g;

    if ($dn eq $self->{_config}{basedn}) {
        # basedn can't be modifed
        return LDAP_UNWILLING_TO_PERFORM;
    }

    if (!$self->_accessAllowed($dn, 'modify', @list)) {
        return LDAP_INSUFFICIENT_ACCESS;
    }

    # reload configuration
    if ($dn =~ /^$confrdn,$self->{_config}{basedn}$/i) {
        return $self->_setConfig($dn, @list);
    }

    # set cluster information
    if ($dn =~ /^$clusterrdn,$self->{_config}{basedn}$/i) {
        return $self->_setClusterInfo($dn, @list);
    }

    # set synchronization information
    if (defined($conf->{sync})) {
        if ($dn =~ /^($syncrdn|$master_syncrdn|$cluster_syncrdn),$self->{_config}{basedn}$/i) {
            $self->{operation} = 'sync';
            return $self->_setSyncInfo($dn, @list);
        }
    }

    $rc = $self->_doUpdate('modify', undef, 1, $oldentry, $dn, @list);

    return $rc;
}

=pod

=head2 add($entryStr)

This method is called when a client tries to add to slapd. This can add the data to all storages required in coufiguration.
Returns 0 if it add the data of one storage or all storages.

=cut

sub add
{
    my $self = shift;
    my $rc;

    eval "\$rc = \$self->_add(\@_)";
    if ($@) {
        $self->log(level => 'err', message => "Add operation failed: $@");
        $rc = LDAP_OPERATIONS_ERROR;
    }
    return $rc;
}

sub _add
{
    my $self = shift;
    my ($entryStr) = @_;
    my $conf = $self->{_lism};
    my $rc;

    $entryStr =~ s/\n\s+//g;
    my ($dn) = ($entryStr =~ /^dn:{1,2} (.*)$/m);
    if ($entryStr =~ /^dn::/) {
        $dn = decode_base64($dn);
    }

    # decode dn, entry
    $dn = decode('utf8', $dn);
    $entryStr = decode('utf8', $entryStr);

    $entryStr =~ s/^dn:.*\n//;

    my $case_exact = 0;
    my $dname = $self->_getDataName($dn);
    if ($dname) {
        my $dconf = $self->{data}{$dname}->{conf};
        if (defined($dconf->{caseexact})) {
            $case_exact = 1;
        }
    }
    if (!$case_exact) {
        $dn =~ tr/A-Z/a-z/;
    }
    $dn =~ s/,\s+/,/g;

    # decode base64
    $entryStr = $self->_decBase64Entry($entryStr);

    if ($entryStr =~ /^userpassword:\s+([^\s]+)$/mi) {
        my $plainpw = $1;
        if ($plainpw !~ /^{[^}]+}/) {
            $entryStr =~ s/^userpassword:.*$/userpassword: $plainpw\nplainpassword: $plainpw/mi;
        }
    }

    if ($dn eq $self->{_config}{basedn}) {
        # basedn already exist
        return LDAP_ALREADY_EXISTS;
    }

    if (!$self->_accessAllowed($dn, 'add', $entryStr)) {
        return LDAP_INSUFFICIENT_ACCESS;
    }

    $rc = $self->_doUpdate('add', undef, 1, undef, $dn, $entryStr);

    return $rc;
}

=pod

=head2 modrdn($dn, $newrdn, $delFlag)

This method is called when a client tries to modrdn to slapd. This can move the data in the storage required in coufiguration but can't do it between two storages.
Returns 0 if it move the data in one storage or all storages successfully.

=cut

sub modrdn
{
    my $self = shift;
    my ($dn, $newrdn, $delFlag) = @_;
    my $conf = $self->{_lism};
    my $rc;

    # decode dn, rdn
    $dn = decode('utf8', $dn);
    $newrdn = decode('utf8', $newrdn);

    my $case_exact = 0;
    my $dname = $self->_getDataName($dn);
    if ($dname) {
        my $dconf = $self->{data}{$dname}->{conf};
        if (defined($dconf->{caseexact})) {
            $case_exact = 1;
        }
    }
    if (!$case_exact) {
        $dn =~ tr/A-Z/a-z/;
    }
    $dn =~ s/,\s+/,/g;

    if ($dn eq $self->{_config}{basedn}) {
        return LDAP_NOT_ALLOWED_ON_NONLEAF;
    }

    if (!$self->_accessAllowed($dn, 'modify')) {
        return LDAP_INSUFFICIENT_ACCESS;
    }

    $rc = $self->_doUpdate('modrdn', undef, 1, undef, $dn, $newrdn, $delFlag);

    return $rc;
}

=pod

=head2 delete($dn)

This method is called when a client tries to delete to slapd. This can delete the data of all storages required in configureation.
Returns 0 if it delete the data of one storage or all storages successfully.

=cut

sub delete
{
    my $self = shift;
    my $rc;

    eval "\$rc = \$self->_delete(\@_)";
    if ($@) {
        $self->log(level => 'err', message => "Delete operation failed: $@");
        $rc = LDAP_OPERATIONS_ERROR;
    }
    return $rc;
}

sub _delete
{
    my $self = shift;
    my ($dn) = @_;
    my $conf = $self->{_lism};
    my $rc;

    # decode dn
    $dn = decode('utf8', $dn);

    my $case_exact = 0;
    my $dname = $self->_getDataName($dn);
    if ($dname) {
        my $dconf = $self->{data}{$dname}->{conf};
        if (defined($dconf->{caseexact})) {
            $case_exact = 1;
        }
    }
    if (!$case_exact) {
        $dn =~ tr/A-Z/a-z/;
    }
    $dn =~ s/,\s+/,/g;

    if ($dn eq $self->{_config}{basedn}) {
        return LDAP_NOT_ALLOWED_ON_NONLEAF;
    }

    if (!$self->_accessAllowed($dn, 'delete')) {
        return LDAP_INSUFFICIENT_ACCESS;
    }

    $rc = $self->_doUpdate('delete', undef, 1, undef, $dn);

    return $rc;
}

=pod

=head2 log(level, message)

log message to syslog.

=cut

sub log
{
    my $self = shift;
    my $conf = $self->{_config};
    my %p = @_;

    if (Encode::is_utf8($p{'message'})) {
        $p{'message'} = encode('utf8', $p{'message'});
    }
    $p{'message'} = uc($p{'level'}).' ['.ref($self).'] '.$p{'message'};

    if ($^O ne 'MSWin32') {
        openlog('LISM', 'pid', $conf->{syslogfacility});
        syslog($p{'level'}, sprintf("%.512s", $p{'message'}));
    } else {
        $self->{log}->log(level => $p{'level'}, message => strftime("%Y/%m/%d %H:%M:%S", localtime(time))." ".$p{'message'}."\n");
    }

    if (defined($conf->{printlog}) && $conf->{printlog} =~ /$p{'level'}/) {
        print $p{'message'}."\n";
    }
}

=pod

=head2 auditlog($type, $dn, $result, $error, @info)

write to the audit log.

=cut

sub auditlog
{
    my $self = shift;
    my $conf = $self->{_config};

    my $message = $self->_auditMsg(@_);
    if (!$message) {
        return;
    }

    if ($^O ne 'MSWin32') {
        openlog('LISM', 'pid', $conf->{auditfacility});
        if (length($message) > 40960) {
            $message = substr($message, 0, 40960);
            if ($message =~ /seciossmember:=/i) {
                $message =~ s/[^;]+$/uid=...,ou=People,/;
            }
        }
        syslog('info', $message);

        if ($conf->{auditfile}) {
            my $fd;
            if (open($fd, ">> $conf->{auditfile}")) {
                print $fd $message."\n";
                close $fd;
            } else {
                $self->log(level => 'err', message => "Can't open $conf->{auditfile}");
            }
        }
    } else {
        $self->{audit}->log(level => 'info', message => strftime("%Y/%m/%d %H:%M:%S", localtime(time))." $message\n");
    }

    if (defined($conf->{'printlog'}) && $conf->{'printlog'} =~ /audit/) {
        print "$message\n";
    }
}

=pod

=head2 error()

return the newest error message.

=cut

sub error
{
    my $self = shift;

    return $self->{error};
}

=pod

=head2 rolelog($roleattrs, $type, $oldentry, $dn, @info)

write to the role log.

=cut

sub rolelog
{
    my $self = shift;
    my ($roleattrs, $type, $oldentry, $dn, @info) = @_;
    my $conf = $self->{_config};
    my @attrs = split(/, */, $roleattrs);
    my $message = '';

    if ($type eq 'add') {
        my $entryStr  = $info[0];
        foreach my $attr (@attrs) {
            my @setval_roles;
            if ($entryStr =~ /^setvalRole: $attr=(.+)$/mi) {
                @setval_roles = split(/;/, $1);
            }
            if (@setval_roles) {
                for (my $i = 0; $i < @setval_roles; $i++) {
                    if ($setval_roles[$i] =~ /^[^=]+=([^,]+),.+/) {
                        $setval_roles[$i] = $1;
                    }
                }
                $message .= ($message ? " ": '')."$attr(rule):+".join(';', @setval_roles);
            }
            my @values = ($entryStr =~ /^$attr: (.+)$/gmi);
            if (@values) {
                for (my $i = 0; $i < @values; $i++) {
                    my $value = $values[$i];
                    if ($value =~ /^[^=]+=([^,]+),.+/) {
                        $value = $1;
                    }
                    if (!grep(/^$value$/i, @setval_roles)) {
                        $message .= ($i == 0 ? ($message ? ' ' : '')."$attr:+" : ';').$value;
                    }
                }
            }
        }
    } elsif ($type eq 'modify' && $oldentry) {
        my %setval_roles;
        for (my $i = 0; $i < @info; $i++) {
            if ($info[$i] =~ /^setvalRole$/i) {
                $i++;
                for (; $i < @info; $i++) {
                    foreach my $attr (@attrs) {
                        if ($info[$i] =~ /^$attr=(.+)$/i) {
                            my @values = split(/;/, $1);
                            for (my $j = 0; $j < @values; $j++) {
                                if ($values[$j] =~ /^[^=]+=([^,]+),.+/) {
                                    $values[$j] = $1;
                                }
                            }
                            $setval_roles{lc($attr)} = \@values;
                            last;
                        }
                    }
                }
                last;
            }
        }
        while (@info > 0) {
            my $action = shift @info;
            my $key = lc(shift @info);
            my @values;

            while (@info > 0 && $info[0] ne "ADD" && $info[0] ne "DELETE" && $info[0] ne "REPLACE") {
                my $value = shift @info;
                if ($value =~ /^[^=]+=([^,]+),.+/) {
                    $value = $1;
                }
                push(@values, $value);
            }

            if (!grep(/^$key$/i, @attrs)) {
                next;
            }

            if ($action eq "ADD") {
                if (defined($setval_roles{$key})) {
                    $message .= ($message ? " " : '')."$key(rule):+".join(';', @{$setval_roles{$key}});
                }
                if (@values) {
                    my $valmatch = 0;
                    for (my $i = 0; $i < @values; $i++) {
                        my $value = $values[$i];
                        if (!grep(/^$value$/i, @{$setval_roles{$key}})) {
                            $message .= (!$valmatch ? ($message ? ' ' : '')."$key:+" : ';').$value;
                            $valmatch = 1;
                        }
                    }
                }
            } elsif ($action eq "REPLACE") {
                my @old_vals = ($oldentry =~ /^$key: (.+)$/gmi);
                for (my $i = 0; $i < @old_vals; $i++) {
                    if ($old_vals[$i] =~ /^[^=]+=([^,]+),.+/) {
                        $old_vals[$i] = $1;
                    }
                }
                my @add_vals;
                my @delete_vals;
                foreach my $value (@values) {
                    my $valmatch = 0;
                    my $i = 0;
                    for ($i = 0; $i < @old_vals; $i++) {
                        if ($old_vals[$i] =~ /^$value$/i) {
                            $valmatch = 1;
                            last;
                        }
                    }
                    if ($valmatch) {
                        splice(@old_vals, $i, 1);
                    } else {
                        push(@add_vals, $value);
                    }
                }
                @delete_vals = @old_vals;
                if (@add_vals) {
                    if (defined($setval_roles{$key})) {
                        my $valmatch = 0;
                        for (my $i = 0; $i < @{$setval_roles{$key}}; $i++) {
                            my $value = ${$setval_roles{$key}}[$i];
                            if (grep(/^$value$/i, @add_vals)) {
                                $message .= (!$valmatch ? ($message ? ' ' : '')."$key(rule):+" : ';').$value;
                                $valmatch = 1;
                            }
                        }
                    }
                    my $valmatch = 0;
                    for (my $i = 0; $i < @add_vals; $i++) {
                        my $value = $add_vals[$i];
                        if (!grep(/^$value$/i, @{$setval_roles{$key}})) {
                            $message .= (!$valmatch ? ($message ? ' ' : '')."$key:+" : ';').$value;
                            $valmatch = 1;
                        }
                    }
                }
                if (@delete_vals) {
                    $message .= ($message ? " ": '')."$key:-".join(';', @delete_vals);
                }
            } else {
                next;
            }
        }
    } else {
        return;
    }
    if (!$message) {
        return;
    }

    $message = "type=modifyrole dn=\"$dn\" result=0 error=\"\" $message";
    my $binddn = defined($self->{bind}{edn}) ? $self->{bind}{edn} : $self->{bind}{dn};
    $message = "user=\"$binddn\" $message";

    my $ip_chain = defined($self->{bind}{ip_chain}) ? $self->{bind}{ip_chain} : '-';
    $message = "ip_chain=\"$ip_chain\" $message";
    if (defined($self->{bind}{ip})) {
        $message = "ip=$self->{bind}{ip} $message";
    } else {
        $message = "ip=- $message";
    }

    if (defined($conf->{logrequestid})) {
        $message = "reqid=".(defined($self->{bind}{reqid}) ? $self->{bind}{reqid} : 0)." $message";
    }

    if (defined($self->{bind}{app}) && $self->{bind}{app}) {
        $message .= " app=\"$self->{bind}{app}\"";
    }

    if (defined($conf->{auditformat})) {
        my $format = $conf->{auditformat};
        eval "\$message =~ s/${$format}[0]/${$format}[1]/is";
    }

    openlog('LISM', 'pid', $conf->{auditfacility});
    syslog('info', $message);
}

=pod

=head2 _slapdCofig()

check slapd configuration.

=cut

sub _slapdConfig
{
    my $self = shift;
    my $conf = $self->{_config};

    if (!defined($conf->{sysloglevel})) {
        $conf->{sysloglevel} = 'info';
    }

    if ($^O ne 'MSWin32') {
        if (!defined($conf->{syslogfacility})) {
            $conf->{syslogfacility} = 'local4';
        }
        if (!defined($conf->{auditfacility})) {
            $conf->{auditfacility} = 'local4';
        }
    } else {
        if (!defined($conf->{logfile})) {
            return 1;
        }

        my $timezone = 'JST';
        my $rotatedate = 'yyyy-MM-dd';
        my $rotatenum = 4;
        if (defined($conf->{logtimezone})) {
            $timezone = $conf->{timezone};
        }
        if (defined($conf->{logrotatedate})) {
            $rotatedate = $conf->{logrotatedate};
        }
        if (defined($conf->{logrotatenum})) {
            $rotatenum = $conf->{logrotatenum};
        }
        $self->{log} = Log::Dispatch::FileRotate->new(name => 'LISM',
                                                     min_level => $conf->{sysloglevel},
                                                     filename => $conf->{logfile},
                                                     mode => 'append',
                                                     TZ => $timezone,
                                                     DatePattern => $rotatedate,
                                                     max => $rotatenum);
        if (defined($conf->{auditfile})) {
            $self->{audit} = Log::Dispatch::FileRotate->new(name => 'LISM',
                                                     min_level => 'info',
                                                     filename => $conf->{auditfile},
                                                     mode => 'append',
                                                     TZ => $timezone,
                                                     DatePattern => $rotatedate,
                                                     max => $rotatenum);
        } else {
            $self->{audit} = $self->{log};
        }
    }

    if (!defined($conf->{basedn})) {
        $self->log(level => 'alert', message => "basedn doesn't exist");
        return 1;
    }
    if (!defined($conf->{syncdir})) {
        $self->log(level => 'alert', message => "syncdir doesn't exist");
        return 1;
    } else {
        my ($dir, @opts) = split(/ +/, $conf->{syncdir});
        my ($user, $group);
        foreach my $opt (@opts) {
            if ($opt =~ /^user=(.+)$/) {
                $user = $1;
            } elsif ($opt =~ /^group=(.+)$/) {
                $group = $1;
            }
        }
        if (@opts) {
            $conf->{syncdir} = $dir;
        }
        if ($user) {
            $conf->{syncdiruid} = (getpwnam($user))[2];
            $conf->{syncdirgid} = $group ? (getgrnam($group))[2] : undef;
        }
        if (!-d $conf->{syncdir}) {
            $self->log(level => 'alert', message => "syncdir doesn't exist");
            return 1;
        }
    }
    if (!defined($conf->{timeout})) {
        $conf->{timeout} = 0;
    }
    if (defined($conf->{customconfig})) {
        foreach my $param (split(/ +/, $conf->{customconfig})) {
            my ($key, $value) = split(/=/, $param);
            $ENV{$key} = $value;
        }
    }
    if (!defined($conf->{conf})) {
        $self->log(level => 'alert', message => "LISM configuration doesn't exist");
        return 1;
    }

    return 0;
}

=pod

=head2 _lismCofig()

check lism configuration.

=cut

sub _lismConfig
{
    my $self = shift;
    my $conf = $self->{_config};

    # parse XML configuration
    $self->{_lism} = XMLin($conf->{conf}, ForceArray => 1);
    my $lismconf = $self->{_lism};

    if (!defined($self->{data})) {$self->{data} = {}}
    foreach my $dname (keys %{$lismconf->{data}}) {
        my $dconf = $lismconf->{data}{$dname};

        # set containers
        if (!defined($dconf->{container}) || !defined($dconf->{container}[0]->{rdn})) {
            $self->log(level => 'alert', message => "$dname data container entry is invalid");
            return 1;
        }
        # normalize dn
        $dconf->{container}[0]->{rdn}[0] =~ tr/A-Z/a-z/;
        $self->{data}{$dname}->{suffix} = $dconf->{container}[0]->{rdn}[0].','.$conf->{basedn};

        # set container entry
        my $entry;
        if (!($entry = LISM::Storage->buildEntryStr($conf->{basedn}, $dconf->{container}[0]))) {
            $self->log(level => 'alert', message => "$dname data container entry is invalid");
            return 1;
        }
        $self->{data}{$dname}->{contentrystr} = $entry;

        $self->{data}{$dname}->{conf} = $dconf;

        # check access rule
        if (defined($dconf->{access})) {
            foreach my $access (@{$dconf->{access}}) {
                if (!defined($access->{dn})) {
                    $self->log(level => 'alert', message => "access rule doesn't have dn");
                    return 1;
                }

                foreach my $right (@{$access->{right}}) {
                    if ($right->{op} !~ /^read|write|add|modify|delete$/) {
                        $self->log(level => 'alert', message => "access operation must read or write");
                        return 1;
                    }

                    if (defined($right->{type}) &&
                        $right->{type}[0] !~ /^(\*|self)$/) {
                        $self->log(level => 'alert', message => "access type is invalid");
                        return 1;
                    }
                }
            }
        }

        # retcode
        if (defined($dconf->{retcode}) && defined($dconf->{retcode}[0]->{result})) {
             $dconf->{retcode}[0]->{result} =~ s/\\n/\n/gmi;
        }

        # dynamic handler
        if (defined($dconf->{dynhandler})) {
            my $dynhandler = $dconf->{dynhandler}[0];
            if (!defined($dynhandler->{match}) || !defined($dynhandler->{dn}) || !defined($dynhandler->{attr})) {
                $self->log(level => 'alert', message => "match, dn or attr doesn't exist in dynhandler");
                return 1;
            }
        }

        if (defined($dconf->{rolelog})) {
            if (!defined($dconf->{rolelog}[0]->{attr})) {
                $self->log(level => 'alert', message => "rolelog doesn't have attr");
                return 1;
            }
        }
    }

    if ((!defined($conf->{disable}) || $conf->{disable} ne 'sync') && defined($lismconf->{sync})) {
        my $sync = $lismconf->{sync}[0];

        # set cluster
        $self->{cluster} = {};

        if (defined($sync->{master})) {
            if (!defined($sync->{master}[0]->{containerdn})) {
                $self->log(level => 'alert', message => "containerdn doesn't exist");
                return 1;
            }

            $self->{master} = {};
            $self->{master}->{primary} = $self->{master}->{current} = $sync->{master}[0]->{data}[0];
            $self->_initMaster($sync->{master}[0]->{data}[0]);

            if (defined($sync->{master}[0]->{backup})) {
                $self->{master}->{backup} = $sync->{master}[0]->{backup};
            } else {
                $self->{master}->{backup} = ();
            }

            if (defined($sync->{master}[0]->{member})) {
                if (!defined($sync->{master}[0]->{member}[0]->{attr})) {
                    $self->log(level => 'alert', message => "member attr must be set");
                    return 1;
                }
                if (defined($sync->{master}[0]->{member}[0]->{groupattr})) {
                    my @attrs = split(/, */, $sync->{master}[0]->{member}[0]->{groupattr});
                    $sync->{master}[0]->{member}[0]->{groupattr_list} = \@attrs;
                }
            }
        }

        foreach my $dname (keys %{$sync->{data}}) {
            if ($dname eq $lism_master) {
                $self->log(level => 'alert', message => "Data name is reserved");
	        return 1;
            }

            if (!defined($lismconf->{data}{$dname})) {
                $self->log(level => 'alert', message => "Data $dname for synchronization doesn't exist");
                return 1;
            }

            my $sdata = $sync->{data}{$dname};

            # synchronization operation
            if (!defined($sdata->{syncop})) {
                $sdata->{syncop} = ['add', 'modify', 'delete'];
            }
            if (!defined($sdata->{masterop})) {
                $sdata->{masterop} = ['add', 'modify', 'delete'];
            }

            my %orders;
            my %clustertype;
            foreach my $oname (keys %{$sdata->{object}}) {
                my $sobject = $sdata->{object}{$oname};

                # ignore dn
                if (!defined($sobject->{dnignore})) {
                    $sobject->{dnignore}[0] = 'off';
                }

                # unique entry
                if (defined($sobject->{unique})) {
                    if (!defined($sobject->{unique}[0]->{base})) {
                        $self->log(level => 'alert', message => "unique must have base");
                        return 1;
                    }
                    if ($sobject->{dnignore}[0] eq 'on') {
                        $self->log(level => 'alert', message => "unique must not be set with dnignore");
                        return 1;
                    }
                }

                # nomalize dn
                if (defined($sobject->{syncdn})) {
                    if ($sobject->{dnignore}[0] eq 'on' && !defined($sobject->{syncfilter})) {
                        $self->log(level => 'alert', message => "syncfilter must be set if dnignore is on");
                        return 1;
                    }

                    for (my $i = 0; $i < @{$sobject->{syncdn}}; $i++) {
                        $sobject->{syncdn}[$i] =~ tr/A-Z/a-z/;
                    }

                    $clustertype{'cluster'} = 1;
                }

                if (defined($sobject->{masterdn})) {
                    if ($sobject->{dnignore}[0] eq 'on' && !defined($sobject->{masterfilter})) {
                        $self->log(level => 'alert', message => "masterfilter must be set if dnignore is on");
                        return 1;
                    }

                    for (my $i = 0; $i < @{$sobject->{masterdn}}; $i++) {
                        $sobject->{masterdn}[$i] =~ tr/A-Z/a-z/;
                    }

                    $clustertype{'master'} = 1;
                }

                if (defined($sobject->{syncflag}) && ref $sobject->{syncflag}[0]) {
                    if (!defined($sobject->{syncflag}[0]->{match}) ||
                        !defined($sobject->{syncflag}[0]->{dn}) ||
                        !defined($sobject->{syncflag}[0]->{filter})) {
                        $self->log(level => 'alert', message => "invalid attributes of syncflag");
                        return 1;
                    }
                    $sobject->{syncflag}[0]->{filter} =~ s/&amp;/&/g;
                    $sobject->{syncflag}[0]->{entryfilter} =~ s/&amp;/&/g;
                }

                if (defined($sobject->{syncfilter})) {
                    $sobject->{syncfilterobj} = Net::LDAP::Filter->new(encode('utf8', $sobject->{syncfilter}[0]));
                }

                if (defined($sobject->{masterfilter})) {
                    $sobject->{masterfilterobj} = Net::LDAP::Filter->new(encode('utf8', $sobject->{masterfilter}[0]));
                }

                if (defined($sobject->{delfilter})) {
                    $sobject->{delfilterobj} = Net::LDAP::Filter->new(encode('utf8', $sobject->{delfilter}[0]));
                }

                # set order
                my $num;
                if (defined($sobject->{order})) {
                    $num = $sobject->{order}[0];
                } else {
                    $num = 100;
                }
                if (defined($orders{$num})) {
                    push(@{$orders{$num}}, $oname);
                } else {
                    $orders{$num} = [$oname];
                }

                # synchronization attributes
                if (defined($sobject->{syncattr})) {
                    foreach my $attr (@{$sobject->{syncattr}}) {
                        if (!defined($attr->{name})) {
                            $self->log(level => 'alert', message => "sync attribute name doesn't exist");
                            return 1;
                        }
                        if (defined($attr->{filter})) {
                            $attr->{filterobj} = Net::LDAP::Filter->new($attr->{filter}[0]);
                        }
                        push(@{$sobject->{syncattrs}}, $attr->{name}[0]);
                    }
                }
                if (defined($sobject->{masterattr})) {
                    foreach my $attr (@{$sobject->{masterattr}}) {
                        if (!defined($attr->{name})) {
                            $self->log(level => 'alert', message => "master attribute name doesn't exist");
                            return 1;
                        }
                        if (defined($attr->{filter})) {
                            $attr->{filterobj} = Net::LDAP::Filter->new($attr->{filter}[0]);
                        }
                        push(@{$sobject->{masterattrs}}, $attr->{name}[0]);
                    }
                }
            }

            # sort object
            $sdata->{order} = [];
            foreach (sort {$a <=> $b} keys %orders) {
                push(@{$sdata->{order}}, @{$orders{$_}});
            }

            # set cluster
            $self->{cluster}{$dname}->{conf} = $sdata;
            $self->{cluster}{$dname}->{status} = 'active';
            $self->{cluster}{$dname}->{info} = join(',', keys %clustertype);
        }

        $self->{cluster}->{$self->{master}->{primary}}->{status} = 'active';
        $self->{cluster}->{$self->{master}->{primary}}->{info} = 'lism-master';
        if ($self->{master}->{backup}) {
            $self->{cluster}->{$self->{master}->{primary}}->{conf} = $self->{cluster}{$self->{master}->{backup}[0]}->{conf};
        } else {
            $self->{cluster}->{$self->{master}->{primary}}->{conf} = undef;
        }
    }

    return 0;
}

sub _initMaster
{
    my $self = shift;
    my ($dname) = @_;
    my $conf = $self->{_lism};
    my $sync = $conf->{sync}[0];

    undef($self->{data}{$lism_master});
    $self->{data}{$lism_master} = {};

    if (!$dname) {
        return 0;
    }

    my $master = $self->{data}{$lism_master};
    my $src_data = $self->{data}{$dname};

    # normalize dn
    my $master_suffix = $sync->{master}[0]->{containerdn}[0].','.$self->{_config}->{basedn};
    ($master->{suffix} = $master_suffix) =~ tr/A-Z/a-z/;
    ($master->{contentrystr} = $src_data->{contentrystr}) =~ s/$src_data->{suffix}$/$master_suffix/mi;
    $master->{conf} = $src_data->{conf};

    $self->_initData($lism_master);

    return 0;
}

sub _startup
{
    my $self = shift;
    my $conf = $self->{_config};

    # check LISM configuration
    if ($self->_lismConfig()) {
        $self->log(level => 'alert', message => "LISM configuration error");
        return 1;
    }

    my @data;
    foreach my $dname (keys %{$self->{data}}) {
        my ($sname) = keys %{$self->{data}{$dname}->{conf}->{storage}};
        if ($sname eq 'CSV') {
            unshift(@data, $dname);
        } else {
            push(@data, $dname);
        }
        if (defined($self->{data}{$dname}->{conf}->{storage}{$sname}->{manageDIT})) {
            $self->{data}{$dname}->{manageDIT} = $self->{data}{$dname}->{conf}->{storage}{$sname}->{manageDIT}[0];
        }
    }
    foreach my $dname (@data) {
        if (defined($conf->{cluster}) && !grep(/^$dname$/i, split(/ +/, $conf->{cluster}))) {
            next;
        }
        if (defined($conf->{cluster_storage})) {
            my ($sname) = keys %{$self->{data}{$dname}->{conf}->{storage}};
            if (!grep(/^$sname$/i, split(/ +/, $conf->{cluster_storage}))) {
                next;
            }
        }
        if ($dname ne $lism_master && $self->_initData($dname)) {
            return 1;
        }
    }

    return 0;
}

sub _destroy
{
    my $self = shift;

    undef($self->{_storage});

    undef($self->{_handler});

    undef($self->{data});

    undef($self->{_lism});

    undef($self->{cluster});

    undef($self->{master});

    return 0;
}

sub _initData
{
    my $self = shift;
    my ($dname) = @_;
    my $conf = $self->{_config};

    my $data = $self->{data}{$dname};
    my $dconf = $data->{conf};
    my $module;

    foreach my $hname (keys %{$dconf->{handler}}) {
        $module = "LISM::Handler::$hname";

        eval "require $module;";
        if ($@) {
            $self->log(level => 'alert', message => "require $module: $@");
            warn $@;
            return 1;
        }

        if (!defined($self->{_handler})) {$self->{_handler} = {}};
        eval "\$self->{_handler}{$dname}{$hname} = new $module(\$self)";
        if ($@) {
            $self->log(level => 'alert', message => "Can't create $module: $@");
            warn $@;
            return 1;
        }

        $dconf->{handler}{$hname}->{sysloglevel} = $conf->{sysloglevel};
        if (defined($conf->{printlog})) {
            $dconf->{handler}{$hname}->{printlog} = $conf->{printlog};
        }
        if (defined($conf->{logfile})) {
            $dconf->{handler}{$hname}->{logfile} = $conf->{logfile};
        }
        if (defined($conf->{logtimezone})) {
            $dconf->{handler}{$hname}->{logtimezone} = $conf->{logtimezone};
        }
        if (defined($conf->{logrotatedate})) {
            $dconf->{handler}{$hname}->{logrotatedate} = $conf->{logrotatedate};
        }
        if (defined($conf->{logrotatenum})) {
            $dconf->{handler}{$hname}->{logrotatenum} = $conf->{logrotatenum};
        }

        $self->{_handler}{$dname}{$hname}->config($dconf->{handler}{$hname});
        $self->{_handler}{$dname}{$hname}->init();
    }

    # load and create the storage object needed
    my ($sname) = keys %{$dconf->{storage}};
    $module = "LISM::Storage::$sname";

    eval "require $module;";
    if ($@) {
        $self->log(level => 'alert', message => "require $module: $@");
        warn $@;
        return 1;
    }

    if (!defined($self->{_storage})) {$self->{_storage} = {}};
    eval "\$self->{_storage}{$dname} = new $module(\'$data->{suffix}\', \'$data->{contentrystr}\', \$self)";
    if ($@) {
        $self->log(level => 'alert', message => "Can't create $module: $@");
        warn $@;
        return 1;
    }

    $dconf->{storage}{$sname}->{sysloglevel} = $conf->{sysloglevel};
    if (defined($conf->{printlog})) {
        $dconf->{storage}{$sname}->{printlog} = $conf->{printlog};
    }
    if (defined($conf->{logfile})) {
        $dconf->{storage}{$sname}->{logfile} = $conf->{logfile};
    }
    if (defined($conf->{logtimezone})) {
        $dconf->{storage}{$sname}->{logtimezone} = $conf->{logtimezone};
    }
    if (defined($conf->{logrotatedate})) {
        $dconf->{storage}{$sname}->{logrotatedate} = $conf->{logrotatedate};
    }
    if (defined($conf->{logrotatenum})) {
        $dconf->{storage}{$sname}->{logrotatenum} = $conf->{logrotatenum};
    }
    if ($sname eq 'Task' && defined($conf->{taskdir})) {
        $dconf->{storage}{$sname}->{directory}[0] = $conf->{taskdir};
    }

    if ($self->{_storage}{$dname}->config($dconf->{storage}{$sname})) {
        $self->log(level => 'alert', message => "Bad configuration of $module");
        return 1;
    }

    if ($self->{_storage}{$dname}->init()) {
        $self->log(level => 'alert', message => "Can't initialize $module");
        return 1;
    }

    $data->{manageDIT} = $self->{_storage}{$dname}->manageDIT();

    if (defined($dconf->{status})  && $dconf->{status}[0] eq 'disable') {
        $self->_removeCluster($dname);
    }

    return 0;
}

=head2 _lock($flag)

get global lock for internal data.

=cut

sub _lock
{
    my $self = shift;
    my ($flag) = @_;
    my $conf = $self->{_config};

    my $file_create = -f "$conf->{syncdir}/$lockFile" ? 0 : 1;

    if (!open($self->{lock}, "> $conf->{syncdir}/$lockFile")) {
        return 1;
    }

    flock($self->{lock}, $flag);

    if ($file_create) {
        chmod(0660, "$conf->{syncdir}/$lockFile");
        if (defined($conf->{syncdiruid})) {
            chown($conf->{syncdiruid}, $conf->{syncdirgid}, "$conf->{syncdir}/$lockFile");
        }
    }

    return 0;
}

=head2 _unlock()

release global lock for internal data.

=cut

sub _unlock
{
    my $self = shift;

    close($self->{lock});

    return 0;
}

sub _accessAllowed
{
    my $self = shift;
    my ($dn, $op, @info) = @_;
    my $rc = 0;

    CHECK: {
        if ($self->{bind}{dn} =~ /^$self->{_config}->{admindn}$/i) {
            $rc = 1;
            last CHECK;
        }

        my $dname = $self->_getDataName($dn);
        if (!$dname) {
            $rc = 1;
            last CHECK;
        }

        my $dconf = $self->{data}{$dname}->{conf};

        # change dn to original data if dn belongs to master data
        $dn = $self->_replMasterDn($dn);

        if (defined($dconf->{access})) {
            foreach my $access (@{$dconf->{access}}) {
                if ($dn !~ /$access->{dn}/i) {
                    next;
                }

                my @matches = ($dn =~ /$access->{dn}/i);

                foreach my $right (@{$access->{right}}) {
                    if ($op =~ /^add|modify|delete$/ && $right->{op} ne 'write' && $op ne $right->{op}) {
                        next;
                    }

                    if (defined($right->{type})) {
                        my $type = $right->{type}[0];
                        if ($type eq '*') {
                            if ($self->_attrAllowed($right, $op, @info)) {
                                $rc = 1;
                                last CHECK;
                            }
                        } elsif ($type eq 'self') {
                            if ($self->{bind}{dn} =~ /^$dn$/i) {
                                if ($self->_attrAllowed($right, $op, @info)) {
                                    $rc = 1;
                                    last CHECK;
                                }
                            }
                        }
                    }

                    if (defined($right->{dn})) {
                        foreach my $allowdn (@{$right->{dn}}) {
                            my $tmpdn = $allowdn;
                            for (my $i = 0; $i < @matches; $i++) {
                                my $num = $i + 1;
                                $tmpdn =~ s/%$num/$matches[$i]/;
                            }
                            if ($self->{bind}{dn} =~ /$tmpdn/i) {
                                if ($self->_attrAllowed($right, $op, @info)) {
                                    $rc = 1;
                                    last CHECK;
                                }
                            }
                        }
                    }

                    if (defined($right->{filter})) {
                        my $filterStr = $right->{filter}[0];
                        for (my $i = 0; $i < @matches; $i++) {
                            my $num = $i + 1;
                            $filterStr =~ s/%$num/$matches[$i]/;
                        }

                        my $filter = Net::LDAP::Filter->new($filterStr);
                        if (!defined($filter)) {
                            next;
                        }

                        if (LISM::Storage->parseFilter($filter, $self->{bind}{entryStr})) {
                            if ($self->_attrAllowed($right, $op, @info)) {
                                $rc = 1;
                                last CHECK;
                            }
                        }
                    }
                }
            }
        } else {
            $rc = 1;
        }
    }

    return $rc;
}

sub _attrAllowed
{
    my $self = shift;
    my ($right, $op, @info) = @_;

    if (defined($right->{attr}) && ($op eq 'add' || $op eq 'modify')) {
        foreach my $attr (keys(%{$right->{attr}})) {
            my $regexp = $right->{attr}{$attr}->{content};
            my @values;
            if ($op eq 'add') {
                @values = ($info[0] =~ /^$attr: (.*)$/gmi);
            } elsif ($op eq 'modify') {
                my $match = 0;
                my $i = 0;
                while ($i < @info) {
                    $i++;
                    my $key    = $info[$i++];
                    if ($key =~ /^$attr$/i) {
                        $match = 1;
                    }
                    while ($i < @info && $info[$i] ne "ADD" && $info[$i] ne "DELETE" && $info[$i] ne "REPLACE") {
                        my $value = $info[$i++];
                        if ($match) {
                            push(@values, $value);
                        }
                    }
                    if ($match) {
                        last;
                    }
                }
            }

            foreach my $value (@values) {
                if ($value !~ /$regexp/i) {
                    return 0;
                }
            }
        }
    }

    return 1;
}

sub _replMasterDn
{
    my $self = shift;
    my ($str, $orgstr) = @_;

    if (!defined($self->{data}{$lism_master}->{suffix})) {
        return $str;
    }

    my $master_suffix = $self->{data}{$lism_master}->{suffix};
    my $current_suffix = $self->{data}{$self->{master}->{current}}->{suffix};

    if ($orgstr) {
        if ($orgstr =~ /$master_suffix$/mi) {
            $str =~ s/$current_suffix/$master_suffix/gmi;
        }
    } else {
        $str =~ s/$master_suffix$/$current_suffix/gmi;
    }

    return $str;
}

sub _do_search
{
    my $self = shift;
    my($base, $scope, $deref, $sizeLim, $timeLim, $filterStr, $attrOnly, @attrs) = @_;
    my $conf = $self->{_lism};
    my $filter;
    my $rc = LDAP_SUCCESS;
    my @srchbases = ();
    my @entries = ();
    my $sync = 0;
    if ($deref == 5) {
        $sync = 1;
        $deref = 0;
    }

    if ($base =~ /^$self->{_config}->{basedn}$/i) {
        if ($scope != 0) {
            # scope isn't base
            foreach my $dname (keys %{$self->{data}}) {
                if (defined($self->{data}{$dname}->{suffix})) {
                    push(@srchbases, $self->{data}{$dname}->{suffix});
                }
            }
        }

        if ($scope == 1) {
            # scope is one
            $scope = 0;
        } else {
            my $rdn = $base;
            $rdn =~ s/^([^=]+)=([^,]+).*/$1: $2/;
            my $entry = "dn: $base\nobjectclass: top\n$rdn\n";
            my $filter = Net::LDAP::Filter->new($filterStr);
            if (!defined($filter)) {
                return (LDAP_FILTER_ERROR, ());
            }

            if (LISM::Storage->parseFilter($filter, $entry)) {
                push(@entries, $entry);
                $sizeLim--;
            }
        }
    } else {
        push(@srchbases, $base);
    }

    if (@srchbases != 0) {
        $rc = LDAP_NO_SUCH_OBJECT;
    }

    if ($self->{_config}->{sysloglevel} eq 'debug') {
        $self->log(level => 'debug', message => "type=search base=$base scope=$scope deref=$deref filter=$filterStr");
    }

    foreach my $srchbase (@srchbases) {
        my $dfilterStr = $filterStr;
        my @subentries;

        my $dname = $self->_getDataName($srchbase);
        if (!$dname) {
            return LDAP_NO_SUCH_OBJECT;
        }

        my $dconf = $self->{data}{$dname}->{conf};
        if (defined($dconf->{retcode}) && defined($dconf->{retcode}[0]->{filter}) && $dfilterStr =~ /$dconf->{retcode}[0]->{filter}/) {
            if (defined($dconf->{retcode}[0]->{result})) {
                return ($dconf->{retcode}[0]->{code}, "dn: $dconf->{retcode}[0]->{result}\n");
            }
        }

        my $storage = $self->_getStorage($dname);
        if (!defined($storage)) {
            next;
        }

        # do pre handler
        $rc = $self->_doHandler('pre', 'search', $dname, \$srchbase, \$dfilterStr);
        if ($rc) {
            last;
        }

        # delete values of dn which isn't in this data directory
        if (!$storage->manageDIT() && defined($self->{data}{$lism_master}->{suffix})) {
            $dfilterStr =~ s/$self->{data}{$lism_master}->{suffix}\)/$self->{data}{$dname}->{suffix})/i;
            my @elts = ($dfilterStr =~ /(\([^(]+,$self->{_config}->{basedn}\))/gi);
            for (my $i = 0; $i < @elts; $i++) {
                if ($elts[$i] !~ /$self->{data}{$dname}->{suffix}\)$/i) {
                    $elts[$i] =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                    $dfilterStr =~ s/$elts[$i]/(objectClass=*)/;
                }
            }
        }

        # call search of the appropriate storage
        ($rc, @subentries) = $storage->search($srchbase, $scope, $deref, $sizeLim, $timeLim, $dfilterStr, $attrOnly, @attrs);
        if ($rc == LDAP_SERVER_DOWN) {
            $self->log(level => 'err', message => "Searching by $dfilterStr at $srchbase in $dname failed($rc)");
            if ($base =~ /^$self->{_config}->{basedn}$/i) {
                $rc = LDAP_SUCCESS;
                next;
            } else {
                last;
            }
        } elsif ($rc && $rc != LDAP_NO_SUCH_OBJECT) {
            $self->log(level => 'err', message => "Searching by $dfilterStr at $srchbase in $dname failed($rc)");
            last;
        }

        if (!$rc) {
            # do post handler
            $self->_doHandler('post', 'search', $dname, \@subentries, \@attrs);
        }

        if ($self->{_config}->{sysloglevel} eq 'debug') {
            for (my $i = 0; $i < @subentries; $i++) {
                my $entry = $subentries[$i];
                $entry =~ s/\n/ /g;
                $self->log(level => 'debug', message => "search result: \"$entry\"");
            }
        }

        push(@entries, @subentries);
        $sizeLim = $sizeLim - @entries;
    }

    if ($rc < 0) {
        $rc = LDAP_OTHER;
    }

    return ($rc, @entries);
}

sub _doUpdate
{
    my $self = shift;
    my ($func, $src_data, $commit, $oldentry, $dn, @info) = @_;
    my $method = "_do_$func";
    my @updated;
    my $rc = LDAP_SUCCESS;
    my $error;

    if ($dn =~ /^[^,]*,$self->{_config}{basedn}$/i) {
        # can't update entry under basedn
        return LDAP_UNWILLING_TO_PERFORM;
    }

    # add timestamp for openldap 2.3(backward compatibility)
    if ($func eq 'add') {
        if ($info[0] !~ /^createtimestamp:/mi) {
            my $ts = strftime("%Y%m%d%H%M%S", localtime(time))."Z";
            $info[0] = $info[0]."createtimestamp: $ts\nmodifytimestamp: $ts\n";
        }
    } elsif ($func eq 'modify') {
        if (!grep(/^modifytimestamp$/, @info)) {
            my $ts = strftime("%Y%m%d%H%M%S", localtime(time))."Z";
            push(@info, 'REPLACE', 'modifytimestamp', $ts);
        }
    }

    my $dname = $self->_getDataName($dn);
    if (!$dname) {
        return LDAP_NO_SUCH_OBJECT;
    }

    my $dconf = $self->{data}{$dname}->{conf};
    if (defined($dconf->{readonly}) && $dconf->{readonly}[0] =~ /^on$/i) {
        return LDAP_UNWILLING_TO_PERFORM;
    }

    if (defined($dconf->{retcode}) && defined($dconf->{retcode}[0]->{dn}) && $dn =~ /$dconf->{retcode}[0]->{dn}/i) {
        return $dconf->{retcode}[0]->{code};
    }

    if (!$self->_checkSync($dname) || $commit) {
        # do pre handler
        $rc = $self->_doHandler('pre', $func, $dname, \$dn, \@info, \$oldentry, \$error);
    }

    if (!$rc) {
        # replicate the udpate operation to the storages
        if ($self->_checkSync($dname) && $commit) {
            ($rc, @updated) = $self->_doSync($func, $src_data, $dn, \@info, \$oldentry);
        } else {
            $self->log(level => 'debug', message => "$func: \"$dn\n".join("\n", @info)."\"");
            ($rc, $error) = $self->$method($dname, $dn, @info);
            if (!$rc) {
                push(@updated, $dname);
            }
        }
    }

    if (!$self->_checkSync($dname) || $commit) {
        # do post handler
        if ($rc) {
            $self->_doHandler('unlock', $func, $dname, \$dn, \@info, \$oldentry);
        } else {
            $rc = $self->_doHandler('post', $func, $dname, \$dn, \@info, \$oldentry, \$error);
            if ($rc == LDAP_USER_CANCELED) {
                push(@updated, $dname);
            }
        }
    }

    if ($commit && @updated) {
        if ($rc) {
            $self->_updateRollback(@updated);
        } else {
            $self->_updateCommit(@updated);
        }
    }

    if ($rc < 0) {
        $rc = LDAP_OTHER;
    }

    if ((!$self->_checkSync($dname) || $commit) && !defined($dconf->{noaudit})) {
        $self->{error} = $error;
        $self->auditlog($func, $dn, $rc, $error, @info);
        if (defined($self->{_config}->{updatelog}) && !$rc && $dname ne 'Task') {
            $self->_writeUpdateLog($func, $dname, $dn, @info);
        }
        if (defined($dconf->{rolelog}) && !$rc) {
            $self->rolelog($dconf->{rolelog}[0]->{attr}, $func, $oldentry, $dn, @info);
        }
    }

    return $rc;
}

sub _do_modify
{
    my $self = shift;
    my ($dname, $dn, @list) = @_;
    my $conf = $self->{_lism};
    my $rc = LDAP_SUCCESS;
    my $error;

    if (!defined($self->{data}{$dname})) {
        return LDAP_NO_SUCH_OBJECT;
    }

    my $dconf = $self->{data}{$dname}->{conf};

    # call modify of the appropriate storage
    my $storage = $self->_getStorage($dname);
    if (defined($storage)) {
        my @mod_list;
        my $parentdn;

        while ( @list > 0) {
            my $action = shift @list;
            my $key    = lc(shift @list);
            my @values;

            while (@list > 0 && $list[0] ne "ADD" && $list[0] ne "DELETE" && $list[0] ne "REPLACE") {
                my $value = shift @list;
                if ($storage->manageDIT() ||
                    $value !~ /$self->{_config}->{basedn}$/i ||
                        $value =~ /$self->{data}{$dname}->{suffix}/i) {
                    push(@values, $value);
                }
            }

            if ($key =~ /^lismparentdn$/i) {
                if ($action eq "REPLACE" && @values && $values[0]) {
                    my $tmpval = $values[0];
                    $tmpval =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                    if ($dn !~ /^[^,]+,$tmpval$/i) {
                        $parentdn = $values[0];
                    }
                    next;
                } else {
                    return LDAP_UNWILLING_TO_PERFORM;
                }
            }

            if ($key =~ /^(?:userpassword|unicodepwd)$/i && @values && $values[0]) {
                # hash the password in the modification data
                my $hashpw = $storage->hashPasswd($values[0]);
                if (!defined($hashpw)) {
                    next;
                }

                $values[0] = $hashpw;
            }

            push(@mod_list, ($action, $key, @values));
        }

        if ($parentdn) {
            ($rc, $error) = $storage->move($dn, $parentdn);
            if (!$rc) {
                $dn =~ s/^([^,]+),.+$/$1,$parentdn/;
            }
        }
        if (!$rc && @mod_list) {
            ($rc, $error) = $storage->modify($dn, @mod_list);
        }
    } else {
        $rc = LDAP_UNAVAILABLE;
    }

    return ($rc, $error);
}

sub _do_add
{
    my $self = shift;
    my ($dname, $dn, $entryStr) = @_;
    my $conf = $self->{_lism};
    my $rc = LDAP_SUCCESS;
    my $error;

    if (!defined($self->{data}{$dname})) {
        return LDAP_NO_SUCH_OBJECT;
    }

    my $dconf = $self->{data}{$dname}->{conf};

    # call add of the appropriate storage
    my $storage = $self->_getStorage($dname);
    if (defined($storage)) {
        # hash the password in the entry
        if ($entryStr =~ /^(userpassword|unicodepwd):\s+([^\s]+)$/mi) {
            my $attr = $1;
            my $plainpw = $2;
            my $hashpw = $storage->hashPasswd($plainpw);
            if (defined($hashpw)) {
                $entryStr =~ s/^$attr:.*$/$attr: $hashpw/mi;
            } else {
                $entryStr =~ s/\n$attr:.*\n/\n/i;
            }
        }

        if (!$storage->manageDIT()) {
            my @dn_vals = ($entryStr =~ /^(.+$self->{_config}->{basedn})$/gmi);
            if (@dn_vals) {
                foreach my $value (@dn_vals) {
                    if ($value !~ /$self->{data}{$dname}->{suffix}$/i) {
                        $entryStr =~ s/\n$value\n/\n/i;
                    }
                }
            }
        }

        ($rc, $error) = $storage->add($dn, $entryStr);
    } else {
        $rc = LDAP_UNAVAILABLE;
    }

    return ($rc, $error);
}

sub _do_modrdn
{
    my $self = shift;
    my ($dname, $dn, $newrdn, $delFlag) = @_;
    my $conf = $self->{_lism};
    my $rc = LDAP_SUCCESS;
    my $error;

    if (!defined($self->{data}{$dname})) {
        return LDAP_NO_SUCH_OBJECT;
    }

    my $dconf = $self->{data}{$dname}->{conf};

    my $storage = $self->_getStorage($dname);
    if (defined($storage)) {
        ($rc, $error) = $storage->modrdn($dn, $newrdn, $delFlag);
    }

    return ($rc, $error);
}

sub _do_delete
{
    my $self = shift;
    my ($dname, $dn, @info) = @_;
    my $conf = $self->{_lism};
    my $rc = LDAP_SUCCESS;
    my $error;

    if (!defined($self->{data}{$dname})) {
        return LDAP_NO_SUCH_OBJECT;
    }

    my $dconf = $self->{data}{$dname}->{conf};

    # call delete of the appropriate storage
    my $storage = $self->_getStorage($dname);
    if (defined($storage)) {
        ($rc, $error) = $storage->delete($dn, @info);
    } else {
        $rc = LDAP_UNAVAILABLE;
    }

    return ($rc, $error);
}

sub _doHandler
{
    my $self = shift;
    my ($type, $func, $dname, @args) = @_;
    my $dconf = $self->{data}{$dname}->{conf};
    my $hselect;
    if ($type =~ /^([^_]+)_(.+)$/) {
        $type = $1;
        $hselect = $2;
    }
    my $method = $type.'_'.$func;
    my $timeout = $self->{_config}->{timeout};
    my $dn;
    my $rc = LDAP_SUCCESS;
    my (@orders) = ('first', 'middle', 'last');
    my $update = ($func =~ /^(add|modify|delete)$/);

    if ((defined($self->{operation}) && $self->{operation} eq 'sync') || $update) {
        push(@orders, 'sync');
    }

    if (!defined($self->{_handler}{$dname}) && !defined($dconf->{dynhandler})) {
        return 0;
    }

    if ($func ne 'search') {
        # change dn to orignal data if dn belongs to master data
        $dn = ${$args[0]};
        ${$args[0]} = $self->_replMasterDn(${$args[0]});
        if ($func eq 'add') {
            ${$args[1]}[0] = $self->_replMasterDn(${$args[1]}[0]);
        } elsif ($func eq 'modify') {
            for (my $i = 0; $i < @{$args[1]}; $i++) {
                if (${$args[1]}[$i] =~ /,[^,=]+=[^,]+,/) {
                    ${$args[1]}[$i] = $self->_replMasterDn(${$args[1]}[$i]);
                }
            }
        }
    }
  DO: {
    if (defined($self->{_handler}{$dname}) && defined($self->{_handler}{$dname}{Rewrite}) && $type eq 'pre' && $func ne 'search' && !$hselect) {
        my $hname = 'Rewrite';
        if ($func =~ /^(modify|delete)$/ &&
            $self->{_handler}{$dname}{$hname}->useprevious() && !defined(${$args[2]})) {
            ($rc, ${$args[2]}) = $self->_do_search(${$args[0]}, 0, 0, 1, $timeout, '(objectClass=*)', 0);
            if ($rc && $rc != LDAP_NO_SUCH_OBJECT) {
                $self->log(level => 'err', message => "Saving ${$args[0]} for handler failed($rc)");
                last DO;
            }
        }

        $rc = $self->{_handler}{$dname}{$hname}->$method(@args, 'prepare');
        if ($rc) {
            last DO;
        }
    }

    my $dynhandler;
    if (defined($dconf->{dynhandler})) {
        $dynhandler = $dconf->{dynhandler}[0];
    }

    if ($dynhandler && $type ne 'unlock' && $func ne 'search' && $dn =~ /$dynhandler->{match}/i && !$hselect) {
        my %dynhandler;
        my $handlerdn = $dynhandler->{dn};
        my $handlerfilter = $dynhandler->{filter};

        my @matches = ($dn =~ /$dynhandler->{match}/i);
        for (my $i = 0; $i < @matches; $i++) {
            my $num = $i + 1;
            $handlerdn =~ s/\%$num/$matches[$i]/g;
            $handlerfilter =~ s/\%$num/$matches[$i]/g;
        }

        my ($rc, $handlerEntry) = $self->_do_search($handlerdn, 2, 0, 0, $self->{_config}->{timeout}, $handlerfilter, 0);
        if (!$rc || $rc == LDAP_NO_SUCH_OBJECT) {
            if ($handlerEntry) {
                my ($xml) = ($handlerEntry =~ /^seciossConfigSerializedData: (.+)$/mi);
                $xml = decode_base64($xml);
                my $dynconf = XMLin($xml, ForceArray => 1);
                foreach my $hname (keys %{$dynconf->{data}{$dname}->{handler}}) {
                    if (!defined($dynhandler{$dname})) {
                        $dynhandler{$dname} = {};
                    }
                    my $module = "LISM::Handler::$hname";
                    if (!defined($self->{_handler}{$dname}{$hname})) {
                        eval "require $module;";
                        if ($@) {
                            $self->log(level => 'err', message => "require $module: $@");
                            $rc = LDAP_OTHER;
                            last DO;
                        }
                    }
                    eval "\$dynhandler{$dname}{$hname} = new $module(\$self)";
                    if ($@) {
                        $self->log(level => 'err', message => "Can't create $module: $@");
                        $rc = LDAP_OTHER;
                        last DO;
                    }

                    $dynhandler{$dname}{$hname}->{sysloglevel} = $self->{_config}->{sysloglevel};
                    $dynhandler{$dname}{$hname}->config($dynconf->{data}{$dname}->{handler}{$hname});
                    $dynhandler{$dname}{$hname}->init();
                }
            }
        } else {
            $self->log(level => 'err', message => "Getting dnyamic handler($handlerdn $handlerfilter) failed($rc)");
            last DO;
        }

        if (%dynhandler) {
            foreach my $order (@orders) {
                foreach my $hname (keys %{$dynhandler{$dname}}) {
                    if ($dynhandler{$dname}{$hname}->getOrder() ne $order) {
                         next;
                    }

                    if ($func =~ /^(modify|delete)$/ &&
                        $dynhandler{$dname}{$hname}->useprevious() && !defined(${$args[2]})) {
                        ($rc, ${$args[2]}) = $self->_do_search(${$args[0]}, 0, 0, 1, $timeout, '(objectClass=*)', 0);
                        if ($rc && $rc != LDAP_NO_SUCH_OBJECT) {
                            $self->log(level => 'err', message => "Saving ${$args[0]} for handler failed($rc)");
                            last;
                        }
                    }

                    $rc = $dynhandler{$dname}{$hname}->$method(@args);
                    if ($rc) {
                        last;
                    }
                }
                if ($rc) {
                    last DO;
                }
            }
        }
    }

    if (!defined($self->{_handler}{$dname})) {
        return 0;
    }

    foreach my $order (@orders) {
        foreach my $hname (keys %{$self->{_handler}{$dname}}) {
            if ($hselect && $hselect ne $hname) {
                next;
            }
            if ($self->{_handler}{$dname}{$hname}->getOrder() ne $order) {
                next;
            }

            if ($type eq 'pre' && $func =~ /^(modify|delete)$/ &&
                $self->{_handler}{$dname}{$hname}->useprevious() && !defined(${$args[2]})) {
                ($rc, ${$args[2]}) = $self->_do_search(${$args[0]}, 0, 0, 1, $timeout, '(objectClass=*)', 0);
                if ($rc && $rc != LDAP_NO_SUCH_OBJECT) {
                    $self->log(level => 'err', message => "Saving ${$args[0]} for handler failed($rc)");
                    last;
                }
            }

            if ($type eq 'pre' && $update) {
                if ($self->{_handler}{$dname}{$hname}->lock($func)) {
                    $rc = LDAP_OTHER;
                    last;
                }
            }

            if ($type ne 'unlock') {
                $rc = $self->{_handler}{$dname}{$hname}->$method(@args);
            } elsif ($hname eq 'Rewrite') {
                my $post_method = 'post_'.$func;
                $rc = $self->{_handler}{$dname}{$hname}->$post_method(@args);
            }
            if (($type eq 'post' || $type eq 'unlock') && $func =~ /^(add|modify|delete)$/) {
                $self->{_handler}{$dname}{$hname}->unlock();
            }

            if ($rc) {
                last;
            }
        }
        if ($rc) {
            last;
        }
    }
  }
    if ($func ne 'search') {
        ${$args[0]} = $self->_replMasterDn(${$args[0]}, $dn);
        if ($func eq 'add') {
            ${$args[1]}[0] = $self->_replMasterDn(${$args[1]}[0], $dn);
        } elsif ($func eq 'modify') {
            for (my $i = 0; $i < @{$args[1]}; $i++) {
                if (${$args[1]}[$i] =~ /,[^,=]+=[^,]+,/) {
                    ${$args[1]}[$i] = $self->_replMasterDn(${$args[1]}[$i], $dn);
                }
            }
        }
    }

    return $rc;
}

sub _setConfig
{
    my $self = shift;
    my ($dn, @list) = @_;

    my $modinfo = join(',', @list);
    if ($modinfo !~ /REPLACE,$confOpAttr,reload/i) {
        return LDAP_UNWILLING_TO_PERFORM;
    }

    $self->_lock(2);

    $self->_destroy();

    if ($self->_startup()) {
        $self->log(level => 'alert', message => "Reload configuration failed");
        exit 1;
    }

    $self->_unlock();

    return 0;
}

sub _addCluster
{
    my $self = shift;
    my ($dname, $nosync) = @_;
    my $cluster = $self->{cluster};
    my $rc;

    if (!defined($cluster->{$dname})) {
        return 0;
    }

    $self->_lock(2);

    if ($cluster->{$dname}->{status} eq 'inactive') {
        $cluster->{$dname}->{status} = 'busy';
        $self->_unlock();

        if (!$nosync) {
            $rc = $self->_setSyncInfo("$cluster_syncrdn,".$self->{_config}->{basedn}, ('DELETE', $syncDataAttr, $dname));
        }

        $self->_lock(2);
        if ($rc) {
            $self->log(level => 'err', message => "Adding \"$dname\" to cluster failed($rc)");
            $cluster->{$dname}->{status} = 'inactive';
        } else {
            if (defined($self->{master})) {
                if ($dname eq $self->{master}->{primary}) {
                    $self->_failback();
                }
            }
            $cluster->{$dname}->{status} = 'active';
        }
    }

    $self->_unlock();

    $self->log(level => 'info', message => "Add cluster \"$dname\"");

    return $rc;
}

sub _removeCluster
{
    my $self = shift;
    my ($dname) = @_;
    my $cluster = $self->{cluster};
    my $master = $self->{master};

    if (!defined($cluster->{$dname})) {
        return 0;
    }

    $self->_lock(2);

    if ($cluster->{$dname}->{status} eq 'active') {
        $cluster->{$dname}->{status} = 'inactive';

        if (defined($self->{master})) {
            if ($dname eq $master->{current}) {
                $self->_failover();
            }
        }
    }

    $self->log(level => 'err', message => "Remove cluster \"$dname\"");

    $self->_unlock();

    return 0;
}

sub _failover
{
    my $self = shift;
    my $cluster = $self->{cluster};
    my $master = $self->{master};

    $master->{current} = '';

    foreach my $backup (@{$master->{backup}}) {
        if ($cluster->{$backup}->{status} eq 'active') {
            $master->{current} = $backup;
            last;
        }
    }

    $self->_initMaster($master->{current});

    return 0;
}

sub _failback
{
    my $self = shift;
    my $cluster = $self->{cluster};
    my $master = $self->{master};

    $master->{current} = $master->{primary};

    $self->_initMaster($master->{current});

    return 0;
}

sub _getClusterInfo
{
    my $self = shift;
    my ($base, $scope, $filterStr, $attrOnly, @attrs) = @_;
    my $cluster = $self->{cluster};

    # don't return entry when the scope isn't base
    if ($scope != 0) {
        return (0, ());
    }

    my $clusterentry = "dn: $base\n$clusterEntry";
    if ($self->{master}->{current}) {
        $clusterentry = "$clusterentry$masterAttr: $self->{master}->{current}\n";
    }

    foreach my $dname (keys %{$cluster}) {
        $clusterentry = "$clusterentry$clusterAttr: $dname\n";
    }
    foreach my $dname (keys %{$cluster}) {
        if ($dname ne $lism_master && $cluster->{$dname}->{status} eq 'active') {
            $clusterentry = "$clusterentry$activeAttr: $dname#$cluster->{$dname}->{info}\n";
        }
    }

    return (LDAP_SUCCESS, ($clusterentry));
}

sub _setClusterInfo
{
    my $self = shift;
    my ($dn, @list) = @_;
    my $cluster = $self->{cluster};
    my $rc = LDAP_SUCCESS;

    my $modinfo = join(',', @list);

    # get synchronized data
    my ($add_dnames) = ($modinfo =~ /ADD,$activeAttr,(.*),?(ADD|DELETE|REPLACE|)/i);
    my ($delete_dnames) = ($modinfo =~ /DELETE,$activeAttr,(.*),?(ADD|DELETE|REPLACE|)/i);

    if ($delete_dnames) {
        foreach my $dname (keys %{$cluster}) {
            if (",$delete_dnames," =~ /$dname,/i) {
                $self->_removeCluster($dname);
            }
        }
    }

    if ($add_dnames) {
        foreach my $dname (keys %{$cluster}) {
            if ($dname eq $lism_master) {
                next;
            }

            if (",$add_dnames," =~ /$dname,/i) {
                my $nosync = 0;
                if ($modinfo =~ /,$optionAttr,nosync(,|)/i) {
                    $nosync = 1;
                }
                $self->_addCluster($dname, $nosync);
            }
        }
    }

    return $rc; 
}

sub _checkSync
{
    my $self = shift;
    my ($dname) = @_;
    my $conf = $self->{_lism};

    if ($dname eq $lism_master) {
        return 1;
    }

    return 0;
}

sub _doSync
{
    my $self = shift;
    my ($func, $src_data, $dn, $infop, $oldentryp) = @_;
    my @info = @{$infop};
    my $conf = $self->{_lism};
    my $master = $self->{data}{$lism_master};
    my $cluster = $self->{cluster};
    my $timeout = $self->{_config}->{timeout};
    my @updated = ();
    my $rc = LDAP_SUCCESS;

    if (!defined($master->{suffix})) {
        return LDAP_NO_SUCH_OBJECT;
    }

    my $entryStr;
    my $newEntryStr;
    my %group_entries;
    if ($func eq 'add') {
        $entryStr = $info[0];
    } else {
        if ($oldentryp && ${$oldentryp}) {
            $entryStr = ${$oldentryp};
            my $current_suffix = $self->{data}{$self->{master}->{current}}->{suffix};
            $entryStr =~ s/$current_suffix$/$master->{suffix}/gmi;
        } else {
            # check entry existence
            my @entries;
            ($rc, @entries) = $self->_do_search($dn, 0, 0, 0, $timeout, '(objectClass=*)');
            if ($rc) {
                $self->log(level => 'err', message => "Getting synchronized entry($dn) failed: error code($rc)");
                return($rc, @updated);
            } elsif (!@entries) {
                return LDAP_NO_SUCH_OBJECT;
            }
            ($entryStr = $entries[0]) =~ s/^dn:.*\n//;
        }
    }
    if ($func eq 'modify') {
        if (defined($conf->{sync}[0]->{master}[0]->{member})) {
            my $match;
            if (defined($conf->{sync}[0]->{master}[0]->{member}[0]->{match})) {
                $match = $conf->{sync}[0]->{master}[0]->{member}[0]->{match};
            }
            if (!$match || $dn =~ /$match/i) {
                my ($rc, @entries) = $self->_do_search($dn, 0, 0, 0, $timeout, '(objectClass=*)', 0, 'memberOf');
                if ($rc) {
                    $self->log(level => 'err', message => "Searching $dn failed($rc)");
                } else {
                    my @memberof = ($entries[0] =~ /^memberOf: (.+)/gmi);
                    if (@memberof) {
                        my @attrs;
                        if (defined($conf->{sync}[0]->{master}[0]->{member}[0]->{groupattr})) {
                            @attrs = @{$conf->{sync}[0]->{master}[0]->{member}[0]->{groupattr_list}};
                        }
                        foreach my $group_dn (@memberof) {
                            my $group_entry;
                            ($rc, $group_entry) = $self->_do_search($group_dn, 0, 0, 0, $timeout, '(objectClass=*)', 0, @attrs);
                            if ($rc) {
                                $self->log(level => 'err', message => "Getting synchronized entry($group_dn) failed: error code($rc)");
                                next;
                            }
                            $group_entry =~ s/^dn:.*\n//;
                            $group_entries{$group_dn} = $group_entry;
                        }
                    }
                }
            }
        }
    }

    # update the master storage
    if ($func ne 'delete' || $conf->{sync}[0]->{delorder}[0] eq 'first') {
        $rc = $self->_doUpdate($func, undef, 0, undef, $dn, @info);
        if ($rc) {
            if ($rc == LDAP_USER_CANCELED) {
                push(@updated, $lism_master);
            }
            $self->log(level => 'err', message => "Updating master entry($dn) failed: error code($rc)");
            return($rc, @updated);
        }
        push(@updated, $lism_master);
    }

    foreach my $dname (keys %{$cluster}) {
        if ($dname eq $self->{master}->{current}) {
            next;
        }
        if ($src_data && $dname eq $src_data) {
            next;
        }

        my $sync_member = 0;
        my $dfunc = $func;
        my ($ddn, @dinfo) = $self->_checkSyncData($dname, 'realtime', $entryStr, $dfunc, $dn, @info);
        if ($dname ne 'Task' && $dfunc eq 'modify') {
            if (!$newEntryStr) {
                $newEntryStr = $entryStr;
                my @list = @info;
                while (@list > 0) {
                    my $action = shift @list;
                    my $attr = shift @list;
                    my @values;
                    while (@list > 0 && $list[0] !~ /^(ADD|DELETE|REPLACE)$/) {
                        push(@values, shift @list);
                    }
                    if ($action eq 'ADD') {
                        foreach my $value (@values) {
                            if ($value !~ /^ *$/) {
                                $newEntryStr .= "$attr: $value\n";
                            }
                        }
                    } elsif ($action eq 'DELETE') {
                        if (@values && $values[0]) {
                            foreach my $value (@values) {
                                $newEntryStr =~ s/^$attr: $value\n//gmi;
                            }
                        } else {
                            $newEntryStr =~ s/^$attr: .*\n//gmi;
                        }
                    } elsif ($action eq 'REPLACE') {
                        $newEntryStr =~ s/^$attr: .*\n//gmi;
                        foreach my $value (@values) {
                            if ($value !~ /^ *$/) {
                                $newEntryStr .= "$attr: $value\n";
                            }
                        }
                    }
                }
            }
            if ($newEntryStr) {
                my ($newdn, @newinfo) = $self->_checkSyncData($dname, 'realtime', $newEntryStr, $dfunc, $dn, @info);
                if ($newdn && !$ddn) {
                    $dfunc = 'add';
                    ($ddn, @dinfo) = $self->_checkSyncData($dname, 'realtime', $newEntryStr, $dfunc, $dn, $newEntryStr);
                    $sync_member = 1;
                } elsif (!$newdn && $ddn) {
                    $dfunc = 'delete';
                    @dinfo = ();
                    ($ddn, @dinfo) = $self->_checkSyncData($dname, 'realtime', $entryStr, $dfunc, $dn);
                }
            }
        }
        if (!$ddn) {
            next;
        }
        if ($dname eq 'Task') {
            if ($dfunc eq 'modify') {
                unshift(@dinfo, 'REPLACE', 'lismPreviousEntry', $entryStr);
            } elsif ($dfunc eq 'delete' &&  $conf->{sync}[0]->{delorder}[0] eq 'first') {
                push(@dinfo, $entryStr);
            }
        }

        # replicate to the storage
        $rc = $self->_doUpdate($dfunc, undef, 0, undef, $ddn, @dinfo);
        if ($rc == LDAP_NO_SUCH_OBJECT) {
            if ($dfunc eq 'delete') {
                next; 
            } elsif ($dfunc eq 'modify') {
                $entryStr =~ s/userPassword: [^\n]+\n//i;
                my ($adddn, @addinfo) = $self->_checkSyncData($dname, 'differential', $entryStr, 'add', $dn, $entryStr);
                $rc = $self->_doUpdate('add', undef, 0, undef, $adddn, @addinfo);
                if (!$rc) {
                    $rc = $self->_doUpdate($dfunc, undef, 0, undef, $ddn, @dinfo);
                }
            }
        } elsif ($rc == LDAP_ALREADY_EXISTS) {
            my @attrs = $self->_unique($dinfo[0] =~ /^([^:]+):/gmi);
            my @modinfo;
            foreach my $attr (@attrs) {
                my @values = $dinfo[0] =~ /^$attr: (.*)$/gmi;
                push(@modinfo, "REPLACE", $attr, @values);
            }
            $rc = $self->_doUpdate('modify', undef, 0, undef, $ddn, @modinfo);
        }

        if ($rc) {
            $self->log(level => 'err', message => "Synchronizing $ddn in $dname failed: error code($rc)");

            if ($conf->{sync}[0]->{transaction}[0] =~ /^on$/i) {
                last;
            }

            $self->_writeSyncFail($dfunc, $dname, $ddn, @dinfo);
        } else {
            push(@updated, $dname);
        }

        if ($sync_member && %group_entries) {
            my $member_attr = $conf->{sync}[0]->{master}[0]->{member}[0]->{attr};
            foreach my $group_dn (keys(%group_entries)) {
                my $group_entry = $group_entries{$group_dn};
                my ($group_ddn, @group_info) = $self->_checkSyncData($dname, 'realtime', $group_entry, 'modify', $group_dn, 'ADD', $member_attr, $dn);
                if (!$group_ddn || !@group_info) {
                    next;
                }

                my $rc2 = $self->_doUpdate('modify', undef, 0, undef, $group_ddn, 'ADD', $group_info[1], $group_info[2]);
                if ($rc2) {
                    $self->log(level => 'err', message => "Synchronizing member($group_info[2]) of $group_ddn in $dname failed: error code($rc2)");
                }
            }
        }
    }

    # Delete master entry last for ldap rewrite map
    if ($func eq 'delete' && $conf->{sync}[0]->{delorder}[0] ne 'first') {
        $rc = $self->_doUpdate($func, undef, 0, undef, $dn, @info);
        if ($rc) {
            $self->log(level => 'err', message => "Updating master entry($dn) failed: error code($rc)");
            return($rc, @updated);
        }
        push(@updated, $lism_master);
    }

    if ($conf->{sync}[0]->{transaction}[0] !~ /^on$/i) {
        $rc = LDAP_SUCCESS;
    }

    return ($rc, @updated);
}

sub _updateCommit
{
    my $self = shift;
    my (@updated) = @_;

    for (my $i = 0; $i < @updated; $i++) {
        $self->{_storage}{$updated[$i]}->commit();
    }
}

sub _updateRollback
{
    my $self = shift;
    my (@updated) = @_;

    for (my $i = 0; $i < @updated; $i++) {
        $self->{_storage}{$updated[$i]}->rollback();
    }
}

sub _getSyncInfo
{
    my $self = shift;
    my ($base, $scope, $filterStr, $attrOnly, @attrs) = @_;
    my $conf = $self->{_lism};
    my $master = $self->{data}{$lism_master};
    my $cluster = $self->{cluster};
    my $timeout = $self->{_config}->{timeout};
    my $present_list;
    my @check_data = ();
    my $syncStatus = '';
    my %nosync_data;
    my %nosync_entries;
    my %deletedn;
    my %syncflag_cache;
    my %opFlag;
    $nosync_entries{'sync'} = {};
    $nosync_entries{'master'} = {};

    # don't return entry when the scope isn't base
    if ($scope != 0 || !defined($master->{suffix})) {
        return (0, ());
    }

    $self->log(level => 'info', message => "Differential check starting");

    # get checked data
    my (@check_dnames) = ($filterStr =~ /\($syncDataAttr=([^)]*)\)/gi);
    if (@check_dnames) {
        foreach my $dname (keys %{$cluster}) {
            if (grep(/^$dname$/i, @check_dnames)) {
                push(@check_data, $dname);
            }
        }
    } else {
        @check_data = keys %{$cluster};
    }

    # get check filter
    my ($checkfilter) = ($filterStr =~ /\($syncFilterAttr=([^)]*)\)/i);
    if ($checkfilter) {
        $checkfilter =~ s/\\28/(/g;
        $checkfilter =~ s/\\29/)/g;
        $checkfilter =~ s/\\5C/\\/gi;
        if ($checkfilter !~ /^\(.+\)$/) {
            $checkfilter = "($checkfilter)";
        }
    } else {
        $checkfilter = "(objectClass=*)";
    }

    # get check base dn
    my ($checkbase) = ($filterStr =~ /\($syncBaseAttr=([^)]*)\)/i);
    if ($checkbase && $checkbase !~ /$master->{suffix}$/i) {
        return LDAP_UNWILLING_TO_PERFORM;
    }
    if (!Encode::is_utf8($checkbase)) {
        $checkbase = decode('utf8', $checkbase);
    }

    # check size limit
    my ($sync_size) = ($filterStr =~ /\($syncSizeAttr=([^)]*)\)/i);
    if (!$sync_size || $sync_size !~ /^[0-9]+$/) {
        $sync_size = $sizeLimit;
    }

    # check operation
    my ($sync_ops) = ($filterStr =~ /\($optionAttr=([^)]*)\)/i);
    foreach my $op ('add', 'modify', 'delete') {
        if (",$sync_ops," =~ /,$op,/i) {
            $opFlag{$op} = 1;
        }
    }

    my $syncentry;
    ($syncentry = $base) =~ s/^([^=]+)=([^,]+),.*/$1: $2/;
    $syncentry = "dn: $base\n$syncInfoEntry$syncentry\n";

    # get present entry list
    $present_list = $self->_getPresentList($checkfilter, $checkbase, @check_data);
    if (!defined($present_list)) {
        return LDAP_OTHER;
    }

    if ($base !~ /^$master_syncrdn/) {
        # check sync data
        foreach my $dname (@check_data) {
            if ($dname eq $self->{master}->{current} || $dname eq 'Task') {
                next;
            }

            # check cluster status
            if ($cluster->{$dname}->{status} eq 'inactive') {
                next;
            }

            my $data = $self->{data}{$dname};
            my $sdata = $cluster->{$dname}->{conf};
            my $dcheckfilter = $checkfilter;
            my $dcheckbase = $checkbase;

            $dcheckfilter =~ s/$master->{suffix}/$data->{suffix}/i;
            $dcheckbase =~ s/$master->{suffix}$/$data->{suffix}/i;

            foreach my $oname (@{$sdata->{order}}) {
                my $sobject = $sdata->{object}{$oname};
                my %ops;
                $ops{add} = 0;
                $ops{modify} = 0;
                $ops{delete} = 0;

                if (!defined($sobject->{syncdn})) {
                    next;
                }

                if (defined($sobject->{synctype}) && $sobject->{synctype}[0] !~ /^(differential|task)$/) {
                    next;
                }

                if (defined($sobject->{syncop})) {
                    foreach my $op (@{$sobject->{syncop}}) {
                        if (!%opFlag || defined($opFlag{$op})) {
                            $ops{$op} = 1;
                        }
                    }
                } else {
                    foreach my $op (@{$sdata->{syncop}}) {
                        if (!%opFlag || defined($opFlag{$op})) {
                            $ops{$op} = 1;
                        }
                    }
                }

                foreach my $syncdn (@{$sobject->{syncdn}}) {
                    my $dbase;
                    my $dregexbase;
                    my $sbase;

                    if ($syncdn eq 'ou=disable') {
                        next;
                    } elsif ($syncdn eq '*') {
                        $dbase = $data->{suffix};
                        $dregexbase = $dbase;
                        $sbase = $master->{suffix};
                    } elsif ($syncdn =~ /[*+]/) {
                        $dbase = $data->{suffix};
                        $dregexbase = $syncdn.','.$data->{suffix};
                        $sbase = $master->{suffix};
                    } else {
                        $dbase = $syncdn.','.$data->{suffix};
                        $dregexbase = $dbase;
                        $sbase = $syncdn.','.$master->{suffix};
                    }

                    if (!defined($present_list->{$sbase})) {
                        next;
                    }

                    if ($dcheckbase && $dcheckbase !~ /$dregexbase$/i) {
                        next;
                    }

                    # synchronization filter
                    my $syncfilter = undef;
                    my $ocheckfilter = $dcheckfilter;
                    if (defined($sobject->{syncfilterobj})) {
                        $syncfilter = $sobject->{syncfilterobj};
                        $ocheckfilter = "(&$ocheckfilter$sobject->{syncfilter}[0])";
                    }

                    # synchronized attributes
                    my @sync_attrs;
                    if (defined($sobject->{syncattrs}) && !defined($sobject->{idmap})) {
                        @sync_attrs = @{$sobject->{syncattrs}};
                    }

                    # get values from data storage
                    my ($rc, @entries) = $self->_do_search($dcheckbase ? $dcheckbase : $dbase, 2, 0, $sizeLimit, $timeout, $ocheckfilter, 0, @sync_attrs, (@sync_attrs ? 'objectClass' : ()));
                    if ($rc && $rc != LDAP_NO_SUCH_OBJECT) {
                        $self->log(level => 'err', message => "Can't get values of $dname($rc)");
                        return ($rc, ());
                    }
                    my $entrynum = @entries;

                    # comare data storage's values with master one
                    for (my $i = 0; $i < @entries; $i++) {
                        my $syncflag = 1;
                        my ($dn) = ($entries[$i] =~ /^dn: (.*)\n/);
                        $dn =~ tr/A-Z/a-z/;
                        my ($key) = ($dn =~ /^(.*?)(?<!\\),/);
                        my $subdn;

                        if (defined($sobject->{idmap})) {
                            my ($idval) = ($entries[$i] =~ /^$sobject->{idmap}[0]->{foreign}: (.+)$/mi);
                            $key = "$sobject->{idmap}[0]->{local}=".lc($idval);
                            if (defined($present_list->{$sbase}{list}{$key})) {
                                ($subdn) = keys %{$present_list->{$sbase}{list}{$key}};
                            }
                        } else {
                            if ($dcheckbase && $sobject->{dnignore}[0] ne 'on' && $dn !~ /$dcheckbase$/i) {
                                next;
                            }

                            ($subdn) = ($dn =~ /^(.*),$dbase$/i);
                            if (!$subdn) {
                                next;
                            }
                        }

                        # check need for synchronization
                        my %attrmap;
                        my %memberattrmap;
                        my @syncdns;
                        if (defined($sobject->{syncflag})) {
                            my $checkEntry;
                            if (defined($sobject->{syncflag}[0]->{attrmap}) || defined($sobject->{syncflag}[0]->{memberattrmap})) {
                                $checkEntry = $entries[$i];
                            } else {
                                $checkEntry = defined($present_list->{$sbase}{list}{$key}) && defined($present_list->{$sbase}{list}{$key}->{$subdn}) ? $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr} : '';
                            }
                            if (!$self->_checkSyncFlag($sobject->{syncflag}[0], "$subdn,$master->{suffix}", $checkEntry, \%syncflag_cache, \%attrmap, \%memberattrmap, \@syncdns)) {
                                $syncflag = 0;
                            } else {
                                if (@syncdns) {
                                    my $match = 0;
                                    foreach my $checkdn (@syncdns) {
                                        if ($dn =~ /$checkdn/i) {
                                            $match = 1;
                                            last;
                                        }
                                    }
                                    if (!$match) {
                                        next;
                                    }
                                }
                                if (defined($sobject->{syncflag}[0]->{attrmap})) {
                                    my ($rdn_attr, $rdn_val, $entry_base) = ($dn =~ /^([^=]+)=([^,]+),(.+)$/);
                                    if (grep(/^$rdn_attr$/i, values(%attrmap))) {
                                        $entry_base =~ s/$dbase/$sbase/i;
                                        my $mrdn_attr;
                                        foreach my $attr (keys(%attrmap)) {
                                            if ($attrmap{$attr} =~ /^$rdn_attr$/i) {
                                                $mrdn_attr = $attr;
                                                last;
                                            }
                                        }
                                        my $entryStr;
                                        ($rc, $entryStr) = $self->_do_search($entry_base, 2, 0, 1, $timeout, "($rdn_attr=$rdn_val)", 0, $mrdn_attr);
                                        if ($rc && $rc != LDAP_NO_SUCH_OBJECT) {
                                            $self->log(level => 'err', message => "Can't get master entry of $dn($rc)");
                                            return ($rc, ());
                                        } elsif ($entryStr) {
                                            my ($mrdn_val) = ($entryStr =~ /^$mrdn_attr: (.*)$/mi);
                                            $key = "$mrdn_attr=$mrdn_val";
                                            $subdn =~ s/^[^,]+,/$key,/;
                                        }
                                    }
                                }
                            }
                        }
 
                        my $mentry;
                        my $srcdn;
                        if ($syncflag && defined($present_list->{$sbase}{list}{$key})) {
                            if (defined($present_list->{$sbase}{list}{$key}->{$subdn})) {
                                if (!defined($syncfilter) ||
                                    LISM::Storage->parseFilter($syncfilter, $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr})) {
                                    $mentry = $present_list->{$sbase}{list}{$key}->{$subdn};
                                }
                            } else {
                                my @subdns = keys %{$present_list->{$sbase}{list}{$key}};
                                for (my $j = 0; $j < @subdns; $j++) {
                                    if ((defined($sobject->{unique}) && $subdns[$j] =~ /,$sobject->{unique}[0]->{base}$/i) ||
                                        $sobject->{dnignore}[0] eq 'on') {
                                        if (!defined($syncfilter) ||
                                            LISM::Storage->parseFilter($syncfilter, $present_list->{$sbase}{list}{$key}->{$subdns[$j]}->{entryStr})) {
                                            if (defined($sobject->{unique})) {
                                                $srcdn = $subdn;
                                            }
                                            $subdn = $subdns[$j];
                                            $mentry = $present_list->{$sbase}{list}{$key}->{$subdn};
                                        }
                                    }
                                }
                            }
                        }

                        if (!$mentry) {
                            # data storage's entry doesn't exist in master storage
                            if ($ops{delete} && (!defined($sobject->{delfilterobj}) || LISM::Storage->parseFilter($sobject->{delfilterobj}, $entries[$i]))) {
                                $nosync_data{$dname} = 1;
                                $nosync_entries{'sync'}{$dn} = "The entry may be invalid in cluster";
                            }
                        } elsif ($srcdn) {
                            $nosync_data{$dname} = 1;
                            $nosync_entries{'sync'}{$dn} = "The entry shoud move to \"$subdn,$dbase\" in cluster";
                        } elsif (defined($sobject->{idmap})) {
                            $dn = "$key,$dbase";
                            $mentry->{entryStr} =~ s/$master->{suffix}$/$data->{suffix}/gmi;
                            if (defined($sobject->{syncattrs})) {
                                my $entryStr = '';
                                foreach my $attr ($sobject->{idmap}[0]->{local}, @{$sobject->{syncattrs}}) {
                                    if ($attr =~ /^userpassword$/i) {
                                        next;
                                    }

                                    my $sattr;
                                    foreach (my $j = 0; $j < @{$sobject->{syncattrs}}; $j++) {
                                        if ($attr eq ${$sobject->{syncattrs}}[$j]) {
                                            $sattr = $sobject->{syncattr}[$j];
                                        }
                                    }

                                    my @vals = ($mentry->{entryStr} =~ /^$attr: (.*)$/gmi);
                                    if (@vals) {
                                        foreach my $val (@vals) {
                                            if ($val =~ /^ *$/) {
                                                next;
                                            }
                                            if ($sattr && defined($sattr->{memberfilter})) {
                                                my $match = 0;
                                                foreach my $memberfilter (@{$sattr->{memberfilter}}) {
                                                    if (!defined($memberfilter->{dn}) || $val =~ /$memberfilter->{dn}/i) {
                                                        if (!defined($memberfilter->{filter})) {
                                                            $match = 1;
                                                            last;
                                                        }
                                                        my ($rc2, $entry2) = $self->_do_search($val, 0, 0, 1, 0, $memberfilter->{filter}, 0, 'objectClass');
                                                        if (!$rc2 && $entry2) {
                                                            $match = 1;
                                                            last;
                                                        } elsif ($rc2) {
                                                            $self->log(level => 'err', message => "Checking member $val failed by $memberfilter->{filter} : $rc2");
                                                        }
                                                    }
                                                }
                                                if (!$match) {
                                                    next;
                                                }
                                            }
                                            $entryStr .= "$attr: $val\n";
                                        }
                                    }
                                }
                                $mentry->{entryStr} = $entryStr;
                            }
                            my @dinfo = ($mentry->{entryStr});
                            my $oldentry;
                            my $error;
                            $rc = $self->_doHandler('pre_Rewrite', 'add', $dname, \$dn, \@dinfo, \$oldentry, \$error);
                            if ($rc) {
                                $self->log(level => 'err', message => "Handler to $key,$dbase failed($rc): $error");
                                next;
                            }
                            $mentry->{entryStr} = $dinfo[0];
                            @sync_attrs = $self->_unique(($mentry->{entryStr} =~ /^([^:]+):/gmi));
                            for (my $j = 0; $j < @sync_attrs; $j++) {
                                my $attr = $sync_attrs[$j];
                                if ($attr =~ /^(objectClass|userpassword|unicodepwd|customAttribute)$/i) {
                                    next;
                                }

                                my $pvals = join(";", sort {lc $a cmp lc $b} $self->_getAttrValues($mentry->{entryStr}, $attr));
                                my $dvals = join(";", sort {lc $a cmp lc $b} $self->_getAttrValues($entries[$i], $attr));
                                my $evals = $pvals;
                                $pvals =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                                if ($dvals !~ /^$pvals$/i && $ops{modify}) {
                                    if ($nosync_entries{'sync'}{$dn}) {
                                        $nosync_entries{'sync'}{$dn} .= ", attr=\'$attr\' expect=\'$evals\' current=\'$dvals\'";
                                    } else {
                                        $nosync_data{$dname} = 1;
                                        $nosync_entries{'sync'}{$dn} = "The value is inconsistent in cluster: attr=\'$attr\' expect=\'$evals\' current=\'$dvals\'";
                                    }
                                }
                            }
                        } else {
                            if (!defined($sobject->{syncattrs})) {
                                @sync_attrs = $self->_unique(($mentry->{entryStr} =~ /^([^:]+):/gmi), ($entries[$i] =~ /\n([^:]+):/gi));
                            }

                            for (my $j = 0; $j < @sync_attrs; $j++) {
                                my $attr = $sync_attrs[$j];
                                my $sync_attr = $attr;
                                my $sattr;
                                my @values;

                                if (defined($attrmap{lc($attr)})) {
                                    $attr = $attrmap{lc($attr)};
                                }

                                if (defined($sobject->{syncattr})) {
                                    $sattr = $sobject->{syncattr}[$j];
                                }

                                if (defined($sattr->{type}) && $sattr->{type}[0] ne 'differential') {
                                    next;
                                }

                                if (defined($sattr->{op}) && !grep(/^modify$/, @{$sattr->{op}})) {
                                    next;
                                }

                                if (defined($sattr->{filterobj}) && !LISM::Storage->parseFilter($sattr->{filterobj}, $mentry->{entryStr})) {
                                    next;
                                }

                                @values = ();
                                foreach my $value ($self->_getAttrValues($mentry->{entryStr}, $attr)) {
                                    if ($value && $value !~ /^ *$/) {
                                        push(@values, $value);
                                    }
                                }
                                if (defined($sattr->{option}) && grep(/^notnull$/, @{$sattr->{option}}) && !@values) {
                                    next
                                }

                                my @sync_vals = $self->_checkSyncAttrs($master, $data, $sattr, \%memberattrmap, @values);
                                my $pvals = join(";", sort {lc $a cmp lc $b} @sync_vals);

                                @values = ();
                                foreach my $value ($self->_getAttrValues($entries[$i], $sync_attr)) {
                                    if ($value && $value !~ /^ *$/) {
                                        push(@values, $value);
                                    }
                                }
                                my ($synced_vals, $left_vals) = $self->_checkSyncedAttrs($data, $master, $sattr, @values);
                                my $dvals = join(";", sort {lc $a cmp lc $b} @{$synced_vals});

                                # ignore passowrd equality if hash type is differnt
                                if ($sync_attr =~ /^userpassword$/i) {
                                    if (!$self->_cmpPwdHash($lism_master, $dname, $pvals, $dvals)) {
                                        next;
                                    }
                                }

                                my $evals = $pvals;
                                $pvals =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                                if ($dvals !~ /^$pvals$/i && $ops{modify}) {
                                    if ($nosync_entries{'sync'}{$dn}) {
                                        $nosync_entries{'sync'}{$dn} .= ", attr=\'$attr\' expect=\'$evals\' current=\'$dvals\'";
                                    } else {
                                        $nosync_data{$dname} = 1;
                                        $nosync_entries{'sync'}{$dn} = "The value is inconsistent in cluster: attr=\'$attr\' expect=\'$evals\' current=\'$dvals\'";
                                    }
                                }
                            }
                        }

                        if ($ops{add} && defined($present_list->{$sbase}{list}{$key}) &&
                            defined($present_list->{$sbase}{list}{$key}->{$subdn})) {
                            $present_list->{$sbase}{list}{$key}->{$subdn}->{sync_present}{$dname} = 1;
                        }
                    }

                    # check added entry in present list
                    if ($ops{add} && $entrynum < $sync_size) {
                        my @syncdns;
                        foreach my $key (keys %{$present_list->{$sbase}{list}}) {
                            foreach my $subdn (keys %{$present_list->{$sbase}{list}{$key}}) {
                                if (defined($sobject->{syncflag}) && !$self->_checkSyncFlag($sobject->{syncflag}[0], "$subdn,$master->{suffix}", $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr}, \%syncflag_cache, undef, undef, \@syncdns)) {
                                    next;
                                }

                                if (defined($present_list->{$sbase}{list}{$key}->{$subdn}->{sync_present}{$dname}) ||
                                    (defined($syncfilter) &&
                                        !LISM::Storage->parseFilter($syncfilter, $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr}))) {
                                    next;
                                }

                                my $nosync_entry;

                                $nosync_data{$dname} = 1;
                                if ($sobject->{dnignore}[0] eq 'on') {
                                    if ($dbase eq $dregexbase) {
                                        $nosync_entry = "$key,$dbase";
                                    } else {
                                        $nosync_entry = "$key,".("$subdn,$dbase" =~ /($dregexbase)$/i)[0];
                                    }
                                } else {
                                    $nosync_entry = "$subdn,$dbase";
                                }

                                if (@syncdns) {
                                    my $match = 0;
                                    foreach my $checkdn (@syncdns) {
                                        if ($nosync_entry =~ /$checkdn/i) {
                                            $match = 1;
                                            last;
                                        }
                                    }
                                    if (!$match) {
                                        next;
                                    }
                                }

                                $nosync_entry =~ tr/A-Z/a-z/;
                                $nosync_entries{'sync'}{$nosync_entry} = "The entry doesn't exist in cluster";
                                $entrynum++;
                            }
                        }
                    }
                }
            }
        }
    }

    if ($base !~ /^$cluster_syncrdn/) {
        # check master data
        foreach my $dname (@check_data) {
            if ($dname eq $self->{master}->{current} || $dname eq 'Task') {
                next;
            }

            # check cluster status
            if ($cluster->{$dname}->{status} eq 'inactive') {
                next;
            }

            my $data = $self->{data}{$dname};
            my $sdata = $cluster->{$dname}->{conf};
            my $dcheckfilter = $checkfilter;
            my $dcheckbase = $checkbase;

            $dcheckfilter =~ s/$master->{suffix}/$data->{suffix}/i;
            $dcheckbase =~ s/$master->{suffix}$/$data->{suffix}/i;

            foreach my $oname (@{$sdata->{order}}) {
	        my $sobject = $sdata->{object}{$oname};
                my %ops;
                $ops{add} = 0;
                $ops{modify} = 0;
                $ops{delete} = 0;

                if (!defined($sobject->{masterdn})) {
                    next;
                }

                foreach my $masterdn (@{$sobject->{masterdn}}) {
                    my $dbase;
                    my $dregexbase;
                    my $sbase;

                    if ($masterdn eq 'ou=disable') {
                        next;
                    } elsif ($masterdn eq '*') {
                        $dbase = $data->{suffix};
                        $dregexbase = $dbase;
                        $sbase = $master->{suffix};
                    } elsif ($masterdn =~ /[*+]/) {
                        $dbase = $data->{suffix};
                        $dregexbase = $masterdn.','.$data->{suffix};
                        $sbase = $master->{suffix};
                    } else {
                        $dbase = $masterdn.','.$data->{suffix};
                        $dregexbase = $dbase;
                        $sbase = $masterdn.','.$master->{suffix};
                    }

                    if ($dcheckbase && $dcheckbase !~ /$dregexbase$/i) {
                        next;
                    }

                    # synchronization filter
                    my $masterfilter = undef;
                    my $ocheckfilter = $dcheckfilter;
                    if (defined($sobject->{masterfilterobj})) {
                        $masterfilter = $sobject->{masterfilterobj};
                        $ocheckfilter = "(&$ocheckfilter$sobject->{masterfilter}[0])";
                    }

                    if (defined($sobject->{masterop})) {
                        foreach my $op (@{$sobject->{masterop}}) {
                            if (!%opFlag || defined($opFlag{$op})) {
                                $ops{$op} = 1;
                                if ($op eq 'delete') {
                                    if (!defined($deletedn{$sbase})) {
                                        $deletedn{$sbase} = [];
                                    }
                                    push(@{$deletedn{$sbase}}, [$dname, $oname]);
                                }
                            }
                        }
                    } else {
                        foreach my $op (@{$sdata->{masterop}}) {
                            if (!%opFlag || defined($opFlag{$op})) {
                                $ops{$op} = 1;
                                if ($op eq 'delete') {
                                    if (!defined($deletedn{$sbase})) {
                                        $deletedn{$sbase} = [];
                                    }
                                    push(@{$deletedn{$sbase}}, [$dname, $oname]);
                                }
                            }
                        }
                    }

                    my $entrynum = $present_list->{$sbase}{'count'};

                    # synchronized attributes
                    my @sync_attrs;
                    if (defined($sobject->{masterattrs})) {
                        @sync_attrs = @{$sobject->{masterattrs}};
                    }

                    # get values from data storage
                    my ($rc, @entries) = $self->_do_search($dcheckbase ? $dcheckbase : $dbase, 2, 0, $sizeLimit, $timeout, $ocheckfilter, 0, , ());
                    if ($rc && $rc != LDAP_NO_SUCH_OBJECT) {
                        $self->log(level => 'err', message => "Can't get values of $dname($rc)");
                        return ($rc, ());
                    }

                    # comare data storage's values with master one
                    for (my $i = 0; $i < @entries; $i++) {
                        my ($dn) = ($entries[$i] =~ /^dn: (.*)\n/);
                        $dn =~ tr/A-Z/a-z/;

                        if ($dcheckbase && $sobject->{dnignore}[0] ne 'on' && $dn !~ /$dcheckbase$/i) {
                            next;
                        }

                        my ($subdn) = ($dn =~ /^(.*),$dbase$/i);
                        if (!$subdn) {
                            next;
                        }

                        my ($key) = ($dn =~ /^(.*?)(?<!\\),/);

                        my $mentry;
                        my $dstdn;
                        if (defined($present_list->{$sbase}{list}{$key})) {
                            if (defined($present_list->{$sbase}{list}{$key}->{$subdn})) {
                                $mentry = $present_list->{$sbase}{list}{$key}->{$subdn};
                            } else {
                                my @subdns = keys %{$present_list->{$sbase}{list}{$key}};
                                for (my $j = 0; $j < @subdns; $j++) {
                                    if ((defined($sobject->{unique}) && $subdns[$j] =~ /,$sobject->{unique}[0]->{base}$/i) ||
                                        $sobject->{dnignore}[0] eq 'on') {
                                        if (defined($sobject->{unique})) {
                                            $dstdn = $subdn;
                                        }
                                        $subdn = $subdns[$j];
                                        $mentry = $present_list->{$sbase}{list}{$key}->{$subdn};
                                    }
                                }
                            }
                        }

                        if (!$mentry) {
                            # data storage's entry doesn't exist in master storage
                            if ($ops{add} && $entrynum < $sync_size) {
                                $nosync_data{$dname} = 1;
                                $nosync_entries{'master'}{$dn} = "The entry doesn't exist in master";
                                $entrynum++;
                            }
                        } elsif ($dstdn) {
                            $nosync_data{$dname} = 1;
                            $nosync_entries{'master'}{$dn} = "The entry should move from \"$subdn,$sbase\" in master";
                        } else {
                            if (defined($nosync_entries{'master'}{$dn})) {
                                $nosync_entries{'master'}{$dn} .= ", duplicate";
                            }

                            if (!defined($sobject->{masterattrs})) {
                                @sync_attrs = $self->_unique(($mentry->{entryStr} =~ /^([^:]+):/gmi), ($entries[$i] =~ /\n([^:]+):/gi));
                            }

                            for (my $j = 0; $j < @sync_attrs; $j++) {
                                my $attr = $sync_attrs[$j];
                                my $sattr;
                                my @values;

                                if (defined($sobject->{masterattr})) {
                                    $sattr = $sobject->{masterattr}[$j];
                                }

                                if (defined($sattr->{op}) && !grep(/^modify$/, @{$sattr->{op}})) {
                                    next;
                                }

                                if (defined($sattr->{filterobj}) && !LISM::Storage->parseFilter($sattr->{filterobj}, $entries[$i])) {
                                    next;
                                }

                                @values = $self->_getAttrValues($entries[$i], $attr);
                                if (defined($sattr->{option}) && grep(/^notnull$/, @{$sattr->{option}}) && !@values) {
                                    next
                                }

                                my @sync_vals = $self->_checkSyncAttrs($data, $master, $sattr, undef, @values);
                                my $dvals = join(";", sort {lc $a cmp lc $b} @sync_vals);

                                @values = $self->_getAttrValues($mentry->{entryStr}, $attr);
                                my ($synced_vals, $left_vals) = $self->_checkSyncedAttrs($master, $data, $sattr, @values);
                                my $pvals = join(";", sort {lc $a cmp lc $b} @{$synced_vals});

                                # ignore passowrd equality if hash type is differnt
                                if ($attr =~ /^userpassword$/i) {
                                    if (!$self->_cmpPwdHash($dname, $lism_master, $dvals, $pvals)) {
                                        next;
                                    }
                                }

                                my $cvals = $pvals;
                                $pvals =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                                if ($dvals !~ /^$pvals$/i && $ops{modify}) {
                                    if ($nosync_entries{'master'}{$dn}) {
                                        $nosync_entries{'master'}{$dn} .= ", attr=\'$attr\' expect=\'$dvals\' current=\'$cvals\'";
                                    } else {
                                        $nosync_data{$dname} = 1;
                                        $nosync_entries{'master'}{$dn} = "The value is inconsistent in master: attr=\'$attr\' expect=\'$dvals\' current=\'$cvals\'";
                                    }
                                }
                            }
                        }

                        if (defined($present_list->{$sbase}{list}{$key}) && $present_list->{$sbase}{list}{$key}->{$subdn}->{present}) {
                            if (defined($nosync_entries{'master'}{$dn})) {
                                if ($nosync_entries{'master'}{$dn} !~ /, duplicate/) {
                                    $nosync_entries{'master'}{$dn} .= ", duplicate";
                                }
                            } else {
                                $nosync_entries{'master'}{$dn} = "The entry is duplicate";
                            }
                        } else {
                            $present_list->{$sbase}{list}{$key}->{$subdn}->{present} = 1;
                        }
	            }
                }
            }
        }

        # check deleted entry in present list
        foreach my $sbase (keys %deletedn) {
            for (my $i = 0; $i < @{$deletedn{$sbase}}; $i++) {
                my $sobject = $cluster->{${$deletedn{$sbase}}[$i][0]}->{conf}->{object}{${$deletedn{$sbase}}[$i][1]};

                # synchronization filter
                my $masterfilter = undef;
                if (defined($sobject->{masterfilterobj})) {
                    $masterfilter = $sobject->{masterfilterobj};
                }

                foreach my $key (keys %{$present_list->{$sbase}{list}}) {
                    foreach my $subdn (keys %{$present_list->{$sbase}{list}{$key}}) {
                        if (!$present_list->{$sbase}{list}{$key}->{$subdn}->{present}) {
                            if (defined($masterfilter) &&
                                !LISM::Storage->parseFilter($masterfilter, $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr})) {
                                next;
                            }
                            if (defined($sobject->{delfilterobj}) && !LISM::Storage->parseFilter($sobject->{delfilterobj}, $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr})) {
                                next;
                            }
                            my $nosync_entry;
                            ($nosync_entry = "$subdn,$sbase") =~ tr/A-Z/a-z/;
                            $nosync_data{${$deletedn{$sbase}}[$i][0]} = 1;
                            $nosync_entries{'master'}{$nosync_entry} = "The entry may be invalid in master";
                        }
                    }
                }
            }
        }
    }

    if (!%nosync_data) {
        $syncentry = $syncentry."$syncInfoAttr: sync\n";
    } else {
        $syncentry = $syncentry."$syncInfoAttr: nosync\n";
        foreach my $dname (keys %nosync_data) {
            $syncentry = $syncentry."$syncDataAttr: $dname\n";
        }
        foreach my $type (keys %nosync_entries) {
            foreach my $dn (keys %{$nosync_entries{$type}}) {
                $syncentry = $syncentry."$nosyncAttr: $dn \"$nosync_entries{$type}{$dn}\"\n";
            }
        }
    }

    $self->log(level => 'info', message => "Differential check finished");

    return (LDAP_SUCCESS, ($syncentry));
}

sub _setSyncInfo
{
    my $self = shift;
    my ($dn, @list) = @_;
    my $conf = $self->{_lism};
    my $master = $self->{data}{$lism_master};
    my $cluster = $self->{cluster};
    my $timeout = $self->{_config}->{timeout};
    my $present_list;
    my @sync_data = ();
    my %nosync_entries;
    my %deletedn;
    my %syncflag_cache;
    my %opFlag;
    my $continueFlag = 0;
    my $rc = LDAP_SUCCESS;
    $nosync_entries{'master'} = {};

    if (!defined($master->{suffix})) {
        return LDAP_UNWILLING_TO_PERFORM;
    }

    $self->log(level => 'info', message => "Differential synchronization starting");

    my $modinfo = encode('utf8', join('#', @list));

    # get synchronized data
    my ($sync_dnames) = ($modinfo =~ /DELETE#$syncDataAttr#(.*)#?(ADD|DELETE|REPLACE|)/i);

    # get check filter
    my ($checkfilter) = ($modinfo =~ /REPLACE#$syncFilterAttr#([^#]*)#?(ADD|DELETE|REPLACE|)/i);

    # get check base dn
    my ($checkbase) = ($modinfo =~ /REPLACE#$syncBaseAttr#([^#]*)#?(ADD|DELETE|REPLACE|)/i);
    if ($checkbase && $checkbase !~ /$master->{suffix}$/i) {
        return LDAP_UNWILLING_TO_PERFORM;
    }
    if (!Encode::is_utf8($checkbase)) {
        $checkbase = decode('utf8', $checkbase);
    }

    # check size limit
    my ($sync_size) = ($modinfo =~ /#$syncSizeAttr#([^#]*)#?(ADD|DELETE|REPLACE|)/i);
    if (!$sync_size || $sync_size !~ /^[0-9]+$/) {
        $sync_size = $sizeLimit;
    }

    # check synchronization option
    foreach my $op ('add', 'modify', 'delete') {
        if ($modinfo =~ /#$optionAttr#$op(#|)/i) {
            $opFlag{$op} = 1;
        }
    }

    # check continue option
    if ($modinfo =~ /#$optionAttr#continue(#|)/i) {
        $continueFlag = 1;
    }

    if ($sync_dnames) {
        foreach my $dname (keys %{$cluster}) {
            if ("#$sync_dnames#" =~ /#$dname#/i) {
                push(@sync_data, $dname);
            }
        }
    } else {
        if (!$checkfilter && !$checkbase && $modinfo !~ /REPLACE#$syncInfoAttr#sync/i) {
            return LDAP_UNWILLING_TO_PERFORM;
        }
        @sync_data = keys %{$cluster};
    }

    if ($checkfilter) {
        $checkfilter =~ s/\\28/(/g;
        $checkfilter =~ s/\\29/)/g;
        $checkfilter =~ s/\\5C/\\/gi;
        if ($checkfilter !~ /^\(.+\)$/) {
            $checkfilter = "($checkfilter)";
        }
    } else {
        $checkfilter = "(objectClass=*)";
    }

    my %update_info;
  DO: {
    if ($dn !~ /^$master_syncrdn/) {
        # get present entry list
        $present_list = $self->_getPresentList($checkfilter, $checkbase, @sync_data);
        if (!defined($present_list)) {
            return LDAP_OTHER;
        }

        $update_info{sync} = {};
        foreach my $dname (@sync_data) {
            if ($dname eq $self->{master}->{current}) {
                next;
            }

            # check cluster status
            if ($cluster->{$dname}->{status} eq 'inactive') {
                next;
            }

            my $data = $self->{data}{$dname};
            my $sdata = $cluster->{$dname}->{conf};
            my $dcheckfilter = $checkfilter;
            my $dcheckbase = $checkbase;
            my %post_delete_list;

            $dcheckfilter =~ s/$master->{suffix}/$data->{suffix}/i;
            $dcheckbase =~ s/$master->{suffix}$/$data->{suffix}/i;

            if (!defined($sdata->{syncop})) {
                next;
            }

            $update_info{sync}->{$dname} = {};
            foreach my $oname (@{$sdata->{order}}) {
                my $sobject = $sdata->{object}{$oname};
                my %ops;
                $ops{add} = 0;
                $ops{modify} = 0;
                $ops{delete} = 0;

                if (!defined($sobject->{syncdn})) {
                    next;
                }

                if (defined($sobject->{synctype}) && $sobject->{synctype}[0] !~ /^(differential|task)$/) {
                    next;
                }

                if (defined($sobject->{syncop})) {
                    foreach my $op (@{$sobject->{syncop}}) {
                        if (!%opFlag || defined($opFlag{$op})) {
                            $ops{$op} = 1;
                        }
                    }
                } else {
                    foreach my $op (@{$sdata->{syncop}}) {
                        if (!%opFlag || defined($opFlag{$op})) {
                            $ops{$op} = 1;
                        }
                    }
                }

                foreach my $syncdn (@{$sobject->{syncdn}}) {
                    my $dbase;
                    my $dregexbase;
                    my $sbase;
                    my @delete_list;

                    if ($syncdn eq 'ou=disable') {
                        next;
                    } elsif ($syncdn eq '*') {
                        $dbase = $data->{suffix};
                        $dregexbase = $dbase;
                        $sbase = $master->{suffix};
                    } elsif ($syncdn =~ /[*+]/) {
                        $dbase = $data->{suffix};
                        $dregexbase = $syncdn.','.$data->{suffix};
                        $sbase = $master->{suffix};
                    } else {
                        $dbase = $syncdn.','.$data->{suffix};
                        $dregexbase = $dbase;
                        $sbase = $syncdn.','.$master->{suffix};
                    }

                    if (!defined($present_list->{$sbase})) {
                        next;
                    }

                    if ($dcheckbase && $dcheckbase !~ /$dregexbase$/i) {
                        next;
                    }

                    if (!defined($update_info{sync}->{$dname}->{$oname})) {
                        $update_info{sync}->{$dname}->{$oname} = {total => 0, add_total => 0, add_success => 0, mod_total => 0, mod_success => 0, del_total => 0, del_success =>0, skip => 0};
                    }

                    # synchronization filter
                    my $syncfilter = undef;
                    my $ocheckfilter = $dcheckfilter;
                    if (defined($sobject->{syncfilterobj})) {
                        $syncfilter = $sobject->{syncfilterobj};
                        $ocheckfilter = "(&$ocheckfilter$sobject->{syncfilter}[0])";
                    }

                    my $total_num = 0;
                    foreach my $key (keys %{$present_list->{$sbase}{list}}) {
                        foreach my $subdn (keys %{$present_list->{$sbase}{list}{$key}}) {
                            if (!defined($syncfilter) ||
                                LISM::Storage->parseFilter($syncfilter, $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr})) {
                                $total_num++;
                            }
                        }
                    }
                    $update_info{sync}->{$dname}->{$oname}{total} += $total_num;

                    # synchronized attributes
                    my @sync_attrs;
                    if (defined($sobject->{syncattrs}) && !defined($sobject->{idmap})) {
                        @sync_attrs = @{$sobject->{syncattrs}};
                    }

                    # get values from data storage
                    my @entries;
                    ($rc, @entries) = $self->_do_search($dcheckbase ? $dcheckbase : $dbase, 2, 0, $sizeLimit, $timeout, $ocheckfilter, 0, @sync_attrs, (@sync_attrs ? 'objectClass' : ()));
                    if ($rc == LDAP_NO_SUCH_OBJECT) {
                        $rc = LDAP_SUCCESS;
                    } elsif ($rc) {
                        $self->log(level => 'err', message => "Can't get values of $dname($rc)");
                        if (!$continueFlag) {
                            last DO;
                        } else {
                            next;
                        }
                    }

                    my $dcheckbase_regex = $dcheckbase;
                    $dcheckbase_regex =~ s/(?<!\\)\\/\\\\/g;
                    # comare data storage's values with master one
                    for (my $i = 0; $i < @entries; $i++) {
                        my $syncflag = 1;
                        my ($dn) = ($entries[$i] =~ /^dn: (.*)\n/);
                        $dn =~ tr/A-Z/a-z/;
                        my ($key) = ($dn =~ /^(.*?)(?<!\\),/);
                        my $subdn;

                        if (defined($sobject->{idmap})) {
                            my ($idval) = ($entries[$i] =~ /^$sobject->{idmap}[0]->{foreign}: (.+)$/mi);
                            $key = "$sobject->{idmap}[0]->{local}=".lc($idval);
                            if (defined($present_list->{$sbase}{list}{$key})) {
                                ($subdn) = keys %{$present_list->{$sbase}{list}{$key}};
                            }
                        } else {
                            if ($dcheckbase && $sobject->{dnignore}[0] ne 'on' && $dn !~ /$dcheckbase_regex$/i) {
                                next;
                            }

                            ($subdn) = ($dn =~ /^(.*),$dbase$/i);
                            if (!$subdn) {
                                next;
                            }
                        }

                        my %attrmap;
                        my %memberattrmap;
                        my @syncdns;
                        if (defined($sobject->{syncflag})) {
                            my $checkEntry;
                            if (defined($sobject->{syncflag}[0]->{attrmap}) || defined($sobject->{syncflag}[0]->{memberattrmap})) {
                                $checkEntry = $entries[$i];
                            } else {
                                $checkEntry = defined($present_list->{$sbase}{list}{$key}) && defined($present_list->{$sbase}{list}{$key}->{$subdn}) ? $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr} : '';
                            }
                            if (!$self->_checkSyncFlag($sobject->{syncflag}[0], "$subdn,$master->{suffix}", $checkEntry, \%syncflag_cache, \%attrmap, \%memberattrmap, \@syncdns)) {
                                $syncflag = 0;
                            } else {
                                if (@syncdns) {
                                    my $match = 0;
                                    foreach my $checkdn (@syncdns) {
                                        if ($dn =~ /$checkdn/i) {
                                            $match = 1;
                                            last;
                                        }
                                    }
                                    if (!$match) {
                                        next;
                                    }
                                }
                                if (defined($sobject->{syncflag}[0]->{attrmap})) {
                                    my ($rdn_attr, $rdn_val, $entry_base) = ($dn =~ /^([^=]+)=([^,]+),(.+)$/);
                                    if (grep(/^$rdn_attr$/i, values(%attrmap))) {
                                        $entry_base =~ s/$dbase/$sbase/i;
                                        my $mrdn_attr;
                                        foreach my $attr (keys(%attrmap)) {
                                            if ($attrmap{$attr} =~ /^$rdn_attr$/i) {
                                                $mrdn_attr = $attr;
                                                last;
                                            }
                                        }
                                        my $entryStr;
                                        ($rc, $entryStr) = $self->_do_search($entry_base, 2, 0, 1, $timeout, "($rdn_attr=$rdn_val)", 0, $mrdn_attr);
                                        if ($rc && $rc != LDAP_NO_SUCH_OBJECT) {
                                            $self->log(level => 'err', message => "Can't get master entry of $dn($rc)");
                                            return ($rc, ());
                                        } elsif ($entryStr) {
                                            my ($mrdn_val) = ($entryStr =~ /^$mrdn_attr: (.*)$/mi);
                                            $key = "$mrdn_attr=$mrdn_val";
                                            $subdn =~ s/^[^,]+,/$key,/;
                                        }
                                    }
                                }
                            }
                        }

                        my $mentry;
                        my $srcdn;
                        if ($syncflag && defined($present_list->{$sbase}{list}{$key})) {
                            if (defined($present_list->{$sbase}{list}{$key}->{$subdn})) {
                                if (!defined($syncfilter) ||
                                    LISM::Storage->parseFilter($syncfilter, $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr})) {
                                    $mentry = $present_list->{$sbase}{list}{$key}->{$subdn};
                                }
                            } else {
                                my @subdns = keys %{$present_list->{$sbase}{list}{$key}};
                                for (my $j = 0; $j < @subdns; $j++) {
                                    if ((defined($sobject->{unique}) && $subdns[$j] =~ /,$sobject->{unique}[0]->{base}$/i) ||
                                        $sobject->{dnignore}[0] eq 'on') {
                                        if (!defined($syncfilter) ||
                                            LISM::Storage->parseFilter($syncfilter, $present_list->{$sbase}{list}{$key}->{$subdns[$j]}->{entryStr})) {
                                            if (defined($sobject->{unique})) {
                                                $srcdn = $subdn;
                                            }
                                            $subdn = $subdns[$j];
                                            $mentry = $present_list->{$sbase}{list}{$key}->{$subdn};
                                        }
                                    }
                                }
                            }
                        }

                        if (!$mentry) {
                            if ($ops{delete} && (!defined($sobject->{delfilterobj}) || LISM::Storage->parseFilter($sobject->{delfilterobj}, $entries[$i]))) {
                                my $level = split(/,/, $subdn);
                                if (defined($sobject->{delorder}) && $sobject->{delorder}[0] eq 'last') {
                                    if (!defined($post_delete_list{$oname})) {
                                        $post_delete_list{$oname} = [];
                                    }
                                    if (!defined($post_delete_list{$oname}[$level])) {
                                        $post_delete_list{$oname}[$level] = [];
                                    }
                                    push(@{$post_delete_list{$oname}[$level]}, [$dn, $entries[$i]]);
                                } else {
                                    if (!defined($delete_list[$level])) {
                                        $delete_list[$level] = [];
                                    }
                                    push(@{$delete_list[$level]}, [$dn, $entries[$i]]);
                                }
                            }
                        } elsif (defined($sobject->{idmap})) {
                            my @modlist;
                            $dn = "$key,$dbase";
                            $mentry->{entryStr} =~ s/$master->{suffix}$/$data->{suffix}/gmi;
                            if (defined($sobject->{syncattrs})) {
                                my $entryStr = '';
                                foreach my $attr ($sobject->{idmap}[0]->{local}, @{$sobject->{syncattrs}}) {
                                    if ($attr =~ /^userpassword$/i) {
                                        next;
                                    }
                                    push(@modlist, 'REPLACE', $attr);

                                    my $sattr;
                                    foreach (my $j = 0; $j < @{$sobject->{syncattrs}}; $j++) {
                                        if ($attr eq ${$sobject->{syncattrs}}[$j]) {
                                            $sattr = $sobject->{syncattr}[$j];
                                        }
                                    }

                                    my @vals = ($mentry->{entryStr} =~ /^$attr: (.*)$/gmi);
                                    if (@vals) {
                                        foreach my $val (@vals) {
                                            if ($val =~ /^ *$/) {
                                                next;
                                            }
                                            if ($sattr && defined($sattr->{memberfilter})) {
                                                my $match = 0;
                                                foreach my $memberfilter (@{$sattr->{memberfilter}}) {
                                                    if (!defined($memberfilter->{dn}) || $val =~ /$memberfilter->{dn}/i) {
                                                        if (!defined($memberfilter->{filter})) {
                                                            $match = 1;
                                                            last;
                                                        }
                                                        my ($rc2, $entry2) = $self->_do_search($val, 0, 0, 1, 0, $memberfilter->{filter}, 0, 'objectClass');
                                                        if (!$rc2 && $entry2) {
                                                            $match = 1;
                                                            last;
                                                        } elsif ($rc2) {
                                                            $self->log(level => 'err', message => "Checking member $val failed by $memberfilter->{filter} : $rc2");
                                                        }
                                                    }
                                                }
                                                if (!$match) {
                                                    next;
                                                }
                                            }
                                            $entryStr .= "$attr: $val\n";
                                            push(@modlist, $val);
                                        }
                                    }
                                }
                                $mentry->{entryStr} = $entryStr;
                            } else {
                                foreach my $attr ($self->_unique(($mentry->{entryStr} =~ /^([^:]+):/gmi))) {
                                    push(@modlist, 'REPLACE', $attr);
                                    my @vals = ($mentry->{entryStr} =~ /^$attr: (.*)$/gmi);
                                    if (@vals) {
                                        foreach my $val (@vals) {
                                            if ($val !~ /^ *$/) {
                                                push(@modlist, $val);
                                            }
                                        }
                                    }
                                }
                            }
                            my @dinfo = ($mentry->{entryStr});
                            my $oldentry;
                            my $error;
                            $rc = $self->_doHandler('pre_Rewrite', 'add', $dname, \$dn, \@dinfo, \$oldentry, \$error);
                            if ($rc) {
                                $self->log(level => 'err', message => "Handler to $key,$dbase failed($rc): $error");
                                next;
                                next;
                            }
                            $mentry->{entryStr} = $dinfo[0];
                            @sync_attrs = $self->_unique(($mentry->{entryStr} =~ /^([^:]+):/gmi));
                            for (my $j = 0; $j < @sync_attrs; $j++) {
                                my $attr = $sync_attrs[$j];
                                if ($attr =~ /^(objectClass|userpassword|unicodepwd|customAttribute)$/i) {
                                    next;
                                }

                                my $pvals = join(";", sort {lc $a cmp lc $b} $self->_getAttrValues($mentry->{entryStr}, $attr));
                                my $dvals = join(";", sort {lc $a cmp lc $b} $self->_getAttrValues($entries[$i], $attr));
                                my $evals = $pvals;
                                $pvals =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                                if ($dvals !~ /^$pvals$/i && $ops{modify}) {
                                    if ($ops{modify}) {
                                        $rc = $self->_doUpdate('modify', undef, 1, $entries[$i], $dn, @modlist);
                                        $update_info{sync}->{$dname}->{$oname}{mod_total}++;
                                        if ($rc) {
                                            $self->_writeSyncFail('modify', $dname, $dn, @modlist);
                                            $update_info{sync}->{$dname}->{$oname}{skip}++;
                                        } else {
                                            $update_info{sync}->{$dname}->{$oname}{mod_success}++;
                                        }
                                    }
                                    last;
                                }
                            }
                        } else {
                            if ($srcdn) {
                                my $newpdn = "$subdn,$dbase";
                                $newpdn =~ s/^[^,]+,//;
                                $rc = $self->_doUpdate('modify', undef, 1, undef, $dn, ('REPLACE', 'lismparentdn', $newpdn));
                                if ($rc) {
                                    $self->_writeSyncFail('modify', $dname, $dn, ('REPLACE', 'lismparentdn', $newpdn));
                                } else {
                                    $dn = "$subdn,$dbase";
                                }
                            }

                            # modify entry which isn't equal to master storage
                            my @modlist;

                            if (!defined($sobject->{syncattrs})) {
                                @sync_attrs = $self->_unique(($mentry->{entryStr} =~ /^([^:]+):/gmi), ($entries[$i] =~ /\n([^:]+):/gi));
                            }

                            for (my $j = 0; $j < @sync_attrs; $j++) {
                                my $attr = $sync_attrs[$j];
                                my $sync_attr = $attr;
                                my $sattr;
                                my @values;

                                if (defined($attrmap{lc($attr)})) {
                                    $attr = $attrmap{lc($attr)};
                                }

                                if (defined($sobject->{syncattr})) {
                                    $sattr = $sobject->{syncattr}[$j];
                                }

                                if (defined($sattr->{type}) && $sattr->{type}[0] ne 'differential') {
                                    next;
                                }

                                if (defined($sattr->{op}) && !grep(/^modify$/, @{$sattr->{op}})) {
                                    next;
                                }

                                if (defined($sattr->{filterobj}) && !LISM::Storage->parseFilter($sattr->{filterobj}, $mentry->{entryStr})) {
                                    next;
                                }

                                @values = ();
                                foreach my $value ($self->_getAttrValues($mentry->{entryStr}, $attr)) {
                                    if ($value && $value !~ /^ *$/) {
                                        push(@values, $value);
                                    }
                                }
                                if (defined($sattr->{option}) && grep(/^notnull$/, @{$sattr->{option}}) && !@values) {
                                    next
                                }

                                my @sync_vals = $self->_checkSyncAttrs($master, $data, $sattr, \%memberattrmap, @values);
                                my $pvals = join(";", sort {lc $a cmp lc $b} @sync_vals);

                                @values = ();
                                foreach my $value ($self->_getAttrValues($entries[$i], $sync_attr)) {
                                    if ($value && $value !~ /^ *$/) {
                                        push(@values, $value);
                                    }
                                }
                                my ($synced_vals, $left_vals) = $self->_checkSyncedAttrs($data, $master, $sattr, @values);
                                my $dvals = join(";", sort {lc $a cmp lc $b} @{$synced_vals});

                                # ignore passowrd equality if hash type is differnt
                                if ($sync_attr =~ /^userpassword$/i) {
                                    if (!$self->_cmpPwdHash($lism_master, $dname, $pvals, $dvals)) {
                                        next;
                                    }
                                }

                                $pvals =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                                if ($dvals !~ m/^$pvals$/i) {
                                    if (@{$left_vals}) {
                                        push(@sync_vals, @{$left_vals});
                                    }
                                    if (@sync_vals) {
                                        push(@modlist, ('REPLACE', $sync_attr, @sync_vals));
                                    } else {
                                        push(@modlist, ('DELETE', $sync_attr));
                                    }
                                }
                            }

                            if (@modlist) {
                                if ($ops{modify}) {
                                    $rc = $self->_doUpdate('modify', undef, 1, $entries[$i], $dn, @modlist);
                                    $update_info{sync}->{$dname}->{$oname}{mod_total}++;
                                    if ($rc) {
                                        $self->_writeSyncFail('modify', $dname, $dn, @modlist);
                                        $update_info{sync}->{$dname}->{$oname}{skip}++;
                                    } else {
                                        $update_info{sync}->{$dname}->{$oname}{mod_success}++;
                                    }
                                }
                            }
                        }

                        if ($rc) {
                            $self->log(level => 'err', message => "Synchronizing \"$dn\" failed($rc)".($continueFlag ? ": Skip operation" : ''));
                            if (!$continueFlag) {
                                last DO;
                            }
                            $rc = LDAP_SUCCESS;
                        }

                        if ($ops{add} && defined($present_list->{$sbase}{list}{$key}) &&
                            defined($present_list->{$sbase}{list}{$key}->{$subdn})) {
                            $present_list->{$sbase}{list}{$key}->{$subdn}->{sync_present}{$dname} = 1;
                        }
                    }

                    if ($ops{delete}) {
                        for (my $i = @delete_list; $i > 0; $i--) {
                            if (!defined($delete_list[$i -1])) {
                                next;
                            }
                            foreach my $elt (@{$delete_list[$i -1]}) {
                                my $dn = ${$elt}[0];
                                # delete entry which don't exist in master storage
                                $rc = $self->_doUpdate('delete', undef, 1, ${$elt}[1], $dn);
                                $update_info{sync}->{$dname}->{$oname}{del_total}++;
                                if ($rc) {
                                    $self->_writeSyncFail('delete', $dname, $dn);
                                    $update_info{sync}->{$dname}->{$oname}{skip}++;
                                    if (!$continueFlag) {
                                        last DO;
                                    }
                                } else {
                                    $update_info{sync}->{$dname}->{$oname}{del_success}++;
                                }
                            }
                        }
                    }

                    # add entries which don't exist in data storages
                    if ($ops{add}) {
                        my @non_present_list;
                        my %attrmap;
                        my %memberattrmap;
                        my @syncdns;

                        foreach my $key (keys %{$present_list->{$sbase}{list}}) {
                            foreach my $subdn (keys %{$present_list->{$sbase}{list}{$key}}) {
                                if (defined($sobject->{syncflag}) && !$self->_checkSyncFlag($sobject->{syncflag}[0], "$subdn,$master->{suffix}", $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr}, \%syncflag_cache, \%attrmap, \%memberattrmap, \@syncdns)) {
                                    next;
                                }

                                if (defined($present_list->{$sbase}{list}{$key}->{$subdn}->{sync_present}{$dname}) ||
                                    (defined($syncfilter) &&
                                        !LISM::Storage->parseFilter($syncfilter, $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr}))) {
                                    next;
                                }

                                my $level = split(/,/, $subdn);
                                ${$non_present_list[$level]}{$subdn} = $key;
                            }
                        }

                        for (my $i = 0; $i < @non_present_list; $i++) {
                            if (!defined($non_present_list[$i])) {
                                next;
                            }

                            foreach my $subdn (keys %{$non_present_list[$i]}) {
                                my $key = ${$non_present_list[$i]}{$subdn};
                                my $nosync_entry;
                                my $mentry = $present_list->{$sbase}{list}{$key}->{$subdn};
                                my ($rdn_attr) = ($key =~ /^([^=]+)=/);
                                my $attr = defined($attrmap{lc($rdn_attr)}) ? $attrmap{lc($rdn_attr)} : $rdn_attr;
                                my ($rdn_val) = ($mentry->{entryStr} =~ /^$attr: (.*)$/mi);
                                if (defined($attrmap{lc($rdn_attr)})) {
                                    $key =~ s/^$rdn_attr=[^,]+/$rdn_attr=$rdn_val/;
                                }
                                my $entryStr = "$rdn_attr: $rdn_val\n";

                                if (!defined($sobject->{syncattrs})) {
                                    @sync_attrs = $self->_unique(($mentry->{entryStr} =~ /^([^:]+):/gmi));
                                } elsif (defined($sobject->{idmap}) && !@sync_attrs) {
                                    @sync_attrs = @{$sobject->{syncattrs}};
                                }

                                for (my $j = 0; $j < @sync_attrs; $j++) {
                                    my $attr = $sync_attrs[$j];
                                    my $sync_attr = $attr;
                                    my $sattr;

                                    if ($attr =~ /^$rdn_attr$/i) {
                                        next;
                                    }

                                    if (defined($attrmap{lc($attr)})) {
                                        $attr = $attrmap{lc($attr)};
                                    }

                                    if (defined($sobject->{syncattr})) {
                                        $sattr = $sobject->{syncattr}[$j];
                                    }

                                    if (defined($sattr->{type}) && $sattr->{type}[0] ne 'differential') {
                                        next;
                                    }

                                    if (defined($sattr->{op}) && !grep(/^add$/, @{$sattr->{op}})) {
                                        next;
                                    }

                                    if (defined($sattr->{filterobj}) && !LISM::Storage->parseFilter($sattr->{filterobj}, $mentry->{entryStr})) {
                                        next;
                                    }

                                    my @values = $self->_getAttrValues($mentry->{entryStr}, $attr);
                                    my @sync_vals = $self->_checkSyncAttrs($master, $data, $sattr, \%memberattrmap, @values);
                                    if (@sync_vals) {
                                        # ignore passowrd equality if hash type is differnt
                                        if ($sync_attr =~ /^userpassword$/i) {
                                            if (!$self->_cmpPwdHash($lism_master, $dname, join(';', @sync_vals))) {
                                                next;
                                            }
                                        }

                                        foreach my $value (@sync_vals) {
                                            $entryStr = "$entryStr$sync_attr: $value\n";
                                        }
                                    }
                                }

                                if ($sobject->{dnignore}[0] eq 'on') {
                                    if ($dbase eq $dregexbase) {
                                        $nosync_entry = "$key,$dbase";
                                    } else {
                                        $nosync_entry = "$key,".("$subdn,$dbase" =~ /($dregexbase)$/i)[0];
                                    }
                                } else {
                                    $nosync_entry = "$subdn,$dbase";
                                }

                                if (@syncdns) {
                                    my $match = 0;
                                    foreach my $checkdn (@syncdns) {
                                        if ($nosync_entry =~ /$checkdn/i) {
                                            $match = 1;
                                            last;
                                        }
                                    }
                                    if (!$match) {
                                        next;
                                    }
                                }

                                $rc = $self->_doUpdate('add', undef, 1, undef, $nosync_entry, $entryStr);
                                $update_info{sync}->{$dname}->{$oname}{add_total}++;
                                if ($rc) {
                                    $self->log(level => 'err', message => "Synchronizing \"$nosync_entry\" failed($rc)".($continueFlag ? ": Skip operation" : ''));
                                    $self->_writeSyncFail('add', $dname, $nosync_entry, $entryStr);
                                    $update_info{sync}->{$dname}->{$oname}{skip}++;
                                    if (!$continueFlag) {
                                        last DO;
                                    }
                                } else {
                                    $update_info{sync}->{$dname}->{$oname}{add_success}++;
                                }
                            }
                        }
                    }
                }
            }
            foreach my $oname (keys %post_delete_list) {
                for (my $i = @{$post_delete_list{$oname}}; $i > 0; $i--) {
                    if (!defined(${$post_delete_list{$oname}}[$i -1])) {
                        next;
                    }
                    foreach my $elt (@{${$post_delete_list{$oname}}[$i -1]}) {
                        my $dn = ${$elt}[0];
                        # delete entry which don't exist in master storage
                        $rc = $self->_doUpdate('delete', undef, 1, ${$elt}[1], $dn);
                        $update_info{sync}->{$dname}->{$oname}{del_total}++;
                        if ($rc) {
                            $self->_writeSyncFail('delete', $dname, $dn);
                            $update_info{sync}->{$dname}->{$oname}{skip}++;
                        } else {
                            $update_info{sync}->{$dname}->{$oname}{del_success}++;
                        }
                    }
                }
            }
        }
    }

    if ($dn !~ /^$cluster_syncrdn/) {
        # get new present entry list
        undef $present_list;
        $present_list = $self->_getPresentList($checkfilter, $checkbase, @sync_data);
        if (!defined($present_list)) {
            return LDAP_OTHER;
        }

        $update_info{master} = {};
        foreach my $dname (@sync_data) {
            if ($dname eq $self->{master}->{current}) {
                next;
            }

            # check cluster status
            if ($cluster->{$dname}->{status} eq 'inactive') {
                next;
            }

            my $data = $self->{data}{$dname};
            my $sdata = $cluster->{$dname}->{conf};
            my ($sname) = keys %{$data->{conf}->{storage}};
            my $dcheckfilter = $checkfilter;
            my $dcheckbase = $checkbase;

            $dcheckfilter =~ s/$master->{suffix}/$data->{suffix}/i;
            $dcheckbase =~ s/$master->{suffix}$/$data->{suffix}/i;

            $update_info{master}->{$dname} = {};
            foreach my $oname (@{$sdata->{order}}) {
                my $sobject = $sdata->{object}{$oname};
                my %ops;
                $ops{add} = 0;
                $ops{modify} = 0;
                $ops{delete} = 0;

                if (!defined($sobject->{masterdn})) {
                    next;
                }

                $update_info{master}->{$dname}->{$oname} = {total => 0, add_total => 0, add_success => 0, mod_total => 0, mod_success => 0, del_total => 0, del_success =>0, skip => 0};
                foreach my $masterdn (@{$sobject->{masterdn}}) {
                    my $dbase;
                    my $dregexbase;
                    my $sbase;

                    if ($masterdn eq 'ou=disable') {
                        next;
                    } elsif ($masterdn eq '*') {
                        $dbase = $data->{suffix};
                        $dregexbase = $dbase;
                        $sbase = $master->{suffix};
                    } elsif ($masterdn =~ /[*+]/) {
                        $dbase = $data->{suffix};
                        $dregexbase = $masterdn.','.$data->{suffix};
                        $sbase = $master->{suffix};
                    } else {
                        $dbase = $masterdn.','.$data->{suffix};
                        $dregexbase = $dbase;
                        $sbase = $masterdn.','.$master->{suffix};
                    }

                    if (!defined($present_list->{$sbase})) {
                        next;
                    }

                    if ($dcheckbase && $dcheckbase !~ /$dregexbase$/i) {
                        next;
                    }

                    # synchronization filter
                    my $masterfilter = undef;
                    my $ocheckfilter = $dcheckfilter;
                    if (defined($sobject->{masterfilterobj})) {
                        $masterfilter = $sobject->{masterfilterobj};
                        $ocheckfilter = "(&$ocheckfilter$sobject->{masterfilter}[0])";
                    }
                    my $ocheckfilterobj = Net::LDAP::Filter->new($ocheckfilter);

                    if (defined($sobject->{masterop})) {
                        foreach my $op (@{$sobject->{masterop}}) {
                            if (!%opFlag || defined($opFlag{$op})) {
                                $ops{$op} = 1;
                                if ($op eq 'delete') {
                                    if (!defined($deletedn{$sbase})) {
                                        $deletedn{$sbase} = [];
                                    }
                                    push(@{$deletedn{$sbase}}, [$dname, $oname]);
                                }
                            }
                        }
                    } else {
                        foreach my $op (@{$sdata->{masterop}}) {
                            if (!%opFlag || defined($opFlag{$op})) {
                                $ops{$op} = 1;
                                if ($op eq 'delete') {
                                    if (!defined($deletedn{$sbase})) {
                                        $deletedn{$sbase} = [];
                                    }
                                    push(@{$deletedn{$sbase}}, [$dname, $oname]);
                                }
                            }
                        }
                    }

                    # synchronized attributes
                    my @sync_attrs;
                    if (defined($sobject->{masterattrs})) {
                        @sync_attrs = @{$sobject->{masterattrs}};
                    }

                    # get values from data storage
                    my @entries;
                    ($rc, @entries) = $self->_do_search($dcheckbase ? $dcheckbase : $dbase, 2, 0, $sizeLimit, $timeout, $ocheckfilter, 0, , ());
                    if ($rc && $rc != LDAP_NO_SUCH_OBJECT) {
                        $self->log(level => 'err', message => "Can't get values of $dname($rc)");
                        last DO;
                    }
                    $update_info{master}->{$dname}->{$oname}{total} += @entries;

                    # comare data storage's values with master one
                    for (my $i = 0; $i < @entries; $i++) {
                        if ($dcheckbase && $sobject->{dnignore}[0] ne 'on' && $entries[$i] !~ /^dn: [^\n]*$dcheckbase\n/i) {
                            next;
                        }

                        if ($sname eq 'CSV') {
                            if (!LISM::Storage->parseFilter($ocheckfilterobj, $entries[$i])) {
                                next;
                            }
                        }

                        my ($subdn) = ($entries[$i] =~ /^dn: (.*),$dbase\n/i);
                        if (!$subdn) {
                            next;
                        }
                        $subdn =~ tr/A-Z/a-z/;

                        my ($key) = ($entries[$i] =~ /^dn: (.*?)(?<!\\),/);
                        my ($rdn_attr, $rdn_val) = split(/=/, $key);
                        $key =~ tr/A-Z/a-z/;
                        if ($entries[$i] !~ /^$rdn_attr:/mi) {
                            $entries[$i] .= "$rdn_attr: $rdn_val\n";
                        }

                        my $mentry;
                        my $dstdn;
                        if (defined($present_list->{$sbase}{list}{$key})) {
                            if (defined($present_list->{$sbase}{list}{$key}->{$subdn})) {
                                $mentry = $present_list->{$sbase}{list}{$key}->{$subdn};
                            } else {
                                my @subdns = keys %{$present_list->{$sbase}{list}{$key}};
                                for (my $j = 0; $j < @subdns; $j++) {
                                    if ((defined($sobject->{unique}) && $subdns[$j] =~ /,$sobject->{unique}[0]->{base}$/i) ||
                                        $sobject->{dnignore}[0] eq 'on') {
                                        if (defined($sobject->{unique})) {
                                            $dstdn = $subdn;
                                        }
                                        $subdn = $subdns[$j];
                                        $mentry = $present_list->{$sbase}{list}{$key}->{$subdn};
                                    }
                                }
                            }
                        } elsif ($sobject->{dnignore}[0] eq 'on') {
                            $subdn =~ s/^([^,]+).*$/$1/;
                        }

                        my $dn = "$subdn,$sbase";
                        if (!$mentry) {
                            # add entry which doesn't exist in master storage
                            my ($rdn_attr) = ($key =~ /^([^=]+)=/);
                            my $entryStr;

                            foreach my $attr ($rdn_attr) {
                                $entryStr = $entryStr.join("\n", ($entries[$i] =~ /^($attr: .*)$/gmi))."\n";
                            }

                            if (!defined($sobject->{masterattrs})) {
                                @sync_attrs = $self->_unique(($entries[$i] =~ /\n([^:]+):/gi));
                            }

                            for (my $j = 0; $j < @sync_attrs; $j++) {
                                my $attr = $sync_attrs[$j];
                                my $sattr;

                                if ($attr =~ /^$rdn_attr$/i) {
                                    next;
                                }

                                if (defined($sobject->{masterattr})) {
                                    $sattr = $sobject->{masterattr}[$j];
                                }

                                if (defined($sattr->{op}) && !grep(/^add$/, @{$sattr->{op}})) {
                                    next;
                                }

                                if (defined($sattr->{filterobj}) && !LISM::Storage->parseFilter($sattr->{filterobj}, $entries[$i])) {
                                    next;
                                }

                                my @values = $self->_getAttrValues($entries[$i], $attr);
                                if (!@values) {
                                    next;
                                }

                                my @sync_vals = $self->_checkSyncAttrs($data, $master, $sattr, undef, @values);

                                if (@sync_vals) {
                                    foreach my $value (@sync_vals) {
                                        $entryStr = "$entryStr$attr: $value\n";
                                    }
                                }
                            }

                            if ($ops{add}) {
                                $rc = $self->_doUpdate('add', $dname, 1, undef, $dn, $entryStr);
                                $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr} = $entryStr;
                                $update_info{master}->{$dname}->{$oname}{add_total}++;
                                if ($rc) {
                                    $self->_writeSyncFail('add', $dname, $dn, $entryStr);
                                    $update_info{master}->{$dname}->{$oname}{skip}++;
                                } else {
                                    $update_info{master}->{$dname}->{$oname}{add_success}++;
                                }
                                if (defined($nosync_entries{'master'}{$dn})) {
                                    $self->auditlog('duplicate', $dn, 0, '');
                                } else {
                                    $nosync_entries{'master'}{$dn} = 1;
                                }
                            }
                        } else {
                            if ($dstdn) {
                                my $newpdn = "$dstdn,$sbase";
                                $newpdn =~ s/^[^,]+,//;
                                $rc = $self->_doUpdate('modify', $dname, 1, undef, $dn, ('REPLACE', 'lismparentdn', $newpdn));
                                if ($rc) {
                                    $self->_writeSyncFail('modify', $dname, $dn, ('REPLACE', 'lismparentdn', $newpdn));
                                } else {
                                    $dn = "$dstdn,$sbase";
                                }
                            }

                            # modify entry which isn't equal to data storage
                            my @modlist;
                            my $entryStr = $mentry->{entryStr};

                            if (!defined($sobject->{masterattrs})) {
                                @sync_attrs = $self->_unique(($mentry->{entryStr} =~ /^([^:]+):/gmi), ($entries[$i] =~ /\n([^:]+):/gi));
                            }

                            for (my $j = 0; $j < @sync_attrs; $j++) {
                                my $attr = $sync_attrs[$j];
                                my $sattr;
                                my @values;

                                if (defined($sobject->{masterattr})) {
                                    $sattr = $sobject->{masterattr}[$j];
                                }

                                if (defined($sattr->{op}) && !grep(/^modify$/, @{$sattr->{op}})) {
                                    next;
                                }

                                if (defined($sattr->{filterobj}) && !LISM::Storage->parseFilter($sattr->{filterobj}, $entries[$i])) {
                                    next;
                                }

                                @values = $self->_getAttrValues($entries[$i], $attr);
                                if (defined($sattr->{option}) && grep(/^notnull$/, @{$sattr->{option}}) && !@values) {
                                    next
                                }

                                my @sync_vals = $self->_checkSyncAttrs($data, $master, $sattr, undef, @values);
                                my $dvals = join(";", sort {lc $a cmp lc $b} @sync_vals);

                                my $synced_vals;
                                my $left_vals;
                                if ($attr =~ /^customAttribute$/i) {
                                    $synced_vals = [];
                                    $left_vals = [];
                                    my %cattrs;
                                    foreach my $sync_val (@sync_vals) {
                                        my ($cattr) = split(/#/, $sync_val);
                                        $cattrs{$cattr} = 1;
                                    }
                                    foreach my $cattr (keys(%cattrs)) {
                                        my @vals = ($mentry->{entryStr} =~ /^$cattr: (.*)$/gmi);
                                        if (@vals) {
                                            foreach my $val (@vals) {
                                                push(@{$synced_vals}, "$cattr#$val");
                                            }
                                        } else {
                                            push(@{$synced_vals}, "$cattr#");
                                        }
                                    }
                                } else {
                                    @values = $self->_getAttrValues($mentry->{entryStr}, $attr);
                                    ($synced_vals, $left_vals) = $self->_checkSyncedAttrs($master, $data, $sattr, @values);
                                }
                                my $pvals = join(";", sort {lc $a cmp lc $b} @{$synced_vals});

                                # ignore passowrd equality if hash type is differnt
                                if ($attr =~ /^userpassword$/i) {
                                    if (!$self->_cmpPwdHash($dname, $lism_master, $dvals, $pvals)) {
                                        next;
                                    }
                                }

                                $pvals =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                                if ($dvals !~ m/^$pvals$/i && $ops{modify}) {
                                    if (@{$left_vals}) {
                                        push(@sync_vals, @{$left_vals});
                                    }

                                    if (@sync_vals) {
                                        push(@modlist, ('REPLACE', $attr, @sync_vals));
                                    } else {
                                        push(@modlist, ('DELETE', $attr));
                                    }

                                    $entryStr =~ s/$attr: .*\n//gi;
                                    foreach my $value (@sync_vals) {
                                        $entryStr = "$entryStr\n$attr: $value";
                                    }
                                }
		            }

                            if (@modlist) {
                                if ($ops{modify}) {
                                    $rc = $self->_doUpdate('modify', $dname, 1, undef, $dn, @modlist);
                                    $mentry->{entryStr} = $entryStr;
                                    $update_info{master}->{$dname}->{$oname}{mod_total}++;
                                    if ($rc) {
                                        $self->_writeSyncFail('modify', $dname, $dn, @modlist);
                                        $update_info{master}->{$dname}->{$oname}{skip}++;
                                    } else {
                                        $update_info{master}->{$dname}->{$oname}{mod_success}++;
                                    }
                                }
                            }
                            if (defined($nosync_entries{'master'}{$dn})) {
                                $self->auditlog('duplicate', $dn, 0, '');
                            } else {
                                $nosync_entries{'master'}{$dn} = 1;
                            }
                        }

                        if ($rc) {
                            $self->log(level => 'err', message => "Synchronizing \"$dn\" failed($rc)".($continueFlag ? ": Skip operation" : ''));
                            if (!$continueFlag) {
                                last DO;
                            }
                            $rc = LDAP_SUCCESS;
                        }

                        if ($ops{delete}) {
                            $present_list->{$sbase}{list}{$key}->{$subdn}->{present} = 1;
                        }
                    }
                }
            }
        }

        # delete entries which don't exist in data storages
        foreach my $sbase (keys %deletedn) {
            for (my $i = 0; $i < @{$deletedn{$sbase}}; $i++) {
                my $sobject = $cluster->{${$deletedn{$sbase}}[$i][0]}->{conf}->{object}{${$deletedn{$sbase}}[$i][1]};

                # synchronization filter
                my $masterfilter = undef;
                if (defined($sobject->{masterfilterobj})) {
                    $masterfilter = $sobject->{masterfilterobj};
                }

                my @nosync_entries;
                foreach my $key (keys %{$present_list->{$sbase}{list}}) {
                    foreach my $subdn (keys %{$present_list->{$sbase}{list}{$key}}) {
                        if (!$present_list->{$sbase}{list}{$key}->{$subdn}->{present}) {
                            if (defined($masterfilter) &&
                                !LISM::Storage->parseFilter($masterfilter, $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr})) {
                                next;
                            }
                            if (defined($sobject->{delfilterobj}) && !LISM::Storage->parseFilter($sobject->{delfilterobj}, $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr})) {
                                next;
                            }

                            my $nosync_entry = "$subdn,$sbase";
                            my $num = split(/,/, $subdn);
                            if (!defined($nosync_entries[$num])) {
                                $nosync_entries[$num] = [];
                            }
                            push(@{$nosync_entries[$num]}, [${$deletedn{$sbase}}[$i][0], $nosync_entry]);
                            $present_list->{$sbase}{list}{$key}->{$subdn}->{present} = 1;
                        }
                    }
                }

                my $dname = ${$deletedn{$sbase}}[$i][0];
                my $oname = ${$deletedn{$sbase}}[$i][1];
                for (my $j = @nosync_entries; $j > 0; $j--) {
                    if (ref($nosync_entries[$j]) ne 'ARRAY') {
                        next;
                    }
                    foreach my $nosync_entry (@{$nosync_entries[$j]}) {
                        $rc = $self->_doUpdate('delete', undef, 1, undef, ${$nosync_entry}[1]);
                        $update_info{master}->{$dname}->{$oname}{del_total}++;
                        if ($rc) {
                            $self->log(level => 'err', message => "Synchronizing \"${$nosync_entry}[1]\" failed($rc)".($continueFlag ? ": Skip operation" : ''));
                            $self->_writeSyncFail('delete', ${$nosync_entry}[0], ${$nosync_entry}[1]);
                            if (!$continueFlag) {
                                last DO;
                            } else {
                                $update_info{master}->{$dname}->{$oname}{del_success}++;
                            }
                        }
                    }
                }
            }
        }
    }
  }

    $self->_syncSumary(%update_info);

    $self->log(level => 'info', message => "Differential synchronization finished");

    return $rc;
}

sub _getPresentList
{
    my $self = shift;
    my ($filterStr, $base, @data) = @_;
    my $conf = $self->{_lism};
    my $master = $self->{data}{$lism_master};
    my $cluster = $self->{cluster};
    my $timeout = $self->{_config}->{timeout};
    my $present_list = {};

    if (!defined($master->{suffix})) {
        return undef;
    }

    foreach my $dname (@data) {
        if ($cluster->{$dname}->{status} eq 'inactive') {
            next;
        }

        my $sdata = $cluster->{$dname}->{conf};

        foreach my $oname (keys %{$sdata->{object}}) {
            my $sobject = $sdata->{object}{$oname};

            foreach my $type ('syncdn', 'masterdn') {
                if (!defined($sobject->{$type})) {
                    next;
                }

                my $mfilter = $filterStr;
                if (defined($conf->{sync}[0]->{master}[0]->{filter}) && defined($conf->{sync}[0]->{master}[0]->{filter}{$oname})) {
                    $mfilter = '(&'.$mfilter.$conf->{sync}[0]->{master}[0]->{filter}{$oname}->{content}.')';
                }
                $mfilter = "(&(lismControl=undeleted=true)$mfilter)";
                foreach my $typedn (@{$sobject->{$type}}) {
                    my $sbase;
                    my $regexbase;

                    if ($typedn eq 'ou=disable') {
                        next;
                    } elsif ($typedn eq '*') {
                        $sbase = $master->{suffix};
                        $regexbase = $sbase;
                    } elsif ($typedn =~ /[*+]/) {
                        $sbase = $master->{suffix};
                        $regexbase = $typedn.','.$master->{suffix};
                    } else {
                        $sbase = $typedn.','.$master->{suffix};
                        $regexbase = $sbase;
                    }

                    if ($base && $base !~ /$sbase$/i) {
                        next;
                    }

                    if (defined($present_list->{$sbase})) {
                        next;
                    }

                    my ($rc, @entries) = $self->_do_search($base ? $base : $sbase, 2, 0, $sizeLimit, $timeout, $mfilter, 0, ());
                    if ($rc) {
                        $self->log(level => 'err', message => "Getting present entries list on ".($base ? $base : $sbase)." failed($rc)");
                        if ($rc != LDAP_NO_SUCH_OBJECT) {
                            return undef;
                        }
                    }

                    $present_list->{$sbase} = {};
                    $present_list->{$sbase}{count} = @entries;
                    $present_list->{$sbase}{list} = {};
                    for (my $i = 0; $i < @entries; $i++) {
                        my ($subdn) = ($entries[$i] =~ /^dn: (.*),$sbase\n/i);

                        if (!$subdn) {
                            next;
                        }
                        $subdn =~ tr/A-Z/a-z/;

                        my ($key) = ($entries[$i] =~ /^dn: (.*?)(?<!\\),/);
                        $key =~ tr/A-Z/a-z/;

                        my $entryStr;
                        ($entryStr = $entries[$i]) =~ s/^dn:.*\n//;
                        $entryStr = $self->_decBase64Entry($entryStr);
                        $present_list->{$sbase}{list}{$key}->{$subdn}->{entryStr} = $entryStr;
                        $present_list->{$sbase}{list}{$key}->{$subdn}->{present} = 0;
                    }
                }
            }
        }
    }

    return $present_list;
}

sub _syncSumary
{
    my $self = shift;
    my (%update_info) = @_;

    foreach my $type (keys %update_info) {
        foreach my $dname (keys %{$update_info{$type}}) {
            foreach my $oname (keys %{$update_info{$type}->{$dname}}) {
                my %info = %{$update_info{$type}->{$dname}->{$oname}};
                $self->log(level => 'info', message => "Data=$dname Object=$oname Total=$info{total} Add=$info{add_total}($info{add_success} succeeded) Modify=$info{mod_total}($info{mod_success} succeeded) Delete=$info{del_total}($info{del_success} succeeded) Error/Skip=$info{skip}");
            }
        }
    }
    return;
}

sub _checkSyncFlag
{
    my $self = shift;
    my ($syncflag, $dn, $entryStr, $cache, $attrmapp, $memberattrmapp, $syncdnp) = @_;

    if ($dn !~ /$syncflag->{match}/i) {
        return 1;
    }

    my $flagdn = $syncflag->{dn};

    my @matches = ($dn =~ /$syncflag->{match}/i);
    for (my $i = 0; $i < @matches; $i++) {
        my $num = $i + 1;
        $flagdn =~ s/\%$num/$matches[$i]/g;
    }

    my $key = $flagdn.'#'.$syncflag->{filter};
    if ($cache && defined(${$cache}{$key})) {
        if ($attrmapp && defined($syncflag->{attrmap}) && defined(${$cache}{'attrmap_'.$key})) {
            $attrmapp = ${$cache}{'attrmap_'.$key};
        }
        if ($memberattrmapp && defined($syncflag->{memberattrmap}) && defined(${$cache}{'memberattrmap_'.$key})) {
            $memberattrmapp = ${$cache}{'memberattrmap_'.$key};
        }
        if ($syncdnp && defined($syncflag->{syncdn}) && defined(${$cache}{'syncdn_'.$key})) {
            @{$syncdnp} = @{${$cache}{'syncdn_'.$key}};
        }
        if (defined($syncflag->{attr}) && ref(${$cache}{$key}) eq 'ARRAY') {
            if (!$entryStr) {
                return 1;
            }
            my @filters = @{${$cache}{$key}};
            my $match = 0;
            foreach my $filter (@filters) {
                if (LISM::Storage->parseFilter(${$filter}, $entryStr)) {
                    $match = 1;
                    last;
                }
            }
            return $match;
        } else {
            return ${$cache}{$key};
        }
    }

    my @attrs = defined($syncflag->{attr}) ? split(/, */, $syncflag->{attr}) : ('objectClass');
    if (defined($syncflag->{attrmap})) {
        push(@attrs, $syncflag->{attrmap});
    }
    if (defined($syncflag->{memberattrmap})) {
        push(@attrs, $syncflag->{memberattrmap});
    }
    if (defined($syncflag->{syncdn})) {
        push(@attrs, $syncflag->{syncdn});
    }
    my ($rc, $flagEntry) = $self->_do_search($flagdn, 2, 0, 0, $self->{_config}->{timeout}, $syncflag->{filter}, 0, @attrs);
    if (!$rc) {
        if ($flagEntry) {
            if ($attrmapp && defined($syncflag->{attrmap})) {
                my %attrmap;
                my $attr = $syncflag->{attrmap};
                my @values = ($flagEntry =~ /^$attr: (.+)$/gmi);
                foreach my $value (@values) {
                    my @elts = split(/=/, $value, 2);
                    if (@elts == 2) {
                        $attrmap{lc($elts[0])} = $elts[1];
                    }
                }
                if (keys(%attrmap)) {
                    ${$cache}{'attrmap_'.$key} = \%attrmap;
                }
                %{$attrmapp} = %attrmap;
            }
            if ($memberattrmapp && defined($syncflag->{memberattrmap})) {
                my %memberattrmap;
                my $attr = $syncflag->{memberattrmap};
                my @values = ($flagEntry =~ /^$attr: (.+)$/gmi);
                foreach my $value (@values) {
                    my @elts = split(/=/, $value, 2);
                    if (@elts == 2) {
                        $memberattrmap{lc($elts[0])} = $elts[1];
                    }
                }
                if (keys(%memberattrmap)) {
                    ${$cache}{'memberattrmap_'.$key} = \%memberattrmap;
                }
                %{$memberattrmapp} = %memberattrmap;
            }
            if ($syncdnp && defined($syncflag->{syncdn})) {
                my @syncdn;
                my $attr = $syncflag->{syncdn};
                my @values = ($flagEntry =~ /^$attr: (.+)$/gmi);
                foreach my $value (@values) {
                    if ($value && $value !~ /^ *$/) {
                        push(@syncdn, $value);
                    }
                }
                if (@syncdn) {
                    ${$cache}{'syncdn_'.$key} = \@syncdn;
                }
                @{$syncdnp} = @syncdn;
            }
            if (defined($syncflag->{attr})) {
                my @values;
                foreach my $attr (@attrs) {
                    push(@values, ($flagEntry =~ /^$attr: (.+)$/gmi));
                }
                my $match = 0;
                my @filters;
                foreach my $value (@values) {
                    if ($value =~ /^ *$/) {
                        next;
                    }
                    my $filterStr = $syncflag->{entryfilter};
                    $filterStr =~ s/\%a/$value/g;
                    my $filter = Net::LDAP::Filter->new($filterStr);
                    if (defined($filter)) {
                        push(@filters, \$filter);
                        if (!$entryStr) {
                            $match = 1;
                        } elsif (!$match && LISM::Storage->parseFilter($filter, $entryStr)) {
                            $match = 1;
                        }
                    } else {
                        $self->log(level => 'err', message => "syncflag filter is invalid: $filterStr");
                    }
                }
                if ($cache) {
                    ${$cache}{$key} = \@filters;
                }
                return $match;
            } else {
                if ($cache) {
                    ${$cache}{$key} = 1;
                }
            }
            return 1;
        } else {
            if ($cache) {
                 ${$cache}{$key} = 0;
            }
            return 0;
        }
    } else {
        return 0;
    }
}

sub _decBase64Entry
{
    my $self = shift;
    my ($entryStr) = @_;

    while ($entryStr =~ /^([^:]+):\:\s*(.+)$/im) {
        my $attr = $1;
        my $decoded = decode_base64($2);
        if (Encode::is_utf8($entryStr)) {
            $decoded = decode('utf8', $decoded);
        }
        $decoded =~ s/(\r\n|\r|\n)/\r/g;
        $entryStr =~ s/^$attr:\:\s*.+$/$attr: $decoded/m;
    }

    return $entryStr;
}

sub _getAttrValues
{
    my $self = shift;
    my ($entryStr, $attr) = @_;
    my @values;

    $entryStr = $self->_decBase64Entry($entryStr);
    @values = $entryStr =~ /^$attr: (.*)$/gmi;

    return @values;
}

sub _checkSyncData
{
    my $self = shift;
    my ($dname, $type, $entryStr, $func, $dn, @info) = @_;
    my $conf = $self->{_lism};
    my $master = $self->{data}{$lism_master};
    my $cluster = $self->{cluster};

    # check cluster status
    if ($cluster->{$dname}->{status} eq 'inactive') {
        return undef;
    }

    my $ddn = $dn;
    my $data = $self->{data}{$dname};
    my @dinfo = ();
    my $sdata = $cluster->{$dname}->{conf};
    my $sobject;
    my $sbase;
    my $sregexbase;
    my %attrmap;
    my %memberattrmap;
    my @syncdns;
    my %ops;
    $ops{add} = 0;
    $ops{modify} = 0;
    $ops{delete} = 0;

    foreach my $op (@{$sdata->{syncop}}) {
        $ops{$op} = 1;
    }

    # operation should be synchronized or not
    if (!$ops{$func}) {
        return undef;
    }

    # get object synchronized
    foreach my $oname (keys %{$sdata->{object}}) {
        if (!defined($sdata->{object}{$oname}->{syncdn})) {
            next;
        }
        if (defined($sdata->{object}{$oname}->{syncop})) {
            if (!grep(/^$func$/, @{$sdata->{object}{$oname}->{syncop}})) {
                next;
            }
        }

        foreach my $syncdn (@{$sdata->{object}{$oname}->{syncdn}}) {
            if ($syncdn eq '*') {
                $sbase = $master->{suffix};
                $sregexbase = $sbase;
            } elsif ($syncdn =~ /[*+]/) {
                $sbase = $master->{suffix};
                $sregexbase = $syncdn.','.$master->{suffix};
            } else {
                $sbase = $syncdn.','.$master->{suffix};
                $sregexbase = $sbase;
            }
            if ($dn =~ /,$sregexbase$/i) {
                # check need for synchronization
                if (defined($sdata->{object}{$oname}->{syncflag})) {
                    if (!$self->_checkSyncFlag($sdata->{object}{$oname}->{syncflag}[0], $dn, $entryStr, undef, \%attrmap, \%memberattrmap, \@syncdns)) {
                        next;
                    }
                }
                if (defined($sdata->{object}{$oname}->{synctype}) && $sdata->{object}{$oname}->{synctype}[0] ne $type && $func ne 'modify') {
                    next;
                }
                if (defined($sdata->{object}{$oname}->{syncfilterobj})) {
                    if (!LISM::Storage->parseFilter($sdata->{object}{$oname}->{syncfilterobj}, "$dn\n$entryStr")) {
                        next;
                    }
                }
                if ($func eq 'delete' && defined($sdata->{object}{$oname}->{delfilterobj})) {
                    if (!LISM::Storage->parseFilter($sdata->{object}{$oname}->{delfilterobj}, "$dn\n$entryStr")) {
                        next;
                    }
                }
                if (@syncdns) {
                    my $match = 0;
                    foreach my $checkdn (@syncdns) {
                        if ($dn =~ /$checkdn/i) {
                            $match = 1;
                            last;
                        }
                    }
                    if (!$match) {
                        next;
                    }
                }
                $sobject = $sdata->{object}{$oname};
                last;
            }
        }
        if ($sobject) {
            last;
        }
    }

    if (!$sobject) {
        return undef;
    }

    # replace dn to dn in the data entry
    $ddn =~ s/$master->{suffix}/$data->{suffix}/i;
    if ($sobject->{dnignore}[0] eq 'on') {
        my $dbase;
        if ($sbase eq $sregexbase) {
            ($dbase = $sbase) =~ s/$master->{suffix}$/$data->{suffix}/i;
        } else {
            my $dregexbase;
            ($dregexbase = $sregexbase) =~ s/$master->{suffix}$/$data->{suffix}/i;
            ($dbase) = ($ddn =~ /($dregexbase)$/i);
        }
        if ($dbase eq $data->{suffix}) {
            $ddn =~ s/^([^,]+,[^,]+),.*$/$1,$dbase/;
        } else {
            $ddn =~ s/^([^,]+),.*$/$1,$dbase/;
        }
    }
    $ddn =~ tr/A-Z/a-z/;

    my ($rdn_attr) = ($dn =~ /^([^=]+)=/);
    if (defined($attrmap{lc($rdn_attr)})) {
        my $attr = $attrmap{lc($rdn_attr)};
        my ($rdn_val) = ($entryStr =~ /^$attr: (.+)$/mi);
        $ddn =~ s/^$rdn_attr=[^,]+/$rdn_attr=$rdn_val/i;
    }

    # get attributes synchronized
    if ($func eq 'add') {
        my $attr = defined($attrmap{lc($rdn_attr)}) ? $attrmap{lc($rdn_attr)} : $rdn_attr;
        my ($rdn_val) = ($info[0] =~ /^$attr: (.*)$/mi);
        $dinfo[0] = "$rdn_attr: $rdn_val\n";

        my @sync_attrs;
        if (defined($sobject->{syncattrs})) {
            @sync_attrs = @{$sobject->{syncattrs}};
        } else {
            @sync_attrs = $self->_unique($info[0] =~ /^([^:]+):/gmi);
        }

        for (my $j = 0; $j < @sync_attrs; $j++) {
            my $attr = $sync_attrs[$j];
            my $sync_attr = $attr;
            my $sattr;

            if ($attr =~ /^$rdn_attr$/i) {
                next;
            }

            if (defined($attrmap{lc($attr)})) {
                $attr = $attrmap{lc($attr)};
            }

            if (defined($sobject->{syncattr})) {
                $sattr = $sobject->{syncattr}[$j];
            }

            if (defined($sattr->{type}) && $type eq 'differential' && $sattr->{type}[0] ne $type) {
                next;
            }

            if (defined($sattr->{op}) && !grep(/^add$/, @{$sattr->{op}})) {
                next;
            }

            if (defined($sattr->{filterobj}) && !LISM::Storage->parseFilter($sattr->{filterobj}, $info[0])) {
                next;
            }

            my @values = $info[0] =~ /^$attr: (.*)$/gmi;
            my @sync_vals = $self->_checkSyncAttrs($master, $data, $sattr, \%memberattrmap, @values);
            if (@sync_vals) {
                foreach my $value (@sync_vals) {
                    $dinfo[0] = "$dinfo[0]$sync_attr: $value\n";
                }
            }
        }

        if (!$dinfo[0]) {
            return undef;
        }
    } elsif ($func eq 'modify') {
        my @tmp = @info;
        my $forcesync = 0;
        my $nosyncattr = 0;
        my $decEntryStr = $self->_decBase64Entry($entryStr);
        my @updated_attrs;
        while (@tmp > 0) {
            my $action = shift @tmp;
            my $attr   = lc(shift @tmp);
            my @values;
            my $sattr;

            while (@tmp > 0 && $tmp[0] ne "ADD" && $tmp[0] ne "DELETE" && $tmp[0] ne "REPLACE") {
                push(@values, shift @tmp);
            }

            if (defined($attrmap{$attr}) && $attrmap{$attr} !~ /^$attr$/i) {
                next;
            }

            if ($attr =~ /^$rdn_attr$/i && (!defined($sobject->{synctype}) || $sobject->{synctype}[0] eq $type)) {
                if (@values) {
                    push(@dinfo, $action, $attr, @values);
                }
                next;
            }

            if (defined($sobject->{forcesyncattr}) && grep(/^$attr$/i, @{$sobject->{forcesyncattr}})) {
                $forcesync = 1;
            }

            my $sync_attr = $attr;
            if (defined($sobject->{syncattrs})) {
                foreach my $key (keys(%attrmap)) {
                    if ($attrmap{$key} =~ /^$attr$/i) {
                        $sync_attr = $key;
                    }
                }
                for (my $i = 0; $i < @{$sobject->{syncattrs}}; $i++) {
                    if ($sync_attr =~ /^$sobject->{syncattrs}[$i]$/i) {
                        $sattr = $sobject->{syncattr}[$i];
                        last;
                    }
                }

                if (!$sattr) {
                    if ($sync_attr =~ /^$rdn_attr$/i && (!defined($sobject->{synctype}) || $sobject->{synctype}[0] eq $type)) {
                        if (@values) {
                            push(@dinfo, $action, $sync_attr, @values);
                        }
                    }
                    next;
                }

                if (defined($sobject->{synctype}) && $sobject->{synctype}[0] ne $type &&
                    (!defined($sattr->{type}) || $sattr->{type}[0] ne $type)) {
                    next;
                }

                if (defined($sattr->{type}) && $sattr->{type}[0] ne $type) {
                    next;
                }

                if (defined($sattr->{op}) && !grep(/^modify$/, @{$sattr->{op}})) {
                    next;
                }

                if (defined($sattr->{option}) && grep(/^notnull$/, @{$sattr->{option}}) && !@values) {
                    next
                }

                if (defined($sattr->{filterobj}) && !LISM::Storage->parseFilter($sattr->{filterobj}, $entryStr)) {
                    $nosyncattr = 1;
                    next;
                }
            } elsif (defined($sobject->{synctype}) && $sobject->{synctype}[0] ne $type) {
                next;
            }

            my @sync_vals = $self->_checkSyncAttrs($master, $data, $sattr, \%memberattrmap, @values);
            if (@sync_vals) {
                push(@dinfo, $action, $sync_attr, @sync_vals);
            } elsif (($action eq "REPLACE" || $action eq "DELETE") && (!@values || !$values[0])) {
                push(@dinfo, $action, $sync_attr);
            }
            push(@updated_attrs, $sync_attr);
        }

        if (!@dinfo) {
            if (($forcesync || $nosyncattr) && (!defined($sobject->{synctype}) || $sobject->{synctype}[0] eq $type)) {
                return ($ddn);
            }
            return undef;
        } elsif (defined($sobject->{useprevious}) && $sobject->{useprevious}[0] && $sobject->{useprevious} ne 'off') {
            my @sync_attrs;
            my @useprev_attrs;
            if ($sobject->{useprevious}[0] ne 'on') {
                @useprev_attrs = split(/, */, $sobject->{useprevious}[0]);
            }
            if (defined($sobject->{syncattrs})) {
                @sync_attrs = @{$sobject->{syncattrs}};
            } else {
                @sync_attrs = $self->_unique($entryStr =~ /^([^:]+):/gmi);
            }
            for (my $i = 0; $i < @sync_attrs; $i++) {
                if (@useprev_attrs && !grep(/^$sync_attrs[$i]$/i, @useprev_attrs)) {
                    next;
                }
                if (!grep(/^$sync_attrs[$i]$/i, @updated_attrs)) {
                    my $sattr;
                    if (defined($sobject->{syncattrs})) {
                        $sattr = $sobject->{syncattr}[$i];
                        if (defined($sattr->{type}) && $sattr->{type}[0] =~ /^(realtime|task)$/) {
                            next;
                        }
                    }
                    my $sync_attr = defined($attrmap{lc($sync_attrs[$i])}) ? $attrmap{lc($sync_attrs[$i])} : $sync_attrs[$i];
                    my @vals = ($decEntryStr =~ /^$sync_attr: +(.+)$/gmi);
                    if (@vals && defined($vals[0]) && $vals[0] ne '') {
                        my @tmpvals;
                        foreach my $val (@vals) {
                            $val =~ s/$master->{suffix}$/$data->{suffix}/i;
                            if ($sattr && defined($sattr->{rule})) {
                                my $doSyncAttr = 1;
                                foreach my $rule (@{$sattr->{rule}}) {
                                    if ($val !~ /$rule/i) {
                                        $doSyncAttr = 0;
                                        last;
                                    }
                                }
                                if (!$doSyncAttr) {
                                    next;
                                }
                            }
                            if ($sattr && defined($sattr->{notrule})) {
                                my $doSyncAttr = 1;
                                foreach my $notrule (@{$sattr->{notrule}}) {
                                    if ($val =~ /$notrule/i) {
                                        $doSyncAttr = 0;
                                        last;
                                    }
                                }
                                if (!$doSyncAttr) {
                                    next;
                                }
                            }
                            if ($sattr && defined($sattr->{memberfilter})) {
                                my $match = 0;
                                foreach my $memberfilter (@{$sattr->{memberfilter}}) {
                                    if (!defined($memberfilter->{dn}) || $val =~ /$memberfilter->{dn}/i) {
                                        if (!defined($memberfilter->{filter})) {
                                            $match = 1;
                                            last;
                                        }
                                        my ($rc, $entry) = $self->_do_search($val, 0, 0, 1, 0, $memberfilter->{filter}, 0, 'objectClass');
                                        if (!$rc && $entry) {
                                            $match = 1;
                                            last;
                                        } elsif ($rc) {
                                            $self->log(level => 'err', message => "Checking member $val failed by $memberfilter->{filter} : $rc");
                                        }
                                    }
                                }
                                if (!$match) {
                                    next;
                                }
                            }
                            push(@tmpvals, $val);
                        }
                        if (@tmpvals) {
                            if (@useprev_attrs) {
                                unshift(@dinfo, 'REPLACE', $sync_attrs[$i], @tmpvals);
                            } else {
                                push(@dinfo, 'REPLACE', $sync_attrs[$i], @tmpvals);
                            }
                        }
                    }
                }
            }
        }
    } else {
        if ($func eq 'delete') {
            if ($sobject->{dnignore}[0] eq 'on') {
                my ($rdn) = ($dn =~ /^([^,]+),/);
                my $num = 0;
                foreach my $syncdn (@{$sobject->{syncdn}}) {
                    my $sbase;
                    if ($syncdn eq '*') {
                        $sbase = $master->{suffix};
                    } elsif ($syncdn =~ /[*+]/) {
                        ($sbase) = ($dn =~ /($sregexbase)$/i);
                    } else {
                        $sbase = $syncdn.','.$master->{suffix};
                    }
                    my ($rc, @entries) = $self->_do_search($sbase, 2, 0, 0, $self->{_config}->{timeout}, "($rdn)");
                    if (!$rc) {
                        $num += @entries;
                    }
                }
                if ($num > 1) {
                    return undef;
                }
            }
            if (defined($sobject->{rename}) && @info) {
                my $oldrdn_val;
                for (my $i = 0; $i < @info; $i++) {
                    if ($info[$i] =~ /^$sobject->{rename}[0]->{oldrdn}$/i) {
                        $oldrdn_val = $info[$i+1];
                        last;
                    }
                }
                if ($oldrdn_val) {
                    $ddn =~ s/^[^,]+/$sobject->{rename}[0]->{rdn}=$oldrdn_val/i;
                }
            }
        }

        @dinfo = @info;
    }

    return ($ddn, @dinfo);
}

sub _checkSyncAttrs
{
    my $self = shift;
    my ($src_data, $dst_data, $sattr, $memberattrmapp, @values) = @_;
    my @sync_vals = ();
    my %memberattrmap = $memberattrmapp ? %{$memberattrmapp} : undef;

    foreach my $value (@values) {
        # check attribute synchronization rule
        my $encval = encode('utf8', $value);
        if ($sattr && defined($sattr->{rule})) {
            my $doSyncAttr = 1;
            foreach my $rule (@{$sattr->{rule}}) {
                if ($encval !~ /^ *$/ && $encval !~ /$rule/i) {
                    $doSyncAttr = 0;
                    last;
                }
            }
            if (!$doSyncAttr) {
                next;
            }
        }

        if ($sattr && defined($sattr->{notrule})) {
            my $doSyncAttr = 1;
            foreach my $notrule (@{$sattr->{notrule}}) {
                if ($encval =~ /$notrule/i) {
                    $doSyncAttr = 0;
                    last;
                }
            }
            if (!$doSyncAttr) {
                next;
            }
        }

        if (%memberattrmap && $value =~ /^([^=]+)=([^,]+),/) {
            my $mrdn_attr = $1;
            my $mrdn_val = $2;
            if (grep(/^$mrdn_attr$/i, keys(%memberattrmap))) {
                my $rdn_attr;
                foreach my $attr (keys(%memberattrmap)) {
                    if ($attr =~ /^$mrdn_attr$/i) {
                        $rdn_attr = $memberattrmap{$attr};
                        last;
                    }
                }
                my $filter = '(objectClass=*)';
                if ($sattr && defined($sattr->{memberfilter})) {
                    foreach my $memberfilter (@{$sattr->{memberfilter}}) {
                        if (!defined($memberfilter->{dn}) || $value =~ /$memberfilter->{dn}/i) {
                            if (defined($memberfilter->{filter})) {
                                $filter = $memberfilter->{filter};
                            }
                            last;
                        }
                    }
                }
                my ($rc, $entryStr) = $self->_do_search($value, 0, 0, 1, 0, $filter, 0, $rdn_attr);
                if ($rc && $rc != LDAP_NO_SUCH_OBJECT) {
                    $self->log(level => 'err', message => "Can't get master entry of $value($rc)");
                } elsif ($entryStr) {
                    my ($rdn_val) = ($entryStr =~ /^$rdn_attr: (.*)$/mi);
                    my $regex_val = $mrdn_val;
                    $regex_val =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                    $value =~ s/^$mrdn_attr=$regex_val/$mrdn_attr=$rdn_val/;
                } else {
                    next;
                }
            }
        }

        if (!%memberattrmap && $sattr && defined($sattr->{memberfilter})) {
            my $match = 0;
            foreach my $memberfilter (@{$sattr->{memberfilter}}) {
                if (!defined($memberfilter->{dn}) || $value =~ /$memberfilter->{dn}/i) {
                    if (!defined($memberfilter->{filter})) {
                        $match = 1;
                        last;
                    }
                    my ($rc, $entry) = $self->_do_search($value, 0, 0, 1, 0, $memberfilter->{filter}, 0, 'objectClass');
                    if (!$rc && $entry) {
                        $match = 1;
                        last;
                    } elsif ($rc) {
                        $self->log(level => 'err', message => "Checking member $value failed by $memberfilter->{filter} : $rc");
                    }
                }
            }
            if (!$match) {
                next;
            }
        }

        if (!defined($sattr->{option}) || !grep(/^noreplacedn$/, @{$sattr->{option}})) {
            # replace suffix of dn values
            $value =~ s/$src_data->{suffix}$/$dst_data->{suffix}/i;

            # don't synchronize values of dn which isn't in this data directory
            if (!$dst_data->{manageDIT} && $value =~ /$self->{_config}->{basedn}$/i &&
                $value !~ /$dst_data->{suffix}$/i) {
                next;
            }
        }

        push(@sync_vals, $value);
    }

    return @sync_vals; 
}

sub _checkSyncedAttrs
{
    my $self = shift;
    my ($src_data, $dst_data, $sattr, @values) = @_;
    my @synced_vals = ();
    my @left_vals = ();

    foreach my $value (@values) {
        my $doSyncAttr = 1;

        # check attribute synchronization rule
        if ($sattr && defined($sattr->{rule})) {
            my $tmpval = $value;

            # replace suffix of dn values
            $tmpval =~ s/$src_data->{suffix}$/$dst_data->{suffix}/i;

            foreach my $rule (@{$sattr->{rule}}) {
                if ($tmpval !~ /$rule/i) {
                    $doSyncAttr = 0;
                    last;
                }
            }
        }

        if ($sattr && defined($sattr->{notrule})) {
            my $tmpval = $value;

            # replace suffix of dn values
            $tmpval =~ s/$src_data->{suffix}$/$dst_data->{suffix}/i;

            foreach my $notrule (@{$sattr->{notrule}}) {
                if ($tmpval =~ /$notrule/i) {
                    $doSyncAttr = 0;
                    last;
                }
            }
        }

        if ($sattr && defined($sattr->{memberfilter})) {
            my $match = 0;
            foreach my $memberfilter (@{$sattr->{memberfilter}}) {
                if (!defined($memberfilter->{dn}) || $value =~ /$memberfilter->{dn}/i) {
                    if (!defined($memberfilter->{filter})) {
                        $match = 1;
                        last;
                    }
                    my ($rc, $entry) = $self->_do_search($value, 0, 0, 1, 0, $memberfilter->{filter}, 0, 'objectClass');
                    if (!$rc && $entry) {
                        $match = 1;
                        last;
                    } elsif ($rc) {
                        $self->log(level => 'err', message => "Checking member $value failed by $memberfilter->{filter} : $rc");
                    }
                }
            }
            if (!$match) {
                $doSyncAttr = 0;
            }
        }

        if ($doSyncAttr) {
            push(@synced_vals, $value);
        } else {
            push(@left_vals, $value);
        }
    }

    return (\@synced_vals, \@left_vals);
}

sub _cmpPwdHash
{
    my $self = shift;
    my ($dname1, $dname2, $val1, $val2) = @_;
    my $salt;

    my $storage1 = $self->_getStorage($dname1);
    my $storage2 = $self->_getStorage($dname2);
    if (!$storage1 || !$storage2) {
        return 0;
    }

    my $shtype1 = $storage1->hashType();
    my $shtype2 = $storage2->hashType();
    my $phtype1 = $shtype1;
    my $phtype2 = $shtype2;
    if ($val1) {
        if ($val1 =~ /^{([^}]+)}/) {
            $phtype1 = $1;
        } else {
            $phtype1 = 'PLAINTEXT';
            $val1 = "{$phtype1}$val1";
        }
    }
    if ($val2) {
        if ($val2 =~ /^{([^}]+)}/) {
            $phtype2 = $1;
        } else {
            $phtype2 = 'PLAINTEXT';
            $val2 = "{$phtype2}$val2";
        }
    }

    $val1 =~ s/^\{[^\}]+\}//;
    $val2 =~ s/^\{[^\}]+\}//;
    if ($phtype1 eq $phtype2) {
        return 1;
    } elsif ($phtype1 eq 'PLAINTEXT') {
        if ($storage2->cmpPasswd($val1, $val2, $phtype2)) {
            return 0;
        } else {
            return 1;
        }
    } elsif ($phtype2 eq 'PLAINTEXT') {
        if ($storage1->cmpPasswd($val2, $val1, $phtype1)) {
            return 0;
        } else {
            return 1;
        }
    } elsif ($phtype1 eq $shtype2 || $shtype2 eq 'PLAINTEXT') {
        return 1;
    }

    return 0;
}

sub _unique
{
    my $self = shift;
    my @array = @_;

    my %hash = map {lc($_) => $_} @array;

    return values %hash;
}

sub _getDataName
{
    my $self = shift;
    my ($dn) = @_;

    foreach my $dname (keys %{$self->{data}}) {
        if (defined($self->{data}{$dname}->{suffix}) &&
            $dn =~ /$self->{data}{$dname}->{suffix}$/i) {
            return $dname;
        }
    }

    return undef;
}

sub _getStorage
{
    my $self = shift;
    my ($dname) = @_;

    if (defined($self->{_storage}{$dname})) {
        return $self->{_storage}{$dname};
    } else {
        return undef;
    }
}

sub _writeLdif
{
    my $self = shift;
    my ($file, $func, $dname, $dn, @info) = @_;
    my $conf = $self->{_config};
    my $fd;
    my $ldif;

    my $file_create = -f $file ? 0 : 1;

    if (!open($fd, ">> $file")) {
        $self->log(level => 'crit', message => "Can't open file: $file");
        return -1;
    }

    flock($fd, 2);
    $ldif = "# ".strftime("%Y%m%d%H%M%S", localtime(time))."\ndn: $dn\nchangetype: $func\n";

    if ($func eq 'modify') {
        while (@info > 0) {
            my $action = shift @info;
            my $attr = shift @info;
            my @values;

            while (@info > 0 && $info[0] ne "ADD" && $info[0] ne "DELETE" && $info[0] ne "REPLACE") {
                push(@values, shift @info);
            }

            $ldif = $ldif.lc($action).": $attr\n";
            foreach my $val (@values) {
                $ldif = "$ldif$attr: $val\n";
            }
            $ldif = "$ldif-\n";
        }
    } elsif ($func eq 'add') {
        $ldif = "$ldif$info[0]";
    } elsif ($func eq 'modrdn') {
        $ldif = $ldif."newrdn: $info[0]\ndeleteoldrdn: $info[1]\n";
    }

    $ldif = encode('utf8', $ldif);
    print $fd "$ldif\n";

    close($fd);

    if ($file_create) {
        chmod(0660, $file);
        if (defined($conf->{syncdiruid})) {
            chown($conf->{syncdiruid}, $conf->{syncdirgid}, $file);
        }
    }

    return 0;
}

sub _writeSyncFail
{
    my $self = shift;
    my ($func, $dname, $dn, @info) = @_;
    my $conf = $self->{_config};
    my $fd;
    my $ldif;

    if (!defined($conf->{syncdir})) {
        return 0;
    }

    return $self->_writeLdif("$conf->{syncdir}/$syncFailLog-$dname.log", @_);
}

sub _writeUpdateLog
{
    my $self = shift;
    my ($func, $dname, $dn, @info) = @_;
    my $conf = $self->{_config};
    my $fd;
    my $ldif;

    if (!defined($conf->{updatelog})) {
        return 0;
    }

    my $file = $conf->{updatelog}."-$dname.log";
    if ($file !~ /^\//) {
        if (!defined($conf->{syncdir})) {
            return 0;
        }
        $file = "$conf->{syncdir}/$file";
    }

    return $self->_writeLdif($file, @_);
}

sub _auditMsg
{
    my $self = shift;
    my ($type, $dn, $result, $error, @info) = @_;
    my $message = '';
    my $maxvallen = 255;
    if (!$error) {
        $error = '';
    }

    if ($error eq 'LISM_NO_OPERATION') {
        return $message;
    }

    my $mfmatch;
    my $mfsubstitute;
    if (defined($self->{_config}->{memberformat})) {
        $mfmatch = ${$self->{_config}->{memberformat}}[0];
        $mfsubstitute = ${$self->{_config}->{memberformat}}[1];
    }

    if ($type eq 'modify') {
        while (@info > 0) {
            my $action = shift @info;
            my $attr = shift @info;
            my @values;
            my $dsn;

            while (@info > 0 && $info[0] ne "ADD" && $info[0] ne "DELETE" && $info[0] ne "REPLACE") {
                my $value = shift @info;
                if (length($value) <= $maxvallen) {
                    if ($mfmatch && $attr =~ /^(member|seciossMember)$/i) {
                        eval "\$value =~ s/$mfmatch/$mfsubstitute/i";
                    }
                    push(@values, $value);
                }
            }

            if ($attr =~ /^(lismPreviousEntry|modifyTimestamp)$/i) {
                next;
            }

            if ($action eq "ADD") {
                $dsn = '+';
            } elsif ($action eq "DELETE") {
                $dsn = '-';
            } else {
                $dsn = '=';
            }

            my $mod;
            if ($attr =~ /^(userPassword|randomPassword|plainpassword|unicodePwd)$/i) {
                $mod = "$attr:$dsn";
            } else {
                $mod = "$attr:$dsn".join(';', @values);
            }

            if ($message) {
                $message = "$message $mod";
            } else {
                $message = $mod;
            }
        }
    } elsif ($type eq 'add') {
        my @list = split("\n", $info[0]);
        my $prev = '';

        while (@list > 0) {
            my $elt = shift @list;
            my ($attr, $value) = ($elt =~ /^([^:]*): (.*)$/);

            if ($attr =~ /^(createTimestamp|modifyTimestamp)$/) {
                next;
            }

            my $mod;
            if ($attr =~ /^(userPassword|plainpassword|unicodePwd)$/i || length($value) > $maxvallen) {
                $mod = "$attr:+";
            } else {
                if ($mfmatch && $attr =~ /^(member|seciossMember)$/i) {
                    $value =~ s/$mfmatch/$mfsubstitute/i;
                }
                $mod = "$attr:+$value";
            }

            if ($prev eq $attr) {
                if (length($value) <= $maxvallen) {
                    $message = "$message;$value";
                }
            } elsif ($message) {
                $message = "$message $mod";
            } else {
                $message = $mod;
            }

            $prev = $attr;
        }
    } elsif ($type eq 'modrdn') {
        $message = "newrdn=$info[0]";
    } elsif ($type eq 'delete') {
        $message = ' ';
    } elsif ($type eq 'duplicate') {
        $message = ' ';
    }
    if (!$message) {
        return $message;
    }

    $message = "type=$type dn=\"$dn\" result=$result error=\"$error\" $message";
    if ($type eq 'bind' && $result) {
        $message = "user=\"$dn\" $message";
    } else {
        my $binddn = defined($self->{bind}{edn}) ? $self->{bind}{edn} : $self->{bind}{dn};
        $message = "user=\"$binddn\" $message";
    }

    my $ip_chain = defined($self->{bind}{ip_chain}) ? $self->{bind}{ip_chain} : '-';
    $message = "ip_chain=\"$ip_chain\" $message";
    if (defined($self->{bind}{ip})) {
        $message = "ip=$self->{bind}{ip} $message";
    } else {
        $message = "ip=- $message";
    }

    if (defined($self->{_config}{logrequestid})) {
        $message = "reqid=".(defined($self->{bind}{reqid}) ? $self->{bind}{reqid} : 0)." $message";
    }

    if (defined($self->{bind}{app}) && $self->{bind}{app}) {
        $message .= " app=\"$self->{bind}{app}\"";
    }

    if (defined($self->{_config}->{auditformat})) {
        my $format = $self->{_config}->{auditformat};
        eval "\$message =~ s/${$format}[0]/${$format}[1]/is";
    }

    if (Encode::is_utf8($message)) {
        $message = encode('utf8', $message);
    }

    return $message;
}

=head1 SEE ALSO

slapd(8), slapd-perl(5)

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

(c) 2006 Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
