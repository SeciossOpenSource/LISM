package LISM::Storage::LDAP;

use strict;
use base qw(LISM::Storage);
use Net::LDAP;
use Net::LDAP::Control::Paged;
use Net::LDAP::Control::VLV;
use Net::LDAP::Control::Sort;
use LISM::Constant;
use MIME::Base64;
use Encode;
use Data::Dumper;

our $controlAttr = 'lismControl';
our $rawattrs = '^(jpegphoto|photo|objectSid|objectGUID|.*;binary)$';
our $TIMEOUT = 5;
our $RETRY = 3;

=head1 NAME

LISM::Storage::LDAP - LDAP storage for LISM

=head1 DESCRIPTION

This class implements the L<LISM::Storage> interface for LDAP directory.

=head1 METHODS

=head2 init

Connect LDAP server.

=cut

sub init
{
    my $self = shift;
    my $conf = $self->{_config};

    $self->SUPER::init();

    if (!Encode::is_utf8($conf->{uri}[0])) {
        $conf->{uri}[0] = decode('utf8', $conf->{uri}[0]);
    }

    if (!defined($conf->{nc})) {
        ($conf->{nc}) = ($conf->{uri}[0] =~ /^ldaps?:\/\/[^\/]+\/(.+)$/i);
    }

    return 0;
}

=pod

=head2 commit

Do nothing.

=cut

sub commit
{
    my $self = shift;
    my $conf = $self->{_config};

    if ($conf->{transaction}[0] !~ /^on$/i) {
        return 0;
    }

    undef($self->{transaction});

    return 0;
}

=pod

=head2 rollback

Do nothing.

=cut

sub rollback
{
    my $self = shift;
    my $conf = $self->{_config};

    if ($conf->{transaction}[0] !~ /^on$/i) {
        return 0;
    }

    if (!defined($self->{transaction}->{op}) || !defined($self->{transaction}->{entryStr})) {
        return 0;
    }

    my $op = $self->{transaction}->{op};
    my $entryStr = $self->{transaction}->{entryStr};
    my $dn;
    my $rc = 0;

    if ($op eq 'add') {
        $dn = $entryStr;
        $rc = $self->delete($dn);
    } elsif ($op eq 'modify') {
        my @list = @{$self->{transaction}->{args}};
        ($dn) = ($entryStr =~ /^dn:{1,2} (.*)$/m);
        $entryStr =~ s/^dn:.*\n//;

        my @info;
        while ( @list > 0) {
            my $action = shift @list;
            my $key    = lc(shift @list);

            while (@list > 0 && $list[0] ne "ADD" && $list[0] ne "DELETE" && $list[0] ne "REPLACE") {
                shift @list;
            }

            my @values = $entryStr =~ /^$key: (.*)$/gmi;
            if (@values) {
                push(@info, "REPLACE", $key, @values);
            } else {
                push(@info, "DELETE", $key);
            } 
        }

        $rc = $self->modify($dn, @info);
    } elsif ($op eq 'delete') {
        ($dn) = ($entryStr =~ /^dn:{1,2} (.*)$/m);
        $entryStr =~ s/^dn:.*\n//;

        # Delete Active Directory internal attributes
        $entryStr =~ s/^(distinguishedName|instantType|whenCreated|whenChanged|uSNCreated|uSNChanged|objectSid|objectGUID|groupType|objectCategory|dSCorePropagationData|lastLogon|lastLogoff|logonCount|accountExpires|badPwdCount|pwdLastSet|badPasswordTime):.*\n//i;

        $rc = $self->add($dn, $entryStr);
    }

    undef($self->{transaction});

    if ($rc) {
        $self->log(level => 'err', message => "Rollback of $op operation($dn) failed($rc)");
    }

    return $rc;
}

=pod

=head2 bind($binddn, $passwd)

Bind to LDAP server.

=cut

sub bind
{
    my $self = shift;
    my($binddn, $passwd) = @_;
    my $conf = $self->{_config};
    my $msg;

    for (my $i=0; $i<$RETRY; $i++) {
        if ($self->_getConnect()) {
            return LDAP_SERVER_DOWN;
        }

        # DN mapping
        foreach my $ldapmap (@{$conf->{ldapmap}}) {
            if ($ldapmap->{type} =~ /^dn$/i) {
                if ($binddn =~ /^$ldapmap->{local}=/i && (!defined($ldapmap->{dn}) || $binddn =~ /$ldapmap->{dn}/i)) {
                    $binddn = $self->_rewriteDn($ldapmap, 'request', $binddn);
                }
            } elsif ($ldapmap->{type} =~ /^attribute$/i) {
                $binddn =~ s/^$ldapmap->{local}=/$ldapmap->{foreign}=/i;
            }
        }
        if ($conf->{nc}) {
            $binddn =~ s/$self->{suffix}$/$conf->{nc}/i;
        } else {
            $binddn =~ s/,$self->{suffix}$//i;
        }

        $msg = $self->{bind}->bind($binddn, password => $passwd);
        if ($msg->code != LDAP_OPERATIONS_ERROR) {
            last;
        }
        
        $self->log(level => 'warning', message => "Can't bind $conf->{uri}[0] by $binddn retry ".($i+1)."/$RETRY: ".$msg->error."(".$msg->code.")");

        $self->_freeConnect($msg, 1);
    }
    
    if ($msg->code != LDAP_SUCCESS) {
        $self->log(level => 'alert', message => "Can't bind $conf->{uri}[0] by $binddn failed: ".$msg->error."(".$msg->code.")");
    }
    
    $self->_freeConnect($msg);

    return $msg->code;
}

=pod

=head2 search($base, $scope, $deref, $sizeLim, $timeLim, $filterStr, $attrOnly, @attrs)

Search LDAP information.

=cut

sub search
{
    my $self = shift;
    my $conf = $self->{_config};

    if (defined($conf->{pagesize})) {
        my @control;
        my $page = Net::LDAP::Control::Paged->new(size => $conf->{pagesize}[0]);
        push(@control, $page);

        return $self->_do_search(\@control, @_);
    } else {
        return $self->_do_search(undef, @_);
    }
}

=pod

=head2 compare($dn, $avaStr)

Compare the value of attribute in LDAP information.

=cut

sub compare
{
    my $self = shift;
    my ($dn, $avaStr) = @_;
    my $conf = $self->{_config};

    my ($key, $val) = split(/=/, $avaStr);

    if ($self->_getConnect()) {
        return LDAP_SERVER_DOWN;
    }

    # Attribute Mapping
    foreach my $ldapmap (@{$conf->{ldapmap}}) {
        if ($ldapmap->{type} =~ /^dn$/i) {
            if ($dn =~ /^$ldapmap->{local}=/i && (!defined($ldapmap->{dn}) || $dn =~ /$ldapmap->{dn}/i)) {
                $dn = $self->_rewriteDn($ldapmap, 'request', $dn);
            }
        } elsif ($ldapmap->{type} =~ /^objectclass$/i) {
            if ($key =~ /^objectClass$/i) {
                $avaStr =~ s/^$ldapmap->{local}$/$ldapmap->{foreign}/i;
            }
        } elsif ($ldapmap->{type} =~ /^attribute$/i) {
            $dn =~ s/^$ldapmap->{local}=/$ldapmap->{foreign}=/i;
            if ($key =~ /^$ldapmap->{local}$/i) {
                $key = $ldapmap->{foreign};
            }
        }
    }

    if ($conf->{nc}) {
        $dn =~ s/$self->{suffix}$/$conf->{nc}/i;
    } else {
        $dn =~ s/,$self->{suffix}$//i;
    }

    my $msg = $self->{ldap}->compare($dn, attr => $key, value => $val);

    $self->_freeConnect($msg);

    return $msg->code;
}

=pod

=head2 modify($dn, @list)

Modify LDAP information.

=cut

sub modify
{
    my $self = shift;
    my ($dn, @list) = @_;
    my $conf = $self->{_config};
    my $rc = LDAP_SUCCESS;
    my ($rdnattr) = ($dn =~ /^([^=]+)=/);
    my $foreign_rdnattr;
    my @orglist = @list;

    if (defined($conf->{noop}) && grep(/^modify$/i, @{$conf->{noop}})) {
        return $rc;
    }

    # DN mapping
    foreach my $ldapmap (@{$conf->{ldapmap}}) {
        if ($ldapmap->{type} =~ /^dn$/i) {
            if ($dn =~ /^$ldapmap->{local}=/i && (!defined($ldapmap->{dn}) || $dn =~ /$ldapmap->{dn}/i)) {
                $dn = $self->_rewriteDn($ldapmap, 'request', $dn);
                $foreign_rdnattr = lc($ldapmap->{foreign});
            }
        } elsif ($ldapmap->{type} =~ /^attribute$/i) {
            $dn =~ s/^$ldapmap->{local}=/$ldapmap->{foreign}=/i;
        }
    }
    if ($conf->{nc}) {
        $dn =~ s/$self->{suffix}$/$conf->{nc}/i;
    } else {
        $dn =~ s/,$self->{suffix}$//i;
    }

    my @changes;
    while ( @list > 0) {
        my $action = shift @list;
        my $key    = lc(shift @list);
        my @values;

        while (@list > 0 && $list[0] ne "ADD" && $list[0] ne "DELETE" && $list[0] ne "REPLACE") {
            push(@values, shift @list);
        }

        if (defined($conf->{operationalattr}) && grep(/^$key$/i, @{$conf->{operationalattr}})) {
            next;
        }

        if ($key =~ /^(modifyTimestamp|plainPassword)$/i) {
            next;
        }

        if ($foreign_rdnattr) {
            if ($key eq $foreign_rdnattr) {
                next;
            }
        } elsif ($key =~ /^$rdnattr$/i) {
            next;
        }

        if ($key eq 'customattribute' || $key eq 'setvalrole') {
            next;
        }

        if ($key eq 'entrycsn') {
            last;
        }

        if ($key =~ /^lismnewrdn$/i) {
            my $rc = $self->modrdn($dn, $values[0], 1);
            if ($rc) {
                return $rc;
            } else {
                $dn =~ s/^[^,]+/$values[0]/;
                next;
            }
        }

        if ($key =~ /^lismparentdn$/i) {
            if ($action eq "REPLACE" && @values && $values[0]) {
                if ($conf->{nc}) {
                    $values[0] =~ s/$self->{suffix}/$conf->{nc}/i;
                } else {
                    $values[0] =~ s/,$self->{suffix}//i;
                }
                if ($dn =~ /^[^,]+,$values[0]$/i) {
                    return LDAP_SUCCESS;
                } else {
                    return $self->move($dn, $values[0]);
                }
            } else {
                return LDAP_UNWILLING_TO_PERFORM;
            }
        }

        # Attribute Mapping
        foreach my $ldapmap (@{$conf->{ldapmap}}) {
            if ($ldapmap->{type} =~ /^objectclass$/i) {
                if ($key =~ /^objectClass$/i) {
                    for (my $i = 0; $i < @values; $i++) {
                        $values[$i] =~ s/^$ldapmap->{local}$/$ldapmap->{foreign}/i;
                    }
                }
            } elsif ($ldapmap->{type} =~ /^attribute$/i) {
                if ($key =~ /^$ldapmap->{local}$/i) {
                    $key = $ldapmap->{foreign};
                }
                if ($key =~ /^userCertificate;binary$/i) {
                    for (my $i = 0; $i < @values; $i++) {
                        $values[$i] = decode_base64($values[$i]);
                    }
                }
            }
        }

        for (my $i = 0; $i < @values; $i++) {
            if ($conf->{nc}) {
                $values[$i] =~ s/$self->{suffix}/$conf->{nc}/i;
            } else {
                $values[$i] =~ s/,$self->{suffix}//i;
            }
            if ($key !~ /$rawattrs/ && $values[$i]) {
                # replace carriage return to linefeed
                $values[$i] =~ s/\r/$conf->{breakchar}/g;
            }
        }

        if ($action eq "DELETE" && !$values[0]) {
            push(@changes, lc($action) => [$key => []]);
        } else {
            push(@changes, lc($action) => [$key => \@values]);
        }
    }

    if (!@changes) {
        return LDAP_SUCCESS;
    }

    $rc = $self->_beginWork('modify', $dn, @orglist);
    if ($rc) {
        return $rc;
    }

    if ($self->_getConnect()) {
        return LDAP_SERVER_DOWN;
    }

    my $msg = $self->{ldap}->modify($dn, changes => [@changes]);
    if ($msg->code) {
        $self->log(level => 'err', message => "Modifying $dn failed: ".$msg->error."(".$msg->code.")");
    }

    $self->_freeConnect($msg);

    return $msg->code;
}

=pod

=head2 add($dn, $entryStr)

Add information in LDAP directory.

=cut

sub add
{
    my $self = shift;
    my ($dn,  $entryStr) = @_;
    my $conf = $self->{_config};
    my $rc = LDAP_SUCCESS;
    my $orgdn = $dn;
    $dn =~ s/\\22/\\"/gi;
    $dn =~ s/\\23/\\#/gi;
    $dn =~ s/\\2B/\\+/gi;
    $dn =~ s/\\2F/\//gi;
    $dn =~ s/\\3B/\\;/gi;
    $dn =~ s/\\3C/\\</gi;
    $dn =~ s/\\3E/\\>/gi;
    $dn =~ s/\\3D/=/gi;
    $dn =~ s/\\5C/\\\\/gi;

    if (defined($conf->{noop}) && grep(/^add$/i, @{$conf->{noop}})) {
        return $rc;
    }

    $rc = $self->_beginWork('add', $dn);
    if ($rc) {
        return $rc;
    }

    if ($self->_getConnect()) {
        return LDAP_SERVER_DOWN;
    }

    # DN mapping
    foreach my $ldapmap (@{$conf->{ldapmap}}) {
        if ($ldapmap->{type} =~ /^dn$/i) {
            if ($dn =~ /^$ldapmap->{local}=/i && (!defined($ldapmap->{dn}) || $dn =~ /$ldapmap->{dn}/i)) {
                my ($rdn_val) = ($entryStr =~ /^$ldapmap->{foreign}: (.*$)/mi);
                if ($rdn_val) {
                    $dn =~ s/^[^,]+/$ldapmap->{foreign}=$rdn_val/i;
                }
            }
        } elsif ($ldapmap->{type} =~ /^attribute$/i) {
            $dn =~ s/^$ldapmap->{local}=/$ldapmap->{foreign}=/i;
        }
    }
    if ($conf->{nc}) {
        $dn =~ s/$self->{suffix}$/$conf->{nc}/i;
    } else {
        $dn =~ s/,$self->{suffix}$//i;
    }

    my %attrs;
    my @info = split(/\n/, $entryStr);
    foreach my $attr (@info) {
        my $key;
        my $val;
        if ($attr =~ /^[^ ]+::/) {
            ($key, $val) = split(/:: /, $attr);
            $val = decode_base64($val);
        } else {
            ($key, $val) = split(/: ?/, $attr, 2);
        }

        if (defined($conf->{operationalattr}) && grep(/^$key$/i, @{$conf->{operationalattr}})) {
            next;
        }

        if ($key =~ /^(createTimestamp|modifyTimestamp|plainpassword|customattribute|setvalrole)$/i) {
            next;
        }

        if ($val eq '') {
            next;
        }

        if ($key eq 'structuralObjectClass') {
            last;
        }

        # Attribute Mapping
        foreach my $ldapmap (@{$conf->{ldapmap}}) {
            if ($ldapmap->{type} =~ /^objectclass$/i) {
                if ($key =~ /^objectClass$/i) {
                    $val =~ s/^$ldapmap->{local}$/$ldapmap->{foreign}/i;
                }
            } elsif ($ldapmap->{type} =~ /^attribute$/i) {
                if ($key =~ /^$ldapmap->{local}$/i) {
                    $key = $ldapmap->{foreign};
                }
            }
        }

        if ($conf->{nc}) {
            $val =~ s/$self->{suffix}/$conf->{nc}/i;
        } else {
            $val =~ s/,$self->{suffix}//i;
        }

        # replace carriage return to linefeed
        $val =~ s/\r/$conf->{breakchar}/g;

        push(@{$attrs{$key}}, $val);
    }

    my $msg = $self->{ldap}->add($dn, attrs => [%attrs]);
    if (defined($conf->{deleteflag}) && $msg->code == LDAP_ALREADY_EXISTS) {
        foreach my $key (keys %{$conf->{deleteflag}}) {
            my $deleteflag = $conf->{deleteflag}{$key};
            if (!defined($deleteflag->{ovrfilter})) {
                next;
            }
            if (defined($deleteflag->{dn}) && $dn !~ /$deleteflag->{dn}/i) {
                next;
            }

            my ($parentdn) = ($orgdn =~ /^[^,]+,(.+)$/);
            my $parentEntry;
            ($rc, $parentEntry) = $self->_do_search(undef, $parentdn, 0, 0, 1, 0, "(!($key=$deleteflag->{value}))", 0, 'objectClass');
            if ($rc) {
                last;
            } elsif (!$parentEntry) {
                return LDAP_NO_SUCH_OBJECT;
            }

            my @delentries;
            ($rc, @delentries) = $self->_do_search(undef, $dn, 2, 0, 0, 0, $deleteflag->{ovrfilter}, 0, 'objectClass');
            if ($rc) {
                last;
            }
            if (@delentries) {
                @delentries = sort {length $b <=> length $a} @delentries;
                foreach my $delentry (@delentries) {
                    my ($deldn) = ($delentry =~ /^dn: ([^\n]+)/);
                    if ($conf->{nc}) {
                        $deldn =~ s/$self->{suffix}/$conf->{nc}/i;
                    } else {
                        $deldn =~ s/,$self->{suffix}//i;
                    }
                    if (defined($deleteflag->{active})) {
                        $msg = $self->{ldap}->modify($deldn, changes => [("replace" => [$key => [$deleteflag->{active}]])]);
                        if ($msg->code) {
                            last;
                        }
                    } else {
                        my $delmsg = $self->{ldap}->delete($deldn);
                        if ($delmsg->code) {
                            $rc = $delmsg->code;
                            last;
                        }
                    }
                }
                if (!$rc && !defined($deleteflag->{active})) {
                    $msg = $self->{ldap}->add($dn, attrs => [%attrs]);
                }
                last;
            }
        }
    }
    if ($msg->code) {
        $self->log(level => 'err', message => "Adding $dn failed: ".$msg->error."(".$msg->code.")");
    }

    $self->_freeConnect($msg);

    return $msg->code;
}

=pod

=head2 modrdn($dn, $newrdn, $delFlag)

move information in LDAP directory.

=cut

sub modrdn
{
    my $self = shift;
    my ($dn, $newrdn, $delFlag) = @_;
    my $conf = $self->{_config};

    if ($self->_getConnect()) {
        return LDAP_SERVER_DOWN;
    }

    # DN mapping
    foreach my $ldapmap (@{$conf->{ldapmap}}) {
        if ($ldapmap->{type} =~ /^dn$/i) {
            if ($dn =~ /^$ldapmap->{local}=/i && (!defined($ldapmap->{dn}) || $dn =~ /$ldapmap->{dn}/i)) {
                $dn = $self->_rewriteDn($ldapmap, 'request', $dn);
            }
        } elsif ($ldapmap->{type} =~ /^attribute$/i) {
            $dn =~ s/^$ldapmap->{local}=/$ldapmap->{foreign}=/i;
        }
    }

    if ($conf->{nc}) {
        $dn =~ s/$self->{suffix}$/$conf->{nc}/i;
    } else {
        $dn =~ s/,$self->{suffix}$//i;
    }

    my $msg = $self->{ldap}->modrdn($dn, newrdn => $newrdn, deleteoldrdn => $delFlag);

    $self->_freeConnect($msg);

    return $msg->code;
}

=pod

=head2 delete($dn)

Delete information from LDAP directory.

=cut

sub delete
{
    my $self = shift;
    my ($dn) = @_;
    my $conf = $self->{_config};
    my $rc = LDAP_SUCCESS;

    if (defined($conf->{noop}) && grep(/^delete$/i, @{$conf->{noop}})) {
        return $rc;
    }

    if (defined($conf->{deleteflag})) {
        my $entryStr;
        ($rc, $entryStr) = $self->_do_search(undef, $dn, 0, 0, 1, 0, '(objectClass=*)', 0);
        if ($rc) {
            return $rc;
        }

        my $match = 0;
        foreach my $key (keys %{$conf->{deleteflag}}) {
            my $deleteflag = $conf->{deleteflag}{$key};
            if (defined($deleteflag->{dn}) && $dn !~ /$deleteflag->{dn}/i) {
                next;
            }
            my @entries;
            ($rc, @entries) = $self->_do_search(undef, $dn, 1, 0, 0, 0, "(!($key=$deleteflag->{value}))", 0, 'objectClass');
            if ($rc) {
                return $rc;
            } elsif (@entries) {
                return LDAP_NOT_ALLOWED_ON_NONLEAF
            }
            if (!defined($deleteflag->{filter}) || $self->parseFilter($deleteflag->{filterobj}, $entryStr)) {
                $rc = $self->modify($dn, "REPLACE", $key, $deleteflag->{value});
                if (!$rc && defined($deleteflag->{superior})) {
                    $rc = $self->move($dn, $deleteflag->{superior});
                }
                $match = 1;
            }
        }
        if ($match) {
            return $rc;
        }
    }

    $rc = $self->_beginWork('delete', $dn);
    if ($rc) {
        return $rc;
    }

    if ($self->_getConnect()) {
        return LDAP_SERVER_DOWN;
    }

    # DN mapping
    foreach my $ldapmap (@{$conf->{ldapmap}}) {
        if ($ldapmap->{type} =~ /^dn$/i) {
            if ($dn =~ /^$ldapmap->{local}=/i && (!defined($ldapmap->{dn}) || $dn =~ /$ldapmap->{dn}/i)) {
                $dn = $self->_rewriteDn($ldapmap, 'request', $dn);
            }
        } elsif ($ldapmap->{type} =~ /^attribute$/i) {
            $dn =~ s/^$ldapmap->{local}=/$ldapmap->{foreign}=/i;
        }
    }

    if ($conf->{nc}) {
        $dn =~ s/$self->{suffix}$/$conf->{nc}/i;
    } else {
        $dn =~ s/,$self->{suffix}$//i;
    }

    my $msg = $self->{ldap}->delete($dn);
    if ($msg->code) {
        $self->log(level => 'err', message => "Deleting $dn failed: ".$msg->error."(".$msg->code.")");
    }

    $self->_freeConnect($msg);

    return $msg->code;
}

=pod

=head2 move($dn, $parentdn)

move information in LDAP directory.

=cut

sub move
{
    my $self = shift;
    my ($dn, $parentdn) = @_;
    my $conf = $self->{_config};

    if ($self->_getConnect()) {
        return LDAP_SERVER_DOWN;
    }

    # DN mapping
    foreach my $ldapmap (@{$conf->{ldapmap}}) {
        if ($ldapmap->{type} =~ /^dn$/i) {
            if ($dn =~ /^$ldapmap->{local}=/i && (!defined($ldapmap->{dn}) || $dn =~ /$ldapmap->{dn}/i)) {
                $dn = $self->_rewriteDn($ldapmap, 'request', $dn);
            }
        } elsif ($ldapmap->{type} =~ /^attribute$/i) {
            $dn =~ s/^$ldapmap->{local}=/$ldapmap->{foreign}=/i;
        }
    }

    if ($conf->{nc}) {
        $dn =~ s/$self->{suffix}$/$conf->{nc}/i;
        $parentdn =~ s/$self->{suffix}$/$conf->{nc}/i;
    } else {
        $dn =~ s/,$self->{suffix}$//i;
        $parentdn =~ s/,$self->{suffix}$//i;
    }
    my ($rdn) = ($dn =~ /^([^,]+),/);

    my $msg = $self->{ldap}->moddn($dn, newrdn => $rdn, newsuperior => $parentdn, deleteoldrdn => 1);

    $self->_freeConnect($msg);

    return $msg->code;
}

=pod

=head2 hashPasswd($passwd, $salt)

add hash schema at the head of hashed password.

=cut

sub hashPasswd
{
    my $self = shift;
    my ($passwd, $salt) =@_;
    my $conf = $self->{_config};

    my ($htype, $otype) = split(/:/, $conf->{hash});
    if ($passwd =~ /^{([^}]+)}/ && $htype ne $1) {
        return $passwd;
    }

    my $hashpw = $self->SUPER::hashPasswd($passwd, $salt);

    if ($htype =~ /^AD$/i) {
        # encoding for Active Directory
        $hashpw = '';
        map {$hashpw .= "$_\000"} split(//, "\"$passwd\"");
    } elsif (defined($hashpw) && $htype =~ /^CRYPT|MD5|SHA|SSHA|SSHA512|PBKDF2_SHA256$/i) {
        $hashpw = "{$htype}$hashpw";
    }

    return $hashpw;
}

sub manageDIT
{
    return 1;
}

sub _getConnect
{
    my $self = shift;
    my $conf = $self->{_config};
    my $msg;

    if (defined($self->{ldap}) && defined($self->{bind}) &&
        (!defined($conf->{connection}[0]->{type}) || $conf->{connection}[0]->{type}[0] ne 'every')) {
        $msg = $self->{ldap}->bind($conf->{binddn}[0], password => $conf->{bindpw}[0]);
        if ($msg->code == LDAP_SUCCESS) {
            return 0;
        }
        
        $self->log(level => 'warning', message => "Connection check($conf->{uri}[0]) failed: ".$msg->error."(".$msg->code.")");
        
        $self->{ldap}->unbind();
        $self->{bind}->unbind();
        undef($self->{ldap});
        undef($self->{bind});
    }

    my $uri;
    foreach (@{$conf->{uri}}) {
        $uri = $_;
        my $connect = 0;
        for (my $i=0; $i<$RETRY; $i++) {
            $self->{ldap} = Net::LDAP->new($uri, timeout => $TIMEOUT);
            $self->{bind} = Net::LDAP->new($uri, timeout => $TIMEOUT);

            if (!defined($self->{ldap}) || !defined($self->{bind})) {
                $self->log(level => 'alert', message => "Can't connect $uri".($@ ? ": $@" : ''));
                undef($self->{ldap});
                undef($self->{bind});
                return -1;
            }

            $msg = $self->{ldap}->bind($conf->{binddn}[0], password => $conf->{bindpw}[0]);
            if ($msg->code == LDAP_SUCCESS) {
                $connect = 1;
                last;
            }

            $self->{ldap}->unbind();
            $self->{bind}->unbind();
            undef($self->{ldap});
            undef($self->{bind});
        
            if ($msg->code != LDAP_OPERATIONS_ERROR) {
                last;
            }

            $self->log(level => 'warning', message => "Can't bind $conf->{uri}[0] by $conf->{binddn}[0] retry ".($i+1)."/$RETRY: ".$msg->error."(".$msg->code.")");
        }
        if ($connect) {
            last;
        }
    }

    if (!defined($self->{ldap}) || !defined($self->{bind})) {
        if (defined($msg)) {
            $self->log(level => 'alert', message => "Can't bind $uri by $conf->{binddn}[0] failed: ".$msg->error."(".$msg->code.")");
        }
        return -1;
    }

    return 0;
}

sub _freeConnect
{
    my $self =shift;
    my $conf = $self->{_config};
    my ($msg, $free) = @_;

    if (!$msg) {
        return -1;
    }

    if ($msg->code == LDAP_SERVER_DOWN || $msg->code == -1 || $free ||
        (defined($conf->{connection}[0]->{type}) && $conf->{connection}[0]->{type}[0] eq 'every')) {
        $self->{ldap}->unbind();
        $self->{bind}->unbind();

        undef($self->{ldap});
        undef($self->{bind});
    }

    return 0;
}

sub _checkConfig
{
    my $self = shift;
    my $conf = $self->{_config};
    my $rc = 0;

    if ($rc = $self->SUPER::_checkConfig()) {
        return $rc;
    }

    if (!defined($conf->{transaction})) {
        $conf->{transaction}[0] = 'off';
    }

    if (defined($conf->{decrypt}) && defined($conf->{bindpw}) && !defined($conf->{passwd_decrypted})) {
        my $decrypt = $conf->{decrypt}[0];
        my $value = $conf->{bindpw}[0];
        $decrypt =~ s/\%s/$value/;
        $value = $self->_doFunction($decrypt);
        if (!defined($value)) {
            $self->log(level => 'err', message => "Decrypt of bindpw failed");
            return 1;
        }
        $conf->{bindpw}[0] = $value;
        $conf->{passwd_decrypted} = 1;
    }

    if (defined($conf->{deleteflag})) {
        foreach my $key (keys %{$conf->{deleteflag}}) {
            if ($conf->{deleteflag}{$key}->{filter}) {
                $conf->{deleteflag}{$key}->{filter} =~ s/&amp;/&/g;
                $conf->{deleteflag}{$key}->{filterobj} = Net::LDAP::Filter->new($conf->{deleteflag}{$key}->{filter});
            }
            if ($conf->{deleteflag}{$key}->{ovrfilter}) {
                $conf->{deleteflag}{$key}->{ovrfilter} =~ s/&amp;/&/g;
            }
        }
    }

    foreach my $ldapmap (@{$conf->{ldapmap}}) {
        if (!defined($ldapmap->{type})) {
            $ldapmap->{type} = 'attribute';
        }
    }

    if (defined($conf->{defaultattrs})) {
        my @attrs = split(/, */, $conf->{defaultattrs}[0]);
        if (@attrs) {
            $conf->{defattrs} = \@attrs;
        }
    }

    return $rc;
}

sub _beginWork
{
    my $self = shift;
    my ($op, $dn, @args) = @_;
    my $conf = $self->{_config};
    my $entryStr;
    my $rc = LDAP_SUCCESS;

    if ($conf->{transaction}[0] !~ /^on$/i) {
        return $rc;
    }

    if ($op eq 'add') {
        $entryStr = $dn;
    } else {
        ($rc, $entryStr) = $self->_do_search(undef, $dn, 0, 0, 1, 0, '(objectClass=*)');
        if ($rc) {
            $self->log(level => 'err', message => "Can't get $dn in beginning transaction");
            return $rc;
        }
    }

    $self->{transaction}->{op} = $op;
    $self->{transaction}->{entryStr} = $entryStr;
    $self->{transaction}->{args} = \@args;

    return $rc;
}

sub _do_search
{
    my $self = shift;
    my($control, $base, $scope, $deref, $sizeLim, $timeLim, $filterStr, $attrOnly, @attrs) = @_;
    my $conf = $self->{_config};
    my @match_entries = ();
    my %ctrl_class;
    my $pagenum = 0;
    my $rc = LDAP_SUCCESS;

    if ($control) {
        for (my $i = 0; $i < @{$control}; $i++) {
            $ctrl_class{ref(${$control}[$i])} = $i;
        }
    }

    my $undeleted = 0;
    my ($lismctrls) = ($filterStr =~ /^\(&\($controlAttr=([^\)]+)\)/i);
    if ($lismctrls) {
        $filterStr =~ s/^\(&\($controlAttr=[^\)]+\)//;
        $filterStr =~ s/\)$//;
        foreach my $lismctrl (split(/&/, $lismctrls)) {
            my $ldapctrl;
            my $class;
            my ($key, $value) = split(/=/, $lismctrl);
            if ($key eq 'paged') {
                my $size;
                ($size, $pagenum) = split(/,/, $value);
                $ldapctrl = Net::LDAP::Control::Paged->new(size => $size);
                $class = 'Net::LDAP::Control::Paged';
            } elsif ($key eq 'vlv') {
                my ($size, $offset) = split(/,/, $value);
                $ldapctrl = Net::LDAP::Control::VLV->new(
                    after => $size -1,
                    before => 0,
                    content => 0,
                    offset => $offset
                );
                $class = 'Net::LDAP::Control::VLV';
            } elsif ($key eq 'sort') {
                $ldapctrl = Net::LDAP::Control::Sort->new(order => $value);
                $class = 'Net::LDAP::Control::Sort';
            } elsif ($key eq 'undeleted') {
                $undeleted = 1;
                next;
            } else {
                next;
            }
            if (defined($ctrl_class{$class})) {
                ${$control}[$ctrl_class{$class}] = $ldapctrl;
            } else {
                if ($control) {
                    push(@{$control}, $ldapctrl);
                } else {
                    $control = [$ldapctrl];
                }
                $ctrl_class{$class} = @{$control} - 1;
            }
        }
    }

    my $filter = Net::LDAP::Filter->new($filterStr);
    if (!defined($filter)) {
        return (LDAP_FILTER_ERROR, ());
    }

    # get entry of data container
    if ($base =~ /^$self->{suffix}$/i) {
        if ($scope != 1) {
            my $entry = $self->{contentrystr};
            if ($self->parseFilter($filter, $entry)) {
                push (@match_entries, $entry);
                $sizeLim--;
            }
        }
    }
    $sizeLim = $sizeLim - @match_entries;

    if ($self->_getConnect()) {
        return LDAP_SERVER_DOWN;
    }

    if (!@attrs && defined($conf->{defattrs})) {
        @attrs = @{$conf->{defattrs}};
    }

    my @disable_attrs;
    if (defined($ENV{lism_disableattrs})) {
        @disable_attrs = split(/, */, $ENV{lism_disableattrs});
    }

    $filterStr = decode('utf8', $filterStr);

    # Attribute mapping
    foreach my $ldapmap (@{$conf->{ldapmap}}) {
        if ($ldapmap->{type} =~ /^dn$/i) {
            if ($base =~ /^$ldapmap->{local}=/i && (!defined($ldapmap->{dn}) || $base =~ /$ldapmap->{dn}/i)) {
                $base = $self->_rewriteDn($ldapmap, 'request', $base);
            }
        } elsif ($ldapmap->{type} =~ /^objectclass$/i) {
            $filterStr =~ s/objectClass=$ldapmap->{local}/objectClass=$ldapmap->{foreign}/mi;
        } elsif ($ldapmap->{type} =~ /^attribute$/i) {
            $base =~ s/^$ldapmap->{local}=/$ldapmap->{foreign}=/i;
            $filterStr =~ s/\($ldapmap->{local}=/\($ldapmap->{foreign}=/gmi;
            for (my $i = 0; $i < @attrs; $i++) {
                $attrs[$i] =~ s/^$ldapmap->{local}$/$ldapmap->{foreign}/i;
            }
        }
    }

    if ($conf->{nc}) {
        $base =~ s/$self->{suffix}$/$conf->{nc}/i;
        $filterStr =~ s/$self->{suffix}(\)*)/$conf->{nc}$1/gi;
    } else {
        $base =~ s/,?$self->{suffix}$//i;
        $filterStr =~ s/,$self->{suffix}(\)*)/$1/gi;
    }
    $filterStr = encode('utf8', $filterStr);
    if (!@attrs) {
        @attrs = ('*');
    } elsif (@attrs == 1 && $attrs[0] eq 'dn') {
        push(@attrs, 'objectClass');
    }

    my @del_flags;
    if ($undeleted && defined($conf->{deleteflag})) {
        foreach my $key (keys %{$conf->{deleteflag}}) {
            my $deleteflag = $conf->{deleteflag}{$key};
            if (!defined($deleteflag->{dn}) || !defined($deleteflag->{ovrfilter})) {
                next;
            }
            my $del_filter = $deleteflag->{ovrfilter};
            if (defined($deleteflag->{filter})) {
                $del_filter = "(&$deleteflag->{filter}$del_filter)";
            }
            push(@del_flags, {dn => $deleteflag->{dn}, filter => Net::LDAP::Filter->new($del_filter)});
        }
    }

    my @rldapmap = reverse(@{$conf->{ldapmap}});
    my $msg;
    for (my $i = 1;;$i++) {
        if (keys %ctrl_class) {
            $msg = $self->{ldap}->search(base => $base, scope => $scope, deref => $deref, sizelimit => $sizeLim, timelimit => $timeLim, filter => $filterStr, attrs => \@attrs, control => $control);
        } else {
            $msg = $self->{ldap}->search(base => $base, scope => $scope, deref => $deref, sizelimit => $sizeLim, timelimit => $timeLim, filter => $filterStr, attrs => \@attrs);
        }

        if ($msg->code) {
            last;
        }

        if (!$pagenum || $pagenum == $i) {
            for (my $j = 0; $j < $msg->count; $j++) {
                my $entry = $msg->entry($j);
                my $dn = decode('utf8', $entry->dn);

                if ($conf->{nc}) {
                    $dn =~ s/$conf->{nc}$/$self->{suffix}/i;
                } else {
                    $dn .= ','.$self->{suffix};
                }
                $dn =~ s/\\"/\\22/g;
                $dn =~ s/\\#/\\23/g;
                $dn =~ s/#/\\23/g;
                $dn =~ s/\\\+/\\2B/g;
                $dn =~ s/\\\//\\2F/g;
                $dn =~ s/\\;/\\3B/g;
                $dn =~ s/\\</\\3C/g;
                $dn =~ s/\\>/\\3E/g;
                $dn =~ s/\\=/\\3D/g;
                $dn =~ s/\\\\/\\5C/g;
                my $entryStr = "dn: $dn\n";
                if ($dn =~ /^$self->{suffix}$/i) {
                    next;
                } else {
                    foreach my $attr ($entry->attributes) {
                        if (@disable_attrs && grep(/^$attr$/i, @disable_attrs)) {
                            next;
                        }
                        if ($attr =~ /^member;range=[0-9]+-([0-9]+)$/i) {
                            my $start = $1 + 1;
                            my $end = $1 + 1500;
                            my @values = $entry->get_value($attr);
                            for (my $k = 0; $k < 100; $k++) {
                                my $gmsg = $self->{ldap}->search(base => $entry->dn, scope => 0, deref => $deref, filter => '(objectClass=*)', attrs => ["member;range=${start}-${end}"]);
                                if ($gmsg->code) {
                                    $self->_freeConnect($msg, defined($ctrl_class{'Net::LDAP::Control::VLV'}));
                                    return ($gmsg->code, @match_entries);
                                }
                                my $gentry = $gmsg->entry(0);
                                my @tmpvals;
                                if ($gentry->exists("member;range=${start}-*")) {
                                    unshift(@values, $gentry->get_value("member;range=${start}-*"));
                                    last;
                                } else {
                                    @tmpvals = $gentry->get_value("member;range=${start}-${end}");
                                }
                                unshift(@values, @tmpvals);
                                if (@tmpvals < 1500) {
                                    last;
                                }
                                $start += 1500;
                                $end += 1500;
                            }
                            foreach my $value (@values) {
                                $value = decode('utf8', $value);
                                if ($conf->{nc}) {
                                    $value =~ s/$conf->{nc}$/$self->{suffix}/i;
                                }
                                $entryStr = $entryStr."member: $value\n";
                            }
                            next;
                        }
                        foreach my $value ($entry->get_value($attr)) {
                            if ($attr =~ /$rawattrs/i) {
                                $value = encode_base64($value, '');
                                $entryStr = $entryStr.$attr.":: $value\n";
                            } else {
                                if ($value =~ /\n/) {
                                    $value = encode_base64($value, '');
                                    $entryStr = $entryStr.$attr.":: $value\n";
                                } else {
                                    $value = decode('utf8', $value);
                                    if ($conf->{nc}) {
                                        $value =~ s/$conf->{nc}$/$self->{suffix}/i;
                                    }
                                    $entryStr = $entryStr.$attr.": $value\n";
                                }
                            }
                        }
                    }
                }

                if (!$self->_checkEntry($entryStr)) {
                    next;
                }

                my $is_deleted = 0;
                foreach my $del_flag (@del_flags) {
                    my $del_dn = $del_flag->{dn};
                    my $del_filter = $del_flag->{filter};
                    if ($dn =~ /$del_dn/i && $self->parseFilter($del_filter, $entryStr)) {
                        $is_deleted = 1;
                    }
                }
                if ($is_deleted) {
                    next;
                }

                # Attribute mapping
                foreach my $ldapmap (@rldapmap) {
                    if ($ldapmap->{type} =~ /^objectclass$/i) {
                        $entryStr =~ s/^objectClass: $ldapmap->{foreign}$/objectClass: $ldapmap->{local}/mi;
                    } elsif ($ldapmap->{type} =~ /^attribute$/i) {
                        $entryStr =~ s/^$ldapmap->{foreign}:/$ldapmap->{local}:/gmi;
                        $entryStr =~ s/: $ldapmap->{foreign}=/: $ldapmap->{local}=/gi;
                    }
                }

                # DN mapping
                foreach my $ldapmap (@rldapmap) {
                    if ($ldapmap->{type} =~ /^dn$/i) {
                        my ($dn) = ($entryStr =~ /^dn: (.*)$/m);
                        if ($dn =~ /^$ldapmap->{foreign}=/i && (!defined($ldapmap->{dn}) || $dn =~ /$ldapmap->{dn}/i)) {
                            my ($rdn, $rdn_val) = ($entryStr =~ /^($ldapmap->{local}): (.*$)/mi);
                            if ($rdn && $rdn_val) {
                                $entryStr =~ s/^dn: [^,]+/dn: $rdn=$rdn_val/i;
                            }
                        }
                    }
                }

                push(@match_entries, $entryStr);
            }
        }

        if (defined($ctrl_class{'Net::LDAP::Control::Paged'})) {
            # Get cookie from paged control
            my ($resp) = $msg->control(LDAP_CONTROL_PAGED) or last;
            my $cookie = $resp->cookie or last;

            # Set cookie in paged control
            ${$control}[$ctrl_class{'Net::LDAP::Control::Paged'}]->cookie($cookie);
        } else {
            last;
        }
    }

    $self->_freeConnect($msg, defined($ctrl_class{'Net::LDAP::Control::VLV'}));

    return ($msg->code , @match_entries);
}

sub _checkEntry
{
    my $self = shift;
    my ($entryStr) = @_;

    if ($entryStr !~ /^dn: .+\n.+/) {
        return 0;
    }

    return 1;
}

sub _rewriteDn
{
    my $self = shift;
    my ($map, $context, $dn) = @_;
    my $conf = $self->{_config};
    my $attr;
    my $msg;

    my ($filterStr) = ($dn =~ /^([^,]+),/);

    if ($context eq 'request') {
        $attr = $map->{foreign};
        $filterStr = "(&($map->{foreign}=*)($filterStr))";

        # Attribute mapping
        foreach my $ldapmap (@{$conf->{ldapmap}}) {
            if ($ldapmap->{type} =~ /^attribute$/i) {
                $filterStr =~ s/$ldapmap->{local}=/$ldapmap->{foreign}=/i;
                $attr =~ s/^$ldapmap->{local}$/$ldapmap->{foreign}/i;
            }
        }
    } else {
        $attr = $map->{local};
        $filterStr = "(&($map->{local}=*)($filterStr))";

        # Attribute mapping
        foreach my $ldapmap (@{$conf->{ldapmap}}) {
            if ($ldapmap->{type} =~ /^attribute$/i) {
                $filterStr =~ s/$ldapmap->{foreign}=/$ldapmap->{local}=/i;
                $attr =~ s/^$ldapmap->{foreign}$/$ldapmap->{local}/i;
            }
        }
    }
    $filterStr = encode('utf8', $filterStr);

    $msg = $self->{ldap}->search(base => $conf->{nc}, scope => 'sub', filter => $filterStr, attrs => [$attr]);

    if ($msg->code) {
        $self->log(level => 'err', message => "search by $filterStr failed(".$msg->code.") in rewriteDn");
    } else {
        if ($msg->count) {
            my $entry = $msg->entry(0);
            my @values = $entry->get_value($attr);

            if (@values) {
                my $rdn_val = $values[0];
                $rdn_val = Encode::is_utf8($rdn_val) ? $rdn_val : decode('utf8', $rdn_val);
                $dn =~ s/^[^,]+/$attr=$rdn_val/i;
            }
        }
    }

    return $dn;
}

=head1 SEE ALSO

L<LISM>,
L<LISM::Storage>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

(c) 2006 Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
