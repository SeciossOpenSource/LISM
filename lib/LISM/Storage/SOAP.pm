package LISM::Storage::SOAP;

use strict;
use base qw(LISM::Storage);
use LISM::Constant;
use Encode;
use IO::Socket::SSL;
use Data::Dumper;
use SOAP::Lite;

our $RETRY = 3;

=head1 NAME

LISM::Storage::SOAP - SOAP storage for LISM

=head1 DESCRIPTION

This class implements the L<LISM::Storage> interface for SOAP.

=head1 METHODS

=head2 init

Connect SOAP server.

=cut

sub init
{
    my $self = shift;
    my $conf = $self->{_config};

    $self->SUPER::init();

    if (!defined($self->{soap})) {
        $self->{soap} = SOAP::Lite->new;
        if (defined($conf->{uri})) {
            $self->{soap}->uri($conf->{uri}[0]);
        }
        my $timeout = $conf->{connection}[0]->{timeout}[0];
        if ($timeout) {
            $self->{soap}->proxy($conf->{proxy}[0], timeout => $timeout);
        } else {
            $self->{soap}->proxy($conf->{proxy}[0]);
        }
        if ($IO::Socket::SSL::VERSION >= 1.79 && defined($ENV{PERL_LWP_SSL_VERIFY_HOSTNAME}) && !$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME}) {
            $self->{soap}->proxy->ssl_opts(SSL_verify_mode => 0);
        }
    }

    if (!Encode::is_utf8($conf->{basedn}[0])) {
        $conf->{basedn}[0] = decode('utf8', $conf->{basedn}[0]);
    }

    return 0;
}

=pod

=head2 commit

Do nothing.

=cut

sub commit
{
    return 0;
}

=pod

=head2 rollback

Do nothing.

=cut

sub rollback
{
    return 0;
}

=pod

=head2 bind($binddn, $passwd)

Bind to SOAP server.

=cut

sub bind
{
    my $self = shift;
    my($binddn, $passwd) = @_;
    my $conf = $self->{_config};
    my $rc = LDAP_SUCCESS;

    $binddn =~ s/$self->{suffix}$/$conf->{basedn}[0]/i;

    if ($self->_getConnect()) {
        return LDAP_SERVER_DOWN;
    }

    my $res;
    for (my $i = 0; $i < $RETRY; $i++) {
        if ($i && $conf->{connection}[0]->{interval}[0]) {
            sleep $conf->{connection}[0]->{interval}[0];
        }
        eval {
            $res = $self->{soap}->bind(
                SOAP::Data->name('binddn' => $binddn),
                SOAP::Data->name('bindpw' => $passwd)
                );
        };

        if ($@) {
            my $error = $@;
            $self->log(level => 'err', message => "Binding by $binddn failed: retry=".($i + 1)." $error");
            $rc = LDAP_OTHER;
            if ($error =~ /[45][0-9]{2} /) {
                next;
            }
        } elsif (!ref $res) {
            $self->log(level => 'err', message => "Binding by $binddn failed: ".$self->{soap}->transport->status);
        } elsif (!defined($res->result)) {
            $self->log(level => 'err', message => "Binding by $binddn failed: ".$res->faultstring);
        } else {
            $rc = LDAP_SUCCESS;
        }
        last;
    }
    if ($rc) {
        return $rc;
    }

    $rc = ${$res->result}[0];
    if (!$rc) {
        $self->{soap}->unbind(
            SOAP::Data->name('sessid' => ${$res->result}[2])
            );
    }

    $self->_freeConnect();

    return $rc;
}

=pod

=head2 search($base, $scope, $deref, $sizeLim, $timeLim, $filterStr, $attrOnly, @attrs)

Search SOAP data.

=cut

sub search
{
    my $self = shift;
    my($base, $scope, $deref, $sizeLim, $timeLim, $filterStr, $attrOnly, @attrs) = @_;
    my $conf = $self->{_config};
    my @match_entries = ();
    my $rc = LDAP_SUCCESS;

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
                if ($sizeLim > 0) {
                    $sizeLim--;
                }
            }
        }
    }
    $sizeLim = $sizeLim > 0 ? $sizeLim - @match_entries : $sizeLim;
    if ($sizeLim < 0) {
        return ($rc, @match_entries);
    }

    if ($self->_getConnect()) {
        return LDAP_SERVER_DOWN;
    }

    $filterStr = $self->_mb_conv($filterStr);

    $base =~ s/$self->{suffix}$/$conf->{basedn}[0]/i;
    $filterStr =~ s/$self->{suffix}(\)*)/$conf->{basedn}[0]$1/gi;
    my $count;
    my $offset = 1;
    my $key = 'cn';
    if (defined($conf->{control}) && defined($conf->{control}[0]->{vlv})) {
        $count = $conf->{control}[0]->{vlv}[0]->{count};
    }
    if (grep(/^uid$/, @attrs)) {
        $key = 'uid';
    }

    while (1) {
        my $soapfilter = $filterStr;
        if ($count) {
            $soapfilter = "(&(lismControl=vlv=$count,$offset&sort=$key:2.5.13.3)$filterStr)";
        }

        my $res;
        for (my $i = 0; $i < $RETRY; $i++) {
            if ($i && $conf->{connection}[0]->{interval}[0]) {
                sleep $conf->{connection}[0]->{interval}[0];
            }
            eval {
                $res = $self->{soap}->search(
                    SOAP::Data->name('sessid' => $self->{sessid}),
                    SOAP::Data->name('base' => $base),
                    SOAP::Data->name('scope' => $scope),
                    SOAP::Data->name('deref' => $deref),
                    SOAP::Data->name('sizeLim' => $sizeLim),
                    SOAP::Data->name('timeLim' => $timeLim),
                    SOAP::Data->name('filter' => decode('utf8', $soapfilter)),
                    SOAP::Data->name('attrOnly' => 0),
                    SOAP::Data->name('attrs' => \@attrs)
                );
            };

            if ($@) {
                my $error = $@;
                $self->log(level => 'err', message => "Searching by $filterStr at $base failed: retry=".($i + 1)." $error");
                if ($error =~ /[45][0-9]{2} /) {
                    $rc = LDAP_OTHER;
                    next;
                }
                return (LDAP_OTHER, ());
            } elsif (!ref $res) {
                $self->log(level => 'err', message => "Searching by $filterStr at $base failed: ".$self->{soap}->transport->status);
                return (LDAP_OTHER, ());
            } elsif (!defined($res->result)) {
                $self->log(level => 'err', message => "Searching by $filterStr ab $base failed: ".$res->faultstring);
                return (LDAP_OTHER, ());
            } elsif (${$res->result}[0] == -1 && ${$res->result}[1] eq "Not authenticated") {
                undef($self->{sessid});
                undef($self->{logintime});
                $self->_getConnect();
                $rc = LDAP_OTHER;
                next;
            }
            $rc = LDAP_SUCCESS;
            last;
        }
        if ($rc) {
            return $rc;
        }

        $rc = ${$res->result}[0];
        if ($rc == 76) {
            $rc = 0;
        }
        if (!$rc) {
            for (my $i = 0; $i < @{${$res->result}[2]}; $i++) {
                my $entryStr = ${${$res->result}[2]}[$i];
                if (!Encode::is_utf8($entryStr)) {
                    $entryStr = decode('utf8', $entryStr);
                }

                $entryStr =~ s/$conf->{basedn}[0]$/$self->{suffix}/gmi;
                if ($entryStr =~ /^dn: $self->{suffix}\n/i) {
                    next;
                }

                $entryStr =~ s/: *$/:/gm;
                if (!$self->_checkEntry($entryStr)) {
                    next;
                }

                push(@match_entries, $entryStr);
            }
        }
        if ($rc || !$count || @{${$res->result}[2]} < $count) {
            last;
        }
        $offset += $count;
    }

    $self->_freeConnect();

    return ($rc , @match_entries);
}

=pod

=head2 modify($dn, @list)

Modify information by SOAP.

=cut

sub modify
{
    my $self = shift;
    my ($dn, @list) = @_;
    my $conf = $self->{_config};
    my $rc = LDAP_SUCCESS;

    $dn =~ s/$self->{suffix}$/$conf->{basedn}[0]/i;

    my @changes;
    while ( @list > 0) {
        my $action = shift @list;
        my $key    = lc(shift @list);
        my @values;

        while (@list > 0 && $list[0] ne "ADD" && $list[0] ne "DELETE" && $list[0] ne "REPLACE") {
            push(@values, shift @list);
        }

        if ($key =~ /^(modifyTimestamp|plainpassword)$/i) {
            next;
        }

        if ($key eq 'entrycsn') {
            last;
        }

        $key =~ s/;/_/g;
        for (my $i = 0; $i < @values; $i++) {
            $values[$i] =~ s/$self->{suffix}/$conf->{basedn}[0]/i;
            $values[$i] = encode('utf8', $values[$i]);
            if ($values[$i]) {
                # replace carriage return to linefeed
                $values[$i] =~ s/\r/$conf->{breakchar}/g;
                if ($key =~ /^userPassword$/i && $conf->{hash} ne 'PLAINTEXT') {
                    $values[$i] = '{'.$conf->{hash}.'}'.$values[$i];
                }
                if ($values[$i] eq 'TRUE' || $values[$i] eq 'FALSE') {
                    $values[$i] = '"'.$values[$i].'"';
                }
            }
        }

        if ($action eq "DELETE" && !$values[0]) {
            push(@changes, SOAP::Data->name(lc($action))->value(\SOAP::Data->value(SOAP::Data->name($key => []))));
        } else {
            push(@changes, SOAP::Data->name(lc($action))->value(\SOAP::Data->value(SOAP::Data->name($key => [@values]))));
        }
    }

    if ($self->_getConnect()) {
        return LDAP_SERVER_DOWN;
    }

    my $res;
    for (my $i = 0; $i < $RETRY; $i++) {
        if ($i && $conf->{connection}[0]->{interval}[0]) {
            sleep $conf->{connection}[0]->{interval}[0];
        }
        eval {
            $res = $self->{soap}->modify(
                SOAP::Data->name('sessid' => $self->{sessid}),
                SOAP::Data->name('dn' => $dn),
                SOAP::Data->name('modifyRequest')
                      ->type('modifyRequest')
                      ->value(\SOAP::Data->value(@changes))
                );
        };

        if ($@) {
            my $error = $@;
            $self->log(level => 'err', message => "Modifying $dn failed: retry=".($i + 1)." $error");
            if ($error =~ /[45][0-9]{2} /) {
                $rc = LDAP_OTHER;
                next;
            }
            return LDAP_OTHER;
        } elsif (!ref $res) {
            $self->log(level => 'err', message => "Modifying $dn failed: ".$self->{soap}->transport->status);
            return LDAP_OTHER;
        } elsif (!defined($res->result)) {
            $self->log(level => 'err', message => "Modifying $dn failed: ".$res->faultstring);
            return LDAP_OTHER;
        } elsif (${$res->result}[0] == -1 && ${$res->result}[1] eq "Not authenticated") {
            $self->log(level => 'err', message => "Modifying $dn failed: retry=".($i + 1)." ".${$res->result}[1]);
            undef($self->{sessid});
            undef($self->{logintime});
            $self->_getConnect();
            $rc = LDAP_OTHER;
            next;
        } else {
            $rc = LDAP_SUCCESS;
        }
        last;
    }
    if ($rc) {
        return $rc;
    }

    $rc = ${$res->result}[0];
    if ($rc) {
        $self->log(level => 'err', message => "Modifying $dn failed: ".decode('utf8', ${$res->result}[1]));
    }

    $self->_freeConnect();

    return $rc;
}

=pod

=head2 add($dn, $entryStr)

Add information by SOAP.

=cut

sub add
{
    my $self = shift;
    my ($dn,  $entryStr) = @_;
    my $conf = $self->{_config};
    my $rc = LDAP_SUCCESS;

    $dn =~ s/$self->{suffix}$/$conf->{basedn}[0]/i;
    $entryStr = encode('utf8', $entryStr);

    my %attrs;
    my @info = split(/\n/, $entryStr);
    foreach my $attr (@info) {
        my ($key, $val) = split(/: /, $attr);
        if ($key =~ /^(createTimestamp|modifyTimestamp|plainpassword)$/i) {
            next;
        }

        if ($key eq 'structuralObjectClass') {
            last;
        }

        $key =~ s/;/_/g;

        $val =~ s/$self->{suffix}/$conf->{basedn}[0]/i;

        # replace carriage return to linefeed
        $val =~ s/\r/$conf->{breakchar}/g;
        if ($key =~ /^userPassword$/i && $conf->{hash} ne 'PLAINTEXT') {
            $val = '{'.$conf->{hash}.'}'.$val;
        }
        if ($val eq 'TRUE' || $val eq 'FALSE') {
            $val = '"'.$val.'"';
        }

        push(@{$attrs{$key}}, $val);
    }

    my @attrs = ();
    foreach my $key (keys %attrs) {
        push(@attrs, SOAP::Data->name($key => $attrs{$key}));
    }

    if ($self->_getConnect()) {
        return LDAP_SERVER_DOWN;
    }

    my $res;
    for (my $i = 0; $i < $RETRY; $i++) {
        if ($i && $conf->{connection}[0]->{interval}[0]) {
            sleep $conf->{connection}[0]->{interval}[0];
        }
        eval {
            $res = $self->{soap}->add(
                SOAP::Data->name('sessid' => $self->{sessid}),
                SOAP::Data->name('dn' => $dn),
                SOAP::Data->name('addRequest')
                      ->type('addRequest')
                      ->value(\SOAP::Data->value(@attrs))
                );
        };

        if ($@) {
            my $error = $@;
            $self->log(level => 'err', message => "Adding $dn failed: retry=".($i + 1)." $error");
            if ($error =~ /[45][0-9]{2} /) {
                $rc = LDAP_OTHER;
                next;
            }
            return LDAP_OTHER;
        } elsif (!ref $res) {
            $self->log(level => 'err', message => "Adding $dn failed: ".$self->{soap}->transport->status);
            return LDAP_OTHER;
        } elsif (!defined($res->result)) {
            $self->log(level => 'err', message => "Adding $dn failed: ".$res->faultstring);
            return LDAP_OTHER;
        } elsif (${$res->result}[0] == -1 && ${$res->result}[1] eq "Not authenticated") {
            $self->log(level => 'err', message => "Adding $dn failed: retry=".($i + 1)." ".${$res->result}[1]);
            undef($self->{sessid});
            undef($self->{logintime});
            $self->_getConnect();
            $rc = LDAP_OTHER;
            next;
        } elsif (${$res->result}[0] == LDAP_ALREADY_EXISTS && $i) {
            $rc = LDAP_SUCCESS;
            ${$res->result}[0] = LDAP_SUCCESS;
        } else {
            $rc = LDAP_SUCCESS;
        }
        last;
    }
    if ($rc) {
        return $rc;
    }

    $rc = ${$res->result}[0];
    if ($rc) {
        $self->log(level => 'err', message => "Adding $dn failed: ".decode('utf8', ${$res->result}[1]));
    }

    if (defined($conf->{deleteflag}) && $rc == LDAP_ALREADY_EXISTS) {
        foreach my $key (keys %{$conf->{deleteflag}}) {
            my $deleteflag = $conf->{deleteflag}{$key};
            if (!defined($deleteflag->{ovrfilter})) {
                next;
            }
            if (defined($deleteflag->{dn}) && $dn !~ /$deleteflag->{dn}/i) {
                next;
            }

            my $delentry;
            ($rc, $delentry) = $self->search($dn, 0, 0, 1, 0, $deleteflag->{ovrfilter}, 0, 'objectClass');
            if ($rc) {
                last;
            }
            if ($delentry) {
                my @list;
                foreach my $attr (keys %attrs) {
                    my @vals;
                    foreach my $val (@{$attrs{$attr}}) {
                        push(@vals, decode('utf8', $val));
                    }
                    push(@list, 'REPLACE', $attr, @vals);
                }
                if (defined($deleteflag->{enable}) && !defined($attrs{$key})) {
                    push(@list, 'REPLACE', $key, $deleteflag->{enable});
                }
                $rc = $self->modify($dn, @list);
                last;
            }
        }
    }

    $self->_freeConnect();

    return $rc;
}

=pod

=head2 delete($dn)

Delete data from SOAP server.

=cut

sub delete
{
    my $self = shift;
    my ($dn) = @_;
    my $conf = $self->{_config};
    my $rc = LDAP_SUCCESS;

    $dn =~ s/$self->{suffix}$/$conf->{basedn}[0]/i;

    if ($self->_getConnect()) {
        return LDAP_SERVER_DOWN;
    }

    if (defined($conf->{deleteflag})) {
        my $entryStr;
        ($rc, $entryStr) = $self->search($dn, 0, 0, 1, 0, '(objectClass=*)');
        if ($rc) {
            return $rc;
        }

        my $match = 0;
        foreach my $key (keys %{$conf->{deleteflag}}) {
            my $deleteflag = $conf->{deleteflag}{$key};
            if (defined($deleteflag->{dn}) && $dn !~ /$deleteflag->{dn}/i) {
                next;
            }
            if (!defined($deleteflag->{filter}) || $self->parseFilter($deleteflag->{filterobj}, $entryStr)) {
                $rc = $self->modify($dn, "REPLACE", $key, $deleteflag->{value});
                $match = 1;
            }
        }
        if ($match) {
            return $rc;
        }
    }

    my $res;
    for (my $i = 0; $i < $RETRY; $i++) {
        if ($i && $conf->{connection}[0]->{interval}[0]) {
            sleep $conf->{connection}[0]->{interval}[0];
        }
        eval {
            $res = $self->{soap}->delete(
                SOAP::Data->name('sessid' => $self->{sessid}),
                SOAP::Data->name('dn' => $dn)
            );
        };

        if ($@) {
            my $error = $@;
            $self->log(level => 'err', message => "Deleting $dn failed: retry=".($i + 1)." $error");
            if ($error =~ /[45][0-9]{2} /) {
                $rc = LDAP_OTHER;
                next;
            }
            return LDAP_OTHER;
        } elsif (!ref $res) {
            $self->log(level => 'err', message => "Deleting $dn failed: ".$self->{soap}->transport->status);
            return LDAP_OTHER;
        } elsif (!defined($res->result)) {
            $self->log(level => 'err', message => "Deleting $dn failed: ".$res->faultstring);
            return LDAP_OTHER;
        } elsif (${$res->result}[0] == -1 && ${$res->result}[1] eq "Not authenticated") {
            $self->log(level => 'err', message => "Deleting $dn failed: retry=".($i + 1)." ".${$res->result}[1]);
            undef($self->{sessid});
            undef($self->{logintime});
            $self->_getConnect();
            $rc = LDAP_OTHER;
            next;
        } elsif (${$res->result}[0] == LDAP_NO_SUCH_OBJECT && $i) {
            $rc = LDAP_SUCCESS;
            ${$res->result}[0] = LDAP_SUCCESS;
        } else {
            $rc = LDAP_SUCCESS;
        }
        last;
    }
    if ($rc) {
        return $rc;
    }

    $rc = ${$res->result}[0];
    if ($rc) {
        $self->log(level => 'err', message => "Deleting $dn failed: ".decode('utf8', ${$res->result}[1]));
    }

    $self->_freeConnect();

    return $rc;
}


sub _getConnect
{
    my $self = shift;
    my $conf = $self->{_config};
    my $res;
    my $rc = LDAP_SUCCESS;

    if (defined($self->{sessid})) {
        if ($self->{logintime} + $conf->{expire}[0] < time) {
            eval "\$res = \$self->{soap}->unbind(\$self->{sessid})";
            undef($self->{sessid});
            undef($self->{logintime});
        } else {
            return 0;
        }
    }

    for (my $i = 0; $i < $RETRY; $i++) {
        if ($i && $conf->{connection}[0]->{interval}[0]) {
            sleep $conf->{connection}[0]->{interval}[0];
        }
        eval "\$res = \$self->{soap}->bind(\$conf->{binddn}[0], \$conf->{bindpw}[0])";
        if ($@) {
            $self->log(level => 'alert', message => "Can't connect to $conf->{proxy}[0]: retry=".($i + 1)." $@");
            $rc = LDAP_OTHER;
            next;
        } elsif (!ref $res || !defined($res->result)) {
            $self->log(level => 'alert', message => "Can't connect to $conf->{proxy}[0]");
            return -1;
        } elsif (${$res->result}[0]) {
            $self->log(level => 'alert', message => "Can't connect to $conf->{proxy}[0](${$res->result}[0])".(defined(${$res->result}[1]) ? ": ${$res->result}[1]" : ''));
            return -1;
        } else {
            $rc = LDAP_SUCCESS;
        }
        last;
    }
    if ($rc) {
        return -1;
    }

    $self->{sessid} = ${$res->result}[2];
    $self->{logintime} = time;

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
    if (!defined($conf->{connection}[0]->{timeout})) {
        $conf->{connection}[0]->{timeout}[0] = 0;
    }
    if (defined($conf->{connection}[0]->{retry})) {
        $RETRY = $conf->{connection}[0]->{retry}[0];
        if ($RETRY <= 0) {
            $RETRY = 1;
        }
    }
    if (!defined($conf->{expire})) {
        $conf->{expire}[0] = 3600;
    }

    if (!defined($conf->{'proxy'})) {
        $self->log(level => 'alert', message => "proxy of SOAP doesn't exist");
        return 1;
    }

    return $rc;
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

sub _mb_conv
{
    my $self = shift;
    my ($str) = @_;

    my @chars = ($str =~ /\\([0-9A-F]{2})/g);

    if (!@chars || @chars % 3) {
        return $str;
    }

    my $conv = pack("H*", join("", @chars));
    my $org = "\\\\".join("\\\\", @chars);
    $str =~ s/$org/$conv/;

    return $str;
}

=head1 SEE ALSO

L<LISM>,
L<LISM::Storage>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2008 by Kaoru Sekiguchi

=cut

1;
