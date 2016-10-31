package LISM::Storage::LDIF;

use strict;
use base qw(LISM::Storage);
use LISM::Constant;
use MIME::Base64;
use Encode;
use Data::Dumper;

=head1 NAME

LISM::Storage::LDIF - LDIF storage for LISM

=head1 DESCRIPTION

This class implements the L<LISM::Storage> interface for LDIF file.

=head1 METHODS

=head2 init

Initialize LDIF.

=cut

sub init
{
    my $self = shift;
    my $conf = $self->{_config};

    $self->SUPER::init();

    if (!defined($conf->{nc})) {
        ($conf->{nc}) = ($conf->{uri}[0] =~ /^ldaps?:\/\/[^\/]+\/(.+)$/i);
    }

    return 0;
}

=pod

=head2 modify($dn, @list)

Modify LDIF.

=cut

sub modify
{
    my $self = shift;
    my ($dn, @list) = @_;
    my $conf = $self->{_config};
    my $rc = LDAP_SUCCESS;
    my $foreign_rdnattr;

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
    $dn =~ s/$self->{suffix}$/$conf->{nc}/i;

    my $ldif = "dn: $dn\nchangetype: modify\n";
    while ( @list > 0) {
        my $action = shift @list;
        my $key    = lc(shift @list);
        my @values;

        while (@list > 0 && $list[0] ne "ADD" && $list[0] ne "DELETE" && $list[0] ne "REPLACE") {
            push(@values, shift @list);
        }

        if ($key =~ /^(modifyTimestamp|plainPassword)$/i) {
            next;
        }

        if ($foreign_rdnattr && $key eq $foreign_rdnattr) {
            next;
        }

        if ($key eq 'entrycsn') {
            last;
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
            $values[$i] =~ s/$self->{suffix}/$conf->{nc}/i;
        }

        if ($action eq "DELETE" && !$values[0]) {
            $ldif .= lc($action).": $key\n";
        } else {
            $ldif .= lc($action).": $key\n";
            foreach my $value (@values) {
                $ldif .= "$key: $value\n";
            }
        }
        $ldif .= "-\n";
    }

    $rc = $self->_write($ldif);

    return ($rc, 'LISM_NO_OPERATION');
}

=pod

=head2 add($dn, $entryStr)

Add LDIF.

=cut

sub add
{
    my $self = shift;
    my ($dn,  $entryStr) = @_;
    my $conf = $self->{_config};
    my $rc = LDAP_SUCCESS;
    $dn =~ s/\\22/\\"/gi;
    $dn =~ s/\\23/\\#/gi;
    $dn =~ s/\\2B/\\+/gi;
    $dn =~ s/\\2F/\//gi;
    $dn =~ s/\\3B/\\;/gi;
    $dn =~ s/\\3C/\\</gi;
    $dn =~ s/\\3E/\\>/gi;
    $dn =~ s/\\3D/=/gi;
    $dn =~ s/\\5C/\\\\/gi;

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
    $dn =~ s/$self->{suffix}$/$conf->{nc}/i;

    my $ldif = "dn: $dn\nchangetype: add\n";
    my @info = split(/\n/, $entryStr);
    foreach my $attr (@info) {
        my $key;
        my $val;
        if ($attr =~ /:: /) {
            ($key, $val) = split(/:: /, $attr);
            $val = decode_base64($val);
        } else {
            ($key, $val) = split(/: ?/, $attr, 2);
        }

        if ($key =~ /^(createTimestamp|modifyTimestamp|plainpassword)$/i) {
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

        $val =~ s/$self->{suffix}/$conf->{nc}/i;

        $ldif .= "$key: $val\n";
    }

    $rc = $self->_write($ldif);

    return ($rc, 'LISM_NO_OPERATION');
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

    $dn =~ s/$self->{suffix}$/$conf->{nc}/i;

    my $ldif = "dn: $dn\nchangetype: delete\n";
    $rc = $self->_write($ldif);

    return ($rc, 'LISM_NO_OPERATION');
}

sub _checkConfig
{
    my $self = shift;
    my $conf = $self->{_config};
    my $rc = 0;

    if ($rc = $self->SUPER::_checkConfig()) {
        return $rc;
    }

    foreach my $ldapmap (@{$conf->{ldapmap}}) {
        if (!defined($ldapmap->{type})) {
            $ldapmap->{type} = 'attribute';
        }
    }

    return $rc;
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

sub _write
{
    my $self = shift;
    my ($ldif) = @_;
    my $conf = $self->{_config};

    if (defined($conf->{file})) {
        my $fd;
        if (!open($fd, ">> $conf->{file}")) {
            return LDAP_OTHER;
        }
        print $fd;
        close($fd);
    } else {
        print encode('utf8', $ldif);
    }

    return LDAP_SUCCESS;
}

=head1 SEE ALSO

L<LISM>,
L<LISM::Storage>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
