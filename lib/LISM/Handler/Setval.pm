package LISM::Handler::Setval;

use strict;
use base qw(LISM::Handler);
use LISM::Constant;
use Encode;
use Data::Dumper;

=head1 NAME

LISM::Handler::Setval - Handler to set value

=head1 DESCRIPTION

This class implements the L<LISM::Hanlder> interface to set value.

=head1 METHODS

=pod

=head2 getOrder

Get order to do handler.

=cut

sub getOrder
{
    return 'first';
}

=head2 pre_add($dnp, $entryStrp)

Set Value before add operation is done.

=cut

sub pre_add
{
    my $self = shift;
    my ($dnp, $entryStrp) = @_;
    my $conf = $self->{_config};

    if (!defined($conf->{entry})) {
        return LDAP_SUCCESS;
    }

    foreach my $entry (@{$conf->{entry}}) {
        if (defined($entry->{dn}) && ${$dnp} !~ /$entry->{dn}/i) {
            next;
        }
        if (defined($entry->{filter}) && !LISM::Storage->parseFilter($entry->{filterobj}, ${$entryStrp}[0])) {
            next;
        }

        # Default value
        if (defined($entry->{default})) {
            foreach my $attr (keys %{$entry->{default}}) {
                if (${$entryStrp}[0] !~ /^$attr:/mi) {
                    my @values = $self->_getStaticValue($entry->{default}{$attr}, ${$dnp}, ${$entryStrp}[0]);
                    foreach my $value (@values) {
                        ${$entryStrp}[0] = "${$entryStrp}[0]$attr: $value\n";
                    }
                }
            }
        }

        # Replace values
        if (defined($entry->{replace})) {
            foreach my $attr (keys %{$entry->{replace}}) {
                my @values = $self->_getStaticValue($entry->{replace}{$attr}, ${$dnp}, ${$entryStrp}[0]);

                ${$entryStrp}[0] =~ s/$attr:{1,2} .*\n//gi;
                foreach my $value (@values) {
                    ${$entryStrp}[0] = "${$entryStrp}[0]$attr: $value\n";
                }
            }
        }

        # Add values
        if (defined($entry->{addition})) {
            foreach my $attr (keys %{$entry->{addition}}) {
                my @values = $self->_getStaticValue($entry->{addition}{$attr}, ${$dnp}, ${$entryStrp}[0]);
                foreach my $value (@values) {
                    my $tmpval = $value;
                    $tmpval =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                    if (${$entryStrp}[0] !~ /^$attr:{1,2} $tmpval/mi) {
                        ${$entryStrp}[0] = "${$entryStrp}[0]$attr: $value\n";
                    }
                }
            }
        }

        # Delete values
        if (defined($entry->{delete})) {
            foreach my $attr (keys %{$entry->{delete}}) {
                my @values = $self->_getStaticValue($entry->{delete}{$attr}, ${$dnp}, ${$entryStrp}[0]);
                foreach my $value (@values) {
                    ${$entryStrp}[0] =~ s/\n$attr:{1,2} $value\n/\n/i;
                }
            }
        }
    }

    return LDAP_SUCCESS;
}

sub _checkConfig
{
    my $self = shift;
    my $conf = $self->{_config};
    my $rc = 0;

    if ($rc = $self->SUPER::_checkConfig()) {
        return $rc;
    }

    if (defined($conf->{libload})) {
        foreach my $lib (@{$conf->{libload}}) {
            eval "do \'$lib\'";
            if ($@) {
                $self->log(level => 'alert', message => "setval do require $lib: $@");
                return 1;
            }
        }
    }

    if (defined($conf->{entry})) {
        foreach my $entry (@{$conf->{entry}}) {
            if (defined($entry->{filter})) {
                $entry->{filter} =~ s/&amp;/&/g;
                $entry->{filterobj} = Net::LDAP::Filter->new(encode('utf8', $entry->{filter}));
            }

            if (defined($entry->{default})) {
                foreach my $attr (keys %{$entry->{default}}) {
                    # check type of value
                    if (defined($entry->{default}{$attr}->{value}) && 
                        !ref($entry->{default}{$attr}->{value}[0])) {
                        $self->log(level => 'alert', message => "type of setval default value doesn't exist");
                        return 1;
                    }
                }
            }

            if (defined($entry->{replace})) {
                foreach my $attr (keys %{$entry->{replace}}) {
                    # check type of value
                    if (defined($entry->{replace}{$attr}->{value}) &&
                        !ref($entry->{replace}{$attr}->{value}[0])) {
                        $self->log(level => 'alert', message => "type of setval replace value doesn't exist");
                        return 1;
                    }
                }
            }

            if (defined($entry->{addition})) {
                foreach my $attr (keys %{$entry->{addition}}) {
                    # check type of value
                    if (defined($entry->{addition}{$attr}->{value}) && 
                        !ref($entry->{addition}{$attr}->{value}[0])) {
                        $self->log(level => 'alert', message => "type of setval addition value doesn't exist");
                        return 1;
                    }
                }
            }
        }
    }

    return $rc;
}

sub _getStaticValue
{
    my $self = shift;
    my ($static, $dn, $entryStr) = @_;
    my @values;

    # get static value
    if (defined($static->{value})) {
        for (my $i = 0; $i < @{$static->{value}}; $i++) {
            my @vals;

            if ($static->{value}[$i]->{type} eq 'function') {
                eval "\@vals = $static->{value}[0]->{content}";
                if ($@) {
                    $self->log(level => 'err', message => "setval $static->{value}[0]->{content} failed: $@");
                }
            } else {
                $vals[0] = $static->{value}[$i]->{content};
            }

            if (@vals && $vals[0] ne '') {
                push(@values, @vals);
            }
        }
    }

    return @values;
}

=head1 SEE ALSO

L<LISM>,
L<LISM::Handler>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
