#!/usr/bin/perl

package LISM::Server;

use strict;
use Data::Dumper;

use Config::General;
use LISM::Constant;
use Net::LDAP::Server;
use base 'Net::LDAP::Server';
use fields qw(config lism);

use constant SIZELIMIT => 1000000;

=head1 NAME

LISM::Server - a class for LISM daemon

=head1 DESCRIPTION

This class use LISM for daemon.

=head1 CONSTRUCTOR

This is a plain constructor.

=cut

# constructor
sub new {
    my ($class, $sock) = @_;
    my $self = $class->SUPER::new($sock);
    return $self;
}

sub init {
    my $self = shift;
    my ($lism) = @_;

    $self->{lism} = $lism;
}

# the bind operation
sub bind {
    my $self = shift;
    my ($reqData) = @_;

    my $rc = $self->{lism}->bind($reqData->{name}, $reqData->{authentication}->{simple});

    return {
        'matchedDN' => '',
        'errorMessage' => '',
        'resultCode' => $rc
    };
}

# the search operation
sub search {
    my $self = shift;
    my $reqData = shift;
    my @match_entries = ();

    if (!$reqData->{sizeLimit}) {
        $reqData->{sizeLimit} = SIZELIMIT;
    }

    my $filter = Net::LDAP::Filter->new;
    %{$filter} = %{$reqData->{filter}};
    my ($rc, @entries) = $self->{lism}->search($reqData->{baseObject},
                                               $reqData->{scope},
                                               $reqData->{derefAliases},
                                               $reqData->{sizeLimit},
                                               $reqData->{timeLimit},
                                               $filter->as_string,
                                               $reqData->{typesOnly},
                                               @{$reqData->{attributes}});
    if ($rc) {
        return {
            'matchedDN' => '',
            'errorMessage' => '',
            'resultCode' => $rc
        };
    }

    for (my $i = 0; $i < @entries; $i++) {
        my ($dn) = ($entries[$i] =~ /^dn: (.*)\n/);
        my $entryStr;
        ($entryStr = $entries[$i]) =~ s/^.*\n//;

        my $entry = Net::LDAP::Entry->new;
        $entry->dn($dn);
        foreach my $attr ($entryStr =~ /^([^:]+): /gm) {
            if ($entry->exists($attr)) {
                next;
            }

            my @values = ($entryStr =~ /^$attr: (.*)$/gmi);
            $entry->add(
                $attr => \@values
            );
        }
        push(@match_entries, $entry);
    }

    return {
            'matchedDN' => '',
            'errorMessage' => '',
            'resultCode' => $rc
    }, @match_entries;
}

# the add operation
sub add {
    my $self = shift;
    my ($reqData) = @_;
    my $rc;

    my $entryStr = "dn: ".$reqData->{objectName}."\n";
    foreach my $attr (@{$reqData->{attributes}}) {
        my $type = $attr->{type};
        foreach my $value (@{$attr->{vals}}) {
            $entryStr = "$entryStr$type: $value\n";
        }
    }

    my $rc = $self->{lism}->add($entryStr);

    return {
            'matchedDN' => '',
            'errorMessage' => $rc && defined($self->{lism}->{error}) ? $self->{lism}->{error} : '',
            'resultCode' => $rc
    };
}

# the modify operation
sub modify {
    my $self = shift;
    my ($reqData) = @_;
    my $rc;

    my @list;
    foreach my $mod (@{$reqData->{modification}}) {
        my $op = $mod->{operation};
        my $type = $mod->{modification}->{type};
        my @values = @{$mod->{modification}->{vals}};

        if ($op == 0) {
            push(@list, "ADD");
        } elsif ($op == 1) {
            push(@list, "DELETE");
        } else {
            push(@list, "REPLACE");
        }
        push(@list, $type);
        if (@values) {
            push(@list, @values);
        }
    }

    my $rc = $self->{lism}->modify($reqData->{object}, @list);

    return {
            'matchedDN' => '',
            'errorMessage' => $rc && defined($self->{lism}->{error}) ? $self->{lism}->{error} : '',
            'resultCode' => $rc
    };
}

# the delete operation
sub delete {
    my $self = shift;
    my ($reqData) = @_;
    my $rc;

    my $rc = $self->{lism}->delete($reqData);

    return {
            'matchedDN' => '',
            'errorMessage' => $rc && defined($self->{lism}->{error}) ? $self->{lism}->{error} : '',
            'resultCode' => $rc
    };
}

# the rest of the operations will return an "unwilling to perform"

=head1 SEE ALSO

L<LISM>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

(c) 2009 Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
