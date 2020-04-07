#!/usr/bin/perl

use strict;
use URI;
use Net::LDAP;
use Net::LDAP::Util qw(ldap_error_text);
use LISM::Constant;

our $RETRY = 3;

sub searchLdap
{
    my ($self, $conf, $param, $pids, $base, $sizeLim, $filter) = @_;
    my $pid = ${$pids}[$#{$pids}];
    my @keys = ();
    my @entries = ();
    my $binddn;
    my $bindpw;
    my $msg;
    my $rc;
    my $error;

    my $uri = URI->new($param->{uri}->{value});
    if (!$uri) {
        return (LDAP_OTHER, "Invalid uri", \@keys, @entries);
    }

    if (defined($param->{binddn})) {
        $binddn = $param->{binddn}->{value};
        $bindpw = $param->{bindpw}->{value};
    }

    for (my $i = 0; $i < $RETRY; $i++) {
        if (!defined($self->{plugin}->{ldap})) {
            $self->{plugin}->{ldap} = Net::LDAP->new($param->{uri}->{value});
            if (!defined($self->{plugin}->{ldap})) {
                $rc = LDAP_SERVER_DOWN;
                $error = "Can't connect $param->{uri}->{value}";
                next;
            }
        }

        if ($binddn) {
            $msg = $self->{plugin}->{ldap}->bind($binddn, password => $bindpw);
        } else {
            $msg = $self->{plugin}->{ldap}->bind();
        }
        if ($msg->code) {
            $self->{plugin}->{ldap}->unbind();
            undef($self->{plugin}->{ldap});
            $rc = $msg->code;
            $error = $msg->error;
            next;
        }
        last;
    }

    if (!defined($self->{plugin}->{ldap})) {
        return ($rc, $error, \@keys, @entries);
    }

    my $searchdn = $uri->dn;
    my $filterStr = $uri->filter;
    $searchdn =~ s/\%c/$pid/g;
    $filterStr =~ s/\%c/$pid/g;
    $msg = $self->{plugin}->{ldap}->search(base => $searchdn, scope => $uri->scope, filter => $filterStr);
    if (!$msg->code) {
        for (my $i = 0; $i < $msg->count; $i++) {
            my $entry = $msg->entry($i);
            my $dn = $entry->dn;
            $dn =~ s/$searchdn/$base/i;

            my $entryStr = "dn: $dn\n";
            foreach my $attr ($entry->attributes) {
                foreach my $value ($entry->get_value($attr)) {
                    $value = decode('utf8', $value);
                    $entryStr = $entryStr.$attr.": $value\n";
                }
            }

            my $key = undef;
            if (defined($param->{id})) {
                if ($param->{id}->{type} eq 'regexp') {
                    ($key) = ($entryStr =~ /$param->{id}->{value}/i);
                } elsif ($param->{id}->{type} eq 'attribute') {
                    ($key) = ($entryStr =~ /^$param->{id}->{value}:\:? (.*)$/mi);
                }
            } else {
                ($key) = ($entryStr =~ /^dn: [^=]+=([^,]+),/i);
            }

            push(@keys, $key);
            push(@entries, $entryStr);
        }
    }

    return ($msg->code, $msg->error, \@keys, @entries);
}

sub searchLism
{
    my ($self, $conf, $param, $pids, $base, $sizeLim, $filter) = @_;
    my $lism = $self->{lism};
    my $filterStr = $filter ? $filter->as_string : '(objectClass=*)';
    my $pid = defined(${$pids}[$#{$pids}]) || !$#{$pids} ? ${$pids}[$#{$pids}] : ${$pids}[$#{$pids} - 1];
    my @attrs;
    my @match_keys = ();
    my @match_entries = ();

    my $searchdn = $param->{base}->{value};
    my $scope = 2;

    if (defined($param->{scope}->{value})) {
        if ($param->{scope}->{value} eq 'base') {
            $scope = 0;
        } elsif ($param->{scope}->{value} eq 'one') {
            $scope = 1;
        }
    }
    if (defined($param->{filter})) {
        if ($param->{filter}->{value} =~ /^\(.+\)$/) {
            $filterStr = "(&$filterStr".$param->{filter}->{value}.")";
        } else {
            $filterStr = "(&$filterStr(".$param->{filter}->{value}."))";
        }
    }
    if (defined($param->{attrs})) {
        @attrs = split(/, */, $param->{attrs}->{value});
    }

    $searchdn =~ s/\%c/$pid/g;
    $filterStr =~ s/\%c/$pid/g;
    my ($rc, @entries) = $lism->search($searchdn, $scope, 1, 0, 0, $filterStr, 0, @attrs);

    foreach my $entry (@entries) {
        $entry =~ s/^dn: ([^,]+).*\n/dn: $1,$base\n/i;

        my $key = undef;
        if (defined($param->{id})) {
            if ($param->{id}->{type} eq 'regexp') {
                ($key) = ($entry =~ /$param->{id}->{value}/i);
            } elsif ($param->{id}->{type} eq 'attribute') {
                ($key) = ($entry =~ /^$param->{id}->{value}:\:? (.*)$/mi);
            }
        } else {
            ($key) = ($entry =~ /^dn: [^=]+=([^,]+),/i);
        }

        push(@match_keys, $key);
        push(@match_entries, $entry);
    }

    return ($rc, ldap_error_text($rc), \@match_keys, @match_entries);
}

1;
