#!/usr/bin/perl
#
# SOAP LDAP Gateway
#
# Copyright(c) 2016 SECIOSS, INC.
#

package SoapLdap;

use strict;
use Net::LDAP;
use CGI::Session;
use Config::General;
use MIME::Base64;
use Encode;
use Data::Dumper;

our $CONF = 'soapldap.conf';
my $SESSION_DIR = '/tmp';
our $rawattrs = '^(jpegphoto|photo|objectSid|objectGUID|.*;binary)$';

sub _config
{
    my $config = Config::General->new($CONF);
    my %conf = $config->getall;

    if (!defined($conf{'sessionexpire'})) {
        $conf{'sessionexpire'} = 86400;
    }

    return %conf;
}

sub _checksession
{
    my $self = shift;
    my ($session, %conf) = @_;

    if ($session->id) {
        if ($session->ctime + $conf{'sessionexpire'} < time) {
            $session->close();
            $session->delete();
            return 0;
        }
        return 1;
    } else {
        return 0;
    }
}

sub isauth
{
    my $self = shift;
    my ($sessid) = @_;
    my %conf = $self->_config;

    my $session = CGI::Session->load($sessid);
    return $self->_checksession($session, %conf);
}

sub bind
{
    my $self = shift;
    my ($binddn, $bindpw) = @_;

    my %conf = $self->_config;

    my $ldap = Net::LDAP->new($conf{'uri'});
    if (!defined($ldap)) {
        return [-1, "Can't connect $conf{'uri'}"];
    }

    if (defined($conf{'suffix'})) {
        $binddn =~ s/o=lism$/$conf{'suffix'}/i;
    }

    my $msg = $ldap->bind($binddn, password => $bindpw);
    if (!$msg->code) {
        my $session = CGI::Session->new(undef, undef, {Directory => $SESSION_DIR});
        $session->param('binddn', $binddn);
        $session->param('bindpw', $bindpw);

        return [$msg->code, $msg->error, $session->id];
    } else {
        return [$msg->code, $msg->error, ''];
    }
}

sub unbind
{
    my $self = shift;
    my ($sessid) = @_;
    my %conf = $self->_config;

    my $session = CGI::Session->load($sessid);
    if (!$self->_checksession($session, %conf)) {
        return [-1, "Not authenticated"];
    }

    $session->close();
    $session->delete();    
}

sub search
{
    my $self = shift;
    my ($sessid, $base, $scope, $deref, $sizeLim, $timeLim, $filter, $attrOnly, $attrs) = @_;
    my @entries;
    my %conf = $self->_config;
    my $suffix;

    my $session = CGI::Session->load($sessid);
    if (!$self->_checksession($session, %conf)) {
        return [-1, "Not authenticated"];
    }

    my $ldap = Net::LDAP->new($conf{'uri'});
    if (!defined($ldap)) {
        return [-1, "Can't connect $conf{'uri'}"];
    }

    if (defined($conf{'suffix'})) {
        $base =~ s/o=lism$/$conf{'suffix'}/i;
        $filter =~ s/o=lism\)/$conf{'suffix'})/gi;
        $suffix = $conf{'suffix'};
        $suffix =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
    }

    my $msg = $ldap->bind($session->param('binddn'), password => $session->param('bindpw'));
    if ($msg->code) {
        return [$msg->code, $msg->error];
    }

    $msg = $ldap->search(base => $base, scope => $scope, deref => $deref, sizelimit => $sizeLim, timelimit => $timeLim, filter => $filter, typesonly => $attrOnly, attrs => $attrs);
    if (!$msg->code) {
        for (my $i = 0; $i < $msg->count; $i++) {
            my $entry = $msg->entry($i);
            my $dn = $entry->dn;
            if ($suffix) {
                $dn =~ s/$suffix$/o=lism/i;
            }

            my $entryStr = "dn: $dn\n";
            foreach my $attr ($entry->attributes) {
                foreach my $value ($entry->get_value($attr)) {
                    if ($attr =~ /$rawattrs/i) {
                        $value = encode_base64($value, '');
                        $entryStr = $entryStr.$attr.":: $value\n";
                    } else {
                        if ($value =~ /\n/) {
                            $value = encode_base64($value, '');
                            $entryStr = $entryStr.$attr.":: $value\n";
                        } else {
                            $entryStr = $entryStr.$attr.": $value\n";
                        }
                    }
                }
            }
            push(@entries, $entryStr);
        }
    }

    return [$msg->code, $msg->error, \@entries];
}

sub add
{
    my $self = shift;
    my ($sessid, $dn, $req) = @_;
    my @attrs = ();
    my %conf = $self->_config;

    my $session = CGI::Session->load($sessid);
    if (!$self->_checksession($session, %conf)) {
        return [-1, "Not authenticated"];
    }

    foreach my $attr (keys %{$req}) {
        my $value = $req->{$attr};
        if (defined($conf{'suffix'})) {
            $value =~ s/o=lism$/$conf{'suffix'}/i;
        }
        push(@attrs, $attr => $value);
    }

    my $ldap = Net::LDAP->new($conf{'uri'});
    if (!defined($ldap)) {
        return [-1, "Can't connect $conf{'uri'}"];
    }

    if (defined($conf{'suffix'})) {
        $dn =~ s/o=lism$/$conf{'suffix'}/i;
    }

    my $msg = $ldap->bind($session->param('binddn'), password => $session->param('bindpw'));
    if ($msg->code) {
        return [$msg->code, $msg->error];
    }

    $msg = $ldap->add($dn, attrs => [@attrs]);

    return [$msg->code, $msg->error];
}

sub modify
{
    my $self = shift;
    my ($sessid, $dn, $req) = @_;
    my @changes = ();
    my %conf = $self->_config;

    my $session = CGI::Session->load($sessid);
    if (!$self->_checksession($session, %conf)) {
        return [-1, "Not authenticated"];
    }

    foreach my $action (keys %{$req}) {
        if (ref($req->{$action}) eq 'ARRAY') {
            foreach my $info (@{$req->{$action}}) {
                if (defined($conf{'suffix'})) {
                    foreach my $attr (keys %{$info}) {
                        for (my $i = 0; $i < @{$info->{$attr}}; $i++) {
                            ${$info->{$attr}}[$i] =~ s/o=lism$/$conf{'suffix'}/i;
                        }
                    }
                }
                push(@changes, lc($action) => [%{$info}]);
            }
        } else {
            if (defined($conf{'suffix'})) {
                foreach my $attr (keys %{$req->{$action}}) {
                    for (my $i = 0; $i < @{$req->{$action}->{$attr}}; $i++) {
                        ${$req->{$action}->{$attr}}[$i] =~ s/o=lism$/$conf{'suffix'}/i;
                    }
                }
            }
            push(@changes, lc($action) => [%{$req->{$action}}]);
        }
    }

    my $ldap = Net::LDAP->new($conf{'uri'});
    if (!defined($ldap)) {
        return [-1, "Can't connect $conf{'uri'}"];
    }

    if (defined($conf{'suffix'})) {
        $dn =~ s/o=lism$/$conf{'suffix'}/i;
    }

    my $msg = $ldap->bind($session->param('binddn'), password => $session->param('bindpw'));
    if ($msg->code) {
        return [$msg->code, $msg->error];
    }

    $msg = $ldap->modify($dn, changes => [@changes]);

    return [$msg->code, $msg->error];
}

sub delete
{
    my $self = shift;
    my ($sessid, $dn) = @_;
    my @attrs = ();
    my %conf = $self->_config;

    my $session = CGI::Session->load($sessid);
    if (!$self->_checksession($session, %conf)) {
        return [-1, "Not authenticated"];
    }

    my $ldap = Net::LDAP->new($conf{'uri'});
    if (!defined($ldap)) {
        return [-1, "Can't connect $conf{'uri'}"];
    }

    if (defined($conf{'suffix'})) {
        $dn =~ s/o=lism$/$conf{'suffix'}/i;
    }

    my $msg = $ldap->bind($session->param('binddn'), password => $session->param('bindpw'));
    if ($msg->code) {
        return [$msg->code, $msg->error];
    }

    $msg = $ldap->delete($dn);

    return [$msg->code, $msg->error];
}

=head1 SEE ALSO

L<LISM>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

(c) 2008 Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
