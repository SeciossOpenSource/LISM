package LISM::Storage::GAE;

use strict;
use base qw(LISM::Storage);
use Net::LDAP;
use LISM::Constant;
use Time::Local;
use Time::HiRes qw(gettimeofday);
use POSIX;
use MIME::Base64;
use Encode;
use Data::Dumper;

=head1 NAME

LISM::Storage::GAE - GAE storage for LISM

=head1 DESCRIPTION

This class implements the L<LISM::Storage> interface for GAE Manager.

=head1 METHODS

=head2 init

Initialize GAE storage.

=cut

sub init
{
    my $self = shift;
    my $conf = $self->{_config};

    $self->SUPER::init();

    return 0;
}

=pod

=head2 _objSearch($obj, $pkeys, $suffix, $sizeLim, $timeLim, $filter)

Search the appropriate records in the object's file.

=cut

sub _objSearch
{
    my $self = shift;
    my ($obj, $pkeys, $suffix, $sizeLim, $filter) = @_;
    my $conf = $self->{_config};
    my $oconf = $obj->{conf};
    my @match_entries = ();
    my @match_keys = ();
    my $rc = LDAP_SUCCESS;

    open(CMD, "$conf->{command}[0] read $obj->{name} $suffix|") || return ($?, \@match_keys, @match_entries);

    my $entryStr = '';
    while (<CMD>) {
        if (/^\n$/) {
            if ($self->parseFilter($filter, $entryStr)) {
                my ($id) = ($entryStr =~ /^[^=]+=([^,]+),/);
                push(@match_entries, $self->_pwdFormat($entryStr));
                push(@match_keys, $id);
            }
            $entryStr = '';
        } else {
            $entryStr .= $_;
        }
    }

    close(CMD);

    return ($rc , \@match_keys, @match_entries);
}

=pod

=head2 modify($dn, @list)

Write modify operation to file.

=cut

sub modify
{
    my $self = shift;
    my ($dn, @list) = @_;
    my $conf = $self->{_config};
    my $timestamp;

    my $rc = $self->_writeUpdateLog('modify', $conf->{updatelog}[0], $dn, @list);
    if ($rc) {
        return LDAP_OTHER;
    }

    return LDAP_SUCCESS;
}

=pod

=head2 add($dn, $entryStr)

Write add operation to file.

=cut

sub add
{
    my $self = shift;
    my ($dn,  $entryStr) = @_;
    my $conf = $self->{_config};

    my $rc = $self->_writeUpdateLog('add', $conf->{updatelog}[0], $dn, $entryStr);
    if ($rc) {
        return LDAP_OTHER;
    }

    return LDAP_SUCCESS;
}

=pod

=head2 delete($dn)

Write delete operation to file.

=cut

sub delete
{
    my $self = shift;
    my ($dn) = @_;
    my $conf = $self->{_config};
    my $rc = LDAP_SUCCESS;

    $rc = $self->_writeUpdateLog('delete', $conf->{updatelog}[0], $dn);
    if ($rc) {
        return LDAP_OTHER;
    }

    return LDAP_SUCCESS;
}

sub _checkConfig
{
    my $self = shift;
    my $conf = $self->{_config};
    my $rc = 0;

    $rc = $self->SUPER::_checkConfig();
    if ($rc) {
        return $rc;
    }

    if (!defined($conf->{appid}) || !$conf->{appid}[0]) {
        $self->log(level => 'alert', message => "Set appid");
        return 1;
    }
    if (!defined($conf->{admin}) || !$conf->{admin}[0]) {
        $self->log(level => 'alert', message => "Set admin");
        return 1;
    }
    if (!defined($conf->{passwd}) || !$conf->{passwd}[0]) {
        $self->log(level => 'alert', message => "Set passwd");
        return 1;
    }
    if (!defined($conf->{command}) || !$conf->{command}[0]) {
        $self->log(level => 'alert', message => "Set command");
        return 1;
    }
    if (!defined($conf->{updatelog}) || !$conf->{updatelog}[0]) {
        $self->log(level => 'alert', message => "Set updatelog");
        return 1;
    }
}

=head1 SEE ALSO

L<LISM>,
L<LISM::Storage>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Kaoru Sekiguchi

=cut

1;
