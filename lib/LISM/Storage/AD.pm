package LISM::Storage::AD;

use strict;
use base qw(LISM::Storage::LDAP);
use Net::LDAP;
use Net::LDAP::Control::Paged;
use LISM::Constant;
use MIME::Base64;
use Encode;
use Data::Dumper;

our $PAGESIZE = 10000;
our $MOVECMD = '/dev/fs/C/Windows/System32/dsmove.exe';
our $RSH = '/usr/bin/rsh';
if ($^O eq 'MSWin32') {
    $RSH = 'rsh';
}

=head1 NAME

LISM::Storage::AD - Active Directory storage for LISM

=head1 DESCRIPTION

This class implements the L<LISM::Storage> interface for Active Directory.

=head1 METHODS

=head2 search($base, $scope, $deref, $sizeLim, $timeLim, $filterStr, $attrOnly, 
@attrs)

Search Active Directory information.

=cut

sub search
{
    my $self = shift;
    my @control;
    my $conf = $self->{_config};

    my $page = Net::LDAP::Control::Paged->new(size => $conf->{pagesize}[0]);
    push(@control, $page);

    return $self->_do_search(\@control, @_);
}

=pod

=head2 move($dn, $parentdn)

move information in Active Directory.

=cut

sub move
{
    my $self = shift;
    my ($dn, $parentdn) = @_;
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
    $parentdn =~ s/$self->{suffix}$/$conf->{nc}/i;

    my ($result) = `$RSH $conf->{host} -l $conf->{admin} $MOVECMD $dn -newparent $parentdn "< /dev/null | cat" 2>&1`;
    Encode::from_to($result, 'shiftjis', 'utf8');
    if ($result =~ /成功/) {
        $rc = LDAP_SUCCESS;
    } else {
        $self->log(level => 'err', message => "Moving $dn failed: $result");
        $rc = LDAP_OTHER;
    }

    return $rc;
}

sub _checkConfig
{
    my $self = shift;
    my $conf = $self->{_config};
    my $rc = 0;

    if ($rc = $self->SUPER::_checkConfig()) {
        return $rc;
    }

    ($conf->{host}) = ($conf->{uri}[0] =~ /^ldaps?:\/\/([^\/:]+)/);
    ($conf->{admin}) = ($conf->{binddn}[0] =~ /^[^=]+=([^,]+),/);
    $conf->{hash} = 'AD';

    if (!defined($conf->{pagesize})) {
        $conf->{pagesize}[0] = $PAGESIZE;
    }

    return $rc;
}

=head1 SEE ALSO

L<LISM>,
L<LISM::Storage>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2016 SECIOSS, INC.

=cut

1;
