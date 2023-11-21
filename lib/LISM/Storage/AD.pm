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

(c) 2006 Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
