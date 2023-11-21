#!/usr/bin/perl

use strict;
use Time::HiRes qw(gettimeofday);

require('LISM/Utils/lism_util.pl');

sub createGuid
{
    my ($sec, $microsec) = gettimeofday;
    $microsec = $microsec * 10**(6 - length($microsec));

    my $dec_hex = sprintf("%x", $microsec);
    my $sec_hex = sprintf("%x", $sec);

    $dec_hex = substr($dec_hex, 0, 5);
    $sec_hex = substr($sec_hex, 0, 6);

    my $guid = $dec_hex;
    $guid .= randString(3, "0..9", "a..f");
    $guid .= '-';
    $guid .= randString(4, "0..9", "a..f");
    $guid .= '-';
    $guid .= randString(4, "0..9", "a..f");
    $guid .= '-';
    $guid .= randString(4, "0..9", "a..f");
    $guid .= '-';
    $guid .= $sec_hex;
    $guid .= randString(6, "0..9", "a..f");

    return $guid;
}

=head1 SEE ALSO

L<LISM>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

(c) 2007 Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
