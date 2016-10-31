#!/usr/bin/perl
#
#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 Copyright (C) 2016 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation.

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

1;
