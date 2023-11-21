#!/usr/bin/perl

use strict;
use Crypt::SmbHash;
use MIME::Base64;
use Data::Dumper;

sub smbPassword
{
    my ($pwdline) = @_;
    my ($attr, $passwd) = ($pwdline =~ /^([^:]+): (.*)$/);

    if (!$attr) {
        return $pwdline;
    }

    my ($pwhtype) = ($passwd =~ /^\{([^\}]+)\}/);
    if ($pwhtype && $pwhtype !~ /^PLAINTEXT$/i) {
        return $pwdline;
    }

    $passwd =~ s/^\{[^\}]+\}//;
    my ($lmpasswd, $ntpasswd) = ntlmgen $passwd;

    return "$pwdline\nsambaLMPassword: $lmpasswd\nsambaNTPassword: $ntpasswd\nsambaPwdLastSet: ".time;
}

sub littleEndian
{
    my ($hex) = @_;
    my $result = '';

    for (my $i = length($hex) - 2; $i >= 0; $i = $i - 2) {
        $result .= substr($hex, $i, 2);
    }

    return $result;
}

sub sidToStr
{
    my ($sid) = @_;

    my $hexsid = unpack("H*", decode_base64($sid));
    my $rev = hex(substr($hexsid, 0, 2));
    my $subcount = hex(substr($hexsid, 2, 2));
    my $auth = hex(substr($hexsid, 4, 12));
    my $result = "S-$rev-$auth";

    my @subauth = ();
    for (my $i = 0;$i < $subcount; $i++) {
        $subauth[$i] = hex(littleEndian(substr($hexsid, 16 + ($i*8), 8)));
        $result .= "-".$subauth[$i];
    }

    return $result;
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
