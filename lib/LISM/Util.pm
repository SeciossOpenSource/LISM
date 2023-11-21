package LISM::Util;

use vars qw(@ISA @EXPORT_OK);
require Exporter;

@ISA        = qw(Exporter);
@EXPORT_OK  = qw(date2time time2date getValue getFileContents randString encrypt3des decrypt3des);

use strict;
use POSIX;
use Digest::MD5;
use Mcrypt;
use Mcrypt qw(:ALGORITHMS);
use Mcrypt qw(:MODES);
use MIME::Base64;
use Time::HiRes qw(gettimeofday);
use Time::Local;

=head1 NAME

LISM::Storage - an base class for LISM storage implementations

=head1 DESCRIPTION

This class is meant as an interface to access arbitrary storage.

=head1 CONSTRUCTOR

This is a plain constructor.

=cut

sub date2time
{
    my ($date) = @_;

    if (!defined($date)) {
        return time;
    }

    my ($year, $mon, $day, $hour, $min, $sec) = ($date =~ /^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z/);

    my $time = timelocal($sec, $min, $hour, $day, $mon - 1, $year);

    return $time;
}

sub time2date
{
    my ($time, $format) = @_;

    if (!defined($time)) {
        $time = time;
    }

    if ($format) {
        return strftime($format, localtime($time));
    } else {
        return strftime("%Y%m%d%H%M%S", localtime($time))."Z";
    }
}

sub getValue
{
    my ($entryStr, $attr, $default, $escape) = @_;

    my $value = ($entryStr =~ /^$attr:\:? +(.*)$/mi)[0];
    if (!defined($value) && defined($default)) {
        $value = $default;
    }
    if ($value && $escape) {
        $value =~ s/"/\\22/g;
        $value =~ s/#/\\23/g;
        $value =~ s/\+/\\2B/g;
        $value =~ s/,/\\2C/g;
        $value =~ s/\//\\2F/g;
        $value =~ s/;/\\3B/g;
        $value =~ s/</\\3C/g;
        $value =~ s/>/\\3E/g;
        $value =~ s/=/\\3D/g;
    }

    return $value;
}

sub getFileContents
{
    my ($file) = @_;
    my $contents = '';

    if (!-f $file) {
        return '';
    }

    open(FILE, "<$file") || return '';

    while (<FILE>) {
        $contents .= $_;
    }

    return $contents;
}

sub randString
{
    my $num = shift;
    my $string;
    my @chars;

    if ($num !~ /[0-9]/) {
        return undef;
    }

    foreach my $arg (@_) {
        if (my ($ch1, $ch2) = ($arg =~ /^['"]?(.?)['"]?\.\.['"]?(.?)['"]?/)) {
            push(@chars,($ch1..$ch2));
        } elsif (length($arg) == 1) {
            push(@chars, $arg);
        }
    }

    my ($sec, $microsec) = gettimeofday();
    srand($microsec);

    for (my $i = 0; $i < $num; $i++) {
        $string .= $chars[int(rand() * @chars)];
    }

    return $string;
}

sub encrypt3des
{
    my ($str, $arg) = @_;

    my $encrypted;

    my $key = Digest::MD5::md5_hex($arg);
    $encrypted = $key.$str;

    my ($sec, $microsec) = gettimeofday();
    srand($microsec);

    my $td = Mcrypt::mcrypt_load( Mcrypt::3DES, '', Mcrypt::CFB, '' );
    $key = substr($key, 0, Mcrypt::mcrypt_get_key_size($td));
    my $iv = substr(Digest::MD5::md5(time), 0, Mcrypt::mcrypt_get_iv_size($td));
    Mcrypt::mcrypt_init($td, $key, $iv) || return $str;
    $encrypted = encode_base64($iv.Mcrypt::mcrypt_encrypt($td, $encrypted), '');
    Mcrypt::mcrypt_end($td);

    return $encrypted;
}

sub decrypt3des
{
    my ($str, $arg) = @_;

    if (!$str) {
        return undef;
    }
    $str = decode_base64($str);

    my $decrypted;
    my $key = Digest::MD5::md5_hex($arg);
    my $checksum = $key;

    my $td = Mcrypt::mcrypt_load( Mcrypt::3DES, '', Mcrypt::CFB, '');
    $key = substr($key, 0, Mcrypt::mcrypt_get_key_size($td));
    my $iv_size = Mcrypt::mcrypt_get_iv_size($td);
    my $iv = substr($str, 0, $iv_size);
    $decrypted = substr($str, $iv_size);
    if (!$decrypted) {
        next;
    }

    Mcrypt::mcrypt_init($td, $key, $iv) || return undef;
    $decrypted = Mcrypt::mcrypt_decrypt($td, $decrypted);
    Mcrypt::mcrypt_end($td);
    if ($decrypted =~ /^$checksum/) {
        return substr($decrypted, 32);
    }

    return undef;
}

=head1 SEE ALSO

L<LISM>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

(c) 2023 Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
