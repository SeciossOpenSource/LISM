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
use Encode;
use MIME::Base64;
use Time::HiRes qw(gettimeofday);
use Data::Dumper;

use LISM::Util qw(date2time time2date getValue getFileContents randString  encrypt3des decrypt3des);

sub getModValue
{
    my ($entryStr, $attr, $default, $escape) = @_;

    my ($value) = ($entryStr =~ /\n$attr\n([^\n]*)/i);
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

sub getSureName
{
    my ($entryStr, $attr) = @_;
    my $regexp = "^$attr: ([^ 　,，\n]+)";
    $regexp = decode('utf8', $regexp);
    my $value = ($entryStr =~ /$regexp/mi)[0];

    return $value;
}

sub getGivenName
{
    my ($entryStr, $attr, $default) = @_;
    my $regexp = "^$attr: [^ 　,，\n]+[ 　,，]+([^\n]+)".'$';
    $regexp = decode('utf8', $regexp);
    my $value = ($entryStr =~ /$regexp/mi)[0];

    if ($value) {
        return $value;
    } else {
        return $default;
    }
}

sub attrJoin
{
    my ($entryStr, $attr, $delim, $num) = @_;
    my @vals;
    my $value = '';
    if (!$delim) {
        $delim = ',';
    }

    if ($entryStr =~ /^(REPLACE|ADD|DELETE)$/m) {
        my @list = split(/\n/, $entryStr);
        shift(@list);
        while ( @list > 0) {
            my $action = shift @list;
            my $attrname    = lc(shift @list);
            while (@list > 0 && $list[0] ne "ADD" && $list[0] ne "DELETE" && $list[0] ne "REPLACE") {
                my $val = shift @list;
                if ($attrname =~ /^$attr$/i) {
                    push(@vals, $val);
                }
            }
        }
    } else {
        @vals = ($entryStr =~ /^$attr:\:? +(.*)$/mi);
    }
    if (@vals) {
        if (!$num) {
            $num = @vals;
        }
        for (my $i = 0; $i < @vals; $i++) {
            if ($i >= $num) {
                last;
            }
            if ($vals[$i]) {
                $value .= ($value ? $delim : '').$vals[$i];
            }
        }
    }

    return $value;
}

sub replace
{
    my ($match, $substitute, $str) = @_;

    $str =~ s/$match/$substitute/gi;

    return $str;
}

sub strmap
{
    my ($match, $substitute, $str) = @_;
    my @matches = split(/,/, $match);
    my @substitutes = split(/,/, $substitute);

    for (my $i = 0; $i < @matches; $i++) {
        if ($str =~ /^$matches[$i]$/i) {
            return $substitutes[$i];
        }
    }

    return $str;
}

sub regmatch
{
    my ($match, $str, $default) = @_;

    my (@vals) = ($str =~ /$match/gi);
    if (!@vals) {
        $vals[0] = $default ? $default : '';
    }

    return @vals;
}

sub dn2oupath
{
    my ($dn, $base, $normalize) = @_;
    if ($dn !~ /,$base.*$/i) {
        return '';
    }
    $dn =~ s/,$base.*$//i;
    my @orgs = ($dn =~ /ou=([^,]+)/gi);
    if (@orgs) {
        my $oupath = join('/', reverse(@orgs));
        $oupath =~ s/\\"/"/g;
        $oupath =~ s/\\#/#/g;
        $oupath =~ s/\\\+/+/g;
        $oupath =~ s/\\;/;/g;
        $oupath =~ s/\\2B/+/gi;
        $oupath =~ s/\\3C/</gi;
        $oupath =~ s/\\3E/>/gi;
        if ($normalize) {
            $oupath =~ tr/A-Z/a-z/;
        }
        return $oupath;
    } else {
        return '';
    }
}

sub getParent
{
    my ($entryStr) = @_;

    my ($parent) = ($entryStr =~ /^[^,]+,[^=]+=([^,]+),/);
    return $parent;
}

sub path2dn
{
    my ($path, $attr, $isReverse) = @_;
    $path =~ s/[^=]+=//;

    my $dn = '';
    my @matches = split(/(?<!\\)\//, $path);
    if ($isReverse == '1') {
        @matches = reverse(@matches);
    }
    for (my $i = 0; $i < @matches; $i++) {
        $matches[$i] =~ s/\\\//\//g;
        $matches[$i] =~ s/\\/\\5C/g;
        $matches[$i] =~ s/"/\\22/g;
        $matches[$i] =~ s/#/\\23/g;
        $matches[$i] =~ s/\+/\\2B/g;
        $matches[$i] =~ s/;/\\3B/g;
        $matches[$i] =~ s/</\\3C/g;
        $matches[$i] =~ s/>/\\3E/g;
        $matches[$i] =~ s/=/\\3D/g;
        $dn .= $attr.'='.$matches[$i];
        if ($i != scalar(@matches)-1) {
        	$dn .= ',';
        }
    }
    return $dn;
}

sub modrdn
{
    my ($rdn, $modlist) = @_;

    if ($modlist =~ /^$rdn,/i) {
        return '';
    } else {
        return "\nlismnewrdn: $rdn";
    }
}

sub regexCount
{
    my ($str, $regex) = @_;
    my $num = 0;

    if ($str =~ /$regex/i) {
        my @vals = ($str =~ /$regex/gmi);
        $num = @vals;
    }

    return $num;
}

sub binToHex
{
    my ($str) = @_;

    return unpack("H*", decode_base64($str));
}

sub randPasswd
{
    my $num = shift;
    my $string;
    my @token;
    my @str_array;

    if ($num !~ /[0-9]/) {
        return undef;
    }

    my @number = (2..9);
    my @small = ('a'..'z');
    splice(@small, 12);
    @small = grep { !/^\s*$/ } @small;
    my @large = ('A'..'Z');
    splice(@large, 9, 15);
    @large = grep { !/^\s*$/ } @large;
    push(@token,\@number);
    push(@token,\@small);
    push(@token,\@large);

    my ($sec, $microsec) = gettimeofday();
    srand($microsec);
    for (my $i = 0; $i < 3; $i++) {
        my @chars = @{$token[$i]};
        for (my $j = 0; $j < $num / 3 && length($#str_array) < $num; $j++) {
            push(@str_array, $chars[int(rand() * @chars)]);
        }
    }

    for (my $i=0; $i < $#str_array+1; $i++) {
        my $a = int(rand($#str_array+1));
        my $b = int(rand($#str_array+1));
        (@str_array[$a],@str_array[$b])=(@str_array[$b],@str_array[$a]);
    }
    foreach my $char (@str_array) {
        $string .= $char;
    }

    return $string;
}

sub setAdditionalAttr
{
    my ($value, $delim, $attr) = @_;
    my ($fval, @avals) = split(/$delim/, $value);

    my $ret = $fval;
    foreach my $aval (@avals) {
        $ret .= "\n$attr: $aval";
    }

    return $ret;
}

sub e164 {
    my ($num, $countryCode, $is_space) = @_;

    my @elts = split(/\-/, $num);
    if (@elts < 3) {
        return '';
    }

    $elts[0] =~ s/^0+//;
    my $enum;
    if ($is_space) {
        $enum = $elts[0].' '.$elts[1].' '.$elts[2];
        if ($countryCode) {
            $enum = '+'.$countryCode.' '.$enum;
        }
    } else {
        $enum = '('.$elts[0].')'.$elts[1].'-'.$elts[2];
        if ($countryCode) {
            $enum = '+'.$countryCode.$enum;
        }
    }

    return $enum;
}

sub str2byte {
    my ($str) = @_;

    $str =~ s/(.)/sprintf('%X', ord($1))/eg;

    return $str;
}

sub unescapedn {
    my ($value) = @_;

    $value =~ s/\\\+/+/g;
    $value =~ s/\\2B/+/gi;

    return $value;
}

sub replaceAttrVals
{
    my ($entryStr, $attr, $match, $substitute) = @_;

    my @values = ($entryStr =~ /^$attr: (.*)$/gmi);
    for (my $i = 0; $i < @values; $i++) {
        if ($values[$i]) {
            $values[$i] =~ s/$match/$substitute/i;
        }
    }
    if (@values == 1) {
       return $values[0];
    } else {
       return @values;
    }
}

=head1 SEE ALSO

L<LISM>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

(c) 2006 Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
