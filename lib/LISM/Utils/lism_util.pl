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
use Time::Local;
use Time::HiRes qw(gettimeofday);
use POSIX;
use Encode;
use MIME::Base64;
use Data::Dumper;

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
    my ($time) = @_;

    if (!defined($time)) {
        $time = time;
    }

    return strftime("%Y%m%d%H%M%S", localtime($time))."Z";
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

sub regmatch
{
    my ($match, $str) = @_;

    my (@vals) = ($str =~ /$match/gi);
    if (!@vals) {
        $vals[0] = '';
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

1;
