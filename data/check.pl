#!/usr/bin/perl

sub checkSurename
{
    my ($value) = @_;

    return $value =~ /^user/mi;
}
