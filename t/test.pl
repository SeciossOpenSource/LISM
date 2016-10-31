#!/usr/bin/perl

use Data::Dumper;

sub output
{
    my ($self, $conf, $param, $pids, $key, $dn, @args) = @_;

    open(DEBUG, '>/tmp/output.txt');
    print DEBUG "dn: $dn\n";
    print DEBUG Dumper($param);
    close(DEBUG);

    return 0;
}

sub addoutput
{
    my ($self, $conf, $param, $pids, $dn, @args) = @_;

    return output($self, $conf, $param, $pids, '', $dn, @args);
}

sub modoutput
{
    return output(@_);
}

sub deloutput
{
    return output(@_);
}
