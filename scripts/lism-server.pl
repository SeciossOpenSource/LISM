#!/usr/bin/perl

use strict;

package Listener;
use lib '../lib/perl';
use Net::Daemon;
use base 'Net::Daemon';
use LISM;
use LISM::Server;
use Data::Dumper;

sub new {
    my ($class, $args, $options) = @_;

    my $self = $class->SUPER::new($args, $options);

    my $conf = Config::General->new($args->{config});
    my %param = $conf->getall;

    $self->{lism} = new LISM;
    foreach my $key (qw(basedn admindn adminpw syncdir conf logfile auditfile logtimezone logrotatedate logrotatenum)) {
        $self->{lism}->config($key, $param{$key});
    }
    if ($self->{lism}->init()) {
        return undef;
    }
    $self;
}

sub Run {
    my $self = shift;

    my $handler = LISM::Server->new($self->{socket});
    $handler->init($self->{lism});

    while (1) {
        my $finished = $handler->handle;
        if ($finished) {
            # we have finished with the socket
            return;
        }
    }
}

package main;
use Getopt::Std;
use Config::General;
use URI;

my %opt;
getopts("h:f:P:", \%opt);

my $configfile = $^O ne 'MSWin32' ? '/opt/secioss/etc/openldap/slapd.conf' : '/secioss/etc/lism-server.conf';
$configfile = defined($opt{'f'}) ? $opt{'f'} : $configfile;
my $config = Config::General->new($configfile);
my %param = $config->getall;
my $pidfile = 'none';
my $mode = 'threads';
if (defined($param{pidfile}) && $param{pidfile}) {
    $pidfile = $param{pidfile};
    $pidfile =~ s![^/]+$!lism-server.pid!;
    $mode = 'fork';
}

my $ldapuri;
foreach my $uri (split(/ +/, $opt{'h'})) {
    if ($uri =~ /^ldap:/) {
        $ldapuri = $uri;
    }
}

if ($ldapuri) {
    my ($ipaddr, $port) = ($ldapuri =~ /^ldap:\/\/([^:]+):?(.*)$/);
    if ($ipaddr !~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) {
        die "Invalid IP address: $ipaddr\n";
    }
    my $listener = Listener->new({
        localaddr => $ipaddr,
        localport => $port ? $port : 3890,
        config => $configfile,
        pidfile => $pidfile,
        mode => $mode,
        childs => defined($opt{'P'}) ? $opt{'P'} : 1
    });
    my $pid;
    unless ($pid = fork) {
        $listener->Bind;
    }
}

=head1 SEE ALSO

L<LISM>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

(c) 2009 Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
