#!/usr/bin/perl
#
#  This code was developped by SECIOSS (http://www.secioss.co.jp/).
#
#                 Copyright (C) 2016 SECIOSS, INC.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation.

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

package ListenerSSL;
use lib '../lib/perl';
use Net::Daemon::SSL;
use base 'Net::Daemon::SSL';
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

my $configfile = $^O ne 'MSWin32' ? '/opt/secioss/etc/lism-server.conf' : '/secioss/etc/lism-server.conf';
$configfile = defined($opt{'f'}) ? $opt{'f'} : $configfile;
my $config = Config::General->new($configfile);
my %param = $config->getall;
my $cafile = defined($param{'TLSCACertificateFile'}) ? $param{'TLSCACertificateFile'} : '';
my $certfile = defined($param{'TLSCertificateFile'}) ? $param{'TLSCertificateFile'} : '';
my $keyfile = defined($param{'TLSCertificateKeyFile'}) ? $param{'TLSCertificateKeyFile'} : '';

my $ldapuri;
my $ldapsuri;
foreach my $uri (split(/ +/, $opt{'h'})) {
    if ($uri =~ /^ldaps:/) {
        $ldapsuri = $uri;
    } elsif ($uri =~ /^ldap:/) {
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
        localport => $port ? $port : 389,
        config => $configfile,
        pidfile => 'none',
        mode => 'threads',
        childs => defined($opt{'P'}) ? $opt{'P'} : 1
    });
    my $pid;
    unless ($pid = fork) {
        $listener->Bind;
    }
}

if ($ldapsuri && $cafile && $certfile && $keyfile) {
    my ($ipaddr, $port) = ($ldapsuri =~ /^ldaps:\/\/([^:]+):?(.*)$/);
    if ($ipaddr !~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/) {
        die "Invalid IP address: $ipaddr\n";
    }
    my $listener = ListenerSSL->new({
        localaddr => $ipaddr,
        localport => $port ? $port : 636,
        config => $configfile,
        pidfile => 'none',
        mode => 'threads',
        childs => defined($opt{'P'}) ? $opt{'P'} : 1,
        SSL_use_cert => 1,
        SSL_ca_file => $cafile,
        SSL_cert_file => $certfile,
        SSL_key_file => $keyfile
    });
    my $pid;
    unless ($pid = fork) {
        $listener->Bind;
    }
}

1;
