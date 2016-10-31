#!/usr/bin/perl

use strict;
use SOAP::Transport::HTTP;
use SoapLdap;
use Data::Dumper;

SOAP::Transport::HTTP::CGI
    -> dispatch_to('SoapLdap')
    -> handle;
