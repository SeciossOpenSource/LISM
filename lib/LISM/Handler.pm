package LISM::Handler;

use strict;
use URI;
use Net::LDAP;
use LISM::Constant;
use POSIX;
use Encode;
use Scalar::Util qw(weaken);
use Data::Dumper;
if ($^O ne 'MSWin32') {
    eval "use Sys::Syslog";
} else {
    eval "use Log::Dispatch::FileRotate";
}

=head1 NAME

LISM::Handler - an base class for LISM handler implementations

=head1 DESCRIPTION

This class is meant as an interface of handler called when the LDAP operation is done.

=head1 CONSTRUCTOR

This is a plain constructor.

=cut

sub new
{
    my $class = shift;
    my ($lism) = @_;

    my $this = {};
    bless $this, $class;
    $this->{lism} = $lism;
    weaken($this->{lism});

    return $this;
}

=head1 METHODS

=head2 config($conf)

Set configuration data.

=cut

sub config
{
    my $self = shift;
    my ($conf) = @_;

    $self->{_config} = $conf;

    return 0;
}

=pod

=head2 init

Initailize the storage object.
Returns 0 if it complete successfully.

=cut

sub init
{
    my $self = shift;
    my $conf = $self->{_config};

    # check configuration
    if ($self->_checkConfig()) {
        $self->log(level => 'alert', message => "Configuration error");
        return -1;
    }

    return 0;
}

=pod

=head2 getOrder

Get order to do handler.

=cut

sub getOrder
{
    return 'middle';
}

=pod

=head2 getOrder

Get order to do handler.

=cut

sub useprevious()
{
    my $self = shift;
    my $conf = $self->{_config};

    return defined($conf->{useprevious}) && $conf->{useprevious} eq 'on' ? 1 : 0;
}

=pod

=head2 pre_bind

This method is called bofore L<LISM> do the bind operation.
Returns 0 if it completes successfully.

=cut

sub pre_bind
{
    return 0;
}

=pod

=head2 post_bind

This method is called after L<LISM> do the bind operation.
Returns 0 if it completes successfully.

=cut

sub post_bind
{
    return 0;
}

=pod

=head2 pre_compare

This method is called bofore L<LISM> do the compare operation.
Returns 0 if it completes successfully.

=cut

sub pre_compare
{
    return 0;
}

=pod

=head2 post_compare

This method is called after L<LISM> do the compare operation.
Returns 0 if it completes successfully.

=cut

sub post_compare
{
    return 0;
}

=pod

=head2 pre_search

This method is called bofore L<LISM> do the search operation.
Returns 0 if it completes successfully.

=cut

sub pre_search
{
    return 0;
}

=pod

=head2 post_search

This method is called after L<LISM> do the search operation.
Returns 0 if it completes successfully.

=cut

sub post_search
{
    return 0;
}

=pod

=head2 pre_modify

This method is called bofore L<LISM> do the modify operation.
Returns 0 if it completes successfully.

=cut

sub pre_modify
{
    return 0;
}

=pod

=head2 post_modify

This method is called after L<LISM> do the modify operation.
Returns 0 if it completes successfully.

=cut

sub post_modify
{
    return 0;
}

=pod

=head2 pre_add

This method is called before L<LISM> do the add operation.
Returns 0 if it completes successfully.

=cut

sub pre_add
{
    return 0;
}

=head2 post_add

This method is called after L<LISM> do the add operation.
Returns 0 if it completes successfully.

=cut

sub post_add
{
    return 0;
}

=pod

=head2 pre_modrdn

This method is called before L<LISM> do the modrdn operation.
Returns 0 if it completes successfully.

=cut

sub pre_modrdn
{
    return 0;
}

=pod

=head2 post_modrdn

This method is called after L<LISM> do the modrdn operation.
Returns 0 if it completes successfully.

=cut

sub post_modrdn
{
    return 0;
}

=pod

=head2 pre_delete

This method is called before L<LISM> do the delete operation.
Returns 0 if it completes successfully.

=cut

sub pre_delete
{
    return 0;
}

=pod

=head2 post_delete

This method is called before L<LISM> do the delete operation.
Returns 0 if it completes successfully.

=cut

sub post_delete
{
    return 0;
}

=pod

=head2 log(level, message)

log message to syslog.

=cut

sub log
{
    my $self = shift;
    my $conf = $self->{_config};
    my %p = @_;

    if (Encode::is_utf8($p{'message'})) {
        $p{'message'} = encode('utf8', $p{'message'});
        $p{'message'} =~ s/(#|:)plainpassword=[^#]+/$1plainpassword=/gmi;
        $p{'message'} =~ s/(#|:)userpassword=[^#]+/$1userpassword=/gmi;
    }
    $p{'message'} = uc($p{'level'}).' ['.ref($self).'] '.$p{'message'};

    if ($^O ne 'MSWin32') {
        openlog('LISM', 'pid', $self->{lism}->{_config}->{syslogfacility});
        if ($conf->{sysloglevel} ne 'info') {
            setlogmask(Sys::Syslog::LOG_UPTO(Sys::Syslog::xlate($conf->{sysloglevel})));
        }
        syslog($p{'level'}, $p{'message'});
        closelog();
    } else {
        $self->{log}->log(level => $p{'level'}, message => strftime("%Y/%m/%d %H:%M:%S", localtime(time))." ".$p{'message'}."\n");
    }

    if (defined($conf->{printlog}) && $conf->{printlog} =~ /$p{'level'}/) {
        print $p{'message'}."\n";
    }
}

sub _checkConfig
{
    my $self = shift;
    my $conf = $self->{_config};

    if ($^O eq 'MSWin32') {
        if (!defined($conf->{logfile})) {
            return 1;
        }

        my $timezone = 'JST';
        my $rotatedate = 'yyyy-MM-dd';
        my $rotatenum = 4;
        if (defined($conf->{logtimezone})) {
            $timezone = $conf->{timezone};
        }
        if (defined($conf->{logrotatedate})) {
            $rotatedate = $conf->{logrotatedate};
        }
        if (defined($conf->{logrotatenum})) {
            $rotatenum = $conf->{logrotatenum};
        }
        $self->{log} = Log::Dispatch::FileRotate->new(name => 'LISM',
                                                     min_level => $conf->{sysloglevel},
                                                     filename => $conf->{logfile},
                                                     mode => 'append',
                                                     TZ => $timezone,
                                                     DatePattern => $rotatedate,
                                                     max => $rotatenum);
    }

    return 0;
}

sub _parseLdapUri
{
    my $self = shift;
    my ($ldapopts, $ldapuri) = @_;

    $ldapopts->{uri} = $ldapuri;
    my $uri = URI->new($ldapopts->{uri});
    $ldapopts->{base} = $uri->dn;
    ($ldapopts->{attr}) = $uri->attributes;
    my %extn = $uri->extensions;
    $ldapopts->{binddn} = $extn{binddn};
    $ldapopts->{bindpw} = $extn{bindpw};

    return 0;
}

sub _searchLdap
{
    my $self = shift;
    my ($ldapopts, $filter) = @_;
    my $base = $ldapopts->{base};
    my $scope = 'sub';
    my $attr;
    my $msg;
    my $rc;
    my @values = ('');

    if (defined($ldapopts->{ldap})) {
        my $cmsg = $ldapopts->{ldap}->bind($ldapopts->{binddn}, password => $ldapopts->{bindpw});
        if ($cmsg->code) {
            $self->log(level => 'err', message => "LDAP connection check failed in handler");
            $ldapopts->{ldap}->unbind();
            undef($ldapopts->{ldap});
        }
    }

    if (!$ldapopts->{ldap}) {
        $ldapopts->{ldap} = Net::LDAP->new($ldapopts->{uri});
        if (!defined($ldapopts->{ldap})) {
            $self->log(level => 'err', message => "Can't connect $ldapopts->{uri}");
            return undef;
        }

        $msg = $ldapopts->{ldap}->bind($ldapopts->{binddn}, password => $ldapopts->{bindpw});
        $rc = $msg->code;
        if ($rc) {
            $self->log(level => 'err', message => "bind by $ldapopts->{binddn}failed($rc)");
            return undef;
        }
    }

    $filter =~ s/^["']//;
    $filter =~ s/["']$//;
    if ($filter =~ /^\(?dn=/) {
        ($base) = ($filter =~ /^\(?dn=(.*)\)?$/);
        $scope = 'base';
        $filter = 'objectClass=*';
    }
    if ($ldapopts->{attr} eq 'parentrdn') {
        $attr = 'dn';
    } else {
        $attr = $ldapopts->{attr};
    }

    $msg = $ldapopts->{ldap}->search(base => $base, scope => $scope, filter => $filter, attrs => [$attr]);

    $rc = $msg->code;
    if ($rc) {
        $self->log(level => 'err', message => "ldap search by $filter failed($rc)");
        if ($rc == LDAP_SERVER_DOWN) {
            $ldapopts->{ldap}->unbind();
            undef($ldapopts->{ldap});
        }

        return undef;
    }

    if ($msg->count) {
        my $entry = $msg->entry(0);
        if ($ldapopts->{attr} eq 'dn') {
            $values[0] = $entry->dn;
        } elsif ($ldapopts->{attr} eq 'parentrdn') {
            @values = ($entry->dn =~ /^[^,]+,([^,]+)/);
        } else {
            @values = $entry->get_value($ldapopts->{attr});
        }

        if (!defined($values[0])) {
            @values = ('');
        }
    }

    return @values;
}

sub _searchLism
{
    my $self = shift;
    my ($lismopts, $cache, $filters, $base, $entryStr) = @_;
    my $conf = $self->{_config};
    my $scope = 2;
    my $attr;
    my @values = ();
    my %attrmap;

    if ($entryStr) {
        if ($base) {
            my ($tmpbase) = ($entryStr =~ /$base/i);
            if ($tmpbase) {
                if ($lismopts->{base}) {
                    $base = $tmpbase.','.$lismopts->{base};
                } else {
                    $base = $tmpbase;
                }
            }
        }
    }
    $base = $lismopts->{base} if !$base;

    if (defined($lismopts->{attrmap}) && $conf->{attrmap} && defined($conf->{attrmap}->{$lismopts->{attrmap}})) {
        my $map = $conf->{attrmap}->{$lismopts->{attrmap}};
        my $map_dn = lc("$map->{dn},$base");
        my $map_key = $lismopts->{attrmap}.'_'.$map_dn;
        if (!defined(${$cache}{lism_attrmap})) {
            ${$cache}{lism_attrmap} = {};
        }
        if (defined(${${$cache}{lism_attrmap}}{$map_key})) {
            %attrmap = %{${${$cache}{lism_attrmap}}{$map_key}};
        } else {
            my ($rc, $map_entry) = $self->{lism}->search($map_dn, 0, 0, 0, 0, '(objectClass=*)', 0, $map->{attr}, 'objectClass');
            if ($rc) {
                $self->log(level => 'err', message => "Searching attrmap $map_dn failed($rc)");
            } elsif ($map_entry) {
                foreach my $value (($map_entry =~ /^$map->{attr}: (.+)$/gmi)) {
                    if ($value !~ /^ *$/) {
                        my @elts = split(/=/, $value);
                        $attrmap{lc($elts[0])} = $elts[1];
                    }
                }
                if (%attrmap) {
                    ${${$cache}{lism_attrmap}}{$map_key} = \%attrmap;
                } else {
                    ${${$cache}{lism_attrmap}}{$map_key} = {};
                }
            }
        }
    }

    if ($entryStr) {
        if ($filters =~ /\%d/) {
            my $suffix = $self->{lism}->{_config}->{basedn};
            my ($dsuffix) = ($base =~ /(ou=[^,]+,$suffix)$/i);
            my ($dn) = ($entryStr =~ /^([^\n]+)/);
            $dn =~ s/^dn: //;
            $dn =~ s/ou=[^,]+,$suffix$/$dsuffix/i;
            $filters =~ s/\%d/$dn/g;
        }
    }

    if (defined($lismopts->{scope})) {
        if ($lismopts->{scope} eq 'base') {
            $scope = 0;
        } elsif ($lismopts->{scope} eq 'one') {
            $scope = 1;
        }
    }

    if ($lismopts->{attr} eq 'parentrdn' || $lismopts->{attr} eq 'parentdn' || $lismopts->{attr} eq 'path') {
        $attr = 'dn';
    } else {
        $attr = $lismopts->{attr};
    }
    if (%attrmap) {
        if (defined($attrmap{lc($attr)})) {
            $attr = $attrmap{lc($attr)};
        }
    }

    foreach my $filter (split(/; +/, $filters)) {
        $filter =~ s/^["']//;
        $filter =~ s/["']$//;
        if ($filter =~ /^\(?dn=/) {
            ($base) = ($filter =~ /^\(?dn=(.+[^\)])\)?$/);
            if ($base) {
                $base =~ s/\\([\(\)])/$1/g;
            }
            $scope = 0;
            $filter = '(objectClass=*)';
        } elsif ($filter =~ /^\(&\(dn=/) {
            $filter =~ s/\\\)/\\\\29/g;
            ($base) = ($filter =~ /^\(&\(dn=([^\)]+)\)/);
            if ($base) {
                $base =~ s/\\\\29/\\)/;
                $base =~ s/\\([\(\)])/$1/g;
            }
            $scope = 0;
            $filter =~ s/^\(&\(dn=[^\)]+\)//;
            $filter =~ s/\)$//;
            $filter =~ s/\\\\29/\\)/;
        }
        if (%attrmap) {
            foreach my $attr1 (keys(%attrmap)) {
                my $attr2 = $attrmap{$attr1};
                $filter =~ s/\($attr1=/($attr2=/gi;
            }
        }

        my $operation;
        if (defined($self->{lism}->{operation})) {
            $operation = $self->{lism}->{operation};
            undef($self->{lism}->{operation});
        }
        my ($rc, @entries) = $self->{lism}->search(encode('utf8', $base), $scope, 0, 0, 0, encode('utf8', $filter), 0, $attr, defined($lismopts->{attrs}) ? @{$lismopts->{attrs}} : 'objectClass');
        if ($operation) {
            $self->{lism}->{operation} = $operation;
        }
        if ($rc) {
            if ($rc == LDAP_NO_SUCH_OBJECT) {
                return ('');
            }
            $self->log(level => 'err', message => "lism search by $filter at $base failed($rc)");

            return undef;
        }

        if (@entries) {
            my $num = 1;
            foreach my $entryStr (@entries) {
                if (defined($lismopts->{sizelimit}) && $num > $lismopts->{sizelimit}) {
                    last;
                }

                my @tmpvals;
                if ($lismopts->{attr} eq 'dn' || $lismopts->{attr} eq 'path') {
                    @tmpvals = ($entryStr =~ /^dn: ([^\n]+)/);
                } elsif ($lismopts->{attr} eq 'parentrdn') {
                    @tmpvals = ($entryStr =~ /^[^,]+,([^,]+)/);
                } elsif ($lismopts->{attr} eq 'parentdn') {
                    @tmpvals = ($entryStr =~ /^[^,]+,(.+),$base\n/i);
                } else {
                    @tmpvals = ($entryStr =~ /^$attr: (.*)$/gmi);
                    if (defined($lismopts->{attrs}) && defined($lismopts->{allvalues})) {
                        foreach my $tmpattr (@{$lismopts->{attrs}}) {
                            my @tmpattrvals = ($entryStr =~ /^$tmpattr: (.*)$/gmi);
                            if (@tmpattrvals) {
                                if (@tmpvals && defined($tmpvals[0]) && $tmpvals[0] !~ /^ *$/) {
                                    push(@tmpvals, @tmpattrvals);
                               } else {
                                    @tmpvals = @tmpattrvals;
                               }
                            }
                        }
                    }
                }

                if (@tmpvals && defined($tmpvals[0]) && $tmpvals[0] !~ /^ *$/) {
                    if (defined($lismopts->{match})) {
                        foreach my $tmpval (@tmpvals) {
                            if ($tmpval =~ /$lismopts->{match}/i) {
                                if (defined($lismopts->{substitution})) {
                                    eval "\$tmpval =~ s/$lismopts->{match}/$lismopts->{substitution}/i";
                                }
                                push(@values, $tmpval);
                            }
                        }
                    } else {
                        push(@values, @tmpvals);
                    }
                }
                $num++;
            }
            last;
        }
    }

    if (!@values || !defined($values[0])) {
        @values = ('');
    }

    return @values;
}

sub _unique
{
    my $self = shift;
    my @array = @_;
    my @uarray = ();
    my %hash;

    for (my $i = 0; $i < @array; $i++) {
        if (!defined($hash{$array[$i]})) {
            $hash{$array[$i]} = 1;
            push(@uarray, $array[$i]);
        }
    }

    return @uarray;
}

sub _delquote
{
    my ($str) = @_;

    $str =~ s/^["']*//;
    $str =~ s/["']*$//;

    return $str;
}

sub lock
{
    my $self = shift;
    my ($op) = @_;
    my $conf = $self->{_config};

    if (!defined($conf->{lock})) {
        return 0;
    }

    my $lockfile;
    if (defined($conf->{lock}[0]->{op})) {
        if ($conf->{lock}[0]->{op} ne $op) {
            return 0;
        }
        $lockfile = $conf->{lock}[0]->{content};
    } else {
        $lockfile = $conf->{lock}[0];
    }
    if (!open($self->{lock}, "> $lockfile")) {
        return 1;
    }

    flock($self->{lock}, 2);

    return 0;
}

sub unlock
{
    my $self = shift;
    my $conf = $self->{_config};

    if (!defined($conf->{lock}) || !defined($self->{lock})) {
        return 0;
    }

    close($self->{lock});
    undef($self->{lock});

    return 0;
}

sub _path2dn
{
    my ($path, $attr, $isReverse) = @_;
    $path =~ s/[^=]+=//;

    my $dn = '';
    my @matches = split(/(?<!\\)\//, $path);
    if ($isReverse == '1') {
        @matches = reverse(@matches);
    }
    for (my $i = 0; $i < @matches; $i++) {
        $matches[$i] =~ s/([,<>#\+";])/\\$1/g;
        $dn .= $attr.'='.$matches[$i];
        if ($i != scalar(@matches)-1) {
                $dn .= ',';
        }
    }
    $dn =~ s/\\\//\//g;
    return $dn;
}

=head1 SEE ALSO

L<LISM>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
