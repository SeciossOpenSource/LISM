package LISM::Handler::Script;

use strict;
use base qw(LISM::Handler);
use LISM::Constant;
use Encode;
use Data::Dumper;

=head1 NAME

LISM::Handler::Script - Handler to do script

=head1 DESCRIPTION

This class implements the L<LISM::Hanlder> interface to do script.

=head1 METHODS

=head2 getOrder

Get order to do handler.

=cut

sub getOrder
{
    return 'last';
}

=pod

=head2 pre_modify($dnp, $listp)

Do script before modify operation is done.

=cut

sub pre_modify
{
    my $self = shift;
    my ($dnp, $listp, $oldentryp, $errorp) = @_;
    my $conf = $self->{_config};

    return $self->_do_modify('pre', $dnp, $listp, $oldentryp, $errorp);
}

=head2 post_modify($dnp, $listp)

Do script after modify operation is done.

=cut

sub post_modify
{
    my $self = shift;
    my ($dnp, $listp, $oldentryp, $errorp) = @_;
    my $conf = $self->{_config};

    return $self->_do_modify('post', $dnp, $listp, $oldentryp);
}

=pod

=head2 pre_add($dnp, $entryStrp, $oldentryp, $errorp)

Do script before add operation is done.

=cut

sub pre_add
{
    my $self = shift;
    my ($dnp, $entryStrp, $oldentryp, $errorp) = @_;
    my $conf = $self->{_config};

    return $self->_do_add('pre', $dnp, $entryStrp, $oldentryp, $errorp);
}

=head2 post_add($dnp, $entryStrp, $oldentryp, $errorp)

Do script after add operation is done.

=cut

sub post_add
{
    my $self = shift;
    my ($dnp, $entryStrp, $oldentryp, $errorp) = @_;
    my $conf = $self->{_config};

    return $self->_do_add('post', $dnp, $entryStrp, $oldentryp, $errorp);
}

=pod

=head2 pre_delete($dnp)

Do script before delete operation is done.
    
=cut
    
sub pre_delete
{
    my $self = shift;
    my ($dnp, $errorp) = @_;
    my $conf = $self->{_config};

    return $self->_do_delete('pre', $dnp, undef, $errorp);
}

=head2 post_delete($dnp)

Do script after delete operation is done.

=cut

sub post_delete
{
    my $self = shift;
    my ($dnp, $null, $oldentryp, $errorp) = @_;
    my $conf = $self->{_config};

    return $self->_do_delete('post', $dnp, $oldentryp, $errorp);
}

sub _checkConfig
{
    my $self = shift;
    my $conf = $self->{_config};
    my $rc = 0;

    if ($rc = $self->SUPER::_checkConfig()) {
        return $rc;
    }

    if (!defined($conf->{timeout})) {
        $conf->{timeout}[0] = 3600;
    }

    # check handler type
    foreach my $rule (@{$conf->{execrule}}) {
        if (!defined($rule->{type}) || $rule->{type} !~ /^(pre|post)$/) {
            $self->log(level => 'alert', message => "script handler type is invalid value");
             return 1;
        }
        if (defined($rule->{filter})) {
            $rule->{filter} =~ s/&amp;/&/g;
            $rule->{filterobj} = Net::LDAP::Filter->new(encode('utf8', $rule->{filter}));
        }
    }

    return 0;
}

=pod

=head2 _do_modify($type, $dnp, $listp)

Do script when modify operation is done.

=cut

sub _do_modify
{
    my $self = shift;
    my ($type, $dnp, $listp, $oldentryp, $errorp) = @_;
    my $conf = $self->{_config};
    my $dn = ${$dnp};
    my $oldentry = defined($oldentryp) ? ${$oldentryp} : undef;
    my $rc = 0;

    my ($rdn_val) = ($dn =~ /^[^=]+=([^,]+),/);

    foreach my $rule (@{$conf->{execrule}}) {
        if ($type ne $rule->{type}) {
            next;
        }

        # check the dn
        if (defined($rule->{dn}) && $dn !~ /$rule->{dn}/i) {
            next;
        }

        my $entryStr = $oldentry;
        my $match = 0;
        my @info;
        my @list = @{$listp};
        while (@list > 0) {
            my $action = shift @list;
            my $attr = lc(shift @list);
            my @values;

            while (@list > 0 && $list[0] ne "ADD" && $list[0] ne "DELETE" && $list[0] ne "REPLACE") {
                push(@values, shift @list);
            }

            if ($attr eq 'entrycsn') {
                last;
            }

            if ($entryStr) {
                if ($action eq 'ADD') {
                    foreach my $value (@values) {
                        $entryStr .= "$attr: $value\n";
                    }
                } elsif ($action eq 'DELETE') {
                    if (@values && $values[0]) {
                        foreach my $value (@values) {
                            $entryStr =~ s/^$attr: $value\n//gmi;
                        }
                    } else {
                        $entryStr =~ s/^$attr: .*\n//gmi;
                    }
                } elsif ($action eq 'REPLACE') {
                    $entryStr =~ s/^$attr: .*\n//gmi;
                    foreach my $value (@values) {
                        $entryStr .= "$attr: $value\n";
                    }
                }
            }

            if (defined($rule->{match}) && !$match) {
                if ("$action: $attr" =~ /$rule->{match}/i) {
                    $match = 1;
                }

                foreach my $value (@values) {
                    if ("$attr: $value" =~ /$rule->{match}/i) {
                        $match = 1;
                        last;
                    }
                }
            }

            if (defined($rule->{attrs}) && ",$rule->{attrs}," !~ /,$attr,/i) {
                next;
            }

            if ($action eq 'ADD') {
                $action = 'A';
            } elsif ($action eq 'DELETE') {
                $action = 'D';
            } elsif ($action eq 'REPLACE') {
                $action = 'R';
            }
            push(@info, "$action:$attr=".join('+', @values));
        }

        # check the filter
        if ($entryStr && defined($rule->{filter}) && !LISM::Storage->parseFilter($rule->{filterobj}, $entryStr)) {
            next;
        }

        # check the rule
        if (defined($rule->{match}) && !$match) {
            next;
        }

        my $modinfo = "dn=$dn#".join('#', @info);
        foreach my $script (@{$rule->{op}{modify}->{script}}) {
            my $cmd = $script;
            my $oldinfo = "dn=$dn#".$self->_parseEntry($oldentry, $rule);
            my %params = ('%r' => $rdn_val, '%i' => $modinfo, '%o' => $oldinfo, '%b' => $self->{lism}->{bind}->{edn});
            $cmd = $self->_parseCommand($cmd, %params);

            if ($cmd =~ /^#/) {
                $cmd =~ s/^#//;
                print "$cmd\n";
            } elsif ($^O ne 'MSWin32') {
                my @messages;
                eval {
                    local $SIG{ALARM} = sub{die;};
                    alarm($conf->{timeout}[0]);
                    open(CMD, "$cmd; echo status=\$?|");
                    while (<CMD>) {
                        chop;
                        push(@messages, $_);
                    }
                    $rc = pop(@messages);
                    ($rc) = ($rc =~ /status=([0-9]+)/);
                    close(CMD);
                };
                alarm(0);
                if ($@) {
                    $rc = -1;
                    push(@messages, 'Timeout');
                }

                $cmd =~ s/(userpassword|plainpassword|unicodepwd)=[^#]+/$1=/gi;
                if ($rc) {
                    $self->log(level => 'err', message => "Script in modify failed($rc): $cmd");
                    $self->log(level => 'err', message => "Script messages: ".join(', ', @messages));
                    ${$errorp} = join(', ', @messages);
                    if ($type eq 'post' && defined($rule->{op}{modify}->{rollback}) && $rule->{op}{modify}->{rollback} eq 'on') {
                        $self->log(level => 'err', message => "Rollback $dn in modify");
                        return LDAP_USER_CANCELED;
                    } else {
                        return ($rc == 32 || $rc == 68) ? $rc : LDAP_OPERATIONS_ERROR;
                    }
                } else {
                    $self->log(level => 'info', message => "Script in modify succeeded: $cmd");
                }
            } else {
                system($cmd);
            }
        }
    }

    return $rc ? LDAP_OPERATIONS_ERROR : LDAP_SUCCESS;
}

=pod

=head2 _do_add($type, $dnp, $entryStrp, $oldentryp, $errorp)

Do script when add opeartion is done.

=cut

sub _do_add
{
    my $self = shift;
    my ($type, $dnp,  $entryStrp, $oldentryp, $errorp) = @_;
    my $conf = $self->{_config};
    my $dn = ${$dnp};
    my $entryStr = ${$entryStrp}[0];
    my $rc = 0;

    my ($rdn_val) = ($dn =~ /^[^=]+=([^,]+),/);

    my @info;

    foreach my $rule (@{$conf->{execrule}}) {
        if ($type ne $rule->{type}) {
            next;
        }

        # check the dn
        if (defined($rule->{dn}) && $dn !~ /$rule->{dn}/i) {
            next;
        }

        # check the filter
        if (defined($rule->{filter}) && !LISM::Storage->parseFilter($rule->{filterobj}, $entryStr)) {
            next;
        }

        # check the rule
        if (defined($rule->{match}) && $entryStr !~ /$rule->{match}/i) {
            next;
        }

        my $addinfo = "dn=$dn#".$self->_parseEntry($entryStr, $rule);
        foreach my $script (@{$rule->{op}{add}->{script}}) {
            my $cmd = $script;
            my %params = ('%r' => $rdn_val, '%i' => $addinfo, '%b' => $self->{lism}->{bind}->{edn});
            $cmd = $self->_parseCommand($cmd, %params);

            if ($cmd =~ /^#/) {
                $cmd =~ s/^#//;
                print encode('utf8', $cmd)."\n";
            } elsif ($^O ne 'MSWin32') {
                my @messages;
                eval {
                    local $SIG{ALARM} = sub{die;};
                    alarm($conf->{timeout}[0]);
                    open(CMD, "$cmd; echo status=\$?|");
                    while (<CMD>) {
                        chop;
                        push(@messages, $_);
                    }
                    $rc = pop(@messages);
                    ($rc) = ($rc =~ /status=([0-9]+)/);
                    close(CMD);
                };
                alarm(0);
                if ($@) {
                    $rc = -1;
                    push(@messages, 'Timeout');
                }

                $cmd =~ s/(userpassword|plainpassword|unicodepwd)=[^#]+/$1=/gi;
                if ($rc) {
                    $self->log(level => 'err', message => "Script in add failed($rc): $cmd");
                    $self->log(level => 'err', message => "Script messages: ".join(', ', @messages));
                    ${$errorp} = join(', ', @messages);
                    if ($type eq 'post' && defined($rule->{op}{add}->{rollback}) && $rule->{op}{add}->{rollback} eq 'on') {
                        $self->log(level => 'err', message => "Rollback $dn in add");
                        return LDAP_USER_CANCELED;
                    } else {
                        return ($rc == 32 || $rc == 68) ? $rc : LDAP_OPERATIONS_ERROR;
                    }
                } else {
                    $self->log(level => 'info', message => "Script in add succeeded: $cmd");
                }
            } else {
                system($cmd);
            }
        }
    }

    return $rc ? LDAP_OPERATIONS_ERROR : LDAP_SUCCESS;
}

=pod

=head2 _do_delete($type, $dnp, $errorp)

Do script when delete operation is done.

=cut

sub _do_delete
{
    my $self = shift;
    my ($type, $dnp, $oldentryp, $errorp) = @_;
    my $conf = $self->{_config};
    my $dn = ${$dnp};
    my $oldentry = defined($oldentryp) ? ${$oldentryp} : undef;
    my $rc = 0;

    my ($rdn_val) = ($dn =~ /^[^=]+=([^,]+),/);

    my $info = "dn=$dn";
    foreach my $rule (@{$conf->{execrule}}) {
        if ($type !~ /$rule->{type}/i) {
            next;
        }

        if (defined($rule->{dn}) && $dn !~ /$rule->{dn}/i) {
            next;
        }

        # check the filter
        if ($oldentry && defined($rule->{filter}) && !LISM::Storage->parseFilter($rule->{filterobj}, $oldentry)) {
            next;
        }

        foreach my $op (keys %{$rule->{op}}) {
            if ($op ne 'delete') {
                next;
            }

            foreach my $script (@{$rule->{op}{$op}->{script}}) {
                my $cmd = $script;
                my $oldinfo = "dn=$dn#".$self->_parseEntry($oldentry, $rule);
                my %params = ('%r' => $rdn_val, '%i' => $info, '%o' => $oldinfo, '%b' => $self->{lism}->{bind}->{edn});
                $cmd = $self->_parseCommand($cmd, %params);

                if ($cmd =~ /^#/) {
                    $cmd =~ s/^#//;
                    print "$cmd\n";
                } elsif ($^O ne 'MSWin32') {
                    my @messages;
                    eval {
                        local $SIG{ALARM} = sub{die;};
                        alarm($conf->{timeout}[0]);
                        open(CMD, "$cmd; echo status=\$?|");
                        while (<CMD>) {
                            chop;
                            push(@messages, $_);
                        }
                        $rc = pop(@messages);
                        ($rc) = ($rc =~ /status=([0-9]+)/);
                        close(CMD);
                    };
                    alarm(0);
                    if ($@) {
                        $rc = -1;
                        push(@messages, 'Timeout');
                    }

                    if ($rc) {
                        $self->log(level => 'err', message => "Script in delete failed($rc): $cmd");
                        $self->log(level => 'err', message => "Script messages: ".join(', ', @messages));
                        ${$errorp} = join(', ', @messages);
                        if ($type eq 'post' && defined($rule->{op}{delete}->{rollback}) && $rule->{op}{delete}->{rollback} eq 'on') {
                            $self->log(level => 'err', message => "Rollback $dn in delete");
                            return LDAP_USER_CANCELED;
                        } else {
                            return ($rc == 32 || $rc == 68) ? $rc : LDAP_OPERATIONS_ERROR;
                        }
                    } else {
                        $self->log(level => 'info', message => "Script in delete succeeded: $cmd");
                    }
                } else {
                    system($cmd);
                }
            }
            next;
        }
    }

    return $rc ? LDAP_OPERATIONS_ERROR : LDAP_SUCCESS;
}

sub _parseCommand
{
    my $self = shift;
    my ($cmd, %params) = @_;

    foreach my $key (keys %params) {
        my $qt = '';
        if ($cmd =~ /'$key'/) {
            $qt = '\'';
        } elsif ($cmd =~ /"$key"/) {
            $qt = '"';
        }

        if ($qt) {
            my $value = $params{$key};
            $value =~ s/([\$\`\\])/\\$1/g;
            $value =~ s/$qt/\\$qt/g;
            $cmd =~ s/$key/$value/g;
        }
        $cmd =~ s/$key/$params{$key}/g;
    }

    return $cmd;
}

sub _parseEntry
{
    my $self = shift;
    my ($entryStr, $rule) = @_;

    if (!$entryStr) {
        return '';
    }

    my @info;
    my (@line) = split(/\n/, $entryStr);
    while (@line > 0) {
        my ($attr, $values) = split(/: /, shift(@line));
        if ($attr =~ /^structuralobjectclass$/i) {
            last;
        }

        while ($line[0] =~ /^$attr: /) {
            $line[0] =~ s/^$attr: //;
            $values = "$values+$line[0]";
            shift @line;
        }

        if (defined($rule->{attrs}) && ",$rule->{attrs}," !~ /,$attr,/i) {
            next;
        }

        push(@info, "$attr=$values");
    }

    return join('#', @info);
}

=head1 SEE ALSO

L<LISM>,
L<LISM::Handler>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
