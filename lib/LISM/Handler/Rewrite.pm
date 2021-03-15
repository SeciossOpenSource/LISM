package LISM::Handler::Rewrite;

use strict;
use base qw(LISM::Handler);
use LISM::Constant;
use Net::LDAP::Filter;
use Encode;
use LISM::Storage;
use Data::Dumper;

=head1 NAME

LISM::Handler::Rewrite - Handler to do script

=head1 DESCRIPTION

This class implements the L<LISM::Hanlder> interface to do script.

=head1 METHODS

=pod

=head2 pre_bind($binddnp)

Rewrite bind dn before bind operation is done.

=cut

sub pre_bind
{
    my $self = shift;
    my ($binddnp) = @_;
    my $conf = $self->{_config};

    foreach my $rule (@{$conf->{rewrite}}) {
        if ($rule->{context} eq 'request' || $rule->{context} eq 'bindRequest') {
            if (defined($rule->{dn}) && ${$binddnp} !~ /$rule->{dn}/i) {
                next;
            }

            if (!defined($rule->{match}) || !defined($rule->{substitution})) {
                next;
            }

            my $substitution = $rule->{substitution};
            $substitution = $self->_rewritePattern($substitution, '%0', ${$binddnp});

            my $str = $self->_rewriteParse($rule->{match}, $substitution, ${$binddnp});
            if (!$str) {
                $self->log(level => 'err', message => "bind rewrite \"${$binddnp}\" failed");
                return LDAP_OPERATIONS_ERROR;
            }
            (${$binddnp}) = split(/\n/, $str);
        }
    }

    return LDAP_SUCCESS;
}

=head2 pre_compare($dnp, $avaStrp)

Rewrite dn and attribute, value before compare operation is done.

=cut

sub pre_compare
{
    my $self = shift;
    my ($dnp, $avaStrp) = @_;
    my $conf = $self->{_config};

    foreach my $rule (@{$conf->{rewrite}}) {
        if ($rule->{context} eq 'request' || $rule->{context} eq 'compareRequest') {
            if (defined($rule->{dn}) && ${$dnp} !~ /$rule->{dn}/i) {
                next;
            }

            if (!defined($rule->{match}) || !defined($rule->{substitution})) {
                next;
            }

            my %rwcache;
            my $substitution = $rule->{substitution};
            $substitution = $self->_rewritePattern($substitution, '%0', "${$dnp}\n${$avaStrp}");

            my $str = $self->_rewriteParse($rule->{match}, $substitution, ${$dnp}, \%rwcache);
            if (!$str) {
                $self->log(level => 'err', message => "compare rewrite \"${$dnp}\" failed");
                return LDAP_OPERATIONS_ERROR;
            }
            (${$dnp}) = split(/\n/, $str);

            $str = $self->_rewriteParse($rule->{match}, $substitution, ${$avaStrp}, \%rwcache);
            if (!$str) {
                $self->log(level => 'err', message => "compcare rewrite \"${$dnp}\" failed");
                return LDAP_OPERATIONS_ERROR;
             }
             (${$avaStrp}) = split(/\n/, $str);
        }
    }

    return LDAP_SUCCESS;
}

=head2 pre_search($basep, $filterStrp)

Rewrite base dn and filter before search operation is done.

=cut

sub pre_search
{
    my $self = shift;
    my ($basep, $filterStrp) = @_;
    my $conf = $self->{_config};

    foreach my $rule (@{$conf->{rewrite}}) {
        if ($rule->{context} eq 'request' || $rule->{context} eq 'searchRequest') {
            if (defined($rule->{dn}) && ${$basep} !~ /$rule->{dn}/i) {
                next;
            }

            if (!defined($rule->{match}) || !defined($rule->{substitution})) {
                next;
            }

            my %rwcache;
            my $substitution = $rule->{substitution};
            $substitution = $self->_rewritePattern($substitution, '%0', "${$basep}\n${$filterStrp}");
            my $str = $self->_rewriteParse($rule->{match}, $substitution, ${$basep}, \%rwcache);
            if (!defined($str)) {
                $self->log(level => 'err', message => "search rewrite \"${$basep}\" failed");
                return LDAP_OPERATIONS_ERROR;
            }
            (${$basep}) = split(/\n/, $str);

            my @elts = (${$filterStrp} =~ /\(([^()]+)\)/g);
            for (my $i = 0; $i < @elts; $i++) {
                $str = $self->_rewriteParse($rule->{match}, $substitution, $elts[$i], \%rwcache);
                if (!defined($str)) {
                    $self->log(level => 'err', message => "search rewrite \"${$filterStrp}\" failed");
                   return LDAP_OPERATIONS_ERROR;
                }

                my $elt;
                foreach my $line (split(/\n/, $str)) {
                    if ($elt) {
                        $elt = "(&$elt($line))";
                    } else {
                        $elt = "($line)";
                    }
                }

                $elts[$i] =~ s/([.*+?\[\]()|\^\$\\\{\}])/\\$1/g;
                ${$filterStrp} =~ s/\($elts[$i]\)/$elt/;
            }
        }
    }
    if (Encode::is_utf8(${$filterStrp})) {
        ${$filterStrp} = encode('utf8', ${$filterStrp});
    }
    return LDAP_SUCCESS;
}

=head2 post_search($entriesp, $attrsp)

Rewrite search results.

=cut

sub post_search
{
    my $self = shift;
    my ($entriesp, $attrsp) = @_;
    my $conf = $self->{_config};

    foreach my $rule (@{$conf->{rewrite}}) {
        if ($rule->{context} eq 'searchResult') {
            if (defined($rule->{attrs}) && @{$attrsp} && !grep(/$rule->{attrs}/i, @{$attrsp})) {
                next;
            }

            my %rwcache;
            for (my $i = 0; $i < @{$entriesp}; $i++) {
                my $entryStr = ${$entriesp}[$i];
                my (@line) = split(/\n/, $entryStr);
                my ($dn) = ($line[0] =~ /^dn: (.*)$/);
                if (defined($rule->{dn}) && $dn !~ /$rule->{dn}/i) {
                    next;
                }
                if (defined($rule->{filter}) && !LISM::Storage->parseFilter($rule->{filterobj}, $entryStr)) {
                    next;
                }

                my $rc = 0;
                my $substitution = $rule->{substitution};
                $substitution = $self->_rewritePattern($substitution, '%0', $entryStr);

                my $str = $self->_rewriteParse($rule->{match}, $substitution, $dn, \%rwcache, 1);
                if (!$str) {
                    $self->log(level => 'err', message => "search result rewrite rule \"$rule->{substitution}\" to \"$dn\" failed");
                    next;
                }
                $line[0] = "dn: $str";

                my @replaced;
                for (my $j = 1; $j < @line; $j++) {
                    my $org = $line[$j];
                    $line[$j] = $self->_rewriteParse($rule->{match}, $substitution, $line[$j], \%rwcache);
                    if (!defined($line[$j])) {
                        $self->log(level => 'err', message => "search result rewrite rule \"$rule->{substitution}\" to \"$dn\" failed");
                        push(@replaced, $org);
                    } elsif ($line[$j]) {
                        push(@replaced, split(/\n/, $line[$j]));
                    }
                }
                ${$entriesp}[$i] = "$line[0]\n".join("\n", $self->_unique(@replaced))."\n";
            }
        }
    }

    return LDAP_SUCCESS;
}

=pod

=head2 pre_modify($dnp, $listp)

Rewrite dn and attributes, values before modify operation is done.

=cut

sub pre_modify
{
    my $self = shift;
    my ($dnp, $listp, $oldentryp, $errorp, $order) = @_;
    my $conf = $self->{_config};

    foreach my $rule (@{$conf->{rewrite}}) {
        if ($rule->{context} eq 'request' || $rule->{context} eq 'modifyRequest') {
            if (defined($rule->{order})) {
                if (!$order || $rule->{order} ne $order) {
                    next;
                }
            } elsif ($order) {
                next;
            }
            if (defined($rule->{dn}) && ${$dnp} !~ /$rule->{dn}/i) {
                next;
            }

            my $entryStr = $oldentryp ? ${$oldentryp} : '';
            my $modlist = "${$dnp}\n";
            my @list = @{$listp};
            while (@list > 0) {
                my $action = shift @list;
                my $attr = shift @list;
                my @values;
                while (@list > 0 && $list[0] !~ /^(ADD|DELETE|REPLACE)$/) {
                    push(@values, shift @list);
                }
                if ($entryStr) {
                    if ($action eq 'ADD') {
                        foreach my $value (@values) {
                            if ($value !~ /^ *$/) {
                                $entryStr .= "$attr: $value\n";
                            }
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
                            if ($value !~ /^ *$/) {
                                $entryStr .= "$attr: $value\n";
                            }
                        }
                    }
                }
                if (defined($rule->{entryattrs})) {
                    if (grep(/$attr/i, split(/, */, $rule->{entryattrs})) && @values) {
                        $modlist .= "$action\n$attr\n".join("\n", @values)."\n";
                    }
                }
            }
            if (!defined($rule->{entryattrs})) {
                $modlist .= join("\n", @{$listp});
            }

            if ($entryStr && defined($rule->{filter}) && !LISM::Storage->parseFilter($rule->{filterobj}, $entryStr)) {
                next;
            }

            if (defined($rule->{profile}) && defined($rule->{roles})) {
                if ($self->_setProfile('modify', $rule, ${$dnp}, $listp, $oldentryp)) {
                    $self->log(level => 'err', message => "modify rewrite rule of profile \"$rule->{profile}\" failed");
                    return LDAP_OPERATIONS_ERROR;
                }
                next;
            }

            if (!defined($rule->{match}) || !defined($rule->{substitution})) {
                next;
            }

            my %rwcache;
            my $substitution = $rule->{substitution};
            $substitution = $self->_rewritePattern($substitution, '%0', $modlist);
            if ($oldentryp) {
                my $tmpstr;
                if (defined($rule->{entryattrs})) {
                    $tmpstr = '';
                    foreach my $attr (split(/, */, $rule->{entryattrs})) {
                        my @values = (${$oldentryp} =~ /^$attr: (.*)$/gmi);
                        if (@values) {
                            foreach my $value (@values) {
                                $tmpstr .= "$attr: $value\n";
                            }
                        }
                    }
                } else {
                    $tmpstr = ${$oldentryp};
                }
                $substitution = $self->_rewritePattern($substitution, '%-', $tmpstr);
            }

            my $str = $self->_rewriteParse($rule->{match}, $substitution, ${$dnp}, \%rwcache, 1);
            if (!$str) {
                $self->log(level => 'err', message => "modify rewrite rule \"$rule->{substitution}\" to \"${$dnp}\" failed");
                return LDAP_OPERATIONS_ERROR;
            }
            (${$dnp}) = split(/\n/, $str);

            my @mod_list;
            my %replace_attrs;
            my %deleteall_attrs;
            while (@{$listp} > 0) {
                my $action = shift @{$listp};
                my $attr = shift @{$listp};
                my @values;
                my %replaced;

                $str = $self->_rewriteParse($rule->{match}, $substitution, "$action: $attr");
                ($attr) = ($str =~ /^[^:]+: (.*)$/);
                while (@{$listp} > 0 && ${$listp}[0] !~ /^(ADD|DELETE|REPLACE)$/) {
                    push(@values, shift @{$listp});
                }

                if ($attr =~ /^lismPreviousEntry$/i) {
                    push(@mod_list, ($action, $attr, @values));
                } elsif (defined($rule->{modop}) && $rule->{modop} !~ /$action/i) {
                    push(@mod_list, ($action, $attr, @values));
                } elsif (@values) {
                    my %rwactions;
                    for (my $i =0; $i < @values; $i++) {
                        $str = $self->_rewriteParse($rule->{match}, $substitution, "$attr: ".$values[$i], \%rwcache);
                        if (!defined($str)) {
                            $self->log(level => 'err', message => "modify rewrite rule \"$rule->{substitution}\" to \"$attr: $values[$i]\" in \"${$dnp}\" failed");
                            return LDAP_OPERATIONS_ERROR;
                        } elsif ($str) {
                            foreach my $line (split(/\n/, $str)) {
                                if ($line =~ /^ADD|DELETE|REPLACE/) {
                                    my ($rwaction, $rwattr) = ($line =~ /(^[^:]*): (.*)$/);
                                    if (!defined($replaced{$rwattr})) {
                                        $rwactions{$rwattr} = $rwaction;
                                    }
                                    next;
                                }
                                my ($rwattr, $value) = ($line =~ /(^[^:]*): (.*)$/);
                                if (!defined($replaced{$rwattr})) {
                                    @{$replaced{$rwattr}} = ();
                                }
                                push(@{$replaced{$rwattr}}, $value);
                            }
                        }
                    }
                    foreach my $rwattr (keys %replaced) {
                        my $rwaction = defined($rwactions{$rwattr}) ? $rwactions{$rwattr} : $action;
                        if ($rwaction eq 'REPLACE' && defined($replace_attrs{lc($rwattr)})) {
                            for (my $i = 0; $i < @mod_list; $i++) {
                                if ($mod_list[$i] =~ /^$rwattr$/i && $mod_list[$i - 1] eq 'REPLACE') {
                                    $i++;
                                    my @values;
                                    my $j;
                                    for ($j = 0; $i + $j < @mod_list; $j++) {
                                        if ($mod_list[$i + $j] =~ /^(ADD|DELETE|REPLACE)$/) {
                                            last;
                                        }
                                        if ($mod_list[$i + $j] !~ /^ *$/) {
                                            push(@values, $mod_list[$i + $j]);
                                        }
                                    }
                                    push(@values, @{$replaced{$rwattr}});
                                    splice(@mod_list, $i, $j, $self->_unique(@values));
                                }
                            }
                        } else {
                            if ($action eq 'DELETE') {
                                if (defined($deleteall_attrs{lc($attr)})) {
                                    next;
                                } elsif (defined($replace_attrs{lc($rwattr)}) && !$values[0]) {
                                    next;
                                } elsif (!${$replaced{$rwattr}}[0]) {
                                    $deleteall_attrs{lc($attr)} = 1;
                                }
                            }
                            push(@mod_list, (defined($rwactions{$rwattr}) ? $rwactions{$rwattr} : $action, $rwattr, $self->_unique(@{$replaced{$rwattr}})));
                            if ($rwaction eq 'REPLACE') {
                                $replace_attrs{lc($rwattr)} = 1;
                            }
                        }
                    }
                } else {
                    $str = $self->_rewriteParse($rule->{match}, $substitution, "$attr: ", \%rwcache);
                    if (!defined($str)) {
                        $self->log(level => 'err', message => "modify rewrite rule \"$rule->{substitution}\" to \"$attr: \" in \"${$dnp}\" failed");
                        return LDAP_OPERATIONS_ERROR;
                    } elsif ($str) {
                        my ($rwattr, $value) = ($str =~ /(^[^:]*): (.*)$/);
                        if ($rwattr) {
                            $attr = $rwattr;
                        }
                        if ($action eq 'DELETE' && !$value) {
                            if (defined($deleteall_attrs{lc($attr)})) {
                                next;
                            } elsif (defined($replace_attrs{lc($rwattr)})) {
                                next;
                            } else {
                                $deleteall_attrs{lc($attr)} = 1;
                            }
                        }
                        if ($action eq 'REPLACE' && defined($replace_attrs{lc($attr)})) {
                            next;
                        }
                        push(@mod_list, ($action, $attr));
                        if ($value) {
                            push(@mod_list, $value);
                        }
                    } else {
                        if ($action eq 'DELETE' && defined($deleteall_attrs{lc($attr)})) {
                            next;
                        }
                        push(@mod_list, ($action, $attr));
                        $deleteall_attrs{lc($attr)} = 1;
                    }
                }
            }
            @{$listp} = @mod_list;
        }
    }

    return LDAP_SUCCESS;
}

sub post_modify
{
    my $self = shift;
    my ($dnp, $listp, $oldentryp) = @_;
    my $conf = $self->{_config};

    foreach my $rule (@{$conf->{rewrite}}) {
        if ($rule->{context} eq 'modifyResult') {
            if (defined($rule->{dn}) && ${$dnp} !~ /$rule->{dn}/i) {
                next;
            }

            my %rwcache;
            my $substitution = $rule->{substitution};
            my $modlist = "${$dnp}\n".join("\n", @{$listp});
            $substitution = $self->_rewritePattern($substitution, '%0', $modlist);
            if ($oldentryp) {
                my $tmpstr;
                if (defined($rule->{entryattrs})) {
                    $tmpstr = '';
                    foreach my $attr (split(/, */, $rule->{entryattrs})) {
                        my @values = (${$oldentryp} =~ /^$attr: (.*)$/gmi);
                        if (@values) {
                            foreach my $value (@values) {
                                $tmpstr .= "$attr: $value\n";
                            }
                        }
                    }
                } else {
                    $tmpstr = ${$oldentryp};
                }
                $substitution = $self->_rewritePattern($substitution, '%-', $tmpstr);
            }

            my $str = $self->_rewriteParse($rule->{match}, $substitution, ${$dnp}, \%rwcache);
            if (!$str) {
                $self->log(level => 'err', message => "modify result rewrite rule \"$rule->{substitution}\" to \"${$dnp}\" failed");
                return LDAP_OPERATIONS_ERROR;
            }
            (${$dnp}) = split(/\n/, $str);

            my @mod_list;
            while (@{$listp} > 0) {
                my $action = shift @{$listp};
                my $attr = shift @{$listp};
                my @values;
                my %replaced;

                $str = $self->_rewriteParse($rule->{match}, $substitution, "$action: $attr");
                ($attr) = ($str =~ /^[^:]+: (.*)$/);
                while (@{$listp} > 0 && ${$listp}[$0] !~ /ADD|DELETE|REPLACE/) {
                    push(@values, shift @{$listp});
                }

                if (defined($rule->{modop}) && $rule->{modop} !~ /$action/i) {
                    push(@mod_list, ($action, $attr, @values));
                } elsif (@values) {
                    my %rwactions;
                    for (my $i =0; $i < @values; $i++) {
                        $str = $self->_rewriteParse($rule->{match}, $substitution, "$attr: ".$values[$i], \%rwcache);
                        if (!defined($str)) {
                            $self->log(level => 'err', message => "modify result rewrite rule \"$rule->{substitution}\" to \"$attr: $values[$i]\" in \"${$dnp}\" failed");
                            return LDAP_OPERATIONS_ERROR;
                        } elsif ($str) {
                            foreach my $line (split(/\n/, $str)) {
                                if ($line =~ /^ADD|DELETE|REPLACE/) {
                                    my ($rwaction, $rwattr) = ($line =~ /(^[^:]*): (.*)$/);
                                    if (!defined($replaced{$rwattr})) {
                                        $rwactions{$rwattr} = $rwaction;
                                    }
                                    next;
                                }
                                my ($rwattr, $value) = ($line =~ /(^[^:]*): (.*)$/);
                                if (!defined($replaced{$rwattr})) {
                                    @{$replaced{$rwattr}} = ();
                                }
                                push(@{$replaced{$rwattr}}, $value);
                            }
                        }
                    }
                    foreach my $rwattr (keys %replaced) {
                        push(@mod_list, (defined($rwactions{$rwattr}) ? $rwactions{$rwattr} : $action, $rwattr, $self->_unique(@{$replaced{$rwattr}})));
                    }
                } else {
                    push(@mod_list, ($action, $attr));
                }
            }
            @{$listp} = @mod_list;
        }
    }

    return LDAP_SUCCESS;
}

=pod

=head2 pre_add($dnp, $entryStrp)

Rewrite entry before add operation is done.

=cut

sub pre_add
{
    my $self = shift;
    my ($dnp, $entryStrp, $oldentryp, $errorp, $order) = @_;
    my $conf = $self->{_config};

    foreach my $rule (@{$conf->{rewrite}}) {
        if ($rule->{context} eq 'request' || $rule->{context} eq 'addRequest') {
            if (defined($rule->{order})) {
                if (!$order || $rule->{order} ne $order) {
                    next;
                }
            } elsif ($order) {
                next;
            }
            if (defined($rule->{dn}) && ${$dnp} !~ /$rule->{dn}/i) {
                next;
            }
            if (defined($rule->{filter}) && !LISM::Storage->parseFilter($rule->{filterobj}, "${$dnp}\n${$entryStrp}[0]")) {
                next;
            }

            if (defined($rule->{profile}) && defined($rule->{roles})) {
                if ($self->_setProfile('add', $rule, ${$dnp}, $entryStrp)) {
                    $self->log(level => 'err', message => "add rewrite rule of profile \"$rule->{profile}\" failed");
                    return LDAP_OPERATIONS_ERROR;
                }
                next;
            }

            if (!defined($rule->{match}) || !defined($rule->{substitution})) {
                next;
            }

            my %rwcache;
            my $substitution = $rule->{substitution};
            my $tmpstr = "${$dnp}\n";
            if (defined($rule->{entryattrs})) {
                foreach my $attr (split(/, */, $rule->{entryattrs})) {
                    my @values = (${$entryStrp}[0] =~ /^$attr: (.*)$/gmi);
                    if (@values) {
                        foreach my $value (@values) {
                            $tmpstr .= "$attr: $value\n";
                        }
                    }
                }
            } else {
                $tmpstr .= ${$entryStrp}[0];
            }
            $substitution = $self->_rewritePattern($substitution, '%0', $tmpstr);

            my $str = $self->_rewriteParse($rule->{match}, $substitution, ${$dnp}, \%rwcache, 1);
            if (!$str) {
                $self->log(level => 'err', message => "add rewrite rule \"$rule->{substitution}\" to \"${$dnp}\" failed");
                return LDAP_OPERATIONS_ERROR;
            }
            (${$dnp}) = split(/\n/, $str);

            my (@line) = split(/\n/, ${$entryStrp}[0]);

            for (my $i = 0; $i < @line; $i++) {
                $line[$i] = $self->_rewriteParse($rule->{match}, $substitution, $line[$i], \%rwcache);
                if (!defined($line[$i])) {
                    $self->log(level => 'err', message => "add rewrite rule \"$rule->{substitution}\" to \"$line[$i]\" in \"${$dnp}\" failed");
                    return LDAP_OPERATIONS_ERROR;
                }
            }
            ${$entryStrp}[0] = '';
            foreach my $elt ($self->_unique(@line)) {
                if ($elt) {
                    ${$entryStrp}[0] .= "$elt\n";
                }
            }
        }
    }

    return LDAP_SUCCESS;
}

sub post_add
{
    my $self = shift;
    my ($dnp, $entryStrp) = @_;
    my $conf = $self->{_config};

    foreach my $rule (@{$conf->{rewrite}}) {
        if ($rule->{context} eq 'addResult') {
            if (defined($rule->{dn}) && ${$dnp} !~ /$rule->{dn}/i) {
                next;
            }
            if (defined($rule->{filter}) && !LISM::Storage->parseFilter($rule->{filterobj}, "${$dnp}\n${$entryStrp}[0]")) {
                next;
            }

            my %rwcache;
            my $substitution = $rule->{substitution};
            $substitution = $self->_rewritePattern($substitution, '%0', "${$dnp}\n${$entryStrp}[0]");

            my $str = $self->_rewriteParse($rule->{match}, $substitution, ${$dnp}, \%rwcache);
            if (!$str) {
                $self->log(level => 'err', message => "add result rewrite rule \"$rule->{substitution}\" to \"${$dnp}\" failed");
                return LDAP_OPERATIONS_ERROR;
            }
            (${$dnp}) = split(/\n/, $str);

            my (@line) = split(/\n/, ${$entryStrp}[0]);

            for (my $i = 0; $i < @line; $i++) {
                $line[$i] = $self->_rewriteParse($rule->{match}, $substitution, $line[$i], \%rwcache);
                if (!defined($line[$i])) {
                    $self->log(level => 'err', message => "add result rewrite rule \"$rule->{substitution}\" to \"$line[$i]\" in \"${$dnp}\" failed");
                    return LDAP_OPERATIONS_ERROR;
                }
            }
            ${$entryStrp}[0] = '';
            foreach my $elt ($self->_unique(@line)) {
                if ($elt) {
                    ${$entryStrp}[0] .= "$elt\n";
                }
            }
        }
    }

    return LDAP_SUCCESS;
}

=head2 pre_modrdn($dnp, $argsp)

Rewrite dn and new rdn before modrdn operation is done.

=cut

sub pre_modrdn
{
    my $self = shift;
    my ($dnp, $argsp) = @_;
    my $conf = $self->{_config};

    foreach my $rule (@{$conf->{rewrite}}) {
        if ($rule->{context} eq 'request' || $rule->{context} eq 'modrdnRequest') {
            if (defined($rule->{dn}) && ${$dnp} !~ /$rule->{dn}/i) {
                next;
            }

            if (!defined($rule->{match}) || !defined($rule->{substitution})) {
                next;
            }

            my %rwcache;
            my $substitution = $rule->{substitution};
            $substitution = $self->_rewritePattern($substitution, '%0', "${$dnp}\n${$argsp}[0]");

            my $str = $self->_rewriteParse($rule->{match}, $substitution, ${$dnp}, \%rwcache);
            if (!$str) {
                $self->log(level => 'err', message => "modrdn rewrite rule \"$rule->{substitution}\" to \"${$dnp}\" failed");
                return LDAP_OPERATIONS_ERROR;
            }
            (${$dnp}) = split(/\n/, $str);

            $str = $self->_rewriteParse($rule->{match}, $substitution, ${$argsp}[0], \%rwcache);
            if (!$str) {
                $self->log(level => 'err', message => "modrdn rewrite rule \"$rule->{substitution}\" to \"${$argsp}[0]\" in \"${$dnp}\" failed");
                return LDAP_OPERATIONS_ERROR;
            }
            ${$argsp}[0] = $str;
        }
    }

    return LDAP_SUCCESS;
}

=pod

=head2 pre_delete($dnp)

Rewrite dn before delete operation is done.

=cut

sub pre_delete
{
    my $self = shift;
    my ($dnp, $argsp, $oldentryp, $errorp, $order) = @_;
    my $conf = $self->{_config};

    foreach my $rule (@{$conf->{rewrite}}) {
        if ($rule->{context} eq 'request' || $rule->{context} eq 'deleteRequest') {
            if (defined($rule->{order})) {
                if (!$order || $rule->{order} ne $order) {
                    next;
                }
            } elsif ($order) {
                next;
            }
            if (defined($rule->{dn}) && ${$dnp} !~ /$rule->{dn}/i) {
                next;
            }

            if (!defined($rule->{match}) || !defined($rule->{substitution})) {
                next;
            }

            my %rwcache;
            my $substitution = $rule->{substitution};
            $substitution = $self->_rewritePattern($substitution, '%0', ${$dnp});
            if ($oldentryp) {
                if (defined($rule->{filter}) && !LISM::Storage->parseFilter($rule->{filterobj}, ${$oldentryp})) {
                    next;
                }

                my $tmpstr;
                if (defined($rule->{entryattrs})) {
                    $tmpstr = '';
                    foreach my $attr (split(/, */, $rule->{entryattrs})) {
                        my @values = (${$oldentryp} =~ /^$attr: (.*)$/gmi);
                        if (@values) {
                            foreach my $value (@values) {
                                $tmpstr .= "$attr: $value\n";
                            }
                        }
                    }
                } else {
                    $tmpstr = ${$oldentryp};
                }
                $substitution = $self->_rewritePattern($substitution, '%-', $tmpstr);
            }

            my $str = $self->_rewriteParse($rule->{match}, $substitution, ${$dnp}, \%rwcache);
            if (!$str) {
                $self->log(level => 'err', message => "delete rewrite rule \"$rule->{substitution}\" to \"${$dnp}\" failed");
                return LDAP_OPERATIONS_ERROR;
            }
            (${$dnp}) = split(/\n/, $str);
        }
    }

    return LDAP_SUCCESS;
}

sub post_delete
{
    my $self = shift;
    my ($dnp, $argsp, $oldentryp) = @_;
    my $conf = $self->{_config};

    foreach my $rule (@{$conf->{rewrite}}) {
        if ($rule->{context} eq 'deleteResult') {
            if (defined($rule->{dn}) && ${$dnp} !~ /$rule->{dn}/i) {
                next;
            }

            my %rwcache;
            my $substitution = $rule->{substitution};
            $substitution = $self->_rewritePattern($substitution, '%0', ${$dnp});
            if ($oldentryp) {
                $substitution = $self->_rewritePattern($substitution, '%-', ${$oldentryp});
            }

            my $str = $self->_rewriteParse($rule->{match}, $substitution, ${$dnp}, \%rwcache);
            if (!$str) {
                $self->log(level => 'err', message => "delete result rewrite rule \"$rule->{substitution}\" to \"${$dnp}\" failed");
                return LDAP_OPERATIONS_ERROR;
            }
            (${$dnp}) = split(/\n/, $str);
        }
    }

    return LDAP_SUCCESS;
}

sub _checkConfig
{
    my $self = shift;
    my $conf = $self->{_config};
    my $rc = 0;

    if ($rc = $self->SUPER::_checkConfig()) {
        return $rc;
    }

    if (defined($conf->{libload})) {
        foreach my $lib (@{$conf->{libload}}) {
            eval "do \'$lib\'";
            if ($@) {
                $self->log(level => 'alert', message => "rewrite do require $lib: $@");
                return 1;
            }
        }
    }

    if (defined($conf->{rewritemap})) {
        foreach my $map_name (keys %{$conf->{rewritemap}}) {
            my $type = $conf->{rewritemap}{$map_name}->{type};
            if ($type eq 'ldap') {
                if (!defined($self->{ldapmap})) {$self->{ldapmap} = {}};
                my $ldapmap = {};
                if (Encode::is_utf8($conf->{rewritemap}{$map_name}->{attrs})) {
                    $conf->{rewritemap}{$map_name}->{attrs} = encode('utf8', $conf->{rewritemap}{$map_name}->{attrs});
                }
                $self->_parseLdapUri($ldapmap, $conf->{rewritemap}{$map_name}->{attrs});
                $self->{ldapmap}{$map_name} = $ldapmap;
            } elsif ($type eq 'lism') {
                if (!defined($self->{lismmap})) {$self->{lismmap} = {}};
                my $lismmap = {};
                my ($base, $attrsStr, $scope, $sizelimit) = split(/\?/, $conf->{rewritemap}{$map_name}->{attrs});
                $lismmap->{base} = $base;
                my ($attr, @attrs) = split(/,/, $attrsStr);
                $lismmap->{attr} = $attr;
                if (@attrs) {
                    $lismmap->{attrs} = \@attrs;
                }
                if ($scope) {
                    $lismmap->{scope} = $scope;
                }
                if ($sizelimit) {
                    $lismmap->{sizelimit} = $sizelimit;
                }
                if (defined($conf->{rewritemap}{$map_name}->{match})) {
                    $lismmap->{match} = $conf->{rewritemap}{$map_name}->{match};
                }
                if (defined($conf->{rewritemap}{$map_name}->{substitution})) {
                    $lismmap->{substitution} = $conf->{rewritemap}{$map_name}->{substitution};
                    $lismmap->{substitution} =~ s/%([0-9]+)/\$$1/;
                }
                if (defined($conf->{rewritemap}{$map_name}->{attrmap})) {
                    $lismmap->{attrmap} = $conf->{rewritemap}{$map_name}->{attrmap};
                }
                $self->{lismmap}{$map_name} = $lismmap;
            }
        }
    }

    if (defined($conf->{rewrite})) {
        foreach my $rule (@{$conf->{rewrite}}) {
            if (defined($rule->{filter})) {
                $rule->{filter} =~ s/&amp;/&/g;
                $rule->{filterobj} = Net::LDAP::Filter->new(encode('utf8', $rule->{filter}));
            }
            if (defined($rule->{attrs})) {
                $rule->{attrs} =~ s/,/|/;
                $rule->{attrs} = '^('.$rule->{attrs}.')$';
            }

            if (defined($rule->{substitution})) {
                # enable escape sequence
                $rule->{substitution} =~ s/([^\\])\\n/$1\n/g;
                $rule->{substitution} =~ s/([^\\])\\t/$1\t/g;
                $rule->{substitution} =~ s/&amp;/&/g;
            }
        }
    }

    return $rc;
}

sub _rewritePattern
{
    my $self = shift;
    my ($str, $pattern, $value) = @_;

    my @rwmaps = ($str =~ /%\{([^(]*\((?:(?!%\{).)*\))\}/gs);
    foreach my $rwmap (@rwmaps) {
        my $tmpstr = $rwmap;
        my $tmpval = $value;
        my $qt = '';
        if ($rwmap =~ /'[^']*$pattern[^']*'/) {
            $qt = '\'';
        } elsif ($rwmap =~ /"[^"]*$pattern[^"]*"/) {
            $qt = '"';
        }

        if ($qt) {
            $tmpval =~ s/$qt/\\$qt/g;
            $tmpstr =~ s/$pattern/$tmpval/g;
        }
        $rwmap =~ s/([.*+?\[\]()|\^\$\\\{\}])/\\$1/g;
        $str =~ s/%\{$rwmap\}/%{$tmpstr}/;
    }

    $str =~ s/$pattern/$value/g;
    return $str;
}

sub _rewriteParse
{
    my $self = shift;
    my ($match, $substitution, $str, $rwcache, $is_dn) = @_;
    my $newstr;

    my @matches = ($str =~ /$match/gi);
    if (!@matches) {
         return $str;
    }

    # replace variables
    for (my $i = 0; $i < @matches; $i++) {
        my $num = $i + 1;
        for (my $j = 0; $substitution =~ /%$num/ && $j < 100; $j++) {
            $substitution = $self->_rewritePattern($substitution, "%$num", $matches[$i]);
            if ($matches[$i] =~ /%$num/) {
                last;
            }
        }
        my $escaped = $matches[$i];
        $escaped =~ s/([\(\)*])/\\$1/g;
        for (my $j = 0; $substitution =~ /%\[${num}E\]/ && $j < 100; $j++) {
            $substitution = $self->_rewritePattern($substitution, '%\['.$num.'E\]', $escaped);
        }
    }

    foreach my $substline ($self->_splitSubst($substitution)) {
        my $oldstr = $str;

        # do functions
        my @substs = ($substline);
        my @rwmaps = ($substline =~ /%\{([^(]*\((?:(?!%\{).)*\))\}/gs);
        foreach my $rwmap (@rwmaps) {
            my @values;
            my $key = lc($rwmap);

            if (defined(${$rwcache}{$key})) {
                @values = @{${$rwcache}{$key}};
            } else {
                my ($map_name, $map_args) = ($rwmap =~ /^([^(]*)\((.*)\)$/s);
                if (!$map_name) {
                    return undef;
                }

                @values = $self->_rewriteMap($map_name, $map_args, $is_dn, $rwcache);
                if (!defined($values[0])) {
                    return undef;
                }

                ${$rwcache}{$key} = \@values;
            }

            if ($values[0] eq '') {
                return $str;
            }

            $rwmap =~ s/([.*+?\[\]()|\^\$\\\{\}])/\\$1/g;
            my @tmpsubsts;
            foreach my $subst (@substs) {
                foreach my $value (@values) {
                    my $tmpsubst = $subst;
                    $tmpsubst =~ s/%\{$rwmap\}/$value/;
                    push(@tmpsubsts, $tmpsubst);
                }
            }
            undef(@substs);
            @substs = @tmpsubsts;
        }

        my @strs;
        foreach my $subst (@substs) {
            my $tmpstr = $oldstr;
            $tmpstr =~ s/$match/$subst/gi;
            push(@strs, $tmpstr);
        }
        if ($newstr) {
            $newstr = "$newstr\n".join("\n", @strs);
        } else {
            $newstr = join("\n", @strs);
        }
    }

    return $newstr;
}

sub _splitSubst
{
    my $self = shift;
    my ($substitution) = @_;
    my @substs;

    my $prevpos = 0;
    my $oldpos = 0;
    while ((my $pos = index($substitution, "\n", $oldpos)) > 0) {
        my $str = substr($substitution, $prevpos, $pos - $prevpos);
        if (index($str, "%{", $oldpos - $prevpos) >= 0) {
            if (index($str, "(", $oldpos - $prevpos) > 0) {
                 $oldpos = $self->_passArgs($substitution, $oldpos);
            }
            $oldpos = index($substitution, "}", $oldpos);
            next;
        }
        push(@substs, $str);
        $prevpos = $oldpos = $pos + 1;
    }
    push(@substs, substr($substitution, $prevpos));

    return @substs;
}

sub _passArgs
{
    my $self = shift;
    my ($str, $oldpos) = @_;
    my $pos = $oldpos;

    $pos = index($str, "(", $pos);
    if ($pos < 0) {
        return $pos;
    }

    my $leftstr = substr($str, $pos + 1);
    my ($qtchar) = ($leftstr =~ /^ *(['"])/);

    while ($qtchar) {
        $pos = index($str, $qtchar, $pos);
        while (1) {
            my $tmppos = index($str, $qtchar, $pos + 1);
            if ($tmppos < 0) {
                last;
            }
            $pos = $tmppos;

            if (substr($str, $tmppos - 1, 1) eq "\\") {
                next;
            }
            last;
        }
        $pos++;

        $leftstr = substr($str, $pos);
        ($qtchar) = ($leftstr =~ /^ *, *(['"])/);
        if (!$qtchar && $leftstr !~ /^ *\)/) {
            my $tmppos = $pos;
            while (1) {
                $tmppos = index($str, ",", $tmppos + 1);
                if ($tmppos < 0) {
                    last;
                }
                $leftstr = substr($str, $tmppos);
                ($qtchar) = ($leftstr =~ /^, *(['"])/);
                if ($qtchar) {
                    $pos = $tmppos;
                    last;
                }
            }
        }
    }

    $pos = index($str, ")", $pos);
    if ($pos < 0) {
        $pos = $oldpos;
    }

    return $pos;
}

sub _rewriteMap
{
    my $self = shift;
    my ($map_name, $map_args, $is_dn, $rwcache) = @_;
    my $conf = $self->{_config};
    my @values = ();

    if (defined($conf->{rewritemap}{$map_name})) {
        my $method = '_'.$conf->{rewritemap}{$map_name}->{type}.'Map';
        @values = $self->$method($map_name, $map_args, $is_dn, $rwcache);
    }

    return @values;
}

sub _ldapMap
{
    my $self = shift;
    my ($map_name, $map_args) = @_;
    my $ldapmap = $self->{ldapmap}{$map_name};

    return $self->_searchLdap($ldapmap, $map_args);
}

sub _lismMap
{
    my $self = shift;
    my ($map_name, $map_args, $is_dn, $rwcache) = @_;
    my $lismmap = $self->{lismmap}{$map_name};
    my $escape = 0;
    if ($map_args =~ /\\'/) {
        $map_args =~ s/\\'/\\27/g;
        $escape = 1;
    }
    my @args = ($map_args =~ /'([^']+)'/g);
    if ($escape) {
        for (my $i = 0; $i < @args; $i++) {
            $args[$i] =~ s/\\27/\'/g;
        }
    }
    my @vals = $self->_searchLism($lismmap, $rwcache, @args);
    if ($is_dn && $lismmap->{attr} ne 'dn' && $lismmap->{attr} ne 'parentdn') {
        for (my $i = 0; $i < @vals; $i++) {
            $vals[$i] =~ s/\\/\\5C/g;
            $vals[$i] =~ s/"/\\22/g;
            $vals[$i] =~ s/#/\\23/g;
            $vals[$i] =~ s/\+/\\2B/g;
            $vals[$i] =~ s/\//\\2F/g;
            $vals[$i] =~ s/;/\\3B/g;
            $vals[$i] =~ s/</\\3C/g;
            $vals[$i] =~ s/>/\\3E/g;
            $vals[$i] =~ s/,/\\2C/g;
        }
    }
    return @vals;
}

sub _functionMap
{
    my $self = shift;
    my ($map_name, $map_args) = @_;
    my @values;

    $map_args =~ s/(?<!\\)\\/\\\\/g;
    $map_args =~ s/\\\\'(?!, *'| *\))/\\'/g;
    eval "\@values = $map_name($map_args)";
    if ($@) {
        $self->log(level => 'err', message => "rewriteMap $map_name failed: $@");
        return undef;
    }

    return @values;
}

sub _regexpMap
{
    my $self = shift;
    my ($map_name, $map_args) = @_;
    my $conf = $self->{_config};

    return ($map_args =~ /$conf->{rewritemap}{$map_name}->{attrs}/gi);
}

sub _setProfile
{
    my $self = shift;
    my ($func, $rule, $dn, $entryp, $oldentryp) = @_;
    my $suffix = $self->{lism}->{_config}->{basedn};
    my ($basedn) = ($dn =~ /(ou=[^,]+,$suffix)$/i);
    my @dbases;
    foreach my $dname (keys %{$self->{lism}->{data}}) {
        my ($dbase) = ($self->{lism}->{data}{$dname}->{suffix} =~ /^(.+),$suffix$/i);
        if ($dbase) {
            push(@dbases, $dbase);
        }
    }

    my @profile_attrs = split(/, */, $rule->{profile});
    my @attrs;
    foreach my $attr (split(/, */, $rule->{roles})) {
        push(@attrs, lc($attr));
    }
    my %replace_roles;
    my %add_roles;
    my %del_roles;
    my @add_profiles;
    my @del_profiles;
    my @mod_list;
    if ($func eq 'add') {
        my $entryStr = ${$entryp}[0];
        foreach my $profile_attr (@profile_attrs) {
            push(@add_profiles, ($entryStr =~ /^$profile_attr: (.+)$/gmi));
        }
    } elsif ($func eq 'modify') {
        my @list = @{$entryp};
        my $updated = 0;
        foreach my $profile_attr (@profile_attrs) {
            if (grep(/^$profile_attr$/i, @list)) {
                $updated = 1;
                last;
            }
        }
        if (!$updated) {
            foreach my $attr (@attrs) {
                if (grep(/^$attr$/i, @list)) {
                    $updated = 1;
                    last;
                }
            }
        }
        if (!$updated) {
            return 0;
        }

        my $entryStr = $oldentryp ? ${$oldentryp} : '';
        my %old_roles;
        foreach my $attr (@attrs) {
            my @tmpvals;
            foreach my $tmpval ($entryStr =~ /^$attr: (.+)$/gmi) {
                if ($tmpval !~ /^ *$/) {
                    if ($basedn && $tmpval =~ /,ou=[^,]+,$basedn$/i) {
                        foreach my $dbase (@dbases) {
                            if ($tmpval =~ /$dbase,$basedn$/i) {
                                $tmpval =~ s/$basedn/$suffix/i;
                                last;
                            }
                        }
                    }
                    push @tmpvals, $tmpval;
                }
            }
            $old_roles{$attr} = \@tmpvals;
        }

        my %profile_updated;
        while (@list > 0) {
            my $action = shift @list;
            my $attr = shift @list;
            my $key = lc($attr);
            my @tmpvals;
            while (@list > 0 && $list[0] !~ /^(ADD|DELETE|REPLACE)$/) {
                my $tmpval = shift @list;
                if ($tmpval !~ /^ *$/) {
                    push(@tmpvals, $tmpval);
                }
            }
            if (grep(/^$attr$/i,  @profile_attrs)) {
                my @old_profiles = ($entryStr =~ /^$attr: (.+)$/gmi);
                if ($action eq 'ADD') {
                    @add_profiles = @tmpvals;
                } elsif ($action eq 'REPLACE') {
                    foreach my $tmpval (@tmpvals) {
                        push(@add_profiles, $tmpval);
                    }
                    foreach my $profile (@old_profiles) {
                        if (!grep(/^$profile$/i, @tmpvals)) {
                            push(@del_profiles, $profile);
                        }
                    }
                } elsif ($action eq 'DELETE') {
                    if (@tmpvals) {
                        @del_profiles = @tmpvals;
                    } else {
                        @del_profiles = @old_profiles;
                    }
                }
                push(@mod_list, $action, $attr, @tmpvals);
                $profile_updated{$key} = 1;
            } elsif (grep(/^$attr$/i, @attrs)) {
                if (@tmpvals) {
                    for (my $i = 0; $i < @tmpvals; $i++) {
                        if ($basedn && $tmpvals[$i] =~ /,ou=[^,]+,$basedn$/i) {
                            foreach my $dbase (@dbases) {
                                if ($tmpvals[$i] =~ /$dbase,$basedn$/i) {
                                    $tmpvals[$i] =~ s/$basedn/$suffix/i;
                                    last;
                                }
                            }
                        }
                    }
                }
                if ($action eq 'ADD') {
                    if (!defined(${$replace_roles{$key}})) {
                        $replace_roles{$key} = $old_roles{$key};
                    }
                    foreach my $tmpval (@tmpvals) {
                        my $regex_val = $tmpval;
                        $regex_val =~ s/([.*+?\[\]()|\^\$\\\{\}])/\\$1/g;
                        if (!grep(/^$regex_val$/i, @{$replace_roles{$key}})) {
                            push(@{$replace_roles{$key}}, $tmpval);
                        }
                    }
                } elsif ($action eq 'REPLACE') {
                    $replace_roles{$key} = \@tmpvals;
                } elsif ($action eq 'DELETE') {
                    if (!defined($replace_roles{$key})) {
                        $replace_roles{$key} = $old_roles{$key};
                    }
                    if (@tmpvals) {
                        foreach my $tmpval (@tmpvals) {
                            for (my $i = 0; $i < @{$replace_roles{$key}}; $i++) {
                                my $regex_val = $tmpval;
                                $regex_val =~ s/([.*+?\[\]()|\^\$\\\{\}])/\\$1/g;
                                if (${$replace_roles{$key}}[$i] =~ /^$regex_val$/i) {
                                    splice(@{$replace_roles{$key}}, $i, 1);
                                    last;
                                }
                            }
                        }
                    } else {
                        $replace_roles{$key} = [];
                    }
                }
            } else {
                push(@mod_list, $action, $attr, @tmpvals);
            }
        }
        foreach my $profile_attr (@profile_attrs) {
            if (!defined($profile_updated{lc($profile_attr)})) {
                my @old_profiles = ($entryStr =~ /^$profile_attr: (.+)$/gmi);
                foreach my $profile (@old_profiles) {
                    if (!grep(/^$profile$/i, @add_profiles)) {
                        push(@add_profiles, $profile);
                    }
                }
            }
        }
        foreach my $attr (@attrs) {
            if (!defined($replace_roles{$attr})) {
                $replace_roles{$attr} = $old_roles{$attr};
            }
        }
    }

    foreach my $profile (@add_profiles) {
        if ($profile =~ /^ *$/) {
            next;
        }
        my ($rc, @entries) = $self->{lism}->search($profile, 0, 0, 0, 0, '(objectClass=*)', 0, @attrs);
        if ($rc) {
            return $rc;
        }
        if (@entries) {
            foreach my $entryStr (@entries) {
                foreach my $attr (@attrs) {
                    my @tmpvals = ($entryStr =~ /^$attr: (.+)$/gmi);
                    if (@tmpvals) {
                        for (my $i = 0; $i < @tmpvals; $i++) {
                            if ($basedn && $tmpvals[$i] =~ /,ou=[^,]+,$basedn$/i) {
                                foreach my $dbase (@dbases) {
                                    if ($tmpvals[$i] =~ /$dbase,$basedn$/i) {
                                        $tmpvals[$i] =~ s/$basedn/$suffix/i;
                                        last;
                                    }
                                }
                            }
                        }
                        if (!defined($add_roles{$attr})) {
                            $add_roles{$attr} = \@tmpvals;
                        } else {
                            foreach my $tmpval (@tmpvals) {
                                my $regex_val = $tmpval;
                                $regex_val =~ s/([.*+?\[\]()|\^\$\\\{\}])/\\$1/g;
                                if (!grep(/^$regex_val$/i, @{$add_roles{$attr}})) {
                                    push(@{$add_roles{$attr}}, $tmpval);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    foreach my $profile (@del_profiles) {
        if ($profile =~ /^ *$/) {
            next;
        }
        my ($rc, @entries) = $self->{lism}->search($profile, 0, 0, 0, 0, '(objectClass=*)', 0, @attrs);
        if ($rc) {
            return $rc;
        }
        if (@entries) {
            foreach my $entryStr (@entries) {
                foreach my $attr (@attrs) {
                    my @tmpvals = ($entryStr =~ /^$attr: (.+)$/gmi);
                    if (@tmpvals) {
                        for (my $i = 0; $i < @tmpvals; $i++) {
                            if ($basedn && $tmpvals[$i] =~ /,ou=[^,]+,$basedn$/i) {
                                foreach my $dbase (@dbases) {
                                    if ($tmpvals[$i] =~ /$dbase,$basedn$/i) {
                                        $tmpvals[$i] =~ s/$basedn/$suffix/i;
                                        last;
                                    }
                                }
                            }
                        }
                        if (!defined($del_roles{$attr})) {
                            $del_roles{$attr} = \@tmpvals;
                        } else {
                            foreach my $tmpval (@tmpvals) {
                                my $regex_val = $tmpval;
                                $regex_val =~ s/([.*+?\[\]()|\^\$\\\{\}])/\\$1/g;
                                if (!grep(/^$regex_val$/i, @{$del_roles{$attr}})) {
                                    push(@{$del_roles{$attr}}, $tmpval);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if ($func eq 'add') {
        my $entryStr = ${$entryp}[0];
        foreach my $attr (@attrs) {
            ${$entryp}[0] =~ s/^$attr:  +\n//gmi;
            my @cmpvals = ($entryStr =~ /^$attr: (.+)$/gmi);
            foreach my $tmpval (@{$add_roles{$attr}}) {
                if ($tmpval =~ /^ *$/) {
                    next;
                }
                my $regex_val = $tmpval;
                $regex_val =~ s/([.*+?\[\]()|\^\$\\\{\}])/\\$1/g;
                if (!grep(/^$regex_val$/i, @cmpvals)) {
                    ${$entryp}[0] .= "$attr: $tmpval\n";
                }
            }
        }
    } elsif ($func eq 'modify') {
        foreach my $attr (@attrs) {
            foreach my $tmpval (@{$del_roles{$attr}}) {
                if ($tmpval =~ /^ *$/) {
                    next;
                }
                my $regex_val = $tmpval;
                $regex_val =~ s/([.*+?\[\]()|\^\$\\\{\}])/\\$1/g;
                for (my $i = 0; $i < @{$replace_roles{$attr}}; $i++) {
                    if (${$replace_roles{$attr}}[$i] =~ /^$regex_val$/i) {
                        splice(@{$replace_roles{$attr}}, $i, 1);
                        last;
                    }
                }
            }
            foreach my $tmpval (@{$add_roles{$attr}}) {
                if ($tmpval =~ /^ *$/) {
                    next;
                }
                my $regex_val = $tmpval;
                $regex_val =~ s/([.*+?\[\]()|\^\$\\\{\}])/\\$1/g;
                my $match = 0;
                for (my $i = 0; $i < @{$replace_roles{$attr}}; $i++) {
                    if (${$replace_roles{$attr}}[$i] =~ /^$regex_val$/i) {
                        $match = 1;
                        last;
                    }
                }
                if (!$match) {
                    push(@{$replace_roles{$attr}}, $tmpval);
                }
            }
            push(@mod_list, 'REPLACE', $attr, @{$replace_roles{$attr}});
        }
        @{$entryp} = @mod_list;
    }

    return 0;
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
