package LISM::Handler::Check;

use strict;
use base qw(LISM::Handler);
use POSIX qw(strftime);
use Config::IniFiles;
use Encode;
use LISM::Constant;
use Data::Dumper;

=head1 NAME

LISM::Handler::Check - Handler to set value

=head1 DESCRIPTION

This class implements the L<LISM::Hanlder> interface to set value.

=head1 METHODS

=pod

=head2 getOrder

Get order to do handler.

=cut

sub getOrder
{
    return 'sync';
}

=head2 post_search($entriesp)

Check search results.

=cut

sub post_search
{
    my $self = shift;
    my ($entriesp) = @_;
    my $conf = $self->{_config};

    my $match = 0;
    foreach my $rule (@{$conf->{check}}) {
        if (!defined($rule->{op}) || (','.$rule->{op}.',') =~ /,search,/) {
            $match = 1;
            last;
        }
    }
    if (!$match) {
        return LDAP_SUCCESS;
    }

    for (my $i = 0; $i < @{$entriesp}; $i++) {
        $self->_checkValues(${$entriesp}[$i], 'search');
    }

    return LDAP_SUCCESS;
}

=head2 pre_modify($dnp, $listp)

Check modify request.

=cut

sub pre_modify
{
    my $self = shift;
    my ($dnp, $listp, $oldentryp, $errorp) = @_;
    my $conf = $self->{_config};

    my $entryStr = "dn: ${$dnp}\n";
    my @list = @{$listp};
    while (@list > 0) {
        my $action = shift @list;
        my $attr = lc(shift @list);
        my @values;

        while (@list > 0 && $list[0] ne "ADD" && $list[0] ne "DELETE" && $list[0] ne "REPLACE") {
            push(@values, shift @list);
        }

        if ($action eq 'DELETE' && !@values) {
            @values = ('');
        } elsif ($action eq 'DELETE') {
            next;
        }

        foreach my $value (@values) {
            $entryStr .= "$attr: $value\n";
        }
    }

    my $rc = $self->_checkValues($entryStr, 'modify', 'pre', $oldentryp ? ${$oldentryp} : '', $errorp);

    return $rc;
}

=head2 pre_add($dnp, $entryStrp, $oldentryp)

Check add request.

=cut

sub pre_add
{
    my $self = shift;
    my ($dnp, $entryStrp, $oldentryp, $errorp) = @_;
    my $conf = $self->{_config};

    my $rc = $self->_checkValues("dn: ${$dnp}\n${$entryStrp}[0]", 'add', 'pre', $oldentryp, $errorp);

    return $rc;
}

=head2 post_modify($dnp, $listp)

Check modify request.

=cut

sub post_modify
{
    my $self = shift;
    my ($dnp, $listp, $oldentryp) = @_;
    my $conf = $self->{_config};
    my $oldentry = defined($oldentryp) ? ${$oldentryp} : '';

    my $entryStr = "dn: ${$dnp}\n";
    my @list = @{$listp};
    while (@list > 0) {
        my $action = shift @list;
        my $attr = lc(shift @list);
        my @values;

        while (@list > 0 && $list[0] ne "ADD" && $list[0] ne "DELETE" && $list[0] ne "REPLACE") {
            push(@values, shift @list);
        }

        if ($action eq 'DELETE') {
            if (@values && $values[0] !~ /^ *$/) {
                foreach my $value (@values) {
                    $entryStr .= "$attr: $value\n";
                }
            } else {
                foreach my $value ($oldentry =~ /^$attr: (.+)$/gmi) {
                    $entryStr .= "$attr: $value\n";
                }
            }
        } elsif ($action eq 'REPLACE') {
            foreach my $value ($oldentry =~ /^$attr: (.+)$/gmi) {
                my $tmpval = $value;
                $tmpval =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                if (!grep(/^$tmpval$/i, @values)) {
                    $entryStr .= "$attr: $value\n";
                }
            }
        }
    }

    return $self->_checkValues($entryStr, 'modify', 'post', $oldentry);
}

=head2 post_add($dnp, $entryStrp)

Check add request.

=cut

sub post_add
{
    my $self = shift;
    my ($dnp, $entryStrp) = @_;
    my $conf = $self->{_config};

    return $self->_checkValues("dn: ${$dnp}\n${$entryStrp}[0]", 'add', 'post');
}

=head2 post_delete($dnp)

Check delete request.

=cut

sub post_delete
{
    my $self = shift;
    my ($dnp, $null, $oldentryp) = @_;
    my $conf = $self->{_config};

    return $self->_checkValues($oldentryp ? ${$oldentryp} : "dn: ${$dnp}\n", 'delete', 'post', $oldentryp ? ${$oldentryp} : '');
}

sub _checkValues
{
    my $self = shift;
    my ($entryStr, $func, $type, $oldentry, $errorp) = @_;
    my $conf = $self->{_config};
    my $rc = LDAP_SUCCESS;
    my $newentry = $entryStr;
    if ($func ne 'add' && $oldentry) {
        foreach my $attr (($oldentry =~ /^([^:]+):/gm)) {
            if ($newentry !~ /^$attr:/mi) {
                foreach my $value (($oldentry =~ /^$attr: (.+)$/gmi)) {
                    $newentry .= "$attr: $value\n";
                }
            }
        }
    } elsif ($func eq 'search') {
        $newentry = $entryStr;
    }

    foreach my $rule (@{$conf->{check}}) {
        my ($dn) = ($entryStr =~ /^dn: (.*)\n/);
        if (defined($rule->{dn}) && $dn !~ /$rule->{dn}/i) {
            next;
        }
        if (defined($rule->{op}) && (','.$rule->{op}.',') !~ /,$func,/) {
            next;
        }
        if (defined($rule->{filter}) && !LISM::Storage->parseFilter($rule->{filterobj}, encode('utf8', $newentry))) {
            next;
        }
        if (defined($rule->{entry})) {
            if (defined($rule->{entry}[0]->{maxentries}) && ($func eq 'add' || $func eq 'delete')) {
                my $mrc;
                if ($type eq 'post') {
                    $mrc = !$self->_updateCurrentEntries($rule->{entry}[0]->{maxentries}[0], $dn, $func);
                    if (!defined($mrc)) {
                        return LDAP_USER_CANCELED;
                    }
                } elsif ($func eq 'add') {
                    my $error;
                    ($mrc, $error) = $self->_checkMaxEntries($rule->{entry}[0]->{maxentries}[0], $dn);
                    if (!defined($mrc)) {
                        return LDAP_OTHER;
                    } elsif (!$mrc) {
                        $self->_perror("Maximum number of entries exceeded($dn): $error");
                        return LDAP_ADMIN_LIMIT_EXCEEDED;
                    }
                }
            }
        }
        my %params;
        if ($type ne 'post' || $func eq 'search') {
            if (defined($rule->{param})) {
                foreach my $param (keys(%{$rule->{param}})) {
                   my $value = $self->_getParam($rule->{param}{$param}, $dn, $param);
                   if (defined($value)) {
                       $params{$param} = $value;
                   }
                }
            }
        }
        foreach my $attr (keys %{$rule->{attr}}) {
            my $cattr = $rule->{attr}{$attr};
            my @tmpvals = ($entryStr =~ /^$attr: (.+)$/gmi);
            my @values;
            foreach my $value (@tmpvals) {
                if (defined($cattr->{notrule})) {
                    my $notrule = $cattr->{notrule}[0];
                    if ($value =~ /$notrule/i) {
                        next;
                    }
                }
                push(@values, $value);
            }
            if (defined($cattr->{maxentries})) {
                my $opts = $cattr->{maxentries}[0];
                my $mrc;
                if ($type eq 'post') {
                    my @delvals;
                    my @tmpvals;
                    if ($func eq 'delete') {
                        @tmpvals = ($oldentry =~ /^$attr: ([^ ]+)$/gmi);
                    } else {
                        @tmpvals = ($entryStr =~ /^$attr: ([^ ]+)$/gmi);
                    }
                    if (defined($cattr->{notrule})) {
                        my $notrule = $cattr->{notrule}[0];
                        foreach my $value (@tmpvals) {
                            if ($value =~ /$notrule/i) {
                                next;
                            }
                            push(@delvals, $value);
                        }
                    } else {
                        @delvals = @tmpvals;
                    }
                    @delvals = $self->_unique(@delvals);
                    ($mrc) = !$self->_updateCurrentEntries($opts, $dn, $func, $attr, @delvals);
                    if (!defined($mrc)) {
                        return LDAP_USER_CANCELED;
                    }
                } elsif ($func eq 'add' || $func eq 'modify') {
                    my @addvals;
                    if ($func eq 'modify') {
                        foreach my $value (@values) {
                            if ($oldentry !~ /^$attr: $value$/mi) {
                                push(@addvals, $value);
                            }
                        }
                    } else {
                        @addvals = @values;
                    }
                    my $error;
                    ($mrc, $error) = $self->_checkMaxEntries($opts, $dn, $attr, @addvals);
                    if (!defined($mrc)) {
                        return LDAP_OTHER;
                    } elsif (!$mrc) {
                        $self->_perror("Maximum number of entries exceeded($dn): $error");
                        return LDAP_SIZELIMIT_EXCEEDED;
                    }
                }
            }
            if ($type eq 'post') {
                next;
            }
            if (defined($cattr->{required}) && $cattr->{required}[0] eq 'on' && ((($func eq 'add' || $func eq 'search') && (!@values || $values[0] =~ /^ *$/)) || ($func eq 'modify' && $entryStr =~ /^$attr: /mi && (!@values || $values[0] =~ /^ *$/)))) {
                $self->_perror("$attr in $dn is required value");
                ${$errorp} = "$attr is required value" if ref($errorp);
                $rc = LDAP_CONSTRAINT_VIOLATION;
            }
            if (defined($cattr->{valexists}) && @values && $values[0] !~ /^ *$/) {
                my $opts = $cattr->{lismopts};
                my $filter = $opts->{filter};
                if ($filter =~ /\(?dn=([^\)]+)/) {
                    my $regexp = $1;
                    my ($filterval) = ($dn =~ /($regexp)/i);
                    $filter = "(dn=$filterval)";
                }
                my ($base) = ($dn =~ /($opts->{base})$/i);

                my @vals = $self->_searchLism($opts, $filter, $base);
                if (defined($opts->{option}) && $opts->{option} =~ /addval=([^&]+)/) {
                    push(@vals, split(/,/, $1));
                }
                foreach my $value (@values) {
                    my $regex_val = $value;
                    $regex_val =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                    if (!grep(/^$regex_val$/, @vals)) {
                        $self->_perror("$attr=$value in $dn is invalid: value doesn't exist in entry");
                        ${$errorp} = "$attr=$value is invalid: value doesn't exist in entry" if ref($errorp);
                        $rc = LDAP_CONSTRAINT_VIOLATION;
                    }
                }
            }
            foreach my $value (@values) {
                if ($value =~ /^ *$/) {
                    next;
                }
                if (defined($cattr->{minlen}) && length($value) < $cattr->{minlen}[0]) {
                    $self->_perror("$attr=$value in $dn is too short");
                    ${$errorp} = "$attr=$value is too short" if ref($errorp);
                    $rc = LDAP_CONSTRAINT_VIOLATION;
                }
                if (defined($cattr->{maxlen}) && length($value) > $cattr->{maxlen}[0]) {
                    $self->_perror("$attr=$value in $dn is too long");
                    ${$errorp} = "$attr=$value is too long" if ref($errorp);
                    $rc = LDAP_CONSTRAINT_VIOLATION;
                }
                if (defined($cattr->{regexp})) {
                    my $regexp = $cattr->{regexp}[0];
                    $regexp = $self->_replaceParam($regexp, %params);
                    if ($value !~ /$regexp/i) {
                        $self->_perror("$attr=$value in $dn is invalid: regular expression is $regexp");
                        ${$errorp} = "$attr=$value is invalid: regular expression is $regexp" if ref($errorp);
                        $rc = LDAP_CONSTRAINT_VIOLATION;
                    }
                }
                if (defined($cattr->{function})) {
                    my $ecode = 0;
                    eval "\$ecode = $cattr->{function}[0](\$value)";
                    if (!$ecode) {
                        $self->_perror("$attr=$value in $dn is invalid: function is $cattr->{function}[0]($ecode)");
                        ${$errorp} = "$attr=$value is invalid" if ref($errorp);
                        $rc = LDAP_CONSTRAINT_VIOLATION;
                    }
                }
                if (defined($cattr->{entryunique})) {
                    my $tmpval = $value;
                    $tmpval =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                    foreach my $uattr (split(/, */, $cattr->{entryunique}[0])) {
                        my $match = 0;
                        if ($entryStr =~ /^$uattr: /mi) {
                            if ($entryStr =~ /^$uattr: $tmpval$/mi) {
                                $match = 1;
                            }
                        } elsif ($oldentry && $oldentry =~ /^$uattr: /mi) {
                            if ($oldentry =~ /^$uattr: $tmpval$/mi) {
                                $match = 1;
                            }
                        }
                        if ($match) {
                            $self->_perror("$attr=$value in $dn is invalid: value exist in $uattr");
                            ${$errorp} = "$attr=$value is invalid: value exist in $uattr" if ref($errorp);
                            $rc = LDAP_CONSTRAINT_VIOLATION;
                            last;
                        }
                    }
                }
                if (defined($cattr->{lismexist})) {
                    my $opts = $cattr->{lismopts};
                    my $filter;
                    my $base;
                    if ($opts->{attr} eq 'path') {
                        ($base) = ($dn =~ /($opts->{base})$/i);
                        $base = LISM::Handler::_path2dn($value, 'ou', 1).',ou=Organizations,'.$base;
                    } elsif ($opts->{attr} eq 'dn' && defined($opts->{filter})) {
                        $base = $value;
                    } else {
                        my $tmpval = $value;
                        $tmpval =~ s/(?<!\\)\\/\\\\/g;
                        $tmpval =~ s/([\(\)*])/\\$1/g;
                        $filter = "($opts->{attr}=$tmpval)";
                        ($base) = ($dn =~ /($opts->{base})$/i);
                    }
                    if (defined($opts->{filter})) {
                        $filter = $filter ? "(&$filter$opts->{filter})" : $opts->{filter};
                    }
                    my @vals = $self->_searchLism($opts, $filter, $base);
                    if (!@vals || !$vals[0]) {
                        $self->_perror("$attr=$value in $dn is invalid: value doesn't exist in data");
                        ${$errorp} = "$attr=$value is invalid: value doesn't exist in data" if ref($errorp);
                        $rc = LDAP_CONSTRAINT_VIOLATION;
                    }
                }
                if (defined($cattr->{lismunique})) {
                    my $opts = $cattr->{lismopts};
                    my $tmpval = $value;
                    $tmpval =~ s/(?<!\\)\\/\\\\/g;
                    $tmpval =~ s/([\(\)*])/\\$1/g;
                    my $filter = "($opts->{attr}=$tmpval)";
                    if (defined($opts->{attrs})) {
                        foreach my $luattr (@{$opts->{attrs}}) {
                            $filter = "(|$filter($luattr=$tmpval))";
                        }
                    }
                    if (defined($opts->{filter})) {
                        $filter = "(&$filter$opts->{filter})";
                    }
                    my ($id) = ($dn =~ /^[^=]+=([^,]+),/);
                    $filter =~ s/\%i/$id/g;
                    $filter =~ s/\%a/$tmpval/g;
                    my ($base) = ($dn =~ /($opts->{base})$/i);
                    my @vals = $self->_searchLism($opts, $filter, $base);
                    if (@vals && $vals[0]) {
                        $self->_perror("$attr=$value in $dn is invalid: value already exist in data");
                        ${$errorp} = "$attr=$value is invalid: value already exist in data" if ref($errorp);
                        $rc = LDAP_CONSTRAINT_VIOLATION;
                    }
                }
                if (defined($cattr->{pwdpolicy})) {
                    my ($prc, $error) = $self->_checkPwdPolicy($cattr->{pwdpolicy}[0], $dn, $oldentry, $value);
                    if (!defined($prc)) {
                        return LDAP_OTHER;
                    } elsif (!$prc) { 
                        $self->_perror("$attr=$value in $dn is invalid: $error");
                        ${$errorp} = "$attr=$value is invalid: $error" if ref($errorp);
                        $rc = LDAP_CONSTRAINT_VIOLATION;
                    }
                }
            }
        }
    }

    return $rc;
}

sub _replaceParam
{
    my $self = shift;
    my ($str, %params) = @_;

    my @keys = ($str =~ /\%{([^}]+)}/g);
    foreach my $key (@keys) {
        my $value = defined($params{$key}) ? $params{$key} : '';
        $str =~ s/\%{$key}/$value/g;
    }

    return $str;
}

sub _getParam
{
    my $self = shift;
    my ($opts, $dn, $param) = @_;

    my $expire = defined($opts->{expire}) ? $opts->{expire} : 300;
    my $base;
    if (defined($opts->{suffix})) {
        $base = $opts->{suffix};
    } else {
        ($base) = ($dn =~ /($opts->{base})/i);
    }
    if (!$base) {
        return undef;
    }

    if (!defined($self->{lism}->{check_param})) {
        $self->{lism}->{check_param} = {};
    }

    my %params;
    if (defined($self->{lism}->{check_param}{$base})) {
        %params = %{$self->{lism}->{check_param}{$base}};
        if (defined($params{$param}) && ${$params{$param}}{timestamp} + $expire < time()) {
            undef($params{$param});
        }
    }
    if (!%params || !defined($params{$param})) {
        my $filter = defined($opts->{filter}) ? $opts->{filter} : '(objectClass=*)';
        my ($rc, @entries) = $self->{lism}->search($base, 2, 0, 0, 0, $filter, 0);
        if ($rc) {
            $self->log(level => 'err', message => "searching parameter($base) failed($rc)");
            return undef;
        }

        $params{$param} = {timestamp => time()};
        if (@entries) {
            my @values;
            for (my $i = 0; $i < @entries; $i++) {
                foreach my $attr (split(/, */, $opts->{attr})) {
                    my @tmpvals = ($entries[$i] =~ /^$attr: (.*)$/gmi);
                    if (@tmpvals) {
                        foreach my $tmpval (@tmpvals) {
                            if ($tmpval !~ /^ *$/ && !grep(/^$tmpval$/i, @values)) {
                                push(@values, $tmpval);
                            }
                        }
                    }
                }
            }
            if (@values) {
                if (@values > 1) {
                    ${$params{$param}}{value} = '('.join('|', @values).')';
                } else {
                    ${$params{$param}}{value} = $values[0];
                }
            }
        }
        if (!defined(${$params{$param}}{value})) {
            ${$params{$param}}{value} = defined($opts->{default}) ? $opts->{default} : '';
        }
        $self->{lism}->{check_param}{$base} = \%params;
    }

    return ${$params{$param}}{value};
}

sub _checkPwdPolicy
{
    my $self = shift;
    my ($opts, $dn, $oldentry, $value) = @_;

    my ($base) = ($dn =~ /($opts->{base})/i);
    if (!$base) {
        return 1;
    }

    my %pwdpolicy;
    if (defined($self->{lism}->{bind}{pwdpolicy}{$base})) {
        %pwdpolicy = %{$self->{lism}->{bind}{pwdpolicy}{$base}};
    } else {
        my $filter = defined($opts->{filter}) ? $opts->{filter} : '(objectClass=*)';
        my ($rc, @entries) = $self->{lism}->search($base, 2, 0, 0, 0, $filter, 0);
        if ($rc) {
            $self->log(level => 'err', message => "searching password policy($base) failed($rc)");
            return undef;
        }

        if (@entries) {
            ($pwdpolicy{minlen}) = ($entries[0] =~ /^pwdMinLength: (.*)$/mi);
            ($pwdpolicy{maxlen}) = ($entries[0] =~ /^seciossPwdMaxLength: (.*)$/mi);
            ($pwdpolicy{inhistory}) = ($entries[0] =~ /^pwdInHistory: (.*)$/mi);
            my @allowedchars = ($entries[0] =~ /^seciossPwdAllowedChars: (.+)$/gmi);
            if (@allowedchars) {
                $pwdpolicy{allowedchars} = \@allowedchars;
            }
            my @deniedchars = ($entries[0] =~ /^seciossPwdDeniedChars: (.+)$/gmi);
            if (@deniedchars) {
                $pwdpolicy{deniedchars} = \@deniedchars;
            }
            if (!defined($self->{lism}->{bind}{pwdpolicy})) {
                $self->{lism}->{bind}{pwdpolicy} = {};
            }
            $self->{lism}->{bind}{pwdpolicy}{$base} = \%pwdpolicy;
        } elsif (defined($opts->{file})) {
            my $pwdconfig = Config::IniFiles->new(-file => $opts->{file});
            if ($pwdconfig) {
                $pwdpolicy{minlen} = LISM::Handler::_delquote($pwdconfig->val('password', 'pwminlen'));
                $pwdpolicy{maxlen} = LISM::Handler::_delquote($pwdconfig->val('password', 'pwmaxlen'));
                $pwdpolicy{inhistory} = LISM::Handler::_delquote($pwdconfig->val('password', 'pwinhistory'));
                my $tmpval = $pwdconfig->val('password', 'pwallow');
                my @allowedchars;
                if (defined($tmpval)) {
                    @allowedchars = ($tmpval);
                } else {
                    @allowedchars = $pwdconfig->val('password', 'pwallow[]');
                }
                if (@allowedchars) {
                    for (my $i = 0; $i < @allowedchars; $i++) {
                        $allowedchars[$i] = LISM::Handler::_delquote($allowedchars[$i]);
                    }
                    $pwdpolicy{allowedchars} = \@allowedchars;
                }
                $tmpval = $pwdconfig->val('password', 'pwdeny');
                my @deniedchars;
                if (defined($tmpval)) {
                    @deniedchars = ($tmpval);
                } else {
                    @deniedchars = $pwdconfig->val('password', 'pwdeny[]');
                }
                if (@deniedchars) {
                    for (my $i = 0; $i < @deniedchars; $i++) {
                        $deniedchars[$i] = LISM::Handler::_delquote($deniedchars[$i]);
                    }
                    $pwdpolicy{deniedchars} = \@deniedchars;
                }
                if (!defined($self->{lism}->{bind}{pwdpolicy})) {
                    $self->{lism}->{bind}{pwdpolicy} = {};
                }
                $self->{lism}->{bind}{pwdpolicy}{$base} = \%pwdpolicy;
            }
        }
    }

    if ($pwdpolicy{minlen} && $pwdpolicy{minlen} > length($value)) {
        return (0, "password length is too short");
    }
    if ($pwdpolicy{maxlen} && $pwdpolicy{maxlen} < length($value)) {
        return (0, "password length is too long");
    }
    if ($pwdpolicy{inhistory} && $oldentry && grep(/^$value$/, ($oldentry =~ /^seciossPwdHistory: (.+)$/))) {
        return (0, "password is in the history");
    }
    if (defined($pwdpolicy{allowedchars})) {
        foreach my $chars (@{$pwdpolicy{allowedchars}}) {
            if ($chars !~ /^ *$/ && $value !~ /$chars/) {
                return (0, "password characters are invalid");
            }
        }
    }
    if (defined($pwdpolicy{deniedchars})) {
        foreach my $chars (@{$pwdpolicy{deniedchars}}) {
            if ($chars !~ /^ *$/ && $value =~ /$chars/) {
                return (0, "password characters are invalid");
            }
        }
    }

    return 1;
}

sub _checkMaxEntries
{
    my $self = shift;
    my ($opts, $dn, $attr, @values) = @_;
    my $conf = $self->{_config};

    my ($base) = ($dn =~ /($opts->{dn})/i);
    if (!$base) {
        return 1;
    }

    my ($rc, @entries) = $self->{lism}->search($base, 0, 0, 0, 0, '(objectClass=*)', 0);
    if ($rc) {
        $self->log(level => 'err', message => "searching max number($base) failed($rc)");
        return undef;
    }

    if (@entries) {
        my $checkEntry = $entries[0];
        if ($attr) {
            undef($opts->{increment});
            $opts->{increment} = {};
            foreach my $value (@values) {
                if ($value =~ /^ *$/) {
                    next;
                }

                my $maxattr = $opts->{max};
                my $currentattr = $opts->{current};
                $maxattr =~ s/\%a/$value/;
                $currentattr =~ s/\%a/$value/;
                my ($max) = ($checkEntry =~ /^$maxattr: (.*)$/mi);
                my ($current) = ($checkEntry =~ /^$currentattr: (.*)$/mi);
                if (!defined($max)) {
                    return 1;
                }
                my $service = $value;
                if (!defined($opts->{increment}->{$service})) {
                    $opts->{increment}->{$service} = 0;
                }
                $opts->{increment}->{$service}++;
                if ($current + $opts->{increment}->{$service} > $max) {
                    return (0, "$maxattr=$max");
                }
            }
        } else {
            my ($max) = ($checkEntry =~ /^$opts->{max}: (.*)$/mi);
            my ($current) = ($checkEntry =~ /^$opts->{current}: (.*)$/mi);
            $current++;
            if (!defined($max)) {
                return 1;
            } elsif ($current > $max) {
                return (0, "$opts->{max}=$max");
            }
        }
    }

    return 1;
}

sub _updateCurrentEntries
{
    my $self = shift;
    my ($opts, $dn, $func, $attr, @delvals) = @_;
    my $conf = $self->{_config};

    my ($base) = ($dn =~ /($opts->{dn})/i);
    if (!$base) {
        return 1;
    }

    for (my $i = 0; $i < 5; $i++) {
        my ($rc, @entries) = $self->{lism}->search($base, 0, 0, 0, 0, '(objectClass=*)', 0);
        if ($rc) {
            $self->log(level => 'err', message => "searching max number($base) failed($rc)");
            return undef;
        }

        if (@entries) {
            my @list;
            my $checkEntry = $entries[0];
            if ($attr) {
                my %currentvals;
                my %oldvals;
                if (($func eq 'add' || $func eq 'modify') && defined($opts->{increment})) {
                    foreach my $service (keys %{$opts->{increment}}) {
                        my $currentattr = $opts->{current};
                        $currentattr =~ s/\%[ai]/$service/;
                        my ($current) = ($checkEntry =~ /^$currentattr: (.*)$/mi);
                        if (defined($current)) {
                            $oldvals{$service} = $current;
                        }
                        $currentvals{$service} = (defined($current) ? $current : 0) + ${$opts->{increment}}{$service};
                    }
                }
                if (($func eq 'modify' || $func eq 'delete') && @delvals && $delvals[0] !~ /^ *$/) {
                    foreach my $value (@delvals) {
                        my $service = $value;
                        if (defined($currentvals{$service})) {
                            $currentvals{$service}--;
                        } else {
                            my $currentattr = $opts->{current};
                            $currentattr =~ s/\%a/$value/;
                            my ($current) = ($checkEntry =~ /^$currentattr: (.*)$/mi);
                            if (defined($current)) {
                                $oldvals{$service} = $current;
                            }
                            $currentvals{$service} = (defined($current) ? $current : 0) - 1;
                        }
                    }
                }
                foreach my $service (keys %currentvals) {
                    my $currentattr = $opts->{current};
                    $currentattr =~ s/\%a/$service/;
                    if (defined($oldvals{$service})) {
                        push(@list, 'DELETE', $currentattr, $oldvals{$service});
                    }
                    push(@list, 'ADD', $currentattr, $currentvals{$service});
                }
            } else {
                my ($current) = ($checkEntry =~ /^$opts->{current}: (.*)$/mi);
                my $oldval = $current;
                $current = defined($current) ? $current : 0;
                if ($func eq 'add') {
                    $current++;
                } else {
                    $current--;
                }
                if (defined($oldval)) {
                    push(@list, 'DELETE', $opts->{current}, $oldval);
                }
                push(@list, 'ADD', $opts->{current}, $current);
            }

            if (@list) {
                $rc = $self->{lism}->modify($base, @list);
                if ($rc && $rc != LDAP_NO_SUCH_ATTRIBUTE && $rc != LDAP_TYPE_OR_VALUE_EXISTS) {
                    $self->log(level => 'err', message => "modifying current number($base) failed($rc)");
                    return undef;
                } if (!$rc) {
                    return 1;
                }
            } else {
                last;
            }
        }
    }

    return 1;
}

sub _perror
{
    my $self = shift;
    my ($message) = @_;
    my $conf = $self->{_config};
    my $fd;

    if (defined($conf->{file})) {
        if ($conf->{file}[0] eq 'stdout') {
            $fd = *STDOUT;
        } elsif (!open($fd, ">> $conf->{file}[0]")) {
            $self->log(level => 'err', message => "Can't open $conf->{file}[0]: $!");
            return LDAP_OTHER;
        }
    } elsif (defined($conf->{command})) {
        if (!open($fd, "|$conf->{command}[0]")) {
            $self->log(level => 'err', message => "Can't open $conf->{command}[0]: $!");
            return LDAP_OTHER;
        }
    }

    print $fd encode('utf8', strftime("%Y/%m/%d %H:%M:%S", localtime(time)).": $message\n");
    $self->log(level => 'err', message => $message);

    if (!defined($conf->{file}) || $conf->{file}[0] ne 'stdout') {
        close($fd);
    }
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
                $self->log(level => 'alert', message => "check do require $lib: $@");
                return 1;
            }
        }
    }

    if (!defined($conf->{file}) && !defined($conf->{command})) {
        $self->log(level => 'alert', message => "Set file or command");
        return 1;
    }

    if (defined($conf->{check})) {
        foreach my $rule (@{$conf->{check}}) {
            if (defined($rule->{filter})) {
                $rule->{filter} =~ s/&amp;/&/g;
                $rule->{filterobj} = Net::LDAP::Filter->new($rule->{filter});
            }
            if (defined($rule->{entry}) && defined($rule->{entry}[0]->{maxentries})) {
                my $maxentries = $rule->{entry}[0]->{maxentries}[0];
                if (!defined($maxentries->{dn}) || !defined($maxentries->{max}) || !defined($maxentries->{current})) {
                    $self->log(level => 'alert', message => "Set dn,max,current in maxentries");
                    return 1;
                }
            }

            foreach my $cattr (keys %{$rule->{attr}}) {
                if (defined($rule->{attr}{$cattr}->{lismexist}) || defined($rule->{attr}{$cattr}->{lismunique}) || defined($rule->{attr}{$cattr}->{valexists})) {
                    if (defined($rule->{attr}{$cattr}->{lismopts})) {
                        next;
                    }
                    my $name;
                    foreach my $key (keys %{$rule->{attr}{$cattr}}) {
                        if ($key =~ /^lismexist|lismunique|valexists$/) {
                            $name = $key;
                        }
                    }
                    my $lismopts = {};
                    my ($base, $attrsStr, $scope, $filter, $option) = split(/\?/, $rule->{attr}{$cattr}->{$name}[0]);
                    $lismopts->{base} = $base;
                    my ($attr, @attrs) = split(/,/, $attrsStr);
                    $lismopts->{attr} = $attr;
                    if (@attrs) {
                        $lismopts->{attrs} = \@attrs;
                        if (defined($rule->{attr}{$cattr}->{valexists})) {
                            $lismopts->{allvalues} = 1;
                        }
                    }
                    if ($scope) {
                        $lismopts->{scope} = $scope;
                    }
                    if ($filter) {
                        $lismopts->{filter} = $filter;
                    }
                    if ($option) {
                        $lismopts->{option} = $option;
                    }
                    $rule->{attr}{$cattr}->{lismopts} = $lismopts;
                } elsif (defined($rule->{attr}{$cattr}->{maxentries})) {
                    my $maxentries = $rule->{attr}{$cattr}->{maxentries}[0];
                    if (!defined($maxentries->{dn}) || !defined($maxentries->{max}) || !defined($maxentries->{current})) {
                        $self->log(level => 'alert', message => "Set dn,max,current,check in maxentries");
                        return 1;
                    }
                }
            }
        }
    }

    return $rc;
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
