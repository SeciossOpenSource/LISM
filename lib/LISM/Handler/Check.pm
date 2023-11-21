package LISM::Handler::Check;

use strict;
use base qw(LISM::Handler);
use POSIX qw(strftime ceil);
use Config::IniFiles;
use Encode;
use PHP::Serialization qw(unserialize);
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

        if (($action eq 'REPLACE' || $action eq 'DELETE') && !@values) {
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

        if (($action eq 'REPLACE' || $action eq 'DELETE') && !@values) {
            @values = ('');
        } elsif ($action eq 'DELETE') {
            next;
        }

        foreach my $value (@values) {
            $entryStr .= "$attr: $value\n";
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
        my $mfunc = $func;
        my ($dn) = ($entryStr =~ /^dn: (.*)\n/);
        if (defined($rule->{dn}) && $dn !~ /$rule->{dn}/i) {
            next;
        }
        if (defined($rule->{op}) && (','.$rule->{op}.',') !~ /,$func,/) {
            next;
        }
        if (defined($rule->{filter}) && !LISM::Storage->parseFilter($rule->{filterobj}, encode('utf8', $newentry))) {
            if ($type eq 'post' && $func eq 'modify' && defined($rule->{filter}) && LISM::Storage->parseFilter($rule->{filterobj}, encode('utf8', $oldentry))) {
                $mfunc = 'delete';
            } else {
                next;
            }
        }
        if ($mfunc eq 'modify' && defined($rule->{filter}) && !LISM::Storage->parseFilter($rule->{filterobj}, encode('utf8', $oldentry))) {
            $mfunc = 'add';
        }
        if (defined($rule->{entry})) {
            if (defined($rule->{entry}[0]->{maxentries}) && ($mfunc eq 'add' || $mfunc eq 'delete')) {
                my $mrc;
                if ($type eq 'post') {
                    $mrc = !$self->_updateCurrentEntries($rule->{entry}[0]->{maxentries}[0], $dn, $func, $mfunc);
                    if (!defined($mrc)) {
                        return LDAP_USER_CANCELED;
                    }
                } elsif ($mfunc eq 'add') {
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
                if (defined($cattr->{rule})) {
                    my $rule = $cattr->{rule}[0];
                    if ($value !~ /$rule/i) {
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
                    if ($mfunc eq 'delete') {
                        @tmpvals = ($oldentry =~ /^$attr: ([^ \n]+)$/gmi);
                    } else {
                        my @oldvals = ($oldentry =~ /^$attr: ([^ \n]+)$/gmi);
                        my @newvals = ($newentry =~ /^$attr: ([^ \n]+)$/gmi);
                        foreach my $value (@oldvals) {
                            my $tmpval = $value;
                            $tmpval =~ s/([.*+?\[\]()|\^\$\\\{\}])/\\$1/g;
                            if (!grep(/^$tmpval$/i, @newvals)) {
                                push(@tmpvals, $value);
                            }
                        }
                    }
                    if (defined($cattr->{notrule})) {
                        my $notrule = $cattr->{notrule}[0];
                        foreach my $value (@tmpvals) {
                            if ($value =~ /$notrule/i) {
                                next;
                            }
                            push(@delvals, $value);
                        }
                    } elsif (defined($cattr->{rule})) {
                        my $rule = $cattr->{rule}[0];
                        foreach my $value (@tmpvals) {
                            if ($value !~ /$rule/i) {
                                next;
                            }
                            push(@delvals, $value);
                        }
                    } else {
                        @delvals = @tmpvals;
                    }
                    @delvals = $self->_unique(@delvals);
                    ($mrc) = !$self->_updateCurrentEntries($opts, $dn, $func, $mfunc, $attr, @delvals);
                    if (!defined($mrc)) {
                        return LDAP_USER_CANCELED;
                    }
                } elsif ($mfunc eq 'add' || $mfunc eq 'modify') {
                    my @addvals;
                    if ($mfunc eq 'modify') {
                        foreach my $value (@values) {
                            if ($oldentry !~ /^$attr: $value$/mi) {
                                push(@addvals, $value);
                            }
                        }
                    } else {
                        @addvals = @values;
                    }

                    my @delvals;
                    if ($mfunc eq 'modify') {
                        my @tmpvals = ($oldentry =~ /^$attr: ([^ \n]+)$/gmi);
                        my $notrule;
                        my $rule;
                        if (defined($cattr->{notrule})) {
                            $notrule = $cattr->{notrule}[0];
                        }
                        if (defined($cattr->{rule})) {
                            $rule = $cattr->{rule}[0];
                        }
                        foreach my $value (@tmpvals) {
                            if ($notrule && $value =~ /$notrule/i) {
                                next;
                            }
                            if ($rule && $value !~ /$rule/i) {
                                next;
                            }
                            if ($entryStr !~ /^$attr: $value$/mi) {
                                push(@delvals, $value);
                            }
                        }
                    }
                    @delvals = $self->_unique(@delvals);

                    my $error;
                    ($mrc, $error) = $self->_checkMaxEntries($opts, $dn, $attr, \@addvals, \@delvals);
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
                $filter = $self->_replaceParam($filter, %params);
                if ($filter =~ /\(?dn=([^\)]+)/) {
                    my $regexp = $1;
                    my ($filterval) = ($dn =~ /($regexp)/i);
                    $filter = "(dn=$filterval)";
                }
                my ($base) = ($dn =~ /($opts->{base})$/i);

                my @vals = $self->_searchLism($opts, undef, $filter, $base);
                if (defined($opts->{option}) && $opts->{option} =~ /addval=([^&]+)/) {
                    push(@vals, split(/,/, $1));
                }
                my $rtrim = defined($opts->{option}) && $opts->{option} =~ /rtrim=([^&]+)/ ? $1 : undef;
                foreach my $value (@values) {
                    my $regex_val = $value;
                    $regex_val =~ s/([.*+?\[\]()|\^\$\\\{\}])/\\$1/g;
                    if (!grep(/^$regex_val$/, @vals)) {
                        my $invalid = 1;
                        if ($rtrim) {
                            $regex_val =~ s/$rtrim$//;
                            if (grep(/^$regex_val$/, @vals)) {
                                $invalid = 0;
                            }
                        }
                        if ($invalid) {
                            $self->_perror("$attr=$value in $dn is invalid: value doesn't exist in entry");
                            ${$errorp} = "$attr=$value is invalid: value doesn't exist in entry" if ref($errorp);
                            $rc = LDAP_CONSTRAINT_VIOLATION;
                        }
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
                if (defined($cattr->{notregexp})) {
                    my $regexp = $cattr->{notregexp}[0];
                    $regexp = $self->_replaceParam($regexp, %params);
                    if ($value =~ /$regexp/i) {
                        $self->_perror("$attr=$value in $dn is invalid: regular expression is not match $regexp");
                        ${$errorp} = "$attr=$value is invalid: regular expression is not match $regexp" if ref($errorp);
                        $rc = LDAP_CONSTRAINT_VIOLATION;
                    }
                }
                if (defined($cattr->{ceregexp})) {
                    my $regexp = $cattr->{ceregexp}[0];
                    $regexp = $self->_replaceParam($regexp, %params);
                    if ($value !~ /$regexp/) {
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
                    $tmpval =~ s/([.*+?\[\]()|\^\$\\\{\}])/\\$1/g;
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
                    my @vals = $self->_searchLism($opts, undef, $filter, $base);
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
                    my @vals = $self->_searchLism($opts, undef, $filter, $base);
                    if (@vals && $vals[0]) {
                        $self->_perror("$attr=$value in $dn is invalid: value already exist in data");
                        ${$errorp} = "$attr=$value is invalid: value already exist in data" if ref($errorp);
                        $rc = LDAP_CONSTRAINT_VIOLATION;
                    }
                }
                if (defined($cattr->{pwdpolicy}) && $value !~ /^{(CRYPT|MD5|SHA|SSHA|SSHA512|PBKDF2_SHA256)}/) {
                    my $notmatch;
                    if (defined($cattr->{pwdpolicy}[0]->{notmatch})) {
                        $notmatch = $cattr->{pwdpolicy}[0]->{notmatch};
                    }
                    if (!$notmatch || $entryStr !~ /$notmatch/mi) {
                        my ($prc, $error) = $self->_checkPwdPolicy($cattr->{pwdpolicy}[0], $dn, $newentry, $oldentry, $value);
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
    }

    return $rc;
}

sub _replaceParam
{
    my $self = shift;
    my ($str, %params) = @_;

    my @keys = ($str =~ /\%\{([^}]+)\}/g);
    foreach my $key (@keys) {
        my $value = defined($params{$key}) ? $params{$key} : '';
        $str =~ s/\%\{$key\}/$value/g;
    }

    return $str;
}

sub _getParam
{
    my $self = shift;
    my ($opts, $dn, $param) = @_;

    if (defined($opts->{regexp})) {
        my $regexp = $opts->{regexp};
        my ($value) = ($dn =~ /$regexp/i);
        return $value;
    }

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
    my ($opts, $dn, $entryStr, $oldentry, $value) = @_;

    my ($base) = ($dn =~ /($opts->{base})/i);
    if (!$base) {
        return 1;
    }

    my %pwdpolicy;
    if (defined($opts->{profile})) {
        my $profile_attr = $opts->{profile};
        my @profiles = ($entryStr =~ /^$profile_attr: ([^ ]+)$/gmi);
        my $max_priority = 0;
        foreach my $profile_dn (@profiles) {
            my ($rc, $profile_entry) = $self->{lism}->search($profile_dn, 0, 0, 0, 0, '(objectClass=*)', 0);
            if ($rc) {
                $self->log(level => 'err', message => "searching profile($profile_dn) failed($rc)");
                next;
            } elsif ($profile_entry) {
                if ($profile_entry !~ /^seciossPwdPolicyEnabled: TRUE$/mi) {
                    next;
                }
                my ($priority) = ($profile_entry =~ /^seciossRoleSpecification: (.+)$/mi);
                if ($priority > $max_priority) {
                    $max_priority = $priority;
                } else {
                    next;
                }

                ($pwdpolicy{minlen}) = ($profile_entry =~ /^(pwdMinLength|passwordMinLength): (.*)$/mi);
                ($pwdpolicy{maxlen}) = ($profile_entry =~ /^seciossPwdMaxLength: (.*)$/mi);
                ($pwdpolicy{inhistory}) = ($profile_entry =~ /^(pwdInHistory|passwordInHistory): (.*)$/mi);
                my @allowedchars = ($profile_entry =~ /^seciossPwdAllowedChars: (.+)$/gmi);
                if (@allowedchars) {
                    $pwdpolicy{allowedchars} = \@allowedchars;
                }
                my @deniedchars = ($profile_entry =~ /^seciossPwdDeniedChars: (.+)$/gmi);
                if (@deniedchars) {
                    $pwdpolicy{deniedchars} = \@deniedchars;
                }
                my ($tmpval) = ($profile_entry =~ /^seciossPwdSerializedData: (.+)$/mi);
                if ($tmpval) {
                    my $options = unserialize($tmpval);
                    if (defined($options->{pwprohibitattr})) {
                        $pwdpolicy{prohibitattr} = $options->{'pwprohibitattr'};
                    }
                    if (defined($options->{pwallowlimit})) {
                        $pwdpolicy{allowlimit} = $options->{'pwallowlimit'};
                    }
                }
                if (!defined($self->{lism}->{bind}{pwdpolicy})) {
                    $self->{lism}->{bind}{pwdpolicy} = {};
                }
                $self->{lism}->{bind}{pwdpolicy}{$base} = \%pwdpolicy;
            }
        }
    }
    if (%pwdpolicy) {
        # profile password policy
    } elsif (defined($self->{lism}->{bind}{pwdpolicy}{$base})) {
        %pwdpolicy = %{$self->{lism}->{bind}{pwdpolicy}{$base}};
    } else {
        my $filter = defined($opts->{filter}) ? $opts->{filter} : '(objectClass=*)';
        my ($rc, @entries) = $self->{lism}->search($base, 2, 0, 0, 0, $filter, 0);
        if ($rc) {
            $self->log(level => 'err', message => "searching password policy($base) failed($rc)");
            return undef;
        }

        if (@entries) {
            ($pwdpolicy{minlen}) = ($entries[0] =~ /^(pwdMinLength|passwordMinLength): (.*)$/mi);
            ($pwdpolicy{maxlen}) = ($entries[0] =~ /^seciossPwdMaxLength: (.*)$/mi);
            ($pwdpolicy{inhistory}) = ($entries[0] =~ /^(pwdInHistory|passwordInHistory): (.*)$/mi);
            my @allowedchars = ($entries[0] =~ /^seciossPwdAllowedChars: (.+)$/gmi);
            if (@allowedchars) {
                $pwdpolicy{allowedchars} = \@allowedchars;
            }
            my @deniedchars = ($entries[0] =~ /^seciossPwdDeniedChars: (.+)$/gmi);
            if (@deniedchars) {
                $pwdpolicy{deniedchars} = \@deniedchars;
            }
            my ($tmpval) = ($entries[0] =~ /^seciossPwdSerializedData: (.+)$/mi);
            if ($tmpval) {
                my $options = unserialize($tmpval);
                if (defined($options->{pwprohibitattr})) {
                    $pwdpolicy{prohibitattr} = $options->{'pwprohibitattr'};
                }
                if (defined($options->{pwallowlimit})) {
                    $pwdpolicy{allowlimit} = $options->{'pwallowlimit'};
                }
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
                $pwdpolicy{allowlimit} = LISM::Handler::_delquote($pwdconfig->val('password', 'pwallowlimit'));
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
                $tmpval = $pwdconfig->val('password', 'pwprohibitattr');
                if (defined($tmpval)) {
                    $tmpval = LISM::Handler::_delquote($tmpval);
                    if ($tmpval) {
                        my @tmpvals = split(/ *, */, $tmpval);
                        $pwdpolicy{prohibitattr} = \@tmpvals;
                    }
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
    if ($pwdpolicy{inhistory} && $oldentry && $self->_pwdInHistory($pwdpolicy{inhistory}, $value, $oldentry)) {
        return (0, "password is in the history");
    }
    if (defined($pwdpolicy{allowedchars}) && $pwdpolicy{allowedchars} && $pwdpolicy{allowedchars}[0] !~ /^ *$/) {
        my $pwallowlimit = scalar @{$pwdpolicy{allowedchars}};
        if (defined($pwdpolicy{allowlimit}) && $pwdpolicy{allowlimit}) {
            $pwallowlimit = int($pwdpolicy{allowlimit});
        }
        my $match = 0;
        foreach my $chars (@{$pwdpolicy{allowedchars}}) {
            if ($chars !~ /^ *$/ && $value =~ /$chars/) {
                $match++;
            }
        }
        if ($match < $pwallowlimit) {
            return (0, "password characters are invalid");
        }
    }
    if (defined($pwdpolicy{deniedchars})) {
        foreach my $chars (@{$pwdpolicy{deniedchars}}) {
            if ($chars !~ /^ *$/ && $value =~ /$chars/) {
                return (0, "password characters are invalid");
            }
        }
    }
    if (defined($pwdpolicy{prohibitattr})) {
        foreach my $attr (@{$pwdpolicy{prohibitattr}}) {
            if ($self->_pwdInAttr($value, $attr, $oldentry)) {
                return (0, "password characters containing $attr");
            }
        }
    }

    return 1;
}

sub _pwdInHistory
{
    my $self = shift;
    my ($max_history, $password, $entryStr) = @_;

    my @pwdhistory = $entryStr =~ /^seciossPwdHistory: (?:.+)#([^#\n]+)$/gmi;
    if (scalar(@pwdhistory) == 0) {
        return 0;
    }
    for (my $i = 0; $i < scalar(@pwdhistory) && $i < $max_history; $i++) {
        my $pwhash = '';
        my $oldpasswd = $pwdhistory[$i];
        if ($oldpasswd =~ /^\{([^}]+)\}(.+)$/) {
            $pwhash = $1;
            $oldpasswd = $2;
        }
        if (LISM::Storage->cmpPasswd($password, $oldpasswd, $pwhash)) {
            return 1;
        }
    }

    return 0;
}

sub _pwdInAttr
{
    my $self = shift;
    my ($password, $attr, $entryStr) = @_;

    my @attrvals = ($entryStr =~ /^$attr: (.+)$/gmi);
    if (!@attrvals || !defined($attrvals[0]) || $attrvals[0] =~ /^ *$/) {
        return 0;
    }
    my $value = $attrvals[0];
    if ($attr eq 'uid' || $attr eq 'mail' || $attr eq 'seciossnotificationmail') {
        if ($value =~ /^([^@]+)@/) {
            $value  = $1;
        }
    } elsif ($attr eq 'seciosstelephonenumber' || $attr eq 'seciossfax' || $attr eq 'seciossmobile' || $attr eq 'seciosshomephone' || $attr eq 'pager') {
        $value =~ s/[\s\-\+\*#]//g;
    } elsif ($attr eq 'cn') {
        if ($self->_pwdInAttr($password, 'sn', $entryStr)) {
            return 1;
        }
        if ($self->_pwdInAttr($password, 'givenname', $entryStr)) {
            return 1;
        }
        return 0;
    }

    my $pattern = quotemeta $value;
    if ($password =~ /$pattern/i) {
        return 1;
    }
    if ($attr ne 'uid' && length($value) > 4) {
        for (my $i = 0; $i <= (length($value) - 4); $i++) {
            $pattern = quotemeta substr($value, $i, 4);
            if ($password =~ /$pattern/i) {
                return 1;
            }
        }
    }
    return 0;
}

sub _checkMaxEntries
{
    my $self = shift;
    my ($opts, $dn, $attr, $addvalsp, $delvalsp) = @_;
    my $conf = $self->{_config};
    my @values = $addvalsp ? @{$addvalsp} : ();
    my @delvals = $delvalsp ? @{$delvalsp} : ();

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
            my $checked = 0;
            my $is_license = 0;
            my $spval = defined($opts->{sp}) ? $opts->{sp} : '';
            if (defined($opts->{license})) {
                my @services;
                if (defined($opts->{service})) {
                    my $serviceattr = $opts->{service};
                    @services = ($checkEntry =~ /^$serviceattr: (.+)$/gmi);
                }
                my $licenseattr = $opts->{license};
                my ($plan) = ($checkEntry =~ /^$licenseattr: (.+)$/mi);
                if ($plan && defined($opts->{plan}) && defined($opts->{plan}{$plan})) {
                    $is_license = 1;
                    my $named = defined($opts->{plan}{$plan}->{named}) ? $opts->{plan}{$plan}->{named} : 0;
                    my $sp = defined($opts->{plan}{$plan}->{sp}) ? $opts->{plan}{$plan}->{sp} : 0;
                    my $maxattr = $opts->{max};
                    $maxattr =~ s/;.+//;
                    my $namedattr = $opts->{current};
                    $namedattr =~ s/\%a/(.*)/;
                    my $spattr = $opts->{current};
                    if ($spval) {
                        $spattr =~ s/\%a/$spval/;
                    }
                    my ($max) = ($checkEntry =~ /^$maxattr: (.*)$/mi);
                    my $namednum = 0;
                    my $spnum = 0;
                    foreach my $line (split(/\n/, $checkEntry)) {
                        if ($spval && $line =~ /^$spattr: (.+)$/mi) {
                            $spnum += $1;
                        } elsif ($line =~ /^$namedattr: (.+)$/mi) {
                            my $service = $1;
                            if (!@services || grep(/^$service$/i, @services)) {
                                $namednum += $2;
                            }
                        }
                    }
                    foreach my $value (@values) {
                        if ($value =~ /^ *$/) {
                            next;
                        }
                        if ($spval && $value =~ /$spval/) {
                            $spnum++;
                        } elsif (!@services || grep(/^$value$/i, @services)) {
                            $namednum++;
                        }
                    }
                    foreach my $value (@delvals) {
                        if ($value =~ /^ *$/) {
                            next;
                        }
                        if ($spval && $value =~ /$spval/) {
                            $spnum--;
                        } elsif (!@services || grep(/^$value$/i, @services)) {
                            $namednum--;
                        }
                    }
                    if ($max && ($named ? ceil($namednum / $named) : 0) + ($sp ? ceil($spnum / $sp) : 0) > $max) {
                        return (0, "$maxattr=$max");
                    }
                    $checked = 1;
                }
            }

            undef($opts->{increment});
            $opts->{increment} = {};
            my $rtrim = $is_license && defined($opts->{rtrim}) ? $opts->{rtrim} : undef;
            foreach my $value (@values) {
                if ($value =~ /^ *$/) {
                    next;
                }
                if ((!$spval || $value !~ /$spval/) && $rtrim) {
                    $value =~ s/$rtrim$//;
                }

                my $maxattr = $opts->{max};
                my $currentattr = $opts->{current};
                $maxattr =~ s/\%a/$value/;
                $currentattr =~ s/\%a/$value/;
                my ($max) = ($checkEntry =~ /^$maxattr: (.*)$/mi);
                my ($current) = ($checkEntry =~ /^$currentattr: (.*)$/mi);
                my $service = $value;
                if (!defined($opts->{increment}->{$service})) {
                    $opts->{increment}->{$service} = 0;
                }
                $opts->{increment}->{$service}++;
                if (!$checked && $max && $current + $opts->{increment}->{$service} > $max) {
                    return (0, "$maxattr=$max");
                }
            }
        } elsif (defined($opts->{current})) {
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
    my ($opts, $dn, $orgfunc, $func, $attr, @delvals) = @_;
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
                    my $is_license = 0;
                    my $licenseattr = $opts->{license};
                    my ($plan) = ($checkEntry =~ /^$licenseattr: (.+)$/mi);
                    if ($plan && defined($opts->{plan}) && defined($opts->{plan}{$plan})) {
                        $is_license = 1;
                    }
                    my $spval = defined($opts->{sp}) ? $opts->{sp} : '';
                    my $rtrim = $is_license && defined($opts->{rtrim}) ? $opts->{rtrim} : undef;
                    foreach my $value (@delvals) {
                        if ((!$spval || $value !~ /$spval/) && $rtrim) {
                            $value =~ s/$rtrim$//;
                        }
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
                if (defined($opts->{current})) {
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
                if (defined($opts->{total}) && ($orgfunc eq 'add' || $orgfunc eq 'delete')) {
                    my ($total) = ($checkEntry =~ /^$opts->{total}: (.*)$/mi);
                    my $oldval = $total;
                    $total = defined($total) ? $total : 0;
                    if ($orgfunc eq 'add') {
                        $total++;
                    } else {
                        $total--;
                    }
                    if (defined($oldval)) {
                        push(@list, 'DELETE', $opts->{total}, $oldval);
                    }
                    push(@list, 'ADD', $opts->{total}, $total);
                }
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
                if (!defined($maxentries->{dn}) || (!defined($maxentries->{total}) && (!defined($maxentries->{max}) || !defined($maxentries->{current})))) {
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
                } elsif (defined($rule->{attr}{$cattr}->{pwdpolicy})) {
                    if (defined($rule->{attr}{$cattr}->{pwdpolicy}[0]->{filter})) {
                        $rule->{attr}{$cattr}->{pwdpolicy}[0]->{filter} =~ s/&amp;/&/g;
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

(c) 2006 Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
