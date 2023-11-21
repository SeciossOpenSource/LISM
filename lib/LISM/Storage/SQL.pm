package LISM::Storage::SQL;

use strict;
use base qw(LISM::Storage);
use Net::LDAP::Filter;
use LISM::Constant;
use DBI;
use MIME::Base64;
use Encode;
use POSIX qw(SIGALRM sigaction);
use Data::Dumper;

our $rawattrs = '^(jpegphoto|photo|.*;binary)$';

=head1 NAME

LISM::Storage::SQL - SQL storage for LISM

=head1 DESCRIPTION

This class implements the L<LISM::Storage> interface for SQL DB.

=head1 METHODS

=head2 init

Connect RDB server.

=cut

sub init
{
    my $self = shift;

    return $self->SUPER::init();
}

=pod

=head2 commit

Commit the transaction to the RDB.

=cut

sub commit
{
    my $self = shift;
    my ($force_commit) = @_;
    my $conf = $self->{_config};
    my $rc = 0;

    if (!defined($self->{db})) {
        return $rc;
    }

    if (defined($conf->{commit}) && $conf->{commit}[0] =~ /^on$/i && !$force_commit) {
        return $rc;
    }

    if (!$self->{db}->commit) {
        $self->log(level => 'crit', message => "Can't commit: ".$self->{db}->errstr);
        $rc = -1;
    }

    $self->_freeConnect();

    return $rc;
}

=pod

=head2 rollback

Rollback the transaction to the RDB.

=cut

sub rollback
{
    my $self = shift;
    my $rc = 0;

    if (!defined($self->{db})) {
        return $rc;
    }

    if (!$self->{db}->rollback) {
        $self->log(level => 'crit', message => "Can't rollback: ".$self->{db}->errstr);
        $rc = -1;
    }

    $self->_freeConnect();

    return $rc;
}

=pod

=head2 hashPasswd($passwd, $salt)

add hash schema at the head of hashed password.

=cut

sub hashPasswd
{
    my $self = shift;
    my ($passwd, $salt) =@_;
    my $conf = $self->{_config};

    my ($htype, $otype) = split(/:/, $conf->{hash});

    my $hashpw = $self->SUPER::hashPasswd($passwd, $salt);

    if ($htype =~ /^MYSQL$/i) {
        # get MySQL password
        if ($self->_getConnect()) {
            return $passwd;
        }

        my $sql = "select password(\'$passwd\');";
        my ($r, $sth) = $self->_sendQuery($sql);
        if ($r) {
            $self->log(level => 'err', message => "MySQL PASSWORD(\'$passwd\') failed: ".$sth);
            return $passwd;
        }
        my @data = $sth->fetchrow_array;
        $hashpw = $data[0];
        $sth->finish;
    }

    return $hashpw;
}

sub _getConnect
{
    my $self = shift;

    return $self->_connect(\$self->{db});
}

sub _connect
{
    my $self = shift;
    my ($db) = @_;
    my $conf = $self->{_config};

    if (defined(${$db}) && (!defined($conf->{connection}[0]->{type}) || $conf->{connection}[0]->{type}[0] ne 'every')) {
        my $sth = ${$db}->prepare("select 'check' from $conf->{connection}[0]->{table}");
        if (!$sth || !$sth->execute) {
            $self->log(level => 'err', message => "Connection check($conf->{dsn}[0]) failed: ".${$db}->errstr);
            ${$db}->disconnect();
            undef(${$db});
        } else {
            return 0;
        }
        if ($sth) {
            $sth->finish;
        }
    }

    foreach my $dsn (@{$conf->{dsn}}) {
        ${$db} = DBI->connect($dsn, $conf->{admin}[0], $conf->{passwd}[0]);
        if (${$db}) {
            last;
        } else {
            $self->log(level => 'alert', message => "Can't connect $dsn: ".$DBI::errstr);
        }
    }
    if (!${$db}) {
        return -1;
    }

    if (defined($conf->{initquery}) && !${$db}->do($conf->{initquery}[0])) {
        $self->log(level => 'crit', message => "$conf->{initquery}[0] failed: ".${$db}->errstr);
        return -1;
    }

    return 0;
}

sub _freeConnect
{
    my $self = shift;
    my $conf = $self->{_config};

    if ($self->{db}->err || (defined($conf->{connection}[0]->{type}) && $conf->{connection}[0]->{type}[0] eq 'every')) {
        $self->{db}->disconnect();

        undef($self->{db});
    }
}

sub _checkConfig
{
    my $self = shift;
    my $conf = $self->{_config};
    my $rc = 0;

    $rc = $self->SUPER::_checkConfig();
    if ($rc) {
        return $rc;
    }

    if (defined($conf->{decrypt}) && defined($conf->{passwd})) {
        my $decrypt = $conf->{decrypt}[0];
        my $value = $conf->{passwd}[0];
        $decrypt =~ s/\%s/$value/;
        $value = $self->_doFunction($decrypt);
        if (!defined($value)) {
            $self->log(level => 'err', message => "Decrypt of passwd failed");
            return 1;
        }
        $conf->{passwd}[0] = $value;
    }

    foreach my $oname (keys %{$conf->{object}}) {
        my $oconf = $conf->{object}{$oname};

        # check container fromtbls
        if (defined($oconf->{container}) && defined($oconf->{container}[0]->{oname})) {
            if (defined($oconf->{container}[0]->{fromtbls})) {
                my $poconf = $self->{object}{$oconf->{container}[0]->{oname}[0]}->{conf};
                if (",$oconf->{container}[0]->{fromtbls}[0]," =~
                    /,$poconf->{table}[0], */) {
                    $self->log(level => 'alert', message => "fromtbls($oconf->{container}[0]->{fromtbls}[0]) mustn't include container object table");
                    return 1;
                }
            }
        }

        foreach my $attr (keys %{$oconf->{attr}}) {
            # check attribute fromtbls
            if (defined($oconf->{attr}{$attr}->{oname})) {
                if (defined($oconf->{attr}{$attr}->{fromtbls})) {
                    my $aoconf = $self->{object}{$oconf->{attr}{$attr}->{oname}[0]}->{conf};
                    if (",$oconf->{attr}{$attr}->{fromtbls}[0]," =~
                        /,$aoconf->{table}[0], */) {
                        $self->log(level => 'alert', message => "fromtbls($oconf->{attr}{$attr}->{fromtbls}[0]) mustn't include attribute object table");
                        return 1;
                    }
                }
            }
        }

        if (!defined($conf->{connection}[0]->{table})) {
            $conf->{connection}[0]->{table} = $oconf->{table}[0];
        }
    }

    return 0;
}

=pod

=head2 _objSearch($obj, $pkeys, $suffix, $sizeLim, $filter)

Search the appropriate records in the object's table.

=cut

sub _objSearch
{
    my $self = shift;
    my ($obj, $pkeys, $suffix, $sizeLim, $filter, $attrOnly, @attrs) = @_;
    my $conf = $self->{_config};
    my $oconf = $obj->{conf};
    my $pkey = $self->_getPid($pkeys);
    my @match_entries = ();
    my @match_keys = ();
    my $rc = LDAP_SUCCESS;

    # do plugin
    if (defined($oconf->{plugin})) {
        my $error;
        my $keys;
        my @entries;

        ($rc, $keys, @entries) = $self->_doPlugin('search', $obj, $pkeys, $suffix, $sizeLim, $filter);
        if ($rc) {
            return ($rc, \@match_keys, @match_entries);
        }

        push(@match_keys, @{$keys});
        push(@match_entries, @entries);

    }

    if (!defined($oconf->{id})) {
        return ($rc, \@match_keys, @match_entries);
    }

    DO: {
        # get data of the entries
        my $table = $oconf->{table}[0];
        $table =~ s/^[^.]+\.//;
        my $sql = "";
        if (defined($oconf->{nodistinct}) && $oconf->{nodistinct}[0] eq "on") {
            $sql = "select $table.$oconf->{id}[0]->{column}[0]";
        } else {
            $sql = "select distinct $table.$oconf->{id}[0]->{column}[0]";
        }
        foreach my $attr ('objectclass', keys %{$oconf->{attr}}) {
            if (!defined($oconf->{attr}{$attr}) || !defined($oconf->{attr}{$attr}->{column})) {
                next;
            }
            $sql = "$sql, $table.$oconf->{attr}{$attr}->{column}[0]";
        }

        # exchange the LDAP filter to SQL
        my $from;
        my $where;
        if (!$self->_filter2sql($oconf, $filter, \$from, \$where)) {
            $rc = LDAP_FILTER_ERROR;
            @match_entries = ();
            last DO;
        }

        # entries below suffix
        if (defined($pkeys) && defined($oconf->{container}) &&
            defined($oconf->{container}[0]->{oname})) {
            my $poconf = $self->{object}{$oconf->{container}[0]->{oname}[0]}->{conf};

            if ($oconf->{table}[0] ne $poconf->{table}[0]) {
                my $idquote = !defined($poconf->{id}[0]->{type}) || $poconf->{id}[0]->{type}[0] !~ /^(int|smallint|float|number|text|boolean)$/i ? "'" : '';
                my $ptable = $poconf->{table}[0];
                $ptable =~ s/^[^.]+\.//;
                $from = "$from, $poconf->{table}[0]";
                $where = "$where and $ptable.$poconf->{id}[0]->{column}[0] ".(defined($pkey) ? "= $idquote$pkey$idquote" : "is NULL");
            }

            if (defined($oconf->{container}[0]->{fromtbls})) {
                $from = "$from, $oconf->{container}[0]->{fromtbls}[0]";
            }

            if (defined($oconf->{container}[0]->{joinwhere})) {
                my $pwhere = $oconf->{container}[0]->{joinwhere}[0];
                if (!defined($pkey)) {
                    $pwhere =~ s/= '?%c'?/is NULL/;
                }
                $pwhere = $self->_containerParse($pwhere, @{$pkeys});
                $where = "$where and $pwhere";
            }
        }

        foreach my $strginfo (@{$oconf->{strginfo}}) {
            if (defined($strginfo->{selwhere})) {
                $where = "$where and $strginfo->{selwhere}[0]";
            }
        }

        $sql = "$sql from $from where $where";
        if (defined($oconf->{sort})) {
            $sql .= " order by $oconf->{sort}[0]";
        }

        # encode value
        $sql = encode($conf->{mbcode}[0], $sql);
        my ($r, $sth) = $self->_sendQuery($sql);
        if ($r) {
            $self->log(level => 'err', message => "Searching by \"$sql\" failed: ".$sth);
            $rc = LDAP_OPERATIONS_ERROR;
            @match_entries = ();
            last DO;
        }

        # get the record from the result
        while (my @data = $sth->fetchrow_array) {
            my $entry;

            # check the number of returned entries
            if ($sizeLim >= 0 && @match_entries == $sizeLim) {
                $rc = LDAP_SIZELIMIT_EXCEEDED;
                last DO;
            }

            my $key = shift(@data);
            if ($key eq '') {
                next;
            }

            my $j = 0;
            foreach my $attr ('objectclass', keys %{$oconf->{attr}}) {
                if ($attr !~ /^objectclass$/i && !defined($oconf->{attr}->{$attr})) {
                    next;
                }

                if (@attrs && $attr !~ /^(objectclass|$oconf->{rdn}[0])$/i && !grep(/^$attr$/i, @attrs)) {
                    if (defined($oconf->{attr}{$attr}->{column})) {
                        $j++;
                    }
                    next;
                }

                if ($attr =~ /^objectclass$/i) {
                    foreach my $oc (@{$oconf->{oc}}) {
                        $entry = $entry."objectclass: $oc\n";
                    }
                } elsif (defined($oconf->{attr}{$attr}->{column})) {
                    if (defined($oconf->{attr}{$attr}->{delim})) {
                        my @values = split($oconf->{attr}{$attr}->{delim}[0], $data[$j]);
                        foreach my $value (@values) {
                            $value =~ s/ *$//;
                            if (!defined($value) || $value ne '') {
                                if ($attr =~ /$rawattrs/i) {
                                    $value = encode_base64($value, '');
                                    $entry = $entry.$attr.":: $value\n";
                                } elsif ($value =~ /\n/) {
                                    Encode::from_to($value, $conf->{mbcode}[0], 'utf8');
                                    $value = encode_base64($value, '');
                                    $entry = $entry.$attr.":: $value\n";
                                } else {
                                    $entry = $entry."$attr: $value\n";
                                }
                            }
                        }
                    } else {
                        my $value = $data[$j];
                        $value =~ s/ *$//;
                        if (!defined($value) || $value ne '') {
                            if ($attr =~ /$rawattrs/i) {
                                $value = encode_base64($value, '');
                                $entry = $entry.$attr.":: $value\n";
                            } elsif ($value =~ /\n/) {
                                Encode::from_to($value, $conf->{mbcode}[0], 'utf8');
                                $value = encode_base64($value, '');
                                $entry = $entry.$attr.":: $value\n";
                            } else {
                                $entry = $entry."$attr: $value\n";
                            }
                        }
                    }
                    $j++;
                } else {
                    # get the values from the attribute's table
                    my $values = $self->_getAttrValues($oconf, $key, $pkey, $attr);
                    if (!defined($values)) {
                        $rc = LDAP_OPERATIONS_ERROR;
                        @match_entries = ();
                        last DO;
                    }

                    if ($values) {
                        $entry = $entry.$values;
                    }
                }
            }

            # multibyte value
            if ($conf->{dsn}[0] =~ /^DBI:Oracle/i && Encode::is_utf8($entry)) {
                # add-hoc method for Oracle
                Encode::_utf8_off($entry);
            }

            Encode::from_to($entry, $conf->{mbcode}[0], 'utf8');
            $entry = decode('utf8', $entry);

            my ($rdn_val) = ($entry =~ /^$oconf->{rdn}[0]: (.*)$/mi);
            my $rdn = "$oconf->{rdn}[0]=$rdn_val";
            $entry = "dn: $rdn,$suffix\n$entry";

            push(@match_entries, $self->_pwdFormat($entry));
            push(@match_keys, $key);
        }

        $sth->finish;
    }

    return ($rc, \@match_keys, @match_entries);
}

=pod

=head2 _objModify($obj, $pekys, $dn, @list)

Update the data of the object's table and insert the data to the attribute's table.

=cut

sub _objModify
{
    my $self = shift;
    my ($obj, $pkeys, $dn, @list) = @_;
    my $conf = $self->{_config};
    my $oconf = $obj->{conf};
    my $pkey = $self->_getPid($pkeys);
    my $rc = LDAP_SUCCESS;

    DO: {
        # start transaction
        if (!$self->{db}->begin_work) {
            $self->log(level => 'err', message => "Can't begin: ".$self->{db}->errstr);
            $rc = LDAP_OPERATIONS_ERROR;
            last DO;
        }

        my $entry;
        my $key;

        ($rc, $key, $entry) = $self->_baseSearch($obj, $pkeys, $dn, 0, 0, 1, 0, undef);
        if ($rc) {
            last DO;
        }

        if (!$entry) {
            $rc = LDAP_NO_SUCH_OBJECT;
            last DO;
        }

        if (defined($oconf->{plugin})) {
            $rc = $self->_doPlugin('modify', $obj, $pkeys, $key, $dn, @list);
            if ($rc) {
                last DO;
            }
        }

        if (defined($oconf->{noop}) && grep(/^modify$/i, @{$oconf->{noop}})) {
            last DO;
        }

        my $idquote = !defined($oconf->{id}[0]->{type}) || $oconf->{id}[0]->{type}[0] !~ /^(int|smallint|float|number|text|boolean)$/i ? "'" : '';
        while ( @list > 0 ) {
            my $action = shift @list;
            my $attr    = lc(shift @list);
            my @values;
            my $sql;
            my $sth;
            my $r;

            while (@list > 0 && $list[0] ne "ADD" && $list[0] ne "DELETE" && $list[0] ne "REPLACE") {
                push(@values, shift @list);
            }

            if (!defined($oconf->{attr}{$attr})) {
                next;
            }

            # can't modify the attribute for rdn
            if ($attr eq $oconf->{rdn}[0]) {
                if ($action ne "REPLACE" || @values != 1) {
                    $rc = LDAP_CONSTRAINT_VIOLATION;
                    last DO;
                } else {
                    my $value = $values[0];
                    $value =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                    if ($entry !~ /^$attr: $value$/mi) {
                        $rc = LDAP_CONSTRAINT_VIOLATION;
                        last DO;
                    }
                }
            }

            for (my $i = 0; $i < @values; $i++) {
                if ($values[$i]) {
                    # replace carriage return to linefeed
                    $values[$i] =~ s/\r/$conf->{breakchar}/g;

                    # escape special character
                    $values[$i] =~ s/'/''/g;
                    $values[$i] =~ s/\\/\\\\/g;
                }
            }

            my $quote = !defined($oconf->{attr}{$attr}->{type}) || $oconf->{attr}{$attr}->{type}[0] !~ /^(int|smallint|float|number|text|boolean)$/i ? "'" : '';
            if($action eq "ADD") {
                # check whether the value already exists
                my $vals_str = "(".join('|', @values).")";
                $vals_str =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                if ($entry =~ /^$attr: $vals_str *$/mi) {
                    $rc = LDAP_TYPE_OR_VALUE_EXISTS;
                    last DO;
                }

                if (defined($oconf->{attr}{$attr}->{column})) {
                    my $value = $values[0];
                    if (defined($oconf->{attr}{$attr}->{delim})) {
                        my @old_vals = ($entry =~ /^$attr: (.*)$/gmi);
                        $value = join($oconf->{attr}{$attr}->{delim}[0], (@old_vals, @values));
                        foreach my $new_val (@old_vals, @values) {
                            $entry = "$entry$attr: $new_val\n";
                        }
                    } elsif ($entry =~ /^$attr: /mi) {
                        # the attribute must not exist
                        $rc = LDAP_CONSTRAINT_VIOLATION;
                        last DO;
                    }
                    $sql = "update $oconf->{table}[0] set $oconf->{attr}{$attr}->{column}[0] = $quote$value$quote where $oconf->{id}[0]->{column}[0] = $idquote$key$idquote";

                    # multibyte value
                    $sql = encode($conf->{mbcode}[0], $sql);

                    ($r, $sth) = $self->_sendQuery($sql);
                    if ($r) {
                        $self->log(level => 'err', message => "Adding values by \"$sql\" failed: ".$sth);
                        $rc = LDAP_OPERATIONS_ERROR;
                        last DO;
                    }
                    $sth->finish;
                }

                if (defined($oconf->{attr}{$attr}->{addproc})) {
                    if ($self->_addAttrValues($oconf->{attr}{$attr}, $key, $pkey, $dn, '', @values)) {
                        $rc = LDAP_OPERATIONS_ERROR;
                        last DO;
                    }
                }
            } elsif($action eq "DELETE") {
                # check whether the value exists
                for (my $i = 0; $i < @values; $i++) {
                    my $value = $values[$i];
                    $value =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                    if ($value && $entry !~ /^$attr: $value *$/mi) {
                        $rc = LDAP_NO_SUCH_ATTRIBUTE;
                        last DO;
                    }
                }

                if (defined($oconf->{attr}{$attr}->{column})) {
                    my $value = '';
                    if (defined($oconf->{attr}{$attr}->{delim}) && $values[0] ne '') {
                        my @old_vals = ($entry =~ /^$attr: (.*)$/gmi);
                        my @new_vals = ();
                        for (my $i = 0; $i < @old_vals; $i++) {
                            if (!grep(/^$old_vals[$i]$/i, @values)) {
                                push(@new_vals, $old_vals[$i]);
                            }
                        }
                        if (@new_vals) {
                            $value = join($oconf->{attr}{$attr}->{delim}[0], @new_vals);
                        }
                    }
                    $sql = "update $oconf->{table}[0] set $oconf->{attr}{$attr}->{column}[0] = $quote$value$quote where $oconf->{id}[0]->{column}[0] = $idquote$key$idquote";

                    # multibyte value
                    $sql = encode($conf->{mbcode}[0], $sql);

                    ($r, $sth) = $self->_sendQuery($sql);
                    if ($r) {
                        $self->log(level => 'err', message => "Deleting values by \"$sql\" failed: ".$sth);
                        $rc = LDAP_OPERATIONS_ERROR;
                        last DO;
                    }
                    $sth->finish;
                }

                if (defined($oconf->{attr}{$attr}->{delproc})) {
                    if (!@values || !$values[0]) {
                        @values = ($entry =~ /^$attr: (.*)$/mgi);
                        for (my $i = 0; $i < @values; $i++) {
                            # escape special character
                            $values[$i] =~ s/'/''/g;
                            $values[$i] =~ s/\\/\\\\/g;
                        }
                    }

                    if ($self->_delAttrValues($oconf->{attr}{$attr}, $key, $pkey, '', @values)) {
                        $rc = LDAP_OPERATIONS_ERROR;
                        last DO;
                    }
                }
            } elsif( $action eq "REPLACE" ) {
                if (defined($oconf->{attr}{$attr}->{column})) {
                    my $value = $values[0];
                    if (defined($oconf->{attr}{$attr}->{delim})) {
                        $value = join($oconf->{attr}{$attr}->{delim}[0], @values);
                    } elsif (@values > 1) {
                        # the attribute must not have more than two value
                        $rc = LDAP_CONSTRAINT_VIOLATION;
                        last DO;
                    }
                    $sql = "update $oconf->{table}[0] set $oconf->{attr}{$attr}->{column}[0] = $quote$value$quote where $oconf->{id}[0]->{column}[0] = $idquote$key$idquote";

                    # multibyte value
                    $sql = encode($conf->{mbcode}[0], $sql);

                    ($r, $sth) = $self->_sendQuery($sql);
                    if ($r) {
                        $self->log(level => 'err', message => "Replacing values by \"$sql\" failed: ".$sth);
                        $rc = LDAP_OPERATIONS_ERROR;
                        last DO;
                    }
                    $sth->finish;
                }

                if (defined($oconf->{attr}{$attr}->{addproc}) || defined($oconf->{attr}{$attr}->{delproc})) {
                    my @old_vals = ($entry =~ /^$attr: (.*)$/gmi);
                    my @add_vals;
                    my @delete_vals;

                    # delete the old values which exists
                    foreach my $value (@values) {
                        my $tmpval = $value;
                        $tmpval =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;

                        my $valmatch = 0;
                        my $i = 0;
                        for ($i = 0; $i < @old_vals; $i++) {
                            if ($old_vals[$i] =~ /^$tmpval$/i) {
                                $valmatch = 1;
                                last;
                            }
                        }
                        if ($valmatch) {
                            splice(@old_vals, $i, 1);
                        } else {
                            # escape special character
                            $value =~ s/'/''/g;
                            $value =~ s/\\/\\\\/g;
                            push(@add_vals, $value);
                        }
                    }
                    @delete_vals = @old_vals;

                    if ($self->_addAttrValues($oconf->{attr}{$attr}, $key, $pkey, $dn, '', @add_vals)) {
                        $rc = LDAP_OPERATIONS_ERROR;
                        last DO;
                    }

                    if ($self->_delAttrValues($oconf->{attr}{$attr}, $key, $pkey, '', @delete_vals)) {
                        $rc = LDAP_OPERATIONS_ERROR;
                        last DO;
                    }
                }
            }
        }
    }

    if ($rc) {
        $self->rollback();
    } elsif (defined($conf->{commit}) && $conf->{commit}[0] =~ /^on$/i) {
        $self->commit(1);
    }

    return $rc;
}

=pod

=head2 _objAdd($obj, $pkeys, $dn, $entryStr)

Insert the data to the object's and the attribute's table.

=cut

sub _objAdd
{
    my $self = shift;
    my ($obj, $pkeys, $dn, $entryStr) = @_;
    my $conf = $self->{_config};
    my $oconf = $obj->{conf};
    my $pkey = $self->_getPid($pkeys);
    my $rc = LDAP_SUCCESS;

    # check whether the entry already exists
    my $entry;
    my $key;

    if (!defined($oconf->{noop}) || !grep(/^add$/i, @{$oconf->{noop}})) {
       ($rc, $key, $entry) = $self->_baseSearch($obj, $pkeys, $dn, 0, 0, 1, 0, undef);
        if ($rc && $rc != LDAP_NO_SUCH_OBJECT) {
            return $rc;
        } elsif ($entry) {
            return LDAP_ALREADY_EXISTS;
        }
    }

    if (defined($oconf->{plugin})) {
        $rc = $self->_doPlugin('add', $obj, $pkeys, $dn, $entryStr);
        if ($rc) {
            return $rc;
        }
    }

    DO: {
        # start transaction
        if (!$self->{db}->begin_work) {
            $self->log(level => 'err', message => "Can't begin: ".$self->{db}->errstr);
            return LDAP_OPERATIONS_ERROR;
        }

        my @cols;
        my @values;
        my %attrs;
        my $sql;
        my $sth;
        my $r;

        if (defined($oconf->{id}[0]->{sequence})) {
            push(@cols, $oconf->{id}[0]->{column}[0]);
            push(@values, $oconf->{id}[0]->{sequence}[0]);
        }

        foreach (split(/\n/, $entryStr)) {
            my ($attr, $value) = split(/: /);
            $attr = lc($attr);
            if (!defined($oconf->{attr}{$attr})) {
                next;
            }

            # repace carriage return to linefeed
            $value =~ s/\r/$conf->{breakchar}/g;

            # escape special character
            $value =~ s/'/''/g;
            $value =~ s/\\/\\\\/g;

            my $quote = !defined($oconf->{attr}{$attr}->{type}) || $oconf->{attr}{$attr}->{type}[0] !~ /^(int|smallint|float|number|text|boolean)$/i ? "'" : '';
            if (defined($oconf->{attr}{$attr}->{column})) {
                if (defined($oconf->{attr}{$attr}->{delim})) {
                    my $match = 0;
                    for (my $i = 0; $i < @cols; $i++) {
                        if ($cols[$i] =~ /^$oconf->{attr}{$attr}->{column}[0]$/) {
                            $values[$i] =~ s/^$quote(.+)$quote$/$quote$1$oconf->{attr}{$attr}->{delim}[0]$value$quote/;
                            $match = 1;
                            last;
                        }
                    }
                    if (!$match) {
                        push(@cols, $oconf->{attr}{$attr}->{column}[0]);
                        push(@values, $quote.$value.$quote);
                    }
                } elsif (!grep(/^$oconf->{attr}{$attr}->{column}[0]$/, @cols)) {
                    push(@cols, $oconf->{attr}{$attr}->{column}[0]);
                    push(@values, $quote.$value.$quote);
                }
            }
            if (defined($oconf->{attr}{$attr}->{addproc})) {
                push(@{$attrs{$attr}}, $value);
            }
        }

        # get the storage-specific information
        my @si_values = ();
        foreach my $strginfo (@{$oconf->{strginfo}}) {
            my $value = $self->_getStaticValue($strginfo, $dn, $entryStr);
            push(@si_values, $value);

            my $quote = !defined($strginfo->{type}) || $strginfo->{type}[0] !~ /^(int|smallint|float|number|text|boolean)$/i ? "'" : '';
            if (defined($strginfo->{column})) {
                if (!grep(/^$strginfo->{column}[0]$/, @cols)) {
                    push(@cols, $strginfo->{column}[0]);
                    push(@values, $quote.$value.$quote);
                }
            }
        }

        if (!defined($oconf->{noop}) || !grep(/^add$/i, @{$oconf->{noop}})) {
            $sql = "insert into $oconf->{table}[0](".join(', ', @cols).") values(".join(', ', @values).")";

            # multibyte value
            $sql = encode($conf->{mbcode}[0], $sql);

            ($r, $sth) = $self->_sendQuery($sql);
            if ($r) {
                $self->log(level => 'err', message => "Adding entry by \"$sql\" failed: ".$sth);
                $rc = LDAP_OPERATIONS_ERROR;
                last DO;
            }
            $sth->finish;
        }

        # get the added object's id from the table
        my ($rdn, $pdn) = ($dn=~ /^([^,]+),(.*)$/);
        my $filter = Net::LDAP::Filter->new("(".encode('utf8', $rdn).")");
        my $keys;

        ($rc, $keys) = $self->_objSearch($obj, undef, $pdn, -1, $filter);
        if ($rc || !@{$keys}) {
            $self->log(level => 'err', message => "Can't get id of $dn from the table");
            $rc = LDAP_OPERATIONS_ERROR;
            last DO;
        }

        # get newest id
        my $key;
        while (@{$keys} > 0) {
            $key = shift @{$keys};
        }

        # add the storage-specific information
        for (my $i = 0; $i < @{$oconf->{strginfo}}; $i++) {
            if (!defined(${$oconf->{strginfo}}[$i]->{addproc})) {
                next;
            }

            foreach my $addproc (@{${$oconf->{strginfo}}[$i]->{addproc}}) {
	        $sql = $addproc;
                $sql =~ s/\%o/$key/g;
                $sql =~ s/\%v/$si_values[$i]/g;
                $sql =~ s/\%c/$pkey/g;
                $sql = $self->_funcParse($sql, $dn, $entryStr);

                # multibyte value
                $sql = encode($conf->{mbcode}[0], $sql);

                ($r, $sth) = $self->_sendQuery($sql);
                if ($r) {
                    $self->log(level => 'err', message => "Adding storage-specific information by \"$sql\" failed: ".$sth);
                    $rc = LDAP_OPERATIONS_ERROR;
                    last DO;
                }
                $sth->finish;
            }
        }

        if (!defined($oconf->{noop}) || !grep(/^add$/i, @{$oconf->{noop}})) {
            # add the values in the attribute's table
            foreach my $attr (keys %attrs) {
                if ($self->_addAttrValues($oconf->{attr}{$attr}, $key, $pkey, $dn, $entryStr, @{$attrs{$attr}})) {
                    $self->log(level => 'err', message => "Adding values of $attr failed");
                    $rc = LDAP_OPERATIONS_ERROR;
                    last DO;
                }
            }
        }

        # add the link with container
        if (defined($pkey) && defined($oconf->{container}) &&
            defined($oconf->{container}[0]->{addproc})) {
            $sql = $oconf->{container}[0]->{addproc}[0];
            $sql =~ s/\%o/$key/g;
            $sql = $self->_containerParse($sql, @{$pkeys});
            $sql = $self->_funcParse($sql, $dn, $entryStr);
            ($r, $sth) = $self->_sendQuery($sql);
            if ($r) {
                $self->log(level => 'err', message => "Adding link of container by \"$sql\" failed: ".$sth);
                $rc = LDAP_OPERATIONS_ERROR;
                last DO;
            }
            $sth->finish;
        }
    }

    if ($rc) {
        $self->rollback();
    } elsif (defined($conf->{commit}) && $conf->{commit}[0] =~ /^on$/i) {
        $self->commit(1);
    }

    return $rc;
}

=pod

=head2 _objDelete($obj, $pkeys, $dn)

delete the data from the object's and the attribute's table.

=cut

sub _objDelete
{
    my $self = shift;
    my ($obj, $pkeys, $dn) = @_;
    my $conf = $self->{_config};
    my $oconf = $obj->{conf};
    my $pkey = $self->_getPid($pkeys);
    my $rc = LDAP_SUCCESS;

    DO: {
        # start transaction
        if (!$self->{db}->begin_work) {
            $self->log(level => 'err', message => "Can't begin: ".$self->{db}->errstr);
            $rc = LDAP_OPERATIONS_ERROR;
            last DO;
        }

        # get the object's id from the table
        my $key;

        ($rc, $key) = $self->_baseSearch($obj, $pkeys, $dn, 0, 0, 1, 0, undef);
        if ($rc) {
            last DO;
        }
        if (!defined($key)) {
            $rc = LDAP_NO_SUCH_OBJECT;
            last DO;
        }

        my $sql;
        my $sth;
        my $r;

        if (!defined($oconf->{noop}) || !grep(/^delete$/i, @{$oconf->{noop}})) {
            # delete the values from the attribute's table
            foreach my $attr (keys %{$oconf->{attr}}) {
                if (defined($oconf->{attr}{$attr}) && defined($oconf->{attr}{$attr}->{delproc})) {
                    if ($self->_delAttrValues($oconf->{attr}{$attr}, $key, $pkey, '', '')) {
                        $rc = LDAP_OPERATIONS_ERROR;
                        last DO;
                    }
                 }
            }
        }

        # delete the storage-specific information
        foreach my $strginfo (@{$oconf->{strginfo}}) {
            if (!defined($strginfo->{delproc})) {
                next;
            }
            my $value = $self->_getStaticValue($strginfo, $dn);
            foreach my $delproc (@{$strginfo->{delproc}}) {
	        $sql = $delproc;
                $sql =~ s/\%o/$key/g;
                $sql =~ s/\%v/$value/g;
                $sql = $self->_funcParse($sql, $dn);

                # multibyte value
                $sql = encode($conf->{mbcode}[0], $sql);

                $sth = $self->_sendQuery($sql);
                if ($r) {
                    $self->log(level => 'err', message => "Deleting storage-specific information by \"$sql\" failed: ".$sth);
                    $rc = LDAP_OPERATIONS_ERROR;
                    last DO;
                }
                $sth->finish;
            }
        }

        if (!defined($oconf->{noop}) || !grep(/^delete$/i, @{$oconf->{noop}})) {
            # delete the link with container
            if (defined($pkey) && defined($oconf->{container}) &&
                defined($oconf->{container}[0]->{delproc})) {
                $sql = $oconf->{container}[0]->{delproc}[0];
                $sql =~ s/\%o/$key/g;
                $sql = $self->_containerParse($sql, @{$pkeys});
                $sql = $self->_funcParse($sql, $dn);
                ($r, $sth) = $self->_sendQuery($sql);
                if ($r) {
                    $self->log(level => 'err', message => "Deleting link of container by \"$sql\" failed: ".$sth);
                    $rc = LDAP_OPERATIONS_ERROR;
                    last DO;
                }
                $sth->finish;
            }

            my $idquote = !defined($oconf->{id}[0]->{type}) || $oconf->{id}[0]->{type}[0] !~ /^(int|smallint|float|number|text|boolean)$/i ? "'" : '';
            # delete the appropriate record from the object's table
            $sql = "delete from $oconf->{table}[0] where $oconf->{id}[0]->{column}[0] = $idquote$key$idquote";
            ($r, $sth) = $self->_sendQuery($sql);
            if ($r) {
                $self->log(level => 'err', message => "Deleting entry by \"$sql\" failed: ".$sth);
                $rc = LDAP_OPERATIONS_ERROR;
                last DO;
            }
            $sth->finish;
        }

        if (defined($oconf->{plugin})) {
            $rc = $self->_doPlugin('delete', $obj, $pkeys, $key, $dn);
            if ($rc) {
                last DO;
            }
        }
    }

    if ($rc) {
        $self->rollback();
    } elsif (defined($conf->{commit}) && $conf->{commit}[0] =~ /^on$/i) {
        $self->commit(1);
    }

    return $rc;
}

=pod

=head2 _objMove($obj, $pekys, $dn, $newpkeys, $newdn)

Move the object.

=cut

sub _objMove
{
    my $self = shift;
    my ($obj, $pkeys, $dn, $newpkeys, $newdn) = @_;
    my $conf = $self->{_config};
    my $oconf = $obj->{conf};
    my $pkey = $self->_getPid($pkeys);
    my $newpkey = $self->_getPid($newpkeys);
    my $sql;
    my $sth;
    my $r;
    my $rc = LDAP_SUCCESS;

    DO: {
        # start transaction
        if (!$self->{db}->begin_work) {
            $self->log(level => 'err', message => "Can't begin: ".$self->{db}->errstr);
            $rc = LDAP_OPERATIONS_ERROR;
            last DO;
        }

        my $entry;
        my $key;
        my $newkey;

        ($rc, $key, $entry) = $self->_baseSearch($obj, $pkeys, $dn, 0, 0, 1, 0, undef);
        if ($rc) {
            last DO;
        }

        if (!$entry) {
            $rc = LDAP_NO_SUCH_OBJECT;
            last DO;
        }

        ($rc, $newkey, $entry) = $self->_baseSearch($obj, $newpkeys, $newdn, 0, 0, 1, 0, undef);
        if ($entry) {
            $rc = LDAP_ALREADY_EXISTS;
            last DO;
        }

        # add the link with container
        if (defined($newpkey) && defined($oconf->{container}) &&
            defined($oconf->{container}[0]->{addproc})) {
            $sql = $oconf->{container}[0]->{addproc}[0];
            $sql =~ s/\%o/$key/g;
            $sql = $self->_containerParse($sql, @{$newpkeys});
            $sql = $self->_funcParse($sql, $newdn, $entry);
            ($r, $sth) = $self->_sendQuery($sql);
            if ($r) {
                $self->log(level => 'err', message => "Adding link of container by \"$sql\" failed: ".$sth);
                $rc = LDAP_OPERATIONS_ERROR;
                last DO;
            }
            $sth->finish;
        }

        # delete the link with container
        if (defined($pkey) && defined($oconf->{container}) &&
            defined($oconf->{container}[0]->{delproc})) {
            $sql = $oconf->{container}[0]->{delproc}[0];
            $sql =~ s/\%o/$key/g;
            $sql = $self->_containerParse($sql, @{$pkeys});
            $sql = $self->_funcParse($sql, $dn);
            ($r, $sth) = $self->_sendQuery($sql);
            if ($r) {
                $self->log(level => 'err', message => "Deleting link of container by \"$sql\" failed: ".$sth);
                $rc = LDAP_OPERATIONS_ERROR;
                last DO;
            }
            $sth->finish;
        }
    }

    if ($rc) {
        $self->rollback();
    } elsif (defined($conf->{commit}) && $conf->{commit}[0] =~ /^on$/i) {
        $self->commit(1);
    }

    return $rc;
}

sub _getParentRdn
{
    my $self = shift;
    my ($obj, $key, $pobj) = @_;
    my $conf = $self->{_config};
    my $oconf = $obj->{conf};
    my $poconf = $pobj->{conf};
    my $selexpr;
    my $from;
    my $where;

    if (defined($oconf->{container}[0]->{rdn})) {
        return $oconf->{container}[0]->{rdn}[0];
    }
    if (!defined($oconf->{container}[0]->{oname})) {
        return undef;
    }

    if (defined($poconf->{entry})) {
        return $poconf->{entry}[0]->{rdn}[0];
    }

    my $ptable = $poconf->{table}[0];
    $ptable =~ s/^[^.]+\.//;
    $selexpr = "$ptable.$poconf->{id}[0]->{column}[0],$ptable.$poconf->{attr}{$poconf->{rdn}[0]}->{column}[0]";

    $from = $oconf->{table}[0];
    if ($from ne $poconf->{table}[0]) {
        $from = "$from,$poconf->{table}[0]";
    }
    if (defined($oconf->{container}[0]->{fromtbls})) {
        $from = "$from,$oconf->{container}[0]->{fromtbls}[0]";
    }

    my $otable = $oconf->{table}[0];
    $otable =~ s/^[^.]+\.//;
    my $idquote = !defined($oconf->{id}[0]->{type}) || $oconf->{id}[0]->{type}[0] !~ /^(int|smallint|float|number|text|boolean)$/i ? "'" : '';
    $where = "$otable.$oconf->{id}[0]->{column}[0] = $idquote$key$idquote";
    if (defined($oconf->{container}[0]->{joinwhere})) {
        if ($oconf->{container}[0]->{joinwhere}[0] =~ /\%c/) {
            my ($pidcol) = ($oconf->{container}[0]->{joinwhere}[0] =~ /([^ ]+) *= *'?\%c'?/);
            $where = "$ptable.$poconf->{id}[0]->{column}[0] = (select $pidcol from $oconf->{table}[0] where $where)";
        } else {
            $where = "$where and $oconf->{container}[0]->{joinwhere}[0]";
        }
    }

    my $sql = "select $selexpr from $from where $where";
    my ($r, $sth) = $self->_sendQuery($sql);
    if ($r) {
        $self->log(level => 'err', message => "Getting rdn by \"$sql\" failed: ".$sth);
        return undef;
    }

    # get rdn value from the result
    my @data = $sth->fetchrow_array;
    $sth->finish;

    my $rdn_val = $data[1];
    $rdn_val =~ s/ *$//;

    if ($data[0]) {
        return ("$poconf->{rdn}[0]=$rdn_val", $data[0]);
    } else {
        return '';
    }
}

sub _getAttrValues
{
    my $self = shift;
    my ($oconf, $key, $pkey, $attr) = @_;
    my $conf = $self->{_config};
    my $aobj = undef;
    my $aoconf = undef;
    my $cobj = undef;
    my $coconf = undef;
    my $attrStr = '';
    my $selexpr;
    my $from;
    my $where;

    $from = $oconf->{table}[0];
    my $otable = $oconf->{table}[0];
    $otable =~ s/^[^.]+\.//;
    if (defined($oconf->{attr}{$attr}->{oname})) {
        $aobj = $self->{object}{$oconf->{attr}{$attr}->{oname}[0]};
        $aoconf = $aobj->{conf};
        my $atable = $aoconf->{table}[0];
        $atable =~ s/^[^.]+\.//;
        $selexpr = "$atable.$aoconf->{id}[0]->{column}[0]";
        if (defined($aoconf->{attr}{$aoconf->{rdn}[0]}->{selexpr})) {
            $selexpr = "$selexpr, $aoconf->{attr}{$aoconf->{rdn}[0]}->{selexpr}[0]";
        } else {
            $selexpr = "$selexpr, $atable.$aoconf->{attr}{$aoconf->{rdn}[0]}->{column}[0]";
        }

        if ($oconf->{table}[0] ne $aoconf->{table}[0]) {
            $from = "$from, $aoconf->{table}[0]";
        }

        if (defined($aoconf->{parentrel}) &&
            $aoconf->{parentrel}[0] eq 'tight') {
            $cobj = $self->{object}{$aoconf->{container}->{oname}[0]};
            $coconf = $cobj->{conf};
            my $ctable = $coconf->{table}[0];
            $ctable =~ s/^[^.]+\.//;
            $selexpr = "$selexpr, $ctable.$coconf->{id}[0]->{column}[0]";
            if (defined($aoconf->{attr}{$aoconf->{rdn}[0]}->{selexpr})) {
                $selexpr = "$selexpr, $coconf->{attr}{$coconf->{rdn}[0]}->{selexpr}[0]";
            } else {
                $selexpr = "$selexpr, $ctable.$coconf->{attr}{$coconf->{rdn}[0]}->{column}[0]";
            }

            $from = "$from, $coconf->{table}[0]";
        }
    } elsif (defined($oconf->{attr}{$attr}->{selexpr})){
        $selexpr = $oconf->{attr}{$attr}->{selexpr}[0];
    } elsif (defined($oconf->{attr}{$attr}->{constant})) {
        return "$attr: $oconf->{attr}{$attr}->{constant}[0]\n";
    } else {
        return '';
    }

    if (defined($oconf->{attr}{$attr}->{fromtbls})) {
        $from = "$from,$oconf->{attr}{$attr}->{fromtbls}[0]";
    }

    if (defined($oconf->{attr}{$attr}->{where})) {
        $where = $oconf->{attr}{$attr}->{where}[0];
        $where =~ s/\%o/$key/g;
        $where =~ s/\%p/$pkey/g;
    } else {
        my $idquote = !defined($oconf->{id}[0]->{type}) || $oconf->{id}[0]->{type}[0] !~ /^(int|smallint|float|number|text|boolean)$/i ? "'" : '';
        $where = "$otable.$oconf->{id}[0]->{column}[0] = $idquote$key$idquote";
        if (defined($oconf->{attr}{$attr}->{joinwhere})) {
            $where = "$where and $oconf->{attr}{$attr}->{joinwhere}[0]";
            $where =~ s/\%o/$key/g;
            $where =~ s/\%p/$pkey/g;
        }
    }

    if ($aoconf) {
        foreach my $strginfo (@{$aoconf->{strginfo}}) {
            if (defined($strginfo->{selwhere})) {
                $where = "$where and $strginfo->{selwhere}[0]";
            }
        }
    }

    my $sql = "select $selexpr from $from where $where";
    my ($r, $sth) = $self->_sendQuery($sql);
    if ($r) {
        $self->log(level => 'err', message => "Getting $attr values by \"$sql\" failed: ".$sth);
        return undef;
    }

    # get the attribute's values from the result
    while (my @data = $sth->fetchrow_array) {
        if (!@data) {
            next;
        } elsif ($aoconf) {
            $attrStr = $attrStr."$attr: $aoconf->{rdn}[0]=$data[1],";
            if ($coconf) {
                $attrStr = $attrStr."$coconf->{rdn}[0]=$data[3],".$self->_getParentDn($cobj, $data[2])."\n";
            } else {
                $attrStr = $attrStr.$self->_getParentDn($aobj, $data[0])."\n";
            }
            $attrStr =~ s/ *,/,/g;
        } else{
            $data[0] =~ s/ *$//;
            if ($data[0] | $data[0] eq '0') {
                if ($data[0] =~ /\n/) {
                    $data[0] = encode_base64($data[0], '');
                    $attrStr = $attrStr.$attr.":: $data[0]\n";
                } else {
                    $attrStr = $attrStr."$attr: $data[0]\n";
                }
            }
        }
    }
    $sth->finish;

    return $attrStr;
}

sub _addAttrValues
{
    my $self = shift;
    my ($aconf, $key, $pkey, $dn, $entryStr, @values) = @_;
    my $conf = $self->{_config};

    if (!defined($aconf->{addproc})) {
        return 0;
    }

    foreach my $value (@values) {
        foreach my $addproc (@{$aconf->{addproc}}) {
            my $sql = $addproc;
            $sql =~ s/\%o/$key/g;
            $sql =~ s/\%p/$pkey/g;
            if (defined($aconf->{oname})) {
                my ($rc, $aobj, $attrpkeys) = $self->_getObject($value);
                if ($rc) {
                    return -1;
                }

                my $attrkey;
                ($rc, $attrkey) =$self->_baseSearch($aobj, $attrpkeys, $value, 0, 0, 1, 0, undef);
                if ($rc) {
                    $self->log(level => 'err', message => "Can't get id of $value in the table");
                    return -1;
                } elsif (!$attrkey) {
		    $self->log(level => 'err', message => "Id of $value doesn't exist in the table");
                    return 1;
                }
                $sql =~ s/\%a/$attrkey/g;

                if (defined($aobj->{conf}->{parentrel}) &&
                    $aobj->{conf}->{parentrel}[0] eq 'tight') {
                    my $contdn;
                    ($contdn = $value) =~ s/^[^,]+,//;
                    my ($rc, $cobj, $contpkeys) = $self->_getObject($contdn);
                    if ($rc) {
                        return -1;
                    }

                    my $contkey;
                    ($rc, $contkey) =$self->_baseSearch($cobj, $contpkeys, $contdn, 0, 0, 1, 0, undef);
                    if ($rc) {
                        $self->log(level => 'err', message => "Can't get id of $contdn in the table");
                        return -1;
                    } elsif (!$contkey) {
                        $self->log(level => 'err', message => "Id of $contdn doesn't exist in the table");
                        return 1;
                    }
                    $sql =~ s/\%c/$contkey/g;
                }
            } else {
                $sql =~ s/\%a/$value/g;
            }

            $sql = $self->_funcParse($sql, $dn, $entryStr);

            # multibyte value
            $sql = encode($conf->{mbcode}[0], $sql);

            # add the values to the attribute's table
            my ($r, $sth) = $self->_sendQuery($sql);
            if ($r) {
                $self->log(level => 'err', message => "Adding values by \"$sql\" failed: ".$sth);
                return -1;
            }
            $sth->finish;
        }
    }

    return 0;
}

sub _delAttrValues
{
    my $self = shift;
    my ($aconf, $key, $pkey, $dn, @values) = @_;
    my $conf = $self->{_config};

    if (!defined($aconf->{delproc})) {
        return 0;
    }

    foreach my $value (@values) {
        foreach my $delproc (@{$aconf->{delproc}}) {
            my $sql = $delproc;
            $sql =~ s/\%o/$key/g;
            $sql =~ s/\%p/$pkey/g;
            if ($value) {
                if (defined($aconf->{oname})) {
                    my ($rc, $aobj, $attrpkeys) = $self->_getObject($value);
                    if ($rc) {
                        return -1;
                    }

                    my $attrkey;
                    ($rc, $attrkey) =$self->_baseSearch($aobj, $attrpkeys, $value, 0, 0, 1, 0, undef);
                    if ($rc) {
		        $self->log(level => 'err', message => "Can't get id of $value from the table");
                        return -1;
                    } elsif (!$attrkey) {
		        $self->log(level => 'err', message => "Id of $value doesn't exist in the table");
                        return 1;
                    }
                    $sql =~ s/\%a/$attrkey/g;

                    if (defined($aobj->{conf}->{parentrel}) &&
                        $aobj->{conf}->{parentrel}[0] eq 'tight') {
                        my $contdn;
                        ($contdn = $value) =~ s/^[^,]+,//;
                        my ($rc, $cobj, $contpkeys) = $self->_getObject($contdn);
                        if ($rc) {
                            return -1;
                        }

                        my $contkey;
                        ($rc, $contkey) =$self->_baseSearch($cobj, $contpkeys, $contdn, 0, 0, 1, 0, undef);
                        if ($rc) {
                            $self->log(level => 'err', message => "Can't get id of $contdn in the table");
                            return -1;
                        } elsif (!$contkey) {
                            $self->log(level => 'err', message => "Id of $contdn doesn't exist in the table");
                            return 1;
                        }
                        $sql =~ s/\%c/$contkey/g;
                    }
                } else {
                    $sql =~ s/\%a/$value/g;
                }
            } else {
                $sql =~ s/\w*\s*=\s*'?\%a'?/1 = 1/g;
                $sql =~ s/\w*\s*=\s*'?\%c'?/1 = 1/g;
            }

            $sql = $self->_funcParse($sql, $dn);

            # multibyte value
            $sql = encode($conf->{mbcode}[0], $sql);

            # delete the values from the attribute's table
            my ($r, $sth) = $self->_sendQuery($sql);
            if ($r) {
                $self->log(level => 'err', message => "Deleting values by \"$sql\" failed: ".$sth);
                return -1;
            }
            $sth->finish;
        }
    }

    return 0;
}

sub _filter2sql
{
    my $self = shift;
    my ($oconf, $filter, $from, $where) = @_;
    my ($type, $attr, $value);
    my $conf = $self->{_config};

    if (!$filter) {
        ${$from} = $oconf->{table}[0];
        ${$where} = '1 = 1';
        return 1;
    }

    my ($op) = keys %{$filter};
    my $args = $filter->{$op};
    my $otable = $oconf->{table}[0];
    $otable =~ s/^[^.]+\.//;

    if ($op eq 'and' || $op eq 'or') {
        my ($lfrom, $lwhere, $rfrom, $rwhere);
        my $left = $self->_filter2sql($oconf, @{$args}[0], \$lfrom, \$lwhere);
        my $right = $self->_filter2sql($oconf, @{$args}[1], \$rfrom, \$rwhere);
        if (!$left || !$right) {
            return 0;
        }

        ${$where} = "($lwhere $op $rwhere)";
        ${$from} = $lfrom;
        foreach my $table (split(/, */, $rfrom)) {
            if (",$lfrom," =~ /, *$table *,/) {
                next;
            }
            ${$from} = "${$from}, $table";
        }
        return 1;
    } elsif ($op eq 'not'){
        if (!$self->_filter2sql($oconf, $args, $from, $where)) {
            return 0;
        }
        ${$where} = "not ${$where}";

        return 1;
    }

    if ($op =~ /^(equalityMatch|greaterOrEqual|lessOrEqual)/) {
        $attr = lc($args->{attributeDesc});
        $value = $args->{assertionValue};
        if ($op eq 'equalityMatch') {
            $type = '=';
        } elsif ($op eq 'greaterOrEqual') {
            $type = '>=';
        } elsif ($op eq 'lessOrEqual') {
            $type = '<=';
        }
    } else {
        $type = 'like';
        if ($op eq 'substrings') {
            $attr = lc($args->{type});
            if (defined($args->{substrings}[0]{any})) {
                $value = "%".$args->{substrings}[0]{any}."%";
            } else {
                $value = $args->{substrings}[0]{initial}."%".$args->{substrings}[1]{final};
            }
        } elsif ($op eq 'present') {
            $attr = lc($args);
            $value = '_%';
        }

        if (defined($oconf->{attr}{$attr}) && defined($oconf->{attr}{$attr}->{oname})) {
            return 0;
        }
    }

    # decode value
    $value = decode('utf8', $value);

    # escape special character
    $value =~ s/'/''/g;
    $value =~ s/\\/\\\\/g;

    my $nml = !defined($oconf->{attr}{$attr}) || !defined($oconf->{attr}{$attr}->{type}) || $oconf->{attr}{$attr}->{type}[0] !~ /^(int|smallint|float|number|date|text|boolean)$/i ? 1 : 0;
    my $quote = !defined($oconf->{attr}{$attr}) || !defined($oconf->{attr}{$attr}->{type}) || $oconf->{attr}{$attr}->{type}[0] !~ /^(int|smallint|float|number)$/i ? "'" : '';
    ${$from} = $oconf->{table}[0];
    if ($attr =~ /^objectclass$/i) {
        # check object class in filter
        $value =~ s/_/./;
        $value =~ s/%/.*/;
        if (grep(/^$value$/i, @{$oconf->{oc}})) {
            ${$where} = '1 = 1';
        } else {
            ${$where} = '1 = 0';
        }
    } elsif (!defined($oconf->{attr}{$attr})) {
        # attribute doesn't exit
            ${$where} = '1 = 1';
    } elsif (defined($oconf->{attr}{$attr}->{column})) {
        ${$where} = ($nml ? "lower($otable.$oconf->{attr}{$attr}->{column}[0])" : "$otable.$oconf->{attr}{$attr}->{column}[0]")." $type ".($nml ? "lower($quote$value$quote)" : "$quote$value$quote");
    } elsif (defined($oconf->{attr}{$attr}->{oname})) {
        my $aconf = $self->{object}{$oconf->{attr}{$attr}->{oname}[0]}->{conf};
        my $atable = $aconf->{table}[0];
        $atable =~ s/^[^.]+\.//;
        if (!grep(/^$aconf->{table}[0]$/, split(/, */, ${$from}))) {
            ${$from} = "${$from},$aconf->{table}[0]";
        }
        if (defined($oconf->{attr}{$attr}->{fromtbls})) {
            ${$from} = "${$from},$oconf->{attr}{$attr}->{fromtbls}[0]";
        }

        my $nml = !defined($aconf->{attr}{$aconf->{rdn}[0]}) || !defined($aconf->{attr}{$aconf->{rdn}[0]}->{type}) || $aconf->{attr}{$$aconf->{rdn}[0]}->{type}[0] !~ /^(int|smallint|float|number|date|text|boolean)$/i ? 1 : 0;
        my $quote = !defined($aconf->{attr}{$aconf->{rdn}[0]}) || !defined($aconf->{attr}{$aconf->{rdn}[0]}->{type}) || $aconf->{attr}{$aconf->{rdn}[0]}->{type}[0] !~ /^(int|smallint|float|number)$/i ? "'" : '';
        ($value) = ($value =~ /^$aconf->{rdn}[0]=([^,]*)/i);
        my $subquery = "select $otable.$oconf->{id}[0]->{column}[0] from ${$from} where ".($nml ? "lower($atable.$aconf->{attr}{$aconf->{rdn}[0]}->{column}[0])" : "$atable.$aconf->{attr}{$aconf->{rdn}[0]}->{column}[0]")." $type ".($nml ? "lower($quote$value$quote)" : "$quote$value$quote");
        if (defined($oconf->{attr}{$attr}->{joinwhere})) {
            $subquery = "$subquery and $oconf->{attr}{$attr}->{joinwhere}[0]";
        }
        ${$where} = "$otable.$oconf->{id}[0]->{column}[0] in ($subquery)";

        if (defined($aconf->{container}) && !defined($aconf->{container}[0]->{rdn})) {
            my $paconf = $self->{object}{$aconf->{container}[0]->{oname}[0]}->{conf};

            ${$from} = "${$from}, $paconf->{table}[0]";
            if (defined($aconf->{container}[0]->{fromtbls})) {
                ${$from} = "${$from}, $oconf->{container}[0]->{fromtbls}[0]";
            }

            if (defined($aconf->{container}[0]->{joinwhere})) {
                ${$where} = "${$where} and $aconf->{container}[0]->{joinwhere}[0]";
            }
        }
    } elsif (defined($oconf->{attr}{$attr}->{constant})) {
        ${$where} = "lower(\'$oconf->{attr}{$attr}->{constant}[0]\') $type lower(\'$value\')";
    } else {
        if (defined($oconf->{attr}{$attr}->{fromtbls})) {
            ${$from} = "${$from},$oconf->{attr}{$attr}->{fromtbls}[0]";
        }
        my $subquery =  "select $otable.$oconf->{id}[0]->{column}[0] from ${$from} where ".($nml ? "lower($oconf->{attr}{$attr}->{selexpr}[0])" : $oconf->{attr}{$attr}->{selexpr}[0])." $type ".($nml ? "lower($quote$value$quote)" : "$quote$value$quote");
        if (defined($oconf->{attr}{$attr}->{joinwhere})) {
            $subquery = "$subquery and $oconf->{attr}{$attr}->{joinwhere}[0]";
        }
        ${$where} = "$otable.$oconf->{id}[0]->{column}[0] in ($subquery)";
    }

    return 1;
}

sub _sendQuery
{
    my $self = shift;
    my ($sql) = @_;
    my $conf = $self->{_config};

    my $timeout = defined($conf->{'timeout'}) && $conf->{'timeout'}[0] ? $conf->{'timeout'}[0] : 0;

    my $sth = $self->{db}->prepare($sql);
    if (!$sth) {
        return (1, '');
    }

    my $rc = 0;
    my $err;
    if ($timeout) {
        my $set = POSIX::SigSet->new(SIGALRM);
        my $act = POSIX::SigAction->new(
            sub {die "TIMEOUT\n";},
            $set
        );
        my $old = POSIX::SigAction->new;
        sigaction(SIGALRM, $act, $old);
        eval {
            eval {
                alarm($timeout);
                if (!$sth->execute) {
                    $rc = 1;
                    $err = $sth->errstr;
                }
            };
            alarm(0);
            die "$@\n" if $@;
        };
        sigaction(SIGALRM, $old);
        if ($@) {
            $rc = 1;
            if ($@ =~ /TIMEOUT\n/) {
                $err = 'Query Timeout.';
            } else {
                $err = $@;
            }
        }
    } else {
        if (!$sth->execute) {
            $rc = 1;
            $err = $sth->errstr;
        }
    }

    return ($rc, ($rc ? $err : $sth));
}

=head1 SEE ALSO

L<LISM>,
L<LISM::Storage>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

(c) 2006 Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
