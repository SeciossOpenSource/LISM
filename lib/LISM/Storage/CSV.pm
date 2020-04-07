package LISM::Storage::CSV;

use strict;
use base qw(LISM::Storage);
use Text::CSV_XS;
use LISM::Constant;
use Net::LDAP::Filter;
use DBI;
use POSIX qw(strftime);
use List::MoreUtils 'first_index';
use Encode;
use Data::Dumper;

=head1 NAME

LISM::Storage::CSV - CSV storage for LISM

=head1 DESCRIPTION

This class implements the L<LISM::Storage> interface for CSV data.

=head1 METHODS

=head2 init

Initialize the configuration data.

=cut

sub init
{
    my $self = shift;

    return $self->SUPER::init();
}

=pod

=head2 commit

Remove all temporary files updated.

=cut

sub commit
{
    my $self = shift;
    my $conf = $self->{_config};

    foreach my $oname (keys %{$conf->{object}}) {
        if (!defined($conf->{object}{$oname}->{file})) {
            next;
        }

        my $file = $conf->{object}{$oname}->{file}[0];
        if (!open(LOCK, "> $file.lock")) {
            $self->log(level => 'alert', message => "Can't open $file.lock");
            return -1;
        }
        flock(LOCK, 2);
        if (-f "$file.tmp") {
            unlink("$file.tmp");
        }
        close(LOCK);
    }

    return 0;
}

=pod

=head2 rollback

Rename all temporary files to each data files.

=cut

sub rollback
{
    my $self = shift;
    my $conf = $self->{_config};

    foreach my $oname (keys %{$conf->{object}}) {
        if (!defined($conf->{object}{$oname}->{file})) {
            next;
        }

        my $file = $conf->{object}{$oname}->{file}[0];
        if (!open(LOCK, "> $file.lock")) {
            $self->log(level => 'alert', message => "Can't open $file.lock");
            return -1;
        }
        flock(LOCK, 2);
        if (-f "$file.tmp") {
            rename("$file.tmp", $file);
        }
        close(LOCK);
    }

    return 0;
}


sub _checkConfig
{
    my $self = shift;
    my $conf = $self->{_config};
    my $rc = 0;

    if ($rc = $self->SUPER::_checkConfig()) {
        return $rc;
    }

    if (!defined($conf->{delim})) {
        $conf->{delim}[0] = ',';
    } elsif ($conf->{delim}[0] eq '\t') {
        $conf->{delim}[0] = "\t";
    }
    if (!defined($conf->{valdelim})) {
        $conf->{valdelim}[0] = ';';
    }
    if (defined($conf->{db})) {
        if (!defined($conf->{db}[0]->{dsn}) || !defined($conf->{db}[0]->{admin}) || !defined($conf->{db}[0]->{passwd})) {
            $self->log(level => 'alert', message => "dsn, admin, passwd must be in db");
            return 1;
        }
    }

    foreach my $oname (keys %{$conf->{object}}) {
        my $oconf = $conf->{object}{$oname};

        foreach my $attr (keys %{$oconf->{attr}}) {
            if (defined($oconf->{attr}{$attr}->{rexpr})) {
                ($oconf->{attr}{$attr}->{rexpr_expr} = $oconf->{attr}{$attr}->{rexpr}[0]) =~ s/\%[0-9]+/(.+)/g;
                $oconf->{attr}{$attr}->{rexpr_columns} = [($oconf->{attr}{$attr}->{rexpr}[0] =~ /\%([0-9]+)/g)];
            }
            if (defined($oconf->{db}) && !defined($conf->{db})) {
                $self->log(level => 'alert', message => "db doesn't exist");
                return 1;
            }
        }
    }

    return $rc;
}

=pod

=head2 _objSearch($obj, $pkeys, $suffix, $sizeLim, $timeLim, $filter)

Search the appropriate records in the object's file.

=cut

sub _objSearch
{
    my $self = shift;
    my ($obj, $pkeys, $suffix, $sizeLim, $filter) = @_;
    my $conf = $self->{_config};
    my $oconf = $obj->{conf};
    my $pkey = $self->_getPid($pkeys);
    my $dlm = $conf->{delim}[0];
    my $valdlm = $conf->{valdelim}[0];
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

    if (!defined($oconf->{mode}) || $oconf->{mode}[0] ne 'append') {
        DO: {
            my ($file, $lock) = $self->_openRead($oconf, $suffix);
            if (!defined($file)) {
                $rc = LDAP_OPERATIONS_ERROR;
                last DO;
            }
            my $csv = Text::CSV_XS->new({binary => 1, allow_whitespace => 1, sep_char => $dlm});
            if (!$csv) {
                $self->log(level => 'err', message => "Can't use CSV_XS: ".Text::CSV_XS->error_diag());
                $rc = LDAP_OPERATIONS_ERROR;
                last DO;
            }

            while (my $row = $csv->getline($file)) {
                my @data = @$row;
                for (my $i = 0; $i < @data; $i++) {
                    Encode::is_utf8($data[$i]) ? $data[$i] : Encode::from_to($data[$i], $conf->{mbcode}[0], 'utf8');
                    if ($conf->{mbcode}[0] ne 'utf8') {
                        $data[$i] = decode('utf8', $data[$i]);
                    }
                }
                my $entry;
                my $match = 1;

                foreach my $strginfo (@{$oconf->{strginfo}}) {
                    if (defined($strginfo->{column}) && defined($strginfo->{filter})) {
                        my $value = $data[$strginfo->{column}[0]];
                        foreach my $sifilter (@{$strginfo->{filter}}) {
                            my $ftype = $sifilter->{type};
                            my $fval = $sifilter->{content};
                            if ($ftype eq 'eq') {
                                if ($value =~ /^[0-9]+$/) {
                                    $match = $value == $fval ? 1 : 0;
                                } else {
                                    $match = $value eq $fval ? 1 : 0;
                                }
                            } elsif ($ftype eq 'not') {
                                if ($value =~ /^[0-9]+$/) {
                                    $match = $value != $fval ? 1 : 0;
                                } else {
                                    $match = $value ne $fval ? 1 : 0;
                                }
                            } elsif ($ftype eq 'lt') {
                                $match = $value < $fval ? 1 : 0;
                            } elsif ($ftype eq 'gt') {
                                $match = $value > $fval ? 1 : 0;
                            } elsif ($ftype eq 'le') {
                                $match = $value <= $fval ? 1 : 0;
                            } elsif ($ftype eq 'ge') {
                                $match = $value >= $fval ? 1 : 0;
                            }
                            if (!$match) {
                                last;
                            }
                        }
                        if (!$match) {
                            last;
                        }
                    }
                }
                if (!$match) {
                    next;
                }

                # check the number of returned entries
                if ($sizeLim >= 0 && @match_entries == $sizeLim) {
                    $rc = LDAP_SIZELIMIT_EXCEEDED;
                    last;
                }

                # entries below suffix
                if (defined($oconf->{container}) && !defined($oconf->{container}[0]->{rdn})) {
                    my $cur_pkey = $data[$oconf->{container}[0]->{idcolumn}[0]];

                    if (!($pkey =~ /^$cur_pkey$/i)) {
                        next;
                    }
                }

                # get all values of the entry
                foreach my $oc (@{$oconf->{oc}}) {
                    $entry = $entry."objectclass: $oc\n";
                }
                foreach my $attr (keys %{$oconf->{attr}}) {
                    if (defined($oconf->{attr}{$attr}->{column})) {
                        foreach my $value (split(/$valdlm/, $data[$oconf->{attr}{$attr}->{column}[0]])) {
                            $value =~ s/ *$//;
                            $value =~ s/\\3B/;/g;
                            $entry = $entry."$attr: $value\n";
                        }
                    } elsif (defined($oconf->{attr}{$attr}->{rexpr})) {
                        my $value = $oconf->{attr}{$attr}->{rexpr}[0];
                        for (my $i = @data; $i >= 0; $i--) {
                            $value =~ s/%$i/$data[$i]/;
                        }
                        $value =~ s/ *$//;
                        if ($value) {
                            $entry = $entry."$attr: $value\n";
                        }
                    } elsif (defined($oconf->{attr}{$attr}->{constant})) {
                        $entry = $entry."$attr: $oconf->{attr}{$attr}->{constant}[0]\n";
                    } else {
                        my $values = $self->_getAttrValues($oconf, $attr, split(/$valdlm/, $data[$oconf->{attr}{$attr}->{idcolumn}[0]]));
                        if (!defined($values)) {
                            $rc = LDAP_OPERATIONS_ERROR;
                            last;
                        }

                        if ($values) {
                            $entry = $entry.$values;
                        }
                    }
                }

                my ($rdn_val) = ($entry =~ /^$oconf->{rdn}[0]: (.*)$/mi);
                if (!$rdn_val) {
                    $self->log(level => 'err', message => "Entry doesn't have RDN");
                    $rc = LDAP_OTHER;
                    last;
                }

                $rdn_val =~ s/\\/\\5C/g;
                $rdn_val =~ s/=/\\3D/g;
                my $rdn = "$oconf->{rdn}[0]=$rdn_val";
                my $dn = "$rdn,$suffix";
                $dn =~ s/"/\\22/g;
                $dn =~ s/#/\\23/g;
                $dn =~ s/\+/\\2B/g;
                $dn =~ s/;/\\3B/g;
                $dn =~ s/</\\3C/g;
                $dn =~ s/>/\\3E/g;
                my $entrystr = "dn: $dn\n$entry";
                if (!Encode::is_utf8($entrystr)) {
                    $entrystr = decode_utf8($entrystr);
                }
                $entry = $entrystr;

                # parse filter
                if ($self->parseFilter($filter, $entry)) {
                    if (defined($oconf->{unique}) && $oconf->{unique}) {
                        my $index = first_index {$_ eq $data[$oconf->{id}[0]->{column}[0]]} @match_keys;
                        if ($index < 0) {
                            push(@match_entries, $self->_pwdFormat($entry));
                            push(@match_keys, $data[$oconf->{id}[0]->{column}[0]]);
                        } else {
                            $match_entries[$index] = $self->_pwdFormat($entry);
                        }
                    } else {
                        push(@match_entries, $self->_pwdFormat($entry));
                        push(@match_keys, $data[$oconf->{id}[0]->{column}[0]]);
                    }
                }
            }
            if ($self->_close($file, $lock, $oconf)) {
                $rc = LDAP_OPERATIONS_ERROR;
            }
        }
    } 

    return ($rc , \@match_keys, @match_entries);
}

=pod

=head2 _objModify($obj, $pkeys, $dn, @list)

Write the modified record to the temporary file.

=cut

sub _objModify
{
    my $self = shift;
    my ($obj, $pkeys, $dn, @list) = @_;
    my $conf = $self->{_config};
    my $oconf = $obj->{conf};
    my $pkey = $self->_getPid($pkeys);
    my $dlm = $conf->{delim}[0];
    my $valdlm = $conf->{valdelim}[0];
    my $match = 0;
    my $rc = LDAP_SUCCESS;

    if (!defined($oconf->{file})) {
        return $rc;
    }

    my ($rdn_val) = ($dn =~ /^[^=]+=([^,]+),/);
    my $regex_rdn_val = $rdn_val;
    $regex_rdn_val =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
    $rdn_val = encode('utf8', $rdn_val);
    $regex_rdn_val = encode('utf8', $regex_rdn_val);

    my $lock;
    my $file;
    my $db;
    my $tmp;

    if (!defined($oconf->{mode}) || $oconf->{mode}[0] ne 'append') {
        if (!$self->_checkFile($oconf->{file}[0])) {
            return LDAP_OPERATIONS_ERROR;
        }
    }

    if (!open($lock, "> $oconf->{file}[0].lock")) {
        $self->log(level => 'alert', message => "Can't open $oconf->{file}[0].lock");
        return LDAP_OPERATIONS_ERROR;
    }
    flock($lock, 2);

    if (defined($oconf->{mode}) && $oconf->{mode}[0] eq 'append') {
        if (!defined($oconf->{db})) {
            if (!open($file, ">> $oconf->{file}[0]")) {
                $self->log(level => 'alert', message => "Can't open $oconf->{file}[0]");
                close($lock);
                return LDAP_OPERATIONS_ERROR;
            }
        }
        $match = 1;
        if (defined($oconf->{op}[0]) && defined($oconf->{op}[0]->{modify}[0])) {
            my $csv = Text::CSV_XS->new({binary => 1, allow_whitespace => 1, sep_char => $dlm});
            if (!$csv) {
                $self->log(level => 'err', message => "Can't use CSV_XS: ".Text::CSV_XS->error_diag());
                $rc = LDAP_OPERATIONS_ERROR;
                last DO;
            }
            my @data;
            my $entryStr = '';
            my $timestamp;

            DO: {
                while ( @list > 0 && !$rc) {
                    my $action = shift @list;
                    my $attr    = lc(shift @list);
                    my @values;
                    my $coln;

                    while (@list > 0 && $list[0] ne "ADD" && $list[0] ne "DELETE" && $list[0] ne "REPLACE") {
                        my $value = shift @list;
                        push(@values, $value);
                        $entryStr .= "$attr: $value\n";
                    }

                    if ($attr eq 'modifytimestamp') {
                        $timestamp = $values[0];
                    }
                    if (!defined($oconf->{attr}{$attr})) {
                        next;
                    }
                    if (defined($oconf->{attr}{$attr}->{column})) {
                        $coln = $oconf->{attr}{$attr}->{column}[0];
                    } else {
                        my @keys;
                        $coln = $oconf->{attr}{$attr}->{idcolumn}[0];

                        # convert the value to object's id
                        ($rc, @keys) = $self->_getAttrKeys($oconf, $attr, @values);
                        if ($rc) {
                            $self->log(level => 'err', message => "Can't get id of $attr values in the file");
                            $rc = LDAP_OTHER;
                            last DO;
                        }
                        @values = @keys;
                    }
                    if ($data[$coln] !~ /^ *$/) {
                        $data[$coln] = "$data[$coln]$valdlm".join($valdlm, @values);
                    } else {
                        $data[$coln] = join($valdlm, @values);
                    }
                    if (ref($oconf->{op}[0]->{modify}[0]) eq 'HASH') {
                        if ($action eq 'ADD' && defined($oconf->{op}[0]->{modify}[0]->{add}[0])) {
                            $data[$oconf->{op}[0]->{modify}[0]->{column}[0]] = $oconf->{op}[0]->{modify}[0]->{add}[0];
                        } elsif ($action eq 'DELETE' && defined($oconf->{op}[0]->{modify}[0]->{delete}[0])) {
                            $data[$oconf->{op}[0]->{modify}[0]->{column}[0]] = $oconf->{op}[0]->{modify}[0]->{delete}[0];
                        } elsif ($action eq 'REPLACE' && defined($oconf->{op}[0]->{modify}[0]->{replace}[0])) {
                            $data[$oconf->{op}[0]->{modify}[0]->{column}[0]] = $oconf->{op}[0]->{modify}[0]->{replace}[0];
                        } else {
                            @data = ();
                        }
                    } else {
                        $data[$oconf->{op}[0]->{column}[0]] = $oconf->{op}[0]->{modify}[0];
                    }
                    if(@data) {
                        $data[$oconf->{attr}{$oconf->{rdn}[0]}{column}[0]] = $rdn_val;
                        foreach my $attr (keys %{$oconf->{attr}}) {
                            if (defined($oconf->{attr}{$attr}->{column}) && !defined($data[$oconf->{attr}{$attr}->{column}[0]])) {
                                $data[$oconf->{attr}{$attr}->{column}[0]] = "";
                            }
                        }
                    }
                }
                if (defined($oconf->{attr}{modifiersname}) && defined($oconf->{attr}{modifiersname}->{column})) {
                    $data[$oconf->{attr}{modifiersname}->{column}[0]] = defined($self->{lism}->{bind}{edn}) ? $self->{lism}->{bind}{edn} : $self->{lism}->{bind}{dn};
                }
                if (defined($oconf->{attr}{requestid}) && defined($oconf->{attr}{requestid}->{column})) {
                    $data[$oconf->{attr}{requestid}->{column}[0]] = defined($self->{lism}->{bind}{reqid}) ? $self->{lism}->{bind}{reqid} : 0;
                }

                foreach my $strginfo (@{$oconf->{strginfo}}) {
                    if (defined($strginfo->{column}) && defined($strginfo->{value})) {
                        my $value = $self->_getStaticValue($strginfo, $dn, $entryStr);
                        $data[$strginfo->{column}[0]] = $value;
                    }
                }

                if (defined($pkey) && defined($oconf->{container}) &&
                    defined($oconf->{container}[0]->{idcolumn})) {
                    $data[$oconf->{container}[0]->{idcolumn}[0]] = $pkey;
                }
                if (!$csv->combine(@data)) {
                    $self->log(level => 'err', message => "Can't combine CSV: ".$csv->error_diag());
                    $rc = LDAP_OTHER;
                    last DO;
                }
                my $line = $csv->string();
                if (!Encode::is_utf8($line)) {
                    $line = decode_utf8($line);
                }
                if (defined($oconf->{db})) {
                    if ($self->_dbInsert($oconf, $conf->{mbcode}[0] eq 'utf8' ? $line : Encode::from_to($line, 'utf8', $conf->{mbcode}[0]), $timestamp)) {
                        $rc = LDAP_OTHER;
                        last DO;
                    }
                } else {
                    print $file encode($conf->{mbcode}[0], $line)."\n";
                }
            }
            if (!defined($oconf->{db})) {
                close($file);
            }
        }
        close($lock);
    } else {
        if (!rename($oconf->{file}[0], "$oconf->{file}[0].tmp")) {
            $self->log(level => 'alert', message => "Can't rename $oconf->{file}[0] to $oconf->{file}[0].tmp");
            close($lock);
            return LDAP_OPERATIONS_ERROR;
        }

        if (!open($tmp, "< $oconf->{file}[0].tmp")) {
            $self->log(level => 'alert', message => "Can't open $oconf->{file}[0].tmp");
            close($lock);
            return LDAP_OPERATIONS_ERROR;
        }

        if (!open($file, "> $oconf->{file}[0]")) {
            $self->log(level => 'alert', message => "Can't open $oconf->{file}[0]");
            close($tmp);
            close($lock);
            return LDAP_OPERATIONS_ERROR;
        }

        DO: {
            my $csv = Text::CSV_XS->new({binary => 1, allow_whitespace => 1, sep_char => $dlm});
            if (!$csv) {
                $self->log(level => 'err', message => "Can't use CSV_XS: ".Text::CSV_XS->error_diag());
                $rc = LDAP_OPERATIONS_ERROR;
                last DO;
            }

            while (my $row = $csv->getline($tmp)) {
                my @data = @$row;
                for (my $i = 0; $i < @data; $i++) {
                    Encode::is_utf8($data[$i]) ? $data[$i] : Encode::from_to($data[$i], $conf->{mbcode}[0], 'utf8');
                }
                # check the data corresponds to the dn
                if (!("$valdlm$data[$oconf->{attr}{$oconf->{rdn}[0]}->{column}[0]]$valdlm" =~ /$valdlm$regex_rdn_val$valdlm/i)) {
                    if (!$csv->print($file, $row)) {
                        $self->log(level => 'err', message => "Can't write CSV: ".$csv->error_diag());
                        $rc = LDAP_OTHER;
                        last DO;
                    }
                    print $file "\n";
                    next;
                }

                # entries below suffix
                if (defined($pkey) && defined($oconf->{container}) && !defined($oconf->{container}[0]->{rdn})) {
                    my $cur_pkey = $data[$oconf->{container}[0]->{idcolumn}[0]];

                    if (!($pkey =~ /^$cur_pkey$/i)) {
                        print $file $_."\n";
                        next;
                    }
                }
                $match = 1;

                while ( @list > 0 && !$rc) {
                    my $action = shift @list;
                    my $attr    = lc(shift @list);
                    my @values;
                    my $coln;

                    while (@list > 0 && $list[0] ne "ADD" && $list[0] ne "DELETE" && $list[0] ne "REPLACE") {
                        push(@values, shift @list);
                    }

                    if (!defined($oconf->{attr}{$attr})) {
                        next;
                    }

                    # can't modify the attribute for rdn
                    if ($attr eq $oconf->{rdn}[0]) {
                        if ($action ne "REPLACE" || join($valdlm, @values) ne $data[$oconf->{attr}{$oconf->{rdn}[0]}{column}[0]]) {
                            $rc =  LDAP_CONSTRAINT_VIOLATION;
                            last;
                        }
                    }
                    if (grep(/\r/, @values)) {
                        $self->log(level => 'err', message => "CSV field can't contain carriage return");
                        $rc = LDAP_UNWILLING_TO_PERFORM;
                        last;
                    }

                    for (my $i = 0; $i < @values; $i++) {
                        $values[$i] =~ s/$valdlm/\\3B/g;
                    }

                    if (defined($oconf->{attr}{$attr}->{column})) {
                        $coln = $oconf->{attr}{$attr}->{column}[0];
                    } else {
                        my @keys;
                        $coln = $oconf->{attr}{$attr}->{idcolumn}[0];

                        # convert the value to object's id
                        ($rc, @keys) = $self->_getAttrKeys($oconf, $attr, @values);
                        if ($rc) {
                            $self->log(level => 'err', message => "Can't get id of $attr values in the file");
                            $rc = LDAP_OTHER;
                            last DO;
                        } 
                        @values = @keys;
                    }

                    if($action eq "ADD") {
                        # check whether the value already exists
                        for (my $i = 0; $i < @values; $i++) {
                            my $value = $values[0];
                            $value =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                            if ("$valdlm$data[$coln]$valdlm" =~ /$valdlm *$value *$valdlm/i) {
                                $rc = LDAP_TYPE_OR_VALUE_EXISTS;
                                last DO;
                            }
                        }
                        if ($data[$coln] !~ /^ *$/) {
                            $data[$coln] = "$data[$coln]$valdlm".join($valdlm, @values);
                        } else {
                            $data[$coln] = join($valdlm, @values);
                        }
                    } elsif($action eq "DELETE") {
                        if (@values && $values[0]) {
                            # check whether the value exists
                            for (my $i = 0;  $i < @values; $i++) {
                                my $value = $values[0];
                                $value =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                                if ("$valdlm$data[$coln]$valdlm" =~ /$valdlm *$value *$valdlm/i) {
                                    my $str = "$valdlm$data[$coln]$valdlm";
                                    $str =~ s/$valdlm$value$valdlm/$valdlm/i;
                                    ($data[$coln]) = ($str =~ /^$valdlm(.*)$valdlm$/);
                                } else {
                                    $rc = LDAP_NO_SUCH_ATTRIBUTE;
                                    last DO;
                                }
                            }
                        } else {
                            $data[$coln] = '';
                        }
                    } elsif($action eq "REPLACE") {
                        $data[$coln] = join($valdlm, @values);
                    }
                }

                if (!$csv->combine(@data)) {
                    $self->log(level => 'err', message => "Can't combine CSV: ".$csv->error_diag());
                    $rc = LDAP_OTHER;
                    last DO;
                }
                my $line = $csv->string();
                if (!Encode::is_utf8($line)) {
                    $line = decode_utf8($line);
                }
                print $file encode($conf->{mbcode}[0], $line)."\n";
            }
        }
        close($file);
        close($tmp);
        close($lock);
    }

    if (!$rc && !$match) {
        $rc =  LDAP_NO_SUCH_OBJECT;
    }

    if ($rc) {
        $self->rollback();
    }

    return ($rc, (!defined($oconf->{mode}) || $oconf->{mode}[0] ne 'append' || !$rc) && defined($conf->{noaudit}) && $conf->{noaudit}[0] eq 'on' ? 'LISM_NO_OPERATION' : '');
}

=pod

=head2 _objAdd($obj, $pkeys, $dn, $entryStr)

Copy the object's file to the temporary file and add the record to it.

=cut

sub _objAdd
{
    my $self = shift;
    my ($obj, $pkeys, $dn,  $entryStr) = @_;
    my $conf = $self->{_config};
    my $oconf = $obj->{conf};
    my $pkey = $self->_getPid($pkeys);
    my $dlm = $conf->{delim}[0];
    my $valdlm = $conf->{valdelim}[0];
    my $rc = LDAP_SUCCESS;

    if (!defined($oconf->{file})) {
        return $rc;
    }

    my ($rdn_val) = ($dn =~ /^[^=]+=([^,]+),/);
    my $regex_rdn_val = $rdn_val;
    $regex_rdn_val =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
    $rdn_val = encode('utf8', $rdn_val);
    $regex_rdn_val = encode('utf8', $regex_rdn_val);

    my $lock;
    my $file;
    my $tmp;

    if (!defined($oconf->{mode}) || $oconf->{mode}[0] ne 'append') {
        if (!$self->_checkFile($oconf->{file}[0])) {
            return LDAP_OPERATIONS_ERROR;
        }
    }

    if (!open($lock, "> $oconf->{file}[0].lock")) {
        $self->log(level => 'alert', message => "Can't open $oconf->{file}[0].lock");
        return LDAP_OPERATIONS_ERROR;
    }
    flock($lock, 2);

    my $csv = Text::CSV_XS->new({binary => 1, allow_whitespace => 1, sep_char => $dlm});
    if (!$csv) {
        $self->log(level => 'err', message => "Can't use CSV_XS: ".Text::CSV_XS->error_diag());
        close($lock);
        return LDAP_OPERATIONS_ERROR;
    }

    if (defined($oconf->{mode}) && $oconf->{mode}[0] eq 'append') {
        if (!defined($oconf->{db})) {
            if (!open($file, ">> $oconf->{file}[0]")) {
                $self->log(level => 'alert', message => "Can't open $oconf->{file}[0]");
                close($lock);
                return LDAP_OPERATIONS_ERROR;
            }
        }
    } else {
        # check whether the entry already exists
        if (!rename($oconf->{file}[0], "$oconf->{file}[0].tmp")) {
            $self->log(level => 'alert', message => "Can't rename $oconf->{file}[0] to $oconf->{file}[0].tmp");
            close($lock);
            return LDAP_OPERATIONS_ERROR;
        }

        if (!open($tmp, "< $oconf->{file}[0].tmp")) {
            $self->log(level => 'alert', message => "Can't open $oconf->{file}[0].tmp");
            close($lock);
            return LDAP_OPERATIONS_ERROR;
        }

        if (!open($file, "> $oconf->{file}[0]")) {
            $self->log(level => 'alert', message => "Can't open $oconf->{file}[0]");
            close($tmp);
            close($lock);
            return LDAP_OPERATIONS_ERROR;
        }

        while (my $row = $csv->getline($tmp)) {
            if (!$csv->print($file, $row)) {
                $self->log(level => 'err', message => "Can't write CSV: ".$csv->error_diag());
                $rc = LDAP_OTHER;
                last DO;
            }
            print $file "\n";

            my @data = @$row;
            for (my $i = 0; $i < @data; $i++) {
                Encode::is_utf8($data[$i]) ? $data[$i] : Encode::from_to($data[$i], $conf->{mbcode}[0], 'utf8');
            }

            # check the data correspods to the dn
            if ("$valdlm$data[$oconf->{attr}{$oconf->{rdn}[0]}->{column}[0]]$valdlm" !~ /$valdlm *$regex_rdn_val *$valdlm/i) {
                next;
            }

            # entries below suffix
            if (defined($pkey) && defined($oconf->{container}) &&
                !defined($oconf->{container}[0]->{rdn})) {
                my $cur_pkey = $data[$oconf->{container}[0]->{idcolumn}[0]];
                if ($pkey !~ /^$cur_pkey$/i) {
                    next;
                }
            }

            $rc = LDAP_ALREADY_EXISTS;
            last;
        }
        close($tmp);
    }

    if (!$rc) {
        my @data;
        my $timestamp;

        DO: {
            foreach my $attr (keys %{$oconf->{attr}}) {
                my $coln;
                my @values = ($entryStr =~ /^$attr:\s(.*)$/gmi);
                if ($attr eq 'modifiersname') {
                    $values[0] = defined($self->{lism}->{bind}{edn}) ? $self->{lism}->{bind}{edn} : $self->{lism}->{bind}{dn};
                }
                if ($attr eq 'requestid') {
                    $values[0] = defined($self->{lism}->{bind}{reqid}) ? $self->{lism}->{bind}{reqid} : 0;
                }
                if ($attr eq 'modifytimestamp') {
                    $timestamp = $values[0];
                }

                for (my $i = 0; $i < @values; $i++) {
                    $values[$i] =~ s/$valdlm/\\3B/g;
                }

                if (defined($oconf->{attr}{$attr}->{rexpr})) {
                    foreach my $value (@values) {
                        my @colvals = ($value =~ $oconf->{attr}{$attr}->{rexpr_expr});
                        for (my $i = 0; $i < @colvals; $i++) {
                            my $colval = $data[$oconf->{attr}{$attr}->{rexpr_columns}[$i]];
                            if (!$colval) {
                                $colval = $colvals[$i];
                            } elsif ("$valdlm$colval$valdlm" !~ /$valdlm$colvals[$i]$valdlm/i) {
                                $colval = $colval.$valdlm.$colvals[$i];
                            }
                            $data[$oconf->{attr}{$attr}->{rexpr_columns}[$i]] = $colval;
                        }
                    }
                } else {
                    if (defined($oconf->{attr}{$attr}->{column})) {
                        $coln = $oconf->{attr}{$attr}->{column}[0];
                    } else {
                        my @keys;
                        $coln = $oconf->{attr}{$attr}->{idcolumn}[0];

                        # convert the value to object's id
                        ($rc, @keys) = $self->_getAttrKeys($oconf, $attr, @values);
                        if ($rc) {
                            $self->log(level => 'err', message => "Can't get id of $attr values in the file");
                            $rc = LDAP_OTHER;
                            last DO;
                        }
                        @values = @keys;
                    }

                    if ($data[$coln] =~ /^ *$/ || @values > split(/$valdlm/, $data[$coln])) {
                        $data[$coln] = join($valdlm, @values);
                    }
                }
            }

            if (defined($oconf->{op}[0]) && defined($oconf->{op}[0]->{add}[0])) {
                $data[$oconf->{op}[0]->{column}[0]] = $oconf->{op}[0]->{add}[0];
            }
            # add storage-specific information
            foreach my $strginfo (@{$oconf->{strginfo}}) {
                if (defined($strginfo->{column}) && defined($strginfo->{value})) {
                    my $value = $self->_getStaticValue($strginfo, $dn, $entryStr);
                    $data[$strginfo->{column}[0]] = $value;
                }
            }

            # add the link with container
            if (defined($pkey) && defined($oconf->{container}) &&
                defined($oconf->{container}[0]->{idcolumn})) {
                $data[$oconf->{container}[0]->{idcolumn}[0]] = $pkey;
            }

            if (!$csv->combine(@data)) {
                $self->log(level => 'err', message => "Can't combine CSV: ".$csv->error_diag());
                $rc = LDAP_OTHER;
                last DO;
            }

            my $line = $csv->string();
            if (!Encode::is_utf8($line)) {
                $line = decode_utf8($line);
            }
            if (defined($oconf->{db})) {
                if ($self->_dbInsert($oconf, $conf->{mbcode}[0] eq 'utf8' ? $line : Encode::from_to($line, 'utf8', $conf->{mbcode}[0]), $timestamp)) {
                    $rc = LDAP_OTHER;
                    last DO;
                }
            } else {
                print $file encode($conf->{mbcode}[0], $line)."\n";
            }
        }
    }
    if (!defined($oconf->{db})) {
        close($file);
    }
    close($lock);

    if ($rc) {
        $self->rollback();
    }

    return ($rc, (!defined($oconf->{mode}) || $oconf->{mode}[0] ne 'append' || !$rc) && defined($conf->{noaudit}) && $conf->{noaudit}[0] eq 'on' ? 'LISM_NO_OPERATION' : '');
}

=pod

=head2 _objDelete($obj, $pkeys, $dn)

Copy the object's file from which the appropriate record is deleted to the temporary file.

=cut

sub _objDelete
{
    my $self = shift;
    my ($obj, $pkeys, $dn) = @_;
    my $conf = $self->{_config};
    my $oconf = $obj->{conf};
    my $pkey = $self->_getPid($pkeys);
    my $dlm = $conf->{delim}[0];
    my $valdlm = $conf->{valdelim}[0];
    my $rc = LDAP_NO_SUCH_OBJECT;

    if (!defined($oconf->{file})) {
        return LDAP_SUCCESS;
    }

    my ($rdn_val) = ($dn =~ /^[^=]+=([^,]+),/);
    my $regex_rdn_val = $rdn_val;
    $regex_rdn_val =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
    $rdn_val = encode('utf8', $rdn_val);
    $regex_rdn_val = encode('utf8', $regex_rdn_val);

    my $lock;
    my $file;
    my $tmp;

    if (!defined($oconf->{mode}) || $oconf->{mode}[0] ne 'append') {
        if (!$self->_checkFile($oconf->{file}[0])) {
            return LDAP_OPERATIONS_ERROR;
        }
    }

    if (!open($lock, "> $oconf->{file}[0].lock")) {
        $self->log(level => 'alert', message => "Can't open $oconf->{file}[0].lock");
        return LDAP_OPERATIONS_ERROR;
    }
    flock($lock, 2);

    if (!defined($oconf->{mode}) || $oconf->{mode}[0] ne 'append') {
        if (!rename($oconf->{file}[0], "$oconf->{file}[0].tmp")) {
            $self->log(level => 'alert', message => "Can't rename $oconf->{file}[0] to $oconf->{file}[0].tmp");
            close($lock);
            return LDAP_OPERATIONS_ERROR;
        }

        if (!open($tmp, "< $oconf->{file}[0].tmp")) {
            $self->log(level => 'alert', message => "Can't open $oconf->{file}[0].tmp");
            close($lock);
            return LDAP_OPERATIONS_ERROR;
        }

        if (!open($file, "> $oconf->{file}[0]")) {
            $self->log(level => 'alert', message => "Can't open $oconf->{file}[0]");
            close($tmp);
            close($lock);
            return LDAP_OPERATIONS_ERROR;
        }

        my $csv = Text::CSV_XS->new({binary => 1, allow_whitespace => 1, sep_char => $dlm});
        if (!$csv) {
            $self->log(level => 'err', message => "Can't use CSV_XS: ".Text::CSV_XS->error_diag());
            close($tmp);
            close($lock);
            return LDAP_OPERATIONS_ERROR;
        }

        while (my $row = $csv->getline($tmp)) {
            my @data = @$row;
            for (my $i = 0; $i < @data; $i++) {
                Encode::is_utf8($data[$i]) ? $data[$i] : Encode::from_to($data[$i], $conf->{mbcode}[0], 'utf8');
            }

            # check the data corresponds to the dn
            if (!("$valdlm$data[$oconf->{attr}{$oconf->{rdn}[0]}{column}[0]]$valdlm" =~ /$valdlm$regex_rdn_val$valdlm/i)) {
                if (!$csv->print($file, $row)) {
                    $self->log(level => 'err', message => "Can't write CSV: ".$csv->error_diag());
                    $rc = LDAP_OTHER;
                    last DO;
                }
                print $file "\n";
                next;
            }

            # entries below suffix
            if (defined($pkey) && defined($oconf->{container}) &&
                !defined($oconf->{container}[0]->{rdn})) {
                my $cur_pkey = $data[$oconf->{container}[0]->{idcolumn}[0]];

                if (!($pkey =~ /^$cur_pkey$/i)) {
                    print $file $_."\n";
                    next;
                }
            }

            $rc = LDAP_SUCCESS;
        }
        close($file);
        close($tmp);
        close($lock);
    } else {
        if (!defined($oconf->{db})) {
            if (!open($file, ">> $oconf->{file}[0]")) {
                $self->log(level => 'alert', message => "Can't open $oconf->{file}[0]");
                close($lock);
                return LDAP_OPERATIONS_ERROR;
            }
        }
        my $csv = Text::CSV_XS->new({binary => 1, allow_whitespace => 1, sep_char => $dlm});
        if (!$csv) {
            $self->log(level => 'err', message => "Can't use CSV_XS: ".Text::CSV_XS->error_diag());
            close($lock);
            return LDAP_OPERATIONS_ERROR;
        }
        if (defined($oconf->{op}[0]) && defined($oconf->{op}[0]->{delete}[0])) {
            my @data;

            DO: {
                foreach my $attr (keys %{$oconf->{attr}}) {
                    if (defined($oconf->{attr}{$attr}->{column})) {
                        if ($attr eq 'modifiersname') {
                            $data[$oconf->{attr}{$attr}->{column}[0]] = defined($self->{lism}->{bind}{edn}) ? $self->{lism}->{bind}{edn} : $self->{lism}->{bind}{dn};
                        } elsif ($attr eq 'modifytimestamp') {
                            $data[$oconf->{attr}{$attr}->{column}[0]] = strftime("%Y%m%d%H%M%S", localtime(time))."Z";
                        } elsif ($attr eq 'requestid') {
                            $data[$oconf->{attr}{$attr}->{column}[0]] = defined($self->{lism}->{bind}{reqid}) ? $self->{lism}->{bind}{reqid} : 0;
                        } else {
                            $data[$oconf->{attr}{$attr}->{column}[0]] = "";
                        }
                    }
                }
                $data[$oconf->{op}[0]->{column}[0]] = $oconf->{op}[0]->{delete}[0];
                $data[$oconf->{attr}{$oconf->{rdn}[0]}{column}[0]] = $rdn_val;

                foreach my $strginfo (@{$oconf->{strginfo}}) {
                    if (defined($strginfo->{column}) && defined($strginfo->{value})) {
                        my $value = $self->_getStaticValue($strginfo, $dn, "");
                        $data[$strginfo->{column}[0]] = $value;
                    }
                }

                if (defined($pkey) && defined($oconf->{container}) &&
                    defined($oconf->{container}[0]->{idcolumn})) {
                    $data[$oconf->{container}[0]->{idcolumn}[0]] = $pkey;
                }
                if (!$csv->combine(@data)) {
                    $self->log(level => 'err', message => "Can't combine CSV: ".$csv->error_diag());
                    $rc = LDAP_OTHER;
                    last DO;
                }
                my $line = $csv->string();
                if (!Encode::is_utf8($line)) {
                    $line = decode_utf8($line);
                }
                if (defined($oconf->{db})) {
                    if ($self->_dbInsert($oconf, $conf->{mbcode}[0] eq 'utf8' ? $line : Encode::from_to($line, 'utf8', $conf->{mbcode}[0]), strftime("%Y%m%d%H%M%S", localtime(time))."Z")) {
                        $rc = LDAP_OTHER;
                        last DO;
                    }
                } else {
                    print $file encode($conf->{mbcode}[0], $line)."\n";
                }
            }
        }
        $rc = LDAP_SUCCESS;
        if (!defined($oconf->{db})) {
            close($file);
        }
        close($lock);
    }

    if ($rc) {
        $self->rollback();
    }

    return ($rc, (!defined($oconf->{mode}) || $oconf->{mode}[0] ne 'append' || !$rc) && defined($conf->{noaudit}) && $conf->{noaudit}[0] eq 'on' ? 'LISM_NO_OPERATION' : '');
}

sub _getParentRdn
{
    my $self = shift;
    my ($obj, $key, $pobj) = @_;
    my $conf = $self->{_config};
    my $oconf = $obj->{conf};
    my $poconf = $pobj->{conf};
    my $dlm = $conf->{delim}[0];
    my $prdn = undef;
    my $pkey = undef;

    if (defined($oconf->{container}[0]->{rdn})) {
        return $oconf->{container}[0]->{rdn}[0];
    }
    if (!defined($oconf->{container}[0]->{oname})) {
        return undef;
    }

    my ($file, $lock) = $self->_openRead($oconf);
    if (!defined($file)) {
        return undef;
    }

    my $csv = Text::CSV_XS->new({binary => 1, allow_whitespace => 1, sep_char => $dlm});
    if (!$csv) {
        $self->log(level => 'err', message => "Can't use CSV_XS: ".Text::CSV_XS->error_diag());
        return undef;
    }

    while (my $row = $csv->getline($file)) {
        my @data = @$row;
        for (my $i = 0; $i < @data; $i++) {
            Encode::is_utf8($data[$i]) ? $data[$i] : Encode::from_to($data[$i], $conf->{mbcode}[0], 'utf8');
        }

        # check the data corresponds to the object's id
        if ($data[$oconf->{id}[0]->{column}[0]] =~ /^$key$/i) {
            $pkey = $data[$oconf->{container}[0]->{idcolumn}[0]];
            last;
        }
    }

    if ($self->_close($file, $lock, $oconf)) {
        return undef;
    }

    ($file, $lock) = $self->_openRead($poconf);
    if (!defined($file)) {
        return undef;
    }

    while (my $row = $csv->getline($file)) {
        my @data = @$row;
        for (my $i = 0; $i < @data; $i++) {
            Encode::is_utf8($data[$i]) ? $data[$i] : Encode::from_to($data[$i], $conf->{mbcode}[0], 'utf8');
        }

        # check the data corresponds to the object's id
        if ($data[$poconf->{id}[0]->{column}[0]] =~ /^$pkey$/i) {
            my $rdn_val = $data[$poconf->{attr}{$poconf->{rdn}[0]}->{column}[0]];
            $rdn_val =~ s/ *$//;
            $prdn = "$poconf->{rdn}[0]=$rdn_val";
            last;
        }
    }
    if ($self->_close($file, $lock, $poconf)) {
        return undef;
    }

    return ($prdn, $pkey);
}

sub _getAttrValues
{
    my $self = shift;
    my ($oconf, $attr, @keys) = @_;
    my $conf = $self->{_config};
    my $dlm = $conf->{delim}[0];
    my $aobj = undef;
    my $aoconf = undef;
    my $attrStr = '';
    my @colnums;
    my $filename;

    my $file;
    my $lock;
    if (defined($oconf->{attr}{$attr}->{oname})) {
        $aobj = $self->{object}{$oconf->{attr}{$attr}->{oname}[0]};
        $aoconf = $aobj->{conf};
        ($file, $lock) = $self->_openRead($aoconf);
    } elsif (defined($oconf->{attr}{$attr}->{file})) {
        @colnums = ($oconf->{attr}{$attr}->{value}[0] =~ /%([0-9]+)/g);
        ($file, $lock) = $self->_openRead($oconf->{attr}{$attr});
    } else {
        return undef;
    }

    if (!defined($file)) {
        return undef;
    }

    my $csv = Text::CSV_XS->new({binary => 1, allow_whitespace => 1, sep_char => $dlm});
    if (!$csv) {
        $self->log(level => 'err', message => "Can't use CSV_XS: ".Text::CSV_XS->error_diag());
        return undef;
    }

    while (my $row = $csv->getline($file)) {
        my @data = @$row;
        for (my $i = 0; $i < @data; $i++) {
            Encode::is_utf8($data[$i]) ? $data[$i] : Encode::from_to($data[$i], $conf->{mbcode}[0], 'utf8');
        }

        # check the data corresponds to the object's id
        for (my $i = 0; $i < @keys; $i++) {
            if (defined($aoconf)) {
                if ($data[$aoconf->{id}[0]->{column}[0]] =~ /^$keys[$i]$/i) {
                    my $rdn_val = $data[$aoconf->{attr}{$aoconf->{rdn}[0]}->{column}[0]];
                    $rdn_val =~ s/ *$//;
                    $attrStr = $attrStr."$attr: $aoconf->{rdn}[0]=$rdn_val,".$self->_getParentDn($aobj, $data[$aoconf->{id}[0]->{column}[0]])."\n";
                    splice(@keys, $i, 1);
                    last;
                }
            } else {
                if ($data[$oconf->{attr}{$attr}->{id}[0]->{column}[0]] =~ /^$keys[$i]/i) {
                    my $value = $oconf->{attr}{$attr}->{value}[0];
                    foreach my $coln (@colnums) {
                        $value =~ s/%$coln/$data[$coln]/g;
                    }
                    $value =~ s/ *$//;

                    if ($value) {
                        $attrStr = $attrStr."$attr: $value\n";
                        splice(@keys, $i, 1);
                    }
       	            last;
                }
	    }
        }

        if (!@keys) {
            last;
        }
    }

    if ($self->_close($file, $lock, $oconf->{attr}{$attr})) {
        return undef;
    }

    # Values not got exist
    if (@keys) {
        return undef;
    }

    return $attrStr;
}

sub _getAttrKeys
{
    my $self = shift;
    my ($oconf, $attr, @values) = @_;
    my $conf = $self->{_config};
    my $dlm = $conf->{delim}[0];
    my @attrkeys = ();
    my $rc = 0;

    if (defined($oconf->{attr}{$attr}->{oname})) {
        for (my $i = 0; $i < @values && $values[$i]; $i++) {
            my $aobj;
            my $attrkey;
            my $attrpkeys;

            ($rc, $aobj, $attrpkeys) = $self->_getObject($values[$i]);
            if ($rc) {
                return (-1, ());
            }

            ($rc, $attrkey) =$self->_baseSearch($aobj, $attrpkeys, $values[$i], 0, 0, 1, 0, undef, 0, ('dn'));
            if ($rc || !$attrkey) {
                return (-1, ());
            }

            push(@attrkeys, $attrkey);
        }
    } elsif (defined($oconf->{attr}{$attr}->{file})) {
        my ($file, $lock) = $self->_openRead($oconf->{attr}{$attr});
        if (!defined($file)) {
            return LDAP_OPERATIONS_ERROR;
        }

        my $csv = Text::CSV_XS->new({binary => 1, allow_whitespace => 1, sep_char => $dlm});
        if (!$csv) {
            $self->log(level => 'err', message => "Can't use CSV_XS: ".Text::CSV_XS->error_diag());
            return LDAP_OPERATIONS_ERROR;
        }

        my @colnums = ($oconf->{attr}{$attr}->{value}[0] =~ /%([0-9]+)/g);
        (my $replace = $oconf->{attr}{$attr}->{value}[0]) =~ s/([*+\/\.^$()\[\]])/\\$1/g;
        $replace =~ s/%[0-9]+/(.+)/ig;

        my @avals;
        for (my $i = 0; $i < @values && $values[$i]; $i++) {
            $avals[$i] = join(';', ($values[$i] =~ /^$replace$/));
        }

        while (my $row = $csv->getline($file)) {
            if (!@avals) {
                last;
            }

            my @data = @$row;
            for (my $i = 0; $i < @data; $i++) {
                Encode::is_utf8($data[$i]) ? $data[$i] : Encode::from_to($data[$i], $conf->{mbcode}[0], 'utf8');
            }

            my $dvals;
            foreach my $coln (@colnums) {
                $data[$coln] =~ s/ *$//;
                if ($dvals) {
                    $dvals = "$dvals;$data[$coln]";
                } else {
                    $dvals = $data[$coln];
                }
            }

            # check the data corresponds to the object's id
            for (my $i = 0; $i < @avals; $i++) {
                if ($dvals =~ /^$avals[$i]$/i) {
                    push(@attrkeys, $data[$oconf->{attr}{$attr}->{id}[0]->{column}[0]]);
                    splice(@avals, $i, 1);
                    last;
		}
	    }
        }

        if ($self->_close($file, $lock, $oconf->{attr}{$attr})) {
            return (-1, ());
        }

        # Values not added exist
        if (@avals) {
            return (-1, ());
        }
    } else {
        return (-1, ());
    }

    return ($rc, @attrkeys);
}

sub _checkFile
{
    my $self = shift;
    my ($filename) = @_;

    if (!-f $filename) {
        my $file;

        if (!open($file, "> $filename")) {
            $self->log(level => 'alert', message => "Can't create $filename");
            return 0;
        }
        close($file);
    }

    return 1;
}

sub _openRead
{
    my $self = shift;
    my ($oconf, $suffix) = @_;
    my $file;
    my $lock;
    $suffix = defined($suffix) ? $suffix : '';

    if (defined($oconf->{file})) {
        if (!$self->_checkFile($oconf->{file}[0])) {
            return undef;
        }

        if (!open($lock, "> $oconf->{file}[0].lock")) {
            $self->log(level => 'alert', message => "Can't open $oconf->{file}[0].lock");
            return undef;
        }
        flock($lock, 1);

        if (!open($file, "< $oconf->{file}[0]")) {
            $self->log(level => 'alert', message => "Can't open $oconf->{file}[0]");
            close($lock);
            return undef;
        }
    } elsif (defined($oconf->{command})) {
        my $command = $oconf->{command}[0];
        $command =~ s/\%b/$suffix/g;
        if (!open($file, "$command|")) {
            $self->log(level => 'alert', message => "Can't open \"$command\"");
            return undef;
        }
    }

    return ($file, $lock);
}

sub _close
{
    my $self = shift;
    my ($file, $lock, $oconf) = @_;
    my $rc = 0;

    close($file);

    if ($lock) {
        close($lock);
    }

    return $rc;
}

sub _getConnect
{
    my $self = shift;
    my $conf = $self->{_config};

    if (defined($conf->{db})) {
        return $self->_dbConnect(\$self->{db});
    }

    return 0;
}

sub _dbConnect
{
    my $self = shift;
    my ($db) = @_;
    my $conf = $self->{_config};

    if (defined(${$db})) {
        return 0;
    }

    ${$db} = DBI->connect($conf->{db}[0]->{dsn}, $conf->{db}[0]->{admin}, $conf->{db}[0]->{passwd});
    if (!${$db}) {
        $self->log(level => 'alert', message => "Can't connect $conf->{db}[0]->{dsn}: ".$DBI::errstr);
        return -1;
    }

    return 0;
}

sub _dbInsert
{
    my $self = shift;
    my ($oconf, $line, $timestamp) = @_;

    my $sql;
    if (defined($oconf->{db}[0]->{timestamp})) {
        $sql = "insert into $oconf->{db}[0]->{table}($oconf->{db}[0]->{column}, $oconf->{db}[0]->{timestamp}) values(?, ?)";
        if (!$timestamp) {
            $timestamp = strftime("%Y%m%d%H%M%S", localtime(time))."Z";
        }
    } else {
        $sql = "insert into $oconf->{db}[0]->{table}($oconf->{db}[0]->{column}) values(?)";
    }
    my $sth = $self->{db}->prepare($sql);
    my $rc = 0;
    if (!$sth) {
        $rc = -1;
    } else {
        if (defined($oconf->{db}[0]->{timestamp})) {
            if (!$sth->execute($line, $timestamp)) {
                $rc = -1;
            }
        } else {
            if (!$sth->execute($line)) {
                $rc = -1;
            }
        }
    }
    if ($rc) {
        $self->log(level => 'err', message => "Inserting csv record by \"$sql\" failed: ".$sth->errstr);
        undef($self->{db});
        if ($self->_dbConnect(\$self->{db})) {
            return -1;
        }
        $rc = 0;
        $sth = $self->{db}->prepare($sql);
        if (!$sth) {
            $rc = -1;
        } else {
            if (defined($oconf->{db}[0]->{timestamp})) {
                if (!$sth->execute($line, $timestamp)) {
                    $rc = -1;
                }
            } else {
                if (!$sth->execute($line)) {
                    $rc = -1;
                }
            }
        }
        if ($rc) {
            $self->log(level => 'err', message => "Inserting csv record by \"$sql\" failed: retry=1 ".$sth->errstr);
            undef($self->{db});
            return -1;
        }
    }
    $sth->finish;

    return 0;
}

=head1 SEE ALSO

L<LISM>,
L<LISM::Storage>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
