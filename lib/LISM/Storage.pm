package LISM::Storage;

use strict;
use Module::Load qw(load);
use LISM::Constant;
use Digest::MD5;
use Digest::SHA1;
use Digest::SHA qw(hmac_sha1 hmac_sha256 hmac_sha512);
use Crypt::CBC;
use MIME::Base64;
use POSIX;
use Encode;
use Scalar::Util qw(weaken);
use Data::Dumper;
if ($^O ne 'MSWin32') {
    eval "load(Secioss::Auth::Util, 'openlog', 'syslog')";
    if ($@) {
        load(Sys::Syslog, 'openlog', 'syslog');
    }
    use Sys::Syslog qw(:macros);
} else {
    load(Log::Dispatch::FileRotate);
}

our $controlAttr = 'lismControl';
our $maxLoopCount = 10;

=head1 NAME

LISM::Storage - an base class for LISM storage implementations

=head1 DESCRIPTION

This class is meant as an interface to access arbitrary storage.

=head1 CONSTRUCTOR

This is a plain constructor.

=cut

sub new
{
    my $class = shift;
    my ($suffix, $contentry, $lism) = @_;

    my $this = {};
    bless $this, $class;

    $this->{suffix} = $suffix;
    $this->{contentrystr} = $contentry;
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

=head2 commit

This method is called when L<LISM> commit the update of storage.

=cut

sub commit
{
    return 0;
}

=pod

=head2 rollback

This method is called when L<LISM> rollback the update of storage.

=cut

sub rollback
{
    return 0;
}

=pod

=head2 bind

This method is called when L<LISM> do the bind operation.
Returns 0 if the authentication succeeds.

=cut

sub bind
{
    my $self = shift;
    my($binddn, $passwd) = @_;
    my $conf = $self->{_config};

    if ($self->_getConnect()) {
        return LDAP_SERVER_DOWN;
    }

    my ($rc, $obj, $pkeys) = $self->_getObject($binddn);
    if ($rc) {
        return $rc;
    }

    DO: {
        my $entry;
        my $key;

        ($rc, $key, $entry) = $self->_baseSearch($obj, $pkeys, $binddn, 0, 0, 1, 0, undef);
        if ($rc) {
            last DO;
        }
        my ($usrpwd) = ($entry =~ m#^(userpassword:.*)$#m);

        # hash the password
        my $hash = $self->_pwdFormat("userpassword: ".$self->hashPasswd($passwd, substr($usrpwd, 0, 2)));

        # validate the password
        if ($usrpwd ne $hash) {
            $rc = LDAP_INVALID_CREDENTIALS;
        }
    }

    $self->_freeConnect();

    return $rc;
}

=pod

=head2 search

This method is called when L<LISM> do the search operation.
Returns 0 if it completes successfully.

=cut

sub search
{
    my $self = shift;
    my($base, $scope, $deref, $sizeLim, $timeLim, $filterStr, $attrOnly, @attrs ) = @_;
    my $conf = $self->{_config};
    my @match_entries = ();

    $base =~ s/\\22/"/gi;
    $base =~ s/\\23/#/gi;
    $base =~ s/\\2B/+/gi;
    $base =~ s/\\2F/\//gi;
    $base =~ s/\\3B/;/gi;
    $base =~ s/\\3C/</gi;
    $base =~ s/\\3E/>/gi;
    $base =~ s/\\3D/=/gi;
    $base =~ s/\\5C/\\/gi;
    $base =~ s/\\(?=[+#"])//gi;

    if ($filterStr =~ /^\(&\($controlAttr=[^\)]+\)/i) {
        $filterStr =~ s/^\(&\($controlAttr=[^\)]+\)//;
        $filterStr =~ s/\)$//;
    }

    my $filter = Net::LDAP::Filter->new($filterStr);
    if (!defined($filter)) {
        return (LDAP_FILTER_ERROR, ());
    }

    if (!$sizeLim) {
        $sizeLim = -1;
    }

    my $retry = 0;
    while (1) {
        if (!$self->_getConnect()) {
            last;
        }

        if ($retry >= $conf->{connection}[0]->{retry}[0]) {
            return (LDAP_SERVER_DOWN, ());
        }
        sleep $conf->{connection}[0]->{interval}[0];
        $retry++;
    }

    my ($rc, @objs) = $self->_searchObjects($base, $scope);
    if ($rc) {
        return ($rc, @match_entries);
    }

    # get entry of data container
    if ($base =~ /^$self->{suffix}$/i) {
        if ($scope != 1) {
            my $entry = $self->{contentrystr};
            if ($self->parseFilter($filter, $entry)) {
                push (@match_entries, $entry);
                $sizeLim--;
            }
        }
    }

    foreach my $objinfo (@objs) {
        my ($obj, $pkeys) = @{$objinfo};
        my $objbase = $base =~ /^$self->{suffix}$/i ? $obj->{suffix} : $base;
        my $objscope;
        my $entry;
        my $key;

        if ($scope == 1 && $base =~ /^$self->{suffix}$/i && $obj->{entrystr}) {
            $objscope = 0;
        } else {
            $objscope = $scope;
        }

        # search base entry
        ($rc, $key, $entry) = $self->_baseSearch($obj, $pkeys, $objbase, 0, $deref, $sizeLim, $timeLim, undef, $attrOnly, @attrs);
        if ($rc) {
            last;
        }

        # don't search children if entry doesn't exist
        if (!$entry && $base !~ /^$self->{suffix}$/i) {
            if ($scope == 0) {
                return LDAP_NO_SUCH_OBJECT;
            } else {
                next;
            }
        } elsif ($objscope !=1 && $self->parseFilter($filter, $entry)) {
            push(@match_entries, $entry);
            $sizeLim = $sizeLim - 1;
        }

        # search entries below base
        my @entries;
        my $keys;

        ($rc, $keys, @entries) = $self->_childSearch($obj, [@{$pkeys}, $key], $objbase, $objscope, $deref, $sizeLim, $timeLim, $filter, $attrOnly, @attrs);
        push(@match_entries, @entries);
        $sizeLim = $sizeLim - @entries;

        if ($rc) {
            last;
        }
    }

    $self->_freeConnect();

    if ($rc && $rc != LDAP_SIZELIMIT_EXCEEDED) {
        @match_entries = ();
    }

    return ($rc, @match_entries);
}

=pod

=head2 compare

This method is called when L<LISM> do the compare operation.
Returns 6 if the compared value exist, 5 if it doesn't exist.

=cut

sub compare
{
    my $self = shift;
    my ($dn, $avaStr) = @_;
    my $conf = $self->{_config};

    my ($attr, $val) = split(/=/, $avaStr);

    my $retry = 0;
    while (1) {
        if (!$self->_getConnect()) {
            last;
        }

        if ($retry >= $conf->{connection}[0]->{retry}[0]) {
            return LDAP_SERVER_DOWN;
        }
        sleep $conf->{connection}[0]->{interval}[0];
        $retry++;
    }

    my ($rc, $obj, $pkeys) = $self->_getObject($dn);
    if ($rc) {
        return $rc;
    }

    DO: {
        my $entry;
        my $key;

        ($rc, $key, $entry) = $self->_baseSearch($obj, $pkeys, $dn, 0, 0, 1, 0, undef);
        if ($rc) {
            last DO;
        }

        # compare the value
        if ($entry =~ /^$attr: $val$/m) {
            $rc = LDAP_COMPARE_TRUE;
        } else {
            $rc = LDAP_COMPARE_FALSE;
        }
    }

    $self->_freeConnect();

    return $rc;
}

=pod

=head2 modify

This method is called when L<LISM> do the modify operation.
Returns 0 if it completes successfully.

=cut

sub modify
{
    my $self = shift;
    my ($dn, @list) = @_;
    my $conf = $self->{_config};
    $dn =~ s/\\22/"/gi;
    $dn =~ s/\\23/#/gi;
    $dn =~ s/\\2B/+/gi;
    $dn =~ s/\\2F/\//gi;
    $dn =~ s/\\3B/;/gi;
    $dn =~ s/\\3C/</gi;
    $dn =~ s/\\3E/>/gi;
    $dn =~ s/\\3D/=/gi;
    $dn =~ s/\\5C/\\/gi;
    $dn =~ s/\\(?=[+#"])//gi;

    my $retry = 0;
    while (1) {
        if (!$self->_getConnect()) {
            last;
        }

        if ($retry >= $conf->{connection}[0]->{retry}[0]) {
            return LDAP_SERVER_DOWN;
        }
        sleep $conf->{connection}[0]->{interval}[0];
        $retry++;
    }

    my ($rc, $obj, $pkeys) = $self->_getObject($dn);
    if ($rc) {
        return $rc;
    }

    return $self->_objModify($obj, $pkeys, $dn, @list);
}

=pod

=head2 add

This method is called when L<LISM> do the add operation.
Returns 0 if it completes successfully.

=cut

sub add
{
    my $self = shift;
    my ($dn, $entryStr) = @_;
    my $conf = $self->{_config};
    $dn =~ s/\\22/"/gi;
    $dn =~ s/\\23/#/gi;
    $dn =~ s/\\2B/+/gi;
    $dn =~ s/\\2F/\//gi;
    $dn =~ s/\\3B/;/gi;
    $dn =~ s/\\3C/</gi;
    $dn =~ s/\\3E/>/gi;
    $dn =~ s/\\3D/=/gi;
    $dn =~ s/\\5C/\\/gi;
    $dn =~ s/\\(?=[+#"])//gi;

    # check rdn's value
    my ($rdn, $rdn_val) = ($dn =~ /^([^=]+)=([^,]+),/);
    $rdn_val = $self->_unescapedn($rdn_val);
    $rdn_val =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
    if ($entryStr !~ /^$rdn: $rdn_val *$/mi) {
        return LDAP_NAMING_VIOLATION;
    }

    my $retry = 0;
    while (1) {
        if (!$self->_getConnect()) {
            last;
        }

        if ($retry >= $conf->{connection}[0]->{retry}[0]) {
            return LDAP_SERVER_DOWN;
        }
        sleep $conf->{connection}[0]->{interval}[0];
        $retry++;
    }

    my ($rc, $obj, $pkeys) = $self->_getObject($dn);
    if ($rc) {
        return $rc;
    }

    return $self->_objAdd($obj, $pkeys, $dn, $entryStr);
}

=pod

=head2 modrdn

This method is called when L<LISM> do the modrdn operation.
Returns 0 if it completes successfully.

=cut

sub modrdn
{
    my $self = shift;
    my ($dn, $newrdn, $delFlag) = @_;
    my $rc;
    my $error;
    my $entry;

    my ($rdn_attr, $superior) = ($dn =~ /^([^=]*)=[^,]*,(.*)$/);

    ($rc, $entry) = $self->search($dn, 0, 0, 1, 0, "(objectClass=*)", 0, ());
    if ($rc) {
        return $rc;
    }

    my ($newval) = ($newrdn =~ /^$rdn_attr=(.*)$/i);
    $entry =~ s/^dn:.*\n//;
    $entry =~ s/^$rdn_attr: .*$/$rdn_attr: $newval/mi;
    my ($passwd) = ($entry =~ /^userpassword: (.*)$/mi);
    if ($passwd) {
        $passwd = $self->hashPasswd($passwd);
        $entry =~ s/^userpassword: .*$/userpassword: $passwd/mi;
    }

    ($rc, $error) = $self->add("$newrdn,$superior", $entry);
    if ($rc) {
        return ($rc, $error);
    }

    if ($delFlag) {
        ($rc, $error) = $self->delete($dn);
    }

    return ($rc, $error);
}

=pod

=head2 delete

This method is called when L<LISM> do the delete operation.
Returns 0 if it completes successfully.

=cut

sub delete
{
    my $self = shift;
    my ($dn) = @_;
    my $conf = $self->{_config};
    $dn =~ s/\\22/"/gi;
    $dn =~ s/\\23/#/gi;
    $dn =~ s/\\2B/+/gi;
    $dn =~ s/\\2F/\//gi;
    $dn =~ s/\\3B/;/gi;
    $dn =~ s/\\3C/</gi;
    $dn =~ s/\\3E/>/gi;
    $dn =~ s/\\3D/=/gi;
    $dn =~ s/\\5C/\\/gi;
    $dn =~ s/\\(?=[+#"])//gi;

    my $retry = 0;
    while (1) {
        if (!$self->_getConnect()) {
            last;
        }

        if ($retry >= $conf->{connection}[0]->{retry}[0]) {
            return LDAP_SERVER_DOWN;
        }
        sleep $conf->{connection}[0]->{interval}[0];
        $retry++;
    }

    my ($rc, $obj, $pkeys) = $self->_getObject($dn);
    if ($rc) {
        return $rc;
    }
    my @pkeyarr = @{$pkeys};

    if ($obj->{conf}->{subcontainer}) {
        if ($dn !~ /,$obj->{conf}->{subcontainer}[0]->{rdn}[0],/i &&
            $dn =~ /^$obj->{conf}->{subcontainer}[0]->{rdn}[0],/i) {
            return LDAP_UNWILLING_TO_PERFORM;
        }
    }

    my $key;

    ($rc, $key) = $self->_baseSearch($obj, $pkeys, $dn, 0, 0, 1, 0, undef);
    if ($rc) {
        return $rc;
    }

    my @children;
    my $keys;
    ($rc, $keys, @children) = $self->_childSearch($obj, [@{$pkeys}, $key], $dn, 1, 0, 1, 0, undef);
    if ($rc) {
        return $rc;
    } elsif (@children) {
        return LDAP_NOT_ALLOWED_ON_NONLEAF;
    }

    return $self->_objDelete($obj, $pkeys, $dn);
}

=pod

=head2 move

This method is called when L<LISM> do the move operation.
Returns 0 if it completes successfully.

=cut

sub move
{
    my $self = shift;
    my ($dn, $parentdn) = @_;
    my $conf = $self->{_config};

    my $retry = 0;
    while (1) {
        if (!$self->_getConnect()) {
            last;
        }

        if ($retry >= $conf->{connection}[0]->{retry}[0]) {
            return LDAP_SERVER_DOWN;
        }
        sleep $conf->{connection}[0]->{interval}[0];
        $retry++;
    }

    my ($rc, $obj, $pkeys) = $self->_getObject($dn);
    if ($rc) {
        return $rc;
    }

    my $newobj;
    my $newpkeys;
    my ($rdn) = ($dn =~ /^([^,]+),/);
    ($rc, $newobj, $newpkeys) = $self->_getObject("$rdn,$parentdn");
    if ($rc) {
        return $rc;
    }

    if ($obj != $newobj) {
        return LDAP_UNWILLING_TO_PERFORM;
    }

    return $self->_objMove($obj, $pkeys, $dn, $newpkeys, "$rdn,$parentdn");
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
    }
    $p{'message'} = uc($p{'level'}).' ['.ref($self).'] '.$p{'message'};

    if ($^O ne 'MSWin32') {
        openlog('LISM', 'pid', $self->{lism}->{_config}->{syslogfacility});
        syslog($p{'level'}, $p{'message'});
    } else {
        $self->{log}->log(level => $p{'level'}, message => strftime("%Y/%m/%d %H:%M:%S", localtime(time))." ".$p{'message'}."\n");
    }

    if (defined($conf->{printlog}) && $conf->{printlog} =~ /$p{'level'}/) {
        print $p{'message'}."\n";
    }
}

=pod

=head2 cmpPasswd($passwd, $hashedpwd, $pwhash)

compare the password with hashed password.

=cut

sub cmpPasswd
{
    my $self = shift;
    my ($passwd, $hashedpwd, $pwhash) = @_;

    my $oldhash;
    my $newhash;
    if ($pwhash eq 'SSHA' || $pwhash eq 'SSHA512') {
        my $hash_length = $pwhash eq 'SSHA512' ? 64 : 20;
        my $salt = substr(decode_base64($hashedpwd), $hash_length);
        $oldhash = $hashedpwd;
        $newhash = $self->hashPasswd($passwd, $salt, $pwhash);
    } elsif ($pwhash eq 'PBKDF2_SHA256') {
        my $iter_length = 4;
        my $key_length = 256;
        my $hash = decode_base64($hashedpwd);
        my $iter_bytes = substr($hash, 0, $iter_length);
        my $iter = unpack("N1", $iter_bytes);
        my $salt = substr($hash, $iter_length, $key_length * -1);
        $oldhash = substr($hash, $key_length * -1);
        $newhash = $self->pbkdf2('SHA256', $passwd, $salt, $iter);
    } elsif ($pwhash eq 'CRYPT') {
        my $salt = substr($hashedpwd, 0, 2);
        $oldhash = $hashedpwd;
        $newhash = $self->hashPasswd($passwd, $salt, $pwhash);
    } else {
        $oldhash = $hashedpwd;
        $newhash = $self->hashPasswd($passwd, undef, $pwhash);
    }
    $newhash =~ s/\n$//;

    return $oldhash eq $newhash;
}

=pod

=head2 hashPasswd($passwd, $salt, $pwhash)

hash the password if it isn't done.

=cut

sub hashPasswd
{
    my $self = shift;
    my ($passwd, $salt, $pwhash) = @_;

    if (!defined($pwhash)) {
        my $conf = $self->{_config};
        $pwhash = $conf->{hash};
    }

    my $hashpw;
    my $iter = 2048;
    my ($htype, $otype, $num) = split(/:/, $pwhash);
    if (!$num) {
        $num = 1;
    } else {
        $iter = $num;
    }

    my ($pwhtype) = ($passwd =~ /^\{([^\}]+)\}/);
    if ($pwhtype) {
        # already hashed password
        if ($pwhtype ne $htype) {
            if ($htype eq 'PLAINTEXT') {
                return $passwd;
            } else {
                return undef;
            }
        }

        $passwd =~ s/^\{[^\}]+\}//;
        if ($otype =~ /^hex$/i && $htype =~ /^MD5|SHA$/i) {
            $passwd = unpack("H*", decode_base64($passwd));
        }

        return $passwd;
    }

    if ($htype =~ /^(CRYPT|MD5|SHA|SSHA|SSHA512|PBKDF2_SHA256)$/i && Encode::is_utf8($passwd)) {
        $passwd = encode('utf8', $passwd);
    }

    # hash the password
    for (my $i = 0; $i < $num; $i++) {
        if ($htype =~ /^SSHA$/i) {
            if (!$salt) {
                $salt = Crypt::CBC->random_bytes(4);
            }
            my $ctx = Digest::SHA1->new;
            $ctx->add($passwd.$salt);
            $hashpw = encode_base64($ctx->digest.$salt);
        } elsif ($htype =~ /^SSHA512$/i) {
            if (!$salt) {
                $salt = Crypt::CBC->random_bytes(8);
            }
            my $ctx = Digest::SHA->new(512);
            $ctx->add($passwd.$salt);
            $hashpw = encode_base64($ctx->digest.$salt);
        } elsif ($htype =~ /^CRYPT$/i) {
            my @chars = ('a'..'z', 'A'..'Z', '0'..'9');
            if (!$salt) {
                $salt .= $chars[int(rand($#chars + 1))] for (1..10);
            }
            $hashpw = crypt($passwd, $salt);
        } elsif ($htype =~ /^MD5$/i) {
            my $ctx = Digest::MD5->new;
            $ctx->add($passwd);
            if ($otype && $otype =~ /^hex$/i) {
                $hashpw = $ctx->hexdigest;
            } else {
                $hashpw = $ctx->b64digest.'==';
            }
        } elsif ($htype =~ /^SHA$/i) {
            my $ctx = Digest::SHA1->new;
            $ctx->add($passwd);
            if ($otype && $otype =~ /^hex$/i) {
                $hashpw = $ctx->hexdigest;
            } else {
                $hashpw = $ctx->b64digest.'=';
            }
        } elsif ($htype =~ /^PBKDF2_SHA256$/i) {
            if (!$salt) {
                $salt = Crypt::CBC->random_bytes(64);
            }
            my $hash = $self->pbkdf2('SHA256', $passwd, $salt, $iter);
            return encode_base64(pack("N1", $iter).$salt.$hash);
        } else {
            $hashpw = $passwd;
        }
        $passwd = $hashpw;
    }

    return $hashpw;
}
 

=pod

=head2 pbkdf2($algo, $str, $salt, $iter);

hash the string with PBKDF2

=cut

sub pbkdf2
{
    my $self = shift;
    my ($algo, $str, $salt, $iter) = @_;

    my $hash_len;
    my $key_len;
    if ($algo eq 'SHA256') {
        $hash_len = 32;
        $key_len = 256;
    } elsif ($algo eq 'SHA512') {
        $hash_len = 64;
        $key_len = 512;
    } else {
        $hash_len = 20;
        $key_len = 160;
    }
    my $m = int($key_len / $hash_len);
    if ($key_len % $hash_len != 0) {
        $m += 1;
    }

    my $hash = '';
    for (my $i = 1; $i <= $m; $i++) {
        my $u = "";
        my $t = "";
        for (my $j = 0; $j < $iter; $j++) {
            if (!$u) {
                $u = $salt.pack("N1", $i);
            }
            if ($algo eq 'SHA256') {
                $u = hmac_sha256($u, $str);
            } elsif ($algo eq 'SHA512') {
                $u = hmac_sha512($u, $str);
            } else {
                $u = hmac_sha1($u, $str);
            }
            if (!$t) {
                $t = $u;
            } else {
                $t ^= $u;
            }
        }
        $hash .= $t;
    }
    return $hash;
}

=pod

=head2 hashType();

get hash type.

=cut

sub hashType
{
    my $self = shift;
    my $conf = $self->{_config};

    my ($htype, $otype) = split(/:/, $conf->{hash});

    return $htype;
}

=pod

=head2 parseFilter($filter, $entry)

parse filter and check entry matching.

=cut

sub parseFilter
{
    my $self = shift;
    my ($filter, $entry) = @_;

    if (!$entry) {
        return 0;
    }

    if (!$filter) {
        return 1;
    }

    # get operand and arguments
    my ($op) = keys %{$filter};
    my $args = $filter->{$op};

    if ($op eq 'and') {
        return $self->parseFilter(@{$args}[0], $entry) & $self->parseFilter(@{$args}[1], $entry);
    } elsif ($op eq 'or') {
        return $self->parseFilter(@{$args}[0], $entry) | $self->parseFilter(@{$args}[1], $entry);
    } elsif ($op eq 'not'){
        return !($self->parseFilter($args, $entry));
    }

    if ($op =~ /^(equalityMatch|greaterOrEqual|lessOrEqual)/) {
        my $rc = 0;
        foreach my $line (split(/\n/, $entry)) {
            my ($attr, $val) = split(/: /, $line);
            if ($attr !~ /^$args->{attributeDesc}$/i) {
                next;
            }

            my $assval =  decode('utf8', $args->{assertionValue});
            if ($op eq 'equalityMatch') {
                $assval =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                $rc = ($val =~ /^$assval$/i);
            } elsif ($op eq 'greaterOrEqual') {
                $rc = ($val ge $assval);
            } elsif ($op eq 'lessOrEqual') {
                $rc = ($val le $assval);
            }

            if ($rc) {
                last;
            }
        }
        return $rc;
    } elsif ($op eq 'substrings') {
        if (defined($args->{substrings}[0]{initial})) {
            my $substr = decode('utf8', $args->{substrings}[0]{initial});
            $substr =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
            return $entry =~ /^$args->{type};?.*: $substr.*$/mi;
        } elsif (defined($args->{substrings}[0]{final})) {
            my $substr = decode('utf8', $args->{substrings}[0]{final});
            $substr =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
            return $entry =~ /^$args->{type};?.*: .*$substr$/mi;
        } else {
            my $substr = decode('utf8', $args->{substrings}[0]{any});
            $substr =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
            return $entry =~ /^$args->{type}: .*$substr.*$/mi;
        }
    } elsif ($op eq 'present') {
        return $entry =~ /^$args: /mi;
    }
}

=pod

=head2 buildEntryStr($basedn, $conf)

get information of container entry.

=cut

sub buildEntryStr
{
    my $self = shift;
    my ($basedn, $conf) = @_;
    my $entry = '';

    if (!defined($conf->{rdn}) || !($conf->{rdn}[0] =~ /^[^=]+=[^,]+/)) {
        return $entry;
    }

    ($entry = $conf->{rdn}[0]."\n") =~ s/=/: /;
    if (defined($conf->{oc})) {
        foreach my $oc (@{$conf->{oc}}) {
            $entry = $entry."objectClass: $oc\n";
        }
    }
    if (defined($conf->{attr})) {
        foreach my $attr (keys %{$conf->{attr}}) {
            $entry = $entry."$attr: $conf->{attr}{$attr}->{content}\n";
        }
    }
    $entry = "dn: $conf->{rdn}[0],$basedn\n$entry";

    return $entry;
}

sub manageDIT
{
    my $self = shift;

    return $self->{_manageDIT};
}


sub _checkConfig
{
    my $self = shift;
    my $conf = $self->{_config};

    if (defined($conf->{libload})) {
        foreach my $lib (@{$conf->{libload}}) {
            eval "do \'$lib\'";
            if ($@) {
                $self->log(level => 'alert', message => "Storage do $lib: $@");
                return 1;
            }
        }
    }

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

    # hash type
    if (!defined($conf->{hash})) {
        $conf->{hash} = 'PLAINTEXT';
    }

    # multibyte character code
    if (defined($conf->{mbcode})) {
        if ($conf->{mbcode}[0] !~ /^(utf8|euc-jp|shiftjis|cp932)/) {
            $self->log(level => 'alert', message => "Character code is invalid");
            return 1;
        }
    } else {
        $conf->{mbcode}[0] = 'utf8';
    }

    # break character in value
    if (defined($conf->{break})) {
        if ($conf->{break}[0] eq 'CR') {
            $conf->{breakchar} = "\r";
        } elsif ($conf->{break}[0] eq 'CRLF') {
            $conf->{breakchar} = "\r\n";
        } else {
            $conf->{breakchar} = "\n";
        }
    } else {
        $conf->{breakchar} = "\n";
    }

    # connection
    if (!defined($conf->{connection}[0]->{retry})
        || $conf->{connection}[0]->{retry}[0] !~ /^[0-9]+$/) {
        $conf->{connection}[0]->{retry}[0] = 3;
    }
    if (!defined($conf->{connection}[0]->{interval})
        || $conf->{connection}[0]->{interval}[0] !~ /^[0-9]+$/) {
        $conf->{connection}[0]->{interval}[0] = 0;
    }

    if (defined($conf->{manageDIT}) && $conf->{manageDIT}[0]) {
        $self->{_manageDIT} = 1;
    } else {
        $self->{_manageDIT} = 0;
    }

    # data object
    if (defined($conf->{object})) {
        $self->{object} = {};
        foreach my $oname (keys %{$conf->{object}}) {
            my $oconf = $conf->{object}{$oname};
            my $entry;

            $self->{object}{$oname}->{name} = $oname;
            $self->{object}{$oname}->{conf} = $oconf;
            $self->{object}{$oname}->{recursive} = 0;

            # set container
            if (!defined($oconf->{container})) {
                my $coname = 'top_'.$oname.'_container';
                if (!defined($self->{object}{$coname})) {
                    $self->{object}{$coname}->{entrystr} = '';
                    # normalize suffix
                    ($self->{object}{$coname}->{suffix} = $self->{suffix}) =~ tr/A-Z/a-z/;
                }
                # set child object
                if (!defined($self->{object}{$coname}->{child})) {
                    $self->{object}{$coname}->{child} = [];
                }
                push(@{$self->{object}{$coname}->{child}}, $self->{object}{$oname});
                $self->{object}{$oname}->{parent} = $coname;
            } elsif (defined($oconf->{container}[0]->{oname})) {
                my $poname;
                if ($oconf->{container}[0]->{oname}[0] eq $oname) {
                    if (defined($oconf->{container}[0]->{parent})) {
                        $poname = $oconf->{container}[0]->{parent}[0];
                    } else {
                        $poname = 'top_'.$oname.'_container';
                        if (!defined($self->{object}{$poname})) {
                            $self->{object}{$poname}->{entrystr} = '';
                            # normalize suffix
                            ($self->{object}{$poname}->{suffix} = $self->{suffix}) =~ tr/A-Z/a-z/;
                        }
                    }
                    $self->{object}{$oname}->{recursive} = 1;
                } else {
                    $poname = $oconf->{container}[0]->{oname}[0];
                }
                $self->{object}{$oname}->{parent} = $poname;
                if (!defined($self->{object}{$poname}->{child})) {
                    $self->{object}{$poname}->{child} = [];
                }
                push(@{$self->{object}{$poname}->{child}}, $self->{object}{$oname});
            } elsif (!($entry = $self->buildEntryStr($self->{suffix}, $oconf->{container}[0]))) {
                $self->log(level => 'alert', message => "$oname object container entry is invalid");
                return 1;
            } else {
                $oconf->{container}[0]->{rdn}[0] =~ tr/A-Z/a-z/;
                my $crdn = $oconf->{container}[0]->{rdn}[0];
                my $coname = $crdn.'_container';
                if (!defined($self->{object}{$coname})) {
                    $self->{object}{$coname}->{entrystr} = $entry;
                    # normalize suffix
                    ($self->{object}{$coname}->{suffix} = "$crdn,".$self->{suffix}) =~ tr/A-Z/a-z/;
                }
                # set child object
                if (!defined($self->{object}{$coname}->{child})) {
                    $self->{object}{$coname}->{child} = [];
                }
                push(@{$self->{object}{$coname}->{child}}, $self->{object}{$oname});
                $self->{object}{$oname}->{parent} = $coname;
            }

            # subcontainer
            if (defined($oconf->{subcontainer})) {
                if (!defined($oconf->{subcontainer}[0]->{rdn})) {
                    $self->log(level => 'alert', message => "Set rdn in subcontainer");
                    return 1;
                }
            }

            foreach my $attr (keys(%{$oconf->{attr}})) {
                # the attribute's name must be lowercase
                if ($attr =~ /[A-Z]/) {
                    $self->log(level => 'alert', message => "Attribute's name must be lowercase: $attr");
                    return 1;
                }

                # multibyte character code
                if (defined($oconf->{attr}{$attr}->{mbcode}) &&
                    !($oconf->{attr}{$attr}->{mbcode}[0] =~ /^(euc-jp|shiftjis)/)) {
                    $self->log(level => 'alert', message => "Character code is invalid");
                    return 1;
                }
            }

            if (!defined($oconf->{rdn}) || !defined($oconf->{attr}{$oconf->{rdn}[0]})) {
                $self->log(level => 'alert', message => "Rdn of $oname object is invalid");
                return 1;
            } else {
                $oconf->{rdn}[0] = encode('utf8', $oconf->{rdn}[0]);
            }

            if (defined($oconf->{strginfo})) {
                foreach my $si (@{$oconf->{strginfo}}) {
                    # check type of value
                    if (defined($si->{value}) && !ref($si->{value}[0])) {
                        $self->log(level => 'alert', message => "Type of strginfo value doesn't exist");
                        return 1;
                    }
                }
            }

            # check paramset
            foreach my $func (keys %{$oconf->{plugin}}) {
                my $plugin = $oconf->{plugin}{$func};
                foreach my $key1 (keys %{$plugin->{param}}) {
                    if (defined($plugin->{param}{$key1}->{type}) &&
                        $plugin->{param}{$key1}->{type} eq 'paramset' &&
                            defined($conf->{paramset}{$plugin->{param}{$key1}->{value}})) {
                        my $paramset = $conf->{paramset}{$plugin->{param}{$key1}->{value}};
                        foreach my $key2 (keys %{$paramset->{param}}) {
                            $plugin->{param}{$key2} = $paramset->{param}{$key2};
                        }
                    }
                }
            }
        }

        # check container's link
        foreach my $oname (keys %{$self->{object}}) {
            my $obj = $self->{object}{$oname};

            if (!defined($obj->{suffix}) || !defined($obj->{child})) {
                next;
            }

            if ($self->_getTreeLevel($obj, 0) < 0) {
                $self->log(level => 'alert', message => "Depth of $oname subtree is too long");
                return 1;
            }
        }
    }

    return 0;
}

sub _getTreeLevel
{
    my $self = shift;
    my ($obj, $current) = @_;
    my $maxlevel = 0;

    if (!defined($obj->{suffix}) || $obj->{entrystr}) {
        $current++;
    }

    if ($current > $maxLoopCount) {
        return -1;
    }

    if (defined($obj->{conf}->{subcontainer})) {
        $current++;
    }

    if (!defined($obj->{child})) {
        return $current;
    }

    foreach my $child (@{$obj->{child}}) {
        my $level = $self->_getTreeLevel($child, $current);
        if ($level < 0) {
            return -1;
        } elsif ($level > $maxlevel) {
            $maxlevel = $level;
        }
    }

    return $maxlevel;
}

sub _getConnect
{
    return 0;
}

sub _freeConnect
{
}

sub _getObject
{
    my $self = shift;
    my ($dn, $multiple) = @_;
    my $conf = $self->{_config};
    my $obj = undef;

    if (!defined($self->{object})) {
        return (LDAP_UNWILLING_TO_PERFORM, $multiple ? [$obj] : $obj, []);
    }

    foreach my $oname (keys %{$self->{object}}) {
        my $tmpobj = $self->{object}{$oname};

        if (defined($tmpobj->{suffix}) && $dn =~ /$tmpobj->{suffix}$/i) {
            if (defined($obj) && length($obj->{suffix}) > length($tmpobj->{suffix})) {
                next;
            }
            $obj = $tmpobj;

            if ($dn =~ /^$obj->{suffix}$/i) {
                return (LDAP_SUCCESS, $multiple ? [$obj] : $obj, []);
            }
        }
    }

    if (!$obj) {
        return (LDAP_NO_SUCH_OBJECT, $multiple ? [$obj] : $obj, []);
    }

    my (@rdn_list) = split(/,/, ($dn =~ /^[^,]+,(.*),?$obj->{suffix}$/i)[0]);
    my @objs = ($obj);
    my @pkeyarr = ();
    my $key;
    my $container_oname;
    for (my $base = $obj->{suffix};1; $base = pop(@rdn_list).','.$base) {
        my $rc;
        my $entry;
        my $skip = 0;

        for (my $i = 0; $i < @objs; $i++) {
            if (defined($objs[$i]->{suffix}) && !$objs[$i]->{entrystr}) {
                $entry = "top_container";
                $obj = $objs[$i];
                $container_oname = undef;
                last;
            }
            if (defined($objs[$i]->{conf}->{subcontainer})) {
                my $rdn = $objs[$i]->{conf}->{subcontainer}[0]->{rdn}[0];
                if ($base =~ /^$rdn,/i) {
                    $key = undef;
                    $entry = "subcontainer";
                    $container_oname = $objs[$i]->{name};
                    last;
                }
                if ($rdn =~ /,/) {
                    my @elts = @rdn_list;
                    my ($top_rdn) = ($dn =~ /^([^,]+),/);
                    unshift(@elts, $top_rdn);
                    my $num = split(/,/, $rdn);
                    my $tmp = $base;
                    for (my $j = 0; $j < $num - 1; $j++) {
                        $tmp = $elts[$#elts - $j].','.$tmp;
                    }
                    if ($tmp =~ /^$rdn,/i) {
                        $key = undef;
                        $entry = "subcontainer";
                        $container_oname = $objs[$i]->{name};
                        $skip = 1;
                        last;
                    }
                }
            }

            ($rc, $key, $entry) = $self->_baseSearch($objs[$i], \@pkeyarr, $base, 0, 0, 1, 0, undef);
            if ($entry) {
                my ($odn) = ($entry =~ /^dn: ([^\n]+)/);
                $odn =~ s/\\22/"/gi;
                $odn =~ s/\\23/#/gi;
                $odn =~ s/\\2B/+/gi;
                $odn =~ s/\\2F/\//gi;
                $odn =~ s/\\3B/;/gi;
                $odn =~ s/\\3C/</gi;
                $odn =~ s/\\3E/>/gi;
                $odn =~ s/\\3D/=/gi;
                $odn =~ s/\\5C/\\/gi;
                my $match = 1;
                my $base_regex = $base;
                $base_regex =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                if ($odn !~ /^$base_regex$/i)  {
                    my @elts = @rdn_list;
                    my ($top_rdn) = ($dn =~ /^([^,]+),/);
                    unshift(@elts, $top_rdn);
                    my $num = split(/,/, ($odn =~ /^(.+),$base_regex$/i)[0]);
                    my $tmp = $base;
                    for (my $j = 0; $j < $num; $j++) {
                        $tmp = $elts[$#elts - $j].','.$tmp;
                    }
                    $odn =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
                    if ($tmp !~ /^$odn,/i) {
                        $match = 0;
                    }
                }
                if ($match) {
                $obj = $objs[$i];
                $container_oname = undef;
                last;
            }
        }
        }
        if (!$skip) {
        push(@pkeyarr, $key);
        }

        if (!$entry && (!$obj->{recursive} || !defined($obj->{child}))) {
            return (LDAP_NO_SUCH_OBJECT, $multiple ? [$obj] : $obj, []);
        }
        if (!@rdn_list) {
            last;
        }

        if ($obj->{recursive}) {
            @objs = ($obj);
        } elsif (defined($obj->{child})) {
            @objs = @{$obj->{child}};
        } else {
            last;
        }
    }

    my %match_objs;
    if (defined($obj->{child})) {
        foreach my $child (@{$obj->{child}}) {
            if ($container_oname && $container_oname ne $child->{name}) {
                next;
            }

            if (defined($child->{conf}->{subcontainer})) {
                my $rdn = $child->{conf}->{subcontainer}[0]->{rdn}[0];
                if ($dn =~ /^$rdn,/i ||
                    $dn =~ /^$child->{conf}->{rdn}[0]=[^,]+,$rdn/i) {
                    if ($multiple) {
                        $match_objs{$child->{name}} = $child;
                    } else {
                        return (LDAP_SUCCESS, $child, \@pkeyarr);
                    }
                }
                if ($rdn =~ /,/) {
                    while ($rdn =~ /,/) {
                        $rdn =~ s/^[^,]+,//;
                        if ($dn =~ /^$rdn,/i ||
                            $dn =~ /^$child->{conf}->{rdn}[0]=[^,]+,$rdn/i) {
                            if ($multiple) {
                                $match_objs{$child->{name}} = $child;
                            } else {
                return (LDAP_SUCCESS, $child, \@pkeyarr);
            }
        }
                    }
                }
            }
        }
        if ($multiple && %match_objs) {
            return (LDAP_SUCCESS, [values(%match_objs)], \@pkeyarr);
        }
        foreach my $child (@{$obj->{child}}) {
            if (defined($child->{conf}->{rdn}) && $dn =~ /^$child->{conf}->{rdn}[0]=/i) {
                if ($multiple) {
                    if ($container_oname && $container_oname ne $child->{name}) {
                        next;
                    }
                    $match_objs{$child->{name}} = $child;
                } else {
                return (LDAP_SUCCESS, $child, \@pkeyarr);
            }
        }
        }
        if ($multiple && %match_objs) {
            return (LDAP_SUCCESS, [values(%match_objs)], \@pkeyarr);
        }
    } elsif ($obj->{recursive}) {
        return (LDAP_SUCCESS, $multiple ? [$obj] : $obj, \@pkeyarr);
    }

    return (LDAP_NO_SUCH_OBJECT, $multiple ? [$obj] : $obj, []);
}

sub _searchObjects
{
    my $self = shift;
    my ($base, $scope) = @_;
    my $conf = $self->{_config};
    my @objs = ();

    if (!defined($conf->{object})) {
        return (LDAP_NO_SUCH_OBJECT, @objs);
    }

    if ($base =~ /^$self->{suffix}$/i) {
        if ($scope != 0) {
            foreach my $oname (keys %{$self->{object}}) {
                if (defined($self->{object}{$oname}->{suffix})) {
                    push(@objs, [$self->{object}{$oname}, []]);
                }
            }
        }
    } else {
        my ($rc, $objsp, $pkeys) = $self->_getObject($base, 1);
        if ($rc) {
            return ($rc, @objs);
        } else {
            foreach my $obj (@{$objsp}) {
            push(@objs, [$obj, $pkeys]);
        }
    }
    }

    return (LDAP_SUCCESS, @objs);
}

sub _baseSearch
{
    my $self = shift;
    my ($obj, $pkeys, $base, $scope, $deref, $sizeLim, $timeLim, $filter, $attrOnly, @attrs) = @_;
    my $oconf = $obj->{conf};
    my @pkeyarr = @{$pkeys};

    if (defined($obj->{suffix}) && $base !~ /$obj->{suffix}$/i) {
        return (LDAP_NO_SUCH_OBJECT, undef, undef);
    }

    if (defined($oconf->{subcontainer})) {
        my $rdn = $oconf->{subcontainer}[0]->{rdn}[0];
        if ($base !~ /,$rdn,/i) {
            my $suffix = $base;
            my $match = 0;
            if ($base =~ /^$rdn,/i) {
                $suffix =~ s/^$rdn,//i;
                $match = 1;
            } elsif ($rdn =~ /,/) {
                my $tmp = $rdn;
                while ($tmp =~/,/) {
                    $tmp =~ s/^[^,]+,//;
                    if ($base =~ /$tmp,/i) {
                        $suffix =~ s/^$tmp,//i;
                        $match = 1;
                        last;
                    }
                }
            }
            if (!$match) {
                return (LDAP_NO_SUCH_OBJECT, undef, undef);
            }

            my $entry = $self->buildEntryStr($suffix, $oconf->{subcontainer}[0]);
            if ($self->parseFilter($filter, $entry) && $scope != 1 && $sizeLim) {
                return (LDAP_SUCCESS, undef, $entry);
            } else {
                return (LDAP_SUCCESS, undef, undef);
            }
        }
    }

    if (defined($obj->{entrystr})) {
        my $entry = $obj->{entrystr};
        if (!$entry) {
            return (LDAP_SUCCESS, undef, undef);
        } elsif ($entry !~ /^dn: $base\n/i) {
            return (LDAP_NO_SUCH_OBJECT, undef, undef);
        } elsif ($self->parseFilter($filter, $entry) && $scope != 1 && $sizeLim) {
            return (LDAP_SUCCESS, undef, $entry);
        } else {
            return (LDAP_SUCCESS, undef, undef);
        }
    }

    my ($rdn, $pdn) = ($base =~ /^([^,]+),(.*)$/);
    $rdn =~ s/([&|!*\(\)])/\\$1/g;
    my $filterStr = "(".encode('utf8', $rdn).")";
    if ($filter) {
        $filterStr = "(&".$filterStr.$filter->as_string.")";
    }
    my $basefilter = Net::LDAP::Filter->new($filterStr);

    my ($rc, $keys, @entries) = $self->_objSearch($obj, $pkeys, $pdn, -1, $basefilter, $attrOnly, @attrs);
    if ($rc) {
        return ($rc, undef, undef);
    }

    return ($rc, ${$keys}[0], $scope != 1 ? $entries[0] : undef);
}

sub _childSearch
{
    my $self = shift;
    my ($obj, $pkeys, $base, $scope, $deref, $sizeLim, $timeLim, $filter, $attrOnly, @attrs) = @_;
    my $oconf = $obj->{conf};
    my @match_entries = ();
    my @match_keys = ();
    my $rc = LDAP_SUCCESS;
    my @pkeyarr = @{$pkeys};
    my @objs;

    if ($scope == 0) {
        return ($rc, \@match_keys, ());
    }

    my @entries;
    my $keys;

    my $match = 0;
    if (defined($oconf->{subcontainer})) {
        my $rdn = $oconf->{subcontainer}[0]->{rdn}[0];
        if ($base =~ /^$rdn,/i) {
            $match = 1;
        } elsif ($rdn =~ /,/) {
            while ($rdn =~ /,/) {
                $rdn =~ s/^[^,]+,//;
                if ($base =~ /^$rdn,/i) {
                    $match = 1;
                    last;
                }
            }
        }
    }
    if ($match) {
        @objs = ($obj);
    } elsif ($obj->{recursive}) {
        @objs = ($obj);
    } else {
        if (!defined($obj->{child})) {
            return ($rc, \@match_keys, @match_entries);
        }
        @objs = @{$obj->{child}};
    }

    RECURSIVE:
    for (my $i = 0; $i < @objs; $i++) {
        my $cbase;
        my @children = ();
        my $ckeys;

        if (defined($objs[$i]->{conf}->{subcontainer}) && $base !~ /^(|.+,)$objs[$i]->{conf}->{subcontainer}[0]->{rdn}[0],/i) {
            my $rdn = $objs[$i]->{conf}->{subcontainer}[0]->{rdn}[0];
            my $add_base;
            if ($rdn =~ /,/) {
                my $tmp = $rdn;
                while ($tmp =~ /,/) {
                    $tmp =~ s/^[^,]+,//;
                    if ($base =~ /^$tmp,/i) {
                        $add_base = $rdn;
                        $add_base =~ s/$tmp$//;
                        last;
                    }
                }
            }
            if ($add_base) {
                $cbase = "$add_base$base";
            } else {
            my $entry = $self->buildEntryStr($base, $objs[$i]->{conf}->{subcontainer}[0]);

            if ($self->parseFilter($filter, $entry) && $sizeLim) {
                push(@match_entries, $entry);
                push(@match_keys, undef);
            }
            if ($scope == 1) {
                next;
            }
            $cbase = $objs[$i]->{conf}->{subcontainer}[0]->{rdn}[0].",$base";
            }
        } else {
            $cbase = $base;
        }

        ($rc, $keys, @entries) = $self->_objSearch($objs[$i], $pkeys, $cbase, $sizeLim, $filter, $attrOnly, @attrs);
        push(@match_entries, @entries);
        push(@match_keys, @{$keys});

        if ($scope == 1 || (!$objs[$i]->{recursive} && !defined($objs[$i]->{child})) || $rc) {
            next;
        }
        $sizeLim = $sizeLim - @match_entries;

        ($rc, $ckeys, @children) = $self->_objSearch($objs[$i], $pkeys, $cbase, -1, undef);
        if ($rc) {
            return ($rc, \@match_keys, @match_entries);
        }

        if ($objs[$i]->{recursive} && @{$ckeys} == 0) {
            if (defined($objs[$i]->{child})) {
                @objs = @{$objs[$i]->{child}};
                goto RECURSIVE;
            }
        }

        for (my $j = 0; $j < @{$ckeys}; $j++) {
            my ($childdn) = ($children[$j] =~ /^dn: (.*)\n/);
            if (!$childdn) {
                return (LDAP_OTHER, \@match_keys, @match_entries);
            }
            $childdn =~ s/\\22/"/gi;
            $childdn =~ s/\\23/#/gi;
            $childdn =~ s/\\2B/+/gi;
            $childdn =~ s/\\2F/\//gi;
            $childdn =~ s/\\3B/;/gi;
            $childdn =~ s/\\3C/</gi;
            $childdn =~ s/\\3E/>/gi;
            $childdn =~ s/\\3D/=/gi;
            $childdn =~ s/\\5C/\\/gi;

            ($rc, $keys, @entries) = $self->_childSearch($objs[$i], [@pkeyarr, ${$ckeys}[$j]], $childdn, $scope, $deref, $sizeLim, $timeLim, $filter, $attrOnly, @attrs);
            if ($rc) {
                return ($rc, \@match_keys, @match_entries);
            }

            push(@match_entries, @entries);
            push(@match_keys, @{$keys});
            $sizeLim = $sizeLim - @entries;
        }
    }

    return ($rc, \@match_keys, @match_entries);
}

sub _objSearch
{
    return (LDAP_UNWILLING_TO_PERFORM, undef, ());
}

sub _objModify
{
    return LDAP_UNWILLING_TO_PERFORM;
}

sub _objAdd
{
    return LDAP_UNWILLING_TO_PERFORM;
}

sub _objDelete
{
    return LDAP_UNWILLING_TO_PERFORM;
}

sub _objMove
{
    return LDAP_UNWILLING_TO_PERFORM;
}

sub _getParentDn
{
    my $self = shift;
    my ($obj, $key) = @_;
    my $conf = $self->{_config};

    RECURSIVE:
    if (defined($obj->{suffix})) {
        return $obj->{suffix};
    }

    my $pobj;
    if ($obj->{recursive}) {
        $pobj = $obj;
    } else {
        if (!defined($obj->{parent})) {
            return undef;
        }

        $pobj = $self->{object}{$obj->{parent}};

        if (defined($pobj->{suffix})) {
            return $pobj->{suffix};
        }
    }

    my ($prdn, $pkey) = $self->_getParentRdn($obj, $key, $pobj);
    if (!$prdn) {
        if ($obj->{recursive}) {
            if (defined($obj->{conf}->{container}[0]->{parent})) {
                $obj = $self->{object}{$obj->{parent}};
                goto RECURSIVE;
            } else {
                $prdn = $obj->{conf}->{subcontainer}[0]->{rdn}[0];
                $pobj = $self->{object}{$obj->{parent}};
            }
        } else {
            return undef;
        }
    }

    my $ppdn = $self->_getParentDn($pobj, $pkey);
    if (!$ppdn) {
        return undef;
    }

    if (defined($obj->{conf}->{subcontainer}) && !$obj->{recursive}) {
        $prdn = "$obj->{conf}->{subcontainer}[0]->{rdn}[0],$prdn";
    }

    return "$prdn,$ppdn";
}

sub _getParentRdn
{
    return undef;
}

sub _getPid
{
    my $self = shift;
    my ($pkeys) = @_;

    if (!defined($pkeys)) {
        return undef;
    }

    return defined(${$pkeys}[$#{$pkeys}]) || !$#{$pkeys} ? ${$pkeys}[$#{$pkeys}] : ${$pkeys}[$#{$pkeys} - 1];
}

sub _getStaticValue
{
    my $self = shift;
    my ($static, $dn, $entryStr) = @_;
    my $value;

    # get static value
    if (defined($static->{value})) {
        if ($static->{value}[0]->{type} eq 'function') {
            eval "\$value = $static->{value}[0]->{content}";
        } else {
            $value = $static->{value}[0]->{content};
        }
    }

    return $value;
}

sub _containerParse
{
    my $self = shift;
    my ($str, @conts) = @_;
    my $cont = defined($conts[$#conts]) || !$#conts ? $conts[$#conts] : $conts[$#conts - 1];

    my @nums = ($str =~ /\%c([0-9]+)/g);
    foreach my $num (@nums) {
        if (defined($conts[$#conts + 1 - $num])) {
            $str =~ s/\%c$num/$conts[$#conts + 1 - $num]/;
        }
    }
    $str =~ s/\%c/$cont/g;

    return $str;
}

sub _funcParse
{
    my $self = shift;
    my ($str, $dn, $entryStr) = @_;

    my @funcs = ($str =~ /%\{([^}]*)\}/g);
    foreach my $func (@funcs) {
        my $value;

        eval "\$value = $func";
        if ($@) {
            $self->log(level => 'err', message => "function $func failed: $@");
        }

        $func =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
        $str =~ s/%\{$func\}/$value/;
    }

    return $str;
}

sub _doPlugin
{
    my $self = shift;
    my ($op, $obj, @args) = @_;
    my $oconf = $obj->{conf};
    my @match_keys;
    my @match_entries;
    my $rc = LDAP_SUCCESS;

    foreach my $func (keys %{$oconf->{plugin}}) {
        my $plugin = $oconf->{plugin}{$func};
        my $error;

        if (!defined($plugin->{op}) || $plugin->{op}[0] eq $op) {
            if ($op eq 'search') {
                my $keys;
                my @entries;

                eval "(\$rc, \$error, \$keys, \@entries) = LISM::Storage::$func(\$self, \$oconf, \$plugin->{param}, \@args)";
                for (my $i = 0; $i < @entries; $i++) {
                    if ($entries[$i] !~ /^dn: .*,$args[1]\n/i) {
                        next;
                    }

                    my $level = split(/,/, ($entries[$i] =~ /^dn: (.*),?$self->{suffix}\n/i)[0]);
                    if ((defined($plugin->{getall}) || @{$args[0]} == $level) &&
                        $self->parseFilter($args[3], $entries[$i])) {
                        push(@match_keys, ${$keys}[$i]);
                        push(@match_entries, $entries[$i]);
                    }
                }
            } else {
                eval "(\$rc, \$error) = LISM::Storage::$func(\$self, \$oconf, \$plugin->{param}, \@args)";
            }
            if ($@) {
                $self->log(level => 'err', message => "plugin $func failed in $op operation: $@");
                $rc = LDAP_OTHER;
                last;
            } elsif ($rc) {
                $self->log(level => 'err', message => "plugin $func returns error in $op operation: $error");
                $rc = LDAP_OTHER;
                last;
            }
        }
    }

    if ($op eq 'search') {
        return ($rc, \@match_keys, @match_entries);
    } else {
        return $rc;
    }
}

sub _doFunction
{
    my $self = shift;
    my ($function) = @_;
    my $value;

    eval "\$value = $function";
    if ($@) {
        $self->log(level => 'err', message => "Function $function failed: $@");
        return $value;
    }

    return $value;
}

sub _pwdFormat
{
    my $self = shift;
    my ($entry) = @_;
    my $conf = $self->{_config};

    if ($entry =~ /^userpassword: (.*)$/mi) {
        my $passwd = $1;
        my ($htype, $otype) = split(/:/, $conf->{hash});

        if ($htype =~ /^CRYPT|MD5|SHA|SSHA|SSHA512|PBKDF2_SHA256$/i) {
            if ($otype =~ /^hex$/i && $htype =~ /^MD5|SHA$/i) {
                $passwd = encode_base64(pack("H*", $passwd), '');
            }
            $passwd = "{$htype}".$passwd;
        }

        $entry =~ s/^userpassword:.*$/userpassword: $passwd/mi;
    }

    return $entry;
}

sub _writeUpdateLog
{
    my $self = shift;
    my ($func, $file, $dn, @info) = @_;
    my $conf = $self->{_config};
    my $lock;
    my $fd;
    my $ldif;

    if (!open($lock, ">$file.lock")) {
        $self->log(level => 'crit', message => "Can't open lock file of update log: $file.lock");
        return -1;
    }

    if (!open($fd, ">> $file")) {
        $self->log(level => 'crit', message => "Can't open update log: $file");
        return -1;
    }

    flock($lock, 2);
    $ldif = "# ".strftime("%Y%m%d%H%M%S", localtime(time))."\ndn: $dn\nchangetype: $func\n";

    if ($func eq 'modify') {
        while (@info > 0) {
            my $action = shift @info;
            my $attr = shift @info;
            my @values;

            while (@info > 0 && $info[0] ne "ADD" && $info[0] ne "DELETE" && $info[0] ne "REPLACE") {
                push(@values, shift @info);
            }

            $ldif = $ldif.lc($action).": $attr\n";
            foreach my $val (@values) {
                $ldif = "$ldif$attr: $val\n";
            }
            $ldif = "$ldif-\n";
        }
    } elsif ($func eq 'add') {
        $ldif = "$ldif$info[0]"
    } elsif ($func eq 'modrdn') {
        $ldif = $ldif."newrdn: $info[0]\ndeleteoldrdn: $info[1]\n";
    }

    $ldif = encode('utf8', $ldif);
    print $fd "$ldif\n";

    close($fd);
    close($lock);

    return 0;
}

sub random
{
    my $self = shift;
    my ($len, $attr, $info) = @_;
    my $string;

    if ($attr) {
        if (ref($info) eq 'ARRAY') {
            my @list = @{$info};
            for (my $i = 0; $i < @list; $i++) {
                if ($list[$i] =~ /^$attr$/i && defined($list[$i + 1]) && $list[$i + 1]) {
                    return $list[$i + 1];
                }
            }
        } else {
            my ($string) = ($info =~ /^$attr: *(.+)$/mi);
            if ($string) {
                return $string;
            }
        }
    }

    my @chars;
    push(@chars, ('a'..'z'), ('A'..'Z',), (0..9));

    my ($sec, $microsec) = gettimeofday();
    srand($microsec);

    for (my $i = 0; $i < 10; $i++) {
        $string = '';
        for (my $j = 0; $j < $len; $j++) {
            $string .= $chars[int(rand() * @chars)];
        }
        if ($string =~ /[a-zA-Z]/ && $string =~ /[0-9]/) {
            last;
        }
    }

    return $string;
}

sub _unescapedn
{
    my $self = shift;
    my ($dn) = @_;

    $dn =~ s/\\(?:3C|<)/</gi;
    $dn =~ s/\\(?:3E|>)/>/gi;
    $dn =~ s/\\(?:2C|,)/,/gi;
    $dn =~ s/\\22/"/gi;
    $dn =~ s/\\23/#/gi;
    $dn =~ s/\\2B/+/gi;
    $dn =~ s/\\2F/\//gi;
    $dn =~ s/\\3B/;/gi;
    $dn =~ s/\\3D/=/gi;
    $dn =~ s/\\5C/\\/gi;

    return $dn;
}

sub _lock
{
    my $self = shift;
    my ($file) = @_;
    my $conf = $self->{lism}->{_config};

    my $file_create = -f $file ? 0 : 1;

    my $lock;
    if (!open($lock, "> $file")) {
        return;
    }

    flock($file, 2);

    if ($file_create) {
        chmod(0660, $file);
        if (defined($conf->{syncdiruid})) {
            chown($conf->{syncdiruid}, $conf->{syncdirgid}, $file);
        }
    }

    return $lock;
}

=head1 SEE ALSO

L<LISM>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

(c) 2006 Kaoru Sekiguchi

This library is free software; you can redistribute it and/or modify
it under the GNU LGPL.

=cut

1;
