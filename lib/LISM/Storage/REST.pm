package LISM::Storage::REST;

use strict;
use base qw(LISM::Storage);
use LISM::Constant;
use Net::LDAP::Filter;
use HTTP::Request::Common qw(GET POST PUT DELETE);
use LWP::UserAgent;
use JSON::DWIW;
use XML::Simple;
use URI::Escape;
use POSIX;
use Encode;
use Data::Dumper;

our $RETRY = 3;

$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

=head1 NAME

LISM::Storage::REST - REST storage for LISM

=head1 DESCRIPTION

This class implements the L<LISM::Storage> interface for REST data.

=head1 METHODS

=head2 init

Initialize the configuration data.

=cut

sub init
{
    my $self = shift;

    return $self->SUPER::init();
}

sub _getConnect
{
    my $self = shift;
    my $conf = $self->{_config};

    if (!defined($self->{ua})) {
        $self->{ua} = LWP::UserAgent->new;
    }
    if (defined($conf->{login})) {
        my ($rc, $error) = $self->_login($conf->{login}[0], defined($conf->{login}[0]->{path}) ? $conf->{login}[0]->{path}[0] : undef);
        if ($rc) {
            $self->log(level => 'err', message => "Login to REST service failed".($error ? ": $error" : ''));
        }
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

    if (defined($conf->{connection}[0]->{retry})) {
        $RETRY = $conf->{connection}[0]->{retry}[0];
        if ($RETRY <= 0) {
            $RETRY = 1;
        }
    }

    if (defined($conf->{url})) {
        $conf->{url}[0] = encode('utf8', $conf->{url}[0]);
    }
    if (!defined($conf->{expire})) {
        $conf->{expire}[0] = 3600;
    }

    if (defined($conf->{login})) {
        my $login = $conf->{login}[0];

        my $authtype = defined($login->{authtype}) ? $login->{authtype}[0] : '';
        $self->{multilogin}->{current} = 'default';
        if (defined($login->{basicuser})) {
            $self->{multilogin}{default}->{basicauth} = {};
            $self->{multilogin}{default}->{basicauth}->{user} = $login->{basicuser}[0];
            my $passwd = $login->{basicpw}[0];
            if (defined($conf->{login}[0]->{decrypt})) {
                my $decrypt = $conf->{login}[0]->{decrypt}[0];
                $decrypt =~ s/\%s/$passwd/;
                $passwd = $self->_doFunction($decrypt);
                if (!defined($passwd)) {
                    $self->log(level => 'err', message => "Decrypt of basicpw failed");
                    return 1;
                }
            }
            $self->{multilogin}{default}->{basicauth}->{pw} = $passwd;
        } elsif ($authtype eq 'oauth') {
            if (!defined($login->{oauth})) {
                $self->log(level => 'alert', message => "Set login oauth");
                return 1;
            }
            if (defined($login->{oauth}[0]->{token})) {
                my $token = $login->{oauth}[0]->{token}[0];
                if (defined($conf->{login}[0]->{decrypt})) {
                    my $decrypt = $conf->{login}[0]->{decrypt}[0];
                    $decrypt =~ s/\%s/$token/;
                    $token = $self->_doFunction($decrypt);
                    if (!defined($token)) {
                        $self->log(level => 'err', message => "Decrypt of token failed");
                        return 1;
                    }
                }
                $self->{multilogin}{default}->{oauth}->{token} = $token;
                if (defined($login->{oauth}[0]->{client_secret})) {
                    $self->{multilogin}{default}->{oauth}->{client_secret} = $login->{oauth}[0]->{client_secret}[0];
                }
            } else {
                if (!defined($login->{oauth}[0]->{client_id}) || !defined($login->{oauth}[0]->{client_secret})) {
                    $self->log(level => 'alert', message => "Set client_id, client_secret");
                    return 1;
                }
                $self->{multilogin}{default}->{oauth}->{client_id} = $login->{oauth}[0]->{client_id}[0];
                $self->{multilogin}{default}->{oauth}->{client_secret} = $login->{oauth}[0]->{client_secret}[0];
                my $refresh_token;
                my $token_time;
                if (defined($login->{oauth}[0]->{refresh_token})) {
                    ($refresh_token, $token_time) = ($login->{oauth}[0]->{refresh_token}[0] =~ /^(.+)#([0-9]+)$/);
                }
                if (defined($login->{oauth}[0]->{token_file}) && -f $login->{oauth}[0]->{token_file}[0]) {
                    my $fd;
                    if (!open($fd, "< $login->{oauth}[0]->{token_file}[0]")) {
                        $self->log(level => 'alert', message => "Can't open token file");
                        return 1;
                    }
                    my $token_data = <$fd>;
                    my @elts = ($token_data =~ /^(.+)#([0-9]+)$/);
                    if (!$refresh_token || $elts[1] > $token_time) {
                        $refresh_token = $elts[0];
                    }
                }
                $self->{multilogin}{default}->{oauth}->{refresh_token} = $refresh_token;
            }
        } elsif ($authtype eq 'parameter') {
            if (defined($login->{webcontent}) && defined($login->{admin}) && defined($login->{passwd})) {
                my $content = $login->{webcontent}[0];
                my $admin = $login->{admin}[0];
                my $passwd = $login->{passwd}[0];
                if (defined($conf->{login}[0]->{decrypt})) {
                    my $decrypt = $conf->{login}[0]->{decrypt}[0];
                    $decrypt =~ s/\%s/$passwd/;
                    $passwd = $self->_doFunction($decrypt);
                    if (!defined($passwd)) {
                        $self->log(level => 'err', message => "Decrypt of passwd failed");
                        return 1;
                    }
                }
                $content =~ s/%u/$admin/g;
                $content =~ s/%s/$passwd/g;
                $self->{multilogin}{default}->{paramauth} = $content;
            }
        } else {
            if (defined($conf->{url})) {
                $self->{multilogin}{default}->{url} = $conf->{url}[0];
            } else {
                $self->log(level => 'alert', message => "Set url");
                return 1;
            }
            if (defined($login->{path})) {
                $self->{multilogin}{default}->{path} = $login->{path}[0];
            }
            if (defined($login->{admin})) {
                $self->{multilogin}{default}->{admin} = $login->{admin}[0];
            }
            if (defined($login->{passwd})) {
                $self->{multilogin}{default}->{passwd} = $login->{passwd}[0];
            }
        }
        if (defined($login->{apiparam})) {
            $self->{multilogin}{default}->{apiparam} = $login->{apiparam};
        }
    }

    foreach my $oname (keys %{$conf->{object}}) {
        my $oconf = $conf->{object}{$oname};

        if (defined($oconf->{container})) {
            if (defined($oconf->{container}[0]->{login})) {
                my $login = $oconf->{container}[0]->{login}[0];
                if (defined($login->{search})) {
                    if (defined($login->{search}[0]->{filter})) {
                        $login->{search}[0]->{filter} =~ s/&amp;/&/g;
                    }
                }
            }
        }

        if (defined($oconf->{attr})) {
            foreach my $attr (keys %{$oconf->{attr}}) {
                if (defined($oconf->{attr}{$attr}->{add}) && ref($oconf->{attr}{$attr}->{add}[0]) eq 'HASH' && defined($oconf->{attr}{$attr}->{add}[0]->{path})) {
                    $oconf->{attr}{$attr}->{add}[0]->{path}[0] = encode('utf8', $oconf->{attr}{$attr}->{add}[0]->{path}[0]);
                }
                if (defined($oconf->{attr}{$attr}->{delete}) && ref($oconf->{attr}{$attr}->{delete}[0]) eq 'HASH' && defined($oconf->{attr}{$attr}->{delete}[0]->{path})) {
                    $oconf->{attr}{$attr}->{delete}[0]->{path}[0] = encode('utf8', $oconf->{attr}{$attr}->{delete}[0]->{path}[0]);
                }
            }
        }

        if (defined($oconf->{search})) {
            if (!defined($oconf->{search}[0]->{list}) ||
                !defined($oconf->{search}[0]->{list}[0]->{tag})) {
                $self->log(level => 'alert', message => "Set list in search");
                return 1;
            }
            if (defined($oconf->{saerch}[0]->{path})) {
                $oconf->{search}[0]->{path}[0] = encode('utf8', $oconf->{search}[0]->{path}[0]);
            }
        }
        if (defined($oconf->{read}) && defined($oconf->{read}[0]->{path})) {
            $oconf->{read}[0]->{path}[0] = encode('utf8', $oconf->{read}[0]->{path}[0]);
        }
        if (defined($oconf->{add}) && defined($oconf->{add}[0]->{path})) {
            $oconf->{add}[0]->{path}[0] = encode('utf8', $oconf->{add}[0]->{path}[0]);
        }
        if (defined($oconf->{modify}) && defined($oconf->{modify}[0]->{path})) {
            $oconf->{modify}[0]->{path}[0] = encode('utf8', $oconf->{modify}[0]->{path}[0]);
        }
        if (defined($oconf->{delete}) && defined($oconf->{delete}[0]->{path})) {
            $oconf->{delete}[0]->{path}[0] = encode('utf8', $oconf->{delete}[0]->{path}[0]);
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
    my @match_entries = ();
    my @match_keys;
    my $pkey = $self->_getPid($pkeys);
    my $login;
    my $format = defined($oconf->{format}) ? $oconf->{format}[0] : $conf->{format}[0];
    my $reqformat = defined($oconf->{reqformat}) ? $oconf->{reqformat}[0] : (defined($conf->{reqformat}) ? $conf->{reqformat}[0] : $format);
    my $baseurl = defined($conf->{url}) ? $conf->{url}[0] : '';
    my $rc = LDAP_SUCCESS;
    my $error;

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

    if (!defined($oconf->{search})) {
        return ($rc, \@match_keys, @match_entries);
    }
    my $search = $oconf->{search}[0];

    my $filterStr;
    if ($filter) {
        $filterStr = $filter->as_string;
    } else {
        $filterStr = '(objectClass=*)';
    }

    # check whether access to REST service is needed
    my $match = 0;
    if ($filterStr =~ /\(objectClass=\*\)/i) {
        $match = 1;
    } elsif ($filterStr =~ /\(objectClass=.+\)/i) {
        foreach my $oc (@{$oconf->{oc}}) {
            if ($filterStr =~ /\(objectClass=$oc\)/i) {
                $match = 1;
            }
        }
    }
    if (!$match) {
        foreach my $attr (keys %{$oconf->{attr}}) {
            if ($filterStr =~ /\($attr=.+\)/i) {
                $match = 1;
                last;
            }
        }
    }
    if (!$match) {
        return ($rc, \@match_keys, @match_entries);
    }

    if (defined($oconf->{container})) {
        if (defined($oconf->{container}[0]->{login})) {
            $login = $oconf->{container}[0]->{login}[0];
            ($rc, $error) = $self->_relogin($pkey, $suffix, $login);
            if ($rc || !$self->{multilogin}->{current}) {
                return (LDAP_SUCCESS, \@match_keys, @match_entries);
            }
            if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{url})) {
                $baseurl = $self->{multilogin}{$self->{multilogin}->{current}}->{url};
            }
        }
    }

    my $url = "$baseurl$search->{path}[0]";

    if (!$pkey) {
        if (defined($conf->{login})) {
            $login = $conf->{login}[0];
        }
        if ($self->{multilogin}->{current} ne 'default' && $login) {
            ($rc) = $self->_relogin('default', $suffix, $login);
            if ($rc) {
                $self->log(level => 'err', message => "Login to default REST service failed");

                return (LDAP_OTHER, \@match_keys, @match_entries);
            }
        }
    }

    my ($rdn_val) = ($filterStr =~ /$oconf->{rdn}[0]=(.[^\)]*)/i);
    $rdn_val =~ s/\\2A/*/gi;
    $rdn_val =~ s/\\28/(/gi;
    $rdn_val =~ s/\\29/)/gi;
    my $regex_rdn_val = $rdn_val;
    $regex_rdn_val =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
    if ($rdn_val && $rdn_val !~ /\*/) {
        if (defined($oconf->{read})) {
            $search = $oconf->{read}[0];
            $url = "$baseurl$search->{path}[0]";
        }

        # rewrite search filter
        if (defined($search->{rewriteFilter})) {
            my $substitution = $search->{rewriteFilter}[0]->{substitution};
            $substitution =~ s/\%r/$rdn_val/;
            $substitution = $self->_containerParse($substitution, @{$pkeys});
            $filterStr =~ s/$search->{rewriteFilter}[0]->{match}/$substitution/i;
            ($rdn_val) = ($filterStr =~ /$oconf->{rdn}[0]=(.[^\)]*)/i);
        }

        $url =~ s/\%r/$rdn_val/g;
    } else {
        $url =~ s/\/[^\/?&]*\%r[^\/]*//g;
        $url =~ s/[^?&=]+=\%r//g;
    }
    $url = $self->_containerParse($url, @{$pkeys});

    # replace dn to filter
    $filterStr =~ s/\(([^=]+=)[^=]+=([^,]+),[^\)]*$self->{suffix}\)/($1$2)/gi;
    $filter = Net::LDAP::Filter->new($filterStr);

    my $method = '';
    if (defined($oconf->{search}[0]->{method})) {
        $method = $oconf->{search}[0]->{method}[0];
    }

    my $reqcontent = '';
    if ($method eq 'POST') {
        if ($reqformat eq 'json') {
            if (defined($search->{webcontent})) {
                $reqcontent = $search->{webcontent}[0];
                $reqcontent =~ s/\%r/$rdn_val/g;
            } else {
                my $json = {};
                if (defined($search->{filter})) {
                    foreach my $attr (keys %{$oconf->{attr}}) {
                        if (!defined($search->{filter}{$attr})) {
                            next;
                        }

                        my ($value) = ($filterStr =~ /$attr=(.[^\)]*)/i);
                        if ($value) {
                            ${$json}{$search->{filter}{$attr}->{param}} = $value;
                        }
                    }
                }
                if (defined($search->{listtag})) {
                    $json = {$search->{listtag}[0] => [$json]};
                }
                if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{apiparam})) {
                    foreach my $param (keys %{$self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}}) {
                        ${$json}{$param} = $self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}{$param}->{value};
                    }
                }
                $reqcontent = JSON::DWIW->new->to_json($json);
            }
        } elsif ($reqformat eq 'POST') {
            if (defined($search->{filter})) {
                foreach my $attr (keys %{$oconf->{attr}}) {
                    if (!defined($search->{filter}{$attr})) {
                        next;
                    }

                    my ($value) = ($filterStr =~ /$attr=(.[^\)]*)/i);
                    if ($value) {
                        $reqcontent .= ($reqcontent ? '&' : '').$search->{filter}{$attr}->{param}.'='.uri_escape($value);
                    }
                }
            }
            if (defined($oconf->{search}[0]->{param})) {
                foreach my $param (keys(%{$oconf->{search}[0]->{param}})) {
                    my $value = $oconf->{search}[0]->{param}{$param}->{value};
                    $reqcontent .= ($reqcontent ? '&' : '')."$param=$value";
                }
            }
            if (defined($self->{session_param})) {
                $reqcontent .= ($reqcontent ? '&' : '')."$self->{session_param}=$self->{session}";
            }
            if (defined($self->{paramauth})) {
                $reqcontent .= ($reqcontent ? '&' : '').$self->{paramauth};
            }
        }
    } else {
        my $querystr = '';
        if (defined($self->{session_param})) {
            $querystr = "$self->{session_param}=$self->{session}";
        }

        if (defined($search->{filter})) {
            foreach my $attr (keys %{$oconf->{attr}}) {
                if (!defined($search->{filter}{$attr})) {
                    next;
                }

                my ($value) = ($filterStr =~ /$attr=(.[^\)]*)/i);
                if ($value) {
                    $querystr = $querystr.($querystr ? '&' : '')."$search->{filter}{$attr}->{param}=$value";
                }
            }
        }
        if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{apiparam})) {
            foreach my $param (keys %{$self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}}) {
                $querystr .= ($querystr ? '&' : '')."$param=$self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}{$param}->{value}";
            }
        }

        if ($querystr) {
            $url = $url.(index($url, '?') < 0 ? '?' : '&').$querystr;
        }
    }

    my $req;
    if ($method eq 'POST') {
        $req = POST $url;
        if (defined($oconf->{reqparam})) {
            $reqcontent = encode('utf8', $reqcontent);
            $reqcontent = $oconf->{reqparam}[0]."=$reqcontent";
            $req->header('Content-Length' => length($reqcontent));
            $req->content($reqcontent);
        } elsif ($reqformat eq 'json') {
            $req->header('Content-Type' => 'application/json');
            $req->header('Content-Length' => length($reqcontent));
            $req->content($reqcontent);
        } elsif ($reqcontent) {
            $req->header('Content-Length' => length($reqcontent));
            $req->content($reqcontent);
        }
    } else {
        $req = GET $url;
    }
    if (defined($self->{basicauth})) {
        $req->authorization_basic($self->{basicauth}->{user}, $self->{basicauth}->{pw});
    }
    if (defined($self->{session_cookie})) {
        $req->header(Cookie => "$self->{session_cookie}=$self->{session}");
    }
    if (defined($self->{oauth})) {
        my $token_type = $login && defined($login->{oauth}) && defined($login->{oauth}[0]->{token_type}) ? $login->{oauth}[0]->{token_type}[0] : 'Bearer';
        $req->header(Authorization => "$token_type $self->{oauth}->{token}");
        if (defined($login->{oauth}[0]->{client_secret_header})) {
            $req->header($login->{oauth}[0]->{client_secret_header}[0], $self->{oauth}->{client_secret});
        }
    }

    my $res;
    my $unavailable = defined($oconf->{result}[0]) && defined($oconf->{result}[0]->{unavailable}) ? $oconf->{result}[0]->{unavailable} : '';
    for (my $i = 0; $i < $RETRY; $i++) {
        $res = $self->{ua}->request($req);
        if ($res->is_error && $res->code == 401 && defined($oconf->{container}) && defined($oconf->{container}[0]->{login})) {
            ($rc, $error) = $self->_relogin($pkey, $suffix, $login);
            if (!$self->{multilogin}->{current}) {
                $rc = LDAP_NO_SUCH_OBJECT;
            }
            if ($rc) {
                $self->log(level => 'err', message => "Login to REST service failed: $error");

                return (LDAP_OTHER,  \@match_keys, @match_entries);
            }
            next;
        } elsif ($res->is_error && ($res->status_line =~ /timeout/ || $res->code =~ /^50/)) {
            sleep $conf->{connection}[0]->{interval}[0] * ($i + 1);
            next;
        }
        last;
    }
    if ($res->is_success) {
        if (defined($oconf->{result})) {
            my %result;
            $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
            if ($rc) {
                my $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                $self->log(level => 'err', message => "Searching $suffix in REST service($url) failed: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST search url=$url content=$reqcontent response=".$res->content);
                }
            }
        }

        my $content;
        my $entries;
        if ($format eq 'json') {
            my $error;
            ($content, $error) = JSON::DWIW->new({convert_bool => 1})->from_json($res->content);
            if (!defined($content)) {
                $self->log(level => 'err', message => "REST search response is not JSON: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST search url=$url response=$content");
                }
                return (LDAP_OTHER , \@match_keys, @match_entries);
            }
        } elsif ($format eq 'xml') {
            $content = eval {XMLin($res->content, ValueAttr => ['value'], KeyAttr => {})};
            if ($@) {
                $self->log(level => 'err', message => "REST search response is not XML: $@");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST search url=$url response=$content");
                }
                return (LDAP_OTHER , \@match_keys, @match_entries);
            }
        }

        $entries = $content;
        foreach my $tag (split(/, */, $search->{list}[0]->{tag})) {
            if (ref($entries) eq 'HASH' && defined($entries->{$tag})) {
                $entries = $entries->{$tag};
            } else {
                last;
            }
        }
        if (ref($entries) ne 'ARRAY') {
            $entries = [$entries];
        }

        foreach my $entry (@{$entries}) {
            if ($rdn_val && $rdn_val !~ /\*/) {
                my $tmpentry = $entry;
                my $tmprdn_val = '';
                my $rdn_param = $oconf->{attr}{$oconf->{rdn}[0]}->{param}[0];
                if (defined($oconf->{param}) && defined($tmpentry->{$oconf->{param}[0]})) {
                    $tmpentry = $tmpentry->{$oconf->{param}[0]}
                }
                if (defined($tmpentry->{$rdn_param})) {
                    $tmprdn_val = encode('utf8', $tmpentry->{$rdn_param});
                    if ($tmprdn_val !~ /^$regex_rdn_val$/i) {
                        next;
                    }
                } else {
                    $tmpentry->{$rdn_param} = $rdn_val;
                }
            }

            my $entryStr = $self->_buildObjectEntry($oconf, $suffix, $entry);
            if (!$entryStr) {
                next;
            }

            foreach my $attr (keys %{$oconf->{attr}}) {
                if (!defined($oconf->{attr}{$attr}->{search})) {
                    next;
                }

                my $id;
                if (defined($oconf->{id}) && $oconf->{id}[0]->{param}[0] ne $oconf->{rdn}[0]) {
                    $id = $entry->{$oconf->{id}[0]->{param}[0]};
                } else {
                    ($id) = ($entryStr =~ /^dn: [^=]+=([^,]+),/);
                }
                my $valStr = $self->_getAttrValues($oconf, $id, $pkeys, $attr);                
                if (!defined($valStr)) {
                    return (LDAP_OTHER , \@match_keys, @match_entries);
                }
                $entryStr = "$entryStr$valStr";
            }

            if ($self->parseFilter($filter, $entryStr)) {
                my $key;
                if (defined($oconf->{id}) && defined($oconf->{id}[0]->{param})) {
                    $key = $entry->{$oconf->{id}[0]->{param}[0]};
                } else {
                    $key = $rdn_val;
                }
                push(@match_keys, $key);
                push(@match_entries, $entryStr);
            }

            if (defined($search->{list}[0]->{recursive}) && $entry->{$search->{list}[0]->{recursive}}) {
                my $keysp;
                my $entriesp;
                ($rc, $keysp, $entriesp) = $self->_getEntries($oconf, $pkeys, $suffix, $filter, $rdn_val, 0, @{$entry->{$search->{list}[0]->{recursive}}});
                if ($rc) {
                    return ($rc, \@match_keys, @match_entries);
                } else {
                    push(@match_keys, @{$keysp});
                    push(@match_entries, @{$entriesp});
                }
            }
        }
        $rc = LDAP_SUCCESS;
    } elsif ($res->code != 404 || !$rdn_val || ($unavailable && $res->content =~ /$unavailable/i)) {
        if (defined($oconf->{result})) {
            my %result;
            $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
            if ($rc) {
                my $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                $self->log(level => 'err', message => "Searching $suffix in REST service($url) failed: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST search url=$url content=$reqcontent response=".$res->content);
                }
                if ($rc == LDAP_NO_SUCH_OBJECT) {
                    $rc = LDAP_SUCCESS;
                }
            }
        } else {
            $self->log(level => 'err', message => "Searching $suffix in REST service($url) failed: ".$res->status_line.($res->content ? ' '.substr($res->content, 0, 512) : ''));
            if ($conf->{sysloglevel} eq 'debug') {
                $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
            }
            $rc = LDAP_OTHER;
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
    my $login;
    my $format = defined($oconf->{format}) ? $oconf->{format}[0] : $conf->{format}[0];
    my $reqformat = defined($oconf->{reqformat}) ? $oconf->{reqformat}[0] : (defined($conf->{reqformat}) ? $conf->{reqformat}[0] : $format);
    my $password;
    my $match = 0;
    my $contentType;
    my $rc = 0;
    my $error;
    my $id;
    my $entry = {};

    if (defined($oconf->{noop}) && grep(/^modify$/i, @{$oconf->{noop}})) {
        return $rc;
    }

    if (defined($oconf->{search})) {
        if (defined($oconf->{rename}) && defined($oconf->{rename}[0]->{oldrdn})) {
            my $oldrdn_val;
            my @tmplist = @list;
            for (my $i = 0; $i < @tmplist; $i++) {
                if ($tmplist[$i] =~ /^$oconf->{rename}[0]->{oldrdn}[0]$/i) {
                    $oldrdn_val = $tmplist[$i + 1];
                   last;
                }
            }
            if ($oldrdn_val) {
                $dn =~ s/^([^=]*=)[^,]+/$1$oldrdn_val/;
            }
        }
        ($rc, $id, $entry) = $self->_restSearch($obj, $pkeys, $dn);
        if ($rc) {
            return $rc;
        } elsif (!$entry) {
            return LDAP_NO_SUCH_OBJECT;
        }
    }

    my ($rdn_val) = ($dn =~ /^[^=]+=([^,]+)/);
    if (!$id) {
        $id = $rdn_val;
    }

    my $randpwd;
    my $url = defined($conf->{url}) ? $conf->{url}[0] : '';
    if (defined($oconf->{container})) {
        if (defined($oconf->{container}[0]->{login})) {
            $login = $oconf->{container}[0]->{login}[0];
            ($rc, $error) = $self->_relogin($pkey, $dn, $login);
            if (!$self->{multilogin}->{current}) {
                return (LDAP_NO_SUCH_OBJECT, $error);
            }
            if ($rc) {
                return (LDAP_OTHER, $error);
            }
            if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{url})) {
                $url = $self->{multilogin}{$self->{multilogin}->{current}}->{url};
            }
            if (grep(/^userpassword$/i, @list) && $self->{multilogin}{$self->{multilogin}->{current}}->{randpwd} && $self->{multilogin}{$self->{multilogin}->{current}}->{admin} ne $id) {
                my ($len, $op) = split(/:/, $self->{multilogin}{$self->{multilogin}->{current}}->{randpwd});
                if ($op && $op ne 'modify') {
                    $randpwd = '';
                } else {
                    $randpwd = $self->random($len, 'randompassword', \@list);
                }
            }
        }
    }
    if (!$pkey) {
        if (defined($conf->{login})) {
            $login = $conf->{login}[0];
        }
        if ($self->{multilogin}->{current} ne 'default' && $login) {
            ($rc, $error) = $self->_relogin('default', $dn, $login);
            if ($rc) {
                return (LDAP_OTHER, $error);
            }
        }
    }

    if (defined($oconf->{undelete}) && defined($entry->{$oconf->{undelete}[0]->{param}[0]}) && $entry->{$oconf->{undelete}[0]->{param}[0]}) {
        ($rc, $error) = $self->_undelete($oconf, $login, $id, $pkeys);
        if ($rc) {
            return ($rc, $error);
        }
    }

    my $method = '';
    my $mod_querystr = '';
    if (defined($oconf->{modify})) {
        if (defined($oconf->{modify}[0]->{method})) {
            $method = $oconf->{modify}[0]->{method}[0];
        }
        if (defined($oconf->{modify}[0]->{type}) && $oconf->{modify}[0]->{type} eq 'differential') {
            $entry = {};
            $entry->{$oconf->{id}[0]->{param}[0]} = $id;
        }

        if (defined($oconf->{modify}[0]->{param})) {
            foreach my $param (keys(%{$oconf->{modify}[0]->{param}})) {
                my $value = $oconf->{modify}[0]->{param}{$param}->{value};
                if ($method eq 'GET') {
                    $mod_querystr .= ($mod_querystr ? '&' : '')."$param=".uri_escape($value);
                } else {
                    $entry->{$param} = $value;
                }
            }
        }
    }

    my $updated = 0;
    my $rename = 0;
    my @orglist = @list;
    while ( @list > 0 && !$rc) {
        my $action = shift @list;
        my $attr    = lc(shift @list);
        my @values;

        while (@list > 0 && $list[0] ne "ADD" && $list[0] ne "DELETE" && $list[0] ne "REPLACE") {
            my $value = shift @list;
            if ($value =~ /$self->{suffix}$/i) {
                $value =~ s/^[^=]+=([^,]+),.*/$1/;
            }
            push(@values, $value);
        }

        if (defined($oconf->{rename}) && defined($oconf->{rename}[0]->{oldrdn}) && $oconf->{rename}[0]->{oldrdn}[0] =~ /^$attr$/i) {
            ($rc, $error) = $self->_rename($oconf, $login, $id, $pkeys, @orglist);
            $rename = 1;
        }

        if (!defined($oconf->{attr}{$attr})) {
            next;
        }
        if (defined($oconf->{attr}{$attr}->{option}) && grep(/^readonly$/, @{$oconf->{attr}{$attr}->{option}})) {
            next;
        }

        if (defined($oconf->{attr}{$attr}->{list}) && defined($oconf->{attr}{$attr}->{webcontent})) {
            my $list_tag = $oconf->{attr}{$attr}->{list}[0];
            if (!defined($entry->{$list_tag}) || $action eq 'REPLACE' || ($action eq 'DELETE' && !@values)) {
                $entry->{$list_tag} = [];
            }
            for (my $i = 0; $i < @values; $i++) {
                if ($values[$i] =~ /^ *$/) {
                    next;
                }

                my $val_content = $oconf->{attr}{$attr}->{webcontent}[0];
                my $val = $values[$i];
                $val_content =~ s/\%a/$val/g;
                if ($reqformat eq 'json') {
                    $val_content = JSON::DWIW->new({convert_bool => 1})->from_json($val_content);
                }
                if ($action eq 'ADD') {
                    my $match = 0;
                    my $str_content = $val_content;
                    if ($reqformat eq 'json') {
                        $str_content = JSON::DWIW->new->to_json($str_content);
                    }
                    for (my $j = 0; $j < @{$entry->{$list_tag}}; $j++) {
                        my $tmp_content = ${$entry->{$list_tag}}[$j];
                        if ($reqformat eq 'json') {
                            $tmp_content = JSON::DWIW->new->to_json($tmp_content);
                        }
                        if ($tmp_content eq $str_content) {
                            $match = 1;
                            last;
                        }
                    }
                    if (!$match) {
                        push(@{$entry->{$list_tag}}, $val_content);
                    }
                } elsif ($action eq 'DELETE') {
                    my $str_content = $val_content;
                    if ($reqformat eq 'json') {
                        $str_content = JSON::DWIW->new->to_json($str_content);
                    }
                    for (my $j = 0; $j < @{$entry->{$list_tag}}; $j++) {
                        my $tmp_content = ${$entry->{$list_tag}}[$j];
                        if ($reqformat eq 'json') {
                            $tmp_content = JSON::DWIW->new->to_json($tmp_content);
                        }
                        if ($tmp_content eq $str_content) {
                            splice(@{$entry->{$list_tag}}, $j, 1);
                            last;
                        }
                    }
                } else {
                    push(@{$entry->{$list_tag}}, $val_content);
                }
            }
            $updated = 1;
            $match = 1;
            next;
        }

        my $tmpentry = defined($oconf->{attr}{$attr}->{parent}) ? $entry->{$oconf->{attr}{$attr}->{parent}[0]} : $entry;
        my $param;
        if ($method eq 'GET') {
            if (defined($oconf->{attr}{$attr}->{query})) {
                $param = $oconf->{attr}{$attr}->{query}[0];
            } else {
                next;
            }
        } elsif (!defined($oconf->{attr}{$attr}->{add})) {
            if (defined($oconf->{attr}{$attr}->{modparam})) {
                $param = $oconf->{attr}{$attr}->{modparam}[0];
            } else {
                $param = $oconf->{attr}{$attr}->{param}[0];
            }
        }

        if ($attr eq 'userpassword') {
            if (defined($randpwd)) {
                $values[0] = $randpwd;
            }
            if (!$values[0]) {
                next;
            }
        }

        if (defined($oconf->{attr}{$attr}->{webcontent})) {
            my $val_content = $oconf->{attr}{$attr}->{webcontent}[0];
            my $val = $values[0];
            $val_content =~ s/\%a/$val/g;
            if ($reqformat eq 'json') {
                $val_content = JSON::DWIW->new({convert_bool => 1})->from_json($val_content);
            }
            $values[0] = $val_content;
        }

        if($action eq "ADD") {
            if (defined($oconf->{attr}{$attr}->{add})) {
                ($rc, $error) = $self->_addAttrValues($oconf, $id, $pkeys, $attr, @values);
                if ($rc) {
                    return (LDAP_OPERATIONS_ERROR, $error);
                }
            } elsif ($method eq 'GET') {
                $mod_querystr .= ($mod_querystr ? '&' : '')."$param=".uri_escape(encode($conf->{mbcode}[0], $values[0]));
            } elsif (defined($tmpentry->{$param})) {
                if ($reqformat eq 'POST' && @values > 1) {
                    $tmpentry->{$param} = \@values;
                } else {
                    $tmpentry->{$param} = $values[0];
                }
                $updated = 1;
            }
            $match = 1;
        } elsif($action eq "DELETE" && @values && $values[0]) {
            if (defined($oconf->{attr}{$attr}->{delete})) {
                ($rc, $error) = $self->_delAttrValues($oconf, $id, $pkeys, $attr, @values);
                if ($rc) {
                    return (LDAP_OPERATIONS_ERROR, $error);
                }
            } elsif ($method eq 'GET') {
                $mod_querystr .= ($mod_querystr ? '&' : '')."$param=\"\"";
                $updated = 1;
            } elsif (defined($tmpentry->{$param})) {
                $tmpentry->{$param} = '';
                $updated = 1;
            }
            $match = 1;
        } else {
            if (defined($oconf->{attr}{$attr}->{add}) || defined($oconf->{attr}{$attr}->{delete})) {
                my @old_vals = ($self->_getAttrValues($oconf, $id, $pkeys, $attr) =~ /^$attr: (.*)$/gmi);
                my @add_vals;
                my @delete_vals;

                if ($action eq "DELETE") {
                    @delete_vals = @old_vals;
                } elsif ($action eq "REPLACE") {
                    foreach my $value (@values) {
                        my $tmpval = $value;
                        $tmpval =~ s/^([^&]+)&[^=]+=.+$/$1/;
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
                            push(@add_vals, $value);
                        }
                    }
                    @delete_vals = @old_vals;
                }

                if (@add_vals) {
                    ($rc, $error) = $self->_addAttrValues($oconf, $id, $pkeys, $attr, @add_vals);
                    if ($rc) {
                        return (LDAP_OPERATIONS_ERROR, $error);
                    }
                    $match = 1;
                }
                if (@delete_vals) {
                    ($rc, $error) = $self->_delAttrValues($oconf, $id, $pkeys, $attr, @delete_vals);
                    if ($rc) {
                        return LDAP_OPERATIONS_ERROR;
                    }
                    $match = 1;
                }
            } elsif (defined($oconf->{attr}{$attr}->{replace})) {
                ($rc, $error) = $self->_replaceAttrValues($oconf, $id, $pkeys, $attr, @values);
                if ($rc) {
                    return (LDAP_OPERATIONS_ERROR, $error);
                }
            } else {
                if ($action eq "DELETE") {
                    if ($method eq 'GET') {
                        $mod_querystr .= ($mod_querystr ? '&' : '')."$param=\"\"";
                    } else {
                        $tmpentry->{$param} = '';
                    }
                    $updated = 1;
                } elsif ($action eq "REPLACE") {
                    if ($method eq 'GET') {
                        $mod_querystr .= ($mod_querystr ? '&' : '')."$param=".uri_escape(encode($conf->{mbcode}[0], $values[0]));
                    } else {
                        if ($reqformat eq 'POST' && @values > 1 || (defined($oconf->{attr}{$attr}->{multivalued}) && $oconf->{attr}{$attr}->{multivalued})) {
                            $tmpentry->{$param} = \@values;
                        } else {
                            $tmpentry->{$param} = $values[0];
                        }
                    }
                    $updated = 1;
                }
                if ($oconf->{rdn}[0] =~ /^$attr$/i) {
                    next;
                }
                $match = 1;
            }
        }
    }

    if (!$match && !$rename) {
        return ($rc, 'LISM_NO_OPERATION');
    }

    if (!defined($oconf->{modify})) {
        return $rc;
    }

    if (!$updated) {
        return ($rc, $error);
    }

    my $modify = $oconf->{modify}[0];

    if (defined($modify->{path})) {
        $url = "$url$modify->{path}[0]";
    }
    if (index($url, '%r') < 0) {
        if ($mod_querystr && defined($oconf->{id})) {
            $mod_querystr .= '&'.$oconf->{id}[0]->{param}[0]."=$id";
        }
    } else {
        $url =~ s/\%r/$id/g;
    }
    $url = $self->_containerParse($url, @{$pkeys});

    my $querystr = '';
    if (defined($self->{session_param})) {
        $querystr = "$self->{session_param}=$self->{session}";
    }

    if ($querystr) {
        $url = $url.(index($url, '?') < 0 ? '?' : '&').$querystr;
    }

    if (defined($oconf->{modify}[0]->{tag})) {
        my $tmpentry = {};
        my $current = \$tmpentry;
        foreach my $tag (split(/, */, $oconf->{modify}[0]->{tag}[0])) {
            if ($tag =~ /^ *$/) {
                last;
            }
            ${$current} = {};
            ${$current}->{$tag} = $entry;
            $current = \${$current}->{$tag};
        }
        $entry = $tmpentry;
    }
    if (defined($oconf->{modify}[0]->{listtag})) {
        my $tmpentry = {$oconf->{modify}[0]->{listtag}[0] => [$entry]};
        $entry = $tmpentry;
    }
    if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{apiparam})) {
        foreach my $param (keys %{$self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}}) {
            ${$entry}{$param} = $self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}{$param}->{value};
        }
    }

    my $content = $self->_buildContent($oconf, $entry);

    if ($reqformat eq 'json') {
        $contentType = 'application/json';
    } elsif ($reqformat eq 'xml') {
        $contentType = 'text/xml';
    }

    if (defined($self->{session_param}) && $reqformat eq 'POST') {
        $content .= '&'.$self->{session_param}.'='.$self->{session};
    }

    if (defined($self->{paramauth})) {
        if ($method eq 'GET') {
            $mod_querystr .= ($mod_querystr ? '&': '').$self->{paramauth};
        } elsif ($reqformat eq 'POST') {
            $content .= '&'.$self->{paramauth};
        }
    }

    my $req;
    if ($method eq 'GET') {
        $req = GET $url.(index($url, '?') < 0 ? '?' : '&').$mod_querystr;
    } elsif ($method eq 'POST') {
        if ($reqformat eq 'POST') {
            $req = POST $url, Content => $content;
        } elsif (defined($oconf->{reqparam})) {
            $req = POST $url, Content => $oconf->{reqparam}[0]."=$content";
        } else {
            $req = POST $url, Content_Type => $contentType, Content => $content;
        }
    } elsif ($method eq 'PATCH') {
        $req = HTTP::Request->new(PATCH => $url);
        $req->header('Content-Type', $contentType);
        $req->content($content);
    } else {
        $req = PUT $url, Content_Type => $contentType, Content => $content;
    }
    if (defined($self->{basicauth})) {
        $req->authorization_basic($self->{basicauth}->{user}, $self->{basicauth}->{pw});
    }
    if (defined($self->{session_cookie})) {
        $req->header(Cookie => "$self->{session_cookie}=$self->{session}");
    }
    if (defined($self->{oauth})) {
        my $token_type = $login && defined($login->{oauth}) && defined($login->{oauth}[0]->{token_type}) ? $login->{oauth}[0]->{token_type}[0] : 'Bearer';
        $req->header(Authorization => "$token_type $self->{oauth}->{token}");
        if (defined($login->{oauth}[0]->{client_secret_header})) {
            $req->header($login->{oauth}[0]->{client_secret_header}[0], $self->{oauth}->{client_secret});
        }
    }

    my $res;
    for (my $i = 0; $i < $RETRY; $i++) {
        $res = $self->{ua}->request($req);
        if ($res->is_error && $res->code == 401 && defined($oconf->{container}) && defined($oconf->{container}[0]->{login})) {
            ($rc, $error) = $self->_relogin($pkey, $dn, $login);
            if (!$self->{multilogin}->{current}) {
                return (LDAP_NO_SUCH_OBJECT, $error);
            }
            if ($rc) {
                return (LDAP_OTHER, $error);
            }
            next;
        } elsif ($res->is_error && ($res->status_line =~ /timeout/ || $res->code =~ /^50/)) {
            sleep $conf->{connection}[0]->{interval}[0] * ($i + 1);
            next;
        }
        last;
    }
    if ($res->is_success) {
        if (defined($oconf->{result})) {
            my %result;
            $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
            if ($rc) {
                $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                $self->log(level => 'err', message => "Modifying $dn in REST service($url) failed: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST modify url=$url content=$content response=".$res->content);
                }
            } elsif (defined($result{message})) {
                $error = $result{message};
            }
        }
    } else {
        $rc = LDAP_OTHER;
        if (defined($oconf->{result})) {
            my %result;
            $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
            if ($rc) {
                $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                $self->log(level => 'err', message => "Modifying $dn in REST service($url) failed: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST modify url=$url content=$content response=".$res->content);
                }
            }
        } else {
            my $econtent = $res->content;
            $econtent =~ s/\n/ /g;
            $error = $res->status_line.(length($econtent) <= 128 ? $econtent : '');
            $self->log(level => 'err', message => "Modifying $dn in REST service($url) failed: $error".($res->content ? ' '.substr($res->content, 0, 512) : ''));
            if ($conf->{sysloglevel} eq 'debug') {
                $self->log(level => 'debug', message => "REST modify url=$url content=$content response=".$res->content);
            }
        }
    }

    return ($rc, $error);
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
    my $login;
    my $format = defined($oconf->{format}) ? $oconf->{format}[0] : $conf->{format}[0];
    my $reqformat = defined($oconf->{reqformat}) ? $oconf->{reqformat}[0] : (defined($conf->{reqformat}) ? $conf->{reqformat}[0] : $format);
    my $contentType;
    my $rc = LDAP_SUCCESS;
    my $error;

    if (defined($oconf->{noop}) && grep(/^add$/i, @{$oconf->{noop}})) {
        return $rc;
    }

    my ($rdn_val) = ($entryStr =~ /^$oconf->{rdn}[0]: (.+)$/mi);
    if (!$rdn_val) {
        $self->log(level => 'err', message => "RDN value doesn't exist in entry($dn)");
        return LDAP_NAMING_VIOLATION;
    }

    if (!defined($oconf->{add})) {
        return $rc;
    }
    my $add = $oconf->{add}[0];

    my $url = defined($conf->{url}) ? $conf->{url}[0] : '';
    if (defined($oconf->{container})) {
        if (defined($oconf->{container}[0]->{login})) {
            $login = $oconf->{container}[0]->{login}[0];
            ($rc, $error) = $self->_relogin($pkey, $dn, $login);
            if (!$self->{multilogin}->{current}) {
                return (LDAP_NO_SUCH_OBJECT, $error);
            }
            if ($rc) {
                return (LDAP_OTHER, $error);
            }
            if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{url})) {
                $url = $self->{multilogin}{$self->{multilogin}->{current}}->{url};
            }
            if ($self->{multilogin}{$self->{multilogin}->{current}}->{randpwd} && $self->{multilogin}{$self->{multilogin}->{current}}->{admin} ne $rdn_val) {
                my ($len, $op) = split(/:/, $self->{multilogin}{$self->{multilogin}->{current}}->{randpwd});
                if (!$op || $op eq 'add') {
                    my $randpwd = $self->random($len, 'randompassword', $entryStr);
                    if ($randpwd) {
                        $entryStr =~ s/^userPassword: .*$/userPassword: $randpwd/mi;
                    }
                } else {
                    $entryStr =~ s/\nuserPassword: [^\n]*\n?/\n/mi;
                }
            }
        }
    }
    if (!$pkey) {
        if (defined($conf->{login})) {
            $login = $conf->{login}[0];
        }
        if ($self->{multilogin}->{current} ne 'default' && $login) {
            ($rc, $error) = $self->_relogin('default', $dn, $login);
            if ($rc) {
                return (LDAP_OTHER, $error);
            }
        }
    }

    if (defined($add->{path})) {
        $url = "$url$add->{path}[0]";
    }
    $url =~ s/\%r/$rdn_val/g;
    $url = $self->_containerParse($url, @{$pkeys});

    my $querystr = '';
    if (defined($self->{session_param})) {
        $querystr = "$self->{session_param}=$self->{session}";
    }

    if ($querystr) {
        $url = $url.(index($url, '?') < 0 ? '?' : '&').$querystr;
    }

    if ($reqformat eq 'json') {
        $contentType = 'application/json';
    } elsif ($reqformat eq 'xml') {
        $contentType = 'text/xml';
    }

    my $method;
    if (defined($oconf->{add}[0]->{method})) {
        $method = $oconf->{add}[0]->{method}[0];
    }

    my $content;
    if (defined($oconf->{add}[0]->{webcontent})) {
        $content = $oconf->{add}[0]->{webcontent}[0];
        $content =~ s/\%r/$rdn_val/g;
        $content = $self->_funcParse($content, $dn, $entryStr);
    } else {
        $content = $self->_entryToContent($oconf, $pkey, "$dn\n$entryStr");
    }

    if (defined($self->{session_param}) && $reqformat eq 'POST') {
        $content .= '&'.$self->{session_param}.'='.$self->{session};
    }

    if (defined($self->{paramauth}) && ($method eq 'GET' || $reqformat eq 'POST')) {
        $content .= '&'.$self->{paramauth};
    }

    my $req;
    if ($method eq 'GET') {
        $req = GET $url.$content;
    } elsif ($reqformat eq 'POST') {
        $req = POST $url, Content => $content;
    } elsif (defined($oconf->{reqparam})) {
        $req = POST $url, Content => $oconf->{reqparam}[0]."=$content";
    } else {
        $req = POST $url, Content_Type => $contentType, Content => $content;
    }
    if (defined($self->{basicauth})) {
        $req->authorization_basic($self->{basicauth}->{user}, $self->{basicauth}->{pw});
    }
    if (defined($self->{session_cookie})) {
        $req->header(Cookie => "$self->{session_cookie}=$self->{session}");
    }
    if (defined($self->{oauth})) {
        my $token_type = $login && defined($login->{oauth}) && defined($login->{oauth}[0]->{token_type}) ? $login->{oauth}[0]->{token_type}[0] : 'Bearer';
        $req->header(Authorization => "$token_type $self->{oauth}->{token}");
        if (defined($login->{oauth}[0]->{client_secret_header})) {
            $req->header($login->{oauth}[0]->{client_secret_header}[0], $self->{oauth}->{client_secret});
        }
    }

    my $res;
    for (my $i = 0; $i < $RETRY; $i++) {
        $res = $self->{ua}->request($req);
        if ($res->is_error && $res->code == 401 && defined($oconf->{container}) && defined($oconf->{container}[0]->{login})) {
            ($rc, $error) = $self->_relogin($pkey, $dn, $login);
            if (!$self->{multilogin}->{current}) {
                return (LDAP_NO_SUCH_OBJECT, $error);
            }
            if ($rc) {
                return (LDAP_OTHER, $error);
            }
            next;
        } elsif ($res->is_error && ($res->status_line =~ /timeout/ || $res->code =~ /^50/)) {
            sleep $conf->{connection}[0]->{interval}[0] * ($i + 1);
            next;
        }
        last;
    }
    if ($res->is_success) {
        if (defined($oconf->{result})) {
            my %result;
            $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code, 'add');
            if ($rc) {
                $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                $self->log(level => 'err', message => "Adding $dn in REST service($url) failed: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST add url=$url content=$content response=".$res->content);
                }
                return ($rc, $error);
            }
        }
    } else {
        $rc = LDAP_OTHER;
        if (defined($oconf->{result})) {
            my %result;
            $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code, 'add');
            if ($rc) {
                $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                $self->log(level => 'err', message => "Adding $dn in REST service($url) failed: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST add url=$url content=$content response=".$res->content);
                }
            }
        } else {
            my $econtent = $res->content;
            $econtent =~ s/\n/ /g;
            $error = $res->status_line.(length($econtent) <= 128 ? $econtent : '');
            $self->log(level => 'err', message => "Adding $dn in REST service($url) failed: $error".($res->content ? ' '.substr($res->content, 0, 512) : ''));
            if ($conf->{sysloglevel} eq 'debug') {
                $self->log(level => 'debug', message => "REST add url=$url content=$content response=".$res->content);
            }
        }
        return ($rc, $error);
    }

    my $id;
    foreach my $attr (keys %{$oconf->{attr}}) {
        if (defined($oconf->{attr}{$attr}->{add})) {
            if (!$id) {
                if (defined($oconf->{id}) && $oconf->{id}[0]->{param}[0] ne $oconf->{rdn}[0] && defined($oconf->{search})) {
                    my $entry;
                    ($rc, $id, $entry) = $self->_restSearch($obj, $pkeys, $dn);
                    if ($rc) {
                        return $rc;
                    } elsif (!$entry) {
                        return LDAP_OTHER;
                    }
                } else {
                    $id = $rdn_val;
                }
            }
            my @values = ($entryStr =~ /^$attr: (.*)/mi);
            if (@values) {
                ($rc, $error) = $self->_addAttrValues($oconf, $id, $pkeys, $attr, @values);
                if ($rc) {
                    $self->_objDelete($obj, $pkeys, $dn);

                    return ($rc, $error);
                }
            }
        }
    }

    return ($rc, $error);
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
    my $login;
    my $format = defined($oconf->{format}) ? $oconf->{format}[0] : $conf->{format}[0];
    my $reqformat = defined($oconf->{reqformat}) ? $oconf->{reqformat}[0] : (defined($conf->{reqformat}) ? $conf->{reqformat}[0] : $format);
    my $contentType;
    my $rc = LDAP_SUCCESS;
    my $error;
    my $id;
    my $entry;

    if (defined($oconf->{noop}) && grep(/^delete$/i, @{$oconf->{noop}})) {
        return $rc;
    }

    if (defined($oconf->{search})) {
        ($rc, $id, $entry) = $self->_restSearch($obj, $pkeys, $dn);
        if ($rc) {
            return $rc;
        } elsif (!$entry) {
            return LDAP_NO_SUCH_OBJECT;
        }
    }

    my ($rdn_val) = ($dn =~ /^[^=]+=([^,]+)/);
    if (!$id) {
        $id = $rdn_val;
    }

    if (!defined($oconf->{delete})) {
        return ($rc, $error);
    }

    my $url = defined($conf->{url}) ? $conf->{url}[0] : '';
    if (defined($oconf->{container})) {
        if (defined($oconf->{container}[0]->{login})) {
            $login =  $oconf->{container}[0]->{login}[0];
            ($rc, $error) = $self->_relogin($pkey, $dn, $login);
            if (!$self->{multilogin}->{current}) {
                return (LDAP_NO_SUCH_OBJECT, $error);
            }
            if ($rc) {
                return (LDAP_OTHER, $error);
            }
            if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{url})) {
                $url = $self->{multilogin}{$self->{multilogin}->{current}}->{url};
            }
        }
    }
    if (!$pkey) {
        if (defined($conf->{login})) {
            $login = $conf->{login}[0];
        }
        if ($self->{multilogin}->{current} ne 'default' && $login) {
            ($rc, $error) = $self->_relogin('default', $dn, $login);
            if ($rc) {
                return (LDAP_OTHER, $error);
            }
        }
    }

    for (my $i = 0; $i < @{$oconf->{delete}}; $i++) {
        my $delete = $oconf->{delete}[$i];
        if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{logicaldelete}) && !defined($delete->{logicaldelete})) {
            next;
        }
        if (defined($delete->{path})) {
            $url = "$url$delete->{path}[0]";
        }
        $url =~ s/\%r/$id/g;
        $url = $self->_containerParse($url, @{$pkeys});

        my $querystr = '';
        if (defined($self->{session_param})) {
            $querystr = "$self->{session_param}=$self->{session}";
        }

        if ($querystr) {
            $url = $url.(index($url, '?') < 0 ? '?' : '&').$querystr;
        }

        my $method;
        if (defined($delete->{method})) {
            $method = $delete->{method}[0];
        }

        my $req;
        if ($method eq 'GET') {
            if (defined($self->{paramauth})) {
                $url .= (index($url, '?') < 0 ? '?' : '&').'&'.$self->{paramauth};
            }
            $req = GET $url;
        } elsif ($method eq 'POST') {
            if (defined($delete->{webcontent})) {
                my $content = $delete->{webcontent}[0];
                $content =~ s/\%r/$id/g;
                if (defined($self->{session_param}) && $reqformat eq 'POST') {
                    $content .= '&'.$self->{session_param}.'='.$self->{session};
                }
                if (defined($self->{paramauth}) && $reqformat eq 'POST') {
                    $content .= '&'.$self->{paramauth};
                }

                $req = POST $url, Content => $content;
                if ($reqformat eq 'json') {
                    $req->header('Content-Type' => 'application/json');
                    $req->header('Content-Length' => length($content));
                }
            } else {
                $req = POST $url;
                if ($reqformat eq 'json') {
                    my $content = '{"'.(defined($oconf->{id}) ? $oconf->{id}[0]->{param}[0] : $oconf->{attr}{$oconf->{rdn}[0]}->{param}[0]).'":"'.$id.'"}';
                    if (defined($oconf->{delete}[0]->{tag})) {
                        my $top = '';
                        my $end = '';
                        foreach my $tag (split(/, */, $oconf->{delete}[0]->{tag})) {
                            if ($tag =~ /^ *$/) {
                                last;
                            }
                            $top .= "{\"$tag\": ";
                            $end .= "}";
                        }
                        if ($top) {
                            $content = "$top$content$end";
                        }
                    }
                    if (defined($oconf->{delete}[0]->{listtag})) {
                        $content = "{\"$oconf->{delete}[0]->{listtag}[0]\":[$content]}";
                    }
                    if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{apiparam})) {
                        my $apiparams = '';
                        foreach my $param (keys %{$self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}}) {
                            $apiparams .= "\"$param\":\"$self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}{$param}->{value}\",";
                        }
                        if ($apiparams) {
                            $content =~ s/^{/{$apiparams/;
                        }
                    }
                    $content = encode('utf8', $content);
                    if (defined($oconf->{reqparam})) {
                        $content = $oconf->{reqparam}[0]."=$content";
                    } else {
                        $req->header('Content-Type' => 'application/json');
                    }
                    $req->header('Content-Length' => length($content));
                    $req->content($content);
                } elsif ($reqformat eq 'POST') {
                    my $content = (defined($oconf->{id}) ? $oconf->{id}[0]->{param}[0] : $oconf->{attr}{$oconf->{rdn}[0]}->{param}[0]).'='.$id;
                    if (defined($delete->{param})) {
                        foreach my $param (keys(%{$delete->{param}})) {
                            $content .= "&$param=".$delete->{param}{$param}->{value};
                        }
                    }
                    if (defined($self->{session_param})) {
                        $content .= '&'.$self->{session_param}.'='.$self->{session};
                    }
                    if (defined($self->{paramauth})) {
                        $content .= '&'.$self->{paramauth};
                    }
                    $req->header('Content-Length' => length($content));
                    $req->content($content);
                }
            }
        } else {
            $req = DELETE $url;
            if ($reqformat eq 'json') {
                my $content = '{"'.(defined($oconf->{id}) ? $oconf->{id}[0]->{param}[0] : $oconf->{attr}{$oconf->{rdn}[0]}->{param}[0]).'":"'.$id.'"}';
                if (defined($oconf->{delete}[0]->{tag})) {
                    my $top = '';
                    my $end = '';
                    foreach my $tag (split(/, */, $oconf->{delete}[0]->{tag})) {
                        if ($tag =~ /^ *$/) {
                            last;
                        }
                        $top .= "{\"$tag\": ";
                        $end .= "}";
                    }
                    if ($top) {
                        $content = "$top$content$end";
                    }
                }
                if (defined($oconf->{delete}[0]->{listtag})) {
                    $content = "{\"$oconf->{delete}[0]->{listtag}[0]\":[$content]}";
                }
                if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{apiparam})) {
                    my $apiparams = '';
                    foreach my $param (keys %{$self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}}) {
                        $apiparams .= "\"$param\":\"$self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}{$param}->{value}\",";
                    }
                    if ($apiparams) {
                        $content =~ s/^{/{$apiparams/;
                    }
                }
                $content = encode('utf8', $content);
                if (defined($oconf->{reqparam})) {
                    $content = $oconf->{reqparam}[0]."=$content";
                } else {
                    $req->header('Content-Type' => 'application/json');
                }
                $req->header('Content-Length' => length($content));
                $req->content($content);
            }
        }
        if (defined($self->{basicauth})) {
            $req->authorization_basic($self->{basicauth}->{user}, $self->{basicauth}->{pw});
        }
        if (defined($self->{session_cookie})) {
            $req->header(Cookie => "$self->{session_cookie}=$self->{session}");
        }
        if (defined($self->{oauth})) {
            my $token_type = $login && defined($login->{oauth}) && defined($login->{oauth}[0]->{token_type}) ? $login->{oauth}[0]->{token_type}[0] : 'Bearer';
            $req->header(Authorization => "$token_type $self->{oauth}->{token}");
            if (defined($login->{oauth}[0]->{client_secret_header})) {
                $req->header($login->{oauth}[0]->{client_secret_header}[0], $self->{oauth}->{client_secret});
            }
        }

        my $res;
        for (my $j = 0; $j < $RETRY; $j++) {
            $res = $self->{ua}->request($req);
            if ($res->is_error && $res->code == 401 && defined($oconf->{container}) && defined($oconf->{container}[0]->{login})) {
                ($rc, $error) = $self->_relogin($pkey, $dn, $login);
                if (!$self->{multilogin}->{current}) {
                    return (LDAP_NO_SUCH_OBJECT, $error);
                }
                if ($rc) {
                    return (LDAP_OTHER, $error);
                }
                next;
            } elsif ($res->is_error && ($res->status_line =~ /timeout/ || $res->code =~ /^50/)) {
                sleep $conf->{connection}[0]->{interval}[0] * ($j + 1);
                next;
            }
            last;
        }
        if ($res->is_success) {
            if (defined($oconf->{result})) {
                my %result;
                $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
                if ($rc) {
                    $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                    $self->log(level => 'err', message => "Deleting $dn in REST service($url) failed: $error");
                    if ($conf->{sysloglevel} eq 'debug') {
                        $self->log(level => 'debug', message => "REST delete url=$url response=".$res->content);
                    }
                }
            }
        } else {
            $rc = LDAP_OTHER;
            if (defined($oconf->{result})) {
                my %result;
                $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
                if ($rc) {
                    $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                    $self->log(level => 'err', message => "Deleting $dn in REST service($url) failed: $error");
                    if ($conf->{sysloglevel} eq 'debug') {
                        $self->log(level => 'debug', message => "REST delete url=$url response=".$res->content);
                    }
                }
            } else {
                my $econtent = $res->content;
                $econtent =~ s/\n/ /g;
                $error = $res->status_line.(length($econtent) <= 128 ? $econtent : '');
                $self->log(level => 'err', message => "Deleting $dn in REST service($url) failed: $error".($res->content ? ' '.substr($res->content, 0, 512) : ''));
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST delete url=$url response=".$res->content);
                }
            }
        }
        if ($rc) {
            last;
        }
    }

    return ($rc, $error);
}

sub _restSearch
{
    my $self = shift;
    my ($obj, $pkeys, $dn) = @_;
    my $conf = $self->{_config};
    my $oconf = $obj->{conf};
    my $pkey = $self->_getPid($pkeys);
    my $login;
    my $format = defined($oconf->{format}) ? $oconf->{format}[0] : $conf->{format}[0];
    my $reqformat = defined($oconf->{reqformat}) ? $oconf->{reqformat}[0] : (defined($conf->{reqformat}) ? $conf->{reqformat}[0] : $format);
    my $rc = LDAP_SUCCESS;
    my $error;

    if (!defined($oconf->{search})) {
        return undef;
    }
    my $search = defined($oconf->{read}) ? $oconf->{read}[0] : $oconf->{search}[0];
    my $baseurl = defined($conf->{url}[0]) ? $conf->{url}[0] : '';

    if (defined($oconf->{container})) {
        if (defined($oconf->{container}[0]->{login})) {
            $login = $oconf->{container}[0]->{login}[0];
            ($rc, $error) = $self->_relogin($pkey, $dn, $login);
            if (!$self->{multilogin}->{current}) {
                $rc = LDAP_NO_SUCH_OBJECT;
            }
            if ($rc) {
                $self->log(level => 'err', message => "Login to REST service failed: $error");

                return (LDAP_OTHER, undef, undef);
            }
            if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{url})) {
                $baseurl = $self->{multilogin}{$self->{multilogin}->{current}}->{url};
            }
        }
    }

    my $url = $baseurl.(defined($search->{path}) ? $search->{path}[0] : '');

    if (!$pkey) {
        if (defined($conf->{login})) {
            $login = $conf->{login}[0];
        }
        if ($self->{multilogin}->{current} ne 'default' && $login) {
            ($rc, $error) = $self->_relogin('default', $dn, $login);
            if ($rc) {
                $self->log(level => 'err', message => "Login to default REST service failed: $error");

                return (LDAP_OTHER, undef, undef);
            }
        }
    }

    my $post_id = 0;
    my ($rdn_val) = ($dn =~ /^[^=]+=([^,]+)/);
    my $regex_rdn_val = $rdn_val;
    $regex_rdn_val =~ s/([.*+?\[\]()|\^\$\\])/\\$1/g;
    if (index($url, '%r') < 0) {
        $post_id = 1;
    } else {
        $url =~ s/\%r/$rdn_val/g;
    }
    $url = $self->_containerParse($url, @{$pkeys});

    my $method = '';
    if (defined($search->{method})) {
        $method = $search->{method}[0];
    }

    my $reqcontent;
    if ($method eq 'POST') {
        if ($reqformat eq 'json') {
            if (defined($search->{webcontent})) {
                $reqcontent = $search->{webcontent}[0];
                $reqcontent =~ s/\%r/$rdn_val/g;
            } else {
                my $json = {};
                if (defined($search->{filter}) && defined($search->{filter}{$oconf->{rdn}[0]})) {
                    ${$json}{$search->{filter}{$oconf->{rdn}[0]}->{param}} = $rdn_val;
                }
                if (defined($search->{listtag})) {
                    $json = {$search->{listtag}[0] => [$json]};
                }
                if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{apiparam})) {
                    foreach my $param (keys %{$self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}}) {
                        ${$json}{$param} = $self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}{$param}->{value};
                    }
                }
                $reqcontent = JSON::DWIW->new->to_json($json);
            }
        } else {
            if ($post_id && defined($oconf->{id}) && defined($oconf->{id}[0]->{param})) {
                $reqcontent = $oconf->{id}[0]->{param}[0]."=$rdn_val";
            }
            if (defined($search->{param})) {
                foreach my $param (keys(%{$search->{param}})) {
                    my $value = $search->{param}{$param}->{value};
                    $reqcontent .= ($reqcontent ? '&' : '')."$param=$value";
                }
            }
            if (defined($self->{session_param})) {
                $reqcontent .= ($reqcontent ? '&' : '')."$self->{session_param}=$self->{session}";
            }
            if (defined($self->{paramauth})) {
                $reqcontent .= ($reqcontent ? '&' : '').$self->{paramauth};
            }
        }
    } else {
        my $querystr = '';
        if (defined($self->{session_param})) {
            $querystr = "$self->{session_param}=$self->{session}";
        }
        if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{apiparam})) {
            foreach my $param (keys %{$self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}}) {
                $querystr .= ($querystr ? '&' : '')."$param=$self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}{$param}->{value}";
            }
        }

        if ($querystr) {
            $url = $url.(index($url, '?') < 0 ? '?' : '&').$querystr;
        }
    }

    my $req;
    if ($method eq 'POST') {
        $req = POST $url;
        if (defined($oconf->{reqparam})) {
            $reqcontent = encode('utf8', $reqcontent);
            $reqcontent = $oconf->{reqparam}[0]."=$reqcontent";
            $req->header('Content-Length' => length($reqcontent));
            $req->content($reqcontent);
        } elsif ($reqformat eq 'json') {
            $req->header('Content-Type' => 'application/json');
            $req->header('Content-Length' => length($reqcontent));
            $req->content($reqcontent);
        } elsif ($reqcontent) {
            $req->header('Content-Length' => length($reqcontent));
            $req->content($reqcontent);
        }
    } else {
        $req = GET $url;
    }
    if (defined($self->{basicauth})) {
        $req->authorization_basic($self->{basicauth}->{user}, $self->{basicauth}->{pw});
    }
    if (defined($self->{session_cookie})) {
        $req->header(Cookie => "$self->{session_cookie}=$self->{session}");
    }
    if (defined($self->{oauth})) {
        my $token_type = $login && defined($login->{oauth}) && defined($login->{oauth}[0]->{token_type}) ? $login->{oauth}[0]->{token_type}[0] : 'Bearer';
        $req->header(Authorization => "$token_type $self->{oauth}->{token}");
        if (defined($login->{oauth}[0]->{client_secret_header})) {
            $req->header($login->{oauth}[0]->{client_secret_header}[0], $self->{oauth}->{client_secret});
        }
    }

    my $res;
    for (my $i = 0; $i < $RETRY; $i++) {
        $res = $self->{ua}->request($req);
        if ($res->is_error && $res->code == 401 && defined($oconf->{container}) && defined($oconf->{container}[0]->{login})) {
            ($rc, $error) = $self->_relogin($pkey, $dn, $login);
            if (!$self->{multilogin}->{current}) {
                $rc = LDAP_NO_SUCH_OBJECT;
            }
            if ($rc) {
                $self->log(level => 'err', message => "Login to REST service failed: $error");

                return (LDAP_OTHER, undef, undef);
            }
            next;
        } elsif ($res->is_error && ($res->status_line =~ /timeout/ || $res->code =~ /^50/)) {
            sleep $conf->{connection}[0]->{interval}[0] * ($i + 1);
            next;
        }
        last;
    }
    if ($res->is_success) {
        if (defined($oconf->{result})) {
            my %result;
            $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
            if ($rc) {
                my $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                $self->log(level => 'err', message => "Searching $dn in REST service($url) failed: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
                }
                return ($rc, undef, undef);
            }
        }

        my $content;
        my $entries;
        if ($format eq 'json') {
            my $error;
            ($content, $error) = JSON::DWIW->new({convert_bool => 1})->from_json($res->content);
            if (!defined($content)) {
                $self->log(level => 'err', message => "REST search response is not JSON: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
                }
                return (LDAP_OTHER, undef, undef);
            }
        } elsif ($format eq 'xml') {
            $content = eval {XMLin($res->content, ValueAttr => ['value'], KeyAttr => {})};
            if ($@) {
                $self->log(level => 'err', message => "REST search response is not XML: $@");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
                }
                return (LDAP_OTHER, undef, undef);
            }
        }

        $entries = $content;
        foreach my $tag (split(/, */, $search->{list}[0]->{tag})) {
            if (ref($entries) eq 'HASH' && defined($entries->{$tag})) {
                $entries = $entries->{$tag};
            } else {
                last;
            }
        }
        if (ref($entries) ne 'ARRAY') {
            $entries = [$entries];
        }

        foreach my $entry (@{$entries}) {
            if (defined($oconf->{param})) {
                if (!defined($entry->{$oconf->{param}[0]})) {
                    next;
                }
                $entry = $entry->{$oconf->{param}[0]};
            }
            if ($entry->{$oconf->{attr}{$oconf->{rdn}[0]}->{param}[0]} =~ /^$regex_rdn_val$/i || !$post_id) {
                my $id = defined($oconf->{id}) && defined($entry->{$oconf->{id}[0]->{param}[0]}) ? $entry->{$oconf->{id}[0]->{param}[0]} : $rdn_val;
                foreach my $attr (keys %{$oconf->{attr}}) {
                    if (!defined($oconf->{attr}{$attr}->{param}) || !defined($oconf->{attr}{$attr}->{valmap})) {
                        next;
                    }
                    my $tmpentry = defined($oconf->{attr}{$attr}->{parent}) ? $entry->{$oconf->{attr}{$attr}->{parent}[0]} : $entry;
                    my $param = $oconf->{attr}{$attr}->{param}[0];
                    if (!defined($tmpentry->{$param})) {
                        next;
                    }
                    my @values = $tmpentry->{$param};
                    my $match = 0;
                    for (my $i = 0; $i < @values; $i++) {
                        foreach my $valmap (@{$oconf->{attr}{$attr}->{valmap}}) {
                            if (!ref($values[$i]) && $valmap->{output} eq $values[$i]) {
                                $values[$i] = $valmap->{input};
                                $match = 1;
                                last;
                            }
                        }
                    }
                    if ($match) {
                        $tmpentry->{$param} = @values;
                    }
                }
                return (LDAP_SUCCESS, $id, $entry);
            }
            if (defined($oconf->{search}[0]->{list}[0]->{recursive}) && $entry->{$oconf->{search}[0]->{list}[0]->{recursive}}) {
                my ($suffix) = ($dn =~ /^[^,]+,(.+)$/);
                my $filter = Net::LDAP::Filter->new("(".$oconf->{rdn}[0]."=$rdn_val)");
                my $keysp;
                my $entriesp;
                ($rc, $keysp, $entriesp) = $self->_getEntries($oconf, undef, $suffix, $filter, $rdn_val, 1, @{$entry->{$oconf->{search}[0]->{list}[0]->{recursive}}});
                if (!$rc && @{$entriesp}) {
                    my $entry2 = ${$entriesp}[0];
                    my $id = defined($oconf->{id}) && defined($entry2->{$oconf->{id}[0]->{param}[0]}) ? $entry2->{$oconf->{id}[0]->{param}[0]} : $rdn_val;
                    foreach my $attr (keys %{$oconf->{attr}}) {
                        if (!defined($oconf->{attr}{$attr}->{param}) || !defined($oconf->{attr}{$attr}->{valmap})) {
                            next;
                        }
                        my $tmpentry = defined($oconf->{attr}{$attr}->{parent}) ? $entry2->{$oconf->{attr}{$attr}->{parent}[0]} : $entry2;
                        my $param = $oconf->{attr}{$attr}->{param}[0];
                        if (!defined($tmpentry->{$param})) {
                            next;
                        }
                        my @values = $tmpentry->{$param};
                        my $match = 0;
                        for (my $i = 0; $i < @values; $i++) {
                            foreach my $valmap (@{$oconf->{attr}{$attr}->{valmap}}) {
                                if (!ref($values[$i]) && $valmap->{output} eq $values[$i]) {
                                    $values[$i] = $valmap->{input};
                                    $match = 1;
                                    last;
                                }
                            }
                        }
                        if ($match) {
                            $tmpentry->{$param} = @values;
                        }
                    }
                    return (LDAP_SUCCESS, $id, $entry2);
                }
            }
        }
    } elsif ($res->code != 404) {
        if (defined($oconf->{result})) {
            my %result;
            $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
            if ($rc) {
                my $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                $self->log(level => 'err', message => "Searching $dn in REST service($url) failed: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
                }
            }
        } else {
            $self->log(level => 'err', message => "Searching $dn in REST service($url) failed: ".$res->status_line.($res->content ? ' '.substr($res->content, 0, 512) : ''));
            if ($conf->{sysloglevel} eq 'debug') {
                $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
            }
            $rc = LDAP_OTHER;
        }

        return ($rc, undef, undef);
    }

    return (LDAP_NO_SUCH_OBJECT, undef, undef);
}

sub _getAttrValues
{
    my $self = shift;
    my ($oconf, $key, $pkeys, $attr) = @_;
    my $conf = $self->{_config};
    my $format = defined($oconf->{format}) ? $oconf->{format}[0] : $conf->{format}[0];
    my $reqformat = defined($oconf->{reqformat}) ? $oconf->{reqformat}[0] : (defined($conf->{reqformat}) ? $conf->{reqformat}[0] : $format);
    my $login;
    if (defined($oconf->{container}) && defined($oconf->{container}[0]->{login})) {
        $login = $oconf->{container}[0]->{login}[0];
    } elsif (defined($conf->{login})) {
        $login = $conf->{login}[0];
    }

    if (!defined($oconf->{attr}{$attr}->{search})) {
        return undef;
    }
    my $search = $oconf->{attr}{$attr}->{search}[0];
    if (defined($oconf->{attr}{$attr}->{format})) {
        $format = $oconf->{attr}{$attr}->{format}[0];
    }

    my $url = defined($conf->{url}) ? $conf->{url}[0] : '';
    if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{url})) {
        $url = $self->{multilogin}{$self->{multilogin}->{current}}->{url};
    }
    $url .= $search->{path}[0];
    $url =~ s/\%r/$key/g;
    $url = $self->_containerParse($url, @{$pkeys});

    my $querystr = '';
    if (defined($self->{session_param})) {
        $querystr = "$self->{session_param}=$self->{session}";
    }

    if ($querystr) {
        $url = $url.(index($url, '?') < 0 ? '?' : '&').$querystr;
    }

    my $method = '';
    if (defined($oconf->{search}[0]->{method})) {
        $method = $oconf->{search}[0]->{method}[0];
    }

    my $content = defined($oconf->{attr}{$attr}->{search}[0]->{webcontent}) ? $oconf->{attr}{$attr}->{search}[0]->{webcontent}[0] : '';
    $content =~ s/\%r/$key/g;

    my $req;
    if ($method eq 'POST') {
        if ($content) {
            if (defined($self->{session_param}) && $reqformat eq 'POST') {
                $content .= '&'.$self->{session_param}.'='.$self->{session};
            }
            if (defined($self->{paramauth})) {
                $content .= '&'.$self->{paramauth};
            }
            $req = POST $url, Content => $content;
            my $contentType;
            if ($reqformat eq 'json') {
                $contentType = 'application/json';
            } elsif ($reqformat eq 'xml') {
                $contentType = 'text/xml';
            }
            if ($contentType) {
                $req->header('Content-Type' => $contentType);
            }
        } else {
            $req = POST $url;
        }
    } else {
        if (defined($self->{paramauth})) {
            $url .= (index($url, '?') < 0 ? '?' : '&').'&'.$self->{paramauth};
        }
        $req = GET $url;
    }
    if (defined($self->{basicauth})) {
        $req->authorization_basic($self->{basicauth}->{user}, $self->{basicauth}->{pw});
    }
    if (defined($self->{session_cookie})) {
        $req->header(Cookie => "$self->{session_cookie}=$self->{session}");
    }
    if (defined($self->{oauth})) {
        my $token_type = $login && defined($login->{oauth}) && defined($login->{oauth}[0]->{token_type}) ? $login->{oauth}[0]->{token_type}[0] : 'Bearer';
        $req->header(Authorization => "$token_type $self->{oauth}->{token}");
        if (defined($login->{oauth}[0]->{client_secret_header})) {
            $req->header($login->{oauth}[0]->{client_secret_header}[0], $self->{oauth}->{client_secret});
        }
    }

    my $res;
    for (my $i = 0; $i < $RETRY; $i++) {
        $res = $self->{ua}->request($req);
        if ($res->is_error && ($res->status_line =~ /timeout/ || $res->code =~ /^50/)) {
            sleep $conf->{connection}[0]->{interval}[0] * ($i + 1);
            next;
        }
        last;
    }
    if (!$res->is_success) {
        $self->log(level => 'err', message => "Searching $attr in REST service($url) failed: ".$res->status_line.($res->content ? ' '.substr($res->content, 0, 512) : ''));
        if ($conf->{sysloglevel} eq 'debug') {
            $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
        }
        return undef;
    }

    my $valStr = '';
    my $content;
    my $values;

    if ($format eq 'json') {
        my $error;
        ($content, $error) = JSON::DWIW->new({convert_bool => 1})->from_json($res->content);
        if (!defined($content)) {
            $self->log(level => 'err', message => "REST search response is not JSON: $error");
            if ($conf->{sysloglevel} eq 'debug') {
                $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
            }
            return undef;
        }
    } elsif ($format eq 'xml') {
        $content = eval {XMLin($res->content, ValueAttr => ['value'], KeyAttr => {})};
        if ($@) {
            $self->log(level => 'err', message => "REST search response is not XML: $@");
            if ($conf->{sysloglevel} eq 'debug') {
                $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
            }
            return undef;
        }
    }

    $values = $content;
    foreach my $tag (split(/, */, $search->{list}[0]->{tag})) {
        if (ref($values) eq 'ARRAY') {
            if (defined(${$values}[0]->{$tag})) {
                $values = ${$values}[0]->{$tag};
            } else {
                last;
            }
        } elsif (ref($values) eq 'HASH' && defined($values->{$tag})) {
            $values = $values->{$tag};
        } else {
            last;
        }
    }
    if (ref($values) ne 'ARRAY') {
        $values = [$values];
    }

    foreach my $value (@{$values}) {
        if (defined($search->{list}[0]->{param})) {
            my $match = 1;
            foreach my $tag (split(/, */, $search->{list}[0]->{param})) {
                if (ref($value) eq 'HASH' && defined($value->{$tag})) {
                    $value = $value->{$tag};
                } else {
                    $match = 0;
                    last;
                }
            }
            if ($match) {
                $valStr = "$valStr$attr: $value\n";
            }
        }
    }

    return $valStr;
}

sub _addAttrValues
{
    my $self = shift;
    my ($oconf, $key, $pkeys, $attr, @values) = @_;
    my $conf = $self->{_config};
    my $format = defined($oconf->{format}) ? $oconf->{format}[0] : $conf->{format}[0];
    my $reqformat = defined($oconf->{reqformat}) ? $oconf->{reqformat}[0] : (defined($conf->{reqformat}) ? $conf->{reqformat}[0] : $format);
    my $rc = LDAP_SUCCESS;
    my $error;
    my $login;
    if (defined($oconf->{container}) && defined($oconf->{container}[0]->{login})) {
        $login = $oconf->{container}[0]->{login}[0];
    } elsif (defined($conf->{login})) {
        $login = $conf->{login}[0];
    }

    if (!defined($oconf->{attr}{$attr}->{add})) {
        return ($rc);
    }

    if (defined($oconf->{attr}{$attr}->{add}[0]->{match}) &&
        !grep(/$oconf->{attr}{$attr}->{add}[0]->{match}/i, @values)) {
        return ($rc);
    }

    if (defined($oconf->{attr}{$attr}->{format})) {
        $format = $oconf->{attr}{$attr}->{format}[0];
    }

    my $url = defined($conf->{url}) ? $conf->{url}[0] : '';
    if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{url})) {
        $url = $self->{multilogin}{$self->{multilogin}->{current}}->{url};
    }
    if (defined($oconf->{attr}{$attr}->{add}[0]->{path})) {
        $url .= $oconf->{attr}{$attr}->{add}[0]->{path}[0];
    }
    $url =~ s/\%r/$key/g;
    $url = $self->_containerParse($url, @{$pkeys});

    my $querystr = '';
    if (defined($self->{session_param})) {
        $querystr = "$self->{session_param}=$self->{session}";
    }

    if ($querystr) {
        $url = $url.(index($url, '?') < 0 ? '?' : '&').$querystr;
    }

    my $method;
    if (defined($oconf->{attr}{$attr}->{add}[0]->{method})) {
        $method = $oconf->{attr}{$attr}->{add}[0]->{method}[0];
    } elsif (defined($oconf->{add}) && defined($oconf->{add}[0]->{method})) {
        $method = $oconf->{add}[0]->{method}[0];
    }

    foreach my $value (@values) {
        my $tmpurl = $url;
        my $content = defined($oconf->{attr}{$attr}->{add}[0]->{webcontent}) ? $oconf->{attr}{$attr}->{add}[0]->{webcontent}[0] : '';

        if ($value =~ /^ +$/) {
            if (defined($oconf->{attr}{$attr}->{delete})) {
                next;
            }
            $value = '';
        }
        $value =~ s/\\([0-9A-Fa-f][0-9A-Fa-f])/pack('H2', $1)/eg;
        $tmpurl =~ s/\%a/$value/g;
        $content =~ s/\%a/$value/g;
        $content =~ s/\%r/$key/g;

        my $req;
        if ($method eq 'GET') {
            if (defined($self->{paramauth})) {
                $tmpurl .= (index($tmpurl, '?') < 0 ? '?' : '&').'&'.$self->{paramauth};
            }
            $req = GET $tmpurl;
        } else {
            if ($content) {
                if (defined($self->{session_param}) && $reqformat eq 'POST') {
                    $content .= '&'.$self->{session_param}.'='.$self->{session};
                }
                if (defined($self->{paramauth})) {
                    $content .= '&'.$self->{paramauth};
                }
                $req = POST $tmpurl, Content => $content;
                my $contentType;
                if ($reqformat eq 'json') {
                    $contentType = 'application/json';
                } elsif ($reqformat eq 'xml') {
                    $contentType = 'text/xml';
                }
                if ($contentType) {
                    $req->header('Content-Type' => $contentType);
                }
            } else {
                $req = POST $tmpurl;
            }
        }
        if (defined($self->{basicauth})) {
            $req->authorization_basic($self->{basicauth}->{user}, $self->{basicauth}->{pw});
        }
        if (defined($self->{session_cookie})) {
            $req->header(Cookie => "$self->{session_cookie}=$self->{session}");
        }
        if (defined($self->{oauth})) {
            my $token_type = $login && defined($login->{oauth}) && defined($login->{oauth}[0]->{token_type}) ? $login->{oauth}[0]->{token_type}[0] : 'Bearer';
            $req->header(Authorization => "$token_type $self->{oauth}->{token}");
            if (defined($login->{oauth}[0]->{client_secret_header})) {
                $req->header($login->{oauth}[0]->{client_secret_header}[0], $self->{oauth}->{client_secret});
            }
        }

        my $res;
        for (my $i = 0; $i < $RETRY; $i++) {
            $res = $self->{ua}->request($req);
            if ($res->is_error && ($res->status_line =~ /timeout/ || $res->code =~ /^50/)) {
                sleep $conf->{connection}[0]->{interval}[0] * ($i + 1);
                next;
            }
            last;
        }
        if ($res->is_success) {
            if (defined($oconf->{result})) {
                my %result;
                $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
                if ($rc) {
                    if ($rc == LDAP_ALREADY_EXISTS) {
                        $rc = LDAP_TYPE_OR_VALUE_EXISTS;
                    } elsif ($rc == LDAP_NO_SUCH_OBJECT) {
                        $rc = LDAP_NO_SUCH_ATTRIBUTE;
                    }
                    $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                    $self->log(level => 'err', message => "Adding \"$value\" to $attr in REST service($tmpurl) failed: $error");
                    if ($conf->{sysloglevel} eq 'debug') {
                        $self->log(level => 'debug', message => "REST add value url=$tmpurl response=".$res->content);
                    }
                }
            }
        } else {
            $rc = LDAP_OTHER;
            if (defined($oconf->{result})) {
                my %result;
                $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
                if ($rc) {
                    if ($rc == LDAP_ALREADY_EXISTS) {
                        $rc = LDAP_TYPE_OR_VALUE_EXISTS;
                    } elsif ($rc == LDAP_NO_SUCH_OBJECT) {
                        $rc = LDAP_NO_SUCH_ATTRIBUTE;
                    }
                    $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                    $self->log(level => 'err', message => "Adding \"$value\" to $attr in REST service($tmpurl) failed: $error");
                    if ($conf->{sysloglevel} eq 'debug') {
                        $self->log(level => 'debug', message => "REST add value url=$tmpurl response=".$res->content);
                    }
                }
            } else {
                my $econtent = $res->content;
                $econtent =~ s/\n/ /g;
                $error = $res->status_line.(length($econtent) <= 128 ? $econtent : '');
                $self->log(level => 'err', message => "Adding \"$value\" to $attr in REST service($tmpurl) failed: $error".($res->content ? ' '.substr($res->content, 0, 512) : ''));
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST add value url=$tmpurl response=".$res->content);
                }
            }
        }
    }

    return ($rc, $error);
}

sub _delAttrValues
{
    my $self = shift;
    my ($oconf, $key, $pkeys, $attr, @values) = @_;
    my $conf = $self->{_config};
    my $format = defined($oconf->{format}) ? $oconf->{format}[0] : $conf->{format}[0];
    my $reqformat = defined($oconf->{reqformat}) ? $oconf->{reqformat}[0] : (defined($conf->{reqformat}) ? $conf->{reqformat}[0] : $format);
    my $rc = LDAP_SUCCESS;
    my $error;
    my $login;
    if (defined($oconf->{container}) && defined($oconf->{container}[0]->{login})) {
        $login = $oconf->{container}[0]->{login}[0];
    } elsif (defined($conf->{login})) {
        $login = $conf->{login}[0];
    }

    if (!defined($oconf->{attr}{$attr}->{delete})) {
        return ($rc);
    }

    if (defined($oconf->{attr}{$attr}->{delete}[0]->{match}) &&
        !grep(/$oconf->{attr}{$attr}->{delete}[0]->{match}/i, @values)) {
        return ($rc);
    }

    if (defined($oconf->{attr}{$attr}->{format})) {
        $format = $oconf->{attr}{$attr}->{format}[0];
    }

    my $url = defined($conf->{url}) ? $conf->{url}[0] : '';
    if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{url})) {
        $url = $self->{multilogin}{$self->{multilogin}->{current}}->{url};
    }
    if (defined($oconf->{attr}{$attr}->{delete}[0]->{path})) {
        $url .= $oconf->{attr}{$attr}->{delete}[0]->{path}[0];
    }
    $url =~ s/\%r/$key/g;
    $url = $self->_containerParse($url, @{$pkeys});

    my $querystr = '';
    if (defined($self->{session_param})) {
        $querystr = "$self->{session_param}=$self->{session}";
    }

    if ($querystr) {
        $url = $url.(index($url, '?') < 0 ? '?' : '&').$querystr;
    }

    my $method;
    if (defined($oconf->{attr}{$attr}->{delete}[0]->{method})) {
        $method = $oconf->{attr}{$attr}->{delete}[0]->{method}[0];
    } elsif (defined($oconf->{delete}) && defined($oconf->{delete}[0]->{method})) {
        $method = $oconf->{delete}[0]->{method}[0];
    }

    foreach my $value (@values) {
        my $tmpurl = $url;
        my $content = defined($oconf->{attr}{$attr}->{delete}[0]->{webcontent}) ? $oconf->{attr}{$attr}->{delete}[0]->{webcontent}[0] : '';

        if ($value =~ /^ +$/) {
            $value = '';
        }
        $value =~ s/\\([0-9A-Fa-f][0-9A-Fa-f])/pack('H2', $1)/eg;
        my $delval = $value;
        if (defined($oconf->{attr}{$attr}->{search}) && defined($oconf->{attr}{$attr}->{id})) {
            my $search = $oconf->{attr}{$attr}->{search}[0];
            my $url = defined($conf->{url}) ? $conf->{url}[0] : '';
            if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{url})) {
                $url = $self->{multilogin}{$self->{multilogin}->{current}}->{url};
            }
            $url .= $search->{path}[0];
            $url =~ s/\%r/$key/g;
            $url =~ s/\%a/$value/g;
            $url = $self->_containerParse($url, @{$pkeys});

            my $querystr = '';
            if (defined($self->{session_param})) {
                $querystr = "$self->{session_param}=$self->{session}";
            }

            if ($querystr) {
                $url = $url.(index($url, '?') < 0 ? '?' : '&').$querystr;
            }

            if (defined($self->{paramauth})) {
                $url .= (index($url, '?') < 0 ? '?' : '&').'&'.$self->{paramauth};
            }

            my $req = GET $url;
            if (defined($self->{basicauth})) {
                $req->authorization_basic($self->{basicauth}->{user}, $self->{basicauth}->{pw});
            }
            if (defined($self->{session_cookie})) {
                $req->header(Cookie => "$self->{session_cookie}=$self->{session}");
            }
            if (defined($self->{oauth})) {
                my $token_type = $login && defined($login->{oauth}) && defined($login->{oauth}[0]->{token_type}) ? $login->{oauth}[0]->{token_type}[0] : 'Bearer';
                $req->header(Authorization => "$token_type $self->{oauth}->{token}");
                if (defined($login->{oauth}[0]->{client_secret_header})) {
                    $req->header($login->{oauth}[0]->{client_secret_header}[0], $self->{oauth}->{client_secret});
                }
            }

            my $res;
            for (my $i = 0; $i < $RETRY; $i++) {
                $res = $self->{ua}->request($req);
                if ($res->is_error && ($res->status_line =~ /timeout/ || $res->code =~ /^50/)) {
                    sleep $conf->{connection}[0]->{interval}[0] * ($i + 1);
                    next;
                }
                last;
            }
            if (!$res->is_success) {
                $self->log(level => 'err', message => "Searching $attr in REST service($url) failed: ".$res->status_line.($res->content ? ' '.substr($res->content, 0, 512) : ''));
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
                }
                return (LDAP_OTHER, $res->status_line);
            }

            my $scontent;
            if ($format eq 'json') {
                my $error;
                ($scontent, $error) = JSON::DWIW->new({convert_bool => 1})->from_json($res->content);
                if (!defined($scontent)) {
                    $self->log(level => 'err', message => "REST search response is not JSON: $error");
                    if ($conf->{sysloglevel} eq 'debug') {
                        $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
                    }
                    return (LDAP_OTHER, $error);
                }
            } elsif ($format eq 'xml') {
                $scontent = eval {XMLin($res->content, ValueAttr => ['value'], KeyAttr => {})};
                if ($@) {
                    $self->log(level => 'err', message => "REST search response is not XML: $@");
                    if ($conf->{sysloglevel} eq 'debug') {
                        $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
                    }
                    return (LDAP_OTHER, $@);
                }
            }

            my $tmpvals = $scontent;
            foreach my $tag (split(/, */, $search->{list}[0]->{tag})) {
                if (ref($tmpvals) eq 'HASH' && defined($tmpvals->{$tag})) {
                    $tmpvals = $tmpvals->{$tag};
                } else {
                    last;
                }
            }
            if (ref($tmpvals) ne 'ARRAY') {
                $tmpvals = [$tmpvals];
            }

            foreach my $tmpval (@{$tmpvals}) {
                if (!defined($tmpval->{$oconf->{attr}{$attr}->{id}[0]->{param}[0]})) {
                    next;
                }
                if (defined($search->{list}[0]->{param})) {
                    my $valid = $tmpval->{$oconf->{attr}{$attr}->{id}[0]->{param}[0]};
                    my $match = 1;
                    foreach my $tag (split(/, */, $search->{list}[0]->{param})) {
                        if (ref($tmpval) eq 'HASH' && defined($tmpval->{$tag})) {
                            $tmpval = $tmpval->{$tag};
                        } else {
                            $match = 0;
                            last;
                        }
                    }
                    if ($match && $value eq $tmpval) {
                        $delval = $valid;
                    }
                }
            }
        }

        $tmpurl =~ s/\%a/$delval/g;
        $content =~ s/\%a/$delval/g;
        $content =~ s/\%r/$key/g;

        my $req;
        if ($method eq 'GET') {
            if (defined($self->{paramauth})) {
                $tmpurl .= (index($tmpurl, '?') < 0 ? '?' : '&').'&'.$self->{paramauth};
            }
            $req = GET $tmpurl;
        } elsif ($method eq 'POST') {
            if ($content) {
                if (defined($self->{session_param}) && $reqformat eq 'POST') {
                    $content .= '&'.$self->{session_param}.'='.$self->{session};
                }
                if (defined($self->{paramauth})) {
                    $content .= '&'.$self->{paramauth};
                }
                $req = POST $tmpurl, Content => $content;
                my $contentType;
                if ($reqformat eq 'json') {
                    $contentType = 'application/json';
                } elsif ($reqformat eq 'xml') {
                    $contentType = 'text/xml';
                }
                if ($contentType) {
                    $req->header('Content-Type' => $contentType);
                }
            } else {
                $req = POST $tmpurl;
            }
        } else {
            $req = DELETE $tmpurl;
        }
        if (defined($self->{basicauth})) {
            $req->authorization_basic($self->{basicauth}->{user}, $self->{basicauth}->{pw});
        }
        if (defined($self->{session_cookie})) {
            $req->header(Cookie => "$self->{session_cookie}=$self->{session}");
        }
        if (defined($self->{oauth})) {
            my $token_type = $login && defined($login->{oauth}) && defined($login->{oauth}[0]->{token_type}) ? $login->{oauth}[0]->{token_type}[0] : 'Bearer';
            $req->header(Authorization => "$token_type $self->{oauth}->{token}");
            if (defined($login->{oauth}[0]->{client_secret_header})) {
                $req->header($login->{oauth}[0]->{client_secret_header}[0], $self->{oauth}->{client_secret});
            }
        }

        my $res;
        for (my $i = 0; $i < $RETRY; $i++) {
            $res = $self->{ua}->request($req);
            if ($res->is_error && ($res->status_line =~ /timeout/ || $res->code =~ /^50/)) {
                sleep $conf->{connection}[0]->{interval}[0] * ($i + 1);
                next;
            }
            last;
        }
        if ($res->is_success) {
            if (defined($oconf->{result})) {
                my %result;
                $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
                if ($rc) {
                    if ($rc == LDAP_ALREADY_EXISTS) {
                        $rc = LDAP_TYPE_OR_VALUE_EXISTS;
                    } elsif ($rc == LDAP_NO_SUCH_OBJECT) {
                        $rc = LDAP_NO_SUCH_ATTRIBUTE;
                    }
                    $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                    $self->log(level => 'err', message => "Deleting \"$value\" from $attr in REST service($tmpurl) failed: $error");
                    if ($conf->{sysloglevel} eq 'debug') {
                        $self->log(level => 'debug', message => "REST delete value url=$tmpurl response=".$res->content);
                    }
                }
            }
        } else {
            $rc = LDAP_OTHER;
            if (defined($oconf->{result})) {
                my %result;
                $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
                if ($rc) {
                    if ($rc == LDAP_ALREADY_EXISTS) {
                        $rc = LDAP_TYPE_OR_VALUE_EXISTS;
                    } elsif ($rc == LDAP_NO_SUCH_OBJECT) {
                        $rc = LDAP_NO_SUCH_ATTRIBUTE;
                    }
                    $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                    $self->log(level => 'err', message => "Deleting \"$value\" from $attr in REST service($tmpurl) failed: $error");
                    if ($conf->{sysloglevel} eq 'debug') {
                        $self->log(level => 'debug', message => "REST delete value url=$tmpurl response=".$res->content);
                    }
                }
            } else {
                my $econtent = $res->content;
                $econtent =~ s/\n/ /g;
                $error = $res->status_line.(length($econtent) <= 128 ? $econtent : '');
                $self->log(level => 'err', message => "Deleting \"$value\" from $attr in REST service($tmpurl) failed: $error".($res->content ? ' '.substr($res->content, 0, 512) : ''));
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST delete value url=$tmpurl response=".$res->content);
                }
            }
        }
    }

    return ($rc, $error);
}

sub _replaceAttrValues
{
    my $self = shift;
    my ($oconf, $key, $pkeys, $attr, @values) = @_;
    my $conf = $self->{_config};
    my $format = defined($oconf->{format}) ? $oconf->{format}[0] : $conf->{format}[0];
    my $reqformat = defined($oconf->{reqformat}) ? $oconf->{reqformat}[0] : (defined($conf->{reqformat}) ? $conf->{reqformat}[0] : $format);
    my $rc = LDAP_SUCCESS;
    my $error;
    my $login;
    if (defined($oconf->{container}) && defined($oconf->{container}[0]->{login})) {
        $login = $oconf->{container}[0]->{login}[0];
    } elsif (defined($conf->{login})) {
        $login = $conf->{login}[0];
    }

    if (!defined($oconf->{attr}{$attr}->{replace})) {
        return ($rc);
    }

    if (defined($oconf->{attr}{$attr}->{replace}[0]->{match}) &&
        !grep(/$oconf->{attr}{$attr}->{replace}[0]->{match}/i, @values)) {
        return ($rc);
    }

    if (defined($oconf->{attr}{$attr}->{format})) {
        $format = $oconf->{attr}{$attr}->{format}[0];
    }
    my $url = defined($conf->{url}) ? $conf->{url}[0] : '';
    if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{url})) {
        $url = $self->{multilogin}{$self->{multilogin}->{current}}->{url};
    }
    if (defined($oconf->{attr}{$attr}->{replace}[0]->{path})) {
        $url .= $oconf->{attr}{$attr}->{replace}[0]->{path}[0];
    }
    $url =~ s/\%r/$key/g;
    $url = $self->_containerParse($url, @{$pkeys});

    my $querystr = '';
    if (defined($self->{session_param})) {
        $querystr = "$self->{session_param}=$self->{session}";
    }

    if ($querystr) {
        $url = $url.(index($url, '?') < 0 ? '?' : '&').$querystr;
    }

    my $method;
    if (defined($oconf->{attr}{$attr}->{replace}[0]->{method})) {
        $method = $oconf->{attr}{$attr}->{replace}[0]->{method}[0];
    } elsif (defined($oconf->{modify}) && defined($oconf->{modify}[0]->{method})) {
        $method = $oconf->{modify}[0]->{method}[0];
    }

    foreach my $value (@values) {
        my $tmpurl = $url;
        my $content = defined($oconf->{attr}{$attr}->{replace}[0]->{webcontent}) ? $oconf->{attr}{$attr}->{replace}[0]->{webcontent}[0] : '';
        if ($value =~ /^ +$/) {
            $value = '';
        }
        $value =~ s/\\([0-9A-Fa-f][0-9A-Fa-f])/pack('H2', $1)/eg;
        my $replaceid;
        if (defined($oconf->{attr}{$attr}->{replace}[0]->{search}) && defined($oconf->{attr}{$attr}->{replace}[0]->{id})) {
            my $search = $oconf->{attr}{$attr}->{replace}[0]->{search}[0];
            my $url = defined($conf->{url}) ? $conf->{url}[0] : '';
            if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{url})) {
                $url = $self->{multilogin}{$self->{multilogin}->{current}}->{url};
            }
            $url .= $search->{path}[0];
            $url =~ s/\%r/$key/g;
            $url =~ s/\%a/$value/g;
            $url = $self->_containerParse($url, @{$pkeys});

            my $querystr = '';
            if (defined($self->{session_param})) {
                $querystr = "$self->{session_param}=$self->{session}";
            }

            if ($querystr) {
                $url = $url.(index($url, '?') < 0 ? '?' : '&').$querystr;
            }

            if (defined($self->{paramauth})) {
                $url .= (index($url, '?') < 0 ? '?' : '&').'&'.$self->{paramauth};
            }

            my $req = GET $url;
            if (defined($self->{basicauth})) {
                $req->authorization_basic($self->{basicauth}->{user}, $self->{basicauth}->{pw});
            }
            if (defined($self->{session_cookie})) {
                $req->header(Cookie => "$self->{session_cookie}=$self->{session}");
            }
            if (defined($self->{oauth})) {
                my $token_type = $login && defined($login->{oauth}) && defined($login->{oauth}[0]->{token_type}) ? $login->{oauth}[0]->{token_type}[0] : 'Bearer';
                $req->header(Authorization => "$token_type $self->{oauth}->{token}");
                if (defined($login->{oauth}[0]->{client_secret_header})) {
                    $req->header($login->{oauth}[0]->{client_secret_header}[0], $self->{oauth}->{client_secret});
                }
            }

            my $res;
            for (my $i = 0; $i < $RETRY; $i++) {
                $res = $self->{ua}->request($req);
                if ($res->is_error && ($res->status_line =~ /timeout/ || $res->code =~ /^50/)) {
                    sleep $conf->{connection}[0]->{interval}[0] * ($i + 1);
                    next;
                }
                last;
            }
            if (!$res->is_success) {
                $self->log(level => 'err', message => "Searching $attr in REST service($url) failed: ".$res->status_line.($res->content ? ' '.substr($res->content, 0, 512) : ''));
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
                }
                return (LDAP_OTHER, $res->status_line);
            }

            my $scontent;
            if ($format eq 'json') {
                my $error;
                ($scontent, $error) = JSON::DWIW->new({convert_bool => 1})->from_json($res->content);
                if (!defined($scontent)) {
                    $self->log(level => 'err', message => "REST search response is not JSON: $error");
                    if ($conf->{sysloglevel} eq 'debug') {
                        $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
                    }
                    return (LDAP_OTHER, $error);
                }
            } elsif ($format eq 'xml') {
                $scontent = eval {XMLin($res->content, ValueAttr => ['value'], KeyAttr => {})};
                if ($@) {
                    $self->log(level => 'err', message => "REST search response is not XML: $@");
                    if ($conf->{sysloglevel} eq 'debug') {
                        $self->log(level => 'debug', message => "REST search url=$url response=".$res->content);
                    }
                    return (LDAP_OTHER, $@);
                }
            }

            my $tmpvals = $scontent;
            foreach my $tag (split(/, */, $search->{list}[0]->{tag})) {
                if (ref($tmpvals) eq 'HASH' && defined($tmpvals->{$tag})) {
                    $tmpvals = $tmpvals->{$tag};
                } else {
                    last;
                }
            }
            if (ref($tmpvals) ne 'ARRAY') {
                $tmpvals = [$tmpvals];
            }

            foreach my $tmpval (@{$tmpvals}) {
                if (!defined($tmpval->{$oconf->{attr}{$attr}->{replace}[0]->{id}[0]->{param}[0]})) {
                    next;
                }
                if (defined($search->{list}[0]->{condition})) {
                    my $valid = $tmpval->{$oconf->{attr}{$attr}->{replace}[0]->{id}[0]->{param}[0]};
                    my $match = 1;
                    foreach my $condition (@{$search->{list}[0]->{condition}}) {
                        if (defined($tmpval->{$condition->{param}})) {
                            my $tmpval2 = $tmpval->{$condition->{param}};
                            if (ref($tmpval2) eq 'JSON::DWIW::Boolean') {
                                $tmpval2 = $tmpval2 ? 'true' : 'false';
                            }
                            if ($condition->{value} ne $tmpval2) {
                                $match = 0;
                                last;
                            }
                        } else {
                            $match = 0;
                            last;
                        }
                    }
                    if ($match) {
                        $replaceid = $valid;
                    }
                }
            }
        }

        if (defined($replaceid)) {
            $tmpurl =~ s/\%a/$replaceid/g;
        }
        $content =~ s/\%a/$value/g;
        $content =~ s/\%r/$key/g;

        my $req;
        if ($method eq 'GET') {
            if (defined($self->{paramauth})) {
                $tmpurl .= (index($tmpurl, '?') < 0 ? '?' : '&').'&'.$self->{paramauth};
            }
            $req = GET $tmpurl;
        } else {
            if ($content) {
                if ($reqformat eq 'json') {
                    if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{apiparam})) {
                        my $json = JSON::DWIW->new->from_json($content);
                        foreach my $param (keys %{$self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}}) {
                            ${$json}{$param} = $self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}{$param}->{value};
                        }
                        $content = JSON::DWIW->new->to_json($json);
                        $content = encode('utf8', $content);
                    }
                } else {
                    if (defined($self->{session_param}) && $reqformat eq 'POST') {
                        $content .= '&'.$self->{session_param}.'='.$self->{session};
                    }
                    if (defined($self->{paramauth})) {
                        $content .= '&'.$self->{paramauth};
                    }
                }
                if ($method eq 'POST') {
                    $req = POST $tmpurl, Content => $content;
                } else {
                    $req = PUT $tmpurl, Content => $content;
                }
                my $contentType;
                if ($reqformat eq 'json') {
                    $contentType = 'application/json';
                } elsif ($reqformat eq 'xml') {
                    $contentType = 'text/xml';
                }
                if ($contentType) {
                    $req->header('Content-Type', $contentType);
                }
            } else {
                if ($method eq 'POST') {
                    $req = POST $tmpurl;
                }
            }
        }
        if (defined($self->{basicauth})) {
            $req->authorization_basic($self->{basicauth}->{user}, $self->{basicauth}->{pw});
        }
        if (defined($self->{session_cookie})) {
            $req->header(Cookie => "$self->{session_cookie}=$self->{session}");
        }
        if (defined($self->{oauth})) {
            my $token_type = $login && defined($login->{oauth}) && defined($login->{oauth}[0]->{token_type}) ? $login->{oauth}[0]->{token_type}[0] : 'Bearer';
            $req->header(Authorization => "$token_type $self->{oauth}->{token}");
            if (defined($login->{oauth}[0]->{client_secret_header})) {
                $req->header($login->{oauth}[0]->{client_secret_header}[0], $self->{oauth}->{client_secret});
            }
        }

        my $res;
        for (my $i = 0; $i < $RETRY; $i++) {
            $res = $self->{ua}->request($req);
            if ($res->is_error && ($res->status_line =~ /timeout/ || $res->code =~ /^50/)) {
                sleep $conf->{connection}[0]->{interval}[0] * ($i + 1);
                next;
            }
            last;
        }
        if ($res->is_success) {
            if (defined($oconf->{result})) {
                my %result;
                $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
                if ($rc) {
                    if ($rc == LDAP_ALREADY_EXISTS) {
                        $rc = LDAP_TYPE_OR_VALUE_EXISTS;
                    } elsif ($rc == LDAP_NO_SUCH_OBJECT) {
                        $rc = LDAP_NO_SUCH_ATTRIBUTE;
                    }
                    $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                    $self->log(level => 'err', message => "Replacing \"$value\" from $attr in REST service($tmpurl) failed: $error");
                    if ($conf->{sysloglevel} eq 'debug') {
                        $self->log(level => 'debug', message => "REST replace value url=$tmpurl response=".$res->content);
                    }
                }
            }
        } else {
            $rc = LDAP_OTHER;
            if (defined($oconf->{result})) {
                my %result;
                $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
                if ($rc) {
                    if ($rc == LDAP_ALREADY_EXISTS) {
                        $rc = LDAP_TYPE_OR_VALUE_EXISTS;
                    } elsif ($rc == LDAP_NO_SUCH_OBJECT) {
                        $rc = LDAP_NO_SUCH_ATTRIBUTE;
                    }
                    $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                    $self->log(level => 'err', message => "Replacing \"$value\" from $attr in REST service($tmpurl) failed: $error");
                    if ($conf->{sysloglevel} eq 'debug') {
                        $self->log(level => 'debug', message => "REST replace value url=$tmpurl response=".$res->content);
                    }
                }
            } else {
                my $econtent = $res->content;
                $econtent =~ s/\n/ /g;
                $error = $res->status_line.(length($econtent) <= 128 ? $econtent : '');
                $self->log(level => 'err', message => "Replacing \"$value\" from $attr in REST service($tmpurl) failed: $error".($res->content ? ' '.substr($res->content, 0, 512) : ''));
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST replace value url=$tmpurl response=".$res->content);
                }
            }
        }
    }

    return ($rc, $error);
}

sub _rename
{
    my $self = shift;
    my ($oconf, $login, $key, $pkeys, @list) = @_;
    my $conf = $self->{_config};
    my $format = defined($oconf->{format}) ? $oconf->{format}[0] : $conf->{format}[0];
    my $reqformat = defined($oconf->{reqformat}) ? $oconf->{reqformat}[0] : (defined($conf->{reqformat}) ? $conf->{reqformat}[0] : $format);
    my $contentType;
    my $rc = 0;
    my $error;
    my $entry;

    if (defined($oconf->{noop}) && grep(/^modify$/i, @{$oconf->{noop}})) {
        return $rc;
    }

    if (!defined($oconf->{rename})) {
        return $rc;
    }

    my $url = $conf->{url}[0];
    if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{url})) {
        $url = $self->{multilogin}{$self->{multilogin}->{current}}->{url};
    }
    if (defined($oconf->{rename}[0]->{path})) {
        $url .= $oconf->{rename}[0]->{path}[0];
    }
    $url =~ s/\%r/$key/g;
    $url = $self->_containerParse($url, @{$pkeys});

    my $querystr = '';
    if (defined($self->{session_param})) {
        $querystr = "$self->{session_param}=$self->{session}";
    }

    if ($querystr) {
        $url = $url.(index($url, '?') < 0 ? '?' : '&').$querystr;
    }

    my $method;
    if (defined($oconf->{rename}[0]->{method})) {
        $method = $oconf->{rename}[0]->{method}[0];
    } elsif (defined($oconf->{modify}) && defined($oconf->{modify}[0]->{method})) {
        $method = $oconf->{modify}[0]->{method}[0];
    }

    my $value;
    for (my $i = 0; $i < @list; $i++) {
        if ($list[$i] =~ /^$oconf->{rdn}[0]$/i) {
            $value = encode('utf8', $list[$i+1]);
            last;
        }
    }
    my $content = defined($oconf->{rename}[0]->{webcontent}) ? $oconf->{rename}[0]->{webcontent}[0] : '';
    $content =~ s/\%a/$value/g;
    $content =~ s/\%r/$key/g;

    my $req;
    if ($method eq 'GET') {
        $req = GET $url;
    } elsif ($method eq 'PUT') {
        $req = PUT $url, Content => $content;
    } else {
        if ($content) {
            if (defined($self->{paramauth})) {
                $content .= '&'.$self->{paramauth};
            }
            $req = POST $url, Content => $content;
            my $contentType;
            if ($format eq 'json') {
                $contentType = 'application/json';
            } elsif ($format eq 'xml') {
                $contentType = 'text/xml';
            }
            if ($contentType) {
                $req->header('Content-Type' => $contentType);
            }
        } else {
            $req = POST $url;
        }
    }
    if (defined($self->{basicauth})) {
        $req->authorization_basic($self->{basicauth}->{user}, $self->{basicauth}->{pw});
    }
    if (defined($self->{session_cookie})) {
        $req->header(Cookie => "$self->{session_cookie}=$self->{session}");
    }
    if (defined($self->{oauth})) {
        my $token_type = $login && defined($login->{oauth}) && defined($login->{oauth}[0]->{token_type}) ? $login->{oauth}[0]->{token_type}[0] : 'Bearer';
        $req->header(Authorization => "$token_type $self->{oauth}->{token}");
        if (defined($login->{oauth}[0]->{client_secret_header})) {
            $req->header($login->{oauth}[0]->{client_secret_header}[0], $self->{oauth}->{client_secret});
        }
    }

    my $res;
    for (my $i = 0; $i < $RETRY; $i++) {
        $res = $self->{ua}->request($req);
        if ($res->is_error && ($res->status_line =~ /timeout/ || $res->code =~ /^50/)) {
            sleep $conf->{connection}[0]->{interval}[0] * ($i + 1);
            next;
        }
        last;
    }
    if ($res->is_success) {
        if (defined($oconf->{result})) {
            my %result;
            $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
            if ($rc) {
                $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                $self->log(level => 'err', message => "Renaming from $key to $value in REST service($url) failed: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST rename url=$url response=".$res->content);
                }
            }
        }
    } else {
        $rc = LDAP_OTHER;
        if (defined($oconf->{result})) {
            my %result;
            $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
            if ($rc) {
                $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                $self->log(level => 'err', message => "Renaming from $key to $value in REST service($url) failed: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST rename url=$url response=".$res->content);
                }
            }
        } else {
            my $econtent = $res->content;
            $econtent =~ s/\n/ /g;
            $error = $res->status_line.(length($econtent) <= 128 ? $econtent : '');
            $self->log(level => 'err', message => "Renaming from $key to $value in REST service($url) failed: $error".($res->content ? ' '.substr($res->content, 0, 512) : ''));
            if ($conf->{sysloglevel} eq 'debug') {
                $self->log(level => 'debug', message => "REST rename url=$url response=".$res->content);
            }
        }
    }

    return ($rc, $error);
}

sub _undelete
{
    my $self = shift;
    my ($oconf, $login, $key, $pkeys) = @_;
    my $conf = $self->{_config};
    my $format = defined($oconf->{format}) ? $oconf->{format}[0] : $conf->{format}[0];
    my $rc = 0;
    my $error;

    my $url = $conf->{url}[0];
    if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{url})) {
        $url = $self->{multilogin}{$self->{multilogin}->{current}}->{url};
    }
    if (defined($oconf->{undelete}[0]->{path})) {
        $url .= $oconf->{undelete}[0]->{path}[0];
    }
    $url =~ s/\%r/$key/g;
    $url = $self->_containerParse($url, @{$pkeys});

    my $querystr = '';
    if (defined($self->{session_param})) {
        $querystr = "$self->{session_param}=$self->{session}";
    }

    if ($querystr) {
        $url = $url.(index($url, '?') < 0 ? '?' : '&').$querystr;
    }

    my $method;
    if (defined($oconf->{undelete}[0]->{method})) {
        $method = $oconf->{undelete}[0]->{method}[0];
    } elsif (defined($oconf->{modify}) && defined($oconf->{modify}[0]->{method})) {
        $method = $oconf->{modify}[0]->{method}[0];
    }

    my $req;
    if ($method eq 'GET') {
        $req = GET $url;
    } elsif ($method eq 'PUT') {
        $req = PUT $url;
    } elsif ($method eq 'DELETE') {
        $req = DELETE $url;
    } else {
        $req = POST $url;
    }
    if (defined($self->{basicauth})) {
        $req->authorization_basic($self->{basicauth}->{user}, $self->{basicauth}->{pw});
    }
    if (defined($self->{session_cookie})) {
        $req->header(Cookie => "$self->{session_cookie}=$self->{session}");
    }
    if (defined($self->{oauth})) {
        my $token_type = $login && defined($login->{oauth}) && defined($login->{oauth}[0]->{token_type}) ? $login->{oauth}[0]->{token_type}[0] : 'Bearer';
        $req->header(Authorization => "$token_type $self->{oauth}->{token}");
        if (defined($login->{oauth}[0]->{client_secret_header})) {
            $req->header($login->{oauth}[0]->{client_secret_header}[0], $self->{oauth}->{client_secret});
        }
    }

    my $res;
    for (my $i = 0; $i < $RETRY; $i++) {
        $res = $self->{ua}->request($req);
        if ($res->is_error && ($res->status_line =~ /timeout/ || $res->code =~ /^50/)) {
            sleep $conf->{connection}[0]->{interval}[0] * ($i + 1);
            next;
        }
        last;
    }
    if ($res->is_success) {
        if (defined($oconf->{result})) {
            my %result;
            $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
            if ($rc) {
                $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                $self->log(level => 'err', message => "Undeleting $key in REST service($url) failed: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST undelete url=$url response=".$res->content);
                }
            }
        }
    } else {
        $rc = LDAP_OTHER;
        if (defined($oconf->{result})) {
            my %result;
            $rc = $self->_checkResult($oconf->{result}[0], $format, $res->content, \%result, $res->code);
            if ($rc) {
                $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                $self->log(level => 'err', message => "Undeleting $key in REST service($url) failed: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST undelete url=$url response=".$res->content);
                }
            }
        } else {
            my $econtent = $res->content;
            $econtent =~ s/\n/ /g;
            $error = $res->status_line.(length($econtent) <= 128 ? $econtent : '');
            $self->log(level => 'err', message => "Undeleting $key in REST service($url) failed: $error".($res->content ? ' '.substr($res->content, 0, 512) : ''));
            if ($conf->{sysloglevel} eq 'debug') {
                $self->log(level => 'debug', message => "REST undelete url=$url response=".$res->content);
            }
        }
    }

    return ($rc, $error);
}

sub _login
{
    my $self = shift;
    my ($login, $path) = @_;
    my $conf = $self->{_config};
    my $current = $self->{multilogin}->{current};
    my $url = $self->{multilogin}{$current}->{url};
    my $querystr = '';
    my $format = defined($login->{format}) ? $login->{format}[0] : $conf->{format}[0];
    my $res;
    my $error;

    if (!$login) {
        return (0);
    }

    if (defined($login->{basicuser})) {
        $self->{basicauth} = $self->{multilogin}{$current}->{basicauth};
        return (0);
    }

    my $authtype = defined($login->{authtype}) ? $login->{authtype}[0] : '';
    if ($authtype eq 'parameter') {
        $self->{paramauth} = $self->{multilogin}{$current}->{paramauth};
        return (0);
    } elsif ($authtype eq 'oauth') {
        if (!defined($self->{multilogin}{$current}->{oauth}->{token_url}) || !$self->{multilogin}{$current}->{oauth}->{token_url}) {
            if (defined($self->{multilogin}{$current}->{oauth}->{token})) {
                $self->{oauth} = $self->{multilogin}{$current}->{oauth};
                return 0;
            } else {
                return (1, "No OAuth token");
            }
        }

        if (defined($self->{multilogin}{$current}->{logintime}) && $self->{multilogin}{$current}->{logintime} + $conf->{expire}[0] >= time) {
            return 0;
        }

        my $client_id = $self->{multilogin}{$current}->{oauth}->{client_id};
        my $client_secret = $self->{multilogin}{$current}->{oauth}->{client_secret};
        my $refresh_token = $self->{multilogin}{$current}->{oauth}->{refresh_token};
        my $token_url = $self->{multilogin}{$current}->{oauth}->{token_url};
        $res = $self->{ua}->post($token_url.(index($token_url, '?') < 0 ? '?' : '&').'grant_type=refresh_token&refresh_token='.$refresh_token.'&client_id='.$client_id.'&client_secret='.$client_secret, Content => 'grant_type=refresh_token&refresh_token='.$refresh_token.'&client_id='.$client_id.'&client_secret='.$client_secret);
        my $content = $res->content;
        if (!$res->is_success) {
            $content =~ s/\n/ /g;
            return (1, "Getting OAuth token failed: ".$content);
        }

        my $access_token;
        my $refresh_token;
        my ($data, $error) = JSON::DWIW->new->from_json($content);
        if (defined($data)) {
            if (defined($data->{access_token})) {
                $access_token = $data->{access_token};
            }
            if (defined($data->{refresh_token})) {
                $refresh_token = $data->{refresh_token};
            }
        } else {
            if ($res->content =~ /<(?:access_token|token)>([^<]+)<\/(?:access_token|token)>/i) {
                $access_token = $1;
            }
            if ($res->content =~ /<refresh_token>([^<]+)<\/refresh_token>/i) {
                $refresh_token = $1;
            }
        }
        if (!$access_token) {
            $content =~ s/\n/ /g;
            return (1, "OAuth has no access_token: ".$content);
        }
        if ($refresh_token) {
            $self->{multilogin}{$current}->{oauth}->{refresh_token} = $refresh_token;
        }
        if ($self->_resetToken($refresh_token, $access_token)) {
            return (1, "Failed to reset refresh token");
        }
        $self->{multilogin}{$current}->{logintime} = time;
        $self->{multilogin}{$current}->{oauth}->{token} = $access_token;
        $self->{oauth} = $self->{multilogin}{$current}->{oauth};

        return 0;
    }

    my $method;
    if (defined($login->{method})) {
        $method = $login->{method}[0];
    }

    if ($method eq 'POST') {
        my $content = '';
        if (defined($login->{webcontent})) {
            $content = $login->{webcontent}[0];
            my $admin = uri_escape($self->{multilogin}{$current}->{admin});
            my $passwd = uri_escape($self->{multilogin}{$current}->{passwd});
            $content =~ s/\%u/$admin/;
            $content =~ s/\%s/$passwd/;
        }
        $res = $self->{ua}->post($url.($path ? $path : ''), Content => $content);
    } else {
        $res = $self->{ua}->request(GET $url.($path ? $path : ''));
    }
    if ($res->is_success) {
        if (defined($login->{result})) {
            my %result;
            if ($self->_checkResult($login->{result}[0], $format, $res->content, \%result, $res->code)) {
                $error = (defined($result{code}) ? "code=$result{code} " : '').(defined($result{message}) ? $result{message} : '');
                $self->log(level => 'err', message => "Autentication to REST service($url$path) failed: $error");
                if ($conf->{sysloglevel} eq 'debug') {
                    $self->log(level => 'debug', message => "REST authentication url=$url$path response=".$res->content);
                }
                return (1, $error);
            }
        }
    } else {
        $self->log(level => 'err', message => "Authentication to REST service($current) failed: ".$res->status_line.($res->content ? ' '.substr($res->content, 0, 512) : ''));
        return (1, $res->status_line);
    }

    if (defined($login->{session})) {
        my $auth = 0;
        if (defined($login->{session}[0]->{cookie})) {
            my $cookie_name = $login->{session}[0]->{cookie}[0];
            my ($cookie) = grep(/^$cookie_name=/, split(/, */, $res->header('Set-Cookie')));
            if ($cookie) {
               ($self->{session}) = ($cookie =~ /^$cookie_name=([^;]+)/);
               $self->{session_cookie} = $cookie_name;
               $auth = 1;
            }
        } else {
            my $session_name = $login->{session}[0]->{tag};
            if ($format eq 'xml') {
                ($self->{session}) = ($res->content =~ /<$session_name>([^<]+)<\/$session_name>/);
                $self->{session_param} = $session_name;
                $auth = 1;
            }
        }
        if ($auth) {
            $self->{multilogin}{$current}->{session} = $self->{session};
        } else {
            $error = "Can't get session";
            $self->log(level => 'err', message => "Authentication to REST service($url$path) failed: $error");
            if ($conf->{sysloglevel} eq 'debug') {
                $self->log(level => 'debug', message => "REST authentication url=$url response=".$res->content);
            }
            return (1, $error);
        }
    }

    return (0);
}

sub _relogin
{
    my $self = shift;
    my ($pkey, $dn, $login) = @_;
    my $conf = $self->{_config};
    my $login_dn;
    my $admin;
    my $passwd;
    my $client_id;
    my $client_secret;
    my $refresh_token;
    my $access_token;
    my $token_url;
    my $refresh_token_attr;
    my $access_token_attr;
    my $url = defined($conf->{url}) ? $conf->{url}[0] : '';
    my $login_key = $pkey;
    if (!$login_key) {
        $login_key = 'default';
    }
    if (defined($login->{prefix})) {
        $login_key = $login->{prefix}.$login_key;
    }

    $self->{multilogin}->{current} = $login_key;

    if (defined($self->{multilogin}{$login_key})) {
        if (defined($self->{multilogin}{$login_key}->{session})) {
            $self->{session} = $self->{multilogin}{$login_key}->{session};
            if (defined($self->{ping})) {
                if (defined($login->{basicuser})) {
                    return 0;
                }
                my $ping = $login->{ping}[0];

                my $url = "$self->{multilogin}{$login_key}->{url}$ping->{path}[0]";
                my $querystr = '';
                if (defined($self->{session_param})) {
                    $querystr = "$self->{session_param}=$self->{session}";
                }

                my $req = GET $url.$querystr;
                if (defined($self->{session_cookie})) {
                    $req->header(Cookie => "$self->{session_cookie}=$self->{session}");
                }
                my $res = $self->{ua}->request($req);
                if ($res->is_success) {
                    return 0;
                } else {
                    $self->log(level => 'err', message => "Connection check to REST service failed");
                    undef($self->{multilogin}{$login_key}->{session});
                    undef($self->{session});
                }
            } else {
                if ($self->{multilogin}{$login_key}->{logintime} + $conf->{expire}[0] < time) {
                    undef($self->{multilogin}{$login_key}->{session});
                    undef($self->{session});
                } else {
                    return 0;
                }
            }
        } elsif (defined($self->{multilogin}{$login_key}->{oauth})) {
            if ($self->{multilogin}{$login_key}->{logintime} + $conf->{expire}[0] < time) {
                undef($self->{multilogin}{$login_key}->{oauth}->{token});
                undef($self->{oauth});
            } else {
                return 0;
            }
        }
    }

    if (defined($login->{search})) {
        my $pdn;
        if ($pkey) {
            ($pdn) = ($dn =~ /^[^,]+,.*([^,=]=$pkey.*),$self->{suffix}$/i);
        }
        my $search = $login->{search}[0];
        if ($search->{type} eq 'lism') {
            my $lism = $self->{lism};
            my $base = $search->{base};
            my $scope = 2;
            my $filter = '(objectClass=*)';

            if (defined($search->{scope})) {
                if ($search->{scope} eq 'base') {
                    $scope = 0;
                } elsif ($login->{scope} eq 'one') {
                    $scope = 1;
                }
            }
            if (defined($search->{filter})) {
                $filter = $search->{filter};
            }
            if ($pkey) {
                $base =~ s/\%c/$pkey/g;
                $base =~ s/\%p/$pdn/g;
                $filter =~ s/\%c/$pkey/g;
            }

            my ($rc, @entries) = $lism->search($base, $scope, 1, 0, 0, $filter);
            if ($rc && $rc != LDAP_NO_SUCH_OBJECT) {
                $self->log(level => 'err', message => "Searching administrator account in LISM failed: base=\"$base\" filter=\"$filter\" rc=\"$rc\"");
                return ($rc, "Can't get administrator account");
            } elsif (!@entries) {
                $self->{multilogin}->{current} = undef;

                return (LDAP_SUCCESS);
            }

            ($login_dn) = ($entries[0] =~ /^dn: (.+)$/mi);
            ($admin) = ($entries[0] =~ /^$search->{admin}: (.+)$/mi);
            if (defined($search->{passwd})) {
                ($passwd) = ($entries[0] =~ /^$search->{passwd}: (.+)$/mi);
                if (defined($search->{decrypt})) {
                    my $decrypt = $search->{decrypt};
                    if ($pkey) {
                        $decrypt =~ s/\%c/$pkey/;
                    }
                    $decrypt =~ s/\%u/$admin/;
                    $decrypt =~ s/\%s/$passwd/;
                    $passwd = $self->_doFunction($decrypt);
                    if (!defined($passwd)) {
                        $self->log(level => 'err', message => "Password Decryption failed");
                        return (LDAP_OTHER, "Can't get administrator password");
                    }
                }
            }
            my $login_time;
            ($client_id) = ($entries[0] =~ /^$search->{client_id}: (.+)$/mi);
            ($client_secret) = ($entries[0] =~ /^$search->{client_secret}: (.+)$/mi);
            ($refresh_token) = ($entries[0] =~ /^$search->{refresh_token}: (.+)$/mi);
            ($access_token, $login_time) = ($entries[0] =~ /^$search->{access_token}: ([^#]+)#([0-9]+)$/mi);
            if ($login_time + $conf->{expire}[0] <= time) {
               undef($access_token);
            }
            ($token_url) = ($entries[0] =~ /^$search->{token_url}: (.+)$/mi);
            $refresh_token_attr = $search->{refresh_token};
            $access_token_attr = $search->{access_token};
            if (defined($search->{url})) {
                ($url) = ($entries[0] =~ /^$search->{url}: (.+)$/mi)
            }

            if (defined($search->{option})) {
                my ($option) = ($entries[0] =~ /^$search->{option}: (.+)$/mi);
                if ($option) {
                    my ($randpwd) = ($option =~ /randpwd=([^#]+)/);
                    $self->{multilogin}{$login_key}->{randpwd} = $randpwd && ($randpwd =~ /^[0-9]+$/ || $randpwd =~ /^[0-9]+:.+$/) ? $randpwd : 0;
                    my ($logicaldelete) = ($option =~ /logicaldelete=([^#]+)/);
                    if ($logicaldelete) {
                        $self->{multilogin}{$login_key}->{logicaldelete} = 1;
                    }
                    my ($apiparam) = ($option =~ /apiparam=([^#]+)/);
                    if ($apiparam) {
                        $self->{multilogin}{$login_key}->{apiparam} = {};
                        foreach my $elt (split(/&/, $apiparam)) {
                            my ($param, $value) = split(/=/, $elt);
                            if ($value =~ /^%{(.+)}$/) {
                                my $func = $1;
                                eval "\$value = $func";
                            }
                            $self->{multilogin}{$login_key}->{apiparam}{$param} = {value => $value};
                        }
                    }
                }
            }
        }
    }
    if ($url) {
        $self->{multilogin}{$login_key}->{url} = $url;
    }

    if (defined($login->{basicuser})) {
        if (defined($login->{search}) || !defined($self->{multilogin}{$login_key}->{basicauth})) {
            my $basicuser = $login->{basicuser}[0];
            if ($pkey) {
                $basicuser =~ s/\%c/$pkey/;
            }
            $basicuser =~ s/\%u/$admin/;
            $basicuser =~ s/([^\x01-\x7E])/'%'.unpack('H2', $1)/eg;
            $basicuser =~ tr/ /+/;
            my $basicpw = $login->{basicpw}[0];
            $basicpw =~ s/\%s/$passwd/;
            $self->{multilogin}{$login_key}->{basicauth}->{user} = $basicuser;
            $self->{multilogin}{$login_key}->{basicauth}->{pw} = $basicpw;
        }
        $self->{basicauth} = $self->{multilogin}{$login_key}->{basicauth};
        if ($url) {
            $self->{multilogin}{$login_key}->{url} = $url;
        }

        return 0;
    }

    my $authtype = defined($login->{authtype}) ? $login->{authtype}[0] : '';
    if ($authtype eq 'parameter') {
        if (defined($login->{search}) || !defined($self->{multilogin}{$login_key}->{paramauth})) {
            my $content = '';
            if (defined($login->{webcontent})) {
                $content = $login->{webcontent}[0];
                $content =~ s/\%u/$admin/;
                $content =~ s/\%s/$passwd/;
                $self->{multilogin}{$login_key}->{admin} = $admin;
                $self->{multilogin}{$login_key}->{passwd} = $passwd;
                $self->{multilogin}{$login_key}->{paramauth} = $content;
            }
        }
        $self->{paramauth} = $self->{multilogin}{$login_key}->{paramauth};
    } elsif ($authtype eq 'oauth') {
        if (defined($login->{search}) && (!defined($self->{multilogin}{$login_key}->{oauth}) || !defined($self->{multilogin}{$login_key}->{oauth}->{token}))) {
            if ($passwd) {
                $self->{multilogin}{$login_key}->{oauth}->{token} = $passwd;
                if ($client_secret) {
                    $self->{multilogin}{$login_key}->{oauth}->{client_secret} = $client_secret;
                }
            } else {
                if (!$client_id || !$client_secret || !$refresh_token || !$token_url) {
                    return (1, "client_id or client_secret or refresh_token or token_url is nothing");
                }
                $self->{multilogin}{$login_key}->{oauth}->{client_id} = $client_id;
                $self->{multilogin}{$login_key}->{oauth}->{client_secret} = $client_secret;
                $self->{multilogin}{$login_key}->{oauth}->{refresh_token} = $refresh_token;
                $self->{multilogin}{$login_key}->{oauth}->{token_url} = $token_url;
                $self->{multilogin}{$login_key}->{oauth}->{refresh_token_attr} = $refresh_token_attr;
                $self->{multilogin}{$login_key}->{oauth}->{access_token_attr} = $access_token_attr;
                if ($access_token) {
                    $self->{multilogin}{login_key}->{logintime} = time;
                    $self->{multilogin}{$login_key}->{oauth}->{token} = $access_token;
                    $self->{oauth} = $self->{multilogin}{$login_key}->{oauth};
                }
            }
        }
    }

    if ($self->{multilogin}{$login_key}->{session}) {
        $self->{session} = $self->{multilogin}{$login_key}->{session};
        return 0;
    } else {
        if ($login_dn) {
            $self->{multilogin}{$login_key}->{login_dn} = $login_dn;
        }

        my $path;
        if ($authtype eq 'oauth') {
            if (defined($self->{multilogin}{$login_key}->{oauth}->{token})) {
                $self->{oauth} = $self->{multilogin}{$login_key}->{oauth};
                return 0;
            }
        } else {
            $path = $login->{path}[0];
            if ($pkey) {
                $path =~ s/\%c/$pkey/;
            }
            $path =~ s/\%u/$admin/;
            $path =~ s/\%s/$passwd/;
            $self->{multilogin}{$login_key}->{admin} = $admin;
            $self->{multilogin}{$login_key}->{passwd} = $passwd;
        }

        return $self->_login($login, $path);
    }
}

sub _resetToken
{
    my $self = shift;
    my ($refresh_token, $access_token) = @_;
    my $conf = $self->{_config};
    my $current = $self->{multilogin}->{current};

    if (defined($self->{multilogin}{$current}->{login_dn})) {
        my $login_dn = $self->{multilogin}{$current}->{login_dn};
        my @info = ('REPLACE', $self->{multilogin}{$current}->{oauth}->{access_token_attr}, $access_token.'#'.time());
        if ($refresh_token) {
            push(@info, 'REPLACE', $self->{multilogin}{$current}->{oauth}->{refresh_token_attr}, $refresh_token);
        }
        my $rc = $self->{lism}->modify($login_dn, @info);
        if ($rc) {
            $self->log(level => 'err', message => "Failed to update token in $login_dn");
            return 1;
        }
    } elsif (defined($conf->{login}[0]->{oauth}[0]->{token_file}) && $refresh_token) {
        my $fd;
        if (!open($fd, "> $conf->{login}[0]->{oauth}[0]->{token_file}[0]")) {
            $self->log(level => 'err', message => "Failed to write token to $conf->{login}[0]->{oauth}[0]->{token_file}[0]");
            return 1;
        }
        print $fd $refresh_token.'#'.time();
        close $fd;
    }

    return 0;
}

sub _buildContent
{
    my $self = shift;
    my ($oconf, $entry) = @_;
    my $conf = $self->{_config};
    my $format = defined($oconf->{format}) ? $oconf->{format}[0] : $conf->{format}[0];
    if (defined($oconf->{reqformat})) {
        $format = $oconf->{reqformat}[0];
    } elsif (defined($conf->{reqformat})) {
        $format = $conf->{reqformat}[0];
    }
    my $content = '';

    if ($format eq 'json') {
        if (defined($oconf->{modify}[0]->{idcontent}) && defined($oconf->{modify}[0]->{idcontent}[0]->{content})) {
            my $id = $entry->{$oconf->{id}[0]->{param}[0]};
            my $idcontent = $oconf->{modify}[0]->{idcontent}[0]->{content};
            $idcontent =~ s/\%r/$id/g;
            my $iddata = JSON::DWIW->new({convert_bool => 1})->from_json($idcontent);
            if (defined($oconf->{modify}[0]->{idcontent}[0]->{tag})) {
                delete $entry->{$oconf->{id}[0]->{param}[0]};
                $entry->{$oconf->{modify}[0]->{idcontent}[0]->{tag}} = $iddata;
            } else {
                $entry->{$oconf->{id}[0]->{param}[0]} = $iddata;
            }
        }
        $content = JSON::DWIW->new->to_json($entry);
    } elsif ($format eq 'xml') {
        $content = XMLout($entry);
    } elsif ($format eq 'POST') {
        if (ref($entry) eq 'HASH') {
            foreach my $param (keys %{$entry}) {
                if (defined($oconf->{id}) && defined($oconf->{id}[0]->{param}) && $oconf->{id}[0]->{param}[0] eq $param) {
                    $content .= ($content ? '&' : '').$param.'='.${$entry}{$param};
                    next;
                }

                my $valformat;
                my $match = 0;
                if (defined($oconf->{modify}[0]->{param}) && defined($oconf->{modify}[0]->{param}{$param})) {
                    $match = 1;
                } else {
                    foreach my $attr (keys(%{$oconf->{attr}})) {
                        if ($oconf->{attr}{$attr}->{param}[0] eq $param) {
                            if (defined($oconf->{attr}{$attr}->{valformat})) {
                                $valformat = $oconf->{attr}{$attr}->{valformat}[0];
                            }
                            $match = 1;
                        }
                    }
                }
                if (!$match) {
                    next;
                }

                if ($valformat) {
                    my @elts = ($valformat =~ /%{([^}]+)}/g);
                    if (@elts) {
                        my @tmpvals;
                        if (ref($entry->{$param}) eq 'ARRAY') {
                            @tmpvals = @{$entry->{$param}};
                        } else {
                            $tmpvals[0] = $entry->{$param};
                        }
                        foreach my $tmpval (@tmpvals) {
                            my $value;
                            if (ref($tmpval) eq 'HASH') {
                                $value = $valformat;
                                foreach my $elt (@elts) {
                                    my $eltval = '';
                                    if (defined($tmpval->{$elt}) && !ref($tmpval->{$elt})) {
                                        $eltval = $tmpval->{$elt};
                                    }
                                    $value =~ s/%{$elt}/$eltval/g;
                                }
                            } else {
                                $value = $tmpval;
                            }
                            if ($value) {
                                $content .= ($content ? '&' : '').$param.(ref($entry->{$param}) eq 'ARRAY' ? '[]' : '').'='.uri_escape(encode($conf->{mbcode}[0], $value));
                            }
                        }
                    }
                } elsif (ref(${$entry}{$param}) eq 'ARRAY') {
                    if (@{${$entry}{$param}}) {
                        foreach my $value (@{${$entry}{$param}}) {
                            $content .= ($content ? '&' : '').$param.'[]='.uri_escape(encode($conf->{mbcode}[0], $value));
                        }
                    } else {
                        $content .= ($content ? '&' : '').$param.'[]=';
                    }
                } elsif (ref(${$entry}{$param}) ne 'HASH') {
                    $content .= ($content ? '&' : '').$param.'='.uri_escape(encode($conf->{mbcode}[0], ${$entry}{$param}));
                }
            }
        }
    }

    if ($format eq 'json' || $format eq 'xml') {
        $content = encode('utf8', $content);
    }

    return $content;
}

sub _buildObjectEntry
{
    my $self = shift;
    my ($oconf, $base, $entry) = @_;

    if (defined($oconf->{param})) {
        if (!defined($entry->{$oconf->{param}[0]})) {
            return '';
        }
        $entry = $entry->{$oconf->{param}[0]}
    }
    if (!defined($entry->{$oconf->{attr}{$oconf->{rdn}[0]}->{param}[0]})) {
        return '';
    }

    my $rdn_val = $entry->{$oconf->{attr}{$oconf->{rdn}[0]}->{param}[0]};
    if (!Encode::is_utf8($rdn_val)) {
        $rdn_val = decode('utf8', $rdn_val);
    }

    my $entryStr = "dn: ".$oconf->{rdn}[0]."=$rdn_val,$base\n";

    foreach my $oc (@{$oconf->{oc}}) {
        $entryStr = $entryStr."objectclass: $oc\n";
    }

    foreach my $attr (keys %{$oconf->{attr}}) {
        my $tmpentry = defined($oconf->{attr}{$attr}->{parent}) ? $entry->{$oconf->{attr}{$attr}->{parent}[0]} : $entry;

        if (defined($oconf->{attr}{$attr}->{list}) && defined($oconf->{attr}{$attr}->{listid})) {
            my $list_param = $oconf->{attr}{$attr}->{list}[0];
            my $list_id = $oconf->{attr}{$attr}->{listid}[0];
            if (defined($tmpentry->{$list_param}) && ref($tmpentry->{$list_param}) eq 'ARRAY') {
                foreach my $value (@{$tmpentry->{$list_param}}) {
                    if (defined($value->{$list_id})) {
                        $entryStr = "$entryStr$attr: ".$value->{$list_id}."\n";
                    }
                }
            }
            next;
        }

        if (!defined($oconf->{attr}{$attr}->{param})) {
            next;
        }

        my @values;
        my $param = $oconf->{attr}{$attr}->{param}[0];
        if (!defined($tmpentry->{$param})) {
            next;
        }

        if (!ref($tmpentry->{$param})) {
            $values[0] = $tmpentry->{$param};
        } elsif (defined($oconf->{attr}{$attr}->{valformat})) {
            my $valformat = $oconf->{attr}{$attr}->{valformat}[0];
            my @elts = ($valformat =~ /%{([^}]+)}/g);
            if (@elts) {
                my @tmpvals;
                if (ref($tmpentry->{$param}) eq 'ARRAY') {
                    @tmpvals = @{$tmpentry->{$param}};
                } else {
                    $tmpvals[0] = $tmpentry->{$param};
                }
                foreach my $tmpval (@tmpvals) {
                    my $value = $valformat;
                    foreach my $elt (@elts) {
                        my $eltval = '';
                        if (defined($tmpval->{$elt}) && !ref($tmpval->{$elt})) {
                            $eltval = $tmpval->{$elt}
                        }
                        $value =~ s/%{$elt}/$eltval/g;
                    }
                    if ($value) {
                        push(@values, $value);
                    }
                }
            }
        } elsif (ref($tmpentry->{$param}) eq 'ARRAY') {
            @values = @{$tmpentry->{$param}};
        } elsif (ref($tmpentry->{$param}) eq 'JSON::DWIW::Boolean') {
            $values[0] = $tmpentry->{$param} ? 1 : 0;
        }

        if (@values) {
            foreach my $value (@values) {
                if ($value) {
                    if (!Encode::is_utf8($value)) {
                        $value = decode('utf8', $value);
                    }
                    $entryStr = "$entryStr$attr: $value\n";
                }
            }
        }
    }

    return $entryStr;
}

sub _getEntries
{
    my $self = shift;
    my ($oconf, $pkeys, $suffix, $filter, $rdn_val, $is_object, @entries) = @_;
    my $rc = LDAP_SUCCESS;
    my @match_keys;
    my @match_entries;

    foreach my $entry (@entries) {
        if (defined($oconf->{search}[0]->{list}[0]->{recursive}) && $entry->{$oconf->{search}[0]->{list}[0]->{recursive}}) {
            my $keysp;
            my $entriesp;
            ($rc, $keysp, $entriesp) = $self->_getEntries($oconf, $pkeys, $suffix, $filter, $rdn_val, $is_object, @{$entry->{$oconf->{search}[0]->{list}[0]->{recursive}}});
            if ($rc) {
                last;
            } else {
                push(@match_keys, @{$keysp});
                push(@match_entries, @{$entriesp});
            }
        }

        if ($rdn_val && $rdn_val !~ /\*/) {
            my $tmpentry = $entry;
            my $tmprdn_val = '';
            my $rdn_param = $oconf->{attr}{$oconf->{rdn}[0]}->{param}[0];
            if (defined($oconf->{param}) && defined($tmpentry->{$oconf->{param}[0]})) {
                $tmpentry = $tmpentry->{$oconf->{param}[0]}
            }
            if (!defined($tmpentry->{$rdn_param})) {
                next;
            }
            $tmprdn_val = encode('utf8', $tmpentry->{$rdn_param});
            if ($tmprdn_val !~ /^$rdn_val$/i) {
                next;
            }
        }

        my $entryStr = $self->_buildObjectEntry($oconf, $suffix, $entry);
        if (!$entryStr) {
            next;
        }

        foreach my $attr (keys %{$oconf->{attr}}) {
            if (!defined($oconf->{attr}{$attr}->{search})) {
                next;
            }

            my $id;
            if (defined($oconf->{id}) && $oconf->{id}[0]->{param}[0] ne $oconf->{rdn}[0]) {
                $id = $entry->{$oconf->{id}[0]->{param}[0]};
            } else {
                ($id) = ($entryStr =~ /^dn: [^=]+=([^,]+),/);
            }
            my $valStr = $self->_getAttrValues($oconf, $id, $pkeys, $attr);
            if (!defined($valStr)) {
                return (LDAP_OTHER , \@match_keys, @match_entries);
            }
            $entryStr = "$entryStr$valStr";
        }

        if ($self->parseFilter($filter, $entryStr)) {
            my $key;
            if (defined($oconf->{id}) && defined($oconf->{id}[0]->{param})) {
                $key = $entry->{$oconf->{id}[0]->{param}[0]};
            } else {
                $key = $rdn_val;
            }
            push(@match_keys, $key);
            if ($is_object) {
                push(@match_entries, $entry);
            } else {
                push(@match_entries, $entryStr);
            }
        }
    }

    return ($rc, \@match_keys, \@match_entries);
}

sub _entryToContent
{
    my $self = shift;
    my ($oconf, $pkey, $entryStr) = @_;
    my $conf = $self->{_config};
    my $content = '';
    my %child_contents;
    my %list_contents;

    my $method = '';
    if (defined($oconf->{add}[0]->{method})) {
        $method = $oconf->{add}[0]->{method}[0];
    }

    my $format = defined($oconf->{reqformat}) ? $oconf->{reqformat}[0] : (defined($conf->{reqformat}) ? $conf->{reqformat}[0] : (defined($oconf->{format}) ? $oconf->{format}[0] : $conf->{format}[0]));
    if ($format eq 'json') {
        $content = "{\n";
        if (defined($oconf->{add}[0]->{tag})) {
            foreach my $tag (split(/, */, $oconf->{add}[0]->{tag}[0])) {
                if ($tag =~ /^ *$/) {
                    last;
                }
                $content .= "\"$tag\": {\n";
            }
        }
    } elsif ($format eq 'xml') {
        if (defined($oconf->{add}[0]->{tag})) {
            foreach my $tag (split(/, */, $oconf->{add}[0]->{tag}[0])) {
                if ($tag =~ /^ *$/) {
                    last;
                }
                $content .= "<$tag>\n";
            }
        }
    }

    if (defined($oconf->{add}[0]->{param})) {
        foreach my $param (keys(%{$oconf->{add}[0]->{param}})) {
            my $value = $oconf->{add}[0]->{param}{$param}->{value};
            if ($method eq 'GET') {
                $content .= ($content ? '&' : '')."$param=".uri_escape(encode($conf->{mbcode}[0], $value));
            } elsif ($format eq 'POST') {
                $content .= ($content ? '&' : '')."$param=$value";
            } elsif ($format eq 'json') {
                $content = "$content   \"$param\" : \"$value\",\n";
            }
        }
    }

    foreach my $attr (keys %{$oconf->{attr}}) {
        if (!defined($oconf->{attr}{$attr}->{param}) && !defined($oconf->{attr}{$attr}->{list})) {
            next;
        }
        if (defined($oconf->{attr}{$attr}->{option}) && grep(/^readonly$/, @{$oconf->{attr}{$attr}->{option}})) {
            next;
        }
        if (defined($oconf->{attr}{$attr}->{add}) || defined($oconf->{attr}{$attr}->{delete})) {
            next;
        }
        if ($entryStr !~ /^$attr: /mi) {
            next;
        }

        my $param;
        if (defined($oconf->{attr}{$attr}->{addparam})) {
            $param = $oconf->{attr}{$attr}->{addparam}[0];
        } elsif (defined($oconf->{attr}{$attr}->{param})) {
            $param = $oconf->{attr}{$attr}->{param}[0];
        }
        my @values = ($entryStr =~ /^$attr: *(.+)$/gmi);
        my $value = $values[0];
        if ($method eq 'GET') {
            if (defined($oconf->{attr}{$attr}->{query})) {
                $param = $oconf->{attr}{$attr}->{query}[0];
                $content .= ($content ? '&' : '')."$param=".uri_escape(encode($conf->{mbcode}[0], $value));
            }
        } elsif ($format eq 'POST') {
            if (@values > 1 || (defined($oconf->{attr}{$attr}->{multivalued}) && $oconf->{attr}{$attr}->{multivalued})) {
                if (@values) {
                    foreach my $val (@values) {
                        if ($val =~ /^ +$/) {
                            $val = '';
                        }
                        $content .= ($content ? '&' : '').$param.'[]='.uri_escape(encode($conf->{mbcode}[0], $val));
                    }
                } else {
                    $content .= ($content ? '&' : '').$param.'[]=';
                }
            } else {
                $content .= ($content ? '&' : '')."$param=".uri_escape(encode($conf->{mbcode}[0], $value));
            }
        } elsif ($format eq 'json') {
            if (defined($oconf->{attr}{$attr}->{parent})) {
                my $parent = $oconf->{attr}{$attr}->{parent}[0];
                if (!defined($child_contents{$parent})) {
                    $child_contents{$parent} = "   \"$parent\" : {\n";
                }
                $child_contents{$parent} = "$child_contents{$parent}   \"$param\" : \"$value\",\n";
            } elsif (defined($oconf->{attr}{$attr}->{list}) && defined($oconf->{attr}{$attr}->{webcontent})) {
                if ($values[0] =~ /^ *$/) {
                    next;
                }
                my $list = $oconf->{attr}{$attr}->{list}[0];
                if (!defined($list_contents{$list})) {
                    $list_contents{$list} = "   \"$list\" : [\n";
                }
                foreach my $tmpval (@values) { 
                    my $val_content = $oconf->{attr}{$attr}->{webcontent}[0];
                    $val_content =~ s/\%a/$tmpval/g;
                    $list_contents{$list} = "$list_contents{$list}   $val_content,\n";
                }
            } elsif (defined($oconf->{attr}{$attr}->{webcontent})) {
                my $val_content = $oconf->{attr}{$attr}->{webcontent}[0];
                $val_content =~ s/\%a/$value/g;
                $content = "$content   \"$param\" : $val_content,\n";
            } elsif (defined($oconf->{attr}{$attr}->{multivalued}) && $oconf->{attr}{$attr}->{multivalued}) {
                my @tmpvals;
                foreach my $tmpval (@values) {
                    if ($tmpval !~ /^ +$/) {
                        push(@tmpvals, "   \"$tmpval\"");
                    }
                }
                if (@tmpvals) {
                    $content = "$content   \"$param\" : [\n".join(",\n", @tmpvals)."\n   ],\n";
                }
            } else {
                $content = "$content   \"$param\" : \"$value\",\n";
            }
        } elsif ($format eq 'xml') {
            $content .= "<$param>$value</$param>\n";
        }
    }

    foreach my $strginfo (@{$oconf->{strginfo}}) {
        if (!defined($strginfo->{value})) {
            next;
        }

        my $param = $strginfo->{param}[0];
        my $value = $strginfo->{value}[0]->{content};
        $value =~ s/\%c/$pkey/gi;

        if ($method eq 'GET') {
            $content = "$content&$param=".uri_escape(encode($conf->{mbcode}[0], $value));
        } elsif ($format eq 'POST') {
            $content = "$content&$param=$value";
        } elsif ($format eq 'json') {
            if (defined($strginfo->{parent})) {
                my $parent = $strginfo->{parent}[0];
                if (!defined($child_contents{$parent})) {
                    $child_contents{$parent} = "   \"$parent\" : {\n";
                }
                $child_contents{$parent} = "$child_contents{$parent}   \"$param\" : \"$value\",\n";
            } elsif ($strginfo->{value}[0]->{type} eq 'webcontent') {
                $content = "$content   \"$param\" : $value,\n";
            } elsif ($value eq 'true' || $value eq 'false') {
                $content = "$content   \"$param\" : $value,\n";
            } else {
                $content = "$content   \"$param\" : \"$value\",\n";
            }
        } elsif ($format eq 'xml') {
            $content .= "<$param>$value</$param>\n";
        }
    }

    if ($format eq 'json') {
        if (%child_contents) {
            foreach my $parent (keys %child_contents) {
                $child_contents{$parent} =~ s/,\n$/\n/;
                $content .= $child_contents{$parent}."   },\n";
            }
        }
        if (%list_contents) {
            foreach my $list (keys %list_contents) {
                $list_contents{$list} =~ s/,\n$/\n/;
                $content .= $list_contents{$list}."   ],\n";
            }
        }
        $content =~ s/,\n$/\n/;
        if (defined($oconf->{add}[0]->{tag})) {
            foreach my $tag (reverse(split(/, */, $oconf->{add}[0]->{tag}[0]))) {
                if ($tag =~ /^ *$/) {
                    last;
                }
                $content .= "}\n";
            }
        }
        $content = "$content}";
        if (defined($oconf->{add}[0]->{listtag})) {
            $content = '{"'.$oconf->{add}[0]->{listtag}[0].'": ['.$content.']}';
        }
        if (defined($self->{multilogin}{$self->{multilogin}->{current}}->{apiparam})) {
            my $apiparams = '';
            foreach my $param (keys %{$self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}}) {
                $apiparams .= "\"$param\":\"$self->{multilogin}{$self->{multilogin}->{current}}->{apiparam}{$param}->{value}\",";
            }
            if ($apiparams) {
                $content =~ s/^{/{$apiparams/;
            }
        }
    } elsif ($format eq 'xml') {
        if (defined($oconf->{add}[0]->{tag})) {
            foreach my $tag (reverse(split(/, */, $oconf->{add}[0]->{tag}[0]))) {
                if ($tag =~ /^ *$/) {
                    last;
                }
                $tag =~ s/^([^ ]+) +.+$/$1/;
                $content .= "</$tag>\n";
            }
        }
    }

    if ($format eq 'json' || $format eq 'xml') {
        $content = encode('utf8', $content);
    }

    return $content;
}

sub _checkResult
{
    my $self = shift;
    my ($resconf, $format, $result, $resp, $status_code, $op) = @_;
    my $rc = $status_code && $status_code !~ /^2[0-9]+$/ ? LDAP_OTHER : LDAP_SUCCESS;

    if (!$result) {
        if (!defined($resconf->{success})) {
            return $format ? 1 : 0;
        }
    }

    if (ref $result) {
        $result = ${$result}[0];
    }

    if ($format eq 'json') {
        if (defined($resconf->{tag}) && $result =~ /"$resconf->{tag}" *: *"([^"]*)"/i) {
            ${$resp}{code} = $1;
        }
        if (defined($resconf->{message}) && $result =~ /"$resconf->{message}" *: *\[?"([^"]*)"/i) {
            my $message = $1;
            if (!Encode::is_utf8($message)) {
                $message = decode('utf8', $message);
            }
            ${$resp}{message} = $message;
        }
    } elsif ($format eq 'xml') {
        if (defined($resconf->{tag})) {
            my $attr = defined($resconf->{attr}) ? $resconf->{attr} : 'value';
            if ($result =~ /<$resconf->{tag} .*$attr="([^"]*)".*>/i) {
                ${$resp}{code} = $1;
            } elsif ($result =~ /<$resconf->{tag}>([^<]*)<\/$resconf->{tag}>/i) {
                ${$resp}{code} = $1;
            }
            if ($result =~ /<$resconf->{tag} .*$resconf->{message}="([^"]*)".*>/i) {
                ${$resp}{message} = $1;
        }
        if (!defined(${$resp}{message}) && $result =~ /<$resconf->{message}>([^<]*)<\/$resconf->{message}>/i) {
                ${$resp}{message} = $1;
            }
        }
    } else {
        if (defined($resconf->{success}) && $result !~ /$resconf->{success}/i) {
            $rc = LDAP_OTHER;
        }
        if (defined($resconf->{tag}) && $result =~ /$resconf->{tag} +([^ ]+)/) {
            ${$resp}{code} = $1;
        }
        if (defined($resconf->{message}) && $result =~ /$resconf->{message} +([^ ]+)/) {
            ${$resp}{message} = $1;
        }
    }

    my $error = defined(${$resp}{code}) ? ${$resp}{code} : (defined(${$resp}{message}) ? ${$resp}{message} : '');
    if ($error && $error !~ /^$resconf->{success}$/i) {
        if (defined($resconf->{alreadyexists}) && $op && $op eq 'add' && $error =~ /^$resconf->{alreadyexists}$/i) {
            $rc = LDAP_ALREADY_EXISTS;
        } elsif (defined($resconf->{nosuchobject}) && $error =~ /^$resconf->{nosuchobject}$/i) {
            $rc = LDAP_NO_SUCH_OBJECT;
        } else {
            $rc = LDAP_OTHER;
        }
    }
    if ($status_code) {
        if (defined($resconf->{success}) && $status_code =~ /^$resconf->{success}$/i) {
            $rc = LDAP_SUCCESS;
        } elsif (defined($resconf->{alreadyexists}) && $status_code =~ /^$resconf->{alreadyexists}$/i) {
            $rc = LDAP_ALREADY_EXISTS;
        } elsif (defined($resconf->{nosuchobject}) && $status_code =~ /^$resconf->{nosuchobject}$/i) {
            $rc = LDAP_NO_SUCH_OBJECT;
        }
    }

    return $rc;
}

=head1 SEE ALSO

L<LISM>,
L<LISM::Storage>

=head1 AUTHOR

Kaoru Sekiguchi, <sekiguchi.kaoru@secioss.co.jp>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2016 SECIOSS, INC.

=cut

1;
