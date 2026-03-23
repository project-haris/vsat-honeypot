#!/usr/bin/env perl
use strict;
use warnings;
use IO::Socket::INET;
use JSON::PP qw(encode_json decode_json);
use File::Path qw(make_path);
use POSIX qw(strftime);
use Digest::SHA qw(sha1_hex);

my $root = '.';
my $public_dir = "$root/public";
my $data_dir = "$root/data";
my $log_dir = "$root/logs";
my $config_dir = "$root/config";
my $config_file = "$config_dir/honeypot.json";
my $state_file = "$data_dir/state.json";
my $request_log = "$log_dir/requests.log";
my $auth_log = "$log_dir/auth.log";
my %rate_limit_buckets;

make_path($public_dir, $data_dir, $log_dir, $config_dir);
bootstrap_config() unless -e $config_file;
my $config = load_config();

my $host = env_or_config('VSAT_BIND', $config->{server}{bind}, '127.0.0.1');
my $port = env_or_config_int('VSAT_PORT', $config->{server}{port}, 8080);
my $nav_source = $config->{navigation}{mode} // 'honeypot';
my $nav_refresh = $config->{navigation}{refreshSeconds} // 30;
my $nav_url = resolve_nav_url($config);
my $trust_proxy_headers = env_or_config_bool('VSAT_TRUST_PROXY_HEADERS', $config->{server}{trustProxyHeaders}) ? 1 : 0;
my $rate_limit_window = env_or_config_int('VSAT_RATE_LIMIT_WINDOW_SECONDS', $config->{server}{rateLimit}{windowSeconds}, 60);
my $rate_limit_max = env_or_config_int('VSAT_RATE_LIMIT_MAX_REQUESTS', $config->{server}{rateLimit}{maxRequestsPerWindow}, 180);

bootstrap_state() unless -e $state_file;

my $server = IO::Socket::INET->new(
    LocalAddr => $host,
    LocalPort => $port,
    Proto     => 'tcp',
    Listen    => 10,
    Reuse     => 1,
) or die "Unable to bind $host:$port: $!";

print "VSAT decoy listening on http://$host:$port\n";

while (my $client = $server->accept()) {
    $client->autoflush(1);
    eval { handle_client($client) };
    close $client;
}

sub handle_client {
    my ($client) = @_;
    my $request_line = <$client>;
    return unless defined $request_line;
    $request_line =~ s/\r?\n$//;
    my ($method, $path, $proto) = split /\s+/, $request_line, 3;
    return unless $method && $path;

    my %headers;
    while (my $line = <$client>) {
        $line =~ s/\r?\n$//;
        last if $line eq '';
        my ($name, $value) = split /:\s*/, $line, 2;
        next unless defined $name;
        $headers{lc $name} = $value // '';
    }

    my $content_length = $headers{'content-length'} // 0;
    my $body = '';
    if ($content_length =~ /^\d+$/ && $content_length > 0) {
        read($client, $body, $content_length);
    }

    my ($uri, $query_string) = split /\?/, $path, 2;
    $uri = normalize_path($uri // '/');

    my $cookie_header = $headers{'cookie'} // '';
    my %cookies = map {
        my ($k, $v) = split /=/, $_, 2;
        defined $k ? ($k => ($v // '')) : ()
    } map { s/^\s+|\s+$//gr } split /;\s*/, $cookie_header;

    my $session_id = $cookies{session_id} // '';
    my $socket_remote = eval { $client->peerhost } // 'unknown';
    my $remote = resolve_client_ip($socket_remote, \%headers);
    my $state = load_state();
    my $now = iso_now();
    my $user = session_user($state, $session_id);
    my $request_meta = extract_request_meta($uri, $method, $body);

    if (!allow_request($remote)) {
        log_line($request_log, encode_json({
            ts => $now,
            remote => $remote,
            socket_remote => $socket_remote,
            method => $method,
            path => $uri,
            query => parse_form($query_string // ''),
            user => $user,
            agent => ($headers{'user-agent'} // ''),
            referer => ($headers{'referer'} // ''),
            host => ($headers{'host'} // ''),
            content_length => ($headers{'content-length'} // 0),
            forwarded_for => ($headers{'x-forwarded-for'} // ''),
            %{$request_meta},
            outcome => 'rate_limited',
        }));
        send_plain($client, 429, "Too many requests\n");
        return;
    }

    log_line($request_log, encode_json({
        ts => $now,
        remote => $remote,
        socket_remote => $socket_remote,
        method => $method,
        path => $uri,
        query => parse_form($query_string // ''),
        user => $user,
        agent => ($headers{'user-agent'} // ''),
        referer => ($headers{'referer'} // ''),
        host => ($headers{'host'} // ''),
        content_length => ($headers{'content-length'} // 0),
        forwarded_for => ($headers{'x-forwarded-for'} // ''),
        %{$request_meta},
        outcome => 'accepted',
    }));

    if ($uri eq '/api/login' && $method eq 'POST') {
        my $payload = parse_json_body($body);
        my $username = trim($payload->{username} // '');
        my $password = $payload->{password} // '';
        my $accepted = ($username eq 'admin' && $password eq '1234') ? 1 : 0;
        $accepted = ($username eq 'service' && $password eq 'service') ? 1 : 0 unless $accepted;
        my $session_for_log = '';
        my @headers;

        if ($accepted) {
            my $new_session = create_session($state, 'admin');
            $session_for_log = $new_session;
            @headers = ("Set-Cookie: session_id=$new_session; Path=/; HttpOnly; SameSite=Lax");
            prepend_command($state, {
                ts => $now,
                operator => 'admin',
                action => 'login',
                detail => 'Operator session established',
            });
            append_event($state, {
                ts => $now,
                level => 'info',
                code => 'AUTH-100',
                message => 'Operator login accepted',
            });
            save_state($state);
        }

        log_line($auth_log, encode_json({
            ts => $now,
            remote => $remote,
            username => $username,
            password => $password,
            session_id => $session_for_log,
            result => $accepted ? 'accepted' : 'denied',
            agent => ($headers{'user-agent'} // ''),
            forwarded_for => ($headers{'x-forwarded-for'} // ''),
        }));

        if ($accepted) {
            send_json($client, 200, {
                ok => JSON::PP::true,
                operator => 'admin',
                redirect => '/dashboard',
            }, \@headers);
        } else {
            send_json($client, 401, {
                ok => JSON::PP::false,
                error => 'Invalid credentials',
            });
        }
        return;
    }

    if ($uri eq '/api/logout' && $method eq 'POST') {
        if ($session_id && exists $state->{sessions}{$session_id}) {
            delete $state->{sessions}{$session_id};
            save_state($state);
        }
        send_json($client, 200, { ok => JSON::PP::true }, [
            "Set-Cookie: session_id=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        ]);
        return;
    }

    if ($uri eq '/api/status' && $method eq 'GET') {
        my $status = build_status($state);
        save_state($state);
        send_json($client, 200, {
            authenticated => $user ? JSON::PP::true : JSON::PP::false,
            operator => $user // '',
            status => $status,
            profile => $state->{profile},
            terminals => $state->{terminals},
            wan => $state->{wan},
            modemProfiles => $state->{modem_profiles},
            blockingZones => $state->{blocking_zones},
            networkPorts => $state->{network_ports},
            configuredVessel => {
                shipName => $config->{navigation}{vesseltracker}{shipName} // '',
                imo => $config->{navigation}{vesseltracker}{imo} // '',
                mode => $nav_source,
            },
            upstreamNav => $state->{upstream_nav},
            logs => {
                events => $state->{events},
                commands => $state->{command_log},
            },
        });
        return;
    }

    if ($uri eq '/api/config/network' && $method eq 'POST') {
        return reject_unauth($client) unless $user;
        my $payload = parse_json_body($body);
        $state->{wan}{targetIp} = trim($payload->{targetIp} // $state->{wan}{targetIp});
        $state->{wan}{mask} = trim($payload->{mask} // $state->{wan}{mask});
        $state->{wan}{gateway} = trim($payload->{gateway} // $state->{wan}{gateway});
        prepend_command($state, {
            ts => $now,
            operator => $user,
            action => 'network-profile-write',
            detail => "Updated modem management network to $state->{wan}{targetIp}/$state->{wan}{mask}",
        });
        append_event($state, {
            ts => $now,
            level => 'notice',
            code => 'CFG-204',
            message => 'Terminal network configuration updated',
        });
        save_state($state);
        send_json($client, 200, { ok => JSON::PP::true, wan => $state->{wan} });
        return;
    }

    if ($uri eq '/api/config/antenna' && $method eq 'POST') {
        return reject_unauth($client) unless $user;
        my $payload = parse_json_body($body);
        $state->{profile}{trackingMode} = trim($payload->{trackingMode} // $state->{profile}{trackingMode});
        $state->{profile}{satelliteName} = trim($payload->{satelliteName} // $state->{profile}{satelliteName});
        $state->{profile}{profileName} = trim($payload->{profileName} // $state->{profile}{profileName});
        prepend_command($state, {
            ts => $now,
            operator => $user,
            action => 'antenna-profile-write',
            detail => "Tracking mode set to $state->{profile}{trackingMode}",
        });
        append_event($state, {
            ts => $now,
            level => 'notice',
            code => 'ANT-117',
            message => 'Antenna profile updated',
        });
        save_state($state);
        send_json($client, 200, { ok => JSON::PP::true, profile => $state->{profile} });
        return;
    }

    if ($uri eq '/api/command' && $method eq 'POST') {
        return reject_unauth($client) unless $user;
        my $payload = parse_json_body($body);
        my $command = trim($payload->{command} // '');
        prepend_command($state, {
            ts => $now,
            operator => $user,
            action => 'cli-command',
            detail => $command || 'blank command',
        });
        append_event($state, {
            ts => $now,
            level => 'warning',
            code => 'CLI-310',
            message => $command ? "Uncommitted command staged: $command" : 'Blank terminal command received',
        });
        save_state($state);
        send_json($client, 200, {
            ok => JSON::PP::true,
            echo => $command,
            output => [
                'command mode: accepted',
                'result: successful',
            ],
        });
        return;
    }

    if ($uri eq '/api/upload' && $method eq 'POST') {
        my $payload = parse_json_body($body);
        my $filename = trim($payload->{filename} // 'unnamed-package.bin');
        my $size = trim($payload->{size} // '0');
        my $mime = trim($payload->{mime} // 'application/octet-stream');
        prepend_command($state, {
            ts => $now,
            operator => $user || 'guest',
            action => 'auth-package-upload',
            detail => "Accepted authentication package for $filename ($size bytes, $mime)",
        });
        append_event($state, {
            ts => $now,
            level => 'notice',
            code => 'UPL-208',
            message => "Authentication package upload completed for $filename",
        });
        save_state($state);
        send_json($client, 200, {
            ok => JSON::PP::true,
            status => 'success',
            message => "Authentication package accepted: $filename",
        });
        return;
    }

    if ($uri eq '/' || $uri eq '/dashboard') {
        send_file($client, "$public_dir/index.html", 'text/html; charset=utf-8');
        return;
    }

    if ($uri =~ m{^/assets/([A-Za-z0-9._/-]+)$}) {
        my $asset = $1;
        my $file = "$public_dir/assets/$asset";
        if (-f $file) {
            my $content_type = mime_type($file);
            send_file($client, $file, $content_type);
        } else {
            send_plain($client, 404, "Not found\n");
        }
        return;
    }

    send_plain($client, 404, "Not found\n");
}

sub bootstrap_state {
    my $state = default_state();
    save_state($state);
}

sub default_state {
    return {
        profile => {
            profileName => 'INTELSAT-907',
            satelliteName => 'IS-907 @ 332.5E',
            trackingMode => 'Steptrack',
            firmware => 'v2.4.3',
            uptimeHours => 2147,
            serialNumber => 'S900-4821-0391',
            modemType => 'SAILOR 900 VSAT Ka',
        },
        wan => {
            targetIp => '192.168.0.1',
            mask => '255.255.255.0',
            gateway => '192.168.0.254',
            qosProfile => 'Fleet-Priority-2',
            dnsPrimary => '8.8.8.8',
            dnsSecondary => '8.8.4.4',
            servicePort => 'LAN port 3',
            proxyMode => 'Direct',
        },
        terminals => [
            {
                name => 'Above Deck Unit (ADU)',
                status => 'Tracking',
                temperature => 38,
                azimuth => 182.4,
                elevation => 38.9,
                polarization => 'RHCP',
            },
            {
                name => 'Below Deck Unit (BDU)',
                status => 'Online',
                temperature => 32,
                azimuth => 0,
                elevation => 0,
                polarization => 'N/A',
            }
        ],
        telemetry => {
            rxDbm => -58.3,
            txDbm => 13.2,
            cNo => 15.8,
            ber => '1.2e-7',
            gps => '59.4370N / 24.7536E',
            heading => 71,
            pitch => 1.3,
            roll => 0.8,
            azimuth => 182.4,
            elevation => 38.9,
            packets => 17424011,
            agc => 72,
            spectralInversion => 'Normal',
            carrier => 'Locked',
            txMute => 'Off',
            posOk => '99.6%',
        },
        modem_profiles => [
            {
                name => 'iDirect X7 Primary',
                txFrequency => '29.500 GHz',
                rxFrequency => '19.700 GHz',
                symbolRate => '45000 ksps',
                network => 'North Atlantic',
                active => JSON::PP::true,
            },
            {
                name => 'Calibration Profile',
                txFrequency => '29.250 GHz',
                rxFrequency => '19.450 GHz',
                symbolRate => '30000 ksps',
                network => 'Commissioning',
                active => JSON::PP::false,
            },
        ],
        blocking_zones => [
            { name => 'Funnel Shadow', start => '315', stop => '045', type => 'RX/TX', status => 'Active' },
            { name => 'Crane Reach', start => '118', stop => '146', type => 'TX', status => 'Active' },
        ],
        network_ports => [
            { port => 'LAN 1', role => 'Bridge group A', ip => '192.168.10.1', status => 'Link up' },
            { port => 'LAN 2', role => 'Bridge group B', ip => '192.168.20.1', status => 'Link down' },
            { port => 'LAN 3', role => 'Service port', ip => '192.168.0.1', status => 'Link up' },
            { port => 'LAN 4', role => 'Bridge group C', ip => '192.168.30.1', status => 'Link up' },
        ],
        upstream_nav => {
            source => $nav_source,
            url => $nav_url,
            refreshedAt => '',
            vesselName => '',
            status => 'mock',
        },
        events => [
            { ts => iso_now(), level => 'info', code => '100', message => 'System startup complete' },
            { ts => iso_now(), level => 'notice', code => '201', message => 'Carrier lock acquired' },
            { ts => iso_now(), level => 'info', code => '305', message => 'Antenna pointing optimized' },
        ],
        command_log => [
            { ts => iso_now(), operator => 'system', action => 'init', detail => 'SAILOR 900 VSAT Ka initialized' },
        ],
        sessions => {},
    };
}

sub bootstrap_config {
    my $config = default_config();
    open my $fh, '>', $config_file or die "Unable to write config: $!";
    print {$fh} JSON::PP->new->pretty->canonical->encode($config);
    close $fh;
}

sub load_config {
    open my $fh, '<', $config_file or die "Unable to read config: $!";
    local $/;
    my $json = <$fh>;
    close $fh;
    my $decoded = eval { decode_json($json) };
    return merge_defaults(default_config(), $decoded && ref $decoded eq 'HASH' ? $decoded : {});
}

sub default_config {
    return {
        server => {
            bind => '127.0.0.1',
            port => 8080,
            trustProxyHeaders => JSON::PP::false,
            rateLimit => {
                windowSeconds => 60,
                maxRequestsPerWindow => 180,
            },
        },
        navigation => {
            mode => 'honeypot',
            refreshSeconds => 30,
            vesseltracker => {
                shipName => 'Megastar',
                imo => '9773064',
                url => '',
            },
        },
    };
}

sub merge_defaults {
    my ($defaults, $overrides) = @_;
    my %merged = %{$defaults || {}};
    for my $key (keys %{$overrides || {}}) {
        my $default_value = $defaults->{$key};
        my $override_value = $overrides->{$key};
        if (ref($default_value) eq 'HASH' && ref($override_value) eq 'HASH') {
            $merged{$key} = merge_defaults($default_value, $override_value);
        } else {
            $merged{$key} = $override_value;
        }
    }
    return \%merged;
}

sub env_or_config {
    my ($env_name, $config_value, $fallback) = @_;
    return $ENV{$env_name} if defined $ENV{$env_name} && $ENV{$env_name} ne '';
    return $config_value if defined $config_value && $config_value ne '';
    return $fallback;
}

sub env_or_config_int {
    my ($env_name, $config_value, $fallback) = @_;
    return $ENV{$env_name} + 0 if defined $ENV{$env_name} && $ENV{$env_name} =~ /^\d+$/;
    return $config_value + 0 if defined $config_value && $config_value =~ /^\d+$/;
    return $fallback;
}

sub env_or_config_bool {
    my ($env_name, $config_value) = @_;
    if (defined $ENV{$env_name} && $ENV{$env_name} ne '') {
        my $value = lc trim($ENV{$env_name});
        return 1 if $value =~ /^(1|true|yes|on)$/;
        return 0 if $value =~ /^(0|false|no|off)$/;
    }
    return $config_value ? 1 : 0;
}

sub resolve_client_ip {
    my ($socket_remote, $headers) = @_;
    return $socket_remote unless $trust_proxy_headers;
    my $forwarded = trim($headers->{'x-forwarded-for'} // '');
    if ($forwarded) {
        my ($first) = split /,/, $forwarded, 2;
        $first = trim($first // '');
        return $first if $first;
    }
    my $real_ip = trim($headers->{'x-real-ip'} // '');
    return $real_ip if $real_ip;
    return $socket_remote;
}

sub allow_request {
    my ($remote) = @_;
    my $now = time;
    my $bucket = $rate_limit_buckets{$remote} ||= { started_at => $now, count => 0 };
    if ($now - $bucket->{started_at} >= $rate_limit_window) {
        $bucket->{started_at} = $now;
        $bucket->{count} = 0;
    }
    $bucket->{count}++;
    return $bucket->{count} <= $rate_limit_max;
}

sub resolve_nav_url {
    my ($config) = @_;
    my $nav = $config->{navigation} || {};
    my $vt = $nav->{vesseltracker} || {};
    return $vt->{url} if $vt->{url};
    my $imo = trim($vt->{imo} // '');
    my $ship_name = trim($vt->{shipName} // '');
    return '' unless $imo && $ship_name;
    return 'https://www.vesseltracker.com/en/Ships/' . slugify_ship_name($ship_name) . '-' . $imo . '.html';
}

sub slugify_ship_name {
    my ($ship_name) = @_;
    $ship_name = lc $ship_name;
    $ship_name =~ s/[^a-z0-9]+/-/g;
    $ship_name =~ s/^-+|-+$//g;
    my @parts = grep { length } split /-+/, $ship_name;
    @parts = map { ucfirst $_ } @parts;
    return join('-', @parts);
}

sub build_status {
    my ($state) = @_;
    my $nav = resolve_navigation($state, time);
    $state->{telemetry}{rxDbm} = sprintf('%.1f', -62.4 + 0.7 * $nav->{sea});
    $state->{telemetry}{txDbm} = sprintf('%.1f', 11.1 + 0.5 * $nav->{swell});
    $state->{telemetry}{cNo} = sprintf('%.1f', 14.7 + 0.4 * $nav->{sea});
    $state->{telemetry}{heading} = $nav->{heading};
    $state->{telemetry}{pitch} = sprintf('%.1f', $nav->{pitch});
    $state->{telemetry}{roll} = sprintf('%.1f', $nav->{roll});
    $state->{telemetry}{gps} = format_gps($nav->{lat}, $nav->{lon});
    $state->{telemetry}{packets} += 320 + int(280 * (1 + $nav->{sea}));
    $state->{profile}{uptimeHours} += 1 if int(time / 3600) > $state->{profile}{uptimeHours};
    return $state->{telemetry};
}

sub resolve_navigation {
    my ($state, $epoch) = @_;
    my $loop = navigation_loop_sample($epoch);

    if ($nav_source eq 'scrape' && $nav_url) {
        my $cached = $state->{upstream_nav} // {};
        my $fresh = ($cached->{refreshedEpoch} // 0) + $nav_refresh > $epoch;
        if (!$fresh) {
            my $scraped = scrape_vesseltracker($nav_url);
            if ($scraped->{ok}) {
                $cached = {
                    source => 'scrape',
                    url => $nav_url,
                    refreshedAt => iso_now(),
                    refreshedEpoch => $epoch,
                    vesselName => $scraped->{vesselName} // '',
                    status => 'live',
                    %$scraped,
                };
                $state->{upstream_nav} = $cached;
            } else {
                $cached->{status} = 'fallback';
                $cached->{error} = $scraped->{error};
                $state->{upstream_nav} = $cached;
            }
        }

        if (($state->{upstream_nav}{heading} // '') ne '') {
            my $heading = $state->{upstream_nav}{heading};
            my $speed = $state->{upstream_nav}{speedKnots};
            my $motion = motion_from_heading($heading, $speed // 0, $epoch);
            return {
                %$loop,
                heading => sprintf('%.0f', $heading),
                lat => $motion->{lat},
                lon => $motion->{lon},
                pitch => $motion->{pitch},
                roll => $motion->{roll},
                sea => $motion->{sea},
                swell => $motion->{swell},
            };
        }
    }

    $state->{upstream_nav} = {
        source => 'honeypot',
        url => '',
        refreshedAt => iso_now(),
        refreshedEpoch => $epoch,
        vesselName => '',
        status => 'mock',
    } if !exists $state->{upstream_nav} || ($nav_source ne 'scrape');

    return $loop;
}

sub navigation_loop_sample {
    my ($epoch) = @_;
    my $loop_seconds = 300;
    my $offset = $epoch % $loop_seconds;
    my $theta = 2 * 3.14159265358979 * ($offset / $loop_seconds);

    # A short repeating harbor-exit style track centered off Tallinn roads.
    my $base_lat = 59.5042;
    my $base_lon = 24.7038;
    my $lat = $base_lat + 0.0120 * sin($theta) + 0.0018 * sin(3 * $theta);
    my $lon = $base_lon + 0.0210 * cos($theta - 0.22) + 0.0025 * sin(2 * $theta);

    my $dlat = 0.0120 * cos($theta) + 0.0054 * cos(3 * $theta);
    my $dlon = -0.0210 * sin($theta - 0.22) + 0.0050 * cos(2 * $theta);
    my $heading = atan2_deg($dlon, $dlat);

    my $sea = sin($theta - 0.35);
    my $swell = sin(2 * $theta + 0.4);

    return {
        lat => $lat,
        lon => $lon,
        heading => sprintf('%.0f', $heading),
        pitch => 1.4 + 0.6 * $swell + 0.2 * sin(5 * $theta),
        roll => 0.8 + 1.0 * $sea + 0.2 * cos(4 * $theta),
        sea => $sea,
        swell => $swell,
    };
}

sub motion_from_heading {
    my ($heading, $speed_knots, $epoch) = @_;
    my $theta = 2 * 3.14159265358979 * (($epoch % 300) / 300);
    my $distance_scale = ($speed_knots || 7.0) / 800;
    my $radians = $heading * 3.14159265358979 / 180;
    my $base_lat = 59.4540;
    my $base_lon = 24.7580;
    return {
        lat => $base_lat + cos($radians) * $distance_scale + 0.0016 * sin($theta),
        lon => $base_lon + sin($radians) * $distance_scale * 1.8 + 0.0020 * cos($theta),
        pitch => 1.2 + 0.5 * sin(2 * $theta + 0.3),
        roll => 0.9 + 0.8 * sin($theta - 0.5),
        sea => sin($theta - 0.35),
        swell => sin(2 * $theta + 0.4),
    };
}

sub scrape_vesseltracker {
    my ($url) = @_;
    return { ok => 0, error => 'Unsupported source URL' }
        unless $url =~ m{^https://www\.vesseltracker\.com/}i;

    my $html = '';
    my $pid = open my $fh, '-|', 'curl', '-s', '-L', '-A', 'Mozilla/5.0', $url;
    return { ok => 0, error => 'Unable to start curl' } unless $pid;
    {
        local $/;
        $html = <$fh> // '';
    }
    close $fh;
    return { ok => 0, error => 'Empty response' } unless length $html;

    my %fields;
    while ($html =~ m{<div class="col-xs-5 key">([^<]+)</div>\s*<div class="col-xs-7 value">(.*?)</div>}gsi) {
        my $key = normalize_html_text($1);
        my $value = normalize_html_text($2);
        $fields{$key} = $value;
    }

    my $title = '';
    if ($html =~ m{<h1>([^<]+)</h1>}i) {
        $title = normalize_html_text($1);
    }

    my ($course_deg, $course_speed) = parse_angle_pair($fields{'Course:'} // '');
    my ($heading_deg, $heading_speed) = parse_angle_pair($fields{'Heading:'} // '');
    my $speed_knots = first_number($fields{'Speed:'} // '');
    $speed_knots = $heading_speed if !defined $speed_knots && defined $heading_speed;
    $speed_knots = $course_speed if !defined $speed_knots && defined $course_speed;

    my $heading = defined $heading_deg ? $heading_deg : $course_deg;
    return { ok => 0, error => 'Heading unavailable on source page' } unless defined $heading;

    return {
        ok => 1,
        vesselName => $title,
        heading => $heading,
        course => $course_deg,
        speedKnots => $speed_knots,
        destination => $fields{'Destination:'} // '',
        eta => $fields{'ETA:'} // '',
    };
}

sub normalize_html_text {
    my ($html) = @_;
    $html //= '';
    $html =~ s/<script\b[^>]*>.*?<\/script>//gis;
    $html =~ s/<style\b[^>]*>.*?<\/style>//gis;
    $html =~ s/<[^>]+>/ /g;
    $html = decode_basic_entities($html);
    $html =~ s/\x{a0}/ /g;
    $html =~ s/\s+/ /g;
    $html =~ s/^\s+|\s+$//g;
    return $html;
}

sub decode_basic_entities {
    my ($text) = @_;
    return '' unless defined $text;
    $text =~ s/&deg;/ deg/gi;
    $text =~ s/&nbsp;/ /gi;
    $text =~ s/&amp;/&/gi;
    $text =~ s/&quot;/"/gi;
    $text =~ s/&#39;/'/gi;
    $text =~ s/&lt;/</gi;
    $text =~ s/&gt;/>/gi;
    $text =~ s/&#(\d+);/chr($1)/eg;
    $text =~ s/&#x([0-9a-fA-F]+);/chr(hex($1))/eg;
    return $text;
}

sub parse_angle_pair {
    my ($value) = @_;
    return unless $value;
    if ($value =~ /([0-9]+(?:\.[0-9]+)?)\s*deg?\s*\/\s*([0-9]+(?:\.[0-9]+)?)/i) {
        return ($1 + 0, $2 + 0);
    }
    if ($value =~ /([0-9]+(?:\.[0-9]+)?)/) {
        return ($1 + 0, undef);
    }
    return;
}

sub first_number {
    my ($value) = @_;
    return undef unless $value;
    return $1 + 0 if $value =~ /([0-9]+(?:\.[0-9]+)?)/;
    return undef;
}

sub atan2_deg {
    my ($y, $x) = @_;
    my $angle = atan2($y, $x) * 180 / 3.14159265358979;
    $angle += 360 if $angle < 0;
    return $angle;
}

sub format_gps {
    my ($lat, $lon) = @_;
    my $lat_hemisphere = $lat >= 0 ? 'N' : 'S';
    my $lon_hemisphere = $lon >= 0 ? 'E' : 'W';
    return sprintf('%.4f%s / %.4f%s', abs($lat), $lat_hemisphere, abs($lon), $lon_hemisphere);
}

sub create_session {
    my ($state, $user) = @_;
    my $session_id = sha1_hex(join ':', $user, time, rand(), $$);
    $state->{sessions}{$session_id} = {
        user => $user,
        issued_at => iso_now(),
    };
    return $session_id;
}

sub session_user {
    my ($state, $session_id) = @_;
    return unless $session_id;
    return unless exists $state->{sessions}{$session_id};
    return $state->{sessions}{$session_id}{user};
}

sub prepend_command {
    my ($state, $item) = @_;
    unshift @{$state->{command_log}}, $item;
    splice @{$state->{command_log}}, 12 if @{$state->{command_log}} > 12;
}

sub append_event {
    my ($state, $item) = @_;
    unshift @{$state->{events}}, $item;
    splice @{$state->{events}}, 12 if @{$state->{events}} > 12;
}

sub load_state {
    open my $fh, '<', $state_file or die "Unable to read state: $!";
    local $/;
    my $json = <$fh>;
    close $fh;
    my $decoded = eval { decode_json($json) };
    return normalize_state($decoded && ref $decoded eq 'HASH' ? $decoded : {});
}

sub normalize_state {
    my ($state) = @_;
    my $normalized = merge_defaults(default_state(), $state);

    # Existing deployments may have older labels or slightly different shapes.
    if (ref($normalized->{terminals}) eq 'ARRAY') {
        for my $terminal (@{$normalized->{terminals}}) {
            next unless ref($terminal) eq 'HASH';
            $terminal->{name} = 'Above Deck Unit (ADU)' if ($terminal->{name} // '') eq 'Above Deck Unit';
            $terminal->{name} = 'Below Deck Unit (BDU)' if ($terminal->{name} // '') eq 'Below Deck Unit';
            $terminal->{status} = 'Online' if ($terminal->{status} // '') eq 'Operational';
        }
    }

    return $normalized;
}

sub save_state {
    my ($state) = @_;
    open my $fh, '>', $state_file or die "Unable to write state: $!";
    print {$fh} encode_json($state);
    close $fh;
}

sub parse_json_body {
    my ($body) = @_;
    return {} unless defined $body && length $body;
    my $decoded = eval { decode_json($body) };
    return $decoded && ref $decoded eq 'HASH' ? $decoded : {};
}

sub extract_request_meta {
    my ($uri, $method, $body) = @_;
    return {} unless $uri eq '/api/upload' && $method eq 'POST';
    my $payload = parse_json_body($body);
    return {
        upload_filename => trim($payload->{filename} // 'unnamed-package.bin'),
        upload_size => trim($payload->{size} // '0'),
        upload_mime => trim($payload->{mime} // 'application/octet-stream'),
    };
}

sub parse_form {
    my ($value) = @_;
    return {} unless defined $value && length $value;
    my %pairs;
    for my $pair (split /&/, $value) {
        my ($k, $v) = split /=/, $pair, 2;
        $k = url_decode($k // '');
        $v = url_decode($v // '');
        $pairs{$k} = $v;
    }
    return \%pairs;
}

sub normalize_path {
    my ($uri) = @_;
    $uri =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
    $uri =~ s/\0//g;
    $uri =~ s#//+#/#g;
    return $uri;
}

sub url_decode {
    my ($text) = @_;
    $text =~ tr/+/ /;
    $text =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
    return $text;
}

sub trim {
    my ($text) = @_;
    $text //= '';
    $text =~ s/^\s+//;
    $text =~ s/\s+$//;
    return $text;
}

sub iso_now {
    return strftime('%Y-%m-%dT%H:%M:%SZ', gmtime());
}

sub log_line {
    my ($file, $line) = @_;
    open my $fh, '>>', $file or die "Unable to append $file: $!";
    print {$fh} $line . "\n";
    close $fh;
}

sub send_file {
    my ($client, $file, $content_type) = @_;
    open my $fh, '<', $file or do {
        send_plain($client, 404, "Not found\n");
        return;
    };
    binmode $fh;
    local $/;
    my $content = <$fh>;
    close $fh;
    send_response($client, 200, 'OK', $content_type, $content, []);
}

sub send_plain {
    my ($client, $status, $content) = @_;
    my %text = (
        401 => 'Unauthorized',
        429 => 'Too Many Requests',
        404 => 'Not Found',
    );
    send_response($client, $status, ($text{$status} // 'OK'), 'text/plain; charset=utf-8', $content, []);
}

sub send_json {
    my ($client, $status, $data, $extra_headers) = @_;
    $extra_headers ||= [];
    my %text = (
        200 => 'OK',
        401 => 'Unauthorized',
    );
    send_response($client, $status, ($text{$status} // 'OK'), 'application/json; charset=utf-8', encode_json($data), $extra_headers);
}

sub reject_unauth {
    my ($client) = @_;
    send_json($client, 401, {
        ok => JSON::PP::false,
        error => 'Authentication required',
    });
}

sub send_response {
    my ($client, $status, $reason, $content_type, $content, $extra_headers) = @_;
    my @headers = (
        "HTTP/1.1 $status $reason",
        "Content-Type: $content_type",
        'Connection: close',
        'Cache-Control: no-store',
        'Referrer-Policy: no-referrer',
        'X-Robots-Tag: noindex, nofollow, noarchive',
        'X-Frame-Options: DENY',
        'X-Content-Type-Options: nosniff',
        'Server: Allegro-WebServer/3.2.1',
        "Content-Length: " . length($content),
        @$extra_headers,
        '',
        '',
    );
    print {$client} join("\r\n", @headers);
    print {$client} $content;
}

sub mime_type {
    my ($file) = @_;
    return 'text/css; charset=utf-8' if $file =~ /\.css$/;
    return 'application/javascript; charset=utf-8' if $file =~ /\.js$/;
    return 'image/svg+xml' if $file =~ /\.svg$/;
    return 'text/html; charset=utf-8' if $file =~ /\.html$/;
    return 'text/plain; charset=utf-8';
}
