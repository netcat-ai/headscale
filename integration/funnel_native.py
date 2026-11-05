#!/usr/bin/env python3
"""Isolated real-process Funnel acceptance; no Docker, production DNS or OS TUN.

Build the three binaries from this checkout's module pins, then run:
  python3 integration/funnel_native.py --bin-dir /tmp/funnel-bin --output /tmp/funnel-report.json
Add --listen-port 443 to exercise that exact port when available.
All credentials and process logs live in a private temporary directory and are
removed even on failure. The JSON artifact contains checks and binary hashes.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--listen-port', type=int, default=0)
    parser.add_argument('--transport-only', action='store_true')
    args = parser.parse_args()
    bins = args.bin_dir.resolve()
    report = {'started': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'checks': {},
              'production_modified': False, 'cleanup': False, 'binaries_sha256': {}}
    for name in ['headscale', 'tailscale', 'tailscaled']:
        with (bins/name).open('rb') as f:
            report['binaries_sha256'][name] = hashlib.file_digest(f, 'sha256').hexdigest()
    env = dict(os.environ, NO_PROXY='*', no_proxy='*', TS_NO_LOGS_NO_SUPPORT='true')
    # Never inherit a workstation's test bypass or TLS session-key logger.
    for name in ['TS_ALLOW_SELF_INGRESS', 'SSLKEYLOGFILE', 'TS_DEBUG_TLS_DIAL']:
        env.pop(name, None)
    processes, logs = [], []

    def run(command, timeout=30, check=True, **kwargs):
        commandenv = env
        if Path(str(command[0])).name == 'headscale':
            commandenv = dict(env, HEADSCALE_LOG_LEVEL='error', HEADSCALE_LOG_FORMAT='text')
        result = subprocess.run([str(x) for x in command], env=commandenv, capture_output=True,
                                text=True, timeout=timeout, **kwargs)
        if check and result.returncode:
            # Do not include command arguments: they may contain an auth key.
            raise RuntimeError(Path(str(command[0])).name+' failed: '+result.stderr[-1800:])
        return result

    def check(name, value):
        report['checks'][name] = bool(value)
        print(name+': '+('PASS' if value else 'FAIL'), flush=True)
        if not value:
            raise RuntimeError(name+' failed')

    def eventually(name, read, timeout=35):
        deadline = time.monotonic()+timeout
        last_error = None
        while time.monotonic() < deadline:
            try:
                value = read()
                if value:
                    check(name, True)
                    return value
            except (OSError, RuntimeError, ValueError) as error:
                last_error = type(error).__name__+': '+str(error)
            time.sleep(.3)
        if last_error:
            print(name+' last error: '+last_error, flush=True)
        check(name, False)

    with tempfile.TemporaryDirectory(prefix='hs-funnel-') as temp:
        d = Path(temp)
        port = args.listen_port or free_port()
        report['shared_listener_port'] = port
        env['SSL_CERT_FILE'] = str(d/'ca.pem')
        env['SSL_CERT_DIR'] = str(d/'empty-certs')
        (d/'empty-certs').mkdir()
        url = f'https://127.0.0.1:{port}'
        hs = [bins/'headscale', '--config', d/'config.yaml']

        def start(command, name):
            log = open(d/(name+'.log'), 'w+')
            logs.append((name, log))
            process = subprocess.Popen([str(x) for x in command], env=env, stdout=log, stderr=log)
            processes.append(process)
            return process

        def stop(process):
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise RuntimeError('process did not shut down gracefully')

        def write_policy(funnel=True, wildcard=False):
            (d/'policy.json').write_text(json.dumps({
                'acls': [{'action': 'accept', 'src': ['*'], 'dst': ['*:*']}] if wildcard else [],
                'nodeAttrs': [{'target': ['*'], 'attr': ['funnel']}] if funnel else [],
            }))

        def control_ok(path='/health'):
            return run(['curl', '-fsS', '--max-time', '3', '--cacert', d/'ca.pem', url+path],
                       timeout=5, check=False).returncode == 0

        def startup_failed(logname):
            return hp.poll() is None and 'Funnel unavailable' in (d/(logname+'.log')).read_text()

        def derp_handshake(name):
            result = json.loads(run(client(name)+['debug', 'derp', '999'], timeout=40).stdout)
            # The fixture binds 127.0.0.1 only. The official diagnostic always
            # probes tcp6 too, which cannot dial this IPv4 literal. Keep every
            # other diagnostic error fatal, including IPv4 TLS/DERP failures.
            report['derp_validation_scope'] = 'IPv4 loopback; IPv6 is not configured'
            errors = [x for x in result.get('Errors') or [] if 'over IPv6:' not in x]
            ok = not errors and any('Successfully established a DERP connection' in x
                                    for x in result.get('Info') or [])
            if not ok:
                print('DERP diagnostic: '+json.dumps(result), flush=True)
            return ok

        def nodes():
            return json.loads(run(hs+['nodes', 'list', '-o', 'json']).stdout)

        def client(name):
            return [bins/'tailscale', '--socket', d/(name+'.sock')]

        def status(name):
            return json.loads(run(client(name)+['status', '--json']).stdout)

        def add_client(name, tag=None):
            auth = ['preauthkeys', 'create', '--expiration', '10m', '-o', 'json']
            if tag:
                auth += ['--tags', tag]
            else:
                user = json.loads(run(hs+['users', 'create', name, '-o', 'json']).stdout)
                auth += ['--user', str(user['id'])]
            key = json.loads(run(hs+auth).stdout)['key']
            keypath = d/(name+'.auth')
            keypath.write_text(key)
            keypath.chmod(0o600)
            socks = free_port()
            p = start([bins/'tailscaled', '--tun=userspace-networking', '--port=0',
                       '--socket='+str(d/(name+'.sock')), '--statedir='+str(d/name),
                       f'--socks5-server=127.0.0.1:{socks}'], name)
            eventually(name+'_local_socket', lambda: (d/(name+'.sock')).exists() and p.poll() is None)
            run(client(name)+['up', '--login-server', url, '--auth-key=file:'+str(keypath),
                             '--hostname='+name, '--accept-dns=false', '--accept-routes=false',
                             '--timeout=30s'], timeout=40)
            check(name+'_registered', status(name)['BackendState'] == 'Running')
            return socks

        def connect(host='target.funnel.test', fragmented=False):
            # MemoryBIO lets the harness split ClientHello across TCP writes.
            raw = socket.create_connection(('127.0.0.1', port), timeout=5)
            context = ssl.create_default_context(cafile=str(d/'ca.pem'))
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            tls = context.wrap_bio(incoming, outgoing, server_hostname=host)
            first = True

            def flush():
                nonlocal first
                data = outgoing.read()
                if first and fragmented:
                    for i in range(0, len(data), 13):
                        raw.sendall(data[i:i+13])
                        time.sleep(.002)
                else:
                    raw.sendall(data)
                first = False

            try:
                while True:
                    try:
                        tls.do_handshake()
                        flush()
                        break
                    except ssl.SSLWantReadError:
                        flush()
                        data = raw.recv(65536)
                        if not data:
                            raise OSError('TLS rejected')
                        incoming.write(data)
                return raw, tls, incoming, outgoing
            except BaseException:
                raw.close()
                raise

        def exchange(connection, data):
            raw, tls, incoming, outgoing = connection
            tls.write(data)
            raw.sendall(outgoing.read())
            while True:
                try:
                    return tls.read(65536)
                except ssl.SSLWantReadError:
                    pending = outgoing.read()
                    if pending:
                        raw.sendall(pending)
                    data = raw.recv(65536)
                    if not data:
                        return b''
                    incoming.write(data)

        def public_ok(fragmented=False, host='target.funnel.test'):
            c = connect(host, fragmented)
            try:
                return exchange(c, b'netcat-funnel-e2e') == b'netcat-funnel-e2e'
            finally:
                c[0].close()

        def rejected(host='target.funnel.test'):
            try:
                return not public_ok(host=host)
            except OSError:
                return True

        backend = None
        try:
            run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                 '-nodes', '-keyout', d/'ca.key', '-out', d/'ca.pem', '-days', '1',
                 '-subj', '/CN=Headscale Funnel isolated E2E', '-addext', 'basicConstraints=critical,CA:TRUE',
                 '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
            run(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                 '-nodes', '-keyout', d/'leaf.key', '-out', d/'leaf.csr', '-subj', '/CN=target.funnel.test'])
            (d/'extensions').write_text('subjectAltName=IP:127.0.0.1,DNS:target.funnel.test,DNS:renamed.funnel.test\n'
                                       'extendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\n'
                                       'keyUsage=critical,digitalSignature\n')
            run(['openssl', 'x509', '-req', '-in', d/'leaf.csr', '-CA', d/'ca.pem', '-CAkey', d/'ca.key',
                 '-CAcreateserial', '-out', d/'leaf.pem', '-days', '1', '-extfile', d/'extensions'])
            config = f'''server_url: {url}
listen_addr: 127.0.0.1:{port}
metrics_listen_addr: 127.0.0.1:{free_port()}
noise:
  private_key_path: {d}/noise.key
prefixes:
  v4: 100.127.250.0/24
  v6: fd7a:115c:a1e0:ffff::/64
database:
  type: sqlite
  sqlite:
    path: {d}/headscale.db
unix_socket: {d}/hs.sock
unix_socket_permission: "0600"
tls:
  cert_path: {d}/leaf.pem
  key_path: {d}/leaf.key
policy:
  mode: file
  path: {d}/policy.json
derp:
  server:
    enabled: true
    region_id: 999
    region_code: isolated
    region_name: isolated-test
    stun_listen_addr: 127.0.0.1:{free_port()}
    private_key_path: {d}/derp.key
    automatically_add_embedded_derp_region: true
    ipv4: 127.0.0.1
  urls: []
  paths: []
  auto_update_enabled: false
dns:
  funnel:
    enabled: true
    state_dir: {d}/ingress
  magic_dns: true
  base_domain: funnel.test
  override_local_dns: false
  nameservers:
    global: [127.0.0.1]
  certificates:
    enabled: true
    zone: funnel.test
  challenge:
    provider:
      name: rfc2136
      server: 127.0.0.1:9
log:
  level: debug
  format: json
'''
            (d/'config.yaml').write_text(config)
            write_policy()
            check('config_valid', run(hs+['configtest']).returncode == 0)
            identitypath = d/'ingress/identity.json'
            if not args.transport_only:
                funnel_block = f'  funnel:\n    enabled: true\n    state_dir: {d}/ingress\n'
                (d/'config.yaml').write_text(config.replace(funnel_block, '')+
                                            f'\nfunnel:\n  enabled: true\n  state_dir: {d}/ingress\n')
                old = run(hs+['configtest'], check=False)
                check('obsolete_top_level_config_rejected', old.returncode != 0 and
                      'moved under dns' in old.stdout+old.stderr)
                (d/'config.yaml').write_text(config.replace(funnel_block, ''))
                hp = start(hs+['serve'], 'headscale-default-off')
                eventually('default_off_control_tls', control_ok)
                add_client('offprobe')
                check('default_off_creates_no_ingress', not identitypath.exists())
                check('default_off_no_funnel_cap', 'funnel' not in status('offprobe')['Self'].get('CapMap', {}))
                stop(hp)

                # These are real filesystem failures, without bypassing auth or
                # injecting a mock client. The main HTTPS listener must survive.
                badpath = d/'not-a-directory'
                badpath.write_text('fixture')
                corrupt = d/'corrupt-identity'
                corrupt.mkdir()
                (corrupt/'identity.json').write_text('{invalid-json')
                for label, path in [('storage_failure', badpath), ('corrupt_identity', corrupt)]:
                    (d/'config.yaml').write_text(config.replace(f'state_dir: {d}/ingress', f'state_dir: {path}'))
                    logname = 'headscale-'+label
                    hp = start(hs+['serve'], logname)
                    eventually(label+'_failure_logged', lambda: startup_failed(logname))
                    check(label+'_control_tls', control_ok())
                    check(label+'_derp_probe', control_ok('/derp/probe'))
                    check(label+'_funnel_rejected', rejected())
                    check(label+'_no_automatic_identity', not identitypath.exists())
                    if label == 'storage_failure':
                        add_client('faultprobe')
                        check('registration_during_startup_failure', status('faultprobe')['BackendState'] == 'Running')
                        check('derp_handshake_during_startup_failure', derp_handshake('faultprobe'))
                    stop(hp)
                check('corrupt_identity_preserved', (corrupt/'identity.json').read_text() == '{invalid-json')
                (d/'config.yaml').write_text(config)
            hp = start(hs+['serve'], 'headscale')
            eventually('ingress_auto_registered', lambda: identitypath.exists() and hp.poll() is None, 65)
            identity = json.loads(identitypath.read_text())
            check('private_identity_permissions', identitypath.stat().st_mode & 0o777 == 0o600)
            add_client('target')
            domain = 'target.funnel.test'
            check('native_certificate_domain', domain in status('target').get('CertDomains', []))

            class Echo(socketserver.BaseRequestHandler):
                def handle(self):
                    try:
                        with server_context.wrap_socket(self.request, server_side=True) as conn:
                            while data := conn.recv(65536):
                                conn.sendall(data)
                    except OSError as error:
                        print('backend TLS: '+str(error), flush=True)

            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(d/'leaf.pem', d/'leaf.key')
            backend = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Echo)
            backend.daemon_threads = True
            threading.Thread(target=backend.serve_forever, daemon=True).start()
            with ssl.create_default_context(cafile=str(d/'ca.pem')).wrap_socket(
                    socket.create_connection(backend.server_address), server_hostname=domain) as direct:
                direct.sendall(b'fixture')
                check('backend_tls_fixture', direct.recv(1024) == b'fixture')
            publish = ['funnel', '--bg', '--yes', '--tcp='+str(port),
                       'tcp://127.0.0.1:'+str(backend.server_address[1])]
            check('closed_funnel_rejected', rejected())
            run(client('target')+publish)
            eventually('native_funnel_tls_passthrough_no_network_grants', public_ok)
            check('fragmented_client_hello_preserved', public_ok(fragmented=True))
            check('unknown_sni_rejected', rejected('unknown.funnel.test'))
            # A normal control request and DERP probe share exactly the same socket.
            for path, label in [('/health', 'control_tls_shared_port'), ('/derp/probe', 'derp_probe_shared_port')]:
                response = run(['curl', '-fsS', '--cacert', d/'ca.pem', url+path])
                check(label, response.returncode == 0)
            if args.transport_only:
                check('transport_completed', True)
                return
            netmap = json.loads(run(client('target')+['debug', 'netmap']).stdout)
            entry = next(p for p in netmap['Peers'] if p['ID'] == identity['node_id'])
            check('ingress_peer_api_only', entry.get('UnsignedPeerAPIOnly') is True)
            check('ingress_has_no_routes', entry['AllowedIPs'] == entry['Addresses'])
            check('no_ordinary_network_grants', not any(r.get('Dsts') for r in netmap.get('PacketFilter', [])))
            targetid = next(n['id'] for n in nodes() if n.get('givenName') == 'target')

            outsider_socks = add_client('outsider')
            # Same claimable tag must never turn an ordinary node into an ingress.
            add_client('spoof', 'tag:headscale-funnel')
            write_policy(wildcard=True)
            hp.send_signal(signal.SIGHUP)
            eventually('wildcard_acl_does_not_break_ingress_filter', public_ok)
            targetstatus = status('target')
            endpoint = targetstatus['Self']['PeerAPIURL'][0]

            def unauthorized():
                result = run(['curl', '-sS', '--max-time', '5', '--socks5', f'127.0.0.1:{outsider_socks}',
                              '--noproxy', '', '-o', '/dev/null', '-w', '%{http_code}', '-X', 'POST',
                              '-H', 'Tailscale-Ingress-Src: 127.0.0.1:1234',
                              '-H', f'Tailscale-Ingress-Target: {domain}:{port}', endpoint+'/v0/ingress'], check=False)
                return result.returncode == 0 and result.stdout == '403'

            eventually('ordinary_authenticated_peer_cannot_ingress', unauthorized)
            netmap = json.loads(run(client('target')+['debug', 'netmap']).stdout)
            entry = next(p for p in netmap['Peers'] if p['ID'] == identity['node_id'])
            entryips = [ipaddress.ip_interface(x).ip for x in entry['Addresses']]
            rules = netmap.get('PacketFilter', [])
            check('wildcard_rules_exclude_ingress_source', all(
                not any(ip in ipaddress.ip_network(src, strict=False) for ip in entryips)
                for r in rules if r.get('Dsts') for src in r.get('Srcs', [])))
            spoof = next(n for n in nodes() if n.get('givenName') == 'spoof')
            spoofpeer = next(p for p in netmap['Peers'] if p['ID'] == int(spoof['id']))
            check('tag_spoof_does_not_gain_ingress_identity', not spoofpeer.get('UnsignedPeerAPIOnly', False))

            stream = connect()
            check('active_stream_before_revoke', exchange(stream, b'before') == b'before')
            write_policy(funnel=False, wildcard=True)
            hp.send_signal(signal.SIGHUP)
            eventually('policy_revoke_stops_new_connections', rejected)
            def stream_closed():
                try:
                    return exchange(stream, b'after') == b''
                except OSError:
                    return True
            eventually('policy_revoke_closes_active_stream', stream_closed)
            stream[0].close()
            write_policy()
            hp.send_signal(signal.SIGHUP)
            eventually('policy_restore', public_ok)
            run(client('target')+['funnel', 'reset'])
            eventually('local_funnel_reset_rejected', rejected)
            run(client('target')+publish)
            eventually('local_funnel_reenabled', public_ok)

            stop(hp)
            hp = start(hs+['serve'], 'headscale-restart')
            eventually('restart_preserves_identity', lambda: hp.poll() is None and public_ok(), 65)
            check('identity_unchanged', json.loads(identitypath.read_text()) == identity)
            check('single_managed_identity', sum('tag:headscale-funnel' in n.get('tags', [])
                                               and int(n['id']) == identity['node_id'] for n in nodes()) == 1)
            run(hs+['nodes', 'rename', '--identifier', str(targetid), 'renamed'])
            eventually('rename_retires_old_domain', rejected)
            eventually('client_observes_renamed_domain', lambda:
                       status('target')['Self']['DNSName'] == 'renamed.funnel.test.')
            run(client('target')+['funnel', 'reset'])
            run(client('target')+publish)
            eventually('renamed_native_funnel', lambda: public_ok(host='renamed.funnel.test'))

            # A persisted identity that was administratively deleted must not
            # prevent the next Headscale startup or be silently recreated.
            run(hs+['nodes', 'delete', '--identifier', str(identity['node_id']), '--force'])
            remaining = len(nodes())
            stop(hp)
            hp = start(hs+['serve'], 'headscale-revoked-restart')
            eventually('revoked_identity_startup_keeps_headscale', lambda: startup_failed('headscale-revoked-restart'))
            check('revoked_identity_startup_control_tls', control_ok())
            check('revoked_identity_startup_derp_probe', control_ok('/derp/probe'))
            check('revoked_identity_not_recreated', len(nodes()) == remaining)
            check('revoked_identity_metadata_preserved', json.loads(identitypath.read_text()) == identity)
            run(hs+['nodes', 'delete', '--identifier', str(targetid), '--force'])
            eventually('deleted_target_rejected', lambda: rejected('renamed.funnel.test'))
            check('completed', True)
        except BaseException as error:
            report['error'] = type(error).__name__
            # Logs are shown locally only; they are never included in artifacts.
            for name, log in logs:
                log.flush()
                log.seek(0)
                print('\n'+name+' last logs:\n'+log.read()[-9000:], flush=True)
            raise
        finally:
            for process in reversed(processes):
                try:
                    stop(process)
                except RuntimeError as error:
                    report['cleanup_error'] = str(error)
            if backend:
                backend.shutdown()
                backend.server_close()
            for _, log in logs:
                log.close()
            report['cleanup'] = all(p.poll() is not None for p in processes)
            report['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
