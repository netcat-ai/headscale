#!/usr/bin/env python3
"""Exercise published containers with synthetic PostgreSQL data; no production access."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.request

OLD = 'ghcr.io/juanfont/headscale@sha256:641742f2c95d199231aa1de79f7bd964b17b86b34aef11cc6d0f61a0014e6b66'
IMAGE = os.environ['CANDIDATE_IMAGE']
ARCH = os.environ['EXPECTED_ARCH']
REVISION = os.environ['EXPECTED_REVISION']
REPORT = {'image': IMAGE, 'old_image': OLD, 'architecture': ARCH,
          'revision': REVISION, 'synthetic_data_only': True, 'checks': {}}
PREFIX = 'netcat-verify-' + secrets.token_hex(4)
CONTAINERS = []
ENTRIES = {}


def run(args, *, data=None, check=True):
    p = subprocess.run(list(map(str, args)), input=data, capture_output=True, timeout=180)
    if check and p.returncode:
        raise RuntimeError(str(args[0]) + ': ' + p.stderr.decode(errors='replace')[-1800:])
    return p


def docker(*args, **kwargs):
    return run(['docker', *args], **kwargs).stdout.decode().strip()


def check(name, value):
    REPORT['checks'][name] = bool(value)
    print(name + ': ' + ('PASS' if value else 'FAIL'), flush=True)
    if not value:
        raise RuntimeError(name)


def sql(query):
    return docker('exec', PREFIX+'-db', 'psql', '-X', '-U', 'netcat', '-d', 'headscale',
                  '-At', '-v', 'ON_ERROR_STOP=1', '-c', query)


def snapshot():
    tables = sql("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename").splitlines()
    return {t: json.loads(sql(f"SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]'::jsonb) FROM {t} t")) for t in tables}


def sequences():
    return json.loads(sql("SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY sequencename),'[]'::jsonb) FROM pg_sequences s WHERE schemaname='public'"))


def cli(name, *args):
    return docker('exec', name, *ENTRIES[name], '--config', '/config/config.yaml', *args)


def start(image, name, directory):
    name = PREFIX+'-'+name
    entry = json.loads(docker('image', 'inspect', image))[0]['Config']['Entrypoint']
    ENTRIES[name] = entry
    CONTAINERS.append(name)
    docker('run', '-d', '--name', name, '--network', PREFIX, '-p', '127.0.0.1::8080',
           '-v', str(directory)+':/config:ro', '--tmpfs', '/state:rw,mode=1777',
           image, '--config', '/config/config.yaml', 'serve')
    for _ in range(90):
        r = run(['docker', 'exec', name, *entry, '--config', '/config/config.yaml',
                 'users', 'list', '-o', 'json'], check=False)
        if r.returncode == 0:
            return name
        if docker('inspect', '-f', '{{.State.Running}}', name) != 'true':
            logs = run(['docker', 'logs', '--tail', '25', name], check=False)
            raise RuntimeError('Server exited: '+(logs.stdout+logs.stderr).decode(errors='replace'))
        time.sleep(1)
    raise RuntimeError('Server readiness timed out: '+name)


def stop(name):
    docker('stop', '--time', '20', name)
    docker('rm', name)
    CONTAINERS.remove(name)


def api_users(name, key):
    binding = docker('port', name, '8080/tcp')
    req = urllib.request.Request('http://'+binding+'/api/v1/user', headers={'Authorization': 'Bearer '+key})
    with urllib.request.urlopen(req, timeout=10) as response:
        return response.status == 200 and len(json.load(response)['users']) == 1


def main():
    try:
        docker('pull', IMAGE)
        docker('pull', OLD)
        docker('pull', 'postgres:18.6')
        info = json.loads(docker('image', 'inspect', IMAGE))[0]
        check('native_platform', info['Architecture'] == ARCH and info['Os'] == 'linux')
        check('revision_label', info['Config']['Labels']['org.opencontainers.image.revision'] == REVISION)
        version = docker('run', '--rm', '--network', 'none', IMAGE, 'version')
        REPORT['version'] = version
        check('clean_build_version', '+dirty' not in version and REVISION in version)
        REPORT['postgres_image'] = json.loads(docker('image', 'inspect', 'postgres:18.6'))[0]['RepoDigests']
        docker('network', 'create', '--internal', PREFIX)
        CONTAINERS.append(PREFIX+'-db')
        docker('run', '-d', '--name', PREFIX+'-db', '--network', PREFIX, '--network-alias', 'db',
               '-e', 'POSTGRES_USER=netcat', '-e', 'POSTGRES_DB=headscale',
               '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '--tmpfs', '/var/lib/postgresql:rw', 'postgres:18.6')
        for _ in range(60):
            p = run(['docker', 'exec', PREFIX+'-db', 'pg_isready', '-U', 'netcat'], check=False)
            if p.returncode == 0:
                break
            time.sleep(1)
        with tempfile.TemporaryDirectory(prefix=PREFIX) as tmp:
            root = Path(tmp)
            old = root/'old'; old.mkdir()
            config = '''server_url: http://127.0.0.1:8080
disable_check_updates: true
listen_addr: 0.0.0.0:8080
grpc_listen_addr: 127.0.0.1:50443
metrics_listen_addr: 127.0.0.1:9090
noise:
  private_key_path: /state/noise.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
database:
  type: postgres
  postgres:
    host: db
    port: 5432
    name: headscale
    user: netcat
    pass: ""
    ssl: false
unix_socket: /state/headscale.sock
unix_socket_permission: "0600"
derp:
  urls: []
  paths: [/config/derp.yaml]
  auto_update_enabled: false
dns:
  magic_dns: true
  base_domain: example.test
  override_local_dns: false
  nameservers:
    global: [192.0.2.53]
policy:
  mode: file
  path: /config/policy.hujson
log:
  level: info
  format: json
'''
            (old/'config.yaml').write_text(config)
            (old/'policy.hujson').write_text(json.dumps({'tagOwners': {'tag:server': ['ci@']}, 'acls': [{'action': 'accept', 'src': ['*'], 'dst': ['*:*']}]}))
            (old/'derp.yaml').write_text('regions:\n  999:\n    regionid: 999\n    regioncode: isolated\n    regionname: isolated\n    nodes:\n      - name: isolated\n        regionid: 999\n        hostname: 127.0.0.1\n        ipv4: 127.0.0.1\n        derpport: 9\n')
            new = root/'new'; new.mkdir()
            for f in old.iterdir():
                (new/f.name).write_bytes(f.read_bytes())
            (new/'config.yaml').write_text(config.replace('  magic_dns: true', '''  certificates:
    enabled: true
    zone: example.test
  challenge:
    provider:
      name: tencentcloud
      secret_id: ci-placeholder
      secret_key: ci-placeholder
      min_ttl: 600
  magic_dns: true'''))
            server = start(OLD, 'old', old)
            user = json.loads(cli(server, 'users', 'create', 'ci', '-o', 'json'))
            auth = json.loads(cli(server, 'preauthkeys', 'create', '--user', str(user['id']), '--expiration', '24h', '--reusable', '-o', 'json'))
            api_key = json.loads(cli(server, 'apikeys', 'create', '--expiration', '24h', '-o', 'json'))
            for name in ['user-node', 'tag-node']:
                rid = 'hskey-authreq-'+secrets.token_hex(12)
                cli(server, 'debug', 'create-node', '--user', 'ci', '--name', name, '--key', rid, '--route', '192.0.2.0/24')
                cli(server, 'auth', 'register', '--user', 'ci', '--auth-id', rid)
            nodes = json.loads(cli(server, 'nodes', 'list', '-o', 'json'))
            for node in nodes:
                cli(server, 'nodes', 'approve-routes', '--identifier', str(node['id']), '--routes', '192.0.2.0/24')
            check('old_api_key_authenticates', api_users(server, api_key))
            stop(server)
            sql(f"UPDATE nodes SET auth_key_id={int(auth['id'])}; UPDATE nodes SET tags='[\"tag:server\"]',user_id=NULL,expiry=NULL WHERE hostname='tag-node'")
            before = snapshot(); seq_before = sequences()
            backup = run(['docker', 'exec', PREFIX+'-db', 'pg_dump', '-U', 'netcat', '-d', 'headscale', '-Fc']).stdout
            REPORT['snapshot_sha256'] = hashlib.sha256(backup).hexdigest()
            server = start(IMAGE, 'candidate', new)
            check('tencentcloud_provider_config', True)
            after = snapshot()
            check('nodes_users_routes_tags_preserved', all(before[t] == after[t] for t in ['nodes', 'users', 'policies']))
            check('legacy_credential_tables_removed', all(t not in after for t in ['api_keys', 'pre_auth_keys', 'oauth_clients', 'oauth_access_tokens']))
            check('credential_counts', len(after['credentials']) == 2)
            ck = next(x for x in after['credentials'] if x['kind'] == 'authkey')
            ak = before['pre_auth_keys'][0]
            check('authkey_identity_and_hash_preserved', ck['id'] == ak['id'] and ck['hash'] == ak['hash'] and ck['identifier'] == ak['prefix'])
            check('node_authkey_foreign_key_valid', sql("SELECT count(*) FROM nodes n LEFT JOIN credentials c ON n.auth_key_id=c.id WHERE c.id IS NULL OR c.kind!='authkey'") == '0')
            check('candidate_node_listing', len(json.loads(cli(server, 'nodes', 'list', '-o', 'json'))) == 2)
            stop(server)
            server = start(IMAGE, 'candidate-again', new)
            check('second_start_idempotent', snapshot() == after)
            check('old_api_key_works_after_upgrade', api_users(server, api_key))
            stop(server)
            docker('exec', PREFIX+'-db', 'dropdb', '-U', 'netcat', 'headscale')
            docker('exec', PREFIX+'-db', 'createdb', '-U', 'netcat', 'headscale')
            run(['docker', 'exec', '-i', PREFIX+'-db', 'pg_restore', '-U', 'netcat', '-d', 'headscale',
                 '--exit-on-error', '--single-transaction', '--no-owner', '--no-privileges'], data=backup)
            check('restored_tables_and_sequences_exact', snapshot() == before and sequences() == seq_before)
            server = start(OLD, 'rollback', old)
            check('old_image_starts_after_restore', len(json.loads(cli(server, 'nodes', 'list', '-o', 'json'))) == 2)
            check('old_api_key_works_after_restore', api_users(server, api_key))
            stop(server)
    except Exception as error:
        REPORT['error'] = str(error)
        print('Verification failed:', str(error), flush=True)
    finally:
        for name in reversed(CONTAINERS):
            run(['docker', 'rm', '-f', '-v', name], check=False)
        run(['docker', 'network', 'rm', PREFIX], check=False)
        REPORT['cleanup'] = not docker('ps', '-aq', '--filter', 'name='+PREFIX)
        Path('image-verification.json').write_text(json.dumps(REPORT, indent=2)+'\n')
    return 1 if REPORT.get('error') or not REPORT['cleanup'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
