# Embedded Funnel

Funnel exposes an explicitly authorized node service to public TLS clients.
It is disabled by default and uses Headscale's existing TLS listener (usually
443). It does not require a gateway process or changes to Tailscale clients.

## Setup

Headscale must terminate its own control-plane TLS. The same listener's TCP
connections are classified by ClientHello SNI before TLS termination. The
`server_url` port must equal `listen_addr`'s port. A TLS-terminating reverse
proxy in front cannot carry the original application TLS through this module.

1. Configure MagicDNS and [node certificates](tls.md), including a DNS-01
   provider. Use a public `dns.base_domain` you control.
2. Point public DNS for the published node names (or a wildcard under the base
   domain) at the Headscale ingress address. This module does not change public
   A/AAAA records. Keep the control-plane hostname separate from node names.
3. Enable the module and persist its directory alongside the database:

   ```yaml
   dns:
     # Alongside base_domain, certificates and challenge:
     funnel:
       enabled: true
       state_dir: /var/lib/headscale/funnel
   ```

4. Authorize selected nodes in policy, for example:

   ```json
   {
     "nodeAttrs": [{"target": ["tag:publish"], "attr": ["funnel"]}]
   }
   ```

5. On an authorized node run `tailscale funnel --bg 3000`. The native client
   obtains its certificate and enables local Serve/Funnel. Use the port of the
   shared listener with `--https` if it differs from 443. To disable publication,
   run `tailscale funnel reset` or remove its policy authorization.

No ordinary node-to-node port grant is required for ingress. Application login
and authorization still apply to the now public service.

## Identity and transport

At first startup, Headscale creates a short-lived, single-use tagged bootstrap
key and starts an embedded userspace `tsnet` node. The key is revoked after
bootstrap. Its state and a node-ID/machine-public-key binding are stored in the
private state directory; subsequent starts reuse and verify that identity.
The tag `tag:headscale-funnel` is informational: claiming the same tag or
hostname never grants ingress authority. No human user is created.

The managed node is distributed only to policy-authorized targets, with
`UnsignedPeerAPIOnly` and host addresses only. All user-defined network and app
rules exclude its source addresses, including wildcard grants. Targets receive
only the `tailscale.com/cap/ingress` grant from this identity; the ingress gets
only the authorized peers and no ordinary packet permissions.

For each accepted public connection, Headscale finds the exact authorized node
name and its advertised PeerAPI endpoint. The ingress sends authenticated
`POST /v0/ingress` over the tailnet with the public source and requested
host:port. The target verifies ingress capability and its local `AllowFunnel`.
After HTTP 101, both directions carry the original TLS bytes on that same
connection. TLS terminates at the target, and Headscale does not need or receive
the target's certificate private key. WireGuard/DERP transport is unchanged.

Unknown names are rejected. Control-host SNI (and no SNI) continues to the
existing TLS/HTTP server, preserving the control API, embedded DERP and ACME.
Ingress admission requires both policy authorization and the client's
publication hint; the target's local Funnel check remains final. Active public
flows are revalidated every second and closed on revocation, rename, expiry or
deletion. ClientHello and PeerAPI handshakes have bounded sizes/timeouts, and
the shared listener bounds concurrent connections.

Funnel initialization runs asynchronously after control HTTP is listening.
Identity storage errors, invalid persisted metadata and registration failures
leave Funnel unavailable while the shared listener, control connections and DERP
keep serving. The failed embedded client is closed; no public forwarding is
admitted and Funnel capabilities are withheld until initialization succeeds.
The error is logged as `Funnel unavailable`; `/health` continues to represent the
control plane, not Funnel readiness. Repair the cause and restart to recover:
there is no background health monitor, automatic retry or replacement of a revoked identity.

A malformed configuration or a broken main TLS listener is still a server
configuration error. Degradation isolates handled Funnel operational failures;
a fatal process crash or resource exhaustion requires process-level isolation.
The obsolete top-level `funnel` settings are rejected with a migration hint.

If the managed node is deleted, replaced or expired, Funnel remains unavailable
instead of silently registering it again. Restore the matching database and
state directory together. To intentionally provision a replacement, stop
Headscale and explicitly archive/reset the Funnel state directory first. An
interrupted first bootstrap without identity metadata also requires explicit
recovery; do not automatically discard the directory. Do not share this
identity directory between concurrent Headscale instances.

## Reproducible end-to-end acceptance

Local acceptance status (2026-11-05): all 64 checks passed on Linux/arm64 in
Apple Container using literal port 443. Startup-failure checks cover an
unusable identity directory, corrupt metadata and a revoked persisted identity:
Headscale keeps serving, native nodes can register, and the IPv4 DERP TLS/upgrade
handshake succeeds. The DNS-scoped switch defaults off and obsolete top-level
settings are rejected. This includes native TLS passthrough
under deny-all network policy, wildcard source exclusion, unauthorized ingress
rejection, tag spoofing, active-flow revocation, local disable, identity
persistence, rename/republication and deletion. The first failed TLS check was
caused by the temporary CA missing its required key-usage extension; the fixture
now validates a direct TLS connection before testing Funnel. Public DNS and real
ACME issuance were not exercised, and this is not production acceptance.

The opt-in harness starts real Headscale and native Tailscale processes with
disposable state, a temporary CA and a TLS echo application. Raw TCP Funnel mode
tests TLS preservation without contacting a public ACME CA or mutating DNS.
It exercises control TLS and DERP on the same listener, deny-all network policy,
wildcard ACL exclusion, unauthorized peers, tag spoofing, local disable,
revocation, active-flow closure, rename, deletion and identity persistence.
It is separate from the Docker integration suite and writes a redacted JSON
artifact containing checks, timestamps and binary SHA-256 hashes.
The full run includes startup-failure checks; `--transport-only` focuses on TLS
passthrough and shared-listener checks. DERP diagnostics validate IPv4 in this
loopback fixture; IPv6 is not configured.

Build on the workstation from this checkout's dependency pins:

```sh
mkdir -p /tmp/headscale-funnel-bin
go build -o /tmp/headscale-funnel-bin/headscale ./cmd/headscale
go build -o /tmp/headscale-funnel-bin/tailscale tailscale.com/cmd/tailscale
go build -o /tmp/headscale-funnel-bin/tailscaled tailscale.com/cmd/tailscaled
sudo python3 integration/funnel_native.py --bin-dir /tmp/headscale-funnel-bin --output /tmp/funnel-report.json
```

To validate literal port 443 in Apple Container, cross-compile these binaries
with `CGO_ENABLED=0 GOOS=linux GOARCH=arm64`. Mount the binary directory at
`/bins`, this checkout's `integration` directory at `/harness` (both read-only),
and an artifact directory at `/artifacts` in a disposable Linux container with
Python 3.11+, OpenSSL and curl. Run:

```sh
container exec headscale-funnel-e2e python3 /harness/funnel_native.py \
  --bin-dir /bins --listen-port 443 --output /artifacts/report.json
```

The pinned native client's enablement flow checks Funnel access on port 443,
even when a different TCP forwarding port is requested. This harness therefore
defaults to literal port 443, including in GitHub Actions, rather than a random
high port. The container is the recommended way to isolate that privileged bind.

The harness does not alter the workstation's Tailscale daemon. Its local CA and
credentials are never exported. Public DNS and real CA issuance need separate
deployment acceptance; this harness verifies the Funnel transport and policy.

## Failure cases to cover before implementation

- An unwritable identity directory, corrupt identity metadata or failed embedded
  client startup must disable only Funnel, preserving control TLS, registration,
  policy updates and embedded DERP.
- A revoked identity on disk must leave Headscale available on restart without
  silently creating a replacement identity.
- Shutdown during asynchronous bootstrap must cancel it before state is closed.
- The DNS-scoped switch must default off; obsolete top-level settings must fail
  configuration validation instead of silently changing their meaning.
- Unknown, missing or malformed SNI must never select an arbitrary upstream.
- Reading a fragmented ClientHello must preserve every byte for the target.
- Sharing a listener must preserve control-plane TLS, ACME and embedded DERP.
- The managed ingress must survive restart without acquiring a new identity.
- A tag or hostname claimed by another node must not grant ingress authority.
- The managed peer must be excluded from ordinary network rules, including wildcard sources.
- A target without policy authorization, an expired target, and a closed local Funnel must reject traffic.
- Policy revocation, rename and deletion must stop admission and retire active forwarding.
- Slow handshakes, oversized headers and connection floods must have bounds.
- Shutdown must release listeners, the embedded client and active connections.
- End-to-end artifacts must contain no private keys, auth keys or database copies.

The acceptance harness uses disposable state and real Tailscale clients. It must
not change the workstation's existing Tailscale daemon or production DNS.
