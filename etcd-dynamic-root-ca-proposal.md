# Proposal: Dynamic Trust Root Reloading for `transport.TLSInfo`

Status: draft

Target: upstream etcd

Scope: `go.etcd.io/etcd/client/pkg/v3/transport`

## Summary

etcd already reloads certificate and key material for new TLS handshakes when
`transport.TLSInfo` is configured with file-backed credentials. It does **not**
reload trust roots dynamically. `ServerConfig()` and `ClientConfig()` build
static `ClientCAs` and `RootCAs` pools once, and those pools remain fixed for
the lifetime of the listener or transport.

This proposal adds an **optional dynamic trust-root hook** to
`transport.TLSInfo` so future handshakes validate peers against the current
trust bundle without restarting the etcd process. Existing connections remain
untouched.

This is useful for environments where trust anchors rotate under stable file
paths or come from a live source such as SPIFFE/SPIRE, cert-manager, Vault PKI,
or other dynamic certificate systems.

Recommended upstream sequencing:

1. land a **generic transport hook** for dynamic trust roots
2. optionally land a **file-backed adapter** on top of that hook

This proposal is deliberately about step 1.

## Why this is needed

Today, these two methods freeze the CA pool:

- `transport.TLSInfo.ServerConfig()` builds `cfg.ClientCAs`
- `transport.TLSInfo.ClientConfig()` builds `cfg.RootCAs`

At the same time, `transport.TLSInfo.baseConfig()` already installs dynamic
cert/key callbacks:

- `GetCertificate`
- `GetClientCertificate`

That means etcd currently has an asymmetric behavior:

- leaf cert and private key can change and be picked up on future handshakes
- trust roots cannot change without rebuilding the listener or transport

The result is a common failure mode:

1. trust anchors rotate under the same file path
2. a peer or client later presents a certificate chaining to the new root
3. a fresh handshake fails because the verifier is still using the old CA pool
4. the only recovery is restarting etcd or the affected transport owner

This affects both:

- embedded etcd
- standalone `etcd`, which also routes through the same transport package

## Current behavior

The current file-backed behavior is:

- server-side:
  - new handshakes re-read the current certificate/key
  - client certificate verification still uses the `ClientCAs` pool created
    when `ServerConfig()` was called
- client-side:
  - new handshakes re-read the current client certificate/key
  - server certificate verification still uses the `RootCAs` pool created when
    `ClientConfig()` was called

Important non-goal:

- do **not** renegotiate or invalidate already-established TLS sessions

Desired behavior:

- existing connections continue as-is
- new TLS material is only enforced on new handshakes

## Proposed API

Add a **generic trust-root provider** to `transport.TLSInfo`.

The key point is that the transport layer should depend on a source of current
trust roots, not on a particular implementation such as a polling file watcher.

Preferred shape:

```go
type CertPoolProvider interface {
	GetCertPool() *x509.CertPool
}

func (info *TLSInfo) SetDynamicTrustRoots(provider CertPoolProvider)
```

with an unexported field inside `TLSInfo`.

Why prefer a setter and unexported storage over a public function field:

- keeps `TLSInfo`'s public data shape simpler
- avoids baking a file-oriented helper into the transport contract
- avoids awkward serialization/config concerns around public func/interface
  fields on a widely used config struct
- still allows embedders to plug in arbitrary live sources

Properties:

- backward-compatible
- generic
- narrow
- solves the actual problem directly
- lets file-backed reloaders be one adapter rather than the transport API itself

## Proposed behavior

### Server side

When no dynamic trust-root provider is configured:

- preserve current upstream behavior exactly

When a dynamic trust-root provider is configured:

- keep existing dynamic `GetCertificate` / `GetClientCertificate` behavior
- install `GetConfigForClient` so each new incoming handshake sees a fresh
  `*tls.Config` with the current `ClientCAs`
- preserve existing `ClientAuth`, TLS version, cipher, and allowed CN/hostname
  settings

Implementation note:

- the callback should start from a prepared base config and clone that config
  for the specific connection
- it should not rebuild TLS policy ad hoc, because that risks drifting from the
  rest of `TLSInfo.ServerConfig()` behavior

Intended effect:

- future incoming handshakes validate client certs against the current trust
  roots
- existing live TLS sessions are unchanged

### Client side

When no dynamic trust-root provider is configured:

- preserve current upstream behavior exactly

When a dynamic trust-root provider is configured:

- keep existing dynamic cert/key callback behavior from `baseConfig()`
- replace static `RootCAs` verification with a mechanism that guarantees each
  **new outgoing handshake** uses the current trust roots
- preserve existing `ServerName` and hostname verification behavior

Important requirement:

- the behavior must hold for the `TLSInfo` client contract itself, not only for
  one convenience helper
- a change limited to `NewTransport()` is too narrow if callers using
  `TLSInfo.ClientConfig()` directly still get frozen roots

Intended effect:

- future outgoing handshakes validate servers against the current trust roots
- existing live TLS sessions are unchanged

## Why this belongs in `client/pkg/v3/transport`

This is the shared seam used by all of the affected paths:

- embedded etcd client listeners
- embedded etcd peer listeners
- outgoing raft peer transports
- standalone `etcd`, which still goes through `embed.StartEtcd`
- ordinary etcd clients using the same transport package

Fixing this at the transport layer avoids:

- process restarts purely for trust-root rotation
- ad hoc listener mutation or unsafe reflection
- duplicated downstream shims around specific etcd subsystems

## Implementation sketch

Primary file:

- `client/pkg/transport/listener.go`

Expected changes:

1. Add generic dynamic trust-root support to `TLSInfo`
2. Update `ServerConfig()` to install a per-handshake config path when the
   callback is set
3. Update `ClientConfig()` to install a per-handshake verification path when
   the callback is set
4. Keep all existing behavior unchanged when the callback is nil

No changes should be required to:

- `server/v3/embed`
- `server/v3/etcdserver`
- `client/v3`

Note:

- patching `ClientConfig()` directly is important
- patching only `NewTransport()` is too narrow, because callers may use
  `TLSInfo.ClientConfig()` directly outside that helper
- landing the generic transport API does not require `embed` wiring in the same
  PR
- follow-up integration work may wire the generic hook into `embed.Config`
  and CLI flags, but that is a separate concern

## Before/after behavior

### Before

- `CertFile`/`KeyFile` changes are observed on future handshakes
- trust-root changes are not observed until the listener or transport is
  rebuilt

### After

- `CertFile`/`KeyFile` changes are observed on future handshakes
- trust-root changes are also observed on future handshakes
- already-open connections remain valid until they reconnect or are otherwise
  closed

## Tests to include

### Unit tests in `client/pkg/v3/transport`

1. `TestServerConfig_DynamicRootCAsAcceptsNewClientCAOnNewHandshake`
   - start a TLS server from `TLSInfo.ServerConfig()`
   - trust `CA1`, connect with client cert under `CA1`, succeed
   - rotate dynamic roots to `CA2`
   - connect with client cert under `CA2`, succeed without rebuilding server

2. `TestClientConfig_DynamicRootCAsAcceptsNewServerCAOnNewHandshake`
   - build client config from `TLSInfo.ClientConfig()`
   - connect to server cert under `CA1`, succeed
   - rotate dynamic roots to `CA2`
   - connect to server cert under `CA2`, succeed without rebuilding client

3. `TestDynamicRootCAs_DoesNotBreakExistingConnection`
   - establish a TLS connection under `CA1`
   - rotate roots to `CA2`
   - verify the already-established connection remains usable
   - verify a **new** handshake reflects the new trust roots

4. `TestDynamicRootCAs_NilPreservesExistingBehavior`
   - prove no behavior change when the callback is unset

5. `TestDynamicRootCAs_PreservesHostnameVerification`
   - ensure the dynamic client path still enforces `ServerName`/hostname rules

### Integration tests

1. Embedded etcd client-port rotation test
   - start embedded etcd with mTLS on the client port
   - rotate trust roots and leaf material under stable paths
   - verify a fresh client handshake succeeds without restarting etcd

2. Peer reconnect / HA rotation test
   - start a two-member cluster
   - rotate peer trust roots and peer leaf material
   - force at least one fresh peer reconnection
   - verify raft peer traffic resumes without restarting members

The second test is the key proof that the transport-layer change also fixes the
outgoing raft transport path.

### Follow-up adapter tests

If a follow-up PR adds a file-backed adapter and `embed`/CLI wiring, add:

1. standalone `etcd` coverage for operator-facing configuration
2. file-rotation coverage proving fresh handshakes pick up new roots
3. observability coverage for reload success/failure metrics or logs introduced
   by that adapter

## Optional follow-up adapter

After the generic transport hook lands, an optional follow-up PR can add a
file-backed implementation, for example a polling CA reloader in `tlsutil`.

That second PR can:

- add a helper that watches CA files and exposes `GetCertPool()`
- wire it into `embed.Config` / CLI flags as an opt-in convenience layer
- keep file-polling policy out of the transport contract itself

This split gives a cleaner layering:

- transport PR: generic capability
- helper PR: one concrete adapter for file-based users

Observability note:

- the generic transport hook does not need to prescribe polling or metrics
- a file-backed adapter may reasonably include reload success/failure/duration
  metrics and operational logs

## Manual reproduction

### Reproducing the bug before the change

Single-node embedded reproduction:

1. Start embedded etcd with:
   - HTTPS client listener
   - `ClientCertAuth=true`
   - `CertFile`, `KeyFile`, and `TrustedCAFile` under stable file paths
2. Create `CA1`, `server leaf 1`, and `client leaf 1`
3. Put `server leaf 1` and `CA1` under the configured file paths
4. Connect with `client leaf 1` chaining to `CA1` and verify success
5. Replace the files with:
   - `CA2`
   - `server leaf 2`
   - `client leaf 2`
6. Open a **fresh** client connection using `client leaf 2`
7. Observe handshake failure:
   - typically `x509: certificate signed by unknown authority`

Why it fails:

- the listener reloads the new server certificate
- the listener still verifies the client certificate against the old
  `ClientCAs` pool

### Reproducing the fix after the change

Repeat the same steps with `DynamicRootCAs` enabled and backed by the current
roots:

1. Start embedded etcd with the same stable file paths
2. Enable `DynamicRootCAs`
3. Connect once under `CA1`
4. Rotate to `CA2` under the same paths
5. Open a **fresh** client connection under `CA2`
6. Observe success without restarting etcd

Expected result:

- the new connection succeeds
- any already-established TLS session remains unaffected until it reconnects

## Compatibility and risk

Compatibility expectations:

- nil callback preserves existing behavior
- current users of `TLSInfo` are unaffected unless they opt in

Main risks:

1. incorrect interaction with existing CN/hostname validation logic
2. accidentally changing behavior for callers that do not opt in
3. missing a code path that still snapshots trust roots elsewhere

The proposed unit and integration tests are intended to cover those risks.

## Relation to current upstream work

There is already prior art in flight around file-backed CA reload.

That work is directionally aligned with this proposal, but this document argues
for a slightly different layering:

- the transport API should accept a generic dynamic trust-root source
- a polling CA reloader should be an optional adapter on top of that API

It also argues for a slightly different completeness boundary:

- the client-side behavior should satisfy the full `TLSInfo` client contract
- not only the specific `NewTransport()` helper path

That allows both classes of users:

- file-backed operators
- embedders with live trust sources such as SPIFFE/SPIRE

## Why this is preferable to downstream workarounds

Compared to downstream restart-based or proxy-based approaches, this proposal:

- fixes the issue at the shared transport seam
- benefits both embedded and standalone etcd
- matches the existing cert/key reload model
- avoids process restarts for trust-root rotation
- keeps existing live connections stable

## Recommendation

Implement generic dynamic trust-root support in
`client/pkg/v3/transport.TLSInfo` and cover it with transport-level unit tests
plus embedded/HA integration tests.

Then, if desired, add a second PR with a file-backed CA reloader that plugs
into that generic transport hook.

This is the smallest coherent upstream change that makes trust-root rotation
behave like certificate/key rotation already does today: future handshakes pick
up new material; existing sessions stay as they are.
