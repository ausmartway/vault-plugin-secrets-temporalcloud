# vault-plugin-secrets-temporalcloud

A HashiCorp Vault secrets engine that turns Temporal Cloud API keys into Vault
dynamic secrets. It provisions Temporal Cloud service accounts, mints API keys
bound to Vault leases, and deletes each key the moment its lease ends.

This document is for the Vault administrator who installs, configures, and
operates the mount. For changing the plugin itself, see
[CONTRIBUTING.md](CONTRIBUTING.md).

Every path in this document is exercised against a real Temporal Cloud account
by a live acceptance suite, not against mocks alone.

## Why run this

Temporal Cloud API keys are static credentials with a few sharp edges:

- The token is shown **once**, at creation. Lose it and your only option is to
  delete the key and mint another.
- Every key **must** expire, with a maximum lifetime of two years. Nothing is
  permanent, so someone has to rotate every key eventually.
- Rotating one by hand is a four-step dance: mint the replacement, wire it into
  whatever holds the old one, verify the new one works, delete the old one.
  Skip step three and you can lock yourself out; skip step four and the old key
  lingers as a standing credential nobody is watching.
- The key has no lifecycle tie to the workload using it. A worker that gets
  torn down does not take its API key with it — the key sits there, valid,
  until someone remembers it.

Vault's dynamic-secrets model answers exactly this: a credential minted for a
lease, deleted when that lease ends. This engine puts Temporal Cloud API keys
behind that model, so the credential a workload holds is short-lived,
attributable, and revocable from Vault.

## Before you start

You need:

- **A Vault server** you can register external plugins on: a configured
  `plugin_directory`, and permission to run `vault plugin register`.
- **A Temporal Cloud API key owned by a service account** with the Global Admin
  (or Account Owner) role, plus that service account's ID.

Two things about that credential are worth getting right up front, because both
are awkward to change later:

> **It must be a service-account key, not a user key.** Temporal Cloud's
> `CreateApiKey` only supports service-account owners, so there is no way to
> mint a replacement for a user identity. Hand this engine a user-owned key and
> `rotate-root` has nothing it can do.
>
> **Treat the key you paste in as disposable.** The first thing you do after
> configuring the mount is rotate it away, which deletes it. That is the
> point: from then on, no working root credential has ever existed outside
> Vault.

## Install

Download the archive for your platform from the
[releases page](https://github.com/ausmartway/vault-plugin-secrets-temporalcloud/releases).

**There are two different checksums involved, and confusing them is the usual
reason registration fails.** The published `_SHA256SUMS` file covers the
*archives* and proves your download arrived intact. Vault instead verifies the
hash of the *extracted binary*.

```bash
VERSION=0.1.1
OS=linux ARCH=amd64                       # or darwin / arm64

# 1. verify the download
shasum -a 256 -c "vault-plugin-secrets-temporalcloud_${VERSION}_SHA256SUMS" \
    --ignore-missing

# 2. extract into Vault's plugin directory
unzip "vault-plugin-secrets-temporalcloud_${VERSION}_${OS}_${ARCH}.zip" \
    -d "$VAULT_PLUGIN_DIR"

# 3. register with the hash of the BINARY, not the archive
SHA=$(shasum -a 256 "$VAULT_PLUGIN_DIR/vault-plugin-secrets-temporalcloud" \
    | cut -d' ' -f1)
vault plugin register -sha256="$SHA" \
    secret vault-plugin-secrets-temporalcloud

vault secrets enable -path=temporalcloud vault-plugin-secrets-temporalcloud
```

Binaries are statically linked (`CGO_ENABLED=0`), so they do not depend on the
Vault host's libc.

**Confirming what you installed.** Vault gives you no way to ask a registered
plugin which build it is running, so ask the binary directly:

```bash
./vault-plugin-secrets-temporalcloud --version
```

**Upgrading.** Replace the binary, re-register with the new hash, then reload:

```bash
vault plugin register -sha256="$NEW_SHA" \
    secret vault-plugin-secrets-temporalcloud
vault plugin reload -plugin=vault-plugin-secrets-temporalcloud
```

Stored configuration and service-account definitions survive an upgrade.
Outstanding leases survive too, and remain revocable.

### Install on a multi-node cluster

Vault keeps the plugin registration in storage, so every node in the cluster
reads the same entry. Vault does not distribute the binary — that part is local
disk on each node, and you put it there yourself.

Install on **every node that can become active**, standbys included. A standby
that holds no binary, or a different one, fails to load the mount at the moment
it takes over. To install across the cluster, follow these steps:

1. Copy the identical binary into `plugin_directory` on every node, at the same
   path.
2. Register the plugin once. The registration is a storage write, and Vault
   forwards it to the active node:

   ```bash
   vault plugin register -sha256="$SHA" \
       secret vault-plugin-secrets-temporalcloud
   ```

3. Enable the mount once:

   ```bash
   vault secrets enable -path=temporalcloud vault-plugin-secrets-temporalcloud
   ```

To upgrade, replace the binary on every node, re-register with the new hash,
then reload across the cluster:

```bash
vault plugin reload -plugin=vault-plugin-secrets-temporalcloud -scope=global
```

`-scope=global` carries the reload to every node. Without it, Vault reloads the
plugin on the single node that served the request and leaves the rest of the
cluster running the old binary.

Two mount behaviours are already cluster-aware and need nothing from you.
`config/rotate-root` forwards from performance standbys and performance
secondaries to the primary, so rotation runs in one place. A `config` write
invalidates the cached Temporal Cloud client on every node, so no node keeps
using a credential that rotation has deleted. For more information, see
[Replication and HA](#replication-and-ha).

## Configure

### 1. Write the root credential

```bash
vault write temporalcloud/config \
    api_key="eyJhbGciOiJFUzI1NiIs..." \
    admin_service_account_id="<service account id>"
```

`admin_service_account_id` is required because the Cloud Ops API has no
"whoami" call — given only a token, there is no way to discover which identity
it belongs to, and rotation needs that identity to mint a replacement.

**Nothing is stored until the credential has been proven to work.** The write
is checked in two stages and fails at whichever comes first:

1. **The key is parsed.** A Temporal Cloud API key is a JWT; the engine reads
   the key's own ID out of it. A key it cannot parse is rejected.
2. **The key is used.** The engine dials Temporal Cloud and reads
   `admin_service_account_id` back. That single call proves both that the key
   authenticates and that the ID is real and readable by it.

Only then is anything persisted. Four mistakes fail at write time, each with a
message naming which one: a wrong key, an expired key, a key whose service
account lacks Global Admin, and a mistyped `admin_service_account_id`. None of
them fails silently, and none waits for a later credential request. A rejected
update leaves the previous configuration exactly as it was, so a bad write
cannot break a working mount.

### 2. Rotate it immediately

```bash
vault write -f temporalcloud/config/rotate-root
```

This mints a new key on the admin service account, verifies it works, stores
it, and **deletes the key you pasted**. Run it as part of setup, not as a
later chore. Until you do, a working root credential exists in your shell
history, your terminal scrollback, and wherever you copied it from.

The ordering inside rotation is deliberate and worth knowing when something
goes wrong: verify before storing means a non-working key never becomes the
stored credential; store before deleting means a failure at the last step
leaves two working keys rather than none. Every intermediate failure leaves the
mount usable — worst case you get a warning that a key needs manual cleanup,
never a bricked mount.

> ### Put the next rotation in your calendar
>
> **Every Temporal Cloud API key expires — including Vault's own.** Re-run
> `config/rotate-root` well before `root_key_ttl` (default 90 days) elapses.
>
> If it expires anyway, the mount stops issuing credentials until an operator
> writes `config` again with a fresh, hand-made key. **There is no automatic
> recovery**: the engine cannot mint a replacement for a key when it no longer
> holds one that works. Rotation is safe to run early and as often as you like.

## Define a service account

Each `service-accounts/<name>` entry is one Temporal Cloud service account plus
the credential policy for keys issued from it.

```bash
vault write temporalcloud/service-accounts/prod-workers \
    account_role=read \
    namespace_access="prod.acct1=write,staging.acct1=read" \
    ttl=15m max_ttl=8h
```

Writing this **creates the service account in Temporal Cloud**. Reading the
entry back shows what Vault has stored, including whether the account was
adopted rather than created:

```bash
vault read temporalcloud/service-accounts/prod-workers
```

### Two behaviours that surprise people

Both change live state in Temporal Cloud, not just what Vault has stored.

**Create requires the spec; update merges.** The first write needs
`account_role` at minimum. Every write after that changes only the fields you
pass — omit one and it keeps its stored value. So this changes the role and
nothing else:

```bash
vault write temporalcloud/service-accounts/prod-workers account_role=admin
```

`namespace_access` needs care, because "omitted" and "empty" look the same to
`vault write`. Omit it entirely to leave namespace permissions untouched; pass
it explicitly as an empty string to clear them:

```bash
vault write temporalcloud/service-accounts/prod-workers namespace_access=""
```

That reaches Temporal Cloud and revokes every namespace permission the account
had. It is not a Vault-side bookkeeping change.

**A name that already exists in Temporal Cloud fails, unless you force it.**
Service-account names are unique across active accounts. If the name is taken —
by a colleague, a previous mount, or something made by hand in the console —
the write fails and names the colliding account's ID. `force=true` adopts that
account instead: Vault binds its entry to it and overwrites its permissions
with your specification.

> **An adopted account becomes fully Vault-managed, exactly as if Vault had
> created it.** `vault delete` on that entry deletes the service account in
> Temporal Cloud, invalidating every API key it owns. Adopt a colleague's
> service account and you have handed Vault the ability to destroy it.
> `vault read` shows `adopted: true` so this stays visible afterwards, but
> nothing stops the delete.

## Issue credentials

```bash
vault read temporalcloud/creds/prod-workers
```

```text
Key                    Value
---                    -----
lease_id               temporalcloud/creds/prod-workers/abc123...
lease_duration         15m
lease_renewable        true
api_key                eyJhbGciOiJFUzI1NiIs...
api_key_id             A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6
expires_at             2026-08-07T09:15:00Z
service_account_id     <service account id>
service_account_name   prod-workers
```

The token appears **once**. Vault does not store it and cannot show it again —
read the path again for a new key.

| Lease event | What happens in Temporal Cloud |
| --- | --- |
| Read | A fresh API key is minted, then read back to confirm it exists before the token is returned |
| Renew | Nothing. Renewal is Vault-side only — the key already outlives any extension Vault can grant |
| Revoke / expire | Vault deletes the key, then confirms the deletion by reading it back |

### Verify key propagation

Temporal Cloud distributes API keys asynchronously. A key that the Cloud Ops
API reports as created might not yet be accepted by every namespace frontend,
because the key and its permissions still have to reach the cells.

A worker does not necessarily recover from that delay. Temporal SDKs treat
`Unauthenticated` and `PermissionDenied` as non-retryable and can fail on the
first connection instead of reconnecting.

Set `verify_propagation=true` on a service account entry to check the key before
returning it:

```bash
vault write temporalcloud/service-accounts/prod-workers \
    account_role=developer \
    namespace_access=prod.acct1=write \
    verify_propagation=true
```

Each `creds/prod-workers` read then connects to every namespace in
`namespace_access` as the new key and waits until each namespace accepts it.
The checks run in parallel.

Before enabling this option, consider these requirements:

- **Allow egress to the namespace frontends.** The Vault node must reach
  `<namespace>.tmprl.cloud:7233`. This destination differs from the
  `saas-api.tmprl.cloud:443` endpoint that the engine otherwise uses.
- **Enable API key authentication on each namespace.** A namespace configured
  for mTLS only cannot accept the probe and produces a warning on every
  credential request.
- **Handle warnings.** A timeout never fails credential issuance. Vault returns
  the credential with a normal lease and a warning naming each namespace that
  did not confirm it. The warning means that Vault could not verify propagation,
  not that the credential is invalid.

An entry that grants access through `account_role` alone has no namespaces to
check. Credential reads from that entry warn that nothing was verified.

Credential work under `creds/<name>` is bounded to 55 seconds, leaving five
seconds for Vault to serialize and deliver the response before its API client's
default 60-second HTTP timeout. The probe uses whatever remains of that
55-second budget after key creation and never waits longer than 55 seconds. If
too little time remains, Vault returns the credential with a warning instead of
risking a client-side timeout.

If you raise `max_ttl` on an entry that has outstanding leases, those leases
keep the ceiling their own keys were minted under. Temporal Cloud fixes an API
key's expiry when it creates the key and offers no call to extend it, so a
lease can never outlive the key behind it. To put a longer ceiling into effect,
revoke the lease and read `creds/<name>` again for a key minted under the new
`max_ttl`.

Revocation is confirmed rather than assumed: the engine does not treat "the API
accepted my delete" as proof the credential is gone. A key that survives a
delete is reported as an error so Vault retries, rather than dropping the lease
and leaving a live credential nobody is tracking.

## Vault policy

```hcl
# Platform operators: manage service accounts.
path "temporalcloud/service-accounts/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Applications: read their own credentials, nothing else.
path "temporalcloud/creds/prod-workers" {
  capabilities = ["read"]
}
```

> **`service-accounts/*` is a privilege boundary, not just a management path.**
> Anyone who can write there can set `account_role=owner` and then read
> `creds/<name>` to mint a key with Account Owner access — full control of your
> Temporal Cloud account.

The engine deliberately does not add a second allowlist on top of that. It
relies on Vault policy to keep `service-accounts/*` restricted to whoever
should be trusted with that power, and expects `creds/<name>` reads to be
handed out far more freely, scoped one path per application.

`config` and `config/rotate-root` deserve the same treatment as
`service-accounts/*`: whoever can write `config` chooses which Temporal Cloud
account the mount points at.

## Capacity planning

> Temporal Cloud allows **20 non-expired API keys per service account**, so at
> most **20 concurrent leases** per `service-accounts/<name>` entry. Revoking a
> lease frees a slot immediately; letting one expire does too. There is no knob
> to raise this.

The arithmetic that catches people is about *concurrency*, not headcount. A
`ttl` of 15 minutes with 40 workers each holding one lease at a time is fine,
as long as no more than 20 are alive at once. But a `ttl` long enough that
leases pile up — say 8 hours, with new workers reading a fresh credential every
hour — can reach the ceiling well before 40 workers exist.

Two fixes, in order of preference: shorten `ttl` so old leases clear faster, or
split the load across additional service accounts. If a workload genuinely
needs more than 20 concurrent credentials, give it its own service account.

Hitting the ceiling fails the read with a message naming the count:

```text
service account "prod-workers" has 20 of 20 permitted API keys in use. Temporal Cloud allows 20
non-expired keys per service account. Revoke leases, lower ttl (currently 15m0s), or create an
additional service account.
```

## Mount operations

### Storage and seal wrap

The root credential lives in the mount's `config` entry, which is registered
for **seal wrapping**. On Vault Enterprise or HSM-backed deployments that means
it is encrypted with the seal in addition to the barrier.

### Replication and HA

`config/rotate-root` is marked to forward from performance standbys and
performance secondaries to the primary. It mutates the stored credential, so it
must run in exactly one place. Rotation is also serialised within a node: two
overlapping rotations would each mint a Global Admin key and one would be left
orphaned outside Vault's `config` entry for its full `root_key_ttl`. Avoid
scheduling rotation from more than one automation.

### Teardown order

Deleting a `service-accounts/<name>` entry deletes the service account in
Temporal Cloud, which invalidates every API key it owns. **Revoke outstanding
leases first:**

```bash
vault lease revoke -prefix temporalcloud/creds/prod-workers
vault delete temporalcloud/service-accounts/prod-workers
```

Deleting the entry while leases are outstanding leaves those leases pointing at
keys whose owning service account is gone. Vault still revokes them on
schedule, and revocation treats an already-absent key as success — but that
specific path has never been exercised against a live account, so revoking
first keeps teardown on proven behaviour.

### What to watch

| Signal | Why it matters |
| --- | --- |
| Days until `root_key_ttl` elapses | An expired root key stops the mount issuing anything, with no automatic recovery |
| Credential requests failing with the 20-key message | A service account is at its ceiling; `ttl` is too long or the workload needs its own account |
| Repeated lease-revocation failures | A key deletion is not taking effect; the credential might still be live in Temporal Cloud |
| Warnings on `config/rotate-root` | Rotation succeeded but a previous key might need deleting by hand |

`vault read temporalcloud/config` reports `api_key_id`, `address`,
`root_key_ttl`, and `admin_service_account_id`. It never returns `api_key`.

### Orphaned keys

Every key is minted with a Temporal Cloud-side expiry of
`max(max_ttl, 24h) + 10m`. That expiry is a **backstop, not the credential's
lifetime**: in normal operation the key is deleted the moment its lease ends,
so `max_ttl=30m` really does mean a 30-minute credential.

It matters only when Vault never gets to revoke — a crash, lost storage, a
deleted mount. Then the key self-destructs on its own at that expiry. The
24-hour floor exists because Temporal Cloud refuses to mint a key expiring
sooner than that (undocumented, found by live testing). The practical
consequence for you: **an orphaned key can outlive its `max_ttl` by up to a
day.** Short lease ceilings still work; the cleanup-of-last-resort window
cannot be shorter than 24 hours.

## Troubleshooting

| Message | Cause | Fix |
| --- | --- | --- |
| `the Temporal Cloud secrets engine is not configured` | No `config` written on this mount | Write `config` |
| `api_key does not look like a Temporal Cloud API key` | Truncated paste, or not an API key | Re-copy the whole key |
| `api_key_id is read-only and cannot be set` | Supplied a field Vault derives itself | Remove it from the write |
| `no service account "…" exists in this Temporal Cloud account` | `admin_service_account_id` is wrong | Check the ID in the Temporal Cloud console |
| `the supplied api_key was rejected, or its service account lacks permission` | Key expired, revoked, or its account lacks Global Admin | Write `config` with a fresh key |
| `The configured root API key was rejected…` on a `creds/` read | The mount's own root key has expired or been revoked | Write `config` with a fresh key, then rotate |
| `no service account named "…" is configured` | Reading `creds/<name>` with no matching entry | Create `service-accounts/<name>` first |
| `…has 20 of 20 permitted API keys in use` | Ceiling reached | Revoke leases, lower `ttl`, or add a service account |
| `a service account named "…" already exists in Temporal Cloud` | Name collision | Choose another name, or `force=true` to adopt |
| `root_key_ttl of … is below Temporal Cloud's minimum` | Below the undocumented 24-hour floor | Raise it to at least 24h |
| `…did not take effect within 15s` | Temporal Cloud accepted a change but the resource does not reflect it | Retry; if persistent, check Temporal Cloud status |
| `timed out after 1m0s waiting for operation` | A Cloud Ops operation never reached a terminal state | Retry; check Temporal Cloud status |

## Path reference

### `config`

| Field | Description |
| --- | --- |
| `api_key` | **Required.** API key owned by a Global Admin service account. Never returned by a read. |
| `admin_service_account_id` | **Required.** ID of the service account owning `api_key`. |
| `address` | Cloud Ops API host:port. Defaults to `saas-api.tmprl.cloud:443`. Override for PrivateLink or non-production endpoints. |
| `root_key_ttl` | Expiry for keys minted by `rotate-root`. Default 90 days. Minimum 24 hours, maximum two years; a value outside that is rejected at write time rather than at rotation time. |
| `api_key_id` | **Read-only.** Returned by a read, rejected on a write. |

Updates merge: `address` and `root_key_ttl` keep their stored values when
omitted, so swapping the credential does not silently revert a PrivateLink
address to the public endpoint. `api_key` and `admin_service_account_id` are
required on every write.

`api_key_id` is read-only because the key already carries it — a Temporal Cloud
API key is a JWT whose payload names its own ID. The engine reads it from the
key you write, so it always describes the key actually in use, and rotation can
always delete the key it replaces. A value you supplied could only ever
*disagree* with the key it names, and rotation **deletes** whatever that ID
names, so accepting one would be a way to destroy an unrelated key by typo.

### `config/rotate-root`

Write-only, no fields. Mints a replacement root key, verifies it, stores it,
deletes the old one.

### `service-accounts/<name>`

| Field | Description |
| --- | --- |
| `account_role` | **Required on every write.** One of `owner`, `admin`, `developer`, `finance-admin`, `read`, `metrics-read`. |
| `namespace_access` | `namespace=permission` pairs (`admin`, `write`, `read`), for example `prod.acct1=write,staging.acct1=read`. |
| `description` | Shown in the Temporal Cloud UI. Defaults to `Managed by Vault mount <mount>`. |
| `ttl` | Default lease TTL for keys issued here. Default 1 hour. |
| `max_ttl` | Maximum lease TTL. Also drives the key's Temporal Cloud expiry. Default 24 hours. |
| `verify_propagation` | Before returning a credential, wait for every namespace in `namespace_access` to accept the new key. Default `false`. See [Verify key propagation](#verify-key-propagation). |
| `force` | Create only. Adopt an existing Temporal Cloud account of the same name instead of failing. |

Supports `read`, `delete`, and `list`.

### `creds/<name>`

Read-only. Mints a key on the named service account and returns it under a
lease.

## Try it locally

`examples/demo.sh` walks the full lifecycle against a dev-mode Vault:
configure, rotate the bootstrap key away, create a service account, mint a
credential, revoke it, tear down. See
[`examples/README.md`](examples/README.md) for what to watch in the Temporal
Cloud UI at each step — it is written for demoing this to someone.

## License

MIT — see [LICENSE](LICENSE). Same license as
[temporalio/temporal](https://github.com/temporalio/temporal).
