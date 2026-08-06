# Demo walkthrough

`demo.sh` drives the whole lifecycle — configure, rotate the root key, create a
service account, mint a credential, revoke it, tear down — against a real
Temporal Cloud account. There is no simulated mode: every step here is a real
Cloud Ops API call.

## Prerequisites

- `vault` on your `PATH` (`brew install vault`)
- Go, to build the plugin
- A Temporal Cloud API key for a service account with the **Global Admin**
  role, and that service account's ID. This is the bootstrap credential —
  step 2 immediately replaces it with one Vault mints itself, so it does not
  need to be long-lived.

```bash
export TEMPORAL_CLOUD_API_KEY="tcld_..."
export TEMPORAL_CLOUD_ADMIN_SA_ID="svcacct-..."

# Optional, but set it if you can — see below.
export TEMPORAL_CLOUD_API_KEY_ID="apikey-..."
```

**Set `TEMPORAL_CLOUD_API_KEY_ID` if you want step 2 to land.** It is the ID
of the bootstrap key itself, shown next to the key in Settings → API Keys.
Without it, Vault has no way to know which key to delete when it rotates: an
API key token does not carry its own ID, and the Cloud Ops API has no call
that maps one to the other. Rotation still succeeds — Vault starts using a key
it minted itself — but it warns you, and the key you pasted stays valid until
you delete it by hand. That is a real behaviour worth showing a customer, but
show it deliberately, not by accident: with the ID set, the demo tells the
whole story of the bootstrap credential being destroyed.

## Running it

Terminal 1:

```bash
make dev
```

This builds the plugin, starts Vault in `-dev` mode with it registered and
mounted at `temporalcloud/`, and prints the export lines below. Dev mode keeps
everything in memory — nothing here needs a running Vault cluster, unsealing,
or storage setup.

Terminal 2:

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
./examples/demo.sh
```

## What each step does, and what to look at in the Temporal Cloud UI

| Step | What happens | Where to look |
| --- | --- | --- |
| 1. Configure | Vault stores the bootstrap API key and validates it by reading the admin service account | Settings → API Keys — your pasted key is still there |
| 2. Rotate root | Vault mints a fresh key on the admin service account, verifies it works, stores it, and deletes the one you pasted — if it was told that key's ID | Settings → API Keys — a key named `vault-root-<timestamp>` appears. With `TEMPORAL_CLOUD_API_KEY_ID` set, the key from step 1 is gone; without it, that key is still listed and Vault warns you to delete it yourself |
| 3. Create service account | Vault creates `demo-workers` with `read` account access | Settings → Identities — a new service account named `demo-workers` |
| 4. Read a credential | Vault mints an API key on `demo-workers` and hands it back once, under a 5-minute lease | Settings → API Keys — a key named `vault-demo-workers-<random>` appears |
| 5. Show the lease | `vault list` on `sys/leases/lookup` — nothing Temporal Cloud–side, just showing Vault's bookkeeping | — |
| 6. Revoke | Vault deletes the API key it minted in step 4 | Settings → API Keys — that key is gone |
| 7. Tear down | Vault deletes the service account in Temporal Cloud, then its own entry | Settings → Identities — `demo-workers` is gone |

## Questions customers usually ask

**What happens to a running worker when I revoke its lease?**
The API key stops working immediately — the Temporal Cloud API rejects it,
and any gRPC connection authenticated with it is refused on its next auth
check. A worker built to reload credentials from Vault (renew before expiry,
re-read `creds/<name>` on auth failure) picks up a new key without a restart.
A worker that read the key once at startup and cached it forever does not,
which is true of any secrets engine, not something specific to this one —
build the reload logic into the worker's startup, same as you would for a
database password.

**Why can I only run 20 of these at once per service account?**
Temporal Cloud enforces at most 20 non-expired API keys per service account.
That is a hard ceiling on concurrent Vault leases against one
`service-accounts/<name>` entry — not a soft limit this engine adds. Revoking
a lease (or letting it expire) frees a slot right away. If a workload needs
more than 20 concurrent credentials, give it its own service account rather
than trying to raise the number; the README's "20-key ceiling" section has
the arithmetic.

**Does this work with mTLS instead of API keys?**
No — this engine is API-key-only, because that is what the Cloud Ops API's
`CreateApiKey` mints. Temporal Cloud's mTLS-based auth is a client certificate
you configure once per namespace, not a per-request credential, so there is
nothing here for a secrets engine to rotate on a schedule. If your Temporal
Cloud namespace uses mTLS, that setup lives outside Vault; this engine is for
the API-key path.
