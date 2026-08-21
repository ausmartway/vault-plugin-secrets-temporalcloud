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
export TEMPORAL_CLOUD_API_KEY="eyJhbGciOiJFUzI1NiIs..."
export TEMPORAL_CLOUD_ADMIN_SA_ID="<service account id>"
```

**Step 2 deletes the key you pasted in step 1, and that is the moment worth
narrating.** Have Settings → API Keys open on screen while it runs: the key you
pasted disappears and a `vault-root-<timestamp>` key takes its place. From that
point no working root credential exists outside Vault.

Vault knows which key to delete because a Temporal Cloud API key is a JWT that
carries its own `key_id` claim, so the engine reads the ID straight out of the
key you handed it. Nobody looks anything up, and there is no window where the
human-held credential outlives its replacement. If someone asks how it knows,
decoding the middle segment of any API key on screen answers it in about ten
seconds.

## Run it

Terminal 1:

```bash
make dev
```

This builds the plugin, starts Vault in `-dev` mode with it registered and
mounted at `temporalcloud/`, and prints the export lines that follow. Dev mode
keeps everything in memory — nothing here needs a running Vault cluster,
unsealing, or storage setup.

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
| 2. Rotate root | Vault mints a fresh key on the admin service account, verifies it works, stores it, and deletes the one you pasted — whose ID it read out of the key itself | Settings → API Keys — a key named `vault-root-<timestamp>` appears and the key from step 1 is gone. Rotate again and watch the same thing happen to the `vault-root-*` key |
| 3. Create service account | Vault creates `demo-workers` with `read` account access | Settings → Identities — a new service account named `demo-workers` |
| 4. Read a credential | Vault mints an API key on `demo-workers` and hands it back once, under a 5-minute lease | Settings → API Keys — a key named `vault-demo-workers-<random>` appears |
| 5. Show the lease | `vault list` on `sys/leases/lookup` — nothing Temporal Cloud–side, this shows Vault's bookkeeping | — |
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
