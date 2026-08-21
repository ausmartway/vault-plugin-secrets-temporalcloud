# Contributing

Development, testing, and release notes. If you are installing or operating
this plugin rather than changing it, [README.md](README.md) is what you want.

## Layout

| Path | What lives there |
| --- | --- |
| `backend.go` | Backend wiring, path registration, the cached Cloud Ops client |
| `path_config.go` | Root credential and connection settings |
| `path_rotate_root.go` | Root key rotation |
| `path_service_accounts.go` | Service-account definitions and credential policy |
| `path_creds.go` | Minting leased API keys |
| `secret_api_key.go` | Lease renew and revoke |
| `client/` | The only package that knows about gRPC or the Cloud Ops API |
| `cmd/sweep/` | Cleans up `vault-acctest-*` debris from failed live runs |

The `client` package exposes `CloudOps`, an interface the Vault paths are
written against, so every handler can be tested without a network.

## Build the plugin

```bash
make build       # compile into ./bin, print the SHA256 Vault needs
make dev         # build + start Vault in -dev mode with it mounted
make fmt         # gofmt -w .
make lint        # golangci-lint run
```

`make dev` starts a dev-mode Vault with the plugin registered and mounted at
`temporalcloud/`. Pair it with `examples/demo.sh` for an end-to-end walkthrough.

## Tests

```bash
make test        # fast suite: no credentials, no network, safe anywhere
make test-live   # acceptance suite against a real Temporal Cloud account
make sweep       # delete leftover vault-acctest-* resources
```

`make test-live` **mutates real state** — it creates and deletes service
accounts and API keys — so point it at an account you are comfortable with
that. It reads:

| Variable | Required | What it does |
| --- | --- | --- |
| `TEMPORAL_CLOUD_API_KEY` | Yes | The root credential the tests configure the engine with. |
| `TEMPORAL_CLOUD_ADMIN_SA_ID` | Yes | The ID of the service account owning that key. |
| `TEMPORAL_CLOUD_ADDRESS` | No | Cloud Ops API host:port. Defaults to `saas-api.tmprl.cloud:443`. |

Two live tests are opt-in beyond those, because of what they do:

- `TestLive_RotateRoot` **deletes the API key in your environment**
  as part of proving rotation end to end. Gated behind
  `TEMPORAL_CLOUD_ALLOW_ROOT_ROTATION=1` so it never runs by accident.
- `TestLive_KeyCapacity` mints all 20 keys a service account can hold, to prove
  the ceiling is enforced and the error message is right. Gated behind
  `TEMPORAL_CLOUD_RUN_CAPACITY_TEST=1`.

If a live run dies mid-flight it leaves real resources behind. `make sweep`
deletes anything named `vault-acctest-*`.

### Testing conventions

Behaviour that matters is expected to have a test that **fails without the
code that implements it**. Several comments in the tree name the test that
pins a given invariant; if you change that behaviour, expect the named test to
be the thing that stops you.

Two conventions worth knowing before adding tests:

- The Temporal Cloud API is reached only through `client.CloudOps`, so path
  handlers are tested against `stubCloudOps` (`path_config_test.go`). The
  `client` package itself is tested against `fakeCloudServiceClient`
  (`client/grpc_test.go`), which stubs individual gRPC methods.
- A real API key is a JWT. `testAPIKey(id)` builds one carrying a given key
  ID, so tests exercise the real derivation path instead of routing around it.
  Never commit a real key as a fixture.

## Cut a release

[GoReleaser](https://goreleaser.com) builds releases from a git tag, for linux
and darwin on amd64 and arm64, statically linked (`CGO_ENABLED=0`) so the
binary does not depend on the Vault host's libc.

```bash
make release-check                        # validate .goreleaser.yaml
make snapshot                             # build locally into dist/, publish nothing
git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z
GITHUB_TOKEN=$(gh auth token) make release
```

GoReleaser refuses to run on an untagged or dirty tree, which is the behaviour
you want.

Note for the release notes: operators register the plugin with the SHA256 of
the **extracted binary**, not of the archive. The published `_SHA256SUMS` file
covers the archives. Both hashes matter and confusing them is the usual reason
a registration fails.
