#!/usr/bin/env bash
# Starts a dev-mode Vault with this plugin built, registered, and mounted.
# Dev mode keeps everything in memory and auto-unseals, so it is right for a
# demo and wrong for anything else.
set -euo pipefail

PLUGIN_NAME="vault-plugin-secrets-temporalcloud"
PLUGIN_DIR="$(pwd)/bin"
MOUNT="${MOUNT:-temporalcloud}"
export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-root}"

command -v vault >/dev/null || { echo "vault is not installed: brew install vault"; exit 1; }

echo "==> Building the plugin"
mkdir -p "$PLUGIN_DIR"
go build -o "$PLUGIN_DIR/$PLUGIN_NAME" "./cmd/$PLUGIN_NAME"

echo "==> Starting Vault in dev mode"
vault server -dev -dev-root-token-id="$VAULT_TOKEN" \
    -dev-plugin-dir="$PLUGIN_DIR" -log-level=info &
VAULT_PID=$!
trap 'kill $VAULT_PID 2>/dev/null || true' EXIT

# Wait for Vault to accept connections rather than guessing with sleep.
for _ in $(seq 1 30); do
    if vault status >/dev/null 2>&1; then break; fi
    sleep 0.5
done

echo "==> Enabling the secrets engine at $MOUNT/"
vault secrets enable -path="$MOUNT" "$PLUGIN_NAME"

cat <<EOF

Vault is running with the plugin mounted at $MOUNT/

  export VAULT_ADDR=$VAULT_ADDR
  export VAULT_TOKEN=$VAULT_TOKEN

Next, configure it against your Temporal Cloud account:

  vault write $MOUNT/config \\
      api_key="\$TEMPORAL_CLOUD_API_KEY"

Then run ./examples/demo.sh for the full walkthrough.
Press Ctrl-C to stop Vault.

EOF

wait $VAULT_PID
