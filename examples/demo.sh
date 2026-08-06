#!/usr/bin/env bash
# End-to-end walkthrough. Run after `make dev` in another terminal, with
# TEMPORAL_CLOUD_API_KEY and TEMPORAL_CLOUD_ADMIN_SA_ID set.
#
# Set TEMPORAL_CLOUD_API_KEY_ID as well — the bootstrap key's own ID, from
# Settings -> API Keys in the Temporal Cloud UI — to see step 2's full story.
# Vault can only delete the key it replaces if it knows that ID: a token does
# not carry it, and the Cloud Ops API has no way to look it up from one.
#
# See examples/README.md for what to look at in the Temporal Cloud UI at each
# step, and for the questions customers usually ask.
set -euo pipefail

MOUNT="${MOUNT:-temporalcloud}"
SA_NAME="${SA_NAME:-demo-workers}"
: "${TEMPORAL_CLOUD_API_KEY:?set TEMPORAL_CLOUD_API_KEY}"
: "${TEMPORAL_CLOUD_ADMIN_SA_ID:?set TEMPORAL_CLOUD_ADMIN_SA_ID}"
API_KEY_ID="${TEMPORAL_CLOUD_API_KEY_ID:-}"

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }

step "1. Configure the engine with the bootstrap credential"
if [[ -n "$API_KEY_ID" ]]; then
    vault write "$MOUNT/config" \
        api_key="$TEMPORAL_CLOUD_API_KEY" \
        api_key_id="$API_KEY_ID" \
        admin_service_account_id="$TEMPORAL_CLOUD_ADMIN_SA_ID"
else
    vault write "$MOUNT/config" \
        api_key="$TEMPORAL_CLOUD_API_KEY" \
        admin_service_account_id="$TEMPORAL_CLOUD_ADMIN_SA_ID"
fi

step "2. Rotate the root key so only Vault holds a working credential"
vault write -f "$MOUNT/config/rotate-root"
if [[ -n "$API_KEY_ID" ]]; then
    echo "The key you pasted in step 1 has been deleted in Temporal Cloud. The only"
    echo "working root credential now is one Vault minted and never showed anyone."
else
    echo "Vault is now using a key it minted itself — but read the warning above: the"
    echo "key you pasted in step 1 is STILL VALID and must be deleted by hand in"
    echo "Settings -> API Keys. Vault could not delete it because it was not told the"
    echo "key's ID. Set TEMPORAL_CLOUD_API_KEY_ID and re-run to see the full story."
fi

step "3. Create a service account in Temporal Cloud"
# ttl/max_ttl here govern the Vault lease, not the key's Temporal Cloud expiry:
# Temporal Cloud refuses any key expiring less than 24h out, so the engine
# floors that side automatically. The key is still deleted the moment the
# lease it belongs to ends, so this is still a 30-minute-lived credential.
vault write "$MOUNT/service-accounts/$SA_NAME" \
    account_role=read \
    ttl=5m max_ttl=30m
vault read "$MOUNT/service-accounts/$SA_NAME"

step "4. Read a dynamic credential"
vault read "$MOUNT/creds/$SA_NAME"
echo "That API key exists in Temporal Cloud right now, and expires with its lease."

step "5. Show the lease"
vault list sys/leases/lookup/"$MOUNT"/creds/"$SA_NAME"

step "6. Revoke every lease — the keys are deleted in Temporal Cloud"
vault lease revoke -prefix "$MOUNT/creds/$SA_NAME"
echo "Check Settings -> API Keys in the Temporal Cloud UI: they are gone."

step "7. Tear down"
# Revoke first (step 6), delete second. Deleting the entry removes the service
# account in Temporal Cloud, and any lease still outstanding would then be
# holding a key whose owner no longer exists.
vault delete "$MOUNT/service-accounts/$SA_NAME"
echo "The service account is deleted in Temporal Cloud too."
