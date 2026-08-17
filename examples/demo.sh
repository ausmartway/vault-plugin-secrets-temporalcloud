#!/usr/bin/env bash
# End-to-end walkthrough. Run after `make dev` in another terminal, with
# TEMPORAL_CLOUD_API_KEY and TEMPORAL_CLOUD_ADMIN_SA_ID set.
#
# See examples/README.md for what to look at in the Temporal Cloud UI at each
# step, and for the questions customers usually ask.
set -euo pipefail

MOUNT="${MOUNT:-temporalcloud}"
SA_NAME="${SA_NAME:-demo-workers}"
: "${TEMPORAL_CLOUD_API_KEY:?set TEMPORAL_CLOUD_API_KEY}"
: "${TEMPORAL_CLOUD_ADMIN_SA_ID:?set TEMPORAL_CLOUD_ADMIN_SA_ID}"

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }

step "1. Configure the engine with the bootstrap credential"
vault write "$MOUNT/config" \
    api_key="$TEMPORAL_CLOUD_API_KEY" \
    admin_service_account_id="$TEMPORAL_CLOUD_ADMIN_SA_ID"

step "2. Rotate the root key so only Vault holds a working credential"
vault write -f "$MOUNT/config/rotate-root"
echo "The key you pasted in step 1 has just been DELETED in Temporal Cloud. Check"
echo "Settings -> API Keys: it is gone, and a vault-root-<timestamp> key has taken"
echo "its place. No working root credential exists outside Vault any more."
echo
echo "Worth pausing on in a demo: Vault knew which key to delete because a Temporal"
echo "Cloud API key is a JWT carrying its own key_id claim, so the engine reads the"
echo "ID straight out of the key you pasted. Nobody had to look it up, and there is"
echo "no window where the human-held key outlives its replacement."

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
