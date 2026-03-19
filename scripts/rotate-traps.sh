#!/usr/bin/env bash
set -euo pipefail

# Rotate trap artifacts and secrets for the k8s-access-portal Worker.
#
# Usage:
#   ./scripts/rotate-traps.sh [--kv-file path/to/kubeconfig.yaml]
#
# What this does:
#   1. Rotates DOWNLOAD_TOKEN_SECRET (invalidates all outstanding download links)
#   2. Optionally uploads a new kubeconfig YAML to KV
#   3. Prompts to rotate each Canary secret (web bug, DNS hostname, webhook URL)
#
# Prerequisites:
#   - wrangler authenticated (run `npx wrangler login` first)
#   - KV namespace ID set in wrangler.jsonc

KV_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kv-file) KV_FILE="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

KV_NS_ID=$(grep '"id"' wrangler.jsonc | head -1 | sed 's/.*"id":\s*"\([^"]*\)".*/\1/')
if [[ -z "${KV_NS_ID}" ]]; then
  echo "error: could not extract KV namespace ID from wrangler.jsonc"
  exit 1
fi

echo "=== Trap Rotation ==="
echo ""

echo "[1/5] Rotating DOWNLOAD_TOKEN_SECRET (invalidates outstanding download links)..."
NEW_SECRET=$(openssl rand -hex 32)
echo "${NEW_SECRET}" | npx wrangler secret put DOWNLOAD_TOKEN_SECRET
echo "  done."
echo ""

if [[ -n "${KV_FILE}" ]]; then
  echo "[2/5] Uploading new kubeconfig to KV from: ${KV_FILE}"
  npx wrangler kv key put --namespace-id="${KV_NS_ID}" "kubeconfig_yaml" --path="${KV_FILE}"
  echo "  done."
else
  echo "[2/5] Skipping kubeconfig rotation (use --kv-file to provide a new kubeconfig)"
fi
echo ""

echo "[3/5] Rotate CANARY_WEB_BUG_URL? (paste new URL or press Enter to skip)"
read -r -p "  > " NEW_WEB_BUG
if [[ -n "${NEW_WEB_BUG}" ]]; then
  echo "${NEW_WEB_BUG}" | npx wrangler secret put CANARY_WEB_BUG_URL
  echo "  done."
else
  echo "  skipped."
fi
echo ""

echo "[4/5] Rotate CANARY_DNS_HOSTNAME? (paste new hostname or press Enter to skip)"
read -r -p "  > " NEW_DNS
if [[ -n "${NEW_DNS}" ]]; then
  echo "${NEW_DNS}" | npx wrangler secret put CANARY_DNS_HOSTNAME
  echo "  done."
else
  echo "  skipped."
fi
echo ""

echo "[5/5] Rotate CANARY_WEBHOOK_URL? (paste new URL or press Enter to skip)"
read -r -p "  > " NEW_WEBHOOK
if [[ -n "${NEW_WEBHOOK}" ]]; then
  echo "${NEW_WEBHOOK}" | npx wrangler secret put CANARY_WEBHOOK_URL
  echo "  done."
else
  echo "  skipped."
fi
echo ""

echo "=== Rotation complete ==="
echo "Deploy to apply: npm run deploy"
