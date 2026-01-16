#!/usr/bin/env bash
set -euo pipefail

BASE="${1:-}"
if [[ -z "${BASE}" ]]; then
  echo "usage: $0 <base-url>"
  echo "example: $0 https://mcp-deception-incubator-kubernetes.<your-account>.workers.dev"
  exit 1
fi

echo "[1/3] GET /"
code="$(curl -sS -o /dev/null -w '%{http_code}' "${BASE}/")"
test "${code}" = "200" && echo "ok"

echo "[2/3] MCP SSE (/sse) responds"
curl -Ns -H "Accept: text/event-stream" "${BASE}/sse" --max-time 3 | head -n 5 || true

echo "[3/3] MCP tool discovery includes expected tools"
hdrs="$(mktemp)"
body="$(mktemp)"

# MCP Streamable HTTP: initialize first, then send Mcp-Session-Id on subsequent requests
curl -sS -D "${hdrs}" -o "${body}" "${BASE}/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"compat-smoke","version":"0.0.0"}}}' >/dev/null

session_id="$(awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}' "${hdrs}" | tr -d '\r' | head -n 1)"
if [[ -z "${session_id}" ]]; then
  echo "error: initialize did not return Mcp-Session-Id"
  head -c 500 "${body}" || true
  echo
  rm -f "${hdrs}" "${body}"
  exit 1
fi

resp="$(curl -sS -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" -H "mcp-session-id: ${session_id}" "${BASE}/mcp" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')"

echo "${resp}" | grep -q "k8s_access_guide"
echo "${resp}" | grep -q "cluster_status_public"
echo "${resp}" | grep -q "kubeconfig_get"
echo "ok"

rm -f "${hdrs}" "${body}"
