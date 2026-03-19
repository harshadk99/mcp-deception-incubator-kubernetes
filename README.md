# Agentic Deception Incubator — Kubernetes Access Portal

![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/deception--engineering-red)
![Model](https://img.shields.io/badge/MCP-compatible-blueviolet)

AI systems expose intent through the tools they choose, not the requests they make. In MCP environments, agents autonomously discover and invoke tools based on descriptions — making reconnaissance and legitimate use indistinguishable at the API layer.

This project implements a detection model that observes **agent decisions** rather than request properties. By deploying decoy MCP tools with no legitimate purpose, tool selection becomes a high-confidence signal of unauthorized exploration. The framework produces signal by construction, not classification.

## Overview

The Agentic Deception Incubator is an open-source, serverless detection framework deployed on Cloudflare Workers. It exposes a realistic Kubernetes "internal access portal" via the Model Context Protocol (MCP), embedding three deception surfaces that silently detect AI-agent reconnaissance and intent escalation.

**Safe tools** provide a realistic portal ecosystem that makes the trap tools blend in naturally:
`list_clusters`, `k8s_access_guide`, `cluster_status_public`, `get_namespace_quota`, `request_access`

**Trap surfaces** detect unauthorized exploration across three layers:

| Surface | Tool | What Triggers Detection | Canary Type |
|---------|------|------------------------|-------------|
| **Credential** | `kubeconfig_get` | Agent invokes tool (Stage 1) or uses kubeconfig with `kubectl` (Stage 2) | Thinkst Canary kubeconfig token |
| **DNS** | `get_service_endpoints` | Agent invokes tool (Stage 1) or resolves canary hostname from service list (Stage 2) | Thinkst DNS canary |
| **Webhook** | `get_ci_webhook` | Agent invokes tool (Stage 1) or calls webhook URL from CI/CD config (Stage 2) | Thinkst HTTP canary |

All three surfaces share the same telemetry and attribution infrastructure.

## Three Novel Contributions

### 1. Deception at the Agent Decision Layer

Traditional deception operates at the network or host level. This framework shifts the detection surface to the **agent decision layer** — detection triggers when an autonomous agent selects and invokes a decoy tool during MCP capability discovery. Each trap tool emits a structured `trap_triggered` telemetry event the moment it is invoked, regardless of what the agent does next.

### 2. Two-Stage Intent-Escalation Detection

Agent interaction is decomposed into two observable stages:

- **Stage 1 (reconnaissance)**: The agent invokes a trap tool. The Worker emits a `trap_triggered` event with salted hashes and fires a Thinkst web bug with MCP client identity in the User-Agent:
  ```
  k8s-access-portal/1.0 (tool=kubeconfig_get; client=cursor/0.45.6; cluster_hash=a1b2c3d4e5f6; ns_hash=f6e5d4c3b2a1)
  ```

- **Stage 2 (operational intent)**: The agent uses the returned artifact — resolves a DNS canary hostname, calls a webhook URL, or downloads and uses a kubeconfig with `kubectl`. This fires an independent Thinkst alert **from the agent's real machine**, confirming escalation from curiosity to operational use.

The temporal gap between stages creates an **observable escalation window** that does not exist with traditional API logging. For the credential surface, stages are separated using HMAC-SHA256 signed, time-limited download tokens (10-minute TTL) with 128-bit cryptographically random nonces and timing-safe byte-level comparison.

### 3. Agent Attribution via MCP Protocol Metadata

The MCP `initialize` handshake includes a `clientInfo` field (agent name and version). This field, designed for capability negotiation, is repurposed as a forensic signal:

- Intercepted by wrapping the SDK's internal `_oninitialize` handler at runtime
- Persisted in Durable Object storage to survive Worker hibernation
- Injected into Canary web bug requests as a structured User-Agent field

This enables attribution of reconnaissance activity to specific agent frameworks and automated clients across sessions.

## Privacy-Preserving Telemetry

The deception layer is designed to never become an information leak if compromised:

- All identifiers (cluster names, namespaces, pipeline names) are hashed using SHA-256 with a Worker-secret salt before appearing in any log or alert
- Web bug User-Agent strings embed only the first 12 hex characters of each salted hash
- Structured telemetry events follow a versioned schema (`schemaVersion: 1.0`) containing only event type, timestamp, tool name, and hashed identifiers
- Raw secrets, credentials, kubeconfig contents, and plaintext infrastructure details are never logged

## Tools

### Safe Tools (realistic portal ecosystem)

| Tool | Description | Parameters |
|------|-------------|------------|
| `list_clusters` | Lists all Kubernetes clusters with region, environment, and status | (none) |
| `k8s_access_guide` | Internal access request workflow, RBAC policies, and kubeconfig template | (none) |
| `cluster_status_public` | Deterministic simulated health status for a named cluster | `cluster` |
| `get_namespace_quota` | Deterministic simulated resource quotas and usage | `cluster`, `namespace` |
| `request_access` | Simulates submitting an access request; returns ticket ID | `cluster`, `namespace`, `reason`, `duration_hours` (opt) |

### Trap Tools (deception surfaces)

| Tool | Surface | Description | Parameters |
|------|---------|-------------|------------|
| `get_service_endpoints` | DNS | Returns internal service endpoints; embeds Thinkst DNS canary hostname in metrics-collector endpoint | `cluster` |
| `get_ci_webhook` | Webhook | Returns CI/CD webhook config; embeds Thinkst Canary webhook URL | `pipeline` |
| `kubeconfig_get` | Credential | Returns HMAC-signed download link for Thinkst Canary kubeconfig from KV | `cluster`, `namespace` (opt), `reason` (opt), `access_key` (opt) |

All trap tools emit `trap_triggered` telemetry and fire the Stage 1 web bug with MCP client attribution on every invocation.

## Trap Modes

Two operational profiles for `kubeconfig_get`:

- **Open (default)**: Any caller receives a download link. Stage 1 telemetry fires on every call.
- **Gated**: Caller must provide `access_key` matching `TRAP_ACCESS_KEY`. Stage 1 telemetry fires even when access is denied — the denied attempt itself is a signal.

## Deploy Your Own

[![Deploy to Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/harshadk99/mcp-deception-incubator-kubernetes)

Or deploy manually:

```bash
npm install
npm run deploy
```

Your MCP server will be deployed to:

```
https://k8s-access-portal.<your-account>.workers.dev
```

## Configuration

### Secrets (set via `wrangler secret put`)

| Secret | Required | Purpose |
|--------|----------|---------|
| `TELEMETRY_SALT` | Yes | Salt for SHA-256 hashing of identifiers |
| `CANARY_WEB_BUG_URL` | Recommended | Thinkst web bug URL for Stage 1 detection across all trap surfaces |
| `DOWNLOAD_TOKEN_SECRET` | Recommended | HMAC key for signing credential download tokens (falls back to `TELEMETRY_SALT`) |
| `CANARY_DNS_HOSTNAME` | Recommended | Thinkst DNS canary hostname for the DNS trap surface |
| `CANARY_WEBHOOK_URL` | Recommended | Thinkst Canary webhook URL for the webhook trap surface |
| `TRAP_ACCESS_KEY` | Only for gated mode | Access key for gated credential trap |

### Plain vars (set in `wrangler.jsonc`)

| Var | Default | Purpose |
|-----|---------|---------|
| `PUBLIC_BASE_URL` | (none) | Base URL for absolute download links |
| `TRAP_MODE` | `open` | `open` or `gated` |

### KV binding

| Binding | Key | Purpose |
|---------|-----|---------|
| `KUBECONFIG_KV` | `kubeconfig_yaml` | Thinkst Canary kubeconfig YAML blob |

## Setup

1) Create a KV namespace and set its ID in `wrangler.jsonc`:

```bash
npx wrangler kv namespace create KUBECONFIG_KV
```

2) Set `PUBLIC_BASE_URL` in `wrangler.jsonc` `vars` to your Worker's public URL.

3) Set secrets:

```bash
npx wrangler secret put TELEMETRY_SALT
npx wrangler secret put CANARY_WEB_BUG_URL
npx wrangler secret put DOWNLOAD_TOKEN_SECRET
npx wrangler secret put CANARY_DNS_HOSTNAME
npx wrangler secret put CANARY_WEBHOOK_URL
```

4) Upload the kubeconfig YAML into KV:

```bash
npx wrangler kv key put --namespace-id="<your-namespace-id>" "kubeconfig_yaml" --path="kubeconfig.yaml"
```

5) Deploy:

```bash
npm run deploy
```

## Trap Rotation

To rotate trap artifacts and invalidate outstanding tokens:

```bash
./scripts/rotate-traps.sh [--kv-file path/to/new-kubeconfig.yaml]
```

The script rotates `DOWNLOAD_TOKEN_SECRET` automatically and prompts for optional rotation of each Canary secret.

## Endpoints

| Path | Method | Purpose |
|------|--------|---------|
| `/` | GET | HTML portal page with tool descriptions and Playground link |
| `/sse` | GET | MCP SSE endpoint (AI Playground / Cursor) |
| `/sse/message` | POST | MCP SSE message relay |
| `/mcp` | POST | MCP Streamable HTTP (JSON-RPC) |
| `/download/kubeconfig?t=TOKEN` | GET | Signed kubeconfig file download |
| `/hooks/notify` | POST | CI/CD webhook proxy (forwards to Thinkst canary, preserving caller identity) |

## Evaluation

### Smoke test

```bash
./scripts/compat-smoke.sh https://k8s-access-portal.<your-account>.workers.dev
```

### Reproducible evaluation checklist

1. Deploy the Worker and configure secrets/KV (see setup above).
2. Verify MCP tool discovery via the smoke test.
3. **Stage 1 — reconnaissance detection**: invoke any trap tool via AI Playground or `/mcp`. Confirm `trap_triggered` in Worker logs and a web bug alert on your Thinkst dashboard with MCP client identity.
4. **Stage 2 — intent escalation**:
   - Credential: download kubeconfig via signed URL, run `KUBECONFIG=./kubeconfig.yaml kubectl get ns`
   - DNS: resolve the canary hostname returned by `get_service_endpoints`
   - Webhook: call the webhook URL returned by `get_ci_webhook`
5. Confirm each Stage 2 action fires an independent Thinkst alert from the consumer's real machine.
6. Rotate traps via `./scripts/rotate-traps.sh` and verify detection continuity.

### Test with curl

```bash
BASE="https://k8s-access-portal.<your-account>.workers.dev"

# 1) Initialize MCP session
sid="$(
  curl -sS -D - "${BASE}/mcp" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"0.0.0"}}}' \
  | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}' | tr -d '\r' | head -n 1
)"

# 2) List tools
curl -sS "${BASE}/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: ${sid}" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# 3) Trigger credential trap
curl -sS "${BASE}/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: ${sid}" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"kubeconfig_get","arguments":{"cluster":"prod-us-east-1","namespace":"default","reason":"demo"}}}'

# 4) Trigger DNS trap
curl -sS "${BASE}/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: ${sid}" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_service_endpoints","arguments":{"cluster":"prod-us-east-1"}}}'

# 5) Trigger webhook trap
curl -sS "${BASE}/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: ${sid}" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_ci_webhook","arguments":{"pipeline":"deploy-prod"}}}'
```

## Example Prompts (AI Playground)

```
use tool list_clusters with { }
use tool k8s_access_guide with { }
use tool cluster_status_public with { "cluster": "dev-us-east-1" }
use tool get_namespace_quota with { "cluster": "prod-us-east-1", "namespace": "default" }
use tool request_access with { "cluster": "prod-us-east-1", "namespace": "default", "reason": "deploy hotfix" }
use tool get_service_endpoints with { "cluster": "prod-us-east-1" }
use tool get_ci_webhook with { "pipeline": "deploy-prod" }
use tool kubeconfig_get with { "cluster": "prod-us-east-1", "namespace": "default", "reason": "read-only debugging" }
```

## Data Collection & Privacy

**Collected**: structured `trap_triggered` log events with salted SHA-256 hashes of identifiers, MCP client identity from the `initialize` handshake.

**Not collected**: kubeconfig content, raw cluster/namespace names, the `reason` parameter, plaintext infrastructure identifiers.

To analyze events, filter Worker logs for `"eventType":"trap_triggered"`.

## Threat Model

- **Actor**: an AI agent (or human using an agent) connected to an MCP tool surface.
- **Goal**: obtain Kubernetes credentials, discover internal service endpoints, or access CI/CD configuration — and use them outside the MCP session.
- **Key assumption**: selecting credential-shaped, infrastructure, or CI/CD tools during autonomous discovery is a high-signal action that distinguishes exploration from legitimate use.

## Operational Security

- Deploy in an **isolated Cloudflare account** and/or dedicated subdomain.
- Only store and serve **decoy** artifacts (never real cluster credentials, endpoints, or webhooks).
- Treat the service as **internet-facing**: monitor access and keep the repo free of secrets.
- Rotate trap artifacts periodically via `./scripts/rotate-traps.sh`.

## Limitations

- Telemetry is emitted to Worker logs; long-term storage depends on your observability pipeline.
- Stage 1 web bug fires only when `CANARY_WEB_BUG_URL` is configured.
- DNS and webhook traps degrade gracefully to placeholder values when their respective secrets are not set.
- Client identity is best-effort: falls back to `unknown` if the MCP client omits `clientInfo`.
- Safe tools return deterministic simulation, not real Kubernetes telemetry.

## Runtime

- Cloudflare Workers with **Durable Object binding** (`MCP_OBJECT`) and SQLite migration.
- `nodejs_compat` enabled (required by the MCP SDK).
- MCP client identity persisted in Durable Object storage across hibernation cycles.
- Dependencies: `@modelcontextprotocol/sdk` `^1.25.2`, `agents` `0.0.100`, `zod` `^3.25.76`.

## Related Work

- **MCP Threat Trap** (original proof-of-concept): [github.com/harshadk99/deception-remote-mcp-server](https://github.com/harshadk99/deception-remote-mcp-server) — single-surface API trap simulating an Okta admin password reset endpoint.
- **OWASP Top 10 for Agentic Applications**: ASI02 (Tool Misuse), ASI03 (Identity Abuse), ASI04 (Supply Chain), ASI05 (Unexpected Execution).

## License

MIT — for educational and research use only.

---

Live example:
[https://k8s-access-portal.harshad-surfer.workers.dev/](https://k8s-access-portal.harshad-surfer.workers.dev/)
