# Kubernetes Access Portal (MCP) — Deception Server (Cloudflare Worker)

![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/security-deception-red)
![Model](https://img.shields.io/badge/MCP-compatible-blueviolet)

A Kubernetes-specific deception server built on Cloudflare Workers and the Model Context Protocol (MCP). It exposes realistic Kubernetes "portal" tooling for MCP clients (Cloudflare AI Playground, Cursor) while embedding high-fidelity detection via a decoy kubeconfig artifact.

## TL;DR

This is the **Kubernetes Access Portal** trap in the **MCP Deception Incubator**: a Cloudflare Worker that exposes an MCP server over **`/sse`** (SSE) and **`/mcp`** (Streamable HTTP) with realistic "internal portal" tooling.

- **Safe tools**: `k8s_access_guide`, `cluster_status_public`
- **Decoy trap**: `kubeconfig_get` issues a short-lived, HMAC-signed download link for a Thinkst Canary kubeconfig YAML stored in Workers KV. It emits hashed telemetry and (optionally) fires a Thinkst web bug with a custom User-Agent that includes the **MCP client identity** (e.g. `cursor/0.45.6`).

## Why It Matters

- **Threat model focus**: catches "helpful agent" misuse where an AI client tries to obtain Kubernetes access (kubeconfig) through MCP tooling.
- **High-signal trap**: `kubeconfig_get` is a credential-shaped action; invoking it is an early indicator of intent to access a cluster.
- **Low-risk telemetry**: emits a structured `trap_triggered` event with salted SHA-256 hashes only (no kubeconfig content, no raw identifiers).
- **Two-stage detection**: optional Thinkst web bug on invocation (`CANARY_WEB_BUG_URL`) with MCP client identity in User-Agent, plus a stronger Thinkst alert if the returned kubeconfig is actually used with `kubectl` (showing the attacker's real IP and User-Agent).
- **Practical deployment**: runs as a Cloudflare Worker (globally reachable) and speaks MCP over `/sse` and `/mcp` for common clients (Playground/Cursor).

## Security posture (what this project actually does)

- **No secrets in code**: the decoy kubeconfig is stored in Workers KV (never committed, never logged, never stored as a Worker secret).
- **Telemetry is non-sensitive**: emits `trap_triggered` with salted hashes only (no kubeconfig contents).
- **Artifact delivery via signed download link**: `kubeconfig_get` returns an absolute URL with an HMAC-signed, time-limited token (10 min TTL). The `/download/kubeconfig` endpoint serves the KV blob byte-for-byte as `Content-Disposition: attachment`, avoiding UI copy/paste corruption of long base64 fields.
- **MCP client identity capture**: during the MCP `initialize` handshake, `clientInfo` (name + version) is persisted in Durable Object storage and included in the web bug User-Agent (e.g. `client=cursor/0.45.6`).
- **Two-stage detection**:
  - Stage 1: invoking `kubeconfig_get` fires a Thinkst web bug in the background (**only if** `CANARY_WEB_BUG_URL` is configured) and emits a `trap_triggered` log event.
  - Stage 2: using the downloaded kubeconfig with `kubectl` triggers an independent Thinkst alert from the attacker's real machine (different IP, real User-Agent).

## Deploy Your Own

[![Deploy to Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/harshadk99/mcp-deception-incubator-kubernetes)

Or deploy manually:

```bash
npm install
npm run deploy
```

Your MCP server will be deployed to:

```
https://mcp-deception-incubator-kubernetes.<your-account>.workers.dev
```

## Endpoints

| Path | Method | Purpose |
|------|--------|---------|
| `/` | GET | HTML portal page with tool descriptions and Playground link |
| `/sse` | GET | MCP SSE endpoint (AI Playground / Cursor) |
| `/sse/message` | POST | MCP SSE message relay |
| `/mcp` | POST | MCP Streamable HTTP (JSON-RPC) |
| `/download/kubeconfig?t=TOKEN` | GET | Signed kubeconfig file download |

## Tools

- **`k8s_access_guide`** (safe): Returns an internal-style guide for requesting, approving, and auditing Kubernetes access, plus a **non-functional** kubeconfig template (`example.invalid`, token `REDACTED`).
- **`cluster_status_public`** (safe): Returns **deterministic simulated** cluster status for the provided cluster name. Parameters: `cluster` (required).
- **`kubeconfig_get`** (**DECOY**): Returns a short-lived, signed **download link** (absolute URL) for a Thinkst Canary kubeconfig artifact stored in KV, and triggers detection signals.  
  Parameters:
  - `cluster` (required)
  - `namespace` (optional, defaults to `default`)
  - `reason` (optional, accepted but **not used or logged**)
  - `access_key` (optional, required only in gated mode)

## Trap modes (open vs gated)

Two operational profiles for research:

- **Open (default)**: anyone who invokes `kubeconfig_get` receives a download link. Accepts noise to maximize coverage. Stage 1 telemetry + web bug still fires on every call.
- **Gated**: callers must provide an `access_key` matching the `TRAP_ACCESS_KEY` secret to receive the download link. Stage 1 telemetry + web bug still fires even when access is denied.

## Deception model: curiosity vs intent

- **Stage 1 (curiosity / early signal)**: When `kubeconfig_get` is invoked, the Worker:
  - emits a structured telemetry event `trap_triggered` with **salted hashes** of `cluster` and `namespace`
  - fires the Thinkst web bug in the background (**if** `CANARY_WEB_BUG_URL` is configured) with a custom User-Agent:
    ```
    mcp-deception-incubator-kubernetes/1.0 (tool=kubeconfig_get; client=cursor/0.45.6; cluster_hash=a1b2c3d4e5f6; ns_hash=f6e5d4c3b2a1)
    ```
  - returns a short-lived, signed download link for the kubeconfig YAML stored in KV

- **Stage 2 (intent / operational use)**: If an attacker (or AI agent) downloads the kubeconfig and uses `kubectl`, Thinkst Canarytokens fire a second, independent alert **from the attacker's real machine** — with their real IP address and User-Agent (e.g. `kubectl/v1.31.0 (darwin/arm64)`). This is a stronger confirmation of operational intent than simply calling the tool.

## Threat model & assumptions

This trap is designed to study and detect a specific class of behavior:

- **Actor**: an AI agent (or human using an agent) connected to an MCP tool surface.
- **Goal**: obtain Kubernetes credentials (kubeconfig) and attempt to use them outside the MCP session.
- **Key assumption**: requesting a kubeconfig via tooling is a high-signal action compared to general "how do I..." questions.

Out of scope for this repo (today):

- rate limiting or abuse throttling
- persistence of telemetry beyond standard Worker logs (use Cloudflare observability or log sinks)

## Data collection & privacy

What is collected by this Worker:

- a single structured log event on trap activation (`eventType: "trap_triggered"`)
- **only salted SHA-256 hashes** of `cluster` and `namespace` (never raw values)
- MCP client identity (`clientInfo` name + version from the initialize handshake) is persisted in DO storage and included in the web bug User-Agent

What is explicitly **not** collected by this Worker:

- kubeconfig content (never logged)
- the `reason` parameter (not used)

To analyze events, use Cloudflare Worker logs/observability and filter for `"eventType":"trap_triggered"`.

## Suggested research questions & experiments

Because the "safe" tools are non-sensitive and the trap tool is credential-shaped, you can run controlled studies such as:

- **Tool-choice behavior**: do agents attempt `kubeconfig_get` without a formal access workflow?
- **Escalation patterns**: what prompts lead from `k8s_access_guide` to `kubeconfig_get`?
- **Operationalization**: how often does Stage 2 (kubeconfig use) occur after Stage 1 (tool invocation)?
- **Client fingerprinting**: which MCP clients (Cursor, Playground, custom agents) trigger the trap?

Simple metrics you can extract from logs:

- count of `trap_triggered` over time
- unique hashed clusters/namespaces requested (cardinality on hashes)
- MCP client identity distribution (from web bug User-Agent)
- time-to-trigger from initial connection (requires correlating with request logs)

## Limitations (important for security interpretation)

- **No built-in persistence**: telemetry is emitted to Worker logs; long-term storage depends on your logging/observability pipeline.
- **Optional Stage 1 signal**: the web bug fires only when `CANARY_WEB_BUG_URL` is configured.
- **Simulated status**: `cluster_status_public` is deterministic simulation derived from the input string (not real Kubernetes telemetry).
- **Unused parameters**: `reason` is accepted by `kubeconfig_get` but is not used or logged.
- **Client identity is best-effort**: MCP client identity is captured from the `initialize` handshake and persisted in DO storage. If the client doesn't send `clientInfo`, it falls back to `unknown`.

## Operational security / safe deployment

This project is intended for controlled security research and deception engineering.

- Deploy in an **isolated Cloudflare account** and/or dedicated subdomain.
- Only ever store and serve **decoy** kubeconfigs/tokens (never real cluster credentials).
- Treat the service as **internet-facing**: monitor access and keep the repo/config free of secrets.
- If your study involves humans, ensure you have appropriate **authorization and disclosure** for your environment.

## Configuration reference

### Secrets (set via `wrangler secret put`)

| Secret | Required | Purpose |
|--------|----------|---------|
| `TELEMETRY_SALT` | Yes | Salt for SHA-256 hashing of cluster/namespace identifiers |
| `CANARY_WEB_BUG_URL` | Recommended | Thinkst Canary web bug URL for Stage 1 detection |
| `DOWNLOAD_TOKEN_SECRET` | Recommended | HMAC key for signing download tokens (falls back to `TELEMETRY_SALT` if unset) |
| `TRAP_ACCESS_KEY` | Only for gated mode | Access key callers must provide to receive the download link |

### Plain vars (set in `wrangler.jsonc` `vars` or environment)

| Var | Default | Purpose |
|-----|---------|---------|
| `PUBLIC_BASE_URL` | (none) | Base URL for absolute download links in tool responses |
| `TRAP_MODE` | `open` | `open` or `gated` |

### KV binding

| Binding | Key | Purpose |
|---------|-----|---------|
| `KUBECONFIG_KV` | `kubeconfig_yaml` | Thinkst Canary kubeconfig YAML blob |

## Setup steps

1) Create a KV namespace:

```bash
npx wrangler kv namespace create KUBECONFIG_KV
```

2) Put the returned namespace id into `wrangler.jsonc` under `kv_namespaces[0].id` (replace the existing value).

3) Set `PUBLIC_BASE_URL` in `wrangler.jsonc` `vars` to your Worker's public URL.

4) Set required secrets:

```bash
npx wrangler secret put TELEMETRY_SALT
npx wrangler secret put CANARY_WEB_BUG_URL
npx wrangler secret put DOWNLOAD_TOKEN_SECRET
```

5) (Optional, for gated mode) Set trap access key:

```bash
npx wrangler secret put TRAP_ACCESS_KEY
```

6) Upload the kubeconfig YAML value into KV (key: `kubeconfig_yaml`) using either the Cloudflare dashboard KV UI or Wrangler KV commands.

7) Deploy:

```bash
npm run deploy
```

## Reproducible evaluation checklist

1) Deploy the Worker (`npm run deploy`).
2) Configure secrets and KV (see setup steps above).
3) Verify MCP surface:
   ```bash
   ./scripts/compat-smoke.sh <base-url>
   ```
4) Trigger detection (Stage 1):
   - call `kubeconfig_get` via AI Playground or `/mcp`
   - confirm a log event with `"eventType":"trap_triggered"`
   - check Thinkst console for web bug alert with MCP client in User-Agent
5) Trigger detection (Stage 2):
   - download kubeconfig via the signed link returned by the tool
   - run `KUBECONFIG=./kubeconfig.yaml kubectl get ns`
   - confirm Thinkst fires an independent alert from your machine's IP

## Test with curl (manual)

```bash
BASE="https://mcp-deception-incubator-kubernetes.<your-account>.workers.dev"

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

# 3) Call kubeconfig_get (returns download link)
curl -sS "${BASE}/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: ${sid}" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"kubeconfig_get","arguments":{"cluster":"prod-us-east-1","namespace":"default","reason":"demo"}}}'

# 4) Download kubeconfig (use the URL from step 3)
curl -sS -o kubeconfig.yaml '<download URL from step 3>'

# 5) Use it (triggers Stage 2)
KUBECONFIG=./kubeconfig.yaml kubectl get ns
```

## Example prompts (AI Playground)

```
use tool k8s_access_guide with { }
use tool cluster_status_public with { "cluster": "dev-us-east-1" }
use tool kubeconfig_get with { "cluster": "prod-us-east-1", "namespace": "default", "reason": "read-only debugging" }
```

## Connect to Cloudflare AI Playground

1. Go to [https://playground.ai.cloudflare.com](https://playground.ai.cloudflare.com)
2. Enter your MCP endpoint:
   ```
   https://mcp-deception-incubator-kubernetes.<your-account>.workers.dev/sse
   ```

## Compatibility smoke test

After deploying, run:

```bash
./scripts/compat-smoke.sh https://mcp-deception-incubator-kubernetes.<your-account>.workers.dev
```

It verifies:
- GET `/` returns 200
- `/sse` responds (SSE)
- `tools/list` includes `k8s_access_guide`, `cluster_status_public`, `kubeconfig_get`

## Worker runtime notes

- This Worker uses a **Durable Object binding** (`MCP_OBJECT`) with SQLite migration, as configured in `wrangler.jsonc`.
- `nodejs_compat` is enabled (required by the MCP SDK).
- MCP client identity (`clientInfo`) is persisted in Durable Object storage to survive hibernation cycles.
- Dependencies: `@modelcontextprotocol/sdk` `^1.25.2`, `agents` `0.0.100`, `zod` `^3.25.76`.

## Troubleshooting MCP Connectivity

1. **Check SDK Versions**: This repo uses `@modelcontextprotocol/sdk` `^1.25.2` and `agents` `0.0.100`.
2. **Verify Tool Structure**: Tool definitions follow the standard `(name, parameters, handler)` format.
3. **Avoid proxy/header surprises**: If you're putting this behind another proxy, avoid overriding response headers in a way that breaks SSE/streaming.
4. **Test with curl**: Use the manual curl flow above to test endpoints directly.
5. **Check Browser Console**: Look for CORS errors in the browser console.

## License

MIT -- for educational and research use only.

---

Live example:
[https://mcp-deception-incubator-kubernetes.harshad-surfer.workers.dev/](https://mcp-deception-incubator-kubernetes.harshad-surfer.workers.dev/)
