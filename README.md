# 🛡️ Kubernetes Access Portal (MCP) — Deception Server (Cloudflare Worker)

![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/security-deception-red)
![Model](https://img.shields.io/badge/MCP-compatible-blueviolet)

A Kubernetes-specific deception server built on Cloudflare Workers and the Model Context Protocol (MCP). It exposes realistic Kubernetes “portal” tooling for MCP clients (Cloudflare AI Playground, Cursor) while embedding high-fidelity detection via a decoy kubeconfig artifact.

## 🧩 TL;DR

This is the **Kubernetes Access Portal** trap in the **MCP Deception Incubator**: a Cloudflare Worker that exposes an MCP server over **`/sse`** (SSE) and **`/mcp`** (Streamable HTTP) with realistic “internal portal” tooling.

- **Safe tools**: `k8s_access_guide`, `cluster_status_public`
- **Decoy trap**: `kubeconfig_get` returns a Thinkst Canary kubeconfig YAML from Workers KV and emits hashed telemetry (and can optionally trigger a Thinkst web bug via `CANARY_WEB_BUG_URL`)

## 💡 Why It Matters

- 🎯 **Threat model focus**: catches “helpful agent” misuse where an AI client tries to obtain Kubernetes access (kubeconfig) through MCP tooling.
- 🧲 **High-signal trap**: `kubeconfig_get` is a credential-shaped action; invoking it is an early indicator of intent to access a cluster.
- 🪵 **Low-risk telemetry**: emits a structured `trap_triggered` event with salted hashes only (no kubeconfig content, no raw identifiers).
- 🕸️ **Two-stage detection**: optional Thinkst web bug on invocation (`CANARY_WEB_BUG_URL`), plus a stronger Thinkst alert if the returned kubeconfig is actually used with `kubectl`.
- 🌍 **Practical deployment**: runs as a Cloudflare Worker (globally reachable) and speaks MCP over `/sse` and `/mcp` for common clients (Playground/Cursor).

## 🔐 Security posture (what this project actually does)

- **No secrets in code**: the decoy kubeconfig is stored in Workers KV (never committed, never logged, never stored as a Worker secret)
- **Telemetry is non-sensitive**: emits `trap_triggered` with salted hashes only (no kubeconfig contents)
- **Two-stage detection**:
  - Stage 1: invoking `kubeconfig_get` triggers a Thinkst web bug in the background (**only if** `CANARY_WEB_BUG_URL` is configured)
  - Stage 2: using the returned kubeconfig with `kubectl` triggers an independent Thinkst alert

## 🚀 Deploy Your Own

[![Deploy to Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/harshadk99/mcp-deception-incubator-kubernetes)

Or deploy manually:

```bash
# Install dependencies
npm install

# Deploy to Cloudflare Workers
npm run deploy
```

Your MCP server will be deployed to:

```
https://mcp-deception-incubator-kubernetes.<your-account>.workers.dev
```

## 🔧 Tools

- **`k8s_access_guide`** (real / safe): Returns an internal-style guide for requesting, approving, and auditing Kubernetes access, plus a **non-functional** kubeconfig template (`example.invalid`, token `REDACTED`).
- **`cluster_status_public`** (real / safe): Returns **simulated** (deterministic) cluster status for the provided cluster name.
- **`kubeconfig_get`** (**DECOY**): Returns a Thinkst Canary kubeconfig YAML loaded from KV (not committed) and triggers detection signals.  
  Notes:
  - `namespace` defaults to `default`
  - `reason` is accepted by the tool interface but is not used or logged by this Worker

## 📡 Connect via MCP SSE

Use this MCP server URL in Cloudflare AI Playground / Cursor MCP:

```
https://mcp-deception-incubator-kubernetes.<your-account>.workers.dev/sse
```

Under the hood, the Worker also serves the MCP SSE message endpoint at:

```
https://mcp-deception-incubator-kubernetes.<your-account>.workers.dev/sse/message
```

## 🧪 Compatibility smoke test

After deploying, run:

```bash
./scripts/compat-smoke.sh https://mcp-deception-incubator-kubernetes.<your-account>.workers.dev
```

It verifies:
- GET `/` returns 200
- `/sse` responds (SSE)
- `tools/list` includes `k8s_access_guide`, `cluster_status_public`, `kubeconfig_get`

## 🧪 Test It with curl (manual)

```bash
# MCP Streamable HTTP requires initialize first, then send the returned mcp-session-id header.
BASE="https://mcp-deception-incubator-kubernetes.<your-account>.workers.dev"

sid="$(
  curl -sS -D - "${BASE}/mcp" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"0.0.0"}}}' \
  | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}' | tr -d '\r' | head -n 1
)"

curl -sS "${BASE}/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: ${sid}" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# SSE endpoint (Playground uses this)
curl -N -H "Accept: text/event-stream" https://mcp-deception-incubator-kubernetes.<your-account>.workers.dev/sse
```

## 🧠 Example prompts (AI Playground)

```
use tool k8s_access_guide with { }
use tool cluster_status_public with { "cluster": "dev-us-east-1" }
use tool kubeconfig_get with { "cluster": "prod-us-east-1", "namespace": "default", "reason": "read-only debugging" }
```

## 🎭 Deception model: curiosity vs intent

- **Stage 1 (curiosity / early signal)**: When `kubeconfig_get` is invoked, the Worker:
  - returns the kubeconfig YAML from KV
  - triggers the Thinkst web bug in the background via `ctx.waitUntil(fetch(...))` **if** `CANARY_WEB_BUG_URL` is configured
  - emits a structured telemetry event `trap_triggered` with **salted hashes** of `cluster` and `namespace`

- **Stage 2 (intent / operational use)**: If an attacker (or AI agent) tries to actually use `kubectl` with the returned kubeconfig, Thinkst Canarytokens will fire a second, independent alert. This is a stronger confirmation of operational intent than simply calling the tool.

## 🧪 Threat model & assumptions (research-oriented)

This trap is designed to study and detect a specific class of behavior:

- **Actor**: an AI agent (or human using an agent) connected to an MCP tool surface.
- **Goal**: obtain Kubernetes credentials (kubeconfig) and attempt to use them outside the MCP session.
- **Key assumption**: requesting a kubeconfig via tooling is a high-signal action compared to general “how do I…” questions.

Out of scope for this repo (today):

- preventing access (no access control / allowlisting)
- rate limiting or abuse throttling
- persistence of telemetry beyond standard Worker logs

## 📊 Data collection & privacy

What is collected by this Worker:

- a single structured log event on trap activation (`eventType: "trap_triggered"`)
- **only salted SHA-256 hashes** of `cluster` and `namespace` (never raw values)

What is explicitly not collected by this Worker:

- kubeconfig content (never logged)
- the `reason` parameter (not used)

To analyze events, use Cloudflare Worker logs/observability for the deployed service and filter for `eventType":"trap_triggered"`.

## 🧫 Suggested research questions & experiments

Because the “safe” tools are non-sensitive and the trap tool is credential-shaped, you can run controlled studies such as:

- **Tool-choice behavior**: do agents attempt `kubeconfig_get` without a formal access workflow?
- **Escalation patterns**: what prompts lead from `k8s_access_guide` → `kubeconfig_get`?
- **Operationalization**: how often does Stage 2 (kubeconfig use) occur after Stage 1 (tool invocation)?

Simple metrics you can extract from logs:

- count of `trap_triggered` over time
- unique hashed clusters/namespaces requested (cardinality on hashes)
- time-to-trigger from initial connection (requires correlating with request logs)

## ⚠️ Limitations (important for security interpretation)

- **Not access control**: this is a detection/deception surface, not a gate. There is no allowlist/authz layer in this repo.
- **No built-in persistence**: telemetry is emitted to Worker logs; long-term storage/analysis depends on your logging/observability pipeline.
- **Optional Stage 1 signal**: the web bug fires only when `CANARY_WEB_BUG_URL` is configured.
- **Simulated status**: `cluster_status_public` is deterministic simulation derived from the input string (not real Kubernetes telemetry).
- **Parameters**: `reason` is accepted by `kubeconfig_get` but is not used or logged by this Worker.

## 🛡️ Operational security / safe deployment

This project is intended for controlled security research and deception engineering.

- Deploy in an **isolated Cloudflare account** and/or dedicated subdomain.
- Only ever store and serve **decoy** kubeconfigs/tokens (never real cluster credentials).
- Treat the service as **internet-facing**: monitor access and keep the repo/config free of secrets.
- If your study involves humans, ensure you have appropriate **authorization and disclosure** for your environment.

## ✅ Reproducible evaluation checklist (security-centric)

1) Deploy the Worker (`npm run deploy`).
2) Configure:
   - `TELEMETRY_SALT` (required for hashing)
   - KV binding `KUBECONFIG_KV` + key `kubeconfig_yaml` (required for the decoy artifact)
   - `CANARY_WEB_BUG_URL` (optional Stage 1 signal)
3) Verify MCP surface:
   - run `./scripts/compat-smoke.sh <base-url>`
4) Trigger detection (Stage 1):
   - call the MCP tool `kubeconfig_get` and confirm a log event with `eventType":"trap_triggered"`
5) (Optional) Trigger detection (Stage 2):
   - use the returned kubeconfig with `kubectl` and confirm your Thinkst token alerting path works end-to-end

## 🗄️ Kubeconfig storage (KV) — required

**Do NOT** store the real kubeconfig in source control or in Worker secrets.

This project uses **Workers KV** to store the Thinkst kubeconfig YAML under key:

```
kubeconfig_yaml
```

### Setup steps

1) Create a KV namespace:

```bash
npx wrangler kv namespace create KUBECONFIG_KV
```

2) Put the returned namespace id into `wrangler.jsonc` under `kv_namespaces[0].id` (replace the existing value in this repo).

3) Set the telemetry salt (used only to hash identifiers):

```bash
npx wrangler secret put TELEMETRY_SALT
```

4) Set the Thinkst Canary web bug URL (recommended, especially if your GitHub repo is public):

```bash
npx wrangler secret put CANARY_WEB_BUG_URL
```

5) Upload the kubeconfig YAML value into KV (key: `kubeconfig_yaml`) using either the Cloudflare dashboard KV UI or Wrangler KV commands.

## 🔁 Deploy from GitHub (Cloudflare “Option A”)

This is the recommended setup to keep your Worker automatically deploying from your GitHub repo.

### 1) Push this project to GitHub

- Create an **empty** GitHub repo (no README/License template).
- Push this folder as the repo root.

### 2) Connect Cloudflare Workers to GitHub

In the Cloudflare dashboard:

- Workers & Pages → Workers → **`mcp-deception-incubator-kubernetes`**
- Go to **Deployments** (or **Builds**) → **Connect to Git**
- Select your repo + main branch
- Build command: `npm ci`
- Deploy command: `npm run deploy`

### 3) Configure secrets (Cloudflare, not GitHub)

Set these secrets in Cloudflare for the Worker:

- `TELEMETRY_SALT`
- `CANARY_WEB_BUG_URL`

### 4) Configure KV value (Cloudflare, not GitHub)

Ensure KV binding exists (`KUBECONFIG_KV` in `wrangler.jsonc`) and store:

- key: `kubeconfig_yaml`
- value: Thinkst kubeconfig YAML

### KV vs R2 (tradeoffs)

- **KV**: simplest to wire for “single blob” text storage, fast global reads; ideal for this decoy artifact.
- **R2**: better for larger artifacts and versioning workflows; more moving parts for simple key/value retrieval.

## 🔍 Troubleshooting MCP Connectivity

If you're having trouble connecting to your MCP server from Cloudflare AI Playground or other clients:

1. **Check SDK Versions**: This repo uses `@modelcontextprotocol/sdk` `^1.25.2` and `agents` `0.0.100`.
2. **Verify Tool Structure**: Make sure your tool definitions follow the standard format: `(name, parameters, handler)`
3. **Avoid proxy/header surprises**: If you’re putting this behind another proxy, avoid overriding response headers in a way that breaks SSE/streaming.
4. **Test with curl**: Use curl to test your endpoints directly
5. **Check Browser Console**: Look for CORS errors or other issues in the browser console

## 📡 Connect to Cloudflare AI Playground

1. Go to [https://playground.ai.cloudflare.com](https://playground.ai.cloudflare.com)
2. Enter your MCP endpoint:

   ```
   https://mcp-deception-incubator-kubernetes.<your-account>.workers.dev/sse
   ```

## 🔍 How It Works

1. **Honeypot Setup**: Deploys as a Cloudflare Worker with MCP and REST endpoints
2. **Deception Layer**: Presents as legitimate internal portal tooling (guide + simulated status)
3. **Detection Mechanism**: When `kubeconfig_get` is invoked, it emits hashed telemetry and can optionally trigger a Thinkst web bug
4. **SSE Communication**: Uses Server-Sent Events for real-time MCP protocol communication

## 🧱 Worker runtime notes

- This Worker uses a **Durable Object binding** (`MCP_OBJECT`) as configured in `wrangler.jsonc`.
- It also enables `nodejs_compat` (see `wrangler.jsonc`).

## 🧠 Try These MCP Tool Prompts

Test out tools using Cloudflare's AI Playground or any MCP-compatible interface:
### ✅ Current tools

```
use tool k8s_access_guide with { }
use tool cluster_status_public with { "cluster": "dev-us-east-1" }
use tool kubeconfig_get with { "cluster": "prod-us-east-1", "namespace": "default", "reason": "read-only debugging" }
```

## 📊 Notes

- This README intentionally documents current behavior. A detailed changelog is not maintained here.

## 🛡️ Future Security Enhancements

Security notes: This project intentionally behaves like an internal portal. Keep it isolated to a test domain/account and monitor alerts from the Thinkst tokens.

## 📄 License

MIT – for educational and research use only.

---

🔗 Live example:
[https://mcp-deception-incubator-kubernetes.harshad-surfer.workers.dev/](https://mcp-deception-incubator-kubernetes.harshad-surfer.workers.dev/)



