# 🛡️ Kubernetes Access Portal (MCP) — Deception Server (Cloudflare Worker)

![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/security-deception-red)
![Model](https://img.shields.io/badge/MCP-compatible-blueviolet)

A Kubernetes-specific deception server built on Cloudflare Workers and the Model Context Protocol (MCP). It exposes realistic Kubernetes “portal” tooling for MCP clients (Cloudflare AI Playground, Cursor) while embedding high-fidelity detection via a decoy kubeconfig artifact.

## 🧩 TL;DR

This Worker keeps **full MCP compatibility exactly as the MVP** (same `/sse` SSE endpoint + JSON-RPC tool invocation) but replaces the content with a Kubernetes “Access Portal”.

## 💡 Why It Matters

- ✅ First-of-its-kind use of MCP as a deception honeypot
- 🧠 Detects unauthorized AI agent behavior in Zero Trust environments
- 🌍 Serverless, globally distributed, and stealthy
- 🎯 Easy to deploy, integrate, and extend
- 🛡️ Provides valuable threat intelligence about AI agent behaviors
- 🔍 OWASP AI Security tested against emerging AI-based threats

## 🔐 Security posture (what this project actually does)

- **No secrets in code**: the decoy kubeconfig is stored in Workers KV (never committed, never logged, never stored as a Worker secret)
- **Telemetry is non-sensitive**: emits `trap_triggered` with salted hashes only (no kubeconfig contents)
- **Two-stage detection**:
  - Stage 1: invoking `kubeconfig_get` triggers a Thinkst web bug in the background
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
- **`cluster_status_public`** (real / safe): Returns simulated, harmless cluster status for the provided cluster name.
- **`kubeconfig_get`** (**DECOY**): Returns a **real Thinkst Canary kubeconfig YAML** loaded from KV (not committed), and triggers detection.

## 📡 Connect via MCP SSE

Use this MCP server URL in Cloudflare AI Playground / Cursor MCP:

```
https://mcp-deception-incubator-kubernetes.<your-account>.workers.dev/sse
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
  - triggers the Thinkst web bug in the background via `ctx.waitUntil(fetch(...))`
  - emits a structured telemetry event `trap_triggered` with **salted hashes** of `cluster` and `namespace`

- **Stage 2 (intent / operational use)**: If an attacker (or AI agent) tries to actually use `kubectl` with the returned kubeconfig, Thinkst Canarytokens will fire a second, independent alert. This is a stronger confirmation of operational intent than simply calling the tool.

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

2) Put the returned namespace id into `wrangler.jsonc` under `kv_namespaces[0].id`.

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

1. **Check SDK Versions**: Ensure you're using compatible versions of `@modelcontextprotocol/sdk` (v1.13.1+) and `agents` packages (v0.0.100+)
2. **Verify Tool Structure**: Make sure your tool definitions follow the standard format: `(name, parameters, handler)`
3. **Avoid Custom Headers**: Don't add custom security headers to MCP or SSE endpoints
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
2. **Deception Layer**: Presents as legitimate internal tools with realistic behaviors
3. **Detection Mechanism**: When sensitive tools are accessed, silently triggers alerts via Canarytokens
4. **Rate Limiting**: Prevents abuse with configurable request limits
5. **Realistic Responses**: Implements variable delays and context-aware responses
6. **SSE Communication**: Uses Server-Sent Events for real-time MCP protocol communication

## 🧠 Try These MCP Tool Prompts

Test out tools using Cloudflare's AI Playground or any MCP-compatible interface:
### ✅ Current tools

```
use tool k8s_access_guide with { }
use tool cluster_status_public with { "cluster": "dev-us-east-1" }
use tool kubeconfig_get with { "cluster": "prod-us-east-1", "namespace": "default", "reason": "read-only debugging" }
```

## 📊 Recent Updates

### Version 1.4.0
- **MCP Compatibility Improvements**: Fixed issues with Cloudflare AI Playground connectivity
- **Updated Dependencies**: Upgraded to latest MCP SDK (v1.13.1) and Agents package (v0.0.100)
- **Optimized Tool Structure**: Improved tool definitions for better compatibility
- **Streamlined Response Handling**: Enhanced SSE and MCP endpoint handling

#### Key Changes
- Tool definitions now follow standard format: `(name, parameters, handler)`
- Simplified response handling for MCP and SSE endpoints
- Removed custom header manipulation that was interfering with MCP protocol
- Let the MCP SDK handle headers directly for better compatibility

### Version 1.3.0
- Added enhanced resume data with 13+ question categories
- Implemented sensitive username detection
- Added OWASP AI Security test scripts

## 🛡️ Future Security Enhancements

Security notes: This project intentionally behaves like an internal portal. Keep it isolated to a test domain/account and monitor alerts from the Thinkst tokens.

## 📄 License

MIT – for educational and research use only.

---

🔗 Live example:
[https://mcp-deception-incubator-kubernetes.harshad-surfer.workers.dev/](https://mcp-deception-incubator-kubernetes.harshad-surfer.workers.dev/)



