<h1 align="center">tiptoe</h1>

<h4 align="center">Shadow AI/ML discovery for Cisco-managed enterprise networks.</h4>

<p align="center">
  <a href="https://github.com/sshpie/tiptoe/releases"><img src="https://img.shields.io/github/v/release/sshpie/tiptoe?style=flat-square" alt="release"></a>
  <a href="https://github.com/sshpie/tiptoe/blob/main/LICENSE"><img src="https://img.shields.io/github/license/sshpie/tiptoe?style=flat-square" alt="license"></a>
  <a href="https://golang.org"><img src="https://img.shields.io/badge/go-1.22%2B-00ADD8?style=flat-square&logo=go" alt="go"></a>
  <a href="https://developer.cisco.com/codeexchange/github/repo/sshpie/tiptoe"><img src="https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg" alt="published on Code Exchange"></a>
</p>

<p align="center">
  <a href="#problem">Problem</a> •
  <a href="#cisco-integration">Cisco Integration</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#pacer-design">Pacer Design</a> •
  <a href="#output">Output</a>
</p>

---

## Problem

AI/ML services are being deployed on enterprise networks without the knowledge of network or security teams. Employees spin up LLM inference servers, vector databases, and model registries on managed devices — often with no authentication. These services expose sensitive data, accept arbitrary prompt input, and create lateral movement paths that existing vulnerability scanners do not detect.

Traditional scanners applied to a single monitored host generate a recognizable scan signature. An IPS flags the source and every tool that follows sees a dark host. Security teams get false negatives presented as findings.

tiptoe is the quiet alternative. It integrates with **Cisco Catalyst Center** to pull managed device inventory, assesses each device below IPS detection thresholds, correlates findings with **ThousandEyes** application health via the Meraki assurance API, and pushes results to **Cisco XDR** and **Cisco Webex**.

---

## Cisco Integration

```
Catalyst Center
  managed device inventory
          |
          v
   tiptoe catalog
          |
          +-- per device ------------------------------------------+
          |   passive intel: Shodan, DNS, CT logs (zero packets)   |
          |   serial active probing: congestion-controlled pacer   |
          |   block detection: halts when host goes silent         |
          +--------------------------------------------------------+
          |
          +-- VERIFIED_UNAUTH findings (50+ platforms: Ollama, Qdrant, MLflow, LangFlow, ...)
          |   labeled with Cisco AI Taxonomy IDs (OB/AITech/AISubtech)
          |
          +-- Catalyst Center        tag device "shadow-ai-detected"
          +-- Cisco Secure Access    add IP to SSE blocked destination list (IP-layer)
          +-- Cisco Umbrella         add IP to DNS block list (DNS-layer)
          +-- Cisco Secure Endpoint  look up managed endpoint; optional isolation
          +-- Cisco ISE              apply ANC quarantine policy (VLAN-layer)
          +-- ThousandEyes           correlate degraded app scores (score < 70)
          |   provision TE agent on eligible Meraki networks
          +-- Cisco XDR              CTIM sighting bundle (IP + services + taxonomy)
          +-- Webex                  per-device alert + catalog summary
          |   MCP: https://mcp.webexapis.com/mcp/webex-messaging (agent-native)
```

### Catalyst Center

tiptoe pulls the full managed device inventory (`GET /dna/intent/api/v1/network-device`) and assesses each management IP. When AI/ML services are found, it creates or updates a `shadow-ai-detected` tag on the device (`POST /dna/intent/api/v2/tag`).

```bash
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token YOUR_TOKEN
```

### Cisco XDR

Verified findings are submitted as CTIM sighting bundles via OAuth2 client credentials. Each sighting carries the IP observable and a service list so XDR can correlate the finding with other telemetry sources.

```bash
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token YOUR_TOKEN \
  --xdr-client-id CLIENT_ID \
  --xdr-client-secret CLIENT_SECRET \
  --xdr-region us
```

### Cisco Webex

Per-device alerts and a full catalog summary post to any Webex room.

```bash
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token YOUR_TOKEN \
  --webex-token BOT_TOKEN \
  --webex-room ROOM_ID
```

### ThousandEyes (via Meraki Assurance API)

When shadow AI is found on a device, tiptoe:

1. **Correlates** — queries `GET /api/v1/organizations/{orgId}/assurance/thousandEyes/applications`
   and reports any applications with a health score below 70, turning a theoretical finding into
   a quantified business impact (impacted client count, score delta, active alerts).

2. **Provisions** — calls `GET /organizations/{orgId}/extensions/thousandEyes/networks/supported`
   to identify which Meraki networks are eligible for ThousandEyes agent activation, then
   provisions an agent (`POST /organizations/{orgId}/extensions/thousandEyes/networks`) on each
   eligible network. Shadow AI found = monitoring activated immediately, in the same run.

```bash
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN \
  --meraki-api-key MERAKI_API_KEY \
  --meraki-org-id ORG_ID \
  --meraki-network-ids N_abc123,N_def456 \
  --webex-token BOT_TOKEN \
  --webex-room ROOM_ID
```

### Cisco AI Taxonomy

Every verified finding is classified against the
[Cisco AI Taxonomy Navigator v1.0.0](https://learn-cloudsecurity.cisco.com/ai-security-framework)
and annotated with the matching Objective/Technique/Subtechnique ID.

| Service detected | Taxonomy mapping |
|---|---|
| Ollama, vLLM, LiteLLM | `OB-018/AISubtech-18.2.2` — Dedicated Malicious Server |
| Qdrant, Chroma, Weaviate | `OB-018/AISubtech-18.2.1` — Abuse of APIs for Mass Automation |
| MLflow, BentoML | `OB-018/AITech-18.1` — Fraudulent Use |
| LangFlow, Flowise, Dify | `OB-001/AITech-1.2` — Indirect Prompt Injection |
| MCP servers | `OB-001/AITech-1.2` + `OB-018/AISubtech-18.2.1` |

Taxonomy labels appear in the terminal output, the Webex alert, and the XDR CTIM sighting.

Example output when shadow AI and application degradation are correlated:

```
[!] shadow AI/ML: ollama :11434 [VERIFIED_UNAUTH], qdrant :6333 [VERIFIED_UNAUTH]
[*] Cisco AI Taxonomy: [OB-018/AISubtech-18.2.2, OB-018/AISubtech-18.2.1]
[+] catalyst: tagged device
[+] thousandeyes: agent activated on network N_abc123
[!] thousandeyes: degraded apps on same network:
      Microsoft 365 (score 42, -18) — 37 client(s) impacted; alerts: High packet loss to O365 endpoints
      Zoom (score 61, -9) — 14 client(s) impacted
```

---

### Cisco Secure Access (SSE)

When shadow AI is found, tiptoe adds the server's IP to a `shadow-ai-detected` blocked
destination list in Cisco Secure Access via the
[Destination Lists API](https://developer.cisco.com/docs/cloud-security/)
(`POST /policies/v2/destinationlists/{id}/destinations`).
The list is created automatically if it doesn't exist (`bundleTypeId: 2`, `access: "block"`).

This enforces network-layer containment on all managed endpoints routed through the SSE —
no per-device config change required. The block propagates within SSE policy enforcement time.

```bash
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN \
  --sse-client-id SSE_CLIENT_ID \
  --sse-client-secret SSE_CLIENT_SECRET
```

Required OAuth2 scope: `policies.destinationLists:write`.

---

### Cisco Umbrella (DNS-layer)

When shadow AI is found, tiptoe adds the server's IP to a `shadow-ai-detected` block list
in Cisco Umbrella via the [Policies API v2](https://developer.cisco.com/docs/cloud-security/)
(`POST /organizations/{orgId}/destinationlists/{id}/destinations`).

Umbrella blocks DNS queries to the IP before a TCP connection can form — complementary to
SSE's IP-layer blocking. Together they cover: DNS resolution (Umbrella) + packet forwarding (SSE).

```bash
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN \
  --umbrella-client-id CLIENT_ID \
  --umbrella-client-secret CLIENT_SECRET
```

---

### Cisco Secure Endpoint

When shadow AI is found, tiptoe queries the Secure Endpoint API v3 for the managed endpoint
connector installed on the device (`GET /computers?internal_ip={ip}`). With `--amp-isolate`,
it triggers network isolation on the connector (`PUT /computers/{guid}/isolation`).

Isolation severs the device's network access while keeping the connector connected to the
Secure Endpoint cloud — the endpoint remains manageable and can be remediated remotely.

```bash
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN \
  --amp-client-id AMP_CLIENT_ID \
  --amp-api-key AMP_API_KEY \
  --amp-cloud nam \
  --amp-isolate
```

Cloud regions: `nam` (default) | `eu` | `apjc`

---

### Cisco ISE (Identity-layer quarantine)

When shadow AI is found, tiptoe applies an ANC (Adaptive Network Control) quarantine policy
to the endpoint via the [ISE ERS API](https://developer.cisco.com/docs/identity-services-engine/)
(`POST /ers/config/ancendpoint/apply`).

ISE re-routes the device through a restricted VLAN and can require re-authentication before
network access is restored. Create the policy (`shadow-ai-quarantine`) in ISE under
Policy > Policy Elements > ANC Policies before use.

```bash
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN \
  --ise-url https://ise.corp.example.com:9060 \
  --ise-user admin \
  --ise-pass PASSWORD \
  --ise-policy shadow-ai-quarantine
```

Required: ISE ERS API enabled; ERS admin role; ANC policy named to match `--ise-policy`.

---

### Cisco Secure Network Analytics (Stealthwatch)

When shadow AI is confirmed on an IP, tiptoe queries SNA for all flows TO that IP
in the previous 60 minutes. Flow data turns a "service is listening" finding into a
"service is actively used" finding with client count and byte volume.

```bash
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN \
  --sna-host sna.corp.example.com \
  --sna-user admin \
  --sna-pass PASSWORD \
  --sna-tenant-id 1234
```

Also queries the SNA security events API for any anomalies already flagged on the host.
Requires SNA v7.0.0 or later. TLS certificate verification is skipped to match SNA's
typical self-signed deployment.

---

### Cisco NSO (RESTCONF — ACL-layer containment)

When shadow AI is found, tiptoe pushes a `deny ip any host {shadowAI-IP}` ACL rule to
every NSO-managed device via RESTCONF. This enforces containment at the network device
level — below SSE (IP-layer) and Umbrella (DNS-layer).

```bash
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN \
  --nso-host nso.corp.example.com \
  --nso-port 8080 \
  --nso-user admin \
  --nso-pass PASSWORD \
  --nso-acl shadow-ai-block
```

The named ACL (`--nso-acl`, default `shadow-ai-block`) must already exist on each device.
NSO RESTCONF base: `http://{host}:8080/restconf` (HTTPS: port 8443).
YANG path: `.../config/tailf-ned-cisco-ios:ip/access-list/extended={acl}`.

---

### Cisco AI Defense (Supply Chain Scanning)

When tiptoe finds an unauth MCP server (family: `agent-platform`) it registers it with
[Cisco AI Defense](https://developer.cisco.com/docs/ai-defense-management/) for automated
supply chain scanning — checking the server's tools, exposed capabilities, and dependencies
for prompt injection vulnerabilities, unsafe tool definitions, and known supply chain risks.

```bash
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN \
  --aidefense-key YOUR_MANAGEMENT_API_KEY
```

Obtain the key in the AI Defense UI under **Administration > API Keys**. This is the Management
API key — separate from the Inspection API key. After scan completion, query findings:

```
GET https://api.security.cisco.com/api/ai-defense/v1/mcp/servers?severity=HIGH&severity=CRITICAL
```

Runtime enforcement events (blocked prompt injection, data leakage):

```
POST /events  {"resource_types": ["MCP_SERVER"], "event_action": "Block"}
```

---

### Cisco Webex

Per-device findings post as **Adaptive Cards** with structured fact sets and action buttons.
Catalog summaries and follow-up containment actions are threaded under each finding card
so the room stays readable.

```bash
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN \
  --webex-token BOT_TOKEN \
  --webex-room ROOM_ID
```

If `--webex-room` is omitted, tiptoe calls `GET /rooms` to find (or creates) a
`tiptoe-alerts` space automatically.

**Card format** — each finding posts:
- Header: "Shadow AI Detected" with host, IP, platform, family, port, auth status
- Two action buttons: **Acknowledge** and **Isolate** (`Action.Submit`)
- Fallback markdown for clients without card support

**Action webhooks** — register once with `RegisterActionWebhook(targetURL)`:

```
POST https://webexapis.com/v1/webhooks
  resource: attachmentActions
  event:    created
```

The webhook fires when a button is clicked. The notification carries no payload
(encrypted). Retrieve the submitted data with `GET /v1/attachment/actions/{id}`.

**Thread replies** — after ISE ANC or Secure Endpoint isolation completes, tiptoe
threads a status reply to the original card with the result, keeping the room clean.

**MCP server** — the bot token is valid for the
[Webex Messaging MCP Server](https://developer.webex.com/mcp/docs/messaging-mcp-server)
(`https://mcp.webexapis.com/mcp/webex-messaging`). Any MCP-enabled agent (Claude Code,
LangGraph, AutoGen) can receive and act on tiptoe findings without a separate integration.

Required OAuth scopes: `spark:messages_write`, `spark:rooms_read`, `spark:rooms_write`,
`spark:webhooks_read`, `spark:webhooks_write`. Add `spark:mcp` when routing through the
MCP server.

---

## Features

- Single Go binary, standard library only, Go 1.22 or later
- **50+ platform fingerprints** — derived from the NuClide tome corpus (339 AI/ML platforms); inference servers, vector DBs, agent platforms, document processors, model registries
- **Cisco Catalyst Center** — pull device inventory, push shadow-AI tags
- **Cisco AI Taxonomy** — every finding labeled with OB/AITech/AISubtech IDs from Cisco's AI Taxonomy Navigator v1.0.0
- **Cisco Secure Access (SSE)** — blocks shadow AI IPs in the SSE destination list (IP-layer containment)
- **Cisco Umbrella** — blocks shadow AI IPs in the Umbrella DNS block list (DNS-layer containment)
- **Cisco Secure Endpoint** — looks up the managed connector by IP; optional endpoint isolation
- **Cisco ISE** — applies ANC quarantine policy (identity/VLAN-layer containment)
- **Cisco AI Defense** — registers detected MCP servers for supply chain scanning (prompt injection, unsafe tool definitions, dependency risks); queries runtime enforcement events
- **Cisco Secure Network Analytics** — queries flows to shadow AI IPs to confirm active usage and quantify client count + byte volume; queries security events already flagged by SNA
- **Cisco NSO (RESTCONF)** — pushes `deny ip any host {ip}` ACL rules to all NSO-managed devices; 5th containment layer at the network device level
- **ThousandEyes** — correlates degraded app scores via Meraki assurance API; provisions TE agents on eligible networks when shadow AI is found
- **Cisco XDR** — CTIM sighting bundle submission via OAuth2
- **Cisco Webex** — Adaptive Card findings with Acknowledge/Isolate action buttons; threaded follow-up for containment results; auto-provision room; bot token valid for Webex Messaging MCP Server
- **Tome-backed port knowledge** — `DefaultPorts()` returns the union of canonical AI/ML ports; used as probe fallback when Shodan has no cached record
- Passive phase sends the host zero packets (Shodan host API, reverse DNS, crt.sh)
- Serial active probing — never parallel, never a port scan signature
- Congestion-controlled pacer: TCP Vegas delay-gradient backoff + TCP Reno multiplicative decrease
- Block detection: when a host goes silent after answering, tiptoe stops and says why
- Per-probe pacer trace in the report (measured RTT, baseline, phi, decision)
- Noise budget readout: connection count and peak rate vs. portscan-detection estimate
- JSON output for `visorlog ingest` or any downstream stage

---

## Installation

```bash
go install github.com/sshpie/tiptoe@latest
```

Or build from source:

```bash
git clone https://github.com/sshpie/tiptoe
cd tiptoe
go build -o tiptoe .
```

Requires Go 1.22 or later. Standard library only — no external dependencies.

---

## Usage

### Catalog mode — scan all managed devices

```bash
# Pull inventory from Catalyst Center, assess each device
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN

# Full Cisco integration: Catalyst Center + XDR + Webex
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN \
  --xdr-client-id ID \
  --xdr-client-secret SECRET \
  --webex-token BOT_TOKEN \
  --webex-room ROOM_ID

# Lab deployment with self-signed certificate
tiptoe catalog \
  --catalyst-url https://192.0.2.10 \
  --catalyst-token TOKEN \
  --catalyst-skip-tls
```

### Single-host mode

```bash
# Passive intel + paced active probing
tiptoe assess 10.0.0.1

# Probe a specific port set and submit finding to XDR
tiptoe assess 10.0.0.1 --ports 8000,11434,6333 \
  --xdr-client-id ID --xdr-client-secret SECRET

# Machine-readable output for downstream tooling
tiptoe assess 10.0.0.1 --json

# Passive only — zero packets to the host
tiptoe passive lab.example.edu
```

### All flags

```
catalog flags:
  --catalyst-url <url>         Catalyst Center base URL (required)
  --catalyst-token <token>     Catalyst Center X-Auth-Token (required)
  --catalyst-skip-tls          skip TLS verification (lab/self-signed certs)
  --ports <csv>                ports to probe per device (default: passive intel → tome)
  --timeout <dur>              per-probe timeout (default 10s)

  --xdr-client-id <id>         Cisco XDR OAuth2 client ID
  --xdr-client-secret <s>      Cisco XDR OAuth2 client secret
  --xdr-region <r>             us (default) | eu | apjc

  --webex-token <token>        Webex bot bearer token
  --webex-room <id>            Webex room ID

  --meraki-api-key <key>       Meraki Dashboard API key (ThousandEyes)
  --meraki-org-id <id>         Meraki organization ID
  --meraki-network-ids <csv>   Meraki network IDs to correlate

  --sse-client-id <id>         Cisco Secure Access OAuth2 client ID
  --sse-client-secret <s>      Cisco Secure Access OAuth2 client secret

  --umbrella-client-id <id>    Cisco Umbrella OAuth2 client ID
  --umbrella-client-secret <s> Cisco Umbrella OAuth2 client secret

  --amp-client-id <id>         Cisco Secure Endpoint API client ID
  --amp-api-key <key>          Cisco Secure Endpoint API key
  --amp-cloud <cloud>          nam (default) | eu | apjc
  --amp-isolate                isolate endpoints where shadow AI is found

  --ise-url <url>              Cisco ISE ERS base URL (e.g. https://ise.corp:9060)
  --ise-user <user>            ISE ERS username
  --ise-pass <pass>            ISE ERS password
  --ise-policy <name>          ANC policy name to apply (default: shadow-ai-quarantine)

assess flags:
  --ports <csv>                ports to probe (default: passive intel → tome)
  --timeout <dur>              per-probe timeout (default 10s)
  --json                       machine-readable output
  --passive-only               skip the active phase
  --xdr-client-id <id>         Cisco XDR client ID
  --xdr-client-secret <s>      Cisco XDR client secret
  --xdr-region <r>             us | eu | apjc (default us)
  --webex-token <token>        Webex bot bearer token
  --webex-room <id>            Webex room ID
```

---

## Pacer Design

The pacer takes two ideas from forty years of TCP congestion control and rejects a third.

**From TCP Vegas: delay-gradient sensing.** Vegas watches round-trip time and reads a rising RTT as a queue building. It slows down before a packet is dropped. tiptoe does the same — a host whose connect and handshake times are creeping above their baseline is starting to throttle. tiptoe reads the gradient and backs off before the hard block.

**From TCP Reno: multiplicative decrease.** A lost probe (silent drop or TCP RST) is treated like a lost segment. The probe rate is cut hard, not trimmed.

**Not from TCP: slow start.** A bulk transfer ramps up exponentially because its goal is to find the bandwidth ceiling fast. A stealth probe's goal is the opposite. tiptoe's control variable is an inter-probe interval — the inverse of TCP's congestion window. It starts deliberately cautious and only earns speed.

tiptoe waits 8 to 120 seconds between probes by default. A host with several open ports can take minutes. A live countdown shows progress during the wait.

---

## Output

The human report has four sections:

- **Passive intel.** What was learned without touching the host.
- **Active probes.** Each port, the service identified, the auth status. Every active finding is verified — not guessed from a port number.
- **Pacer trace.** The congestion controller's per-probe decisions.
- **Noise.** Connection count and peak rate vs. portscan-detection estimate.

`--json` emits the full assessment for `visorlog ingest` or any other downstream stage.

---

## Where tiptoe sits in the chain

| Tool | Built for |
|------|-----------|
| aimap, scanner | population sweeps, thousands of hosts, load distributed |
| **tiptoe** | the single monitored host — quiet, paced, block-aware |

Use the population tools to find the fleet. Use tiptoe on the host that watches back.

---

## Related projects

- [aimap](https://github.com/sshpie/aimap) — AI/ML infrastructure fingerprinter and deep enumerator
- [BARE](https://github.com/sshpie/BARE) — semantic exploit-module ranking over scanner findings
- [agent-logging-system](https://github.com/sshpie/agent-logging-system) — operational monitor for AI agent pipelines

---

## License

MIT. See [LICENSE](LICENSE).
