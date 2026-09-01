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
          +-- VERIFIED_UNAUTH findings (Ollama, Qdrant, MLflow, ...)
          |   labeled with Cisco AI Taxonomy IDs (OB/AITech/AISubtech)
          |
          +-- Catalyst Center     tag device "shadow-ai-detected"
          +-- Cisco Secure Access add IP to blocked destination list (SSE enforcement)
          +-- ThousandEyes        correlate degraded app scores (score < 70)
          |   provision TE agent on eligible Meraki networks
          +-- Cisco XDR           CTIM sighting bundle (IP + services + taxonomy)
          +-- Webex               per-device alert + catalog summary
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

## Features

- Single Go binary, standard library only, Go 1.22 or later
- **Cisco Catalyst Center** integration — pull device inventory, push shadow-AI tags
- **Cisco AI Taxonomy** classification — every finding labeled with OB/AITech/AISubtech IDs from Cisco's AI Taxonomy Navigator v1.0.0
- **ThousandEyes** correlation via Meraki assurance API — app health scores + impacted client counts
- **ThousandEyes provisioning** — activates TE agents on eligible Meraki networks when shadow AI is found (`POST /extensions/thousandEyes/networks`)
- **Cisco Secure Access (SSE)** — blocks shadow AI server IPs in the SSE destination list (Policies API v2, `bundleTypeId: 2`, `access: "block"`); list created automatically
- **Cisco XDR** integration — CTIM sighting bundle submission via OAuth2
- **Cisco Webex** integration — per-device alerts and catalog summaries
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
  --catalyst-url <url>      Catalyst Center base URL (required)
  --catalyst-token <token>  Catalyst Center X-Auth-Token (required)
  --catalyst-skip-tls       skip TLS verification (lab/self-signed certs)
  --ports <csv>             ports to probe per device (default: passive intel)
  --timeout <dur>           per-probe timeout (default 10s)
  --xdr-client-id <id>      Cisco XDR OAuth2 client ID
  --xdr-client-secret <s>   Cisco XDR OAuth2 client secret
  --xdr-region <r>          us (default) | eu | apjc
  --webex-token <token>     Webex bot bearer token
  --webex-room <id>         Webex room ID
  --meraki-api-key <key>    Meraki Dashboard API key (ThousandEyes correlation)
  --meraki-org-id <id>      Meraki organization ID
  --meraki-network-ids <csv> comma-separated Meraki network IDs to correlate

assess flags:
  --ports <csv>             ports to probe (default: from passive intel)
  --timeout <dur>           per-probe timeout (default 10s)
  --json                    machine-readable output
  --passive-only            skip the active phase
  --xdr-client-id <id>      Cisco XDR client ID
  --xdr-client-secret <s>   Cisco XDR client secret
  --xdr-region <r>          us | eu | apjc (default us)
  --webex-token <token>     Webex bot bearer token
  --webex-room <id>         Webex room ID
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
