<h1 align="center">AISM</h1>

<h4 align="center">AI Attack Surface Management (AISM)</h4>

<p align="center">
  <a href="https://github.com/sshpie/aism/releases"><img src="https://img.shields.io/github/v/release/sshpie/aism?style=flat-square" alt="release"></a>
  <a href="https://github.com/sshpie/aism/blob/main/LICENSE"><img src="https://img.shields.io/github/license/sshpie/aism?style=flat-square" alt="license"></a>
  <a href="https://golang.org"><img src="https://img.shields.io/badge/go-1.22%2B-00ADD8?style=flat-square&logo=go" alt="go"></a>
  <a href="https://developer.cisco.com/codeexchange/github/repo/sshpie/aism"><img src="https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg" alt="published on Code Exchange"></a>
</p>

<p align="center">
  <a href="#problem">Problem</a> •
  <a href="#features">Features</a> •
  <a href="#cisco-integration">Cisco Integration</a> •
  <a href="#detection-intelligence">Detection</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#pacer-design">Pacer Design</a> •
  <a href="#output">Output</a>
</p>

---

## Problem

Employees deploy LLM servers, vector databases, and model registries on managed devices without telling security teams. Most ship with no authentication. Existing scanners don't look for them — and when they do, they announce themselves. A port scan against a monitored host trips IPS detection, the source is flagged, and every tool that follows sees a dark target. False negatives presented as findings.

AISM pulls device inventory from **Cisco Catalyst Center** and assesses each host below IPS detection thresholds. Findings go to **Cisco XDR** and **Webex**. **ThousandEyes** application health is correlated via the Meraki assurance API to confirm active usage before any finding is reported.

---

## Features

Single Go binary, standard library only, Go 1.22 or later.

| Cisco integrations | Detection & scanning |
|---|---|
| **Catalyst Center** — device inventory pull, shadow-AI tagging | **100+ platform fingerprints** — inference servers, vector DBs, agent platforms, document processors, model registries, voice AI, MCP servers, Cisco network infrastructure |
| **AI Taxonomy** — every finding labeled with OB/AITech/AISubtech IDs | **Voice AI layer** — 42 fingerprints; CORS/CSWSH check on confirmed voice services |
| **Secure Access (SSE)** — IP-layer containment via destination block list | **MCP HTTP server detection** — `tools/list` scan for V2 tool description injection; escalates to CRITICAL |
| **Umbrella** — DNS-layer containment via block list | **Ollama model poisoning** — impersonation names, V2 system prompt injection, V3 message history injection; escalates to CRITICAL |
| **Secure Endpoint** — connector lookup by IP; optional endpoint isolation | **Cisco ASA WebVPN** — SAML metadata exposure, `fcadbadd=1` logon bypass, ASDM version extraction |
| **ISE** — ANC quarantine policy (identity/VLAN-layer containment) | **Passive phase** — zero packets sent (Shodan, reverse DNS, crt.sh) |
| **AI Defense** — MCP server supply chain scan; runtime enforcement query | **Serial active probing** — never parallel, never a port scan signature |
| **Secure Network Analytics** — flow query to confirm active usage, client count, byte volume | **Congestion-controlled pacer** — TCP Vegas delay-gradient + TCP Reno multiplicative decrease |
| **NSO (RESTCONF)** — ACL push to all managed devices (network device level containment) | **Block detection** — halts when a host goes silent mid-probe, reports why |
| **ThousandEyes** — app score correlation; TE agent provisioning on shadow-AI networks | **Pacer trace** — measured RTT, baseline, phi, and decision in every report |
| **XDR** — CTIM sighting bundle via OAuth2 | **Noise budget** — connection count and peak rate vs. portscan-detection threshold |
| **Webex** — Adaptive Card findings; Acknowledge/Isolate buttons; threaded containment follow-up | **JSON output** — structured for `visorlog ingest` or any downstream stage |

---

## Cisco Integration

```
Catalyst Center
  managed device inventory
          |
          v
   aism catalog
          |
          +-- per device ------------------------------------------+
          |   passive intel: Shodan, DNS, CT logs (zero packets)   |
          |   serial active probing: congestion-controlled pacer   |
          |   block detection: halts when host goes silent         |
          +--------------------------------------------------------+
          |
          +-- VERIFIED_UNAUTH findings (100+ platforms: Ollama, Qdrant, MLflow, LangFlow, ...)
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

aism pulls the full managed device inventory (`GET /dna/intent/api/v1/network-device`) and assesses each management IP. When AI/ML services are found, it creates or updates a `shadow-ai-detected` tag on the device (`POST /dna/intent/api/v2/tag`).

```bash
aism catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token YOUR_TOKEN
```

### Cisco XDR

Verified findings are submitted as CTIM sighting bundles via OAuth2 client credentials. Each sighting carries the IP observable and a service list so XDR can correlate the finding with other telemetry sources.

```bash
aism catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token YOUR_TOKEN \
  --xdr-client-id CLIENT_ID \
  --xdr-client-secret CLIENT_SECRET \
  --xdr-region us
```

### Cisco Webex

Per-device alerts and a full catalog summary post to any Webex room.

```bash
aism catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token YOUR_TOKEN \
  --webex-token BOT_TOKEN \
  --webex-room ROOM_ID
```

### ThousandEyes (via Meraki Assurance API)

When shadow AI is found on a device, aism:

1. **Correlates** — queries `GET /api/v1/organizations/{orgId}/assurance/thousandEyes/applications`
   and reports any applications with a health score below 70, turning a theoretical finding into
   a quantified business impact (impacted client count, score delta, active alerts).

2. **Provisions** — calls `GET /organizations/{orgId}/extensions/thousandEyes/networks/supported`
   to identify which Meraki networks are eligible for ThousandEyes agent activation, then
   provisions an agent (`POST /organizations/{orgId}/extensions/thousandEyes/networks`) on each
   eligible network. Shadow AI found = monitoring activated immediately, in the same run.

```bash
aism catalog \
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

When shadow AI is found, aism adds the server's IP to a `shadow-ai-detected` blocked
destination list in Cisco Secure Access via the
[Destination Lists API](https://developer.cisco.com/docs/cloud-security/)
(`POST /policies/v2/destinationlists/{id}/destinations`).
The list is created automatically if it doesn't exist (`bundleTypeId: 2`, `access: "block"`).

This enforces network-layer containment on all managed endpoints routed through the SSE —
no per-device config change required. The block propagates within SSE policy enforcement time.

```bash
aism catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN \
  --sse-client-id SSE_CLIENT_ID \
  --sse-client-secret SSE_CLIENT_SECRET
```

Required OAuth2 scope: `policies.destinationLists:write`.

---

### Cisco Umbrella (DNS-layer)

When shadow AI is found, aism adds the server's IP to a `shadow-ai-detected` block list
in Cisco Umbrella via the [Policies API v2](https://developer.cisco.com/docs/cloud-security/)
(`POST /organizations/{orgId}/destinationlists/{id}/destinations`).

Umbrella blocks DNS queries to the IP before a TCP connection can form — complementary to
SSE's IP-layer blocking. Together they cover: DNS resolution (Umbrella) + packet forwarding (SSE).

```bash
aism catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN \
  --umbrella-client-id CLIENT_ID \
  --umbrella-client-secret CLIENT_SECRET
```

---

### Cisco Secure Endpoint

When shadow AI is found, aism queries the Secure Endpoint API v3 for the managed endpoint
connector installed on the device (`GET /computers?internal_ip={ip}`). With `--amp-isolate`,
it triggers network isolation on the connector (`PUT /computers/{guid}/isolation`).

Isolation severs the device's network access while keeping the connector connected to the
Secure Endpoint cloud — the endpoint remains manageable and can be remediated remotely.

```bash
aism catalog \
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

When shadow AI is found, aism applies an ANC (Adaptive Network Control) quarantine policy
to the endpoint via the [ISE ERS API](https://developer.cisco.com/docs/identity-services-engine/)
(`POST /ers/config/ancendpoint/apply`).

ISE re-routes the device through a restricted VLAN and can require re-authentication before
network access is restored. Create the policy (`shadow-ai-quarantine`) in ISE under
Policy > Policy Elements > ANC Policies before use.

```bash
aism catalog \
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

When shadow AI is confirmed on an IP, aism queries SNA for all flows TO that IP
in the previous 60 minutes. Flow data turns a "service is listening" finding into a
"service is actively used" finding with client count and byte volume.

```bash
aism catalog \
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

When shadow AI is found, aism pushes a `deny ip any host {shadowAI-IP}` ACL rule to
every NSO-managed device via RESTCONF. This enforces containment at the network device
level — below SSE (IP-layer) and Umbrella (DNS-layer).

```bash
aism catalog \
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

When aism finds an unauth MCP server (family: `agent-platform`) it registers it with
[Cisco AI Defense](https://developer.cisco.com/docs/ai-defense-management/) for automated
supply chain scanning — checking the server's tools, exposed capabilities, and dependencies
for prompt injection vulnerabilities, unsafe tool definitions, and known supply chain risks.

```bash
aism catalog \
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
aism catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN \
  --webex-token BOT_TOKEN \
  --webex-room ROOM_ID
```

If `--webex-room` is omitted, aism calls `GET /rooms` to find (or creates) a
`aism-alerts` space automatically.

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

**Thread replies** — after ISE ANC or Secure Endpoint isolation completes, aism
threads a status reply to the original card with the result, keeping the room clean.

**MCP server** — the bot token is valid for the
[Webex Messaging MCP Server](https://developer.webex.com/mcp/docs/messaging-mcp-server)
(`https://mcp.webexapis.com/mcp/webex-messaging`). Any MCP-enabled agent (Claude Code,
LangGraph, AutoGen) can receive and act on aism findings without a separate integration.

Required OAuth scopes: `spark:messages_write`, `spark:rooms_read`, `spark:rooms_write`,
`spark:webhooks_read`, `spark:webhooks_write`. Add `spark:mcp` when routing through the
MCP server.

---

### Voice AI Coverage

aism fingerprints **42 voice AI platforms** across three families. These services are
common in research clusters, edge deployments, and AI workstations — and almost universally
unauthenticated by default.

| Family | Platforms (sample) | Distinctive ports |
|---|---|---|
| `voice-synthesis` | Kokoro TTS, AllTalk TTS, CosyVoice 2, GPT-SoVITS, Fish Speech, MaryTTS, Piper TTS, RVC WebUI, Applio, Moshi, OpenedAI Speech, OpenVoiceOS, ChatTTS, MetaVoice, F5-TTS, Bark, StyleTTS2, Tortoise, Parler, Spark TTS, MegaTTS3, IndexTTS, OpenVoice, Orpheus TTS, Coqui TTS, EmotiVoice, MeloTTS, OpenTTS, Chatterbox TTS | 8880, 50000, 9880, 6969, 10200, 59125, 7851, 7865, 7861, 58003, 8998, 5500, 5002, 8181 |
| `voice-asr` | WhisperX, Whisper ASR Webservice, Modern Whisper, WhisperLive, Whisper.cpp Server, FunASR, WeNet, WhisperFusion, Vosk, Subtitle Generator | 9090, 10095, 10086, 2700 |
| `voice-infrastructure` | Rhasspy, Silero VAD, Lunary | 12101, 10400 |

Detection sources: snake's `DETECT_CHECKS` (tested against live instances), the VDT
voice AI wiki (59-platform corpus), and the galleria corpus (port sets for 30+ voice platforms).

Gradio-based platforms are confirmed via `/info` JSON, which exposes a `{"title":"<AppName>"}`
field unique to each app — a reliable discriminator when many services share port 7860.
OpenAI-compatible voice gateways (Kokoro, OpenedAI Speech) are confirmed by their
specific voice model IDs (`"af_"`, `"tts-1"`).

---

## Detection Intelligence

AISM's detections are grounded in original research, not CVE databases. Each layer below came from binary RE, live-host observation, or autonomous worm telemetry — not vendor documentation.

### Ollama Model Poisoning

After confirming an Ollama instance, AISM fetches the full model list and deep-inspects each model for two injection classes documented in autonomous model-poisoning worm research (1,347 compromised hosts, 3,949 models):

| Signal | Method | Injection class |
|---|---|---|
| Model named `gpt-4:latest`, `claude-3-opus:latest`, `gpt-4o:latest` | `/api/tags` name match | Known worm artifact |
| Model named after any closed commercial LLM | `/api/tags` prefix match | Impersonation deployment |
| Canary content in `.system` field | `/api/show` body scan | V2 — system prompt injection |
| Non-empty `.messages[]` array | `/api/show` body scan | V3 — pre-conversation injection |

V3 is the stealthier variant: the worm injects into stored message history rather than the system prompt, so it persists even when the system prompt is cleared and survives model pulls. Legitimate Ollama models ship with no stored message history — a non-empty array is anomalous regardless of content.

Escalates to **CRITICAL** on any match.

### MCP Tool Description Poisoning

After confirming a network-accessible MCP HTTP server, AISM calls `tools/list` and scans each tool's `description` field for 18 injection patterns. Tool description injection (V2) fires at LLM planning time — before any tool call executes — and leaves zero trace in call logs. The `[IMPORTANT: ...]` bracket pattern was confirmed effective by Microsoft's GitHub Copilot security team.

Escalates to **CRITICAL** when poisoning is detected.

### Cisco ASA WebVPN

Three exposure checks grounded in live-ASA testing and binary RE of `lina`/`vpnagentd`:

| Check | Path | Finding |
|---|---|---|
| SAML SP metadata | `/+CSCOE+/saml/sp/metadata` | Exposed without auth on all ASA versions with SAML configured; reveals SP EntityID and ACS URL |
| Logon bypass | `/+CSCOE+/logon.html?fcadbadd=1` | Cisco-internal debug parameter left in production; returns full portal HTML (11KB+) without credentials |
| ASDM exposure | `/admin/` | Management interface accessible; JAR URL embeds exact ASA version string for precise CVE matching |

### Voice AI CORS/CSWSH

On confirmed voice AI services, AISM probes for `Access-Control-Allow-Origin: *` with a spoofed `Origin` header. A wildcard CORS policy on a voice service enables cross-site WebSocket hijacking: an attacker's page opens a WebSocket connection to the server and controls TTS output or receives ASR transcript without user interaction.

Escalates confirmed UNAUTH voice services to **CRITICAL** when CSWSH risk is present.

---

## Installation

```bash
go install github.com/sshpie/aism@latest
```

Or build from source:

```bash
git clone https://github.com/sshpie/aism
cd aism
go build -o aism .
```

Requires Go 1.22 or later. Standard library only — no external dependencies.

---

## Usage

### Catalog mode — scan all managed devices

```bash
# Pull inventory from Catalyst Center, assess each device
aism catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN

# Full Cisco integration: Catalyst Center + XDR + Webex
aism catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token TOKEN \
  --xdr-client-id ID \
  --xdr-client-secret SECRET \
  --webex-token BOT_TOKEN \
  --webex-room ROOM_ID

# Lab deployment with self-signed certificate
aism catalog \
  --catalyst-url https://192.0.2.10 \
  --catalyst-token TOKEN \
  --catalyst-skip-tls
```

### Single-host mode

```bash
# Passive intel + paced active probing
aism assess 10.0.0.1

# Probe a specific port set and submit finding to XDR
aism assess 10.0.0.1 --ports 8000,11434,6333 \
  --xdr-client-id ID --xdr-client-secret SECRET

# Machine-readable output for downstream tooling
aism assess 10.0.0.1 --json

# Passive only — zero packets to the host
aism passive lab.example.edu
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

**From TCP Vegas: delay-gradient sensing.** Vegas watches round-trip time and reads a rising RTT as a queue building. It slows down before a packet is dropped. aism does the same — a host whose connect and handshake times are creeping above their baseline is starting to throttle. aism reads the gradient and backs off before the hard block.

**From TCP Reno: multiplicative decrease.** A lost probe (silent drop or TCP RST) is treated like a lost segment. The probe rate is cut hard, not trimmed.

**Not from TCP: slow start.** A bulk transfer ramps up exponentially because its goal is to find the bandwidth ceiling fast. A stealth probe's goal is the opposite. aism's control variable is an inter-probe interval — the inverse of TCP's congestion window. It starts deliberately cautious and only earns speed.

aism waits 8 to 120 seconds between probes by default. A host with several open ports can take minutes. A live countdown shows progress during the wait.

---

## Output

The human report has four sections:

- **Passive intel.** What was learned without touching the host.
- **Active probes.** Each port, the service identified, the auth status. Every active finding is verified — not guessed from a port number.
- **Pacer trace.** The congestion controller's per-probe decisions.
- **Noise.** Connection count and peak rate vs. portscan-detection estimate.

`--json` emits the full assessment for `visorlog ingest` or any other downstream stage.

---

## License

MIT. See [LICENSE](LICENSE).
