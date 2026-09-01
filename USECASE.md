# Use Case: Shadow AI/ML Discovery for Cisco-Managed Enterprise Networks

## Title

Shadow AI/ML Discovery for Cisco-Managed Enterprise Networks

## Products

- Cisco Catalyst Center (DNA Center)
- Cisco XDR
- Cisco Webex

## Category

Security / AI Agents / Observability

## Problem

AI/ML services are being deployed on enterprise networks without the knowledge of network or security teams. Employees and application owners spin up LLM inference servers, vector databases, and model registries on managed devices — often with no authentication. These services expose sensitive data, accept arbitrary prompt input, and create lateral movement paths that do not appear in existing vulnerability scanners or SIEM rules.

Traditional port scanners applied to a single monitored host generate a recognizable scan signature. An IPS flags the source, and every tool that runs after it sees a dark host. Security teams end up with false negatives presented as findings.

## Solution

tiptoe is a quiet, congestion-controlled single-host assessor built specifically for monitored targets. It integrates with Cisco Catalyst Center to pull the managed device inventory, assesses each device serially with a TCP Vegas-style pacer that stays below IPS detection thresholds, and reports findings back to the Cisco ecosystem.

**Catalog mode** (`tiptoe catalog`) connects to Catalyst Center, fetches all managed devices, runs a quiet assessment on each management IP, and:
- Tags devices in Catalyst Center where shadow AI/ML services are found
- Submits CTIM sighting bundles to Cisco XDR for incident correlation
- Posts a room summary to Cisco Webex

**Single-host mode** (`tiptoe assess`) targets one host with optional XDR and Webex output.

## How It Works

```
Catalyst Center inventory
        |
        v
 tiptoe catalog
        |
        +-- per device: passive intel (Shodan, DNS, CT logs) -- zero packets
        |
        +-- per device: serial active probing, congestion-controlled
        |      TCP Vegas delay-gradient backoff
        |      TCP Reno multiplicative decrease on RST
        |      block detection: halts when host goes silent
        |
        +-- findings: unauthenticated AI/ML services (Ollama, Qdrant,
        |             ChromaDB, Milvus, MLflow, vLLM, ...)
        |
        +-- Catalyst Center: tag device "shadow-ai-detected"
        +-- Cisco XDR: CTIM sighting bundle (IP observable + service list)
        +-- Webex: per-device alert + catalog summary
```

## Installation

```bash
go install github.com/sshpie/tiptoe@latest
```

Requires Go 1.22 or later. Standard library only — no external dependencies.

## Usage

```bash
# Scan all Catalyst Center managed devices, tag findings, notify Webex
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token YOUR_TOKEN \
  --webex-token BOT_TOKEN \
  --webex-room ROOM_ID

# Include Cisco XDR sighting submission
tiptoe catalog \
  --catalyst-url https://catalyst.corp.example.com \
  --catalyst-token YOUR_TOKEN \
  --xdr-client-id CLIENT_ID \
  --xdr-client-secret CLIENT_SECRET \
  --webex-token BOT_TOKEN \
  --webex-room ROOM_ID

# Single-host assessment with XDR output
tiptoe assess 10.0.0.1 \
  --xdr-client-id CLIENT_ID \
  --xdr-client-secret CLIENT_SECRET
```

## Links

- GitHub: https://github.com/sshpie/tiptoe
- Cisco DevNet Code Exchange: https://developer.cisco.com/codeexchange/github/repo/sshpie/tiptoe
