<h1 align="center">tiptoe</h1>

<h4 align="center">Quiet, congestion-controlled assessment for AI and ML infrastructure.</h4>

<p align="center">
  <a href="https://github.com/sshpie/tiptoe/releases"><img src="https://img.shields.io/github/v/release/sshpie/tiptoe?style=flat-square" alt="release"></a>
  <a href="https://github.com/sshpie/tiptoe/blob/main/LICENSE"><img src="https://img.shields.io/github/license/sshpie/tiptoe?style=flat-square" alt="license"></a>
  <a href="https://golang.org"><img src="https://img.shields.io/badge/go-1.22%2B-00ADD8?style=flat-square&logo=go" alt="go"></a>
  <a href="https://sshpie.com"><img src="https://img.shields.io/badge/by--blue?style=flat-square" alt=""></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#pacer-design">Pacer Design</a> •
  <a href="#output">Output</a> •
  <a href="#scope">Scope</a>
</p>

---

tiptoe is a single Go binary that probes one monitored host without tripping its portscan detector. The population scanners in the  arsenal (aimap, scanner, menlohunt) distribute load over thousands of hosts. Point those same tools at a single target and the economics invert. A 40-port fingerprint sweep concentrated on one host is a textbook scan signature. An IPS flags it and filters the source. Every tool that runs after that sees a dark host and reports "no open ports", a false negative presented as a finding.

tiptoe is the quiet mode. Passive intel first, then one probe at a time, paced by a TCP-style congestion controller, with a block detector that halts the run when the host stops answering.

# Features

- Single Go binary, standard library only, Go 1.22 or later
- Passive phase sends the host zero packets (Shodan host API, reverse DNS, crt.sh)
- Serial active probing, never parallel, never a port scan signature
- Congestion-controlled pacer: TCP Vegas delay-gradient backoff plus TCP Reno multiplicative decrease, deliberately no slow start
- Block detection: once a host answers and then goes silent, tiptoe concludes the source is filtered and stops
- Per-probe pacer trace (measured RTT, baseline, ratio, decision) recorded in the report
- Noise budget readout: connections counted, peak rate compared against a portscan-detection estimate
- JSON output shaped for `visorlog ingest`
- Read-only marker probes only, no credential traffic

# Installation

```bash
go install -v github.com/sshpie/tiptoe@latest
```

Or build from source:

```bash
git clone https://github.com/sshpie/tiptoe
cd tiptoe
go build -o tiptoe .
```

Requires Go 1.22 or later. Standard library only.

# Usage

```console
tiptoe assess  192.0.2.10                       # passive intel, then paced active probing
tiptoe passive 192.0.2.10                       # passive only, zero packets to the host
tiptoe assess  192.0.2.10 --ports 8000,8888     # probe a specific port set
tiptoe assess  192.0.2.10 --json                # machine-readable output for the chain
tiptoe assess  192.0.2.10 --timeout 30s         # duration unit required (8s, 1m, not bare 8)
```

An IP address is the only required argument. For a host Shodan has indexed, the active phase probes whatever ports passive intel turned up, so `tiptoe assess <ip>` is fully automatic. For an IP with no Shodan record, pass `--ports`.

`~/.shodan/api_key` holds the Shodan API key. Without it, the passive phase skips Shodan and `--ports` becomes mandatory.

# Pacer design

The pacer takes two ideas from forty years of TCP congestion control and rejects a third.

**From TCP Vegas: delay-gradient sensing.** Vegas watches round-trip time and reads a rising RTT as a queue building in the network. It slows down before a packet is dropped. tiptoe does the same. A host whose connect and handshake times are creeping up above their baseline is starting to throttle. tiptoe reads the gradient and backs off before the hard block.

**From TCP Reno: multiplicative decrease.** A lost probe (silent drop or TCP RST) is treated like a lost segment. The probe rate is cut hard, not trimmed. A RST is the louder signal of the two and backs off harder.

**Not from TCP: slow start.** A bulk transfer ramps up exponentially because its goal is to find the bandwidth ceiling fast. A stealth probe's goal is the opposite. tiptoe's control variable is an inter-probe interval, the inverse of TCP's congestion window. It grows when cwnd would shrink, starts deliberately cautious, and only earns speed.

tiptoe waits 8 to 120 seconds between probes by default. A host with several ports can take minutes. A live status line shows a countdown so the wait reads as progress. For a quick first run, name two or three ports with `--ports`.

# Output

The human report has four parts:

- **Passive intel.** What was learned without touching the host.
- **Active probes.** Each port, the service identified, the auth status. Every active finding is verified, not guessed from a port number.
- **Pacer trace.** The congestion controller's per-probe decisions.
- **Noise.** Budget readout. tiptoe counts its own connections and reports the peak rate against a portscan-detection estimate, so loudness is a number you can see rather than a thing you hope about.

`--json` emits the full assessment for ledger ingest or any other stage of the chain.

# Where tiptoe sits in the chain

| Tool | Built for |
|------|-----------|
| aimap, scanner, menlohunt | population sweeps, thousands of hosts, load distributed |
| **tiptoe** | the single monitored host, quiet, paced, block-aware |

Use the loud tools to find the population. Use tiptoe on the host that would notice.

# Scope

tiptoe sends real TCP packets, paced and serialized. It does not authenticate, POST data, execute exploits, or modify anything on the target. Stealth pacing is not authorization. Only probe systems you own or have explicit written authorization to test.

# Our other projects

- [aimap](https://github.com/sshpie/aimap) — AI/ML infrastructure fingerprint scanner, the deep-enum stage
- [scanner](https://github.com/sshpie/scanner) — fast banner stage for population sweeps
- [menlohunt](https://github.com/sshpie/menlohunt) — zero-knowledge GCP perimeter scanner
- [BARE](https://github.com/sshpie/BARE) — semantic exploit-module ranking over scanner findings
- [VisorLog](https://github.com/sshpie/visorlog) — finding ledger and ingest pipeline

# License

MIT. Part of the  toolchain. Contact: [sshpie.com](https://sshpie.com)
