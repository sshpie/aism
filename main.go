// Command tiptoe is a quiet, block-aware assessor for AI/LLM infrastructure.
//
// The  arsenal is built for population sweeps — aimap, menlohunt and the
// rest spread their load over thousands of hosts, so no single host ever sees
// a scan signature. Concentrate those tools on ONE monitored host and they go
// loud: the host's IPS flags the scan and every tool after it runs blind
// against a now-filtered target.
//
// tiptoe is the quiet counterpart. It is passive-first (the recon phase sends
// the target zero packets), it probes serially and paced by a TCP-style
// congestion controller, and it watches its own probe outcomes so it can tell
// when it has been filtered — and stop, instead of hammering a dark host.
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sshpie/tiptoe/cisco"
)

const version = "0.2.0"

// ANSI styling. Emitted only when stderr is a real terminal, so a piped or
// redirected run stays clean.
const (
	ansiReset = "\x1b[0m"
	ansiCyan  = "\x1b[36m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
)

var stderrTTY = func() bool {
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

func sgr(code string) string {
	if stderrTTY {
		return code
	}
	return ""
}

// printBanner writes the tiptoe banner to stderr — stdout is left clean so
// `--json` output is never polluted.
func printBanner() {
	fmt.Fprint(os.Stderr, sgr(ansiCyan)+`
   _   _      _
  | |_(_)_ __| |_ ___  ___
  | __| | '_ \ __/ _ \/ -_)
   \__|_| .__/\__\___/\___|
        |_|`+sgr(ansiReset)+sgr(ansiDim)+`   v`+version+`  ·  `+
		sgr(ansiReset)+`

`+sgr(ansiBold)+`   quiet, block-aware assessment for AI/LLM infrastructure`+
		sgr(ansiReset)+`
`+sgr(ansiDim)+`   the arsenal goes loud across thousands of hosts;
   tiptoe assesses the one host that watches back.`+sgr(ansiReset)+"\n")
}

func usage() {
	printBanner()
	fmt.Fprint(os.Stderr, `
usage:
  tiptoe assess  <host>   passive intel, then congestion-controlled active probing
  tiptoe passive <host>   passive intel only, zero packets to the target
  tiptoe catalog          pull Catalyst Center inventory, assess each managed device
  tiptoe version          print the version and exit

assess flags:
  --ports <csv>           ports to probe (default: ports from passive intel)
  --timeout <dur>         per-probe timeout (default 10s)
  --json                  emit JSON instead of the human report
  --passive-only          skip the active phase

  Cisco XDR output (optional):
  --xdr-client-id <id>    Cisco XDR OAuth2 client ID
  --xdr-client-secret <s> Cisco XDR OAuth2 client secret
  --xdr-region <r>        XDR region: us (default) | eu | apjc

  Cisco Webex notification (optional):
  --webex-token <token>   Webex bot bearer token
  --webex-room <id>       Webex room ID to post results

catalog flags:
  --catalyst-url <url>    Catalyst Center base URL (required)
  --catalyst-token <tok>  Catalyst Center X-Auth-Token (required)
  --catalyst-skip-tls     skip TLS verification (lab/self-signed certs)
  --ports <csv>           ports to probe per device (default: passive intel)
  --timeout <dur>         per-probe timeout (default 10s)
  --xdr-client-id <id>    submit findings to Cisco XDR
  --xdr-client-secret <s>
  --xdr-region <r>        us | eu | apjc (default us)
  --webex-token <token>   post catalog summary to Webex
  --webex-room <id>

  ThousandEyes correlation + provisioning (optional):
  --meraki-api-key <key>      Meraki Dashboard API key
  --meraki-org-id <id>        Meraki organization ID
  --meraki-network-ids <csv>  Meraki network IDs to correlate (comma-separated)

  Cisco Secure Access (SSE) enforcement (optional):
  --sse-client-id <id>        Secure Access OAuth2 client ID (scope: policies.destinationLists:write)
  --sse-client-secret <s>     Secure Access OAuth2 client secret

examples:
  tiptoe assess  10.0.0.1
  tiptoe assess  10.0.0.1 --ports 8000,11434 --json
  tiptoe assess  10.0.0.1 --xdr-client-id ID --xdr-client-secret SECRET
  tiptoe passive lab.example.edu
  tiptoe catalog --catalyst-url https://catalyst.corp.example.com --catalyst-token TOKEN
  tiptoe catalog --catalyst-url https://catalyst/ --catalyst-token TOKEN \
                 --webex-token BOT_TOKEN --webex-room ROOM_ID

`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "assess":
		runCmd(os.Args[2:], false)
	case "passive":
		runCmd(os.Args[2:], true)
	case "catalog":
		runCatalog(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("tiptoe %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "tiptoe: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func runCmd(args []string, passiveOnly bool) {
	name := "assess"
	if passiveOnly {
		name = "passive"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "emit JSON")
	portsCSV := fs.String("ports", "", "comma-separated ports to probe")
	timeout := fs.Duration("timeout", 10*time.Second, "per-probe timeout")
	forcePassive := fs.Bool("passive-only", false, "skip the active phase")

	// Cisco XDR
	xdrClientID := fs.String("xdr-client-id", "", "Cisco XDR OAuth2 client ID")
	xdrClientSecret := fs.String("xdr-client-secret", "", "Cisco XDR OAuth2 client secret")
	xdrRegion := fs.String("xdr-region", "us", "Cisco XDR region (us|eu|apjc)")

	// Cisco Webex
	webexToken := fs.String("webex-token", "", "Webex bot bearer token")
	webexRoom := fs.String("webex-room", "", "Webex room ID")

	// The stdlib flag package stops parsing at the first non-flag argument,
	// so `tiptoe assess host --json` would silently leave --json unparsed.
	// Parse once, lift out the host, then parse whatever flags followed it.
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintf(os.Stderr, "tiptoe %s: need a host\n", name)
		os.Exit(2)
	}
	host := rest[0]
	if len(rest) > 1 {
		_ = fs.Parse(rest[1:])
	}
	if passiveOnly {
		*forcePassive = true
	}

	if !*jsonOut {
		printBanner()
	}
	fmt.Fprintf(os.Stderr, "[*] passive intel — %s\n", host)

	intel, err := gatherIntel(host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[+] %s -> %s\n", host, intel.IP)
	if len(intel.ShodanPorts) > 0 {
		fmt.Fprintf(os.Stderr, "[+] Shodan: org=%q ports=%v\n",
			intel.ShodanOrg, intel.ShodanPorts)
	}

	a := Assessment{
		Target:    host,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Intel:     intel,
	}

	if !*forcePassive {
		ports := parsePorts(*portsCSV)
		if len(ports) == 0 {
			ports = intel.ShodanPorts
		}
		if len(ports) == 0 {
			ports = DefaultPorts()
			fmt.Fprintf(os.Stderr, "[*] no passive intel — using tome default port set (%d ports)\n",
				len(ports))
		}
		if len(ports) > 0 {
			fmt.Fprintf(os.Stderr, "[*] active phase — %d port(s), serialized, "+
				"congestion-controlled pacing\n\n", len(ports))
			a = runAssessment(intel, ports, *timeout, NewPacer(), !*jsonOut)
		}
	}

	if *jsonOut {
		printJSON(a)
	} else {
		printReport(a)
	}

	// Cisco integrations — fire after the report so the human output is never
	// delayed by API round-trips.
	services := unauthServices(a)
	if len(services) > 0 {
		if *xdrClientID != "" && *xdrClientSecret != "" {
			xdr := cisco.NewXDRClient(*xdrClientID, *xdrClientSecret, *xdrRegion)
			if err := xdr.SubmitSightings([]cisco.Sighting{{
				IP: intel.IP, Services: services, ScanTime: a.StartedAt,
			}}); err != nil {
				fmt.Fprintf(os.Stderr, "[!] xdr: %v\n", err)
			} else {
				fmt.Fprintln(os.Stderr, "[+] xdr: sighting submitted")
			}
		}
		if *webexToken != "" && *webexRoom != "" {
			wx := cisco.NewWebexClient(*webexToken, *webexRoom)
			if err := wx.Notify(host, intel.IP, services, a.Blocked); err != nil {
				fmt.Fprintf(os.Stderr, "[!] webex: %v\n", err)
			} else {
				fmt.Fprintln(os.Stderr, "[+] webex: notification sent")
			}
		}
	}
}

// runCatalog fetches all managed devices from Cisco Catalyst Center and runs
// a quiet tiptoe assessment on each one, serially. Devices where AI/ML services
// are found are tagged in Catalyst Center and optionally reported to Cisco XDR
// and a Webex room.
func runCatalog(args []string) {
	fs := flag.NewFlagSet("catalog", flag.ExitOnError)
	catalystURL := fs.String("catalyst-url", "", "Catalyst Center base URL (required)")
	catalystToken := fs.String("catalyst-token", "", "Catalyst Center X-Auth-Token (required)")
	catalystSkipTLS := fs.Bool("catalyst-skip-tls", false, "skip TLS verification")
	portsCSV := fs.String("ports", "", "comma-separated ports to probe per device")
	timeout := fs.Duration("timeout", 10*time.Second, "per-probe timeout")
	xdrClientID := fs.String("xdr-client-id", "", "Cisco XDR client ID")
	xdrClientSecret := fs.String("xdr-client-secret", "", "Cisco XDR client secret")
	xdrRegion := fs.String("xdr-region", "us", "Cisco XDR region (us|eu|apjc)")
	webexToken := fs.String("webex-token", "", "Webex bot token")
	webexRoom := fs.String("webex-room", "", "Webex room ID")
	merakiAPIKey := fs.String("meraki-api-key", "", "Meraki Dashboard API key")
	merakiOrgID := fs.String("meraki-org-id", "", "Meraki organization ID")
	merakiNetworkIDs := fs.String("meraki-network-ids", "", "comma-separated Meraki network IDs")
	// Cisco Secure Access (SSE) — block shadow AI IPs at the SSE layer.
	sseClientID := fs.String("sse-client-id", "", "Cisco Secure Access OAuth2 client ID")
	sseClientSecret := fs.String("sse-client-secret", "", "Cisco Secure Access OAuth2 client secret")

	// Cisco Secure Endpoint (AMP) — look up device by IP, isolate if shadow AI found.
	ampClientID := fs.String("amp-client-id", "", "Cisco Secure Endpoint API client ID")
	ampAPIKey := fs.String("amp-api-key", "", "Cisco Secure Endpoint API key")
	ampCloud := fs.String("amp-cloud", "nam", "Secure Endpoint cloud (nam|eu|apjc)")
	ampIsolate := fs.Bool("amp-isolate", false, "isolate endpoints where shadow AI is found")

	// Cisco Umbrella — block shadow AI server IPs/domains at the DNS layer.
	umbrellaClientID := fs.String("umbrella-client-id", "", "Cisco Umbrella OAuth2 client ID")
	umbrellaClientSecret := fs.String("umbrella-client-secret", "", "Cisco Umbrella OAuth2 client secret")

	// Cisco ISE — trigger ANC quarantine policy on devices with shadow AI.
	iseURL := fs.String("ise-url", "", "Cisco ISE ERS base URL (e.g. https://ise.corp:9060)")
	iseUser := fs.String("ise-user", "", "Cisco ISE ERS username")
	isePass := fs.String("ise-pass", "", "Cisco ISE ERS password")
	isePolicy := fs.String("ise-policy", "shadow-ai-quarantine", "ISE ANC policy name to apply")

	// Cisco AI Defense — submit detected MCP servers for supply chain scanning.
	aiDefenseKey := fs.String("aidefense-key", "", "Cisco AI Defense Management API key (Administration > API Keys)")

	// Cisco Secure Network Analytics (Stealthwatch) — query flows and security events.
	snaHost := fs.String("sna-host", "", "Cisco SNA Management Console hostname (no scheme)")
	snaUser := fs.String("sna-user", "", "SNA username")
	snaPass := fs.String("sna-pass", "", "SNA password")
	snaTenantID := fs.String("sna-tenant-id", "", "SNA tenant ID (numeric)")

	// Cisco NSO (RESTCONF) — push ACL deny rules to managed devices.
	nsoHost := fs.String("nso-host", "", "Cisco NSO hostname")
	nsoPort := fs.Int("nso-port", 8080, "NSO RESTCONF port (8080=HTTP, 8443=HTTPS)")
	nsoUser := fs.String("nso-user", "", "NSO username")
	nsoPass := fs.String("nso-pass", "", "NSO password")
	nsoACL := fs.String("nso-acl", "shadow-ai-block", "ACL name to add deny rules to on NSO-managed devices")

	_ = fs.Parse(args)

	if *catalystURL == "" || *catalystToken == "" {
		fmt.Fprintln(os.Stderr, "tiptoe catalog: --catalyst-url and --catalyst-token are required")
		os.Exit(2)
	}

	printBanner()

	cc := cisco.NewCatalystClient(*catalystURL, *catalystToken, *catalystSkipTLS)

	fmt.Fprintf(os.Stderr, "[*] pulling device inventory from Catalyst Center...\n")
	devices, err := cc.Devices()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] catalyst: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[+] %d managed devices\n\n", len(devices))

	var xdrClient *cisco.XDRClient
	if *xdrClientID != "" && *xdrClientSecret != "" {
		xdrClient = cisco.NewXDRClient(*xdrClientID, *xdrClientSecret, *xdrRegion)
	}
	var webexClient *cisco.WebexClient
	if *webexToken != "" && *webexRoom != "" {
		webexClient = cisco.NewWebexClient(*webexToken, *webexRoom)
	}
	var sseClient *cisco.SecureAccessClient
	if *sseClientID != "" && *sseClientSecret != "" {
		sseClient = cisco.NewSecureAccessClient(*sseClientID, *sseClientSecret)
	}
	var ampClient *cisco.SecureEndpointClient
	if *ampClientID != "" && *ampAPIKey != "" {
		ampClient = cisco.NewSecureEndpointClient(*ampClientID, *ampAPIKey, *ampCloud)
	}
	var umbrellaClient *cisco.UmbrellaClient
	if *umbrellaClientID != "" && *umbrellaClientSecret != "" {
		umbrellaClient = cisco.NewUmbrellaClient(*umbrellaClientID, *umbrellaClientSecret)
	}
	var iseClient *cisco.ISEClient
	if *iseURL != "" && *iseUser != "" && *isePass != "" {
		iseClient = cisco.NewISEClient(*iseURL, *iseUser, *isePass)
	}
	var aiDefenseClient *cisco.AIDefenseClient
	if *aiDefenseKey != "" {
		aiDefenseClient = cisco.NewAIDefenseClient(*aiDefenseKey)
	}
	var snaClient *cisco.StealthwatchClient
	if *snaHost != "" && *snaUser != "" && *snaPass != "" && *snaTenantID != "" {
		sc, err := cisco.NewStealthwatchClient(*snaHost, *snaUser, *snaPass, *snaTenantID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] sna: auth failed: %v\n", err)
		} else {
			snaClient = sc
			defer snaClient.Close()
		}
	}
	var nsoClient *cisco.NSOClient
	if *nsoHost != "" && *nsoUser != "" && *nsoPass != "" {
		nsoClient = cisco.NewNSOClient(*nsoHost, *nsoUser, *nsoPass, *nsoPort)
	}

	// ThousandEyes — query once upfront and cache; correlate + provision after each finding.
	var te *cisco.MerakiThousandEyesClient
	var netIDStrs []string
	var teApps []cisco.TEApplication
	supportedNetworkSet := map[string]bool{} // networks eligible for agent provisioning
	if *merakiAPIKey != "" && *merakiOrgID != "" && *merakiNetworkIDs != "" {
		netIDStrs = strings.Split(*merakiNetworkIDs, ",")
		for i := range netIDStrs {
			netIDStrs[i] = strings.TrimSpace(netIDStrs[i])
		}
		te = cisco.NewMerakiThousandEyesClient(*merakiOrgID, *merakiAPIKey, netIDStrs)
		fmt.Fprintf(os.Stderr, "[*] querying ThousandEyes application assurance (%d network(s))...\n",
			len(netIDStrs))
		var teErr error
		teApps, teErr = te.Applications(0)
		if teErr != nil {
			fmt.Fprintf(os.Stderr, "[!] thousandeyes: %v\n", teErr)
		} else {
			fmt.Fprintf(os.Stderr, "[+] ThousandEyes: %d application(s) loaded\n", len(teApps))
		}
		// Pre-fetch networks eligible for agent activation (agentInstalled=false).
		notInstalled := false
		supported, supErr := te.SupportedNetworks(&notInstalled)
		if supErr != nil {
			fmt.Fprintf(os.Stderr, "[!] thousandeyes: supported networks: %v\n", supErr)
		} else {
			for _, id := range supported {
				supportedNetworkSet[id] = true
			}
			fmt.Fprintf(os.Stderr, "[+] ThousandEyes: %d network(s) eligible for agent activation\n",
				len(supported))
		}
	}

	staticPorts := parsePorts(*portsCSV)
	var xdrSightings []cisco.Sighting
	var flaggedIPs []string
	devicesWithFindings := 0

	for i, dev := range devices {
		ip := dev.ManagementIPAddr
		if ip == "" {
			continue
		}
		fmt.Fprintf(os.Stderr, "[%d/%d] %s  %s (%s)\n",
			i+1, len(devices), ip, dev.Hostname, dev.Platform)

		intel, err := gatherIntel(ip)
		if err != nil {
			fmt.Fprintf(os.Stderr, "      [!] resolve: %v\n", err)
			continue
		}

		ports := staticPorts
		if len(ports) == 0 {
			ports = intel.ShodanPorts
		}
		if len(ports) == 0 {
			ports = DefaultPorts()
			fmt.Fprintf(os.Stderr, "      [*] no passive intel — using tome default port set (%d ports)\n",
				len(ports))
		}

		a := runAssessment(intel, ports, *timeout, NewPacer(), stderrTTY)
		services := unauthServices(a)
		if len(services) == 0 {
			fmt.Fprintf(os.Stderr, "      [-] no AI/ML services found\n")
			continue
		}

		devicesWithFindings++
		flaggedIPs = append(flaggedIPs, ip)

		// Cisco AI Taxonomy classification — label each finding with the
		// matching Objective/Technique/Subtechnique from Cisco's AI Taxonomy Navigator.
		svcNames := unauthServiceNames(a)
		taxEntries := cisco.ClassifyAll(svcNames)
		taxLabel := cisco.TaxonomyLabel(taxEntries)
		if taxLabel != "" {
			fmt.Fprintf(os.Stderr, "      [!] shadow AI/ML: %s\n      [*] Cisco AI Taxonomy: %s\n",
				strings.Join(services, ", "), taxLabel)
		} else {
			fmt.Fprintf(os.Stderr, "      [!] shadow AI/ML: %s\n", strings.Join(services, ", "))
		}

		// Tag the device in Catalyst Center.
		if dev.ID != "" {
			tagDesc := fmt.Sprintf("tiptoe found: %s", strings.Join(services, "; "))
			if err := cc.TagDevice(dev.ID, "shadow-ai-detected", tagDesc); err != nil {
				fmt.Fprintf(os.Stderr, "      [!] catalyst tag: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "      [+] catalyst: tagged device\n")
			}
		}

		// Cisco Secure Access — block the shadow AI server's IP in SSE.
		// This creates/updates the "shadow-ai-detected" blocked destination list,
		// which enforces network-layer containment for all managed endpoints.
		if sseClient != nil {
			if err := sseClient.BlockShadowAI([]string{ip}, strings.Join(services, "; ")); err != nil {
				fmt.Fprintf(os.Stderr, "      [!] secure-access: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "      [+] secure-access: %s added to blocked destination list\n", ip)
			}
		}

		// Cisco Secure Endpoint — look up the device by management IP and optionally
		// isolate it when shadow AI is confirmed. The API returns a connector GUID
		// that uniquely identifies the managed endpoint; isolation requires it.
		if ampClient != nil {
			guid, hostname, err := ampClient.FindByIP(ip)
			if err != nil {
				fmt.Fprintf(os.Stderr, "      [!] secure-endpoint: %v\n", err)
			} else if guid != "" {
				fmt.Fprintf(os.Stderr, "      [+] secure-endpoint: device found — %s (%s)\n", hostname, guid)
				if *ampIsolate {
					if err := ampClient.Isolate(guid, "shadow AI detected by tiptoe: "+strings.Join(services, ", ")); err != nil {
						fmt.Fprintf(os.Stderr, "      [!] secure-endpoint: isolate: %v\n", err)
					} else {
						fmt.Fprintf(os.Stderr, "      [+] secure-endpoint: endpoint isolated\n")
					}
				}
			}
		}

		// Cisco Umbrella — block shadow AI server IPs at the DNS layer.
		// Complements SSE (IP-layer) with DNS-layer enforcement.
		if umbrellaClient != nil {
			if err := umbrellaClient.BlockShadowAI([]string{ip}); err != nil {
				fmt.Fprintf(os.Stderr, "      [!] umbrella: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "      [+] umbrella: %s added to DNS block list\n", ip)
			}
		}

		// Cisco ISE — apply ANC quarantine policy to the endpoint.
		// ISE then re-routes the device through a restricted VLAN until cleared.
		if iseClient != nil {
			if err := iseClient.ApplyANC(ip, *isePolicy); err != nil {
				fmt.Fprintf(os.Stderr, "      [!] ise: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "      [+] ise: ANC policy %q applied to %s\n", *isePolicy, ip)
			}
		}

		// Cisco AI Defense — register detected MCP servers for supply chain scanning.
		// AI Defense checks the server's tools, capabilities, and dependencies for
		// prompt injection vulnerabilities and supply chain risks.
		if aiDefenseClient != nil {
			for _, r := range a.Probes {
				if r.State != StateUnauth || r.Family != "agent-platform" {
					continue
				}
				name := fmt.Sprintf("shadow-mcp-%s-%d", ip, r.Port)
				serverURL := fmt.Sprintf("http://%s:%d", ip, r.Port)
				sid, err := aiDefenseClient.RegisterMCPServer(name, serverURL,
					cisco.MCPConnectionSSE, "")
				if err != nil {
					fmt.Fprintf(os.Stderr, "      [!] ai-defense: %v\n", err)
				} else {
					fmt.Fprintf(os.Stderr, "      [+] ai-defense: MCP server submitted for supply chain scan (id: %s)\n", sid)
				}
			}
		}

		// Cisco Secure Network Analytics — query flows TO the shadow AI server's IP
		// to confirm the service is actively used, not just listening. Quantifies
		// client count and byte volume for the finding.
		if snaClient != nil {
			sum, err := snaClient.QueryFlowsToIP(ip, 60)
			if err != nil {
				fmt.Fprintf(os.Stderr, "      [!] sna: %v\n", err)
			} else if sum.TotalFlows > 0 {
				fmt.Fprintf(os.Stderr, "      [+] sna: %d active flow(s) to %s in last 60min (%d bytes)\n",
					sum.TotalFlows, ip, sum.TotalBytes)
				services = append(services,
					fmt.Sprintf("SNA: %d active flows (%d bytes)", sum.TotalFlows, sum.TotalBytes))
			} else {
				fmt.Fprintf(os.Stderr, "      [-] sna: no flows to %s in last 60min (service may be idle)\n", ip)
			}
		}

		// Cisco NSO — push an ACL deny rule to block traffic to the shadow AI server.
		// This enforces containment at the network device level, below SSE and Umbrella.
		if nsoClient != nil {
			blocked, errs := nsoClient.BlockIPViaACLAllDevices(*nsoACL, ip)
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "      [!] nso: %v\n", e)
			}
			if len(blocked) > 0 {
				fmt.Fprintf(os.Stderr, "      [+] nso: ACL deny rule pushed to %d device(s): %s\n",
					len(blocked), strings.Join(blocked, ", "))
			}
		}

		// ThousandEyes correlation — report degraded apps on the same networks.
		if len(teApps) > 0 {
			degraded := cisco.DegradedSummary(teApps, 70)
			if degraded != "" {
				fmt.Fprintf(os.Stderr, "      [!] thousandeyes: degraded apps on same network:\n")
				for _, line := range strings.Split(strings.TrimRight(degraded, "\n"), "\n") {
					fmt.Fprintf(os.Stderr, "            %s\n", line)
				}
				// Append ThousandEyes context to the services list for XDR/Webex.
				services = append(services,
					fmt.Sprintf("ThousandEyes degradation: %s",
						strings.ReplaceAll(strings.TrimRight(degraded, "\n"), "\n", "; ")))
			}
		}

		// ThousandEyes provisioning — if any configured network is eligible for
		// agent activation (not yet installed), activate it now that shadow AI has
		// been confirmed on a device in the org.
		if te != nil && len(supportedNetworkSet) > 0 {
			for _, netID := range netIDStrs {
				if supportedNetworkSet[netID] {
					cfg, provErr := te.ProvisionNetwork(netID, true)
					if provErr != nil {
						fmt.Fprintf(os.Stderr, "      [!] thousandeyes: provision %s: %v\n", netID, provErr)
					} else {
						fmt.Fprintf(os.Stderr, "      [+] thousandeyes: agent activated on network %s\n",
							cfg.NetworkID)
						// Mark as installed so we don't re-provision on subsequent findings.
						delete(supportedNetworkSet, netID)
					}
				}
			}
		}

		// Queue XDR sighting.
		if xdrClient != nil {
			xdrSightings = append(xdrSightings, cisco.Sighting{
				IP: ip, Services: services, ScanTime: a.StartedAt,
			})
		}

		// Per-device Webex notification.
		if webexClient != nil {
			if err := webexClient.Notify(ip, ip, services, a.Blocked); err != nil {
				fmt.Fprintf(os.Stderr, "      [!] webex: %v\n", err)
			}
		}
	}

	// Batch XDR submission.
	if xdrClient != nil && len(xdrSightings) > 0 {
		if err := xdrClient.SubmitSightings(xdrSightings); err != nil {
			fmt.Fprintf(os.Stderr, "[!] xdr: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "[+] xdr: %d sighting(s) submitted\n", len(xdrSightings))
		}
	}

	// Catalog summary to Webex.
	if webexClient != nil {
		if err := webexClient.NotifySummary(len(devices), devicesWithFindings, flaggedIPs); err != nil {
			fmt.Fprintf(os.Stderr, "[!] webex summary: %v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "[+] webex: catalog summary sent")
		}
	}

	fmt.Fprintf(os.Stderr, "\n[=] catalog complete: %d/%d devices with shadow AI/ML services\n",
		devicesWithFindings, len(devices))
}

// unauthServices returns human-readable service strings for all VERIFIED_UNAUTH
// probes in the assessment. These are the findings submitted to Cisco XDR and Webex.
func unauthServices(a Assessment) []string {
	var out []string
	for _, p := range a.Probes {
		if p.State == StateUnauth {
			svc := p.Service
			if svc == "" {
				svc = "unknown"
			}
			out = append(out, fmt.Sprintf("%s :%d [%s]", svc, p.Port, p.State))
		}
	}
	return out
}

// unauthServiceNames returns raw service names (e.g. "ollama", "qdrant") for all
// VERIFIED_UNAUTH probes — used for Cisco AI Taxonomy classification.
func unauthServiceNames(a Assessment) []string {
	var out []string
	for _, p := range a.Probes {
		if p.State == StateUnauth {
			svc := p.Service
			if svc == "" {
				svc = "unknown"
			}
			out = append(out, svc)
		}
	}
	return out
}

// parsePorts parses a comma-separated port list, silently skipping junk.
func parsePorts(csv string) []int {
	var out []int
	for _, f := range strings.Split(csv, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if n, err := strconv.Atoi(f); err == nil && n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	return out
}
