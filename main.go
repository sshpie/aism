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

  ThousandEyes correlation (optional):
  --meraki-api-key <key>      Meraki Dashboard API key
  --meraki-org-id <id>        Meraki organization ID
  --meraki-network-ids <csv>  Meraki network IDs to correlate (comma-separated)

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
			fmt.Fprintln(os.Stderr, "[!] no ports to probe — pass --ports, "+
				"or the host has no passive footprint")
		} else {
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

	// ThousandEyes — query once upfront and cache; correlate after each finding.
	var teApps []cisco.TEApplication
	if *merakiAPIKey != "" && *merakiOrgID != "" && *merakiNetworkIDs != "" {
		netIDStrs := strings.Split(*merakiNetworkIDs, ",")
		for i := range netIDStrs {
			netIDStrs[i] = strings.TrimSpace(netIDStrs[i])
		}
		te := cisco.NewMerakiThousandEyesClient(*merakiOrgID, *merakiAPIKey, netIDStrs)
		fmt.Fprintf(os.Stderr, "[*] querying ThousandEyes application assurance (%d network(s))...\n",
			len(netIDStrs))
		var teErr error
		teApps, teErr = te.Applications(0)
		if teErr != nil {
			fmt.Fprintf(os.Stderr, "[!] thousandeyes: %v\n", teErr)
		} else {
			fmt.Fprintf(os.Stderr, "[+] ThousandEyes: %d application(s) loaded\n", len(teApps))
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
			fmt.Fprintf(os.Stderr, "      [-] no ports to probe (no Shodan record, use --ports)\n")
			continue
		}

		a := runAssessment(intel, ports, *timeout, NewPacer(), stderrTTY)
		services := unauthServices(a)
		if len(services) == 0 {
			fmt.Fprintf(os.Stderr, "      [-] no AI/ML services found\n")
			continue
		}

		devicesWithFindings++
		flaggedIPs = append(flaggedIPs, ip)
		fmt.Fprintf(os.Stderr, "      [!] shadow AI/ML: %s\n", strings.Join(services, ", "))

		// Tag the device in Catalyst Center.
		if dev.ID != "" {
			tagDesc := fmt.Sprintf("tiptoe found: %s", strings.Join(services, "; "))
			if err := cc.TagDevice(dev.ID, "shadow-ai-detected", tagDesc); err != nil {
				fmt.Fprintf(os.Stderr, "      [!] catalyst tag: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "      [+] catalyst: tagged device\n")
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
