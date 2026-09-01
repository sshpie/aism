package main

// signatures_cisco_infra.go fingerprints Cisco network infrastructure services
// found on enterprise networks alongside shadow AI deployments.
//
// These are not AI/ML platforms — they are the network control plane that
// shadow AI sits behind. Detecting them in the same assessment gives the
// operator the full attack surface picture: unauth LLM at :11434 on a device
// that also has an exposed ASA WebVPN portal at :443 is a chain, not two
// independent findings.
//
// Fingerprints are grounded in live-ASA testing (asa-exploitation-log.txt)
// and binary RE of lina/vpnagentd (anyconnect-ablation, ftd-ablation).

var ciscoInfraSignatures = []llmSignature{

	// Cisco ASA WebVPN — SSL VPN portal exposed on enterprise network devices.
	// The /+CSCOE+/ path prefix is a reliable ASA discriminator; no other
	// platform uses it. SAML metadata endpoint is unauthenticated by design.
	// Deep probe checks the fcadbadd=1 logon bypass (confirmed live) and ASDM.
	{platform: "Cisco ASA WebVPN", family: "network-gateway",
		ports:       []int{443, 8443, 10443},
		rootHint:    "+CSCOE+",
		confirmPath: "/+CSCOE+/logon.html",
		confirmHint: "webvpn",
		noAuth:      false,
		authPath:    "/+CSCOE+/saml/sp/metadata"},

	// Cisco ASDM — Java-based ASA management console.
	// Accessible on the same HTTPS port as WebVPN; /admin/ serves the launcher
	// page with the ASDM JAR URL embedding the exact ASA version string.
	{platform: "Cisco ASDM", family: "network-gateway",
		ports:       []int{443, 8443},
		rootHint:    "asdm",
		confirmPath: "/admin/",
		confirmHint: "ASDM",
		noAuth:      false,
		authPath:    "/admin/"},
}

func init() {
	if len(signatures) == 0 {
		signatures = ciscoInfraSignatures
		return
	}
	last := signatures[len(signatures)-1]
	signatures = append(signatures[:len(signatures)-1], ciscoInfraSignatures...)
	signatures = append(signatures, last)
}
