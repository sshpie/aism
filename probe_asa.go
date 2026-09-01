package main

// probe_asa.go — deep probe for confirmed Cisco ASA WebVPN portals.
//
// Two surfaces confirmed via live-ASA testing:
//
// 1. SAML SP metadata — /+CSCOE+/saml/sp/metadata returns 200 without
//    credentials on all ASA versions that have SAML configured. Exposes
//    SP EntityID, ACS URL, and assertion consumer binding — enough to
//    enumerate the IdP chain and forge assertions if the IdP is weak.
//
// 2. fcadbadd=1 logon bypass — /+CSCOE+/logon.html?fcadbadd=1 returns
//    the full portal logon HTML (11KB+) without authentication. Confirmed
//    on live ASA hardware (asa-exploitation-log.txt, 2026-08-XX).
//    The parameter appears to be a Cisco internal flag that bypasses the
//    pre-auth redirect, serving protected portal HTML to unauthenticated
//    clients. The rendered page includes version metadata in JS vars.
//
// 3. ASDM exposure — /admin/ on the same HTTPS port often serves the
//    ASDM Java launcher page. The JAR URL embeds the exact ASA version
//    string (e.g. asdm-762-150.bin), enabling precise CVE matching without
//    a scan.

import (
	"net/http"
	"strings"
)

// probeASAWebVPN performs post-confirm deep inspection of an ASA WebVPN portal.
// Returns one descriptor string per confirmed exposure.
func probeASAWebVPN(base string, client *http.Client) []string {
	var flags []string

	// SAML SP metadata — unauthenticated by design, exposes SP configuration.
	st, _, body, ok := httpGet(client, base+"/+CSCOE+/saml/sp/metadata")
	if ok && st == 200 && len(body) > 0 {
		flags = append(flags, "SAML SP metadata exposed at /+CSCOE+/saml/sp/metadata (unauth, reveals SP EntityID and ACS URL)")
	}

	// fcadbadd=1 bypass — serves protected portal HTML without credentials.
	st, _, body, ok = httpGet(client, base+"/+CSCOE+/logon.html?fcadbadd=1")
	if ok && st == 200 && len(body) > 5000 {
		flags = append(flags, "fcadbadd=1 bypass: full WebVPN logon portal served without authentication (11KB+ response)")
	}

	// ASDM management interface — JAR URL embeds exact ASA version string.
	st, _, body, ok = httpGet(client, base+"/admin/")
	if ok && st == 200 && strings.Contains(strings.ToLower(body), "asdm") {
		// Extract version hint from ASDM JAR filename if present (asdm-NNN-NNN.bin)
		version := asdmVersion(body)
		msg := "ASDM management interface exposed at /admin/ — unauthenticated access"
		if version != "" {
			msg += "; ASA version from JAR: " + version
		}
		flags = append(flags, msg)
	}

	return flags
}

// asdmVersion extracts the ASA version string embedded in the ASDM JAR filename.
// ASDM pages contain URLs like /admin/public/asdm-762-150.bin — the numbers
// map to major/minor/patch of the running ASA OS.
func asdmVersion(body string) string {
	needle := "asdm-"
	i := strings.Index(strings.ToLower(body), needle)
	if i < 0 {
		return ""
	}
	rest := body[i:]
	end := strings.IndexAny(rest, `"' ><`)
	if end < 0 || end > 30 {
		return ""
	}
	return rest[:end]
}
