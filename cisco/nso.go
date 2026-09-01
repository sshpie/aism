package cisco

// NSOClient integrates with Cisco Network Services Orchestrator (NSO) via RESTCONF.
// When tiptoe finds shadow AI on a device, NSO can push an ACL rule to block
// traffic to the shadow AI server's IP at the network layer — enforced on the
// managed device's interface, not just at the SSE or DNS layer.
//
// This adds a 5th containment layer below the existing SSE (IP-layer), Umbrella
// (DNS-layer), Secure Endpoint (endpoint isolation), and ISE (VLAN-quarantine):
//   network device ACL → SSE → Umbrella → ISE → Secure Endpoint
//
// API Reference: https://nso-docs.cisco.com/guides/developer-reference/restconf-api.md
// Base URL: http://{nso-host}:8080/restconf  (HTTPS: port 8443)
// Auth: HTTP Basic (NSO admin credentials)
// Standard: RFC 8040 RESTCONF, RFC 7950 YANG
//
// YANG path for IOS/IOS-XE ACL via NSO device config:
//   /restconf/data/devices/device={name}/config/tailf-ned-cisco-ios:ip/access-list/extended={acl}

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NSOClient pushes network policy changes via Cisco NSO RESTCONF.
type NSOClient struct {
	base   string // e.g. http://nso.corp.example.com:8080/restconf
	user   string
	pass   string
	client *http.Client
}

// NewNSOClient returns a client for NSO RESTCONF.
// host: hostname or IP of the NSO server.
// port: typically 8080 (HTTP) or 8443 (HTTPS). The default NSO RESTCONF port is 8080.
func NewNSOClient(host, user, pass string, port int) *NSOClient {
	scheme := "http"
	if port == 8443 || port == 443 {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s:%d/restconf", scheme, host, port)
	return &NSOClient{
		base:   base,
		user:   user,
		pass:   pass,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *NSOClient) do(method, path string, body any) (*http.Response, error) {
	var r *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	var req *http.Request
	var err error
	if r != nil {
		req, err = http.NewRequest(method, c.base+path, r)
	} else {
		req, err = http.NewRequest(method, c.base+path, nil)
	}
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("Accept", "application/yang-data+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/yang-data+json")
	}
	return c.client.Do(req)
}

// NSODevice is a managed device entry from the NSO device list.
type NSODevice struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// ListDevices returns all managed devices from the NSO device tree.
// GET /restconf/data/devices/device?fields=name;address
func (c *NSOClient) ListDevices() ([]NSODevice, error) {
	resp, err := c.do("GET", "/data/devices/device?fields=name;address", nil)
	if err != nil {
		return nil, fmt.Errorf("nso: list devices: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("nso: list devices: HTTP %d", resp.StatusCode)
	}
	var result struct {
		TailfNcsDp struct {
			Device []NSODevice `json:"device"`
		} `json:"tailf-ncs:devices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("nso: list devices: decode: %w", err)
	}
	return result.TailfNcsDp.Device, nil
}

// BlockIPViaACL pushes an extended ACL deny rule for the given destination IP
// to the named device through NSO.
//
// The ACL named aclName must already exist on the device; tiptoe adds a new
// deny-any rule at the given sequence number. A sequence of 0 appends to the
// end of the ACL (NSO auto-assigns the sequence).
//
// PATCH /restconf/data/devices/device={deviceName}/config/
//
//	tailf-ned-cisco-ios:ip/access-list/extended={aclName}
//
// YANG body adds a "deny ip any host {destIP}" rule.
func (c *NSOClient) BlockIPViaACL(deviceName, aclName, destIP string, sequence int) error {
	encDevice := url.PathEscape(deviceName)
	encACL := url.PathEscape(aclName)
	path := fmt.Sprintf("/data/devices/device=%s/config/tailf-ned-cisco-ios:ip/access-list/extended=%s",
		encDevice, encACL)

	type ruleEntry struct {
		ID     int    `json:"id,omitempty"`
		Action string `json:"action"`
		Proto  string `json:"protocol"`
		SrcAny bool   `json:"source-any,omitempty"`
		DstHost string `json:"destination-host,omitempty"`
	}

	type aclEntry struct {
		Name  string      `json:"name"`
		Rule  []ruleEntry `json:"rule"`
	}

	rule := ruleEntry{
		Action:  "deny",
		Proto:   "ip",
		SrcAny:  true,
		DstHost: destIP,
	}
	if sequence > 0 {
		rule.ID = sequence
	}

	body := map[string]any{
		"tailf-ned-cisco-ios:extended": []aclEntry{{
			Name: aclName,
			Rule: []ruleEntry{rule},
		}},
	}

	resp, err := c.do("PATCH", path, body)
	if err != nil {
		return fmt.Errorf("nso: block IP ACL: %w", err)
	}
	defer resp.Body.Close()
	// RESTCONF PATCH returns 204 No Content on success.
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("nso: block IP ACL: HTTP %d", resp.StatusCode)
	}
	return nil
}

// BlockIPViaACLAllDevices pushes the deny rule to every managed device
// that NSO has in its device tree. Skips devices that return errors (logged
// to errs) rather than stopping on first failure.
func (c *NSOClient) BlockIPViaACLAllDevices(aclName, destIP string) (blocked []string, errs []error) {
	devices, err := c.ListDevices()
	if err != nil {
		return nil, []error{fmt.Errorf("nso: list devices: %w", err)}
	}
	for _, dev := range devices {
		if err := c.BlockIPViaACL(dev.Name, aclName, destIP, 0); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", dev.Name, err))
			continue
		}
		blocked = append(blocked, dev.Name)
	}
	return blocked, errs
}

// SyncDevice triggers NSO to sync the device's running configuration from
// the live device. Run before reading or patching device config to ensure
// NSO's CDB reflects the current device state.
//
// POST /restconf/operations/devices/device={name}/sync-from
func (c *NSOClient) SyncDevice(deviceName string) error {
	encDevice := url.PathEscape(deviceName)
	path := "/operations/devices/device=" + encDevice + "/sync-from"

	req, err := http.NewRequest("POST", c.base+path, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("Content-Type", "application/yang-data+json")
	req.Header.Set("Accept", "application/yang-data+json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("nso: sync-from %s: %w", deviceName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("nso: sync-from %s: HTTP %d", deviceName, resp.StatusCode)
	}
	return nil
}
