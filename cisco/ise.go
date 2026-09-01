package cisco

// ISE integrates with Cisco Identity Services Engine (ISE) via the ERS API.
// When aism finds shadow AI on a managed device, it applies an ANC
// (Adaptive Network Control) quarantine policy to the endpoint by IP.
//
// ISE then re-routes the device through a restricted quarantine VLAN and
// can require re-authentication, removing network access until the shadow AI
// is remediated and the ANC policy is cleared.
//
// API Reference: https://developer.cisco.com/docs/identity-services-engine/
// Base URL: https://{ise_host}:9060/ers
// Auth: HTTP Basic (ISE admin credentials)
// Required: ERS and ANC features enabled in ISE; admin has ERS permissions.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ISEClient applies ANC policies via the Cisco ISE ERS API.
type ISEClient struct {
	base   string // e.g. https://ise.corp.example.com:9060/ers
	user   string
	pass   string
	client *http.Client
}

// NewISEClient returns a client for the Cisco ISE ERS API.
// baseURL: full base including port, e.g. "https://ise.corp.example.com:9060"
func NewISEClient(baseURL, user, pass string) *ISEClient {
	return &ISEClient{
		base:   strings.TrimRight(baseURL, "/") + "/ers",
		user:   user,
		pass:   pass,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *ISEClient) do(method, path string, body any) (*http.Response, error) {
	var bodyReader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(b)
	}

	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequest(method, c.base+path, bodyReader)
	} else {
		req, err = http.NewRequest(method, c.base+path, nil)
	}
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.client.Do(req)
}

// iseEndpointSearchResp is the ERS endpoint search response.
type iseEndpointSearchResp struct {
	SearchResult struct {
		Resources []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"resources"`
	} `json:"SearchResult"`
}

// FindByIP returns the ISE endpoint ID for the given IP address.
// Returns "" if no managed endpoint matches.
//
// GET /config/endpoint?filter=ipAddress.EQ.{ip}
func (c *ISEClient) FindByIP(ip string) (id string, err error) {
	filter := url.QueryEscape("ipAddress.EQ." + ip)
	resp, err := c.do("GET", "/config/endpoint?filter="+filter, nil)
	if err != nil {
		return "", fmt.Errorf("ise: find endpoint: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return "", nil
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("ise: find endpoint: HTTP %d", resp.StatusCode)
	}
	var r iseEndpointSearchResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", fmt.Errorf("ise: find endpoint: decode: %w", err)
	}
	if len(r.SearchResult.Resources) == 0 {
		return "", nil
	}
	return r.SearchResult.Resources[0].ID, nil
}

// ApplyANC applies an ANC quarantine policy to the endpoint at the given IP.
// The policy name must exist in ISE — the default is "shadow-ai-quarantine"
// (create this in ISE Policy > Policy Elements > ANC Policies).
//
// ISE ERS ANC endpoint apply:
// POST /config/ancendpoint
// {"OperationAdditionalData": {"additionalData": [
//
//	{"name": "ipAddress", "value": ip},
//	{"name": "policyName", "value": policy}
//
// ]}}
func (c *ISEClient) ApplyANC(ip, policyName string) error {
	body := map[string]interface{}{
		"OperationAdditionalData": map[string]interface{}{
			"additionalData": []map[string]string{
				{"name": "ipAddress", "value": ip},
				{"name": "policyName", "value": policyName},
			},
		},
	}
	resp, err := c.do("POST", "/config/ancendpoint/apply", body)
	if err != nil {
		return fmt.Errorf("ise: apply ANC: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("ise: apply ANC: HTTP %d", resp.StatusCode)
	}
	return nil
}

// ClearANC removes an ANC policy from the endpoint at the given IP,
// restoring normal network access after a finding is remediated.
//
// POST /config/ancendpoint/clear
func (c *ISEClient) ClearANC(ip, policyName string) error {
	body := map[string]interface{}{
		"OperationAdditionalData": map[string]interface{}{
			"additionalData": []map[string]string{
				{"name": "ipAddress", "value": ip},
				{"name": "policyName", "value": policyName},
			},
		},
	}
	resp, err := c.do("POST", "/config/ancendpoint/clear", body)
	if err != nil {
		return fmt.Errorf("ise: clear ANC: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("ise: clear ANC: HTTP %d", resp.StatusCode)
	}
	return nil
}
