package cisco

// SecureEndpoint integrates with the Cisco Secure Endpoint (AMP) API v3.
// When aism finds shadow AI on a managed device it can:
//   - Look up the Secure Endpoint connector installed on that device by IP
//   - Optionally trigger endpoint isolation (requires --amp-isolate flag)
//
// API Reference: https://developer.cisco.com/docs/secure-endpoint/
// Base URL (NAM): https://api.amp.cisco.com/v3
// Auth: HTTP Basic — client_id:api_key

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ampCloudBases maps the cloud region name to the API base URL.
var ampCloudBases = map[string]string{
	"nam":  "https://api.amp.cisco.com/v3",
	"eu":   "https://api.eu.amp.cisco.com/v3",
	"apjc": "https://api.apjc.amp.cisco.com/v3",
}

// SecureEndpointClient queries the Cisco Secure Endpoint API.
type SecureEndpointClient struct {
	clientID string
	apiKey   string
	base     string
	client   *http.Client
}

// NewSecureEndpointClient returns a client for the given cloud region.
// cloud: "nam" (default) | "eu" | "apjc"
func NewSecureEndpointClient(clientID, apiKey, cloud string) *SecureEndpointClient {
	base, ok := ampCloudBases[strings.ToLower(cloud)]
	if !ok {
		base = ampCloudBases["nam"]
	}
	return &SecureEndpointClient{
		clientID: clientID,
		apiKey:   apiKey,
		base:     base,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *SecureEndpointClient) get(path string, out any) error {
	req, err := http.NewRequest("GET", c.base+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.clientID, c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("secure-endpoint: GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("secure-endpoint: GET %s: HTTP %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("secure-endpoint: GET %s: decode: %w", path, err)
	}
	return nil
}

// FindByIP looks up the Secure Endpoint connector installed on the device
// with the given management IP. Returns the connector GUID, hostname, and any
// error. Returns ("", "", nil) when no managed endpoint matches the IP.
//
// GET /computers?internal_ip={ip}
func (c *SecureEndpointClient) FindByIP(ip string) (guid, hostname string, err error) {
	path := "/computers?internal_ip=" + url.QueryEscape(ip)

	var resp struct {
		Data []struct {
			ConnectorGUID string `json:"connector_guid"`
			Hostname      string `json:"hostname"`
		} `json:"data"`
	}
	if err := c.get(path, &resp); err != nil {
		return "", "", err
	}
	if len(resp.Data) == 0 {
		return "", "", nil
	}
	return resp.Data[0].ConnectorGUID, resp.Data[0].Hostname, nil
}

// Isolate triggers network isolation on the endpoint identified by connectorGUID.
// Isolation severs the endpoint's network access while keeping the Secure Endpoint
// connector connected to the cloud for remediation.
//
// PUT /computers/{connector_guid}/isolation
func (c *SecureEndpointClient) Isolate(connectorGUID, comment string) error {
	path := "/computers/" + url.PathEscape(connectorGUID) + "/isolation"

	body, err := json.Marshal(map[string]string{
		"comment": comment,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", c.base+path, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.clientID, c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("secure-endpoint: isolate: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("secure-endpoint: isolate: HTTP %d", resp.StatusCode)
	}
	return nil
}

// StopIsolation removes the isolation policy from a connector.
// Use to restore network access after a finding is remediated.
//
// DELETE /computers/{connector_guid}/isolation
func (c *SecureEndpointClient) StopIsolation(connectorGUID string) error {
	path := "/computers/" + url.PathEscape(connectorGUID) + "/isolation"

	req, err := http.NewRequest("DELETE", c.base+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.clientID, c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("secure-endpoint: stop-isolation: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("secure-endpoint: stop-isolation: HTTP %d", resp.StatusCode)
	}
	return nil
}
