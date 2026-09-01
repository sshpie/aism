package cisco

// SecureAccess integrates with the Cisco Secure Access (SSE) Destination Lists API.
// When aism finds shadow AI on a managed device it adds the server's IP to a
// blocked destination list — SSE then enforces the block on all managed endpoints
// routed through the SSE without any per-device configuration change.
//
// API Reference: https://developer.cisco.com/docs/cloud-security/
// Base URL: https://api.sse.cisco.com/policies/v2
// Auth: OAuth2 client credentials — scope policies.destinationLists:write

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	ssePoliciesBase = "https://api.sse.cisco.com/policies/v2"
	sseAuthURL      = "https://api.sse.cisco.com/auth/v2/token"
	// bundleTypeID 2 = web profile (required by API for new lists).
	sseBundleTypeID = 2
)

// SecureAccessClient submits shadow AI findings to Cisco Secure Access (SSE)
// as blocked destinations, enforcing network-layer containment.
type SecureAccessClient struct {
	ClientID     string
	ClientSecret string
	token        string
	tokenExpiry  time.Time
	client       *http.Client
}

// NewSecureAccessClient returns a client for the Cisco Secure Access policies API.
func NewSecureAccessClient(clientID, clientSecret string) *SecureAccessClient {
	return &SecureAccessClient{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

// authenticate fetches an OAuth2 bearer token using client credentials.
// Tokens are cached until 60s before expiry.
func (c *SecureAccessClient) authenticate() error {
	if c.token != "" && time.Now().Before(c.tokenExpiry.Add(-60*time.Second)) {
		return nil
	}

	body := url.Values{}
	body.Set("grant_type", "client_credentials")
	body.Set("scope", "policies.destinationLists:read policies.destinationLists:write")

	req, err := http.NewRequest("POST", sseAuthURL, strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("secure-access: auth: %w", err)
	}
	defer resp.Body.Close()

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return fmt.Errorf("secure-access: auth: decode: %w", err)
	}
	if tok.AccessToken == "" {
		return fmt.Errorf("secure-access: auth: empty token (HTTP %d)", resp.StatusCode)
	}

	c.token = tok.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return nil
}

// sseDestinationList is the Secure Access destination list object.
type sseDestinationList struct {
	ID           int    `json:"id"`
	OrgID        int    `json:"organizationId"`
	Name         string `json:"name"`
	Access       string `json:"access"`
	IsGlobal     bool   `json:"isGlobal"`
	BundleTypeID int    `json:"bundleTypeId"`
}

type sseListResponse struct {
	Status struct {
		Code int    `json:"code"`
		Text string `json:"text"`
	} `json:"status"`
	Data sseDestinationList `json:"data"`
}

type ssePaginatedListResponse struct {
	Status struct {
		Code int    `json:"code"`
		Text string `json:"text"`
	} `json:"status"`
	Data []sseDestinationList `json:"data"`
	Meta struct {
		Page  int `json:"page"`
		Limit int `json:"limit"`
		Total int `json:"total"`
	} `json:"meta"`
}

// ListDestinationLists returns all destination lists for the organization.
// GET /destinationlists
func (c *SecureAccessClient) ListDestinationLists() ([]sseDestinationList, error) {
	if err := c.authenticate(); err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", ssePoliciesBase+"/destinationlists", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secure-access: list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("secure-access: list: HTTP %d", resp.StatusCode)
	}

	var r ssePaginatedListResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("secure-access: list: decode: %w", err)
	}
	return r.Data, nil
}

// findListByName returns the ID of the first destination list matching name.
// Returns 0 if not found.
func (c *SecureAccessClient) findListByName(name string) (int, error) {
	lists, err := c.ListDestinationLists()
	if err != nil {
		return 0, err
	}
	for _, l := range lists {
		if l.Name == name {
			return l.ID, nil
		}
	}
	return 0, nil
}

// CreateDestinationList creates a new destination list.
// access: "block" to block destinations, "allow" to allow, "none" for monitor-only.
// POST /destinationlists
func (c *SecureAccessClient) CreateDestinationList(name, access string) (int, error) {
	if err := c.authenticate(); err != nil {
		return 0, err
	}

	body, err := json.Marshal(map[string]interface{}{
		"bundleTypeId": sseBundleTypeID,
		"isGlobal":     false,
		"name":         name,
		"access":       access,
	})
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequest("POST", ssePoliciesBase+"/destinationlists", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("secure-access: create list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("secure-access: create list: HTTP %d", resp.StatusCode)
	}

	var r sseListResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return 0, fmt.Errorf("secure-access: create list: decode: %w", err)
	}
	return r.Data.ID, nil
}

// EnsureDestinationList finds an existing destination list by name or creates it.
// Returns the list ID. access is only used when creating — not updated on existing lists.
func (c *SecureAccessClient) EnsureDestinationList(name, access string) (int, error) {
	id, err := c.findListByName(name)
	if err != nil {
		return 0, err
	}
	if id != 0 {
		return id, nil
	}
	return c.CreateDestinationList(name, access)
}

// AddDestinations adds one or more IP addresses or domain names to a destination list.
// Each request accepts up to 500 destinations.
// POST /destinationlists/{id}/destinations
func (c *SecureAccessClient) AddDestinations(listID int, destinations []string) error {
	if err := c.authenticate(); err != nil {
		return err
	}

	// Build the destinations array.
	type destObj struct {
		Destination string `json:"destination"`
	}
	objs := make([]destObj, len(destinations))
	for i, d := range destinations {
		objs[i] = destObj{Destination: d}
	}

	body, err := json.Marshal(objs)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/destinationlists/%d/destinations", ssePoliciesBase, listID)
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("secure-access: add destinations: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("secure-access: add destinations: HTTP %d", resp.StatusCode)
	}
	return nil
}

// BlockShadowAI adds shadow AI server IPs to the "shadow-ai-detected" blocked
// destination list in Cisco Secure Access. Creates the list if it doesn't exist.
// This is the one-call remediation path: detect -> block in SSE.
func (c *SecureAccessClient) BlockShadowAI(ips []string, comment string) error {
	const listName = "shadow-ai-detected"

	listID, err := c.EnsureDestinationList(listName, "block")
	if err != nil {
		return fmt.Errorf("secure-access: ensure list: %w", err)
	}

	if len(ips) == 0 {
		return nil
	}

	// API limit: 500 destinations per request.
	for start := 0; start < len(ips); start += 500 {
		end := start + 500
		if end > len(ips) {
			end = len(ips)
		}
		if err := c.AddDestinations(listID, ips[start:end]); err != nil {
			return err
		}
	}
	return nil
}
