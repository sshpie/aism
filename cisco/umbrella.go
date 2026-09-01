package cisco

// Umbrella integrates with the Cisco Umbrella Policies API v2.
// When aism finds shadow AI, it adds the server's IP to a blocked
// destination list in Umbrella — enforcing DNS-layer blocking on all
// endpoints that resolve DNS through the Umbrella resolver.
//
// This complements Cisco Secure Access (SSE) IP-layer blocking with
// DNS-layer blocking: SSE drops packets; Umbrella drops DNS queries.
//
// API Reference: https://developer.cisco.com/docs/cloud-security/
// Base URL: https://api.umbrella.com/policies/v2
// Auth: OAuth2 client credentials — https://api.umbrella.com/auth/v2/token

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
	umbrellaBase    = "https://api.umbrella.com/policies/v2"
	umbrellaAuthURL = "https://api.umbrella.com/auth/v2/token"
)

// UmbrellaClient submits shadow AI findings to Cisco Umbrella as DNS-blocked
// destinations, enforcing query-level containment before a TCP connection forms.
type UmbrellaClient struct {
	clientID     string
	clientSecret string
	token        string
	tokenExpiry  time.Time
	orgID        string // resolved after first auth
	client       *http.Client
}

// NewUmbrellaClient returns a client for the Cisco Umbrella Policies API.
func NewUmbrellaClient(clientID, clientSecret string) *UmbrellaClient {
	return &UmbrellaClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

// authenticate fetches an OAuth2 bearer token using client credentials.
// Tokens are cached until 60s before expiry.
func (c *UmbrellaClient) authenticate() error {
	if c.token != "" && time.Now().Before(c.tokenExpiry.Add(-60*time.Second)) {
		return nil
	}

	body := url.Values{}
	body.Set("grant_type", "client_credentials")

	req, err := http.NewRequest("POST", umbrellaAuthURL, strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.clientID, c.clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("umbrella: auth: %w", err)
	}
	defer resp.Body.Close()

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
		OrgID       string `json:"org_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return fmt.Errorf("umbrella: auth: decode: %w", err)
	}
	if tok.AccessToken == "" {
		return fmt.Errorf("umbrella: auth: empty token (HTTP %d)", resp.StatusCode)
	}

	c.token = tok.AccessToken
	c.orgID = tok.OrgID
	c.tokenExpiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return nil
}

func (c *UmbrellaClient) authHeader(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
}

type umbrellaDestList struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Access     string `json:"access"`
	IsGlobal   bool   `json:"isGlobal"`
	OrgID      int    `json:"organizationId"`
}

type umbrellaListsResp struct {
	Data []umbrellaDestList `json:"data"`
}

// listDestinationLists returns all destination lists for the organization.
func (c *UmbrellaClient) listDestinationLists() ([]umbrellaDestList, error) {
	if err := c.authenticate(); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("%s/organizations/%s/destinationlists", umbrellaBase, c.orgID)
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	c.authHeader(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("umbrella: list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("umbrella: list: HTTP %d", resp.StatusCode)
	}
	var r umbrellaListsResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("umbrella: list: decode: %w", err)
	}
	return r.Data, nil
}

// findOrCreateBlockList returns the ID of the named destination block list,
// creating it if it doesn't exist.
func (c *UmbrellaClient) findOrCreateBlockList(name string) (int, error) {
	lists, err := c.listDestinationLists()
	if err != nil {
		return 0, err
	}
	for _, l := range lists {
		if l.Name == name {
			return l.ID, nil
		}
	}

	// Create a new block list.
	createBody, err := json.Marshal(map[string]interface{}{
		"name":     name,
		"access":   "block",
		"isGlobal": false,
	})
	if err != nil {
		return 0, err
	}
	path := fmt.Sprintf("%s/organizations/%s/destinationlists", umbrellaBase, c.orgID)
	req, err := http.NewRequest("POST", path, bytes.NewReader(createBody))
	if err != nil {
		return 0, err
	}
	c.authHeader(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("umbrella: create list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return 0, fmt.Errorf("umbrella: create list: HTTP %d", resp.StatusCode)
	}
	var r struct {
		Data umbrellaDestList `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return 0, fmt.Errorf("umbrella: create list: decode: %w", err)
	}
	return r.Data.ID, nil
}

// AddDestinations adds IPs to an Umbrella destination list.
// Each destination is submitted as {"destination": ip, "type": "ip"}.
//
// POST /organizations/{orgId}/destinationlists/{listId}/destinations
func (c *UmbrellaClient) AddDestinations(listID int, ips []string) error {
	if len(ips) == 0 {
		return nil
	}

	type dest struct {
		Destination string `json:"destination"`
		Type        string `json:"type"`
		Comment     string `json:"comment,omitempty"`
	}
	dests := make([]dest, len(ips))
	for i, ip := range ips {
		dests[i] = dest{Destination: ip, Type: "ip", Comment: "shadow AI detected by aism"}
	}
	body, err := json.Marshal(dests)
	if err != nil {
		return err
	}

	path := fmt.Sprintf("%s/organizations/%s/destinationlists/%d/destinations",
		umbrellaBase, c.orgID, listID)
	req, err := http.NewRequest("POST", path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.authHeader(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("umbrella: add destinations: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("umbrella: add destinations: HTTP %d", resp.StatusCode)
	}
	return nil
}

// BlockShadowAI adds shadow AI server IPs to the "shadow-ai-detected" blocked
// destination list in Cisco Umbrella. Creates the list if it doesn't exist.
// All endpoints resolving DNS through Umbrella will have queries to these IPs
// blocked immediately after policy propagation.
func (c *UmbrellaClient) BlockShadowAI(ips []string) error {
	if err := c.authenticate(); err != nil {
		return err
	}
	listID, err := c.findOrCreateBlockList("shadow-ai-detected")
	if err != nil {
		return fmt.Errorf("umbrella: ensure list: %w", err)
	}
	return c.AddDestinations(listID, ips)
}
