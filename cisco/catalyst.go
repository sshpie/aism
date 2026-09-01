// Package cisco provides integration adapters for Cisco infrastructure platforms.
// All API calls use the Go standard library only — no external dependencies.
package cisco

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// CatalystClient talks to a Cisco Catalyst Center (formerly DNA Center) instance
// via its northbound Intent API v2.
type CatalystClient struct {
	BaseURL string
	Token   string
	client  *http.Client
}

// NewCatalystClient returns a CatalystClient. Set skipTLS for lab deployments
// with self-signed certificates.
func NewCatalystClient(baseURL, token string, skipTLS bool) *CatalystClient {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS}, //nolint:gosec
	}
	return &CatalystClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		client:  &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}
}

// Device is a managed network device from the Catalyst Center inventory.
type Device struct {
	ID                 string `json:"id"`
	ManagementIPAddr   string `json:"managementIpAddress"`
	Hostname           string `json:"hostname"`
	Platform           string `json:"platformId"`
	ReachabilityStatus string `json:"reachabilityStatus"`
	Role               string `json:"role"`
}

type deviceListResponse struct {
	Response []Device `json:"response"`
}

// Devices returns all managed devices in the Catalyst Center inventory.
// Paginates automatically — returns the full list regardless of size.
func (c *CatalystClient) Devices() ([]Device, error) {
	var all []Device
	offset := 1
	limit := 500
	for {
		url := fmt.Sprintf("%s/dna/intent/api/v1/network-device?offset=%d&limit=%d",
			c.BaseURL, offset, limit)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-Auth-Token", c.Token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("catalyst: get devices: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("catalyst: get devices returned %d", resp.StatusCode)
		}
		var page deviceListResponse
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			return nil, fmt.Errorf("catalyst: decode devices: %w", err)
		}
		all = append(all, page.Response...)
		if len(page.Response) < limit {
			break
		}
		offset += limit
	}
	return all, nil
}

// DeviceByIP returns the first managed device whose management IP matches ip.
// Returns nil, nil if no device is found.
func (c *CatalystClient) DeviceByIP(ip string) (*Device, error) {
	url := fmt.Sprintf("%s/dna/intent/api/v1/network-device/ip-address/%s", c.BaseURL, ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("catalyst: get device by IP: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("catalyst: get device by IP returned %d", resp.StatusCode)
	}
	var dr struct {
		Response Device `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, fmt.Errorf("catalyst: decode device: %w", err)
	}
	return &dr.Response, nil
}

// TagDevice attaches a named tag to the device. Creates the tag if it does not
// already exist. Used to mark devices where shadow AI/ML services were found.
func (c *CatalystClient) TagDevice(deviceID, tagName, description string) error {
	tagID, err := c.ensureTag(tagName, description)
	if err != nil {
		return err
	}

	type memberReq struct {
		NetworkDevice struct {
			ID []string `json:"id"`
		} `json:"networkDevice"`
	}
	var mr memberReq
	mr.NetworkDevice.ID = []string{deviceID}
	body, _ := json.Marshal(mr)

	req, err := http.NewRequest("POST",
		fmt.Sprintf("%s/dna/intent/api/v1/tag/%s/member", c.BaseURL, tagID),
		strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("X-Auth-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("catalyst: tag member: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return fmt.Errorf("catalyst: tag member returned %d", resp.StatusCode)
	}
	return nil
}

// ensureTag returns the ID of the named tag, creating it if necessary.
func (c *CatalystClient) ensureTag(name, description string) (string, error) {
	// Try to fetch the tag by name first.
	if id, err := c.tagIDByName(name); err == nil && id != "" {
		return id, nil
	}

	// Create it.
	type createReq struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	body, _ := json.Marshal(createReq{Name: name, Description: description})
	req, err := http.NewRequest("POST", c.BaseURL+"/dna/intent/api/v2/tag",
		strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Auth-Token", c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("catalyst: create tag: %w", err)
	}
	defer resp.Body.Close()
	// 201 = created, 409 = already exists — both OK.
	if resp.StatusCode != 201 && resp.StatusCode != 200 && resp.StatusCode != 409 {
		return "", fmt.Errorf("catalyst: create tag returned %d", resp.StatusCode)
	}

	return c.tagIDByName(name)
}

type tagListResponse struct {
	Response []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"response"`
}

func (c *CatalystClient) tagIDByName(name string) (string, error) {
	req, err := http.NewRequest("GET",
		c.BaseURL+"/dna/intent/api/v2/tag?name="+name, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Auth-Token", c.Token)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("catalyst: list tags: %w", err)
	}
	defer resp.Body.Close()
	var tlr tagListResponse
	if err := json.NewDecoder(resp.Body).Decode(&tlr); err != nil {
		return "", fmt.Errorf("catalyst: decode tags: %w", err)
	}
	for _, t := range tlr.Response {
		if t.Name == name {
			return t.ID, nil
		}
	}
	return "", fmt.Errorf("catalyst: tag %q not found", name)
}
