package cisco

// StealthwatchClient integrates with Cisco Secure Network Analytics (SNA),
// formerly known as Stealthwatch Enterprise.
//
// When tiptoe detects a shadow AI service on a host, SNA can confirm whether
// that service is actively being used: flow queries show who is connecting to
// it and how much traffic has passed. Security event queries show whether SNA
// has already flagged anomalous behavior from that host.
//
// Both vectors turn a "service is listening" finding into a "service is in use"
// finding — quantified with client count, byte volume, and any existing alerts.
//
// API Reference: https://developer.cisco.com/docs/stealthwatch/
// Auth:    POST https://{smc-host}/token/v2/authenticate (cookie + XSRF-TOKEN)
// Flows:   /sw-reporting/v2/tenants/{tid}/flows/queries
// Events:  /sw-reporting/v1/tenants/{tid}/security-events/queries
// Logout:  DELETE https://{smc-host}/token

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

const xsrfHeader = "X-XSRF-TOKEN"

// StealthwatchClient queries Cisco Secure Network Analytics for flow and
// security event data correlated with shadow AI findings.
type StealthwatchClient struct {
	host      string // e.g. "sna.corp.example.com" (no scheme, no trailing slash)
	tenantID  string
	xsrfToken string
	client    *http.Client
}

// NewStealthwatchClient creates a client and authenticates to the SMC.
// host: FQDN of the Stealthwatch Management Console, no scheme.
// tenantID: numeric tenant ID (visible in the SMC URL or via GET /sw-reporting/v2/tenants).
// SNA deployments typically use self-signed TLS; certificate verification is
// skipped to match the behavior of Cisco's own sample scripts.
func NewStealthwatchClient(host, user, pass, tenantID string) (*StealthwatchClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	c := &StealthwatchClient{
		host:     strings.TrimRight(host, "/"),
		tenantID: tenantID,
		client: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
			Jar: jar,
		},
	}
	if err := c.authenticate(user, pass); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *StealthwatchClient) base() string {
	return "https://" + c.host
}

// authenticate performs the SMC session login.
// POST /token/v2/authenticate sets the session cookie; the XSRF-TOKEN cookie
// value must be echoed back as X-XSRF-TOKEN on all subsequent requests.
func (c *StealthwatchClient) authenticate(user, pass string) error {
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass)
	resp, err := c.client.Post(c.base()+"/token/v2/authenticate",
		"application/json", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("sna: auth: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("sna: auth: HTTP %d", resp.StatusCode)
	}
	// Extract XSRF-TOKEN from the response cookies.
	// The cookie jar also retains the session cookie for subsequent requests.
	for _, ck := range resp.Cookies() {
		if ck.Name == "XSRF-TOKEN" {
			c.xsrfToken = ck.Value
			break
		}
	}
	return nil
}

// Close logs out of the SMC session.
// Call defer client.Close() after NewStealthwatchClient succeeds.
func (c *StealthwatchClient) Close() {
	req, err := http.NewRequest("DELETE", c.base()+"/token", nil)
	if err != nil {
		return
	}
	req.Header.Set(xsrfHeader, c.xsrfToken)
	c.client.Do(req) //nolint:errcheck
}

func (c *StealthwatchClient) post(path string, body any) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", c.base()+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(xsrfHeader, c.xsrfToken)
	return c.client.Do(req)
}

func (c *StealthwatchClient) get(path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", c.base()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set(xsrfHeader, c.xsrfToken)
	return c.client.Do(req)
}

// SNAFlow is a single network flow record from SNA.
type SNAFlow struct {
	Subject  string `json:"subject"`
	Peer     string `json:"peer"`
	Protocol int    `json:"protocol"`
	Bytes    int64  `json:"bytes"`
	Packets  int64  `json:"packets"`
}

// FlowSummary is the aggregated result of a flow query.
type FlowSummary struct {
	Flows       []SNAFlow
	TotalBytes  int64
	TotalFlows  int
}

// QueryFlowsToIP returns all flows TO the given IP observed in the last
// durationMinutes minutes. Use to confirm whether a detected shadow AI
// service has live connections and quantify usage.
//
// POST /sw-reporting/v2/tenants/{tid}/flows/queries
// GET  /sw-reporting/v2/tenants/{tid}/flows/queries/{id}
// GET  /sw-reporting/v2/tenants/{tid}/flows/queries/{id}/results
func (c *StealthwatchClient) QueryFlowsToIP(ip string, durationMinutes int) (*FlowSummary, error) {
	if durationMinutes <= 0 {
		durationMinutes = 60
	}
	now := time.Now().UTC()
	start := now.Add(-time.Duration(durationMinutes) * time.Minute)

	requestBody := map[string]any{
		"startDateTime": start.Format("2006-01-02T15:04:05Z"),
		"endDateTime":   now.Format("2006-01-02T15:04:05Z"),
		"recordLimit":   100,
		"peer": map[string]any{
			"ipAddresses": map[string]any{
				"includes": []string{ip},
			},
		},
	}

	tenantPath := "/sw-reporting/v2/tenants/" + c.tenantID
	resp, err := c.post(tenantPath+"/flows/queries", requestBody)
	if err != nil {
		return nil, fmt.Errorf("sna: flow query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("sna: flow query: HTTP %d", resp.StatusCode)
	}

	var qresp struct {
		Data struct {
			Query struct {
				ID              string  `json:"id"`
				PercentComplete float64 `json:"percentComplete"`
			} `json:"query"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&qresp); err != nil {
		return nil, fmt.Errorf("sna: flow query: decode: %w", err)
	}
	queryID := qresp.Data.Query.ID

	// Poll until complete (max 60s).
	deadline := time.Now().Add(60 * time.Second)
	for qresp.Data.Query.PercentComplete < 100.0 {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("sna: flow query %s timed out", queryID)
		}
		time.Sleep(2 * time.Second)
		r, err := c.get(tenantPath + "/flows/queries/" + queryID)
		if err != nil {
			return nil, fmt.Errorf("sna: flow query poll: %w", err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if err := json.Unmarshal(b, &qresp); err != nil {
			return nil, fmt.Errorf("sna: flow query poll: decode: %w", err)
		}
	}

	// Retrieve results.
	r, err := c.get(tenantPath + "/flows/queries/" + queryID + "/results")
	if err != nil {
		return nil, fmt.Errorf("sna: flow results: %w", err)
	}
	defer r.Body.Close()
	var rresp struct {
		Data struct {
			Flows []SNAFlow `json:"flows"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&rresp); err != nil {
		return nil, fmt.Errorf("sna: flow results: decode: %w", err)
	}

	sum := &FlowSummary{Flows: rresp.Data.Flows, TotalFlows: len(rresp.Data.Flows)}
	for _, f := range rresp.Data.Flows {
		sum.TotalBytes += f.Bytes
	}
	return sum, nil
}

// SNASecurityEvent is a single SNA security event.
type SNASecurityEvent struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	HostIP      string `json:"hostIpAddress"`
	Severity    string `json:"severity"`
	DateTime    string `json:"timestamp"`
}

// QuerySecurityEventsForIP returns recent security events flagged by SNA
// for the given IP (last durationMinutes minutes). Complements flow data
// with behavioral anomalies SNA has already detected on the host.
//
// POST /sw-reporting/v1/tenants/{tid}/security-events/queries
// GET  /sw-reporting/v1/tenants/{tid}/security-events/queries/{id}
// GET  /sw-reporting/v1/tenants/{tid}/security-events/results/{id}
func (c *StealthwatchClient) QuerySecurityEventsForIP(ip string, durationMinutes int) ([]SNASecurityEvent, error) {
	if durationMinutes <= 0 {
		durationMinutes = 60
	}
	now := time.Now().UTC()
	start := now.Add(-time.Duration(durationMinutes) * time.Minute)

	requestBody := map[string]any{
		"timeRange": map[string]string{
			"from": start.Format("2006-01-02T15:04:05Z"),
			"to":   now.Format("2006-01-02T15:04:05Z"),
		},
		"hosts": []map[string]string{
			{"ipAddress": ip},
		},
	}

	tenantPath := "/sw-reporting/v1/tenants/" + c.tenantID
	resp, err := c.post(tenantPath+"/security-events/queries", requestBody)
	if err != nil {
		return nil, fmt.Errorf("sna: security-events query: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("sna: security-events query: HTTP %d", resp.StatusCode)
	}

	var qresp struct {
		Data struct {
			PercentComplete float64 `json:"percentComplete"`
			SearchJobID     string  `json:"searchJobId"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&qresp); err != nil {
		return nil, fmt.Errorf("sna: security-events query: decode: %w", err)
	}
	searchID := qresp.Data.SearchJobID

	deadline := time.Now().Add(60 * time.Second)
	for qresp.Data.PercentComplete < 100.0 {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("sna: security-events query %s timed out", searchID)
		}
		time.Sleep(2 * time.Second)
		r, err := c.get(tenantPath + "/security-events/queries/" + searchID)
		if err != nil {
			return nil, fmt.Errorf("sna: security-events poll: %w", err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if err := json.Unmarshal(b, &qresp); err != nil {
			return nil, fmt.Errorf("sna: security-events poll: decode: %w", err)
		}
	}

	r, err := c.get(tenantPath + "/security-events/results/" + searchID)
	if err != nil {
		return nil, fmt.Errorf("sna: security-events results: %w", err)
	}
	defer r.Body.Close()
	var rresp struct {
		Data struct {
			Results []SNASecurityEvent `json:"results"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&rresp); err != nil {
		return nil, fmt.Errorf("sna: security-events results: decode: %w", err)
	}
	return rresp.Data.Results, nil
}
