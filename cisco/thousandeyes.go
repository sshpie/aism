package cisco

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MerakiThousandEyesClient queries ThousandEyes application assurance data
// via the Meraki Dashboard API (beta). Auth is an X-Cisco-Meraki-API-Key
// header — no OAuth2 required.
//
// API: GET /api/v1/organizations/{orgId}/assurance/thousandEyes/applications
type MerakiThousandEyesClient struct {
	OrgID      string
	APIKey     string
	NetworkIDs []string // required by the API; set at construction time
	client     *http.Client
}

// NewMerakiThousandEyesClient returns a client configured for the given Meraki
// organization. networkIDs is the list of Meraki network IDs to query — the API
// requires at least one.
func NewMerakiThousandEyesClient(orgID, apiKey string, networkIDs []string) *MerakiThousandEyesClient {
	return &MerakiThousandEyesClient{
		OrgID:      orgID,
		APIKey:     apiKey,
		NetworkIDs: networkIDs,
		client:     &http.Client{Timeout: 30 * time.Second},
	}
}

// TEApplication is one ThousandEyes-monitored application with its health score
// and any active alerts for a given network.
type TEApplication struct {
	AppID       string
	TestID      string
	Description string
	TagName     string
	NetworkID   string
	NetworkName string

	Score       int // 0-100; lower = worse
	ScoreChange int // delta vs. previous period

	ImpactedClientsTotal       int
	ImpactedClientsNetwork     int
	ImpactedClientsApplication int

	AgentDeployed bool
	AgentEnabled  bool

	Issues []TEIssue
}

// TEIssue is one active ThousandEyes alert on an application.
type TEIssue struct {
	AlertID  string
	Type     string
	Message  string
	Impacted bool
}

// Degraded returns true if the application score is below the threshold (0-100).
// A threshold of 70 is a reasonable default for "poor health."
func (a *TEApplication) Degraded(threshold int) bool {
	return a.Score < threshold
}

// raw API response types

type teAppResponse struct {
	SelectedClient string        `json:"selectedClient"`
	Applications   []teAppEntry  `json:"applications"`
	Score          teScore       `json:"score"`
	Agent          teAgent       `json:"agent"`
	Network        teNetwork     `json:"network"`
}

type teAppEntry struct {
	AppID                          string    `json:"appId"`
	TestID                         string    `json:"testId"`
	Description                    string    `json:"description"`
	TagName                        string    `json:"tagName"`
	ImpactedClientsTotalCount      int       `json:"impactedClientsTotalCount"`
	NetworkImpactedClientsCount    int       `json:"networkImpactedClientsCount"`
	ApplicationImpactedClientsCount int      `json:"applicationImpactedClientsCount"`
	Issues                         []teIssue `json:"issues"`
}

type teIssue struct {
	AlertID  string `json:"alertId"`
	Type     string `json:"type"`
	Message  string `json:"message"`
	Impacted bool   `json:"impacted"`
}

type teScore struct {
	Score  int `json:"score"`
	Change int `json:"change"`
}

type teAgent struct {
	Deployed bool `json:"deployed"`
	Enabled  bool `json:"enabled"`
}

type teNetwork struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Applications returns ThousandEyes application health for the client's networks.
// timespanSeconds is the lookback window (300–604800); pass 0 to use the API default (7200).
func (c *MerakiThousandEyesClient) Applications(timespanSeconds float64) ([]TEApplication, error) {
	base := fmt.Sprintf(
		"https://api.meraki.com/api/v1/organizations/%s/assurance/thousandEyes/applications",
		url.PathEscape(c.OrgID))

	params := url.Values{}
	for _, id := range c.NetworkIDs {
		params.Add("networkIds[]", id)
	}
	if timespanSeconds > 0 {
		params.Set("timespan", fmt.Sprintf("%.0f", timespanSeconds))
	}

	req, err := http.NewRequest("GET", base+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Cisco-Meraki-API-Key", c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("thousandeyes: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("thousandeyes: API returned %d", resp.StatusCode)
	}

	// The API returns an array of per-network result objects.
	var raw []teAppResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("thousandeyes: decode: %w", err)
	}

	var out []TEApplication
	for _, r := range raw {
		for _, app := range r.Applications {
			a := TEApplication{
				AppID:                      app.AppID,
				TestID:                     app.TestID,
				Description:                app.Description,
				TagName:                    app.TagName,
				NetworkID:                  r.Network.ID,
				NetworkName:                r.Network.Name,
				Score:                      r.Score.Score,
				ScoreChange:                r.Score.Change,
				ImpactedClientsTotal:       app.ImpactedClientsTotalCount,
				ImpactedClientsNetwork:     app.NetworkImpactedClientsCount,
				ImpactedClientsApplication: app.ApplicationImpactedClientsCount,
				AgentDeployed:              r.Agent.Deployed,
				AgentEnabled:               r.Agent.Enabled,
			}
			for _, iss := range app.Issues {
				a.Issues = append(a.Issues, TEIssue{
					AlertID:  iss.AlertID,
					Type:     iss.Type,
					Message:  iss.Message,
					Impacted: iss.Impacted,
				})
			}
			out = append(out, a)
		}
	}
	return out, nil
}

// --- Provisioning (extensions API) ---
// These endpoints activate ThousandEyes agents on Meraki-managed networks.
// Auth: same X-Cisco-Meraki-API-Key used for the assurance API.
// Scope required: dashboard:general:config:write (POST/PUT/DELETE).
//                 dashboard:general:config:read  (GET).

const merakiBase = "https://api.meraki.com/api/v1"

// TENetworkConfig represents a ThousandEyes agent configuration for a Meraki network.
type TENetworkConfig struct {
	NetworkID   string   `json:"networkId"`
	NetworkName string   `json:"networkName,omitempty"`
	Enabled     bool     `json:"enabled"`
	Tests       []TETest `json:"tests,omitempty"`
}

// TETest is a ThousandEyes test attached to a network TE agent.
type TETest struct {
	TestID   string `json:"testId,omitempty"`
	TestName string `json:"testName,omitempty"`
	Network  struct {
		ID string `json:"id"`
	} `json:"network"`
}

// SupportedNetworks lists Meraki network IDs that are eligible for ThousandEyes
// agent activation under the configured organization.
// GET /organizations/{orgId}/extensions/thousandEyes/networks/supported
// agentInstalled: nil = all eligible; true = already has agent; false = eligible but no agent yet.
func (c *MerakiThousandEyesClient) SupportedNetworks(agentInstalled *bool) ([]string, error) {
	endpoint := fmt.Sprintf("%s/organizations/%s/extensions/thousandEyes/networks/supported",
		merakiBase, url.PathEscape(c.OrgID))

	params := url.Values{}
	params.Set("perPage", "500")
	if agentInstalled != nil {
		if *agentInstalled {
			params.Set("agentInstalled", "true")
		} else {
			params.Set("agentInstalled", "false")
		}
	}

	req, err := http.NewRequest("GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Cisco-Meraki-API-Key", c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("thousandeyes: supported: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("thousandeyes: supported: HTTP %d", resp.StatusCode)
	}

	// Response is an array of network objects with at least a networkId field.
	var raw []struct {
		NetworkID string `json:"networkId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("thousandeyes: supported: decode: %w", err)
	}

	ids := make([]string, 0, len(raw))
	for _, n := range raw {
		ids = append(ids, n.NetworkID)
	}
	return ids, nil
}

// ProvisionNetwork activates a ThousandEyes agent on the given Meraki network.
// This is a write operation — requires dashboard:general:config:write scope.
// POST /organizations/{orgId}/extensions/thousandEyes/networks
// Returns the created config on success.
func (c *MerakiThousandEyesClient) ProvisionNetwork(networkID string, enabled bool) (*TENetworkConfig, error) {
	endpoint := fmt.Sprintf("%s/organizations/%s/extensions/thousandEyes/networks",
		merakiBase, url.PathEscape(c.OrgID))

	body, err := json.Marshal(map[string]interface{}{
		"networkId": networkID,
		"enabled":   enabled,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Cisco-Meraki-API-Key", c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("thousandeyes: provision: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return nil, fmt.Errorf("thousandeyes: provision: HTTP %d", resp.StatusCode)
	}

	var cfg TENetworkConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("thousandeyes: provision: decode: %w", err)
	}
	return &cfg, nil
}

// ListNetworkConfigs returns all ThousandEyes network agent configurations
// currently active under the organization.
// GET /organizations/{orgId}/extensions/thousandEyes/networks
func (c *MerakiThousandEyesClient) ListNetworkConfigs() ([]TENetworkConfig, error) {
	endpoint := fmt.Sprintf("%s/organizations/%s/extensions/thousandEyes/networks",
		merakiBase, url.PathEscape(c.OrgID))

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Cisco-Meraki-API-Key", c.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("thousandeyes: list configs: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("thousandeyes: list configs: HTTP %d", resp.StatusCode)
	}

	var cfgs []TENetworkConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfgs); err != nil {
		return nil, fmt.Errorf("thousandeyes: list configs: decode: %w", err)
	}
	return cfgs, nil
}

// DegradedSummary returns a human-readable summary of all applications with
// score below threshold. Used in Webex alerts to correlate shadow AI findings
// with measurable application degradation on the same network.
func DegradedSummary(apps []TEApplication, threshold int) string {
	var degraded []TEApplication
	for _, a := range apps {
		if a.Degraded(threshold) {
			degraded = append(degraded, a)
		}
	}
	if len(degraded) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, a := range degraded {
		sb.WriteString(fmt.Sprintf("%s (score %d, %+d) — %d client(s) impacted",
			a.Description, a.Score, a.ScoreChange, a.ImpactedClientsTotal))
		if len(a.Issues) > 0 {
			sb.WriteString(fmt.Sprintf("; alerts: %s", a.Issues[0].Message))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
