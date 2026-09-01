package cisco

import (
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
