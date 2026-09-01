package cisco

// AIDefenseClient integrates with the Cisco AI Defense Management API.
// When tiptoe detects an MCP server or other AI/ML service on the network,
// it can register that server with AI Defense for supply chain security
// scanning — checking for prompt injection vulnerabilities, exposed tools,
// and unsafe dependencies.
//
// API Reference: https://developer.cisco.com/docs/ai-defense-management/
// Base URL: https://api.security.cisco.com/api/ai-defense/v1
// Auth: x-cisco-ai-defense-tenant-api-key header
//       (Administration > API Keys in the AI Defense UI; separate from the Inspection API key)
//
// Typical flow:
//   1. tiptoe detects an MCP server at http://10.0.0.5:8080
//   2. RegisterMCPServer → AI Defense queues a supply chain scan
//   3. (after scan completes) ListMCPServerThreats → returns severity-filtered findings
//   4. ListRuntimeEvents(MCP_SERVER, Block) → returns any blocked prompt injection events

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const aiDefenseBase = "https://api.security.cisco.com/api/ai-defense/v1"

// AIDefenseClient calls the Cisco AI Defense Management API.
type AIDefenseClient struct {
	apiKey string
	client *http.Client
}

// NewAIDefenseClient returns a client for the AI Defense Management API.
// apiKey is the tenant API key from Administration > API Keys in the AI Defense UI.
func NewAIDefenseClient(apiKey string) *AIDefenseClient {
	return &AIDefenseClient{
		apiKey: apiKey,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *AIDefenseClient) do(method, path string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, aiDefenseBase+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-cisco-ai-defense-tenant-api-key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.client.Do(req)
}

// MCPConnectionType maps tiptoe's detected transport to the AI Defense enum.
type MCPConnectionType string

const (
	MCPConnectionSSE        MCPConnectionType = "SSE"
	MCPConnectionStreamable MCPConnectionType = "STREAMABLE"
	MCPConnectionStdio      MCPConnectionType = "STDIO"
)

type mcpRegisterRequest struct {
	Name           string            `json:"name"`
	URL            string            `json:"url"`
	Description    string            `json:"description,omitempty"`
	ConnectionType MCPConnectionType `json:"connectionType,omitempty"`
	ScanEnabled    bool              `json:"scanEnabled"`
	ConnectorID    string            `json:"connector_id,omitempty"`
}

// RegisterMCPServer submits a newly-discovered MCP server to AI Defense for
// supply chain scanning. Returns the AI Defense serverId on success.
//
// name: human label (e.g. "shadow-mcp-10.0.0.5-8080")
// url:  full URL tiptoe reached the server on
// connType: transport detected; use MCPConnectionSSE for HTTP-based servers
// connectorID: leave empty for internet-reachable servers; set to the
//
//	on-prem connector ID when the server is only reachable from the
//	internal network (the common case for shadow AI)
//
// POST /mcp/servers
func (c *AIDefenseClient) RegisterMCPServer(name, url string, connType MCPConnectionType, connectorID string) (serverID string, err error) {
	req := mcpRegisterRequest{
		Name:           name,
		URL:            url,
		Description:    "Shadow AI MCP server detected by tiptoe",
		ConnectionType: connType,
		ScanEnabled:    true,
		ConnectorID:    connectorID,
	}
	resp, err := c.do("POST", "/mcp/servers", req)
	if err != nil {
		return "", fmt.Errorf("ai-defense: register MCP server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ai-defense: register MCP server: HTTP %d: %s", resp.StatusCode, b)
	}
	var result struct {
		ServerID string `json:"serverId"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("ai-defense: register MCP server: decode: %w", err)
	}
	return result.ServerID, nil
}

// MCPServerThreat is a single MCP server entry returned by AI Defense.
type MCPServerThreat struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	URL             string `json:"url"`
	OnboardStatus   string `json:"onboarding_status"`
	ConnectionType  string `json:"connection_type"`
	LastScannedAt   string `json:"last_scanned_at"`
	ThreatSummary   struct {
		Critical int `json:"critical"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
	} `json:"threat_summary"`
}

// ListMCPServerThreats returns AI Defense-registered MCP servers filtered to
// those with HIGH or CRITICAL severity findings. Call after RegisterMCPServer
// once AI Defense has completed its scan.
//
// GET /mcp/servers?severity=HIGH,CRITICAL&limit=100
func (c *AIDefenseClient) ListMCPServerThreats() ([]MCPServerThreat, error) {
	resp, err := c.do("GET", "/mcp/servers?severity=HIGH&severity=CRITICAL&limit=100", nil)
	if err != nil {
		return nil, fmt.Errorf("ai-defense: list MCP threats: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ai-defense: list MCP threats: HTTP %d", resp.StatusCode)
	}
	var result struct {
		MCPServers struct {
			Items []MCPServerThreat `json:"items"`
		} `json:"mcp_servers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ai-defense: list MCP threats: decode: %w", err)
	}
	return result.MCPServers.Items, nil
}

// RuntimeEvent is a single AI Defense runtime event (policy enforcement action).
type RuntimeEvent struct {
	EventID       string `json:"event_id"`
	EventDate     string `json:"event_date"`
	ApplicationID string `json:"application_id"`
	PolicyID      string `json:"policy_id"`
	ConnectionID  string `json:"connection_id"`
	EventAction   string `json:"event_action"` // Block | Allow
}

// ListRuntimeEvents returns recent AI Defense runtime events for the given
// resource type, filtered to the given action. Used to correlate prompt
// injection or data leakage events on detected AI services with tiptoe findings.
//
// resourceType: "MCP_SERVER" | "LLM"
// action:       "Block" | "Allow" | "" (all)
//
// POST /events
func (c *AIDefenseClient) ListRuntimeEvents(resourceType, action string, limit int) ([]RuntimeEvent, error) {
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	body := map[string]any{
		"limit":    limit,
		"expanded": false,
	}
	if resourceType != "" {
		body["resource_types"] = []string{resourceType}
	}
	if action != "" {
		body["event_action"] = action
	}

	resp, err := c.do("POST", "/events", body)
	if err != nil {
		return nil, fmt.Errorf("ai-defense: list events: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ai-defense: list events: HTTP %d: %s", resp.StatusCode, b)
	}
	var result struct {
		Events struct {
			Items []RuntimeEvent `json:"items"`
		} `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ai-defense: list events: decode: %w", err)
	}
	return result.Events.Items, nil
}
