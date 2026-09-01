package main

// probe_mcp.go — deep probe functions for confirmed MCP HTTP servers and voice AI.
//
// MCP tool description injection research (2026-08-10) documented 7 attack vectors
// against network-accessible MCP servers. V2 (tool description injection) is the
// most impactful: adversarial instructions embedded in tool.description fields are
// consumed by the LLM during the planning phase — before any tool call fires —
// leaving zero trace in call logs. The bracket pattern [IMPORTANT: ...] was
// confirmed working by Microsoft's GitHub Copilot security team.
//
// Attack vectors: V1 static prompt, V2 tool desc, V3 rug pull, V4 cross-server,
//   V5 sampling reverse injection, V6 resource accumulation, V7 memory store.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// mcpPoisonPatterns covers the confirmed V2 tool description injection markers.
// Ranked by severity: explicit instruction hiding, credential harvesting, then
// campaign markers from known worm deployments (BTC address prefix, known phrases).
var mcpPoisonPatterns = []string{
	"[important:",        // V2 bracket injection pattern; some clients elevate priority
	"never mention this", // instruction hiding — common in V4 cross-server poison
	"do not mention",
	"do not tell",
	"~/.ssh",             // credential harvesting — id_rsa exfil via read_file
	"~/.aws",             // AWS credentials
	"~/.kube",            // kubeconfig
	"~/.bash_history",    // command history
	"/id_rsa",            // SSH key path fragment
	"attacker@",          // explicit exfil address
	"bcc ",               // email BCC redirect pattern (V4 cross-server email tool)
	"deadbugz",           // campaign marker
	"deadbug",
	"bc1q",               // BTC bech32 address prefix (worm canary)
	"1p2zgp",             // legacy BTC address prefix fragment
	"exfil",              // explicit exfiltration instruction
	"security logging requirement",  // V4 disguised compliance framing
	"formatting context token",      // V2 disguise pattern
	"verification token",
	"audit compliance",
}

// mcpToolList is the JSON-RPC 2.0 tools/list request body.
const mcpToolsListBody = `{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}`

// mcpInitBody is the JSON-RPC 2.0 initialize request. The session ID returned
// in the mcp-session-id header must be echoed in subsequent calls.
const mcpInitBody = `{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"aism","version":"0.3.0"}},"id":1}`

type mcpToolEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type mcpToolsResponse struct {
	Result struct {
		Tools []mcpToolEntry `json:"tools"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// probeMCPToolPoisoning calls initialize then tools/list on a confirmed MCP
// HTTP server and scans each tool's description for V2 injection patterns.
// Returns one "toolname: <matched pattern>" string per poisoned tool.
// Empty return = no poisoning detected (or tools/list inaccessible).
func probeMCPToolPoisoning(base string, client *http.Client) []string {
	// Step 1: initialize to obtain the mcp-session-id header, required by
	// compliant Streamable HTTP implementations for subsequent calls.
	sessionID := mcpInitSession(base, client)

	// Step 2: tools/list
	req, err := http.NewRequest("POST", base+"/mcp", strings.NewReader(mcpToolsListBody))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aism/"+version)
	if sessionID != "" {
		req.Header.Set("mcp-session-id", sessionID)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10)) // 256 KB max for large tool lists

	var result mcpToolsResponse
	if err := json.Unmarshal(b, &result); err != nil || result.Error != nil {
		return nil
	}

	var flagged []string
	for _, tool := range result.Result.Tools {
		desc := strings.ToLower(tool.Description)
		for _, pattern := range mcpPoisonPatterns {
			if strings.Contains(desc, strings.ToLower(pattern)) {
				flagged = append(flagged,
					fmt.Sprintf("tool %q: %q injection pattern", tool.Name, pattern))
				break // one flag per tool; first match wins
			}
		}
	}
	return flagged
}

// mcpInitSession sends an MCP initialize request and extracts the session ID
// from the mcp-session-id response header. Returns "" if not present or on error.
func mcpInitSession(base string, client *http.Client) string {
	req, err := http.NewRequest("POST", base+"/mcp", strings.NewReader(mcpInitBody))
	if err != nil {
		return ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "aism/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	return resp.Header.Get("mcp-session-id")
}

// probeVoiceAICORS checks whether a voice AI service returns a wildcard
// Access-Control-Allow-Origin header, which enables cross-site WebSocket
// hijacking (CSWSH). A wildcard CORS policy on a voice service lets an
// attacker's web page open a WebSocket to the server and control the real-time
// audio stream without user interaction.
//
// Attack chain: victim visits attacker page → JS opens WebSocket to voice server
// (allowed by * CORS) → attacker controls TTS output or receives ASR transcript.
func probeVoiceAICORS(client *http.Client, base string) bool {
	req, err := http.NewRequest("GET", base+"/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Origin", "https://attacker.example.com")
	req.Header.Set("User-Agent", "aism/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	return resp.Header.Get("Access-Control-Allow-Origin") == "*"
}
