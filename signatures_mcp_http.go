package main

// signatures_mcp_http.go fingerprints network-accessible MCP HTTP servers.
//
// Unlike stdio MCP servers (not Shodan-visible, no network port), Streamable
// HTTP MCP servers expose an HTTP endpoint. The v2 spec for the Streamable HTTP
// transport (MCP spec §6.2) requires servers to accept:
//   POST /mcp — client-to-server JSON-RPC requests
//   GET  /mcp — SSE stream for server-to-client notifications
//
// Detection: POST /mcp with a JSON-RPC initialize request returns a response
// containing "protocolVersion" if the server is MCP-compliant. The response also
// carries an "mcp-session-id" header that later calls must echo.
//
// After detection, aism calls tools/list and scans tool descriptions for V2
// injection patterns. Tool description injection fires at LLM planning time —
// before any tool call — leaving zero trace in call logs.
//
// Port basis: tool injection research estimates "hundreds to thousands" of exposed
// MCP HTTP endpoints. Common deployment ports from GitHub survey (2026-08):
//   3000  FastMCP default
//   8000  FastMCP / uvicorn defaults
//   8080  Nginx proxy frontends
//   7443  HTTPS MCP
//   4000  Alternative dev port
//   3001  Alternative React-adjacent dev port

var mcpHTTPSignatures = []llmSignature{

	// FastMCP — the dominant Python framework for MCP HTTP servers.
	// POST /mcp → JSON-RPC result with protocolVersion field.
	// rootHint "fastmcp" appears on the optional GET / landing page some
	// deployments serve; the POST-based confirm is authoritative.
	{platform: "FastMCP Server", family: "mcp-server",
		ports:         []int{8000, 3000, 8080},
		rootHint:      "fastmcp",
		confirmPath:   "/mcp",
		confirmHint:   `"protocolVersion"`,
		confirmMethod: "POST",
		confirmBody:   mcpInitBody,
		noAuth:        true},

	// Generic Streamable HTTP MCP server — any compliant implementation.
	// rootHint "mcp-session-id" catches servers that include the header
	// in their GET / response (some frameworks do this for discoverability).
	// Confirm: POST /mcp initialize → protocolVersion in response body.
	{platform: "MCP HTTP Server", family: "mcp-server",
		ports:         []int{3000, 4000, 5000, 7443, 3001},
		rootHint:      "mcp-session-id",
		confirmPath:   "/mcp",
		confirmHint:   `"protocolVersion"`,
		confirmMethod: "POST",
		confirmBody:   mcpInitBody,
		noAuth:        true},

	// A2A agent server with embedded MCP endpoint.
	// A2A (Agent-to-Agent) protocol servers expose /.well-known/agent.json;
	// if they also serve MCP, GET /mcp returns 200 or SSE.
	// V7 attack: poison the A2A agent card at /.well-known/agent.json to
	// inject into every agent that connects.
	{platform: "A2A+MCP Agent Server", family: "mcp-server",
		ports:         []int{8000, 3000, 443, 80},
		rootHint:      `"agentCard"`,
		confirmPath:   "/.well-known/agent.json",
		confirmHint:   `"url"`,
		noAuth:        true},
}

func init() {
	// Inject MCP HTTP signatures before the last entry (OpenAI catch-all).
	// Slot after tome signatures so MCP-specific platforms match before generic
	// OpenAI-compatible catch-all claims any JSON-returning server.
	if len(signatures) == 0 {
		signatures = mcpHTTPSignatures
		return
	}
	last := signatures[len(signatures)-1]
	signatures = append(signatures[:len(signatures)-1], mcpHTTPSignatures...)
	signatures = append(signatures, last)
}
