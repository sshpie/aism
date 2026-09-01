package cisco

import "strings"

// TaxonomyEntry maps a tiptoe-detected service to a Cisco AI Taxonomy entry.
// Source: Cisco AI Taxonomy Navigator v1.0.0
// https://learn-cloudsecurity.cisco.com/ai-security-framework
type TaxonomyEntry struct {
	ObjectiveID   string // e.g. "OB-018"
	ObjectiveName string // e.g. "System Misuse"
	TechID        string // e.g. "AITech-18.2"
	TechName      string // e.g. "Malicious Workflows"
	SubtechID     string // e.g. "AISubtech-18.2.2"; empty if technique-level only
	SubtechName   string // e.g. "Dedicated Malicious Server or Infrastructure"
	// Indicators lists which Cisco indicator columns apply:
	// "Agentic", "MCP", "ModelFile"
	Indicators []string
}

// Short returns a compact label for use in alerts: "OB-018/AISubtech-18.2.2".
func (e TaxonomyEntry) Short() string {
	if e.SubtechID != "" {
		return e.ObjectiveID + "/" + e.SubtechID
	}
	return e.ObjectiveID + "/" + e.TechID
}

// serviceEntries maps lowercase service name prefixes to one or more taxonomy entries.
// When a service matches multiple entries, all apply — some services are both a
// "dedicated malicious server" and an "abuse of APIs" vector simultaneously.
var serviceEntries = map[string][]TaxonomyEntry{
	// LLM inference servers — unauthorized inference server on a managed device
	// is the canonical "Dedicated Malicious Server or Infrastructure" case.
	"ollama": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.2",
			SubtechName:   "Dedicated Malicious Server or Infrastructure",
			Indicators:    []string{"Agentic"},
		},
	},
	"vllm": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.2",
			SubtechName:   "Dedicated Malicious Server or Infrastructure",
			Indicators:    []string{"Agentic"},
		},
	},
	"litellm": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.2",
			SubtechName:   "Dedicated Malicious Server or Infrastructure",
			Indicators:    []string{"Agentic"},
		},
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.1",
			SubtechName:   "Abuse of APIs for Mass Automation",
			Indicators:    []string{"Agentic"},
		},
	},
	"text-generation-webui": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.2",
			SubtechName:   "Dedicated Malicious Server or Infrastructure",
			Indicators:    []string{"Agentic"},
		},
	},
	"localai": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.2",
			SubtechName:   "Dedicated Malicious Server or Infrastructure",
			Indicators:    []string{"Agentic"},
		},
	},
	"koboldcpp": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.2",
			SubtechName:   "Dedicated Malicious Server or Infrastructure",
			Indicators:    []string{"Agentic"},
		},
	},
	"openwebui": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.2",
			SubtechName:   "Dedicated Malicious Server or Infrastructure",
			Indicators:    []string{"Agentic"},
		},
	},

	// Vector databases — exposed vector DB APIs enable mass embedding extraction
	// and are a prerequisite surface for RAG-based data exfiltration chains.
	"qdrant": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.1",
			SubtechName:   "Abuse of APIs for Mass Automation",
			Indicators:    []string{"Agentic"},
		},
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.1",
			TechName:      "Fraudulent Use",
			Indicators:    []string{"Agentic"},
		},
	},
	"chroma": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.1",
			SubtechName:   "Abuse of APIs for Mass Automation",
			Indicators:    []string{"Agentic"},
		},
	},
	"weaviate": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.1",
			SubtechName:   "Abuse of APIs for Mass Automation",
			Indicators:    []string{"Agentic"},
		},
	},
	"milvus": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.1",
			SubtechName:   "Abuse of APIs for Mass Automation",
			Indicators:    []string{"Agentic"},
		},
	},

	// Model registries — unauthorized access to model artifacts is Fraudulent Use;
	// registry APIs also enable mass model extraction (18.2.1).
	"mlflow": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.1",
			TechName:      "Fraudulent Use",
			Indicators:    []string{"Agentic", "ModelFile"},
		},
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.1",
			SubtechName:   "Abuse of APIs for Mass Automation",
			Indicators:    []string{"Agentic"},
		},
	},
	"bentoml": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.1",
			TechName:      "Fraudulent Use",
			Indicators:    []string{"Agentic", "ModelFile"},
		},
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.2",
			SubtechName:   "Dedicated Malicious Server or Infrastructure",
			Indicators:    []string{"Agentic"},
		},
	},

	// Model servers — GPU-backed inference endpoints on managed devices are
	// both dedicated malicious infrastructure and model file exposure surfaces.
	"triton": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.2",
			SubtechName:   "Dedicated Malicious Server or Infrastructure",
			Indicators:    []string{"Agentic", "ModelFile"},
		},
	},
	"torchserve": {
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.2",
			SubtechName:   "Dedicated Malicious Server or Infrastructure",
			Indicators:    []string{"Agentic", "ModelFile"},
		},
	},

	// Agent platforms — exposed orchestration endpoints are Indirect Prompt Injection
	// vectors (OB-001/AITech-1.2) and Context Window Manipulation surfaces (AITech-1.4).
	"langflow": {
		{
			ObjectiveID:   "OB-001",
			ObjectiveName: "Goal Hijacking",
			TechID:        "AITech-1.2",
			TechName:      "Indirect Prompt Injection",
			Indicators:    []string{"Agentic"},
		},
		{
			ObjectiveID:   "OB-001",
			ObjectiveName: "Goal Hijacking",
			TechID:        "AITech-1.4",
			TechName:      "Context Window Manipulation",
			Indicators:    []string{"Agentic"},
		},
	},
	"flowise": {
		{
			ObjectiveID:   "OB-001",
			ObjectiveName: "Goal Hijacking",
			TechID:        "AITech-1.2",
			TechName:      "Indirect Prompt Injection",
			Indicators:    []string{"Agentic"},
		},
	},
	"dify": {
		{
			ObjectiveID:   "OB-001",
			ObjectiveName: "Goal Hijacking",
			TechID:        "AITech-1.2",
			TechName:      "Indirect Prompt Injection",
			Indicators:    []string{"Agentic"},
		},
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.2",
			SubtechName:   "Dedicated Malicious Server or Infrastructure",
			Indicators:    []string{"Agentic"},
		},
	},

	// MCP servers — exposed Model Context Protocol servers are both Indirect Prompt
	// Injection vectors (an attacker controls tool responses the model receives) and
	// Abuse of APIs surfaces (MCP tool calls can be scripted at scale).
	"mcp": {
		{
			ObjectiveID:   "OB-001",
			ObjectiveName: "Goal Hijacking",
			TechID:        "AITech-1.2",
			TechName:      "Indirect Prompt Injection",
			Indicators:    []string{"MCP", "Agentic"},
		},
		{
			ObjectiveID:   "OB-018",
			ObjectiveName: "System Misuse",
			TechID:        "AITech-18.2",
			TechName:      "Malicious Workflows",
			SubtechID:     "AISubtech-18.2.1",
			SubtechName:   "Abuse of APIs for Mass Automation",
			Indicators:    []string{"MCP"},
		},
	},
}

// Classify returns all Cisco AI Taxonomy entries that apply to the given service name.
// The service string should be the raw label from tiptoe's fingerprinter
// (e.g. "ollama", "qdrant", "mcp-server"). Case-insensitive prefix match.
// Returns nil if the service has no known taxonomy mapping.
func Classify(service string) []TaxonomyEntry {
	lc := strings.ToLower(service)
	// Exact match first.
	if entries, ok := serviceEntries[lc]; ok {
		return entries
	}
	// Prefix match — handles "mcp-server", "mlflow-tracking", "ollama-webui" etc.
	for key, entries := range serviceEntries {
		if strings.HasPrefix(lc, key) {
			return entries
		}
	}
	return nil
}

// ClassifyAll returns the deduplicated union of taxonomy entries for all services.
// Deduplication is by SubtechID (or TechID when no subtech), so the same taxonomy
// node is never listed twice even if multiple services map to it.
func ClassifyAll(services []string) []TaxonomyEntry {
	seen := map[string]bool{}
	var out []TaxonomyEntry
	for _, svc := range services {
		for _, e := range Classify(svc) {
			key := e.SubtechID
			if key == "" {
				key = e.TechID
			}
			if !seen[key] {
				seen[key] = true
				out = append(out, e)
			}
		}
	}
	return out
}

// TaxonomyLabel formats a compact reference list for inclusion in alerts.
// Example: "[OB-018/AISubtech-18.2.2, OB-001/AITech-1.2]"
func TaxonomyLabel(entries []TaxonomyEntry) string {
	if len(entries) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteByte('[')
	for i, e := range entries {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(e.Short())
	}
	sb.WriteByte(']')
	return sb.String()
}
