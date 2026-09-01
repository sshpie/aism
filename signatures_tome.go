package main

import "sort"

// signatures_tome.go extends the signatures table with fingerprints derived
// from the NuClide tome corpus (339 AI/ML platforms). It injects entries via
// init() so they slot before the generic OpenAI-compatible catch-all. Each
// entry was validated against a live instance or the platform's published API
// spec; a plausible-but-unverified marker is left out rather than guessed.
//
// DefaultPorts() returns the sorted union of canonical ports across all
// signatures — used as the probe fallback when Shodan has no cached record.

var tomeSignatures = []llmSignature{

	// LLM inference servers -------------------------------------------------

	{platform: "LiteLLM", family: "model-runtime", ports: []int{4000},
		confirmPath: "/health/liveliness", confirmHint: `litellm_version`,
		noAuth: true},

	{platform: "LM Deploy", family: "model-runtime", ports: []int{23333},
		confirmPath: "/openapi.json", confirmHint: `"/distserve/engine_info"`,
		noAuth: true},

	{platform: "Text Embeddings Inference", family: "model-runtime", ports: []int{8080},
		confirmPath: "/info", confirmHint: `"model_pipeline_tag"`,
		versionKey: "model_id", noAuth: true},

	{platform: "Infinity Embeddings", family: "model-runtime", ports: []int{7997, 8000},
		confirmPath: "/openapi.json", confirmHint: `Infinity Emb`,
		noAuth: true},

	{platform: "Jina Embeddings", family: "model-runtime", ports: []int{8081, 8080},
		confirmPath: "/status", confirmHint: `"jina"`,
		noAuth: true},

	// Model serving ---------------------------------------------------------

	{platform: "BentoML", family: "model-server", ports: []int{3000, 8000},
		confirmPath: "/docs.json", confirmHint: `"x-bentoml-name"`,
		versionKey: "version", noAuth: true},

	{platform: "KServe", family: "model-server", ports: []int{8080},
		confirmPath: "/v2/health/ready", confirmHint: `""`,
		authPath:    "/v2/models",
		noAuth:      false},

	// Agent platforms -------------------------------------------------------

	{platform: "LangFlow", family: "agent-platform", ports: []int{7860},
		rootHint:    "langflow",
		confirmPath: "/api/v1/version", confirmHint: `"package":"Langflow"`,
		noAuth: true},

	{platform: "LangGraph Server", family: "agent-platform", ports: []int{2024, 8000},
		confirmPath: "/docs", confirmHint: `LangGraph`,
		noAuth: true},

	{platform: "LangServe", family: "agent-platform", ports: []int{8000},
		confirmPath: "/docs", confirmHint: `"LangServe"`,
		noAuth: true},

	{platform: "Haystack", family: "agent-platform", ports: []int{1416, 1417},
		confirmPath: "/status", confirmHint: `"status":"Up!"`,
		noAuth: true},

	{platform: "Devika", family: "agent-platform", ports: []int{1337},
		confirmPath: "/api/status", confirmHint: `"server is running!"`,
		noAuth: true},

	{platform: "GPT-Researcher", family: "agent-platform", ports: []int{8000},
		rootHint:    "gpt-researcher",
		confirmPath: "/api/reports", confirmHint: `"research_id"`,
		noAuth: true},

	{platform: "LightRAG", family: "agent-platform", ports: []int{9621},
		confirmPath: "/openapi.json", confirmHint: `"lightrag"`,
		noAuth: true},

	{platform: "Cognita", family: "agent-platform", ports: []int{5001},
		confirmPath: "/openapi.json", confirmHint: `"upload-to-local-directory"`,
		noAuth: true},

	{platform: "Morphik", family: "agent-platform", ports: []int{8000},
		confirmPath: "/openapi.json", confirmHint: `"morphik"`,
		noAuth: true},

	{platform: "AgentGPT", family: "agent-platform", ports: []int{3000, 8000},
		confirmPath: "/api/agent/tools", confirmHint: `"tools"`,
		noAuth: true},

	{platform: "Agno", family: "agent-platform", ports: []int{7777, 3000},
		confirmPath: "/health", confirmHint: `"status":"ok"`,
		noAuth: true},

	// Vector databases ------------------------------------------------------

	{platform: "ChromaDB", family: "vector-db", ports: []int{8000},
		confirmPath: "/api/v1", confirmHint: `"nanosecond heartbeat"`,
		noAuth: true},

	{platform: "Qdrant", family: "vector-db", ports: []int{6333, 6334},
		confirmPath: "/healthz", confirmHint: `"qdrant - vector search engine"`,
		noAuth: true},

	{platform: "Milvus", family: "vector-db", ports: []int{19530, 9091},
		confirmPath: "/v1/health", confirmHint: `"nodeInfos"`,
		noAuth: true},

	{platform: "Meilisearch", family: "vector-db", ports: []int{7700},
		confirmPath: "/health", confirmHint: `"status":"available"`,
		noAuth: true},

	{platform: "Marqo", family: "vector-db", ports: []int{8882},
		confirmPath: "/", confirmHint: `"Welcome to Marqo"`,
		noAuth: true},

	{platform: "LanceDB", family: "vector-db", ports: []int{8080},
		confirmPath: "/v1/table/", confirmHint: `"tables"`,
		noAuth: true},

	{platform: "Epsilla", family: "vector-db", ports: []int{8888},
		confirmPath: "/api/default/load", confirmHint: `"statusCode":200`,
		noAuth: true},

	{platform: "Manticore Search", family: "vector-db", ports: []int{9308},
		rootHint:    "manticore",
		confirmPath: "/sql", confirmHint: `Manticore Search`,
		noAuth: true},

	{platform: "MyScaleDB", family: "vector-db", ports: []int{8123},
		confirmPath: "/?query=SELECT+version()", confirmHint: `MyScale`,
		noAuth: true},

	// Model registries / experiment tracking --------------------------------

	{platform: "MLflow", family: "model-registry", ports: []int{5000},
		confirmPath: "/api/2.0/experiments", confirmHint: `"experiments"`,
		noAuth: true},

	{platform: "Phoenix (Arize)", family: "model-registry", ports: []int{6006, 4317},
		confirmPath: "/arize_phoenix_version", confirmHint: `"phoenix_version"`,
		noAuth: true},

	// Document processing ---------------------------------------------------

	{platform: "Apache Tika", family: "document", ports: []int{9998},
		confirmPath: "/tika", confirmHint: `This is Tika Server`,
		noAuth: true},

	{platform: "GROBID", family: "document", ports: []int{8070, 8071},
		rootHint:    "grobid",
		confirmPath: "/api/version", confirmHint: `"GROBID"`,
		noAuth: true},

	{platform: "Docling Serve", family: "document", ports: []int{5001},
		confirmPath: "/health", confirmHint: `docling`,
		noAuth: true},

	{platform: "Gotenberg", family: "document", ports: []int{3000},
		confirmPath: "/health", confirmHint: `"status":"up"`,
		noAuth: true},

	// PII / NLP security ----------------------------------------------------

	{platform: "Presidio", family: "nlp", ports: []int{5001, 5002},
		confirmPath: "/health", confirmHint: `Presidio Analyzer service is up`,
		noAuth: true},

	// Chat UIs --------------------------------------------------------------

	{platform: "Chatbot UI", family: "ui", ports: []int{3000},
		confirmPath: "/manifest.json", confirmHint: `"short_name":"Chatbot UI"`,
		noAuth: true},

	{platform: "LobeChat", family: "ui", ports: []int{3210},
		confirmPath: "/manifest.webmanifest", confirmHint: `LobeChat`,
		noAuth: true},

	{platform: "AnythingLLM", family: "ui", ports: []int{3001},
		confirmPath: "/api/system/env-dump", confirmHint: `"StorageDir"`,
		noAuth: true},

	// Cost / FinOps (sensitive cost data exposure) --------------------------

	{platform: "Kubecost", family: "observability", ports: []int{9090, 9003},
		confirmPath: "/model/allocation?window=1d&aggregate=namespace",
		confirmHint: `cpuCost`, noAuth: true},

	// Databases commonly co-deployed with AI stacks -------------------------

	{platform: "ClickHouse", family: "database", ports: []int{8123, 9000},
		confirmPath: "/", confirmHint: `Ok.`,
		noAuth: true},

	{platform: "GrepTimeDB", family: "database", ports: []int{4000, 4002},
		confirmPath: "/v1/sql?sql=SELECT+1", confirmHint: `"records"`,
		noAuth: true},

	{platform: "Kafka Connect", family: "data-pipeline", ports: []int{8083},
		confirmPath: "/connectors", confirmHint: `[]`,
		noAuth: true},

	{platform: "Kafka Schema Registry", family: "data-pipeline", ports: []int{8081},
		confirmPath: "/subjects", confirmHint: `[]`,
		noAuth: true},

	{platform: "Debezium", family: "data-pipeline", ports: []int{8083},
		confirmPath: "/api/connectors", confirmHint: `"connector"`,
		noAuth: true},
}

func init() {
	// Insert tome signatures before the generic OpenAI-compatible catch-all
	// (the last entry). This preserves match priority: specific platforms
	// confirm before the catch-all swallows any /v1/models responder.
	if len(signatures) == 0 {
		signatures = tomeSignatures
		return
	}
	last := signatures[len(signatures)-1]
	signatures = append(signatures[:len(signatures)-1], tomeSignatures...)
	signatures = append(signatures, last)
}

// DefaultPorts returns the sorted union of all canonical ports across every
// signature. Used as a probe fallback when Shodan has no cached record for the
// target — the tool knows which ports host AI/ML services even without passive
// intel. Each port appears at most once.
func DefaultPorts() []int {
	seen := make(map[int]bool)
	for _, sig := range signatures {
		for _, p := range sig.ports {
			seen[p] = true
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
