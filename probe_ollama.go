package main

// probe_ollama.go — deep probe for confirmed Ollama instances.
//
// Autonomous model-poisoning worm research (2026-08-10) documented poisoning
// across 1,347 Ollama hosts. The worm deploys models with OpenAI/Anthropic
// product names (gpt-4:latest, claude-3-opus:latest, gpt-4o:latest) — names
// that do not exist in a legitimate Ollama deployment. Ollama uses its own
// naming scheme (llama3.2:latest, mistral:latest, etc.). A model named
// after a proprietary commercial LLM is either a worm artifact or deliberate
// deception.
//
// Two injection depths found in the wild:
//   V2 — system prompt field: visible in /api/show response body .system
//   V3 — pre-conversation message injection: stored in .messages[] array.
//        V3 is stealthier — it persists even when the system prompt is cleared
//        and survives model pulls. A non-empty messages[] on a local Ollama
//        model is itself anomalous; legitimate models ship with no stored history.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// wormModelNames are model names deployed by the model-poisoning worm.
// These names are verified from 1,347 compromised hosts across all worm runs.
// No legitimate Ollama operator names local models after proprietary LLMs.
var wormModelNames = []string{
	"gpt-4:latest",
	"gpt-4o:latest",
	"claude-3-opus:latest",
}

// impersonationPrefixes are naming patterns that indicate model impersonation.
// Ollama-native models use families like llama, mistral, gemma, phi, qwen, etc.
// These prefixes belong to closed commercial products and cannot be downloaded
// through Ollama's registry — their presence means local manual deployment.
var impersonationPrefixes = []string{
	"gpt-4",
	"gpt-3.5",
	"gpt-4o",
	"o1-",
	"o3-",
	"claude-3",
	"claude-2",
	"claude-",
	"gemini-",
	"bard-",
}

// poisonContentPatterns are strings found in canary content injected by the
// model-poisoning worm into model system prompts and message histories.
var poisonContentPatterns = []string{
	"deadbugz",
	"deadbug",
	"bc1q",      // BTC bech32 worm canary address prefix
	"1p2zgp",    // legacy BTC address fragment
	"issa worm", // worm canary phrase
}

type ollamaTagsResponse struct {
	Models []struct {
		Name string `json:"name"`
	} `json:"models"`
}

type ollamaShowRequest struct {
	Name string `json:"name"`
}

type ollamaShowResponse struct {
	System   string `json:"system"`
	Template string `json:"template"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
}

// probeOllamaModels fetches the deployed model list and inspects each suspicious
// model's internals for worm indicators. Returns one descriptor string per
// flagged finding.
func probeOllamaModels(base string, client *http.Client) []string {
	// Step 1: enumerate all deployed models
	_, _, tagsBody, ok := httpGet(client, base+"/api/tags")
	if !ok {
		return nil
	}
	var tags ollamaTagsResponse
	if err := json.Unmarshal([]byte(tagsBody), &tags); err != nil {
		return nil
	}

	var flagged []string
	seen := map[string]bool{}

	for _, m := range tags.Models {
		name := m.Name
		low := strings.ToLower(name)

		// Check for exact known worm model names first
		for _, worm := range wormModelNames {
			if low == strings.ToLower(worm) {
				flag := fmt.Sprintf("model %q: known worm artifact — impersonates commercial LLM", name)
				if !seen[flag] {
					flagged = append(flagged, flag)
					seen[flag] = true
				}
				break
			}
		}

		// Check for impersonation naming patterns
		isImpersonation := false
		for _, prefix := range impersonationPrefixes {
			if strings.HasPrefix(low, prefix) {
				isImpersonation = true
				flag := fmt.Sprintf("model %q: impersonates commercial LLM", name)
				if !seen[flag] {
					flagged = append(flagged, flag)
					seen[flag] = true
				}
				break
			}
		}

		// Deep-inspect all impersonation models + all models with commercial names
		// for V2 (system prompt) and V3 (message history) injection
		if isImpersonation {
			if f := inspectOllamaModel(base, client, name); f != "" {
				if !seen[f] {
					flagged = append(flagged, f)
					seen[f] = true
				}
			}
		}
	}

	// Inspect the first 5 non-impersonation models for V3 injection
	// V3 can be deployed into any model, not just impersonation ones
	checked := 0
	for _, m := range tags.Models {
		if checked >= 5 {
			break
		}
		low := strings.ToLower(m.Name)
		skip := false
		for _, prefix := range impersonationPrefixes {
			if strings.HasPrefix(low, prefix) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		if f := inspectOllamaModel(base, client, m.Name); f != "" {
			if !seen[f] {
				flagged = append(flagged, f)
				seen[f] = true
			}
		}
		checked++
	}

	return flagged
}

// inspectOllamaModel calls /api/show for one model and checks for:
//   - V2: canary content in the system prompt field
//   - V3: non-empty messages[] array (no legitimate model ships with stored history)
func inspectOllamaModel(base string, client *http.Client, name string) string {
	body := fmt.Sprintf(`{"name":%q}`, name)
	req, err := http.NewRequest("POST", base+"/api/show", strings.NewReader(body))
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
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	var show ollamaShowResponse
	if err := json.Unmarshal(b, &show); err != nil {
		return ""
	}

	// V2: canary in system prompt
	systemLow := strings.ToLower(show.System)
	for _, pattern := range poisonContentPatterns {
		if strings.Contains(systemLow, strings.ToLower(pattern)) {
			return fmt.Sprintf("model %q: V2 system prompt poison (%q pattern)", name, pattern)
		}
	}

	// V3: non-empty message history — legitimate models have no stored messages
	if len(show.Messages) > 0 {
		// Check message content for canary markers
		for _, msg := range show.Messages {
			contentLow := strings.ToLower(msg.Content)
			for _, pattern := range poisonContentPatterns {
				if strings.Contains(contentLow, strings.ToLower(pattern)) {
					return fmt.Sprintf("model %q: V3 message history poison (%q pattern in %s role)",
						name, pattern, msg.Role)
				}
			}
		}
		// Even without a known canary, pre-stored messages are anomalous
		return fmt.Sprintf("model %q: V3 anomaly — %d pre-stored message(s) in history (legitimate models ship with no stored history)",
			name, len(show.Messages))
	}

	return ""
}
