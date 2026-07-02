package netpolicy

import (
	"encoding/json"
	"net/http"
	"strings"
)

type llmRecognizer struct{}

// llmHostService maps host patterns to service names and recognized path prefixes.
var llmHostService = []struct {
	host        string   // exact host or suffix match
	suffix      bool     // if true, match as suffix
	service     string
	pathPrefixes []string
}{
	{host: "api.anthropic.com", service: "anthropic", pathPrefixes: []string{"/v1/messages"}},
	{host: "api.openai.com", service: "openai", pathPrefixes: []string{"/v1/chat/completions", "/v1/embeddings"}},
	{host: "generativelanguage.googleapis.com", service: "google-ai", pathPrefixes: []string{"/v1/models/"}},
	{host: ".openai.azure.com", suffix: true, service: "azure-openai", pathPrefixes: []string{"/openai/deployments/"}},
}

func (r *llmRecognizer) Recognize(host string, req *http.Request, bodyBytes []byte) *Operation {
	hostname, _ := splitHostPort(host)
	lower := strings.ToLower(hostname)
	path := req.URL.Path

	for _, entry := range llmHostService {
		var match bool
		if entry.suffix {
			match = strings.HasSuffix(lower, entry.host)
		} else {
			match = lower == entry.host
		}
		if !match {
			continue
		}

		// Check that the path matches one of the recognized prefixes.
		pathMatched := false
		for _, prefix := range entry.pathPrefixes {
			if strings.HasPrefix(path, prefix) {
				pathMatched = true
				break
			}
		}
		if !pathMatched {
			continue
		}

		verb := methodToVerb(req.Method)
		resourceName, payload := extractLLMBody(bodyBytes)

		// Determine resource type from path.
		resourceType := llmResourceType(path, entry.service)

		return &Operation{
			Protocol:     "http",
			Service:      entry.service,
			Verb:         verb,
			ResourceType: resourceType,
			ResourceName: resourceName,
			Host:         host,
			Method:       req.Method,
			Path:         path,
			Payload:      payload,
		}
	}

	return nil
}

// llmResourceType infers a resource type from the LLM API path.
func llmResourceType(path, service string) string {
	switch {
	case strings.Contains(path, "/messages"):
		return "messages"
	case strings.Contains(path, "/chat/completions"):
		return "chat/completions"
	case strings.Contains(path, "/embeddings"):
		return "embeddings"
	case strings.Contains(path, "generateContent"):
		return "generateContent"
	default:
		return ""
	}
}

// extractLLMBody extracts model name and message content from a JSON request body.
func extractLLMBody(bodyBytes []byte) (model string, payload map[string]interface{}) {
	if len(bodyBytes) == 0 {
		return "", nil
	}

	var body map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		return "", nil
	}

	if m, ok := body["model"].(string); ok {
		model = m
	}

	// Extract message contents for PII scanning.
	payload = make(map[string]interface{})
	if messages, ok := body["messages"].([]interface{}); ok {
		var contents []string
		for _, msg := range messages {
			if m, ok := msg.(map[string]interface{}); ok {
				if c, ok := m["content"].(string); ok {
					contents = append(contents, c)
				}
			}
		}
		if len(contents) > 0 {
			payload["message_contents"] = contents
		}
	}

	return model, payload
}
