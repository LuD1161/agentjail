package netpolicy

import (
	"encoding/json"
	"net/http"
	"strings"
)

// xaiRecognizer recognizes xAI / Grok API traffic (api.x.ai). Unlike the
// generic recognizer it parses the request body into Operation.Payload so that
// scan.payload rules (e.g. a canary secret leaked from a project file) can be
// evaluated, and it derives a resource_type from the path so a policy can allow
// the model turn (/v1/responses) while denying the session-trace upload
// (/v1/storage) — two endpoints that share the same host and so cannot be
// separated by a host allowlist alone.
//
// It is deliberately narrow: only api.x.ai. Everything else falls through to
// the next recognizer. Mirrors the llmRecognizer pattern (recognize_llm.go).
type xaiRecognizer struct{}

// xaiHosts are the xAI/Grok endpoints whose bodies we parse. api.x.ai is the
// documented model API; cli-chat-proxy.grok.com is what Grok Build CLI 0.2.93
// actually routes model turns and trace uploads through (observed on the wire).
var xaiHosts = map[string]bool{
	"api.x.ai":                true,
	"cli-chat-proxy.grok.com": true,
}

func (r *xaiRecognizer) Recognize(host string, req *http.Request, bodyBytes []byte) *Operation {
	hostname, _ := splitHostPort(host)
	if !xaiHosts[strings.ToLower(hostname)] {
		return nil
	}

	path := req.URL.Path
	return &Operation{
		Protocol:     "http",
		Service:      "xai",
		Verb:         methodToVerb(req.Method),
		ResourceType: xaiResourceType(path),
		Host:         host,
		Method:       req.Method,
		Path:         path,
		Payload:      extractXAIBody(bodyBytes),
		BodySize:     int64(len(bodyBytes)),
	}
}

// xaiResourceType maps an xAI API path to a coarse resource type used by
// policy templates. "/v1/responses" -> "responses" (the model turn),
// "/v1/storage" -> "storage" (the session-trace upload), otherwise the first
// path segment after /v1/.
func xaiResourceType(path string) string {
	trimmed := strings.TrimPrefix(path, "/v1/")
	if i := strings.IndexByte(trimmed, '/'); i >= 0 {
		trimmed = trimmed[:i]
	}
	return trimmed
}

// extractXAIBody parses the request body so content-scan rules can match on it.
// A JSON object is returned as-is (values are scanned after re-marshaling); any
// other shape (JSON array, or a non-JSON upload) is preserved under "_raw" so a
// plaintext secret still surfaces to scan.payload.
func extractXAIBody(bodyBytes []byte) map[string]any {
	if len(bodyBytes) == 0 {
		return nil
	}
	var obj map[string]any
	if err := json.Unmarshal(bodyBytes, &obj); err == nil {
		return obj
	}
	return map[string]any{"_raw": string(bodyBytes)}
}
