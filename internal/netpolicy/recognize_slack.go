package netpolicy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

type slackRecognizer struct{}

func (r *slackRecognizer) Recognize(host string, req *http.Request, bodyBytes []byte) *Operation {
	lower := strings.ToLower(host)
	if lower != "slack.com" && lower != "api.slack.com" {
		return nil
	}

	path := req.URL.Path

	// Slack API paths look like /api/{method} (on slack.com) or /{method} (on api.slack.com).
	var apiMethod string
	if strings.HasPrefix(path, "/api/") {
		apiMethod = strings.TrimPrefix(path, "/api/")
	} else if lower == "api.slack.com" {
		apiMethod = strings.TrimPrefix(path, "/")
	}

	if apiMethod == "" {
		return nil
	}

	// Strip trailing slashes.
	apiMethod = strings.TrimRight(apiMethod, "/")

	verb, resourceType := slackMethodToVerbResource(apiMethod)

	// Extract channel/user from body.
	resourceName := extractSlackResourceName(req, bodyBytes)

	return &Operation{
		Protocol:     "http",
		Service:      "slack",
		Verb:         verb,
		ResourceType: resourceType,
		ResourceName: resourceName,
		Host:         host,
		Method:       req.Method,
		Path:         path,
	}
}

// slackMethodToVerbResource maps Slack API method names to verb and resource type.
func slackMethodToVerbResource(method string) (verb, resourceType string) {
	switch method {
	case "chat.postMessage":
		return "create", "messages"
	case "chat.update":
		return "update", "messages"
	case "chat.delete":
		return "delete", "messages"
	case "conversations.history":
		return "get", "messages"
	case "files.upload":
		return "create", "files"
	case "users.list":
		return "list", "users"
	case "conversations.list":
		return "list", "conversations"
	default:
		// Derive from method name parts.
		parts := strings.SplitN(method, ".", 2)
		if len(parts) == 2 {
			return parts[1], parts[0]
		}
		return method, ""
	}
}

// extractSlackResourceName tries to extract a channel or user from the request body.
// Supports both form-encoded and JSON bodies.
func extractSlackResourceName(req *http.Request, bodyBytes []byte) string {
	ct := req.Header.Get("Content-Type")

	// Try form-encoded first.
	if strings.Contains(ct, "application/x-www-form-urlencoded") {
		if values, err := url.ParseQuery(string(bodyBytes)); err == nil {
			if ch := values.Get("channel"); ch != "" {
				return ch
			}
			if u := values.Get("user"); u != "" {
				return u
			}
		}
		return ""
	}

	// Try JSON.
	if strings.Contains(ct, "application/json") || len(bodyBytes) > 0 {
		var body map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &body); err == nil {
			if ch, ok := body["channel"].(string); ok && ch != "" {
				return ch
			}
			if u, ok := body["user"].(string); ok && u != "" {
				return u
			}
		}
	}

	return ""
}
