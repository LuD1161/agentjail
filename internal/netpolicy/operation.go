package netpolicy

// Operation is a normalized representation of an intercepted network request
// that the policy engine evaluates against templates.
type Operation struct {
	Protocol     string            `json:"protocol"`      // "http", "postgres", "redis", "mongodb"
	Service      string            `json:"service"`       // "kubernetes", "slack", "anthropic", "openai", "github", "generic"
	Verb         string            `json:"verb"`          // "get", "create", "update", "delete", "drop", "select", "insert", "list", "watch"
	ResourceType string            `json:"resource_type"` // "pods", "tables", "keys", "collections", "channels", "messages"
	ResourceName string            `json:"resource_name"` // "web-frontend-abc123", "users", "#general"
	Namespace    string            `json:"namespace"`     // "production", "default", "mydb"
	Host         string            `json:"host"`          // "k8s-api:6443", "prod-db:5432"
	Method       string            `json:"method"`        // HTTP method: "GET", "POST", "DELETE"
	Path         string            `json:"path"`          // "/api/v1/namespaces/production/pods/web-123"
	RawQuery     string            `json:"raw_query"`     // SQL text, Redis command, full URL query string
	Payload      map[string]any    `json:"payload"`       // parsed request body
	Headers      map[string]string `json:"headers"`       // HTTP headers
	BodySize     int64             `json:"body_size"`
}
