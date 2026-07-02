package netpolicy

import (
	"net/http"
	"strings"
)

type k8sRecognizer struct{}

func (r *k8sRecognizer) Recognize(host string, req *http.Request, bodyBytes []byte) *Operation {
	if !isK8sHost(host) {
		return nil
	}

	path := req.URL.Path
	segments := splitPath(path)

	verb, resourceType, resourceName, namespace := parseK8sPath(segments, req)

	// Handle watch queries.
	if req.Method == http.MethodGet && req.URL.Query().Get("watch") == "true" {
		verb = "watch"
	}

	return &Operation{
		Protocol:     "http",
		Service:      "kubernetes",
		Verb:         verb,
		ResourceType: resourceType,
		ResourceName: resourceName,
		Namespace:    namespace,
		Host:         host,
		Method:       req.Method,
		Path:         path,
	}
}

// isK8sHost returns true if the host looks like a Kubernetes API server.
func isK8sHost(host string) bool {
	// Strip port for hostname checks.
	hostname, port := splitHostPort(host)
	lower := strings.ToLower(hostname)

	if port == "6443" {
		return true
	}

	for _, kw := range []string{"k8s", "kube", "kubernetes"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}

	// Cloud provider managed Kubernetes patterns.
	if strings.HasSuffix(lower, ".eks.amazonaws.com") ||
		strings.HasSuffix(lower, ".azmk8s.io") ||
		strings.HasSuffix(lower, ".gke.io") {
		return true
	}

	return false
}

// splitHostPort splits a host into hostname and port parts.
// If no port is present, port is empty.
func splitHostPort(host string) (string, string) {
	// Handle IPv6 addresses in brackets.
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Make sure this is a port separator, not part of an IPv6 address.
		if bracketIdx := strings.LastIndex(host, "]"); bracketIdx < idx {
			return host[:idx], host[idx+1:]
		}
	}
	return host, ""
}

// splitPath splits a URL path into non-empty segments.
func splitPath(path string) []string {
	var segments []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			segments = append(segments, s)
		}
	}
	return segments
}

// parseK8sPath extracts verb, resource type, resource name, and namespace from
// Kubernetes API URL path segments and the HTTP request.
//
// Patterns:
//   - Core API:       /api/v1/namespaces/{ns}/{resource}[/{name}[/{subresource}]]
//   - Named API:      /apis/{group}/{version}/namespaces/{ns}/{resource}[/{name}[/{subresource}]]
//   - Cluster-scoped: /api/v1/{resource}[/{name}]
func parseK8sPath(segments []string, req *http.Request) (verb, resourceType, resourceName, namespace string) {
	if len(segments) == 0 {
		return methodToK8sVerb(req.Method, false), "", "", ""
	}

	var rest []string

	switch segments[0] {
	case "api":
		// /api/v1/...
		if len(segments) < 2 {
			return methodToK8sVerb(req.Method, false), "", "", ""
		}
		rest = segments[2:] // skip "api" and version
	case "apis":
		// /apis/{group}/{version}/...
		if len(segments) < 3 {
			return methodToK8sVerb(req.Method, false), "", "", ""
		}
		rest = segments[3:] // skip "apis", group, and version
	default:
		return methodToK8sVerb(req.Method, false), "", "", ""
	}

	// Now rest is everything after the version.
	// Check for namespaced resources: namespaces/{ns}/{resource}[/{name}[/{subresource}]]
	if len(rest) >= 2 && rest[0] == "namespaces" {
		namespace = rest[1]
		rest = rest[2:] // skip "namespaces" and namespace name
	}

	// rest is now: [{resource}[, {name}[, {subresource}]]]
	if len(rest) == 0 {
		return methodToK8sVerb(req.Method, false), "", "", namespace
	}

	resourceType = rest[0]

	if len(rest) == 1 {
		// No name - this is a list or create.
		verb = methodToK8sVerb(req.Method, false)
		return verb, resourceType, "", namespace
	}

	resourceName = rest[1]

	// Check for sub-resources like exec, attach, log, portforward.
	if len(rest) >= 3 {
		subResource := rest[2]
		resourceType = resourceType + "/" + subResource
		switch subResource {
		case "exec":
			verb = "exec"
		case "attach":
			verb = "attach"
		case "portforward":
			verb = "portforward"
		case "log":
			verb = methodToK8sVerb(req.Method, true)
		default:
			verb = methodToK8sVerb(req.Method, true)
		}
		return verb, resourceType, resourceName, namespace
	}

	verb = methodToK8sVerb(req.Method, true)
	return verb, resourceType, resourceName, namespace
}

// methodToK8sVerb maps HTTP method to Kubernetes verb.
// hasName indicates whether a specific resource name is present in the path.
func methodToK8sVerb(method string, hasName bool) string {
	switch method {
	case http.MethodGet:
		if hasName {
			return "get"
		}
		return "list"
	case http.MethodPost:
		return "create"
	case http.MethodPut:
		return "update"
	case http.MethodPatch:
		return "patch"
	case http.MethodDelete:
		return "delete"
	default:
		return strings.ToLower(method)
	}
}
