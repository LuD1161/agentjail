package netpolicy

import (
	"net/http"
	"strings"
)

type githubRecognizer struct{}

func (r *githubRecognizer) Recognize(host string, req *http.Request, bodyBytes []byte) *Operation {
	hostname, _ := splitHostPort(host)
	if strings.ToLower(hostname) != "api.github.com" {
		return nil
	}

	path := req.URL.Path
	segments := splitPath(path)

	// GitHub REST API pattern: /repos/{owner}/{repo}/{resource}[/{number}]
	// Also handles non-repo endpoints like /user, /orgs, etc.
	verb, resourceType, resourceName := parseGitHubPath(segments, req)

	return &Operation{
		Protocol:     "http",
		Service:      "github",
		Verb:         verb,
		ResourceType: resourceType,
		ResourceName: resourceName,
		Host:         host,
		Method:       req.Method,
		Path:         path,
	}
}

// parseGitHubPath extracts verb, resource type, and resource name/number from
// a GitHub API URL path.
func parseGitHubPath(segments []string, req *http.Request) (verb, resourceType, resourceName string) {
	if len(segments) == 0 {
		return githubMethodToVerb(req.Method, false), "", ""
	}

	// /repos/{owner}/{repo}/{resource}[/{number_or_name}]
	if segments[0] == "repos" && len(segments) >= 3 {
		// segments: repos, owner, repo, [resource, [name/number, ...]]
		if len(segments) >= 4 {
			resourceType = segments[3]
		}
		if len(segments) >= 5 {
			resourceName = segments[4]
			return githubMethodToVerb(req.Method, true), resourceType, resourceName
		}
		// No specific resource number - could be list or create.
		return githubMethodToVerb(req.Method, false), resourceType, ""
	}

	// Non-repo endpoints: /user, /orgs/{org}, etc.
	resourceType = segments[0]
	if len(segments) >= 2 {
		resourceName = segments[1]
		return githubMethodToVerb(req.Method, true), resourceType, resourceName
	}
	return githubMethodToVerb(req.Method, false), resourceType, ""
}

// githubMethodToVerb maps HTTP method to a GitHub API verb.
// hasName indicates whether a specific resource is targeted.
func githubMethodToVerb(method string, hasName bool) string {
	switch method {
	case http.MethodGet:
		if hasName {
			return "get"
		}
		return "list"
	case http.MethodPost:
		return "create"
	case http.MethodPatch:
		return "update"
	case http.MethodPut:
		return "update"
	case http.MethodDelete:
		return "delete"
	default:
		return strings.ToLower(method)
	}
}
