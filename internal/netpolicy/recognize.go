package netpolicy

import "net/http"

// Recognizer converts an HTTP request into a normalized Operation.
// Returns nil if this recognizer doesn't handle the request.
type Recognizer interface {
	Recognize(host string, req *http.Request, bodyBytes []byte) *Operation
}

// recognizers is the ordered list of recognizers; most specific first.
var recognizers = []Recognizer{
	&k8sRecognizer{},
	&slackRecognizer{},
	&llmRecognizer{},
	&githubRecognizer{},
	&genericRecognizer{},
}

// RecognizeHTTP runs all registered recognizers against an HTTP request.
// Returns the first match, or a generic HTTP operation if none match.
func RecognizeHTTP(host string, req *http.Request, bodyBytes []byte) *Operation {
	for _, r := range recognizers {
		if op := r.Recognize(host, req, bodyBytes); op != nil {
			return op
		}
	}
	// Should never reach here because genericRecognizer always matches,
	// but return a minimal operation as a safety net.
	return &Operation{
		Protocol: "http",
		Service:  host,
		Verb:     methodToVerb(req.Method),
		Host:     host,
		Method:   req.Method,
		Path:     req.URL.Path,
	}
}

// RecognizeTCP dispatches raw TCP payload bytes to the appropriate
// protocol parser based on the destination port. Returns nil if no
// parser matches or the data is unrecognizable.
func RecognizeTCP(host string, port int, data []byte) *Operation {
	switch port {
	case 5432:
		return ParsePostgresMessage(data)
	case 6379:
		return ParseRedisCommand(data)
	case 27017:
		return ParseMongoMessage(data)
	case 22:
		return ParseSSHVersion(data, host)
	default:
		return nil
	}
}

// methodToVerb converts an HTTP method to a lowercase verb string.
func methodToVerb(method string) string {
	switch method {
	case http.MethodGet:
		return "get"
	case http.MethodPost:
		return "post"
	case http.MethodPut:
		return "put"
	case http.MethodPatch:
		return "patch"
	case http.MethodDelete:
		return "delete"
	default:
		return "unknown"
	}
}
