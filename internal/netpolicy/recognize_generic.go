package netpolicy

import (
	"net/http"
	"strings"
)

type genericRecognizer struct{}

func (r *genericRecognizer) Recognize(host string, req *http.Request, bodyBytes []byte) *Operation {
	path := req.URL.Path
	segments := splitPath(path)

	verb := strings.ToLower(req.Method)

	var resourceType, resourceName string
	if len(segments) >= 1 {
		resourceType = segments[0]
	}
	if len(segments) >= 2 {
		resourceName = segments[1]
	}

	return &Operation{
		Protocol:     "http",
		Service:      host,
		Verb:         verb,
		ResourceType: resourceType,
		ResourceName: resourceName,
		Host:         host,
		Method:       req.Method,
		Path:         path,
	}
}
