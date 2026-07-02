package netpolicy

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func makeRequest(method, rawURL string, body string, headers map[string]string) *http.Request {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	var req *http.Request
	if bodyReader != nil {
		req, _ = http.NewRequest(method, rawURL, bodyReader)
	} else {
		req, _ = http.NewRequest(method, rawURL, nil)
	}
	req.URL = u
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestRecognizeK8sDelete(t *testing.T) {
	req := makeRequest("DELETE", "https://k8s.example.com/api/v1/namespaces/production/pods/web-123", "", nil)
	op := RecognizeHTTP("k8s.example.com", req, nil)

	assertEqual(t, "service", "kubernetes", op.Service)
	assertEqual(t, "verb", "delete", op.Verb)
	assertEqual(t, "namespace", "production", op.Namespace)
	assertEqual(t, "resource_type", "pods", op.ResourceType)
	assertEqual(t, "resource_name", "web-123", op.ResourceName)
}

func TestRecognizeK8sList(t *testing.T) {
	req := makeRequest("GET", "https://k8s.example.com/api/v1/namespaces/default/pods", "", nil)
	op := RecognizeHTTP("k8s.example.com", req, nil)

	assertEqual(t, "service", "kubernetes", op.Service)
	assertEqual(t, "verb", "list", op.Verb)
	assertEqual(t, "namespace", "default", op.Namespace)
	assertEqual(t, "resource_type", "pods", op.ResourceType)
	assertEqual(t, "resource_name", "", op.ResourceName)
}

func TestRecognizeK8sExec(t *testing.T) {
	req := makeRequest("POST", "https://k8s.example.com/api/v1/namespaces/production/pods/web-123/exec", "", nil)
	op := RecognizeHTTP("k8s.example.com", req, nil)

	assertEqual(t, "service", "kubernetes", op.Service)
	assertEqual(t, "verb", "exec", op.Verb)
	assertEqual(t, "namespace", "production", op.Namespace)
	assertEqual(t, "resource_type", "pods/exec", op.ResourceType)
	assertEqual(t, "resource_name", "web-123", op.ResourceName)
}

func TestRecognizeK8sWatch(t *testing.T) {
	req := makeRequest("GET", "https://k8s.example.com/api/v1/namespaces/default/pods?watch=true", "", nil)
	op := RecognizeHTTP("k8s.example.com", req, nil)

	assertEqual(t, "service", "kubernetes", op.Service)
	assertEqual(t, "verb", "watch", op.Verb)
}

func TestRecognizeK8sPort6443(t *testing.T) {
	req := makeRequest("GET", "https://my-cluster:6443/api/v1/namespaces/kube-system/pods", "", nil)
	op := RecognizeHTTP("my-cluster:6443", req, nil)

	assertEqual(t, "service", "kubernetes", op.Service)
	assertEqual(t, "verb", "list", op.Verb)
	assertEqual(t, "namespace", "kube-system", op.Namespace)
}

func TestRecognizeK8sEKS(t *testing.T) {
	req := makeRequest("GET", "https://abc123.eks.amazonaws.com/api/v1/nodes", "", nil)
	op := RecognizeHTTP("abc123.eks.amazonaws.com", req, nil)

	assertEqual(t, "service", "kubernetes", op.Service)
}

func TestRecognizeK8sAttach(t *testing.T) {
	req := makeRequest("POST", "https://k8s.example.com/api/v1/namespaces/default/pods/my-pod/attach", "", nil)
	op := RecognizeHTTP("k8s.example.com", req, nil)

	assertEqual(t, "verb", "attach", op.Verb)
	assertEqual(t, "resource_type", "pods/attach", op.ResourceType)
}

func TestRecognizeK8sLog(t *testing.T) {
	req := makeRequest("GET", "https://k8s.example.com/api/v1/namespaces/default/pods/my-pod/log", "", nil)
	op := RecognizeHTTP("k8s.example.com", req, nil)

	assertEqual(t, "verb", "get", op.Verb)
	assertEqual(t, "resource_type", "pods/log", op.ResourceType)
}

func TestRecognizeK8sPortForward(t *testing.T) {
	req := makeRequest("POST", "https://k8s.example.com/api/v1/namespaces/default/pods/my-pod/portforward", "", nil)
	op := RecognizeHTTP("k8s.example.com", req, nil)

	assertEqual(t, "verb", "portforward", op.Verb)
	assertEqual(t, "resource_type", "pods/portforward", op.ResourceType)
}

func TestRecognizeK8sNamedAPI(t *testing.T) {
	req := makeRequest("GET", "https://k8s.example.com/apis/apps/v1/namespaces/production/deployments/web", "", nil)
	op := RecognizeHTTP("k8s.example.com", req, nil)

	assertEqual(t, "service", "kubernetes", op.Service)
	assertEqual(t, "verb", "get", op.Verb)
	assertEqual(t, "namespace", "production", op.Namespace)
	assertEqual(t, "resource_type", "deployments", op.ResourceType)
	assertEqual(t, "resource_name", "web", op.ResourceName)
}

func TestRecognizeSlackPostMessage(t *testing.T) {
	body := `channel=%23general&text=hello`
	req := makeRequest("POST", "https://slack.com/api/chat.postMessage", body, map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	op := RecognizeHTTP("slack.com", req, []byte(body))

	assertEqual(t, "service", "slack", op.Service)
	assertEqual(t, "verb", "create", op.Verb)
	assertEqual(t, "resource_type", "messages", op.ResourceType)
	assertEqual(t, "resource_name", "#general", op.ResourceName)
}

func TestRecognizeSlackJSON(t *testing.T) {
	body := `{"channel":"#general","text":"hello"}`
	req := makeRequest("POST", "https://slack.com/api/chat.postMessage", body, map[string]string{
		"Content-Type": "application/json",
	})
	op := RecognizeHTTP("slack.com", req, []byte(body))

	assertEqual(t, "service", "slack", op.Service)
	assertEqual(t, "verb", "create", op.Verb)
	assertEqual(t, "resource_name", "#general", op.ResourceName)
}

func TestRecognizeSlackList(t *testing.T) {
	req := makeRequest("GET", "https://api.slack.com/users.list", "", nil)
	op := RecognizeHTTP("api.slack.com", req, nil)

	assertEqual(t, "service", "slack", op.Service)
	assertEqual(t, "verb", "list", op.Verb)
	assertEqual(t, "resource_type", "users", op.ResourceType)
}

func TestRecognizeSlackDelete(t *testing.T) {
	body := `{"channel":"C123"}`
	req := makeRequest("POST", "https://slack.com/api/chat.delete", body, map[string]string{
		"Content-Type": "application/json",
	})
	op := RecognizeHTTP("slack.com", req, []byte(body))

	assertEqual(t, "verb", "delete", op.Verb)
	assertEqual(t, "resource_type", "messages", op.ResourceType)
}

func TestRecognizeAnthropic(t *testing.T) {
	body := `{"model":"claude-opus-4-8","messages":[{"role":"user","content":"Hello"}]}`
	req := makeRequest("POST", "https://api.anthropic.com/v1/messages", body, map[string]string{
		"Content-Type": "application/json",
	})
	op := RecognizeHTTP("api.anthropic.com", req, []byte(body))

	assertEqual(t, "service", "anthropic", op.Service)
	assertEqual(t, "verb", "post", op.Verb)
	assertEqual(t, "resource_name", "claude-opus-4-8", op.ResourceName)
	assertEqual(t, "resource_type", "messages", op.ResourceType)

	// Verify payload extraction.
	if op.Payload == nil {
		t.Fatal("expected Payload to be non-nil")
	}
	contents, ok := op.Payload["message_contents"].([]string)
	if !ok || len(contents) == 0 {
		t.Fatal("expected message_contents in payload")
	}
	if contents[0] != "Hello" {
		t.Errorf("expected message content 'Hello', got %q", contents[0])
	}
}

func TestRecognizeOpenAI(t *testing.T) {
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}`
	req := makeRequest("POST", "https://api.openai.com/v1/chat/completions", body, map[string]string{
		"Content-Type": "application/json",
	})
	op := RecognizeHTTP("api.openai.com", req, []byte(body))

	assertEqual(t, "service", "openai", op.Service)
	assertEqual(t, "resource_name", "gpt-4", op.ResourceName)
	assertEqual(t, "resource_type", "chat/completions", op.ResourceType)
}

func TestRecognizeAzureOpenAI(t *testing.T) {
	body := `{"model":"gpt-4"}`
	req := makeRequest("POST", "https://myinstance.openai.azure.com/openai/deployments/gpt4/chat/completions", body, map[string]string{
		"Content-Type": "application/json",
	})
	op := RecognizeHTTP("myinstance.openai.azure.com", req, []byte(body))

	assertEqual(t, "service", "azure-openai", op.Service)
	assertEqual(t, "resource_name", "gpt-4", op.ResourceName)
}

func TestRecognizeGoogleAI(t *testing.T) {
	body := `{"model":"gemini-pro"}`
	req := makeRequest("POST", "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent", body, map[string]string{
		"Content-Type": "application/json",
	})
	op := RecognizeHTTP("generativelanguage.googleapis.com", req, []byte(body))

	assertEqual(t, "service", "google-ai", op.Service)
	assertEqual(t, "resource_type", "generateContent", op.ResourceType)
}

func TestRecognizeGitHubDelete(t *testing.T) {
	req := makeRequest("DELETE", "https://api.github.com/repos/LuD1161/agentjail/issues/42", "", nil)
	op := RecognizeHTTP("api.github.com", req, nil)

	assertEqual(t, "service", "github", op.Service)
	assertEqual(t, "verb", "delete", op.Verb)
	assertEqual(t, "resource_type", "issues", op.ResourceType)
	assertEqual(t, "resource_name", "42", op.ResourceName)
}

func TestRecognizeGitHubList(t *testing.T) {
	req := makeRequest("GET", "https://api.github.com/repos/LuD1161/agentjail/pulls", "", nil)
	op := RecognizeHTTP("api.github.com", req, nil)

	assertEqual(t, "service", "github", op.Service)
	assertEqual(t, "verb", "list", op.Verb)
	assertEqual(t, "resource_type", "pulls", op.ResourceType)
	assertEqual(t, "resource_name", "", op.ResourceName)
}

func TestRecognizeGitHubCreate(t *testing.T) {
	req := makeRequest("POST", "https://api.github.com/repos/LuD1161/agentjail/issues", "", nil)
	op := RecognizeHTTP("api.github.com", req, nil)

	assertEqual(t, "service", "github", op.Service)
	assertEqual(t, "verb", "create", op.Verb)
	assertEqual(t, "resource_type", "issues", op.ResourceType)
}

func TestRecognizeGeneric(t *testing.T) {
	req := makeRequest("POST", "https://api.stripe.com/v1/charges", "", nil)
	op := RecognizeHTTP("api.stripe.com", req, nil)

	assertEqual(t, "service", "api.stripe.com", op.Service)
	assertEqual(t, "verb", "post", op.Verb)
	assertEqual(t, "resource_type", "v1", op.ResourceType)
}

func TestRecognizeGenericWithName(t *testing.T) {
	req := makeRequest("GET", "https://api.example.com/users/123", "", nil)
	op := RecognizeHTTP("api.example.com", req, nil)

	assertEqual(t, "service", "api.example.com", op.Service)
	assertEqual(t, "verb", "get", op.Verb)
	assertEqual(t, "resource_type", "users", op.ResourceType)
	assertEqual(t, "resource_name", "123", op.ResourceName)
}

func assertEqual(t *testing.T, field, expected, actual string) {
	t.Helper()
	if expected != actual {
		t.Errorf("%s: expected %q, got %q", field, expected, actual)
	}
}
