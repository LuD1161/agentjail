package main

import (
	"encoding/json"
	"testing"
)

func TestClaudeSuccessfulPostToolUseNeverInfersSandboxDenialFromOutput(t *testing.T) {
	input := hookInput{
		HookEventName: "PostToolUse",
		ToolResponse:  json.RawMessage(`{"stdout":"docs mention sandbox deny and EPERM: operation not permitted","success":true}`),
	}

	got := classifyOutcome("claude", input)
	if got.SandboxDenied {
		t.Fatalf("successful PostToolUse output produced sandbox denial: %+v", got)
	}
}

func TestClaudePostToolUseFailureRequiresDenialSignature(t *testing.T) {
	tests := []struct {
		name string
		err  string
		deny bool
	}{
		{name: "sandbox denial", err: "cat: /home/user/.ssh/id_rsa: Operation not permitted", deny: true},
		{name: "ordinary failure", err: "command exited with non-zero status code 1", deny: false},
		{name: "empty error is not failure evidence", err: "", deny: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyOutcome("claude", hookInput{
				HookEventName: claudePostToolUseFailure,
				Error:         tt.err,
			})
			if got.SandboxDenied != tt.deny {
				t.Fatalf("SandboxDenied = %v, want %v; outcome=%+v", got.SandboxDenied, tt.deny, got)
			}
		})
	}
}

func TestCodexPostToolUseRequiresStructuredNonzeroExit(t *testing.T) {
	tests := []struct {
		name     string
		response string
		deny     bool
		exitCode int
	}{
		{
			name:     "structured failure with signature",
			response: `{"exit_code":1,"stderr":"open: operation not permitted"}`,
			deny:     true,
			exitCode: 1,
		},
		{
			name:     "structured success containing documentation",
			response: `{"exit_code":0,"stdout":"EPERM means operation not permitted"}`,
			deny:     false,
			exitCode: 0,
		},
		{
			name:     "plain current Bash output has no failure evidence",
			response: `"open: operation not permitted"`,
			deny:     false,
			exitCode: 0,
		},
		{
			name:     "ordinary structured failure is not sandbox denial",
			response: `{"metadata":{"exit_code":2},"stderr":"test assertion failed"}`,
			deny:     false,
			exitCode: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyOutcome("codex", hookInput{
				HookEventName: "PostToolUse",
				ToolResponse:  json.RawMessage(tt.response),
			})
			if got.SandboxDenied != tt.deny {
				t.Fatalf("SandboxDenied = %v, want %v; outcome=%+v", got.SandboxDenied, tt.deny, got)
			}
			if got.ExitCode != tt.exitCode {
				t.Fatalf("ExitCode = %d, want %d; outcome=%+v", got.ExitCode, tt.exitCode, got)
			}
		})
	}
}

func TestSandboxDenialSignatureRejectsLooseSandboxProse(t *testing.T) {
	if matched, _ := sandboxDenialSignature("the sandbox may deny this operation"); matched {
		t.Fatal("loose sandbox/deny prose matched a sandbox denial signature")
	}
}
