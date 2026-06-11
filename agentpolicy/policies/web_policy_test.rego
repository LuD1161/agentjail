# web_policy_test.rego — unit tests for the WebSearch / WebFetch posture.
package agentjail

import future.keywords.if
import future.keywords.in

# WebSearch always allows, regardless of config.
test_websearch_allows if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name": "WebSearch",
		"tool_input": {"query": "remotion vs revideo"},
	}
	d.action == "allow"
	d.rule_id == "web_policy/search"
}

# WebFetch to an ordinary host allows by default (empty blocklist).
test_webfetch_allows_by_default if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name": "WebFetch",
		"tool_input": {"url": "https://www.pkgpulse.com/blog/x"},
	}
	d.action == "allow"
	d.rule_id == "web_policy/fetch"
}

# WebFetch to a blocked host denies; blocked takes precedence over the allow.
test_webfetch_blocked_host_denies if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name": "WebFetch",
		"tool_input": {"url": "https://evil.tracking.example.com/collect?x=1"},
	}
		with data.agentjail.config as {"web": {"blocked": ["*tracking*"]}}
	d.action == "deny"
	d.rule_id == "web_policy/fetch_blocked"
}

# A blocklist that does not match leaves WebFetch allowed.
test_webfetch_nonmatching_block_allows if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name": "WebFetch",
		"tool_input": {"url": "https://docs.example.org/page"},
	}
		with data.agentjail.config as {"web": {"blocked": ["*tracking*", "169.254.*"]}}
	d.action == "allow"
	d.rule_id == "web_policy/fetch"
}

# Host match is case-insensitive and ignores the port.
test_webfetch_block_case_and_port if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name": "WebFetch",
		"tool_input": {"url": "https://API.Internal.Corp:8443/secret"},
	}
		with data.agentjail.config as {"web": {"blocked": ["*.internal.corp"]}}
	d.action == "deny"
	d.rule_id == "web_policy/fetch_blocked"
}

# A malformed (scheme-less) WebFetch URL can't be parsed for a host; it falls
# back to the default allow rather than erroring.
test_webfetch_malformed_url_allows if {
	d := decision with input as {
		"hook_event": "PreToolUse",
		"tool_name": "WebFetch",
		"tool_input": {"url": "not-a-url"},
	}
		with data.agentjail.config as {"web": {"blocked": ["*tracking*"]}}
	d.action == "allow"
	d.rule_id == "web_policy/fetch"
}

# A non-web tool gets no candidate from this policy (no web_policy/* rule_id).
test_non_web_tool_unaffected if {
	not web_fetch_host with input as {
		"hook_event": "PreToolUse",
		"tool_name": "Read",
		"tool_input": {"file_path": "/tmp/x"},
	}
}
