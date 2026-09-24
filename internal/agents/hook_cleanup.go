package agents

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Decode only owned settings seams; retain foreign fields verbatim as JSON.
// See ADR 0151-install-lifecycle.
func cleanupJSONObject(raw []byte, name string) (map[string]json.RawMessage, error) {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, fmt.Errorf("%s must be an object", name)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return object, nil
}

func cleanupJSONArray(raw []byte, name string) ([]json.RawMessage, error) {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, fmt.Errorf("%s must be an array", name)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return entries, nil
}

func cleanupJSONString(object map[string]json.RawMessage, key, name string) (string, error) {
	raw, present := object[key]
	if !present {
		return "", nil
	}
	var value string
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", fmt.Errorf("%s.%s must be a string", name, key)
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s.%s must be a string: %w", name, key, err)
	}
	return value, nil
}

func removeRegisteredHookGroups(raw []byte, events []string, owned func(string) bool, dropEmpty bool) ([]byte, bool, error) {
	root, err := cleanupJSONObject(raw, "settings")
	if err != nil {
		return raw, false, err
	}
	encodedHooks, present := root["hooks"]
	if !present {
		return raw, false, nil
	}
	hooks, err := cleanupJSONObject(encodedHooks, "hooks")
	if err != nil {
		return raw, false, err
	}
	changed := false
	for _, event := range events {
		encodedGroups, present := hooks[event]
		if !present {
			continue
		}
		groups, err := cleanupJSONArray(encodedGroups, "hooks."+event)
		if err != nil {
			return raw, false, err
		}
		keptGroups := make([]json.RawMessage, 0, len(groups))
		eventChanged := false
		for _, encodedGroup := range groups {
			group, err := cleanupJSONObject(encodedGroup, "hooks."+event+" group")
			if err != nil {
				return raw, false, err
			}
			if _, err := cleanupJSONString(group, "matcher", "hook group"); err != nil {
				return raw, false, err
			}
			encodedEntries := group["hooks"]
			// Codex previously emitted empty groups; retain its normalization.
			if dropEmpty && (encodedEntries == nil || bytes.Equal(bytes.TrimSpace(encodedEntries), []byte("null"))) {
				eventChanged = true
				continue
			}
			entries, err := cleanupJSONArray(encodedEntries, "hooks."+event+" group.hooks")
			if err != nil {
				return raw, false, err
			}
			keptEntries := make([]json.RawMessage, 0, len(entries))
			for _, encodedEntry := range entries {
				entry, err := cleanupJSONObject(encodedEntry, "hook")
				if err != nil {
					return raw, false, err
				}
				command, err := cleanupJSONString(entry, "command", "hook")
				if err != nil {
					return raw, false, err
				}
				hookType, err := cleanupJSONString(entry, "type", "hook")
				if err != nil {
					return raw, false, err
				}
				if (hookType == "" || hookType == "command") && owned(command) {
					continue
				}
				keptEntries = append(keptEntries, encodedEntry)
			}
			if len(keptEntries) != len(entries) || (dropEmpty && len(entries) == 0) {
				eventChanged = true
				if len(keptEntries) == 0 {
					continue
				}
				group["hooks"], _ = json.Marshal(keptEntries)
				encodedGroup, _ = json.Marshal(group)
			}
			keptGroups = append(keptGroups, encodedGroup)
		}
		if eventChanged {
			hooks[event], _ = json.Marshal(keptGroups)
			changed = true
		}
	}
	if !changed {
		return raw, false, nil
	}
	root["hooks"], _ = json.Marshal(hooks)
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return raw, false, err
	}
	return append(out, '\n'), true, nil
}

func removeRegisteredFlatHooks(raw []byte, events []string, owned func(string) bool) ([]byte, bool, error) {
	root, err := cleanupJSONObject(raw, "settings")
	if err != nil {
		return raw, false, err
	}
	encodedHooks, present := root["hooks"]
	if !present {
		return raw, false, nil
	}
	hooks, err := cleanupJSONObject(encodedHooks, "hooks")
	if err != nil {
		return raw, false, err
	}
	changed := false
	for _, event := range events {
		encoded, present := hooks[event]
		if !present {
			continue
		}
		entries, err := cleanupJSONArray(encoded, "hooks."+event)
		if err != nil {
			return raw, false, err
		}
		kept := make([]json.RawMessage, 0, len(entries))
		for _, encodedEntry := range entries {
			entry, err := cleanupJSONObject(encodedEntry, "hook")
			if err != nil {
				return raw, false, err
			}
			command, err := cleanupJSONString(entry, "command", "hook")
			if err != nil {
				return raw, false, err
			}
			if !owned(command) {
				kept = append(kept, encodedEntry)
			}
		}
		if len(kept) != len(entries) {
			if len(kept) == 0 {
				delete(hooks, event)
			} else {
				hooks[event], _ = json.Marshal(kept)
			}
			changed = true
		}
	}
	if !changed {
		return raw, false, nil
	}
	root["hooks"], _ = json.Marshal(hooks)
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return raw, false, err
	}
	return append(out, '\n'), true, nil
}
