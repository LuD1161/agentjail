// rule_id_aliases.go — backward-compatibility alias map for command_policy rule_ids.
//
// Prior to ADR 0014 §0a, command_policy.rego emitted 16 unprefixed rule_ids
// (e.g. "no-sudo", "confirm-git-push").  They were renamed to the namespaced
// form ("command_policy/no-sudo", "command_policy/confirm-git-push") so the
// disabled_rules feature can operate on coherent "command_policy/*" globs.
//
// RuleIDAliases maps each OLD (pre-rename) rule_id to its NEW namespaced
// equivalent.  Use this map to normalize any stored, logged, or user-supplied
// rule_id that may reference the old form — for example when resolving a
// disabled_rules entry from a policy.yaml written before the upgrade.
//
// Invariant (tested in rule_id_aliases_test.go):
//   - Every old id maps to exactly "command_policy/<old>".
//   - The map has exactly 16 entries — one per renamed rule.
package policy

// RuleIDAliases maps pre-0014§0a (unprefixed) command_policy rule_ids to
// their current namespaced form.  This is the canonical backward-compat
// lookup; do not scatter ad-hoc string replacements across the codebase.
var RuleIDAliases = map[string]string{
	"no-sudo":                    "command_policy/no-sudo",
	"no-rm-rf-absolute":          "command_policy/no-rm-rf-absolute",
	"no-git-push-force":          "command_policy/no-git-push-force",
	"no-chmod-777":               "command_policy/no-chmod-777",
	"no-dd-device-read":          "command_policy/no-dd-device-read",
	"no-device-overwrite":        "command_policy/no-device-overwrite",
	"no-env-exfil":               "command_policy/no-env-exfil",
	"no-gpg-secret-export":       "command_policy/no-gpg-secret-export",
	"no-launchctl-remove":        "command_policy/no-launchctl-remove",
	"no-pipe-to-shell":           "command_policy/no-pipe-to-shell",
	"no-ssh-keygen-outside-tmp":  "command_policy/no-ssh-keygen-outside-tmp",
	"no-systemctl-disrupt":       "command_policy/no-systemctl-disrupt",
	"no-bash-touch-sensitive-path": "command_policy/no-bash-touch-sensitive-path",
	"confirm-curl-download":      "command_policy/confirm-curl-download",
	"confirm-git-push":           "command_policy/confirm-git-push",
	"confirm-publish":            "command_policy/confirm-publish",
}

// ResolveRuleID returns the canonical (namespaced) form of id.
// If id is a known old alias it returns the new name; otherwise it returns id
// unchanged.  Callers should use this before comparing against registered
// rule_ids or evaluating disabled_rules globs.
func ResolveRuleID(id string) string {
	if canonical, ok := RuleIDAliases[id]; ok {
		return canonical
	}
	return id
}
