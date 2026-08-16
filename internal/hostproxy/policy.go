package hostproxy

import (
	"path/filepath"
	"strings"
)

type Decision struct {
	Action Action
	Reason string
}

var deniedExecutables = map[string]string{
	"git": "git clients", "gh": "git clients",
	"aws": "cloud and infrastructure clients", "kubectl": "cloud and infrastructure clients",
	"helm": "cloud and infrastructure clients", "terraform": "cloud and infrastructure clients",
	"tofu": "cloud and infrastructure clients", "gcloud": "cloud and infrastructure clients", "az": "cloud and infrastructure clients",
	"sh": "shells", "bash": "shells", "zsh": "shells", "dash": "shells", "fish": "shells",
	"ksh": "shells", "csh": "shells", "tcsh": "shells", "pwsh": "shells", "powershell": "shells", "cmd": "shells",
	"python": "interpreters", "python3": "interpreters", "node": "interpreters", "nodejs": "interpreters",
	"perl": "interpreters", "ruby": "interpreters", "php": "interpreters", "deno": "interpreters", "bun": "interpreters",
	"env": "wrappers and escalators", "xargs": "wrappers and escalators", "sudo": "wrappers and escalators",
	"nohup": "wrappers and escalators", "timeout": "wrappers and escalators", "command": "wrappers and escalators",
	"nice": "wrappers and escalators", "stdbuf": "wrappers and escalators", "setsid": "wrappers and escalators",
	"busybox": "wrappers and escalators", "doas": "wrappers and escalators", "chroot": "wrappers and escalators",
	"script": "wrappers and escalators", "make": "wrappers and escalators",
	"npm": "package and runtime wrappers", "npx": "package and runtime wrappers", "pnpm": "package and runtime wrappers",
	"yarn": "package and runtime wrappers", "corepack": "package and runtime wrappers",
	"uv": "package and runtime wrappers", "uvx": "package and runtime wrappers", "pipx": "package and runtime wrappers",
	"agentjail": "AgentJail control binaries", "agentjail-daemon": "AgentJail control binaries",
	"agentjail-shield": "AgentJail control binaries", "agentjail-netproxy": "AgentJail control binaries",
	"agentjail-secrets": "AgentJail control binaries", "agentjail-hook": "AgentJail control binaries",
}

func Evaluate(target Target) Decision {
	if target.Executable == "" || len(target.Argv) == 0 || target.Argv[0] == "" {
		return Decision{Action: ActionDeny, Reason: "empty or malformed command"}
	}
	name := strings.ToLower(filepath.Base(target.Executable))
	if category, denied := deniedExecutables[name]; denied {
		return Decision{Action: ActionDeny, Reason: name + " is denied through the host proxy (" + category + ")"}
	}
	for _, runtimeName := range []string{"python", "node", "nodejs", "perl", "ruby", "php"} {
		if versionedRuntime(name, runtimeName) {
			return Decision{Action: ActionDeny, Reason: name + " is denied through the host proxy (interpreters)"}
		}
	}
	return Decision{Action: ActionAsk, Reason: "host execution requires one-time user approval"}
}

func versionedRuntime(name, base string) bool {
	if !strings.HasPrefix(name, base) || len(name) == len(base) {
		return false
	}
	for _, r := range name[len(base):] {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}
