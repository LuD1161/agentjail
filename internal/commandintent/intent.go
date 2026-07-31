// Package commandintent classifies parsed shell invocations into semantic
// operations consumed by command policy.
package commandintent

import (
	"strings"

	"github.com/LuD1161/agentjail/internal/shellparse"
)

// Intent is a semantic command operation, independent of shell spelling.
type Intent string

const (
	GitPush              Intent = "git-push"
	GitPushForceDefault  Intent = "git-push-force-default"
	GitPushForceTopic    Intent = "git-push-force-topic"
	GitPushForceImplicit Intent = "git-push-force-implicit"
)

// Analyze classifies every executable invocation recovered from a shell
// expression. Duplicate intents are collapsed while preserving first-seen
// order.
func Analyze(parsed shellparse.Result) []Intent {
	seen := make(map[Intent]struct{})
	intents := make([]Intent, 0)
	for _, invocation := range parsed.Invocations {
		intent, ok := classifyGit(invocation)
		if !ok {
			continue
		}
		if _, exists := seen[intent]; exists {
			continue
		}
		seen[intent] = struct{}{}
		intents = append(intents, intent)
	}
	return intents
}

type gitCommand struct {
	Name      string
	Arguments []string
	Aliases   map[string]string
}

func classifyGit(invocation shellparse.Invocation) (Intent, bool) {
	if invocation.Binary != "git" {
		return "", false
	}
	command, ok := parseGitCommand(invocation.Arguments)
	if !ok {
		return "", false
	}
	command = expandInlineAlias(command)
	if command.Name != "push" {
		return "", false
	}
	return classifyPush(command.Arguments), true
}

func parseGitCommand(arguments []string) (gitCommand, bool) {
	aliases := make(map[string]string)
	for i := 0; i < len(arguments); {
		argument := arguments[i]
		switch {
		case argument == "--":
			i++
			if i >= len(arguments) {
				return gitCommand{}, false
			}
			return gitCommand{Name: arguments[i], Arguments: arguments[i+1:], Aliases: aliases}, true
		case argument == "-C" || argument == "-c":
			if i+1 >= len(arguments) {
				return gitCommand{}, false
			}
			if argument == "-c" {
				recordAlias(aliases, arguments[i+1])
			}
			i += 2
		case strings.HasPrefix(argument, "-C") && argument != "-C":
			i++
		case strings.HasPrefix(argument, "-c") && argument != "-c":
			recordAlias(aliases, strings.TrimPrefix(argument, "-c"))
			i++
		case isGitGlobalFlag(argument):
			i++
		case strings.HasPrefix(argument, "--git-dir="),
			strings.HasPrefix(argument, "--work-tree="),
			strings.HasPrefix(argument, "--namespace="),
			strings.HasPrefix(argument, "--config-env="),
			strings.HasPrefix(argument, "--exec-path="):
			i++
		case strings.HasPrefix(argument, "-"):
			// Unknown global flags are skipped conservatively. Git's documented
			// value-taking global flags are handled above.
			i++
		default:
			return gitCommand{Name: argument, Arguments: arguments[i+1:], Aliases: aliases}, true
		}
	}
	return gitCommand{}, false
}

func isGitGlobalFlag(argument string) bool {
	switch argument {
	case "-p", "--paginate", "-P", "--no-pager",
		"--no-replace-objects", "--no-lazy-fetch", "--no-optional-locks",
		"--no-advice", "--bare", "--html-path", "--man-path", "--info-path",
		"--exec-path":
		return true
	default:
		return false
	}
}

func recordAlias(aliases map[string]string, config string) {
	key, value, ok := strings.Cut(config, "=")
	if !ok || !strings.HasPrefix(key, "alias.") {
		return
	}
	name := strings.TrimPrefix(key, "alias.")
	if name != "" {
		aliases[name] = value
	}
}

func expandInlineAlias(command gitCommand) gitCommand {
	value, ok := command.Aliases[command.Name]
	if !ok || strings.HasPrefix(value, "!") {
		return command
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return command
	}
	return gitCommand{
		Name:      fields[0],
		Arguments: append(fields[1:], command.Arguments...),
		Aliases:   command.Aliases,
	}
}

type pushShape struct {
	force          bool
	repositoryFlag bool
	broadTarget    bool
	positionals    []string
	defaultHint    bool
}

func classifyPush(arguments []string) Intent {
	shape := parsePushShape(arguments)
	if !shape.force {
		return GitPush
	}

	refspecs := shape.positionals
	if !shape.repositoryFlag && len(refspecs) > 0 {
		refspecs = refspecs[1:]
	}
	if shape.defaultHint || refspecTargetsDefault(refspecs) {
		return GitPushForceDefault
	}
	if shape.broadTarget || len(refspecs) == 0 {
		return GitPushForceImplicit
	}
	return GitPushForceTopic
}

func parsePushShape(arguments []string) pushShape {
	var shape pushShape
	for i := 0; i < len(arguments); i++ {
		argument := arguments[i]
		switch {
		case argument == "--":
			shape.positionals = append(shape.positionals, arguments[i+1:]...)
			return shape
		case argument == "-f" || argument == "--force":
			shape.force = true
		case shortFlagsContainForce(argument):
			shape.force = true
		case strings.HasPrefix(argument, "--force-with-lease"):
			shape.force = true
			if value, ok := strings.CutPrefix(argument, "--force-with-lease="); ok {
				ref, _, _ := strings.Cut(value, ":")
				shape.defaultHint = isDefaultRef(ref)
			}
		case argument == "--all" || argument == "--mirror":
			shape.broadTarget = true
		case argument == "--repo" || argument == "--receive-pack" ||
			argument == "--exec" || argument == "--push-option" ||
			argument == "-o" || argument == "--server-option":
			if i+1 < len(arguments) {
				if argument == "--repo" {
					shape.repositoryFlag = true
				}
				i++
			}
		case strings.HasPrefix(argument, "--repo="):
			shape.repositoryFlag = true
		case strings.HasPrefix(argument, "-"):
			// Other push options do not contribute positional refspecs.
		default:
			shape.positionals = append(shape.positionals, argument)
			if strings.HasPrefix(argument, "+") {
				shape.force = true
			}
		}
	}
	return shape
}

func shortFlagsContainForce(argument string) bool {
	if len(argument) < 2 || argument[0] != '-' || argument[1] == '-' {
		return false
	}
	return strings.ContainsRune(argument[1:], 'f')
}

func refspecTargetsDefault(refspecs []string) bool {
	for _, refspec := range refspecs {
		refspec = strings.TrimPrefix(refspec, "+")
		_, destination, hasDestination := strings.Cut(refspec, ":")
		if hasDestination {
			if isDefaultRef(destination) {
				return true
			}
			continue
		}
		if isDefaultRef(refspec) {
			return true
		}
	}
	return false
}

func isDefaultRef(ref string) bool {
	ref = strings.TrimPrefix(ref, "refs/heads/")
	return ref == "main" || ref == "master"
}
