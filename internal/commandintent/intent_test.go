package commandintent

import (
	"reflect"
	"testing"

	"github.com/LuD1161/agentjail/internal/shellparse"
)

func TestAnalyzeGitPush(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want []Intent
	}{
		{"plain", "git push origin topic", []Intent{GitPush}},
		{"working directory", "git -C /tmp/work push origin topic", []Intent{GitPush}},
		{"repeated global options", "git -C /tmp -c color.ui=false -C work push origin topic", []Intent{GitPush}},
		{"long global options", "git --no-pager --git-dir=/tmp/repo.git --work-tree=/tmp/work push origin topic", []Intent{GitPush}},
		{"absolute binary", "/usr/bin/git -C /tmp/work push origin topic", []Intent{GitPush}},
		{"environment wrapper", "env TRACE=1 git -C /tmp/work push origin topic", []Intent{GitPush}},
		{"shell wrapper", "sh -c 'git -C /tmp/work push origin topic'", []Intent{GitPush}},
		{"inline alias", "git -c alias.ship=push ship origin topic", []Intent{GitPush}},
		{"force default", "git -C /tmp/work push --force origin main", []Intent{GitPushForceDefault}},
		{"force default destination", "git -C /tmp/work push -f origin HEAD:refs/heads/main", []Intent{GitPushForceDefault}},
		{"force lease default", "git push --force-with-lease=master origin", []Intent{GitPushForceDefault}},
		{"plus default", "git push origin +main", []Intent{GitPushForceDefault}},
		{"force topic", "git -C /tmp/work push --force-with-lease origin HEAD:refs/heads/topic", []Intent{GitPushForceTopic}},
		{"combined force topic", "git push -uf origin topic", []Intent{GitPushForceTopic}},
		{"plus topic", "git push origin +topic", []Intent{GitPushForceTopic}},
		{"force implicit", "git -C /tmp/work push -f", []Intent{GitPushForceImplicit}},
		{"force all", "git push --force --all origin", []Intent{GitPushForceImplicit}},
		{"repo option topic", "git push --repo origin.git -f topic", []Intent{GitPushForceTopic}},
		{"text search", `rg -n "git push" README.md`, []Intent{}},
		{"echo text", `printf '%s\n' "git -C /tmp push origin topic"`, []Intent{}},
		{"global option value named push", "git -C push status", []Intent{}},
		{"config value mentions push", "git -c demo.value=push status", []Intent{}},
		{"status", "git status", []Intent{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Analyze(shellparse.Parse(tt.cmd))
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Analyze(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}
