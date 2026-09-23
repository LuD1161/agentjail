package policyeval

import (
	"context"
	"testing"

	agentconfig "github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/projectpolicy"
)

func TestProjectEngineRejectsPublicationAfterReload(t *testing.T) {
	e := newTrustTestEvaluator(t)
	old := &projectEngine{eng: e.engine, cache: e.cache, generation: e.gen.Load()}
	if err := e.Reload(context.Background(), e.modules, agentconfig.Default()); err != nil {
		t.Fatal(err)
	}
	if e.publishProjectEngine("project", old) {
		t.Fatal("published engine from previous global generation")
	}
	if len(e.projectEngines) != 0 {
		t.Fatal("obsolete engine populated project cache")
	}
}

func TestProjectEngineLookupRequiresCurrentGeneration(t *testing.T) {
	const overlay = "mcp:\n  allowed: [test-server]\n"
	root, _ := setupTrustTestRepo(t, overlay, true)
	e := newTrustTestEvaluator(t)
	obsolete := &projectEngine{eng: e.engine, cache: e.cache, configHash: projectpolicy.HashContent([]byte(overlay))}
	e.projectEngines = map[string]*projectEngine{root: obsolete}
	e.gen.Store(1)
	eng, _ := e.resolveProjectEngine(context.Background(), root)
	if eng == nil || eng == obsolete.eng {
		t.Fatal("did not rebuild engine for current global generation")
	}
	if e.projectEngines[root].generation != 1 {
		t.Fatal("compiled engine has incorrect generation")
	}
}
