package proxyctl

import (
	"reflect"
	"strings"
	"testing"
)

// TestGrantInfoHasNoToken is a structural guard for ADR 0044: the grant_list
// response (GrantInfo) is printed to a human terminal by `agentjail grants` and
// must NEVER carry the session's data-plane bearer token. netproxy resolves
// session->token from its own in-memory registration by GrantID; the token is
// never persisted, listed, or accepted from approval input. This test fails
// loudly if a future edit adds a Token-shaped field so the leak is caught at
// build time rather than in a live session.
func TestGrantInfoHasNoToken(t *testing.T) {
	assertNoTokenField(t, reflect.TypeOf(GrantInfo{}))
}

func assertNoTokenField(t *testing.T, typ reflect.Type) {
	t.Helper()
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if strings.Contains(strings.ToLower(f.Name), "token") {
			t.Errorf("%s has a token-shaped field %q -- the grant list must never carry the session token (ADR 0044)", typ.Name(), f.Name)
		}
		tag := strings.ToLower(f.Tag.Get("json"))
		if strings.Contains(tag, "token") {
			t.Errorf("%s field %q has a token-shaped json tag %q -- the grant list must never serialize the session token (ADR 0044)", typ.Name(), f.Name, tag)
		}
		if f.Type == reflect.TypeOf(Token("")) {
			t.Errorf("%s field %q is a proxyctl.Token -- it must not appear in the human-facing grant list (ADR 0044)", typ.Name(), f.Name)
		}
	}
}
