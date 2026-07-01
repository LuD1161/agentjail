// audit.go — audit helpers for policy mutations.
//
// All policy mutation functions now use policyctl.Controller which
// encapsulates the two-phase audit ceremony (Plan 009 / Plan 010).
// This file is intentionally empty; the old appendAuditEvent and
// emitPolicyAudit helpers have been replaced by policyctl.Apply /
// policyctl.ApplyWithConfig.
package main
