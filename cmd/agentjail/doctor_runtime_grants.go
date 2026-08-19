package main

// runtimeGrantDiagnostic is the value-free state projection doctor can report.
// It deliberately has no destination, token, request, or approval reference.
// See ADR 0141-runtime-grants.
type runtimeGrantDiagnostic string

const (
	grantDiagnosticUnknown              runtimeGrantDiagnostic = "unknown"
	grantDiagnosticPolicyDenied         runtimeGrantDiagnostic = "policy_denied"
	grantDiagnosticApprovalUnavailable  runtimeGrantDiagnostic = "approval_unavailable"
	grantDiagnosticApprovalPending      runtimeGrantDiagnostic = "approval_pending"
	grantDiagnosticApprovalDenied       runtimeGrantDiagnostic = "approval_denied"
	grantDiagnosticInactive             runtimeGrantDiagnostic = "inactive"
	grantDiagnosticExpired              runtimeGrantDiagnostic = "expired"
	grantDiagnosticRevoked              runtimeGrantDiagnostic = "revoked"
	grantDiagnosticTransportUnavailable runtimeGrantDiagnostic = "transport_unavailable"
	grantDiagnosticActivationFailed     runtimeGrantDiagnostic = "activation_failed"
	grantDiagnosticUpstreamUnreachable  runtimeGrantDiagnostic = "upstream_unreachable"
	grantDiagnosticActive               runtimeGrantDiagnostic = "active"
)

func runtimeGrantDiagnosticCheck(state runtimeGrantDiagnostic) doctorCheck {
	check := doctorCheck{label: "Runtime grant", status: statusWarn}
	switch state {
	case grantDiagnosticPolicyDenied:
		check.detail = "policy denied; a runtime grant cannot override an explicit or locked deny"
	case grantDiagnosticApprovalUnavailable:
		check.detail = "approval transport unavailable; request remains unauthorized"
	case grantDiagnosticApprovalPending:
		check.detail = "approval pending; request remains unauthorized"
	case grantDiagnosticApprovalDenied:
		check.detail = "approval denied; request remains unauthorized"
	case grantDiagnosticInactive:
		check.detail = "grant inactive; approval has not completed required activation"
	case grantDiagnosticExpired:
		check.detail = "grant expired; request a new approval"
	case grantDiagnosticRevoked:
		check.detail = "grant revoked or consumed; request a new approval"
	case grantDiagnosticTransportUnavailable:
		check.detail = "connector transport unavailable for this isolation boundary"
	case grantDiagnosticActivationFailed:
		check.detail = "connector activation or readiness probe failed; no authority was exposed"
	case grantDiagnosticUpstreamUnreachable:
		check.detail = "configured upstream unreachable; authorization and reachability are separate"
	case grantDiagnosticActive:
		check.status, check.detail = statusOK, "grant active; exact configured resource is ready"
	default:
		check.status, check.detail = statusSkip, "no live runtime grant to inspect; approval, activation, and reachability are reported separately"
	}
	return check
}
