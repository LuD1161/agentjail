package approvalexec

const RedeemRequestType = "codex_approval_redeem"

type WireRedeemRequest struct {
	Type        string      `json:"type"`
	ChallengeID ChallengeID `json:"challenge_id"`
	Operation   Operation   `json:"operation"`
}

type WireRedeemResponse struct {
	OK        bool      `json:"ok"`
	Command   Command   `json:"command,omitempty"`
	CWD       string    `json:"cwd,omitempty"`
	ToolUseID ToolUseID `json:"tool_use_id,omitempty"`
	Error     string    `json:"error,omitempty"`
}
