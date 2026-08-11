// Package credentialguidance owns the session instruction shared by agent
// adapters and the credential MCP server.
package credentialguidance

const SessionInstructions = "You are running inside an AgentJail session without ambient CLI credentials. Before using a credentialed CLI, call list_credentials, select the exact credential ID matching the user's requested account or context, and call request_credential with a concrete reason. If more than one credential could match, ask the user; AgentJail never chooses one for you. Apply the returned environment variables or mode-0600 file only inside this session, and never print credential values."
