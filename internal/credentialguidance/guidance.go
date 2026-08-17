// Package credentialguidance owns the session instruction shared by agent
// adapters and the credential MCP server.
package credentialguidance

const SessionInstructions = "You are running inside an AgentJail session without ambient credentials. Before using a credential, call list_credentials and select the exact user-defined credential ID. Names, labels, and tags are descriptive only; AgentJail does not infer a provider, permission level, or purpose. If more than one credential could match, ask the user. Apply the returned environment variables or mode-0600 file only inside this session, and never print credential values."
