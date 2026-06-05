export type TranscriptLine =
  | {kind: 'user'; text: string}
  | {kind: 'assistant'; text: string}
  | {kind: 'tool'; command: string}
  | {kind: 'blocked'; rule: string};

export type LogRow = {
  time: string;
  action: 'ALLOW' | 'DENY' | 'ASK';
  tool: string;
  impact?: string;
  cmd?: string;
};

// Verdict strings verified against real `agentjail try` output.
// NOTE: `agentjail try` subcommand is not implemented in the current build;
// using expected values from the policy engine.
export const RULE = 'file_policy/sensitive_credential';

export const beat1: TranscriptLine[] = [
  {kind: 'user', text: 'clean up my Downloads, it’s huge'},
  {kind: 'assistant', text: 'I’ll clear out the contents.'},
  {kind: 'tool', command: 'rm -rf ~/Downloads/*'},
  {kind: 'blocked', rule: RULE},
  {kind: 'assistant', text: 'That’s blocked by your policy — I won’t touch those files.'},
];

export const beat2: TranscriptLine[] = [
  {kind: 'user', text: 'summarize my project so I can paste it into an LLM'},
  {kind: 'assistant', text: 'Reading the project config…'},
  {kind: 'tool', command: 'cat .env ~/.aws/credentials'},
  {kind: 'blocked', rule: RULE},
  {kind: 'assistant', text: 'Those are credential files — agentjail won’t let me read them.'},
];

export const seedRows: LogRow[] = [
  {time: '19:24:01', action: 'ALLOW', tool: 'Bash'},
  {time: '19:24:03', action: 'ALLOW', tool: 'Read'},
];

export const denyRow1: LogRow = {
  time: '19:24:07', action: 'DENY', tool: 'Bash',
  impact: 'sensitive path', cmd: 'rm -rf ~/Downloads/*',
};
export const denyRow2: LogRow = {
  time: '19:24:12', action: 'DENY', tool: 'Bash',
  impact: 'credential read', cmd: 'cat .env ~/.aws/credentials',
};

export const montageIcons = [
  'amazonwebservices', 'kubernetes', 'docker', 'github',
  'stripe', 'twilio', 'npm', 'slack', 'googlecloud',
];

export const installCmd = 'curl -fsSL https://…/install.sh | sh';
export const tagline = 'your agent literally can’t do that';
