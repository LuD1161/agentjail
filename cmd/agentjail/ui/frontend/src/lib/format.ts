export function formatTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleTimeString(undefined, { hour12: false })
}

export function formatBytes(n?: number): string {
  if (!n) return '0 B'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

export function actionClass(action?: string): string {
  switch (action) {
    case 'allow':
      return 'text-[#56d364]'
    case 'deny':
      return 'text-[#ff7b72] font-bold'
    case 'ask':
      return 'text-[#e3b341]'
    default:
      return 'text-[#9ca3af]'
  }
}

// ADR 0112: the policy `action` ("allow"/"deny"/"ask") and the observed
// `final_action` ("allowed"/"blocked"/"ask") use different vocabularies --
// this maps final_action onto action's color-class keys so both can share
// actionClass().
const FINAL_ACTION_TO_ACTION: Record<string, string> = {
  allowed: 'allow',
  blocked: 'deny',
  ask: 'ask',
}

/** The truthful verdict to display: the observed outcome if we have one, else the raw policy action. */
export function displayVerdict(action?: string, finalAction?: string): string | undefined {
  if (finalAction) return FINAL_ACTION_TO_ACTION[finalAction] ?? finalAction
  return action
}

/** True when the OS sandbox is the layer that produced a "blocked" final outcome. */
export function isSandboxBlock(finalAction?: string, enforcer?: string): boolean {
  return enforcer === 'sandbox' && finalAction === 'blocked'
}

/** Human note when the final outcome diverges from the raw policy action, e.g. "policy: allow → sandbox: blocked". Undefined when they agree or we lack outcome data. */
export function finalOutcomeNote(action?: string, finalAction?: string, enforcer?: string): string | undefined {
  if (!finalAction || !enforcer) return undefined
  if ((FINAL_ACTION_TO_ACTION[finalAction] ?? finalAction) === action) return undefined
  return `policy: ${action ?? '-'} → ${enforcer}: ${finalAction}`
}
