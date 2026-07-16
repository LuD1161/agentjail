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
