const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })
const dayFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' })

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return 'n/a'
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? value : dateFmt.format(d)
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return 'n/a'
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? value : dayFmt.format(d)
}

export function duration(start: string | null, end: string | null): string | null {
  if (!start || !end) return null
  const ms = new Date(end).getTime() - new Date(start).getTime()
  if (!Number.isFinite(ms) || ms < 0) return null
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`
}

export function percent(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined) return 'n/a'
  return `${(value * 100).toFixed(digits)}%`
}

const BLOCK_MESSAGES: Record<string, string> = {
  'blocked_target.ip_address': "Raw IP addresses can't be scanned. Enter a domain name such as example.com.",
  'blocked_target.private_ip':
    "This domain points to a private, internal or reserved address (like 10.x, 192.168.x or cloud metadata), which can't be scanned.",
  'blocked_target.internal_host': "Internal hostnames (.local, .internal, localhost…) can't be scanned.",
  'blocked_target.credentials': "URLs with usernames or passwords aren't allowed.",
  'blocked_target.port': 'Only the standard web ports 80 and 443 can be scanned.',
  'blocked_target.scheme': 'Only http:// and https:// targets are supported.',
  'blocked_target.unresolvable': "That domain doesn't resolve in DNS. Check the spelling.",
}

export function blockedTargetMessage(code: string, fallback: string): string {
  return BLOCK_MESSAGES[code] ?? fallback
}
