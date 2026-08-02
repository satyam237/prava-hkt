/** Thin Warrant API client. Paths match backend/app/main.py. Proxy: /api → :8000 */

const BASE = '/api'

export type MoneyStr = string

export type IntentBody = {
  reference: string
  sku: string
  description: string
  quantity: number
  amount: MoneyStr
  currency?: string
  expected_fulfillment_by?: string | null
}

export type Merchant = {
  domain: string
  host: string
  url: string
  source?: string
}

export type Authorization = {
  sku: string
  description: string
  quantity: number
  amount: MoneyStr
  currency: string
  single_use: boolean
  expected_fulfillment_by: string | null
}

export type IntentResponse = {
  intent_id: string
  merchant: Merchant
  authorization: Authorization
}

export type SignalPayload = {
  name: string
  tier: string
  value: unknown
  status: 'PASS' | 'FAIL' | 'UNAVAILABLE' | string
  detail?: string | null
}

export type ProbeAnnounced = { name: string; tier: string }

export type StartedEvent = {
  verification_id: string
  intent_id: string
  merchant: { domain: string; host: string; url: string }
  probes: ProbeAnnounced[]
}

export type VerdictEvent = {
  verification_id: string
  verdict: 'PASS' | 'HALT' | string
  score: string
  content_hash: string
  content_bytes?: number
  content_error?: string | null
  signals: SignalPayload[]
  halt_reason: string | null
  warrant: WarrantDocument | null
  warrant_hash: string | null
  payment?: {
    available: boolean
    passkey?: string
    notice?: string
  }
}

export type WarrantDocument = {
  version: string
  warrant_id: string
  issued_at: string
  merchant: { domain: string; resolved_name: string | null }
  authorization: Authorization
  verification: {
    verdict: string
    score: string
    content_hash: string
    signals: SignalPayload[]
  }
  signature?: string | null
}

export type SessionResponse = {
  session_id: string
  iframe_url?: string | null
  order_id?: string | null
  expires_at?: string | null
  status?: string | null
  mandate_id?: string | null
  notice?: string | null
}

export type SessionResult = {
  session_id: string
  status?: string | null
  mandate_id?: string | null
  error?: { code?: string; message?: string } | null
  [key: string]: unknown
}

export type OutcomeBody = {
  warrant_id: string
  merchant_domain: string
  sku?: string | null
  description?: string | null
  quantity?: number | null
  amount?: MoneyStr | null
  currency?: string | null
  delivered?: boolean | null
  order_id?: string | null
  source?: string | null
  fulfilled_at?: string | null
}

export type BreachRow = {
  code: string
  provenance?: string
  expected?: string | null
  observed?: string | null
  evidence?: string | null
  detail?: string | null
}

export type ReconcileResponse = {
  reconciliation: {
    warrant_id: string
    status: 'SETTLED' | 'BREACH' | 'PENDING' | string
    breaches: BreachRow[]
    reconciled_at: string
  }
  dispute_packet?: unknown
  backend_pending?: boolean
  demo?: boolean
}

async function parseError(res: Response): Promise<string> {
  try {
    const body = await res.json()
    if (typeof body?.detail === 'string') return body.detail
    if (Array.isArray(body?.detail)) {
      return body.detail.map((d: { msg?: string }) => d.msg ?? JSON.stringify(d)).join('; ')
    }
    return JSON.stringify(body)
  } catch {
    return res.statusText || `HTTP ${res.status}`
  }
}

export async function resolveMerchant(reference: string): Promise<Merchant> {
  const res = await fetch(`${BASE}/v1/merchants/resolve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reference }),
  })
  if (!res.ok) throw new Error(await parseError(res))
  return res.json()
}

export async function createIntent(body: IntentBody): Promise<IntentResponse> {
  const res = await fetch(`${BASE}/v1/intents`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(await parseError(res))
  return res.json()
}

export function verifyStreamUrl(intentId: string): string {
  return `${BASE}/v1/intents/${encodeURIComponent(intentId)}/verify`
}

export async function getWarrant(warrantId: string): Promise<{
  warrant: WarrantDocument
  warrant_hash: string
}> {
  const res = await fetch(`${BASE}/v1/warrants/${encodeURIComponent(warrantId)}`)
  if (!res.ok) throw new Error(await parseError(res))
  return res.json()
}

export function warrantDocumentUrl(warrantId: string): string {
  return `${BASE}/v1/warrants/${encodeURIComponent(warrantId)}/document`
}

export async function openSession(warrantId: string): Promise<SessionResponse> {
  const res = await fetch(`${BASE}/v1/warrants/${encodeURIComponent(warrantId)}/session`, {
    method: 'POST',
  })
  if (!res.ok) throw new Error(await parseError(res))
  return res.json()
}

export async function pollSessionResult(sessionId: string): Promise<SessionResult> {
  const res = await fetch(`${BASE}/v1/sessions/${encodeURIComponent(sessionId)}/result`)
  if (!res.ok) throw new Error(await parseError(res))
  return res.json()
}

/** Expected when backend ships reconcile. Returns backend_pending on 404. */
export async function reconcileWarrant(
  warrantId: string,
  outcome: OutcomeBody,
): Promise<ReconcileResponse> {
  const res = await fetch(`${BASE}/v1/warrants/${encodeURIComponent(warrantId)}/reconcile`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ outcome }),
  })
  if (res.status === 404 || res.status === 405) {
    return {
      backend_pending: true,
      reconciliation: {
        warrant_id: warrantId,
        status: 'PENDING',
        breaches: [],
        reconciled_at: new Date().toISOString(),
      },
    }
  }
  if (!res.ok) throw new Error(await parseError(res))
  return res.json()
}

export { parseError }
