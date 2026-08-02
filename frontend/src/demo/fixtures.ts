/** Demo storefronts — ours, labeled on screen. Never dress as real brands. */

export type DemoPreset = 'spoof' | 'clear' | 'breach'

export type DemoIntent = {
  preset: DemoPreset
  label: string
  notice: string
  reference: string
  sku: string
  description: string
  quantity: number
  amount: string
  currency: string
  /** For reconciliation screen when POST /reconcile is missing */
  observed?: {
    quantity: number
    amount: string
    description: string
    sku: string
    merchant_domain: string
  }
}

export const DEMO_PRESETS: Record<DemoPreset, DemoIntent> = {
  spoof: {
    preset: 'spoof',
    label: 'Harbor Lane (WARRANT demo · spoof)',
    notice: 'Demo storefront on :8011 — injection bait. Expect HALT.',
    reference: 'http://127.0.0.1:8011/',
    sku: 'HL-DEMO-01',
    description: 'Harbor Lane demo titanium clip',
    quantity: 1,
    amount: '84.00',
    currency: 'USD',
  },
  clear: {
    preset: 'clear',
    label: 'Northstar Supply (WARRANT demo · clear)',
    notice: 'Demo storefront on :8012 — clean catalogue. Expect CLEARED, then settle 1×.',
    reference: 'http://127.0.0.1:8012/',
    sku: 'NS-CLIP-84',
    description: 'Northstar Field Clips',
    quantity: 1,
    amount: '84.00',
    currency: 'USD',
    observed: {
      quantity: 1,
      amount: '84.00',
      description: 'Northstar Field Clips',
      sku: 'NS-CLIP-84',
      merchant_domain: '127.0.0.1',
    },
  },
  breach: {
    preset: 'breach',
    label: 'Northstar Supply (WARRANT demo · breach)',
    notice: 'Demo storefront on :8012 — authorizes 1, merchant bills 12. Expect BREACH stamp.',
    reference: 'http://127.0.0.1:8012/',
    sku: 'NS-CLIP-84',
    description: 'Northstar Field Clips',
    quantity: 1,
    amount: '84.00',
    currency: 'USD',
    observed: {
      quantity: 12,
      amount: '1008.00',
      description: 'Northstar Field Clips',
      sku: 'NS-CLIP-84',
      merchant_domain: '127.0.0.1',
    },
  },
}

export function demoFromQuery(): DemoPreset | null {
  const q = new URLSearchParams(window.location.search).get('demo')
  if (q === 'spoof' || q === 'clear' || q === 'breach') return q
  return null
}
