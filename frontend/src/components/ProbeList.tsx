import { motion } from 'framer-motion'
import type { ProbeAnnounced, SignalPayload } from '../api/client'
import { prefersReducedMotion } from '../lib/motion'

type Row = {
  name: string
  tier: string
  signal?: SignalPayload
}

type Props = {
  announced: ProbeAnnounced[]
  signals: SignalPayload[]
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'string') return value
  return JSON.stringify(value)
}

export function ProbeList({ announced, signals }: Props) {
  const byName = new Map(signals.map((s) => [s.name, s]))
  const names = new Set([...announced.map((p) => p.name), ...signals.map((s) => s.name)])
  const rows: Row[] = [...names].map((name) => {
    const a = announced.find((p) => p.name === name)
    const signal = byName.get(name)
    return {
      name,
      tier: signal?.tier ?? a?.tier ?? '?',
      signal,
    }
  })

  const reduced = prefersReducedMotion()

  return (
    <ul className="divide-y divide-steel/20 border-y border-steel/25">
      {rows.map((row, i) => {
        const pending = !row.signal
        const body = (
          <li
            key={row.name}
            className="grid grid-cols-[4.5rem_1fr_auto] items-baseline gap-3 py-3 font-mono text-[12px] sm:grid-cols-[5rem_7rem_1fr_auto]"
            style={{ fontFamily: 'var(--font-mono)' }}
          >
            <span className="text-steel">TIER {row.tier}</span>
            <span className="text-ink">{row.name}</span>
            <span className="col-span-1 truncate text-steel sm:col-span-1">
              {pending ? 'resolving…' : formatValue(row.signal?.value)}
            </span>
            <span className="text-right text-ink">{pending ? '—' : row.signal?.status}</span>
          </li>
        )

        if (reduced || !row.signal) return body

        return (
          <motion.div
            key={row.name}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: Math.min(i * 0.05, 0.25), duration: 0.22 }}
          >
            {body}
          </motion.div>
        )
      })}
    </ul>
  )
}
