import { motion } from 'framer-motion'
import { prefersReducedMotion } from '../lib/motion'

type StampKind = 'CLEARED' | 'HALT' | 'SETTLED' | 'BREACH'

const STYLES: Record<StampKind, { color: string; rotate: number }> = {
  CLEARED: { color: 'var(--color-verify)', rotate: -6 },
  SETTLED: { color: 'var(--color-verify)', rotate: -6 },
  HALT: { color: 'var(--color-halt)', rotate: -12 },
  BREACH: { color: 'var(--color-halt)', rotate: -12 },
}

type Props = {
  kind: StampKind
  subtitle?: string | null
  hash?: string | null
}

export function Stamp({ kind, subtitle, hash }: Props) {
  const style = STYLES[kind]
  const reduced = prefersReducedMotion()

  return (
    <motion.div
      className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center"
      initial={reduced ? false : { opacity: 0, scale: 1.35 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={reduced ? { duration: 0 } : { type: 'spring', stiffness: 260, damping: 18 }}
    >
      <div
        className="border-[3px] px-5 py-3 text-center"
        style={{
          color: style.color,
          borderColor: style.color,
          transform: `rotate(${style.rotate}deg)`,
          background: 'rgba(242, 244, 243, 0.88)',
        }}
      >
        <div
          className="font-display text-4xl font-extrabold tracking-[0.14em] sm:text-5xl"
          style={{ fontFamily: 'var(--font-display)' }}
        >
          {kind}
        </div>
        {subtitle ? (
          <div
            className="mt-2 max-w-sm font-mono text-[11px] leading-snug tracking-wide"
            style={{ fontFamily: 'var(--font-mono)', color: style.color }}
          >
            {subtitle}
          </div>
        ) : null}
        {hash ? (
          <div
            className="mt-2 max-w-md break-all font-mono text-[10px] opacity-80"
            style={{ fontFamily: 'var(--font-mono)' }}
          >
            {hash}
          </div>
        ) : null}
      </div>
    </motion.div>
  )
}
