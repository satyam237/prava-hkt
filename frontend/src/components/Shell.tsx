type Props = {
  step: number
  title: string
  children: React.ReactNode
  aside?: React.ReactNode
}

const STEPS = ['Intent', 'Verify', 'Approve', 'Reconcile', 'Record'] as const

export function Shell({ step, title, children, aside }: Props) {
  return (
    <div className="mx-auto flex min-h-screen max-w-3xl flex-col px-5 py-7 sm:px-8">
      <header className="mb-8 flex items-end justify-between gap-4 border-b border-steel/25 pb-4">
        <div>
          <div
            className="font-display text-3xl font-extrabold tracking-tight text-ink sm:text-4xl"
            style={{ fontFamily: 'var(--font-display)' }}
          >
            Warrant
          </div>
          <p className="mt-1 text-sm text-steel">
            Verify before credential. Reconcile after charge.
          </p>
        </div>
        <ol className="hidden items-center gap-1 font-mono text-[10px] uppercase tracking-wider text-steel sm:flex">
          {STEPS.map((label, i) => (
            <li key={label} className="flex items-center gap-1">
              {i > 0 ? <span className="text-steel/40">/</span> : null}
              <span className={i === step ? 'text-ink' : i < step ? 'text-steel' : 'text-steel/40'}>
                {label}
              </span>
            </li>
          ))}
        </ol>
      </header>

      <div className="mb-5 flex items-baseline justify-between gap-3">
        <h1
          className="font-display text-xl font-bold tracking-tight text-ink sm:text-2xl"
          style={{ fontFamily: 'var(--font-display)' }}
        >
          {title}
        </h1>
        <span className="font-mono text-[11px] text-steel" style={{ fontFamily: 'var(--font-mono)' }}>
          {String(step + 1).padStart(2, '0')} / 05
        </span>
      </div>

      <main className="flex-1">{children}</main>
      {aside ? <div className="mt-8">{aside}</div> : null}
    </div>
  )
}
