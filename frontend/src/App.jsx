import { useState } from 'react'
import ConstellationBackground from './ConstellationBackground'

const severityStyle = {
  high: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
  medium: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
  low: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
}
const typeLabels = {
  urgency: 'Manufactured Urgency',
  verification_pressure: 'Verification Pressure',
  reward: 'Reward / Prize Bait',
  payment_request: 'Payment Request',
  authority_impersonation: 'Authority Impersonation',
}

const SAMPLES = [
  { label: '⚡ Urgent Bank Verification', text: 'URGENT! Your Wire Transfer #8942-US has been placed on hold. Verify your account immediately or funds will forfeit.' },
  { label: '🎁 Executive Gift Card', text: 'Hey, are you at your desk? I need you to send a gift card for the client meeting immediately.' },
  { label: '🏆 Prize / Lottery', text: 'URGENT! You have won a free prize. Verify your account immediately to claim your reward.' },
]

function buildSegments(text, annotations) {
  const sorted = [...annotations].sort((a, b) => a.start - b.start)
  const segments = []
  let cursor = 0
  for (const ann of sorted) {
    if (ann.start < cursor) continue
    if (ann.start > cursor) segments.push({ kind: 'text', content: text.slice(cursor, ann.start) })
    segments.push({ kind: 'annotation', content: text.slice(ann.start, ann.end), ...ann })
    cursor = ann.end
  }
  if (cursor < text.length) segments.push({ kind: 'text', content: text.slice(cursor) })
  return segments
}

function HighlightedMessage({ text, annotations }) {
  const segments = buildSegments(text, annotations)
  return (
    <p className="font-body text-base leading-relaxed text-surface whitespace-pre-wrap">
      {segments.map((seg, i) => {
        if (seg.kind === 'text') return <span key={i}>{seg.content}</span>
        const cls = severityStyle[seg.severity] || severityStyle.medium
        return (
          <span key={i} className="relative group inline">
            <span className={`border px-1.5 py-0.5 rounded font-mono text-xs cursor-help ${cls}`}>
              {seg.content}
            </span>
            <span className="pointer-events-none absolute left-1/2 -translate-x-1/2 bottom-full mb-2 w-56 rounded-lg bg-panel-high border border-white/10 text-surface text-sm font-body px-3 py-2 opacity-0 group-hover:opacity-100 transition-opacity z-20 shadow-xl">
              {seg.explanation}
            </span>
          </span>
        )
      })}
    </p>
  )
}

function MarkersGrid({ annotations }) {
  const unique = []
  const seen = new Set()
  for (const a of annotations) {
    if (!seen.has(a.type)) { seen.add(a.type); unique.push(a) }
  }
  if (unique.length === 0) return null
  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2">
      {unique.map((a) => (
        <div key={a.type} className={`p-2.5 rounded-lg bg-panel-high border ${severityStyle[a.severity]?.split(' ')[2] || 'border-white/10'} flex flex-col gap-1`}>
          <span className="font-mono text-[11px] uppercase tracking-wider font-bold text-mist">[{a.severity}]</span>
          <span className="text-xs text-white font-semibold">{typeLabels[a.type] || a.type}</span>
        </div>
      ))}
    </div>
  )
}

function ArchetypeCard({ archetype }) {
  if (!archetype) return null
  return (
    <div className="bg-void border border-white/10 rounded-xl p-4 mt-3">
      <span className="font-mono text-xs text-mist font-semibold tracking-wider">LIKELY PATTERN</span>
      <h4 className="font-display text-xl text-white font-bold mt-1">{archetype.name}</h4>
      <p className="font-body text-sm text-mist mt-1">{archetype.why}</p>
    </div>
  )
}

function FeatureCard({ tag, title, description, comingSoon, accent }) {
  return (
    <div className={`bg-panel p-6 rounded-2xl border border-white/10 hover:border-${accent}-500/40 transition-all flex flex-col justify-between`}>
      <div>
        <div className={`inline-block px-2 py-0.5 rounded bg-${accent}-500/20 border border-${accent}-500/30 font-mono text-xs text-${accent}-300 font-semibold mb-3`}>
          {tag}
        </div>
        <h3 className="font-display text-xl text-white mb-2">{title}</h3>
        <p className="font-body text-mist text-sm mb-2">{description}</p>
      </div>
      {comingSoon && (
        <span className="inline-block mt-2 font-mono text-xs text-amber-300 border border-amber-500/30 bg-amber-500/10 rounded-full px-3 py-1 self-start">
          Coming soon
        </span>
      )}
    </div>
  )
}

function App() {
  const [text, setText] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  async function handleAnalyze() {
    setLoading(true); setError(null); setResult(null)
    try {
      const response = await fetch('http://localhost:8000/api/analyze/message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text })
      })
      if (!response.ok) throw new Error(`Server responded with ${response.status}`)
      setResult(await response.json())
    } catch (err) {
      setError('Could not reach the analyzer. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-void text-surface font-body">
      {/* Header */}
      <header className="fixed top-0 left-0 right-0 z-50 bg-void/85 backdrop-blur-xl border-b border-white/10">
        <div className="h-16 max-w-6xl mx-auto px-6 flex items-center justify-between">
          <span className="font-display text-lg font-bold text-white">Scamly</span>
          <a href="#features" className="font-body text-sm px-4 py-2 rounded-lg bg-cyan-400 text-void font-semibold hover:brightness-110 transition-all">
            Try it free
          </a>
        </div>
      </header>

      {/* Hero */}
      <section className="relative overflow-hidden pt-32 pb-16 px-6 text-center min-h-[600px]">
        <div className="absolute -top-24 right-[-5%] w-[600px] h-[600px] rounded-full blur-[130px] opacity-40 pointer-events-none"
          style={{ background: 'radial-gradient(circle at 60% 40%, #ff7b25, #f59e0b 24%, #a855f7 48%, #00f0ff 72%, transparent 88%)' }} />
        <ConstellationBackground />

        <div className="relative max-w-3xl mx-auto">
          <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-panel/80 backdrop-blur border border-cyan-500/25 mb-6">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span className="font-mono text-xs text-cyan-300 font-bold uppercase tracking-widest">Pattern-based detection</span>
          </span>

          <h1 className="font-display text-4xl sm:text-5xl font-bold mb-4 leading-tight">
            <span className="text-white">Deception has a spectrum.</span><br />
            <span className="bg-gradient-to-r from-cyan-pale via-cyan to-violet bg-clip-text text-transparent">
              We illuminate the invisible.
            </span>
          </h1>
          <p className="text-mist max-w-xl mx-auto mb-8">
            Unmask manipulative subtext and coercive urgency in incoming messages before you ever tap reply.
          </p>

          <div className="bg-panel/90 backdrop-blur-2xl rounded-2xl p-5 border border-white/10 shadow-2xl text-left">
            <textarea
              className="w-full h-28 p-4 bg-void border border-cyan-500/30 rounded-xl font-body text-surface placeholder:text-mist resize-none focus:outline-none focus:border-cyan-500/60 transition-colors"
              placeholder="Paste a suspicious message here..."
              value={text}
              onChange={(e) => setText(e.target.value)}
            />
            <div className="flex flex-wrap gap-2 mt-3">
              {SAMPLES.map((s) => (
                <button
                  key={s.label}
                  onClick={() => setText(s.text)}
                  className="font-mono text-xs px-3 py-1 rounded-md bg-panel-high border border-cyan-500/30 text-mist hover:text-cyan-300 hover:border-cyan-500/50 transition-all"
                >
                  {s.label}
                </button>
              ))}
            </div>
            <button
              onClick={handleAnalyze}
              disabled={loading || !text.trim()}
              className="mt-4 bg-cyan-400 text-void font-display font-semibold px-6 py-2 rounded-lg hover:brightness-110 disabled:bg-white/10 disabled:text-mist disabled:cursor-not-allowed transition-all"
            >
              {loading ? 'Analyzing…' : 'Analyze'}
            </button>

            {error && <p className="mt-4 text-rose-400 text-sm">{error}</p>}

            {result && (
              <div className="mt-6 border-t border-white/10 pt-5">
                <p className="font-mono text-xs text-mist tracking-wider mb-3">// ORIGINAL MESSAGE</p>
                <div className="bg-void border border-white/10 rounded-xl p-4">
                  <HighlightedMessage text={result.text} annotations={result.annotations} />
                  <MarkersGrid annotations={result.annotations} />
                </div>
                <ArchetypeCard archetype={result.archetype} />
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="max-w-5xl mx-auto px-6 py-20 border-t border-white/5">
        <p className="font-mono text-xs text-cyan-300 font-bold uppercase tracking-widest mb-2">// how scamly reads a message</p>
        <h2 className="font-display text-3xl text-white mb-10">Engineered to see what a quick glance misses.</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <FeatureCard
            accent="cyan"
            tag="Live now"
            title="Inline Highlighting"
            description="Suspicious phrases are highlighted right inside your message, with a plain-language reason for each one."
          />
          <FeatureCard
            accent="purple"
            tag="Live now"
            title="Scam Archetype ID"
            description="Instead of a bare risk score, get a likely category — fake job, prize scam, phishing — with the reasoning behind it."
          />
          <FeatureCard
            accent="amber"
            tag="Roadmap"
            title="What Happens Next"
            description="A clearly labeled simulation of how this kind of scam typically escalates, so you know what to expect."
            comingSoon
          />
        </div>
      </section>

      {/* CTA */}
      <section className="max-w-5xl mx-auto px-6 pb-20">
        <div className="bg-panel/90 backdrop-blur-2xl border border-white/10 rounded-2xl p-8 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div>
            <h2 className="font-display text-2xl text-white mb-2">Stop guessing. Start seeing the pattern.</h2>
            <p className="text-mist text-sm max-w-md">Paste any suspicious message above and see exactly what gives it away.</p>
          </div>
          <a href="#top" className="shrink-0 bg-cyan-400 text-void font-display font-semibold px-6 py-3 rounded-lg hover:brightness-110 transition-all text-center">
            Try Scamly
          </a>
        </div>
      </section>

      <footer className="border-t border-white/10 py-8 px-6 text-center">
        <span className="font-mono text-xs text-mist">Scamly — built as a learning project</span>
      </footer>
    </div>
  )
}

export default App