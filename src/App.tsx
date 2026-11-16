import { RouteApp } from './router.tsx'
import { Landing, MockFrame, MockList } from './Landing.tsx'
import Tool from './Tool.tsx'
import Docs from './Docs.tsx'

function ProductLanding() {
  return (
    <Landing
      name="Webhook Chaos"
      icon="bolt"
      tagline="Stripe webhook reliability tester"
      headline="Prove your Stripe webhook *before production does.*"
      support="Run chaos deliveries (duplicates, out-of-order, bad signatures, stale timestamps) against demo handlers or your HTTPS endpoint. Debug failing signatures in-browser."
      audience="For teams shipping Stripe billing webhooks."
      features={[
        {
          icon: 'speed',
          title: 'Chaos score',
          body: 'Ten checks, from duplicates and reordering to forged, replayed and rolled-secret signatures, scored 0 to 100.',
        },
        {
          icon: 'link',
          title: 'Demo vs your URL',
          body: 'Try the built-in demo handlers, point it at your HTTPS endpoint, or download a script for localhost.',
        },
        {
          icon: 'bug_report',
          title: 'Signature debugger',
          body: 'Paste body, Stripe-Signature, and secrets to diagnose verify failures in-browser.',
        },
      ]}
      slides={[
        {
          title: 'Chaos score',
          caption: 'A handler can answer 200 to everything and still score 55/100.',
          preview: (
            <MockFrame title="Chaos score">
              <div className="mock-score tone-bad">55/100</div>
              <MockList
                items={[
                  { badge: 'Fail', text: 'Duplicate delivery recorded twice', tone: 'bad' },
                  { badge: 'Fail', text: 'Replayed timestamp accepted', tone: 'bad' },
                  { badge: 'Warn', text: 'One response took over 3s', tone: 'warn' },
                ]}
              />
            </MockFrame>
          ),
        },
        {
          title: 'Check results',
          caption: 'Each chaos check shows pass/fail with the delivery pattern that broke it.',
          preview: (
            <MockFrame title="Check results">
              <MockList
                items={[
                  { badge: 'Pass', text: 'Valid delivery, in order', tone: 'good' },
                  { badge: 'Fail', text: 'Out-of-order delivery: canceled subscription active again', tone: 'bad' },
                  { badge: 'Fail', text: 'Secret being rolled: second v1 ignored', tone: 'bad' },
                  { badge: 'Pass', text: 'Forged signature rejected with 400', tone: 'good' },
                ]}
              />
            </MockFrame>
          ),
        },
        {
          title: 'Signature debugger',
          caption: 'Findings tell you whether the body, header, or secret is wrong.',
          preview: (
            <MockFrame title="Signature debugger">
              <MockList
                items={[
                  { badge: 'Bad', text: 'Signature matches the pretty-printed JSON, not this body', tone: 'bad' },
                  { badge: 'Warn', text: 'Secret has surrounding whitespace', tone: 'warn' },
                  { badge: 'Good', text: 'Timestamp within tolerance (4s ago)', tone: 'good' },
                ]}
              />
            </MockFrame>
          ),
        },
      ]}
    />
  )
}

export default function App() {
  return <RouteApp landing={<ProductLanding />} tool={<Tool />} docs={<Docs />} />
}
