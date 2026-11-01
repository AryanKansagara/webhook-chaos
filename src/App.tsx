import { RouteApp } from './router.tsx'
import { Landing, MockFrame, MockList } from './Landing.tsx'
import Tool from './Tool.tsx'

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
          body: 'Get a 0–100 reliability score from how your handler deals with messy Stripe deliveries.',
        },
        {
          icon: 'link',
          title: 'Demo vs your URL',
          body: 'Try built-in naive/idempotent demos, or point chaos at your own HTTPS endpoint.',
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
          caption: 'A weak handler fails replay and signature checks — scored 42/100.',
          preview: (
            <MockFrame title="Chaos score">
              <div className="mock-score tone-bad">42/100</div>
              <MockList
                items={[
                  { badge: 'Bad', text: 'Accepted forged signature', tone: 'bad' },
                  { badge: 'Bad', text: 'Double-processed duplicate event', tone: 'bad' },
                  { badge: 'Warn', text: 'Ignored stale timestamp', tone: 'warn' },
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
                  { badge: 'Fail', text: 'Duplicate delivery — processed twice', tone: 'bad' },
                  { badge: 'Fail', text: 'Out-of-order events — wrong state', tone: 'bad' },
                  { badge: 'Pass', text: 'Valid signed event accepted', tone: 'good' },
                  { badge: 'Fail', text: 'Bad signature still 200 OK', tone: 'bad' },
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
                  { badge: 'Bad', text: 'v1 signature does not match any secret', tone: 'bad' },
                  { badge: 'Warn', text: 'Timestamp skew > 5 minutes', tone: 'warn' },
                  { badge: 'Info', text: 'Body whitespace differs from signed bytes', tone: 'info' },
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
  return <RouteApp landing={<ProductLanding />} tool={<Tool />} />
}
