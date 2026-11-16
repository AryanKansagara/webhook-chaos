// Builds a self-contained bash script that replays the chaos deliveries from the user's own machine,
// for endpoints this site cannot reach (localhost, VPN, staging behind a firewall).
// The signing secret never leaves that machine: the script reads it from the environment and signs with openssl.
import { buildScenario, serialize, type StripeEvent } from '../api/_lib/stripe.ts'

type Mode = 'valid' | 'rotated' | 'bad' | 'stale' | 'tampered' | 'missing'
interface Step { label: string; event: StripeEvent; mode: Mode }

function base64(text: string): string {
  let bin = ''
  for (const b of new TextEncoder().encode(text)) bin += String.fromCharCode(b)
  return btoa(bin)
}

export function buildScript(now: number): string {
  const sc = buildScenario(now)
  const [created, updated, deleted] = sc.reorder
  const steps: Step[] = [
    ...sc.lifecycle.map((event): Step => ({ label: event.type, event, mode: 'valid' })),
    { label: 'redelivery of invoice.paid (same event id)', event: sc.lifecycle[1], mode: 'valid' },
    { label: `${created.type} (second subscription)`, event: created, mode: 'valid' },
    { label: `${deleted.type} (arrives early)`, event: deleted, mode: 'valid' },
    { label: `${updated.type} (arrives late)`, event: updated, mode: 'valid' },
    { label: 'two v1 signatures, yours second (secret being rolled)', event: sc.probe(), mode: 'rotated' },
    { label: 'customer.updated (unhandled event type)', event: sc.unhandled(), mode: 'valid' },
    { label: 'signed with the wrong secret', event: sc.probe(), mode: 'bad' },
    { label: 'signed 10 minutes ago (replay)', event: sc.probe(), mode: 'stale' },
    { label: 'amount_paid edited after signing', event: sc.probe(), mode: 'tampered' },
    { label: 'no Stripe-Signature header', event: sc.probe(), mode: 'missing' },
  ]
  const want = (m: Mode) => (m === 'valid' || m === 'rotated' ? 2 : 4)
  const calls = steps.map((s) => `send ${want(s.mode)} ${s.mode} '${s.label}' \\\n  ${base64(serialize(s.event))}`).join('\n')

  return `#!/usr/bin/env bash
# Webhook Chaos, local run. Sends ${steps.length} test-mode Stripe webhook deliveries to an endpoint on your machine.
#
#   STRIPE_WEBHOOK_SECRET=whsec_... bash webhook-chaos.sh http://localhost:3000/webhooks/stripe
#
# Needs bash, curl and openssl. The secret is only used here, to sign each request with openssl.
# Every event has livemode=false and ids that do not exist in any Stripe account.
set -u
url="\${1:?usage: STRIPE_WEBHOOK_SECRET=whsec_... bash webhook-chaos.sh <endpoint url>}"
secret="\${STRIPE_WEBHOOK_SECRET:?set STRIPE_WEBHOOK_SECRET to the signing secret your endpoint verifies with}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
passed=0
failed=0
slow=0

# hex(HMAC-SHA256(secret, "<timestamp>.<body>")), the v1 scheme
sign() {
  { printf '%s.' "$2"; cat "$1"; } | openssl dgst -sha256 -hmac "$3" | sed 's/^.*= *//'
}

# send <expected status class> <mode> <label> <base64 body>
send() {
  local expect="$1" mode="$2" label="$3" body="$tmp/body" t sig out code secs verdict
  local -a header=()
  printf '%s' "$4" | openssl base64 -d -A > "$body"
  t="$(date +%s)"
  case "$mode" in
    valid)    header=(-H "Stripe-Signature: t=$t,v1=$(sign "$body" "$t" "$secret")") ;;
    rotated)  header=(-H "Stripe-Signature: t=$t,v1=$(sign "$body" "$t" "whsec_previous_secret_being_retired"),v1=$(sign "$body" "$t" "$secret")") ;;
    bad)      header=(-H "Stripe-Signature: t=$t,v1=$(sign "$body" "$t" "whsec_not_your_secret_0000000000")") ;;
    stale)    t=$((t - 600)); header=(-H "Stripe-Signature: t=$t,v1=$(sign "$body" "$t" "$secret")") ;;
    tampered) sig="$(sign "$body" "$t" "$secret")"
              sed 's/"amount_paid": [0-9]*/"amount_paid": 1/' "$body" > "$body.edited" && mv "$body.edited" "$body"
              header=(-H "Stripe-Signature: t=$t,v1=$sig") ;;
    missing)  ;;
  esac
  out="$(curl -sS -o /dev/null -w '%{http_code} %{time_total}' --max-time 10 -X POST "$url" \\
    -H 'Content-Type: application/json; charset=utf-8' \\
    -H 'User-Agent: Stripe/1.0 (+https://stripe.com/docs/webhooks) WebhookChaos/1.0' \\
    \${header[@]+"\${header[@]}"} --data-binary "@$body" 2>/dev/null)" || out="000 0"
  code="\${out%% *}"
  secs="\${out##* }"
  if [ "\${code:0:1}" = "$expect" ]; then verdict=PASS; passed=$((passed + 1)); else verdict=FAIL; failed=$((failed + 1)); fi
  case "$secs" in [3-9].*|[1-9][0-9].*) slow=$((slow + 1)) ;; esac
  printf '%s  got %s  want %sxx  %ss  %s\\n' "$verdict" "$code" "$expect" "$secs" "$label"
}

${calls}

echo
echo "$passed passed, $failed failed."
[ "$slow" -gt 0 ] && echo "$slow responses took 3s or longer: acknowledge first, do slow work in a queue."
echo "HTTP status is only half of it. Now look at what your handler stored:"
echo "  - invoice ${sc.lifecycle[1].data.object.id} was delivered twice and must be recorded once"
echo "  - subscription ${sc.subB} must be canceled (its .updated arrived after .deleted)"
echo "  - subscription ${sc.subA} must be canceled"
[ "$failed" -eq 0 ]
`
}
