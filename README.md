# Webhook Chaos

Stripe webhook chaos tester and signature debugger. Live at https://webhook-chaos.vercel.app

## What it does

- **Chaos tests.** Sends up to 15 signed test-mode deliveries (in order, duplicated, reordered, signed during a secret
  roll, an unhandled type, forged, replayed, tampered, unsigned) to a built-in demo handler or your own HTTPS
  endpoint, and scores the responses. For the demo handlers it also compares what the handler stored with what it
  should have stored.
- **Local script.** For localhost or firewalled endpoints, downloads a bash script that sends the same deliveries
  from your machine with `curl` and signs them with `openssl`. The secret is read from `STRIPE_WEBHOOK_SECRET` and
  never leaves your shell.
- **Signature debugger.** Paste a body, a `Stripe-Signature` header and one or more secrets. It runs in the browser
  and says whether the body, the header, the secret or the clock is the problem, using the header's `payload=` and
  `secret=` debugging entries when they are present.

`/docs` in the app describes every check, the scoring, and the limits.

## Reference data

| Used for | Source | Retrieved |
| --- | --- | --- |
| Header entries, tolerance, retries, ordering, secret rolling | https://docs.stripe.com/webhooks | 2026-11-16 |
| Event and object fields, API version `2026-09-30.endive` | https://github.com/stripe/openapi (`openapi/spec3.json`, MIT) | 2026-11-16 |
| Header parsing and mismatch diagnostics | https://github.com/stripe/stripe-node (`src/Webhooks.ts`, MIT) | 2026-11-16 |
| HMAC-SHA256 test vectors | RFC 4231 | |

`api/_lib/fixtures/stripe-openapi-excerpt.json` is an excerpt of the OpenAPI spec (property names, required lists and
enums). `src/fixtures/reserialized.json` is one synthetic signed event plus the bytes that Python `json.dumps`, Go
`encoding/json` and `jq` produce after parsing it. All events are synthetic.

## Develop

```bash
npm install
npm run dev     # serves the app and POST /api/run
npm test        # the script tests need bash, curl and openssl and are skipped without them
npm run build
npm run test:e2e  # builds, then runs the Playwright (Chromium) suite against `vite preview`
```

First time only: `npx playwright install chromium`. The E2E server port defaults to 4184; set `E2E_PORT` to use another.

## Tests

- `npm test` runs the unit tests: the engine, signature scheme and debugger (`src/`, `api/`), plus `tests/`, which
  exercises the outbound-request protections (`api/_lib/net.ts`) against a throwaway HTTPS server on 127.0.0.1:
  redirects are not followed, the response body is capped, and a request that never answers times out.
- `npm run test:e2e` drives the production build in Chromium (`e2e/`). `vite preview` has no `/api/run`, so every test
  gets a stand-in: demo targets run through the real handler (`api/run.ts`) inside the test process, and "Your
  endpoint" runs are answered by an in-process endpoint through the real engine. Inputs the real handler refuses
  (private addresses, bad secrets) are forwarded to it. Requests to anything but the preview server are blocked, and a
  test fails on any uncaught page error or request to an unexpected host. Nothing is ever sent to a real URL.
- The debugger tests sign their vectors with `node:crypto` following the scheme in the Stripe docs; the docs do not
  print a complete body, secret and signature, so the header the docs do print is used only for what a header alone shows.
- Tests marked `test.fail()` assert what a user should get for a bug that is filed as an issue (#2, #3, #4). They pass while the bug
  exists and start failing when it is fixed, which is the cue to remove the marker.
- CI (`.github/workflows/ci.yml`, job `test`) runs install, build, unit tests and E2E on pull requests and pushes to `main`.
- Only `main` is deployed to Vercel (`vercel.json` turns off branch previews); pull requests are checked by CI alone.

## Known gaps

- Snapshot events for subscriptions, invoices and customers only. No thin events, Connect events or other objects.
- A handler that fetches each object from the Stripe API fails the baseline check, because the ids are synthetic.
- For your own endpoint, duplicate and ordering handling cannot be observed; a 2xx passes and you verify state by hand.
- Retries over time are not simulated.
- The debugger cannot trace a re-serialized body back to the signed bytes when it contains a float such as `25.0`.
- No PHP fixture: `json_encode` output is recognised by rule, not tested against a real PHP run.
- The run rate limit is per server instance. Nothing is stored between runs.


