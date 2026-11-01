import { defineConfig, type Connect, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'

/** Serves POST /api/run during `vite` so ChaosTab works without `vercel dev`. */
function apiRunPlugin(): Plugin {
  return {
    name: 'webhook-chaos-api-run',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url?.split('?')[0] !== '/api/run' || req.method !== 'POST') {
          next()
          return
        }
        void handleApiRun(req, res, () => server.ssrLoadModule('/api/run.ts')).catch((err) => {
          res.statusCode = 500
          res.setHeader('content-type', 'application/json')
          res.end(JSON.stringify({ error: (err as Error).message || 'API error' }))
        })
      })
    },
  }
}

async function handleApiRun(
  req: Connect.IncomingMessage,
  res: Connect.ServerResponse,
  load: () => Promise<Record<string, unknown>>,
) {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
  const raw = Buffer.concat(chunks)
  const headers = new Headers()
  for (const [key, value] of Object.entries(req.headers)) {
    if (value == null) continue
    if (Array.isArray(value)) for (const v of value) headers.append(key, v)
    else headers.set(key, value)
  }
  if (!headers.has('x-real-ip')) headers.set('x-real-ip', '127.0.0.1')

  const mod = await load()
  const POST = mod.POST as (request: Request) => Promise<Response>
  const response = await POST(
    new Request('http://localhost/api/run', { method: 'POST', headers, body: raw }),
  )
  res.statusCode = response.status
  response.headers.forEach((value, key) => res.setHeader(key, value))
  res.end(Buffer.from(await response.arrayBuffer()))
}

export default defineConfig({
  plugins: [react(), apiRunPlugin()],
})
