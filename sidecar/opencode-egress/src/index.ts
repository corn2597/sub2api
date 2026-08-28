import UpstreamWebSocket, { type RawData } from "ws"
import { HttpsProxyAgent } from "https-proxy-agent"
import { createHash } from "node:crypto"
import {
  extractOpenCodePayloadIdentity,
  normalizeManagementHeaders,
  normalizeModelHeaders,
  normalizeModelWebSocketHeaders,
  openAIProviderVersion,
  providerUtilsVersion,
  isOpenCodeUserAgent,
} from "./fingerprint"
import { fetchWithProxy, proxyForBun } from "./proxy"
import { buildOAuthForm } from "./oauth"

const OPENCODE_VERSION = process.env.OPENCODE_VERSION ?? "1.18.20"
const bind = process.env.SUB2API_EGRESS_BIND ?? "127.0.0.1"
const port = parsePositiveInteger("SUB2API_EGRESS_PORT", 12783)
const sharedSecret = process.env.SUB2API_EGRESS_SECRET ?? ""
const wsMaxPayloadBytes = parsePositiveInteger(
  "SUB2API_EGRESS_WS_MAX_PAYLOAD_BYTES",
  256 * 1024 * 1024 + 64 * 1024,
)
const wsBackpressureBytes = parsePositiveInteger(
  "SUB2API_EGRESS_WS_BACKPRESSURE_BYTES",
  16 * 1024 * 1024,
)
const httpMaxBodyBytes = parsePositiveInteger(
  "SUB2API_EGRESS_HTTP_MAX_BODY_BYTES",
  256 * 1024 * 1024,
)
const authIssuer = "https://auth.openai.com"
const deviceUserAgent = `opencode/${OPENCODE_VERSION}`
const protocolVersion = "3"
const auditEnabled = /^(1|true|yes)$/i.test(process.env.SUB2API_EGRESS_AUDIT_LOG ?? "")
const auditPayloadLimit = 4 * 1024 * 1024
const metrics = { http: 0, websocket: 0, oauth: 0, fingerprintViolations: 0 }

if (!sharedSecret) {
  throw new Error("SUB2API_EGRESS_SECRET is required")
}

const hopByHopHeaders = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
  "trailer", "transfer-encoding", "upgrade", "host", "content-length",
  "sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions",
  "sec-websocket-protocol",
])

type HeaderMap = Record<string, string[] | string>
type SocketData = {
  targetURL: string
  targetHeaders: HeaderMap
  targetProxy?: string
  upstream?: UpstreamWebSocket
  ready: boolean
  sending: boolean
  paused: boolean
  handshakeReported: boolean
}

function parsePositiveInteger(name: string, fallback: number) {
  const raw = process.env[name]
  if (!raw) return fallback
  const value = Number(raw)
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`)
  return value
}

function json(data: unknown, status = 200, headers?: HeadersInit) {
  const responseHeaders = new Headers(headers)
  responseHeaders.set("content-type", "application/json; charset=utf-8")
  responseHeaders.set("x-sub2api-egress-protocol", protocolVersion)
  return new Response(JSON.stringify(data), { status, headers: responseHeaders })
}

function controlledError(error: unknown) {
  const name = error instanceof Error ? error.name : "Error"
  const timeout = name === "TimeoutError" || name === "AbortError" && /timeout/i.test(String(error))
  return json({ error: { type: timeout ? "upstream_timeout" : "upstream_transport_error" } }, timeout ? 504 : 502)
}

function authorized(request: Request) {
  return request.headers.get("x-sub2api-egress-secret") === sharedSecret
}

function isAllowedTarget(value: string, protocol: "https:" | "wss:") {
  try {
    const target = new URL(value)
    if (target.protocol !== protocol || target.username || target.password) return false
    const hostname = target.hostname.toLowerCase()
    return hostname === "auth.openai.com" || hostname === "api.openai.com" ||
      hostname === "chatgpt.com" || hostname.endsWith(".openai.com") ||
      hostname.endsWith(".chatgpt.com")
  } catch {
    return false
  }
}

function decodeTargetHeaders(request: Request): HeaderMap | null {
  const encoded = request.headers.get("x-sub2api-target-headers")
  if (!encoded) return {}
  try {
    const value = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"))
    if (!value || typeof value !== "object" || Array.isArray(value)) return null
    const result: HeaderMap = {}
    for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
      if (hopByHopHeaders.has(key.toLowerCase())) continue
      if (typeof raw === "string") result[key] = raw
      else if (Array.isArray(raw) && raw.every((entry) => typeof entry === "string")) {
        result[key] = raw as string[]
      } else return null
    }
    return result
  } catch {
    return null
  }
}

function proxyValue(value: unknown) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined
}

function targetResponse(upstream: Response) {
  const headers = new Headers(upstream.headers)
  for (const key of hopByHopHeaders) headers.delete(key)
  headers.delete("content-encoding")
  headers.delete("content-length")
  headers.set("x-sub2api-egress-protocol", protocolVersion)
  return new Response(upstream.body, { status: upstream.status, headers })
}

async function forwardOAuth(request: Request, flow: "exchange" | "refresh") {
  let payload: Record<string, unknown>
  try {
    payload = await request.json() as Record<string, unknown>
  } catch {
    return json({ error: { type: "invalid_json" } }, 400)
  }
  const upstream = await fetchWithProxy(`${authIssuer}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "user-agent": deviceUserAgent },
    body: buildOAuthForm(payload, flow),
    redirect: "manual",
    signal: request.signal,
  }, proxyValue(payload.proxy_url))
  metrics.oauth++
  return targetResponse(upstream)
}

async function deviceRequest(request: Request, action: "start" | "poll") {
  let payload: Record<string, unknown> = {}
  try {
    if (request.headers.get("content-length") !== "0") payload = await request.json() as Record<string, unknown>
  } catch {
    if (action === "poll") return json({ error: { type: "invalid_json" } }, 400)
  }
  const path = action === "start" ? "/api/accounts/deviceauth/usercode" : "/api/accounts/deviceauth/token"
  const body = action === "start"
    ? { client_id: "app_EMoamEEZ73f0CkXaXp7hrann" }
    : { device_auth_id: payload.device_auth_id, user_code: payload.user_code }
  const upstream = await fetchWithProxy(`${authIssuer}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": deviceUserAgent },
    body: JSON.stringify(body),
    redirect: "manual",
    signal: request.signal,
  }, proxyValue(payload.proxy_url))
  return targetResponse(upstream)
}

async function proxyHTTP(request: Request) {
  const targetURL = request.headers.get("x-sub2api-target-url") ?? ""
  const method = (request.headers.get("x-sub2api-target-method") || "GET").toUpperCase()
  const identity = request.headers.get("x-sub2api-target-identity")
  const targetHeaders = decodeTargetHeaders(request)
  if (!isAllowedTarget(targetURL, "https:")) return json({ error: { type: "target_not_allowed" } }, 403)
  if (!targetHeaders) return json({ error: { type: "invalid_target_headers" } }, 400)
  if (!/^[A-Z]+$/.test(method)) return json({ error: { type: "invalid_target_method" } }, 400)
  if (identity !== "model" && identity !== "management") {
    return json({ error: { type: "invalid_target_identity" } }, 400)
  }
  const headers = identity === "management"
    ? normalizeManagementHeaders(targetHeaders)
    : normalizeModelHeaders(targetHeaders)
  assertOpenCodeFingerprint(headers)
  metrics.http++
  auditOutbound("http", targetURL, headers, method)
  const targetProxy = proxyValue(request.headers.get("x-sub2api-target-proxy"))
  // Bun cannot reliably send a server-side ReadableStream through an HTTP
  // CONNECT proxy: ChatGPT closes the tunnel before returning a response.
  // Buffer proxied HTTP bodies with a hard cap so Alpha, Chat, and image
  // requests are emitted as a fixed-length request while direct egress keeps
  // the original streaming behavior.
  let requestBody: BodyInit | undefined = method === "GET" || method === "HEAD"
    ? undefined
    : request.body
  if (targetProxy && requestBody) {
    try {
      requestBody = await readRequestBody(request, httpMaxBodyBytes)
    } catch (error) {
      if (error instanceof RequestBodyTooLarge) {
        return json({ error: { type: "request_body_too_large", limit_bytes: httpMaxBodyBytes } }, 413)
      }
      throw error
    }
  }

  let upstream: Response
  try {
    upstream = await fetchWithProxy(targetURL, {
      method,
      headers,
      body: requestBody,
      redirect: "manual",
      signal: request.signal,
    }, targetProxy)
  } catch (error) {
    auditUpstreamFailure(targetURL, error)
    throw error
  }
  auditUpstreamResponse(targetURL, upstream)
  return targetResponse(upstream)
}

class RequestBodyTooLarge extends Error {}

async function readRequestBody(request: Request, limit: number) {
  if (!request.body) return Buffer.alloc(0)
  const reader = request.body.getReader()
  const chunks: Buffer[] = []
  let total = 0
  try {
    while (true) {
      const next = await reader.read()
      if (next.done) break
      const chunk = Buffer.from(next.value)
      total += chunk.byteLength
      if (total > limit) {
        await reader.cancel()
        throw new RequestBodyTooLarge()
      }
      chunks.push(chunk)
    }
  } finally {
    reader.releaseLock()
  }
  return Buffer.concat(chunks, total)
}

function parseSocketData(request: Request): SocketData | null {
  const targetURL = request.headers.get("x-sub2api-target-url") ?? ""
  const targetHeaders = decodeTargetHeaders(request)
  if (!isAllowedTarget(targetURL, "wss:") || !targetHeaders) return null
  return {
    targetURL,
    targetHeaders,
    targetProxy: proxyValue(request.headers.get("x-sub2api-target-proxy")),
    ready: false,
    sending: false,
    paused: false,
    handshakeReported: false,
  }
}

const server = Bun.serve<SocketData>({
  hostname: bind,
  port,
  async fetch(request, server) {
    if (!authorized(request)) return json({ error: { type: "unauthorized" } }, 401)
    const pathname = new URL(request.url).pathname
    try {
      if (pathname === "/health" && request.method === "GET") {
        return json({
          ok: true,
          service: "sub2api-opencode-egress",
          opencode_version: OPENCODE_VERSION,
          openai_provider_version: openAIProviderVersion,
          provider_utils_version: providerUtilsVersion,
          runtime: "bun",
          protocol: protocolVersion,
          ws_max_payload_bytes: wsMaxPayloadBytes,
          ws_idle_timeout_seconds: 0,
          ws_send_pings: false,
          outbound_http_total: metrics.http,
          outbound_websocket_total: metrics.websocket,
          outbound_oauth_total: metrics.oauth,
          fingerprint_violation_total: metrics.fingerprintViolations,
        })
      }
      if (pathname === "/oauth/exchange" && request.method === "POST") return await forwardOAuth(request, "exchange")
      if (pathname === "/oauth/refresh" && request.method === "POST") return await forwardOAuth(request, "refresh")
      if (pathname === "/device/start" && request.method === "POST") return await deviceRequest(request, "start")
      if (pathname === "/device/poll" && request.method === "POST") return await deviceRequest(request, "poll")
      if (pathname === "/proxy/http" && request.method === "POST") {
        server.timeout(request, 0)
        return await proxyHTTP(request)
      }
      if (pathname === "/proxy/ws" && request.headers.get("upgrade")?.toLowerCase() === "websocket") {
        const data = parseSocketData(request)
        if (!data) return json({ error: { type: "target_not_allowed" } }, 403)
        if (server.upgrade(request, { data })) return undefined
        return json({ error: { type: "websocket_upgrade_failed" } }, 400)
      }
      return json({ error: { type: "not_found" } }, 404)
    } catch (error) {
      return controlledError(error)
    }
  },
  websocket: {
    idleTimeout: 0,
    sendPings: false,
    maxPayloadLength: wsMaxPayloadBytes,
    backpressureLimit: wsBackpressureBytes,
    closeOnBackpressureLimit: false,
    perMessageDeflate: false,
    open(socket) {
      void connectUpstreamSocket(socket)
    },
    message(socket, message) {
      const data = socket.data
      const upstream = data.upstream
      if (!data.ready || !upstream || upstream.readyState !== UpstreamWebSocket.OPEN) {
        socket.close(1008, "upstream handshake incomplete")
        return
      }
      if (data.sending) {
        socket.close(1011, "concurrent upstream writes are not supported")
        upstream.terminate()
        return
      }
      data.sending = true
      auditOutboundMessageIdentity(message)
      upstream.send(message, { binary: typeof message !== "string" }, (error?: Error) => {
        data.sending = false
        if (error && socket.readyState === WebSocket.OPEN) socket.close(1011, "upstream websocket write failed")
      })
    },
    drain(socket) {
      if (socket.data.paused) {
        socket.data.paused = false
        socket.data.upstream?.resume()
      }
    },
    close(socket) {
      const upstream = socket.data.upstream
      socket.data.upstream = undefined
      if (upstream && upstream.readyState !== UpstreamWebSocket.CLOSED) upstream.close()
    },
  },
})

async function connectUpstreamSocket(socket: Bun.ServerWebSocket<SocketData>) {
  const target = socket.data
  try {
    const headers = normalizeModelWebSocketHeaders(target.targetHeaders)
    assertOpenCodeFingerprint(headers)
    metrics.websocket++
    auditOutbound("websocket", target.targetURL, headers, "GET")
    const proxy = await proxyForBun(target.targetProxy)
    if (socket.readyState !== WebSocket.OPEN) return
    const upstream = new UpstreamWebSocket(target.targetURL, {
      headers: Object.fromEntries(headers.entries()),
      maxPayload: wsMaxPayloadBytes,
      perMessageDeflate: true,
      ...(proxy ? { agent: new HttpsProxyAgent(proxy) } : {}),
    })
    target.upstream = upstream
    upstream.once("open", () => {
      if (socket.readyState !== WebSocket.OPEN) return upstream.close()
      target.ready = true
      target.handshakeReported = true
      socket.send(JSON.stringify({
        type: "sub2api.egress.ready",
        protocol: protocolVersion,
        headers: {},
      }))
    })
    upstream.on("message", (message: RawData, isBinary: boolean) => {
      if (socket.readyState !== WebSocket.OPEN) return
      const bytes = toContiguousBytes(message)
      const sent = socket.send(isBinary ? bytes : bytes.toString("utf8"))
      if (sent === 0) {
        upstream.terminate()
        socket.close(1011, "downstream websocket backpressure exceeded")
      } else if (sent === -1 && !target.paused) {
        target.paused = true
        upstream.pause()
      }
    })
    upstream.on("error", () => {
      if (!target.handshakeReported) reportHandshakeFailure(socket, 0)
      else if (socket.readyState === WebSocket.OPEN) socket.close(1011, "upstream websocket error")
    })
    upstream.on("close", (code, reason) => {
      if (!target.handshakeReported) reportHandshakeFailure(socket, 0)
      else if (socket.readyState === WebSocket.OPEN) socket.close(code || 1000, reason.toString() || "upstream closed")
    })
  } catch {
    reportHandshakeFailure(socket, 0)
  }
}

function reportHandshakeFailure(socket: Bun.ServerWebSocket<SocketData>, status: number) {
  if (socket.data.handshakeReported || socket.readyState !== WebSocket.OPEN) return
  socket.data.handshakeReported = true
  socket.send(JSON.stringify({
    type: "sub2api.egress.handshake_error",
    protocol: protocolVersion,
    status,
    headers: {},
  }))
}

function toContiguousBytes(data: RawData) {
  if (Array.isArray(data)) return Buffer.concat(data)
  if (data instanceof ArrayBuffer) return Buffer.from(data)
  return Buffer.from(data.buffer, data.byteOffset, data.byteLength)
}

function assertOpenCodeFingerprint(headers: Headers) {
  const userAgent = headers.get("user-agent") ?? ""
  let invalid = headers.get("originator") !== "opencode" ||
    !isOpenCodeUserAgent(userAgent, OPENCODE_VERSION) ||
    /sub2api|go-http-client/i.test(userAgent)
  for (const [key, value] of headers) {
    if (/sub2api/i.test(key) || /sub2api|go-http-client/i.test(value)) invalid = true
  }
  if (!invalid) return
  metrics.fingerprintViolations++
  throw new Error("outbound fingerprint invariant violated")
}

function auditOutbound(
  transport: "http" | "websocket",
  targetURL: string,
  headers: Headers,
  method: string,
) {
  if (!auditEnabled) return
  const target = new URL(targetURL)
  console.log(JSON.stringify({
    event: "opencode_egress_outbound",
    transport,
    method,
    host: target.host,
    path: target.pathname,
    originator: headers.get("originator"),
    user_agent: headers.get("user-agent"),
    session_hash: hashValue(headers.get("session-id")),
    account_hash: hashValue(headers.get("chatgpt-account-id")),
    header_names: [...headers.keys()].map((name) => name.toLowerCase()).sort(),
    fingerprint_valid: true,
  }))
}

function auditOutboundMessageIdentity(message: string | Buffer) {
  if (!auditEnabled) return
  const bytes = typeof message === "string" ? Buffer.byteLength(message) : message.byteLength
  if (bytes > auditPayloadLimit) {
    console.log(JSON.stringify({
      event: "opencode_egress_message_identity",
      payload_bytes: bytes,
      identity_audit: "skipped_payload_too_large",
    }))
    return
  }
  const identity = extractOpenCodePayloadIdentity(
    typeof message === "string" ? message : message.toString("utf8"),
  )
  if (!identity) return
  console.log(JSON.stringify({
    event: "opencode_egress_message_identity",
    payload_bytes: bytes,
    installation_hash: hashValue(identity.installationID ?? null),
    session_hash: hashValue(identity.sessionID ?? null),
    thread_hash: hashValue(identity.threadID ?? null),
    turn_hash: hashValue(identity.turnID ?? null),
    window_hash: hashValue(identity.windowID ?? null),
    embedded_consistent: identity.embeddedConsistent,
  }))
}

function auditUpstreamResponse(targetURL: string, response: Response) {
  if (!auditEnabled) return
  const target = new URL(targetURL)
  console.log(JSON.stringify({
    event: "opencode_egress_upstream_response",
    transport: "http",
    host: target.host,
    path: target.pathname,
    status: response.status,
    content_type: response.headers.get("content-type"),
    request_id: response.headers.get("x-request-id"),
  }))
}

function auditUpstreamFailure(targetURL: string, error: unknown) {
  if (!auditEnabled) return
  const target = new URL(targetURL)
  const cause = error instanceof Error && error.cause instanceof Error ? error.cause : undefined
  console.log(JSON.stringify({
    event: "opencode_egress_upstream_failure",
    transport: "http",
    host: target.host,
    path: target.pathname,
    error_name: error instanceof Error ? error.name : "Error",
    error_message: error instanceof Error ? error.message.slice(0, 256) : String(error).slice(0, 256),
    cause_code: cause && "code" in cause ? String(cause.code).slice(0, 64) : undefined,
    cause_message: cause ? cause.message.slice(0, 256) : undefined,
  }))
}

function hashValue(value: string | null) {
  return value ? createHash("sha256").update(value).digest("hex").slice(0, 16) : undefined
}

console.log(`sub2api opencode egress listening on http://${server.hostname}:${server.port} (opencode ${OPENCODE_VERSION})`)
