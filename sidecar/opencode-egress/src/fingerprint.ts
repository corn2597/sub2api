import { VERSION as OPENAI_PROVIDER_VERSION } from "@ai-sdk/openai"
import {
  VERSION as PROVIDER_UTILS_VERSION,
  getRuntimeEnvironmentUserAgent,
  withUserAgentSuffix,
} from "@ai-sdk/provider-utils"
import os from "node:os"

export const openAIProviderVersion = OPENAI_PROVIDER_VERSION
export const providerUtilsVersion = PROVIDER_UTILS_VERSION
export const openAIWebSocketProtocol = "responses_websockets=2026-02-06"

const OPENCODE_VERSION = process.env.OPENCODE_VERSION ?? "1.18.20"
export const openCodeUserAgent = `opencode/${OPENCODE_VERSION} (${os.platform()} ${os.release()}; ${os.arch()})`

export function isOpenCodeUserAgent(value: string, version = OPENCODE_VERSION) {
  const prefix = `opencode/${version}`
  return value.startsWith(prefix) && /^[\s(]/.test(value.slice(prefix.length))
}

type HeaderInput = Record<string, string[] | string>

export type OpenCodePayloadIdentity = {
  installationID?: string
  sessionID?: string
  threadID?: string
  turnID?: string
  windowID?: string
  embeddedConsistent: boolean
}

const hopByHopHeaders = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "sec-websocket-key",
  "sec-websocket-version",
  "sec-websocket-extensions",
  "sec-websocket-protocol",
])

const modelHeaders = new Set([
  // OpenAI HTTP model protocol headers. These are request semantics rather
  // than transport/client identity and must survive the sidecar hop for
  // alpha search, image Responses bridging, and Responses compatibility.
  "accept",
  "authorization",
  "chatgpt-account-id",
  "content-type",
  "openai-beta",
  "openai-organization",
  "openai-project",
  "session-id",
  "version",
  "x-codex-beta-features",
  "x-codex-turn-metadata",
  "x-codex-turn-state",
  "x-parent-session-id",
  "x-session-affinity",
  "x-session-id",
  "x-openai-internal-codex-residency",
])

const managementHeaders = new Set([
  "accept",
  "authorization",
  "chatgpt-account-id",
  "content-type",
  "openai-beta",
  "x-openai-fedramp",
])

function normalizeHeaders(input: HeaderInput | undefined, allowed: Set<string>) {
  const result = new Headers()
  if (!input) return result
  for (const [key, raw] of Object.entries(input)) {
    const lower = key.toLowerCase()
    if (hopByHopHeaders.has(lower) || !allowed.has(lower)) continue
    for (const value of Array.isArray(raw) ? raw : [raw]) {
      const normalized = lower === "x-codex-turn-metadata"
        ? normalizeTurnMetadataHeader(String(value))
        : String(value)
      if (normalized !== undefined) result.append(key, normalized)
    }
  }
  return result
}

function normalizeTurnMetadataHeader(raw: string): string | undefined {
  const value = raw.trim()
  if (!value) return undefined
  if (isASCIIHTTPHeaderValue(value)) return value
  // OpenAI's Codex endpoint rejects non-ASCII turn metadata even when it is
  // represented as JSON unicode escapes. The Go layer omits the same value
  // from the outbound WS payload; this is a defensive sidecar guard.
  return undefined
}

function isASCIIHTTPHeaderValue(value: string) {
  for (const codePoint of value) {
    const code = codePoint.codePointAt(0) ?? 0
    if (code === 0x09 || (code >= 0x20 && code <= 0x7e)) continue
    return false
  }
  return true
}

function validOpenCodeSession(input: HeaderInput | undefined, names: string[]) {
  if (!input) return undefined
  const wanted = new Set(names.map((name) => name.toLowerCase()))
  for (const [name, raw] of Object.entries(input)) {
    if (!wanted.has(name.toLowerCase())) continue
    for (const candidate of Array.isArray(raw) ? raw : [raw]) {
      const value = String(candidate).trim()
      if (/^ses_[0-9A-Za-z]{20,128}$/.test(value)) return value
    }
  }
  return undefined
}

export function normalizeModelHeaders(input?: HeaderInput) {
  const result = normalizeHeaders(input, modelHeaders)
  const sessionID = validOpenCodeSession(input, ["x-session-affinity", "x-session-id", "session-id"])
  if (sessionID) {
    result.set("session-id", sessionID)
    result.set("x-session-affinity", sessionID)
    result.set("x-session-id", sessionID)
  } else {
    result.delete("session-id")
    result.delete("x-session-affinity")
    result.delete("x-session-id")
  }
  const parentSessionID = validOpenCodeSession(input, ["x-parent-session-id"])
  if (parentSessionID) result.set("x-parent-session-id", parentSessionID)
  else result.delete("x-parent-session-id")

  result.set("originator", "opencode")
  result.set("user-agent", openCodeUserAgent)
  return new Headers(
    withUserAgentSuffix(
      result,
      `ai-sdk/provider-utils/${PROVIDER_UTILS_VERSION}`,
      getRuntimeEnvironmentUserAgent(),
    ),
  )
}

export function normalizeModelWebSocketHeaders(input?: HeaderInput) {
  const result = normalizeModelHeaders(input)
  result.set("openai-beta", openAIWebSocketProtocol)
  return result
}

export function normalizeManagementHeaders(input?: HeaderInput) {
  const result = normalizeHeaders(input, managementHeaders)
  result.set("originator", "opencode")
  result.set("user-agent", openCodeUserAgent)
  return new Headers(
    withUserAgentSuffix(
      result,
      `ai-sdk/provider-utils/${PROVIDER_UTILS_VERSION}`,
      getRuntimeEnvironmentUserAgent(),
    ),
  )
}

export function extractOpenCodePayloadIdentity(raw: string): OpenCodePayloadIdentity | undefined {
  let payload: unknown
  try {
    payload = JSON.parse(raw)
  } catch {
    return undefined
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return undefined
  const metadata = (payload as Record<string, unknown>).client_metadata
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return undefined
  const values = metadata as Record<string, unknown>
  const embedded = parseEmbeddedIdentity(values["x-codex-turn-metadata"])
  const identity: OpenCodePayloadIdentity = {
    installationID: stringValue(values["x-codex-installation-id"]),
    sessionID: stringValue(values.session_id),
    threadID: stringValue(values.thread_id),
    turnID: stringValue(values.turn_id),
    windowID: stringValue(values["x-codex-window-id"]),
    embeddedConsistent: true,
  }
  const pairs: Array<[string | undefined, string | undefined]> = [
    [identity.installationID, embedded.installationID],
    [identity.sessionID, embedded.sessionID],
    [identity.threadID, embedded.threadID],
    [identity.turnID, embedded.turnID],
    [identity.windowID, embedded.windowID],
  ]
  identity.embeddedConsistent = pairs.every(([flat, nested]) => !flat || !nested || flat === nested)
  if (!pairs.some(([flat, nested]) => flat || nested)) return undefined
  return identity
}

function parseEmbeddedIdentity(raw: unknown) {
  if (typeof raw !== "string" || !raw.trim()) return {} as Record<string, string | undefined>
  try {
    const value = JSON.parse(raw) as Record<string, unknown>
    if (!value || typeof value !== "object" || Array.isArray(value)) return {}
    return {
      installationID: stringValue(value.installation_id),
      sessionID: stringValue(value.session_id),
      threadID: stringValue(value.thread_id),
      turnID: stringValue(value.turn_id),
      windowID: stringValue(value.window_id),
    }
  } catch {
    return {}
  }
}

function stringValue(value: unknown) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined
}
