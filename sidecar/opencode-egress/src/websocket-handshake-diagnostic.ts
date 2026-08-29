import { randomBytes } from "node:crypto"
import * as http from "node:http"
import * as https from "node:https"
import { HttpsProxyAgent } from "https-proxy-agent"

export type WebSocketHandshakeDiagnostic = {
  status: number
  headers: Record<string, string | string[]>
  body: Buffer
}

export function diagnoseWebSocketHandshake(
  targetURL: string,
  sourceHeaders: Headers,
  proxyURL?: string,
  timeoutMs = 8_000,
): Promise<WebSocketHandshakeDiagnostic> {
  const target = new URL(targetURL)
  if (target.protocol !== "ws:" && target.protocol !== "wss:") {
    return Promise.reject(new Error(`unsupported websocket protocol ${target.protocol}`))
  }

  const headers = Object.fromEntries(sourceHeaders.entries())
  headers.connection = "Upgrade"
  headers.upgrade = "websocket"
  headers["sec-websocket-key"] = randomBytes(16).toString("base64")
  headers["sec-websocket-version"] = "13"

  return new Promise((resolve, reject) => {
    const transport = target.protocol === "wss:" ? https : http
    let settled = false
    const finish = (result: WebSocketHandshakeDiagnostic) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(result)
    }
    const fail = (error: Error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      reject(error)
    }
    const request = transport.request({
      protocol: target.protocol === "wss:" ? "https:" : "http:",
      hostname: target.hostname,
      port: target.port || undefined,
      path: `${target.pathname}${target.search}`,
      method: "GET",
      headers,
      ...(proxyURL ? { agent: new HttpsProxyAgent(proxyURL) } : {}),
    })
    const timer = setTimeout(() => {
      request.destroy(new Error(`websocket handshake diagnostic timed out after ${timeoutMs}ms`))
    }, timeoutMs)

    request.once("response", (response) => {
      const chunks: Buffer[] = []
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)))
      response.once("end", () => finish({
        status: response.statusCode ?? 0,
        headers: normalizeHeaders(response.headers),
        body: Buffer.concat(chunks),
      }))
      response.once("error", fail)
    })
    request.once("upgrade", (response, socket, head) => {
      socket.destroy()
      finish({
        status: response.statusCode ?? 101,
        headers: normalizeHeaders(response.headers),
        body: Buffer.from(head),
      })
    })
    request.once("error", fail)
    request.end()
  })
}

function normalizeHeaders(headers: http.IncomingHttpHeaders) {
  const result: Record<string, string | string[]> = {}
  for (const [name, value] of Object.entries(headers)) {
    if (typeof value === "string" || Array.isArray(value)) result[name] = value
  }
  return result
}
