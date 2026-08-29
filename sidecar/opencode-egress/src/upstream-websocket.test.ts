import { afterEach, describe, expect, test } from "bun:test"
import { UpstreamWebSocket } from "./upstream-websocket"

let server: ReturnType<typeof Bun.serve> | undefined

afterEach(() => {
  server?.stop(true)
  server = undefined
})

describe("upstream websocket runtime", () => {
  test("reports a failed upgrade with the complete response", async () => {
    const detail = "upstream handshake rejected: capacity is temporarily unavailable"
    server = Bun.serve({
      port: 0,
      fetch() {
        return new Response(detail, {
          status: 503,
          headers: { "x-request-id": "req_handshake_test" },
        })
      },
    })

    const result = await new Promise<{ status: number; requestID: string; body: string }>((resolve, reject) => {
      const socket = new UpstreamWebSocket(`ws://127.0.0.1:${server!.port}/responses`)
      socket.once("unexpected-response", (_request, response) => {
        const chunks: Buffer[] = []
        response.on("data", (chunk) => chunks.push(Buffer.from(chunk)))
        response.once("end", () => resolve({
          status: response.statusCode ?? 0,
          requestID: String(response.headers["x-request-id"] ?? ""),
          body: Buffer.concat(chunks).toString("utf8"),
        }))
      })
      socket.once("error", reject)
    })

    expect(result).toEqual({ status: 503, requestID: "req_handshake_test", body: detail })
  })
})
