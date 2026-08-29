import { afterEach, describe, expect, test } from "bun:test"
import { diagnoseWebSocketHandshake } from "./websocket-handshake-diagnostic"

let server: ReturnType<typeof Bun.serve> | undefined

afterEach(() => {
  server?.stop(true)
  server = undefined
})

describe("websocket handshake diagnostics", () => {
  test("retains the complete failed-upgrade response", async () => {
    const detail = "upstream handshake rejected: capacity is temporarily unavailable"
    server = Bun.serve({
      port: 0,
      fetch(request) {
        expect(request.headers.get("originator")).toBe("opencode")
        expect(request.headers.get("upgrade")).toBe("websocket")
        return new Response(detail, {
          status: 503,
          headers: { "x-request-id": "req_handshake_test" },
        })
      },
    })

    const result = await diagnoseWebSocketHandshake(
      `ws://127.0.0.1:${server.port}/responses`,
      new Headers({ originator: "opencode" }),
    )

    expect(result.status).toBe(503)
    expect(result.headers["x-request-id"]).toBe("req_handshake_test")
    expect(result.body.toString("utf8")).toBe(detail)
  })
})
