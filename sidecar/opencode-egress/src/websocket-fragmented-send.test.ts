import { describe, expect, test } from "bun:test"
import WebSocket, { WebSocketServer } from "ws"
import { createHash } from "node:crypto"
import { sendWebSocketMessage, type WebSocketFragmentSender } from "./websocket-fragmented-send"

describe("websocket message send", () => {
  test("delivers a large payload as one complete message", async () => {
    const payload = Buffer.alloc(2 * 1024 * 1024 + 17, 0x61)
    const expectedHash = createHash("sha256").update(payload).digest("hex")
    const wss = new WebSocketServer({ port: 0, perMessageDeflate: true, maxPayload: 16 * 1024 * 1024 })
    let client: WebSocket | undefined

    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("websocket test timed out")), 10_000)
      wss.once("connection", (socket) => {
        let messageCount = 0
        socket.on("message", (data) => {
          messageCount++
          const received = Buffer.from(data as any)
          clearTimeout(timeout)
          expect(messageCount).toBe(1)
          expect(received).toHaveLength(payload.length)
          expect(createHash("sha256").update(received).digest("hex")).toBe(expectedHash)
          resolve()
          socket.terminate()
          client?.terminate()
          wss.close()
        })
        socket.once("error", reject)
      })

      wss.once("listening", () => {
        client = new WebSocket(`ws://127.0.0.1:${(wss.address() as any).port}`, {
          perMessageDeflate: true,
          maxPayload: 16 * 1024 * 1024,
        })
        client.once("open", () => {
          const sender = client as unknown as WebSocketFragmentSender
          sendWebSocketMessage(sender, payload, false, (error?: Error) => {
            if (error) reject(error)
          })
        })
        client.once("error", reject)
      })
    })
  }, { timeout: 30_000 })
})
