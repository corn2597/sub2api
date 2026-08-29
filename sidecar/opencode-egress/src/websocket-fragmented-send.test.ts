import { describe, expect, test } from "bun:test"
import { sendWebSocketMessageFragmented, type WebSocketFragmentSender } from "./websocket-fragmented-send"

describe("websocket fragmented send", () => {
  test("emits one text message as ordered continuation frames", async () => {
    const frames: Array<{ data: Buffer; binary: boolean; compress: boolean; fin: boolean }> = []
    const sender: WebSocketFragmentSender = {
      send(data, options, callback) {
        frames.push({ data: Buffer.from(data), ...options })
        callback()
      },
    }
    const payload = Buffer.alloc(2 * 1024 * 1024 + 17, 0x61)

    await new Promise<void>((resolve, reject) => {
      sendWebSocketMessageFragmented(sender, payload, false, 1024 * 1024, (error) => {
        if (error) reject(error)
        else resolve()
      })
    })

    expect(frames).toHaveLength(3)
    expect(frames.map((frame) => frame.data.byteLength)).toEqual([1048576, 1048576, 17])
    expect(frames.map((frame) => frame.fin)).toEqual([false, false, true])
    expect(frames.every((frame) => !frame.binary && frame.compress)).toBe(true)
    expect(Buffer.concat(frames.map((frame) => frame.data))).toEqual(payload)
  })
})
