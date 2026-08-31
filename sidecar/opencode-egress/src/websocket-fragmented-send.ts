export type WebSocketFragmentSender = {
  send(
    data: Buffer,
    options: { binary: boolean; compress: boolean },
    callback: (error?: Error) => void,
  ): void
}

// Send one logical WebSocket message. The ws library may split it into wire
// frames internally; application-layer sends must never create partial JSON
// messages that the upstream interprets independently.
export function sendWebSocketMessage(
  sender: WebSocketFragmentSender,
  message: string | Buffer,
  binary: boolean,
  callback: (error?: Error) => void,
) {
  const payload = typeof message === "string" ? Buffer.from(message) : Buffer.from(message)
  sender.send(payload, { binary, compress: true }, callback)
}
