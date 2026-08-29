export type WebSocketFragmentSender = {
  send(
    data: Buffer,
    options: { binary: boolean; compress: boolean; fin: boolean },
    callback: (error?: Error) => void,
  ): void
}

export function sendWebSocketMessageFragmented(
  sender: WebSocketFragmentSender,
  message: string | Buffer,
  binary: boolean,
  fragmentBytes: number,
  callback: (error?: Error) => void,
) {
  const payload = typeof message === "string" ? Buffer.from(message) : Buffer.from(message)
  if (payload.byteLength === 0 || payload.byteLength <= fragmentBytes) {
    sender.send(payload, { binary, compress: true, fin: true }, callback)
    return
  }

  let offset = 0
  const sendNext = () => {
    const end = Math.min(payload.byteLength, offset + fragmentBytes)
    const final = end === payload.byteLength
    sender.send(payload.subarray(offset, end), { binary, compress: true, fin: final }, (error) => {
      if (error) {
        callback(error)
        return
      }
      offset = end
      if (final) callback()
      else sendNext()
    })
  }
  sendNext()
}
