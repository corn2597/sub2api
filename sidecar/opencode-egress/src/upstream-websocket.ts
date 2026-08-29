import type WebSocket from "ws"
import type { RawData } from "ws"

// Bun aliases the bare "ws" runtime import to its compatibility layer, which
// does not implement the unexpected-response event. Load the installed ws
// package entrypoint explicitly so failed upgrades retain status, headers, and
// the complete response body.
const runtimeURL = new URL("../node_modules/ws/wrapper.mjs", import.meta.url).href
const runtimeModule = await import(runtimeURL) as { default: typeof WebSocket }

export const UpstreamWebSocket = runtimeModule.default
export type UpstreamWebSocket = WebSocket
export type { RawData }
