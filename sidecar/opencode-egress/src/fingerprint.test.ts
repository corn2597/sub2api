import { describe, expect, test } from "bun:test"
import {
  extractOpenCodePayloadIdentity,
  isOpenCodeUserAgent,
  normalizeManagementHeaders,
  normalizeModelHeaders,
  normalizeModelWebSocketHeaders,
} from "./fingerprint"

describe("OpenCode outbound fingerprint", () => {
  test("accepts the actual OpenCode UA shape and rejects version-prefix spoofing", () => {
    expect(isOpenCodeUserAgent("opencode/1.18.20 (darwin; arm64) runtime/bun/1.3.14")).toBe(true)
    expect(isOpenCodeUserAgent("opencode/1.18.200 (darwin; arm64)")).toBe(false)
    expect(isOpenCodeUserAgent("opencode/1.18.20-custom")).toBe(false)
  })
  test("drops every Sub2API and original client identity", () => {
    const headers = normalizeModelHeaders({
      authorization: "Bearer token",
      "chatgpt-account-id": "acct",
      "session-id": "not-an-opencode-session",
      "user-agent": "Go-http-client/2.0 Sub2API",
      "x-sub2api-account-id": "42",
      "x-codex-installation-id": "device",
      "x-client-request-id": "thread",
    })
    expect(headers.get("authorization")).toBe("Bearer token")
    expect(headers.get("session-id")).toBeNull()
    expect(headers.get("x-sub2api-account-id")).toBeNull()
    expect(headers.get("x-codex-installation-id")).toBeNull()
    expect(headers.get("x-client-request-id")).toBeNull()
    expect(headers.get("accept")).toBeNull()
    expect(headers.get("originator")).toBe("opencode")
    const userAgent = headers.get("user-agent") ?? ""
    expect(userAgent.startsWith("opencode/1.18.20 ")).toBeTrue()
    expect(userAgent).toContain("ai-sdk/provider-utils/4.0.38")
    expect(userAgent).toContain("runtime/bun/1.3.14")
    expect(userAgent.toLowerCase()).not.toContain("sub2api")
    expect(userAgent).not.toContain("Go-http-client")
  })

  test("preserves OpenAI HTTP protocol headers while replacing client identity", () => {
    const headers = normalizeModelHeaders({
      accept: "text/event-stream",
      "openai-beta": "responses=experimental",
      version: "0.146.0",
      "x-codex-beta-features": "remote_compaction_v2",
      "x-codex-turn-metadata": '{"turn_id":"turn-1"}',
      "x-codex-turn-state": "state-1",
      origin: "https://chatgpt.com",
      referer: "https://chatgpt.com/",
    })
    expect(headers.get("accept")).toBe("text/event-stream")
    expect(headers.get("openai-beta")).toBe("responses=experimental")
    expect(headers.get("version")).toBe("0.146.0")
    expect(headers.get("x-codex-beta-features")).toBe("remote_compaction_v2")
    expect(headers.get("x-codex-turn-metadata")).toBe('{"turn_id":"turn-1"}')
    expect(headers.get("x-codex-turn-state")).toBe("state-1")
    expect(headers.get("origin")).toBeNull()
    expect(headers.get("referer")).toBeNull()
  })

  test("preserves only a Go-derived stable OpenCode session", () => {
    const session = "ses_0123456789abcdef0123456789abcdef"
    const headers = normalizeModelWebSocketHeaders({
      "session-id": session,
      "x-session-id": "ses_wrong_wrong_wrong_wrong",
      "x-session-affinity": session,
      "x-parent-session-id": "ses_fedcba9876543210fedcba9876543210",
    })
    expect(headers.get("session-id")).toBe(session)
    expect(headers.get("x-session-id")).toBe(session)
    expect(headers.get("x-session-affinity")).toBe(session)
    expect(headers.get("x-parent-session-id")).toBe("ses_fedcba9876543210fedcba9876543210")
    expect(headers.get("openai-beta")).toBe("responses_websockets=2026-02-06")
  })

  test("drops Unicode turn metadata rejected by the upstream endpoint", () => {
    const raw = JSON.stringify({
      workspace_kind: "project",
      workspaces: { "/Users/demo/语音记账": "changed" },
      label: "😀",
    })
    const headers = normalizeModelWebSocketHeaders({ "x-codex-turn-metadata": raw })
    expect(headers.get("x-codex-turn-metadata")).toBeNull()
  })

  test("drops unsafe opaque turn metadata instead of aborting the handshake", () => {
    const headers = normalizeModelWebSocketHeaders({ "x-codex-turn-metadata": "turn-元数据" })
    expect(headers.get("x-codex-turn-metadata")).toBeNull()
  })

  test("management requests use the same OpenCode identity allowlist", () => {
    const headers = normalizeManagementHeaders({
      authorization: "Bearer token",
      accept: "application/json",
      origin: "https://chatgpt.com",
      referer: "https://chatgpt.com/",
      "x-sub2api-debug": "1",
    })
    expect(headers.get("authorization")).toBe("Bearer token")
    expect(headers.get("accept")).toBe("application/json")
    expect(headers.get("origin")).toBeNull()
    expect(headers.get("referer")).toBeNull()
    expect(headers.get("x-sub2api-debug")).toBeNull()
    expect(headers.get("originator")).toBe("opencode")
  })

  test("extracts hashed-audit inputs without exposing or changing payload identity", () => {
    const identity = extractOpenCodePayloadIdentity(JSON.stringify({
      type: "response.create",
      client_metadata: {
        "x-codex-installation-id": "install-a",
        session_id: "ses_session_a_0123456789",
        thread_id: "ses_thread_a_0123456789",
        turn_id: "turn-a",
        "x-codex-window-id": "ses_thread_a_0123456789:0",
        "x-codex-turn-metadata": JSON.stringify({
          installation_id: "install-a",
          session_id: "ses_session_a_0123456789",
          thread_id: "ses_thread_a_0123456789",
          turn_id: "turn-a",
          window_id: "ses_thread_a_0123456789:0",
        }),
      },
    }))
    expect(identity).toEqual({
      installationID: "install-a",
      sessionID: "ses_session_a_0123456789",
      threadID: "ses_thread_a_0123456789",
      turnID: "turn-a",
      windowID: "ses_thread_a_0123456789:0",
      embeddedConsistent: true,
    })
  })
})
