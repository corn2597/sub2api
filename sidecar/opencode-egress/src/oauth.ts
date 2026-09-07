export type OAuthFlow = "exchange" | "refresh"

const fields: Record<OAuthFlow, readonly string[]> = {
  exchange: ["grant_type", "code", "redirect_uri", "client_id", "code_verifier"],
  refresh: ["grant_type", "refresh_token", "client_id"],
}

// Field order is observable on the wire and follows OpenCode.
export function buildOAuthForm(payload: Record<string, unknown>, flow: OAuthFlow) {
  const form = new URLSearchParams()
  for (const key of fields[flow]) {
    const value = payload[key]
    if (value !== undefined && value !== null) form.set(key, String(value))
  }
  return form
}
