import { expect, test } from "bun:test"
import { buildOAuthForm } from "./oauth"

test("OAuth exchange form follows OpenCode field order", () => {
  const form = buildOAuthForm({
    code_verifier: "verifier",
    client_id: "client",
    redirect_uri: "http://localhost/callback",
    code: "code",
    grant_type: "authorization_code",
    ignored: "value",
  }, "exchange")
  expect(form.toString()).toBe(
    "grant_type=authorization_code&code=code&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&client_id=client&code_verifier=verifier",
  )
})

test("OAuth refresh form does not leak unrelated fields", () => {
  const form = buildOAuthForm({
    client_id: "client",
    refresh_token: "refresh",
    grant_type: "refresh_token",
    scope: "should-not-be-sent",
  }, "refresh")
  expect(form.toString()).toBe("grant_type=refresh_token&refresh_token=refresh&client_id=client")
})
