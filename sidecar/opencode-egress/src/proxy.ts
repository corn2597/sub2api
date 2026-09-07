import { randomBytes } from "node:crypto"
import { createServer } from "node:http"
import type { Socket } from "node:net"
import { SocksClient, type SocksProxy } from "socks"

const socksScheme = /^socks(?:4|5)(?:h)?:$/i
const routeByToken = new Map<string, SocksProxy>()
const tokenByProxy = new Map<string, string>()
let adapterAddress: Promise<string> | undefined

export function isSocksProxy(value: string | undefined) {
  if (!value) return false
  try {
    return socksScheme.test(new URL(value).protocol)
  } catch {
    return false
  }
}

export async function proxyForBun(proxyURL: string | undefined) {
  const value = proxyURL?.trim()
  if (!value || !isSocksProxy(value)) return value
  let token = tokenByProxy.get(value)
  if (!token) {
    token = randomBytes(24).toString("base64url")
    tokenByProxy.set(value, token)
    routeByToken.set(token, parseSocksProxy(value))
  }
  return `http://${token}:x@${await getAdapterAddress()}`
}

export type BunFetchInit = RequestInit & { proxy?: string; timeout?: false | number }

export async function fetchWithProxy(input: string | URL, init: BunFetchInit = {}, proxyURL?: string) {
  const proxy = await proxyForBun(proxyURL)
  return fetch(input, { ...init, ...(proxy ? { proxy } : {}), timeout: false } as BunFetchInit)
}

function parseSocksProxy(value: string): SocksProxy {
  const proxy = new URL(value)
  const port = Number(proxy.port)
  if (!proxy.hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("invalid SOCKS proxy address")
  }
  return {
    host: proxy.hostname,
    port,
    type: proxy.protocol.toLowerCase().startsWith("socks4") ? 4 : 5,
    ...(proxy.username ? { userId: decodeURIComponent(proxy.username) } : {}),
    ...(proxy.password ? { password: decodeURIComponent(proxy.password) } : {}),
  }
}

function getAdapterAddress() {
  if (!adapterAddress) adapterAddress = startAdapter()
  return adapterAddress
}

function startAdapter(): Promise<string> {
  return new Promise((resolve, reject) => {
    const server = createServer((_request, response) => {
      response.writeHead(405, { connection: "close" })
      response.end()
    })
    server.on("connect", (request, rawClient, head) => {
      const client = rawClient as Socket
      const token = proxyToken(request.headers["proxy-authorization"])
      const proxy = token ? routeByToken.get(token) : undefined
      const destination = parseAuthority(request.url)
      if (!proxy || !destination) {
        client.end("HTTP/1.1 407 Proxy Authentication Required\r\nConnection: close\r\n\r\n")
        return
      }
      void SocksClient.createConnection({
        command: "connect",
        proxy,
        destination,
        timeout: 30_000,
        set_tcp_nodelay: true,
      }).then(({ socket: upstream }) => {
        if (client.destroyed) {
          upstream.destroy()
          return
        }
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n")
        if (head.length) upstream.write(head)
        client.setNoDelay(true)
        upstream.setNoDelay(true)
        client.pipe(upstream)
        upstream.pipe(client)
        client.once("error", () => upstream.destroy())
        upstream.once("error", () => client.destroy())
      }).catch(() => {
        if (!client.destroyed) client.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
      })
    })
    server.once("error", reject)
    server.listen(0, "127.0.0.1", () => {
      const address = server.address()
      if (!address || typeof address === "string") return reject(new Error("failed to bind SOCKS adapter"))
      server.unref()
      resolve(`127.0.0.1:${address.port}`)
    })
  })
}

function proxyToken(header: string | string[] | undefined) {
  const value = Array.isArray(header) ? header[0] : header
  if (!value?.startsWith("Basic ")) return undefined
  try {
    return Buffer.from(value.slice(6), "base64").toString("utf8").split(":", 1)[0]
  } catch {
    return undefined
  }
}

function parseAuthority(authority: string | undefined) {
  if (!authority) return undefined
  try {
    const target = new URL(`http://${authority}`)
    const port = Number(target.port || "443")
    if (!target.hostname || !Number.isInteger(port) || port < 1 || port > 65535) return undefined
    return { host: target.hostname, port }
  } catch {
    return undefined
  }
}
