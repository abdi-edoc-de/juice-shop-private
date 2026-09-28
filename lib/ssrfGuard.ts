/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import dns from 'node:dns/promises'
import net from 'node:net'

/** Thrown whenever a URL must not be requested by the server itself. */
export class UnsafeUrlError extends Error {
  constructor (message: string) {
    super(message)
    this.name = 'UnsafeUrlError'
  }
}

const ALLOWED_PROTOCOLS = ['http:', 'https:']
const REDIRECT_STATUS_CODES = [301, 302, 303, 307, 308]

/**
 * Hostnames that may resolve to a private/loopback address anyway. Only meant for
 * local development and automated tests (e.g. SSRF_ALLOWED_PRIVATE_HOSTS=localhost)
 * and empty by default.
 */
const allowedPrivateHosts = (): string[] => {
  return (process.env.SSRF_ALLOWED_PRIVATE_HOSTS ?? '')
    .split(',')
    .map((host) => host.trim().toLowerCase())
    .filter((host) => host !== '')
}

const blockList = new net.BlockList()

// Non-globally-routable or otherwise special purpose IPv4 ranges (RFC 6890)
const blockedIPv4Subnets: Array<[string, number]> = [
  ['0.0.0.0', 8], // "this host on this network"
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // shared address space (CGNAT)
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local, includes cloud metadata services
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // documentation
  ['192.88.99.0', 24], // 6to4 relay anycast
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // documentation
  ['203.0.113.0', 24], // documentation
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4] // reserved, includes 255.255.255.255
]

// Non-globally-routable or otherwise special purpose IPv6 ranges (RFC 6890)
const blockedIPv6Subnets: Array<[string, number]> = [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  ['::ffff:0:0', 96], // IPv4-mapped (dotted notation is normalized to IPv4 before)
  ['64:ff9b::', 96], // IPv4/IPv6 translation
  ['100::', 64], // discard-only
  ['2001:db8::', 32], // documentation
  ['fc00::', 7], // unique local
  ['fe80::', 10], // link-local
  ['ff00::', 8] // multicast
]

for (const [address, prefix] of blockedIPv4Subnets) {
  blockList.addSubnet(address, prefix, 'ipv4')
}
for (const [address, prefix] of blockedIPv6Subnets) {
  blockList.addSubnet(address, prefix, 'ipv6')
}

const normalizeIpAddress = (address: string): string => {
  const withoutZoneIndex = address.split('%')[0]
  const ipv4Mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(withoutZoneIndex)
  return ipv4Mapped !== null ? ipv4Mapped[1] : withoutZoneIndex
}

/** Returns true for loopback, private, link-local, multicast and other non-public addresses. */
export const isBlockedIpAddress = (address: string): boolean => {
  const normalized = normalizeIpAddress(address)
  if (net.isIPv4(normalized)) {
    return blockList.check(normalized, 'ipv4')
  }
  if (net.isIPv6(normalized)) {
    return blockList.check(normalized, 'ipv6')
  }
  return true // anything that is not a parseable IP address is not considered safe
}

const stripIpv6Brackets = (hostname: string): string => hostname.replace(/^\[/, '').replace(/\]$/, '')

const resolveHostname = async (hostname: string): Promise<string[]> => {
  if (net.isIP(hostname) !== 0) {
    return [hostname]
  }
  try {
    const records = await dns.lookup(hostname, { all: true, verbatim: true })
    return records.map((record) => record.address)
  } catch {
    // Not provably unsafe, just unreachable, therefore no UnsafeUrlError
    throw new Error(`Hostname "${hostname}" could not be resolved`)
  }
}

/**
 * Validates that a URL may be requested by the server: only HTTP(S), no embedded
 * credentials and no hostname resolving to a non-public IP address.
 *
 * @throws {UnsafeUrlError} if the URL must not be requested server-side
 * @throws {TypeError} if the given value is not a valid URL at all
 */
export const assertSafeUrl = async (candidate: string | URL): Promise<URL> => {
  const url = candidate instanceof URL ? candidate : new URL(candidate)
  if (!ALLOWED_PROTOCOLS.includes(url.protocol)) {
    throw new UnsafeUrlError(`Protocol "${url.protocol}" is not allowed`)
  }
  if (url.username !== '' || url.password !== '') {
    throw new UnsafeUrlError('Credentials embedded in the URL are not allowed')
  }
  const hostname = stripIpv6Brackets(url.hostname).toLowerCase()
  if (hostname === '') {
    throw new UnsafeUrlError('URL without hostname is not allowed')
  }
  if (allowedPrivateHosts().includes(hostname)) {
    return url
  }
  const addresses = await resolveHostname(hostname)
  if (addresses.length === 0) {
    throw new Error(`Hostname "${hostname}" could not be resolved`)
  }
  for (const address of addresses) {
    if (isBlockedIpAddress(address)) {
      throw new UnsafeUrlError(`Hostname "${hostname}" resolves to the non-public address ${address}`)
    }
  }
  return url
}

/** The global fetch Response type, re-exported to avoid clashes with `express.Response`. */
export type FetchResponse = Response

export interface SafeFetchOptions {
  maxRedirects?: number
  timeoutMs?: number
  headers?: Record<string, string>
}

/**
 * Like fetch() but every hop - including each redirect target - has to pass
 * {@link assertSafeUrl} first, so redirects cannot be used to reach internal hosts.
 *
 * Note: the destination is validated before the request is sent, so a hostname whose
 * DNS answer changes between validation and connection (DNS rebinding) is not covered.
 */
export const safeFetch = async (candidate: string | URL, { maxRedirects = 3, timeoutMs = 5000, headers }: SafeFetchOptions = {}): Promise<FetchResponse> => {
  let url = await assertSafeUrl(candidate)
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const response = await fetch(url, {
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
      headers
    })
    if (response.type === 'opaqueredirect' || response.status === 0) {
      // Redirect target is not visible to us, so it cannot be validated and must not be followed
      throw new Error('Redirect target of the url could not be validated')
    }
    const location = response.headers.get('location')
    if (!REDIRECT_STATUS_CODES.includes(response.status) || location === null) {
      return response
    }
    await response.body?.cancel()
    url = await assertSafeUrl(new URL(location, url))
  }
  throw new Error(`Exceeded the maximum of ${maxRedirects} redirects`)
}
