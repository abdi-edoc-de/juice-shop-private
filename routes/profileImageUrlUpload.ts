/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns/promises'
import net from 'node:net'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

/**
 * Checks whether an IP address belongs to a private, internal, or otherwise
 * non-public range that should not be reachable via SSRF.
 */
function isPrivateOrReservedIP (ip: string): boolean {
  // Normalize IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)
  let normalizedIp = ip
  if (normalizedIp.startsWith('::ffff:')) {
    normalizedIp = normalizedIp.slice(7)
  }

  if (net.isIPv4(normalizedIp)) {
    const parts = normalizedIp.split('.').map(Number)
    // Loopback: 127.0.0.0/8
    if (parts[0] === 127) return true
    // Private: 10.0.0.0/8
    if (parts[0] === 10) return true
    // Private: 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
    // Private: 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true
    // Link-local: 169.254.0.0/16
    if (parts[0] === 169 && parts[1] === 254) return true
    // Current network: 0.0.0.0/8
    if (parts[0] === 0) return true
    // Shared address space (CGNAT): 100.64.0.0/10
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true
    // IETF Protocol Assignments: 192.0.0.0/24
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 0) return true
    // Documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) return true
    if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return true
    if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return true
    // Benchmarking: 198.18.0.0/15
    if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return true
    // Multicast: 224.0.0.0/4
    if (parts[0] >= 224 && parts[0] <= 239) return true
    // Reserved: 240.0.0.0/4
    if (parts[0] >= 240) return true
    return false
  }

  if (net.isIPv6(normalizedIp)) {
    const lower = normalizedIp.toLowerCase()
    // Loopback ::1
    if (lower === '::1') return true
    // Unspecified ::
    if (lower === '::') return true
    // Link-local fe80::/10
    if (lower.startsWith('fe80')) return true
    // Unique local fc00::/7
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true
    // Multicast ff00::/8
    if (lower.startsWith('ff')) return true
    return false
  }

  // If we can't parse it, block it
  return true
}

/**
 * Validates a URL for SSRF protection:
 * - Must be http or https
 * - Hostname must not be an IP literal in a private range
 * - DNS resolution must not resolve to a private/internal IP
 */
async function validateUrlForSSRF (urlString: string): Promise<{ valid: boolean, error?: string }> {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(urlString)
  } catch {
    return { valid: false, error: 'Invalid URL format' }
  }

  // Only allow http and https protocols
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return { valid: false, error: 'Only http and https protocols are allowed' }
  }

  const hostname = parsedUrl.hostname

  // Block empty hostname
  if (!hostname) {
    return { valid: false, error: 'URL must contain a hostname' }
  }

  // If the hostname is an IP address, check it directly
  // Remove brackets from IPv6 literals (URL parser keeps them as [::1])
  const cleanHostname = hostname.replace(/^\[/, '').replace(/\]$/, '')
  if (net.isIP(cleanHostname)) {
    if (isPrivateOrReservedIP(cleanHostname)) {
      return { valid: false, error: 'Access to internal network addresses is not allowed' }
    }
    return { valid: true }
  }

  // Block common localhost aliases
  const blockedHostnames = ['localhost', 'localhost.localdomain', '0.0.0.0', 'metadata.google.internal', 'metadata.aws.internal']
  if (blockedHostnames.includes(cleanHostname.toLowerCase())) {
    return { valid: false, error: 'Access to internal network addresses is not allowed' }
  }

  // Resolve the hostname and check all resolved IPs
  try {
    const addresses = await dns.resolve4(hostname).catch(() => [] as string[])
    const addresses6 = await dns.resolve6(hostname).catch(() => [] as string[])
    const allAddresses = [...addresses, ...addresses6]

    if (allAddresses.length === 0) {
      // If DNS resolution fails, block the request
      return { valid: false, error: 'Could not resolve hostname' }
    }

    for (const addr of allAddresses) {
      if (isPrivateOrReservedIP(addr)) {
        return { valid: false, error: 'Access to internal network addresses is not allowed' }
      }
    }
  } catch {
    return { valid: false, error: 'Could not resolve hostname' }
  }

  return { valid: true }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        // Validate URL to prevent SSRF attacks
        const validation = await validateUrlForSSRF(url)
        if (!validation.valid) {
          res.status(400).json({ error: validation.error })
          return
        }

        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
