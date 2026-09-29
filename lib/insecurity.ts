/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from '@juice-shop/models/user'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

export const publicKey = fs ? fs.readFileSync('encryptionkeys/jwt.pub', 'utf8') : 'placeholder-public-key'
const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIICXAIBAAKBgQDNwqLEe9wgTXCbC7+RPdDbBbeqjdbs4kOPOIGzqLpXvJXlxxW8iMz0EaM4BKUqYsIa+ndv3NAn2RxCd5ubVdJJcX43zO6Ko0TFEZx/65gY3BE0O6syCEmUP4qbSd6exou/F+WTISzbQ5FBVPVmhnYhG/kpwt/cIxK5iUn5hm+4tQIDAQABAoGBAI+8xiPoOrA+KMnG/T4jJsG6TsHQcDHvJi7o1IKC/hnIXha0atTX5AUkRRce95qSfvKFweXdJXSQ0JMGJyfuXgU6dI0TcseFRfewXAa/ssxAC+iUVR6KUMh1PE2wXLitfeI6JLvVtrBYswm2I7CtY0q8n5AGimHWVXJPLfGV7m0BAkEA+fqFt2LXbLtyg6wZyxMA/cnmt5Nt3U2dAu77MzFJvibANUNHE4HPLZxjGNXN+a6m0K6TD4kDdh5HfUYLWWRBYQJBANK3carmulBwqzcDBjsJ0YrIONBpCAsXxk8idXb8jL9aNIg15Wumm2enqqObahDHB5jnGOLmbasizvSVqypfM9UCQCQl8xIqy+YgURXzXCN+kwUgHinrutZms87Jyi+D8Br8NY0+Nlf+zHvXAomD2W5CsEK7C+8SLBr3k/TsnRWHJuECQHFE9RA2OP8WoaLPuGCyFXaxzICThSRZYluVnWkZtxsBhW2W8z1b8PvWUE7kMy7TnkzeJS2LSnaNHoyxi7IaPQUCQCwWU4U+v4lD7uYBw00Ga/xt+7+UqFPlPVdz1yyr4q24Zxaw0LgmuEvgU5dycq8N7JxjTubX0MIRR+G9fmDBBl8=\r\n-----END RSA PRIVATE KEY-----'

interface ResponseWithUser {
  status?: string
  data: UserModel
  iat?: number
  exp?: number
  bid?: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token?: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (str.includes(nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

/* The one and only algorithm this application ever issues tokens with. It is pinned on the
   verification side as well, so that the `alg` header of an incoming token can never select
   the verification algorithm (which would allow `alg: none` forgeries or HMAC/RSA key
   confusion using the well-known public key as the shared secret). */
export const jwtAlgorithm = 'RS256'

export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: jwtAlgorithm })
export const decode = (token: string) => { return jws.decode(token)?.payload }

export const verify = (token?: string) => {
  if (!token) {
    return false
  }
  try {
    const decoded = jws.decode(token)
    /* Reject anything that does not explicitly claim the pinned algorithm - most importantly
       unsigned (`alg: none`) tokens - before any signature check is attempted. */
    if (!decoded || decoded.header?.alg !== jwtAlgorithm) {
      return false
    }
    /* The algorithm is passed explicitly, so it is never taken from the token header. */
    if (!jws.verify(token, jwtAlgorithm, publicKey)) {
      return false
    }
    const payload = decoded.payload
    if (payload === null || payload === undefined || typeof payload !== 'object') {
      return false
    }
    const now = Math.floor(Date.now() / 1000)
    if (typeof payload.exp === 'number' && now >= payload.exp) {
      return false
    }
    if (typeof payload.nbf === 'number' && now < payload.nbf) {
      return false
    }
    return true
  } catch {
    return false
  }
}

const unauthorized = (res: Response) => {
  res.status(401).json({ status: 'error', message: 'Unauthorized' })
}

/* Requires a token that carries a valid RS256 signature of this application. */
export const isAuthorized = () => (req: Request, res: Response, next: NextFunction) => {
  if (!verify(utils.jwtFrom(req))) {
    unauthorized(res)
    return
  }
  next()
}

/* Unconditionally refuses access. No token - forged or genuine - can satisfy this guard. */
export const denyAll = () => (_req: Request, res: Response) => {
  unauthorized(res)
}

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

/* Allowlist for fields that are intentionally rendered as HTML. It keeps the formatting and
   links used by the shipped texts but drops scriptable constructs such as event-handler
   attributes, <script>/<img>/<svg> tags and `javascript:` URLs. */
const richTextSanitizerOptions = {
  allowedTags: [...sanitizeHtmlLib.defaults.allowedTags, 'h1', 'h2', 'span', 'small', 'sub', 'sup', 'strike', 'u'],
  allowedAttributes: {
    ...sanitizeHtmlLib.defaults.allowedAttributes,
    a: ['href', 'name', 'target', 'rel', 'title']
  },
  allowedSchemes: ['http', 'https', 'ftp', 'mailto']
}

export const sanitizeRichText = (html: string): string => {
  if (!html) {
    return html
  }
  let sanitized = sanitizeHtmlLib(html, richTextSanitizerOptions)
  let next = sanitizeHtmlLib(sanitized, richTextSanitizerOptions)
  while (next !== sanitized) {
    sanitized = next
    next = sanitizeHtmlLib(sanitized, richTextSanitizerOptions)
  }
  return sanitized
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token?: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon?: string) => {
  if (!coupon) {
    return undefined
  }
  const decoded = z85.decode(coupon)
  if (decoded && (hasValidFormat(decoded.toString()) != null)) {
    const parts = decoded.toString().split('-')
    const validity = parts[0]
    if (utils.toMMMYY(new Date()) === validity) {
      const discount = parts[1]
      return parseInt(discount)
    }
  }
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
export const redirectAllowlist = new Set([
  'https://github.com/juice-shop/juice-shop',
  'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6', // vuln-code-snippet vuln-line redirectCryptoCurrencyChallenge
  'http://shop.spreadshirt.com/juiceshop',
  'http://shop.spreadshirt.de/juiceshop',
  'https://www.stickeryou.com/products/owasp-juice-shop/794',
  'http://leanpub.com/juice-shop'
])

export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl) // vuln-code-snippet vuln-line redirectChallenge
  }
  return allowed
}
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  const hmac = crypto.createHmac('sha256', privateKey)
  return hmac.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error: unknown) {
      res.status(401).json({ status: 'error', message: utils.getErrorMessage(error) })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token && authenticatedUsers.get(token) === undefined && verify(token)) {
    const decoded = decode(token) as ResponseWithUser | undefined
    if (decoded?.data !== undefined) {
      authenticatedUsers.put(token, decoded)
      res.cookie('token', token)
    }
  }
  next()
}
