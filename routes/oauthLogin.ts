/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import crypto from 'node:crypto'
import config from 'config'

import { BasketModel } from '../models/basket'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

const TOKEN_INFO_URL = 'https://oauth2.googleapis.com/tokeninfo'
const USER_INFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo'
const REQUEST_TIMEOUT_MS = 5000

interface GoogleTokenInfo {
  aud?: string
  azp?: string
  email?: string
  email_verified?: string | boolean
  expires_in?: string | number
  scope?: string
}

/**
 * Verifies the access token handed over by the client against Google and only accepts it
 * if it was issued for this application. This makes the identity provider - and not the
 * browser - the authority about who is signing in.
 */
async function verifyAccessToken (accessToken: string): Promise<{ email: string } | null> {
  const expectedClientId = config.has('application.googleOauth.clientId')
    ? config.get<string>('application.googleOauth.clientId')
    : undefined
  if (!expectedClientId) {
    return null
  }

  const tokenInfoResponse = await fetch(`${TOKEN_INFO_URL}?access_token=${encodeURIComponent(accessToken)}`, {
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
  })
  if (!tokenInfoResponse.ok) {
    return null
  }
  const tokenInfo = await tokenInfoResponse.json() as GoogleTokenInfo

  const audience = tokenInfo.aud ?? tokenInfo.azp
  if (!audience || !timingSafeEqual(audience, expectedClientId)) {
    return null
  }
  if (Number(tokenInfo.expires_in) <= 0) {
    return null
  }

  let email = tokenInfo.email
  let emailVerified = tokenInfo.email_verified === true || tokenInfo.email_verified === 'true'
  if (!email) {
    const userInfoResponse = await fetch(USER_INFO_URL, {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    })
    if (!userInfoResponse.ok) {
      return null
    }
    const userInfo = await userInfoResponse.json() as GoogleTokenInfo
    email = userInfo.email
    emailVerified = userInfo.email_verified === true || userInfo.email_verified === 'true'
  }

  if (!email || !emailVerified) {
    return null
  }
  return { email }
}

function timingSafeEqual (a: string, b: string) {
  const bufferA = Buffer.from(a)
  const bufferB = Buffer.from(b)
  if (bufferA.length !== bufferB.length) {
    return false
  }
  return crypto.timingSafeEqual(bufferA, bufferB)
}

export function oauthLogin () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const accessToken = req.body?.access_token
    if (typeof accessToken !== 'string' || accessToken.length === 0) {
      res.status(400).json({ error: 'Missing OAuth access token' })
      return
    }

    let profile: { email: string } | null
    try {
      profile = await verifyAccessToken(accessToken)
    } catch {
      res.status(401).send(res.__('Invalid email or password.'))
      return
    }
    if (!profile) {
      res.status(401).send(res.__('Invalid email or password.'))
      return
    }

    try {
      let user = await UserModel.findOne({ where: { email: profile.email } })
      if (!user) {
        // Accounts provisioned through OAuth get a random password which is never handed
        // out, so the identity provider stays the only way to authenticate as them.
        user = await UserModel.create({
          email: profile.email,
          password: crypto.randomBytes(48).toString('base64url')
        })
      }
      if (!user.isActive) {
        res.status(401).send(res.__('Invalid email or password.'))
        return
      }
      if (user.totpSecret !== '') {
        res.status(401).json({
          status: 'totp_token_required',
          data: {
            tmpToken: security.authorize({
              userId: user.id,
              type: 'password_valid_needs_second_factor_token'
            })
          }
        })
        return
      }

      const [basket] = await BasketModel.findOrCreate({ where: { UserId: user.id } })
      const authenticatedUser = { data: user, bid: basket.id }
      const token = security.authorize(authenticatedUser)
      security.authenticatedUsers.put(token, authenticatedUser)
      res.json({ authentication: { token, bid: basket.id, umail: user.email } })
    } catch (error) {
      next(error)
    }
  }
}
