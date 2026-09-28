/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'

import * as security from '../lib/insecurity'

/**
 * Terminates the session by deleting the `token` cookie.
 *
 * Required because the cookie is issued as `HttpOnly` and can therefore no longer be removed by
 * the client-side script when the user logs out.
 */
export function logout () {
  return (req: Request, res: Response) => {
    security.clearSessionTokenCookie(req, res)
    res.status(200).json({ status: 'success' })
  }
}
