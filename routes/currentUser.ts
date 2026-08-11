/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

// Whitelist of fields that are safe to expose via the fields parameter
const ALLOWED_FIELDS = new Set(['id', 'email', 'lastLoginIp', 'profileImage', 'username', 'role', 'isActive'])

export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    let user
    let response: any
    const emptyUser = { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined }
    try {
      if (security.verify(req.cookies.token)) {
        user = security.authenticatedUsers.get(req.cookies.token)

        // Parse the fields parameter into an array, splitting by comma.
        // If not provided, both these variables will be undefined.
        const fieldsParam = req.query?.fields as string | undefined
        const requestedFields = fieldsParam ? fieldsParam.split(',').map(f => f.trim()) : []

        let baseUser: any = {}

        if (requestedFields.length > 0) {
          // When fields are specified, return only those fields that are in the whitelist
          for (const field of requestedFields) {
            if (ALLOWED_FIELDS.has(field) && user?.data[field as keyof typeof user.data] !== undefined) {
              baseUser[field] = user?.data[field as keyof typeof user.data]
            }
          }
        } else {
          // If no fields parameter, return standard fields (not password field)
          baseUser = {
            id: user?.data?.id,
            email: user?.data?.email,
            lastLoginIp: user?.data?.lastLoginIp,
            profileImage: user?.data?.profileImage
          }
        }

        response = { user: baseUser }
      } else {
        response = { user: emptyUser }
      }
    } catch (err) {
      response = { user: emptyUser }
    }
    // Solve passwordHashLeakChallenge when password field is included in response
    challengeUtils.solveIf(challenges.passwordHashLeakChallenge, () => response?.user?.password)

    // Disable JSONP support to prevent cross-origin data exfiltration.
    // Always return JSON regardless of callback parameter.
    if (req.query.callback !== undefined) {
      challengeUtils.solveIf(challenges.emailLeakChallenge, () => { return true })
    }
    res.json(response)
  }
}
