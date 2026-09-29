/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

// Orders are persisted with the customer e-mail in the same masked form used by /rest/order-history
const maskEmail = (email: string) => email.replace(/[aeiou]/gi, '*')

export function trackOrder () {
  return (req: Request, res: Response) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (!loggedInUser?.data?.email || !loggedInUser.data.id) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const maskedEmail = maskEmail(loggedInUser.data.email)
    const isAccounting = loggedInUser.data.role === security.roles.accounting

    // Truncate id to avoid unintentional RCE
    const id = !utils.isChallengeEnabled(challenges.reflectedXssChallenge) ? String(req.params.id).replace(/[^\w-]+/g, '') : utils.trunc(req.params.id, 60)

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return id.includes('<iframe src="javascript:alert(`xss`)">') })
    db.ordersCollection.find({ $where: `this.orderId === '${id}'` }).then((order: any) => {
      const orders: any[] = Array.isArray(order) ? order : []
      challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => { return orders.length > 1 })
      // Only the customer who placed an order (or the accounting role) may see it
      const ownOrders = isAccounting ? orders : orders.filter((doc: any) => doc?.email === maskedEmail)
      const result = utils.queryResultToJson(ownOrders)
      if (result.data[0] === undefined) {
        // Same response shape for unknown and for foreign orders so the route cannot be used as an existence oracle
        result.data[0] = { orderId: id }
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
