/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'

export function orderHistory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers?.authorization?.replace('Bearer ', '')
    // Defense-in-depth: verify the token signature before trusting the cached user data.
    // This prevents forged alg:none tokens from being used to access order history.
    if (!token || !security.verify(token)) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }
    const loggedInUser = security.authenticatedUsers.get(token)
    if (loggedInUser?.data?.email && loggedInUser.data.id) {
      const email = loggedInUser.data.email
      const updatedEmail = email.replace(/[aeiou]/gi, '*')
      const order = await ordersCollection.find({ email: updatedEmail })
      res.status(200).json({ status: 'success', data: order })
    } else {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}

export function allOrders () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const order = await ordersCollection.find()
    res.status(200).json({ status: 'success', data: order.reverse() })
  }
}

export function toggleDeliveryStatus () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const deliveryStatus = !req.body.deliveryStatus
    const eta = deliveryStatus ? '0' : '1'
    await ordersCollection.update({ _id: req.params.id }, { $set: { delivered: deliveryStatus, eta } })
    res.status(200).json({ status: 'success' })
  }
}
