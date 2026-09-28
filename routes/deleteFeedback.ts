/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'

/* Only administrators may delete arbitrary feedback. Everybody else is limited to
   feedback they have authored themselves. */
export const authorizeFeedbackDeletion = () => async (req: Request, res: Response, next: NextFunction) => {
  if (security.hasRole(req, security.roles.admin)) {
    next()
    return
  }

  const userId = security.userIdFrom(req)
  if (!userId) {
    res.status(401).json({ error: 'Unauthorized' })
    return
  }

  const id = Number.parseInt(req.params.id, 10)
  if (Number.isNaN(id)) {
    res.status(400).json({ error: 'Invalid feedback id' })
    return
  }

  try {
    const feedback = await FeedbackModel.findByPk(id)
    if (!feedback) {
      res.status(404).json({ error: 'Not Found' })
      return
    }
    if (feedback.UserId !== userId) {
      res.status(403).json({ error: 'Malicious activity detected' })
      return
    }
    next()
  } catch (error) {
    next(error)
  }
}
