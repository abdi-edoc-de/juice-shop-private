/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

/**
 * Restricts `PUT /api/Hints/:id` to unlocking a hint.
 *
 * The only hint mutation the application offers is the score board's lightbulb
 * button, which sends `{ unlocked: true }`. Without this guard the request falls
 * through to the auto-generated update handler, which assigns every column of
 * the Hint model, allowing anyone to rewrite `text`, `order` or `ChallengeId` of
 * a hint row that is rendered to all visitors (mass assignment / broken object
 * property authorization).
 */
export const restrictHintUpdateToUnlocking = () => (req: Request, res: Response, next: NextFunction) => {
  const body = req.body
  const isUnlockRequest = body !== null && typeof body === 'object' && !Array.isArray(body) &&
    Object.keys(body).length === 1 && body.unlocked === true

  if (!isUnlockRequest) {
    res.status(400).json({ status: 'error', message: 'Only unlocking a hint is supported.' })
    return
  }

  // Never pass anything but the single writable property on to the update handler
  req.body = { unlocked: true }
  next()
}
