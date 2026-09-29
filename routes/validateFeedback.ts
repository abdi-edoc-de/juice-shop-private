/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

/* Matches the declared width of the Feedbacks.comment column, which SQLite does not enforce itself. */
export const MAX_COMMENT_LENGTH = 255

export const validateFeedback = () => (req: Request, res: Response, next: NextFunction) => {
  const comment = req.body?.comment
  if (comment !== undefined && comment !== null) {
    if (typeof comment !== 'string') {
      res.status(400).send(res.__('Invalid feedback comment.'))
      return
    }
    if (comment.length > MAX_COMMENT_LENGTH) {
      res.status(400).send(res.__('Feedback comment is too long.'))
      return
    }
  }
  next()
}
