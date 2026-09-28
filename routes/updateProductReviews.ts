/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req) // vuln-code-snippet vuln-line forgedReviewChallenge
    if (!user?.data?.email) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    // The selector must be a plain string. Accepting arbitrary JSON here would
    // let a caller inject query operators (e.g. { "$ne": -1 }) that are
    // evaluated by the data layer and match documents they do not own.
    const id: unknown = req.body.id
    const message: unknown = req.body.message
    if (typeof id !== 'string' || id.length === 0 || typeof message !== 'string') {
      res.status(400).json({ error: 'Wrong Params' })
      return
    }

    db.reviewsCollection.findOne({ _id: id }).then( // vuln-code-snippet neutral-line forgedReviewChallenge
      (review: { author?: string } | null) => {
        if (!review) {
          res.status(404).json({ error: 'Not found' })
          return
        }
        // Object level authorization: a review may only be edited by its author.
        if (review.author !== user.data.email) {
          res.status(403).json({ error: 'Forbidden' })
          return
        }
        return db.reviewsCollection.update(
          { _id: id }, // vuln-code-snippet vuln-line noSqlReviewsChallenge forgedReviewChallenge
          { $set: { message } },
          { multi: false } // vuln-code-snippet vuln-line noSqlReviewsChallenge
        ).then((result: { modified: number, original: Array<{ author: any }> }) => {
          challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 }) // vuln-code-snippet hide-line
          challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 }) // vuln-code-snippet hide-line
          res.json(result)
        })
      }
    ).catch((err: unknown) => {
      res.status(500).json(err)
    })
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
