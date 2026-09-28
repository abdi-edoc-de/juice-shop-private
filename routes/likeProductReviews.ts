/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from '../data/types'
import * as db from '../data/mongodb'

// Pending like operations per review. Used to serialise the read-check-write
// sequence below, because MarsDB offers no atomic conditional update ($addToSet
// or a $ne match guard) that could enforce the one-like-per-user rule in a
// single operation.
const reviewLikeLocks = new Map<string, Promise<void>>()

const lockKey = (id: unknown) => typeof id === 'string' ? id : JSON.stringify(id)

/**
 * Runs `task` exclusively for the given review id, queueing concurrent
 * requests for the same review instead of letting them interleave.
 */
async function withReviewLock<T> (id: unknown, task: () => Promise<T>): Promise<T> {
  const key = lockKey(id)
  const previous = reviewLikeLocks.get(key) ?? Promise.resolve()
  const run = previous.then(task, task)
  const settled = run.then(() => undefined, () => undefined)
  reviewLikeLocks.set(key, settled)
  try {
    return await run
  } finally {
    if (reviewLikeLocks.get(key) === settled) {
      reviewLikeLocks.delete(key)
    }
  }
}

export function likeProductReviews () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const id = req.body.id
    const user = security.authenticatedUsers.from(req)
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    try {
      return await withReviewLock(id, async () => {
        const review: Review = await db.reviewsCollection.findOne({ _id: id })
        if (!review) {
          return res.status(404).json({ error: 'Not found' })
        }

        const likedBy: string[] = review.likedBy
        if (likedBy.includes(user.data.email)) {
          return res.status(403).json({ error: 'Not allowed' })
        }

        // Deduplicated write, so a stale read can never store the same user twice.
        const updatedLikedBy = Array.from(new Set([...likedBy, user.data.email]))

        const count = updatedLikedBy.filter(email => email === user.data.email).length
        challengeUtils.solveIf(challenges.timingAttackChallenge, () => count > 2)

        await db.reviewsCollection.update(
          { _id: id },
          { $set: { likedBy: updatedLikedBy } }
        )
        // Counter is only raised after the guarded membership write succeeded,
        // keeping likesCount consistent with likedBy.
        const result = await db.reviewsCollection.update(
          { _id: id },
          { $inc: { likesCount: 1 } }
        )
        return res.json(result)
      })
    } catch (err) {
      return res.status(400).json({ error: 'Wrong Params' })
    }
  }
}
