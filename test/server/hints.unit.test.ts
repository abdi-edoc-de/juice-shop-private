/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { restrictHintUpdateToUnlocking } from '../../routes/hints'

void describe('restrictHintUpdateToUnlocking', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    req = { body: {} }
    res = { status: mock.fn(() => res), json: mock.fn() }
    next = mock.fn()
  })

  void it('should pass on a request that only unlocks a hint', () => {
    req.body = { unlocked: true }

    restrictHintUpdateToUnlocking()(req, res, next)

    assert.equal(next.mock.calls.length, 1)
    assert.deepEqual(req.body, { unlocked: true })
  })

  void it('should reject additional properties next to "unlocked"', () => {
    req.body = { unlocked: true, text: 'tampered', order: 1, ChallengeId: 2 }

    restrictHintUpdateToUnlocking()(req, res, next)

    assert.equal(next.mock.calls.length, 0)
    assert.equal(res.status.mock.calls[0].arguments[0], 400)
  })

  void it('should reject writes to other properties than "unlocked"', () => {
    req.body = { text: 'tampered' }

    restrictHintUpdateToUnlocking()(req, res, next)

    assert.equal(next.mock.calls.length, 0)
    assert.equal(res.status.mock.calls[0].arguments[0], 400)
  })

  void it('should reject locking a hint again', () => {
    req.body = { unlocked: false }

    restrictHintUpdateToUnlocking()(req, res, next)

    assert.equal(next.mock.calls.length, 0)
    assert.equal(res.status.mock.calls[0].arguments[0], 400)
  })

  void it('should reject a non-boolean "unlocked" value', () => {
    req.body = { unlocked: 'true' }

    restrictHintUpdateToUnlocking()(req, res, next)

    assert.equal(next.mock.calls.length, 0)
    assert.equal(res.status.mock.calls[0].arguments[0], 400)
  })

  void it('should reject an empty body', () => {
    req.body = {}

    restrictHintUpdateToUnlocking()(req, res, next)

    assert.equal(next.mock.calls.length, 0)
    assert.equal(res.status.mock.calls[0].arguments[0], 400)
  })

  void it('should reject a non-object body', () => {
    for (const body of ['unlocked=true', null, undefined, [{ unlocked: true }]]) {
      res.status.mock.resetCalls()
      next.mock.resetCalls()
      req.body = body

      restrictHintUpdateToUnlocking()(req, res, next)

      assert.equal(next.mock.calls.length, 0)
      assert.equal(res.status.mock.calls[0].arguments[0], 400)
    }
  })
})
