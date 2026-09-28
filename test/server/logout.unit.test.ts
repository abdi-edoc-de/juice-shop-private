/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { logout } from '../../routes/logout'

void describe('logout', () => {
  let req: any
  let res: any

  beforeEach(() => {
    req = { cookies: {}, headers: {}, secure: true }
    res = { clearCookie: mock.fn(), status: mock.fn(() => res), json: mock.fn() }
  })

  void it('should delete the session token cookie with its original attributes', () => {
    logout()(req, res)

    assert.equal(res.clearCookie.mock.calls.length, 1)
    assert.equal(res.clearCookie.mock.calls[0].arguments[0], 'token')
    const options = res.clearCookie.mock.calls[0].arguments[1]
    assert.equal(options.httpOnly, true)
    assert.equal(options.secure, true)
    assert.equal(options.sameSite, 'strict')
    assert.equal(options.path, '/')
  })

  void it('should confirm the logout with status 200', () => {
    logout()(req, res)

    assert.equal(res.status.mock.calls[0].arguments[0], 200)
    assert.deepEqual(res.json.mock.calls[0].arguments[0], { status: 'success' })
  })
})
