/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { orderHistory } from '../../routes/orderHistory'
import * as security from '../../lib/insecurity'
import { ordersCollection } from '../../data/mongodb'

void describe('orderHistory', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    req = { headers: { authorization: 'Bearer token' }, params: {}, body: {}, socket: { remoteAddress: '127.0.0.1' } }
    res = { status: mock.fn(() => res), json: mock.fn() }
    next = mock.fn()
  })

  void it('should call next with error if user is not authenticated', async () => {
    mock.method(security.authenticatedUsers, 'get', () => undefined)

    await orderHistory()(req, res, next)

    assert.equal(next.mock.calls.length, 1)
    assert.match(next.mock.calls[0].arguments[0].message, /Blocked illegal activity/)
  })

  void it('should query orders by the id of the logged in user only', async () => {
    mock.method(security.authenticatedUsers, 'get', () => ({ data: { id: 42, email: 'test@juice-sh.op' } }))
    const find = mock.method(ordersCollection, 'find', async () => [])

    await orderHistory()(req, res, next)

    assert.equal(next.mock.calls.length, 0)
    assert.equal(find.mock.calls.length, 1)
    assert.deepEqual(find.mock.calls[0].arguments[0], { userId: 42 })
  })

  void it('should not return orders of an account whose masked email collides', async () => {
    const victimOrder = { orderId: '1234-abcd', userId: 30, email: 'v**ct**m@ju*c*-sh.*p' }
    mock.method(ordersCollection, 'find', async (query: any) => {
      return [victimOrder].filter((order) => order.userId === query.userId)
    })
    mock.method(security.authenticatedUsers, 'get', () => ({ data: { id: 33, email: 'vaactaam@juice-sh.op' } }))

    await orderHistory()(req, res, next)

    assert.equal(res.json.mock.calls.length, 1)
    assert.deepEqual(res.json.mock.calls[0].arguments[0], { status: 'success', data: [] })
  })
})
