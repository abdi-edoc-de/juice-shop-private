/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

const adminCredentials = {
  email: 'admin@' + config.get<string>('application.domain'),
  password: 'admin123'
}

const customerCredentials = {
  email: 'jim@' + config.get<string>('application.domain'),
  password: 'ncc-1701'
}

async function ownOrderIdOf (credentials: { email: string, password: string }) {
  const { token } = await login(app, credentials)
  const res = await request(app)
    .get('/rest/order-history')
    .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

  assert.equal(res.status, 200)
  assert.ok(res.body.data.length > 0)
  return { token, orderId: res.body.data[0].orderId as string }
}

void describe('/rest/track-order/:id', () => {
  void it('GET tracking results for an own order', async () => {
    const { token, orderId } = await ownOrderIdOf(adminCredentials)

    const res = await request(app)
      .get('/rest/track-order/' + orderId)
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

    assert.equal(res.status, 200)
    assert.equal(res.body.data.length, 1)
    assert.equal(res.body.data[0].orderId, orderId)
    assert.ok(Array.isArray(res.body.data[0].products))
  })

  void it('GET tracking results is forbidden for anonymous users', async () => {
    const { orderId } = await ownOrderIdOf(adminCredentials)

    const res = await request(app)
      .get('/rest/track-order/' + orderId)

    assert.equal(res.status, 401)
    assert.equal(res.body.data, undefined)
  })

  void it('GET tracking results of another customers order leaks no order data', async () => {
    const { orderId } = await ownOrderIdOf(adminCredentials)
    const { token } = await login(app, customerCredentials)

    const res = await request(app)
      .get('/rest/track-order/' + orderId)
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

    assert.equal(res.status, 200)
    assert.deepEqual(res.body.data, [{ orderId }])
  })

  void it('GET all orders by injecting into orderId only returns own orders', async () => {
    const { token } = await login(app, adminCredentials)

    const res = await request(app)
      .get('/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27')
      .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.ok(Array.isArray(res.body.data))
    const maskedAdminEmail = adminCredentials.email.replace(/[aeiou]/gi, '*')
    for (const item of res.body.data) {
      assert.equal(typeof item.orderId, 'string')
      assert.equal(item.email, maskedAdminEmail)
    }
  })
})
