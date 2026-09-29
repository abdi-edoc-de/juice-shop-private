/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

const injectedScope = 'scope[include][association]=Baskets&scope[include][include][association]=User&scope[include][include][attributes][0]=email&scope[include][include][attributes][1]=password&scope[include][include][attributes][2]=totpSecret'

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('Sequelize query-option injection on generated API endpoints', () => {
  void it('GET product by id with injected scope query options is rejected', async () => {
    const res = await request(app).get(`/api/Products/1?${injectedScope}`)
    assert.equal(res.status, 400)
    assert.ok(!JSON.stringify(res.body).includes('password'))
  })

  void it('PUT product by id with injected scope query options is rejected', async () => {
    const res = await request(app)
      .put(`/api/Products/1?${injectedScope}`)
      .set('content-type', 'application/json')
      .send({ description: 'The all-time classic.' })
    assert.equal(res.status, 400)
    assert.ok(!JSON.stringify(res.body).includes('password'))
  })

  void it('GET product list with an undeclared scope name is rejected', async () => {
    const res = await request(app).get('/api/Products?scope=allAttributes')
    assert.equal(res.status, 400)
  })

  void it('GET product by id without query options still exposes no credential attributes', async () => {
    const res = await request(app).get('/api/Products/1')
    assert.equal(res.status, 200)
    assert.equal(res.body.data.password, undefined)
    assert.equal(res.body.data.totpSecret, undefined)
    assert.equal(res.body.data.Baskets, undefined)
  })

  void it('GET with flat attribute filter is still supported', async () => {
    const res = await request(app).get('/api/Challenges/?name=Score%20Board')
    assert.equal(res.status, 200)
  })
})
