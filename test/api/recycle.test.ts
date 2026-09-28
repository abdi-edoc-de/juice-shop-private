/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express
let authHeader: { Authorization: string, 'content-type': string }
let otherAuthHeader: { Authorization: string, 'content-type': string }
let ownRecycleId: number

before(async () => {
  const result = await createTestApp()
  app = result.app

  const { token } = await login(app, {
    email: 'jim@juice-sh.op',
    password: 'ncc-1701'
  })
  authHeader = { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }

  const { token: otherToken } = await login(app, {
    email: 'bender@juice-sh.op',
    password: 'OhG0dPlease1nsertLiquor!'
  })
  otherAuthHeader = { Authorization: 'Bearer ' + otherToken, 'content-type': 'application/json' }
}, { timeout: 60000 })

void describe('/api/Recycles', () => {
  void it('POST new recycle', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set(authHeader)
      .send({
        quantity: 200,
        AddressId: '1',
        isPickup: true,
        date: '2017-05-31'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
    ownRecycleId = res.body.data.id
  })

  void it('POST new recycle is forbidden via public API', async () => {
    const res = await request(app)
      .post('/api/Recycles')
      .set({ 'content-type': 'application/json' })
      .send({
        quantity: 200,
        AddressId: '1',
        isPickup: true,
        date: '2017-05-31'
      })
    assert.equal(res.status, 401)
  })

  void it('POST new recycle cannot be attributed to another user', async () => {
    const baseline = await request(app)
      .post('/api/Recycles')
      .set(authHeader)
      .send({
        quantity: 200,
        AddressId: '1',
        isPickup: true,
        date: '2017-05-31'
      })
    assert.equal(baseline.status, 201)
    const ownUserId = baseline.body.data.UserId

    const spoofed = await request(app)
      .post('/api/Recycles')
      .set(authHeader)
      .send({
        UserId: ownUserId + 1000,
        quantity: 200,
        AddressId: '1',
        isPickup: true,
        date: '2017-05-31'
      })
    assert.equal(spoofed.status, 201)
    assert.equal(spoofed.body.data.UserId, ownUserId)
  })

  void it('Will prevent GET all recycles from this endpoint', async () => {
    const res = await request(app)
      .get('/api/Recycles')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.err, 'Sorry, this endpoint is not supported.')
  })

  void it('Will GET own recycle from this endpoint', async () => {
    const res = await request(app)
      .get('/api/Recycles/' + ownRecycleId)
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    const items = res.body.data
    assert.ok(Array.isArray(items))
    assert.equal(items.length, 1)
    for (const item of items) {
      assert.equal(typeof item.id, 'number')
      assert.equal(typeof item.UserId, 'number')
      assert.equal(typeof item.AddressId, 'number')
      assert.equal(typeof item.quantity, 'number')
      assert.equal(typeof item.isPickup, 'boolean')
      assert.ok(item.date !== undefined)
      assert.equal(typeof item.createdAt, 'string')
      assert.equal(typeof item.updatedAt, 'string')
    }
  })

  void it('GET recycle by id is forbidden via public API', async () => {
    const res = await request(app)
      .get('/api/Recycles/' + ownRecycleId)
    assert.equal(res.status, 401)
  })

  void it('GET recycle of another user is not possible', async () => {
    const res = await request(app)
      .get('/api/Recycles/' + ownRecycleId)
      .set(otherAuthHeader)
    assert.equal(res.status, 400)
    assert.equal(res.body.status, 'error')
  })

  void it('GET recycle cannot widen the selector with a JSON array', async () => {
    const res = await request(app)
      .get('/api/Recycles/' + encodeURIComponent('[1,2,3]'))
      .set(authHeader)
    assert.equal(res.status, 400)
    assert.equal(res.body.status, 'error')
  })

  void it('PUT update existing recycle is forbidden', async () => {
    const res = await request(app)
      .put('/api/Recycles/1')
      .set(authHeader)
      .send({
        quantity: 100000
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing recycle is forbidden', async () => {
    const res = await request(app)
      .delete('/api/Recycles/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })
})
