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

void describe('/api/Complaints', () => {
  void it('POST new complaint', async () => {
    const res = await request(app)
      .post('/api/Complaints')
      .set(authHeader)
      .send({
        message: 'You have no clue what https://github.com/eslint/eslint-scope/issues/39 means, do you???'
      })
    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
  })

  void it('GET all complaints is forbidden via public API', async () => {
    const res = await request(app)
      .get('/api/Complaints')
    assert.equal(res.status, 401)
  })

  void it('GET all complaints only returns the own complaints', async () => {
    const message = 'OWN-COMPLAINT-ONLY-VISIBLE-TO-AUTHOR'
    const created = await request(app)
      .post('/api/Complaints')
      .set(authHeader)
      .send({ message })
    assert.equal(created.status, 201)

    const res = await request(app)
      .get('/api/Complaints')
      .set(authHeader)
    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.body.data))
    assert.ok(res.body.data.some((complaint: any) => complaint.message === message))
    assert.ok(res.body.data.every((complaint: any) => complaint.UserId === created.body.data.UserId))

    const otherRes = await request(app)
      .get('/api/Complaints')
      .set(otherAuthHeader)
    assert.equal(otherRes.status, 200)
    assert.ok(otherRes.body.data.every((complaint: any) => complaint.message !== message))
  })

  void it('POST new complaint cannot be attributed to another user', async () => {
    const baseline = await request(app)
      .post('/api/Complaints')
      .set(authHeader)
      .send({ message: 'BASELINE-COMPLAINT' })
    assert.equal(baseline.status, 201)
    const ownUserId = baseline.body.data.UserId

    const spoofed = await request(app)
      .post('/api/Complaints')
      .set(authHeader)
      .send({ UserId: ownUserId + 1000, message: 'FORGED-ATTRIBUTION-ATTEMPT' })
    assert.equal(spoofed.status, 201)
    assert.equal(spoofed.body.data.UserId, ownUserId)
  })
})

void describe('/api/Complaints/:id', () => {
  void it('GET existing complaint by id is forbidden', async () => {
    const res = await request(app)
      .get('/api/Complaints/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })

  void it('PUT update existing complaint is forbidden', async () => {
    const res = await request(app)
      .put('/api/Complaints/1')
      .set(authHeader)
      .send({
        message: 'Should not work...'
      })
    assert.equal(res.status, 401)
  })

  void it('DELETE existing complaint is forbidden', async () => {
    const res = await request(app)
      .delete('/api/Complaints/1')
      .set(authHeader)
    assert.equal(res.status, 401)
  })
})
