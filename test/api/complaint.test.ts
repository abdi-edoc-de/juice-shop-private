/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import * as security from '../../lib/insecurity'

let app: Express
const authHeader = { Authorization: 'Bearer ' + security.authorize({ data: { id: 1, email: 'admin@juice-sh.op' } }), 'content-type': 'application/json' }

before(async () => {
  const result = await createTestApp()
  app = result.app
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

  void it('GET complaints for authenticated user', async () => {
    const res = await request(app)
      .get('/api/Complaints')
      .set(authHeader)
    assert.equal(res.status, 200)
  })

  void it('GET complaints only returns own complaints', async () => {
    // Create a complaint as user 1
    await request(app)
      .post('/api/Complaints')
      .set(authHeader)
      .send({ message: 'Complaint from user 1' })

    // Create a complaint as user 2
    const user2AuthHeader = { Authorization: 'Bearer ' + security.authorize({ data: { id: 2, email: 'user2@juice-sh.op' } }), 'content-type': 'application/json' }
    await request(app)
      .post('/api/Complaints')
      .set(user2AuthHeader)
      .send({ message: 'Complaint from user 2' })

    // User 2 should only see their own complaints
    const res = await request(app)
      .get('/api/Complaints')
      .set(user2AuthHeader)
    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.body.data))
    for (const complaint of res.body.data) {
      assert.equal(complaint.UserId, 2)
    }
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
