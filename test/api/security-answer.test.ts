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
const jsonHeader = { 'content-type': 'application/json' }
let jimHeader: { Authorization: string, 'content-type': string }
let answerlessUserId: number
let answerlessUserHeader: { Authorization: string, 'content-type': string }

async function registerUser (user: { email: string, password: string, securityQuestion?: { id: number }, securityAnswer?: string }) {
  const res = await request(app)
    .post('/api/Users')
    .set(jsonHeader)
    .send({
      email: user.email,
      password: user.password,
      passwordRepeat: user.password,
      securityQuestion: user.securityQuestion ?? null,
      securityAnswer: user.securityAnswer ?? null
    })

  assert.equal(res.status, 201)
  return res.body
}

async function securityQuestionOf (email: string) {
  // the answer of a registering user is stored by the server while the response is sent
  for (let attempt = 0; attempt < 20; attempt++) {
    const res = await request(app).get(`/rest/user/security-question?email=${encodeURIComponent(email)}`)
    if (res.body?.question) {
      return res.body.question
    }
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
  return undefined
}

before(async () => {
  const result = await createTestApp()
  app = result.app

  const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  jimHeader = { Authorization: 'Bearer ' + token, ...jsonHeader }

  const answerlessUser = await registerUser({ email: 'answerless.user@te.st', password: '12345' })
  answerlessUserId = answerlessUser.id
  const answerlessLogin = await login(app, { email: 'answerless.user@te.st', password: '12345' })
  answerlessUserHeader = { Authorization: 'Bearer ' + answerlessLogin.token, ...jsonHeader }
}, { timeout: 60000 })

void describe('/api/SecurityAnswers', () => {
  void it('GET all security answers is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers')
      .set(jimHeader)

    assert.equal(res.status, 401)
  })

  void it('POST new security answer is forbidden without authentication', async () => {
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(jsonHeader)
      .send({
        UserId: 1,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 401)
  })

  void it('POST new security answer is always bound to the authenticated user', async () => {
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(answerlessUserHeader)
      .send({
        UserId: 1, // owner from the request body must be ignored
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 201)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.UserId, answerlessUserId)
    assert.equal(typeof res.body.data.id, 'number')
    assert.equal(typeof res.body.data.createdAt, 'string')
    assert.equal(typeof res.body.data.updatedAt, 'string')
  })

  void it('POST new security answer for a user who already has one fails from unique constraint', async () => {
    const res = await request(app)
      .post('/api/SecurityAnswers')
      .set(jimHeader)
      .send({
        UserId: 1,
        SecurityQuestionId: 1,
        answer: 'Horst'
      })

    assert.equal(res.status, 400)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.message, 'Validation error')
  })

  void it('POST registration stores the security answer server-side for the created user', async () => {
    const email = 'registered.with.answer@te.st'
    await registerUser({ email, password: '12345', securityQuestion: { id: 1 }, securityAnswer: 'Horst' })

    const question = await securityQuestionOf(email)
    assert.ok(question)
    assert.equal(question.id, 1)
  })
})

void describe('/api/SecurityAnswers/:id', () => {
  void it('GET existing security answer by id is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .get('/api/SecurityAnswers/1')
      .set(jimHeader)

    assert.equal(res.status, 401)
  })

  void it('PUT update existing security answer is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .put('/api/SecurityAnswers/1')
      .set(jimHeader)
      .send({
        answer: 'Blurp'
      })

    assert.equal(res.status, 401)
  })

  void it('DELETE existing security answer is forbidden via public API even when authenticated', async () => {
    const res = await request(app)
      .delete('/api/SecurityAnswers/1')
      .set(jimHeader)

    assert.equal(res.status, 401)
  })
})
