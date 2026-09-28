/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as utils from '../../lib/utils'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'

let app: Express

const adminHeader = { Authorization: `Bearer ${security.authorize({ data: { email: 'admin@juice-sh.op', role: security.roles.admin } })}` }

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/support/logs/:file', () => {
  void it('GET access log file for the current day as admin', async () => {
    const res = await request(app)
      .get('/support/logs/access.log.' + utils.toISO8601(new Date()))
      .set(adminHeader)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/octet-stream'))
  })

  void it('GET access log file without authorization fails', async () => {
    const res = await request(app)
      .get('/support/logs/access.log.' + utils.toISO8601(new Date()))

    assert.ok(res.status === 401 || res.status === 403)
  })

  void it('GET log file whose name contains a forward slash fails with a 403 error', async () => {
    const res = await request(app)
      .get('/support/logs/%2fetc%2fpasswd')
      .set(adminHeader)

    assert.equal(res.status, 403)
    assert.ok(res.text.includes('Error: Only log files can be requested by their plain file name!'))
  })

  void it('GET file which is not a log file fails with a 403 error', async () => {
    const res = await request(app)
      .get('/support/logs/audit.json')
      .set(adminHeader)

    assert.equal(res.status, 403)
  })
})
