/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import * as security from '../../lib/insecurity'
import type { Product as ProductConfig } from '../../lib/config.schema'
import { createTestApp } from './helpers/setup'

const christmasProduct = config.get<ProductConfig[]>('products').filter(({ useForChristmasSpecialChallenge }) => useForChristmasSpecialChallenge)[0]
const pastebinLeakProduct = config.get<ProductConfig[]>('products').filter(({ keywordsForPastebinDataLeakChallenge }) => keywordsForPastebinDataLeakChallenge)[0]

const sqlInjectionPayloads = [
  "';",
  "'(",
  "' union select id,email,password from users--",
  "') union select id,email,password from users--",
  "')) union select * from users--",
  "')) union select 1,2,3,4,5,6,7,8,9--",
  "')) union select '1','2','3','4','5','6','7','8','9' from users--",
  "')) union select id,'2','3',email,password,'6','7','8','9' from users--",
  "')) union select sql,'2','3','4','5','6','7','8','9' from sqlite_master--",
  "'))--"
]

const searchFor = async (app: Express, criteria: string) =>
  await request(app).get(`/rest/products/search?q=${encodeURIComponent(criteria)}`)

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/products/search', () => {
  void it('GET product search with no matches returns no products', async () => {
    const res = await request(app)
      .get('/rest/products/search?q=nomatcheswhatsoever')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })

  void it('GET product search with one match returns found product', async () => {
    const res = await request(app)
      .get('/rest/products/search?q=o-saft')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 1)
  })

  void it('GET product search treats SQL metacharacters as literal search terms', async () => {
    for (const payload of sqlInjectionPayloads) {
      const res = await searchFor(app, payload)
      assert.equal(res.status, 200, `Payload must not trigger a database error: ${payload}`)
      assert.ok(res.headers['content-type']?.includes('application/json'))
      assert.equal(res.body.data.length, 0, `Payload must not return any rows: ${payload}`)
    }
  })

  void it('GET product search does not expose user credentials via UNION SELECT', async () => {
    const res = await searchFor(app, "')) union select id,'2','3',email,password,'6','7','8','9' from users--")
    assert.equal(res.status, 200)
    const body = JSON.stringify(res.body)
    assert.ok(!body.includes(`admin@${config.get<string>('application.domain')}`), 'Response must not contain user e-mail addresses')
    assert.ok(!body.includes(security.hash('admin123')), 'Response must not contain password hashes')
  })

  void it('GET product search does not expose the database schema via UNION SELECT', async () => {
    const res = await searchFor(app, "')) union select sql,'2','3','4','5','6','7','8','9' from sqlite_master--")
    assert.equal(res.status, 200)
    assert.ok(!JSON.stringify(res.body).includes('CREATE TABLE'), 'Response must not contain table definitions')
  })

  void it('GET product search cannot select logically deleted christmas special by default', async () => {
    const res = await request(app)
      .get('/rest/products/search?q=seasonal%20special%20offer')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })

  void it('GET product search cannot select logically deleted christmas special by terminating the where clause', async () => {
    const res = await searchFor(app, `${christmasProduct.name}'))--`)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })

  void it('GET product search cannot select logically deleted unsafe product by terminating the where clause', async () => {
    const res = await searchFor(app, `${pastebinLeakProduct.name}'))--`)
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('application/json'))
    assert.equal(res.body.data.length, 0)
  })

  void it('GET product search with empty search parameter returns all products', async () => {
    const productsRes = await request(app)
      .get('/api/Products')
    assert.equal(productsRes.status, 200)
    assert.ok(productsRes.headers['content-type']?.includes('application/json'))
    const products = productsRes.body.data

    const searchRes = await request(app)
      .get('/rest/products/search?q=')
    assert.equal(searchRes.status, 200)
    assert.ok(searchRes.headers['content-type']?.includes('application/json'))
    assert.equal(searchRes.body.data.length, products.length)
  })

  void it('GET product search without search parameter returns all products', async () => {
    const productsRes = await request(app)
      .get('/api/Products')
    assert.equal(productsRes.status, 200)
    assert.ok(productsRes.headers['content-type']?.includes('application/json'))
    const products = productsRes.body.data

    const searchRes = await request(app)
      .get('/rest/products/search')
    assert.equal(searchRes.status, 200)
    assert.ok(searchRes.headers['content-type']?.includes('application/json'))
    assert.equal(searchRes.body.data.length, products.length)
  })
})
