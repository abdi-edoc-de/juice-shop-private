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

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/redirect', () => {
  void it('GET redirected to https://github.com/juice-shop/juice-shop when this URL is passed as "to" parameter', async () => {
    const res = await request(app)
      .get('/redirect?to=https://github.com/juice-shop/juice-shop')
      .redirects(0)
    assert.equal(res.status, 302)
  })

  void it('GET redirected to https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm when this URL is passed as "to" parameter', async () => {
    const res = await request(app)
      .get('/redirect?to=https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm')
      .redirects(0)
    assert.equal(res.status, 302)
  })

  void it('GET redirected to http://shop.spreadshirt.com/juiceshop when this URL is passed as "to" parameter', async () => {
    const res = await request(app)
      .get('/redirect?to=http://shop.spreadshirt.com/juiceshop')
      .redirects(0)
    assert.equal(res.status, 302)
  })

  void it('GET redirected to http://shop.spreadshirt.de/juiceshop when this URL is passed as "to" parameter', async () => {
    const res = await request(app)
      .get('/redirect?to=http://shop.spreadshirt.de/juiceshop')
      .redirects(0)
    assert.equal(res.status, 302)
  })

  void it('GET redirected to https://www.stickeryou.com/products/owasp-juice-shop/794 when this URL is passed as "to" parameter', async () => {
    const res = await request(app)
      .get('/redirect?to=https://www.stickeryou.com/products/owasp-juice-shop/794')
      .redirects(0)
    assert.equal(res.status, 302)
  })

  void it('GET redirected to https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW when this URL is passed as "to" parameter', async () => {
    const res = await request(app)
      .get('/redirect?to=https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW')
      .redirects(0)
    assert.equal(res.status, 302)
  })

  void it('GET redirected to https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6 when this URL is passed as "to" parameter', async () => {
    const res = await request(app)
      .get('/redirect?to=https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6')
      .redirects(0)
    assert.equal(res.status, 302)
  })

  void it('GET rejected when calling /redirect without query parameter', async () => {
    const res = await request(app)
      .get('/redirect')
    assert.equal(res.status, 406)
    assert.ok(res.text.includes('Unrecognized target URL for redirect'))
  })

  void it('GET rejected when calling /redirect with unrecognized query parameter', async () => {
    const res = await request(app)
      .get('/redirect?x=y')
    assert.equal(res.status, 406)
    assert.ok(res.text.includes('Unrecognized target URL for redirect'))
  })

  void it('GET rejected without reflecting the target when calling /redirect with an unrecognized "to" target', async () => {
    const res = await request(app)
      .get('/redirect?to=whatever')
    assert.equal(res.status, 406)
    assert.ok(res.text.includes('Unrecognized target URL for redirect'))
    assert.ok(!res.text.includes('Unrecognized target URL for redirect: whatever'))
  })

  void it('GET rejected when an allow-listed URL is only part of the target URL', async () => {
    const res = await request(app)
      .get('/redirect?to=https://evil.example/phish?x=https://github.com/juice-shop/juice-shop')
      .redirects(0)
    assert.equal(res.status, 406)
  })

  void it('GET rejected for fragment smuggling of an allow-listed URL', async () => {
    const res = await request(app)
      .get('/redirect?to=https://attacker.test/login%23https://github.com/juice-shop/juice-shop')
      .redirects(0)
    assert.equal(res.status, 406)
  })

  void it('GET rejected for protocol-relative target URL smuggling an allow-listed URL', async () => {
    const res = await request(app)
      .get('/redirect?to=//evil.example/?x=https://github.com/juice-shop/juice-shop')
      .redirects(0)
    assert.equal(res.status, 406)
  })
})
