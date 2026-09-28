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

void describe('/promotion', () => {
  void it('GET promotion video page is publicly accessible', async () => {
    const res = await request(app)
      .get('/promotion')
    assert.equal(res.status, 200)
  })

  void it('GET promotion video page contains embedded video', async () => {
    const res = await request(app)
      .get('/promotion')
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<source src="./video" type="video/mp4">'))
  })

  void it('GET promotion video page contains subtitles as <script>', async () => {
    const res = await request(app)
      .get('/promotion')
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('<script id="subtitle" type="text/vtt" data-label="English" data-lang="en">'))
  })
})

void describe('/video', () => {
  void it('GET promotion video is publicly accessible', async () => {
    const res = await request(app)
      .get('/video')
    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('video/mp4'))
  })

  void it('GET promotion video with valid range returns partial content', async () => {
    const res = await request(app)
      .get('/video')
      .set('Range', 'bytes=0-100')
    assert.equal(res.status, 206)
    assert.equal(res.headers['content-length'], '101')
    assert.ok(res.headers['content-range']?.startsWith('bytes 0-100/'))
  })

  void it('GET promotion video with suffix range returns partial content', async () => {
    const res = await request(app)
      .get('/video')
      .set('Range', 'bytes=-100')
    assert.equal(res.status, 206)
    assert.equal(res.headers['content-length'], '100')
  })

  void it('GET promotion video clamps a range reaching beyond EOF', async () => {
    const res = await request(app)
      .get('/video')
      .set('Range', 'bytes=0-99999999')
    assert.equal(res.status, 206)
    const [, total] = /\/(\d+)$/.exec(res.headers['content-range'] ?? '') ?? []
    assert.ok(total !== undefined)
    assert.equal(res.headers['content-range'], `bytes 0-${Number(total) - 1}/${total}`)
  })

  void it('GET promotion video ignores a non-numeric range instead of failing', async () => {
    for (const range of ['bytes=abc-', 'bytes=abc-def', 'bytes=-', 'kilobytes=0-100', 'bytes=0-100,200-300']) {
      const res = await request(app)
        .get('/video')
        .set('Range', range)
      assert.equal(res.status, 200, `expected full content for Range "${range}"`)
      assert.ok(res.headers['content-type']?.includes('video/mp4'))
    }
  })

  void it('GET promotion video rejects an unsatisfiable range without leaking a stack trace', async () => {
    for (const range of ['bytes=500-1', 'bytes=99999999-', 'bytes=-0']) {
      const res = await request(app)
        .get('/video')
        .set('Range', range)
      assert.equal(res.status, 416, `expected 416 for Range "${range}"`)
      assert.ok(res.headers['content-range']?.startsWith('bytes */'))
      assert.ok(!res.text?.includes('ERR_OUT_OF_RANGE'))
      assert.ok(!res.text?.includes('node_modules'))
    }
  })
})
