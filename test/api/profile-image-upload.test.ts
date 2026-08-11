/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import path from 'node:path'
import http from 'node:http'
import fs from 'node:fs'
import { type AddressInfo } from 'node:net'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/profile/image/file', () => {
  void it('POST profile image file valid for JPG format', async () => {
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')

    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .attach('file', file)
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST profile image file invalid type', async () => {
    const file = path.resolve(__dirname, '../files/invalidProfileImageType.docx')

    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .attach('file', file)

    assert.equal(res.status, 415)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes(`${config.get<string>('application.name')} (Express`))
    assert.ok(res.text.includes('Error: Profile image upload does not accept this file type'))
  })

  void it('POST profile image file forbidden for anonymous user', async () => {
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')

    const res = await request(app)
      .post('/profile/image/file')
      .attach('file', file)

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST profile image file rejected for unrecognizable file content', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .attach('file', Buffer.from('not an image, just plain text content'), 'random.bin')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('Error: Illegal file type'))
  })
})

void describe('/profile/image/url', () => {
  void it('POST profile image URL blocked for invalid URL format', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'cataas.com/cat')

    assert.equal(res.status, 400)
    assert.ok(res.body.error?.includes('Invalid URL format'))
  })

  void it('POST profile image URL redirects for valid external HTTPS URL', async () => {
    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'https://notanimage.here/100/100')
      .redirects(0)

    // DNS resolution may fail for fake domain, resulting in a 400 (blocked)
    // or 302 if it resolves to a public IP
    assert.ok(res.status === 302 || res.status === 400)
  })

  void it('POST profile image URL forbidden for anonymous user', { skip: 'FIXME runs into "socket hang up"' }, async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .field('imageUrl', 'https://cataas.com/cat')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('POST valid image with tampered content length', { skip: 'Fails on CI/CD pipeline' }, async () => {
    const file = path.resolve(__dirname, '../files/validProfileImage.jpg')

    const { token } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })

    const res = await request(app)
      .post('/profile/image/file')
      .set('Cookie', `token=${token}`)
      .set('Content-Length', '42')
      .attach('file', file)
      .redirects(0)

    assert.equal(res.status, 500)
    assert.ok(res.text.includes('Unexpected end of form'))
  })
})

void describe('/profile/image/url SSRF protection', () => {
  let mockServer: http.Server
  let mockPort: number
  let token: string

  before(async () => {
    const { token: userToken } = await login(app, {
      email: `jim@${config.get<string>('application.domain')}`,
      password: 'ncc-1701'
    })
    token = userToken

    const imageBuffer = fs.readFileSync(path.resolve(__dirname, '../files/validProfileImage.jpg'))

    mockServer = http.createServer((req, res) => {
      res.statusCode = 200
      res.setHeader('Content-Type', 'image/jpeg')
      res.end(imageBuffer)
    })
    await new Promise<void>((resolve) => { mockServer.listen(0, resolve) })
    mockPort = (mockServer.address() as AddressInfo).port
  })

  after(async () => {
    await new Promise<void>((resolve, reject) => {
      mockServer.close((err) => { err != null ? reject(err) : resolve() })
    })
  })

  void it('POST blocks localhost URLs to prevent SSRF', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', `http://localhost:${mockPort}/photo.jpg`)

    assert.equal(res.status, 400)
    assert.ok(res.body.error?.includes('internal network'))
  })

  void it('POST blocks 127.0.0.1 URLs to prevent SSRF', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', `http://127.0.0.1:${mockPort}/photo.jpg`)

    assert.equal(res.status, 400)
    assert.ok(res.body.error?.includes('internal network'))
  })

  void it('POST blocks private network IPs (10.x.x.x)', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'http://10.0.0.1/image.jpg')

    assert.equal(res.status, 400)
    assert.ok(res.body.error?.includes('internal network'))
  })

  void it('POST blocks private network IPs (192.168.x.x)', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'http://192.168.1.1/image.jpg')

    assert.equal(res.status, 400)
    assert.ok(res.body.error?.includes('internal network'))
  })

  void it('POST blocks private network IPs (172.16.x.x)', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'http://172.16.0.1/image.jpg')

    assert.equal(res.status, 400)
    assert.ok(res.body.error?.includes('internal network'))
  })

  void it('POST blocks link-local IPs (169.254.x.x)', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'http://169.254.169.254/latest/meta-data/')

    assert.equal(res.status, 400)
    assert.ok(res.body.error?.includes('internal network'))
  })

  void it('POST blocks non-HTTP protocols', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'file:///etc/passwd')

    assert.equal(res.status, 400)
    assert.ok(res.body.error?.includes('Only http and https'))
  })

  void it('POST blocks IPv6 loopback', async () => {
    const res = await request(app)
      .post('/profile/image/url')
      .set('Cookie', `token=${token}`)
      .field('imageUrl', 'http://[::1]:3000/rest/admin/application-version')

    assert.equal(res.status, 400)
    assert.ok(res.body.error?.includes('internal network'))
  })
})
