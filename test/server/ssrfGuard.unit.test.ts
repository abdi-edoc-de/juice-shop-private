/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { assertSafeUrl, isBlockedIpAddress, UnsafeUrlError } from '../../lib/ssrfGuard'

void describe('ssrfGuard', () => {
  void describe('isBlockedIpAddress', () => {
    for (const address of [
      '127.0.0.1',
      '127.1.2.3',
      '0.0.0.0',
      '10.0.0.7',
      '172.16.5.4',
      '192.168.1.1',
      '169.254.169.254', // cloud metadata service
      '100.64.0.1',
      '224.0.0.1',
      '255.255.255.255',
      '::1',
      '::',
      '::ffff:127.0.0.1',
      '::ffff:7f00:1',
      'fe80::1',
      'fc00::1',
      'ff02::1',
      'not-an-ip-address'
    ]) {
      void it(`should block ${address}`, () => {
        assert.equal(isBlockedIpAddress(address), true)
      })
    }

    for (const address of ['1.1.1.1', '8.8.8.8', '93.184.216.34', '2606:4700:4700::1111']) {
      void it(`should allow ${address}`, () => {
        assert.equal(isBlockedIpAddress(address), false)
      })
    }
  })

  void describe('assertSafeUrl', () => {
    for (const url of [
      'http://127.0.0.1:3000/robots.txt',
      'http://127.0.0.1:3000/ftp/legal.md',
      'https://[::1]/secret',
      'http://169.254.169.254/latest/meta-data/',
      'http://192.168.0.1/admin',
      'http://10.1.2.3/internal.jpg'
    ]) {
      void it(`should reject the non-public destination ${url}`, async () => {
        await assert.rejects(async () => { await assertSafeUrl(url) }, UnsafeUrlError)
      })
    }

    for (const url of [
      'file:///etc/passwd',
      'ftp://1.1.1.1/image.jpg',
      'javascript' + ':alert(1)',
      'data:image/svg+xml;base64,PHN2Zy8+'
    ]) {
      void it(`should reject the unsupported protocol in ${url}`, async () => {
        await assert.rejects(async () => { await assertSafeUrl(url) }, UnsafeUrlError)
      })
    }

    void it('should reject URLs with embedded credentials', async () => {
      await assert.rejects(async () => { await assertSafeUrl('http://user:pass@1.1.1.1/image.jpg') }, UnsafeUrlError)
    })

    void it('should reject values that are no URL at all', async () => {
      await assert.rejects(async () => { await assertSafeUrl('cataas.com/cat') }, TypeError)
    })

    void it('should accept public HTTP(S) destinations', async () => {
      const url = await assertSafeUrl('https://1.1.1.1/image.jpg')

      assert.equal(url.href, 'https://1.1.1.1/image.jpg')
    })

    void it('should accept explicitly allowlisted private hosts', async () => {
      process.env.SSRF_ALLOWED_PRIVATE_HOSTS = 'localhost'
      try {
        const url = await assertSafeUrl('http://localhost:3000/image.jpg')

        assert.equal(url.hostname, 'localhost')
      } finally {
        delete process.env.SSRF_ALLOWED_PRIVATE_HOSTS
      }
    })
  })
})
