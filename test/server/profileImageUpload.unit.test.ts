/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'

import { PROFILE_IMAGE_UPLOAD_DIRECTORY, profileImageUploadPath, toImageExtension, toUserId } from '../../lib/profileImageUpload'

void describe('profileImageUpload', () => {
  void describe('toUserId', () => {
    void it('accepts positive integers and their decimal string representation', () => {
      assert.equal(toUserId(1), 1)
      assert.equal(toUserId(42), 42)
      assert.equal(toUserId('42'), 42)
    })

    void it('rejects path traversal sequences', () => {
      assert.equal(toUserId('../../vfy4411a'), null)
      assert.equal(toUserId('../../../etc/cron.d/backdoor'), null)
      assert.equal(toUserId('..%2f..%2fx'), null)
      assert.equal(toUserId('/absolute/path'), null)
      assert.equal(toUserId('1/../../2'), null)
      assert.equal(toUserId('1\u0000.png'), null)
    })

    void it('rejects anything that is not a positive safe integer', () => {
      assert.equal(toUserId(0), null)
      assert.equal(toUserId(-1), null)
      assert.equal(toUserId(1.5), null)
      assert.equal(toUserId(''), null)
      assert.equal(toUserId(' 1 '), null)
      assert.equal(toUserId('1e3'), null)
      assert.equal(toUserId(Number.MAX_SAFE_INTEGER + 2), null)
      assert.equal(toUserId(undefined), null)
      assert.equal(toUserId(null), null)
      assert.equal(toUserId({ toString: () => '1' }), null)
    })
  })

  void describe('toImageExtension', () => {
    void it('normalizes alphanumeric extensions to lowercase', () => {
      assert.equal(toImageExtension('png'), 'png')
      assert.equal(toImageExtension('JPEG'), 'jpeg')
    })

    void it('rejects extensions containing path or null byte characters', () => {
      assert.equal(toImageExtension('png/../../x'), null)
      assert.equal(toImageExtension('pn\u0000g'), null)
      assert.equal(toImageExtension('.png'), null)
      assert.equal(toImageExtension(''), null)
      assert.equal(toImageExtension(undefined), null)
    })
  })

  void describe('profileImageUploadPath', () => {
    void it('resolves inside the uploads directory', () => {
      assert.equal(
        profileImageUploadPath(42, 'png'),
        path.resolve(PROFILE_IMAGE_UPLOAD_DIRECTORY, '42.png')
      )
    })

    void it('never leaves the uploads directory', () => {
      const uploadDirectory = path.resolve(PROFILE_IMAGE_UPLOAD_DIRECTORY)
      assert.equal(path.dirname(profileImageUploadPath(1, 'gif')), uploadDirectory)
    })
  })
})
