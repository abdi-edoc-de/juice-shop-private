/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import { PROFILE_IMAGE_UPLOAD_DIRECTORY, resolveProfileImagePath } from '../../lib/profileImagePath'

const uploadDirectory = path.resolve(PROFILE_IMAGE_UPLOAD_DIRECTORY)

void describe('profileImagePath', () => {
  void describe('resolveProfileImagePath', () => {
    void it('resolves integer user id into the uploads directory', () => {
      assert.equal(resolveProfileImagePath(42, 'png'), path.join(uploadDirectory, '42.png'))
    })

    void it('resolves numeric string user id into the uploads directory', () => {
      assert.equal(resolveProfileImagePath('42', 'jpg'), path.join(uploadDirectory, '42.jpg'))
    })

    void it('rejects user id containing a relative path traversal', () => {
      assert.equal(resolveProfileImagePath('../../pwned', 'svg'), null)
      assert.equal(resolveProfileImagePath('..%2f..%2fpwned', 'svg'), null)
      assert.equal(resolveProfileImagePath('1/../../pwned', 'svg'), null)
    })

    void it('rejects user id pointing to an absolute path', () => {
      assert.equal(resolveProfileImagePath('/tmp/pwned', 'svg'), null)
    })

    void it('rejects non-numeric, empty, null and undefined user id', () => {
      assert.equal(resolveProfileImagePath('admin', 'png'), null)
      assert.equal(resolveProfileImagePath('1a', 'png'), null)
      assert.equal(resolveProfileImagePath('', 'png'), null)
      assert.equal(resolveProfileImagePath(null, 'png'), null)
      assert.equal(resolveProfileImagePath(undefined, 'png'), null)
    })

    void it('rejects file extension that is not alphanumeric', () => {
      assert.equal(resolveProfileImagePath(42, '../png'), null)
      assert.equal(resolveProfileImagePath(42, 'p/n.g'), null)
      assert.equal(resolveProfileImagePath(42, ''), null)
    })
  })
})
