/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { sanitizeFileTypeLabel } from '../../routes/metrics'

void describe('metrics', () => {
  void describe('sanitizeFileTypeLabel', () => {
    void it('keeps known MIME types as label value', () => {
      assert.equal(sanitizeFileTypeLabel('application/pdf'), 'application/pdf')
      assert.equal(sanitizeFileTypeLabel('image/png'), 'image/png')
      assert.equal(sanitizeFileTypeLabel('application/xml'), 'application/xml')
    })

    void it('normalizes casing, whitespace and parameters of known MIME types', () => {
      assert.equal(sanitizeFileTypeLabel(' Image/PNG '), 'image/png')
      assert.equal(sanitizeFileTypeLabel('text/xml; charset=utf-8'), 'text/xml')
    })

    void it('folds unknown client-supplied MIME types into a single bucket', () => {
      assert.equal(sanitizeFileTypeLabel('application/x-attacker-unique-777'), 'other')
      assert.equal(sanitizeFileTypeLabel('application/x-big-' + 'e'.repeat(8000)), 'other')
      assert.equal(sanitizeFileTypeLabel('image/png\nfoo'), 'other')
    })

    void it('folds missing or non-string MIME types into a single bucket', () => {
      assert.equal(sanitizeFileTypeLabel(undefined), 'other')
      assert.equal(sanitizeFileTypeLabel(''), 'other')
      assert.equal(sanitizeFileTypeLabel(null as unknown as string), 'other')
    })
  })
})
