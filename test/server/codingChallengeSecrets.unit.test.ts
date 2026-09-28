/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'

import * as codingChallenges from '../../lib/codingChallenges'
import * as security from '../../lib/insecurity'

const privateKeyPattern = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g

// Snippets are plain source excerpts, so keys embedded in string literals still carry their escape sequences
const unescapeNewlines = (pem: string) => pem.replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\r/g, '\n')

const spkiOf = (key: crypto.KeyObject) => key.export({ type: 'spki', format: 'der' }).toString('base64')

void describe('coding challenge snippets', () => {
  void it('must not expose a private key belonging to the JWT verification key', async () => {
    const tokenSigningKey = spkiOf(crypto.createPublicKey(security.publicKey))
    const challenges = await codingChallenges.getCodeChallenges()

    for (const [challengeKey, { snippet }] of challenges) {
      for (const match of snippet.match(privateKeyPattern) ?? []) {
        let publicKey
        try {
          publicKey = crypto.createPublicKey(unescapeNewlines(match))
        } catch {
          continue // not a parsable key, so it cannot be used to sign anything
        }
        assert.notEqual(
          spkiOf(publicKey),
          tokenSigningKey,
          `Code snippet of "${challengeKey}" discloses the private key used to sign session tokens`
        )
      }
    }
  })
})
