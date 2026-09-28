/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, mock } from 'node:test'
import assert from 'node:assert/strict'
import { retrieveAppConfiguration } from '../../routes/appConfiguration'

void describe('appConfiguration', () => {
  let req: any
  let res: any

  void it('should return configuration object', () => {
    req = {}
    res = { json: mock.fn() }

    retrieveAppConfiguration()(req, res)
    assert.equal(res.json.mock.calls.length, 1)
    const returnedConfig = res.json.mock.calls[0].arguments[0].config
    assert.ok(returnedConfig.application != null)
  })

  void it('should not expose chatBot.llmApiUrl', () => {
    req = {}
    res = { json: mock.fn() }

    retrieveAppConfiguration()(req, res)
    const returnedConfig = res.json.mock.calls[0].arguments[0].config
    assert.ok(returnedConfig.application.chatBot != null)
    assert.ok(!('llmApiUrl' in returnedConfig.application.chatBot))
  })

  void it('should not expose security questions and answers of memories', () => {
    req = {}
    res = { json: mock.fn() }

    retrieveAppConfiguration()(req, res)
    const returnedConfig = res.json.mock.calls[0].arguments[0].config
    assert.ok(Array.isArray(returnedConfig.memories))
    for (const memory of returnedConfig.memories) {
      for (const key of Object.keys(memory)) {
        assert.ok(!/securityanswer|securityquestion/i.test(key), `${key} must not be exposed`)
      }
    }
  })

  void it('should not expose any value stored under a secret-like key', () => {
    req = {}
    res = { json: mock.fn() }

    retrieveAppConfiguration()(req, res)
    const returnedConfig = res.json.mock.calls[0].arguments[0].config
    const serialized = JSON.stringify(returnedConfig)
    assert.ok(!serialized.includes('Daniel Boone National Forest'))
    assert.ok(!serialized.includes('ITsec'))
  })
})
