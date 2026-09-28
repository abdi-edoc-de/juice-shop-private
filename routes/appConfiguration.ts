/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

/*
 * The application configuration is served to anonymous callers because the
 * frontend needs it to bootstrap. It must therefore never contain values that
 * can be used to authenticate as, or recover the account of, another principal.
 * Any configuration key whose name ends with one of the suffixes below is
 * considered a secret and is stripped from the response, e.g. the security
 * question answers of the seeded "geo stalking" memories, which are the sole
 * factor accepted by POST /rest/user/reset-password.
 */
const SENSITIVE_KEY_SUFFIX_PATTERN = /(securityanswer|securityquestion|password|passphrase|secret|apikey|apiurl|accesskey|privatekey|credentials?|token)$/i

function redactSensitiveValues (value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(redactSensitiveValues)
  }
  if (value !== null && typeof value === 'object') {
    const redacted: Record<string, unknown> = {}
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_KEY_SUFFIX_PATTERN.test(key)) {
        continue
      }
      redacted[key] = redactSensitiveValues(entry)
    }
    return redacted
  }
  return value
}

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    const safeConfig = redactSensitiveValues(structuredClone(config.util.toObject(config)))
    res.json({ config: safeConfig })
  }
}
