/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import request from 'supertest'
import type { Express } from 'express'

/**
 * Evaluates the arithmetic CAPTCHA challenge (three terms combined by '*', '+' or '-')
 * honouring operator precedence. The expected answer is no longer part of the
 * issuance response, so tests have to solve the challenge themselves.
 */
export function solveCaptcha (expression: string): string {
  const tokens = expression.split(/([*+-])/).filter((token) => token.length > 0)

  const afterMultiplication: string[] = []
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i] === '*') {
      const left = Number(afterMultiplication.pop())
      i++
      afterMultiplication.push(String(left * Number(tokens[i])))
    } else {
      afterMultiplication.push(tokens[i])
    }
  }

  let result = Number(afterMultiplication[0])
  for (let i = 1; i < afterMultiplication.length; i += 2) {
    const operand = Number(afterMultiplication[i + 1])
    result = afterMultiplication[i] === '+' ? result + operand : result - operand
  }
  return String(result)
}

/** Requests a fresh CAPTCHA and returns the payload fields needed to pass verification. */
export async function obtainSolvedCaptcha (app: Express): Promise<{ captchaId: number, captcha: string }> {
  const res = await request(app).get('/rest/captcha')
  if (res.status !== 200) {
    throw new Error(`Unable to obtain CAPTCHA (status ${res.status})`)
  }
  return { captchaId: res.body.captchaId, captcha: solveCaptcha(res.body.captcha) }
}
