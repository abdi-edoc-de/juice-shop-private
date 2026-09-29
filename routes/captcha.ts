/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'
import { CaptchaModel } from '../models/captcha'

/* A CAPTCHA is only accepted within this time window after it has been issued. */
export const CAPTCHA_TTL_MS = 5 * 60 * 1000
/* The generated answers are small integers, so anything longer is bogus input. */
const MAX_SUBMITTED_ANSWER_LENGTH = 16

export function captchas () {
  return async (req: Request, res: Response) => {
    const captchaId = req.app.locals.captchaId++
    const operators = ['*', '+', '-']

    const firstTerm = Math.floor((Math.random() * 10) + 1)
    const secondTerm = Math.floor((Math.random() * 10) + 1)
    const thirdTerm = Math.floor((Math.random() * 10) + 1)

    const firstOperator = operators[Math.floor((Math.random() * 3))]
    const secondOperator = operators[Math.floor((Math.random() * 3))]

    const expression = firstTerm.toString() + firstOperator + secondTerm.toString() + secondOperator + thirdTerm.toString()
    const answer = eval(expression).toString() // eslint-disable-line no-eval

    const captchaInstance = CaptchaModel.build({
      captchaId,
      captcha: expression,
      answer
    })
    await captchaInstance.save()
    /* The expected answer is deliberately NOT part of the response so that the
       challenge cannot be satisfied by simply echoing back the issued solution. */
    res.json({
      captchaId,
      captcha: expression
    })
  }
}

const parseCaptchaId = (rawCaptchaId: unknown): number | undefined => {
  if (typeof rawCaptchaId !== 'number' && typeof rawCaptchaId !== 'string') {
    return undefined
  }
  const captchaId = Number(rawCaptchaId)
  return Number.isInteger(captchaId) && captchaId >= 0 ? captchaId : undefined
}

export const verifyCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const captchaId = parseCaptchaId(req.body?.captchaId)
    const submittedAnswer = req.body?.captcha
    if (captchaId === undefined || typeof submittedAnswer !== 'string' || submittedAnswer.length === 0 || submittedAnswer.length > MAX_SUBMITTED_ANSWER_LENGTH) {
      res.status(400).send(res.__('Missing or invalid CAPTCHA. Please request a new one and try again.'))
      return
    }

    const captcha = await CaptchaModel.findOne({
      where: {
        captchaId,
        createdAt: {
          [Op.gt]: new Date(Date.now() - CAPTCHA_TTL_MS)
        }
      }
    })
    if (captcha == null || submittedAnswer !== captcha.answer) {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
      return
    }

    /* Consume the CAPTCHA so that a solved (captchaId, answer) pair cannot be replayed. */
    await captcha.destroy()
    next()
  } catch (error) {
    next(error)
  }
}
