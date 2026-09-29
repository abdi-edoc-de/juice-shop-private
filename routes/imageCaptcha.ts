/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'

import { ImageCaptchaModel } from '../models/imageCaptcha'
import * as security from '../lib/insecurity'

export function imageCaptchas () {
  return async (req: Request, res: Response) => {
    try {
      const { default: svgCaptcha } = await import('svg-captcha')
      const captcha = svgCaptcha.create({ size: 5, noise: 2, color: true })

      const user = security.authenticatedUsers.from(req)
      if (!user) {
        res.status(401).send(res.__('You need to be logged in to request a CAPTCHA.'))
        return
      }

      const imageCaptchaInstance = ImageCaptchaModel.build({
        image: captcha.data,
        answer: captcha.text,
        UserId: user.data.id
      })
      await imageCaptchaInstance.save()
      // Never return the solution to the client: it would make the CAPTCHA
      // trivially solvable by an automated client replaying the answer.
      res.json({ image: captcha.data })
    } catch (error) {
      res.status(400).send(res.__('Unable to create CAPTCHA. Please try again.'))
    }
  }
}

export const verifyImageCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = security.authenticatedUsers.from(req)
    const UserId = user?.data?.id
    if (!UserId) {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
      return
    }
    const captchas = await ImageCaptchaModel.findAll({
      limit: 1,
      where: {
        UserId,
        createdAt: {
          [Op.gt]: new Date(Date.now() - 300000)
        }
      },
      order: [['createdAt', 'DESC'], ['id', 'DESC']]
    })
    const captcha = captchas[0]
    // A missing (or expired) CAPTCHA must fail closed, otherwise the gate can be
    // skipped entirely by simply never requesting a CAPTCHA.
    if (!captcha) {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
      return
    }
    // Each CAPTCHA is single-use, so a known answer cannot be replayed and a
    // single challenge cannot be brute-forced.
    await captcha.destroy()
    if (typeof req.body?.answer === 'string' && req.body.answer === captcha.answer) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    res.status(401).send(res.__('Something went wrong while submitting CAPTCHA. Please try again.'))
  }
}
