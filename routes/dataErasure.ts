/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import express, { type NextFunction, type Request, type Response } from 'express'
import path from 'node:path'
import config from 'config'
import { themes } from '../views/themes/themes'
import * as utils from '../lib/utils'
import { AllHtmlEntities as Entities } from 'html-entities'

import { SecurityQuestionModel } from '../models/securityQuestion'
import { PrivacyRequestModel } from '../models/privacyRequests'
import { SecurityAnswerModel } from '../models/securityAnswer'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'

const entities = new Entities()

const router = express.Router()

/*
 * The hbs view engine treats the `layout` local as a template path that is resolved relative to
 * the views directory and then compiled and executed as a Handlebars template. A client-supplied
 * value therefore enables arbitrary local file read (CWE-22) as well as server-side template
 * injection (CWE-1336) for every file that an attacker can influence. Layouts are hence limited
 * to paths inside the application directory and files that hold credentials, keys or
 * attacker-writable content are rejected.
 */
const forbiddenLayoutPathFragments = [
  'ftp',
  'ctf.key',
  'encryptionkeys',
  'users.yml',
  `${path.sep}logs${path.sep}`,
  `${path.sep}uploads${path.sep}`,
  `${path.sep}.env`,
  '.key',
  '.pem',
  '.sqlite'
]

const isForbiddenLayout = (layout: string): boolean => {
  const applicationRoot = path.resolve('.')
  // mirrors how the view engine resolves the layout, so the check applies to the file actually loaded
  const resolvedLayoutPath = path.resolve('views', layout)
  if (!resolvedLayoutPath.startsWith(applicationRoot + path.sep)) {
    return true
  }
  const normalizedLayoutPath = resolvedLayoutPath.toLowerCase()
  return forbiddenLayoutPathFragments.some((fragment) => normalizedLayoutPath.includes(fragment.toLowerCase()))
}

router.get('/', (req: Request, res: Response, next: NextFunction) => {
  void (async () => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }
    const email = loggedInUser.data.email

    try {
      const answer = await SecurityAnswerModel.findOne({
        include: [{
          model: UserModel,
          where: { email }
        }]
      })
      if (answer == null) {
        throw new Error('No answer found!')
      }
      const question = await SecurityQuestionModel.findByPk(answer.SecurityQuestionId)
      if (question == null) {
        throw new Error('No question found!')
      }

      const themeKey = config.get<string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']
      res.render('dataErasureForm', {
        userEmail: email,
        securityQuestion: question.question,
        _title_: entities.encode(config.get<string>('application.name')),
        _favicon_: utils.extractFilename(config.get('application.favicon')),
        _bgColor_: theme.bgColor,
        _textColor_: theme.textColor,
        _navColor_: theme.navColor,
        _primLight_: theme.primLight,
        _primDark_: theme.primDark,
        _logo_: utils.extractFilename(config.get('application.logo'))
      })
    } catch (error) {
      next(error)
    }
  })()
})

interface DataErasureRequestParams {
  layout?: string
  email: string
  securityAnswer: string
}

router.post('/', (req: Request<Record<string, unknown>, Record<string, unknown>, DataErasureRequestParams>, res: Response, next: NextFunction): void => {
  void (async () => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    try {
      await PrivacyRequestModel.create({
        UserId: loggedInUser.data.id,
        deletionRequested: true
      })

      res.clearCookie('token')

      const themeKey = config.get<string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']
      const themeVars = {
        _title_: entities.encode(config.get<string>('application.name')),
        _favicon_: utils.extractFilename(config.get('application.favicon')),
        _bgColor_: theme.bgColor,
        _textColor_: theme.textColor,
        _navColor_: theme.navColor,
        _primLight_: theme.primLight,
        _primDark_: theme.primDark,
        _logo_: utils.extractFilename(config.get('application.logo'))
      }

      const layout = req.body.layout
      /*
       * The request body is never spread into the render context: doing so would let a client
       * define view-engine locals (most notably `layout`) and thereby choose the template file
       * that is read and executed on the server.
       */
      if (layout && utils.isChallengeEnabled(challenges.lfrChallenge)) {
        if (typeof layout !== 'string' || isForbiddenLayout(layout)) {
          next(new Error('File access not allowed'))
          return
        }
        res.render('dataErasureResult', {
          layout,
          ...themeVars
        }, (error, html) => {
          if (!html || error) {
            next(new Error(error.message))
          } else {
            const sendlfrResponse: string = html.slice(0, 100) + '......'
            res.send(sendlfrResponse)
            challengeUtils.solveIf(challenges.lfrChallenge, () => { return true })
          }
        })
      } else {
        res.render('dataErasureResult', {
          ...themeVars
        })
      }
    } catch (error) {
      next(error)
    }
  })()
})

export default router
