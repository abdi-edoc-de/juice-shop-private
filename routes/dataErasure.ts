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

// The `hbs` view engine treats the `layout` local as a filesystem path that it reads
// and renders around the view. Any request-body field named `layout` must therefore
// never reach the render context, otherwise a caller can read arbitrary files from
// the host filesystem. The layout is resolved explicitly (and validated) below instead.
const stripLayout = (body: DataErasureRequestParams): Record<string, unknown> => {
  const { layout, ...rest } = body ?? ({} as DataErasureRequestParams)
  return rest
}

// Only layouts that stay inside the application's own `views` directory are acceptable.
// Anything else (traversal sequences, absolute paths, null bytes, non-string input)
// is rejected instead of being handed to the view engine as a file path.
const resolveLayoutWithinViews = (layout: unknown): string | null => {
  if (typeof layout !== 'string' || layout.includes('\0')) {
    return null
  }
  const viewsDir = path.resolve('views')
  const candidate = path.resolve(viewsDir, layout)
  const relative = path.relative(viewsDir, candidate)
  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
    return null
  }
  return candidate
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

      const renderContext = stripLayout(req.body)

      if (req.body?.layout) {
        const safeLayout = resolveLayoutWithinViews(req.body.layout)
        if (safeLayout === null) {
          next(new Error('File access not allowed'))
          return
        }
        res.render('dataErasureResult', {
          ...renderContext,
          ...themeVars,
          layout: safeLayout
        }, (error, html) => {
          if (!html || error) {
            next(new Error(error ? error.message : 'Rendering failed'))
          } else {
            res.send(html)
            challengeUtils.solveIf(challenges.lfrChallenge, () => { return true })
          }
        })
      } else {
        res.render('dataErasureResult', {
          ...renderContext,
          ...themeVars
        })
      }
    } catch (error) {
      next(error)
    }
  })()
})

export default router
