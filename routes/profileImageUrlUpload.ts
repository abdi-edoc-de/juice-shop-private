/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          // Fix: Parse URL properly to extract extension from pathname only (strip query string)
          let urlPathname: string
          try {
            urlPathname = new URL(url).pathname
          } catch {
            urlPathname = url.split('?')[0]
          }
          const ext = ['jpg', 'jpeg', 'png', 'gif'].includes(urlPathname.split('.').slice(-1)[0].toLowerCase()) ? urlPathname.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          // Fix: Sanitize user ID to prevent path traversal
          const sanitizedId = String(loggedInUser.data.id).replace(/[^a-zA-Z0-9_-]/g, '_')
          const uploadsDir = 'frontend/dist/frontend/assets/public/images/uploads'
          const targetPath = path.join(uploadsDir, `${sanitizedId}.${ext}`)
          // Fix: Ensure resolved path stays within the uploads directory
          const resolvedTarget = path.resolve(targetPath)
          const resolvedUploadsDir = path.resolve(uploadsDir)
          if (!resolvedTarget.startsWith(resolvedUploadsDir + path.sep) && resolvedTarget !== resolvedUploadsDir) {
            throw new Error('Invalid file path detected')
          }
          const fileStream = fs.createWriteStream(targetPath, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${sanitizedId}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
