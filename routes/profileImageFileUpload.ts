/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import { type Request, type Response, type NextFunction } from 'express'
import fileType from 'file-type'

import logger from '../lib/logger'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'
import { profileImageUploadPath, toImageExtension, toUserId } from '../lib/profileImageUpload'

export function profileImageFileUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const file = req.file
    const buffer = file?.buffer
    if (buffer === undefined) {
      res.status(500)
      next(new Error('Illegal file type'))
      return
    }
    const uploadedFileType = await fileType.fromBuffer(buffer)
    if (uploadedFileType === undefined) {
      res.status(500)
      next(new Error('Illegal file type'))
      return
    }
    if (uploadedFileType === null || !uploadedFileType.mime.startsWith('image')) {
      res.status(415)
      next(new Error(`Profile image upload does not accept this file type${uploadedFileType ? (': ' + uploadedFileType.mime) : '.'}`))
      return
    }
    const ext = toImageExtension(uploadedFileType.ext)
    if (ext === null) {
      res.status(415)
      next(new Error(`Profile image upload does not accept this file type: ${uploadedFileType.mime}`))
      return
    }
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }
    // The user id originates from the session/JWT payload and must never be interpolated
    // into a filesystem path unvalidated, otherwise traversal sequences in it would let
    // the upload escape the uploads directory (arbitrary file write).
    const userId = toUserId(loggedInUser.data.id)
    if (userId === null) {
      res.status(400)
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    try {
      await fs.writeFile(profileImageUploadPath(userId, ext), buffer)
    } catch (err) {
      logger.warn('Error writing file: ' + (err instanceof Error ? err.message : String(err)))
    }

    try {
      const user = await UserModel.findByPk(userId)
      if (user != null) {
        await user.update({ profileImage: `assets/public/images/uploads/${userId}.${ext}` })
      }
    } catch (error) {
      next(error)
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
