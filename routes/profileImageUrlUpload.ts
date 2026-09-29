/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable, Transform } from 'node:stream'
import { pipeline } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const UPLOAD_DIR = 'frontend/dist/frontend/assets/public/images/uploads'
const ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'svg', 'gif']
/* Keep in sync with the multer file size limit used for POST /profile/image/file */
const MAX_PROFILE_IMAGE_BYTES = 200000
const FETCH_TIMEOUT_MS = 10000

/* Caps the number of bytes that may flow through to the destination file */
function byteLimiter (maxBytes: number) {
  let bytes = 0
  return new Transform({
    transform (chunk, _encoding, callback) {
      bytes += chunk.length
      if (bytes > maxBytes) {
        callback(new Error(`profile image exceeds the maximum allowed size of ${maxBytes} bytes`))
        return
      }
      callback(null, chunk)
    }
  })
}

/* Only one uploaded profile image per user: drop the previously written files with other extensions */
async function removeStaleUploads (userId: number | string, keptExtension: string) {
  await Promise.all(ALLOWED_EXTENSIONS
    .filter((extension) => extension !== keptExtension)
    .map(async (extension) => {
      await fs.promises.rm(`${UPLOAD_DIR}/${userId}.${extension}`, { force: true })
    }))
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (!loggedInUser) {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
      /* The destination file name must never be derived from the token claims alone: only an
         existing user record may cause a file to be written, so no orphaned (and therefore
         unremovable) objects can be created with a forged token. */
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (user == null) {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
      const ext = ALLOWED_EXTENSIONS.includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
      const filePath = `${UPLOAD_DIR}/${user.id}.${ext}`
      try {
        const response = await fetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) })
        if (!response.ok || !response.body) {
          throw new Error('url returned a non-OK status code or an empty body')
        }
        const contentLength = Number(response.headers.get('content-length'))
        if (Number.isFinite(contentLength) && contentLength > MAX_PROFILE_IMAGE_BYTES) {
          throw new Error(`profile image exceeds the maximum allowed size of ${MAX_PROFILE_IMAGE_BYTES} bytes`)
        }
        try {
          await pipeline(
            Readable.fromWeb(response.body as any),
            byteLimiter(MAX_PROFILE_IMAGE_BYTES),
            fs.createWriteStream(filePath, { flags: 'w' })
          )
        } catch (error) {
          /* Never leave a partially written file behind on the publicly served volume */
          await fs.promises.rm(filePath, { force: true })
          throw error
        }
        await removeStaleUploads(user.id, ext)
        await user.update({ profileImage: `/assets/public/images/uploads/${user.id}.${ext}` })
      } catch (error) {
        try {
          await user.update({ profileImage: url })
          logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
        } catch (error) {
          next(error)
          return
        }
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
