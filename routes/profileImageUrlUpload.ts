/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import { Readable } from 'node:stream'
import { type Request, type Response, type NextFunction } from 'express'
import fileType from 'file-type'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'
import { resolveProfileImagePath } from '../lib/profileImagePath'

const ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'svg', 'gif']
/** Upper bound for the fetched body buffered in memory before it is validated and persisted. */
const MAX_IMAGE_SIZE = 10 * 1024 * 1024

/** Reads the stream into a buffer, aborting as soon as it exceeds the allowed size. */
async function readBody (stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of stream) {
    const buffer = Buffer.from(chunk)
    size += buffer.length
    if (size > MAX_IMAGE_SIZE) {
      throw new Error('url returned a body exceeding the maximum allowed image size')
    }
    chunks.push(buffer)
  }
  return Buffer.concat(chunks)
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        const urlExt = url.split('.').slice(-1)[0].toLowerCase()
        const ext = ALLOWED_EXTENSIONS.includes(urlExt) ? urlExt : 'jpg'
        const filePath = resolveProfileImagePath(loggedInUser.data.id, ext)
        if (filePath === null) { // the user id from the token cannot safely be used as a file name
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
          return
        }
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const buffer = await readBody(Readable.fromWeb(response.body as any))
          const fetchedFileType = await fileType.fromBuffer(buffer)
          if (fetchedFileType?.mime === undefined || !fetchedFileType.mime.startsWith('image')) {
            throw new Error(`url did not return image content${fetchedFileType?.mime ? (' but ' + fetchedFileType.mime) : ''}`)
          }
          await fs.writeFile(filePath, buffer)
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${String(loggedInUser.data.id)}.${ext}` })
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
