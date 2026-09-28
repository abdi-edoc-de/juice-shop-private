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
import { safeFetch, UnsafeUrlError, type FetchResponse } from '../lib/ssrfGuard'
import logger from '../lib/logger'

const MAX_IMAGE_SIZE_BYTES = 2 * 1024 * 1024
const FETCH_TIMEOUT_MS = 5000

const readLimitedBody = async (response: FetchResponse) => {
  const declaredSize = Number(response.headers.get('content-length'))
  if (Number.isFinite(declaredSize) && declaredSize > MAX_IMAGE_SIZE_BYTES) {
    throw new Error(`url returned more than the allowed ${MAX_IMAGE_SIZE_BYTES} bytes`)
  }
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of Readable.fromWeb(response.body as any)) {
    const buffer = Buffer.from(chunk)
    size += buffer.length
    if (size > MAX_IMAGE_SIZE_BYTES) {
      throw new Error(`url returned more than the allowed ${MAX_IMAGE_SIZE_BYTES} bytes`)
    }
    chunks.push(buffer)
  }
  return Buffer.concat(chunks)
}

const isHttpUrl = (url: string) => {
  try {
    return ['http:', 'https:'].includes(new URL(url).protocol)
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await safeFetch(url, { timeoutMs: FETCH_TIMEOUT_MS, headers: { Accept: 'image/*' } })
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const buffer = await readLimitedBody(response)
          const detectedFileType = await fileType.fromBuffer(buffer)
          if (detectedFileType === undefined || !detectedFileType.mime.startsWith('image/')) {
            throw new Error(`url did not return a supported image type${detectedFileType === undefined ? '' : ': ' + detectedFileType.mime}`)
          }
          // The extension is taken from the actual content instead of the URL suffix
          const ext = detectedFileType.ext
          await fs.writeFile(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, buffer)
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          if (error instanceof UnsafeUrlError) {
            // Neither fetch nor store the URL as it does not point to a public HTTP(S) location
            logger.warn(`Blocked profile image URL: ${utils.getErrorMessage(error)}`)
          } else if (isHttpUrl(url)) {
            try {
              const user = await UserModel.findByPk(loggedInUser.data.id)
              await user?.update({ profileImage: url })
              logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
            } catch (error) {
              next(error)
              return
            }
          } else {
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; keeping the previous profile image`)
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
