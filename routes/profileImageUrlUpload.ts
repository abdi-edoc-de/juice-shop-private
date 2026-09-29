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

// Only non-scripting raster image extensions are allowed. Especially "svg" must never be
// allowed here: SVG files are served as image/svg+xml from the application origin and are
// therefore active content which would enable stored cross-site scripting.
const ALLOWED_IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif']
const ALLOWED_URL_PROTOCOLS = ['http:', 'https:']
const MAX_PROFILE_IMAGE_BYTES = 2 * 1024 * 1024

/**
 * Rejects URLs with a protocol other than http(s), e.g. "data:" URLs which would allow
 * an attacker to supply the stored bytes inline without any external host.
 */
function hasAllowedProtocol (url: string): boolean {
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(url.trim())
  if (scheme === null) {
    return true // no explicit protocol, so fetch will either resolve it relative or fail
  }
  return ALLOWED_URL_PROTOCOLS.includes(`${scheme[1].toLowerCase()}:`)
}

/**
 * Derives the file extension from the _path_ of the given URL only, so that neither a query
 * string nor a fragment (e.g. "...#x.svg") can influence the extension of the stored file.
 * Extensions outside the allowlist fall back to "jpg".
 */
function imageExtensionFromUrl (url: string): string {
  let path = url.split('#')[0].split('?')[0]
  try {
    path = new URL(url).pathname
  } catch {
    // not an absolute URL, keep the manually stripped value
  }
  const filename = path.split('/').slice(-1)[0]
  const extension = filename.includes('.') ? filename.split('.').slice(-1)[0].toLowerCase() : ''
  return ALLOWED_IMAGE_EXTENSIONS.includes(extension) ? extension : 'jpg'
}

async function readBoundedBody (body: any): Promise<Buffer> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of Readable.fromWeb(body)) {
    const buffer = Buffer.from(chunk as Uint8Array)
    size += buffer.length
    if (size > MAX_PROFILE_IMAGE_BYTES) {
      throw new Error('url returned a body exceeding the maximum profile image size')
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
        if (!hasAllowedProtocol(url)) {
          res.status(400)
          next(new Error('Profile image upload only accepts http(s) URLs'))
          return
        }
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const buffer = await readBoundedBody(response.body)
          const detectedType = await fileType.fromBuffer(buffer)
          if (detectedType === undefined || !detectedType.mime.startsWith('image/')) {
            throw new Error(`url did not return a recognizable image${detectedType ? (': ' + detectedType.mime) : ''}`)
          }
          const ext = imageExtensionFromUrl(url)
          await fs.writeFile(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, buffer)
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
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
