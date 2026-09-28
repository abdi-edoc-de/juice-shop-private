/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const keyFolder = path.resolve('encryptionkeys')
/* Only public key material may leave the server, private/symmetric key files
   (e.g. *.key) must never be downloadable. */
const allowedExtensions = ['.pub']

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/') || file.includes('\\')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
      return
    }

    if (!allowedExtensions.includes(path.extname(file).toLowerCase())) {
      res.status(403)
      next(new Error('Only public key files can be retrieved!'))
      return
    }

    const filePath = path.resolve(keyFolder, file)
    if (path.dirname(filePath) !== keyFolder) {
      res.status(403)
      next(new Error('File names cannot contain path traversal sequences!'))
      return
    }

    res.sendFile(filePath)
  }
}
