/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      res.sendFile(path.resolve('encryptionkeys/', file), (err: Error & { status?: number }) => {
        if (!err) {
          return
        }
        if (res.headersSent) {
          next(err)
          return
        }
        /* The raw file system error must never reach the client: it contains the
           resolved absolute path of the key directory and echoes the requested
           file name back to the caller. */
        res.status(err.status ?? 404)
        next(new Error('Requested key file could not be served!'))
      })
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
