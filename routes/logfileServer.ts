/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

const logFolder = path.resolve('logs')

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (file.includes('/') || file.includes('\\')) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
      return
    }

    const filePath = path.resolve(logFolder, file)
    if (path.dirname(filePath) !== logFolder) {
      res.status(403)
      next(new Error('File names cannot contain path traversal sequences!'))
      return
    }

    res.sendFile(filePath)
  }
}
