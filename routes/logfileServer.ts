/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'

const logFilePattern = /^[\w.-]+\.log(\.[\w-]+)?$/

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file
    const sanitizedFile = security.sanitizeFilename(file)

    if (sanitizedFile !== file || !logFilePattern.test(sanitizedFile)) {
      res.status(403)
      next(new Error('Only log files can be requested by their plain file name!'))
      return
    }

    const logsRoot = path.resolve('logs')
    const resolvedPath = path.resolve(logsRoot, sanitizedFile)
    if (resolvedPath !== path.join(logsRoot, sanitizedFile)) {
      res.status(403)
      next(new Error('Only log files can be requested by their plain file name!'))
      return
    }

    res.sendFile(resolvedPath)
  }
}
