/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

const ftpFolder = path.resolve('ftp')

export function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify (unsafeFile: string, res: Response, next: NextFunction) {
    // Truncate at the poison null byte marker *before* validating, so that the
    // file type allowlist is applied to exactly the name that is read from disk.
    // Validating the untruncated name would let e.g. "package.json.bak%00.md"
    // pass the check while "package.json.bak" is served.
    const file = security.cutOffPoisonNullByte(unsafeFile)

    if (!file || file.includes('\u0000') || !(endsWithAllowlistedFileType(file) || file === 'incident-support.kdbx')) {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
      return
    }

    const resolvedPath = path.resolve(ftpFolder, file)
    if (!resolvedPath.startsWith(ftpFolder + path.sep)) {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
      return
    }

    challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })

    res.sendFile(resolvedPath)
  }

  function endsWithAllowlistedFileType (param: string) {
    return param.endsWith('.md') || param.endsWith('.pdf')
  }
}
