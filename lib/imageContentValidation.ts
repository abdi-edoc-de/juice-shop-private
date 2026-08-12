/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import fileType from 'file-type'
import { type Request, type Response, type NextFunction } from 'express'

// Allowed image MIME types based on actual file content (magic bytes)
const ALLOWED_IMAGE_MIMES = new Set([
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'image/bmp',
  'image/tiff'
])

/**
 * Middleware that validates uploaded file content (written to disk by multer)
 * by checking magic bytes. Rejects and deletes the file if content doesn't
 * match an allowed image type.
 */
export function validateMemoryImageContent () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!req.file?.path) {
      next()
      return
    }

    try {
      const buffer = await fs.readFile(req.file.path)
      const detectedType = await fileType.fromBuffer(buffer)

      if (!detectedType || !ALLOWED_IMAGE_MIMES.has(detectedType.mime)) {
        // Delete the invalid file from disk
        await fs.unlink(req.file.path).catch(() => {})
        res.status(500)
        next(new Error('Invalid file content: file does not contain a valid image'))
        return
      }

      next()
    } catch (err) {
      // If we can't read the file, remove it and reject
      if (req.file?.path) {
        await fs.unlink(req.file.path).catch(() => {})
      }
      res.status(500)
      next(new Error('Error validating uploaded file'))
    }
  }
}
