/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import { type Request, type Response, type NextFunction } from 'express'
import { MemoryModel } from '../models/memory'
import { UserModel } from '../models/user'

/**
 * Removes an already uploaded file from disk again if the request it belonged to
 * did not complete successfully. Without this, rejected requests (e.g. missing
 * authorization) would leave orphaned files behind which are not referenced by
 * any memory record but are still served publicly.
 */
export function discardUploadOnFailure (req: Request, res: Response, next: NextFunction) {
  res.once('close', () => {
    const filePath = req.file?.path
    const failed = res.statusCode >= 400 || !res.writableEnded
    if (filePath && failed) {
      void fs.unlink(filePath).catch(() => { /* file is already gone - nothing to clean up */ })
    }
  })
  next()
}

export function addMemory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const record = {
      caption: req.body.caption,
      imagePath: 'assets/public/images/uploads/' + req.file?.filename,
      UserId: req.body.UserId
    }
    const memory = await MemoryModel.create(record)
    res.status(200).json({ status: 'success', data: memory })
  }
}

export function getMemories () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const memories = await MemoryModel.findAll({ include: [UserModel] })
    res.status(200).json({ status: 'success', data: memories })
  }
}
