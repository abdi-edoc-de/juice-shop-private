/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { MemoryModel } from '../models/memory'
import { UserModel } from '../models/user'

// The photo wall is a public feature, so only the bare minimum of uploader data
// may be serialised here. Never expand this list with sensitive columns such as
// email, password, role, deluxeToken, lastLoginIp or totpSecret.
const PUBLIC_UPLOADER_ATTRIBUTES = ['id', 'username'] as const

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
    const memories = await MemoryModel.findAll({
      include: [{
        model: UserModel,
        attributes: [...PUBLIC_UPLOADER_ATTRIBUTES]
      }]
    })
    res.status(200).json({ status: 'success', data: memories })
  }
}
