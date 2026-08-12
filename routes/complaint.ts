/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { ComplaintModel } from '../models/complaint'
import * as security from '../lib/insecurity'

export function getComplaints () {
  return async (req: Request, res: Response) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    const UserId = loggedInUser?.data?.id
    if (!UserId) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }
    const complaints = await ComplaintModel.findAll({ where: { UserId } })
    res.status(200).json({ status: 'success', data: complaints })
  }
}
