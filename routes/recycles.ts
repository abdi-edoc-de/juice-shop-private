/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'

import * as utils from '../lib/utils'

export const getRecycleItem = () => async (req: Request, res: Response) => {
  // The path parameter has to be a plain numeric id so it cannot widen the
  // selector of the where clause into an array or an operator object.
  if (!/^\d+$/.test(req.params.id)) {
    res.status(400).json(utils.queryResultToJson('Invalid recycle id.', 'error'))
    return
  }
  const recycle = await RecycleModel.findOne({ where: { id: Number.parseInt(req.params.id, 10), UserId: req.body.UserId } })
  if (recycle == null) {
    res.status(400).json(utils.queryResultToJson('Malicious activity detected.', 'error'))
    return
  }
  res.status(200).json(utils.queryResultToJson([recycle]))
}

export const blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
