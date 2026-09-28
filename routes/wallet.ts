/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { WalletModel } from '../models/wallet'
import { CardModel } from '../models/card'

// Server-side top-up bounds. The wallet form in the SPA applies the same limits,
// but client-side validators can be bypassed by calling the API directly, so the
// authoritative check has to happen here.
const MIN_TOP_UP_AMOUNT = 10
const MAX_TOP_UP_AMOUNT = 1000

export function getWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } })
    if (wallet != null) {
      res.status(200).json({ status: 'success', data: wallet.balance })
    } else {
      res.status(404).json({ status: 'error' })
    }
  }
}

/**
 * Turns an untrusted top-up amount into a positive amount within the allowed
 * bounds and rounded to two decimals, or returns null if it cannot be accepted.
 */
function parseTopUpAmount (rawAmount: unknown): number | null {
  if (typeof rawAmount !== 'number' && typeof rawAmount !== 'string') {
    return null
  }
  const amount = typeof rawAmount === 'string' ? Number(rawAmount.trim()) : rawAmount
  if (!Number.isFinite(amount) || amount < MIN_TOP_UP_AMOUNT || amount > MAX_TOP_UP_AMOUNT) {
    return null
  }
  return Math.round(amount * 100) / 100
}

export function addWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const amount = parseTopUpAmount(req.body.balance)
    if (amount === null) {
      res.status(400).json({
        status: 'error',
        message: `Invalid top-up amount. Must be a number between ${MIN_TOP_UP_AMOUNT} and ${MAX_TOP_UP_AMOUNT}.`
      })
      return
    }
    const cardId = req.body.paymentId
    const card = cardId ? await CardModel.findOne({ where: { id: cardId, UserId: req.body.UserId } }) : null
    if (card != null) {
      try {
        await WalletModel.increment({ balance: amount }, { where: { UserId: req.body.UserId } })
        res.status(200).json({ status: 'success', data: amount })
      } catch {
        res.status(404).json({ status: 'error' })
      }
    } else {
      res.status(402).json({ status: 'error', message: 'Payment not accepted.' })
    }
  }
}
