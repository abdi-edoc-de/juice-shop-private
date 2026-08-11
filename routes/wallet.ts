/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { WalletModel } from '../models/wallet'
import { CardModel } from '../models/card'

const MAX_WALLET_DEPOSIT = 1000
const MIN_WALLET_DEPOSIT = 10

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

export function addWalletBalance () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const balance = req.body.balance
    if (!Number.isFinite(balance) || balance <= 0) {
      res.status(400).json({ status: 'error', message: 'Invalid balance amount. Amount must be a positive number.' })
      return
    }
    if (balance < MIN_WALLET_DEPOSIT) {
      res.status(400).json({ status: 'error', message: `Minimum deposit is ${MIN_WALLET_DEPOSIT}.` })
      return
    }
    if (balance > MAX_WALLET_DEPOSIT) {
      res.status(400).json({ status: 'error', message: `Deposit amount exceeds the maximum of ${MAX_WALLET_DEPOSIT}.` })
      return
    }
    if (!Number.isInteger(balance)) {
      res.status(400).json({ status: 'error', message: 'Invalid balance amount. Amount must be a whole number.' })
      return
    }
    const cardId = req.body.paymentId
    const card = cardId ? await CardModel.findOne({ where: { id: cardId, UserId: req.body.UserId } }) : null
    if (card != null) {
      try {
        await WalletModel.increment({ balance }, { where: { UserId: req.body.UserId } })
        res.status(200).json({ status: 'success', data: balance })
      } catch {
        res.status(404).json({ status: 'error' })
      }
    } else {
      res.status(402).json({ status: 'error', message: 'Payment not accepted.' })
    }
  }
}
