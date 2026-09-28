/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketModel } from '../models/basket'
import * as security from '../lib/insecurity'

export function applyCoupon () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const { params, body } = req
    try {
      const id = params.id
      let coupon: string | undefined | null = params.coupon ? decodeURIComponent(params.coupon) : undefined
      const discount = security.discountFromCoupon(coupon)
      coupon = discount ? coupon : null

      /* Coupons can only be applied to the basket of the authenticated user (see security.appendUserId) */
      const basket = await BasketModel.findOne({ where: { id, UserId: body.UserId } })
      if (!basket) {
        next(new Error(`Basket with id=${id} does not exist.`))
        return
      }

      await basket.update({ coupon: coupon?.toString() })
      if (discount) {
        return res.json({ discount })
      } else {
        return res.status(404).send('Invalid coupon.')
      }
    } catch (error) {
      next(error)
    }
  }
}
