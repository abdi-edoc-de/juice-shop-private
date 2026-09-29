/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { Op } from 'sequelize'
import { BasketItemModel } from '../models/basketitem'
import { BasketModel } from '../models/basket'
import { QuantityModel } from '../models/quantity'
import * as challengeUtils from '../lib/challengeUtils'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

interface RequestWithRawBody extends Request {
  rawBody: string
}

export function addBasketItem () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const result = utils.parseJsonCustom((req as RequestWithRawBody).rawBody)
    const productIds = []
    const basketIds = []
    const quantities = []

    for (let i = 0; i < result.length; i++) {
      if (result[i].key === 'ProductId') {
        productIds.push(result[i].value)
      } else if (result[i].key === 'BasketId') {
        basketIds.push(result[i].value)
      } else if (result[i].key === 'quantity') {
        quantities.push(result[i].value)
      }
    }

    const user = security.authenticatedUsers.from(req)
    if (user && basketIds[0] && basketIds[0] !== 'undefined' && Number(user.bid) != Number(basketIds[0])) { // eslint-disable-line eqeqeq
      res.status(401).send('{\'error\' : \'Invalid BasketId\'}')
    } else {
      const basketItem = {
        ProductId: productIds[productIds.length - 1],
        BasketId: basketIds[basketIds.length - 1],
        quantity: quantities[quantities.length - 1]
      }
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && basketItem.BasketId && basketItem.BasketId !== 'undefined' && user.bid != basketItem.BasketId }) // eslint-disable-line eqeqeq

      const basketItemInstance = BasketItemModel.build(basketItem)
      try {
        const addedBasketItem = await basketItemInstance.save()
        res.json({ status: 'success', data: addedBasketItem })
      } catch (error) {
        next(error)
      }
    }
  }
}

export function quantityCheckBeforeBasketItemAddition () {
  return (req: Request, res: Response, next: NextFunction) => {
    void quantityCheck(req, res, next, req.body.ProductId, req.body.quantity).catch((error: Error) => {
      next(error)
    })
  }
}
export function quantityCheckBeforeBasketItemUpdate () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const item = await BasketItemModel.findOne({ where: { id: req.params.id } })
      const user = security.authenticatedUsers.from(req)
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => { return user && req.body.BasketId && user.bid != req.body.BasketId }) // eslint-disable-line eqeqeq
      if (req.body.quantity) {
        if (item == null) {
          throw new Error('No such item found!')
        }
        void quantityCheck(req, res, next, item.ProductId, req.body.quantity)
      } else {
        next()
      }
    } catch (error) {
      next(error)
    }
  }
}

async function quantityCheck (req: Request, res: Response, next: NextFunction, id: number, quantity: number) {
  const product = await QuantityModel.findOne({ where: { ProductId: id } })
  if (product == null) {
    throw new Error('No such product found!')
  }

  // is product limited per user and order, except if user is deluxe?
  if (!product.limitPerUser || (product.limitPerUser && product.limitPerUser >= quantity) || security.isDeluxe(req)) {
    if (product.quantity >= quantity) { // enough in stock?
      next()
    } else {
      res.status(400).json({ error: res.__('We are out of stock! Sorry for the inconvenience.') })
    }
  } else {
    res.status(400).json({ error: res.__('You can order only up to {{quantity}} items of this product.', { quantity: product.limitPerUser.toString() }) })
  }
}

/* Resolves the basket ids owned by the currently authenticated user. */
async function ownedBasketIds (req: Request) {
  const userId = security.authenticatedUsers.from(req)?.data?.id
  if (!userId) {
    return []
  }
  const baskets = await BasketModel.findAll({ where: { UserId: userId }, attributes: ['id'] })
  return baskets.map((basket) => basket.id)
}

/* Only returns the basket items belonging to a basket of the authenticated user instead of the whole table. */
export function getBasketItems () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const basketIds = await ownedBasketIds(req)
      if (basketIds.length === 0) {
        res.json([])
        return
      }
      const basketItems = await BasketItemModel.findAll({ where: { BasketId: { [Op.in]: basketIds } } })
      res.json(basketItems)
    } catch (error) {
      next(error)
    }
  }
}

/* Only returns a basket item if it belongs to a basket of the authenticated user, otherwise it is indistinguishable from a non-existing one. */
export function getBasketItemById () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const id = Number(req.params.id)
      if (!Number.isInteger(id)) {
        res.status(404).json({ message: 'Not Found', errors: [] })
        return
      }
      const basketIds = await ownedBasketIds(req)
      const basketItem = basketIds.length > 0
        ? await BasketItemModel.findOne({ where: { id, BasketId: { [Op.in]: basketIds } } })
        : null
      if (basketItem == null) {
        res.status(404).json({ message: 'Not Found', errors: [] })
        return
      }
      res.json({ status: 'success', data: basketItem })
    } catch (error) {
      next(error)
    }
  }
}
