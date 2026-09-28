/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { placeOrder } from '../../routes/order'
import { BasketModel } from '../../models/basket'
import { BasketItemModel } from '../../models/basketitem'
import { QuantityModel } from '../../models/quantity'
import { WalletModel } from '../../models/wallet'
import { DeliveryModel } from '../../models/delivery'
import * as db from '../../data/mongodb'
import * as security from '../../lib/insecurity'

void describe('order', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    req = { params: { id: '1' }, body: {}, headers: {}, __: mock.fn((s) => s), socket: { remoteAddress: '127.0.0.1' } }
    res = { json: mock.fn(), status: mock.fn(() => res) }
    next = mock.fn()
    // Reset mocks that might have been set globally or on models
    mock.restoreAll()
  })

  void it('should call next with error if basket does not exist', async () => {
    mock.method(BasketModel, 'findOne', async () => null)

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p as Error

    assert.match(err.message, /Basket with id=1 does not exist/)
  })

  void it('should call next with error if QuantityModel.findOne fails', async () => {
    const basket = {
      id: 1,
      Products: [{
        BasketItem: { ProductId: 1, quantity: 1 },
        price: 10,
        deluxePrice: 5,
        name: 'Product 1',
        id: 1
      }],
      update: mock.fn()
    }
    mock.method(BasketModel, 'findOne', async () => basket)
    mock.method(security.authenticatedUsers, 'from', () => ({ data: { email: 'test@juice-sh.op' } }))
    const error = new Error('Quantity error')
    mock.method(QuantityModel, 'findOne', async () => { throw error })

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p

    assert.equal(err, error)
  })

  void it('should call next with error if QuantityModel.update fails', async () => {
    const basket = {
      id: 1,
      Products: [{
        BasketItem: { ProductId: 1, quantity: 1 },
        price: 10,
        deluxePrice: 5,
        name: 'Product 1',
        id: 1
      }],
      update: mock.fn()
    }
    mock.method(BasketModel, 'findOne', async () => basket)
    mock.method(security.authenticatedUsers, 'from', () => ({ data: { email: 'test@juice-sh.op' } }))
    mock.method(QuantityModel, 'findOne', async () => ({ quantity: 10 }))
    const error = new Error('Quantity update error')
    mock.method(QuantityModel, 'update', async () => { throw error })

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p

    assert.equal(err, error)
  })

  void it('should call next with error if WalletModel.decrement fails', async () => {
    const basket = {
      id: 1,
      Products: [{
        BasketItem: { ProductId: 1, quantity: 1 },
        price: 100,
        deluxePrice: 100,
        name: 'Expensive Product',
        id: 1
      }],
      update: mock.fn()
    }
    mock.method(BasketModel, 'findOne', async () => basket)
    mock.method(security.authenticatedUsers, 'from', () => ({ data: { email: 'test@juice-sh.op' } }))
    mock.method(QuantityModel, 'findOne', async () => ({ quantity: 10 }))
    mock.method(QuantityModel, 'update', async () => [1])
    req.body.UserId = 1
    req.body.orderDetails = { paymentId: 'wallet' }
    mock.method(WalletModel, 'findOne', async () => ({ balance: 1000 }))
    const error = new Error('Wallet decrement error')
    mock.method(WalletModel, 'decrement', async () => { throw error })

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p

    assert.equal(err, error)
  })

  void it('should call next with error if WalletModel.increment fails', async () => {
    const basket = {
      id: 1,
      Products: [{
        BasketItem: { ProductId: 1, quantity: 1 },
        price: 10,
        deluxePrice: 5,
        name: 'Product 1',
        id: 1
      }],
      update: mock.fn(),
      coupon: null
    }
    mock.method(BasketModel, 'findOne', async () => basket)
    mock.method(security.authenticatedUsers, 'from', () => ({ data: { email: 'test@juice-sh.op' } }))
    mock.method(QuantityModel, 'findOne', async () => ({ quantity: 10 }))
    mock.method(QuantityModel, 'update', async () => [1])
    req.body.UserId = 1
    const error = new Error('Wallet increment error')
    mock.method(WalletModel, 'increment', async () => { throw error })

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p

    assert.equal(err, error)
  })

  void it('should call next with error if DeliveryModel.findOne fails', async () => {
    const basket = {
      id: 1,
      Products: [],
      update: mock.fn(),
      coupon: null
    }
    mock.method(BasketModel, 'findOne', async () => basket)
    mock.method(security.authenticatedUsers, 'from', () => ({ data: { email: 'test@juice-sh.op' } }))
    req.body.orderDetails = { deliveryMethodId: 1 }
    const error = new Error('Delivery error')
    mock.method(DeliveryModel, 'findOne', async () => { throw error })

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p

    assert.equal(err, error)
  })

  void it('should call next with error if ordersCollection.insert fails', async () => {
    const basket = {
      id: 1,
      Products: [],
      update: mock.fn(),
      coupon: null
    }
    mock.method(BasketModel, 'findOne', async () => basket)
    mock.method(security.authenticatedUsers, 'from', () => ({ data: { email: 'test@juice-sh.op' } }))
    const error = new Error('Insert error')
    mock.method(db.ordersCollection, 'insert', async () => { throw error })

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p

    assert.equal(err, error)
  })

  void it('should call next with error if BasketItemModel.destroy fails', async () => {
    const basket = {
      id: 1,
      Products: [],
      update: mock.fn(async () => {}),
      coupon: null
    }
    mock.method(BasketModel, 'findOne', async () => basket)
    mock.method(security.authenticatedUsers, 'from', () => ({ data: { email: 'test@juice-sh.op' } }))
    const error = new Error('Destroy error')
    mock.method(BasketItemModel, 'destroy', async () => { throw error })
    mock.method(db.ordersCollection, 'insert', async () => {})

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p

    assert.equal(err, error)
  })

  const campaignBasket = () => ({
    id: 1,
    Products: [{
      BasketItem: { ProductId: 1, quantity: 1 },
      price: 100,
      deluxePrice: 100,
      name: 'Product 1',
      id: 1
    }],
    update: mock.fn(async () => {}),
    coupon: null
  })

  const placeOrderWithCouponData = async (couponData: string) => {
    req.body.couponData = couponData

    mock.method(BasketModel, 'findOne', async () => campaignBasket())
    mock.method(security.authenticatedUsers, 'from', () => ({ data: { email: 'test@juice-sh.op' } }))
    mock.method(QuantityModel, 'findOne', async () => ({ quantity: 10 }))
    mock.method(QuantityModel, 'update', async () => {})
    mock.method(BasketItemModel, 'destroy', async () => {})
    mock.method(WalletModel, 'increment', async () => {})

    const p = new Promise<any>((resolve) => {
      mock.method(db.ordersCollection, 'insert', async (order: any) => { resolve(order) })
    })

    placeOrder()(req, res, next)
    return await p
  }

  void it('should not apply the discount of an expired campaign even if the client claims it is valid', async () => {
    const validOn = new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime()
    const couponData = Buffer.from(`WMNSDY2019-${validOn}`).toString('base64')

    const order = await placeOrderWithCouponData(couponData)

    assert.equal(order.promotionalAmount, '0')
    assert.equal(order.totalPrice, 100)
  })

  void it('should apply the discount of a campaign that is active according to the server clock', async () => {
    const validOn = new Date('Mar 08, 2019 00:00:00 GMT+0100').getTime()
    // The client claims a date on which the campaign was already over, the server clock decides.
    const couponData = Buffer.from(`WMNSDY2019-${validOn + 10 * 24 * 60 * 60 * 1000}`).toString('base64')

    mock.timers.enable({ apis: ['Date'], now: validOn + 60 * 60 * 1000 })
    try {
      const order = await placeOrderWithCouponData(couponData)

      assert.equal(order.promotionalAmount, '75.00')
      assert.equal(order.totalPrice, 25)
    } finally {
      mock.timers.reset()
    }
  })

  void it('should ignore coupon data that does not reference a known campaign', async () => {
    const couponData = Buffer.from('constructor-0').toString('base64')

    const order = await placeOrderWithCouponData(couponData)

    assert.equal(order.promotionalAmount, '0')
    assert.equal(order.totalPrice, 100)
  })

  void it('should call next with error if wallet balance is insufficient', async () => {
    const basket = {
      id: 1,
      Products: [{
        BasketItem: { ProductId: 1, quantity: 1 },
        price: 100,
        deluxePrice: 100,
        name: 'Expensive Product',
        id: 1
      }],
      update: mock.fn()
    }
    mock.method(BasketModel, 'findOne', async () => basket)
    mock.method(security.authenticatedUsers, 'from', () => ({ data: { email: 'test@juice-sh.op' } }))
    mock.method(QuantityModel, 'findOne', async () => ({ quantity: 10 }))
    mock.method(QuantityModel, 'update', async () => [1])
    req.body.UserId = 1
    req.body.orderDetails = { paymentId: 'wallet' }
    mock.method(WalletModel, 'findOne', async () => ({ balance: 10 }))

    const p = new Promise((resolve) => {
      next = (err: any) => { resolve(err) }
    })

    placeOrder()(req, res, next)
    const err = await p as Error

    assert.match(err.message, /Insufficient wallet balance/)
  })
})
