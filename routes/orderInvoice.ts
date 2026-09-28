/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'

/*
 * Order confirmation PDFs contain customer PII (e-mail address, ordered products, prices and
 * bonus points) and must therefore never be written into a publicly browsable folder like 'ftp/'.
 * They are stored in this dedicated directory which is not exposed by any static file route and
 * can only be read through serveOrderInvoice() by the customer who placed the order.
 */
export const invoiceDirectory = path.resolve('invoices')

/** Order ids are generated as `<4 hex chars>-<16 hex chars>` - anything else is rejected. */
const ORDER_ID_PATTERN = /^[a-f0-9]{1,64}-[a-f0-9]{1,64}$/i

export const invoiceFileName = (orderId: string) => `order_${orderId}.pdf`

export const invoicePath = (orderId: string) => path.join(invoiceDirectory, invoiceFileName(orderId))

export const ensureInvoiceDirectoryExists = () => {
  fs.mkdirSync(invoiceDirectory, { recursive: true })
}

export const isInvoiceFileName = (fileName: string) => /^order_.*\.pdf$/i.test(fileName)

export function serveOrderInvoice () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.from(req)
    if (!loggedInUser?.data?.email) {
      res.status(401)
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    const orderId = req.params.orderId
    if (!orderId || !ORDER_ID_PATTERN.test(orderId)) {
      res.status(400)
      next(new Error('Invalid order id'))
      return
    }

    // Orders are persisted with the same masked e-mail address that /rest/order-history filters on
    const maskedEmail = loggedInUser.data.email.replace(/[aeiou]/gi, '*')
    const order = await ordersCollection.findOne({ orderId })
    const file = invoicePath(orderId)

    if (!order || !order.email || order.email !== maskedEmail || !fs.existsSync(file)) {
      res.status(404)
      next(new Error('Order invoice not found'))
      return
    }

    res.type('application/pdf')
    res.sendFile(file)
  }
}
