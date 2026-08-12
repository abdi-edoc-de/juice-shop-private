/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { AddressModel } from '../models/address'

export function getAddress () {
  return async (req: Request, res: Response) => {
    const addresses = await AddressModel.findAll({ where: { UserId: req.body.UserId } })
    res.status(200).json({ status: 'success', data: addresses })
  }
}

export function getAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

export function putAddress () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address != null) {
      try {
        const updatedAddress = await address.update({
          fullName: req.body.fullName ?? address.fullName,
          mobileNum: req.body.mobileNum ?? address.mobileNum,
          zipCode: req.body.zipCode ?? address.zipCode,
          streetAddress: req.body.streetAddress ?? address.streetAddress,
          city: req.body.city ?? address.city,
          state: req.body.state ?? address.state,
          country: req.body.country ?? address.country
        })
        res.status(200).json({ status: 'success', data: updatedAddress })
      } catch (error: any) {
        if (error.name === 'SequelizeValidationError') {
          res.status(400).json({ status: 'error', data: error.errors?.map((e: any) => e.message) ?? 'Validation error' })
        } else {
          throw error
        }
      }
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

export function delAddressById () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.destroy({ where: { id: req.params.id, UserId: req.body.UserId } })
    if (address) {
      res.status(200).json({ status: 'success', data: 'Address deleted successfully.' })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}
