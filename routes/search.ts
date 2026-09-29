/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as models from '../models/index'

class ErrorWithParent extends Error {
  parent: Error | undefined
}

const MAX_CRITERIA_LENGTH = 200

/**
 * Normalizes the `q` query-string parameter into a bounded string.
 *
 * Express exposes repeated or bracketed query parameters as arrays or objects,
 * so anything that is not a plain string is rejected instead of being coerced.
 */
function normalizeCriteria (rawCriteria: unknown): string {
  if (typeof rawCriteria !== 'string' || rawCriteria === 'undefined') {
    return ''
  }
  return rawCriteria.substring(0, MAX_CRITERIA_LENGTH)
}

export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    const criteria = normalizeCriteria(req.query.q)
    // The search term is passed as a bound replacement and never concatenated into
    // the statement, so it cannot terminate the string literal or append operators
    // such as UNION SELECT to read from other tables.
    models.sequelize.query(
      'SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name',
      { replacements: { criteria: `%${criteria}%` } }
    )
      .then(([products]: any) => {
        for (let i = 0; i < products.length; i++) {
          products[i].name = req.__(products[i].name)
          products[i].description = req.__(products[i].description)
        }
        res.json(utils.queryResultToJson(products))
      }).catch((error: ErrorWithParent) => {
        next(error.parent)
      })
  }
}
