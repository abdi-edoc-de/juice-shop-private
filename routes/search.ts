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

function normalizeCriteria (q: Request['query']['q']): string {
  const raw = Array.isArray(q) ? q[0] : q
  if (raw === undefined || raw === null || typeof raw !== 'string' || raw === 'undefined') {
    return ''
  }
  return raw.length <= MAX_CRITERIA_LENGTH ? raw : raw.substring(0, MAX_CRITERIA_LENGTH)
}

// Escape the LIKE wildcards so that user input is always matched literally.
function escapeLikePattern (criteria: string): string {
  return criteria.replace(/[\\%_]/g, (character) => `\\${character}`)
}

export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    const criteria = normalizeCriteria(req.query.q)
    // The search term is passed as a bound parameter, never concatenated into the statement,
    // so it can neither terminate the string literal nor append additional SQL (e.g. UNION SELECT).
    models.sequelize.query(
      "SELECT * FROM Products WHERE ((name LIKE $criteria ESCAPE '\\' OR description LIKE $criteria ESCAPE '\\') AND deletedAt IS NULL) ORDER BY name",
      { bind: { criteria: `%${escapeLikePattern(criteria)}%` } }
    )
      .then(([products]: any) => {
        for (let i = 0; i < products.length; i++) {
          products[i].name = req.__(products[i].name)
          products[i].description = req.__(products[i].description)
        }
        res.json(utils.queryResultToJson(products))
      }).catch((error: ErrorWithParent) => {
        next(error.parent ?? error)
      })
  }
}
