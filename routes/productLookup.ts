/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as models from '../models/index'

// DEMO vulnerability: unsanitized user input is concatenated directly into a
// raw SQL query. Exposed at GET /rest/products/lookup?name=... and reachable
// on the deployed endpoint, so a CI/CD pentest can exploit it live
// (e.g. ?name=') UNION SELECT ... -- ) and extract arbitrary rows.
export function lookupProduct () {
  return (req: Request, res: Response, next: NextFunction) => {
    const name = req.query.name ?? ''
    models.sequelize
      .query(`SELECT * FROM Products WHERE name = '${name}' AND deletedAt IS NULL`)
      .then(([products]: any) => {
        res.json(utils.queryResultToJson(products))
      })
      .catch((error: Error) => {
        next(error)
      })
  }
}
