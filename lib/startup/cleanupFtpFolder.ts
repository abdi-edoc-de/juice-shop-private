/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { glob } from 'glob'
import logger from '../logger'
import fs from 'fs-extra'
import * as utils from '../utils'

const cleanupFtpFolder = async () => {
  // 'ftp/*.pdf' is included to also remove order invoices left behind by previous versions
  // which used to write them into the publicly browsable /ftp folder
  for (const pattern of ['ftp/*.pdf', 'invoices/*.pdf']) {
    try {
      const files = await glob(pattern, { windowsPathsNoEscape: true })
      for (const filename of files) {
        await fs.remove(filename)
      }
    } catch (err) {
      logger.warn(`Error listing PDF files in ${pattern}: ` + utils.getErrorMessage(err))
    }
  }
}
export default cleanupFtpFolder
