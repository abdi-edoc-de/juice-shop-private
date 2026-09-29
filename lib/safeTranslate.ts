/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import i18n from 'i18n'
import { type Request } from 'express'

/**
 * Translates database-sourced text without handing it to a template engine.
 *
 * The i18n `__()` helper renders its argument with Mustache whenever it contains
 * `{{ }}` constructs. Passing user-writable text (e.g. product names and
 * descriptions, which can be changed through the REST API) into it turns stored
 * strings into server-side templates that are compiled and executed on every
 * read: injected templates get evaluated, and malformed ones raise engine
 * exceptions which break shared endpoints for all readers while leaking parser
 * internals in the error response.
 *
 * This helper only performs a plain lookup in the locale catalog of the current
 * request and falls back to the original text, so the text is never compiled and
 * no interpolation is performed on it.
 */
export function translateWithoutTemplating (req: Request, text: string): string {
  const catalog = resolveCatalog(req)
  if (catalog && Object.prototype.hasOwnProperty.call(catalog, text)) {
    const translation = catalog[text]
    if (typeof translation === 'string') {
      return translation
    }
  }
  return text
}

function resolveCatalog (req: Request): Record<string, unknown> | undefined {
  try {
    const catalog: unknown = i18n.getCatalog(i18n.getLocale(req))
    if (catalog !== null && typeof catalog === 'object') {
      return catalog as Record<string, unknown>
    }
  } catch {
    // no catalog available (e.g. i18n not initialized yet) -> fall back to the original text
  }
  return undefined
}
