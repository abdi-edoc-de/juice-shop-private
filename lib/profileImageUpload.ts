/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'

export const PROFILE_IMAGE_UPLOAD_DIRECTORY = 'frontend/dist/frontend/assets/public/images/uploads'

const RESOLVED_UPLOAD_DIRECTORY = path.resolve(PROFILE_IMAGE_UPLOAD_DIRECTORY)

/**
 * Coerces an (untrusted) user id - e.g. taken from a JWT payload - into a positive integer.
 *
 * Returns `null` for anything that is not an exact decimal representation of a positive
 * safe integer, which rules out path traversal sequences, absolute paths, null bytes and
 * other filesystem metacharacters before they can ever reach a file path.
 */
export function toUserId (id: unknown): number | null {
  if (typeof id !== 'number' && typeof id !== 'string') return null
  const asString = String(id)
  if (!/^\d+$/.test(asString)) return null
  const asNumber = Number(asString)
  if (!Number.isSafeInteger(asNumber) || asNumber <= 0) return null
  return asNumber
}

/**
 * Normalizes an image file extension to lowercase and returns `null` unless it consists
 * of a short, purely alphanumeric sequence (no dots, separators or null bytes).
 */
export function toImageExtension (ext: unknown): string | null {
  if (typeof ext !== 'string') return null
  const normalized = ext.toLowerCase()
  return /^[a-z0-9]{1,8}$/.test(normalized) ? normalized : null
}

/**
 * Builds the destination path of a profile image upload from an already validated integer
 * user id and image extension, and asserts that the result is contained directly within
 * the uploads directory.
 *
 * @throws Error if the resulting path would escape the uploads directory.
 */
export function profileImageUploadPath (userId: number, ext: string): string {
  const filePath = path.resolve(RESOLVED_UPLOAD_DIRECTORY, `${userId}.${ext}`)
  if (path.dirname(filePath) !== RESOLVED_UPLOAD_DIRECTORY) {
    throw new Error('Invalid profile image upload destination')
  }
  return filePath
}
