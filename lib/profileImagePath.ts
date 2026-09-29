/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'

export const PROFILE_IMAGE_UPLOAD_DIRECTORY = 'frontend/dist/frontend/assets/public/images/uploads'

/**
 * Resolves the absolute destination for the profile image of the given user id.
 *
 * The user id originates from the (potentially tampered) JWT payload, therefore it is strictly
 * validated as an integer, reduced to its base name and finally verified to resolve to a direct
 * child of the uploads directory. Any id that could escape that directory yields `null` so that
 * callers can reject the request instead of writing to an arbitrary location.
 */
export function resolveProfileImagePath (userId: unknown, ext: string): string | null {
  if (!/^\d+$/.test(String(userId))) { // ids issued by the application are always integers
    return null
  }
  if (!/^[a-z0-9]+$/i.test(ext)) {
    return null
  }
  const uploadDirectory = path.resolve(PROFILE_IMAGE_UPLOAD_DIRECTORY)
  const fileName = path.basename(`${String(userId)}.${ext}`)
  const filePath = path.resolve(uploadDirectory, fileName)
  if (path.dirname(filePath) !== uploadDirectory) {
    return null
  }
  return filePath
}
