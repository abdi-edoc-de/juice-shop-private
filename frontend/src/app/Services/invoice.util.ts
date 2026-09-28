/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/**
 * Opens an order invoice which was downloaded via the authenticated
 * /rest/order-history/:orderId/invoice endpoint in a new browser tab.
 */
export function openInvoiceInNewTab (invoice: Blob) {
  const url = URL.createObjectURL(invoice)
  window.open(url, '_blank')
  setTimeout(() => { URL.revokeObjectURL(url) }, 10000)
}
