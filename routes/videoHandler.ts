/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import config from 'config'
import { type Request, type Response } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const entities = new Entities()

/* Single byte range as defined by RFC 7233, e.g. "bytes=0-100", "bytes=500-" or "bytes=-500".
   Multiple ranges and non-"bytes" units are deliberately not matched and lead to the header being ignored. */
const SINGLE_BYTE_RANGE_PATTERN = /^bytes=(\d*)-(\d*)$/

type ParsedRange =
  /* Header is well-formed and can be served as 206 Partial Content */
  | { type: 'satisfiable', start: number, end: number }
  /* Header is well-formed but cannot be satisfied for this file, must be answered with 416 */
  | { type: 'unsatisfiable' }
  /* Header is malformed or unsupported, must be ignored and the full entity served instead */
  | { type: 'ignore' }

/**
 * Parses and validates a client-supplied Range header against the actual file size.
 *
 * Never returns NaN, negative, inverted or out-of-bounds offsets, so the result can safely be
 * handed to fs.createReadStream() without risking a synchronous ERR_OUT_OF_RANGE throw (which
 * would surface as a 500 response including a server-side stack trace).
 */
function parseByteRange (rangeHeader: string, fileSize: number): ParsedRange {
  const match = SINGLE_BYTE_RANGE_PATTERN.exec(rangeHeader.trim())
  if (match === null) {
    return { type: 'ignore' }
  }

  const [, rawStart, rawEnd] = match
  if (rawStart === '' && rawEnd === '') {
    return { type: 'ignore' }
  }

  if (rawStart === '') {
    /* Suffix range "bytes=-N": the last N bytes of the file */
    const suffixLength = Number(rawEnd)
    if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0 || fileSize === 0) {
      return { type: 'unsatisfiable' }
    }
    return { type: 'satisfiable', start: Math.max(fileSize - suffixLength, 0), end: fileSize - 1 }
  }

  const start = Number(rawStart)
  const requestedEnd = rawEnd === '' ? fileSize - 1 : Number(rawEnd)
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(requestedEnd)) {
    return { type: 'unsatisfiable' }
  }
  if (start >= fileSize) {
    return { type: 'unsatisfiable' }
  }
  /* An end beyond EOF is clamped, an inverted range is rejected */
  const end = Math.min(requestedEnd, fileSize - 1)
  if (end < start) {
    return { type: 'unsatisfiable' }
  }
  return { type: 'satisfiable', start, end }
}

export const getVideo = () => {
  return (req: Request, res: Response) => {
    const path = videoPath()
    const stat = fs.statSync(path)
    const fileSize = stat.size
    const range = req.headers.range
    const parsedRange = range ? parseByteRange(range, fileSize) : { type: 'ignore' as const }

    if (parsedRange.type === 'unsatisfiable') {
      res.writeHead(416, {
        'Content-Range': `bytes */${fileSize}`,
        'Accept-Ranges': 'bytes'
      })
      res.end()
      return
    }

    if (parsedRange.type === 'satisfiable') {
      const { start, end } = parsedRange
      const chunksize = (end - start) + 1
      const file = fs.createReadStream(path, { start, end })
      const head = {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Location': '/assets/public/videos/owasp_promo.mp4',
        'Content-Type': 'video/mp4'
      }
      res.writeHead(206, head)
      file.on('error', () => { res.destroy() })
      file.pipe(res)
    } else {
      const head = {
        'Content-Length': fileSize,
        'Accept-Ranges': 'bytes',
        'Content-Type': 'video/mp4'
      }
      res.writeHead(200, head)
      const file = fs.createReadStream(path)
      file.on('error', () => { res.destroy() })
      file.pipe(res)
    }
  }
}

export const promotionVideo = () => {
  return (req: Request, res: Response) => {
    fs.readFile('views/promotionVideo.pug', async function (err, buf) {
      if (err != null) throw err
      let template = buf.toString()
      const subs = getSubsFromFile()

      challengeUtils.solveIf(challenges.videoXssChallenge, () => { return subs.includes('</script><script>alert(`xss`)</script>') })

      const themeKey = config.get<string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']
      template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
      template = template.replace(/_favicon_/g, favicon())
      template = template.replace(/_bgColor_/g, theme.bgColor)
      template = template.replace(/_textColor_/g, theme.textColor)
      template = template.replace(/_navColor_/g, theme.navColor)
      template = template.replace(/_primLight_/g, theme.primLight)
      template = template.replace(/_primDark_/g, theme.primDark)
      const pug = (await import('pug')).default
      const fn = pug.compile(template)
      let compiledTemplate = fn()
      compiledTemplate = compiledTemplate.replace('<script id="subtitle"></script>', '<script id="subtitle" type="text/vtt" data-label="English" data-lang="en">' + subs + '</script>')
      res.send(compiledTemplate)
    })
  }
  function favicon () {
    return utils.extractFilename(config.get('application.favicon'))
  }
}

function getSubsFromFile () {
  const subtitles = config.get<string>('application.promotion.subtitles') ?? 'owasp_promo.vtt'
  const data = fs.readFileSync('frontend/dist/frontend/assets/public/videos/' + subtitles, 'utf8')
  return data.toString()
}

function videoPath () {
  if (config.get<string>('application.promotion.video') !== null) {
    const video = utils.extractFilename(config.get<string>('application.promotion.video'))
    return 'frontend/dist/frontend/assets/public/videos/' + video
  }
  return 'frontend/dist/frontend/assets/public/videos/owasp_promo.mp4'
}
