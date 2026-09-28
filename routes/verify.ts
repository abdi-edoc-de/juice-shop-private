/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type NextFunction, type Request, type Response } from 'express'
import { Op, col, fn, where as sequelizeWhere } from 'sequelize'
import jwt from 'jsonwebtoken'
import config from 'config'
import jws from 'jws'

import { challenges, products, retrieveBlueprintChallengeFile } from '../data/datacache'
import type { Product as ProductConfig } from '../lib/config.schema'
import { type Challenge, type Product } from '../data/types'
import * as challengeUtils from '../lib/challengeUtils'
import * as antiCheat from '../lib/antiCheat'
import { ComplaintModel } from '../models/complaint'
import { FeedbackModel } from '../models/feedback'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'
import { buildSystemPrompt } from './chat'

export const emptyUserRegistration = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.emptyUserRegistration, () => {
    return req.body && req.body.email === '' && req.body.password === ''
  })
  next()
}

export const forgedFeedbackChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.forgedFeedbackChallenge, () => {
    const user = security.authenticatedUsers.from(req)
    const userId = user?.data ? user.data.id : undefined
    return req.body?.UserId && req.body.UserId != userId // eslint-disable-line eqeqeq
  })
  next()
}

export const captchaBypassChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  if (challengeUtils.notSolved(challenges.captchaBypassChallenge)) {
    if (req.app.locals.captchaReqId >= 10) {
      if ((new Date().getTime() - req.app.locals.captchaBypassReqTimes[req.app.locals.captchaReqId - 10]) <= 20000) {
        challengeUtils.solve(challenges.captchaBypassChallenge)
      }
    }
    req.app.locals.captchaBypassReqTimes[req.app.locals.captchaReqId - 1] = new Date().getTime()
    req.app.locals.captchaReqId++
  }
  next()
}

export const registerAdminChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.registerAdminChallenge, () => {
    return req.body && req.body.role === security.roles.admin
  })
  next()
}

export const passwordRepeatChallenge = () => (req: Request, res: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.passwordRepeatChallenge, () => { return req.body && req.body.passwordRepeat !== req.body.password })
  next()
}

export const accessControlChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  const { url } = req
  const uiBypassed = req.header('sec-fetch-dest') === 'document' || !req.header('referer')
  challengeUtils.solveIf(challenges.scoreBoardChallenge, () => { return url.endsWith('/1px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.web3SandboxChallenge, () => { return url.endsWith('/11px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.adminSectionChallenge, () => { return url.endsWith('/19px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.tokenSaleChallenge, () => { return url.endsWith('/56px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.privacyPolicyChallenge, () => { return url.endsWith('/81px.png') }, false, uiBypassed)
  challengeUtils.solveIf(challenges.extraLanguageChallenge, () => { return url.endsWith('/tlh_AA.json') })
  challengeUtils.solveIf(challenges.retrieveBlueprintChallenge, () => { return url.endsWith(retrieveBlueprintChallengeFile ?? '') })
  challengeUtils.solveIf(challenges.securityPolicyChallenge, () => { return url.endsWith('/security.txt') })
  challengeUtils.solveIf(challenges.missingEncodingChallenge, () => { return url.toLowerCase().endsWith('%e1%93%9a%e1%98%8f%e1%97%a2-%23zatschi-%23whoneedsfourlegs-1572600969477.jpg') })
  challengeUtils.solveIf(challenges.accessLogDisclosureChallenge, () => { return url.match(/access\.log(0-9-)*/) })
  challengeUtils.solveIf(challenges.misplacedIacFiles, () => { return (url.endsWith('.tf') || url.endsWith('Dockerfile') || url.endsWith('docker-compose.yml')) })
  next()
}

export const errorHandlingChallenge = () => (err: unknown, req: Request, { statusCode }: Response, next: NextFunction) => {
  challengeUtils.solveIf(challenges.errorHandlingChallenge, () => { return err && (statusCode === 200 || statusCode > 401) })
  next(err)
}

export const jwtChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  if (challengeUtils.notSolved(challenges.jwtUnsignedChallenge)) {
    jwtChallenge(challenges.jwtUnsignedChallenge, req, 'none', /jwtn3d@/)
  }
  if (utils.isChallengeEnabled(challenges.jwtForgedChallenge) && challengeUtils.notSolved(challenges.jwtForgedChallenge)) {
    jwtChallenge(challenges.jwtForgedChallenge, req, 'HS256', /rsa_lord@/)
  }
  if (challengeUtils.notSolved(challenges.iacLeakedKeyChallenge)) {
    jwtChallenge(challenges.iacLeakedKeyChallenge, req, 'RS256', /cloud-admin@/)
  }
  next()
}

export const serverSideChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  if (req.query.key === 'tRy_H4rd3r_n0thIng_iS_Imp0ssibl3') {
    if (challengeUtils.notSolved(challenges.sstiChallenge) && req.app.locals.abused_ssti_bug === true) {
      challengeUtils.solve(challenges.sstiChallenge)
      res.status(204).send()
      return
    }

    if (challengeUtils.notSolved(challenges.ssrfChallenge) && req.app.locals.abused_ssrf_bug === true) {
      challengeUtils.solve(challenges.ssrfChallenge)
      res.status(204).send()
      return
    }
  }
  next()
}

function jwtChallenge (challenge: Challenge, req: Request, algorithm: string, email: string | RegExp) {
  const token = utils.jwtFrom(req)
  if (token) {
    const decoded = jws.decode(token) ? jwt.decode(token) : null

    if (decoded === null || typeof decoded === 'string') {
      return
    }

    jwt.verify(token, security.publicKey, (err: jwt.VerifyErrors | null) => {
      if (err === null) {
        challengeUtils.solveIf(challenge, () => {
          return hasAlgorithm(token, algorithm) && hasEmail(decoded as { data: { email: string } }, email)
        })
      }
    })
  }
}

function hasAlgorithm (token: string, algorithm: string) {
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString())
  return token && header && header.alg === algorithm
}

function hasEmail (token: { data: { email: string } }, email: string | RegExp) {
  return token?.data?.email?.match(email)
}

async function checkPatternInFeedbackAndComplaints (
  challenge: Challenge,
  fieldCriteria: any
): Promise<void> {
  const feedbackCheck = FeedbackModel.findAndCountAll({
    where: { comment: fieldCriteria }
  }).then(({ count, rows }: { count: number, rows: any[] }) => {
    if (count > 0) {
      const isCheating = rows.some((row: any) => antiCheat.checkForSourceFileOverlap(challenge.key, row.comment ?? ''))
      challengeUtils.solve(challenge, false, isCheating)
    }
  }).catch(() => {
    throw new Error('Unable to retrieve feedback details. Please try again')
  })

  const complaintCheck = ComplaintModel.findAndCountAll({
    where: { message: fieldCriteria }
  }).then(({ count, rows }: { count: number, rows: any[] }) => {
    if (count > 0) {
      const isCheating = rows.some((row: any) => antiCheat.checkForSourceFileOverlap(challenge.key, row.message ?? ''))
      challengeUtils.solve(challenge, false, isCheating)
    }
  }).catch(() => {
    throw new Error('Unable to retrieve complaint details. Please try again')
  })

  await Promise.all([feedbackCheck, complaintCheck])
}

export const databaseRelatedChallenges = () => (req: Request, res: Response, next: NextFunction) => {
  if (challengeUtils.notSolved(challenges.changeProductChallenge) && products.osaft) {
    changeProductChallenge(products.osaft)
  }
  if (challengeUtils.notSolved(challenges.feedbackChallenge)) {
    feedbackChallenge()
  }
  if (challengeUtils.notSolved(challenges.knownVulnerableComponentChallenge)) {
    knownVulnerableComponentChallenge()
  }
  if (challengeUtils.notSolved(challenges.weirdCryptoChallenge)) {
    weirdCryptoChallenge()
  }
  if (challengeUtils.notSolved(challenges.typosquattingNpmChallenge)) {
    typosquattingNpmChallenge()
  }
  if (challengeUtils.notSolved(challenges.typosquattingAngularChallenge)) {
    typosquattingAngularChallenge()
  }
  if (challengeUtils.notSolved(challenges.hiddenImageChallenge)) {
    hiddenImageChallenge()
  }
  if (challengeUtils.notSolved(challenges.supplyChainAttackChallenge)) {
    supplyChainAttackChallenge()
  }
  if (challengeUtils.notSolved(challenges.dlpPastebinDataLeakChallenge)) {
    dlpPastebinDataLeakChallenge()
  }
  if (challengeUtils.notSolved(challenges.csafChallenge)) {
    csafChallenge()
  }
  if (challengeUtils.notSolved(challenges.leakedApiKeyChallenge)) {
    leakedApiKeyChallenge()
  }
  if (challengeUtils.notSolved(challenges.vulnerableDockerImageChallenge)) {
    vulnerableDockerImageChallenge()
  }
  if (challengeUtils.notSolved(challenges.systemPromptExtractionChallenge)) {
    void systemPromptExtractionChallenge()
  }
  next()
}

function changeProductChallenge (osaft: Product) {
  let urlForProductTamperingChallenge: string | null = null
  void osaft.reload().then(() => {
    for (const product of config.get<ProductConfig[]>('products')) {
      if (product.urlForProductTamperingChallenge !== undefined) {
        urlForProductTamperingChallenge = product.urlForProductTamperingChallenge
        break
      }
    }
    if (urlForProductTamperingChallenge) {
      if (!osaft.description.includes(`${urlForProductTamperingChallenge}`)) {
        if (osaft.description.includes(`<a href="${config.get<string>('challenges.overwriteUrlForProductTamperingChallenge')}" target="_blank">`)) {
          challengeUtils.solve(challenges.changeProductChallenge)
        }
      }
    }
  })
}

function feedbackChallenge () {
  FeedbackModel.findAndCountAll({ where: { rating: 5 } }).then(({ count }: { count: number }) => {
    if (count === 0) {
      challengeUtils.solve(challenges.feedbackChallenge)
    }
  }).catch(() => {
    throw new Error('Unable to retrieve feedback details. Please try again')
  })
}

function knownVulnerableComponentChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.knownVulnerableComponentChallenge,
    { [Op.or]: knownVulnerableComponents() }
  )
}

function knownVulnerableComponents () {
  return [
    {
      [Op.and]: [
        { [Op.like]: '%sanitize-html%' },
        { [Op.like]: '%1.4.2%' }
      ]
    },
    {
      [Op.and]: [
        { [Op.like]: '%express-jwt%' },
        { [Op.like]: '%0.1.3%' }
      ]
    }
  ]
}

function weirdCryptoChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.weirdCryptoChallenge,
    { [Op.or]: weirdCryptos() }
  )
}

function weirdCryptos () {
  return [
    { [Op.like]: '%z85%' },
    { [Op.like]: '%base85%' },
    { [Op.like]: '%hashids%' },
    { [Op.like]: '%md5%' },
    { [Op.like]: '%base64%' }
  ]
}

function typosquattingNpmChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.typosquattingNpmChallenge,
    { [Op.like]: '%epilogue-js%' }
  )
}

function typosquattingAngularChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.typosquattingAngularChallenge,
    { [Op.like]: '%ngy-cookie%' }
  )
}

function hiddenImageChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.hiddenImageChallenge,
    { [Op.like]: '%pickle rick%' }
  )
}

function supplyChainAttackChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.supplyChainAttackChallenge,
    { [Op.or]: eslintScopeVulnIds() }
  )
}

function eslintScopeVulnIds () {
  return [
    { [Op.like]: '%eslint-scope/issues/39%' },
    { [Op.like]: '%npm:eslint-scope:20180712%' }
  ]
}

function dlpPastebinDataLeakChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.dlpPastebinDataLeakChallenge,
    { [Op.and]: dangerousIngredients() }
  )
}

function csafChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.csafChallenge,
    { [Op.like]: '%' + config.get<string>('challenges.csafHashValue') + '%' }
  )
}

function leakedApiKeyChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.leakedApiKeyChallenge,
    { [Op.like]: '%6PPi37DBxP4lDwlriuaxP15HaDJpsUXY5TspVmie%' }
  )
}

function vulnerableDockerImageChallenge () {
  void checkPatternInFeedbackAndComplaints(
    challenges.vulnerableDockerImageChallenge,
    {
      [Op.and]: [
        { [Op.like]: '%mongo%' },
        { [Op.like]: '%4.4.29%' }
      ]
    }
  )
}

function dangerousIngredients () {
  return config.get<ProductConfig[]>('products')
    .flatMap((product) => product.keywordsForPastebinDataLeakChallenge)
    .filter(Boolean)
    .map((keyword) => {
      return { [Op.like]: `%${keyword}%` }
    })
}

const SYSTEM_PROMPT_SIMILARITY_NGRAM_SIZE = 3
const SYSTEM_PROMPT_SIMILARITY_THRESHOLD = 0.25
/** Number of complaints inspected per scan, keeping the work triggered by a single request constant. */
const SYSTEM_PROMPT_SCAN_BATCH_SIZE = 100
/** Minimum delay before already inspected complaints are examined again. */
const SYSTEM_PROMPT_RESCAN_INTERVAL_MS = 60000

/** Id of the last complaint inspected, so that every complaint is only examined once per rescan interval. */
let systemPromptScanCursor = 0
let systemPromptLastFullScanAt = 0
let systemPromptScanRunning = false

/**
 * Longest submission that can still reach the given similarity threshold against a reference of the
 * given length. Anything longer is guaranteed to score below the threshold, because the number of
 * matching n-grams is capped by the shorter of both strings while the denominator keeps growing.
 */
function maxRelevantSubmissionLength (referenceLength: number, threshold: number, n: number): number {
  const maxMatchingNGrams = Math.max(0, referenceLength - n + 1)
  return Math.floor((2 * maxMatchingNGrams) / threshold - referenceLength + 2 * (n - 1))
}

export function checkSystemPromptSimilarity (submission: string, reference: string, threshold = SYSTEM_PROMPT_SIMILARITY_THRESHOLD): boolean {
  const normalizedSubmission = (submission ?? '').toLowerCase().trim()
  const normalizedReference = reference.toLowerCase().trim()
  // Skip the O(n) comparison for submissions that cannot possibly reach the threshold anyway
  if (normalizedSubmission.length > maxRelevantSubmissionLength(normalizedReference.length, threshold, SYSTEM_PROMPT_SIMILARITY_NGRAM_SIZE)) {
    return false
  }
  const score = utils.diceCoefficient(normalizedSubmission, normalizedReference, SYSTEM_PROMPT_SIMILARITY_NGRAM_SIZE)
  return score >= threshold
}

/**
 * Scans complaints for a leaked system prompt. As this runs for every request as long as the challenge
 * is unsolved, the scan is deliberately bounded: overlapping scans are suppressed and each scan reads at
 * most one batch of complaints, only the message column, only complaints not inspected yet and only
 * those short enough to be able to reach the similarity threshold at all. Without those bounds the
 * complaints table - which anyone can grow but nobody can shrink - would turn every single request into
 * an ever increasing amount of synchronous work on the event loop.
 */
async function systemPromptExtractionChallenge (): Promise<void> {
  if (systemPromptScanRunning) {
    return
  }
  systemPromptScanRunning = true
  try {
    const now = Date.now()
    if (systemPromptScanCursor > 0 && now - systemPromptLastFullScanAt >= SYSTEM_PROMPT_RESCAN_INTERVAL_MS) {
      systemPromptScanCursor = 0 // occasionally start over, e.g. to cope with reset challenge progress
    }
    const reference = buildSystemPrompt().toLowerCase().trim()
    const maxMessageLength = maxRelevantSubmissionLength(reference.length, SYSTEM_PROMPT_SIMILARITY_THRESHOLD, SYSTEM_PROMPT_SIMILARITY_NGRAM_SIZE)
    const complaints = await ComplaintModel.findAll({
      attributes: ['id', 'message'],
      where: {
        [Op.and]: [
          { id: { [Op.gt]: systemPromptScanCursor } },
          sequelizeWhere(fn('length', col('message')), { [Op.lte]: maxMessageLength })
        ]
      },
      order: [['id', 'ASC']],
      limit: SYSTEM_PROMPT_SCAN_BATCH_SIZE
    }).catch(() => [])
    for (const complaint of complaints) {
      systemPromptScanCursor = complaint.id
      if (checkSystemPromptSimilarity(complaint.message ?? '', reference)) {
        challengeUtils.solveIf(challenges.systemPromptExtractionChallenge, () => true)
        return
      }
    }
    if (complaints.length < SYSTEM_PROMPT_SCAN_BATCH_SIZE) {
      systemPromptLastFullScanAt = now // all complaints inspected, the next scans only pick up new ones
    }
  } finally {
    systemPromptScanRunning = false
  }
}
