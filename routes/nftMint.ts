import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as challengeUtils from '../lib/challengeUtils'
import { nftABI } from '../data/static/contractABIs'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const nftAddress = '0x41427790c94E7a592B17ad694eD9c06A02bb9C39'
const addressesMinted = new Set()
/* Minimum time to wait before a failed listener setup may open another outbound connection */
const RECONNECT_COOLDOWN_MS = 60 * 1000

/* Holds the one-and-only listener setup. Storing the promise (instead of a boolean that is
   flipped after an `await`) makes sure that concurrent requests share a single outbound
   WebSocket connection instead of each creating their own. */
let eventListenerSetup: Promise<void> | null = null
let nextSetupAllowedAt = 0

function discardEventListener (provider?: { destroy: () => unknown }) {
  eventListenerSetup = null
  nextSetupAllowedAt = Date.now() + RECONNECT_COOLDOWN_MS
  if (provider) {
    /* Release the socket of the broken provider instead of leaking it */
    void Promise.resolve()
      .then(() => provider.destroy())
      .catch((error: unknown) => { logger.warn(`Could not destroy WebSocket provider (NFT Mint Listener): ${utils.getErrorMessage(error)}`) })
  }
}

async function createEventListener () {
  const { WebSocketProvider, Contract } = await import('ethers')
  const provider = new WebSocketProvider(`wss://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY ?? ''}`)
  provider.websocket.onerror = (error: any) => {
    logger.error(`WebSocket error (NFT Mint Listener): ${error.message || error}`)
    discardEventListener(provider)
  }
  const contract = new Contract(nftAddress, nftABI, provider as any)
  void contract.on('NFTMinted', (minter: string) => {
    if (!addressesMinted.has(minter)) {
      addressesMinted.add(minter)
    }
  })
}

function ensureEventListener () {
  if (eventListenerSetup === null && Date.now() >= nextSetupAllowedAt) {
    /* Assigned synchronously, i.e. before the first `await`, so that a burst of requests
       cannot slip past the guard and each open its own connection */
    eventListenerSetup = createEventListener().catch((error: unknown) => {
      discardEventListener()
      throw error
    })
  }
  return eventListenerSetup
}

export function nftMintListener () {
  return async (req: Request, res: Response) => {
    try {
      await ensureEventListener()
      res.status(200).json({ success: true, message: 'Event Listener Created' })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}

export function walletNFTVerify () {
  return (req: Request, res: Response) => {
    try {
      const metamaskAddress = req.body.walletAddress
      if (addressesMinted.has(metamaskAddress)) {
        addressesMinted.delete(metamaskAddress)
        challengeUtils.solveIf(challenges.nftMintChallenge, () => true)
        res.status(200).json({ success: true, message: 'Challenge successfully solved', status: challenges.nftMintChallenge })
      } else {
        res.status(200).json({ success: false, message: 'Wallet did not mint the NFT', status: challenges.nftMintChallenge })
      }
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
