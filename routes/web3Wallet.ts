import { type Request, type Response } from 'express'

import logger from '../lib/logger'
import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'
import { web3WalletABI } from '../data/static/contractABIs'

const web3WalletAddress = '0x413744D59d31AFDC2889aeE602636177805Bd7b0'
const walletsConnected = new Set<string>()
/* Only syntactically valid EOA/contract addresses are tracked */
const walletAddressPattern = /^0x[0-9a-fA-F]{40}$/
/* Upper bound for the process-lifetime set of connected wallets (oldest entries are evicted) */
const MAX_WALLETS_CONNECTED = 1000
/* Minimum time to wait before a failed listener setup may open another outbound connection */
const RECONNECT_COOLDOWN_MS = 60 * 1000

/* Holds the one-and-only listener setup. Storing the promise (instead of a boolean that is
   flipped after an `await`) makes sure that concurrent requests share a single outbound
   WebSocket connection instead of each creating their own. */
let eventListenerSetup: Promise<void> | null = null
let nextSetupAllowedAt = 0

function rememberWallet (walletAddress: unknown) {
  if (typeof walletAddress !== 'string' || !walletAddressPattern.test(walletAddress)) {
    return
  }
  if (!walletsConnected.has(walletAddress) && walletsConnected.size >= MAX_WALLETS_CONNECTED) {
    for (const oldestWallet of walletsConnected) {
      walletsConnected.delete(oldestWallet)
      break
    }
  }
  walletsConnected.add(walletAddress)
}

function discardEventListener (provider?: { destroy: () => unknown }) {
  eventListenerSetup = null
  nextSetupAllowedAt = Date.now() + RECONNECT_COOLDOWN_MS
  if (provider) {
    /* Release the socket of the broken provider instead of leaking it */
    void Promise.resolve()
      .then(() => provider.destroy())
      .catch((error: unknown) => { logger.warn(`Could not destroy WebSocket provider (Contract Exploit Listener): ${utils.getErrorMessage(error)}`) })
  }
}

async function createEventListener () {
  const { WebSocketProvider, Contract } = await import('ethers')
  const provider = new WebSocketProvider(`wss://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY ?? ''}`)
  provider.websocket.onerror = (error: any) => {
    logger.error(`WebSocket error (Contract Exploit Listener): ${error.message || error}`)
    discardEventListener(provider)
  }
  const contract = new Contract(web3WalletAddress, web3WalletABI, provider as any)
  void contract.on('ContractExploited', (exploiter: string) => {
    if (walletsConnected.has(exploiter)) {
      walletsConnected.delete(exploiter)
      challengeUtils.solveIf(challenges.web3WalletChallenge, () => true)
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

export function contractExploitListener () {
  return async (req: Request, res: Response) => {
    rememberWallet(req.body?.walletAddress)
    try {
      await ensureEventListener()
      res.status(200).json({ success: true, message: 'Event Listener Created' })
    } catch (error) {
      res.status(500).json(utils.getErrorMessage(error))
    }
  }
}
