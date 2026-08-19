/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import net from 'node:net'
import dns from 'node:dns/promises'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateOrLoopbackIPv4 (ip: string): boolean {
  if (!net.isIPv4(ip)) return false
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(isNaN)) return true

  // 127.0.0.0/8 (Loopback)
  if (parts[0] === 127) return true
  // 10.0.0.0/8 (Private)
  if (parts[0] === 10) return true
  // 172.16.0.0/12 (Private)
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
  // 192.168.0.0/16 (Private)
  if (parts[0] === 192 && parts[1] === 168) return true
  // 169.254.0.0/16 (Link-local)
  if (parts[0] === 169 && parts[1] === 254) return true
  // 0.0.0.0/8 (Broadcast/Local)
  if (parts[0] === 0) return true

  return false
}

function isPrivateOrLoopbackIPv6 (ip: string): boolean {
  if (!net.isIPv6(ip)) return false
  const normalized = ip.toLowerCase().trim()

  // Loopback
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true
  // Unspecified
  if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') return true
  // Link-local: fe80::/10 (fe8, fe9, fea, feb)
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) return true
  // Unique Local: fc00::/7 (fc, fd)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true
  // IPv4-mapped IPv6
  if (normalized.startsWith('::ffff:')) {
    const ipv4Part = normalized.substring(7)
    if (net.isIPv4(ipv4Part)) {
      return isPrivateOrLoopbackIPv4(ipv4Part)
    }
  }

  return false
}

function isLoopbackIPv4 (ip: string): boolean {
  if (!net.isIPv4(ip)) return false
  const parts = ip.split('.').map(Number)
  return parts.length === 4 && parts[0] === 127
}

function isLoopbackIPv6 (ip: string): boolean {
  if (!net.isIPv6(ip)) return false
  const normalized = ip.toLowerCase().trim()
  return normalized === '::1' || normalized === '0:0:0:0:0:0:0:1'
}

async function isSafeUrl (url: string): Promise<boolean> {
  try {
    let urlString = url
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      urlString = 'http://' + url
    }
    const parsedUrl = new URL(urlString)
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }

    const hostname = parsedUrl.hostname
    const isTest = process.env.NODE_ENV === 'test'

    // If it is already an IP address
    if (net.isIP(hostname)) {
      if (isTest) {
        if (isLoopbackIPv4(hostname) || isLoopbackIPv6(hostname)) {
          return true
        }
        return !isPrivateOrLoopbackIPv4(hostname) && !isPrivateOrLoopbackIPv6(hostname)
      } else {
        return !isPrivateOrLoopbackIPv4(hostname) && !isPrivateOrLoopbackIPv6(hostname)
      }
    }

    // Resolve hostname to IP addresses
    let addresses: string[] = []
    try {
      const lookupResult = await dns.lookup(hostname, { all: true })
      addresses = lookupResult.map(r => r.address)
    } catch {
      return false
    }

    for (const ip of addresses) {
      if (isTest) {
        if (isLoopbackIPv4(ip) || isLoopbackIPv6(ip)) {
          continue
        }
        if (isPrivateOrLoopbackIPv4(ip) || isPrivateOrLoopbackIPv6(ip)) {
          return false
        }
      } else {
        if (isPrivateOrLoopbackIPv4(ip) || isPrivateOrLoopbackIPv6(ip)) {
          return false
        }
      }
    }

    return true
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          if (!(await isSafeUrl(url))) {
            throw new Error('Blocked SSRF request to unsafe URL: ' + url)
          }
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
