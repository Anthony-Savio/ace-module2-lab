/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'
import fs from 'node:fs/promises'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

function unescapeString (str: string): string {
  return str.replace(/\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)/g, (match, p1) => {
    if (p1.startsWith('u')) {
      return String.fromCharCode(parseInt(p1.substring(1), 16))
    }
    if (p1.startsWith('x')) {
      return String.fromCharCode(parseInt(p1.substring(1), 16))
    }
    switch (p1) {
      case 'n': return '\n'
      case 'r': return '\r'
      case 't': return '\t'
      case 'b': return '\b'
      case 'f': return '\f'
      case 'v': return '\v'
      case '0': return '\0'
      default: return p1
    }
  })
}

type Token =
  | { type: 'NUMBER'; value: number }
  | { type: 'STRING'; value: string }
  | { type: 'OPERATOR'; value: string }

function tokenize (code: string): Token[] {
  const tokenRegex = /\s+|'([^'\\]*(?:\\.[^'\\]*)*)'|"([^"\\]*(?:\\.[^"\\]*)*)"|`([^`\\]*(?:\\.[^`\\]*)*)`|(\d+(?:\.\d+)?)|([+\-*/%()])/g
  const tokens: Token[] = []
  let lastIndex = 0
  let match

  while ((match = tokenRegex.exec(code)) !== null) {
    if (match.index !== lastIndex) {
      throw new Error(`Unexpected token at index ${lastIndex}`)
    }

    const [, singleStr, doubleStr, backtickStr, numStr, opStr] = match

    if (singleStr !== undefined) {
      tokens.push({ type: 'STRING', value: unescapeString(singleStr) })
    } else if (doubleStr !== undefined) {
      tokens.push({ type: 'STRING', value: unescapeString(doubleStr) })
    } else if (backtickStr !== undefined) {
      tokens.push({ type: 'STRING', value: unescapeString(backtickStr) })
    } else if (numStr !== undefined) {
      tokens.push({ type: 'NUMBER', value: parseFloat(numStr) })
    } else if (opStr !== undefined) {
      tokens.push({ type: 'OPERATOR', value: opStr })
    }

    lastIndex = tokenRegex.lastIndex
  }

  if (lastIndex < code.length) {
    throw new Error(`Unexpected token at index ${lastIndex}`)
  }

  return tokens
}

class SafeExpressionParser {
  private readonly tokens: Token[]
  private index: number = 0

  constructor (tokens: Token[]) {
    this.tokens = tokens
  }

  private peek (): Token | undefined {
    return this.tokens[this.index]
  }

  private consume (): Token {
    return this.tokens[this.index++]
  }

  public parse (): any {
    if (this.tokens.length === 0) {
      throw new Error('Empty expression')
    }
    if (this.tokens.length > 100) {
      throw new Error('Too many tokens')
    }
    const result = this.parseAdditive()
    if (this.index < this.tokens.length) {
      throw new Error(`Unexpected token at index ${this.index}`)
    }
    return result
  }

  private parseAdditive (): any {
    let left = this.parseMultiplicative()
    while (true) {
      const token = this.peek()
      if (token && token.type === 'OPERATOR' && (token.value === '+' || token.value === '-')) {
        this.consume()
        const right = this.parseMultiplicative()
        if (token.value === '+') {
          left = left + right
        } else {
          left = left - right
        }
      } else {
        break
      }
    }
    return left
  }

  private parseMultiplicative (): any {
    let left = this.parsePrimary()
    while (true) {
      const token = this.peek()
      if (token && token.type === 'OPERATOR' && (token.value === '*' || token.value === '/' || token.value === '%')) {
        this.consume()
        const right = this.parsePrimary()
        if (token.value === '*') {
          left = left * right
        } else if (token.value === '/') {
          left = left / right
        } else {
          left = left % right
        }
      } else {
        break
      }
    }
    return left
  }

  private parsePrimary (): any {
    const token = this.peek()
    if (!token) {
      throw new Error('Unexpected end of expression')
    }

    if (token.type === 'NUMBER' || token.type === 'STRING') {
      this.consume()
      return token.value
    }

    if (token.type === 'OPERATOR' && token.value === '(') {
      this.consume() // consume '('
      const result = this.parseAdditive()
      const closing = this.peek()
      if (!closing || closing.type !== 'OPERATOR' || closing.value !== ')') {
        throw new Error("Expected ')'")
      }
      this.consume() // consume ')'
      return result
    }

    throw new Error(`Unexpected token: ${JSON.stringify(token)}`)
  }
}

function safeEval (code: string): any {
  const tokens = tokenize(code)
  const parser = new SafeExpressionParser(tokens)
  return parser.parse()
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
    } catch (err) {
      next(err)
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress)); return
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.data.id)
    } catch (error) {
      next(error)
      return
    }

    if (!user) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    let username = user.username

    if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
      req.app.locals.abused_ssti_bug = true
      const code = username?.substring(2, username.length - 1)
      try {
        if (!code) {
          throw new Error('Username is null')
        }
        username = safeEval(code)
      } catch (err) {
        username = '\\\\' + username
      }
    } else {
      username = '\\\\' + username
    }

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    if (username) {
      template = template.replace(/_username_/g, username)
    }
    template = template.replace(/_emailHash_/g, security.hash(user?.email))
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, favicon())
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

    try {
      const pug = (await import('pug')).default
      const fn = pug.compile(template)
      const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'`

      challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
        return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>')
      })

      res.set({
        'Content-Security-Policy': CSP
      })

      res.send(fn(user))
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
