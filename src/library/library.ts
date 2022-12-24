import crypto from 'crypto'

import type { User } from '../types/types'

function getHash(pass: string) {
  const salt = '::HXAuymPGKKcThn6n'
  const hashsum = crypto.createHash('sha512')
  hashsum.update(pass + salt)
  return hashsum.digest('hex')
}

function getAuthToken(clientid: string) {
  return getHash(clientid + new Date().getTime())
}

function getToken(id: string, user: User) {
  if (!('clientList' in user)) return false
  const client = user.clientList.filter((e) => {
    return e.id === id
  })
  if (client.length !== 1) return false
  return client[0].token
}

function getUniqueString(length: number) {
  const strong = length ? Math.pow(10, length) : 1000
  return new Date().getTime().toString(16) + Math.floor(strong * Math.random()).toString(16)
}

function getRandomString(length: number) {
  const strong = length ? Math.pow(10, length + 1) : 1000
  return Math.floor(strong * Math.random()).toString(16)
}

function escapeReg(string: string) {
  const reRegExp = /[\\^$.*+?()[\]{}|]/g
  const reHasRegExp = new RegExp(reRegExp.source)
  return string && reHasRegExp.test(string) ? string.replace(reRegExp, '\\$&') : string
}

function showTime() {
  const time = new Date()
  const z = (v: number) => {
    const s = '00' + v
    return s.substr(s.length - 2, 2)
  }
  // const time = (new Date()).getTime()
  return (
    time.getFullYear() +
    '/' +
    (time.getMonth() + 1) +
    '/' +
    time.getDate() +
    ' ' +
    z(time.getHours()) +
    ':' +
    z(time.getMinutes()) +
    ':' +
    z(time.getSeconds())
  )
}

export const lib = {
  getHash,
  getAuthToken,
  getToken,
  getUniqueString,
  getRandomString,
  escapeReg,
  showTime,
}
