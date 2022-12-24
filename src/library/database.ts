import path from "path"
import NeDB from "nedb"

import { lib } from "./library"

import { mail } from "./mail"
import { v4 as uuidv4 }from "uuid"

const authDB = new NeDB({
  filename: path.join(__dirname, '../database/auth.db'),
  autoload: true,
  timestampData: true
})

// ユーザー情報をアップデートする
// in: user[object](たぶん)
// out: callback(err)
function updateUser (user, callback) {
  authDB.update({userid: user.userid}, user, {}, (err, n) => {
    if (err) return callback(err)
    callback(null)
  })
}

// ユーザー情報を取得する
// in: userid
// out: callback(user[object])
function getUser (userid, callback) {
  authDB.findOne({userid}, (err, user) => {
    if (err || user === null) return callback(null)
    callback(user)
  })
}

// ユーザーを新規追加する
// in: userid, passwd
// out: callback(token, userkey)
async function addUser (userid, passwd, clientid, useragent, callback) {
  if (await checkRegs(userid)) return callback({type: 'alreadyRegisteredError'}, null)
  const hash = lib.getHash(passwd)
  const clientToken = lib.getAuthToken(clientid)
  const clientList = [{
    agent: useragent,
    id: clientid,
    token: clientToken,
    lastLogin: (new Date()).getTime()
  }]
  const user = {
    name: userid,
    userid,
    hash,
    email: null,
    emailValid: false,
    emailValidKey: null,
    emailValidExpire: null,
    clientList,
    regTime: (new Date()).getTime()
  }
  authDB.insert(user, (err, newdoc) => {
    if (err || !newdoc) return callback({type: 'DBError'}, null)
    callback(null, user)
  })
}

function checkRegs (userid) {
  return new Promise((resolve) => {
    authDB.findOne({userid}, (userError, userResult) => {
      if (userError) return resolve({type: 'DBError'})
      if (userResult) return resolve({type: 'alreadySignuped'})
      return userResult ? resolve(true) : resolve(false)
    })
  })
}

// ユーザーを削除する
// in: userid, passwd
// out: callback(token, userkey)
function deleteUser (userid, passwd, callback) {
  const hash = lib.getHash(passwd)
  getUser(userid, (user) => {
    if (!user || user.hash !== hash) return callback(null)
    authDB.remove({userid}, {}, (err, numRemoved) => {
      if (err) return callback(null)
      callback(numRemoved)
    })
  })
}

// ログイン処理
// in: userid, passwd
// out: callback(err, token)
function login (userid, passwd, clientid, useragent, callback) {
  const hash = lib.getHash(passwd)
  const clientToken = lib.getAuthToken(clientid)
  const lastLoginTime = (new Date()).getTime()
  getUser(userid, (user) => {
    if (!user || user.hash !== hash) return callback({type: 'DBError'}, null)
    lib.getToken(clientid, user) ? console.log('Known device') : console.log('New device')
    const newClientList = lib.getToken(clientid, user) ?
    user.clientList.map(client => {
      return client.id === clientid ? {
        ...client,
        token: clientToken,
        lastLogin: lastLoginTime
      } : client
    }) :
    user.clientList.concat({
      agent: useragent,
      id: clientid,
      token: clientToken,
      lastLogin: lastLoginTime
    })
    const newUser = {
      ...user,
      clientList: newClientList
    }
    updateUser(newUser, (err) => {
      if (err) return callback(err, null)
      return callback(null, newUser)
    })
  })
}

function auth (session, callback) {
  getUser(session.userid, (user) => {
    if (!user) return callback({type: 'DBError'}, null)
    if (lib.getToken(session.clientid, user) !== session.clientToken) return callback({type: 'notMatchToken'}, null)
    const clientList = user.clientList.map(client => {
      if (client.id === session.clientid) client.lastLogin = (new Date()).getTime()
      return client
    })
    const newUser = {
      ...user,
      clientList
    }
    updateUser(newUser, (err) => {
      if (err) return callback(err, null)
      return callback(null, newUser)
    })
  })
}

// in: userid, token
// out: callback(err, user[object])
function checkToken (session, callback) {
  getUser(session.userid, (user) => {
    if (!user) return callback({type: 'DBError'}, null)
    if (lib.getToken(session.clientid, user) !== session.clientToken) return callback({type: 'notMatchToken'}, null)
    callback(null, user)
  })
}

function changeName (userid, name, callback) {
  console.log('[listDB] changeName')
  authDB.update({userid}, {$set: {name}}, {}, (err, newdoc) => {
    if (err) return callback(err)
    return callback(null)
  })
}

function changeMail (user, email, callback) {
  console.log('[listDB] changeMail')
  if (email === '') {
    authDB.update({userid: user.userid}, {$set: {email: ''}}, {}, (err, newdoc) => {
      if (err) return callback(err, null)
      return callback(null, null)
    })
  } else if (user.email && user.emailValid) {
    return callback(null, true)
  } else {
    const emailHash = lib.getHash(email)
    const newUser = {
      ...user,
      email,
      emailHash,
      emailValid: false,
      emailValidKey: uuidv4().split('-').join(''),
      emailValidExpire: (new Date()).setHours((new Date()).getHours() + 24)
    }
    authDB.update({userid: user.userid}, newUser, {}, (err, newdoc) => {
      if (err) return callback(err, null)
      mail.sendUpdateEmail(newUser)
      return callback(null, null)
    })
  }
}

function emailValid (key, callback) {
  authDB.findOne({emailValidKey: key}, (userFindError, user) => {
    if (userFindError) return callback({err: true, type: 'DBError'}, user)
    if (!user) return callback({err: true, type: 'noDataError'}, user)
    if ((new Date()).getTime() > user.emailValidExpire) return callback({err: true, type: 'expiredError'}, user)
    if (user.emailValid) return callback({err: true, type: 'alreadyValid'}, user)
    const newUser = {
      ...user,
      emailValid: true
    }
    authDB.update({emailValidKey: key}, newUser, {}, (updateError, num) => {
      if (updateError || !num) return callback({err: true, type: 'DBError'}, newUser)
      return callback(null, newUser)
    })
  })
}

function deleteSession (session, clientid, callback) {
  getUser(session.userid, (user) => {
    if (!user) return callback({type: 'DBError'}, null)
    const newClientList = user.clientList.filter((e) => {return e.id !== clientid})
    const newUser = {
      ...user,
      clientList: newClientList
    }
    authDB.update({userid: session.userid}, newUser, {}, (updateError, num) => {
      if (updateError || !num) return callback({err: true, type: 'DBError'}, newUser)
      return callback(null, newUser)
    })
  })
}

function updateAdmin (userid, admin, callback) {
  console.log('[listDB] updateAdmin')
  authDB.update({userid}, {$set: {admin}}, {}, (err, newdoc) => {
    if (err) return callback(err)
    return callback(null)
  })
}

function updateScoreAdmin (userid, scoreAdmin, callback) {
  console.log('[listDB] updateScoreAdmin')
  authDB.update({userid}, {$set: {scoreAdmin}}, {}, (err, newdoc) => {
    if (err) return callback(err)
    return callback(null)
  })
}

function checkPass (userid, oldPass, newPass, callback) {
  const oldHash = lib.getHash(oldPass)
  const newHash = lib.getHash(newPass)
  getUser(userid, (user) => {
    if (!user || user.hash !== oldHash) return callback(null)
    user.hash = newHash
    updateUser(user, (err) => {
      if (err) return callback(null)
      callback(true)
    })
  })
}

export const database = {
  getUser, addUser, deleteUser, login, auth, checkToken, changeName, changeMail, emailValid, deleteSession, updateAdmin, updateScoreAdmin, checkPass
}
