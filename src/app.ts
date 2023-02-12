import express from 'express'
import 'dotenv/config'

const ADD_USER_HASH = process.env.ADD_USER_HASH
const SETTING_ADMIN_HASH = process.env.SETTING_ADMIN_HASH
const SETTING_SCORE_ADMIN_HASH = process.env.SETTING_SCORE_ADMIN_HASH

const app = express()

app.use(express.urlencoded({ extended: true }))
app.use(express.json())

import compression from 'compression'
app.use(
  compression({
    threshold: 0,
    level: 9,
    memLevel: 9,
  })
)

// CORSを許可する
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*')
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
  next()
})

import { database as auth } from './library/database'
import { lib } from './library/library'
import type { Session } from './types/types'

// ルートアクセス
app.get('/', (req, res) => {
  console.log('[' + lib.showTime() + '] root access')
  res.redirect(301, 'https://winds-n.com')
})

// API 設定

// ユーザを新しく追加する
// [input]: userid: ユーザー名, passwd: パスワード, key: 承認キー
// [NGout]: status: false
// [OKout]: status: true, token: トークン
app.post('/adduser', (req, res) => {
  const userid = req.body.userid
  const passwd = req.body.passwd
  const key = req.body.key
  const clientid = req.body.clientid
  const useragent = req.body.useragent
  const version = req.body.version
  console.log('[' + lib.showTime() + '] adduser:', version, userid, ', (passwd), ', key)
  // パラメータが空の場合はエラー
  if (userid === '' || passwd === '') return res.json({ status: false })
  // 承認キーが合わない場合はエラー
  if (lib.getHash(key) !== ADD_USER_HASH) return res.json({ status: false })
  auth.addUser(userid, passwd, clientid, useragent, (err, user) => {
    if (err || !user) return res.json({ status: false, err })
    return res.json({ status: true, token: lib.getToken(clientid, user), user })
  })
})

// ログイン認証
// [input]: userid: ユーザー名, passwd: パスワード, key: 承認キー
// [NGout]: status: false, code: エラーコード(あんま使わないかも)
// [OKout]: status: true, hash: ハッシュ
app.post('/login', (req, res) => {
  const userid = req.body.userid
  const passwd = req.body.passwd
  const clientid = req.body.clientid
  const useragent = req.body.useragent
  const version = req.body.version
  auth.login(userid, passwd, clientid, useragent, (err, user) => {
    if (err || !user) {
      console.log('[' + lib.showTime() + '] login: ' + userid + ', (passwd), version: ' + version + ', (NG)')
      return res.json({ status: false })
    }
    console.log('[' + lib.showTime() + '] login: ' + userid + ', (passwd), version: ' + version + ', (OK)')
    res.json({ status: true, token: lib.getToken(clientid, user), user })
  })
})

app.post('/logout', (req, res) => {
  const session = req.body.session
  auth.auth(session, (err, user) => {
    if (err) return res.json({ status: false })
    auth.deleteSession(session, session.clientid, (deleteSessionError, user) => {
      if (deleteSessionError) return res.json({ status: false })
      console.log('[' + lib.showTime() + '] logout: (OK)')
      res.json({ status: true })
    })
  })
})

// 通常認証
app.post('/auth', (req, res) => {
  const session = req.body.session
  auth.auth(session, (err, user) => {
    if (err || !user) {
      if (!session.version) {
        console.log('[' + lib.showTime() + '] auth: ' + session.userid + ', request from api (NG)')
      } else {
        console.log('[' + lib.showTime() + '] auth: ' + session.userid + ', version: ' + session.version + ' (NG)')
      }
      return res.json({ status: false })
    }
    if (!session.version) {
      console.log('[' + lib.showTime() + '] auth: ' + session.userid + ', request from api (OK)')
    } else {
      console.log('[' + lib.showTime() + '] auth: ' + session.userid + ', version: ' + session.version + ' (OK)')
    }
    res.json({ status: true, token: lib.getToken(session.clientid, user), user })
  })
})

// 状態取得
app.post('/status', (req, res) => {
  const session: Session = req.body.session
  const userid = session.userid
  console.log('[' + lib.showTime() + '] status: ' + userid)
  auth.checkToken(session, (err, user) => {
    if (err) return res.json({ status: false })
    res.json({ status: true, user })
  })
})

app.post('/setting/status', (req, res) => {
  const session = req.body.session
  console.log('[' + lib.showTime() + '] api/setting/status: ' + session.userid + ', (token)')
  auth.checkToken(session, (err, user) => {
    if (err || !user) return res.json({ status: false })
    return res.json({ status: true, user })
  })
})

app.post('/api/setting/username', (req, res) => {
  const session = req.body.session
  const text = req.body.text
  console.log('[' + lib.showTime() + '] api/setting/username: ' + text)
  auth.checkToken(session, (err, user) => {
    if (err || !user) return res.json({ status: false })
    auth.changeName(user.userid, text, (err) => {
      if (err) return res.json({ status: false })
      res.json({ status: true })
    })
  })
})

app.post('/api/setting/email', (req, res) => {
  const session = req.body.session
  const text = req.body.text
  const delMail = req.body.delMail
  if (!delMail && !text.match(/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/)) {
    console.log('[' + lib.showTime() + '] api/setting/email: メールアドレスの形式ではない')
    return res.json({ status: false })
  }
  console.log('[' + lib.showTime() + '] api/setting/email: ' + text)
  auth.checkToken(session, (err, user) => {
    if (err || !user) return res.json({ status: false })
    console.log('[api] setting/email => (auth.checkToken) OK: done')
    auth.changeMail(user, text, (err, valid) => {
      if (err) return res.json({ status: false })
      if (valid) return res.json({ status: true, valid: true })
      res.json({ status: true })
    })
  })
})

app.post('/api/setting/password', (req, res) => {
  const session = req.body.session
  const newPass = req.body.new
  const oldPass = req.body.old
  console.log('[' + lib.showTime() + '] api/setting/password: ' + session.userid)
  auth.checkToken(session, (err, user) => {
    if (err) return res.json({ status: false })
    auth.checkPass(session.userid, oldPass, newPass, (result) => {
      if (!result) return res.json({ status: false })
      res.json({ status: true })
    })
  })
})

app.post('/api/setting/deletesession', (req, res) => {
  const session = req.body.session
  const clientid = req.body.clientid
  console.log('[' + lib.showTime() + '] api/setting/deletesession: ' + session.userid)
  auth.checkToken(session, (err, user) => {
    if (err) return res.json({ status: false })
    auth.deleteSession(session, clientid, (err, newUser) => {
      if (err) return res.json({ status: false, err })
      return res.json({ status: true, user: newUser })
    })
  })
})

app.post('/api/setting/delete', (req, res) => {
  const session = req.body.session
  const pass = req.body.pass
  console.log('[' + lib.showTime() + '] api/setting/delete: ' + session.userid)
  auth.checkToken(session, (err, user) => {
    if (err) return res.json({ status: false })
    console.log('[api] setting/delete: (hash)')
    auth.deleteUser(session.userid, pass, (result) => {
      if (!result) return res.json({ status: false })
      res.json({ status: true })
    })
  })
})

// Administrator
app.post('/api/setting/admin', (req, res) => {
  const session = req.body.session
  const admin = req.body.admin
  const pass = req.body.pass
  console.log('[' + lib.showTime() + '] api/setting/admin: ' + session.userid)
  auth.checkToken(session, (err, user) => {
    if (err) return res.json({ status: false })
    console.log('[api] setting/admin')
    if (admin === 'true') {
      if (lib.getHash(pass) === SETTING_ADMIN_HASH) {
        auth.updateAdmin(session.userid, true, (err) => {
          if (err) return res.json({ status: false })
          console.log(session.userid + ': admin available')
          return res.json({ status: true, admin: true, error: false })
        })
      } else {
        console.log(session.userid + ': admin not available')
        return res.json({ status: true, admin: false, error: true })
      }
    } else {
      auth.updateAdmin(session.userid, false, (err) => {
        if (err) return res.json({ status: false })
        console.log(session.userid + ': turn off admin')
        return res.json({ status: true, admin: false, error: false })
      })
    }
  })
})

app.post('/api/setting/score/admin', (req, res) => {
  const session = req.body.session
  const admin = req.body.admin
  const pass = req.body.pass
  console.log('[' + lib.showTime() + '] api/setting/score/admin: ' + session.userid)
  auth.checkToken(session, (err, user) => {
    if (err) return res.json({ status: false })
    console.log('[api] setting/score/admin')
    if (admin === 'true') {
      if (lib.getHash(pass) === SETTING_SCORE_ADMIN_HASH) {
        auth.updateScoreAdmin(session.userid, true, (err) => {
          if (err) return res.json({ status: false })
          console.log(session.userid + ': score admin available')
          return res.json({ status: true, admin: true, error: false })
        })
      } else {
        console.log(session.userid + ': score admin not available')
        return res.json({ status: true, admin: false, error: true })
      }
    } else {
      auth.updateScoreAdmin(session.userid, false, (err) => {
        if (err) return res.json({ status: false })
        console.log(session.userid + ': turn off score admin')
        return res.json({ status: true, admin: false, error: false })
      })
    }
  })
})

// email validation
app.post('/user/valid', (req, res) => {
  const session = req.body.session
  const key = req.body.key
  console.log('[' + lib.showTime() + '] /user/valid: ', key)
  auth.checkToken(session, (err, user) => {
    if (err || !user) return res.json({ status: false })
    if (user.emailValidKey !== key) return res.json({ status: true, err: { type: 'notMatchError' }, user })
    auth.emailValid(key, (emailValidError, newUser) => {
      console.log(emailValidError ? 'Validation NG' : 'Validation OK')
      if (emailValidError) return res.json({ status: true, err: emailValidError, user: newUser })
      return res.json({ status: true, err: false, valid: true, user: newUser })
    })
  })
})

app.listen(3003)
