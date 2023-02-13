import nodeMailer from 'nodemailer'

import { lib } from './library'

import type { User } from '../types/types'

import 'dotenv/config'

const MAIL_DOVECOT_PASS_NOREPLY = process.env.MAIL_DOVECOT_PASS_NOREPLY as string

const mailSetting = {
  host: 'mail.winds-n.com',
  auth: {
    user: 'noreply@winds-n.com',
    pass: MAIL_DOVECOT_PASS_NOREPLY,
    port: '465',
  },
  tls: { rejectUnauthorized: false },
  debug: true,
}

const smtp = nodeMailer.createTransport(mailSetting)

function sendUpdateEmail(userdata: User) {
  console.log('[' + lib.showTime() + '] sendUpdateEmail to: ', userdata.email)
  const emailPath = 'https://member.winds-n.com/valid/' + userdata.emailValidKey
  const mailText =
    userdata.name +
    ' 様\r\n' +
    '\r\n' +
    'ウィンズアプリのご利用ありがとうございます。\r\n' +
    '登録されたメールアドレスの確認を行います。\r\n' +
    '\r\n' +
    '以下のURLへアクセスしてください。\r\n' +
    '↓\r\n' +
    emailPath +
    '\r\n' +
    '\r\n' +
    'URLの有効期間は登録から24時間です。\r\n' +
    '期限が切れた場合はユーザー設定ページから再度確認をお願いします。\r\n' +
    'このメールに心当たりのない場合は、お手数ですが下記までご連絡ください。\r\n' +
    '\r\n' +
    '--\r\n' +
    '\r\n' +
    'ザ・ウィンド・アンサンブル\r\n' +
    'https://winds-n.com'
  const mailContents = {
    from: 'ザ・ウィンド・アンサンブル <noreply@winds-n.com>',
    to: userdata.email || '',
    subject: 'ウィンズよりメールアドレスの確認',
    // html: '',
    text: mailText,
  }
  smtp.sendMail(mailContents, (err, result) => {
    if (err) {
      console.log('NG', err)
    } else {
      console.log('OK', result)
    }
  })
}

export const mail = {
  sendUpdateEmail,
}
