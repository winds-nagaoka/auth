import nodeMailer from "nodemailer"

import secrets from "../../../secrets/mail"

const mailSetting = {
  host: 'mail.winds-n.com',
  auth: {
    user: 'noreply@winds-n.com',
    pass: secrets.dovecotPass.noreply,
    port: '465'
  },
  tls: {rejectUnauthorized: false},
  debug:true
}

const smtp = nodeMailer.createTransport(mailSetting)

import { lib }from "./library"

function sendUpdateEmail (userdata) {
  console.log('[' + lib.showTime() + '] sendUpdateEmail to: ', userdata.email)
  const emailPath = 'https://member.winds-n.com/valid/' + userdata.emailValidKey
  const mailText =
  userdata.name + ' 様\r\n' +
  '\r\n' +
  'ウィンズアプリのご利用ありがとうございます。\r\n' +
  '登録されたメールアドレスの確認を行います。\r\n' +
  '\r\n' +
  '以下のURLへアクセスしてください。\r\n' +
  '↓\r\n' +
  emailPath + '\r\n' +
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
    to: userdata.email,
    subject: 'ウィンズよりメールアドレスの確認',
    // html: '',
    text: mailText
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
  sendUpdateEmail
}