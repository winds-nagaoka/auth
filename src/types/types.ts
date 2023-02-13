export type Client = {
  agent: string
  id: string
  token: string
  lastLogin: number
}

export type User = {
  name: string
  userid: string
  hash: string
  email: string | null
  emailHash?: string
  emailValid: boolean
  emailValidKey: string | null
  emailValidExpire: number | null
  clientList: Client[]
  regTime: number
}

export type Callback<T> = (type: { type: string } | null, value: T | null) => void

export type Session = {
  userid: string
  clientid: string
  clientToken: string
  useragent: string
  version: string
}
