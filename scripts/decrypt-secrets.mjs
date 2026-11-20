#!/usr/bin/env node

// Opens an envelope of secrets (made by the installer, apps/installer/src/business-logic/secret-envelope.ts of
// atex-products/mytype): `v1.` and the base64 of a JSON { alg, key, iv, data }; `data` is the text encrypted with a
// random AES-256-GCM key (`iv`, the tag after the ciphertext), `key` is that AES key wrapped with RSA-OAEP (SHA-256).
// It names no product and keeps nothing: a script of this repository, run by the job that holds the private key,
// opens the envelope in memory, masks the values and uses them there (prepare-app.mjs). Nothing writes the text to a
// file, and an error never carries a value.
import { constants, createDecipheriv, createPrivateKey, privateDecrypt } from 'node:crypto'

export const ENVELOPE_PREFIX = 'v1.'
export const ENVELOPE_ALGORITHM = 'RSA-OAEP-256+A256GCM'
const IV_BYTES = 12
const TAG_BYTES = 16

const fail = (message) => {
  throw new Error(message)
}

const field = (body, name) =>
  typeof body[name] === 'string' ? Buffer.from(body[name], 'base64') : fail(`The envelope has no ${name}`)

/** The text inside `envelope`, or an Error that says what is wrong with it and never what it holds. */
export const decryptEnvelope = (envelope, privateKeyPem) => {
  if (!envelope.startsWith(ENVELOPE_PREFIX)) {
    fail(`The value is not an encrypted envelope (${ENVELOPE_PREFIX}…): a value in clear is refused`)
  }
  let body
  try {
    body = JSON.parse(Buffer.from(envelope.slice(ENVELOPE_PREFIX.length), 'base64').toString('utf8'))
  } catch {
    fail('The envelope is malformed')
  }
  if (body === null || typeof body !== 'object') {
    fail('The envelope is malformed')
  }
  if (body.alg !== ENVELOPE_ALGORITHM) {
    fail('The envelope uses an algorithm this runner does not support')
  }
  const [wrappedKey, iv, data] = ['key', 'iv', 'data'].map((name) => field(body, name))
  if (iv.length !== IV_BYTES || data.length <= TAG_BYTES) {
    fail('The envelope is malformed')
  }

  let privateKey
  try {
    privateKey = createPrivateKey(privateKeyPem)
  } catch {
    fail('The private key is not a private key in PEM')
  }
  try {
    const aesKey = privateDecrypt(
      { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      wrappedKey
    )
    const decipher = createDecipheriv('aes-256-gcm', aesKey, iv)
    decipher.setAuthTag(data.subarray(data.length - TAG_BYTES))
    return Buffer.concat([decipher.update(data.subarray(0, data.length - TAG_BYTES)), decipher.final()]).toString(
      'utf8'
    )
  } catch {
    return fail('The envelope cannot be decrypted: wrong key, or it was altered')
  }
}

/** The workflow commands that mask the envelope and the value of every KEY=VALUE line of `text`. */
export const maskCommands = (envelope, text) =>
  [envelope, ...text.split('\n').map((line) => line.replace(/\r$/, '').slice(line.indexOf('=') + 1))]
    .filter((value) => value !== '')
    .map((value) => `::add-mask::${value}`)
