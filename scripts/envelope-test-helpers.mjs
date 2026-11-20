// What the tests of this directory share: a key pair, and the installer's half of the envelope as WebCrypto does it in
// the browser (apps/installer/src/business-logic/secret-envelope.ts of atex-products/mytype), written again here so a
// round trip is two implementations of the format, not one.
import { generateKeyPairSync } from 'node:crypto'

export const pair = () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  }
}

export const b64 = (bytes) => Buffer.from(bytes).toString('base64')

export const encrypt = async (text, publicKey) => {
  const wrapper = await crypto.subtle.importKey(
    'spki',
    Buffer.from(publicKey, 'base64'),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  )
  const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(text))
  const key = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, wrapper, await crypto.subtle.exportKey('raw', aesKey))
  return seal({ alg: 'RSA-OAEP-256+A256GCM', key: b64(key), iv: b64(iv), data: b64(data) })
}

export const seal = (body) => `v1.${Buffer.from(JSON.stringify(body)).toString('base64')}`
export const open = (envelope) => JSON.parse(Buffer.from(envelope.slice(3), 'base64').toString('utf8'))
