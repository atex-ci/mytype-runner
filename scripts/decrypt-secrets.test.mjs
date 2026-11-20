// node --test scripts/decrypt-secrets.test.mjs
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, readFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import { decryptEnvelope, decryptToFile, maskCommands } from './decrypt-secrets.mjs'

const pair = () => {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  }
}
const keys = pair()

// The installer's side, as WebCrypto does it in the browser (apps/installer/src/business-logic/secret-envelope.ts):
// written here again, so the round trip is two implementations of the format, not one
const b64 = (bytes) => Buffer.from(bytes).toString('base64')
const encrypt = async (text, publicKey) => {
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
  const body = { alg: 'RSA-OAEP-256+A256GCM', key: b64(key), iv: b64(iv), data: b64(data) }
  return `v1.${Buffer.from(JSON.stringify(body)).toString('base64')}`
}
const open = (envelope) => JSON.parse(Buffer.from(envelope.slice(3), 'base64').toString('utf8'))
const seal = (body) => `v1.${Buffer.from(JSON.stringify(body)).toString('base64')}`
const flip = (text) => b64(Buffer.from(text, 'base64').map((byte, at) => (at === 3 ? byte ^ 1 : byte)))

const SECRET = 'client-secret-value'
const text = `KEYCLOAK_CLIENT_SECRET=${SECRET}\nKEYCLOAK_REALM=réalm\nAUTH_URL=\n`

describe('decryptEnvelope', () => {
  it('opens what the installer sealed, a value that is not Latin-1 included', async () => {
    assert.equal(decryptEnvelope(await encrypt(text, keys.publicKey), keys.privateKey), text)
  })

  it('is a different envelope every time, and holds the secret nowhere in it', async () => {
    const first = await encrypt(text, keys.publicKey)
    const second = await encrypt(text, keys.publicKey)

    assert.notEqual(first, second)
    for (const envelope of [first, second]) {
      assert.ok(!envelope.includes(SECRET))
      assert.ok(!Buffer.from(envelope.slice(3), 'base64').toString('utf8').includes(SECRET))
      assert.ok(!Buffer.from(open(envelope).data, 'base64').includes(SECRET))
    }
  })

  it('refuses a value in clear, without echoing it', () => {
    for (const clear of [Buffer.from(text).toString('base64'), text, '']) {
      assert.throws(
        () => decryptEnvelope(clear, keys.privateKey),
        (error) => error.message.includes('a value in clear is refused') && !error.message.includes(SECRET)
      )
    }
  })

  it('refuses an envelope altered in its ciphertext, its tag, its iv or its wrapped key', async () => {
    const envelope = await encrypt(text, keys.publicKey)
    const body = open(envelope)
    for (const name of ['data', 'iv', 'key']) {
      assert.throws(
        () => decryptEnvelope(seal({ ...body, [name]: flip(body[name]) }), keys.privateKey),
        (error) => error.message.includes('wrong key, or it was altered') && !error.message.includes(SECRET)
      )
    }
    const data = Buffer.from(body.data, 'base64')
    const tag = b64(Buffer.concat([data.subarray(0, -1), Buffer.from([data.at(-1) ^ 1])]))
    assert.throws(() => decryptEnvelope(seal({ ...body, data: tag }), keys.privateKey), /altered/)
  })

  it('refuses the wrong private key', async () => {
    const envelope = await encrypt(text, keys.publicKey)

    assert.throws(
      () => decryptEnvelope(envelope, pair().privateKey),
      (error) => error.message.includes('wrong key, or it was altered') && !error.message.includes(SECRET)
    )
  })

  it('refuses an envelope that is malformed, an algorithm that is not its own, a field that is missing', async () => {
    const body = open(await encrypt(text, keys.publicKey))

    assert.throws(() => decryptEnvelope('v1.%%%', keys.privateKey), /malformed/)
    assert.throws(() => decryptEnvelope(`v1.${b64('not json')}`, keys.privateKey), /malformed/)
    assert.throws(() => decryptEnvelope(seal(null), keys.privateKey), /malformed/)
    assert.throws(() => decryptEnvelope(seal({ ...body, alg: 'none' }), keys.privateKey), /algorithm/)
    assert.throws(() => decryptEnvelope(seal({ ...body, iv: undefined }), keys.privateKey), /no iv/)
    assert.throws(() => decryptEnvelope(seal({ ...body, iv: b64('short') }), keys.privateKey), /malformed/)
  })

  it('says when the private key is not one, without printing it', async () => {
    const envelope = await encrypt(text, keys.publicKey)

    assert.throws(
      () => decryptEnvelope(envelope, 'not a key'),
      (error) => error.message === 'The private key is not a private key in PEM'
    )
  })
})

describe('maskCommands', () => {
  it('masks the envelope and the value of every line, not its name, and skips an empty value', () => {
    assert.deepEqual(maskCommands('v1.abc', 'A=1\nB=x=y z\nC=\n'), ['::add-mask::v1.abc', '::add-mask::1', '::add-mask::x=y z'])
  })

  it('masks a line that is not KEY=VALUE whole, and a value that ends in a carriage return without it', () => {
    assert.deepEqual(maskCommands('v1.abc', 'plainsecret\nA=1\r\n'), [
      '::add-mask::v1.abc',
      '::add-mask::plainsecret',
      '::add-mask::1',
    ])
  })
})

describe('decryptToFile', () => {
  const run = async (overrides = {}) => {
    const out = join(mkdtempSync(join(tmpdir(), 'decrypt-')), 'variables')
    const logged = []
    const env = {
      ENVELOPE: await encrypt(text, keys.publicKey),
      INSTALL_SECRETS_PRIVATE_KEY: keys.privateKey,
      ...overrides,
    }
    return { out, logged, run: () => decryptToFile({ env, out, log: (line) => logged.push(line) }) }
  }

  it('masks first, then writes the text to a file only its owner reads', async () => {
    const { out, logged, run: go } = await run()

    go()

    assert.ok(logged.includes(`::add-mask::${SECRET}`))
    assert.ok(logged.every((line) => line.startsWith('::add-mask::')))
    assert.equal(readFileSync(out, 'utf8'), text)
    assert.equal(statSync(out).mode & 0o777, 0o600)
  })

  it('writes nothing when the envelope is refused', async () => {
    const { out, logged, run: go } = await run({ ENVELOPE: Buffer.from(text).toString('base64') })

    assert.throws(go, /in clear is refused/)
    assert.deepEqual(logged, [])
    assert.throws(() => statSync(out))
  })

  it('needs the envelope and the key, and says which is missing', async () => {
    assert.throws((await run({ ENVELOPE: '' })).run, /no envelope/)
    assert.throws((await run({ INSTALL_SECRETS_PRIVATE_KEY: '' })).run, /INSTALL_SECRETS_PRIVATE_KEY is not set/)
  })
})
