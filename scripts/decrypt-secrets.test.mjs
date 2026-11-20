// node --test scripts/decrypt-secrets.test.mjs
import assert from 'node:assert/strict'
import { createPrivateKey } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { describe, it } from 'node:test'
import { decryptEnvelope, maskCommands } from './decrypt-secrets.mjs'
import { b64, encrypt, open, pair, seal } from './envelope-test-helpers.mjs'

const golden = JSON.parse(readFileSync(new URL('./__fixtures__/golden-envelope.json', import.meta.url), 'utf8'))

const keys = pair()
const context = 'contributor/contributor-test'

const flip = (text) => b64(Buffer.from(text, 'base64').map((byte, at) => (at === 3 ? byte ^ 1 : byte)))

const SECRET = 'client-secret-value'
const text = `KEYCLOAK_CLIENT_SECRET=${SECRET}\nKEYCLOAK_REALM=réalm\nAUTH_URL=\n`

describe('decryptEnvelope', () => {
  it('opens what the installer sealed, a value that is not Latin-1 included', async () => {
    assert.equal(decryptEnvelope(await encrypt(text, keys.publicKey, context), keys.privateKey, context), text)
  })

  it('is a different envelope every time, and holds the secret nowhere in it', async () => {
    const first = await encrypt(text, keys.publicKey, context)
    const second = await encrypt(text, keys.publicKey, context)

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
        () => decryptEnvelope(clear, keys.privateKey, context),
        (error) => error.message.includes('a value in clear is refused') && !error.message.includes(SECRET)
      )
    }
  })

  it('refuses an envelope altered in its ciphertext, its tag, its iv or its wrapped key', async () => {
    const envelope = await encrypt(text, keys.publicKey, context)
    const body = open(envelope)
    for (const name of ['data', 'iv', 'key']) {
      assert.throws(
        () => decryptEnvelope(seal({ ...body, [name]: flip(body[name]) }), keys.privateKey, context),
        (error) => error.message.includes('or it was altered') && !error.message.includes(SECRET)
      )
    }
    const data = Buffer.from(body.data, 'base64')
    const tag = b64(Buffer.concat([data.subarray(0, -1), Buffer.from([data.at(-1) ^ 1])]))
    assert.throws(() => decryptEnvelope(seal({ ...body, data: tag }), keys.privateKey, context), /altered/)
  })

  it('refuses the wrong private key', async () => {
    const envelope = await encrypt(text, keys.publicKey, context)

    assert.throws(
      () => decryptEnvelope(envelope, pair().privateKey, context),
      (error) => error.message.includes('or it was altered') && !error.message.includes(SECRET)
    )
  })

  it('refuses an envelope that is malformed, an algorithm that is not its own, a field that is missing', async () => {
    const body = open(await encrypt(text, keys.publicKey, context))

    assert.throws(() => decryptEnvelope('v1.%%%', keys.privateKey, context), /malformed/)
    assert.throws(() => decryptEnvelope(`v1.${b64('not json')}`, keys.privateKey, context), /malformed/)
    assert.throws(() => decryptEnvelope(seal(null), keys.privateKey, context), /malformed/)
    assert.throws(() => decryptEnvelope(seal({ ...body, alg: 'none' }), keys.privateKey, context), /algorithm/)
    assert.throws(() => decryptEnvelope(seal({ ...body, iv: undefined }), keys.privateKey, context), /no iv/)
    assert.throws(() => decryptEnvelope(seal({ ...body, iv: b64('short') }), keys.privateKey, context), /malformed/)
  })

  it('opens only for the product and the environment it was sealed for, and says so without a value', async () => {
    const envelope = await encrypt(text, keys.publicKey, context)

    for (const other of ['contributor/contributor-other', 'insights/contributor-test', 'contributor/contributor-test/']) {
      assert.throws(
        () => decryptEnvelope(envelope, keys.privateKey, other),
        (error) => error.message.includes('another product or environment') && !error.message.includes(SECRET)
      )
    }
    assert.throws(() => decryptEnvelope(envelope, keys.privateKey, ''), /needs a context/)
  })

  it('says when the private key is not one, without printing it', async () => {
    const envelope = await encrypt(text, keys.publicKey, context)

    assert.throws(
      () => decryptEnvelope(envelope, 'not a key', context),
      (error) => error.message === 'The private key is not a private key in PEM'
    )
  })
})

// TEST ONLY: the key pair of the golden vector protects nothing; the same file is in atex-products/mytype, where the
// installer's real encryptSecrets made the envelope
describe('the golden vector made by the real encryptSecrets of the installer', () => {
  const privateKey = createPrivateKey({
    key: Buffer.from(golden.privateKeyPkcs8, 'base64'),
    format: 'der',
    type: 'pkcs8',
  }).export({ type: 'pkcs8', format: 'pem' })

  it('is opened by the real decryptEnvelope, for its context', () => {
    assert.equal(decryptEnvelope(golden.envelope, privateKey, golden.context), golden.plaintext)
  })

  it('is refused for another context', () => {
    assert.throws(() => decryptEnvelope(golden.envelope, privateKey, 'contributor/another'), /another product/)
  })
})

describe('maskCommands', () => {
  it('masks the envelope and the value of every line, not its name, and skips an empty value', () => {
    assert.deepEqual(maskCommands('v1.abc', 'A=1\nB=x=y z\nC=\n'), ['::add-mask::v1.abc', '::add-mask::1', '::add-mask::x=y z'])
  })

  it('escapes the value as @actions/core does: a % first, then a carriage return and a line feed', () => {
    assert.deepEqual(maskCommands('v1.abc', 'A=100%\nB=x%25y\nC=a\rb\n'), [
      '::add-mask::v1.abc',
      '::add-mask::100%25',
      '::add-mask::x%2525y',
      '::add-mask::a%0Db',
    ])
  })

  it('masks a line that is not KEY=VALUE whole, and a value that ends in a carriage return without it', () => {
    assert.deepEqual(maskCommands('v1.abc', 'plainsecret\nA=1\r\n'), [
      '::add-mask::v1.abc',
      '::add-mask::plainsecret',
      '::add-mask::1',
    ])
  })
})
