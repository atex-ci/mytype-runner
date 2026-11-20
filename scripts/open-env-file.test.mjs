// node --test scripts/open-env-file.test.mjs
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import { fileURLToPath } from 'node:url'
import { encrypt, pair } from './envelope-test-helpers.mjs'
import { openEnvFile, secretValues } from './open-env-file.mjs'

const keys = pair()
const NAME = 'acme-dev'
const CONTEXT = `mytype/${NAME}`

// What the installer sends as the file: not a real one, and with no final newline, as the installer's has none
const FEATHERS = 'feathers-secret-value'
const PASSWORD = 'aurora-password-value'
const file = [
  'ENV_TYPE=dev',
  'CONVOX_APP=mytype-acme-dev',
  `AURORA_PASSWORD="${PASSWORD}"`,
  `FEATHERS_SECRET=${FEATHERS}`,
  'LOGTAIL_KEY=',
  'MY_LABEL=città',
].join('\n')
// What the old flow carried as ENV_FILE_CONTENT: the base64 the installer made of the file
const oldInput = Buffer.from(file).toString('base64')

const open = async (overrides = {}) => {
  const logged = []
  const env = {
    ENVELOPE: await encrypt(oldInput, keys.publicKey, CONTEXT),
    INSTALL_SECRETS_PRIVATE_KEY: keys.privateKey,
    ENV_FILE_NAME: NAME,
    ...overrides,
  }
  return { logged, run: () => openEnvFile({ env, log: (line) => logged.push(line) }), env }
}

describe('openEnvFile', () => {
  it('returns exactly what the old flow received as ENV_FILE_CONTENT, so boot.sh writes the same file', async () => {
    const { run } = await open()
    const content = run()

    assert.equal(content, oldInput)
    assert.deepEqual(Buffer.from(content, 'base64'), Buffer.from(file))
  })

  it('masks the envelope, the base64 and the value of every line whose key looks like a secret, and no other', async () => {
    const { run, logged, env } = await open()
    run()

    assert.deepEqual(logged, [
      `::add-mask::${env.ENVELOPE}`,
      `::add-mask::${oldInput}`,
      `::add-mask::${PASSWORD}`,
      `::add-mask::${FEATHERS}`,
    ])
  })

  it('masks before it returns: nothing is returned that was not masked', async () => {
    const { run, logged } = await open()
    const content = run()

    assert.ok(logged.includes(`::add-mask::${content}`))
  })

  it('refuses the old flow: a base64 in clear, without echoing it', async () => {
    const { run } = await open({ ENVELOPE: oldInput })

    assert.throws(run, (error) => error.message.includes('a value in clear is refused') && !error.message.includes(FEATHERS))
  })

  it('refuses an envelope made for another environment, which is how a copied one is refused', async () => {
    const { run } = await open({ ENV_FILE_NAME: 'acme-staging' })

    assert.throws(run, /cannot be decrypted/)
  })

  it('refuses a name that is not an environment name, and a missing envelope or key', async () => {
    for (const [overrides, message] of [
      [{ ENV_FILE_NAME: 'Acme_dev' }, /ENV_FILE_NAME is/],
      [{ ENV_FILE_NAME: '' }, /ENV_FILE_NAME is/],
      [{ ENVELOPE: '' }, /no envelope/],
      [{ INSTALL_SECRETS_PRIVATE_KEY: '' }, /INSTALL_SECRETS_PRIVATE_KEY is not set/],
    ]) {
      const { run } = await open(overrides)
      assert.throws(run, message)
    }
  })

  it('refuses a content that is not base64, without echoing it', async () => {
    const { run } = await open({ ENVELOPE: await encrypt(`not base64 ${FEATHERS}`, keys.publicKey, CONTEXT) })

    assert.throws(run, (error) => error.message.includes('not base64') && !error.message.includes(FEATHERS))
  })
})

describe('secretValues', () => {
  it('takes the values of the secret-looking keys, as the BUILD step did', () => {
    const text = 'A_PASSWORD=p1\nB_SECRET="s2"\nC_TOKEN=t3\nD_KEY=k4\nE_DSN=d5\nF_CLIENT_ID=c6\nPLAIN=x\nEMPTY_KEY=\n'

    assert.deepEqual(secretValues(text), ['p1', 's2', 't3', 'k4', 'd5', 'c6'])
  })

  it('keeps an equals sign inside a value', () => {
    assert.deepEqual(secretValues('A_SECRET=ab==cd\n'), ['ab==cd'])
  })

  it('ignores a line without an equals sign and a carriage return', () => {
    assert.deepEqual(secretValues('# a_secret\r\nA_SECRET=x\r\n'), ['x'])
  })
})

describe('the script', () => {
  const script = fileURLToPath(new URL('./open-env-file.mjs', import.meta.url))

  it('writes the content to OPENED_FILE for this user only, and masks first', async () => {
    const { env } = await open()
    const opened = join(mkdtempSync(join(tmpdir(), 'open-env-')), 'env-file-content')
    const result = spawnSync('node', [script], {
      env: { ...process.env, ...env, OPENED_FILE: opened },
      encoding: 'utf8',
    })

    assert.equal(result.status, 0, result.stderr)
    assert.equal(readFileSync(opened, 'utf8'), oldInput)
    assert.equal(statSync(opened).mode & 0o777, 0o600)
    assert.ok(result.stdout.startsWith('::add-mask::'))
  })

  it('fails with a message that holds no value, and writes nothing', async () => {
    const { env } = await open({ ENVELOPE: oldInput })
    const opened = join(mkdtempSync(join(tmpdir(), 'open-env-')), 'env-file-content')
    const result = spawnSync('node', [script], {
      env: { ...process.env, ...env, OPENED_FILE: opened },
      encoding: 'utf8',
    })

    assert.equal(result.status, 1)
    assert.ok(!result.stderr.includes(FEATHERS) && !result.stdout.includes(FEATHERS))
    assert.throws(() => readFileSync(opened))
  })
})
