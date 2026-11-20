// node --test scripts/generate-install-keys.test.mjs
import assert from 'node:assert/strict'
import { createPrivateKey, createPublicKey } from 'node:crypto'
import { describe, it } from 'node:test'
import { generateInstallKeys, REPOSITORY, SECRET_NAME } from './generate-install-keys.mjs'

// A gh that records what it is given and lists the secrets it is told exist
const fakeGh = ({ existing = [], failOn } = {}) => {
  const calls = []
  const run = (args, input) => {
    calls.push({ args, input })
    if (failOn === args[1]) {
      return { status: 1, stdout: '', stderr: `${args[1]} failed` }
    }
    return { status: 0, stdout: args[1] === 'list' ? `${existing.join('\n')}\n` : '', stderr: '' }
  }
  return { calls, run }
}

describe('generateInstallKeys', () => {
  it('stores the private key through stdin of gh secret set, and returns the matching public key', () => {
    const { calls, run } = fakeGh()

    const publicKey = generateInstallKeys({ run })

    const set = calls.find(({ args }) => args[1] === 'set')
    assert.deepEqual(set.args, ['secret', 'set', SECRET_NAME, '-R', REPOSITORY])
    const stored = createPublicKey(createPrivateKey(set.input)).export({ type: 'spki', format: 'der' })
    assert.equal(publicKey, stored.toString('base64'))
  })

  it('puts no part of the private key on a command line, and the public key is not the private one', () => {
    const { calls, run } = fakeGh()

    const publicKey = generateInstallKeys({ run })

    const body = calls.find(({ args }) => args[1] === 'set').input.replace(/-----[A-Z ]+-----|\s/g, '')
    for (const { args } of calls) {
      assert.ok(args.every((arg) => !arg.includes(body.slice(0, 40))))
    }
    assert.ok(!publicKey.includes(body.slice(0, 40)))
  })

  it('refuses to replace a secret that exists, then does with --replace', () => {
    const existing = fakeGh({ existing: [SECRET_NAME] })

    assert.throws(() => generateInstallKeys({ run: existing.run }), /already exists.*--replace/)
    assert.ok(existing.calls.every(({ args }) => args[1] !== 'set'))
    assert.ok(generateInstallKeys({ run: fakeGh({ existing: [SECRET_NAME] }).run, replace: true }))
  })

  it('names the failing gh step and prints no key', () => {
    for (const step of ['list', 'set']) {
      assert.throws(
        () => generateInstallKeys({ run: fakeGh({ failOn: step }).run }),
        (error) => error.message.includes(`${step} failed`) && !error.message.includes('-----BEGIN')
      )
    }
  })
})
