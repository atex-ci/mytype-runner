// node --test scripts/prepare-app.test.mjs
import assert from 'node:assert/strict'
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import { b64, encrypt, pair } from './envelope-test-helpers.mjs'
import { childEnvironment, createAppLine, parseVariables, prepareApp, shell } from './prepare-app.mjs'

const keys = pair()
const CONTEXT = 'contributor/contributor-test'
const SECRET = 'client-secret-value'
const text = `KEYCLOAK_CLIENT_SECRET=${SECRET}\nKEYCLOAK_REALM=réalm\nAUTH_SECRET=generated-secret-value\nAUTH_URL=\n`

const envFileText = [
  'TARGET=convox',
  'CONVOX_RACK=atex-cloud/newsbeat-prod',
  'CONVOX_APP=contributor-test',
  'CONVOX_MANIFEST=apps/contributor/convox.yml',
  'CONVOX_IGNORE_FILE=apps/contributor/Dockerfile.dockerignore',
  'ENV_TYPE=dev',
  'URL=',
  '',
].join('\n')

// A convox that keeps the apps of the rack and their variables in a directory, and records every call and every stdin
const FAKE_CONVOX = `#!/bin/bash
state="$STATE"
echo "$*" >> "$state/calls"
app=""
for ((i = 1; i <= $#; i++)); do
  if [ "\${!i}" = "--app" ]; then j=$((i + 1)); app="\${!j}"; fi
done
case "$1 $2" in
  "login console.convox.com") ;;
  "apps create") echo "$3" >> "$state/apps"; : > "$state/env-$3" ;;
  "apps info") printf 'Name        %s\\nStatus      running\\n' "$3" ;;
  "env set") cat >> "$state/env-$app" ;;
  "env --app") cat "$state/env-$app" ;;
  *) printf 'APP  STATUS  GENERATION\\n'; [ -f "$state/apps" ] && sed 's/$/  running  2/' "$state/apps" ;;
esac
`

const rack = ({ apps = {}, timeline = [] } = {}) => {
  const state = mkdtempSync(join(tmpdir(), 'fake-convox-'))
  writeFileSync(join(state, 'convox'), FAKE_CONVOX)
  chmodSync(join(state, 'convox'), 0o755)
  writeFileSync(join(state, 'apps'), Object.keys(apps).map((app) => `${app}\n`).join(''))
  for (const [app, variables] of Object.entries(apps)) {
    writeFileSync(join(state, `env-${app}`), variables)
  }
  const out = []
  const err = []
  const env = { ...process.env, PATH: `${state}:${process.env.PATH}`, STATE: state, CONVOX_TOKEN: 'test-token' }
  const calls = () => (existsSync(join(state, 'calls')) ? readFileSync(join(state, 'calls'), 'utf8') : '')
  const variables = (app = 'contributor-test') => readFileSync(join(state, `env-${app}`), 'utf8')
  const io = shell({
    env,
    out: { write: (chunk) => (out.push(chunk), timeline.push(['out', chunk])) },
    err: { write: (chunk) => (err.push(chunk), timeline.push(['err', chunk])) },
  })
  return { state, env, calls, variables, out, err, ...io }
}

const present = ({ branch = true, files = [] } = {}) => ({
  branch: async () => branch,
  file: async (path) => files.includes(path),
})
const manifestFiles = ['apps/contributor/convox.yml', 'apps/contributor/Dockerfile.dockerignore']

const inputs = async (overrides = {}) => ({
  PRODUCT: 'contributor',
  ENVIRONMENT: 'contributor-test',
  GIT_BRANCH: 'main',
  ENV_FILE_CONTENT: b64(envFileText),
  ENVELOPE: await encrypt(text, keys.publicKey, CONTEXT),
  INSTALL_SECRETS_PRIVATE_KEY: keys.privateKey,
  ...overrides,
})

const prepare = async ({ overrides, github = present({ files: manifestFiles }), timeline = [], ...fakeRack } = {}) => {
  const r = rack({ ...fakeRack, timeline })
  const logged = []
  const result = prepareApp({
    env: await inputs(overrides),
    github,
    run: r.run,
    runWithInput: r.runWithInput,
    log: (line) => (logged.push(line), timeline.push(['log', line])),
  })
  return { ...r, logged, result }
}

describe('prepareApp, on a rack that does not list the app', () => {
  it('creates the app, marks it, and sets the variables from stdin', async () => {
    const r = await prepare()

    await r.result
    assert.match(r.calls(), /apps create contributor-test --rack atex-cloud\/newsbeat-prod/)
    assert.equal(r.variables(), `INSTALLED_PRODUCT=contributor\n${text}`)
  })

  it('reports nothing to the next job: it returns no name and no value', async () => {
    const r = await prepare()

    assert.equal(await r.result, undefined)
  })

  it('puts no value on a command line, in the output of the run, or in a file', async () => {
    const r = await prepare()

    await r.result
    const printed = [r.calls(), ...r.out, ...r.err].join('')
    for (const value of [SECRET, 'generated-secret-value', 'réalm', b64(text)]) {
      assert.ok(!printed.includes(value), `${value.slice(0, 6)}… was printed`)
    }
    for (const file of readdirSync(r.state).filter((name) => !name.startsWith('env-') && name !== 'convox')) {
      assert.ok(!readFileSync(join(r.state, file), 'utf8').includes(SECRET), `${file} holds a secret`)
    }
  })

  it('masks every value before the rack is touched', async () => {
    const timeline = []
    const result = prepareApp({
      env: await inputs(),
      github: present({ files: manifestFiles }),
      run: async () => timeline.push('run'),
      runWithInput: async () => timeline.push('input'),
      log: (line) => timeline.push(line),
    })

    await result
    const firstRun = timeline.findIndex((entry) => entry === 'run')
    assert.ok(firstRun > 0)
    for (const value of [SECRET, 'generated-secret-value', 'réalm']) {
      assert.ok(timeline.slice(0, firstRun).includes(`::add-mask::${value}`))
    }
  })

  it('prints every mask before anything else: the lines it runs and the output of the rack come after', async () => {
    const timeline = []
    const r = await prepare({ timeline })

    await r.result
    const lastMask = timeline.findLastIndex(([kind]) => kind === 'log')
    const firstOther = timeline.findIndex(([kind]) => kind !== 'log')
    assert.ok(lastMask >= 0 && firstOther > lastMask, 'something was printed before the last mask')
    assert.ok(timeline.every(([kind, line]) => kind !== 'log' || line.startsWith('::add-mask::')))
  })

  it('sets an empty value as it is', async () => {
    const r = await prepare({ overrides: { ENVELOPE: await encrypt('AUTH_URL=\n', keys.publicKey, CONTEXT) } })

    await r.result
    assert.equal(r.variables(), 'INSTALLED_PRODUCT=contributor\nAUTH_URL=\n')
  })
})

describe('prepareApp, on a rack that lists the app', () => {
  it('goes on with an app of its own: nothing is created, the variables are merged', async () => {
    const r = await prepare({ apps: { 'contributor-test': 'OLD=1\nINSTALLED_PRODUCT=contributor\n' } })

    await r.result
    assert.ok(!r.calls().includes('apps create'))
    assert.equal(r.variables(), `OLD=1\nINSTALLED_PRODUCT=contributor\n${text}`)
  })

  it('refuses an app without the mark, or marked for another product, and changes nothing', async () => {
    for (const before of ['DATABASE_URL=x\n', 'INSTALLED_PRODUCT=insights\n']) {
      const r = await prepare({ apps: { 'contributor-test': before } })

      await assert.rejects(r.result, /A command of the install failed/)
      assert.ok(
        r.err.join('').includes(
          'app contributor-test exists on atex-cloud/newsbeat-prod and was not created by an install of contributor'
        )
      )
      assert.ok(
        r.err.join('').includes(
          'mark it by hand and run the install again: convox env set INSTALLED_PRODUCT=contributor --app contributor-test --rack atex-cloud/newsbeat-prod'
        )
      )
      assert.ok(!r.calls().includes('apps create'))
      assert.equal(r.variables(), before)
    }
  })
})

describe('prepareApp, before the rack is touched', () => {
  const refused = async (message, options) => {
    const r = await prepare(options)

    await assert.rejects(r.result, message)
    assert.equal(r.calls(), '', 'the rack was called')
    assert.deepEqual(r.logged, [], 'a value was masked, so it was opened')
  }
  const withEnvFile = async (change) => ({ ENV_FILE_CONTENT: b64(change(envFileText)) })

  it('refuses a name that is not an environment name, a product that is not one', async () => {
    await refused(/ENVIRONMENT starts with a letter/, { overrides: { ENVIRONMENT: 'Contributor-test' } })
    await refused(/ENVIRONMENT starts with a letter/, { overrides: { ENVIRONMENT: 'contributor-' } })
    await refused(/PRODUCT is not a product name/, { overrides: { PRODUCT: '../x' } })
  })

  it('refuses an environment file that is not a Convox one the environment names', async () => {
    await refused(/TARGET must be convox, got 'ecs'/, {
      overrides: await withEnvFile((text) => text.replace('TARGET=convox', 'TARGET=ecs')),
    })
    await refused(/CONVOX_RACK is organization\/rack/, {
      overrides: await withEnvFile((text) => text.replace('atex-cloud/newsbeat-prod', 'a b;c')),
    })
    await refused(/CONVOX_APP must be the environment name 'contributor-test', got 'other'/, {
      overrides: await withEnvFile((text) => text.replace('CONVOX_APP=contributor-test', 'CONVOX_APP=other')),
    })
    await refused(/ENV_TYPE must be one of dev, staging, production, got 'prod'/, {
      overrides: await withEnvFile((text) => text.replace('ENV_TYPE=dev', 'ENV_TYPE=prod')),
    })
  })

  it('refuses a branch that is missing, an environment file that exists, a manifest the branch lacks', async () => {
    await refused(/The branch main does not exist/, { github: present({ branch: false }) })
    await refused(/apps\/contributor\/deploy\/contributor-test.env already exists on main/, {
      github: present({ files: [...manifestFiles, 'apps/contributor/deploy/contributor-test.env'] }),
    })
    await refused(/apps\/contributor\/convox.yml does not exist on main/, { github: present() })
  })

  it('refuses a value in clear, a tampered envelope, the wrong key, without echoing a value', async () => {
    const attempts = [
      { ENVELOPE: b64(text) },
      { ENVELOPE: `${await encrypt(text, keys.publicKey, CONTEXT)}AA` },
      { INSTALL_SECRETS_PRIVATE_KEY: pair().privateKey },
    ]
    for (const overrides of attempts) {
      const r = await prepare({ overrides })

      await assert.rejects(r.result, (error) => !error.message.includes(SECRET))
      assert.equal(r.calls(), '')
    }
  })

  it('refuses an envelope sealed for another environment or product, without echoing a value', async () => {
    for (const sealedFor of ['contributor/contributor-other', 'insights/contributor-test']) {
      const r = await prepare({ overrides: { ENVELOPE: await encrypt(text, keys.publicKey, sealedFor) } })

      await assert.rejects(r.result, (error) => error.message.includes('another product or environment') && !error.message.includes(SECRET))
      assert.equal(r.calls(), '')
      assert.deepEqual(r.logged, [])
    }
  })

  it('refuses an empty envelope, and says that the key is not set', async () => {
    await refused(/no envelope/, { overrides: { ENVELOPE: '' } })
    await refused(/INSTALL_SECRETS_PRIVATE_KEY is not set/, { overrides: { INSTALL_SECRETS_PRIVATE_KEY: '' } })
  })

  it('refuses variables with a carriage return or a line that is not KEY=VALUE, naming the line only', async () => {
    for (const [body, message] of [
      ['A=1\r\nB=this-is-a-secret\r\n', 'VARIABLES line 1 has a carriage return'],
      ['A=1\nthis-is-a-secret', 'VARIABLES line 2 is not KEY=VALUE'],
    ]) {
      const r = await prepare({ overrides: { ENVELOPE: await encrypt(body, keys.publicKey, CONTEXT) } })

      await assert.rejects(r.result, (error) => error.message === message)
      assert.equal(r.calls(), '')
    }
  })
})

describe('parseVariables', () => {
  it('reads KEY=VALUE lines, keeping a value as written', () => {
    assert.deepEqual(parseVariables('A=1\n\nB=x=y z\nC=\n'), { A: '1', B: 'x=y z', C: '' })
  })
})

describe('createAppLine', () => {
  it('quotes what is not a plain word', () => {
    const line = createAppLine({ rack: 'org/rack', app: 'a', product: "it's" })

    assert.ok(line.includes("'INSTALLED_PRODUCT=it'\\''s'"))
  })
})

describe('childEnvironment', () => {
  it('keeps the envelope, the private key and the credential of GitHub from the commands it runs, not the token of Convox', () => {
    const env = childEnvironment({
      PATH: '/bin',
      CONVOX_TOKEN: 'convox-token',
      ENVELOPE: 'v1.x',
      INSTALL_SECRETS_PRIVATE_KEY: 'key',
      GH_PASSWORD: 'github',
      GH_OWNER: 'atex-ci',
    })

    assert.deepEqual(env, { PATH: '/bin', CONVOX_TOKEN: 'convox-token', GH_OWNER: 'atex-ci' })
  })

  it('is what the commands see: a bash of the install finds none of them', async () => {
    const r = rack()
    const hidden = childEnvironment({
      ...r.env,
      ENVELOPE: 'v1.x',
      INSTALL_SECRETS_PRIVATE_KEY: 'a-private-key',
      GH_PASSWORD: 'a-credential',
    })
    const out = []
    const { run } = shell({ env: hidden, out: { write: (chunk) => out.push(chunk) }, err: { write: () => {} } })

    run('env | grep -c -E "^(ENVELOPE|INSTALL_SECRETS_PRIVATE_KEY|GH_PASSWORD)=" || true')

    assert.ok(out.join('').trim().endsWith('0'))
  })
})
